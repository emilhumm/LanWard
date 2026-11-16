"""Shared helpers for LanWard: paths, the SQLite connection and its schema
migration, alert writing with de-duplication, push notifications (Home Assistant
webhook and/or Apprise services), MAC vendor lookup and a few local network facts
(own MAC, default gateway, the LAN to watch).

Every other module imports this one, so keep it free of heavy imports.
"""
import hashlib
import ipaddress
import json
import os
import re
import math
import secrets
import socket
import sqlite3
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("LANWARD_DATA") or ROOT / "data")
DB_PATH = DATA_DIR / "scanner.db"
SCHEMA_SQL = ROOT / "db" / "schema.sql"
SCAN_LOCK = DATA_DIR / ".scan.lock"          # "pid\nlog path\nsubnet" of the running scan
SCAN_LOG_DIR = DATA_DIR / "scan-logs"



def _route_iface():
    """The interface of the IPv4 default route (eno1, eth0...), from /proc/net/route."""
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            if len(f) > 3 and f[1] == "00000000" and int(f[3], 16) & 2:     # 0.0.0.0 via a gateway
                return f[0]
    except (OSError, ValueError):
        pass
    return None


def _iface_inet(iface):
    """The IPv4 address and prefix on `iface` ("192.168.1.50/24"), or None."""
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", iface],
                             capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out)
    return m.group(1) if m else None


def _saved_override(name):
    """A network value saved on the Settings page (kv setting:IFACE / setting:SUBNET), read once here at
    startup. It only takes effect on a restart, because the packet listener binds to the interface at boot,
    so it is read from the file directly (read-only), not through the live setting() cache (2026-10-28)."""
    if not DB_PATH.exists():
        return None
    try:
        conn = sqlite3.connect(f"{DB_PATH.as_uri()}?mode=ro", uri=True, timeout=5)
        try:
            row = conn.execute("SELECT value FROM kv WHERE key = ?", (f"setting:{name}",)).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    return row[0].strip() if row and row[0] and row[0].strip() else None


# The LAN LanWard watches: IFACE and SUBNET from the Settings page, else .env, else the interface of the
# default route and the network on it, so a fresh install needs no editing (2026-10-27). A value set on the
# page takes effect only on a restart (_saved_override). SUBNET stays empty when nothing works; scan.py then
# says so instead of scanning a guess.
IFACE = _saved_override("IFACE") or os.environ.get("IFACE", "").strip() or _route_iface() or "eth0"
_INET = _iface_inet(IFACE)
SUBNET = (_saved_override("SUBNET") or os.environ.get("SUBNET", "").strip()
          or (str(ipaddress.ip_interface(_INET).network) if _INET else ""))
DASHBOARD_URL = (os.environ.get("DASHBOARD_URL", "").strip()
                 or f"http://{_INET.split('/')[0] if _INET else 'localhost'}:{os.environ.get('PORT', '8080')}"
                 ).rstrip("/")


def dashboard_port():
    """The TCP port LanWard serves its own dashboard on (PORT, from DASHBOARD_PORT; default 8080). Used to keep
    LanWard from alerting that its own machine opened a new port when that port is just its own dashboard."""
    try:
        return int(os.environ.get("PORT", "8080"))
    except ValueError:
        return 8080

# Where alerts go, all optional (2026-10-27: LanWard knows no particular service), set on the
# Settings page or in .env (see SETTING_DEFAULTS):
# - WEBHOOK_URLS: every alert POSTed as JSON to each URL (Home Assistant, Node-RED, n8n...),
#   separated by spaces. HA_WEBHOOK_URL is one more such URL, the setting's older name.
# - NOTIFY_URLS: a message straight to a phone or inbox through Apprise (ntfy://, tgram://,
#   pover://, mailto://, discord://...; https://github.com/caronc/apprise/wiki).
HA_WEBHOOK_URL = os.environ.get("HA_WEBHOOK_URL", "").strip()

SEVERITY_RANK = {"info": 0, "warning": 1, "alert": 2}
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


# What the dashboard's Settings page can change (2026-10-27), as the text .env would hold. A value
# saved on the page (kv "setting:NAME") wins over .env, which wins over these defaults. Every
# process reads them fresh (setting(), cached a few seconds), so a change needs no restart.
SETTING_DEFAULTS = {
    "WEBHOOK_URLS": "", "NOTIFY_URLS": "", "NOTIFY_MIN_SEVERITY": "warning",
    "SCAN_HOURS": "0,6,12,18", "RETAIN_SCAN_DAYS": "365", "BACKUP_KEEP_DAYS": "14",
    "WATCH_OFFLINE_MINUTES": "10", "DHCP_SERVERS_OK": "", "STATUS_ALLOW": "127.0.0.1",
    "SCANNERS_OK": "",                      # MACs allowed to scan the network (watcher.check_scanners)
    "FULL_PORT_CHECK_DAYS": "1",            # every port of every device once in this many days (0: never)
    "SUPPORT_CHECK": "on",                  # known-flaw (CISA) + end-of-life checks per device (supportcheck.py)
    "AUTO_LOGOUT_MINUTES": "0",             # log out after this many idle minutes (0: stay logged in)
    # Quiet (info) alerts always show on the dashboard; each can also be pushed to every destination
    # (phone, webhooks), past NOTIFY_MIN_SEVERITY, when its INFO_PUSH_<KIND> is on. See write_info_alert.
    "INFO_PUSH_FIRMWARE": "off", "INFO_PUSH_GHOST": "off",
    "INFO_PUSH_SCANNING": "off", "INFO_PUSH_ONLINE": "on",
}
_SETTINGS_CACHE = {"at": float("-inf"), "page": {}}


def setting_base(name):
    """A setting without the Settings page: .env, else the default. HA_WEBHOOK_URL joins the webhooks."""
    value = os.environ.get(name)
    value = SETTING_DEFAULTS[name] if value is None else value.strip()
    if name == "WEBHOOK_URLS" and HA_WEBHOOK_URL and HA_WEBHOOK_URL not in value.split():
        value = f"{value} {HA_WEBHOOK_URL}".strip()
    return value


def page_settings():
    """{NAME: value} of what was saved on the Settings page (re-read every 5 s)."""
    if time.monotonic() - _SETTINGS_CACHE["at"] > 5:
        try:
            conn = connect()
            try:
                _SETTINGS_CACHE["page"] = {r[0][8:]: r[1] for r in conn.execute(
                    "SELECT key, value FROM kv WHERE key LIKE 'setting:%'")}
            finally:
                conn.close()
        except sqlite3.Error:               # no kv table yet (before migrate): keep what we had
            pass
        _SETTINGS_CACHE["at"] = time.monotonic()
    return _SETTINGS_CACHE["page"]


def setting(name):
    """The Settings page's value for NAME, else .env's, else the default."""
    value = page_settings().get(name)
    return setting_base(name) if value is None else value


def setting_on(name):
    """A yes/no setting as a bool (on/1/true/yes = on)."""
    return setting(name).strip().lower() in ("on", "1", "true", "yes")


def save_settings(conn, values):
    """Store what the Settings page sent ({NAME: text}). A value equal to the .env/default one is not
    stored (any stored one is removed), so .env stays in charge of what the page did not change."""
    for name, value in values.items():
        if value == setting_base(name):
            conn.execute("DELETE FROM kv WHERE key = ?", (f"setting:{name}",))
        else:
            kv_set(conn, f"setting:{name}", value)
    kv_set(conn, "settings_changed_at", now_iso())      # the scheduler re-plans when this moves
    _SETTINGS_CACHE["at"] = float("-inf")


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def iso_ago(**delta):
    return (datetime.now() - timedelta(**delta)).isoformat(timespec="seconds")


def log(*parts):
    print(datetime.now().strftime("%H:%M:%S"), *parts, flush=True)


# ------------------------------------------------------------------ database

def connect(autocommit=False):
    """Open scanner.db. autocommit=True suits the long-running processes
    (passive monitor, watcher) so they never hold a write lock between ticks."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30,
                           isolation_level=None if autocommit else "DEFERRED")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _add_columns(conn, table, columns):
    have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    for name, typ in columns:
        if name not in have:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {typ}")


def migrate(conn):
    """Bring any scanner.db (fresh or from an older version) up to the current
    schema. Idempotent and cheap; every process calls it at start."""
    try:                                    # WAL: readers never block the writer; the setting stays in the file
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError:        # busy: the next process start tries again
        pass
    conn.executescript(SCHEMA_SQL.read_text())
    _add_columns(conn, "hosts", [
        ("http_server", "TEXT"), ("http_title", "TEXT"), ("ssh_banner", "TEXT"),
        ("tls_cert_cn", "TEXT"), ("tls_cert_issuer", "TEXT"),
        ("tls_cert_not_before", "TEXT"), ("tls_cert_not_after", "TEXT"),
        ("tls_cert_fingerprint", "TEXT"), ("tls_cert_san", "TEXT"),
        ("mdns_services", "TEXT"), ("upnp_info", "TEXT"), ("ipv6_addrs", "TEXT"),
        ("open_ports", "TEXT"), ("web_info", "TEXT"), ("findings", "TEXT"),
        # The MAC the device was reached through when it is not its own: Sonos speakers on
        # SonosNet answer ARP with the bridging speaker's MAC (2026-10-27)
        ("bridge_mac", "TEXT"),
    ])
    _add_columns(conn, "alerts", [("acknowledged_at", "TEXT"), ("kind", "TEXT")])
    # Ports the device never had open before, for alerts.py (scan.py, 2026-10-27)
    _add_columns(conn, "hosts", [("new_ports", "TEXT")])
    _add_columns(conn, "port_checks", [("first_full_at", "TEXT")])
    # What is behind each port and how LanWard knows (portid.py), when the network was last asked, and where a
    # random port moved after a restart (record_open_ports), 2026-11-02
    _add_columns(conn, "open_ports_seen", [("what", "TEXT"), ("how", "TEXT"), ("sure", "INTEGER"),
                                           ("checked_at", "TEXT"), ("moved_to", "TEXT"), ("moved_from", "TEXT")])
    conn.execute("UPDATE port_checks SET first_full_at = full_checked_at WHERE first_full_at IS NULL")
    _add_columns(conn, "host_labels", [("watch_offline", "INTEGER DEFAULT 0")])
    # 1 when the offline alert went to Home Assistant, so "back online" is pushed only then (2026-10-26)
    _add_columns(conn, "watch_state", [("pushed", "INTEGER")])
    # Which service a queued push is for (2026-10-27; NULL: rows from when Home Assistant was the only one)
    _add_columns(conn, "notify_outbox", [("target", "TEXT")])
    # Since when outages are recorded (uptime() counts no time before it; 2026-10-27)
    if kv_get(conn, "outages_since") is None:
        kv_set(conn, "outages_since", now_iso())
    # The first full hour counted without LanWard's own ARP and the answers to it: activity.py learns
    # what is usual from then on (2026-10-27)
    if kv_get(conn, "activity_clean_since") is None:
        next_hour = datetime.now().replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        kv_set(conn, "activity_clean_since", next_hour.strftime("%Y-%m-%dT%H"))
    # Scans used to store MACs upper-case and everything else lower-case.
    if kv_get(conn, "mac_lowercase_done") is None:
        conn.execute("UPDATE hosts SET mac = LOWER(mac) WHERE mac <> LOWER(mac)")
        conn.execute("UPDATE OR IGNORE observations SET mac = LOWER(mac) WHERE mac <> LOWER(mac)")
        kv_set(conn, "mac_lowercase_done", now_iso())
    conn.commit()


def kv_get(conn, key, default=None):
    row = conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def kv_set(conn, key, value):
    conn.execute(
        "INSERT INTO kv (key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, value, now_iso()),
    )


# ------------------------------------------------------------------ alerts

def is_new(conn, key, days=30, refresh=True):
    """True if `key` was not seen in the last `days` days. Records it either
    way, so a condition that persists alerts once, and again only after it
    has been gone for `days` days. refresh=False records it only when it is new,
    so `days` counts from the last alert: a condition that persists alerts again
    every `days` days."""
    row = conn.execute("SELECT last_at FROM alert_memory WHERE key = ?", (key,)).fetchone()
    new = row is None or row[0] < iso_ago(days=days)
    if new or refresh:
        now = now_iso()
        conn.execute(
            "INSERT INTO alert_memory (key, first_at, last_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET last_at = excluded.last_at",
            (key, now, now),
        )
    return new


def write_alert(conn, severity, title, details="", *, kind=None, dedupe_key=None,
                dedupe_days=30, scan_id=None, prev_scan_id=None,
                push=True, force_push=False, repeat=False):
    """Insert an alert and send it on to Home Assistant. Returns False when
    `dedupe_key` was already alerted within `dedupe_days` (repeat=True: counted
    from the last alert written, see is_new's refresh).

    The dedupe record and the alert are committed together, before the push: a
    failed insert cannot leave the key marked as alerted, and no write lock is
    held while Home Assistant is slow to answer."""
    if not conn.in_transaction:             # autocommit connections (watcher) need their own BEGIN
        conn.execute("BEGIN IMMEDIATE")
    try:
        if dedupe_key and not is_new(conn, dedupe_key, dedupe_days, refresh=not repeat):
            conn.commit()
            return False
        conn.execute(
            "INSERT INTO alerts (created_at, scan_id, prev_scan_id, severity, title, details, kind) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (now_iso(), scan_id, prev_scan_id, severity, title, details, kind),
        )
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        raise
    if push:
        try:
            result = notify(severity, title, details, kind=kind, force=force_push, conn=conn)
            if result is not None:
                kv_set(conn, "notify_last", f"{now_iso()} {result}")
            conn.commit()
        except sqlite3.Error as e:          # the alert is saved; only the outbox/bookkeeping row is lost
            conn.rollback()
            log(f"[!] push bookkeeping for {title!r} failed: {e}")
    return True


def write_info_alert(conn, kind, severity, title, details="", **kw):
    """A quiet (info) alert: it always shows on the dashboard, and is also pushed to every destination
    (past NOTIFY_MIN_SEVERITY) when INFO_PUSH_<KIND> is on in Settings → Alerts. Pass the usual
    write_alert kwargs (dedupe_key, scan_id, ...)."""
    push = setting_on(f"INFO_PUSH_{kind.upper()}")
    kw.pop("push", None)
    kw.pop("force_push", None)
    return write_alert(conn, severity, title, details, kind=kind, push=push, force_push=push, **kw)


def _url_id(url):
    return hashlib.sha256(url.encode()).hexdigest()[:12]      # not the URL: URLs hold tokens


def destinations():
    """{target id: url} of every place alerts go. The id is stored with a queued push: "ha" for
    HA_WEBHOOK_URL (its id since 2026-10-13), "webhook:<hash>" per other WEBHOOK_URLS entry,
    "apprise:<hash>" per NOTIFY_URLS entry."""
    out = {("ha" if u == HA_WEBHOOK_URL else f"webhook:{_url_id(u)}"): u for u in setting("WEBHOOK_URLS").split()}
    out.update({f"apprise:{_url_id(u)}": u for u in setting("NOTIFY_URLS").split()})
    return out


def target_name(target, url=""):
    """How a destination reads in the dashboard and the log: "webhook 192.168.10.88", "ntfy"..."""
    if target == "ha" or target.startswith("webhook:"):
        return f"webhook {urllib.parse.urlsplit(url).hostname or ''}".strip()
    return url.split("://", 1)[0] if "://" in url else "Apprise"


def notify_services():
    return [target_name(t, u) for t, u in destinations().items()]


# Errors no retry can fix: reported (Overview, log), not queued for 48 h.
_NOT_RETRIED = ("not a valid Apprise URL", "Apprise is not installed")


def _send(target, url, payload):
    """Push one payload to one destination; None on success, else the error."""
    return _post_apprise(url, payload) if target.startswith("apprise:") else _post_webhook(url, payload)


def _post_apprise(url, payload):
    """Send one payload through Apprise (imported only here: it is slow to load, and an
    install that only uses Home Assistant never needs it)."""
    try:
        import apprise
    except ImportError:
        return "Apprise is not installed in the image (rebuild it: docker compose build)"
    ap = apprise.Apprise()
    if not ap.add(url):
        return "not a valid Apprise URL"
    kind = {"alert": apprise.NotifyType.FAILURE, "warning": apprise.NotifyType.WARNING}.get(
        payload["severity"], apprise.NotifyType.INFO)
    body = payload["message"] + (f"\n\n{payload['url']}" if payload.get("url") else "")
    try:
        with apprise.LogCapture(level=apprise.logging.WARNING, fmt="%(message)s") as said:
            ok = ap.notify(title=f"LanWard: {payload['title']}"[:250], body=body, notify_type=kind)
    except Exception as e:                  # a plugin bug must not take the alert's caller down
        return f"{e}"[:200]
    return None if ok else ((said.getvalue().strip().splitlines() or ["failed"])[-1])[:200]


def _post_webhook(url, payload):
    """POST one payload as JSON to a webhook; None on success, else the error."""
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(req, timeout=5).read()
        return None
    except Exception as e:
        return f"{e}"[:200]


def push_wanted(severity, force=False):
    """Whether notify() sends an alert of this severity: a push service is configured
    and it is at least NOTIFY_MIN_SEVERITY (or forced)."""
    lowest = (setting("NOTIFY_MIN_SEVERITY") or "warning").lower()
    return bool(destinations()) and (force or SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(lowest, 1))


def notify(severity, title, details="", kind=None, force=False, conn=None):
    """Push an alert to every configured destination (webhooks, Apprise URLs).
    Never raises. Returns None when nothing was sent (not configured, or below
    NOTIFY_MIN_SEVERITY without force), else "ok" or the errors. force=True is used for
    "back online" after an offline notification. With `conn`, a push a service did not
    take goes into notify_outbox for that service and the watcher sends it again
    (flush_outbox)."""
    if not push_wanted(severity, force):
        return None
    payload = {                             # what a webhook receives (README: Alerts out)
        "severity": severity,
        "kind": kind,
        "title": title[:200],
        "message": (details or title)[:1500],
        "time": now_iso(),
        "url": f"{DASHBOARD_URL}/alerts",
    }
    targets = destinations()
    errors = []
    for target, url in targets.items():
        err = _send(target, url, payload)
        if err is None:
            if conn is not None:
                kv_set(conn, f"notify_ok:{target}", now_iso())
            continue
        errors.append(f"{target_name(target, url)}: {err}")
        if conn is not None and not err.startswith(_NOT_RETRIED):
            conn.execute("INSERT INTO notify_outbox (created_at, payload, attempts, last_error, target) "
                         "VALUES (?, ?, 1, ?, ?)", (now_iso(), json.dumps(payload), err, target))
    if conn is not None and len(errors) < len(targets):
        kv_set(conn, "notify_last_ok", now_iso())           # the dashboard's "last sent"
    if not errors:
        return "ok"
    return (("failed, queued: " if conn is not None else "failed: ") + "; ".join(errors))[:200]


OUTBOX_MAX_AGE_H = 48


def flush_outbox(conn):
    """Send queued pushes, oldest first; a service that fails again is left for the next round (it is
    still away), the others go on. The message says it is late. Pushes older than OUTBOX_MAX_AGE_H,
    or for a service no longer in .env, are dropped (they stay on the dashboard's Alerts page).
    Returns (sent, dropped)."""
    sent = dropped = 0
    targets, away = destinations(), set()
    for row in conn.execute("SELECT id, created_at, payload, target FROM notify_outbox ORDER BY id").fetchall():
        target = row["target"] or "ha"          # rows from before 2026-10-27 were all for Home Assistant
        if row["created_at"] < iso_ago(hours=OUTBOX_MAX_AGE_H) or target not in targets:
            conn.execute("DELETE FROM notify_outbox WHERE id = ?", (row["id"],))
            dropped += 1
            continue
        if target in away:
            continue
        payload = json.loads(row["payload"])
        when = row["created_at"][11:16]
        if row["created_at"][:10] != now_iso()[:10]:
            when = f"{when} on {row['created_at'][:10]}"
        payload["message"] = (f"(Delayed: raised at {when}, when it could not be delivered.)\n"
                              + payload.get("message", ""))[:1600]
        err = _send(target, targets[target], payload)
        if err is not None:
            conn.execute("UPDATE notify_outbox SET attempts = attempts + 1, last_error = ? WHERE id = ?",
                         (err, row["id"]))
            away.add(target)
            continue
        conn.execute("DELETE FROM notify_outbox WHERE id = ?", (row["id"],))
        kv_set(conn, f"notify_ok:{target}", now_iso())
        sent += 1
    if sent:
        kv_set(conn, "notify_last_ok", now_iso())
    if sent or dropped:
        log(f"[outbox] sent {sent} delayed push(es), dropped {dropped} older than {OUTBOX_MAX_AGE_H} h")
        kv_set(conn, "notify_last", f"{now_iso()} outbox sent {sent}, dropped {dropped}")
    conn.commit()
    return sent, dropped


def plural(n, word, many=None):
    """'1 firmware update', '6 firmware updates', '2 addresses'."""
    return f"{n} {word if n == 1 else many or word + 's'}"


_PLURAL_MARK = re.compile(r"\((e?s)\)")


def tidy_plural(title):
    """Alerts written before 2026-10-26 say '1 firmware update(s)'; drop or keep the
    ending by the title's leading number."""
    m = re.match(r"\s*(\d+)\b", title or "")
    if not m:
        return _PLURAL_MARK.sub(r"\1", title or "")
    one = m.group(1) == "1"
    return _PLURAL_MARK.sub("" if one else r"\1", title)


def details_dict(raw):
    """An observation's details JSON as a dict: {} when empty, broken or not an object."""
    try:
        d = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return d if isinstance(d, dict) else {}


def own_ip_of(source, ip, details):
    """The device's own address as one observation states it, else None. An ARP request's
    ip is the address it asks for (its own is in details), and a DHCP client sends from
    0.0.0.0 before it has one (the address it asks for is requested_ip)."""
    details = details if isinstance(details, dict) else {}
    if source == "arp_req":
        return details.get("own_ip")
    if source == "dhcp" and (not ip or ip == "0.0.0.0"):
        return details.get("requested_ip")
    return ip if ip and ip != "0.0.0.0" else None


def claimed_ipv4s(conn, since):
    """IPv4 addresses some device has used as its own since `since` (DHCP, ARP, mDNS)."""
    claimed = set()
    for r in conn.execute("SELECT source, ip, details FROM observations WHERE last_seen >= ?", (since,)):
        own = own_ip_of(r["source"], r["ip"], details_dict(r["details"]))
        if own and ":" not in own:
            claimed.add(own)
    return claimed


# ------------------------------------------------------------------ what a device says it is

# Names a whole product line uses ("SonosZP" is every Sonos speaker's DHCP name), so they name no device.
_GENERIC_HOSTNAME = re.compile(r"^(localhost|unknown|android-[0-9a-f]+|esp(32|8266)?[-_]?[0-9a-f]+|espressif|none|"
                               r"sonoszp)$", re.I)
_VENDOR_CLASS_HINT = [("msft", "Windows PC"), ("android-dhcp", "Android device"), ("dhcpcd", "Linux device"),
                      ("udhcp", "embedded Linux device")]


def _useful_name(value):
    v = value.strip() if isinstance(value, str) else ""
    return len(v) >= 3 and re.search(r"[A-Za-z]{2}", v) and not re.fullmatch(r"[0-9a-fA-F:.-]+", v)


_IP_IN_NAME = re.compile(r"\d{1,3}[-._]\d{1,3}[-._]\d{1,3}[-._]\d{1,3}")    # "host-192-168-10-5", "192.168.10.5 - Sonos"


def host_name(value):
    """A name a device gives itself, if it is worth showing: not generic ("localhost",
    "esp32-1a2b3c"), not made of its address ("192-168-10-5.lan"). None otherwise."""
    v = value.strip() if isinstance(value, str) else ""
    if not _useful_name(v) or _GENERIC_HOSTNAME.match(v) or _IP_IN_NAME.search(v):
        return None
    return v[:60]


# Apple's internal board codes as they appear in mDNS TXT records (model=, am=), as people say them.
APPLE_MODELS = {
    "J71bAP": "iPad (6th gen) Wi-Fi", "J72bAP": "iPad (6th gen) Wi-Fi + Cellular",
    "J71sAP": "iPad (5th gen) Wi-Fi", "J72sAP": "iPad (5th gen) Wi-Fi + Cellular", "J42dAP": "Apple TV HD",
    "J305AP": "Apple TV 4K (2nd gen)", "J42AP": "Apple TV HD", "AppleTV5,3": "Apple TV HD",
    "AudioAccessory1,1": "HomePod (1st gen)", "AudioAccessory5,1": "HomePod mini",
    "D16AP": "iPhone 13 mini", "D17AP": "iPhone 13",
    "iPhone14,4": "iPhone 13 mini", "iPhone14,5": "iPhone 13", "iPhone15,2": "iPhone 14 Pro",
    "iPhone15,3": "iPhone 14 Pro Max", "iPhone16,1": "iPhone 15 Pro", "iPhone16,2": "iPhone 15 Pro Max",
    "MacBookPro18,1": "MacBook Pro 16-inch (M1 Pro/Max)", "MacBookPro18,3": "MacBook Pro 14-inch (M1 Pro/Max)",
    "Mac14,7": "MacBook Pro 13-inch (M2)", "iPad13,1": "iPad Air (4th gen) Wi-Fi",
    "iPad14,1": "iPad mini (6th gen) Wi-Fi",
}


# mDNS "md" sometimes carries the platform/OS (webOS, Tizen) rather than a model; map for display and a skip set.
MDNS_OS = {"webos": "webOS", "tizen": "Tizen", "tvos": "tvOS", "ios": "iOS", "ipados": "iPadOS",
           "android": "Android", "roku": "Roku OS", "fireos": "Fire OS"}


def mdns_txt_model(txt):
    """The model string from an mDNS TXT dict (HomeKit/AirPlay `md`, `model`, `am`, `fn`, `product`, `ty`),
    skipping an `md` that is really a platform word like WEBOS (the OS, not the model). None when nothing is
    useful; a non-dict `txt` yields None (2026-10-28)."""
    if not isinstance(txt, dict):
        return None
    for key in ("md", "model", "am", "fn", "product", "ty"):
        value = txt.get(key)
        if key == "md" and isinstance(value, str) and value.strip().lower() in MDNS_OS:
            continue                                    # it is the OS, surfaced on its own, not the model
        if _useful_name(value):
            return value.strip()[:60]
    return None


def name_hint(conn, mac, days=30):
    """A guess at what a device is, from what it announces about itself (2026-10-13): the model in its mDNS TXT
    records (HomeKit/AirPlay/Google Cast `md`, `model`, `am`, `fn`, e.g. "TRADFRI gateway"), else a name it gives
    itself: its DHCP host name ("Galaxy-Tab-S5e"), its mDNS host name ("Alexs-MacBook"), its NetBIOS name
    ("DESKTOP-1A2B3C"); else what the newest scan heard: the UPnP model ("Sonos One") or friendly name, the reverse
    DNS (PTR) name (2026-10-27). Plus the kind of system its DHCP vendor class gives ("MSFT 5.0" = Windows PC). The
    chip vendor from the MAC address (Murata, Intel, Luxshare) rarely says what the device is. None when it says
    nothing useful."""
    mac = (mac or "").lower()
    model = kind = None
    names = {}                                      # source -> its newest useful host name
    for r in conn.execute(
        "SELECT source, hostname, details FROM observations WHERE mac = ? AND source IN ('mdns', 'dhcp', 'netbios') "
        "AND last_seen >= ? ORDER BY last_seen DESC", (mac, iso_ago(days=days))
    ):
        d = details_dict(r["details"])
        if r["source"] not in names and host_name(r["hostname"]):
            names[r["source"]] = host_name(r["hostname"])
        if r["source"] == "mdns" and not model:
            model = mdns_txt_model(d.get("txt"))        # prefers a real model over an `md` platform word
        elif r["source"] == "dhcp":
            vc = d.get("vendor_class") if isinstance(d.get("vendor_class"), str) else ""
            vc = vc.lower()
            if not kind and vc:
                kind = next((label for key, label in _VENDOR_CLASS_HINT if vc.startswith(key)), None)
    if model in APPLE_MODELS:
        model = APPLE_MODELS[model]
    elif model and re.fullmatch(r"[A-Z]\d{1,3}[a-zA-Z]{0,3}AP", model):
        model = f"Apple device (model {model})"       # a board code not in APPLE_MODELS yet
    hint = model or names.get("dhcp") or names.get("mdns") or names.get("netbios")
    is_model = bool(model)
    if not hint:                                    # what the newest scan heard (UPnP, reverse DNS)
        row = conn.execute("SELECT hostname, upnp_info FROM hosts WHERE mac = ? ORDER BY scan_id DESC LIMIT 1",
                           (mac,)).fetchone()
        if row:
            upnp = details_dict(row["upnp_info"])
            ptr = row["hostname"].split(".")[0] if isinstance(row["hostname"], str) else None
            upnp_model = upnp.get("modelName").strip()[:60] if _useful_name(upnp.get("modelName")) else None
            hint, is_model = upnp_model or host_name(upnp.get("friendlyName")) or host_name(ptr), bool(upnp_model)
    # The kind of system goes with a host name ("Galaxy-Tab (Android device)"); a model says more already.
    if kind and hint and not is_model and kind.split()[0].lower() not in hint.lower():
        return f"{hint} ({kind})"
    # the vendor class alone is no name: many gadgets copy Windows' "MSFT 5.0" (the Tapo camera does)
    return hint


# ------------------------------------------------------------------ watched devices

OUTAGE_BLIP_MIN = 2                 # shorter outages are blips: not counted


def uptime(conn, mac, days=30):
    """How a watched device did over the last `days` days, from the outages the watcher recorded:
    {uptime_pct, outages: [{start, end, minutes}], count, longest_min, since}.

    Only time since it is watched (kv watched_since:<mac>, set by the watcher) and since outages
    are recorded at all (kv outages_since) counts; `since` says from when. Outages under
    OUTAGE_BLIP_MIN minutes are left out. `outages` lists each one with its own start, end (None
    while it lasts) and length, oldest first; uptime_pct counts only the part inside the window.
    uptime_pct is None when the device is not watched (no watched time to measure)."""
    mac = (mac or "").lower()
    now = datetime.now()
    starts = [now - timedelta(days=days)]
    for key in ("outages_since", f"watched_since:{mac}"):
        try:
            starts.append(datetime.fromisoformat(kv_get(conn, key)))
        except (TypeError, ValueError):
            if key != "outages_since":
                starts = None               # not watched now
                break
    since = max(starts) if starts else None
    outages, down_min = [], 0.0
    for r in conn.execute("SELECT started_at, ended_at FROM outages WHERE mac = ? "
                          "AND (ended_at IS NULL OR ended_at > ?) ORDER BY started_at",
                          (mac, (since or now - timedelta(days=days)).isoformat(timespec="seconds"))):
        try:
            start = datetime.fromisoformat(r["started_at"])
            end = datetime.fromisoformat(r["ended_at"]) if r["ended_at"] else None
        except ValueError:
            continue
        minutes = ((end or now) - start).total_seconds() / 60
        if minutes < OUTAGE_BLIP_MIN:
            continue
        outages.append({"start": r["started_at"], "end": r["ended_at"], "minutes": int(round(minutes))})
        if since:
            down_min += max(0.0, ((end or now) - max(start, since)).total_seconds() / 60)
    watched_min = (now - since).total_seconds() / 60 if since else 0
    return {
        "uptime_pct": round(max(0.0, 100 * (1 - down_min / watched_min)), 2) if watched_min > 0 else None,
        "outages": outages,
        "count": len(outages),
        "longest_min": max((o["minutes"] for o in outages), default=0),
        "since": since.isoformat(timespec="seconds") if since else None,
    }


# ------------------------------------------------------------------ MACs + vendors

def norm_mac(mac):
    mac = (mac or "").strip().lower().replace("-", ":")
    return mac if MAC_RE.match(mac) else None


def mac_is_randomized(mac):
    """Locally administered bit: a phone/laptop privacy address or a VM."""
    mac = norm_mac(mac) or ""
    try:
        return bool(int(mac.split(":")[0], 16) & 0b10)
    except (ValueError, AttributeError, IndexError):
        return False


def mac_is_device(mac):
    """A unicast MAC that belongs to a device (not multicast/broadcast/zero)."""
    mac = norm_mac(mac)
    if not mac or mac == "00:00:00:00:00:00":
        return False
    return not int(mac.split(":")[0], 16) & 0b1


_VENDORS = None


def _load_vendors():
    """IEEE oui.csv in the data dir if present (nicer names), else nmap's
    nmap-mac-prefixes, which ships with the image and stays current."""
    table = {}
    nmap_db = Path("/usr/share/nmap/nmap-mac-prefixes")
    if nmap_db.exists():
        for line in nmap_db.read_text(errors="replace").splitlines():
            if line and not line.startswith("#"):
                prefix, _, name = line.partition(" ")
                if name:
                    table[prefix.upper()] = name.strip()[:80]
    ieee = DATA_DIR / "oui.csv"
    if ieee.exists():
        for line in ieee.read_text(errors="replace").splitlines():
            parts = line.split(",", 3)
            if len(parts) >= 3 and re.match(r"^[0-9A-F]{6}$", parts[1].strip().upper()):
                table[parts[1].strip().upper()] = parts[2].strip().strip('"')[:80]
    return table


def vendor_for(mac):
    global _VENDORS
    mac = norm_mac(mac)
    if not mac:
        return None
    if _VENDORS is None:
        _VENDORS = _load_vendors()
    hexmac = mac.replace(":", "").upper()
    for n in (9, 7, 6):                    # nmap lists some MA-S / MA-M blocks
        if hexmac[:n] in _VENDORS:
            return _VENDORS[hexmac[:n]]
    return None


# ------------------------------------------------------------------ HTTP

USER_AGENT = "LanWard (home network inventory)"


def http_get(ip, port, tls=False, path="/", timeout=4, method="GET",
             body=None, headers=None, limit=65536):
    """One HTTP(S) request without certificate checks (home devices use
    self-signed certs). Returns (status, {header: value}, text); status is
    None when the device did not answer."""
    import http.client
    import ssl
    conn = None
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:                                # old embedded web servers
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except (ValueError, ssl.SSLError):
                pass
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request(method, path, body=body,
                     headers={"User-Agent": USER_AGENT, "Connection": "close", **(headers or {})})
        resp = conn.getresponse()
        data = resp.read(limit)
        return (resp.status, {k.lower(): v for k, v in resp.getheaders()},
                data.decode("utf-8", errors="replace"))
    except Exception:
        return None, {}, ""
    finally:
        if conn is not None:
            conn.close()


def http_json(ip, port, path, timeout=4):
    status, _, text = http_get(ip, port, path=path, timeout=timeout)
    if status != 200:
        return status, None
    try:
        return status, json.loads(text)
    except ValueError:
        return status, None


# ------------------------------------------------------------------ local network

def own_mac(iface=IFACE):
    try:
        return norm_mac(Path(f"/sys/class/net/{iface}/address").read_text())
    except OSError:
        return None


def own_listening_ports():
    """The TCP ports this machine listens on for the network, from /proc/net/tcp and tcp6: exact, without a scan.
    The container shares the host's network, so these are the host's, other containers' published ports included.
    Ports open only on loopback or a Docker bridge address are left out. None where /proc has no such list."""
    me = own_ip()
    wanted = {"tcp": {"00000000"} | ({socket.inet_aton(me)[::-1].hex().upper()} if me else set()),
              "tcp6": {"0" * 32}}
    ports, found = set(), False
    for name, addrs in wanted.items():
        try:
            lines = Path(f"/proc/net/{name}").read_text().splitlines()[1:]
        except OSError:
            continue
        found = True
        for line in lines:
            parts = line.split()
            if len(parts) > 3 and parts[3] == "0A":         # 0A: listening
                addr, port = parts[1].rsplit(":", 1)
                if addr in addrs:
                    ports.add(int(port, 16))
    return sorted(ports) if found else None


# What the services devices announce over mDNS are, in plain words (Traffic, and new-port alerts via portid.py)
MDNS_SERVICE_NAMES = {
    "_airplay._tcp": "AirPlay", "_raop._tcp": "AirPlay audio", "_googlecast._tcp": "Chromecast",
    "_spotify-connect._tcp": "Spotify Connect", "_sonos._tcp": "Sonos",
    "_hap._tcp": "HomeKit accessory", "_hap._udp": "HomeKit accessory (Thread)", "_homekit._tcp": "HomeKit",
    "_companion-link._tcp": "Apple Companion Link", "_sleep-proxy._udp": "Apple sleep proxy",
    "_device-info._tcp": "Device model info", "_home-assistant._tcp": "Home Assistant",
    "_esphomelib._tcp": "ESPHome", "_shelly._tcp": "Shelly", "_hue._tcp": "Philips Hue bridge",
    "_matter._tcp": "Matter device", "_matterc._udp": "Matter device ready to pair",
    "_meshcop._udp": "Thread border router", "_trel._udp": "Thread radio link", "_mqtt._tcp": "MQTT broker",
    "_http._tcp": "Web page", "_https._tcp": "Web page (HTTPS)", "_ssh._tcp": "SSH login",
    "_sftp-ssh._tcp": "SFTP file transfer", "_smb._tcp": "File sharing (SMB)",
    "_afpovertcp._tcp": "File sharing (AFP)", "_adisk._tcp": "Time Machine disk", "_rfb._tcp": "Screen sharing (VNC)",
    "_ipp._tcp": "Printer (IPP)", "_ipps._tcp": "Printer (IPP over TLS)", "_printer._tcp": "Printer (LPD)",
    "_pdl-datastream._tcp": "Printer (raw)", "_uscan._tcp": "Scanner", "_workstation._tcp": "Computer",
}


# Ports from here up are the ones operating systems hand out for a while (phones and computers open and close
# them as apps run): a new one there is a note on the dashboard, not a push.
EPHEMERAL_PORT = 49152

# Well-known ports, named in plain words so an alert reads "7000 (AirPlay)" instead of a bare number. Only
# common, home-relevant services; an unknown port stays a bare number. Descriptive, not a safety verdict.
KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "email (SMTP)", 53: "DNS", 67: "DHCP", 80: "web",
    110: "email (POP3)", 123: "time (NTP)", 137: "Windows networking", 139: "Windows sharing",
    143: "email (IMAP)", 161: "SNMP", 443: "secure web", 445: "Windows/SMB sharing", 515: "printing",
    548: "Apple file sharing", 554: "camera stream (RTSP)", 631: "printing (IPP)", 1883: "smart home (MQTT)",
    1900: "UPnP discovery (SSDP)", 3689: "AirPlay / iTunes", 5000: "UPnP", 5060: "VoIP (SIP)",
    5353: "device discovery (mDNS)", 7000: "AirPlay", 7100: "AirPlay", 8008: "Chromecast", 8009: "Chromecast",
    8060: "Roku", 8080: "web", 8443: "secure web", 9100: "printing", 32469: "Plex media",
    51827: "HomeKit", 62078: "iPhone Wi-Fi sync",
    # 2026-11-02, for "What's running": the system's own names for these read as jargon ("ms-wbt-server")
    111: "RPC port directory", 502: "energy readings (Modbus)", 1400: "Sonos", 2049: "NFS file sharing",
    3306: "MySQL database", 3389: "Windows remote desktop", 3493: "UPS monitoring (NUT)", 5432: "PostgreSQL database",
    5900: "screen sharing (VNC)", 6379: "Redis database", 8123: "Home Assistant", 27017: "MongoDB database",
}


def port_label(port):
    """A plain-words service name for a well-known home port ('AirPlay' for 7000). Falls back to the standard
    service name the operating system knows from /etc/services (no network), so a user's less common equipment
    still gets a name; None if neither knows it. KNOWN_PORTS wins so the common home services read in plain words."""
    if port in KNOWN_PORTS:
        return KNOWN_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp")
    except (OSError, OverflowError, TypeError):
        return None
BASELINE_HOURS = 1      # what a device opens in the hour after its first full check is still its baseline
MOVING_PORT = 32768     # from here up a service can be handed a random port each time it starts (Linux's range)
MOVED_DAYS = 7          # a random port that closed this recently can have moved to a new number


def record_open_ports(conn, mac, ports, full):
    """Note what a check found open on `mac` (`full`: every port was checked) and return the ports it never had
    open before. Nothing is new until BASELINE_HOURS after the device's first full check: what it opens until then
    is its baseline (services still starting: the watcher's first read came before LanWard's own dashboard was
    listening, 2026-10-27).

    Moved, not new (2026-11-02): NFS's helpers next to rpcbind, or a Home Assistant integration's callback server,
    get a random port from MOVING_PORT up each time they start. After a restart (Proxmox host and HA VM, 1 Nov) the
    old numbers close and as many new ones open, which is not a new service. So new ports from MOVING_PORT up are
    not returned when the device had at least as many there that closed in the last MOVED_DAYS days; those closed
    numbers are marked as moved (moved_to; the new ones get moved_from), so they cannot excuse a port twice and the
    device's page can say where they went. More new ones than closed: all are returned."""
    now = now_iso()
    row = conn.execute("SELECT first_full_at FROM port_checks WHERE mac = ?", (mac,)).fetchone()
    seen = {r[0]: r for r in conn.execute("SELECT port, last_seen, moved_to FROM open_ports_seen WHERE mac = ?", (mac,))}
    new = sorted(set(ports) - set(seen)) if row and row[0] and row[0] <= iso_ago(hours=BASELINE_HOURS) else []
    moved_in, closed = [p for p in new if p >= MOVING_PORT], []
    if moved_in:
        recent = iso_ago(days=MOVED_DAYS)
        closed = sorted(p for p, r in seen.items() if p >= MOVING_PORT and p not in ports and not r[2]
                        and (r[1] or "") >= recent)
        if len(moved_in) <= len(closed):
            new = [p for p in new if p < MOVING_PORT]
            log(f"[*] {mac}: {len(moved_in)} random port(s) moved after a restart "
                f"({', '.join(map(str, closed))} -> {', '.join(map(str, moved_in))}), not new")
        else:
            moved_in = []
    conn.executemany("INSERT INTO open_ports_seen (mac, port, first_seen, last_seen) VALUES (?, ?, ?, ?) "
                     "ON CONFLICT(mac, port) DO UPDATE SET last_seen = excluded.last_seen",
                     [(mac, p, now, now) for p in ports])
    if moved_in:
        conn.executemany("UPDATE open_ports_seen SET moved_to = ? WHERE mac = ? AND port = ?",
                         [(",".join(map(str, moved_in)), mac, p) for p in closed])
        conn.executemany("UPDATE open_ports_seen SET moved_from = ? WHERE mac = ? AND port = ?",
                         [(",".join(map(str, closed)), mac, p) for p in moved_in])
    if full:
        conn.execute("INSERT INTO port_checks (mac, full_checked_at, full_tried_at, first_full_at) VALUES (?, ?, ?, ?) "
                     "ON CONFLICT(mac) DO UPDATE SET full_checked_at = excluded.full_checked_at, "
                     "full_tried_at = excluded.full_tried_at, "
                     "first_full_at = COALESCE(port_checks.first_full_at, excluded.first_full_at)", (mac, now, now, now))
    return new


def full_check_due(conn, macs, scans_per_day):
    """The MACs whose turn it is for a check of every port: those checked (or tried) longest ago, and enough of
    them that each device gets one every FULL_PORT_CHECK_DAYS days at this many scans a day. A device checked in
    the last half of that period waits."""
    raw = setting("FULL_PORT_CHECK_DAYS").strip()
    days = int(raw) if raw.isdigit() else 1
    if days <= 0 or not macs:
        return []
    last = {r[0]: max(r[1] or "", r[2] or "") for r in conn.execute(
        "SELECT mac, full_checked_at, full_tried_at FROM port_checks")}
    fresh = iso_ago(hours=days * 12)
    stale = sorted((last.get(m, ""), m) for m in macs if last.get(m, "") < fresh)
    quota = math.ceil(len(macs) / (days * max(1, scans_per_day)))
    return [m for _, m in stale[:quota]]


def mark_full_tried(conn, macs):
    now = now_iso()
    conn.executemany("INSERT INTO port_checks (mac, full_tried_at) VALUES (?, ?) "
                     "ON CONFLICT(mac) DO UPDATE SET full_tried_at = excluded.full_tried_at", [(m, now) for m in macs])


def internet_exposure(conn, ip, ports):
    """Whether the router opened `ports` of `ip` to the internet by UPnP, in a sentence, from what the last home
    checks read off the router (homechecks.py stores router_upnp); None when that is unknown or over 2 days old.
    A forward set up by hand on the router is not visible to LanWard, and the sentence says so."""
    try:
        state = json.loads(kv_get(conn, "router_upnp") or "null")
    except ValueError:
        return None
    if not isinstance(state, dict) or (state.get("at") or "") < iso_ago(days=2):
        return None
    by_hand = "Only a forward set up by hand on the router could open it."
    if state.get("state") == "off":
        return f"Not by UPnP: your router doesn't let devices open ports themselves. {by_hand}"
    hits = [f for f in state.get("forwards") or [] if f[0] == ip and f[1] in set(ports)]
    if hits:
        return ("Yes: your router forwards " + ", ".join(f"{f[1]} (outside port {f[2]})" for f in hits)
                + " to the internet, opened by the device itself through UPnP.")
    if state.get("complete"):
        return f"Not by UPnP: your router has no UPnP forward to it. {by_hand}"
    return None


def alert_new_ports(conn, mac, name, ip, ports, titles=None, scan_id=None, ids=None):
    """One alert for ports a device never had open before (record_open_ports): a warning, pushed, unless all of
    them are at EPHEMERAL_PORT or up, which phones and computers open and close as apps run (info then). Each port
    says what it is and how LanWard knows (`ids`, portid.identify; else the web page's title or the usual service
    for that number), then whether the router opened it to the internet, then why this is usually nothing
    (2026-10-29; what it is and the internet, 2026-11-02)."""
    titles, ids = titles or {}, ids or {}
    all_ephemeral = all(p >= EPHEMERAL_PORT for p in ports)
    severity = "info" if all_ephemeral else "warning"

    def line(p):
        found = ids.get(p)
        if found:
            what = found["what"] if found.get("sure") else f"probably {found['what']}"
            return f"- {p}: {what}, from {found['how']}" if found.get("sure") else f"- {p}: {what} ({found['how']})"
        if titles.get(p):
            return f'- {p}: a web page, "{titles[p]}"'
        label = port_label(p)
        if label:
            return f"- {p}: probably {label} (the usual service on that port number)"
        return f"- {p}: not identified: it didn't answer LanWard's questions, and {name} doesn't announce it"

    sure = {p: f["what"] for p, f in ids.items() if f.get("sure") and p in ports}
    if len(ports) == 1:
        short = sure.get(ports[0]) if len(sure.get(ports[0]) or "") <= 40 else None
        title = f"New open port on {name}: {ports[0]}" + (f" ({short})" if short else "")
    else:
        title = f"{len(ports)} new open ports on {name}"
        if len(sure) == len(ports) and len(set(sure.values())) == 1 and len(sure[ports[0]]) <= 40:
            title += f" ({sure[ports[0]]})"
    if all_ephemeral:
        why = ("These are temporary high-numbered ports that phones, computers and smart-TVs open and close by "
               "themselves as background apps run — they change all the time, so this is almost always nothing. "
               "Worth a look only if this is a device that should never run any services.")
    else:
        why = ("Devices often start listening on service ports when they wake up or you use a feature on them — "
               "casting or AirPlay, screen- or file-sharing, a media, remote-control or smart-home app, or a "
               f"service you just set up. If someone was using {name} around then, this is expected. Take a "
               "closer look only if you don't recognise the device or nobody was using it.")
    exposure = internet_exposure(conn, ip, ports) if ip else None
    detail = (f"{name} ({ip or 'address not known'}) listens on "
              f"{'a port' if len(ports) == 1 else 'ports'} it never had open before:\n"
              + "\n".join(line(p) for p in ports)
              + (f"\n\nOpen to the internet? {exposure}" if exposure else "") + "\n\n" + why)
    return write_alert(conn, severity, title, detail, kind="new_port",
                       dedupe_key=f"new-port:{mac}:{','.join(map(str, ports))}", scan_id=scan_id)


def own_ip(iface=IFACE):
    inet = _iface_inet(iface)
    return inet.split("/")[0] if inet else None


def default_gateway():
    try:
        out = subprocess.run(["ip", "-4", "route", "show", "default"],
                             capture_output=True, text=True, timeout=3).stdout
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def api_key(conn, new=False):
    """The read-only API key (kv api_key), made on first use; new=True replaces it, which stops the old one."""
    key = None if new else kv_get(conn, "api_key")
    if not key:
        key = "ns_" + secrets.token_urlsafe(24)
        kv_set(conn, "api_key", key)
        conn.commit()
    return key


def send_test(conn=None):
    """A test alert to every destination: [(name, None or the error)]. With `conn`, a success
    counts as that destination's last delivery (the Settings page shows it)."""
    payload = {"severity": "info", "kind": "test", "title": "Test alert", "time": now_iso(),
               "message": "If you can read this, LanWard's alerts reach you here.", "url": f"{DASHBOARD_URL}/"}
    out = []
    for target, url in destinations().items():
        err = _send(target, url, payload)
        if err is None and conn is not None:
            kv_set(conn, f"notify_ok:{target}", now_iso())
        out.append((target_name(target, url), err))
    return out


def test_push():
    """`python3 common.py test-push` (in Docker: docker exec lanward python3 common.py test-push)."""
    results = send_test()
    if not results:
        print("Alerts go nowhere yet: add a webhook or a phone push on the Settings page "
              "(or WEBHOOK_URLS / NOTIFY_URLS in .env)")
        return 1
    for name, err in results:
        print(f"{name:16} {'sent' if err is None else 'FAILED: ' + err}")
    return 1 if any(err for _, err in results) else 0


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["test-push"]:
        sys.exit(test_push())
    if sys.argv[1:] in (["api-key"], ["api-key", "--new"]):
        c = connect()
        migrate(c)
        print(api_key(c, new=sys.argv[2:] == ["--new"]))
        sys.exit(0)
    print("Usage: python3 common.py test-push | api-key [--new]")
    sys.exit(2)
