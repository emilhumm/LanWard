#!/usr/bin/env python3
"""LanWard dashboard: home-network security at a glance, served from scanner.db."""
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import math
import os
import re
import secrets
import signal
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, redirect, url_for, abort, Response, g, session,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import common  # noqa: E402



DEFAULT_PASSWORD = "lanward"            # a fresh install logs in with this, then you change it in Settings


def _configured_password():
    """(password, is_default, env_off) for the login. DASHBOARD_PASSWORD in .env wins: "off" turns login
    off entirely; any other value is the password. Unset (the normal case) → the known default, so a
    fresh install is reachable without digging in logs but still asks for a password."""
    pw = os.environ.get("DASHBOARD_PASSWORD", "").strip()
    if pw.lower() == "off":
        return "", False, True
    if pw:
        return pw, False, False
    return DEFAULT_PASSWORD, True, False


AUTH_PASSWORD, PW_IS_DEFAULT, AUTH_OFF_ENV = _configured_password()
OWN_IP = common.own_ip()


def _session_secret():
    """A stable key for signing the login cookie, kept in the data folder so sessions survive a restart."""
    kept = common.DATA_DIR / "session-secret.txt"
    try:
        secret = kept.read_text().strip()
    except OSError:
        secret = ""
    if not secret:
        secret = secrets.token_urlsafe(32)
        try:
            common.DATA_DIR.mkdir(parents=True, exist_ok=True)
            kept.write_text(secret + "\n")
            kept.chmod(0o600)
        except OSError:
            pass            # read-only data dir (e.g. tests): a per-process key still signs this run's cookies
    return secret


def status_allow():
    """Who may read the API without the key: this host (loopback, its own address) and STATUS_ALLOW
    from the Settings page or .env, e.g. Home Assistant's address for a REST sensor (2026-10-13)."""
    listed = {a for a in re.split(r"[\s,]+", common.setting("STATUS_ALLOW")) if a}
    return listed | {"127.0.0.1"} | ({OWN_IP} if OWN_IP else set())


def _hash_password(pw, salt=None, rounds=200_000):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), rounds).hex()
    return f"pbkdf2_sha256${rounds}${salt}${digest}"


_PASSWORDS_OK = set()           # (stored hash, sha256 of a password that matched it): checked once


def _password_ok(given, stored):
    """The password set on the Settings page (`stored`, a PBKDF2 hash in kv dashboard_password) if
    there is one, else .env's or the generated one. Every page and file asks again, so a match is
    remembered rather than hashed 200,000 rounds each time."""
    if not stored:
        return bool(AUTH_PASSWORD) and hmac.compare_digest(given.encode(), AUTH_PASSWORD.encode())
    seen = (stored, hashlib.sha256(given.encode()).hexdigest())
    if seen in _PASSWORDS_OK:
        return True
    try:
        _, rounds, salt, digest = stored.split("$")
        ok = hmac.compare_digest(_hash_password(given, salt, int(rounds)).rsplit("$", 1)[1], digest)
    except ValueError:
        ok = False
    if ok:
        _PASSWORDS_OK.add(seen)
    return ok
MAC_PATH_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
SEV_RANK = common.SEVERITY_RANK

app = Flask(__name__)
app.secret_key = _session_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),      # the cookie's own life; idle logout is enforced below
)
_scan_proc = None           # last scan started from the web UI (reaped in is_scan_running)

# Paths reachable without logging in: the login page itself, the health probe, and static files.
_OPEN_PATHS = {"/login", "/logout", "/healthz"}


def auth_off():
    """True when no login is asked for: DASHBOARD_PASSWORD=off in .env, or the Settings tickbox turned
    it off (a password may still be stored; the tickbox decides whether it is enforced)."""
    if AUTH_OFF_ENV:
        return True
    conn = get_db()
    required = common.kv_get(conn, "require_password")
    conn.close()
    return required == "off"


def _idle_limit():
    """Seconds a session may sit idle before it is logged out, or 0 for "stay logged in"."""
    try:
        return max(0, int(common.setting("AUTO_LOGOUT_MINUTES"))) * 60
    except (TypeError, ValueError):
        return 0


# ────────────────────────────────────────────  login

@app.before_request
def same_origin_posts():
    """Every POST must come from a LanWard page. The login cookie rides along with any request to this
    host, so without this a web page elsewhere could press "This is my new router" (and silence the
    impostor alarm) or rename devices. Browsers send Origin on POSTs; Referer is the fallback. Behind a
    reverse proxy (nginx) the page's host may arrive as X-Forwarded-Host, a header a cross-site form
    cannot set."""
    if request.method != "POST":
        return
    source = request.headers.get("Origin") or request.headers.get("Referer") or ""
    hosts = {request.host, request.headers.get("X-Forwarded-Host", "").split(",")[0].strip()} - {""}
    if urlparse(source).netloc not in hosts:
        return Response("Forms only work from LanWard's own pages.", 403)


@app.before_request
def require_auth():
    if request.path in _OPEN_PATHS or (request.endpoint == "static"):
        return
    if auth_off():
        return
    if request.path.startswith("/api/") and request.method == "GET":
        # The read-only API: the API key as a bearer token, or an address in STATUS_ALLOW (2026-10-27);
        # a browser logged in to the dashboard (the session cookie, below) may read it too.
        if request.remote_addr in status_allow():
            return
        bearer = request.headers.get("Authorization", "")
        if bearer[:7].lower() == "bearer " and hmac.compare_digest(bearer[7:].strip().encode(), api_key().encode()):
            return
    if _session_live():
        return
    if request.path.startswith("/api/"):            # machines want a plain 401, not an HTML login page
        return Response("Auth required", 401)
    return redirect(url_for("login", next=request.full_path if request.method == "GET" else None))


def _session_live():
    """True if this request carries a valid, not-timed-out login cookie. The scan-status page reloads
    itself every 5 s; that poll must not keep a walked-away session alive, so it does not count as
    activity for the idle clock."""
    if not session.get("authed"):
        return False
    limit = _idle_limit()
    if limit:
        seen = session.get("seen", 0)
        if time.time() - seen > limit:
            session.clear()
            return False
    if request.endpoint != "scan_status":
        session["seen"] = time.time()
    return True


@app.route("/login", methods=["GET", "POST"])
def login():
    if auth_off():                                  # login is turned off: nothing to sign in to
        return redirect(url_for("home"))
    conn = get_db()
    stored = common.kv_get(conn, "dashboard_password")
    conn.close()
    nxt = request.values.get("next") or ""
    parsed = urlparse(nxt)              # only a path on this site, never an open redirect to another host
    if parsed.scheme or parsed.netloc or "\\" in nxt or not nxt.startswith("/") or nxt.startswith("//"):
        nxt = url_for("home")
    if session.get("authed"):
        return redirect(nxt)
    error = None
    if request.method == "POST":
        if _password_ok(request.form.get("password", ""), stored):
            session.clear()
            session.permanent = True
            session["authed"] = True
            session["seen"] = time.time()
            return redirect(nxt)
        error = "That password didn't match. Try again."
    return render_template("login.html", error=error, next=nxt, default_password=DEFAULT_PASSWORD,
                           is_default=bool(PW_IS_DEFAULT and not stored)), (401 if error else 200)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.context_processor
def _asset_version():
    """A cache-busting token for the CSS/JS: the newest mtime across every stylesheet and script, so a
    deploy's assets are fetched fresh instead of a stale browser copy (links had no version, 2026-10-29)."""
    static = Path(app.static_folder)
    try:
        files = list(static.glob("*.css")) + list(static.glob("*.js"))
        return {"asset_v": int(max((f.stat().st_mtime for f in files), default=0))}
    except OSError:
        return {"asset_v": 0}


@app.context_processor
def _auth_context():
    """For the header: whether a login is in force (so we show Log out) and whether the dashboard is
    still on the built-in default password (so we show the "change it" banner)."""
    conn = get_db()
    stored = common.kv_get(conn, "dashboard_password")
    required = common.kv_get(conn, "require_password")
    conn.close()
    login_on = not AUTH_OFF_ENV and required != "off"
    return {"login_on": login_on,
            "on_default_password": bool(login_on and PW_IS_DEFAULT and not stored)}


# ────────────────────────────────────────────  helpers

def api_key(new=False):
    conn = get_db()
    key = common.api_key(conn, new)
    conn.close()
    return key


def get_db():
    conn = common.connect()
    if not getattr(app, "_migrated", False):
        common.migrate(conn)
        app._migrated = True
    g.setdefault("_conns", []).append(conn)          # closed after the request, also when a page fails
    return conn


@app.teardown_appcontext
def _close_dbs(exc):
    for conn in g.pop("_conns", []):
        conn.close()


def _labels_map():
    """Per-request cache of {mac: {label, note, watch}} from host_labels."""
    if not hasattr(g, "_labels_map"):
        conn = get_db()
        g._labels_map = {
            row["mac"].lower(): {"label": row["label"], "note": row["note"] or "",
                                 "watch": bool(row["watch_offline"])}
            for row in conn.execute("SELECT mac, label, note, watch_offline FROM host_labels")
            if row["mac"]
        }
        conn.close()
    return g._labels_map


# iphone/ipad also inside names like "AlexsiPhone"; the generic words only as whole words.
PHONE_NAME_RE = re.compile(r"iphone|ipad|\b(android|galaxy|pixel|phone|tablet)\b")
MEDIA_NAME_RE = re.compile(r"apple-?tv|homepod|chromecast|\bsonos")
SERVER_PORTS = ("home-assistant", "proxmox", "frigate", "docker-api", "plex")


def classify(vendor, ports, hostname=None, label=None):
    """One category per device, from maker, open ports and names. Your label counts as a
    name: private MAC addresses carry no maker, so "Kims Ipad" is what says it is a tablet."""
    v, p = (vendor or "").lower(), (ports or "").lower()
    port_set = set(p.split(","))
    n = " ".join(x for x in (label, hostname) if x).lower()
    if "rtsp" in p or any(x in v for x in ["hikvision", "dahua", "reolink", "axis comm"]):
        return "camera"
    if PHONE_NAME_RE.search(n):
        return "phone"
    if port_set & set(SERVER_PORTS):
        return "server"
    if MEDIA_NAME_RE.search(n):
        return "media"
    if any(x in n for x in ["shelly", "tradfri", "ikea", "zigbee", "tasmota", "esphome"]) or "esphome" in port_set or \
            any(x in v for x in ["espressif", "shelly", "tuya", "irobot", "allterco", "signify", "philips lighting"]):
        return "iot"
    if port_set & {"printer", "ipp"} or v in ("hp", "hp inc.") or \
            any(x in v for x in ["xerox", "brother", "hewlett", "hp ", "canon", "epson", "zebra"]):
        return "printer"
    if any(x in v for x in ["sonos", "lg innotek", "lg electronics", "samsung", "roku",
                            "nintendo", "sony", "google", "amazon"]):
        return "media"
    if "proxmox" in v or "proxmox" in p:
        return "server"
    if any(x in v for x in ["tp-link", "asustek", "netgear", "ubiquiti", "mikrotik", "cisco",
                            "zyxel", "d-link", "aruba", "fortinet", "eks elektronik"]):
        return "network"
    if "rdp" in p or any(x in v for x in ["intel", "dell", "lenovo", "micro-star", "apple",
                                           "microsoft", "lcfc"]):
        return "computer"
    return "other"


def parse_json(raw, default=None):
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return default


def decorate(row):
    d = dict(row)
    mac = (d.get("mac") or "").lower()
    rec = _labels_map().get(mac) if mac else None
    d["label"] = rec["label"] if rec else None
    d["label_note"] = rec["note"] if rec else ""
    d["label_watch"] = rec["watch"] if rec else False
    d["category"] = classify(d.get("vendor"), d.get("ports"), d.get("hostname"), d["label"])
    parsed_findings = parse_json(d.get("findings"), [])
    d["findings_list"] = [f for f in parsed_findings if isinstance(f, dict)] if isinstance(parsed_findings, list) else []
    # NULL open_ports: nmap did not finish this device's port check (scan.py), unknown rather than none open
    d["ports_unknown"] = d.get("scan_id") is not None and "open_ports" in d and d["open_ports"] is None
    p = (d.get("ports") or "").lower()
    d["risky"] = any(f["severity"] != "info" for f in d["findings_list"]) or "telnet" in p
    u = parse_json(d.get("upnp_info"), {})
    u = u if isinstance(u, dict) else {}
    cn = d.get("tls_cert_cn")
    if cn and not cn.strip("*. "):          # a bare wildcard certificate ("*") names nothing
        cn = None
    d["identity"] = (cn or u.get("friendlyName") or u.get("modelName")
                     or d.get("http_title") or d.get("http_server") or d.get("ssh_banner") or None)
    # Each open port as a chip (2026-10-27): its number and the title of the web page it shows (a link to it), else
    # its name without the number some names carry ("http-5111": "http"; a bare number: no name)
    web = parse_json(d.get("web_info"), {})
    web = web if isinstance(web, dict) else {}
    labels = (d.get("ports") or "").split(",") if d.get("ports") else []
    d["port_chips"] = []
    open_ports = parse_json(d.get("open_ports"), [])
    open_ports = open_ports if isinstance(open_ports, list) else []
    for i, port in enumerate(open_ports):
        page = web.get(str(port)) or {}
        shows = bool(page) and (page.get("status") or 500) < 400       # not "401 Authorization Required"
        label = labels[i] if i < len(labels) else str(port)
        title = page.get("title") if shows else None
        name = title or label.removesuffix(f"-{port}")
        d["port_chips"].append({
            "port": port, "label": label, "name": None if name == str(port) else name,
            "title": title,
            "url": f"{'https' if page.get('tls') else 'http'}://{d.get('ip')}:{port}/" if page else None})
    return d


def get_scan_hosts(conn, scan_id):
    return conn.execute("SELECT * FROM hosts WHERE scan_id = ? ORDER BY ip", (scan_id,)).fetchall()


def _ip_sort_key(ip):
    try:
        return tuple(int(p) for p in (ip or "").split("."))
    except (ValueError, AttributeError):
        return (1 << 30,)


@app.template_filter("sort_ip")
def jinja_sort_ip(rows):
    return sorted(rows or [], key=lambda r: _ip_sort_key(r.get("ip") if hasattr(r, "get") else r["ip"]))


@app.template_filter("when")
def jinja_when(ts):
    return (ts or "").replace("T", " ")


app.template_filter("tidy")(common.tidy_plural)


@app.template_filter("short_when")
def jinja_short_when(ts):
    """When, the Overview's way: "Today 13:05", "Mon 22:24" within the week, else "21 Oct 00:03"."""
    return _when(ts, datetime.now()) if ts else ""


def _scan_started(scan_id):
    """When a scan began, for naming it by its time; cached for the request (preload with _preload_scans)."""
    cache = g.setdefault("scan_started", {})
    if scan_id not in cache:
        conn = get_db()
        row = conn.execute("SELECT started_at FROM scans WHERE id = ?", (scan_id,)).fetchone()
        conn.close()
        cache[scan_id] = row[0] if row else None
    return cache[scan_id]


def _preload_scans(conn, ids):
    cache = g.setdefault("scan_started", {})
    ids = [i for i in set(ids) if i and i not in cache]
    for i in range(0, len(ids), 500):
        part = ids[i:i + 500]
        cache.update({r[0]: r[1] for r in conn.execute(
            f"SELECT id, started_at FROM scans WHERE id IN ({','.join('?' * len(part))})", part)})


@app.template_filter("scan_name")
def jinja_scan_name(value):
    """A scan by its time instead of its number (2026-10-27): "today's 17:22 scan", "yesterday's 20:00 scan",
    "Monday's 22:24 scan" within the week, else "the 21 Oct 00:03 scan". Takes a start time or a scan's id."""
    t = _parse_ts(_scan_started(value) if isinstance(value, int) else value)
    if not t:
        return "an older scan"
    days, hm = (datetime.now().date() - t.date()).days, t.strftime("%H:%M")
    return (f"today's {hm} scan" if days == 0 else f"yesterday's {hm} scan" if days == 1
            else f"{t:%A}'s {hm} scan" if days < 7 else f"the {t:%d %b} {hm} scan" if days < 300
            else f"the {t:%d %b %Y} {hm} scan")


@app.template_filter("scan_time")
def jinja_scan_time(ts):
    """Scan start times, all in one format."""
    t = _parse_ts(ts)
    return t.strftime("%Y-%m-%d %H:%M") if t else (ts or "")


# LanWard's own glyphs (2026-11-01, picked on the canvas: "Signature"), one per kind of device (classify()) for the
# Devices, Network and Traffic pages: solid shapes with cut-outs, filled in currentColor with fill-rule evenodd
# (_icons.html cat_icon). Controls and the alerts timeline's kinds below stay thin line icons.
CAT_ICONS = {
    "network": "M6.68 9.27A6.5 6.5 0 0 1 17.32 9.27L15.69 10.42A4.5 4.5 0 0 0 8.31 10.42zM3.4 6.98A10.5 10.5 0 0 1 20.6 "
               "6.98L18.96 8.12A8.5 8.5 0 0 0 5.04 8.12zM6.5 14h11a2.5 2.5 0 0 1 0 5h-11a2.5 2.5 0 0 1 0-5zM12 15.5a1 1 0 1 0 0 "
               "2a1 1 0 1 0 0-2z",
    "server": "M5 3h14a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2zM5 13h14a2 2 0 0 1 2 2v4a2 2 0 0 1-2 "
              "2H5a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2zM7 5.8a1.2 1.2 0 1 0 0 2.4a1.2 1.2 0 1 0 0-2.4zM7 15.8a1.2 1.2 0 1 0 0 "
              "2.4a1.2 1.2 0 1 0 0-2.4zM11.75 6.25h5.5a.75.75 0 0 1 0 1.5h-5.5a.75.75 0 0 1 0-1.5zM11.75 16.25h5.5a.75.75 0 0 "
              "1 0 1.5h-5.5a.75.75 0 0 1 0-1.5z",
    "iot": "M12 2a7 7 0 0 1 4.2 12.6V16a1 1 0 0 1-1 1H8.8a1 1 0 0 1-1-1v-1.4A7 7 0 0 1 12 2zM12 6.2a.9.9 0 0 1 0 1.8a2.2 2.2 0 "
           "0 0-2.2 2.2a.9.9 0 0 1-1.8 0A4 4 0 0 1 12 6.2zM9 18.5h6v.75A2.25 2.25 0 0 1 12.75 21.5h-1.5A2.25 2.25 0 0 1 9 19.25z",
    "media": "M4 3.5h16a2 2 0 0 1 2 2V15a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5.5a2 2 0 0 1 2-2zM10 7.6v5.8l4.8-2.9zM11 17h2v2.5h-2zM7.75 "
             "19.5h8.5a.75.75 0 0 1 0 1.5h-8.5a.75.75 0 0 1 0-1.5z",
    "printer": "M7 3h10v4.5H7zM5 8.5h14a3 3 0 0 1 3 3V16H2v-4.5a3 3 0 0 1 3-3zM7 17h10v4H7zM17 10.8a1 1 0 1 0 0 2a1 1 0 1 0 0-2z",
    "phone": "M8 2h8a3 3 0 0 1 3 3v14a3 3 0 0 1-3 3H8a3 3 0 0 1-3-3V5a3 3 0 0 1 3-3zM10.5 4.25h3a.75.75 0 0 1 0 1.5h-3a.75.75 0 0 "
             "1 0-1.5zM10 18.6h4a.6.6 0 0 1 0 1.2h-4a.6.6 0 0 1 0-1.2z",
    "computer": "M5 4h14a2 2 0 0 1 2 2v9H3V6a2 2 0 0 1 2-2zM1.5 16.5h21v.5a3 3 0 0 1-3 3h-15a3 3 0 0 1-3-3zM10 16.5h4a1 1 0 0 1-1 "
                "1h-2a1 1 0 0 1-1-1z",
    "camera": "M4 4h12.5A1.5 1.5 0 0 1 18 5.5v5a1.5 1.5 0 0 1-1.5 1.5H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zM18 6.2l3.1-1.4a.6.6 0 0 1 "
              ".9.55v5.3a.6.6 0 0 1-.9.55L18 9.8zM5.5 6.7a1.3 1.3 0 1 0 0 2.6a1.3 1.3 0 1 0 0-2.6zM8 12h3v4.5H8zM6 16.5h7a1.5 "
              "1.5 0 0 1 1.5 1.5v2.5h-10V18A1.5 1.5 0 0 1 6 16.5z",
    "other": "M12 3.3l7 3.95-7 3.95-7-3.95zM4.2 8.6l7.1 4v8.1l-7.1-4zM19.8 8.6l-7.1 4v8.1l7.1-4z",
}
# The same kinds as thin line icons (2026-10-27), for the places that draw a stroke: the alerts timeline, the
# services and the kinds of broadcast on Traffic.
LINE_ICONS = {
    "network": "M4.5 10.5a11 11 0 0 1 15 0M7.5 13.8a6.5 6.5 0 0 1 9 0M10.5 17a2.2 2.2 0 0 1 3 0M12 20h.01",
    "server": "M5.5 4h13a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zM5.5 13h13a2 2 0 0 1 2 2v3a2 2 0 0 "
              "1-2 2h-13a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2zM7.5 7.5h.01M7.5 16.5h.01",
    "iot": "M9 3v5M15 3v5M6.5 8h11v3.5a5.5 5.5 0 0 1-11 0zM12 17v4",
    "printer": "M7 9V3h10v6M6 17H4a1 1 0 0 1-1-1v-6a1 1 0 0 1 1-1h16a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1h-2M7 14h10v7H7z",
    "computer": "M5.5 5h13a1.5 1.5 0 0 1 1.5 1.5v8a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 14.5v-8A1.5 1.5 0 0 1 5.5 5zM2.5 19h19",
    "other": "M12 3a9 9 0 1 1 0 18a9 9 0 1 1 0-18zM12 9a3 3 0 1 1 0 6a3 3 0 1 1 0-6z",
}
# The other glyphs in that style: the router in the middle of the map, the map's own groups, and the status
GLYPHS = {
    "router": "M6.5 4.5a1 1 0 0 1 2 0V12h-2zM15.5 4.5a1 1 0 0 1 2 0V12h-2zM6 12h12a3 3 0 0 1 3 3v2a3 3 0 0 1-3 3H6a3 3 0 0 "
              "1-3-3v-2a3 3 0 0 1 3-3zM7.8 14.8a1.2 1.2 0 1 0 0 2.4a1.2 1.2 0 1 0 0-2.4zM11.8 14.8a1.2 1.2 0 1 0 0 2.4a1.2 1.2 0 1 "
              "0 0-2.4zM14.5 15.25h3a.75.75 0 0 1 0 1.5h-3a.75.75 0 0 1 0-1.5z",
    "tag": "M3 4.8A1.8 1.8 0 0 1 4.8 3h7a1.8 1.8 0 0 1 1.27.53l7.4 7.4a1.8 1.8 0 0 1 0 2.54l-7 7a1.8 1.8 0 0 1-2.54 0l-7.4-7.4A1.8 "
           "1.8 0 0 1 3 11.8zM7.75 6a1.75 1.75 0 1 0 0 3.5a1.75 1.75 0 1 0 0-3.5z",
    "house": "M10.7 3.1a2 2 0 0 1 2.6 0l7 5.9a2 2 0 0 1 .7 1.5V19a2 2 0 0 1-2 2h-4.5v-5.5a1.5 1.5 0 0 0-1.5-1.5h-2a1.5 1.5 0 0 "
             "0-1.5 1.5V21H5a2 2 0 0 1-2-2v-8.5a2 2 0 0 1 .7-1.5z",
    "shield": "M12 2.5l8 3v6.2c0 5-3.4 8.4-8 9.8-4.6-1.4-8-4.8-8-9.8V5.5z",
    "bang": "M12 6.8a1 1 0 0 1 1 1v5a1 1 0 0 1-2 0v-5a1 1 0 0 1 1-1zM12 15a1.25 1.25 0 1 0 0 2.5a1.25 1.25 0 1 0 0-2.5z",
    "tick": "M8.2 11.6l1.4-1.4 1.9 1.9 3.9-3.9 1.4 1.4-5.3 5.3z",
    "circle": "M12 2a10 10 0 1 0 0 20a10 10 0 1 0 0-20z",
    "target": "M12 2a10 10 0 1 0 0 20a10 10 0 1 0 0-20zM12 5a7 7 0 1 0 0 14a7 7 0 1 0 0-14zM12 8.5a3.5 3.5 0 1 0 0 7a3.5 3.5 "
              "0 1 0 0-7z",
    "info": "M12 6a1.25 1.25 0 1 0 0 2.5a1.25 1.25 0 1 0 0-2.5zM12 10.2a1 1 0 0 1 1 1v5a1 1 0 0 1-2 0v-5a1 1 0 0 1 1-1z",
    "bell": "M12 2.5a6 6 0 0 1 6 6c0 4.6 1.4 6.9 2.4 7.9a.6.6 0 0 1-.4 1.1H4a.6.6 0 0 1-.4-1.1c1-1 2.4-3.3 2.4-7.9a6 6 0 0 1 6-6zM9.8 "
            "19.5h4.4a2.2 2.2 0 0 1-4.4 0z",
    "eye": "M12 5c5.5 0 9 4.4 10 7-1 2.6-4.5 7-10 7S3 14.6 2 12c1-2.6 4.5-7 10-7zM12 8.5a3.5 3.5 0 1 0 0 7a3.5 3.5 0 1 0 0-7zM12 "
           "10.3a1.7 1.7 0 1 0 0 3.4a1.7 1.7 0 1 0 0-3.4z",
}


@app.context_processor
def inject_icons():
    return {"cat_icons": CAT_ICONS, "glyphs": GLYPHS}


@app.context_processor
def inject_globals():
    try:
        conn = get_db()
        n = conn.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0 "
                         "AND severity <> 'info'").fetchone()[0]
        conn.close()
    except sqlite3.OperationalError:
        n = 0
    return {
        "unread_alerts": n,
        "scan_running": is_scan_running(),
        "vendor_or_random": vendor_or_random,
        "mac_is_randomized": common.mac_is_randomized,
        "humanise_age": _humanise_age,
    }


def vendor_or_random(vendor, mac):
    if vendor:
        return vendor
    if mac and common.mac_is_randomized(mac):
        return "(private MAC)"
    return "-"


def _parse_ts(s):
    """DB timestamps are ISO local time."""
    try:
        return datetime.fromisoformat(s) if s else None
    except (TypeError, ValueError):
        return None


def _humanise_age(ts_str, now=None):
    ts = _parse_ts(ts_str) if isinstance(ts_str, str) else ts_str
    if ts is None:
        return "never"
    secs = ((now or datetime.now()) - ts).total_seconds()
    if secs < 60:
        return f"{int(max(secs, 0))}s ago"
    if secs < 3600:
        return f"{int(secs / 60)}m ago"
    if secs < 86400:
        return f"{int(secs / 3600)}h ago"
    return f"{int(secs / 86400)}d ago"


def _age_seconds(ts_str):
    ts = _parse_ts(ts_str)
    return (datetime.now() - ts).total_seconds() if ts else None


def _per_day(row):
    """An observation keeps one running count; spread it over the days the row spans."""
    first, last = _parse_ts(row["first_seen"]), _parse_ts(row["last_seen"])
    span_days = (last - first).total_seconds() / 86400 if first and last else 0
    return row["count"] / max(span_days, 1)


def _nameable(h):
    """A device you can name: it has a real MAC and is not LanWard's own PC (the rule unknown_devices uses)."""
    mac = (h.get("mac") or "").lower()
    return bool(mac) and mac != common.own_mac() and common.mac_is_device(mac)


def _scan_hours():
    """The hours SCAN_HOURS schedules scans at (bad values ignored) and the gap between them in hours."""
    hours = sorted({int(h) for h in common.setting("SCAN_HOURS").split(",")
                    if h.strip().isdigit() and int(h) < 24})
    return hours, (24 // len(hours) if hours else None)


def _scan_every():
    hours, interval = _scan_hours()
    return f"every {interval} hours" if hours else "only when you start one"


def _heard_map(conn):
    """{mac: when LanWard last heard it}. A device reached through another's MAC (hosts.bridge_mac: Sonos
    speakers on SonosNet answer with the bridging speaker's MAC, 2026-10-27) is heard when its own IP is,
    behind that MAC."""
    heard = {r[0]: r[1] for r in conn.execute(
        "SELECT LOWER(mac), MAX(last_seen) FROM observations WHERE mac IS NOT NULL GROUP BY LOWER(mac)")}
    for mac, last in conn.execute(
            "SELECT h.mac, MAX(o.last_seen) FROM hosts h JOIN observations o ON o.mac = h.bridge_mac AND o.ip = h.ip "
            "WHERE h.scan_id = (SELECT MAX(id) FROM scans) AND h.bridge_mac IS NOT NULL GROUP BY h.mac"):
        if mac and last and last > (heard.get(mac) or ""):
            heard[mac] = last
    return heard


def _own_ipv4_maps(conn):
    """({mac: its newest own IPv4}, {IPv4: the newest mac that used it as its own})."""
    ip_by_mac, ip_to_mac = {}, {}
    for r in conn.execute("SELECT source, mac, ip, details FROM observations WHERE mac IS NOT NULL "
                          "ORDER BY last_seen DESC"):
        own = common.own_ip_of(r["source"], r["ip"], common.details_dict(r["details"]))
        if own and ":" not in own:
            ip_by_mac.setdefault(r["mac"].lower(), own)
            ip_to_mac.setdefault(own, r["mac"].lower())
    return ip_by_mac, ip_to_mac


# ────────────────────────────────────────────  home

def unknown_devices(conn, days=7):
    """Devices seen in the last `days` days that have no label yet."""
    labeled = set(_labels_map())
    me = common.own_mac()
    devs = {}

    def slot(mac):
        return devs.setdefault(mac, {"mac": mac, "ip": None, "hostname": None, "vendor": None,
                                     "first_seen": None, "last_seen": None, "sources": set()})

    for r in conn.execute(
        "SELECT mac, source, ip, hostname, vendor, details, first_seen, last_seen FROM observations "
        "WHERE last_seen >= ? AND mac IS NOT NULL ORDER BY last_seen", (common.iso_ago(days=days),)
    ):
        mac = r["mac"].lower()
        if mac in labeled or mac == me or not common.mac_is_device(mac):
            continue
        d = slot(mac)
        d["sources"].add(r["source"])
        d["first_seen"] = min(filter(None, [d["first_seen"], r["first_seen"]]))
        d["last_seen"] = r["last_seen"]
        own = common.own_ip_of(r["source"], r["ip"], common.details_dict(r["details"]))
        if own and ":" not in own:
            d["ip"] = own
        if r["source"] == "dhcp" and r["hostname"]:
            d["hostname"] = r["hostname"]
        d["vendor"] = d["vendor"] or r["vendor"]
    latest = conn.execute("SELECT id, started_at FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    if latest and (_age_seconds(latest["started_at"]) or 1e9) < days * 86400:
        for h in conn.execute("SELECT mac, ip, hostname, vendor FROM hosts "
                              "WHERE scan_id = ? AND mac IS NOT NULL", (latest["id"],)):
            mac = h["mac"].lower()
            if mac in labeled or mac == me or not common.mac_is_device(mac):
                continue
            d = slot(mac)
            d["sources"].add("scan")
            d["ip"] = d["ip"] or h["ip"]
            d["hostname"] = d["hostname"] or h["hostname"]
            d["vendor"] = d["vendor"] or h["vendor"]
            d["last_seen"] = d["last_seen"] or latest["started_at"]
    if devs:        # first seen ever, not just in the rows touched this week
        marks = ",".join("?" * len(devs))
        for r in conn.execute(f"SELECT LOWER(mac), MIN(first_seen) FROM observations WHERE LOWER(mac) IN ({marks}) "
                              "GROUP BY LOWER(mac)", list(devs)):
            devs[r[0]]["first_seen"] = min(filter(None, [devs[r[0]]["first_seen"], r[1]]))
    for d in devs.values():
        d["vendor"] = d["vendor"] or common.vendor_for(d["mac"])
        d["randomized"] = common.mac_is_randomized(d["mac"])
        d["sources"] = sorted(d["sources"])
        d["hint"] = common.name_hint(conn, d["mac"])      # "TRADFRI gateway": prefills the Approve name
    return sorted(devs.values(), key=lambda d: d["last_seen"] or "", reverse=True)


def latest_lan_scan(conn):
    """The newest scan of the whole LAN (SUBNET): a Run scan of a few addresses must not shrink the Overview."""
    cols = "SELECT id, started_at, host_count, subnet FROM scans"
    return conn.execute(f"{cols} WHERE subnet = ? ORDER BY id DESC LIMIT 1", (common.SUBNET,)).fetchone() or         conn.execute(f"{cols} ORDER BY id DESC LIMIT 1").fetchone()


def checked_scan_id(conn):
    """The newest scan whose security checks have finished (homechecks.py records it). A scan's
    hosts are saved minutes before their findings, and in between it would read as "no findings"."""
    done = common.kv_get(conn, "homechecks_done")
    if done and str(done).isdigit():
        return int(done)
    return conn.execute("SELECT MAX(id) FROM scans").fetchone()[0]


def latest_findings(conn):
    scan_id = checked_scan_id(conn)
    if not scan_id:
        return []
    out = []
    for h in conn.execute("SELECT ip, mac, hostname, vendor, findings FROM hosts "
                          "WHERE scan_id = ? AND findings IS NOT NULL", (scan_id,)):
        rec = _labels_map().get((h["mac"] or "").lower())
        name = (rec and rec["label"]) or h["hostname"] or h["vendor"] or h["ip"]
        for f in parse_json(h["findings"], []) or []:
            out.append({**f, "ip": h["ip"], "mac": h["mac"], "name": name, "scan_id": scan_id})
    out.sort(key=lambda f: (-SEV_RANK.get(f["severity"], 0), _ip_sort_key(f["ip"])))
    return out


def watched_devices(conn):
    """Watched devices with `view`: "up", "down" once the watcher has alerted (it waits
    WATCH_OFFLINE_MINUTES), else "checking" (just ticked, or quiet but not long enough yet);
    `uptime` is common.uptime() over 30 days and `uptime_text` says it in a few words."""
    out = []
    for r in conn.execute("SELECT l.mac, l.label, s.state, s.since, s.last_ok, s.last_ip, s.alerted "
                          "FROM host_labels l LEFT JOIN watch_state s ON s.mac = l.mac "
                          "WHERE l.watch_offline = 1 ORDER BY l.label COLLATE NOCASE"):
        w = dict(r)
        w["view"] = "up" if w["state"] == "up" else "down" if w["state"] == "down" and w["alerted"] else "checking"
        w["uptime"] = common.uptime(conn, w["mac"])
        w["uptime_text"] = _uptime_text(w["uptime"])
        w["uptime_short"] = _uptime_text(w["uptime"], short=True)
        out.append(w)
    return out


def _uptime_text(u, short=False):
    """ "99.8 % · 2 outages, longest 14 min · 30 days" ("99.8 % · 2 outages" with short=True, for the
    Overview's narrow Watched card); "" before anything was measured."""
    if u["uptime_pct"] is None:
        return ""
    since = _parse_ts(u["since"])
    span = "30 days" if since and (datetime.now() - since).days >= 29 else f"since {since:%d %b}" if since else ""
    if not u["count"]:
        return f"no outages · {span}"
    pct = f"{u['uptime_pct']:.1f}".rstrip("0").rstrip(".")
    if short:
        return f"{pct} % · {common.plural(u['count'], 'outage')}"
    return (f"{pct} % · {common.plural(u['count'], 'outage')}, longest {_duration(u['longest_min'])} · {span}")


def _duration(minutes):
    return f"{minutes} min" if minutes < 120 else f"{minutes / 60:.0f} h" if minutes < 2880 else f"{minutes / 1440:.0f} days"


def _uptime_days(u, days=30):
    """The last `days` days, oldest first, for the device page's strip: how many minutes the device was
    out each day (None before LanWard watched it)."""
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    since = _parse_ts(u["since"])
    spans = [(_parse_ts(o["start"]), _parse_ts(o["end"]) or datetime.now()) for o in u["outages"]]
    out = []
    for i in range(days - 1, -1, -1):
        start = today - timedelta(days=i)
        end = start + timedelta(days=1)
        if not since or end <= since:
            out.append({"label": f"{start:%a %d %b}", "down": None})
            continue
        down = sum(max(0.0, (min(e, end) - max(s, start)).total_seconds()) for s, e in spans if s and e) / 60
        out.append({"label": f"{start:%a %d %b}", "down": round(down)})
    return out


def gateway_status(conn):
    """Who claimed the router's address in the last 15 minutes: ARP answers, and ARP
    requests sent from it (the same signals watcher.check_gateway alerts on)."""
    ip = common.default_gateway() or common.kv_get(conn, "gateway_ip")
    mac = common.kv_get(conn, "gateway_mac")
    others = []
    if ip and mac:
        recent = common.iso_ago(minutes=15)
        claims = {r[0].lower() for r in conn.execute(
            "SELECT mac FROM observations WHERE source = 'arp' AND ip = ? AND last_seen >= ? AND mac IS NOT NULL",
            (ip, recent))}
        for r in conn.execute("SELECT mac, details FROM observations WHERE source = 'arp_req' AND mac IS NOT NULL "
                              "AND last_seen >= ? AND details LIKE ?", (recent, f'%"{ip}"%')):
            if common.details_dict(r["details"]).get("own_ip") == ip:
                claims.add(r["mac"].lower())
        others = sorted(claims - {mac})
    return {"ip": ip, "mac": mac, "others": others}


def _router_state(gateway):
    """(status, value, detail) of the router check: fail while another device answers for it, warn while
    LanWard is still learning the router's MAC."""
    if gateway["others"]:
        return ("fail", f"{len(gateway['others'])} impostor(s)",
                f"{', '.join(gateway['others'])} also answered for the router {gateway['ip']}.")
    if gateway["mac"]:
        return "ok", gateway["ip"], "Only the usual router answers for it"
    return "warn", gateway["ip"] or "unknown", "Still learning the router's MAC address."


def _health_checks(conn, now, last_scan, findings, watched, gateway):
    """The checks behind the Overview's status: each {name, status ok|warn|fail, value, detail}."""
    # Only what the passive monitor hears: the scan's WS-Discovery probe also writes observations.
    last_obs = conn.execute("SELECT MAX(last_seen) FROM observations WHERE source <> 'wsd'").fetchone()[0]
    watcher_beat = common.kv_get(conn, "watcher_heartbeat")
    notify_last = common.kv_get(conn, "notify_last")
    notify_ok = common.kv_get(conn, "notify_last_ok") or \
        (notify_last.split(" ")[0] if notify_last and notify_last.endswith(" ok") else None)
    waiting = conn.execute("SELECT COUNT(*) FROM notify_outbox").fetchone()[0]
    checks = {}

    def check(name, status, value, detail):
        checks[name] = {"name": name, "status": status, "value": value, "detail": detail}

    obs_age = _age_seconds(last_obs)
    if obs_age is None:
        check("Listening", "fail", "no data", "Nothing captured yet. Is the container running?")
    elif obs_age > 3600:
        check("Listening", "warn", _humanise_age(last_obs, now),
              "No packets recorded for over an hour; the container log (docker logs lanward) says why.")
    else:
        check("Listening", "ok", _humanise_age(last_obs, now), "DHCP, ARP and mDNS from every device")

    beat_age = _age_seconds(watcher_beat)
    if beat_age is None or beat_age > 180:
        check("Watcher", "fail", _humanise_age(watcher_beat, now),
              "The process that raises new-device, router and offline alerts is not running or keeps "
              "failing; the container log (docker logs lanward) says why.")
    else:
        check("Watcher", "ok", _humanise_age(watcher_beat, now), "New devices, router and offline checks")

    scan_age = _age_seconds(last_scan["started_at"]) if last_scan else None
    hours, interval = _scan_hours()
    nxt = next((h for h in hours if h > now.hour), hours[0] if hours else None)
    every = f"every {interval} h · next at {nxt:02d}:00" if hours else "only when you start one"
    if last_scan is None:
        check("Scans", "warn", "none yet", "The first scan runs shortly after start." if hours else
              "No scans are scheduled (SCAN_HOURS is empty); use Run scan.")
    elif not hours:
        check("Scans", "ok", (_parse_ts(last_scan["started_at"]) or now).strftime("%d %b %H:%M"), every)
    elif scan_age is None or scan_age > 2 * interval * 3600:
        check("Scans", "warn", _humanise_age(last_scan["started_at"], now),
              f"The last scan is over {2 * interval} hours old (they run every {interval} hours).")
    else:
        check("Scans", "ok", (_parse_ts(last_scan["started_at"]) or now).strftime("%H:%M"), every)

    check("Router", *_router_state(gateway))

    sent = _parse_ts(notify_ok)
    last_sent = "last sent " + (sent.strftime("%d %b %H:%M") if sent else "never")
    services = common.notify_services()
    if not services:
        check("Alerts out", "warn", "off", "Add a webhook (Home Assistant, Node-RED...) or a phone push (ntfy, "
              "Telegram, email...) on the Settings page, and send a test alert from there.")
    elif waiting:
        check("Alerts out", "fail", f"{waiting} waiting",
              f"{common.plural(waiting, 'alert')} that a destination did not take; the watcher retries "
              f"every 30 s for up to 48 h. {last_sent.capitalize()}. Last attempt: {notify_last or '-'}.")
    elif notify_last and "failed" in notify_last:
        check("Alerts out", "fail", "failing", f"The last hand-over failed: {notify_last}")
    else:
        check("Alerts out", "ok", "ready", f"To {', '.join(services)} · {last_sent}")

    serious = [f for f in findings if f["severity"] != "info"]
    worst = max((f["severity"] for f in serious), key=lambda s: SEV_RANK.get(s, 0), default=None)
    check("Security findings", "fail" if worst == "alert" else "warn" if worst == "warning" else "ok",
          str(len(serious)), f"{len(findings) - len(serious)} tips")

    down = [w for w in watched if w["view"] == "down"]
    check("Watched devices", "fail" if down else "ok", f"{len(down)} offline" if down else f"{len(watched)} watched",
          ", ".join(w["label"] for w in down) + " not answering." if down else "All answering.")
    return checks


# What the Overview says, as a headline, when one of LanWard's own checks is not fine.
CHECK_HEADLINES = {
    ("Listening", "fail"): "LanWard hears nothing", ("Listening", "warn"): "LanWard has heard nothing for an hour",
    ("Watcher", "fail"): "The watcher has stopped",
    ("Scans", "warn"): "No recent scan",
    ("Router", "fail"): "Another device answers for your router", ("Router", "warn"): "Still learning your router",
    ("Alerts out", "fail"): "Alerts are not getting out", ("Alerts out", "warn"): "Alerts go nowhere yet",
}

# Device kinds as people say them (classify() returns the keys).
CATEGORY_LABELS = {
    "network": "Network", "server": "Servers", "iot": "Smart home", "media": "Entertainment",
    "phone": "Phones & tablets", "computer": "Computers", "camera": "Cameras", "printer": "Printers",
    "other": "Other",
}
app.template_filter("cat_label")(lambda c: CATEGORY_LABELS.get(c or "other", (c or "other").title()))

# The Network tab's map, read row by row around the router (the centre slot). Each group takes
# the latest scan's devices of these classify() categories; its colour is the first one's.
MAP_LAYOUT = [
    ("Network", "Access points and switches", ("network",)),
    ("Homelab", "Servers and what runs on them, and the machine LanWard runs on", ("server",)),
    ("Cameras", "", ("camera",)),
    ("People", "Phones, tablets and computers", ("phone", "computer", "other")),
    "router",
    ("Entertainment", "Speakers, TVs and consoles", ("media", "printer")),
    "unnamed",
    ("Smart home", "Plugs, meters, hubs and robots", ("iot",)),
    "ghosts",
]


def _device_url(h):
    """The device page for a hosts row or finding; the per-scan page only when there is no MAC."""
    return url_for("host_history", mac=h["mac"]) if h.get("mac") else \
        url_for("host_in_scan", scan_id=h["scan_id"], ip=h["ip"])


def _when(ts, now):
    t = _parse_ts(ts)
    if not t:
        return ts or ""
    if t.date() == now.date():
        return "Today " + t.strftime("%H:%M")
    return t.strftime("%a %H:%M") if (now - t).days < 6 else t.strftime("%d %b %H:%M")


ACT_W = 1000        # the activity chart's SVG width in user units; CSS stretches it to the card


def _nice_ceil(v):
    """The smallest round number (1, 1.5, 2, 2.5, 3, 4, 5, 6, 8 times a power of ten) at or above v."""
    step = 10 ** max(0, len(str(int(v))) - 1)
    return next(int(m * step) for m in (1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10) if m * step >= v)


def _short_num(n):
    return f"{n / 1000:g}k" if n >= 1000 else f"{n:g}"


def _smooth(pts):
    """An SVG path through the points [(x, y)] as a monotone cubic curve: smooth, but never bulging past
    the data (Fritsch-Carlson)."""
    if len(pts) == 1:
        return f"M{pts[0][0]:.1f} {pts[0][1]:.1f} L{pts[0][0] + 0.1:.1f} {pts[0][1]:.1f}"
    m = [(b[1] - a[1]) / (b[0] - a[0]) for a, b in zip(pts, pts[1:])]
    t = [m[0]] + [0 if m[i - 1] * m[i] <= 0 else (m[i - 1] + m[i]) / 2 for i in range(1, len(m))] + [m[-1]]
    for i, mi in enumerate(m):
        if mi == 0:
            t[i] = t[i + 1] = 0
            continue
        a, b = t[i] / mi, t[i + 1] / mi
        if a * a + b * b > 9:
            q = 3 / math.hypot(a, b)
            t[i], t[i + 1] = q * a * mi, q * b * mi
    d = [f"M{pts[0][0]:.1f} {pts[0][1]:.1f}"]
    for i, ((x0, y0), (x1, y1)) in enumerate(zip(pts, pts[1:])):
        h = (x1 - x0) / 3
        d.append(f"C{x0 + h:.1f} {y0 + t[i] * h:.1f} {x1 - h:.1f} {y1 - t[i + 1] * h:.1f} {x1:.1f} {y1:.1f}")
    return " ".join(d)


def _runs(indexes):
    """The sorted `indexes` cut into runs of consecutive ones: a line breaks where nothing was counted."""
    runs = []
    for i in indexes:
        if runs and i == runs[-1][-1] + 1:
            runs[-1].append(i)
        else:
            runs.append([i])
    return runs


def _act_title(p):
    """One hour of the activity chart as hover text."""
    t, usual = p["t"], p["usual"]
    bits = [(f"{t:%a %d %b}" if p.get("day") else f"{t:%a %H}:00") + (" (so far)" if p["partial"] else "")]
    if p["devices"] is not None:
        bits.append(f"{p['devices']} devices" + (f", usually {usual['devices'][0]}–{usual['devices'][1]}" if usual else ""))
    if p["packets"] is not None:
        bits.append(f"{'about ' if p['partial'] else ''}{p['packets']:,} packets"
                    + (f", usually {usual['packets'][0]:,}–{usual['packets'][1]:,}" if usual else ""))
    if len(bits) == 1:
        bits.append("not counted yet" if not p["counted"] else "counted when the hour is over" if p["partial"]
                    else "nothing counted")
    return " · ".join(bits)


def _act_chart(points, field, height):
    """One activity chart in an ACT_W x height box: the counted line as a smooth curve over a soft fill (gaps
    where nothing was counted), a dashed estimate for the current hour, the usual line inside the usual range,
    rings on the hours far outside that range ("much" busier or quieter: a tenth of all hours lie just outside
    it) and a dot on the latest hour (both as % / px for HTML)."""
    import activity
    vals = [p[field] for p in points]
    usual = [p["usual"] for p in points]
    every = [v for v in vals if v is not None] + [x for u in usual if u for x in u[field]]
    if field == "devices":
        lo = max(0, (min(every, default=10) - 2) // 5 * 5)
        hi = lo + max(10, math.ceil((max(every, default=10) + 2 - lo) / 10) * 10)
        grid_step = 5 if hi - lo <= 20 else 10
    else:
        lo, hi = 0, _nice_ceil(max(max(every, default=0) * 1.1, 100))
        grid_step = _nice_ceil(hi / 3)
    step = ACT_W / (len(points) - 1)

    def X(i):
        return i * step

    def Y(v):
        return height - (v - lo) / (hi - lo) * height

    full = [i for i, p in enumerate(points) if vals[i] is not None and not p["partial"]]
    line, area = [], []
    for run in _runs(full):
        pts = [(X(i), Y(vals[i])) for i in run]
        path = _smooth(pts)
        line.append(path)
        area.append(f"{path} L{pts[-1][0]:.1f} {height} L{pts[0][0]:.1f} {height} Z")
    mid, band, mid_area = [], [], []
    # The usual median line always draws, with a soft fill beneath it — like the actual line's — so the two
    # read the same way (a line with its colour under it), rather than a filled low–high band.
    for run in _runs([i for i, u in enumerate(usual) if u]):
        mpath = _smooth([(X(i), Y(usual[i]["mid"][field])) for i in run])
        mid.append(mpath)
        mid_area.append(f"{mpath} L{X(run[-1]):.1f} {height} L{X(run[0]):.1f} {height} Z")
    end, last = len(points) - 1, (full[-1] if full else None)
    estimate = f"M{X(last):.1f} {Y(vals[last]):.1f} L{X(end):.1f} {Y(vals[end]):.1f}" \
        if points[end]["partial"] and vals[end] is not None and last == end - 1 else ""

    def spot(i):
        return {"left": round(100 * i / end, 2), "top": round(Y(vals[i]), 1)}

    grid = [g for g in range(int(lo) + grid_step - int(lo) % grid_step, int(hi), grid_step)]
    return {"height": height, "line": " ".join(line), "area": " ".join(area), "estimate": estimate,
            "usual": " ".join(mid), "band": " ".join(band), "usual_area": " ".join(mid_area),
            "grid": [{"y": round(Y(g), 1), "label": _short_num(g)} for g in grid],
            "flags": [spot(i) for i in full if usual[i] and activity.verdict(
                vals[i], usual[i][field], activity.margin(field, usual[i][field])).startswith("much")],
            "now": spot(last) if last is not None else None,
            "hits": [{"x": f"{(i - 0.5) * step:.1f}", "w": f"{step:.1f}", "tip": _act_title(p),
                      "cx": round(100 * i / (len(points) - 1), 2) if len(points) > 1 else 0,
                      "cy": round(Y(vals[i]), 1) if vals[i] is not None else None}
                     for i, p in enumerate(points)],
            "empty": not full, "low": min((v for v in vals if v is not None), default=None),
            "high": max((v for v in vals if v is not None), default=None)}


def _act_xlabels(points):
    """x-axis labels: every 6 hours over a day (the weekday at midnight), the weekday at noon over a week, every
    Monday's date over a month, each month's name over a year, and "now" (by day: "today") at the end."""
    n, out = len(points), []
    if points and points[0].get("day"):
        year = n > 60
        for i, p in enumerate(points[:-1]):
            t = p["t"]
            if (t.day == 1 if year else t.weekday() == 0) and n - 1 - i > (14 if year else 2):
                out.append({"left": round(100 * i / (n - 1), 2), "text": f"{t:%b}" if year else f"{t:%d %b}"})
        return out + [{"left": 100, "text": "today", "end": True}]
    for i, p in enumerate(points[:-1]):
        t, room = p["t"], n - 1 - i
        if n <= 48 and t.hour % 6 == 0 and room > 2:
            out.append({"left": round(100 * i / (n - 1), 2), "text": f"{t:%a}" if t.hour == 0 else f"{t:%H}:00"})
        elif n > 48 and t.hour == 12 and room > 8:
            out.append({"left": round(100 * i / (n - 1), 2), "text": f"{t:%a}"})
    return out + [{"left": 100, "text": "now", "end": True}]


def _act_headline(data, field, total=None):
    """The big number over the chart: the last full hour of `field` and how it compares with what is usual.
    For devices, `total` (the latest scan's device count) renders the value as "heard of total"."""
    last = data["last"]
    if not last:
        return {"value": "–", "unit": "nothing counted in the last hour", "pill": None,
                "note": "If this stays empty, check that LanWard is running."}
    unit = "devices heard" if field == "devices" else "packets"
    val = f"{last[field]:,}"
    if field == "devices" and total:
        val = f"{val} of {total:,}"
    usual = last["usual"]
    if not usual:
        when = data["learning_from"]
        return {"value": val, "unit": unit, "pill": ("Learning what is usual", "learn"),
                "note": f"the usual range shows from about {when:%a %d %b}" if when else ""}
    verdict = last[f"{field}_verdict"]
    lo, hi = usual[field]
    where = {"weekday": " on weekdays", "weekend": " at weekends"}.get(usual["kind"], "")
    return {"value": val, "unit": unit,
            "pill": (verdict.capitalize(), "ok" if verdict == "as usual" else "busy" if "busier" in verdict else "quiet"),
            "note": f"usually {lo:,}–{hi:,} at this hour{where}"}


def _activity_panel(conn, now, online=None):
    """The Overview's Network activity panel: per measure (chatter, devices heard) the last full hour against
    what is usual and a chart of the last 24 hours or 7 days, and any device that is suddenly very chatty.
    Chatter is first (the default view); `online` (the latest scan's device count) lets the devices headline
    read "heard of total"."""
    import activity
    data = activity.network(conn, now)
    metrics = [{"key": "packets", "label": "Chatter", "headline": _act_headline(data, "packets")},
               {"key": "devices", "label": "Devices heard", "headline": _act_headline(data, "devices", online)}]
    ranges = [{"key": "24h", "label": "24 hours", "hours": 24}, {"key": "7d", "label": "7 days", "hours": 168},
              {"key": "30d", "label": "30 days", "days": 30}, {"key": "365d", "label": "365 days", "days": 365}]
    first = data["first"]
    # One query for both day views; over 365 days no usual range: it is what is usual in the last 4 weeks
    year = activity.daily(conn, now, 365)
    by_days = {30: year[-30:], 365: [{**p, "usual": None} for p in year]}
    whole = first and (first if first.hour == 0 else first.replace(hour=0) + timedelta(days=1))
    views = []
    for r in ranges:
        points = by_days[r["days"]] if r.get("days") else data["points"][-r["hours"]:]
        per = "day" if r.get("days") else "hour"
        began = None if points[0]["counted"] or not first else f"{first:%a %d %b}" if per == "day" else \
            f"{first:%a} {first:%H}:00"
        for m in metrics:
            chart = _act_chart(points, m["key"], 220)
            views.append({"metric": m["key"], "range": r["key"], "chart": chart, "xlabels": _act_xlabels(points),
                          "caption": f"{'Devices heard' if m['key'] == 'devices' else 'Packets'} per {per}, last {r['label']}",
                          "now_label": "Today so far" if per == "day" else "This hour so far",
                          "per": per,
                          "empty": (f"Each day shows once it is over, the first on {whole:%a %d %b}" if per == "day" and whole
                                    else "Nothing counted yet"),
                          "began": began})

    labels = _labels_map()

    def link(mac, name=None):
        return {"name": name or (labels.get(mac) or {}).get("label") or mac, "url": url_for("host_history", mac=mac)}

    # "Out of the ordinary": only devices that are suddenly very chatty (often one restarting in a loop).
    # The "usually here but away since <day>" notices were dropped from the Overview (2026-10-29): a device
    # that is normally home being away for a while is routine, not something to flag. activity.away_devices
    # stays available for other uses.
    busy = activity.busy_devices(conn, now)
    names = _names_by_mac(conn) if busy else {}
    unusual = [{"kind": "busy", "devices": [link(mac, names.get(mac))],
                "why": f"sent {n:,} packets in the last hour, at most {most:,} in a usual hour. Often a device that "
                       "restarts again and again."} for mac, n, most in busy]
    return {"metrics": metrics, "ranges": ranges, "views": views, "unusual": unusual}


def _network_map(conn, hosts, unknown, gateway):
    """The Network tab's map: one cell per MAP_LAYOUT slot around the router, each device of the newest scan
    once (unnamed ones in "Not named yet", LanWard's own PC in Homelab), a green dot for each heard in the last
    10 minutes, and addresses nobody uses that devices still ask for in "Nobody home"."""
    from alerts import CLAIMED_DAYS, ghost_targets, listening_since
    heard = _heard_map(conn)
    ghosts = ghost_targets(conn)
    first_week = (listening_since(conn) or "9") > common.iso_ago(days=CLAIMED_DAYS)
    labels = _labels_map()
    status, _, detail = _router_state(gateway)

    def live(mac):
        """Heard by the passive monitor in the last 10 minutes (the map legend's green dot)."""
        age = _age_seconds(heard.get((mac or "").lower()))
        return age is not None and age < 600

    me, gw_ip = common.own_mac(), gateway["ip"]
    router = next((h for h in hosts if h["ip"] == gw_ip), None)
    unnamed_macs = {d["mac"] for d in unknown}

    def mine(h):
        return bool(me) and (h["mac"] or "").lower() == me

    cells = []
    for slot in MAP_LAYOUT:
        if slot == "router":
            cells.append({"kind": "router", "name": (router or {}).get("label") or "Router", "ip": gw_ip or "?",
                          "status": status, "detail": detail,
                          "url": _device_url(router) if router else None,
                          "risky": bool(router) and any(f["severity"] != "info" for f in router["findings_list"])})
        elif slot == "unnamed":
            items = [{"name": d["hint"] or d["hostname"] or d["vendor"] or ("Private MAC" if d["randomized"] else "Unknown"),
                      "ip": d["ip"] or "-", "live": live(d["mac"]), "risky": False,
                      "url": url_for("host_history", mac=d["mac"]), "title": d["mac"]} for d in unknown]
            cells.append({"kind": "unnamed", "label": "Not named yet", "items": items, "cat": "other",
                          "note": "Seen this week, no name" if items else "Every device seen this week has a name",
                          "action": ("Name it" if len(items) == 1 else "Name them", url_for("home") + "#name-devices") if items else None})
        elif slot == "ghosts":
            items = [{"name": ip, "ip": f"{a['per_day']:,.0f}/day", "live": False, "risky": False,
                      "url": url_for("flows"), "title": "Asked for by " + ", ".join(
                          labels.get(m, {}).get("label") or m for m in sorted(a["askers"]))}
                     for ip, a in sorted(ghosts.items(), key=lambda kv: -kv[1]["per_day"])]
            askers = sorted({labels.get(m, {}).get("label") or m for a in ghosts.values() for m in a["askers"]})
            cells.append({"kind": "ghosts", "label": "Nobody home", "items": items, "cat": "other",
                          "note": (f"No device has used {'this address' if len(items) == 1 else 'these addresses'} for a week, "
                                   f"but {', '.join(askers)} still ask{'s' if len(askers) == 1 else ''} for "
                                   f"{'it' if len(items) == 1 else 'them'}.") if items
                                  else f"Shown after {CLAIMED_DAYS} days of listening" if first_week
                                  else "Every address something asks for is in use",
                          "action": ("See who asks", url_for("flows")) if items else None})
        else:
            label, note, cats = slot
            # Each device once: unnamed ones sit in "Not named yet", LanWard's own PC in Homelab.
            members = [h for h in hosts if h is not router and (h["mac"] or "").lower() not in unnamed_macs
                       and (mine(h) if label == "Homelab" and mine(h) else h["category"] in cats and not mine(h))]
            items = [{"name": h["label"] or h["hostname"] or h["vendor"] or h["ip"], "ip": h["ip"] or "-",
                      "live": live(h["mac"]),
                      "risky": any(f["severity"] != "info" for f in h["findings_list"]),
                      "url": _device_url(h),
                      "title": f"{h['ip']} · {vendor_or_random(h['vendor'], h['mac'])}"}
                     for h in sorted(members, key=lambda h: _ip_sort_key(h["ip"]))]
            cells.append({"kind": "group", "label": label, "note": note, "items": items, "cat": cats[0]})

    return cells


@app.route("/network")
def network():
    """The home network (2026-10-27, from the Overview): the router, then the newest scan's devices grouped by
    kind, with devices not named yet and addresses nobody uses as rows worth a look."""
    conn = get_db()
    last_scan = latest_lan_scan(conn)
    hosts = [decorate(r) for r in get_scan_hosts(conn, last_scan["id"])] if last_scan else []
    cells = _network_map(conn, hosts, unknown_devices(conn), gateway_status(conn))
    conn.close()
    scan_at = _when(last_scan["started_at"], datetime.now()).replace("Today ", "") if last_scan else None
    n_live = sum(1 for c in cells if c["kind"] in ("group", "unnamed") for d in c["items"] if d["live"])
    return render_template("network.html", cells=cells, scan_at=scan_at, n_hosts=len(hosts), n_live=n_live)


@app.route("/")
def home():
    from alerts import ghost_targets
    conn = get_db()
    now = datetime.now()
    last_scan = latest_lan_scan(conn)
    unknown = unknown_devices(conn)
    findings = latest_findings(conn)
    watched = watched_devices(conn)
    gateway = gateway_status(conn)
    checks = _health_checks(conn, now, last_scan, findings, watched, gateway)
    unack = {r["severity"]: r["n"] for r in conn.execute(
        "SELECT severity, COUNT(*) AS n FROM alerts WHERE acknowledged = 0 GROUP BY severity")}
    hosts = [decorate(r) for r in get_scan_hosts(conn, last_scan["id"])] if last_scan else []
    ghosts = ghost_targets(conn)
    learning_until = common.kv_get(conn, "learning_until")
    labels = _labels_map()
    checked = checked_scan_id(conn)
    unseen = [dict(r) for r in conn.execute(
        "SELECT id, created_at, severity, title FROM alerts WHERE acknowledged = 0 AND severity IN ('warning', 'alert') "
        "ORDER BY id DESC LIMIT 3")]
    act = _activity_panel(conn, now, len(hosts))
    conn.close()

    # ── what needs a look ──
    insights = []
    for name in ("Router", "Watched devices", "Watcher", "Listening", "Scans", "Alerts out"):
        c = checks[name]
        if c["status"] != "ok":
            down = [w["label"] for w in watched if w["view"] == "down"]
            title = (f"{', '.join(down)} {'is' if len(down) == 1 else 'are'} offline" if name == "Watched devices"
                     else CHECK_HEADLINES.get((name, c["status"]), f"{name}: {c['value']}"))
            insights.append({"level": c["status"], "title": title, "detail": c["detail"], "action": None})
    for f in findings:
        if f["severity"] != "info":
            insights.append({"level": "fail" if f["severity"] == "alert" else "warn", "title": f"{f['name']}: {f['title']}",
                             "detail": f["detail"], "action": ("Open device", _device_url(f))})
    updates = [f for f in findings if f["id"].startswith("shelly-update")]
    if updates:
        insights.append({"level": "info", "title": f"Firmware update waiting on {common.plural(len(updates), 'Shelly device')}",
                         "detail": "; ".join(f"{f['name']}: {f['title'].split(': ', 1)[-1]}" for f in updates[:4]),
                         "action": None})
    # Alerts nobody has marked as seen, the newest 3 by title (2026-10-27: instead of a Recent alerts card)
    n_unack = sum(unack.get(s, 0) for s in ("warning", "alert"))      # the same count as the nav badge
    if n_unack:
        for a in unseen:
            a["when"] = _when(a["created_at"], now)
        more = n_unack - len(unseen)
        insights.append({"level": "fail" if unack.get("alert") else "warn",
                         "title": f"{common.plural(n_unack, 'alert')} you haven't seen",
                         "lines": unseen, "detail": f"And {more} more." if more > 0 else "",
                         "action": ("Open alerts", url_for("alerts"))})

    # Small things to tidy up (the Network tab's dashed boxes): never a reason for a warning.
    tidy = []
    if unknown:
        def called(d):
            return d["hint"] or d["hostname"] or d["vendor"] or ("Private MAC" if d["randomized"] else "Unknown")
        if len(unknown) == 1:
            d = unknown[0]
            detail = (f"{called(d)} ({d['ip'] or d['mac']}), last seen {_humanise_age(d['last_seen'], now)}. "
                      "Name it if you know it: a name marks it as yours.")
        else:
            detail = (", ".join(called(d) for d in unknown[:4]) + (f" and {len(unknown) - 4} more" if len(unknown) > 4 else "")
                      + ". Name the ones you know: a name marks a device as yours.")
        tidy.append({"level": "tidy", "title": f"{common.plural(len(unknown), 'device')} not named yet", "detail": detail,
                     "action": ("Name it ↓" if len(unknown) == 1 else "Name them ↓", "#name-devices")})
    if ghosts:
        ips = sorted(ghosts, key=lambda ip: -ghosts[ip]["per_day"])
        askers = sorted({labels.get(m, {}).get("label") or m for a in ghosts.values() for m in a["askers"]})
        one = len(ips) == 1
        tidy.append({"level": "info",
                     "title": "An address nobody uses is still asked for" if one else
                              f"{len(ips)} addresses nobody uses are still asked for",
                     "detail": f"No device has used {', '.join(ips[:3])}{' and more' if len(ips) > 3 else ''} for a week, "
                               f"but {', '.join(askers)} still ask{'s' if len(askers) == 1 else ''} for "
                               f"{'it' if one else 'them'}, about {sum(a['per_day'] for a in ghosts.values()):,.0f} "
                               "times a day. Often a setting that still points at an old device.",
                     "action": ("See who asks →", url_for("flows"))})

    # ── hero ──
    level = "fail" if any(i["level"] == "fail" for i in insights) else \
            "warn" if any(i["level"] == "warn" for i in insights) else "ok"
    insights += tidy
    unnamed_hosts = [h for h in hosts if _nameable(h) and not h["label"]]
    all_named = bool(hosts) and not unnamed_hosts
    if level == "ok":
        hero = {"level": "ok", "title": "Nothing needs you right now", "text": None}     # the facts say it
    else:
        first = next(i for i in insights if i["level"] == level)
        more = len([i for i in insights if i["level"] in ("fail", "warn")]) - 1
        hero = {"level": level, "title": first["title"],
                "text": first["detail"] + (f" And {more} more under Worth a look." if more > 0 else "")}
    # A fresh install's first day (watcher.start_learning): unless something is wrong, say what is going on.
    until = _parse_ts(learning_until)
    if until and until > now and level != "fail":
        open_items = len([i for i in insights if i["level"] == "warn"])
        hero = {"level": "learn", "title": "Getting to know your network",
                "text": f"Until {_when(learning_until, now).replace('Today ', 'today ')} LanWard records what is "
                        "already at home, without new-device alerts. Name the devices you know under Name new "
                        "devices: anything unnamed that turns up after that gets a push."
                        + (f" {common.plural(open_items, 'thing')} under Worth a look." if open_items else "")}

    # ── the line under the status (2026-10-27, picked on the canvas: "6", alerts before watched): a small icon and a
    #    few words each ("Security fine, 7 tips"); only what needs you gets a colour, the icon's (`tone`) and, with
    #    `hl`, the bold word's too. `opens`: the item opens a popup with the details (home.html: watched devices,
    #    security checks, Worth a look) ──
    up = sum(1 for w in watched if w["view"] == "up")
    down = sum(1 for w in watched if w["view"] == "down")
    serious = [f for f in findings if f["severity"] != "info"]
    tips = len(findings) - len(serious)
    worst_unack = next((s for s in ("alert", "warning") if unack.get(s)), None)

    def item(icon, strong, post="", pre="", tone="", hl=False, url=None, opens=None):
        return {"icon": icon, "pre": pre, "strong": strong, "post": post, "tone": tone, "hl": hl, "url": url,
                "opens": opens}
    status_line = [item("devices", str(len(hosts)), " devices online" + (
        f", {len(unknown)} to name" if unknown else ", all named" if all_named else ""),
        tone="warn" if unknown else "", url="#name-devices" if unknown else url_for("devices"))
        if hosts else item("devices", "No", " scan yet", tone="warn", hl=True, url=url_for("run_scan"))]
    unack_tone = {"alert": "alert", "warning": "warn"}.get(worst_unack, "")
    status_line.append(item("alerts", str(n_unack) if n_unack else "No", " new alert" + ("" if n_unack == 1 else "s"),
                            tone=unack_tone, hl=bool(unack_tone), url=url_for("alerts")))
    checking = len(watched) - up - down
    if not watched:
        status_line.append(item("watched", "No", " watched devices"))
    elif down:
        status_line.append(item("watched", f"{up} of {len(watched)}", f" watched online, {down} offline",
                                tone="alert", hl=True, opens="watched"))
    elif up == 0 and checking:
        status_line.append(item("watched", "Checking", " %d watched device%s…" % (len(watched), "" if len(watched) == 1 else "s"),
                                opens="watched"))
    else:
        status_line.append(item("watched", f"{up} of {len(watched)}", " watched online", tone="ok", opens="watched"))
    tip_text = f", {common.plural(tips, 'tip')}" if tips else ""
    if serious:
        status_line.append(item("security", str(len(serious)),
                                (" serious finding" if len(serious) == 1 else " serious findings") + tip_text,
                                tone="alert" if any(f["severity"] == "alert" for f in serious) else "warn", hl=True,
                                opens="security"))
    elif checked:
        status_line.append(item("security", "fine", tip_text, pre="Security ", opens="security"))
    else:
        status_line.append(item("security", "waiting", " for the first scan", pre="Security checks "))
    if insights:
        levels = {i["level"] for i in insights}
        tone = "alert" if "fail" in levels else "warn" if "warn" in levels else "info"
        n = len(insights)
        what = ("tip" if n == 1 else "tips") if tone == "info" else ("thing" if n == 1 else "things")
        status_line.append(item("look", str(n), f" {what} worth a look", tone=tone, hl=True, opens="look"))
    else:
        status_line.append(item("look", "Nothing", " worth a look"))
    health = [checks[n] for n in ("Listening", "Watcher", "Scans", "Router", "Alerts out")]

    return render_template(
        "home.html", hero=hero, health=health, status_line=status_line, insights=insights, watched=watched, act=act,
        unknown=unknown, findings=findings, gateway=gateway, now=now, last_scan=last_scan, checked=checked)


@app.route("/healthz")
def healthz():
    return {"ok": True}


@app.route("/api/status")
def api_status():
    """LanWard at a glance, for Home Assistant or anything else that polls (2026-10-13): `level` ok | warn | fail
    and a one-line `summary` like the Overview's, last scan, open alerts, findings, unnamed devices with a name hint,
    watched devices, the last 7 days' alerts, and whether the background processes and alerts keep up.
    Read with the API key (Authorization: Bearer ...), from a STATUS_ALLOW address, or logged in."""
    conn = get_db()
    last = conn.execute("SELECT id, started_at, host_count FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    open_counts = {r[0]: r[1] for r in conn.execute(
        "SELECT severity, COUNT(*) FROM alerts WHERE acknowledged = 0 GROUP BY severity")}
    alerts_open = [dict(r) for r in conn.execute(
        "SELECT id, created_at, severity, kind, title FROM alerts WHERE acknowledged = 0 ORDER BY id DESC LIMIT 20")]
    week = [dict(r) for r in conn.execute(
        "SELECT id, created_at, severity, kind, title, acknowledged FROM alerts WHERE created_at >= ? "
        "ORDER BY id DESC LIMIT 30", (common.iso_ago(days=7),))]
    unknown = [{"mac": d["mac"], "ip": d["ip"], "vendor": d["vendor"], "hostname": d["hostname"], "hint": d["hint"],
                "private_mac": d["randomized"], "first_seen": d["first_seen"], "last_seen": d["last_seen"]}
               for d in unknown_devices(conn)]
    findings = [{"ip": f["ip"], "device": f["name"], "severity": f["severity"], "title": f["title"],
                 "detail": f["detail"]} for f in latest_findings(conn)]
    # "down" only once the watcher has alerted, like the Overview; a short silence is still "unknown".
    watched = [{"label": w["label"], "state": {"up": "up", "down": "down"}.get(w["view"], "unknown"), "since": w["since"],
                "uptime_30d": w["uptime"]["uptime_pct"], "outages_30d": w["uptime"]["count"]}
               for w in watched_devices(conn)]
    passive = conn.execute("SELECT MAX(last_seen) FROM observations WHERE source <> 'wsd'").fetchone()[0]
    import activity
    act = activity.network(conn, hours=1)
    act_words, act_last = activity.describe(act), act["last"]
    # What needs a look, as on the Overview: LanWard's own checks, serious findings, unacknowledged warnings.
    checks = _health_checks(conn, datetime.now(), latest_lan_scan(conn), latest_findings(conn),
                            watched_devices(conn), gateway_status(conn))
    issues = [c["status"] for name, c in checks.items() if c["status"] != "ok" and name != "Security findings"]
    issues += ["fail" if f["severity"] == "alert" else "warn" for f in findings if f["severity"] != "info"]
    if open_counts.get("alert") or open_counts.get("warning"):
        issues.append("warn")
    level = "fail" if "fail" in issues else "warn" if issues else "ok"
    out = {
        "updated": common.now_iso(),
        "level": level,
        "summary": "All well" if not issues else f"{len(issues)} to look at",
        "learning_until": common.kv_get(conn, "learning_until"),
        "last_scan": {"id": last["id"], "started_at": last["started_at"], "devices": last["host_count"]} if last else None,
        # A scan is only written to `scans` when it ends; this says one is running now (2026-11-13, for Homelab Village)
        "scan_running": is_scan_running(),
        "alerts_open": {sev: open_counts.get(sev, 0) for sev in ("alert", "warning", "info")},
        "alerts_open_list": alerts_open,        # the newest 20
        "alerts_7d": week,                      # the newest 30
        "findings": findings,
        "unknown_devices": unknown,
        "watched": watched,
        # The last full hour against what is usual for it (the Overview's Network activity)
        "activity": {"hour": activity.hour_key(act_last["t"]), "devices": act_last["devices"],
                     "packets": act_last["packets"],
                     "devices_usual": list(act_last["usual"]["devices"]) if act_last["usual"] else None,
                     "packets_usual": list(act_last["usual"]["packets"]) if act_last["usual"] else None,
                     "verdict": act_words["verdict"], "summary": act_words["title"], "detail": act_words["text"]}
                    if act_last else None,
        "watcher_heartbeat": common.kv_get(conn, "watcher_heartbeat"),
        "passive_last_seen": passive,
        "outbox": conn.execute("SELECT COUNT(*) FROM notify_outbox").fetchone()[0],
        "notify_last": common.kv_get(conn, "notify_last"),
        "notify_last_ok": common.kv_get(conn, "notify_last_ok"),
    }
    conn.close()
    return out


@app.route("/api/devices")
def api_devices():
    """Every device: those in the newest scan of the whole LAN, plus any heard in the last 24 hours that the
    scan missed (asleep at scan time, just arrived). online = heard in the last 10 minutes."""
    conn = get_db()
    scan = latest_lan_scan(conn)
    hosts = [decorate(r) for r in get_scan_hosts(conn, scan["id"])] if scan else []
    heard = _heard_map(conn)
    ip_by_mac, _ = _own_ipv4_maps(conn)
    names = _names_by_mac(conn)
    watched = {w["mac"]: w for w in watched_devices(conn)}
    svc = {}
    for r in conn.execute("SELECT mac, port, what, how FROM open_ports_seen WHERE what IS NOT NULL"):
        svc.setdefault(r["mac"], {})[r["port"]] = {"what": r["what"], "how": r["how"]}
    conn.close()
    me, labels = common.own_mac(), _labels_map()

    def device(mac, ip, vendor, hostname, category, h=None):
        last = heard.get(mac or "")
        w = watched.get(mac or "")
        return {"mac": mac, "ip": ip, "name": (labels.get(mac or "") or {}).get("label"), "hostname": hostname,
                "vendor": vendor_or_random(vendor, mac) if mac else vendor, "kind": CATEGORY_LABELS.get(category),
                "online": (_age_seconds(last) or 1e9) < 600, "last_heard": last, "in_scan": h is not None,
                "watched": ({"up": "up", "down": "down"}.get(w["view"], "unknown") if w else None),
                "uptime_30d": w["uptime"]["uptime_pct"] if w else None,
                "open_ports": (None if h["ports_unknown"] else [p for p in (h["ports"] or "").split(",") if p])
                              if h else None,
                "services": [{"port": p, "what": svc.get(mac or "", {}).get(p, {}).get("what"),
                              "how": svc.get(mac or "", {}).get(p, {}).get("how")}
                             for p in parse_json(h.get("open_ports"), [])] if h and not h["ports_unknown"] else None,
                "findings": [{"severity": f["severity"], "title": f["title"]} for f in h["findings_list"]] if h else []}

    out, seen = [], set()
    for h in sorted(hosts, key=lambda h: _ip_sort_key(h["ip"])):
        mac = (h["mac"] or "").lower() or None
        seen.add(mac)
        out.append(device(mac, h["ip"], h["vendor"], h["hostname"], h["category"], h))
    recent = common.iso_ago(hours=24)
    for mac, last in sorted(heard.items(), key=lambda kv: kv[1], reverse=True):
        if mac not in seen and last >= recent and mac != me and common.mac_is_device(mac):
            out.append(device(mac, ip_by_mac.get(mac), common.vendor_for(mac), names.get(mac),
                              classify(common.vendor_for(mac), None, names.get(mac),
                                       (labels.get(mac) or {}).get("label"))))
    return {"updated": common.now_iso(), "scan": dict(scan) if scan else None, "devices": out}


@app.route("/api/alerts")
def api_alerts():
    """The newest alerts, newest first: ?limit= (default 100, at most 1000), ?open=1 for unacknowledged only."""
    limit = max(1, min(request.args.get("limit", 100, type=int), 1000))
    where = "WHERE acknowledged = 0" if request.args.get("open") == "1" else ""
    conn = get_db()
    rows = [dict(r) for r in conn.execute(
        f"SELECT id, created_at, severity, kind, title, details, acknowledged, acknowledged_at FROM alerts {where} "
        "ORDER BY id DESC LIMIT ?", (limit,))]
    conn.close()
    for r in rows:
        r["acknowledged"] = bool(r["acknowledged"])
    return {"updated": common.now_iso(), "alerts": rows}


@app.route("/gateway/accept", methods=["POST"])
def gateway_accept():
    mac = (request.form.get("mac") or "").strip().lower()
    if not MAC_PATH_RE.match(mac):
        abort(400)
    conn = get_db()
    common.kv_set(conn, "gateway_mac", mac)
    conn.commit()
    conn.close()
    return redirect(url_for("home"))


# ────────────────────────────────────────────  scans

def _csv_cell(v):
    """Device-supplied text (host names, page titles, banners) must not run as a spreadsheet formula."""
    return "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def _csv_download(filename, fields, rows):
    """A CSV file to save (Traffic's views, 2026-10-27): `fields` as (column, key) pairs, one line per row."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([column for column, _ in fields])
    for r in rows:
        writer.writerow([_csv_cell(r.get(key)) for _, key in fields])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.route("/scan/<int:scan_id>/export.csv")
def scan_export_csv(scan_id):
    conn = get_db()
    if not conn.execute("SELECT 1 FROM scans WHERE id = ?", (scan_id,)).fetchone():
        abort(404)
    rows = get_scan_hosts(conn, scan_id)
    cols = [c[0] for c in conn.execute("SELECT * FROM hosts LIMIT 0").description]
    conn.close()
    buf = io.StringIO()
    labels = _labels_map()
    cols.insert(cols.index("mac") + 1, "label")                 # your name for it, next to the MAC
    writer = csv.DictWriter(buf, fieldnames=cols)
    writer.writeheader()
    for r in rows:
        row = {**dict(r), "label": (labels.get((r["mac"] or "").lower()) or {}).get("label")}
        writer.writerow({k: _csv_cell(v) for k, v in row.items()})
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.csv"'})


@app.route("/scan/<int:scan_id>/host/<path:ip>")
def host_in_scan(scan_id, ip):
    conn = get_db()
    row = conn.execute(
        "SELECT h.*, s.subnet, s.started_at FROM hosts h JOIN scans s ON h.scan_id = s.id "
        "WHERE h.scan_id = ? AND h.ip = ?", (scan_id, ip)).fetchone()
    if not row:
        abort(404)
    conn.close()
    return render_template("host_detail.html", host=_with_scan_facts(decorate(row)))


def _with_scan_facts(host):
    """A decorated hosts row plus its scan's web pages, UPnP, mDNS and IPv6 parsed for _scan_facts.html."""
    upnp_parsed = parse_json(host.get("upnp_info"), {})
    host["upnp_parsed"] = upnp_parsed if isinstance(upnp_parsed, dict) else {}
    web_parsed = parse_json(host.get("web_info"), {})
    host["web_parsed"] = web_parsed if isinstance(web_parsed, dict) else {}
    host["mdns_list"] = (host.get("mdns_services") or "").split(",") if host.get("mdns_services") else []
    ipv6_list = parse_json(host.get("ipv6_addrs"), [])
    host["ipv6_list"] = ipv6_list if isinstance(ipv6_list, list) else []
    return host


def _device_activity(conn, mac, now=None):
    """The device page's activity (2026-11-01; was a 7-day heatmap): this device's packets as the Overview's chart,
    over 24 hours, 7 days, 30 days or 365 days, against what is usual for it (activity.network / daily with `mac`)."""
    import activity
    now = now or datetime.now()
    data = activity.network(conn, now, mac=mac)
    year = activity.daily(conn, now, 365, mac=mac)
    one = lambda points: [{**p, "devices": None} for p in points]       # a device has no "devices heard"
    ranges = [{"key": "24h", "label": "24 hours"}, {"key": "7d", "label": "7 days"},
              {"key": "30d", "label": "30 days"}, {"key": "365d", "label": "365 days"}]
    series = {"24h": one(data["points"][-24:]), "7d": one(data["points"]),
              "30d": one(year[-30:]), "365d": [{**p, "usual": None} for p in one(year)]}
    first = data["first"]
    views = []
    for r in ranges:
        points = series[r["key"]]
        per = "day" if points[0].get("day") else "hour"
        views.append({"range": r["key"], "chart": _act_chart(points, "packets", 200), "xlabels": _act_xlabels(points),
                      "caption": f"Packets per {per} from this device, last {r['label']}", "per": per,
                      "now_label": "Today so far" if per == "day" else "This hour so far",
                      "began": None if points[0]["counted"] or not first else
                               f"{first:%a %d %b}" if per == "day" else f"{first:%a} {first:%H}:00"})
    return {"ranges": ranges, "views": views}


def _port_history(conn, mac):
    """The device page's "Open ports" (2026-11-02): every port it has had open (open_ports_seen), what each is and
    how LanWard knows (portid.py), since when, and the ones that closed in the last 30 days, with where a random
    port moved after a restart. Open = found open by the device's newest check (all its open ports are stamped with
    that check's time). None when LanWard has no port history for it."""
    rows = conn.execute("SELECT port, first_seen, last_seen, what, how, sure, moved_to, moved_from FROM open_ports_seen "
                        "WHERE mac = ? ORDER BY port", (mac,)).fetchall()
    if not rows:
        return None
    now, newest = datetime.now(), max(r["last_seen"] for r in rows)
    full = conn.execute("SELECT first_full_at FROM port_checks WHERE mac = ?", (mac,)).fetchone()
    start = _parse_ts(full[0]) if full and full[0] else None
    baseline_end = (start + timedelta(hours=common.BASELINE_HOURS)).isoformat(timespec="seconds") if start else None
    week, month = common.iso_ago(days=7), common.iso_ago(days=30)

    def item(r):
        first, last = _parse_ts(r["first_seen"]), _parse_ts(r["last_seen"])
        return {"port": r["port"], "what": r["what"], "how": r["how"], "sure": bool(r["sure"]),
                "temporary": r["port"] >= common.EPHEMERAL_PORT,
                "new": bool(baseline_end) and r["first_seen"] > baseline_end and r["first_seen"] >= week,
                "first": r["first_seen"], "last": r["last_seen"],
                "since": f"{first.day} {first:%b}" if first else "", "since_when": _when(r["first_seen"], now),
                "until": f"{last.day} {last:%b}" if last else "", "moved_to": r["moved_to"], "moved_from": r["moved_from"]}

    open_ = [item(r) for r in rows if r["last_seen"] == newest]
    closed = sorted((item(r) for r in rows if r["last_seen"] != newest and r["last_seen"] >= month),
                    key=lambda i: i["last"], reverse=True)
    first = _parse_ts(min(r["first_seen"] for r in rows))
    return {"open": open_, "closed": closed, "new": sum(1 for i in open_ if i["new"]),
            "since": f"{first.day} {first:%b}" if first else "", "as_of": _when(newest, now),
            "current": newest >= common.iso_ago(hours=12)}


@app.route("/host/<path:mac>")
def host_history(mac):
    """The device page: everything about one device by MAC. Name and watch, whether it is
    live, findings, how LanWard knows what it is, whom it asks for, its mDNS services, the
    last 7 days of activity, what the latest scan found and every scan that caught it.
    A device no scan caught gets what listening heard of it."""
    mac_lc = mac.lower()
    if not MAC_PATH_RE.match(mac_lc):
        abort(400)
    conn = get_db()
    rows = conn.execute(
        "SELECT h.*, s.subnet, s.started_at FROM hosts h JOIN scans s ON h.scan_id = s.id "
        "WHERE h.mac = ? ORDER BY s.id DESC LIMIT 300", (mac_lc,)).fetchall()
    heard = conn.execute("SELECT MIN(first_seen) AS first, MAX(last_seen) AS last, "
                         "GROUP_CONCAT(DISTINCT source) AS sources FROM observations WHERE mac = ?",
                         (mac_lc,)).fetchone()
    if not rows and not heard["last"] and mac_lc not in _labels_map():
        conn.close()
        abort(404)
    names = _names_by_mac(conn)
    ip_by_mac, ip_to_mac = _own_ipv4_maps(conn)
    if rows:
        host = _with_scan_facts(decorate(rows[0]))
    else:       # never caught by a scan: build what we know from listening
        vendor = conn.execute("SELECT vendor FROM observations WHERE mac = ? AND vendor IS NOT NULL LIMIT 1",
                              (mac_lc,)).fetchone()
        host = _with_scan_facts(decorate({"mac": mac_lc, "ip": ip_by_mac.get(mac_lc), "scan_id": None,
                                          "vendor": (vendor[0] if vendor else None) or common.vendor_for(mac_lc),
                                          "hostname": names.get(mac_lc) if mac_lc not in _labels_map() else None,
                                          "ports": None, "findings": None}))
    # The model the device announces over mDNS, newest row first so the winner is deterministic. The shared
    # helper prefers a real model over an `md` platform word ("WEBOS"), unlike the old txt_model shortcut.
    model = None
    for r in conn.execute("SELECT details FROM observations WHERE source = 'mdns' AND mac = ? "
                          "ORDER BY last_seen DESC", (mac_lc,)):
        model = common.mdns_txt_model(common.details_dict(r["details"]).get("txt"))
        if model:
            break
    ip_names = {ip: names[m] for ip, m in ip_to_mac.items() if m in names}
    intel = _gather_device_intel(conn, host, {mac_lc: model} if model else {}, ip_names)
    activity = _device_activity(conn, mac_lc)
    ports = _port_history(conn, mac_lc)
    watch = next((w for w in watched_devices(conn) if w["mac"] == mac_lc), None)
    uptime_days = _uptime_days(watch["uptime"]) if watch else None
    latest_scan_id = conn.execute("SELECT MAX(id) FROM scans").fetchone()[0]
    conn.close()
    row = get_db().execute("SELECT full_checked_at, full_tried_at FROM port_checks WHERE mac = ?", (mac_lc,)).fetchone()
    days = common.setting("FULL_PORT_CHECK_DAYS").strip()
    host["port_check"] = (f"last {_when(row['full_checked_at'], datetime.now()).replace('Today ', 'today ')}"
                          if row and row["full_checked_at"] else
                          "tried, but it took too long; it is tried again on its next turn" if row and row["full_tried_at"]
                          else "off (Settings)" if days == "0"
                          else f"not yet: each device gets its turn within {common.plural(int(days) if days.isdigit() else 1, 'day')}")
    return render_template("host.html", mac=mac_lc, host=host, intel=intel, heard=heard, activity=activity, ports=ports,
                           watch=watch, uptime_days=uptime_days, latest_scan_id=latest_scan_id,
                           observations=[decorate(r) for r in rows])


# ────────────────────────────────────────────  what's running (2026-11-02)

# Traffic's "What's running": every open port of the latest scan, grouped by what it is (portid.py's answer). Each
# group: (key, title, what its subtitle says, the words in a port's name that put it there), checked in this order.
RUNNING_GROUPS = [
    ("ssh", "SSH logins", "the version from each one's own answer", ("ssh",)),
    ("files", "File and media sharing", "who shares files or media",
     ("nfs", "file sharing", "windows sharing", "rpc port", "media server", "ftp", "afp", "time machine", "smb")),
    ("remote", "Remote access", "remote desktop and screen sharing", ("remote desktop", "vnc", "screen sharing", "telnet")),
    ("data", "Databases", "databases reachable on your network", ("database", "redis", "memcache", "mongodb")),
    ("web", "Web pages", "the title from each page, else what its server calls itself",
     ("web page", "web server", "web proxy", "control page", "web")),
    ("devices", "Smart home and devices", "control and streaming ports",
     ("mqtt", "modbus", "sonos", "airplay", "rtsp", "camera", "chromecast", "print", "homekit", "ups", "upnp",
      "spotify", "shelly", "matter", "home assistant")),
    ("other", "Other services", "named, but none of the above", ()),
    ("unknown", "Not identified", "ports that didn't say what they are, and that nothing names", ()),
]
RUNNING_TITLES = {key: title for key, title, _, _ in RUNNING_GROUPS}


def service_group(what):
    """The RUNNING_GROUPS key for a port that portid.py named `what` (unknown when it named nothing)."""
    w = (what or "").lower()
    if not w:
        return "unknown"
    for key, _, _, words in RUNNING_GROUPS:
        if any(word in w for word in words):
            return key
    return "other"


def _port_rows(conn):
    """Every port in every device's history (open_ports_seen) with the device it belongs to, for the exports:
    {device, mac, ip, kind, port, open_now, what, how, sure, group, first_seen, last_seen, moved_from, moved_to}."""
    names, labels = _names_by_mac(conn), _labels_map()
    ip_by_mac, _ = _own_ipv4_maps(conn)
    scan = latest_lan_scan(conn)
    hosts = {(h["mac"] or "").lower(): h for h in map(decorate, get_scan_hosts(conn, scan["id"]))} if scan else {}
    rows = conn.execute("SELECT * FROM open_ports_seen ORDER BY mac, port").fetchall()
    newest = {}
    for r in rows:
        newest[r["mac"]] = max(newest.get(r["mac"], ""), r["last_seen"])
    out = []
    for r in rows:
        mac, h = r["mac"], hosts.get(r["mac"])
        out.append({"device": (labels.get(mac) or {}).get("label") or names.get(mac) or (h and h["hostname"]) or mac,
                    "mac": mac, "ip": (h and h["ip"]) or ip_by_mac.get(mac),
                    "kind": CATEGORY_LABELS.get(h["category"]) if h else None, "port": r["port"],
                    "open_now": r["last_seen"] == newest[mac], "what": r["what"], "how": r["how"],
                    "sure": None if r["what"] is None else bool(r["sure"]),
                    "group": RUNNING_TITLES[service_group(r["what"])],
                    "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                    "moved_from": r["moved_from"], "moved_to": r["moved_to"]})
    return out


PORT_CSV_FIELDS = [("Device", "device"), ("MAC", "mac"), ("IP", "ip"), ("Kind", "kind"), ("Port", "port"),
                   ("Open now", "open_now"), ("What it is", "what"), ("How LanWard knows", "how"),
                   ("Sure (else a guess)", "sure"), ("Group", "group"), ("First seen", "first_seen"),
                   ("Last seen", "last_seen"), ("Moved from", "moved_from"), ("Moved to", "moved_to")]


def _cert_time(text):
    """A certificate's notAfter ('May 14 14:08:14 2027 GMT') as a datetime, or None."""
    try:
        return datetime.strptime(" ".join(text.split()), "%b %d %H:%M:%S %Y GMT")
    except (TypeError, ValueError, AttributeError):
        return None


@app.route("/traffic/running")
def running():
    """Traffic's "What's running" (2026-11-02): every open port the latest scan of the LAN found, what each is and
    how LanWard knows (portid.py), grouped; the certificates of the secure pages; ?format=csv: every port in every
    device's history (the Settings export)."""
    conn = get_db()
    if request.args.get("format") == "csv":
        rows = _port_rows(conn)
        conn.close()
        return _csv_download("lanward-ports-and-services.csv", PORT_CSV_FIELDS, rows)
    scan = latest_lan_scan(conn)
    hosts = [decorate(r) for r in get_scan_hosts(conn, scan["id"])] if scan else []
    known = {}
    for r in conn.execute("SELECT mac, port, what, how, sure FROM open_ports_seen WHERE what IS NOT NULL"):
        known.setdefault(r["mac"], {})[r["port"]] = r
    conn.close()
    groups = {key: {} for key, *_ in RUNNING_GROUPS}
    certs, temporary, n_ports, devices_with = [], 0, 0, set()
    soon = datetime.now() + timedelta(days=30)
    for h in sorted(hosts, key=lambda h: _ip_sort_key(h["ip"])):
        mac = (h["mac"] or "").lower()
        if h["ports_unknown"] or not mac:
            continue
        ports = parse_json(h.get("open_ports"), [])
        web = parse_json(h.get("web_info"), {})
        dev = {"name": h["label"] or h["hostname"] or h["vendor"] or h["ip"], "ip": h["ip"], "cat": h["category"],
               "url": url_for("host_history", mac=mac)}
        for port in ports:
            n_ports += 1
            devices_with.add(mac)
            k = known.get(mac, {}).get(port)
            if not k and port >= common.EPHEMERAL_PORT:
                temporary += 1
                continue
            page = web.get(str(port)) or {}
            entry = groups[service_group(k and k["what"])].setdefault(
                (k["what"] if k else "", port),
                {"what": k["what"] if k else None, "how": k["how"] if k else None, "sure": bool(k and k["sure"]),
                 "port": port, "devices": [], "https": bool(page.get("tls")), "web": bool(page),
                 "login": page.get("login") or ("basic" if page.get("status") == 401 else None)})
            entry["devices"].append(dev)
        for port, page in web.items():
            cert = page.get("cert") or {}
            if cert.get("not_after"):
                until = _cert_time(cert["not_after"])
                certs.append({"device": dev, "port": port, "cn": cert.get("cn") or "(no name)",
                              "until": f"{until:%b %Y}" if until else cert["not_after"],
                              "soon": bool(until and until < soon), "sort": until or datetime.max})
    out = []
    for key, title, sub, _ in RUNNING_GROUPS:
        items = sorted(groups[key].values(), key=lambda e: (-len(e["devices"]), (e["what"] or "").lower(), e["port"]))
        if items:
            out.append({"key": key, "title": title, "sub": sub, "items": items,
                        "n": sum(len(e["devices"]) for e in items),
                        "n_devices": len({d["url"] for e in items for d in e["devices"]})})
    certs.sort(key=lambda c: c["sort"])
    # Web pages first and Not identified last, both full width; the groups between and the certificates pair up
    out.sort(key=lambda g: 0 if g["key"] == "web" else 2 if g["key"] == "unknown" else 1)
    return render_template("running.html", groups=out, certs=certs, temporary=temporary, n_ports=n_ports,
                           n_devices=len(devices_with), count={g["key"]: g["n"] for g in out}, scan=scan)


@app.route("/api/ports")
def api_ports():
    """Every port in every device's history: what it is, how LanWard knows, open now, since when (as the CSV)."""
    conn = get_db()
    rows = _port_rows(conn)
    conn.close()
    return {"updated": common.now_iso(), "ports": rows}


# ────────────────────────────────────────────  alerts

# The alerts timeline (2026-10-27): per alert kind (write_alert's kind=) its filter group, colour and icon.
ALERT_KINDS = {
    "offline": ("offline", "#e66767", "M4.5 10.5a11 11 0 0 1 15 0M7.5 13.8a6.5 6.5 0 0 1 9 0M12 20h.01M3 3l18 18"),
    "online": ("offline", "#3DDC5C", LINE_ICONS["network"]),
    "new_device": ("new", "#2DD4BF", "M12 3a9 9 0 1 1 0 18a9 9 0 1 1 0-18zM12 8v8M8 12h8"),
    "finding": ("security", "#fab219", "M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6l7-3zM12 8v5M12 16h.01"),
    "tls": ("security", "#9085e9", "M7 11V8a5 5 0 0 1 10 0v3M6 11h12a1 1 0 0 1 1 1v7a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-7a1 1 0 0 1 1-1z"),
    "gateway": ("security", "#e66767", "M5 13h14a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2zM7 16.5h.01M11 16.5h.01"
                                       "M8 9.5a6 6 0 0 1 8 0M5.5 7a9.5 9.5 0 0 1 13 0"),
    "ipv6_router": ("security", "#e66767", "M5 13h14a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2zM7 16.5h.01"
                                           "M11 16.5h.01M8 9.5a6 6 0 0 1 8 0M5.5 7a9.5 9.5 0 0 1 13 0"),
    "dhcp": ("security", "#e66767", "M12 3a9 9 0 1 1 0 18a9 9 0 1 1 0-18zM12 7.5v5M12 16h.01"),
    "ip_conflict": ("security", "#fab219", "M8 7h12l-3-3M16 17H4l3 3"),
    "scanning": ("security", "#fab219", "M12 3a9 9 0 1 1 0 18a9 9 0 1 1 0-18zM12 7a5 5 0 1 1 0 10a5 5 0 1 1 0-10zM12 12l5-5"),
    "firmware": ("firmware", "#5BA3F5", "M12 4v11M7.5 10.5L12 15l4.5-4.5M5 19h14"),
    "new_port": ("security", "#fab219", "M5 21V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v16M3 21h18M14.5 12h.01"),
    "ghost": ("ghost", "#7D8999", "M12 3a9 9 0 1 1 0 18a9 9 0 1 1 0-18zM9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6v.6M12 17h.01"),
}
ALERT_OTHER = ("other", "#7D8999", "M6 16V11a6 6 0 0 1 12 0v5l2 2H4zM10 21h4")
ALERT_FILTERS = [("offline", "Offline and back"), ("security", "Security"), ("new", "New devices"),
                 ("firmware", "Firmware"), ("ghost", "Nobody home"), ("other", "Other")]


@app.route("/alerts")
def alerts():
    """The alerts as a timeline, newest first, grouped by day; ?kind= one of ALERT_FILTERS shows only those,
    ?all=1 also the acknowledged info alerts, ?range= the period (PERIODS, 7 days by default; 2026-10-27).
    Alerts nobody has acknowledged show whatever the period."""
    conn = get_db()
    show_info = request.args.get("all") == "1"
    period, since = _period()
    where = "WHERE (created_at >= ? OR acknowledged = 0)" + ("" if show_info else " AND (severity <> 'info' OR acknowledged = 0)")
    rows = conn.execute(f"SELECT * FROM alerts {where} ORDER BY created_at DESC, id DESC LIMIT 500", (since,)).fetchall()
    unack = {r[0]: r[1] for r in conn.execute(
        "SELECT severity = 'info', COUNT(*) FROM alerts WHERE acknowledged = 0 GROUP BY severity = 'info'")}
    last_ack_at = conn.execute(
        "SELECT MAX(acknowledged_at) FROM alerts WHERE acknowledged = 1").fetchone()[0]
    conn.close()
    items = []
    for r in rows:
        a = dict(r)
        a["group"], a["color"], a["icon"] = ALERT_KINDS.get(a["kind"] or "", ALERT_OTHER)
        lines = [("• " + line[2:]) if line.startswith("- ") else line for line in (a["details"] or "").strip().splitlines()]
        a["head"], a["more"] = "\n".join(lines[:3]).strip(), "\n".join(lines[3:]).strip()
        a["more_lines"] = len([line for line in lines[3:] if line.strip()])
        items.append(a)
    conn = get_db()
    _preload_scans(conn, [a["scan_id"] for a in items])
    conn.close()
    groups = Counter(a["group"] for a in items)
    kind = request.args.get("kind") if request.args.get("kind") in groups else None
    filters = [{"key": k, "label": label, "n": groups[k], "color": next(
                   (c for g, c, _ in ALERT_KINDS.values() if g == k), ALERT_OTHER[1]),
                "icon": next((i for g, _, i in ALERT_KINDS.values() if g == k), ALERT_OTHER[2])}
               for k, label in ALERT_FILTERS if groups.get(k)]
    today = datetime.now().date()
    days = []
    for a in items:
        if kind and a["group"] != kind:
            continue
        t = _parse_ts(a["created_at"])
        label = "Today" if t and t.date() == today else "Yesterday" if t and (today - t.date()).days == 1 \
            else t.strftime("%A %d %B") if t else "Earlier"
        a["time"] = t.strftime("%H:%M") if t else ""
        if not days or days[-1]["label"] != label:
            days.append({"label": label, "items": []})
        days[-1]["items"].append(a)
    return render_template("alerts.html", days=days, filters=filters, kind=kind, total=len(items),
                           unack_count=unack.get(0, 0), unack_info=unack.get(1, 0),
                           last_ack_at=last_ack_at, show_info=show_info, current_range=period, ranges=PERIODS)


@app.route("/alerts/<int:alert_id>/ack", methods=["POST"])
def alert_ack(alert_id):
    conn = get_db()
    conn.execute("UPDATE alerts SET acknowledged = 1, acknowledged_at = ? WHERE id = ?",
                 (common.now_iso(), alert_id))
    conn.commit()
    conn.close()
    return redirect(url_for("alerts", all=request.form.get("all") or None, range=request.form.get("range") or None))


@app.route("/alerts/ack-all", methods=["POST"])
def alert_ack_all():
    conn = get_db()
    kind = request.form.get("kind") or None
    params = [common.now_iso()]
    where = "acknowledged = 0"
    if kind:                                  # scope to the active kind filter, not every alert in the period
        members = [k for k, v in ALERT_KINDS.items() if v[0] == kind]
        if members:
            where += " AND kind IN (%s)" % ",".join("?" * len(members))
            params += members
        else:
            kind = None
    conn.execute(f"UPDATE alerts SET acknowledged = 1, acknowledged_at = ? WHERE {where}", params)
    conn.commit()
    conn.close()
    return redirect(url_for("alerts", all=request.form.get("all") or None,
                            kind=kind or None, range=request.form.get("range") or None))


@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html"), 404


# ────────────────────────────────────────────  labels (= approving a device)

@app.route("/labels/set", methods=["POST"])
def label_set():
    mac = (request.form.get("mac") or "").strip().lower()
    label = (request.form.get("label") or "").strip()
    note = (request.form.get("note") or "").strip() or None
    watch = 1 if request.form.get("watch") == "on" else 0
    redirect_to = request.form.get("redirect_to") or url_for("home")
    # Back to a LanWard page only: "//host" is another site, and CR/LF would break the header.
    if not MAC_PATH_RE.match(mac) or not redirect_to.startswith("/") or redirect_to.startswith(("//", "/\\")) \
            or any(c in redirect_to for c in "\r\n"):
        abort(400)
    conn = get_db()
    if not label:
        conn.execute("DELETE FROM host_labels WHERE mac = ?", (mac,))
    else:
        now = common.now_iso()
        conn.execute(
            "INSERT INTO host_labels (mac, label, note, suppress_new_alert, watch_offline, "
            "created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?, ?) "
            "ON CONFLICT(mac) DO UPDATE SET label = excluded.label, note = excluded.note, "
            "watch_offline = excluded.watch_offline, updated_at = excluded.updated_at",
            (mac, label, note, watch, now, now))
    if not label or not watch:          # no name means no watch either
        conn.execute("DELETE FROM watch_state WHERE mac = ?", (mac,))
    conn.commit()
    conn.close()
    return redirect(redirect_to)


@app.route("/labels/<path:mac>/delete", methods=["POST"])
def label_delete(mac):
    mac = mac.lower()
    if not MAC_PATH_RE.match(mac):
        abort(400)
    conn = get_db()
    conn.execute("DELETE FROM host_labels WHERE mac = ?", (mac,))
    conn.execute("DELETE FROM watch_state WHERE mac = ?", (mac,))
    conn.commit()
    conn.close()
    return redirect(url_for("host_history", mac=mac))


# ────────────────────────────────────────────  devices (per-device cards)

APPLE_MODELS = common.APPLE_MODELS        # Apple board codes in mDNS TXT records (common.py)
WINDOWS_OPENSSH_VERSIONS = {
    "9.5": "Windows 11 23H2/24H2 / Server 2025", "9.4": "Windows 11 23H2",
    "8.6": "Windows 11 22H2 / Server 2022", "8.1": "Windows 10 22H2 / Server 2019",
    "8.0": "Windows 10 ~21H1", "7.7": "Windows 10 1809+",
}
# Offered only by Windows. Not _workstation._tcp: that is avahi's default on Linux
# (a Home Assistant VM or a Debian server announces it).
WINDOWS_MDNS_SERVICES = {
    "_dosvc._tcp": "Delivery Optimization (Windows)",
    "_microsoft_mcc._tcp": "Microsoft Connected Cache (Windows)",
}
# Devices identified as these are not Windows PCs even when their DHCP says "MSFT 5.0",
# which many gadgets copy (the Tapo camera does).
NOT_WINDOWS_CATEGORIES = {"camera", "iot", "media", "network", "phone", "printer", "server"}


def _friendly_device_name(host, txt_models):
    if host.get("label"):
        return host["label"]
    txt_model = txt_models.get((host.get("mac") or "").lower())
    if txt_model in APPLE_MODELS:
        return APPLE_MODELS[txt_model]
    for key in ("hostname", "http_title", "vendor", "ip"):
        if host.get(key) and host[key] not in ("-", "<local>"):
            return host[key]
    return "(unknown)"


def _detect_windows(host, mdns_details, dhcp_details):
    """Windows from passive signals: SSH banner, Windows-only mDNS services the device
    offers (looking for one says nothing), and the DHCP vendor class unless the device
    is clearly something else. Returns (version_guess, [evidence])."""
    signals, guess = [], None
    m = re.search(r"OpenSSH_for_Windows_(\d+\.\d+)", host.get("ssh_banner") or "", re.I)
    if m:
        guess = WINDOWS_OPENSSH_VERSIONS.get(m.group(1), f"Windows (OpenSSH {m.group(1)})")
        signals.append(f"SSH banner: OpenSSH for Windows {m.group(1)}")
    vc = (dhcp_details or {}).get("vendor_class", "")
    if vc.startswith("MSFT") and host.get("category") not in NOT_WINDOWS_CATEGORIES:
        signals.append(f"DHCP vendor class: {vc}")
        guess = guess or "Windows"
    for svc in set((mdns_details or {}).get("services_adv") or []) & set(WINDOWS_MDNS_SERVICES):
        signals.append(f"mDNS service: {svc}")
        guess = guess or "Windows"
    return guess, signals


def _status(last_seen):
    """live < 5 min < recent < 1 h < today < 24 h < week < 7 days < stale."""
    age = _age_seconds(last_seen)
    return ("unknown" if age is None else "live" if age < 300 else "recent" if age < 3600
            else "today" if age < 86400 else "week" if age < 7 * 86400 else "stale")


def _activity_24h(conn, mac=None):
    """{mac: packets heard per hour over the last 24 h, oldest first} from the activity table."""
    now_hour = datetime.now().replace(minute=0, second=0, microsecond=0)
    since = (now_hour - timedelta(hours=23)).strftime("%Y-%m-%dT%H")
    rows = conn.execute("SELECT mac, hour, n FROM activity WHERE hour >= ?" + (" AND mac = ?" if mac else ""),
                        (since, mac) if mac else (since,))
    out = {}
    for r in rows:
        ago = int((now_hour - datetime.strptime(r["hour"], "%Y-%m-%dT%H")).total_seconds() // 3600)
        if 0 <= ago < 24:
            out.setdefault(r["mac"], [0] * 24)[23 - ago] += r["n"]
    return out


def _spark_paths(counts, w=96, h=28):
    """24 hourly counts as a small area chart in a w x h box (smooth line and the area under it), scaled to the
    device's own busiest hour; None when nothing was heard."""
    if not counts or not any(counts):
        return None
    top = max(counts)
    line = _smooth([(i * w / (len(counts) - 1), h - 2 - n / top * (h - 6)) for i, n in enumerate(counts)])
    return {"line": line, "area": f"{line} L{w} {h} L0 {h} Z"}


def _latest_details(conn, mac, source):
    row = conn.execute("SELECT details FROM observations WHERE source = ? AND mac = ? "
                       "ORDER BY last_seen DESC LIMIT 1", (source, mac)).fetchone()
    return common.details_dict(row["details"]) if row else None


def _clean_fw(fv):
    """An mDNS/AirPlay firmware string without the AirPlay protocol prefix: "p20.97.2-81220" -> "97.2-81220"."""
    if not fv:
        return None
    return re.sub(r"^p\d+\.", "", str(fv)).strip() or None


def _os_label(md):
    """An OS name from an mDNS "md" TXT value, but only when it really is an OS (webOS, Tizen...) and not a
    model string or a list of numbers (Sonos keeps HomeKit category numbers in md)."""
    return common.MDNS_OS.get((str(md) if md else "").strip().lower())


def _gather_device_intel(conn, host, txt_models, ip_names):
    intel = dict(host)
    mac = (host.get("mac") or "").lower()
    intel["friendly_name"] = _friendly_device_name(host, txt_models)
    mdns_details = _latest_details(conn, mac, "mdns") if mac else None
    dhcp_details = _latest_details(conn, mac, "dhcp") if mac else None
    mdns_txt = (mdns_details or {}).get("txt")
    mdns_txt = mdns_txt if isinstance(mdns_txt, dict) else {}    # a legacy/corrupt non-dict txt is ignored

    chain = []
    if (host.get("tls_cert_cn") or "").strip("*. "):        # a bare "*" certificate names nothing
        chain.append(("TLS certificate", host["tls_cert_cn"]))
    if mac in txt_models:
        model = txt_models[mac]
        chain.append(("mDNS model", f"{model} = {APPLE_MODELS[model]}" if model in APPLE_MODELS else model))
    fw = _clean_fw(mdns_txt.get("fv"))
    if fw and fw not in (host.get("firmware") or "").split():   # as a whole token, not a substring of the scan's
        chain.append(("mDNS firmware", fw))
    os_name = _os_label(mdns_txt.get("md"))
    if os_name:
        chain.append(("Runs", os_name))
    win, win_signals = _detect_windows(host, mdns_details, dhcp_details)
    if win:
        chain.insert(0, ("Detected as", win))
    for key, label in (("http_title", "Web page title"), ("hostname", "Hostname"),
                       ("firmware", "Firmware"), ("ssh_banner", "SSH banner"), ("vendor", "Maker")):
        if host.get(key) and host[key] not in ("-", "<local>"):
            chain.append((label, host[key]))
    if dhcp_details and dhcp_details.get("fingerprint_match"):
        chain.append(("DHCP fingerprint", dhcp_details["fingerprint_match"]))
    if host.get("bridge_mac"):
        bridge = (_labels_map().get(host["bridge_mac"]) or {}).get("label") or host["bridge_mac"]
        chain.append(("Reached through", f"{bridge}: it bridges this device onto your network (SonosNet), so "
                                         "its traffic arrives under that device's MAC address"))
    chain += [("Windows signal", s) for s in win_signals]
    intel["chain"] = chain
    intel["is_random_mac"] = bool(mac and common.mac_is_randomized(mac))
    intel["services_adv"] = ((mdns_details or {}).get("services_adv") or [])[:8]
    intel["services_qry"] = ((mdns_details or {}).get("services_qry") or [])[:8]

    intel["last_seen"] = _heard_map(conn).get(mac) if mac else None
    intel["status"] = _status(intel["last_seen"])

    # The addresses it asks for most often per day. Not its own: a device checking that
    # nobody else uses its address is not talking to anyone.
    talks = []
    if mac:
        for r in conn.execute("SELECT ip, details, first_seen, last_seen, count FROM observations "
                              "WHERE source = 'arp_req' AND mac = ?", (mac,)):
            if r["ip"] in (common.details_dict(r["details"]).get("own_ip"), host.get("ip")):
                continue
            talks.append({"target_ip": r["ip"], "name": ip_names.get(r["ip"]),
                          "per_day": _per_day(r), "last_seen": r["last_seen"]})
    intel["talks_to"] = sorted(talks, key=lambda t: -t["per_day"])[:4]
    return intel


@app.route("/scans")
@app.route("/devices")
def devices():
    """Every device in one scan as a table: the latest scan, or ?scan=<id> for an earlier one.
    Each row says whether the device is live now, when it was last heard and how busy it was
    over the last 24 hours. ?sort=attention puts devices with findings or no name first."""
    conn = get_db()
    requested = request.args.get("scan", type=int)
    selected = conn.execute("SELECT * FROM scans WHERE id = ?", (requested,)).fetchone() \
        if requested is not None else None
    missing = requested if requested is not None and selected is None else None
    selected = selected or conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    hosts = [decorate(r) for r in get_scan_hosts(conn, selected["id"])] if selected else []
    heard = _heard_map(conn)
    spark = _activity_24h(conn)
    all_scans = conn.execute("SELECT id, started_at, host_count FROM scans ORDER BY id DESC").fetchall()
    conn.close()
    for h in hosts:
        mac = (h["mac"] or "").lower()
        h["last_heard"] = heard.get(mac)
        h["status"] = _status(h["last_heard"])
        h["spark"] = _spark_paths(spark.get(mac))
        serious = sum(1 for f in h["findings_list"] if f["severity"] != "info")
        h["attention"] = 6 * serious + 4 * (_nameable(h) and not h["label"]) + bool(h["findings_list"])
        h["look"] = bool(serious) or (_nameable(h) and not h["label"])
        h["tips"] = any(f["severity"] == "info" for f in h["findings_list"])
    attention = request.args.get("sort") == "attention"
    if attention:
        hosts.sort(key=lambda h: (-h["attention"], _ip_sort_key(h["ip"])))
    show = request.args.get("show") if request.args.get("show") in ("look", "tips") else None
    counts = {"all": len(hosts), "look": sum(h["look"] for h in hosts), "tips": sum(h["tips"] for h in hosts)}
    kpi = {
        "host_count": len(hosts),
        "live_count": sum(1 for h in hosts if h["status"] == "live"),
        "unlabeled": sum(1 for h in hosts if _nameable(h) and not h["label"]),
        "with_findings": sum(1 for h in hosts if any(f["severity"] != "info" for f in h["findings_list"])),
        "with_cert": sum(1 for h in hosts if (h.get("tls_cert_cn") or "").strip("*. ")),
        "private_macs": sum(1 for h in hosts if h["mac"] and common.mac_is_randomized(h["mac"])),
        "category_dist": Counter(h["category"] for h in hosts),
    }
    active_cat = request.args.get("cat")
    if active_cat not in kpi["category_dist"]:
        active_cat = None
    if show:
        hosts = [h for h in hosts if h[show]]
    if active_cat:
        hosts = [h for h in hosts if h["category"] == active_cat]
    from scan import PORT_LABELS
    return render_template("devices.html", selected=selected, hosts=hosts, kpi=kpi, scans=all_scans,
                           n_ports=len(PORT_LABELS), attention=attention, missing=missing, show=show,
                           active_cat=active_cat, counts=counts)


# ────────────────────────────────────────────  flows (relationships)

MDNS_SERVICE_NAMES = common.MDNS_SERVICE_NAMES     # also names announced ports in alerts (portid.py)
MDNS_META_SERVICES = {"_dns-sd._udp"}     # "list every service": every device asks it
# What a service is, in plain words, for the Services view (2026-10-27)
MDNS_SERVICE_WHAT = {
    "_airplay._tcp": "Apple screen and video sharing", "_raop._tcp": "Speakers Apple devices can play music to",
    "_googlecast._tcp": "Cast video and music from a phone", "_spotify-connect._tcp": "Play from the Spotify app",
    "_sonos._tcp": "Sonos speakers", "_hap._tcp": "Apple Home accessories",
    "_hap._udp": "Apple Home accessories over Thread", "_homekit._tcp": "Apple Home",
    "_companion-link._tcp": "Apple devices finding each other (Handoff, AirDrop)",
    "_sleep-proxy._udp": "Wakes sleeping Apple devices when they are needed",
    "_device-info._tcp": "A device telling others its model", "_home-assistant._tcp": "Home Assistant, for its apps to find",
    "_esphomelib._tcp": "ESPHome devices, for Home Assistant", "_shelly._tcp": "Shelly plugs, relays and meters",
    "_hue._tcp": "Philips Hue lights", "_matter._tcp": "Smart-home devices that speak Matter",
    "_matterc._udp": "A Matter device waiting to be added", "_meshcop._udp": "Joins Thread devices to the network",
    "_trel._udp": "Thread devices talking over Wi-Fi", "_mqtt._tcp": "Messages between smart-home devices",
    "_http._tcp": "A web page", "_https._tcp": "A web page", "_ssh._tcp": "Remote command-line login",
    "_sftp-ssh._tcp": "File transfer over SSH", "_smb._tcp": "Shared folders (Windows)",
    "_afpovertcp._tcp": "Shared folders (Mac)", "_adisk._tcp": "A backup disk for Macs", "_rfb._tcp": "Remote screen",
    "_ipp._tcp": "Printing", "_ipps._tcp": "Printing", "_printer._tcp": "Printing", "_pdl-datastream._tcp": "Printing",
    "_uscan._tcp": "Scanning documents", "_workstation._tcp": "A computer announcing itself",
}
# What a service is, in plain words, for the Services view (2026-10-27)
MDNS_SERVICE_WHAT = {
    "_airplay._tcp": "Apple screen and video sharing", "_raop._tcp": "Speakers Apple devices can play music to",
    "_googlecast._tcp": "Cast video and music from a phone", "_spotify-connect._tcp": "Play from the Spotify app",
    "_sonos._tcp": "Sonos speakers", "_hap._tcp": "Apple Home accessories",
    "_hap._udp": "Apple Home accessories over Thread", "_homekit._tcp": "Apple Home",
    "_companion-link._tcp": "Apple devices finding each other (Handoff, AirDrop)",
    "_sleep-proxy._udp": "Wakes sleeping Apple devices when they are needed",
    "_device-info._tcp": "A device telling others its model", "_home-assistant._tcp": "Home Assistant, for its apps to find",
    "_esphomelib._tcp": "ESPHome devices, for Home Assistant", "_shelly._tcp": "Shelly plugs, relays and meters",
    "_hue._tcp": "Philips Hue lights", "_matter._tcp": "Smart-home devices that speak Matter",
    "_matterc._udp": "A Matter device waiting to be added", "_meshcop._udp": "Joins Thread devices to the network",
    "_trel._udp": "Thread devices talking over Wi-Fi", "_mqtt._tcp": "Messages between smart-home devices",
    "_http._tcp": "A web page", "_https._tcp": "A web page", "_ssh._tcp": "Remote command-line login",
    "_sftp-ssh._tcp": "File transfer over SSH", "_smb._tcp": "Shared folders (Windows)",
    "_afpovertcp._tcp": "Shared folders (Mac)", "_adisk._tcp": "A backup disk for Macs", "_rfb._tcp": "Remote screen",
    "_ipp._tcp": "Printing", "_ipps._tcp": "Printing", "_printer._tcp": "Printing", "_pdl-datastream._tcp": "Printing",
    "_uscan._tcp": "Scanning documents", "_workstation._tcp": "A computer announcing itself",
}

# Traffic's service cards: (colour, icon) by a piece of the service name, first match wins; "" for the rest.
SERVICE_LOOKS = {
    "_airplay": ("#5BA3F5", "M5 17H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h16a1 1 0 0 1 1 1v11a1 1 0 0 1-1 1h-1M12 15l5 6H7z"),
    "_googlecast": ("#5BA3F5", "M5 17H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h16a1 1 0 0 1 1 1v11a1 1 0 0 1-1 1h-1M12 15l5 6H7z"),
    "_raop": ("#c98500", "M6 4h12a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1zM12 13a3 3 0 1 1 0 6a3 3 0 1 1 0-6zM12 8h.01"),
    "_sonos": ("#c98500", "M6 4h12a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1zM12 13a3 3 0 1 1 0 6a3 3 0 1 1 0-6zM12 8h.01"),
    "_spotify": ("#3DDC5C", "M9 18V6l11-2v12M9 18a3 3 0 1 1-6 0a3 3 0 1 1 6 0zM20 16a3 3 0 1 1-6 0a3 3 0 1 1 6 0z"),
    "_home-assistant": ("#2DD4BF", "M3 11l9-7 9 7M5 10v10h14V10M10 20v-6h4v6"),
    "_hap": ("#fab219", "M3 11l9-7 9 7M5 10v10h14V10M12 13.5h.01"),
    "_homekit": ("#fab219", "M3 11l9-7 9 7M5 10v10h14V10M12 13.5h.01"),
    "_matter": ("#2DD4BF", "M12 3l8 4.5v9L12 21l-8-4.5v-9zM12 12l8-4.5M12 12v9M12 12L4 7.5"),
    "_meshcop": ("#2DD4BF", "M12 3l8 4.5v9L12 21l-8-4.5v-9zM12 12l8-4.5M12 12v9M12 12L4 7.5"),
    "_trel": ("#2DD4BF", "M12 3l8 4.5v9L12 21l-8-4.5v-9zM12 12l8-4.5M12 12v9M12 12L4 7.5"),
    "_shelly": ("#d55181", LINE_ICONS["iot"]),
    "_esphome": ("#d55181", LINE_ICONS["iot"]),
    "_hue": ("#d55181", "M9 18h6M10 21h4M12 3a6 6 0 0 0-4 10.5c.7.7 1 1.5 1 2.5h6c0-1 .3-1.8 1-2.5A6 6 0 0 0 12 3z"),
    "_companion-link": ("#9085e9", "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"),
    "_device-info": ("#9085e9", "M12 3a9 9 0 1 1 0 18a9 9 0 1 1 0-18zM12 11v5M12 7.5h.01"),
    "_smb": ("#9085e9", "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"),
    "_afpovertcp": ("#9085e9", "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"),
    "_adisk": ("#9085e9", "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"),
    "_ipp": ("#c98500", LINE_ICONS["printer"]),
    "_printer": ("#c98500", LINE_ICONS["printer"]),
    "_pdl-datastream": ("#c98500", LINE_ICONS["printer"]),
    "_uscan": ("#c98500", LINE_ICONS["printer"]),
    "ssh": ("#7D8999", "M4 5h16a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1zM7 10l3 2-3 2M12 15h5"),
    "_rfb": ("#7D8999", LINE_ICONS["computer"]),
    "_workstation": ("#7D8999", LINE_ICONS["computer"]),
    "_http": ("#5BA3F5", "M12 3a9 9 0 1 1 0 18a9 9 0 1 1 0-18zM3 12h18M12 3c2.5 2.5 3.5 5.5 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-5.5-3.5-9s1-6.5 3.5-9z"),
    "_mqtt": ("#2DD4BF", "M5 12a7 7 0 0 1 14 0M8.5 12a3.5 3.5 0 0 1 7 0M12 12v8"),
    "": ("#7D8999", "M12 3a9 9 0 1 1 0 18a9 9 0 1 1 0-18zM12 9a3 3 0 1 1 0 6a3 3 0 1 1 0-6z"),
}


def _names_by_mac(conn):
    """Best name per MAC for pages built from raw observations: your label, else the DHCP
    hostname, else an Apple model from mDNS."""
    names = {}
    for r in conn.execute("SELECT mac, source, hostname, details FROM observations "
                          "WHERE mac IS NOT NULL AND source IN ('dhcp', 'mdns') ORDER BY last_seen"):
        mac = r["mac"].lower()
        if r["source"] == "dhcp" and r["hostname"]:
            names[mac] = r["hostname"]
        elif r["source"] == "mdns" and mac not in names:
            model = common.details_dict(r["details"]).get("txt_model")
            if model in APPLE_MODELS:
                names[mac] = APPLE_MODELS[model]
    names.update({mac: rec["label"] for mac, rec in _labels_map().items()})
    return names


# The periods Traffic and Alerts offer (2026-10-27: "All" became the last 365 days; what was heard is kept 366 days).
PERIODS = [("day", "24 hours", 1), ("week", "7 days", 7), ("month", "30 days", 30), ("year", "365 days", 365)]
PER_PAGE = 20               # rows per page on the paged Traffic lists (flows, observations)


def _period(arg=None):
    """The period ?range= (or `arg`) picks, 7 days unless it names one: (its slug, the ISO time it starts at)."""
    days = {slug: d for slug, _, d in PERIODS}
    slug = (arg if arg is not None else request.args.get("range") or "").lower()
    slug = slug if slug in days else "week"
    return slug, common.iso_ago(days=days[slug])


def _traffic_range():
    """The Traffic views' period: (its slug, an SQL condition on last_seen, its params)."""
    slug, since = _period()
    return slug, "AND last_seen >= ?", (since,)


def _period_label(slug):
    return next((label for s, label, _ in PERIODS if s == slug), "7 days")


def _measured_since(slug):
    """The first day (YYYY-MM-DD) of the chosen period: that many calendar days back, today included
    (so "7 days" is today and the six days before it, "24 hours" is today)."""
    days = next((d for s, _, d in PERIODS if s == slug), 7)
    return (datetime.now().date() - timedelta(days=days - 1)).isoformat()


def _measured_counts(conn, cutoff_day):
    """{(source, mac, ip): n} of really-measured per-day counts (observation_counts) from cutoff_day to today.
    mac/ip are '' where the observation has none, matching how the monitor stores them."""
    return {(r["source"], r["mac"], r["ip"]): r["n"] for r in conn.execute(
        "SELECT source, mac, ip, SUM(n) AS n FROM observation_counts WHERE day >= ? GROUP BY source, mac, ip",
        (cutoff_day,))}


def _period_total(measured, source, mac, ip):
    """How many times this (source, mac, ip) was really counted in the chosen period — the measured total
    only, no estimate or averaging. Zero where there is no per-day data yet; the longer periods fill in as
    days of counting accumulate (per-day counting began 2026-10-29)."""
    return measured.get((source, mac or "", ip or ""), 0)


@app.route("/flows")
def flows():
    """Device relationships visible on a switched LAN without port mirroring: ARP requests ("X asks for Y").
    The mDNS services are their own view since 2026-10-27 (network_services)."""
    range_arg, time_clause, params = _traffic_range()
    me = common.own_mac()

    conn = get_db()
    # LanWard's own sweep asks for every address; leave it out before ranking, not after.
    arp_rows = conn.execute(
        f"SELECT mac, ip AS target_ip, vendor, details, first_seen, last_seen, count FROM observations "
        f"WHERE source = 'arp_req' AND mac IS NOT NULL AND mac IS NOT ? {time_clause}", (me, *params)).fetchall()
    # Newest answer wins when an address has changed hands.
    ip_to_device = {r["ip"]: (r["mac"], r["vendor"]) for r in conn.execute(
        "SELECT ip, mac, vendor FROM observations WHERE source = 'arp' AND ip IS NOT NULL ORDER BY last_seen")}
    mac_to_ip, _ = _own_ipv4_maps(conn)
    names = _names_by_mac(conn)
    from alerts import ghost_targets
    ghosts = ghost_targets(conn)
    heard = _heard_map(conn)
    gw_ip = gateway_status(conn)["ip"]
    scan = latest_lan_scan(conn)
    cats = {(h["mac"] or "").lower(): h["category"] for h in map(decorate, get_scan_hosts(conn, scan["id"]))} if scan else {}
    measured = _measured_counts(conn, _measured_since(range_arg))
    conn.close()

    arp_flows = []
    for r in arp_rows:
        d = dict(r)
        mac = r["mac"].lower()
        own_ip = common.details_dict(r["details"]).get("own_ip")
        if r["target_ip"] in (own_ip, mac_to_ip.get(mac)):    # checking its own address, not talking to anyone
            continue
        d["asker_ip_borrowed"] = not own_ip and bool(mac_to_ip.get(mac))
        d["asker_ip"] = own_ip or mac_to_ip.get(mac)
        d["asker_name"] = names.get(mac)
        target = ip_to_device.get(r["target_ip"])
        d["target_mac"], d["target_vendor"] = target if target else (None, None)
        d["target_name"] = names.get((d["target_mac"] or "").lower())
        # period_est is how many requests were really counted in the chosen period (observation_counts);
        # per_day stays the all-time average, shown separately as context.
        d["per_day"] = _per_day(r)
        d["period_est"] = _period_total(measured, "arp_req", r["mac"], r["target_ip"])
        arp_flows.append(d)
    arp_flows.sort(key=lambda d: d["period_est"], reverse=True)
    arp_total = len(arp_flows)
    period_label = _period_label(range_arg)
    if request.args.get("format") == "csv":
        for d in arp_flows:
            d["per_day_rounded"], d["in_period"] = round(d["per_day"], 1), round(d["period_est"])
        return _csv_download(f"lanward-who-asks-for-whom-{range_arg}.csv", [
            ("asker", "asker_name"), ("asker_mac", "mac"), ("asker_ip", "asker_ip"), ("asker_maker", "vendor"),
            ("asks_for", "target_name"), ("asks_for_mac", "target_mac"), ("asks_for_ip", "target_ip"),
            ("in_period", "in_period"), ("per_day_all_time", "per_day_rounded"), ("times_all_time", "count"),
            ("first_seen", "first_seen"), ("last_seen", "last_seen")],
            arp_flows)
    top = max(arp_flows[0]["period_est"], 1) if arp_flows else 1    # busiest overall, for the bars (linear scale)
    pages = max(1, math.ceil(arp_total / PER_PAGE))
    page = min(max(1, request.args.get("page", type=int) or 1), pages)
    start = (page - 1) * PER_PAGE
    arp_flows = arp_flows[start:start + PER_PAGE]
    for d in arp_flows:
        d["asker_cat"] = cats.get(d["mac"].lower()) or classify(d["vendor"], None, None, d["asker_name"])
        target = (d["target_mac"] or "").lower()
        d["target_cat"] = cats.get(target) or (classify(d["target_vendor"], None, None, d["target_name"]) if target else "other")
        d["bar"] = max(2.0, round(100 * max(0.0, d["period_est"]) / top, 1)) if d["period_est"] else 0
        first = _parse_ts(d["first_seen"])
        d["since"] = f"{first:%d %b}" if first else "-"
        age = _age_seconds(heard.get(target))
        d["note"], d["odd"] = (("nobody home for a week", True) if d["target_ip"] in ghosts
                               else ("the router", False) if d["target_ip"] == gw_ip
                               else ("no device answers for it", True) if not target
                               else (f"last heard {_humanise_age(heard[target])}", False) if age and age > 3600
                               else ("", False))
        # What a tap on the row says (2026-10-27: on a phone there is no hover)
        asker, whom = d["asker_name"] or d["vendor"] or d["mac"], d["target_name"] or d["target_ip"]
        d["detail"] = (f"{d['period_est']:,.0f} in the last {period_label} "
                       f"(~{d['per_day']:,.0f} a day overall since {d['since']}); last asked {_humanise_age(d['last_seen'])}.")
        d["why"] = (f"Nobody has used {d['target_ip']} for a week, but {asker} keeps asking for it."
                    if d["target_ip"] in ghosts
                    else f"No device answers for {d['target_ip']}: {asker} keeps asking for something that isn't there."
                    if not target
                    else f"{whom} was last heard {_humanise_age(heard[target])}: {asker} keeps asking for something "
                         f"that is off or gone." if age and age > 86400 else "")

    return render_template("flows.html", arp_flows=arp_flows, arp_total=arp_total, period_label=period_label,
                           page=page, pages=pages, start=start, per_page=PER_PAGE,
                           current_range=range_arg, ranges=PERIODS)


@app.route("/services")
def network_services():
    """Traffic's Services view (2026-10-27; it was under "Who talks to whom"): which mDNS services the devices
    offered in the period, and who looked for each."""
    range_arg, time_clause, params = _traffic_range()
    conn = get_db()
    mdns_rows = conn.execute(f"SELECT mac, ip, vendor, details FROM observations "
                             f"WHERE source = 'mdns' {time_clause}", params).fetchall()
    names = _names_by_mac(conn)
    scan = latest_lan_scan(conn)
    cats = {(h["mac"] or "").lower(): h["category"] for h in map(decorate, get_scan_hosts(conn, scan["id"]))} if scan else {}
    conn.close()

    offers, wants, devices = {}, {}, {}
    for r in mdns_rows:
        if not r["mac"]:
            continue
        mac = r["mac"].lower()
        det = common.details_dict(r["details"])
        dev = devices.setdefault(mac, {"mac": mac, "name": names.get(mac), "vendor": r["vendor"], "ip": None})
        if r["ip"] and ":" not in r["ip"]:
            dev["ip"] = r["ip"]
        for svc in det.get("services_adv") or []:
            offers.setdefault(svc, set()).add(mac)
        for svc in det.get("services_qry") or []:
            wants.setdefault(svc, set()).add(mac)

    def by_name(macs):
        return sorted((devices[m] for m in macs), key=lambda d: (d["name"] or "~", d["mac"]))
    services = sorted(
        ({"service": svc, "label": MDNS_SERVICE_NAMES.get(svc), "what": MDNS_SERVICE_WHAT.get(svc),
          "offered": by_name(macs), "wanted": by_name(wants.get(svc, set()) - macs),
          "look": next((v for k, v in SERVICE_LOOKS.items() if k in svc), SERVICE_LOOKS[""])}
         for svc, macs in offers.items() if svc not in MDNS_META_SERVICES),
        key=lambda s: (s["label"] is None, (s["label"] or s["service"]).lower()))
    for svc in services:
        for d in svc["offered"]:
            d["cat"] = cats.get(d["mac"]) or classify(d["vendor"], None, None, d["name"])
    # Optional filter (the header search links here with ?q=): a service whose name or type matches, or
    # that a matching device offers or looks for.
    q = request.args.get("q", "").strip()
    if q:
        ql = q.lower()

        def dev_matches(d):
            return any(ql in (v or "").lower() for v in (d.get("name"), d.get("vendor"), d.get("mac"), d.get("ip")))
        services = [s for s in services if ql in (s["label"] or "").lower() or ql in s["service"].lower()
                    or any(dev_matches(d) for d in s["offered"] + s["wanted"])]
    if request.args.get("format") == "csv":
        def names(devs):
            return "; ".join(d["name"] or d["vendor"] or d["mac"] for d in devs)
        return _csv_download(f"lanward-services-{range_arg}.csv", [
            ("service", "label"), ("what_it_is", "what"), ("type", "service"), ("offered_by", "offered_names"),
            ("looked_for_by", "wanted_names")],
            [{**s, "offered_names": names(s["offered"]), "wanted_names": names(s["wanted"])} for s in services])
    return render_template("services.html", services=services, current_range=range_arg, ranges=PERIODS, q=q)


# ────────────────────────────────────────────  passive observations

# "Everything heard" (2026-10-27): per kind of observation a plain name, colour and icon, and (OBS_TECH) the
# technical name shown small beside it.
OBS_KINDS = {
    "arp": ("Says where it is", "#5BA3F5", "M9 14L4 9l5-5M4 9h11a5 5 0 0 1 0 10h-3"),
    "arp_req": ("Looks for a device", "#2DD4BF", "M11 4a7 7 0 1 1 0 14a7 7 0 1 1 0-14zM20 20l-4-4"),
    "dhcp": ("Asks for an address", "#199e70", "M4 6h16a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1zM7 10h5M7 14h8"),
    "dhcp_server": ("Hands out addresses", "#fab219", LINE_ICONS["server"]),
    "mdns": ("Announces what it offers", "#9085e9", "M12 12h.01M8.5 15.5a5 5 0 0 1 0-7M15.5 8.5a5 5 0 0 1 0 7M5.6 18.4a9 9 0 0 1 0-12.8M18.4 5.6a9 9 0 0 1 0 12.8"),
    "lldp": ("Switch or access point", "#d95926", LINE_ICONS["network"]),
    "cdp": ("Switch or access point", "#d95926", LINE_ICONS["network"]),
    "netbios": ("Windows name", "#e66767", LINE_ICONS["computer"]),
    "wsd": ("Shows itself to Windows", "#7D8999", LINE_ICONS["computer"]),
}
OBS_TECH = {"arp": "ARP", "arp_req": "ARP", "dhcp": "DHCP", "dhcp_server": "DHCP", "mdns": "mDNS", "lldp": "LLDP",
            "cdp": "CDP", "netbios": "NetBIOS", "wsd": "WS-Discovery"}


def _obs_said(d, names, ip_to_mac):
    """What one observation says, in words, and a few details as chips."""
    det, src = d["details_parsed"], d["source"]
    if src == "arp":
        return f"Answers for {d['ip'] or 'its address'}", []
    if src == "arp_req":
        target = names.get(ip_to_mac.get(d["asks_for"] or "", ""))
        return f"Asks who has {d['asks_for']}" + (f" ({target})" if target else ""), []
    if src == "dhcp":
        chips = [c for c in (det.get("vendor_class"), det.get("fingerprint_match")) if c]
        return ("Asks the router for an address" + (f", {det['requested_ip']}" if det.get("requested_ip") else "")
                + (f", as {d['hostname']}" if d.get("hostname") else "")), chips
    if src == "dhcp_server":
        return f"Hands out addresses (server {det.get('server_id') or d['ip'] or '?'})", []
    if src == "mdns":
        offers = [MDNS_SERVICE_NAMES.get(x, x) for x in det.get("services_adv") or [] if x not in MDNS_META_SERVICES]
        asks = [x for x in det.get("services_qry") or [] if x not in MDNS_META_SERVICES]
        model = det.get("txt_model")
        text = (f"Offers {', '.join(offers[:3])}{f' and {len(offers) - 3} more' if len(offers) > 3 else ''}" if offers
                else f"Looks for {common.plural(len(asks), 'kind')} of service" if asks else "Announces itself")
        return text, ([APPLE_MODELS.get(model, model)] if model else [])
    if src in ("lldp", "cdp"):
        return (f"A switch or access point announcing itself{': ' + d['hostname'] if d.get('hostname') else ''}",
                [f"port {det['port_desc']}"] if det.get("port_desc") else [])
    if src == "netbios":
        return (f"Windows / Samba name {d.get('hostname') or '?'}",
                [c for c in (f"Windows {det['os_version']}" if det.get("os_version") else None, det.get("comment")) if c])
    if src == "wsd":
        return "Announces itself to Windows computers", [t.split(":")[-1] for t in (det.get("Types") or "").split()][:3]
    return "", [f"{k}: {v}" for k, v in list(det.items())[:3]]


@app.route("/observations")
def observations():
    conn = get_db()
    source_filter = request.args.get("source", "").strip().lower()
    q = request.args.get("q", "").strip()
    range_arg, time_clause, range_params = _traffic_range()
    # LanWard's own sweep asks for every address on the LAN; it says nothing about other devices.
    where, params = f"WHERE NOT (source = 'arp_req' AND mac IS ?) {time_clause}", [common.own_mac(), *range_params]
    if q:
        # Search across every page: device name/label, MAC, address, maker, and what it said (details JSON).
        where += f" AND ({_OBS_SEARCH})"
        params += [_like(q)] * 6
    totals = {r["source"]: r["n"] for r in conn.execute(
        f"SELECT source, COUNT(*) AS n FROM observations {where} GROUP BY source ORDER BY source", params)}
    if source_filter:
        where, params = where + " AND source = ?", params + [source_filter]
    as_csv = request.args.get("format") == "csv"
    shown_of = totals.get(source_filter, 0) if source_filter else sum(totals.values())
    pages = max(1, math.ceil(shown_of / PER_PAGE))
    page = min(max(1, request.args.get("page", type=int) or 1), pages)
    start = (page - 1) * PER_PAGE
    limit = "" if as_csv else f" LIMIT {PER_PAGE} OFFSET {start}"
    rows = conn.execute(f"SELECT * FROM observations {where} ORDER BY last_seen DESC{limit}", params).fetchall()
    ip_by_mac, ip_to_mac = _own_ipv4_maps(conn)
    names = _names_by_mac(conn)
    scan = latest_lan_scan(conn)
    cats = {(h["mac"] or "").lower(): h["category"] for h in map(decorate, get_scan_hosts(conn, scan["id"]))} if scan else {}
    measured = _measured_counts(conn, _measured_since(range_arg))
    conn.close()
    obs = []
    period_label = _period_label(range_arg)
    for r in rows:
        d = dict(r)
        d["period_est"] = _period_total(measured, r["source"], r["mac"], r["ip"])
        det = d["details_parsed"] = common.details_dict(d.get("details"))
        mac = (d.get("mac") or "").lower()
        d["ip"], d["ip_note"] = common.own_ip_of(d["source"], r["ip"], det), None
        if d["source"] == "dhcp" and r["ip"] in (None, "", "0.0.0.0") and d["ip"]:
            d["ip_note"] = "Requested from the router (the request itself comes from 0.0.0.0)"
        if not d["ip"] and ip_by_mac.get(mac):
            d["ip"], d["ip_note"] = ip_by_mac[mac], "From another observation of this device"
        if d["source"] == "arp_req":
            d["asks_for"] = r["ip"]
            d["asks_for_name"] = names.get(ip_to_mac.get(r["ip"], ""))
        d["name"] = names.get(mac) or d.get("hostname") or d.get("vendor") or (
            "Private MAC" if mac and common.mac_is_randomized(mac) else mac or d["ip"] or "unknown")
        d["cat"] = cats.get(mac) or classify(d.get("vendor"), None, d.get("hostname"), names.get(mac))
        d["kind"] = OBS_KINDS.get(d["source"], (d["source"], "#7D8999", LINE_ICONS["other"]))
        d["tech"] = OBS_TECH.get(d["source"], "")
        d["said"], d["chips"] = _obs_said(d, names, ip_to_mac)
        first = _parse_ts(d["first_seen"])
        d["since"] = f"{first:%d %b}" if first else ""
        obs.append(d)
    if as_csv:
        for d in obs:
            d["kind_name"], d["chips_text"] = d["kind"][0], "; ".join(d["chips"])
            d["in_period"] = round(d["period_est"])
        return _csv_download(f"lanward-everything-heard-{range_arg}{'-' + source_filter if source_filter else ''}.csv", [
            ("device", "name"), ("mac", "mac"), ("ip", "ip"), ("kind", "kind_name"), ("protocol", "tech"),
            ("what_it_said", "said"), ("details", "chips_text"), ("in_period", "in_period"),
            ("times_all_time", "count"), ("first_seen", "first_seen"), ("last_seen", "last_seen")], obs)
    kinds = [{"source": src, "n": n, "kind": OBS_KINDS.get(src, (src, "#7D8999", LINE_ICONS["other"])),
              "tech": OBS_TECH.get(src, "")} for src, n in totals.items()]
    return render_template("observations.html", observations=obs, totals=totals, kinds=kinds, q=q,
                           active_source=source_filter, shown_of=shown_of, period_label=period_label,
                           page=page, pages=pages, start=start, current_range=range_arg, ranges=PERIODS,
                           unknown_source=bool(source_filter) and source_filter not in totals)


# ────────────────────────────────────────────  run scan


def is_scan_running():
    """True if the scan lock names a live (non-zombie) scan.py process."""
    if _scan_proc is not None:
        _scan_proc.poll()                       # reap our own finished child
    try:
        pid = int(common.SCAN_LOCK.read_text().splitlines()[0].strip())
    except (OSError, ValueError, IndexError):
        return False
    proc = Path(f"/proc/{pid}")
    try:
        state = next((l for l in (proc / "status").read_text().splitlines() if l.startswith("State:")), "")
        cmdline = (proc / "cmdline").read_bytes().decode("utf-8", "replace")
    except OSError:
        return False
    return "Z" not in state and "X" not in state and "scan.py" in cmdline


def _scan_info():
    """(subnet, log_text) for the running or latest scan, from the scan lock and the newest log file."""
    subnet, log_file = "", None
    try:
        parts = common.SCAN_LOCK.read_text().strip().split("\n")
        subnet = parts[2] if len(parts) >= 3 else ""
        log_file = Path(parts[1]) if len(parts) >= 2 else None
    except OSError:
        pass
    if log_file is None:
        logs = sorted(common.SCAN_LOG_DIR.glob("*.log")) if common.SCAN_LOG_DIR.exists() else []
        log_file = logs[-1] if logs else None
    log_text = ""
    if log_file:
        try:
            log_text = log_file.read_text(errors="replace")[-8000:]
        except OSError:
            pass
    return subnet, log_text


def _start_scan():
    """Start a background scan of the network LanWard is on (common.SUBNET) — no user-supplied range, so a
    typo can't point the port check at the internet. Returns an error string, or None on success / already
    running. The subnet is changed in Settings → Network."""
    global _scan_proc
    if is_scan_running():
        return None
    subnet = common.SUBNET
    if not subnet:
        return "LanWard hasn't found your network yet — set it in Settings → Network, then try again."
    common.SCAN_LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = common.SCAN_LOG_DIR / f"{time.strftime('%Y%m%d-%H%M%S')}.log"
    _scan_proc = subprocess.Popen(
        [sys.executable, str(common.ROOT / "scan.py"), "--subnet", subnet, "--log", str(log_file)],
        cwd=common.ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL, start_new_session=True,
    )
    common.SCAN_LOCK.write_text(f"{_scan_proc.pid}\n{log_file}\n{subnet}\n")
    return None


def _stop_scan():
    """Stop the running scan: terminate scan.py and its children (it starts a new session, so its pid is
    the process-group leader) and clear the lock. No-op if nothing is running."""
    global _scan_proc
    pid = None
    try:
        pid = int(common.SCAN_LOCK.read_text().splitlines()[0].strip())
    except (OSError, ValueError, IndexError):
        pass
    if pid:
        for kill in (lambda: os.killpg(os.getpgid(pid), signal.SIGTERM), lambda: os.kill(pid, signal.SIGTERM)):
            try:
                kill()
                break
            except (ProcessLookupError, PermissionError, OSError, AttributeError):
                continue
    if _scan_proc is not None:
        try:
            _scan_proc.terminate()
        except (OSError, ValueError):
            pass
        _scan_proc = None
    try:
        common.SCAN_LOCK.unlink()
    except OSError:
        pass


@app.route("/scan/dialog")
def scan_dialog():
    """The Run scan popup: a confirm when idle, live progress while a scan runs, a stop confirmation when
    ?confirm=stop."""
    subnet, log_text = _scan_info()
    return render_template("_scan_dialog.html", running=is_scan_running(), confirm=request.args.get("confirm"),
                           subnet=subnet or common.SUBNET, log_text=log_text)


@app.route("/scan/stop", methods=["POST"])
def scan_stop():
    _stop_scan()
    return render_template("_scan_dialog.html", running=is_scan_running(), stopped=True,
                           subnet=common.SUBNET, log_text="")


@app.route("/scan/start", methods=["POST"])
def scan_start():
    error = _start_scan()
    subnet, log_text = _scan_info()
    return render_template("_scan_dialog.html", running=is_scan_running(),
                           subnet=subnet or common.SUBNET, log_text=log_text, error=error)


@app.route("/scan/progress")
def scan_progress():
    """The live part of the popup, polled every couple of seconds until the scan finishes."""
    subnet, log_text = _scan_info()
    return render_template("_scan_live.html", running=is_scan_running(), subnet=subnet, log_text=log_text)


@app.route("/scan/button")
def scan_button():
    """The header Run scan button, polled by itself while a scan runs so it reverts when the scan ends."""
    return render_template("_scan_button.html", running=is_scan_running())


@app.route("/run-scan", methods=["GET", "POST"])
def run_scan():
    """Fallback page for the scan (the header uses the popup). Scans the detected network; no range to pick."""
    from scan import PORT_LABELS
    if request.method == "POST":
        error = _start_scan()
        if error:
            return render_template("run_scan.html", subnet=common.SUBNET, running=is_scan_running(),
                                   n_ports=len(PORT_LABELS), every=_scan_every(), error=error), 400
        return redirect(url_for("scan_status"))
    return render_template("run_scan.html", subnet=common.SUBNET, running=is_scan_running(),
                           n_ports=len(PORT_LABELS), every=_scan_every())


@app.route("/scan-status")
def scan_status():
    subnet, log_text = _scan_info()
    return render_template("scan_status.html", running=is_scan_running(), log_text=log_text, subnet=subnet)


# ────────────────────────────────────────────  settings

ENDPOINTS = [
    ("/api/status", "The summary: level (ok, warn, fail) and summary (\"All well\", \"2 to look at\"), open alerts, "
                    "findings, unnamed and watched devices."),
    ("/api/devices", "Every device: name, IP, MAC, maker, kind, online now, open ports and what each is, findings."),
    ("/api/ports", "Every port each device has had open: what it is, how LanWard knows, open now, first and last seen."),
    ("/api/alerts", "The newest alerts (?limit=, default 100; ?open=1 for unacknowledged ones)."),
]
# (setting, form field, lowest, highest) of the whole numbers the page edits
NUMBER_SETTINGS = [("RETAIN_SCAN_DAYS", "retain_days", 30, 3650), ("BACKUP_KEEP_DAYS", "backup_days", 0, 365),
                   ("WATCH_OFFLINE_MINUTES", "offline_minutes", 2, 1440), ("FULL_PORT_CHECK_DAYS", "full_days", 0, 30),
                   ("AUTO_LOGOUT_MINUTES", "auto_logout", 0, 1440)]

# Quiet (info) alerts: always on the dashboard, with a per-kind "also push" toggle. (setting, field, name, one-liner).
INFO_ALERT_SETTINGS = [
    ("INFO_PUSH_FIRMWARE", "info_firmware", "Firmware updates", "A device's firmware version changed"),
    ("INFO_PUSH_GHOST", "info_ghost", "Addresses nobody uses", "Something keeps asking for an IP no device answers for"),
    ("INFO_PUSH_SCANNING", "info_scanning", "A named device scanning", "A device you've named is mapping the network"),
    ("INFO_PUSH_ONLINE", "info_online", "Watched device back online", "A device you watch answers again after being offline"),
]


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _is_cidr(text):
    try:
        ipaddress.ip_network(text, strict=False)
        return "/" in text
    except ValueError:
        return False


def _apprise_ok(url):
    """Whether Apprise knows this address (any reachable or not); without Apprise: it looks like a URL."""
    try:
        import apprise
    except ImportError:
        return "://" in url
    return bool(apprise.Apprise().add(url))


def _read_settings_form(form):
    """({SETTING: text as .env holds it}, {form field: what is wrong}) from a Settings page POST."""
    values, errors = {}, {}
    hooks = list(dict.fromkeys(u.strip() for u in form.getlist("webhook") if u.strip()))
    bad = [u for u in hooks if urlparse(u).scheme not in ("http", "https") or not urlparse(u).netloc]
    if bad:
        errors["webhook"] = f"Not a web address (http:// or https://): {bad[0]}"
    values["WEBHOOK_URLS"] = " ".join(hooks)
    pushes = list(dict.fromkeys(u.strip() for u in form.getlist("push") if u.strip()))
    bad = [u for u in pushes if not _apprise_ok(u)]
    if bad:
        errors["push"] = f"Not an address Apprise knows: {bad[0]}"
    values["NOTIFY_URLS"] = " ".join(pushes)
    # "Send warnings" checkbox: on = warnings and alerts go out; off = alerts only. (Serious alerts always go.)
    values["NOTIFY_MIN_SEVERITY"] = "warning" if form.get("send_warnings") else "alert"
    values["SCAN_HOURS"] = ",".join(str(h) for h in sorted({int(h) for h in form.getlist("scan_hour")
                                                              if h.isdigit() and int(h) < 24}))
    for name, field, lo, hi in NUMBER_SETTINGS:
        raw = (form.get(field) or "").strip()
        if not raw.isdigit() or not lo <= int(raw) <= hi:
            errors[field] = f"A whole number from {lo} to {hi}"
        values[name] = str(int(raw)) if raw.isdigit() else raw
    allow = list(dict.fromkeys(a for a in re.split(r"[\s,]+", form.get("status_allow", "")) if a))
    bad = [a for a in allow if not _is_ip(a)]
    if bad:
        errors["status_allow"] = f"Not an IP address: {bad[0]}"
    values["STATUS_ALLOW"] = ",".join(allow)
    macs = [m for m in re.split(r"[\s,]+", form.get("dhcp_ok", "")) if m]
    bad = [m for m in macs if not common.norm_mac(m)]
    if bad:
        errors["dhcp_ok"] = f"Not a MAC address: {bad[0]}"
    values["DHCP_SERVERS_OK"] = ",".join(dict.fromkeys(common.norm_mac(m) for m in macs if common.norm_mac(m)))
    scanners = [m for m in re.split(r"[\s,]+", form.get("scanners_ok", "")) if m]
    bad = [m for m in scanners if not common.norm_mac(m)]
    if bad:
        errors["scanners_ok"] = f"Not a MAC address: {bad[0]}"
    values["SCANNERS_OK"] = ",".join(dict.fromkeys(common.norm_mac(m) for m in scanners if common.norm_mac(m)))
    values["SUPPORT_CHECK"] = "on" if form.get("support_check") else "off"
    for name, field, *_ in INFO_ALERT_SETTINGS:
        values[name] = "on" if form.get(field) else "off"   # a checkbox: present = push on
    pw, again = form.get("new_password", ""), form.get("new_password2", "")
    if (pw or again) and len(pw) < 8:
        errors["new_password"] = "At least 8 characters"
    elif pw != again:
        errors["new_password"] = "The two passwords are not the same"
    return values, errors


def _destinations(conn, kind):
    """The webhook (kind "webhook") or Apprise ("push") rows: url, when it last took an alert, what is waiting."""
    waiting = {r[0] or "ha": (r[1], r[2]) for r in conn.execute(
        "SELECT target, COUNT(*), MAX(last_error) FROM notify_outbox GROUP BY target")}
    rows = []
    for target, url in common.destinations().items():
        if target.startswith("apprise:") != (kind == "push"):
            continue
        n, err = waiting.get(target, (0, None))
        rows.append({"url": url, "ok": common.kv_get(conn, f"notify_ok:{target}"), "waiting": n, "error": err})
    return rows


def _settings_view(conn, form=None, errors=None):
    """Everything settings.html shows; `form` (a POST with mistakes) fills the fields with what was typed."""
    page = common.page_settings()

    def source(name):           # compose always passes SCAN_HOURS: ".env" only when it differs from the default
        return ("set here" if name in page else ".env" if common.setting_base(name) != common.SETTING_DEFAULTS[name]
                else "default")

    hooks = _destinations(conn, "webhook")
    pushes = _destinations(conn, "push")
    if form is not None:            # show what was typed, mistakes included
        hooks = [{"url": u, "ok": None, "waiting": 0, "error": None} for u in form.getlist("webhook") if u.strip()]
        pushes = [{"url": u, "ok": None, "waiting": 0, "error": None} for u in form.getlist("push") if u.strip()]
    value = (lambda field, name: form.get(field, "")) if form is not None else (lambda field, name: common.setting(name))
    on_hours = ({int(h) for h in form.getlist("scan_hour") if h.isdigit()} if form is not None
                else set(_scan_hours()[0]))
    hours, interval = _scan_hours()
    now = datetime.now()
    nxt = next((h for h in hours if h > now.hour), hours[0] if hours else None)
    backups = sorted((common.DATA_DIR / "backups").glob("scanner-*.db.gz"))
    stored_pw = common.kv_get(conn, "dashboard_password")
    env_pw_set = os.environ.get("DASHBOARD_PASSWORD", "").strip().lower() not in ("", "off")
    if AUTH_OFF_ENV:
        password_from = "turned off in .env (DASHBOARD_PASSWORD=off)"
    elif stored_pw:
        password_from = "the password you set here"
    elif env_pw_set:
        password_from = "set in .env (DASHBOARD_PASSWORD)"
    else:
        password_from = "the built-in default — set your own below"
    learning = common.kv_get(conn, "learning_until")
    last_scan = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    test = parse_json(common.kv_get(conn, "settings_test"), None)
    if test and (test.get("at") or "") < common.iso_ago(minutes=10):   # a transient confirmation, not a status
        test = None
    gateway = gateway_status(conn)
    # The network interface/subnet can be overridden here, but only take effect on a restart (common._saved_override).
    saved_iface = common.kv_get(conn, "setting:IFACE") or ""
    saved_subnet = common.kv_get(conn, "setting:SUBNET") or ""

    def net_src(saved, env_name):
        return "set here" if saved else (".env" if os.environ.get(env_name, "").strip() else "found by itself")
    return {
        "errors": errors or {}, "key": common.api_key(conn), "endpoints": ENDPOINTS,
        "dashboard_url": common.DASHBOARD_URL, "hooks": hooks, "pushes": pushes,
        "send_warnings": (form.get("send_warnings") is not None) if form is not None
        else common.setting("NOTIFY_MIN_SEVERITY").strip().lower() != "alert",
        "hours": [{"h": h, "on": h in on_hours} for h in range(24)],
        "schedule": (f"{common.plural(len(hours), 'scan')} a day · next at {nxt:02d}:00" if hours
                     else "No scheduled scans: only when you press Run scan"),
        "retain_days": value("retain_days", "RETAIN_SCAN_DAYS"), "backup_days": value("backup_days", "BACKUP_KEEP_DAYS"),
        "offline_minutes": value("offline_minutes", "WATCH_OFFLINE_MINUTES"),
        "full_days": value("full_days", "FULL_PORT_CHECK_DAYS"),
        "support_check": (form.get("support_check") is not None) if form is not None else common.setting_on("SUPPORT_CHECK"),
        "info_alerts": [{"field": field, "name": name, "sub": sub,
                         "on": (form.get(field) is not None) if form is not None else common.setting_on(setting_name)}
                        for setting_name, field, name, sub in INFO_ALERT_SETTINGS],
        "status_allow": value("status_allow", "STATUS_ALLOW"), "dhcp_ok": value("dhcp_ok", "DHCP_SERVERS_OK"),
        "scanners_ok": value("scanners_ok", "SCANNERS_OK"),
        "last_backup": backups[-1].name if backups else None,
        "iface_value": form.get("iface", "") if form is not None else saved_iface,
        "subnet_value": form.get("subnet", "") if form is not None else saved_subnet,
        "running_iface": common.IFACE, "running_subnet": common.SUBNET or "none found",
        "iface_src": net_src(saved_iface, "IFACE"), "subnet_src": net_src(saved_subnet, "SUBNET"),
        "net_restart": bool(saved_iface and saved_iface != common.IFACE)
        or bool(saved_subnet and saved_subnet != (common.SUBNET or "")),
        "net_readonly": [
            ("Router", f"{gateway['ip'] or '?'}" + (f" · {gateway['mac']}" if gateway["mac"] else ""),
             "learned from traffic"),
            ("Dashboard address", common.DASHBOARD_URL,
             ".env" if os.environ.get("DASHBOARD_URL", "").strip() else "found by itself")],
        "sources": {n: source(n) for n in common.SETTING_DEFAULTS},
        "password_from": password_from,
        "auto_logout": value("auto_logout", "AUTO_LOGOUT_MINUTES"),
        "require_password": (form.get("require_password") is not None) if form is not None
        else common.kv_get(conn, "require_password") != "off",
        "login_locked_off": AUTH_OFF_ENV,
        "default_password": DEFAULT_PASSWORD,
        "learning_until": learning if learning and learning > common.now_iso() else None,
        "test": test, "saved": request.args.get("saved") == "1", "new_key": request.args.get("key") == "new",
        "export_scan": last_scan["id"] if last_scan else None,
    }


@app.route("/settings", methods=["GET", "POST"])
def settings():
    """Everything a home sets, in one place (2026-10-27): the API key, where alerts go, scan times,
    how long things are kept, the login. A value saved here wins over .env (common.setting) and
    applies without a restart, except the network interface/subnet, which bind at boot and so take
    effect only when LanWard restarts (common._saved_override)."""
    conn = get_db()
    if request.method == "POST":
        values, errors = _read_settings_form(request.form)
        iface = (request.form.get("iface") or "").strip()
        subnet = (request.form.get("subnet") or "").strip()
        if iface and not re.match(r"^[A-Za-z0-9_.:-]{1,32}$", iface):
            errors["iface"] = "An interface name, like eth0 or eno1"
        if subnet and not _is_cidr(subnet):
            errors["subnet"] = "A network in CIDR form, like 192.168.1.0/24"
        if errors:
            view = _settings_view(conn, request.form, errors)
            conn.close()
            return render_template("settings.html", **view), 400
        common.save_settings(conn, values)
        for name, val in (("IFACE", iface), ("SUBNET", subnet)):   # applied on the next restart
            if val:
                common.kv_set(conn, f"setting:{name}", val)
            else:
                conn.execute("DELETE FROM kv WHERE key = ?", (f"setting:{name}",))
        if request.form.get("new_password"):
            common.kv_set(conn, "dashboard_password", _hash_password(request.form["new_password"]))
        if not AUTH_OFF_ENV:            # .env can hard-disable login; otherwise the tickbox controls it
            common.kv_set(conn, "require_password", "on" if request.form.get("require_password") else "off")
        conn.commit()
        conn.close()
        return redirect(url_for("settings", saved=1))
    view = _settings_view(conn)
    conn.close()
    return render_template("settings.html", **view)


@app.route("/settings/test", methods=["POST"])
def settings_test():
    """Send a test alert to every destination; the page shows how each went."""
    conn = get_db()
    results = common.send_test(conn)
    common.kv_set(conn, "settings_test", json.dumps(
        {"at": common.now_iso(), "results": [{"name": n, "error": e} for n, e in results]}))
    conn.commit()
    conn.close()
    return redirect(url_for("settings", _anchor="alerts-out"))


@app.route("/settings/api-key", methods=["POST"])
def settings_new_key():
    api_key(new=True)
    return redirect(url_for("settings", key="new", _anchor="api"))


@app.route("/settings/end-learning", methods=["POST"])
def settings_end_learning():
    """The first day's learning (watcher.start_learning) ends now: new devices alert from here on."""
    conn = get_db()
    common.kv_set(conn, "learning_until", common.now_iso())
    conn.commit()
    conn.close()
    return redirect(url_for("settings", saved=1))


# ────────────────────────────────────────────  search

SEARCH_LIMIT = 200
# Header as-you-type dropdown: how many rows each group may show.
SUGGEST_DEVICES = 6
SUGGEST_HEARD = 3
SUGGEST_SERVICES = 3

# The observations search, shared by the Traffic "Everything heard" page and the header search: device
# name/label, MAC, address, maker, and what the device said (details JSON). Six '?' params (the LIKE value).
_OBS_SEARCH = ("LOWER(IFNULL(mac,'')) LIKE ? ESCAPE '\\' OR LOWER(IFNULL(ip,'')) LIKE ? ESCAPE '\\' "
               "OR LOWER(IFNULL(hostname,'')) LIKE ? ESCAPE '\\' OR LOWER(IFNULL(vendor,'')) LIKE ? ESCAPE '\\' "
               "OR LOWER(IFNULL(details,'')) LIKE ? ESCAPE '\\' OR EXISTS (SELECT 1 FROM host_labels l "
               "WHERE l.mac = observations.mac AND LOWER(l.label) LIKE ? ESCAPE '\\')")


def _like(q):
    return "%" + q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _services_matching(conn, q, limit=None):
    """mDNS services whose friendly name or type contains q (all-time), with how many devices offer and look
    for each — so a header search like "airplay" finds the service itself, not only the devices behind it."""
    ql = q.lower()
    offers, wants = {}, {}
    for r in conn.execute("SELECT mac, details FROM observations WHERE source = 'mdns' AND mac IS NOT NULL"):
        det = common.details_dict(r["details"])
        mac = r["mac"].lower()
        for svc in det.get("services_adv") or []:
            offers.setdefault(svc, set()).add(mac)
        for svc in det.get("services_qry") or []:
            wants.setdefault(svc, set()).add(mac)
    out = []
    for svc, macs in offers.items():
        if svc in MDNS_META_SERVICES:
            continue
        label = MDNS_SERVICE_NAMES.get(svc)
        if ql in svc.lower() or (label and ql in label.lower()):
            out.append({"service": svc, "label": label or svc, "what": MDNS_SERVICE_WHAT.get(svc),
                        "offered": len(macs), "wanted": len(wants.get(svc, set()) - macs)})
    out.sort(key=lambda s: (-s["offered"], s["label"].lower()))
    return out[:limit] if limit else out


def _traffic_match_count(conn, like):
    """How many observations (any period) match the search — the 'N things heard' figure, excluding
    LanWard's own sweep as the Traffic page does."""
    return conn.execute(f"SELECT COUNT(*) FROM observations WHERE NOT (source = 'arp_req' AND mac IS ?) "
                        f"AND ({_OBS_SEARCH})", (common.own_mac(), *([like] * 6))).fetchone()[0]

@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    if not q:
        return render_template("search.html", q="", hosts=[], heard=[], services=[], traffic_count=0)
    like = _like(q)
    conn = get_db()
    # web_info: the title of every web page a device shows, on any port (a dashboard's page title finds the server behind it);
    # open_ports: the port numbers ("8080"), as ports holds their names
    fields = ("h.ip", "h.mac", "h.vendor", "h.hostname", "h.ports", "h.open_ports", "h.firmware", "h.http_title",
              "h.web_info", "h.tls_cert_cn", "l.label")
    rows = conn.execute(
        "SELECT h.*, MAX(s.id) AS scan_id FROM hosts h JOIN scans s ON h.scan_id = s.id "
        "LEFT JOIN host_labels l ON l.mac = h.mac WHERE "
        + " OR ".join(f"LOWER(IFNULL({f}, '')) LIKE ? ESCAPE '\\'" for f in fields)
        + f" GROUP BY h.mac, h.ip ORDER BY h.ip LIMIT {SEARCH_LIMIT + 1}", (like,) * len(fields)).fetchall()
    heard = _heard_only_devices(conn, q.lower())
    services = _services_matching(conn, q)
    traffic_count = _traffic_match_count(conn, like)
    conn.close()
    return render_template("search.html", q=q, hosts=[decorate(r) for r in rows[:SEARCH_LIMIT]], heard=heard,
                           services=services, traffic_count=traffic_count,
                           capped=len(rows) > SEARCH_LIMIT, limit=SEARCH_LIMIT)


@app.route("/search/suggest")
def search_suggest():
    """As-you-type dropdown for the header search: the first few scanned devices whose name, IP,
    MAC, maker (and the rest of the search fields) match. Returns the rendered _suggest.html partial
    for suggest.js to drop under the box; empty (204) below two characters."""
    q = request.args.get("q", "").strip()
    if len(q) < 2:
        return ("", 204)
    like = _like(q)
    conn = get_db()
    # Scanned devices
    fields = ("h.ip", "h.mac", "h.vendor", "h.hostname", "h.ports", "h.open_ports", "h.firmware", "h.http_title",
              "h.web_info", "h.tls_cert_cn", "l.label")
    rows = conn.execute(
        "SELECT h.*, MAX(s.id) AS scan_id FROM hosts h JOIN scans s ON h.scan_id = s.id "
        "LEFT JOIN host_labels l ON l.mac = h.mac WHERE "
        + " OR ".join(f"LOWER(IFNULL({f}, '')) LIKE ? ESCAPE '\\'" for f in fields)
        + f" GROUP BY h.mac, h.ip ORDER BY h.ip LIMIT {SUGGEST_DEVICES + 1}", (like,) * len(fields)).fetchall()
    hosts = []
    for r in rows[:SUGGEST_DEVICES]:
        h = decorate(r)
        h["url"] = _device_url(h)
        hosts.append(h)
    # Devices the passive monitor heard but no scan ever caught, and matching Traffic (services + activity)
    heard = _heard_only_devices(conn, q.lower())[:SUGGEST_HEARD]
    for d in heard:
        d["category"] = classify(d.get("vendor"), None, None, d.get("name"))
        d["url"] = url_for("host_history", mac=d["mac"])
    services = _services_matching(conn, q, limit=SUGGEST_SERVICES)
    traffic_count = _traffic_match_count(conn, like)
    conn.close()
    return render_template("_suggest.html", q=q, hosts=hosts, more_devices=len(rows) > SUGGEST_DEVICES,
                           heard=heard, services=services, traffic_count=traffic_count)


def _heard_only_devices(conn, q):
    """Devices the passive monitor heard that no scan ever caught (phones asleep at scan
    time, visitors), matched on MAC, own IP, DHCP name, maker or your label."""
    scanned = {r[0] for r in conn.execute("SELECT DISTINCT LOWER(mac) FROM hosts WHERE mac IS NOT NULL")}
    ip_by_mac, _ = _own_ipv4_maps(conn)
    names, me = _names_by_mac(conn), common.own_mac()
    devs = {}
    for r in conn.execute("SELECT LOWER(mac) AS mac, vendor, last_seen FROM observations "
                          "WHERE mac IS NOT NULL ORDER BY last_seen"):
        if r["mac"] in scanned or r["mac"] == me or not common.mac_is_device(r["mac"]):
            continue
        d = devs.setdefault(r["mac"], {"mac": r["mac"], "vendor": None})
        d["vendor"] = r["vendor"] or d["vendor"]
        d["last_seen"] = r["last_seen"]
    out = []
    for mac, d in devs.items():
        d["ip"], d["name"] = ip_by_mac.get(mac), names.get(mac)
        if any(q in (v or "").lower() for v in (mac, d["ip"], d["name"], d["vendor"])):
            out.append(d)
    return sorted(out, key=lambda d: d["last_seen"] or "", reverse=True)


@app.after_request
def log_api_and_posts(resp):
    """One log line per API call and form post (who reads the report, what was changed); page views and
    files stay out of the log. Waitress, unlike Flask's development server, logs no requests itself."""
    if request.path.startswith("/api/") or request.method == "POST":
        common.log(f"[web] {request.remote_addr} {request.method} {request.full_path.rstrip('?')} {resp.status_code}")
    return resp


if __name__ == "__main__":
    PORT = int(os.environ.get("PORT", "8080"))
    try:
        from waitress import serve          # a production web server (Debian's python3-waitress, 2026-10-27)
    except ImportError:                      # outside the image (a laptop test): Flask's own
        app.run(host="0.0.0.0", port=PORT, debug=False)
    else:
        serve(app, host="0.0.0.0", port=PORT, threads=8, ident="LanWard")
