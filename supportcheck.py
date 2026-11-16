#!/usr/bin/env python3
"""Known-flaw and end-of-life checks for a scan's devices (2026-10-28).

LanWard already learns each device's MODEL from what it announces on the
network (LLDP, UPnP, mDNS, its own default name, the MAC's maker). This turns
that model into two kinds of finding, written into hosts.findings next to the
home-security checks:

- **No more updates from the maker** (end of life): a quiet `info` finding, from
  a built-in table of models whose maker has stopped security updates. It does
  not push; it rests in the dashboard's tip count.
- **Attackers are using a flaw in this model**: an `alert` (so it pushes),
  from CISA's Known Exploited Vulnerabilities list, downloaded once a day and
  compared here at home. Matched only for models with an explicit matcher, so it
  never fires on a guess.

It is model-level and honest about it: a model known only from the device's own
network name is marked "probably", and a device that announces no model is not
checked. No firmware version is needed; where LanWard already knows the version
(Sonos, Shelly) the home checks use it.

Nothing about your devices leaves the house: only the public CISA list is
downloaded, the same file every user fetches. Off switch: the SUPPORT_CHECK
setting ("off" disables everything here, no download).

Usage: supportcheck.py [scan_id]      # prints what it would add, changes nothing
"""
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime

import common
from common import log

# ── where the downloaded lists live ──
FEED_DIR = common.DATA_DIR / "feeds"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_FILE = FEED_DIR / "cisa_kev.json"
KEV_MAX_AGE_HOURS = 12            # re-download at most twice a day; CISA changes on about 40% of days


# ── the model knowledge base ──────────────────────────────────────────────
# One entry per model (family) worth saying something about. A model that is
# fine and has no exploited-flaw matcher needs no entry: silence is "fine".
#   need: how to recognise it. "vendor" matches the MAC maker; "any"/"all" match
#         the device's announced text (names, models, services, banners).
#   how:  "announced" (the device states this model itself) or "probably" (read
#         from the device's own default network name, which can be changed).
#   eol:  ("ended", note) no more security updates; ("aged", note) old, unclear,
#         tell the user to check; or absent when the model is still supported.
#   kev:  (vendor_regex, product_regex) pairs matched against CISA's list. Empty
#         or absent: never matched there (safe default).
PRODUCTS = [
    {
        "key": "asus-rt-ac68u", "name": "ASUS RT-AC68U", "how": "announced",
        "need": {"vendor": r"asus", "any": [r"rt-ac68u"]},
        "eol": ("ended",
                "ASUS lists the RT-AC68U as end of life; its last firmware came out in May 2026, and security "
                "flaws found from now on will not be fixed. If it is a Wi-Fi access point, every wireless device "
                "passes through it. Plan to replace it; keep its firmware at ASUS's last build until you do. "
                "(asus.com/event/network/eol-product)"),
        "kev": [(r"asus", r"rt-?ac68u")],
    },
    {
        "key": "tplink-tapo-cam", "name": "TP-Link Tapo camera", "how": "probably",
        "need": {"vendor": r"tp-link|tplink", "any": [r"tapo", r"\bc2\d\d\b", r"tpri-device"]},
        # still sold and updated: no end-of-life finding, only the exploited-flaw watch. The KEV product must
        # say "tapo": matching a bare C2xx would also catch TP-Link's Archer C2### routers and misattribute them.
        "kev": [(r"tp-?link", r"tapo")],
    },
    {
        "key": "samsung-tab-s5e", "name": "Samsung Galaxy Tab S5e", "how": "probably",
        "need": {"any": [r"galaxy-tab-s5e", r"sm-t72[05]"]},
        "eol": ("ended",
                "Samsung stopped security updates for the Galaxy Tab S5e around 2022-2023; it is stuck on an old "
                "Android. Fine as a wall tablet on your own network, but treat it as untrusted: don't use it for "
                "banking or email, and keep it off any guest-facing network."),
    },
    {
        "key": "apple-ipad-6", "name": "Apple iPad (6th generation, 2018)", "how": "announced",
        "need": {"any": [r"\bj71bap\b", r"\bj72bap\b", r"ipad7,[56]"]},
        "eol": ("ended",
                "This iPad stopped at iPadOS 17; Apple's iPadOS 18 and later dropped it, so it no longer gets "
                "security updates. Fine for light use at home, but avoid banking and email on it."),
    },
    {
        "key": "lg-webos-tv", "name": "LG TV (webOS)", "how": "announced",
        "need": {"vendor": r"lg\b", "any": [r"webos", r"lgwebostv", r"\boled\d"]},
        "eol": ("aged",
                "Smart TVs get security updates for only a few years. Check for a software update in the TV's "
                "settings; if none comes and the TV is several years old, keep it on your own network and don't "
                "enter important passwords on it."),
    },
]


def finding(fid, severity, title, detail):
    return {"id": fid, "severity": severity, "title": title, "detail": detail}


# ── identifying a device from what it announces ────────────────────────────

def _obs_text(conn, macs):
    """{mac: one lowercase blob of everything the device announced passively} for the given MACs
    (LLDP model, DHCP vendor-class and host name, mDNS model/host). Empty when there are none."""
    out = {}
    macs = [m for m in {(m or "").lower() for m in macs} if m]
    if not macs:
        return out
    rows = conn.execute(
        "SELECT mac, hostname, details FROM observations WHERE mac IN (%s)" % ",".join("?" * len(macs)),
        macs).fetchall()
    for mac, hostname, details in rows:
        out.setdefault(mac.lower(), []).append(" ".join(filter(None, (hostname, details))))
    return {mac: " ".join(parts).lower() for mac, parts in out.items()}


def _signals(h, obs_text):
    """(vendor, one lowercase blob) of everything LanWard knows that could name a device's model."""
    parts = [h["vendor"], h["hostname"], h["http_server"], h["http_title"], h["firmware"], h["mdns_services"]]
    try:
        upnp = json.loads(h["upnp_info"]) if h["upnp_info"] else {}
    except (ValueError, TypeError):
        upnp = {}
    if isinstance(upnp, dict):
        parts += [upnp.get(k) for k in ("friendlyName", "modelName", "modelNumber", "manufacturer", "server")]
    text = " ".join(str(p) for p in parts if p).lower() + " " + obs_text    # UPnP JSON may hold a non-string
    return (h["vendor"] or "").lower(), text


def _matches(need, vendor, text):
    if need.get("vendor") and not re.search(need["vendor"], vendor):
        return False
    if need.get("any") and not any(re.search(p, text) for p in need["any"]):
        return False
    if need.get("all") and not all(re.search(p, text) for p in need["all"]):
        return False
    return True


def identify(h, obs_text):
    """The first PRODUCTS entry this device matches, or None."""
    vendor, text = _signals(h, obs_text)
    for product in PRODUCTS:
        if _matches(product["need"], vendor, text):
            return product
    return None


# ── CISA's Known Exploited Vulnerabilities list ────────────────────────────

def refresh_kev(conn):
    """Download CISA's list if the local copy is missing or older than KEV_MAX_AGE_HOURS, asking the server
    'changed since last time?' so an unchanged list costs almost nothing. Best-effort: on any failure the last
    copy is kept. Returns True when a usable copy is present afterwards."""
    fetched = common.kv_get(conn, "kev_fetched_at")
    if KEV_FILE.exists() and fetched:
        try:
            age = datetime.now() - datetime.fromisoformat(fetched)
            if age.total_seconds() < KEV_MAX_AGE_HOURS * 3600:
                return True
        except ValueError:
            pass
    headers = {"User-Agent": common.USER_AGENT}
    if KEV_FILE.exists():
        if etag := common.kv_get(conn, "kev_etag"):
            headers["If-None-Match"] = etag
        if modified := common.kv_get(conn, "kev_modified"):
            headers["If-Modified-Since"] = modified
    try:
        with urllib.request.urlopen(urllib.request.Request(KEV_URL, headers=headers), timeout=30) as resp:
            data = resp.read()
            try:                                 # a captcha / maintenance page is still a 200: don't cache it
                catalogue = json.loads(data)
                if not isinstance(catalogue, dict) or "vulnerabilities" not in catalogue:
                    raise ValueError("not the KEV catalogue")
            except ValueError:
                log("    CISA download was not the expected list; keeping the last copy")
                return KEV_FILE.exists()
            FEED_DIR.mkdir(parents=True, exist_ok=True)
            KEV_FILE.write_bytes(data)
            common.kv_set(conn, "kev_fetched_at", common.now_iso())
            if resp.headers.get("ETag"):
                common.kv_set(conn, "kev_etag", resp.headers["ETag"])
            if resp.headers.get("Last-Modified"):
                common.kv_set(conn, "kev_modified", resp.headers["Last-Modified"])
            conn.commit()
            log(f"    CISA list downloaded ({len(data) // 1024} KB)")
            return True
    except urllib.error.HTTPError as e:
        if e.code == 304:                       # not changed since last time
            common.kv_set(conn, "kev_fetched_at", common.now_iso())
            conn.commit()
            return KEV_FILE.exists()
        log(f"    CISA list not downloaded (HTTP {e.code}); keeping the last copy")
    except Exception as e:                       # offline, DNS, timeout: keep whatever we have
        log(f"    CISA list not downloaded ({e}); keeping the last copy")
    return KEV_FILE.exists()


def load_kev():
    """CISA's list as [{vendor, product, cve, date, ransomware}], lower-cased for matching. [] when absent."""
    try:
        catalogue = json.loads(KEV_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out = []
    for v in catalogue.get("vulnerabilities", []):
        out.append({
            "vendor": (v.get("vendorProject") or "").lower(),
            "product": (v.get("product") or "").lower(),
            "cve": v.get("cveID") or "",
            "date": v.get("dateAdded") or "",
            "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
        })
    return out


def kev_hits(product, kev):
    matchers = product.get("kev") or []
    if not matchers:
        return []
    return [row for row in kev
            if any(re.search(vp, row["vendor"]) and re.search(pp, row["product"]) for vp, pp in matchers)]


# ── the findings ───────────────────────────────────────────────────────────

def _how_note(product):
    if product["how"] == "probably":
        return (" LanWard reads this model from the device's own default name on the network, so it is a likely "
                "match, not a certain one.")
    return ""


def eol_finding(product):
    eol = product.get("eol")
    if not eol:
        return None
    status, note = eol
    if status == "ended":
        title = f"No more security updates: {product['name']}"
    else:                                        # aged
        title = f"Check it still gets updates: {product['name']}"
    return finding(f"eol:{product['key']}", "info", title, note + _how_note(product))


def kev_finding(product, hits):
    cves = sorted({h["cve"] for h in hits})
    ransom = any(h["ransomware"] for h in hits)
    detail = (f"CISA lists {common.plural(len(cves), 'flaw')} in {product['name']} as being used in real attacks "
              f"right now ({', '.join(cves)})."
              + (" At least one is used by ransomware groups." if ransom else "")
              + " Update its firmware from the maker's app or website at once; if no update exists, take it off the "
              "network or replace it." + _how_note(product))
    return finding(f"kev:{product['key']}", "alert", f"Attackers are using a known flaw in {product['name']}", detail)


class Support:
    """Loaded once per scan: the passive signals for the scan's devices. The CISA list is downloaded and
    parsed lazily, only once a device whose model actually has a known-flaw matcher turns up, so a home
    with nothing matchable pays no download or parse."""

    def __init__(self, conn, hosts):
        self.conn = conn
        self.obs = _obs_text(conn, [h["mac"] for h in hosts])
        self._kev = None

    def _kev_list(self):
        if self._kev is None:
            refresh_kev(self.conn)
            self._kev = load_kev()
        return self._kev

    def findings_for(self, h):
        product = identify(h, self.obs.get((h["mac"] or "").lower(), ""))
        if not product:
            return []
        out = []
        if (f := eol_finding(product)):
            out.append(f)
        if product.get("kev") and (hits := kev_hits(product, self._kev_list())):
            out.append(kev_finding(product, hits))
        return out


if __name__ == "__main__":                       # dry run: print what it would add, change nothing
    conn = common.connect()
    common.migrate(conn)
    sid = int(sys.argv[1]) if len(sys.argv) > 1 else conn.execute("SELECT MAX(id) FROM scans").fetchone()[0]
    hosts = conn.execute("SELECT * FROM hosts WHERE scan_id = ?", (sid,)).fetchall()
    support = Support(conn, hosts)
    log(f"[*] Support/known-flaw check on scan {sid}")
    for h in hosts:
        for f in support.findings_for(h):
            log(f"    {h['ip']:<15} {f['severity']:<7} {f['title']}")
    if support._kev is not None:
        log(f"    (CISA list: {len(support._kev)} entries loaded for the devices that could match)")
    conn.close()
