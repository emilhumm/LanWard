#!/usr/bin/env python3
"""Continuous checks between scans. Runs as its own process in the lanward
container (docker/entrypoint.py restarts it if it dies).

Every 30 s it reads what passive-monitor.py has written and checks:
  * a new device joined the network     -> warning + push, about a minute
                                            after its first packet
  * someone else answers for the router's IP, announces itself as an IPv6
    router, or a second DHCP server appears -> alert + push (traffic interception)
  * two devices answer for one IP at the same time -> warning
  * a device scans the network (ARP for 50+ addresses in 10 minutes)
                                         -> warning + push; info for a named device
  * a watched device stops answering     -> warning + push after
    WATCH_OFFLINE_MINUTES; "back online" -> info + push; each outage is
    kept in the outages table (common.uptime)

A device is "known" once it has a label (the Approve button on the home
page). The only packets it sends are ARP requests (arping) to watched
devices that have been quiet for 2 minutes, once a minute.
"""
import os
import re
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import common
from common import log

TICK = 30
NEW_DEVICE_GRACE = 60          # wait for DHCP/mDNS to tell us its name


def offline_minutes():
    """WATCH_OFFLINE_MINUTES, from the Settings page or .env (read each time: no restart needed)."""
    return int(common.setting("WATCH_OFFLINE_MINUTES") or 10)


PROBE_EVERY = 60
CONFLICT_EVERY = 300
CONFLICT_GAP_MIN = 10          # two MACs answering for one IP this close together = at the same time
ONLINE_MINUTES = 15            # heard from this recently = online (lookalike check)
SCAN_EVERY = 300
SCAN_TARGETS = 50              # ARP requests for this many addresses within SCAN_WINDOW_MIN = a network scan
SCAN_WINDOW_MIN = 10
# A fresh install first learns what is already at home: no new-device pushes for this long (2026-10-27).
LEARN_HOURS = float(os.environ.get("LEARN_HOURS") or 24)
GENERIC_HOSTNAMES = {"iphone", "ipad", "mac", "macbook", "macbook-pro", "macbook-air",
                     "android", "localhost", "espressif", "unknown", "galaxy"}


def dhcp_servers_ok():
    """DHCP servers besides the router that are meant to be there (Pi-hole, AdGuard Home): DHCP_SERVERS_OK."""
    return {m for m in map(common.norm_mac, re.split(r"[\s,]+", common.setting("DHCP_SERVERS_OK"))) if m}


def scanners_ok():
    """Devices that may scan the network without an alert (SCANNERS_OK)."""
    return {m for m in map(common.norm_mac, re.split(r"[\s,]+", common.setting("SCANNERS_OK"))) if m}

_stop = False


def _stop_handler(*_):
    global _stop
    _stop = True


def new_device_cutoff(conn):
    """Devices first seen before this were handled by the previous watcher run: its last
    heartbeat, less the grace and a tick for the ones it still had pending. None on a
    first start (no heartbeat yet)."""
    try:
        hb = datetime.fromisoformat(common.kv_get(conn, "watcher_heartbeat"))
    except (TypeError, ValueError):
        return None
    return (hb - timedelta(seconds=NEW_DEVICE_GRACE + 2 * TICK)).isoformat(timespec="seconds")


def known_macs(conn, before=None):
    """MACs that get no new-device alert: labelled ones, ones already alerted, and ones
    first seen before `before` (new_device_cutoff; None: everything in the DB). A device
    that showed up while the watcher was down (restart, deploy) is still new; the
    new-device dedupe key stops a second alert for one that was already alerted."""
    macs = set()
    queries = [("SELECT mac FROM host_labels", ()),
               ("SELECT SUBSTR(key, 12) FROM alert_memory WHERE key LIKE 'new-device:%'", ())]
    if before:
        queries += [("SELECT DISTINCT mac FROM observations WHERE mac IS NOT NULL AND first_seen < ?", (before,)),
                    ("SELECT DISTINCT h.mac FROM hosts h JOIN scans s ON s.id = h.scan_id "
                     "WHERE h.mac IS NOT NULL AND s.started_at < ?", (before,))]
    else:
        queries += [("SELECT DISTINCT mac FROM hosts WHERE mac IS NOT NULL", ()),
                    ("SELECT DISTINCT mac FROM observations WHERE mac IS NOT NULL", ())]
    for sql, args in queries:
        macs.update(m for (m,) in conn.execute(sql, args) if m)
    return {m.lower() for m in macs}


def latest_ipv4(conn, mac):
    """The newest address the device used as its own: from its DHCP request, its ARP
    traffic or mDNS, so a device that just joined has one before any scan sees it."""
    for r in conn.execute("SELECT source, ip, details FROM observations WHERE mac = ? "
                          "ORDER BY last_seen DESC", (mac,)):
        own = common.own_ip_of(r["source"], r["ip"], common.details_dict(r["details"]))
        if own and ":" not in own:
            return own
    row = conn.execute("SELECT ip FROM hosts WHERE mac = ? ORDER BY scan_id DESC LIMIT 1", (mac,)).fetchone()
    return row[0] if row else None


# ------------------------------------------------------------------ new devices

# What a DHCP vendor class (option 60) says about the device, for "Looks like".
_VENDOR_CLASS_KIND = [("msft", "Windows PC (or a gadget that says so: its DHCP vendor class is {vc})"),
                      ("android-dhcp", "Android device"), ("udhcp", "Linux gadget (udhcp)"),
                      ("dhcpcd", "Linux (dhcpcd)")]


def vendor_class_kind(vc):
    low = vc.lower()
    return next((kind.format(vc=vc) for key, kind in _VENDOR_CLASS_KIND if low.startswith(key)), vc)


def describe(conn, mac):
    """Everything we know about a MAC, for the new-device alert."""
    d = {"mac": mac, "ip": latest_ipv4(conn, mac), "vendor": common.vendor_for(mac),
         "randomized": common.mac_is_randomized(mac), "sources": set()}
    names = {}
    for r in conn.execute("SELECT source, hostname, vendor, details FROM observations "
                          "WHERE mac = ? ORDER BY last_seen", (mac,)):
        d["sources"].add(r["source"])
        d["vendor"] = d["vendor"] or r["vendor"]
        if r["hostname"] and r["source"] == "dhcp":
            d["hostname"] = r["hostname"]
        elif r["source"] in ("mdns", "netbios") and common.host_name(r["hostname"]):
            names[r["source"]] = common.host_name(r["hostname"])  # its mDNS / NetBIOS name
        det = common.details_dict(r["details"])
        if r["source"] == "dhcp":
            d["os_guess"] = det.get("fingerprint_match") or d.get("os_guess")
            d["vendor_class"] = det.get("vendor_class") or d.get("vendor_class")
        if r["source"] == "mdns" and isinstance(det.get("services_adv"), list):
            d["services"] = det["services_adv"][:6]
    if not d.get("hostname") and (names.get("mdns") or names.get("netbios")):
        d["hostname"] = names.get("mdns") or names.get("netbios")      # same order as common.name_hint
    return d


def lookalike(conn, hostname):
    """A labeled device, not online right now, that used the same (distinctive) DHCP
    hostname: most likely the same phone/laptop with a new private MAC address. The
    host name is whatever the new device says, so a twin that is online at the same
    time does not count."""
    if not hostname or len(hostname) < 4 or hostname.lower() in GENERIC_HOSTNAMES:
        return None
    recent = common.iso_ago(minutes=ONLINE_MINUTES)
    for label, mac in conn.execute(
        "SELECT DISTINCT l.label, l.mac FROM observations o JOIN host_labels l ON l.mac = o.mac "
        "WHERE o.source = 'dhcp' AND LOWER(o.hostname) = LOWER(?)", (hostname,),
    ).fetchall():
        seen = conn.execute("SELECT MAX(last_seen) FROM observations WHERE mac = ?", (mac,)).fetchone()[0]
        if not (seen and seen >= recent):
            return label
    return None


def alert_new_device(conn, mac):
    d = describe(conn, mac)
    name = d.get("hostname") or d.get("vendor") or ("a device with a private MAC address"
                                                    if d["randomized"] else "unknown device")
    lines = [f"- MAC: {mac}" + (" (private/randomized address)" if d["randomized"] else ""),
             f"- IP: {d['ip'] or 'not known yet'}"]
    if d.get("vendor"):
        lines.append(f"- Maker: {d['vendor']}")
    if d.get("hostname"):
        lines.append(f"- Calls itself: {d['hostname']}")
    if d.get("os_guess") or d.get("vendor_class"):
        lines.append(f"- Looks like: {d.get('os_guess') or vendor_class_kind(str(d['vendor_class']))}")
    if d.get("services"):
        lines.append(f"- Offers: {', '.join(map(str, d['services']))}")
    # Only a private address explains a known device turning up under a new MAC.
    twin = lookalike(conn, d.get("hostname")) if d["randomized"] else None
    if twin:
        lines.append(f"- Probably {twin} with a new private address")
    lines.append("\nNew devices show up whenever something joins your Wi-Fi — a visitor's phone, a gadget you "
                 "just set up, or one of your own under a fresh private address. Give it a name on the LanWard "
                 "Overview (Name new devices) if you recognise it; take a closer look if you don't and nobody "
                 "added anything.")
    common.write_alert(conn, "info" if twin else "warning", f"New device on your network: {name}",
                       "\n".join(lines), kind="new_device", dedupe_key=f"new-device:{mac}",
                       dedupe_days=3650, force_push=bool(twin))     # pushed either way
    log(f"new device {mac} ({name})" + (f", probably {twin}" if twin else ""))


def check_new_devices(conn, state):
    me = common.own_mac()
    rows = conn.execute("SELECT DISTINCT mac FROM observations WHERE last_seen >= ? AND mac IS NOT NULL",
                        (state["since"],)).fetchall()
    rows = [(mac, None) for (mac,) in rows]
    latest = conn.execute("SELECT MAX(id) FROM scans").fetchone()[0]
    if latest:
        rows += conn.execute("SELECT DISTINCT mac, bridge_mac FROM hosts WHERE scan_id = ? AND mac IS NOT NULL",
                             (latest,)).fetchall()
    now = time.monotonic()
    until = common.kv_get(conn, "learning_until")      # the Settings page can end it early
    learning = until is not None and common.now_iso() < until
    for mac, bridge in rows:
        mac = (mac or "").lower()
        if mac in state["known"] or mac == me or not common.mac_is_device(mac):
            continue
        # A Sonos speaker behind a known SonosNet bridge: the scan found its own MAC (from its UPnP
        # UDN) where ARP only ever showed the bridge's. Not a new device (2026-10-27).
        if bridge and bridge.lower() in state["known"]:
            state["known"].add(mac)
            log(f"{mac} is behind the known bridge {bridge.lower()}: not new")
            continue
        if learning:                    # part of the household LanWard is still getting to know
            state["known"].add(mac)
            log(f"learning: {mac}")
            continue
        state["pending"].setdefault(mac, now)
    for mac, first in list(state["pending"].items()):
        if now - first >= NEW_DEVICE_GRACE:
            alert_new_device(conn, mac)
            state["known"].add(mac)
            del state["pending"][mac]


# ------------------------------------------------------------------ router + DHCP

def gateway_baseline(conn, gw_ip):
    mac = common.kv_get(conn, "gateway_mac")
    if mac:
        return mac
    row = conn.execute(
        "SELECT mac FROM observations WHERE source = 'arp' AND ip = ? AND mac IS NOT NULL "
        "ORDER BY count DESC LIMIT 1", (gw_ip,)).fetchone()
    if row:
        common.kv_set(conn, "gateway_mac", row[0].lower())
        common.kv_set(conn, "gateway_ip", gw_ip)
        log(f"gateway baseline: {gw_ip} is {row[0].lower()}")
        return row[0].lower()
    return None


def check_gateway(conn, state):
    gw_ip = state.get("gw_ip") or common.default_gateway()
    state["gw_ip"] = gw_ip
    if not gw_ip:
        return
    gw_mac = gateway_baseline(conn, gw_ip)
    if not gw_mac:
        return
    recent = common.iso_ago(minutes=15)
    claims = {r[0].lower() for r in conn.execute(
        "SELECT mac FROM observations WHERE source = 'arp' AND ip = ? AND last_seen >= ? AND mac IS NOT NULL",
        (gw_ip, recent))}
    for r in conn.execute("SELECT mac, details FROM observations WHERE source = 'arp_req' "
                          "AND last_seen >= ? AND details LIKE ? AND mac IS NOT NULL", (recent, f'%"{gw_ip}"%')):
        if common.details_dict(r["details"]).get("own_ip") == gw_ip:
            claims.add(r["mac"].lower())
    # repeat=True: while it keeps claiming the router, once a day (counted from the
    # last alert, not from the last sighting, which would mean never again).
    for mac in claims - {gw_mac}:
        common.write_alert(
            conn, "alert", "Another device is claiming to be your router",
            f"- Router {gw_ip} is normally {gw_mac}\n- Now also answered by {mac} "
            f"({common.vendor_for(mac) or 'unknown maker'})\n\nThis is how traffic gets "
            "intercepted (ARP spoofing). Find and unplug that device. If you replaced the "
            "router, accept the new one on the LanWard Overview.",
            kind="gateway", dedupe_key=f"gateway:{mac}", dedupe_days=1, repeat=True)
    for r in conn.execute("SELECT mac, ip, details FROM observations WHERE source = 'dhcp_server' "
                          "AND last_seen >= ?", (common.iso_ago(hours=1),)):
        mac = (r["mac"] or "").lower()
        if mac and mac != gw_mac and mac not in dhcp_servers_ok():
            common.write_alert(
                conn, "alert", "A second DHCP server is handing out addresses",
                f"- Your router {gw_ip} ({gw_mac}) is the normal one\n- Also answering: "
                f"{mac} ({common.vendor_for(mac) or 'unknown maker'}), server address {r['ip']}\n\n"
                "Usually a travel router or AP plugged in the wrong way round; at worst an attempt "
                "to redirect traffic. Devices that take its offer may lose internet.",
                kind="dhcp", dedupe_key=f"dhcp-server:{mac}", dedupe_days=1)


def device_name(conn, mac):
    """The best name we have for a MAC, for alert text: your label, its DHCP host name,
    what it says it is (common.name_hint), its maker."""
    row = conn.execute("SELECT label FROM host_labels WHERE mac = ?", (mac,)).fetchone()
    if row:
        return row[0]
    row = conn.execute("SELECT hostname FROM observations WHERE mac = ? AND source = 'dhcp' AND hostname <> '' "
                       "ORDER BY last_seen DESC LIMIT 1", (mac,)).fetchone()
    return ((row and row[0]) or common.name_hint(conn, mac) or common.vendor_for(mac)
            or ("a device with a private MAC address" if common.mac_is_randomized(mac) else "unknown device"))


def check_ip_conflicts(conn, state):
    """Two MACs answering ARP for one IP at the same time: their periods overlap (a
    phone that changed its private MAC and got the old IP back does not overlap) and
    both answered within CONFLICT_GAP_MIN of each other (the first/last-seen spans
    alone also "overlap" when A, then B, then A again used the address in one day)."""
    skip = {state.get("gw_ip"), common.own_ip()}
    by_ip = {}
    for r in conn.execute("SELECT ip, mac, first_seen, last_seen FROM observations "
                          "WHERE source = 'arp' AND ip IS NOT NULL AND mac IS NOT NULL AND last_seen >= ?",
                          (common.iso_ago(hours=24),)):
        if r["ip"] not in skip:
            by_ip.setdefault(r["ip"], []).append(r)
    for ip, rows in by_ip.items():
        for i, a in enumerate(rows):
            for b in rows[i + 1:]:
                start, end = max(a["first_seen"], b["first_seen"]), min(a["last_seen"], b["last_seen"])
                if end <= start:
                    continue
                overlap = (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()
                if overlap < 600:
                    continue
                gap = abs((datetime.fromisoformat(a["last_seen"])
                           - datetime.fromisoformat(b["last_seen"])).total_seconds())
                if gap > CONFLICT_GAP_MIN * 60:
                    continue
                pair = sorted([a["mac"].lower(), b["mac"].lower()])
                common.write_alert(
                    conn, "warning", f"Two devices are using the same address {ip}",
                    f"- {pair[0]} ({device_name(conn, pair[0])})\n- {pair[1]} "
                    f"({device_name(conn, pair[1])})\n\nBoth answered for {ip} at the same "
                    "time. Usually a device with a fixed IP inside the DHCP range.",
                    kind="ip_conflict", dedupe_key=f"dup-ip:{ip}:{','.join(pair)}", dedupe_days=7)


def check_scanners(conn, state):
    """A device that ARP-asks for SCAN_TARGETS or more addresses within SCAN_WINDOW_MIN minutes is
    mapping the network (2026-10-27). Normal devices do it too (on this LAN an iPhone, both access
    points' network map and a laptop asked for 200-230 addresses at once), so a device you named
    gets an info alert without a push. Never for LanWard's own sweeps, SCANNERS_OK, or while a
    fresh install is still learning the network. Once a month at most per device. (alerts.py's
    ghost-address check leaves such sweepers out on its own: SWEEP_TARGETS.)"""
    until = common.kv_get(conn, "learning_until")
    if until is not None and common.now_iso() < until:
        return
    me, ok = common.own_mac(), scanners_ok()
    for r in conn.execute(
        "SELECT LOWER(mac) AS mac, COUNT(DISTINCT ip) AS n, MIN(last_seen) AS first, MAX(last_seen) AS last "
        "FROM observations WHERE source = 'arp_req' AND last_seen >= ? AND mac IS NOT NULL "
        "GROUP BY LOWER(mac) HAVING COUNT(DISTINCT ip) >= ?",
        (common.iso_ago(minutes=SCAN_WINDOW_MIN), SCAN_TARGETS)).fetchall():
        mac = r["mac"]
        if mac == me or mac in ok:
            continue
        named = conn.execute("SELECT 1 FROM host_labels WHERE mac = ?", (mac,)).fetchone() is not None
        name = device_name(conn, mac)
        ip = latest_ipv4(conn, mac)
        lines = [f"- {mac} ({name})" + (f", IP {ip}" if ip else ""),
                 f"- Asked for {r['n']} different addresses within {SCAN_WINDOW_MIN} minutes "
                 f"(between {r['first'][11:16]} and {r['last'][11:16]})"]
        if named:
            lines.append("\nFine if it ran a network-scanner app or it is the access point or router "
                         "drawing its network map; if not, check it.")
        else:
            lines.append("\nA device that asks for every address is mapping the network: a network-scanner "
                         "app (Fing, a phone's device list), an access point's network map, a NAS or Home "
                         "Assistant looking for devices, or someone looking for something to attack. If you "
                         "do not know this device, find it and unplug it. If it is fine, name it on the "
                         "Overview, or add it to the devices allowed to scan (SCANNERS_OK) in Settings.")
        title = f"{name[:1].upper() + name[1:]} is scanning your network"
        body = "\n".join(lines)
        if named:   # a device you named: a quiet info alert you control in Settings → Alerts
            wrote = common.write_info_alert(conn, "scanning", "info", title, body,
                                            dedupe_key=f"scanning:{mac}", dedupe_days=30, repeat=True)
        else:       # an unknown device mapping the network: a pushed warning, gated by severity
            wrote = common.write_alert(conn, "warning", title, body, kind="scanning",
                                       dedupe_key=f"scanning:{mac}", dedupe_days=30, repeat=True)
        if wrote:
            log(f"{mac} ({name}) asked for {r['n']} addresses in {SCAN_WINDOW_MIN} min")


def check_ipv6_routers(conn, state):
    """A device other than the router announcing itself as an IPv6 router: a router advertisement
    with a router lifetime above 0 (2026-10-27). Devices that take it send their IPv6 traffic
    through it, and with its RDNSS option their DNS lookups too, even where the router gives out
    no IPv6 at all. Lifetime 0 offers no route (Apple TV and HomePod Thread border routers send
    those to announce their Thread network) and never alerts. Like the ARP impostor: an alert,
    again once a day while it lasts."""
    gw_mac = common.kv_get(conn, "gateway_mac")
    if not gw_mac:                                  # no router baseline yet (check_gateway makes it)
        return
    for r in conn.execute("SELECT mac, ip, details FROM observations WHERE source = 'ra' AND last_seen >= ? "
                          "AND mac IS NOT NULL", (common.iso_ago(minutes=15),)).fetchall():
        mac = r["mac"].lower()
        det = common.details_dict(r["details"])
        lifetime = det.get("router_lifetime")
        if mac == gw_mac or not isinstance(lifetime, int) or lifetime <= 0:
            continue
        lines = [f"- {mac} ({device_name(conn, mac)}) sends IPv6 router advertisements from {r['ip']} "
                 f"(router lifetime {lifetime} s)"]
        if det.get("prefixes"):
            lines.append(f"- Addresses it hands out: {', '.join(map(str, det['prefixes']))}")
        if det.get("rdnss"):
            lines.append(f"- DNS servers it hands out: {', '.join(map(str, det['rdnss']))}")
        lines.append(f"- Your router is {gw_mac}")
        lines.append("\nDevices that accept it send their IPv6 traffic through this device"
                     + (", and their name lookups to its DNS servers" if det.get("rdnss") else "")
                     + ": it can read or redirect that traffic, even if your router gives out no IPv6. "
                     "Usually a misconfigured device (a PC, VM host or travel router sharing its "
                     "connection); at worst an attack (rogue router advertisements). Find that device and "
                     "unplug it or turn off its IPv6 router.")
        common.write_alert(conn, "alert", "Another device is announcing itself as an IPv6 router",
                           "\n".join(lines), kind="ipv6_router", dedupe_key=f"ipv6-router:{mac}",
                           dedupe_days=1, repeat=True)


# ------------------------------------------------------------------ watched devices

def arping(ip):
    """MACs that answered an ARP request for `ip` (empty set: no answer)."""
    try:
        out = subprocess.run(["arping", "-c", "2", "-w", "3", "-I", common.IFACE, ip],
                             capture_output=True, text=True, timeout=6).stdout
    except (OSError, subprocess.TimeoutExpired):
        return set()
    return {m.lower() for m in re.findall(r"\[([0-9A-Fa-f:]{17})\]", out)}


def start_outage(conn, state, mac, alerted=False):
    """Record that a watched device is down from now, unless an outage of it is already open."""
    if not conn.execute("SELECT 1 FROM outages WHERE mac = ? AND ended_at IS NULL", (mac,)).fetchone():
        conn.execute("INSERT INTO outages (mac, started_at, alerted) VALUES (?, ?, ?)",
                     (mac, common.now_iso(), int(alerted)))
        state.setdefault("outage_start", {})[mac] = time.monotonic()


def end_outage(conn, state, mac):
    """The open outage of `mac` ends now. If this process started it and the wall clock moved
    more than 3 minutes against the monotonic one meanwhile (NTP after a power cut), the start
    is moved so the outage is as long as measured."""
    row = conn.execute("SELECT id, started_at FROM outages WHERE mac = ? AND ended_at IS NULL "
                       "ORDER BY started_at DESC LIMIT 1", (mac,)).fetchone()
    mono = state.setdefault("outage_start", {}).pop(mac, None)
    if not row:
        return
    now, start = datetime.now(), row["started_at"]
    if mono is not None:
        measured = time.monotonic() - mono
        try:
            off = abs((now - datetime.fromisoformat(start)).total_seconds() - measured) > 180
        except ValueError:
            off = True
        if off:
            start = (now - timedelta(seconds=measured)).isoformat(timespec="seconds")
    conn.execute("UPDATE outages SET started_at = ?, ended_at = ? WHERE id = ?",
                 (start, now.isoformat(timespec="seconds"), row["id"]))


def end_outages_at_restart(conn):
    """Outages still open from the previous watcher run end at its last heartbeat: while no watcher
    ran, nothing was watched, and a device still down gets a new outage from the first check."""
    hb = common.kv_get(conn, "watcher_heartbeat") or common.now_iso()
    conn.execute("UPDATE outages SET ended_at = MAX(started_at, ?) WHERE ended_at IS NULL", (hb,))


def check_watched(conn, state):
    """Recent passive traffic counts as up; quiet devices get an arping.

    Offline time is counted on this process's monotonic clock, from the first check that
    found the device down. After a power cut the wall clock of a machine without a clock battery starts at its last
    shutdown time and jumps forward when NTP syncs (2026-10-18 and -20), and while LanWard
    itself is off it watches nothing; neither may count as a device being offline.

    Each outage also goes in the outages table (common.uptime), from the first check that
    found the device down to the first that found it back."""
    watched = conn.execute("SELECT mac, label FROM host_labels WHERE watch_offline = 1").fetchall()
    down_since = state.setdefault("down_since", {})     # mac -> time.monotonic() first seen down
    macs = [w["mac"] for w in watched]
    for mac in set(down_since) - set(macs):
        del down_since[mac]                             # no longer watched: a re-watch starts from zero
    outage_start = state.setdefault("outage_start", {})
    for mac in set(outage_start) - set(macs):
        del outage_start[mac]
    # uptime() counts from when a device is watched; an unwatched one's open outage ends now.
    marks = ",".join("?" * len(macs))
    conn.execute(f"UPDATE outages SET ended_at = ? WHERE ended_at IS NULL AND mac NOT IN ({marks})",
                 (common.now_iso(), *macs))
    conn.execute(f"DELETE FROM kv WHERE key LIKE 'watched_since:%' AND SUBSTR(key, 15) NOT IN ({marks})", macs)
    for mac in macs:
        if common.kv_get(conn, f"watched_since:{mac}") is None:
            common.kv_set(conn, f"watched_since:{mac}", common.now_iso())
    if not watched:
        return
    # Probe in parallel; sqlite reads stay on this thread.
    targets = {w["mac"]: (latest_ipv4(conn, w["mac"]),
                          conn.execute("SELECT MAX(last_seen) FROM observations WHERE mac = ?",
                                       (w["mac"],)).fetchone()[0]) for w in watched}
    recent = common.iso_ago(minutes=2)
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {mac: pool.submit(arping, ip) for mac, (ip, seen) in targets.items()
                   if ip and not (seen and seen >= recent)}
    now = common.now_iso()
    for w in watched:
        mac, label = w["mac"], w["label"]
        ip, seen = targets[mac]
        up = bool(seen and seen >= recent) or (mac in futures and mac in futures[mac].result())
        st = conn.execute("SELECT * FROM watch_state WHERE mac = ?", (mac,)).fetchone()
        if up:
            end_outage(conn, state, mac)
            if st and st["state"] == "down" and st["alerted"]:
                if mac in down_since:
                    mins = int((time.monotonic() - down_since[mac]) // 60)
                    body = f"- {label} ({ip}) answers again after about {mins} minute(s)."
                else:
                    body = f"- {label} ({ip}) answers again. It was already offline when LanWard restarted."
                # Delivery (off / dashboard / push) is set per kind in Settings → Alerts.
                common.write_info_alert(conn, "online", "info", f"{label} is back online", body)
            down_since.pop(mac, None)
            if not st or st["state"] != "up":
                conn.execute("INSERT OR REPLACE INTO watch_state (mac, state, since, last_ok, last_ip, alerted, pushed) "
                             "VALUES (?, 'up', ?, ?, ?, 0, 0)", (mac, now, now, ip))
            else:
                conn.execute("UPDATE watch_state SET last_ok = ?, last_ip = ? WHERE mac = ?", (now, ip, mac))
            continue
        down_since.setdefault(mac, time.monotonic())
        # also after a watcher restart while it was down (end_outages_at_restart closed the old one)
        start_outage(conn, state, mac, alerted=bool(st and st["state"] == "down" and st["alerted"]))
        if not st or st["state"] != "down":
            conn.execute("INSERT OR REPLACE INTO watch_state (mac, state, since, last_ok, last_ip, alerted, pushed) "
                         "VALUES (?, 'down', ?, ?, ?, 0, 0)",
                         (mac, now, st["last_ok"] if st else None, ip))
            continue
        down_min = (time.monotonic() - down_since[mac]) / 60
        if not st["alerted"] and down_min >= offline_minutes():
            lines = [f"- {label} ({ip or 'IP unknown'}) has not answered for {int(down_min)} minutes."]
            # The wall-clock time of the last answer only if the clock agrees with what we measured.
            if st["last_ok"]:
                wall_min = (datetime.now() - datetime.fromisoformat(st["last_ok"])).total_seconds() / 60
                if abs(wall_min - down_min) <= 3:
                    lines.append(f"- Last answer: {st['last_ok'].replace('T', ' ')}.")
            lines.append("\nYou asked LanWard to watch this one, so it tells you when it goes quiet. Devices go "
                         "quiet when they sleep, are switched off, or leave the house — worth attention mainly "
                         "if this is something that should always be on.")
            common.write_alert(conn, "warning", f"{label} is offline", "\n".join(lines), kind="offline")
            conn.execute("UPDATE watch_state SET alerted = 1, pushed = ? WHERE mac = ?",
                         (int(common.push_wanted("warning")), mac))
            conn.execute("UPDATE outages SET alerted = 1 WHERE mac = ? AND ended_at IS NULL", (mac,))
            log(f"{label} offline")


# ------------------------------------------------------------------ main loop

def start_learning(conn, first_start):
    """On a fresh install (no watcher has run, no scan yet), every device at home would be "new" and push
    within a minute. Instead LanWard learns for LEARN_HOURS: devices seen then become known without an
    alert, and the dashboard asks you to name them. Returns the ISO end of the learning period, or None."""
    until = common.kv_get(conn, "learning_until")
    if until is None and first_start and LEARN_HOURS > 0             and not conn.execute("SELECT 1 FROM scans LIMIT 1").fetchone():
        until = (datetime.now() + timedelta(hours=LEARN_HOURS)).isoformat(timespec="seconds")
        common.kv_set(conn, "learning_until", until)
        log(f"[watcher] fresh install: learning the network until {until.replace('T', ' ')} "
            "(no new-device alerts until then; LEARN_HOURS)")
    return until


def check_own_ports(conn, state):
    """LanWard's own machine: the ports it listens on, read every minute (exact, no scan, common.own_listening_ports).
    A port it never had open before is alerted at once; the first read is the baseline. The list is written when it
    changes, and once an hour so the ports stay recent."""
    ports, mac = common.own_listening_ports(), common.own_mac()
    if ports is None or not mac:
        return
    t = time.monotonic()
    if ports == state.get("own_ports") and t - state.get("own_ports_at", float("-inf")) < 3600:
        return
    state["own_ports"], state["own_ports_at"] = ports, t
    new = common.record_open_ports(conn, mac, ports, full=True)
    new = [p for p in new if p != common.dashboard_port()]      # 8080 here is LanWard's own dashboard, not a surprise
    if new:
        import portid
        ip = common.own_ip()
        ids = portid.identify(conn, mac, ip, new, ports)
        portid.save(conn, mac, ids, [p for p in new if p < common.EPHEMERAL_PORT])
        common.alert_new_ports(conn, mac, device_name(conn, mac), ip, new, ids=ids)


def run_check(check, *args):
    """Run one check; an error is logged (keep watching, retry next time)."""
    try:
        check(*args)
    except Exception as e:
        log(f"[watcher] {check.__name__}: {e!r}")


def main():
    signal.signal(signal.SIGTERM, _stop_handler)
    signal.signal(signal.SIGINT, _stop_handler)
    conn = common.connect(autocommit=True)
    common.migrate(conn)
    # Devices first seen while the watcher was down are still new (see known_macs).
    cutoff = new_device_cutoff(conn)
    start_learning(conn, first_start=cutoff is None)
    end_outages_at_restart(conn)
    state = {"known": known_macs(conn, cutoff), "pending": {},
             "since": min(cutoff or common.iso_ago(minutes=5), common.iso_ago(minutes=5))}
    log(f"[watcher] started: {len(state['known'])} known MACs, offline after {offline_minutes()} min")
    # Intervals on the monotonic clock: the wall clock jumps after a power cut.
    last_probe = last_conflict = last_scanners = last_ports = float("-inf")
    while not _stop:
        t = time.monotonic()
        # Each check on its own: one that keeps failing must not stop the others,
        # the outbox or the heartbeat.
        run_check(check_new_devices, conn, state)
        run_check(check_gateway, conn, state)
        run_check(check_ipv6_routers, conn, state)
        if t - last_conflict >= CONFLICT_EVERY:
            run_check(check_ip_conflicts, conn, state)
            last_conflict = t
        if t - last_scanners >= SCAN_EVERY:
            run_check(check_scanners, conn, state)
            last_scanners = t
        if t - last_probe >= PROBE_EVERY:
            run_check(check_watched, conn, state)
            last_probe = t
        if t - last_ports >= 60:
            run_check(check_own_ports, conn, state)
            last_ports = t
        run_check(common.flush_outbox, conn)        # pushes HA did not take, again until it does (or 48 h)
        run_check(common.kv_set, conn, "watcher_heartbeat", common.now_iso())
        for _ in range(TICK):
            if _stop:
                break
            time.sleep(1)
    conn.close()
    log("[watcher] stopped")


if __name__ == "__main__":
    sys.exit(main())
