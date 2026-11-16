#!/usr/bin/env python3
"""Scan-based alerts, run at the end of every scan (scan.py):

  * new home-security findings (homechecks.py)  -> one grouped alert, pushed
                                                   when one is a warning or worse
  * TLS certificate replaced on a device's port  -> warning, pushed
  * firmware changed                             -> info (dashboard only)
  * "ghost" IPs some device keeps asking for
    but no device has used for a week            -> info (dashboard only)

Every item alerts once; it alerts again only after it has been gone for
30 days (common.is_new). Things that need an answer within minutes (new
device, router impersonation, devices going offline) are in watcher.py.

Usage: alerts.py [scan_id]       # defaults to the latest scan
"""
import ipaddress
import json
import sys
from collections import defaultdict

import common
from common import log

SEV_ORDER = ["info", "warning", "alert"]
SWEEP_TARGETS = 20      # a device asking for more unclaimed addresses than this in 24 h is sweeping the subnet
CLAIMED_DAYS = 7        # an address some device used as its own this recently is not a ghost
HISTORY_DAYS = 30       # how far back a device's last known certificate and firmware are looked up
GHOST_RATE_HOURS = 24   # the ghost ask-rate is the asks over the last this-many hours (a true rolling window)
GHOST_MIN_PER_DAY = 144  # a ghost address must be asked for at least this often RECENTLY to count: ~2 lookups an hour,
                         # as a lookup nobody answers goes out 3 times. (Was 48, 16 lookups a day: a once-an-hour
                         # "is it on?" ping of a PC that is off, 72 asks a day, kept "Nobody home" up; 2026-11-01.)
GHOST_MIN_RECENT = 20   # ...and at least this many times over the window, so a stray ask or two is ignored
GHOST_HOUR_CAP = 24     # towards GHOST_MIN_PER_DAY one hour counts at most this many asks: a burst (Home Assistant
                        # retrying everything as it restarts: 48 in an hour) is not a poller


def _host_label(conn, mac):
    if not mac:
        return None
    row = conn.execute("SELECT label FROM host_labels WHERE mac = ?", (mac,)).fetchone()
    return row["label"] if row else None


def _name(conn, h):
    return _host_label(conn, h["mac"]) or h["hostname"] or h["vendor"] or h["ip"]


def _seen_at_bridge(conn, h, fid):
    """Before 2026-10-27 a Sonos speaker behind a SonosNet bridge was filed under the bridge's MAC: a finding
    alerted there in the last 30 days is not new now that the speaker has its own (read only, records nothing)."""
    if not h["bridge_mac"]:
        return False
    row = conn.execute("SELECT last_at FROM alert_memory WHERE key = ?",
                       (f"finding:{h['bridge_mac']}:{fid}",)).fetchone()
    return row is not None and row[0] >= common.iso_ago(days=30)


def check_findings(conn, scan_id, hosts):
    new = []
    for h in hosts:
        for f in json.loads(h["findings"] or "[]"):
            if (common.is_new(conn, f"finding:{h['mac'] or h['ip']}:{f['id']}")
                    and not _seen_at_bridge(conn, h, f["id"])):
                new.append((h, f))
    if not new:
        return 0
    worst = max((f["severity"] for _, f in new), key=SEV_ORDER.index)
    pushed = [(h, f) for h, f in new if f["severity"] != "info"]
    lines = [f"- {_name(conn, h)} ({h['ip']}): {f['title']}" for h, f in new]
    title = (f"{len(new)} new security findings" if len(new) > 1
             else f"{_name(conn, new[0][0])}: {new[0][1]['title']}")
    common.write_alert(
        conn, worst, title,
        "\n".join(lines) + "\n\nDetails and what to do: LanWard Overview, Security checks.",
        kind="finding", scan_id=scan_id, push=bool(pushed),
    )
    return 1


def check_new_ports(conn, scan_id, hosts):
    """Ports a device never had open before (scan.py's record_ports put them in hosts.new_ports), one alert per
    device, each port saying what it is and how LanWard knows (portid.py: asked gently, once, just those ports)."""
    import portid
    n = 0
    for h in hosts:
        new = json.loads(h["new_ports"] or "[]")
        if not new:
            continue
        web = json.loads(h["web_info"] or "{}")
        titles = {p: web.get(str(p), {}).get("title") for p in new}
        opened = json.loads((h["open_ports"] if "open_ports" in h.keys() else None) or "[]")
        ids = portid.stored(conn, (h["mac"] or "").lower(), new)            # the scan's Phase P named them
        missing = [p for p in new if p not in ids]
        if missing:
            ids.update(portid.identify(conn, h["mac"], h["ip"], missing, opened, web))
        n += bool(common.alert_new_ports(conn, h["mac"], _name(conn, h), h["ip"], new, titles, scan_id=scan_id,
                                         ids=ids))
    return n


def _one_device_per_mac(rows):
    """The rows whose MAC no other address had in the same scan. Sonos speakers behind a SonosNet bridge
    all answer with the bridge's MAC (enrich.py gives them their own since 2026-10-27): such a MAC's rows
    mix several devices, so their certificates and firmware say nothing about any one of them."""
    count = defaultdict(int)
    for r in rows:
        if r["mac"]:
            count[(r["scan_id"], r["mac"])] += 1
    return [r for r in rows if not r["mac"] or count[(r["scan_id"], r["mac"])] == 1]


def _history(conn, scan, days=HISTORY_DAYS):
    """Rows of earlier scans by this version, oldest first. A scan that could not read a device's
    certificate or firmware (a timeout, ports not checked) leaves a gap; comparing with the last
    value the device had, not with the previous scan only, keeps the gap from hiding a change."""
    return _one_device_per_mac(conn.execute(
        "SELECT h.scan_id, h.ip, h.mac, h.firmware, h.web_info FROM hosts h JOIN scans s ON s.id = h.scan_id "
        "WHERE s.id < ? AND s.notes IS ? AND s.started_at >= ? ORDER BY s.id",
        (scan["id"], scan["notes"], common.iso_ago(days=days))).fetchall())


def _certs(h):
    """{port: {fingerprint, cn, not_after}} of a device's TLS ports (enrich.py puts them in web_info)."""
    try:
        web = json.loads(h["web_info"] or "{}") or {}
    except ValueError:
        return {}
    return {port: w["cert"] for port, w in web.items()
            if isinstance(w, dict) and (w.get("cert") or {}).get("fingerprint")}


def check_tls_changes(conn, scan_id, prev_id, hosts, history):
    """Per device (MAC, else IP) and port, against the certificate it last showed there. Keyed by IP
    and the first port that answered, an address handed to another device or a second port with its
    own certificate looked "replaced" (2026-10-26)."""
    last = {}
    for r in history:
        for port, c in _certs(r).items():
            last[(r["mac"] or r["ip"], port)] = c["fingerprint"]
    changed = []
    for h in hosts:
        who = h["mac"] or h["ip"]
        for port, c in sorted(_certs(h).items()):
            old = last.get((who, port))
            if old and old != c["fingerprint"] and common.is_new(conn, f"tls-change:{who}:{port}:{c['fingerprint']}"):
                changed.append((h, port, c))
    if not changed:
        return 0
    lines = [f"- {_name(conn, h)} ({h['ip']}), port {port}: new certificate {c.get('cn') or ''}, "
             f"valid until {c.get('not_after') or '?'}" for h, port, c in changed]
    common.write_alert(
        conn, "warning", common.plural(len(changed), "TLS certificate") + " replaced",
        "\n".join(lines) + "\n\nUsually a renewal or firmware update. If you didn't expect it, "
        "check the device before logging in to it.",
        kind="tls", scan_id=scan_id, prev_scan_id=prev_id,
    )
    return 1


def check_firmware(conn, scan_id, prev_id, hosts, history):
    last = {r["mac"]: r["firmware"] for r in history if r["mac"] and r["firmware"]}
    changed = [h for h in hosts if h["mac"] and h["firmware"] and last.get(h["mac"])
               and last[h["mac"]] != h["firmware"]
               and common.is_new(conn, f"fw:{h['mac']}:{h['firmware']}")]
    if not changed:
        return 0
    lines = [f"- {_name(conn, h)}: {last[h['mac']]} -> {h['firmware']}" for h in changed]
    common.write_info_alert(conn, "firmware", "info", common.plural(len(changed), "firmware update"),
                            "\n".join(lines), scan_id=scan_id, prev_scan_id=prev_id)
    return 1


def _on_subnet(net, ip):
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def check_ghost_targets(conn, scan_id):
    """Alert once per ghost address (see ghost_targets)."""
    ghosts = {ip: a for ip, a in ghost_targets(conn).items() if common.is_new(conn, f"ghost:{ip}")}
    if not ghosts:
        return 0
    lines = []
    for ip, a in sorted(ghosts.items(), key=lambda kv: -kv[1]["per_day"])[:30]:
        who = ", ".join(_host_label(conn, m) or m for m in sorted(a["askers"]))
        lines.append(f"- {ip}: about {a['per_day']:.0f} times a day since {a['since'][:10]}, by {who}")
    common.write_info_alert(
        conn, "ghost", "info", common.plural(len(ghosts), "address", "addresses") + " asked for that no device uses",
        "\n".join(lines) + f"\n\nNo device has used these addresses for {CLAIMED_DAYS} days. Usually an app "
        "or integration still polling a device that moved to another IP or was removed.",
        scan_id=scan_id)
    return 1


def listening_since(conn):
    """When the passive monitor recorded its first packet (ISO), or None."""
    return conn.execute("SELECT MIN(first_seen) FROM observations").fetchone()[0]


def ghost_targets(conn):
    """IPs that devices keep ARPing for but that no device uses: usually an
    integration (Home Assistant, a NAS, the TV) polling a device that moved.
    Returns {ip: {total, per_day, since, askers}}; the dashboard's map shows them too.

    Not ghosts (2026-10-13, after three info alerts that were all of these):
    LanWard's own ARP sweep, and any other device that sweeps the subnet (more than
    SWEEP_TARGETS unclaimed addresses in 24 h: the Asus access points' network map
    asked for 210 addresses at once on 2026-10-07); addresses off the subnet, i.e.
    link-local 169.254.x.x (self-assigned addresses, which the Sonos probes nightly,
    and 169.254.169.254, the cloud-metadata address some apps look for).

    In use (2026-10-26): an address some device claimed as its own in the last
    CLAIMED_DAYS days (DHCP request, ARP, mDNS). LanWard rarely sees ARP replies on
    a switched LAN, so "never answered" flagged a phone that was home for 20 minutes
    (.212 on 2026-10-20); a device checking its own address is not asking for anyone."""
    # "Nobody used it for a week" needs a week of listening (a fresh install: 2026-10-27).
    if not common.SUBNET or (listening_since(conn) or "9") > common.iso_ago(days=CLAIMED_DAYS):
        return {}
    me = common.own_mac()
    net = ipaddress.ip_network(common.SUBNET, strict=False)
    claimed = common.claimed_ipv4s(conn, common.iso_ago(days=CLAIMED_DAYS))
    rows = []
    for r in conn.execute("SELECT ip, mac, details, first_seen FROM observations "
                          "WHERE source = 'arp_req' AND last_seen >= ?", (common.iso_ago(hours=24),)):
        own = (json.loads(r["details"] or "{}") or {}).get("own_ip")
        if r["ip"] not in claimed and r["ip"] != own and r["mac"] != me and _on_subnet(net, r["ip"]):
            rows.append(r)
    targets = {}
    for r in rows:
        targets.setdefault(r["mac"], set()).add(r["ip"])
    sweepers = {mac for mac, ips in targets.items() if len(ips) > SWEEP_TARGETS}
    # Per address: the askers kept (not a sweeper, not LanWard itself) and when they first asked.
    by_ip = {}
    for r in rows:
        if r["mac"] in sweepers:
            continue
        e = by_ip.setdefault(r["ip"], {"askers": set(), "since": r["first_seen"]})
        e["askers"].add(r["mac"])
        e["since"] = min(e["since"], r["first_seen"])
    if not by_ip:
        return {}
    # Rate = the asks over the last GHOST_RATE_HOURS, from arp_ask_hours (the per-(asker, target, hour)
    # tally the monitor keeps): a true rolling 24-hour window, not a calendar-day average. The count over
    # 24 h is itself the per-day rate. Not the lifetime running count (overstates an old heavy poller).
    cutoff = common.iso_ago(hours=GHOST_RATE_HOURS)[:13]        # local "2026-10-31T14"
    ips = list(by_ip)
    recent, steady = {}, {}
    q = ("SELECT ip, mac, n FROM arp_ask_hours WHERE hour >= ? "
         "AND ip IN (%s)" % ",".join("?" * len(ips)))
    for r in conn.execute(q, [cutoff, *ips]):                   # one row per asker, address and hour
        if r["mac"] not in by_ip.get(r["ip"], {}).get("askers", ()):   # only the kept askers count
            continue
        recent[r["ip"]] = recent.get(r["ip"], 0) + r["n"]
        steady[r["ip"]] = steady.get(r["ip"], 0) + min(r["n"], GHOST_HOUR_CAP)
    out = {}
    for ip, e in by_ip.items():
        n = recent.get(ip, 0)
        per_day = n          # asks in the last 24 h = the per-day rate (shown); the test leaves out bursts
        if n >= GHOST_MIN_RECENT and steady.get(ip, 0) >= GHOST_MIN_PER_DAY:
            out[ip] = {"total": n, "per_day": per_day, "since": e["since"], "askers": e["askers"]}
    return out


def compute_alerts(scan_id):
    conn = common.connect()
    common.migrate(conn)
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        log(f"[!] No scan #{scan_id}")
        return 0
    hosts = conn.execute("SELECT * FROM hosts WHERE scan_id = ?", (scan_id,)).fetchall()
    prev = conn.execute(
        "SELECT id FROM scans WHERE subnet = ? AND id < ? AND notes = ? ORDER BY id DESC LIMIT 1",
        (scan["subnet"], scan_id, scan["notes"]),
    ).fetchone()
    prev_id = prev["id"] if prev else None
    # Every earlier scan counts, a Run scan of a few addresses too: it may be the one that saw the change.
    history = _history(conn, scan)
    single = _one_device_per_mac(hosts)

    n = check_findings(conn, scan_id, hosts)
    n += check_tls_changes(conn, scan_id, prev_id, single, history)
    n += check_firmware(conn, scan_id, prev_id, single, history)
    n += check_ghost_targets(conn, scan_id)
    n += check_new_ports(conn, scan_id, hosts)
    conn.commit()
    conn.close()
    log(f"[*] {n} alert(s) written for scan #{scan_id}")
    return n


def main():
    conn = common.connect()
    scan_id = int(sys.argv[1]) if len(sys.argv) > 1 else conn.execute(
        "SELECT MAX(id) FROM scans").fetchone()[0]
    conn.close()
    if not scan_id:
        sys.exit("No scans in the database.")
    compute_alerts(scan_id)


if __name__ == "__main__":
    main()
