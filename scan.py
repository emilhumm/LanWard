#!/usr/bin/env python3
"""One LanWard run: find the devices on the LAN, check which home-relevant
TCP ports they have open, enrich them, run the home-security checks and write
alerts. The container's scheduler runs it every 6 hours; the dashboard's
"Run scan" button runs it on demand.

  python3 scan.py                         # scan $SUBNET (default: the LAN on the default-route interface)
  python3 scan.py --subnet 192.168.1.0/24
  python3 scan.py --no-enrich             # devices + ports only

Read-only and gentle: ARP sweep, then a TCP connect scan of the usual ports of
all devices at once (up to 64), at most 100 probes a second in all, one retry
and a 5-minute cap per host; once a day every port of each device. No exploits,
no logins, no password guessing.
"""
import argparse
import fcntl
import ipaddress
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime

import common
from common import log

# Ports that matter on a home network, with the label shown in the dashboard.
PORT_LABELS = {
    21: "ftp", 22: "ssh", 23: "telnet", 53: "dns", 80: "http", 139: "netbios",
    443: "https", 445: "smb", 548: "afp", 554: "rtsp", 631: "ipp", 873: "rsync",
    1400: "sonos", 1883: "mqtt", 2049: "nfs", 2323: "telnet-alt",
    2375: "docker-api", 3000: "http-3000", 3306: "mysql", 3389: "rdp",
    5000: "http-5000", 5432: "postgres", 5900: "vnc", 6053: "esphome",
    6379: "redis", 7547: "tr-069", 8006: "proxmox", 8008: "http-8008",
    8080: "http-alt", 8123: "home-assistant", 8443: "https-alt",
    8554: "rtsp-alt", 8883: "mqtts", 8971: "frigate", 9000: "http-9000",
    9100: "printer", 9443: "https-9443", 11211: "memcached", 27017: "mongodb",
    32400: "plex",
}
# The usual check: at most 100 probes a second for the whole network, all devices at once. A device that ignores
# probes no longer makes the scan wait on every port — every device also gets FULL_TIMING's far faster every-port
# probes once a day anyway.
NMAP_TIMING = ["-T3", "--max-rate", "100", "--max-retries", "1", "--host-timeout", "300s"]
# Every port (1-65535) of the devices whose turn it is (common.full_check_due), FULL_BATCH at a time: 800 to 1000
# probes a second in all, shared by the devices checked together (~160 each for 5), which small home devices cope
# with. One probe per port: a home LAN rarely loses one, and a port missed is found on the next turn. The minimum
# rate (2026-10-27): without it nmap kept slowing down on a device that answers nothing (it takes silence for a
# congested network), and a Nintendo Switch held the 16:00 scan for its full 20 minutes; at the minimum rate a
# silent device takes about 8 minutes at worst. One that takes over 10 is tried again on its next turn.
FULL_TIMING = ["-T3", "--max-retries", "0", "--min-rate", "800", "--max-rate", "1000", "--host-timeout", "10m"]
# For the SYN scan: the system finds each device's hardware address, with its retries, as for the connect scan.
# nmap's own lookup asks once at --max-retries 0, and a dozing Wi-Fi device that missed it was left out
# (a Windows PC and a tablet, 2026-10-27).
SYN_ARGS = ["-sS", "--send-ip"]
FULL_BATCH = 6
KNOWN_PORT_DAYS = 30    # ports a device had open in this many days are checked at every scan
# A second chance for devices the sweep missed (2026-10-27): a phone or tablet with its screen off dozes and can miss
# the sweep's one ARP question (an iPad heard all afternoon was missing from the 17:22 scan). Those in the previous
# scan or heard by the passive monitor in the last SECOND_CHANCE_MINUTES are asked again, more patiently; one that
# still does not answer but was heard in the last HEARD_MINUTES is counted anyway, its ports not checked.
SECOND_CHANCE_MINUTES = 30
HEARD_MINUTES = 10
PATIENT_ARP = ["-sn", "-PR", "--max-retries", "6", "--initial-rtt-timeout", "500ms", "--max-rtt-timeout", "2s"]
# The usual check, all devices at once (2026-10-27; was 10 at a time, one batch after another): each device still
# gets a probe every 500 ms, the network ~2 a second per device.
BATCH_SIZE = 64
SCAN_NOTES = "lanward home v2"      # written to scans.notes, so scans by this version can be told apart


class Tee:
    """Send the run's output to the container log and to scan-logs/<ts>.log."""

    def __init__(self, path):
        self.file = open(path, "a", buffering=1, encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, s):
        self.stdout.write(s)
        self.file.write(s)

    def flush(self):
        self.stdout.flush()
        self.file.flush()


def run_nmap(args, timeout):
    """Run nmap with XML output to a temp file and return the parsed root, or None when it failed.
    Whatever nmap says on stderr goes into the scan log."""
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        out = tmp.name
    try:
        proc = subprocess.run(["nmap", *args, "-oX", out], stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, timeout=timeout, check=False)
        said = proc.stderr.decode("utf-8", errors="replace").strip()
        if said:
            log(f"    nmap (exit {proc.returncode}): " + said[:2000].replace("\n", "\n        "))
        root = ET.parse(out).getroot()
        finished = root.find("runstats/finished")
        if finished is not None and finished.get("exit") == "error":
            log(f"[!] nmap failed: {finished.get('errormsg')}")
            return None
        return root
    except (ET.ParseError, subprocess.TimeoutExpired, OSError) as e:
        log(f"[!] nmap failed: {e}")
        return None
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass


def discover(subnet):
    """ARP sweep. Returns {ip: {mac, vendor, hostname}}, or None when nmap failed."""
    root = run_nmap(["-sn", "-T3", subnet], timeout=600)
    return None if root is None else up_hosts(root)


def up_hosts(root):
    """{ip: {mac, vendor, hostname}} of the hosts an nmap ping scan found up."""
    found = {}
    for host in root.findall("host"):
        if host.find("status") is None or host.find("status").get("state") != "up":
            continue
        ip = mac = vendor = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = common.norm_mac(addr.get("addr"))
                vendor = addr.get("vendor")
        name = host.find("hostnames/hostname")
        if ip:
            found[ip] = {"mac": mac, "vendor": vendor,
                         "hostname": name.get("name") if name is not None else None}
    return found


def second_chance(conn, subnet, hosts, me_ip):
    """The devices that should be here but missed the sweep (in the previous scan, or heard in the last
    SECOND_CHANCE_MINUTES), asked again with PATIENT_ARP; those that answer join `hosts`, and so do those still
    silent but heard in the last HEARD_MINUTES. Returns the addresses of the latter: counted, ports not checked."""
    net = ipaddress.ip_network(subnet, strict=False)
    expected = {}                                   # ip: (mac, when last heard or None)
    prev = conn.execute("SELECT MAX(id) FROM scans WHERE subnet = ?", (subnet,)).fetchone()[0]
    for ip, mac in conn.execute("SELECT ip, mac FROM hosts WHERE scan_id = ?", (prev,)) if prev else ():
        expected[ip] = (common.norm_mac(mac) if mac else None, None)
    for r in conn.execute("SELECT mac, source, ip, details, last_seen FROM observations WHERE last_seen >= ? "
                          "AND mac IS NOT NULL ORDER BY last_seen", (common.iso_ago(minutes=SECOND_CHANCE_MINUTES),)):
        ip = common.own_ip_of(r["source"], r["ip"], common.details_dict(r["details"]))
        if ip and ":" not in ip:
            expected[ip] = (common.norm_mac(r["mac"]), r["last_seen"])
    found_macs = {h["mac"] for h in hosts.values() if h["mac"]}
    missing = {ip: v for ip, v in expected.items()
               if ip not in hosts and ip != me_ip and (v[0] is None or v[0] not in found_macs)
               and ipaddress.ip_address(ip) in net}
    if not missing:
        return set()
    root = run_nmap([*PATIENT_ARP, *sorted(missing, key=ipaddress.ip_address)], timeout=300)
    answered = up_hosts(root) if root is not None else {}
    hosts.update(answered)
    recent, heard_only = common.iso_ago(minutes=HEARD_MINUTES), set()
    for ip, (mac, heard) in missing.items():
        if ip not in answered and mac and heard and heard >= recent \
                and mac not in {h["mac"] for h in hosts.values()}:
            hosts[ip] = {"mac": mac, "vendor": None, "hostname": None}
            heard_only.add(ip)
    log(f"    {common.plural(len(missing), 'device')} that should be here missed the sweep, asked again: "
        f"{len(answered)} answered" + (f"; counted as heard in the last {HEARD_MINUTES} minutes, ports not checked: "
                                        f"{', '.join(sorted(heard_only, key=ipaddress.ip_address))}" if heard_only else ""))
    return heard_only


def port_scan(ips, known=None, full=False):
    """TCP connect scan. Usually PORT_LABELS plus the ports `known` ({ip: ports}) lists for a device of the batch
    (found open on it before), politely timed; full=True: every port of each device (FULL_TIMING), as a half-open
    (SYN) scan when LanWard runs as root (in the container), which opens no connections on the device.
    Every device of a batch is checked at the same time (--min-hostgroup: nmap would otherwise start a full check
    with 4 and the rest after them).
    Returns {ip: [open ports]}, with None for a device whose check did not finish (its host timeout, or the
    batch's nmap failed): unknown, which used to be saved as "no open ports" and made its findings vanish
    (2026-10-26)."""
    result = {ip: None for ip in ips}
    size = FULL_BATCH if full else BATCH_SIZE
    batches = [ips[i:i + size] for i in range(0, len(ips), size)]
    for n, batch in enumerate(batches, 1):
        t0 = time.time()
        if full:
            kind = SYN_ARGS if hasattr(os, "geteuid") and os.geteuid() == 0 else ["-sT"]
            args, timeout = [*kind, *FULL_TIMING, "-p", "1-65535"], 1200
        else:
            extra = set().union(*((known or {}).get(ip, ()) for ip in batch))
            args, timeout = ["-sT", *NMAP_TIMING, "-p", ",".join(str(p) for p in sorted(set(PORT_LABELS) | extra))], 900
        root = run_nmap(["-Pn", "--min-hostgroup", str(len(batch)), *args, *batch], timeout=timeout)
        timed_out, took = [], []
        if root is not None:
            for host in root.findall("host"):
                addr = host.find("address[@addrtype='ipv4']")
                if addr is None:
                    continue
                ip = addr.get("addr")
                if host.get("starttime", "").isdigit() and host.get("endtime", "").isdigit():
                    took.append((int(host.get("endtime")) - int(host.get("starttime")), ip))
                if host.get("timedout") == "true":
                    timed_out.append(ip)
                    continue
                result[ip] = sorted({int(port.get("portid")) for port in host.findall("ports/port")
                                     if port.find("state") is not None
                                     and port.find("state").get("state") == "open"})
        note = f", timed out: {', '.join(timed_out)}" if timed_out else ""
        if root is None:
            note += ", nmap failed: ports not checked"
        log(f"    batch {n}/{len(batches)}: {len(batch)} host(s) in {time.time() - t0:.0f}s{note}")
        if full and took:           # which device took how long, slowest first
            log("    " + ", ".join(f"{ip} {secs // 60}m{secs % 60:02d}s" for secs, ip in sorted(took, reverse=True)))
    return result


def device_ids(hosts, shared):
    """{ip: the MAC that names the device there}, for the every-port rota and the port history: the MAC it answers
    ARP with, except where several addresses answer with one (Sonos speakers behind a SonosNet bridge answer with
    the bridge's). There, a Sonos speaker's own MAC from the RINCON id in its description on port 1400, as the
    UPnP phase (enrich.py) reads it later; an address that gives none is left out. Until 2026-10-27 all of them
    were left out: no every-port check, no port history, no new-port alerts."""
    ids = {ip: h["mac"] for ip, h in hosts.items() if h["mac"] and h["mac"] not in shared}
    behind = [ip for ip, h in hosts.items() if h["mac"] in shared]
    if not behind:
        return ids
    import enrich as enrich_mod      # noqa: E402  (db/ is on sys.path)
    from concurrent.futures import ThreadPoolExecutor

    def own_mac(ip):
        return enrich_mod.sonos_mac(enrich_mod.follow_upnp_location(f"http://{ip}:1400/xml/device_description.xml"))
    with ThreadPoolExecutor(max_workers=8) as pool:
        found = {ip: mac for ip, mac in zip(behind, pool.map(own_mac, behind)) if mac}
    ids.update(found)
    log(f"    {common.plural(len(behind), 'address', 'addresses')} share a MAC; "
        + (f"{len(found)} known by their Sonos id" if found else "none gives a Sonos id, left out of the port history"))
    return ids


def known_ports(conn, ids):
    """{ip: ports found open on it in the last KNOWN_PORT_DAYS days that PORT_LABELS does not list}: checked again
    at every scan, so a service found by a full check is followed from then on. `ids`: device_ids()."""
    by_mac = {}
    for mac, port in conn.execute("SELECT mac, port FROM open_ports_seen WHERE last_seen >= ?",
                                  (common.iso_ago(days=KNOWN_PORT_DAYS),)):
        if port not in PORT_LABELS:
            by_mac.setdefault(mac, set()).add(port)
    return {ip: by_mac[mac] for ip, mac in ids.items() if mac in by_mac}


def scans_per_day():
    hours = {h.strip() for h in common.setting("SCAN_HOURS").split(",") if h.strip().isdigit() and int(h) < 24}
    return len(hours) or 1          # none scheduled: each Run scan does a day's share


def record_ports(conn, scan_id, ids, ports, fully_checked, me_ip):
    """Each device's open ports into its history (common.record_open_ports), under the MAC device_ids() gives it
    (an address without one has no history); ports a device never had open before go in its hosts row's
    new_ports for alerts.py. LanWard's own machine's new ports are the watcher's, which reads them every minute."""
    for ip, found in ports.items():
        mac = ids.get(ip)
        if found is None or not mac:
            continue
        new = common.record_open_ports(conn, mac, found, full=ip in fully_checked)
        if new and ip != me_ip:
            conn.execute("UPDATE hosts SET new_ports = ? WHERE scan_id = ? AND ip = ?", (json.dumps(new), scan_id, ip))
    conn.commit()


def passive_hostnames(conn):
    """Latest DHCP hostname from the passive monitor: per MAC, and per (MAC, address it asked for)."""
    names, by_ip = {}, {}
    for r in conn.execute(
        "SELECT LOWER(mac) AS mac, ip, hostname, details FROM observations "
        "WHERE source = 'dhcp' AND hostname IS NOT NULL AND hostname <> '' "
        "ORDER BY last_seen"
    ):
        names[r["mac"]] = r["hostname"]
        ip = common.own_ip_of("dhcp", r["ip"], common.details_dict(r["details"]))
        if ip:
            by_ip[(r["mac"], ip)] = r["hostname"]
    return names, by_ip


def save_scan(conn, subnet, started, hosts, ports):
    cur = conn.execute(
        "INSERT INTO scans (subnet, started_at, host_count, notes) VALUES (?, ?, ?, ?)",
        (subnet, started, len(hosts), SCAN_NOTES),
    )
    scan_id = cur.lastrowid
    for ip, h in hosts.items():
        open_ports = ports.get(ip)          # None: not checked, saved as NULL (unknown)
        conn.execute(
            "INSERT INTO hosts (scan_id, ip, mac, vendor, hostname, ports, open_ports) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, ip, h["mac"], h["vendor"], h["hostname"],
             ",".join(PORT_LABELS.get(p, str(p)) for p in open_ports or []) or None,
             None if open_ports is None else json.dumps(open_ports)),
        )
    conn.commit()
    return scan_id


def scan(subnet, enrich=True):
    started = datetime.now().isoformat(timespec="seconds")
    t0 = time.time()
    conn = common.connect()
    common.migrate(conn)

    log(f"[*] Scan of {subnet} starting")
    log("[*] Device discovery (ARP sweep)")
    hosts = discover(subnet)
    if not hosts:
        log("[!] Device discovery failed (nmap, above); no scan saved" if hosts is None
            else "[!] No devices answered; not saving an empty scan")
        conn.close()
        return None
    me_ip, me_mac = common.own_ip(), common.own_mac()
    heard_only = second_chance(conn, subnet, hosts, me_ip)

    # nmap leaves out its own MAC; DHCP names fill hostnames the PTR lookup lacks.
    if me_ip in hosts:
        hosts[me_ip].update(mac=hosts[me_ip]["mac"] or me_mac,
                            hostname=hosts[me_ip]["hostname"] or socket.gethostname())
    dhcp_names, dhcp_by_ip = passive_hostnames(conn)
    # A MAC that answers for several addresses (Sonos speakers behind a SonosNet bridge answer
    # with the bridge's; enrich.py gives them their own) names only the address its DHCP lease is for.
    macs = [h["mac"] for h in hosts.values() if h["mac"]]
    shared = {m for m in macs if macs.count(m) > 1}
    for ip, h in hosts.items():
        if h["mac"]:
            h["vendor"] = h["vendor"] or common.vendor_for(h["mac"])
            h["hostname"] = h["hostname"] or (dhcp_by_ip.get((h["mac"], ip)) if h["mac"] in shared
                                              else dhcp_names.get(h["mac"]))
    log(f"    {len(hosts)} device(s) up")

    ips = sorted(hosts, key=lambda ip: ipaddress.ip_address(ip))
    # LanWard's own machine: the ports it listens on, read directly (exact). The other devices: every port of the
    # ones whose turn it is, then the usual ports plus the ones found open before for the rest.
    own = common.own_listening_ports() if me_ip in hosts else None
    targets = [ip for ip in ips if not (own is not None and ip == me_ip) and ip not in heard_only]
    ids = device_ids(hosts, shared)
    mac_of = {ip: ids[ip] for ip in targets if ip in ids}
    due = set(common.full_check_due(conn, sorted(set(mac_of.values())), scans_per_day()))
    full_ips = [ip for ip in targets if mac_of.get(ip) in due]
    full = {}
    if full_ips:
        log(f"[*] Every port (1-65535) of {common.plural(len(full_ips), 'device')}, whose turn it is: {', '.join(full_ips)}")
        common.mark_full_tried(conn, [mac_of[ip] for ip in full_ips])
        conn.commit()
        full = {ip: found for ip, found in port_scan(full_ips, full=True).items() if found is not None}
        # Nothing open on a device that had ports open lately: more likely it did not answer than closed them all
        had = {r[0] for r in conn.execute("SELECT DISTINCT mac FROM open_ports_seen WHERE last_seen >= ?",
                                          (common.iso_ago(days=KNOWN_PORT_DAYS),))}
        full = {ip: found for ip, found in full.items() if found or mac_of[ip] not in had}
        missed = [ip for ip in full_ips if ip not in full]
        if missed:
            log(f"    not finished, the usual ports instead: {', '.join(missed)}")
    known = known_ports(conn, ids)
    rest = [ip for ip in targets if ip not in full]
    n_known = len(set().union(*(known.get(ip, ()) for ip in rest)))
    log(f"[*] Port check: {len(PORT_LABELS)} home-relevant TCP ports"
        + (f" and {common.plural(n_known, 'port')} found open before" if n_known else ""))
    ports = port_scan(rest, known)
    ports.update(full)
    ports.update({ip: None for ip in heard_only})          # did not answer: ports not checked
    if own is not None:
        ports[me_ip] = own
        log(f"    {me_ip} (LanWard's own machine): listens on {', '.join(map(str, own)) or 'nothing'}")
    scan_id = save_scan(conn, subnet, started, hosts, ports)
    record_ports(conn, scan_id, ids, ports, set(full) | ({me_ip} if own is not None else set()), me_ip)
    conn.close()
    unchecked = sum(1 for p in ports.values() if p is None)
    log(f"[*] Saved scan #{scan_id}: {len(hosts)} devices, "
        f"{sum(1 for p in ports.values() if p)} with open ports"
        f"{f', {unchecked} not checked' if unchecked else ''} ({time.time() - t0:.0f}s)")

    if enrich:
        import enrich as enrich_mod      # noqa: E402  (db/ is on sys.path)
        import homechecks
        enrich_mod.enrich_scan(scan_id)
        homechecks.run(scan_id)
    import alerts
    alerts.compute_alerts(scan_id)
    log(f"[*] Scan #{scan_id} complete in {time.time() - t0:.0f}s")
    return scan_id


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--subnet", default=common.SUBNET)
    ap.add_argument("--no-enrich", action="store_true")
    ap.add_argument("--log", help="log file (default scan-logs/<timestamp>.log)")
    args = ap.parse_args()
    if not args.subnet:
        sys.exit(f"No network to scan: set SUBNET in .env (none could be read from {common.IFACE}).")
    ipaddress.ip_network(args.subnet, strict=False)     # fail fast on a typo

    common.SCAN_LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = args.log or str(common.SCAN_LOG_DIR / f"{datetime.now():%Y%m%d-%H%M%S}.log")
    sys.stdout = Tee(log_path)

    # One scan at a time, whoever started it (scheduler or dashboard).
    flock = open(common.DATA_DIR / ".scan.flock", "w")
    try:
        fcntl.flock(flock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log("[!] Another scan is already running")
        sys.exit(3)
    common.SCAN_LOCK.write_text(f"{os.getpid()}\n{log_path}\n{args.subnet}\n")
    try:
        if scan(args.subnet, enrich=not args.no_enrich) is None:
            sys.exit(1)                     # nothing saved: the scheduler logs a failed run
    except Exception:
        # Into the scan log too: only stdout is teed, and a scan started from the dashboard
        # has no stderr at all.
        log("[!] Scan failed:\n" + traceback.format_exc())
        raise
    finally:
        try:
            if common.SCAN_LOCK.read_text().split("\n", 1)[0] == str(os.getpid()):
                common.SCAN_LOCK.unlink()
        except OSError:
            pass


if __name__ == "__main__":
    sys.path.insert(0, str(common.ROOT / "db"))
    main()
