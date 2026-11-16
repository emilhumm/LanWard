#!/usr/bin/env python3
"""What is behind each open port (2026-11-02), so LanWard can say what a device runs instead of a bare number: the
"Open ports" card on a device's page, Traffic's "What's running", the new-port alerts and the exports. Sources, the
most reliable that answers winning, and each answer says where it came from:

  1. the device's own announcement: the port of a service it announces over mDNS ("my AirPlay is on 7000"),
     heard by the passive monitor; nothing is sent
  2. what LanWard already read in this scan (enrich.py): the port's web page (title, else the server's own name)
     and the SSH banner
  3. its own port directory: rpcbind on port 111 lists which RPC program is on which port (NFS's helpers move to a
     new random port at every restart: Proxmox host, 1 Nov); one read-only DUMP call
  4. the port's own answer: nmap's light version check (--version-light) on just those ports
  5. the usual service for that port number, marked as a guess

1 and 2 cost nothing and run at every scan. 3 and 4 ask the network, gently: only ports nobody has named yet, at
most PHASE_MAX_PORTS a scan (new ports first), a port asked again only after RECHECK_DAYS, and never a temporary
port (EPHEMERAL_PORT up: phones and computers open and close those as apps run). The answers are kept per port in
open_ports_seen (what, how, sure, checked_at); a sure answer is never replaced by a guess. Nothing here changes
anything on a device; a source that fails is skipped.
"""
import json
import random
import re
import socket
import struct

import common
from common import log

MAX_PORTS = 12              # at most this many ports of one device are asked about at a time
PHASE_MAX_PORTS = 30        # ...and this many in one scan
RECHECK_DAYS = 30           # a port nothing could name is asked again after this long
NMAP_TIMEOUT = 90

HOW_ANNOUNCED = "the device's own announcement (mDNS)"
HOW_WEB = "its web page"
HOW_SSH = "its own answer"
HOW_RPC = "its own port directory (rpcbind)"
HOW_CHECK = "its own answer to a light check"
HOW_GUESS = "the usual service on that port number; the port didn't say"

# ONC RPC programs (rpcbind's directory), in plain words
RPC_PROGRAMS = {
    100000: "RPC port directory (rpcbind)", 100001: "system status (rstatd)", 100002: "logged-in users (rusersd)",
    100003: "NFS file sharing", 100004: "NIS directory (ypserv)", 100005: "NFS mount service (mountd)",
    100007: "NIS binding (ypbind)", 100009: "NIS passwords (yppasswdd)", 100011: "NFS disk quotas (rquotad)",
    100021: "NFS file locking (nlockmgr)", 100024: "NFS status monitor (statd)", 100227: "NFS access lists (nfs_acl)",
}

# nmap's service names in plain words; anything else keeps nmap's own name
NMAP_NAMES = {
    "http": "web server", "http-proxy": "web proxy", "http-alt": "web server", "https": "secure web server",
    "ssl/http": "secure web server", "ssh": "SSH login", "telnet": "Telnet login", "ftp": "FTP file transfer",
    "domain": "DNS", "rtsp": "camera or media stream (RTSP)", "mqtt": "smart home messages (MQTT)",
    "upnp": "UPnP device control", "microsoft-ds": "Windows file sharing (SMB)", "netbios-ssn": "Windows sharing",
    "vnc": "screen sharing (VNC)", "ms-wbt-server": "Windows remote desktop", "ipp": "printing (IPP)",
    "jetdirect": "printing", "rpcbind": "RPC port directory (rpcbind)", "nfs": "NFS file sharing",
    "mountd": "NFS mount service (mountd)", "nlockmgr": "NFS file locking (nlockmgr)",
    "status": "NFS status monitor (statd)", "mysql": "MySQL database", "postgresql": "PostgreSQL database",
    "redis": "Redis database", "mongodb": "MongoDB database", "memcache": "Memcached", "sip": "phone calls (SIP)",
    "airplay": "AirPlay", "rtsp-alt": "camera or media stream (RTSP)", "docker": "Docker API",
}

# A web page's title that says nothing about what it is (the server's own name says more)
GENERIC_TITLES = re.compile(r"^(error\b.*|\d{3}\b.*|redirecting\.*|not found|forbidden|unauthorized|"
                            r"document moved|object moved|index of /?)$", re.I)
# What a web server's own name says it is
SERVER_NAMES = [
    (re.compile(r"Sonos/"), "Sonos speaker control"),
    (re.compile(r"AirTunes/"), "AirPlay"),
    (re.compile(r"ShellyHTTP"), "Shelly control page"),
    (re.compile(r"MiniDLNA/([\d.]+)"), "media server (MiniDLNA {0})"),
]


def _announced(conn, mac):
    """{port: plain name} from the services `mac` announces over mDNS (passive-monitor.py's service_ports)."""
    out = {}
    for (details,) in conn.execute("SELECT details FROM observations WHERE source = 'mdns' AND mac = ?", (mac,)):
        ports = common.details_dict(details).get("service_ports")
        if not isinstance(ports, dict):
            continue
        for service, port in ports.items():
            if isinstance(port, int):
                out.setdefault(port, common.MDNS_SERVICE_NAMES.get(service) or service.strip("_").split("._")[0])
    return out


def web_label(entry):
    """What enrich.py's record of one port's web page says it is, or None: its title, else what the server's own
    name says (Sonos, AirPlay, Shelly...), else the server's name, else the status it answers."""
    if not entry:
        return None
    title = (entry.get("title") or "").strip()
    if title and not GENERIC_TITLES.match(title):
        return f'a web page, "{title}"'
    server = (entry.get("server") or "").strip()
    for pattern, plain in SERVER_NAMES:
        m = pattern.search(server)
        if m:
            return plain.format(*m.groups())
    if server:
        return f"a web server ({server})"
    if entry.get("status"):
        return f"a web server that answers {entry['status']} on its front page and gives no name"
    return None


def ssh_label(banner):
    """'SSH login (OpenSSH 10.3)' from an SSH banner ('SSH-2.0-OpenSSH_10.3'), or None."""
    m = re.match(r"SSH-[\d.]+-(\S+)", banner or "")
    return f"SSH login ({m.group(1).replace('_', ' ')})" if m else None


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError("connection closed")
        data += chunk
    return data


def rpc_directory(ip, timeout=3):
    """{port: plain name} of the TCP programs rpcbind on `ip` lists (PMAPPROC_DUMP, portmapper version 2), or {}."""
    xid = random.getrandbits(32)
    call = struct.pack(">10I", xid, 0, 2, 100000, 2, 4, 0, 0, 0, 0)      # CALL, RPC 2, portmapper v2 DUMP, no auth
    try:
        with socket.create_connection((ip, 111), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(struct.pack(">I", 0x80000000 | len(call)) + call)
            reply = b""
            while True:                                 # record marking: fragments until the last one
                head = struct.unpack(">I", _recv_exact(s, 4))[0]
                reply += _recv_exact(s, head & 0x7FFFFFFF)
                if head & 0x80000000 or len(reply) > 65536:
                    break
        return parse_rpc_dump(reply, xid)
    except (OSError, struct.error, ValueError):
        return {}


def parse_rpc_dump(reply, xid=None):
    """{port: plain name} from a PMAPPROC_DUMP reply body (TCP entries only)."""
    rxid, mtype, stat = struct.unpack(">3I", reply[:12])
    if (xid is not None and rxid != xid) or mtype != 1 or stat != 0:
        return {}
    verf_len = struct.unpack(">I", reply[16:20])[0]
    pos = 20 + (verf_len + 3) // 4 * 4
    if struct.unpack(">I", reply[pos:pos + 4])[0] != 0:          # accept_stat: SUCCESS
        return {}
    pos += 4
    out = {}
    while struct.unpack(">I", reply[pos:pos + 4])[0] == 1:          # value follows
        prog, _vers, prot, port = struct.unpack(">4I", reply[pos + 4:pos + 20])
        pos += 20
        if prot == 6 and port:                                      # TCP
            out.setdefault(port, RPC_PROGRAMS.get(prog, f"RPC program {prog}"))
    return out


def version_check(ip, ports):
    """{port: (plain name, nmap's detail)} from nmap's light version check of just these ports, for the ones it
    recognises (a guess marked with "?" or a bare "tcpwrapped" is no answer)."""
    try:
        from scan import run_nmap
    except Exception:                           # noqa: BLE001 - no scan module (tests), no answer
        return {}
    root = run_nmap(["-sV", "--version-light", "-Pn", "-n", "-T3", "--max-retries", "1",
                     "-p", ",".join(map(str, ports)), ip], NMAP_TIMEOUT)
    out = {}
    if root is None:
        return out
    for port in root.iter("port"):
        svc = port.find("service")
        state = port.find("state")
        if svc is None or state is None or state.get("state") != "open":
            continue
        name = (svc.get("name") or "").strip()
        if not name or name in ("unknown", "tcpwrapped") or name.endswith("?") or svc.get("method") == "table":
            continue
        if svc.get("tunnel") == "ssl" and name == "http":
            name = "ssl/http"
        product = " ".join(x for x in (svc.get("product"), svc.get("version")) if x).strip()
        plain = NMAP_NAMES.get(name, name)
        out[int(port.get("portid"))] = (plain, product)
    return out


def _id(what, how, sure=True):
    return {"what": what, "how": how, "sure": sure}


def free(conn, mac, ports, web=None, ssh_banner=None):
    """What costs nothing to know (sources 1 and 2): {port: {"what", "how", "sure"}} for the `ports` it names."""
    ports, web, out = set(ports), web or {}, {}
    try:
        for port, name in _announced(conn, mac).items():
            if port in ports:
                out[port] = _id(name, HOW_ANNOUNCED)
    except Exception as e:                      # noqa: BLE001
        log(f"    portid: announcements for {mac}: {e}")
    for port in ports - set(out):
        label = web_label(web.get(str(port)))
        if label:
            out[port] = _id(label, HOW_WEB)
    if 22 in ports and 22 not in out and ssh_label(ssh_banner):
        out[22] = _id(ssh_label(ssh_banner), HOW_SSH)
    return out


def ask(ip, ports, open_ports=()):
    """Sources 3 and 4, for `ports` of `ip`: its RPC directory when it has one (port 111), then the light check."""
    ports, out = sorted(ports)[:MAX_PORTS], {}
    if not ports or not ip:
        return out
    if 111 in set(open_ports) | set(ports):
        for port, name in rpc_directory(ip).items():
            if port in ports:
                out[port] = _id(name, HOW_RPC)
    left = [p for p in ports if p not in out]
    if left:
        try:
            for port, (plain, product) in version_check(ip, left).items():
                out[port] = _id(f"{plain} ({product})" if product else plain, HOW_CHECK)
        except Exception as e:                  # noqa: BLE001
            log(f"    portid: version check of {ip}: {e}")
    return out


def guess(port):
    label = common.port_label(port)
    return _id(label, HOW_GUESS, False) if label else None


def identify(conn, mac, ip, ports, open_ports=(), web=None, ssh_banner=None):
    """{port: {"what": plain words, "how": where that came from, "sure": False for a guess}} for `ports` of `mac`
    at `ip`, from every source in this file's docstring (new ports: the watcher, and alerts.py when the scan's own
    phase did not reach them). Ports nobody could name are left out."""
    ports = sorted(ports)[:MAX_PORTS]
    out = free(conn, mac, ports, web, ssh_banner)
    left = [p for p in ports if p not in out and p < common.EPHEMERAL_PORT]
    out.update(ask(ip, left, open_ports))
    for port in ports:
        if port not in out and guess(port):
            out[port] = guess(port)
    return out


def stored(conn, mac, ports=None):
    """{port: {"what", "how", "sure"}} kept for `mac` (all its ports, or just `ports`)."""
    rows = conn.execute("SELECT port, what, how, sure FROM open_ports_seen WHERE mac = ? AND what IS NOT NULL", (mac,))
    want = set(ports) if ports is not None else None
    return {r[0]: _id(r[1], r[2], bool(r[3])) for r in rows if want is None or r[0] in want}


def save(conn, mac, ids, checked=()):
    """Keep `ids` for `mac`'s ports, a guess never replacing a sure answer; `checked`: ports the network was just
    asked about (answered or not), so they are not asked again for RECHECK_DAYS."""
    for port, i in ids.items():
        sure = int(bool(i.get("sure")))
        conn.execute("UPDATE open_ports_seen SET what = ?, how = ?, sure = ? WHERE mac = ? AND port = ? "
                     "AND (what IS NULL OR COALESCE(sure, 0) <= ?)", (i["what"], i["how"], sure, mac, port, sure))
    now = common.now_iso()
    conn.executemany("UPDATE open_ports_seen SET checked_at = ? WHERE mac = ? AND port = ?",
                     [(now, mac, p) for p in checked])


def run_phase(conn, scan_id):
    """The scan's step (enrich.py, after the web pages): every open port of every device gets what costs nothing to
    know; ports nobody has named are asked about gently (see this file's docstring), new ones first."""
    log("[*] Phase P: what is behind each open port")
    hosts = conn.execute("SELECT ip, mac, open_ports, web_info, ssh_banner FROM hosts WHERE scan_id = ? "
                         "AND mac IS NOT NULL AND open_ports IS NOT NULL", (scan_id,)).fetchall()
    recheck, recent = common.iso_ago(days=RECHECK_DAYS), common.iso_ago(days=1)
    plans = []
    for h in hosts:
        mac, ports = h["mac"].lower(), json.loads(h["open_ports"] or "[]")
        if not ports:
            continue
        have = {r[0]: r for r in conn.execute(
            "SELECT port, what, sure, checked_at, first_seen FROM open_ports_seen WHERE mac = ?", (mac,))}
        ids = free(conn, mac, ports, json.loads(h["web_info"] or "{}"), h["ssh_banner"])
        unnamed = [p for p in ports if p not in ids and p < common.EPHEMERAL_PORT and p in have
                   and not have[p][2] and (have[p][3] or "") < recheck]
        new_first = sorted(unnamed, key=lambda p: (have[p][4] or "") < recent)
        plans.append([h, mac, ports, ids, new_first, have])
    budget = PHASE_MAX_PORTS
    for plan in sorted(plans, key=lambda pl: not any((pl[5][p][4] or "") >= recent for p in pl[4])):
        h, mac, ports, ids, unnamed, have = plan
        take = unnamed[:min(MAX_PORTS, budget)]
        if take and h["ip"]:
            budget -= len(take)
            ids.update(ask(h["ip"], take, ports))
        for port in ports:
            if port not in ids and not (port in have and have[port][1]) and guess(port):
                ids[port] = guess(port)
        plan.append(take)
    for h, mac, ports, ids, unnamed, have, take in plans:
        save(conn, mac, ids, take)
    conn.commit()
    named = sum(len(p[3]) for p in plans)
    log(f"    {named} port(s) named, {PHASE_MAX_PORTS - budget} asked about")


if __name__ == "__main__":
    import sys
    c = common.connect()
    host_ip, host_mac, *rest = sys.argv[1:]
    print(json.dumps(identify(c, host_mac, host_ip, [int(p) for p in rest], open_ports=[111]), indent=1))
