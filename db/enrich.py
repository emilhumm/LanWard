#!/usr/bin/env python3
"""Enrich a scan's devices with what they say about themselves. Read-only.

  A  SSH banner, web page per HTTP(S) port (status, server, title, login
     page?), TLS certificate, reverse DNS
  B  UPnP / SSDP (also: does the router offer UPnP port forwarding? Sonos
     speakers behind a SonosNet bridge get their own MAC from their RINCON id)
  C  mDNS services (a burst of queries; replies are read from what the
     passive monitor captures)
  H  WS-Discovery (Windows PCs, printers, ONVIF cameras)
  I  IPv6 link-local addresses
  P  what is behind each open port (portid.py: the web pages above, announcements, and a gentle check of the
     ports nothing has named yet)

Usage: enrich.py [scan_id]        # defaults to the latest scan
"""
import json
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import common  # noqa: E402
from common import log  # noqa: E402

HTTP_PORTS = {80, 1400, 3000, 5000, 8008, 8080, 8123, 9000, 32400}
TLS_PORTS = [443, 8006, 8443, 9443, 8971]           # certificate priority order
# Telnet's ports, asked for a web page too: Fully Kiosk Browser's remote admin (wall tablets) is HTTP on 2323, and
# was reported as "Telnet (port 2323) is open" in every scan. A real Telnet server does not answer HTTP (http_get
# returns no status), so only ports that do get relabelled and lose the Telnet finding (homechecks.py).
TELNET_PORTS = {23: "telnet", 2323: "telnet-alt"}
# Ports that are no web page: everything else open (the ports a full check finds, 2026-10-27) is asked for one,
# over HTTP and else HTTPS, up to OTHER_WEB_MAX of them per device.
NOT_WEB_PORTS = {21, 22, 25, 53, 110, 139, 143, 445, 548, 554, 631, 873, 993, 995, 1400, 1883, 2049, 3306, 3389,
                 5432, 5900, 6053, 6379, 7547, 8554, 8883, 9100, 11211, 27017, 62078}
OTHER_WEB_MAX = 20
MDNS_ADDR = ("224.0.0.251", 5353)
SSDP_ADDR = ("239.255.255.250", 1900)
IGD_RE = re.compile(r"InternetGatewayDevice|WAN(IP|PPP)Connection")     # a router's port-mapping service


# ============================================================  A: banners, web, TLS

def grab_ssh_banner(ip, timeout=3):
    """The server's version line ("SSH-2.0-OpenSSH_9.6"). RFC 4253 lets a server send other lines first; a reply
    of blank lines used to raise IndexError and end the whole enrichment (2026-10-26)."""
    try:
        with socket.create_connection((ip, 22), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
    except OSError:
        return None
    lines = [l.strip() for l in data.decode("utf-8", errors="replace").splitlines() if l.strip()]
    line = next((l for l in lines if l.startswith("SSH-")), lines[0] if lines else None)
    return line[:200] if line else None


def web_page(ip, port, tls):
    """GET / on one port: status, server, title and whether it asks for a
    password (and how)."""
    status, headers, text = common.http_get(ip, port, tls=tls, timeout=4)
    if status is None:
        return None
    info = {"status": status, "tls": tls}
    if headers.get("server"):
        info["server"] = headers["server"][:120]
    if headers.get("location"):
        info["redirect"] = headers["location"][:200]
    m = re.search(r"<title[^>]*>([^<]+)</title>", text, re.I | re.S)
    if not m and 300 <= status < 400 and headers.get("location", "").startswith("/"):
        # A page that sends you on within the same site ("/" -> "/login") is named by where it sends you
        _, _, target = common.http_get(ip, port, tls=tls, path=headers["location"], timeout=4)
        m = re.search(r"<title[^>]*>([^<]+)</title>", target, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()
        if title:
            info["title"] = title[:120]
    auth = headers.get("www-authenticate", "").lower()
    if status == 401 and auth.startswith("basic"):
        info["login"] = "basic"
    elif status == 401 and auth:
        info["login"] = auth.split()[0]
    elif re.search(r"""type\s*=\s*["']?password""", text, re.I):
        info["login"] = "form"
    return info


def reverse_dns(ip, timeout=2):
    """PTR name, or None. gethostbyaddr ignores socket timeouts, so it runs in a thread
    that is given up on after `timeout` seconds."""
    found = []

    def lookup():
        try:
            found.append(socket.gethostbyaddr(ip)[0])
        except (OSError, UnicodeError):
            pass

    t = threading.Thread(target=lookup, daemon=True)
    t.start()
    t.join(timeout)
    return found[0][:120] if found and found[0] else None


def _tls_context():
    """No certificate checks, old protocol versions and ciphers allowed: as common.http_get, so a device whose web
    page LanWard can read also gives its certificate (TLS 1.0-only devices had a page but no certificate)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    return ctx


def _dn_value(line, attr="CN"):
    """One attribute of a name as openssl prints it with -nameopt RFC2253 ("subject=O=Acme\\, Inc,CN=nas"),
    unescaped: "\\," is a comma inside the value, "\\C3\\98" two UTF-8 bytes."""
    m = re.search(rf"(?:^|[=,+]){attr}=((?:\\.|[^,+\\])+)", line)
    if not m:
        return None
    raw = re.sub(rb"\\([0-9A-Fa-f]{2}|.)",
                 lambda e: bytes([int(e.group(1), 16)]) if len(e.group(1)) == 2 else e.group(1),
                 m.group(1).encode())
    return raw.decode("utf-8", errors="replace").strip() or None


def get_tls_cert(ip, port, timeout=4):
    """cn, issuer, not_before, not_after, fingerprint, sans via the openssl CLI
    (Python's getpeercert() is empty for unverified, self-signed certs)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with _tls_context().wrap_socket(raw) as s:
                der = s.getpeercert(binary_form=True)
        if not der:
            return {}
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-startdate",
             "-enddate", "-fingerprint", "-sha256", "-ext", "subjectAltName",
             "-nameopt", "RFC2253"],
            input=ssl.DER_cert_to_PEM_cert(der), capture_output=True, text=True, timeout=5,
        )
    except (OSError, ssl.SSLError, ValueError, subprocess.TimeoutExpired):
        return {}
    out = {}
    for line in proc.stdout.splitlines():
        if line.startswith("subject="):
            cn = _dn_value(line)
            if cn:
                out["cn"] = cn[:120]
        elif line.startswith("issuer="):
            cn = _dn_value(line)
            if cn:
                out["issuer"] = cn[:120]
        elif line.startswith("notBefore="):
            out["not_before"] = line.split("=", 1)[1].strip()[:64]
        elif line.startswith("notAfter="):
            out["not_after"] = line.split("=", 1)[1].strip()[:64]
        elif line.lower().startswith("sha256 fingerprint="):
            out["fingerprint"] = line.split("=", 1)[1].strip().replace(":", "").lower()[:64]
        elif "DNS:" in line or "IP Address:" in line:
            sans = re.findall(r"(?:DNS|IP Address):([^,\s]+)", line)
            if sans:
                out["sans"] = ",".join(sans)[:300]
    return out


def run_phase_banners(conn, hosts, scan_id):
    log("[*] Phase A: SSH banner, web pages, TLS certificates, reverse DNS")
    rows = []
    for h in hosts:
        ip = h["ip"]
        ports = set(json.loads(h["open_ports"] or "[]"))
        ssh = grab_ssh_banner(ip) if 22 in ports else None
        web = {}
        for port in sorted(ports & (HTTP_PORTS | set(TLS_PORTS) | set(TELNET_PORTS))):
            page = web_page(ip, port, tls=port in TLS_PORTS)
            if page:
                web[str(port)] = page
        labels = (h["ports"] or "").split(",") if h["ports"] else []
        other = sorted(ports - HTTP_PORTS - set(TLS_PORTS) - set(TELNET_PORTS) - NOT_WEB_PORTS)
        for port in other[:OTHER_WEB_MAX]:
            page = web_page(ip, port, tls=False)
            if page is None or page["status"] == 400:      # 400: plain HTTP sent to an HTTPS port
                page = web_page(ip, port, tls=True) or page
            if page:
                web[str(port)] = page
                if str(port) in labels:                     # PORT_LABELS has no name for it: say what it is
                    labels[labels.index(str(port))] = f"{'https' if page['tls'] else 'http'}-{port}"
        for port, telnet_label in TELNET_PORTS.items():
            if str(port) in web and telnet_label in labels:
                labels[labels.index(telnet_label)] = f"http-{port}"
        server = next((w["server"] for w in web.values() if w.get("server")), None)
        title = next((w["title"] for w in web.values() if w.get("title")), None)
        # Each TLS port's certificate goes with its web page, for alerts.py to compare port by port (a device
        # whose 443 and 8443 differ looked "replaced" whenever 443 missed a scan). The host's tls_cert_* columns
        # keep the first one in TLS_PORTS order.
        cert = {}
        for port in TLS_PORTS:
            if port in ports:
                c = get_tls_cert(ip, port)
                if c and str(port) in web:
                    web[str(port)]["cert"] = {k: c[k] for k in ("fingerprint", "cn", "not_after") if c.get(k)}
                cert = cert or c
        hostname = h["hostname"] or reverse_dns(ip)
        rows.append((ssh, json.dumps(web) if web else None, server, title,
                     cert.get("cn"), cert.get("issuer"), cert.get("not_before"),
                     cert.get("not_after"), cert.get("fingerprint"), cert.get("sans"),
                     hostname, ",".join(labels) if labels else h["ports"], scan_id, ip))
    # Written in one go after the network work: holding the write lock across it made the passive
    # monitor and the watcher wait, then fail with "database is locked" (2026-10-26).
    conn.executemany(
        "UPDATE hosts SET ssh_banner=?, web_info=?, http_server=?, http_title=?, "
        "tls_cert_cn=?, tls_cert_issuer=?, tls_cert_not_before=?, tls_cert_not_after=?, "
        "tls_cert_fingerprint=?, tls_cert_san=?, hostname=?, ports=? WHERE scan_id=? AND ip=?", rows)
    conn.commit()


# ============================================================  B: UPnP / SSDP

def _own_url(url, ip):
    """A LOCATION LanWard may fetch: http(s) on the responder's own address, nothing else."""
    try:
        u = urllib.parse.urlparse(url)
        return u.scheme in ("http", "https") and u.hostname == ip
    except ValueError:
        return False


def ssdp_discover(timeout=5):
    """{ip: {st, server, location}}. A device can answer for several root devices, each with its own
    LOCATION (a router's media server besides its Internet gateway); the gateway's is kept then, so
    homechecks.py finds the port-mapping service (2026-10-26)."""
    msg = ("M-SEARCH * HTTP/1.1\r\n"
           f"HOST: {SSDP_ADDR[0]}:{SSDP_ADDR[1]}\r\n"
           'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
    results = defaultdict(lambda: {"st": set()})
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(timeout)
    try:
        try:
            sock.sendto(msg.encode(), SSDP_ADDR)
        except OSError as e:
            log(f"    [!] could not send the SSDP search: {e}")
            return results
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:                     # timeout
                break
            entry = results[addr[0]]
            head = {}
            for line in data.decode("utf-8", errors="replace").splitlines():
                k, sep, v = line.partition(":")
                if sep:
                    head[k.strip().upper()] = v.strip()
            if head.get("ST"):
                entry["st"].add(head["ST"])
            if head.get("SERVER"):
                entry.setdefault("server", head["SERVER"])
            location = head.get("LOCATION")
            if location and _own_url(location, addr[0]):
                if IGD_RE.search(head.get("ST", "")):
                    entry["location"] = location
                else:
                    entry.setdefault("location", location)
    finally:
        sock.close()
    return results


def follow_upnp_location(url, timeout=3):
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": common.USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            xml = resp.read(65536).decode("utf-8", errors="replace")
    except Exception:
        return {}
    info = {}
    for tag in ("friendlyName", "manufacturer", "modelName", "modelNumber", "UDN"):
        m = re.search(f"<{tag}>([^<]+)</{tag}>", xml)
        if m:
            info[tag] = m.group(1).strip()[:120]
    return info


def sonos_mac(info):
    """A Sonos speaker's own MAC from its RINCON id (UDN "uuid:RINCON_542A1B00AA0101400", also at the end
    of its friendlyName): RINCON_ + the 12 hex digits of the MAC + "01400". None for anything else."""
    m = re.search(r"RINCON_([0-9A-Fa-f]{12})", f"{info.get('UDN') or ''} {info.get('friendlyName') or ''}")
    mac = common.norm_mac(":".join(m.group(1)[i:i + 2] for i in range(0, 12, 2))) if m else None
    return mac if common.mac_is_device(mac) else None


def run_phase_ssdp(conn, scan_id):
    log("[*] Phase B: UPnP / SSDP")
    found = ssdp_discover()
    rows = []
    for ip, data in found.items():
        info = {"server": data.get("server"), "location": data.get("location"),
                "st": sorted(data["st"])[:40]}
        if data.get("location"):
            info.update(follow_upnp_location(data["location"]))
        info = {k: v for k, v in info.items() if v}
        m = re.search(r"Sonos/(\S+)", info.get("server") or "")
        rows.append((ip, info, f"Sonos {m.group(1)}" if m else None))
    # SonosNet (2026-10-27): speakers behind the bridging speaker answer ARP with its MAC, so one MAC
    # stands for several addresses; each one's RINCON id names its own. Only a MAC that several addresses
    # share is replaced: a Sonos on Wi-Fi of its own answers with a MAC that need not be the RINCON one,
    # and the passive monitor, labels and watcher know it by that.
    macs = {r["ip"]: r["mac"] for r in conn.execute("SELECT ip, mac FROM hosts WHERE scan_id=?", (scan_id,))}
    sharing = defaultdict(int)
    for mac in macs.values():
        if mac:
            sharing[mac] += 1
    moved = []
    for ip, info, _ in rows:
        own, wire = sonos_mac(info), macs.get(ip)
        if own and wire and own != wire and sharing[wire] > 1:
            name = conn.execute("SELECT hostname FROM observations WHERE source = 'dhcp' AND mac = ? AND hostname <> '' "
                                "ORDER BY last_seen DESC LIMIT 1", (own,)).fetchone()
            moved.append((own, wire, common.vendor_for(own), name["hostname"] if name else None, scan_id, ip))
    for ip, info, firmware in rows:           # after the HTTP fetches: a short write
        conn.execute("UPDATE hosts SET upnp_info=? WHERE scan_id=? AND ip=?",
                     (json.dumps(info), scan_id, ip))
        if firmware:
            conn.execute("UPDATE hosts SET firmware=? WHERE scan_id=? AND ip=? AND firmware IS NULL",
                         (firmware, scan_id, ip))
    # The DHCP name of the shared MAC was the bridging speaker's (scan.py leaves it out); the speaker's own, if any.
    conn.executemany("UPDATE hosts SET mac=?, bridge_mac=?, vendor=COALESCE(NULLIF(vendor, ''), ?), "
                     "hostname=COALESCE(hostname, ?) WHERE scan_id=? AND ip=?", moved)
    conn.commit()
    log(f"    {len(found)} UPnP responder(s)"
        + (f"; {common.plural(len(moved), 'Sonos speaker')} behind a SonosNet bridge, MAC from the RINCON id"
           if moved else ""))


# ============================================================  C: mDNS

MDNS_QUERIES = [
    "_services._dns-sd._udp.local", "_http._tcp.local", "_https._tcp.local",
    "_ssh._tcp.local", "_ipp._tcp.local", "_printer._tcp.local", "_smb._tcp.local",
    "_airplay._tcp.local", "_raop._tcp.local", "_googlecast._tcp.local",
    "_hap._tcp.local", "_homekit._tcp.local", "_hue._tcp.local", "_sonos._tcp.local",
    "_spotify-connect._tcp.local", "_device-info._tcp.local", "_shelly._tcp.local",
    "_esphomelib._tcp.local", "_home-assistant._tcp.local", "_mqtt._tcp.local",
    "_workstation._tcp.local", "_amzn-alexa._tcp.local", "_rtsp._tcp.local",
]


def _mdns_query(name):
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\x00"
    return struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + qname + struct.pack(">HH", 12, 1)


def run_phase_mdns(conn, hosts, scan_id):
    """Ask for common service types so quiet devices announce themselves; the
    passive monitor captures the answers into observations."""
    log("[*] Phase C: mDNS services")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        for q in MDNS_QUERIES:
            sock.sendto(_mdns_query(q), MDNS_ADDR)
        sock.close()
    except OSError as e:
        log(f"    [!] could not send mDNS queries: {e}")
    time.sleep(6)
    cutoff = common.iso_ago(days=7)
    # Behind a SonosNet bridge the packets carry the bridge's MAC for every speaker, the bridge's own too:
    # for a MAC on the wire for several devices, only the rows at the device's address are its own.
    wire = defaultdict(int)
    for h in hosts:
        if h["mac"]:
            wire[h["bridge_mac"] or h["mac"]] += 1
    n = 0
    for h in hosts:
        if not h["mac"]:
            continue
        mac = h["bridge_mac"] or h["mac"]
        where, args = ("mac=? AND ip=?", (mac, h["ip"])) if wire[mac] > 1 else ("mac=?", (mac,))
        services = set()
        for r in conn.execute(
            f"SELECT details FROM observations WHERE source='mdns' AND {where} AND last_seen >= ?",
            (*args, cutoff),
        ):
            try:
                services.update(json.loads(r["details"] or "{}").get("services_adv") or [])
            except ValueError:
                pass
        if services:
            n += 1
            conn.execute("UPDATE hosts SET mdns_services=? WHERE scan_id=? AND ip=?",
                         (",".join(sorted(services)), scan_id, h["ip"]))
    conn.commit()
    log(f"    {n} device(s) advertise mDNS services")


# ============================================================  H: WS-Discovery

def wsd_discover(timeout=5):
    # A new MessageID per probe: responders may drop a message ID they have already answered.
    probe = f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <s:Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
    <a:MessageID>urn:uuid:{uuid.uuid4()}</a:MessageID>
    <a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
  </s:Header>
  <s:Body><d:Probe/></s:Body>
</s:Envelope>"""
    results = defaultdict(dict)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    sock.settimeout(timeout)
    try:
        try:
            sock.sendto(probe.encode(), ("239.255.255.250", 3702))
        except OSError as e:
            log(f"    [!] could not send the WS-Discovery probe: {e}")
            return results
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(8192)
            except OSError:                     # timeout
                break
            xml = data.decode("utf-8", errors="replace")
            for tag in ("Types", "XAddrs"):
                m = re.search(f"<[^>]*{tag}[^>]*>([^<]+)</[^>]*{tag}>", xml)
                if m:
                    results[addr[0]][tag] = m.group(1).strip()[:200]
    finally:
        sock.close()
    return results


def run_phase_wsd(conn, hosts):
    """Stored under the responder's MAC from this scan. With mac NULL the upsert never
    matched (NULLs are never equal in a UNIQUE key), so every scan added a copy."""
    log("[*] Phase H: WS-Discovery")
    now = common.now_iso()
    found = wsd_discover()
    # the MAC on the wire, as the passive monitor files it: a SonosNet bridge's for the speakers behind it
    mac_by_ip = {h["ip"]: (h["bridge_mac"] or h["mac"] or "").lower() or None for h in hosts}
    for ip, info in found.items():
        mac = mac_by_ip.get(ip)
        row = conn.execute("SELECT id FROM observations WHERE source = 'wsd' AND mac IS ? AND ip = ?",
                           (mac, ip)).fetchone()
        if row:
            conn.execute("UPDATE observations SET last_seen = ?, details = ?, count = count + 1 WHERE id = ?",
                         (now, json.dumps(info), row["id"]))
        else:
            conn.execute("INSERT INTO observations (source, mac, ip, details, first_seen, last_seen) "
                         "VALUES ('wsd', ?, ?, ?, ?, ?)", (mac, ip, json.dumps(info), now, now))
    conn.commit()
    log(f"    {len(found)} WS-Discovery responder(s)")


# ============================================================  I: IPv6

def ipv6_to_mac(ll):
    """MAC behind a modified-EUI-64 link-local address, else None."""
    m = re.match(r"^fe80::([0-9a-f]{1,4}):([0-9a-f]{1,4}):([0-9a-f]{1,4}):([0-9a-f]{1,4})$", ll, re.I)
    if not m:
        return None
    raw = "".join(g.zfill(4) for g in m.groups()).lower()
    if raw[6:10] != "fffe":
        return None
    first = int(raw[0:2], 16) ^ 0x02
    return ":".join([f"{first:02x}", raw[2:4], raw[4:6], raw[10:12], raw[12:14], raw[14:16]])


def run_phase_ipv6(conn, hosts, scan_id):
    log(f"[*] Phase I: IPv6 link-local sweep on {common.IFACE}")
    try:
        out = subprocess.run(["ping", "-6", "-c", "3", "-W", "1", "-I", common.IFACE, "ff02::1"],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        out = ""
    addrs = set(re.findall(r"from (fe80::[0-9a-f:]+)", out, re.I))
    by_mac = {h["mac"]: h["ip"] for h in hosts if h["mac"]}
    by_ip = defaultdict(list)
    for ll in addrs:
        ip = by_mac.get(ipv6_to_mac(ll))
        if ip:
            by_ip[ip].append(ll)
    for ip, lls in by_ip.items():
        conn.execute("UPDATE hosts SET ipv6_addrs=? WHERE scan_id=? AND ip=?",
                     (json.dumps(sorted(lls)), scan_id, ip))
    conn.commit()
    log(f"    {len(addrs)} IPv6 responder(s), {len(by_ip)} matched to a device")


# ============================================================  main

def enrich_scan(scan_id):
    conn = common.connect()
    common.migrate(conn)
    hosts = conn.execute(
        "SELECT ip, mac, hostname, open_ports, ports FROM hosts WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    if not hosts:
        log(f"[!] No hosts in scan #{scan_id}")
        return
    run_phase_banners(conn, hosts, scan_id)
    run_phase_ssdp(conn, scan_id)
    # Again: the SSDP phase gives Sonos speakers behind a SonosNet bridge their own MAC (bridge_mac).
    hosts = conn.execute(
        "SELECT ip, mac, bridge_mac, hostname, open_ports, ports FROM hosts WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    run_phase_mdns(conn, hosts, scan_id)
    run_phase_wsd(conn, hosts)
    run_phase_ipv6(conn, hosts, scan_id)
    try:
        import portid
        portid.run_phase(conn, scan_id)
    except Exception as e:                  # noqa: BLE001 - naming ports never costs a scan its other results
        log(f"[!] Phase P failed: {e}")
    conn.close()
    log(f"[*] Enrichment complete for scan #{scan_id}")


def main():
    conn = common.connect()
    scan_id = int(sys.argv[1]) if len(sys.argv) > 1 else conn.execute(
        "SELECT MAX(id) FROM scans").fetchone()[0]
    conn.close()
    if not scan_id:
        sys.exit("No scans in the database.")
    enrich_scan(scan_id)


if __name__ == "__main__":
    main()
