#!/usr/bin/env python3
"""Home-security checks on one scan. Each device gets a list of findings in
hosts.findings; alerts.py turns new ones into an alert (once per finding).

Everything here is read-only: it asks devices what they publish anyway
(Shelly's /shelly info, UPnP's list of port mappings, web page headers,
which SMB shares a guest may list or open). No logins, no password
guessing, no changes.

Usage: homechecks.py [scan_id]      # defaults to the latest scan
"""
import ipaddress
import json
import re
import socket
import struct
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import common
from common import log

# Open port -> (severity, title, what to do). severity: alert | warning | info
RISKY_PORTS = {
    23: ("alert", "Telnet is open",
         "Telnet sends passwords in clear text and is a favourite target of IoT malware. "
         "Turn it off in the device settings."),
    2323: ("alert", "Telnet (port 2323) is open",
           "An alternate Telnet port, used by many cheap IoT devices and by botnets. "
           "Turn it off if you can; otherwise keep the device on a separate network."),
    2375: ("alert", "Docker API is open without TLS",
           "Anyone on the network can run containers on this host, which means full control "
           "of it. Bind the API to localhost or use TLS on port 2376."),
    21: ("warning", "FTP is open",
         "FTP sends passwords in clear text. Use SFTP instead, or turn it off if unused."),
    3389: ("warning", "Remote Desktop is open",
           "Fine if you use it: make sure the account has a strong password and Network "
           "Level Authentication is on."),
    5900: ("warning", "VNC is open",
           "VNC is often set up with a weak password or none. Turn it off if unused."),
    6379: ("warning", "Redis is reachable from the network",
           "Redis has no password by default. Bind it to localhost or set requirepass."),
    27017: ("warning", "MongoDB is reachable from the network",
            "Make sure authentication is on, or bind it to localhost."),
    11211: ("warning", "Memcached is reachable from the network",
            "Memcached has no authentication. Bind it to localhost."),
    7547: ("warning", "TR-069 remote management is open",
           "This is the ISP remote-management port, with a long history of router takeovers. "
           "Nothing on your LAN should expose it."),
    1883: ("info", "MQTT without encryption",
           "Fine on a home LAN if the broker requires a username and password."),
    554: ("info", "Camera stream (RTSP) is open",
          "Make sure the stream needs a password; some cameras ship with it off."),
    8554: ("info", "Camera stream (RTSP, port 8554) is open",
           "Make sure the stream needs a password."),
    873: ("info", "rsync is open",
          "Make sure rsync modules require a password or are read-only."),
}


def finding(fid, severity, title, detail):
    return {"id": fid, "severity": severity, "title": title, "detail": detail}


# ------------------------------------------------------------------ is the open service protected? (2026-10-13)
# "MQTT without encryption", "VNC is open" and "camera stream is open" are only a problem when nobody needs a
# password; ask once, without credentials, and say which it is. No login, no password guessing: an anonymous
# request either way.

def mqtt_allows_anonymous(ip, port=1883, timeout=4):
    """One MQTT 3.1.1 CONNECT without a user name. True: the broker accepts it (anyone on the LAN can read and send
    messages), False: it refuses for want of a login (CONNACK code 4/5), None: no MQTT answer, or a refusal for
    another reason (1 protocol version, 2 client id, 3 unavailable) that says nothing about passwords.
    Disconnects straight away."""
    client_id = b"lanward-check"
    body = b"\x00\x04MQTT\x04\x02\x00\x1e" + struct.pack(">H", len(client_id)) + client_id
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"\x10" + bytes([len(body)]) + body)
            data = s.recv(4)
            if len(data) >= 4 and data[0] == 0x20:
                if data[3] == 0:
                    s.sendall(b"\xe0\x00")              # DISCONNECT
                    return True
                if data[3] in (4, 5):                   # bad user name or password / not authorised
                    return False
    except OSError:
        pass
    return None


def rtsp_needs_password(ip, port=554, paths=("/stream1", "/", "/live", "/h264Preview_01_main"), timeout=4):
    """RTSP DESCRIBE without credentials on common stream paths. True: the camera answers 401 (it needs its account),
    False: it hands out a stream description (200) to anyone, None: no path answered either way."""
    for path in paths:
        req = (f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n"
               f"User-Agent: {common.USER_AGENT}\r\n\r\n")
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(req.encode())
                m = re.match(r"RTSP/1\.0 (\d{3})", s.recv(512).decode("latin-1"))
        except OSError:
            continue
        if m and m.group(1) == "401":
            return True
        if m and m.group(1) == "200":
            return False
    return None


def vnc_needs_password(ip, port=5900, timeout=4):
    """RFB handshake up to the server's list of security types, then hang up without picking
    one (2026-10-26). True: every type needs a password (VNC password, the macOS account for
    Screen Sharing), False: type 1 "None" is offered, so anyone on the LAN can see and control
    the screen, None: no VNC answer."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            m = re.match(rb"RFB (\d{3})\.(\d{3})\n", s.recv(12))
            if not m:
                return None
            minor = int(m.group(2)) if m.group(1) == b"003" else 8    # macOS says 003.889
            if minor < 7:                     # RFB 3.3: the server picks the type itself
                s.sendall(b"RFB 003.003\n")
                data = s.recv(4)
                if len(data) < 4 or struct.unpack(">I", data)[0] == 0:
                    return None
                return struct.unpack(">I", data)[0] != 1
            s.sendall(b"RFB 003.008\n" if minor >= 8 else b"RFB 003.007\n")
            n = s.recv(1)
            if not n or n[0] == 0:            # 0 types: the server refuses (too many tries, ...)
                return None
            return 1 not in s.recv(n[0])
    except OSError:
        return None


def verified_service_findings(ip, ports):
    """The MQTT, VNC and RTSP findings, replaced by what the anonymous check showed (or as before when it could not
    tell)."""
    out = {}
    if 1883 in ports:
        anon = mqtt_allows_anonymous(ip)
        if anon:
            out[1883] = finding(
                "mqtt-anonymous", "warning", "MQTT accepts connections without a password",
                "Anyone on your network can read every message and send commands to whatever listens on MQTT. "
                "Remedy: in the broker require a login (Home Assistant's Mosquitto add-on: Settings > Add-ons > "
                "Mosquitto > Configuration, keep anonymous off) and give each client its own user.")
        elif anon is False:
            out[1883] = finding(
                "port-1883", "info", "MQTT without encryption (a password is required)",
                "Checked: the broker refuses connections without a password, which is what matters on a home LAN. "
                "Optional: TLS on port 8883 so passwords do not cross the network in clear text.")
    if 5900 in ports:
        needs = vnc_needs_password(ip)
        if needs is False:
            out[5900] = finding(
                "vnc-no-password", "alert", "VNC lets anyone see and control the screen",
                "Checked: the VNC server offers access without a password. Anyone on your network can watch "
                "and use this computer. Remedy: set a VNC password, or turn screen sharing off.")
        elif needs:
            out[5900] = finding(
                "port-5900", "info", "Screen sharing (VNC) is on and asks for a password",
                "Checked: it needs a password or the computer's account (macOS Screen Sharing does). Fine if you "
                "use it; otherwise turn it off (macOS: System Settings > General > Sharing > Screen Sharing).")
    for port in (554, 8554):
        if port in ports:
            needs = rtsp_needs_password(ip, port)
            if needs is False:
                out[port] = finding(
                    f"rtsp-open:{port}", "warning", f"Camera stream (RTSP, port {port}) plays without a password",
                    "Anyone on your network can watch it. Remedy: set a camera account (on a Tapo: Camera Settings > "
                    "Advanced Settings > Camera Account) and use it in your recorder (Frigate, go2rtc...).")
            elif needs:
                out[port] = finding(
                    f"port-{port}", "info", f"Camera stream (RTSP{'' if port == 554 else ', port 8554'}) needs a password",
                    "Checked: the stream asks for the camera account. Nothing to do; the stream itself is unencrypted, "
                    "which is normal for RTSP on a home LAN.")
    return out


# ------------------------------------------------------------------ SMB file sharing (2026-10-27)
# Shared folders a guest can open. smbclient without a password (-N): the share list, then `ls` of the top folder
# of each disk share, nothing deeper, no file read or written; it disconnects when the command is done. A device
# that fails to negotiate at smbclient's default minimum protocol is asked once more with SMB1 allowed.

SMBCLIENT = ["smbclient"]
SMB1 = "--option=client min protocol=NT1"
SMB_RUN_TIMEOUT = 20                    # seconds per smbclient run; -t 5 per request inside it
SMB_MAX_SHARES = 10
SMB_DENIED = re.compile(r"NT_STATUS_(ACCESS_DENIED|LOGON_FAILURE|ACCOUNT_\w+|WRONG_PASSWORD|BAD_NETWORK_NAME|"
                        r"NETWORK_ACCESS_DENIED|INVALID_ACCOUNT_NAME|NO_SUCH_USER)")


def _smbclient(args, smb1=False):
    """(exit code, output) of one smbclient run without a password, or (None, why) when it did not run."""
    cmd = [*SMBCLIENT, "-N", "-p", "445", "-t", "5", *([SMB1] if smb1 else []), *args]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=SMB_RUN_TIMEOUT,
                           stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        return None, "smbclient is not installed"
    except subprocess.TimeoutExpired:
        return None, f"no answer in {SMB_RUN_TIMEOUT} s"
    except OSError as e:
        return None, str(e)
    return p.returncode, p.stdout + p.stderr


def smb_shares(ip, smb1=False):
    """The share list as a guest: ("list", [(type, name, comment)]), ("denied", None), ("old", None) when the
    protocol negotiation failed, or (None, why) when it could not tell (no answer, refused, ...)."""
    code, out = _smbclient(["-L", f"//{ip}", "-g"], smb1)
    if code is None:
        return None, out
    # After the list smbclient reconnects with SMB1 for the workgroup list, and that may fail on its own
    # ("protocol negotiation failed", "Unable to connect with SMB1"): a list that came first counts.
    shares = [tuple((line.split("|", 2) + ["", ""])[:3]) for line in out.splitlines()
              if line.split("|")[0] in ("Disk", "IPC", "Printer")]
    if shares:
        return "list", shares
    if "protocol negotiation failed" in out:
        return "old", None
    if SMB_DENIED.search(out):
        return "denied", None
    if code == 0:
        return "list", []
    status = re.findall(r"NT_STATUS_\w+", out)
    return None, status[-1] if status else f"smbclient exit {code}"


def smb_share_opens(ip, share, smb1=False):
    """True: the share opens and its top folder lists without a password, False: refused, None: could not tell."""
    code, out = _smbclient([f"//{ip}/{share}", "-c", "ls"], smb1)
    if code is None:
        return None
    if SMB_DENIED.search(out):          # also "NT_STATUS_ACCESS_DENIED listing \*": connected, but no reading
        return False
    if code == 0 and re.search(r"blocks of size|^\s+\.{1,2}\s+D\s", out, re.M):
        return True
    return None


def smb_remedy(h, ports, shares):
    """How to close guest access, for the devices we know."""
    names = {name.lower() for _, name, _ in shares}
    comments = " ".join(comment for _, _, comment in shares).lower()
    if {"admin$", "c$"} & names or "remote ipc" in comments:
        return ("Windows: turn on password-protected sharing (Settings > Network & internet > Advanced network settings > "
                "Advanced sharing settings > All networks), so only accounts on the PC can open its shares.")
    if 8123 in ports or {"addons", "ssl"} <= names:
        return ("Home Assistant's Samba share add-on: Settings > Add-ons > Samba share > Configuration, set a "
                "username and password and do not allow guests.")
    if "asustek" in (h["vendor"] or "").lower():
        return ("Asus router or access point with a USB disk: USB Application > Network Place (Samba) Share / Cloud "
                "Disk, turn off guest access (\"Allow guest login\" / share without login), so the share needs a "
                "router account.")
    return "Turn off guest access for these shares in the device's sharing settings, or give them a username and password."


def smb_findings(h, ports):
    """What a guest can do with the device's file sharing (port 445)."""
    if 445 not in ports:
        return []
    ip, out = h["ip"], []
    state, shares = smb_shares(ip)
    smb1 = False
    if state == "old":
        state, shares = smb_shares(ip, smb1=True)
        if state in ("list", "denied"):
            smb1 = True
            out.append(finding(
                "smb1", "warning", "File sharing speaks only SMB1",
                "Checked: the device's file sharing (SMB) only works with SMB1, the old protocol without encryption "
                "or protection against tampering that the WannaCry worm spread through. Remedy: turn on SMB2/SMB3 in "
                "its sharing settings (an Asus router's Samba share has a protocol choice), update its firmware, or "
                "turn file sharing off if the device can do no better."))
        elif state == "old":
            state, shares = None, "protocol negotiation failed, also with SMB1"
    if state is None:
        log(f"    {ip:<15} SMB not checked ({shares})")
    elif state == "denied":
        out.append(finding(
            "port-445", "info", "File sharing (SMB) asks for a password",
            "Checked: the device refuses to show or open its shared folders without an account. Fine."))
    else:
        # Hidden shares are not tried: Windows' admin shares (C$, ADMIN$) and print$ (printer drivers, readable by design).
        disks = [name for typ, name, _ in shares if typ == "Disk" and not name.endswith("$")]
        opened = [name for name in disks[:SMB_MAX_SHARES] if smb_share_opens(ip, name, smb1)]
        if opened:
            out.append(finding(
                "smb-guest", "warning",
                f"Shared {'folder' if len(opened) == 1 else 'folders'} open without a password: {', '.join(opened)}",
                f"Checked: {', '.join(opened)} opened as a guest. Anyone on your network can read the files, and maybe "
                f"change or delete them. Remedy: {smb_remedy(h, ports, shares)}"))
        elif disks:
            out.append(finding(
                "smb-list", "info", "Shared folder names are visible without a password",
                f"Checked: anyone on your network can see the names ({', '.join(disks[:SMB_MAX_SHARES])}), but none "
                "opened without a password. Fine; turn off anonymous share listing to hide the names too."))
        else:
            out.append(finding(
                "port-445", "info", "File sharing (SMB) asks for a password",
                "Checked: no shared folder opens without an account. Fine."))
    return out


def login_remedy(h, port, w):
    """What to do about a login page over plain HTTP, for the devices we know."""
    title = (w.get("title") or "").lower()
    if "fully" in title:
        return ("Fully Kiosk Browser's Remote Admin page (a wall tablet). It asks for its password, but over plain "
                "HTTP. Remedy: keep a strong Remote Admin password, and turn Remote Administration off (Fully: Settings > "
                "Remote Administration) if you do not use it; Home Assistant's Fully Kiosk integration needs it on.")
    if h["ip"] == common.own_ip():
        return ("LanWard's own dashboard. Its password crosses the LAN unencrypted. Remedy: fine on a home LAN; "
                "for HTTPS, put it behind a reverse proxy that has a certificate.")
    return ("The password travels unencrypted on your network. Use the HTTPS address if the device has one.")


# ------------------------------------------------------------------ Shelly

def _short_fw(fw):
    m = re.search(r"v?(\d+\.\d+\.\d+[^-/]*)", fw or "")
    return m.group(1) if m else (fw or "")


def shelly_info(ip):
    """Shelly's own unauthenticated info endpoint. None if not a Shelly."""
    _, d = common.http_json(ip, 80, "/shelly", timeout=3)
    if not isinstance(d, dict) or not (d.get("type") or d.get("gen") or d.get("app")):
        return None
    gen = d.get("gen") or 1
    if gen == 1:
        info = {"gen": 1, "auth": bool(d.get("auth")), "model": d.get("type"),
                "fw": _short_fw(d.get("fw"))}
    else:
        info = {"gen": gen, "auth": bool(d.get("auth_en")),
                "model": d.get("app") or d.get("model"),
                "fw": d.get("ver") or _short_fw(d.get("fw_id"))}
    # Pending update. With a password set, these endpoints answer 401: fine.
    if not info["auth"]:
        if gen == 1:
            _, st = common.http_json(ip, 80, "/status", timeout=4)
            upd = (st or {}).get("update") or {}
            if upd.get("has_update"):
                info["update"] = _short_fw(upd.get("new_version"))
        else:
            _, st = common.http_json(ip, 80, "/rpc/Sys.GetStatus", timeout=4)
            stable = ((st or {}).get("available_updates") or {}).get("stable") or {}
            if stable.get("version"):
                info["update"] = stable["version"]
    return info


def shelly_findings(info):
    out = []
    if not info["auth"]:
        out.append(finding(
            "shelly-no-password", "warning", "No password on this Shelly",
            "Anyone on your Wi-Fi (a guest, or a compromised gadget) can switch it and change "
            "its settings. Set one in the Shelly app or web page: Settings > Authentication."))
    if info.get("update"):
        out.append(finding(
            f"shelly-update:{info['update']}", "info",
            f"Firmware update available: {info['fw']} -> {info['update']}",
            "Install it from the Shelly app or the device's web page."))
    return out


# ------------------------------------------------------------------ UPnP on the router

def _upnp_control_url(location):
    try:
        req = urllib.request.Request(location, headers={"User-Agent": common.USER_AGENT})
        xml = urllib.request.urlopen(req, timeout=4).read(131072).decode("utf-8", "replace")
    except Exception:
        return None, None
    for block in re.findall(r"<service>(.*?)</service>", xml, re.S):
        st = re.search(r"<serviceType>\s*([^<]+?)\s*</serviceType>", block)
        cu = re.search(r"<controlURL>\s*([^<]+?)\s*</controlURL>", block)
        if st and cu and re.search(r"WAN(IP|PPP)Connection", st.group(1)):
            url = urllib.parse.urljoin(location, cu.group(1))
            here, there = urllib.parse.urlparse(location), urllib.parse.urlparse(url)
            if (there.scheme, there.hostname) != (here.scheme, here.hostname):
                return None, None          # the description may name any URL; only the router itself is asked
            return st.group(1), url
    return None, None


def _mapping_entry(url, service, i):
    """One GetGenericPortMappingEntry call: the entry as a dict, "end" past the last entry, or None
    when the router gave no usable answer (a timeout, or a fault such as 606 Action not authorized)."""
    body = (
        '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
        f'<u:GetGenericPortMappingEntry xmlns:u="{service}">'
        f'<NewPortMappingIndex>{i}</NewPortMappingIndex>'
        '</u:GetGenericPortMappingEntry></s:Body></s:Envelope>'
    ).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": f'"{service}#GetGenericPortMappingEntry"',
        "User-Agent": common.USER_AGENT,
    })
    try:
        xml = urllib.request.urlopen(req, timeout=4).read(16384).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            fault = e.read(4096).decode("utf-8", "replace")
        except Exception:
            fault = ""
        code = re.search(r"<errorCode>\s*(\d+)\s*</errorCode>", fault)
        # 713 SpecifiedArrayIndexInvalid (714 NoSuchEntryInArray on some routers) = past the last entry
        return "end" if e.code == 500 and (not code or code.group(1) in ("713", "714")) else None
    except Exception:
        return None
    get = lambda tag: (re.search(f"<{tag}>([^<]*)</{tag}>", xml) or [None, ""])[1]  # noqa: E731
    return {
        "proto": get("NewProtocol"), "external": get("NewExternalPort"),
        "client": get("NewInternalClient"), "internal": get("NewInternalPort"),
        "description": get("NewPortMappingDescription"), "enabled": get("NewEnabled"),
    }


def upnp_port_mappings(location, limit=64):
    """List the router's UPnP port forwards (GetGenericPortMappingEntry, a read-only call).
    Returns (list of dicts, complete): ([], True) when there are none, (None, False) when the
    list could not be read. A call that fails part-way is tried once more; a timeout is not the
    end of the list (2026-10-26)."""
    service, url = _upnp_control_url(location)
    if not url:
        return None, False
    mappings = []
    for i in range(limit):
        entry = _mapping_entry(url, service, i) or _mapping_entry(url, service, i)
        if entry == "end":
            return mappings, True
        if entry is None:
            return mappings or None, False
        mappings.append(entry)
    return mappings, False


# What the router's UPnP says about forwards (router_findings), stored by run() as router_upnp for new-port alerts:
# whether the router opened a device's port to the internet (common.internet_exposure, 2026-11-02)
ROUTER_UPNP = {}


def _port(v):
    return int(v) if str(v).strip().isdigit() else None


def router_findings(upnp):
    st = " ".join(upnp.get("st") or [])
    if not re.search(r"InternetGatewayDevice|WAN(IP|PPP)Connection", st):
        ROUTER_UPNP.update(state="off")
        return []
    mappings, complete = upnp_port_mappings(upnp["location"]) if upnp.get("location") else (None, False)
    # Disabled entries forward nothing.
    forwards = [m for m in mappings or [] if m["enabled"].strip().lower() not in ("0", "false")]
    ROUTER_UPNP.update(state="on", complete=bool(complete and mappings is not None),
                       forwards=[[m["client"], _port(m["internal"]), _port(m["external"]), m["proto"]]
                                 for m in forwards])
    if forwards:
        lines = [f"- {m['proto']} {m['external']} -> {m['client']}:{m['internal']}"
                 f"{' (' + m['description'] + ')' if m['description'] else ''}" for m in forwards]
        # One id while any port is open: a device that moved to another address, or a port that changed,
        # is no new alert; the list here always shows what is open now (2026-10-26).
        return [finding(
            "upnp-open", "warning",
            f"UPnP has opened {common.plural(len(forwards), 'port')} on your router to the internet",
            "Devices opened these themselves, without asking:\n" + "\n".join(lines) +
            ("" if complete else "\n(The router stopped answering part-way through the list: there may be more.)") +
            "\nIf you don't recognise one, turn UPnP off in the router and forward ports by hand.")]
    if not complete:
        return [finding(
            "upnp-enabled", "info", "UPnP port forwarding is on in your router",
            "Any device on the LAN (including a compromised one) can open ports to the internet without asking. "
            "LanWard could not read the list of ports opened through it (the router did not answer). "
            "Consider turning it off.")]
    return [finding(
        "upnp-enabled", "info", "UPnP port forwarding is on in your router",
        "Any device on the LAN (including a compromised one) can open ports to the internet "
        "without asking. No ports are open through it right now. Consider turning it off.")]


# ------------------------------------------------------------------ TLS

def _cert_date(value):
    """openssl's "Nov 15 18:28:52 2026 GMT" as a naive UTC datetime, else None."""
    try:
        return datetime.strptime((value or "").replace(" GMT", "").strip(), "%b %d %H:%M:%S %Y")
    except ValueError:
        return None


# ------------------------------------------------------------------ per device

def check_host(h, gateway_ip):
    """Returns (findings, firmware or None)."""
    out, firmware = [], None
    ports = set(json.loads(h["open_ports"] or "[]")) if h["open_ports"] else set()
    web = json.loads(h["web_info"] or "{}") if h["web_info"] else {}

    verified = verified_service_findings(h["ip"], ports)
    for port, (sev, title, detail) in RISKY_PORTS.items():
        if port in ports:
            if port in (23, 2323) and str(port) in web:
                continue    # answered as a web page (Fully Kiosk's remote admin on 2323), not Telnet: see below
            out.append(verified.get(port) or finding(f"port-{port}", sev, title, detail))
    out += smb_findings(h, ports)

    shelly = shelly_info(h["ip"]) if 80 in ports else None
    if shelly:
        out += shelly_findings(shelly)
        firmware = f"Shelly {shelly['model'] or ''} {shelly['fw'] or ''}".strip()

    if "frigate" in (web.get("5000", {}).get("title") or "").lower():
        out.append(finding(
            "frigate-5000", "warning", "Frigate's unauthenticated port 5000 is reachable",
            "Port 5000 is Frigate's internal API: no login, so anyone on the LAN can watch the "
            "cameras and change settings. Use the authenticated port 8971 and stop publishing 5000."))

    for port, w in web.items():
        if (not w.get("tls") and w.get("login") in ("form", "basic")
                and not 300 <= (w.get("status") or 0) < 400 and not shelly):
            out.append(finding(
                f"http-login:{port}", "info", f"Login page over plain HTTP (port {port})",
                login_remedy(h, port, w)))

    not_after, not_before = _cert_date(h["tls_cert_not_after"]), _cert_date(h["tls_cert_not_before"])
    if not_after:
        left = not_after - datetime.now(timezone.utc).replace(tzinfo=None)
        # A month's notice, or a quarter of the lifetime for short-lived certificates: their ACME client renews them
        # at about a third, so only a renewal that stopped working gets this close. "Expires soon" and "has expired"
        # are separate findings, so the expiry itself alerts too (2026-10-26; expired kept the old id).
        notice = min(timedelta(days=30), (not_after - not_before) / 4) if not_before else timedelta(days=30)
        about = (f"Certificate {h['tls_cert_cn'] or ''} (valid until {h['tls_cert_not_after']}). "
                 "Renew it so browsers and apps keep trusting it.")
        if left < timedelta(0):
            out.append(finding(f"tls-expiry:{h['tls_cert_fingerprint']}", "warning",
                               "TLS certificate has expired", about))
        elif left <= notice:
            out.append(finding(f"tls-expiring:{h['tls_cert_fingerprint']}", "warning",
                               f"TLS certificate expires in {common.plural(left.days, 'day')}", about))

    if h["ip"] == gateway_ip and h["upnp_info"]:
        try:
            out += router_findings(json.loads(h["upnp_info"]))
        except ValueError:
            pass
    return out, firmware


def carried_findings(conn, h, scan_id):
    """nmap could not finish this device's ports (open_ports NULL, scan.py), and no findings would read as
    "all fixed": the findings of its last scan whose port check finished, marked with that scan's id.
    A MAC that several addresses shared in a scan (the SonosNet bridge's, 2026-10-27) counts only at
    this device's address; a speaker behind the bridge is found under the bridge's MAC before then."""
    if not h["mac"]:
        rows = conn.execute("SELECT scan_id, ip, findings FROM hosts WHERE ip = ? AND scan_id < ? AND open_ports "
                            "IS NOT NULL ORDER BY scan_id DESC LIMIT 1", (h["ip"], scan_id)).fetchall()
    else:
        rows = conn.execute(
            "SELECT scan_id, ip, findings FROM hosts WHERE (mac = ? OR (mac = ? AND ip = ?)) AND scan_id = ("
            "SELECT MAX(scan_id) FROM hosts WHERE (mac = ? OR (mac = ? AND ip = ?)) AND scan_id < ? "
            "AND open_ports IS NOT NULL) AND open_ports IS NOT NULL",
            (h["mac"], h["bridge_mac"], h["ip"]) * 2 + (scan_id,)).fetchall()
        if len(rows) > 1:                   # one MAC on several addresses in that scan: this one's row, if any
            rows = [r for r in rows if r["ip"] == h["ip"]]
    row = rows[0] if rows else None
    if not row or not row["findings"]:
        return []
    return [{**f, "from_scan": row["scan_id"]} for f in json.loads(row["findings"])]


def _whole_lan(subnet):
    try:
        return ipaddress.ip_network(subnet, strict=False) == ipaddress.ip_network(common.SUBNET, strict=False)
    except ValueError:
        return False


def run(scan_id):
    log("[*] Home-security checks")
    conn = common.connect()
    common.migrate(conn)
    gateway = common.default_gateway()
    hosts = conn.execute("SELECT * FROM hosts WHERE scan_id = ?", (scan_id,)).fetchall()
    ROUTER_UPNP.clear()
    results = []
    for h in hosts:
        if h["open_ports"] is None:
            results.append((h, carried_findings(conn, h, scan_id), None))
        else:
            results.append((h, *check_host(h, gateway)))
    # Known-flaw (CISA) and end-of-life findings from each device's model (supportcheck.py, 2026-10-28).
    # Best-effort and gated by a setting: a failure here never costs the home-security findings above.
    if common.setting_on("SUPPORT_CHECK"):
        try:
            import supportcheck
            support = supportcheck.Support(conn, hosts)
            for i, (h, found, firmware) in enumerate(results):
                have = {f.get("id") for f in found}     # a carried-forward list (ports unscanned) may already hold them
                extra = [f for f in support.findings_for(h) if f.get("id") not in have]
                if extra:
                    results[i] = (h, found + extra, firmware)
        except Exception as e:                  # noqa: BLE001 - never let it break a scan
            log(f"    support/known-flaw check skipped: {e}")
    # Written after all the checks: holding the write lock across them made the passive monitor and
    # the watcher wait, then fail with "database is locked" (2026-10-26).
    total = 0
    for h, found, firmware in results:
        total += len(found)
        conn.execute(
            "UPDATE hosts SET findings=?, firmware=COALESCE(?, firmware) WHERE scan_id=? AND ip=?",
            (json.dumps(found) if found else None, firmware, scan_id, h["ip"]),
        )
        for f in found:
            note = f" (from scan #{f['from_scan']}: ports not checked this time)" if f.get("from_scan") else ""
            log(f"    {h['ip']:<15} {f['severity']:<7} {f['title']}{note}")
    # The dashboard shows the findings of the newest scan of the whole LAN whose checks are done (a Run
    # scan of a few addresses would hide the rest).
    scan = conn.execute("SELECT subnet FROM scans WHERE id = ?", (scan_id,)).fetchone()
    done = common.kv_get(conn, "homechecks_done")
    if scan and _whole_lan(scan["subnet"]) and not (done and str(done).isdigit() and int(done) > scan_id):
        common.kv_set(conn, "homechecks_done", str(scan_id))
    if ROUTER_UPNP:                             # the router answered: what it forwards, for new-port alerts
        common.kv_set(conn, "router_upnp", json.dumps({**ROUTER_UPNP, "at": common.now_iso()}))
    conn.commit()
    conn.close()
    log(f"    {total} finding(s) on {len(hosts)} device(s)")


if __name__ == "__main__":
    c = common.connect()
    sid = int(sys.argv[1]) if len(sys.argv) > 1 else c.execute("SELECT MAX(id) FROM scans").fetchone()[0]
    c.close()
    run(sid)
