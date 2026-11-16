#!/usr/bin/env python3
"""Passive network monitor — long-running tshark capturing broadcast /
multicast announcements (LLDP, CDP, DHCP, ARP, mDNS, NetBIOS, IPv6 router
advertisements) and writing deduped observations to scanner.db. watcher.py
turns these into new-device, router-impersonation and offline alerts.

Runs as a child of docker/entrypoint.py, which restarts it if it exits.

Usage:
  passive-monitor.py --iface eno1
"""
import argparse
import collections
import itertools
import json
import os
import queue
import re
import signal
import sqlite3
import subprocess
import threading
import time
from datetime import datetime

import common

# tshark accumulates dissector / per-conversation state indefinitely on
# long-running captures (well-documented Wireshark behaviour). Recycle the
# child process when either limit is hit to keep memory bounded.
# Both can be overridden by env so the docker stack can tune without rebuilds.
DEFAULT_MAX_AGE_H  = int(os.environ.get("TSHARK_MAX_AGE_HOURS") or 24)
DEFAULT_MAX_RSS_MB = int(os.environ.get("TSHARK_MAX_RSS_MB") or 400)
RESOURCE_CHECK_SEC = 60   # how often we poke /proc/<pid>/status

# Tab is unsafe (LLDP descriptions can contain tabs); use ASCII unit separator.
# Repeated values of one field are joined with the record separator, not a comma:
# host names and LLDP system names can contain commas ("Switch, floor 2").
SEP = "\x1f"
AGG = "\x1e"

TSHARK_FIELDS = [
    "frame.time_epoch",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ipv6.src",
    "arp.opcode",
    "arp.src.hw_mac",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
    "lldp.tlv.system.name",
    "lldp.chassis.id",              # chassis ID subtypes other than MAC, as hex bytes
    "lldp.chassis.id.mac",          # chassis ID subtype 4 (MAC), the usual one
    "lldp.port.id",
    "lldp.port.id.mac",
    "lldp.port.desc",
    "cdp.deviceid",
    "cdp.portid",
    "dhcp.option.hostname",
    "dhcp.option.vendor_class_id",
    "dhcp.hw.mac_addr",
    "dhcp.option.requested_ip_address",
    "dhcp.ip.your",
    "dhcp.option.dhcp",
    "dhcp.option.dhcp_server_id",
    "dhcp.option.request_list_item",
    "dns.flags.response",
    "dns.resp.name",
    "dns.resp.type",                # per record, in the same order as dns.resp.name (1 = A, 28 = AAAA)
    "dns.a",
    "dns.aaaa",
    "dns.qry.name",
    "dns.txt",
    "dns.srv.target",
    "dns.srv.port",
    # IPv6 router advertisements (2026-10-27)
    "icmpv6.type",
    "icmpv6.nd.ra.router_lifetime",
    "icmpv6.nd.ra.cur_hop_limit",
    "icmpv6.opt.type",
    "icmpv6.opt.prefix",
    "icmpv6.opt.rdnss",
    # NetBIOS names: name registrations (UDP 137) and browser host announcements (UDP 138)
    "nbns.name",                    # "DESKTOP-1A2B3C<20>"
    "nbns.flags.opcode",
    "nbns.flags.response",
    "nbns.nb_flags.group",
    "nbns.addr",
    "browser.command",
    "browser.server",
    "browser.comment",
    "browser.os_major",
    "browser.os_minor",
]
F = {name: i for i, name in enumerate(TSHARK_FIELDS)}

DISPLAY_FILTER = "lldp or cdp or dhcp or arp or mdns or nbns or browser or icmpv6.type == 134"
# Kernel-level (BPF) filter: tshark only ever sees the packets it keeps.
# Without it, tshark dissected every packet on the interface (SSH, other
# containers' traffic, backups), which is where its memory growth came from.
# ICMPv6 only as router advertisements (type 134; ip6[40] is the ICMPv6 type
# when no extension header comes first, which RAs never have).
CAPTURE_FILTER = ("arp or udp port 67 or udp port 68 or udp port 5353 "
                  "or udp port 137 or udp port 138 "
                  "or ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc "
                  "or (icmp6 and ip6[40] == 134)")

MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
SERVICE_RE = re.compile(r"(_[\w-]+\._(?:tcp|udp))")

# Built-in DHCP fingerprint dictionary. Key = comma-separated parameter request
# list (option 55). Source: published reverse-engineering / fingerbank samples.
# Not exhaustive; designed to identify the 90% of devices on a typical LAN.
DHCP_FINGERPRINTS = {
    "1,121,3,6,15,119,252":             "macOS",
    "1,3,6,15,119,252":                 "iOS / iPadOS",
    "1,3,6,15,119,252,95,44,46":        "iOS (newer)",
    "1,3,6,15,28,33,51,58,59,119":      "Android",
    "1,3,6,15,26,28,51,58,59,43":       "Android (older)",
    "1,15,3,6,44,46,47,31,33,121,249,43": "Windows",
    "1,3,6,15,31,33,43,44,46,47,121,249,252": "Windows 10/11",
    "1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,33,252,42": "Linux dhclient",
    "1,3,6,12,15,26,28,121":            "Linux systemd-networkd",
    "1,3,6,15":                         "Espressif (ESP8266/ESP32 / Shelly)",
    "1,3,28,51,58,59":                  "Espressif (variant)",
    "1,3,6,15,28,33,51,58,59":          "Generic embedded / IoT",
    "1,3,6,15,42,17,121":               "Roku / smart TV",
    "1,3,6,15,42":                      "Sonos",
    "1,2,3,15,6,44":                    "Brother / printer",
}


def dhcp_fingerprint_label(fp_string):
    """Return a friendly OS guess for a DHCP parameter-request-list fingerprint."""
    return DHCP_FINGERPRINTS.get(fp_string)


def vendor_for(mac, _oui=None):
    return common.vendor_for(mac)


# ------------------------------------------------------------ DB

def open_db():
    # Autocommit: each upsert commits immediately so scans and the watcher
    # never wait on a held write-transaction. migrate() puts the file in WAL mode.
    conn = common.connect(autocommit=True)
    common.migrate(conn)
    return conn


def flush_activity(conn, pending):
    """Add the packets counted per (mac, hour) since the last flush to the activity table."""
    if not pending:
        return
    try:
        conn.execute("BEGIN")
        conn.executemany(
            "INSERT INTO activity (mac, hour, n) VALUES (?, ?, ?) "
            "ON CONFLICT(mac, hour) DO UPDATE SET n = n + excluded.n",
            [(mac, hour, n) for (mac, hour), n in pending.items()])
        conn.execute("COMMIT")
        pending.clear()
    except sqlite3.Error as e:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        print(f"[!] activity flush failed (kept for the next try): {e}", flush=True)


def flush_obs_counts(conn, pending):
    """Add the per-(source, mac, ip, day) observation counts since the last flush to observation_counts, so
    the Traffic views can show real per-period totals (2026-10-29)."""
    if not pending:
        return
    try:
        conn.execute("BEGIN")
        conn.executemany(
            "INSERT INTO observation_counts (source, mac, ip, day, n) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(source, mac, ip, day) DO UPDATE SET n = n + excluded.n",
            [(s, m, i, d, n) for (s, m, i, d), n in pending.items()])
        conn.execute("COMMIT")
        pending.clear()
    except sqlite3.Error as e:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        print(f"[!] obs_counts flush failed (kept for the next try): {e}", flush=True)


def flush_arp_hours(conn, pending):
    """Add the per-(asker mac, target ip, hour) ARP-ask counts since the last flush to arp_ask_hours, so
    the ghost-address rate can be a true rolling last-24-hours (alerts.ghost_targets, 2026-10-31)."""
    if not pending:
        return
    try:
        conn.execute("BEGIN")
        conn.executemany(
            "INSERT INTO arp_ask_hours (mac, ip, hour, n) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(mac, ip, hour) DO UPDATE SET n = n + excluded.n",
            [(m, i, h, n) for (m, i, h), n in pending.items()])
        conn.execute("COMMIT")
        pending.clear()
    except sqlite3.Error as e:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        print(f"[!] arp_hours flush failed (kept for the next try): {e}", flush=True)


def upsert(conn, source, mac, ip, hostname, vendor, details, now):
    row = conn.execute(
        "SELECT id, details FROM observations WHERE source=? AND mac IS ? AND ip IS ?",
        (source, mac, ip),
    ).fetchone()
    if row:
        merged = details
        # mDNS, DHCP and NetBIOS packets each tell part of the story (a DHCP NAK or a
        # REQUEST without options says less than the DISCOVER), so keep what earlier ones said.
        if source in ("mdns", "dhcp", "netbios") and row["details"]:
            prev = common.details_dict(row["details"])
            merged = {**prev, **details}
        if source == "dhcp" and "dhcp_fingerprint" in details and "fingerprint_match" not in details:
            merged.pop("fingerprint_match", None)       # a new fingerprint no longer matches the old label
        if source == "mdns" and row["details"]:
            for key in ("services", "services_adv", "services_qry"):
                p = set(prev.get(key) or [])
                n = set(details.get(key) or [])
                if p or n:
                    merged[key] = sorted(p | n)
            # Merge TXT key/value dicts: keys we just learned are added, and a
            # newer value replaces an older one for the same key.
            prev_txt = prev.get("txt") if isinstance(prev.get("txt"), dict) else {}
            new_txt = details.get("txt") if isinstance(details.get("txt"), dict) else {}
            if prev_txt or new_txt:
                merged["txt"] = {**prev_txt, **new_txt}
            # The port each service is on, the newest announcement winning (a restart can move it)
            prev_ports = prev.get("service_ports") if isinstance(prev.get("service_ports"), dict) else {}
            new_ports = details.get("service_ports") if isinstance(details.get("service_ports"), dict) else {}
            if prev_ports or new_ports:
                merged["service_ports"] = {**prev_ports, **new_ports}
        conn.execute(
            "UPDATE observations SET last_seen=?, count=count+1, "
            "hostname=COALESCE(?, hostname), vendor=COALESCE(?, vendor), "
            "details=? WHERE id=?",
            (now, hostname, vendor,
             json.dumps(merged, default=str) if merged else None, row["id"]),
        )
    else:
        conn.execute(
            "INSERT INTO observations "
            "(source, mac, ip, hostname, vendor, details, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (source, mac, ip, hostname, vendor,
             json.dumps(details, default=str) if details else None, now, now),
        )


# ------------------------------------------------------------ parse

def _first(val):
    """tshark with occurrence=a gives comma-joined values; take the first."""
    if not val:
        return None
    return val.split(AGG, 1)[0].strip() or None


def _all(val):
    """Split an aggregated tshark value into a list."""
    if not val:
        return []
    return [p.strip() for p in val.split(AGG) if p.strip()]


def _num(val):
    """The first value of a numeric field as an int ("5", or "0x01" for BASE_HEX fields), else None."""
    v = _first(val)
    try:
        return int(v, 16) if v and v.lower().startswith("0x") else int(v)
    except (TypeError, ValueError):
        return None


def _true(val):
    """A boolean field: tshark 4.4 prints True/False, older ones 1/0."""
    return _first(val) in ("1", "True", "true")


NB_NAME_RE = re.compile(r"(.*?)\s*<([0-9a-fA-F]{2})>")


def parse_line(line, oui):
    """Return a list of (source, mac, ip, hostname, vendor, details) tuples.
    Most packet types yield 0 or 1 observation; a single DHCP OFFER/ACK
    packet yields 2 (a client-side and a server-side observation).
    """
    fields = line.split(SEP)
    if len(fields) < len(TSHARK_FIELDS):
        fields += [""] * (len(TSHARK_FIELDS) - len(fields))

    eth_src = _first(fields[F["eth.src"]])

    # LLDP --- (any LLDP field: System Name is optional, and a MAC chassis ID is
    # lldp.chassis.id.mac, not lldp.chassis.id)
    chassis_mac = _first(fields[F["lldp.chassis.id.mac"]])
    sys_name = _first(fields[F["lldp.tlv.system.name"]])
    port_id = _first(fields[F["lldp.port.id"]]) or _first(fields[F["lldp.port.id.mac"]])
    port_desc = _first(fields[F["lldp.port.desc"]])
    if chassis_mac or _first(fields[F["lldp.chassis.id"]]) or sys_name or port_id or port_desc:
        mac = chassis_mac if chassis_mac and MAC_RE.match(chassis_mac) else eth_src
        details = {}
        if port_id:
            details["port_id"] = port_id
        if port_desc:
            details["port_desc"] = port_desc
        return [("lldp", mac, None, sys_name, vendor_for(mac, oui), details)]

    # CDP ---
    device_id = _first(fields[F["cdp.deviceid"]])
    if device_id or _first(fields[F["cdp.portid"]]):
        port_id = _first(fields[F["cdp.portid"]])
        mac = eth_src
        details = {}
        if port_id:
            details["port_id"] = port_id
        return [("cdp", mac, None, device_id, vendor_for(mac, oui), details)]

    # DHCP ---
    dhcp_mac = _first(fields[F["dhcp.hw.mac_addr"]])
    dhcp_host = _first(fields[F["dhcp.option.hostname"]])
    dhcp_vcid = _first(fields[F["dhcp.option.vendor_class_id"]])
    dhcp_req_ip = _first(fields[F["dhcp.option.requested_ip_address"]])
    dhcp_your_ip = _first(fields[F["dhcp.ip.your"]])
    dhcp_msgtype = _first(fields[F["dhcp.option.dhcp"]])
    dhcp_server_id = _first(fields[F["dhcp.option.dhcp_server_id"]])
    dhcp_param_list = _all(fields[F["dhcp.option.request_list_item"]])
    if dhcp_mac or dhcp_host or dhcp_vcid:
        # CLIENT observation — keyed on chaddr (the device the DHCP lease
        # belongs to). Holds vendor class, fingerprint, hostname, etc.
        client_mac = dhcp_mac or eth_src
        client_ip = dhcp_your_ip or dhcp_req_ip
        details = {}
        if dhcp_vcid:
            details["vendor_class"] = dhcp_vcid
        if dhcp_req_ip and dhcp_req_ip != client_ip:
            details["requested_ip"] = dhcp_req_ip
        if dhcp_param_list:
            fp_string = ",".join(dhcp_param_list)
            details["dhcp_fingerprint"] = fp_string
            label = dhcp_fingerprint_label(fp_string)
            if label:
                details["fingerprint_match"] = label
        out = [("dhcp", client_mac, client_ip, dhcp_host,
                vendor_for(client_mac, oui), details)]
        # A server's NAK (broadcast) or its ACK to an INFORM gives the client no
        # address and says nothing about it: no client observation from those.
        if dhcp_msgtype in ("2", "5", "6") and client_ip in (None, "0.0.0.0"):
            out = []

        # SERVER observation — only on OFFER (2) or ACK (5) packets, where
        # the SOURCE of the packet is the DHCP server (not the chaddr,
        # which is the client). dhcp_server_id is the IP the server is
        # advertising. Stored under source='dhcp_server' so the rogue-DHCP
        # detector can scan for >1 distinct server MAC.
        if dhcp_msgtype in ("2", "5") and eth_src and dhcp_server_id:
            srv_details = {
                "server_id": dhcp_server_id,
                "acting_as_server": True,
                "msgtype": dhcp_msgtype,
            }
            out.append(("dhcp_server", eth_src, dhcp_server_id, None,
                        vendor_for(eth_src, oui), srv_details))
        return out

    # ARP ---
    arp_op = _first(fields[F["arp.opcode"]])
    if arp_op == "2":
        # Reply: "I'm <mac>, my IP is <src.proto>"
        mac = _first(fields[F["arp.src.hw_mac"]]) or eth_src
        ip = _first(fields[F["arp.src.proto_ipv4"]])
        return [("arp", mac, ip, None, vendor_for(mac, oui), {})]
    if arp_op == "1":
        # Request: "<mac> wants to know who has <target_ip>".
        # We store target_ip in the `ip` column so each (asker, target) pair
        # gets its own row — that's the relationship we actually care about.
        mac = _first(fields[F["arp.src.hw_mac"]]) or eth_src
        own_ip = _first(fields[F["arp.src.proto_ipv4"]])
        target_ip = _first(fields[F["arp.dst.proto_ipv4"]])
        if not target_ip or target_ip == "0.0.0.0":
            return []
        details = {}
        if own_ip and own_ip != "0.0.0.0":
            details["own_ip"] = own_ip
        return [("arp_req", mac, target_ip, None, vendor_for(mac, oui), details)]

    # IPv6 router advertisement --- (2026-10-27) the watcher alerts on one with a router
    # lifetime from anything but the router; lifetime 0 (Apple TV / HomePod Thread border
    # routers announcing routes) offers no default route.
    if _num(fields[F["icmpv6.type"]]) == 134:
        details = {
            "router_lifetime": _num(fields[F["icmpv6.nd.ra.router_lifetime"]]),
            "hop_limit": _num(fields[F["icmpv6.nd.ra.cur_hop_limit"]]),
            "prefixes": _all(fields[F["icmpv6.opt.prefix"]]),
            "rdnss": _all(fields[F["icmpv6.opt.rdnss"]]),
            "options": sorted({int(t) for t in _all(fields[F["icmpv6.opt.type"]]) if t.isdigit()}),
        }
        details = {k: v for k, v in details.items() if v is not None and v != []}
        return [("ra", eth_src, _first(fields[F["ipv6.src"]]), None, vendor_for(eth_src, oui), details)]

    # NetBIOS --- (2026-10-27) a Windows PC or Samba box naming itself: a name registration or
    # refresh (UDP 137; queries are names being looked for, not own names) or a browser host
    # announcement (UDP 138). Only the machine's own name: suffix <00> or <20>, not a group
    # name (the workgroup is <00> too).
    nb_name = _first(fields[F["nbns.name"]])
    browser_cmd = _num(fields[F["browser.command"]])
    if nb_name or browser_cmd is not None:
        ip = _first(fields[F["ip.src"]]) or _first(fields[F["nbns.addr"]])
        details = {}
        name = None
        if nb_name:
            m = NB_NAME_RE.fullmatch(nb_name)
            if (m and m.group(2) in ("00", "20") and not _true(fields[F["nbns.flags.response"]])
                    and _num(fields[F["nbns.flags.opcode"]]) in (5, 8, 9)          # registration, refresh
                    and not _true(fields[F["nbns.nb_flags.group"]])):
                name = m.group(1).strip()
        elif browser_cmd in (1, 15):        # host announcement, local master announcement
            name = _first(fields[F["browser.server"]])
            major, minor = _num(fields[F["browser.os_major"]]), _num(fields[F["browser.os_minor"]])
            if major is not None:
                details["os_version"] = f"{major}.{minor or 0}"
            if _first(fields[F["browser.comment"]]):
                details["comment"] = _first(fields[F["browser.comment"]])[:120]
        if not name:
            return []
        return [("netbios", eth_src, ip, name[:60], vendor_for(eth_src, oui), details)]

    # mDNS ---
    # Records in a query are the asker's known answers (other devices' services it has
    # already heard of), not its own; only a response says what the sender offers.
    is_response = _true(fields[F["dns.flags.response"]])
    resp_names = _all(fields[F["dns.resp.name"]]) if is_response else []
    resp_types = _all(fields[F["dns.resp.type"]]) if is_response else []
    qry_names = _all(fields[F["dns.qry.name"]])
    txt_records = _all(fields[F["dns.txt"]]) if is_response else []
    # Its own host name: the owner of an A/AAAA record ("Alexs-MacBook.local"), when the
    # response holds the address it came from. A Bonjour Sleep Proxy answers for sleeping
    # Macs with their addresses, so their names do not become the proxy's.
    hostname = None
    sources = {_first(fields[F["ip.src"]]), _first(fields[F["ipv6.src"]])} - {None}
    if sources & (set(_all(fields[F["dns.a"]])) | set(_all(fields[F["dns.aaaa"]]))):
        hostname = next((nm.split(".")[0] for nm, t in zip(resp_names, resp_types)
                         if t in ("1", "28") and re.fullmatch(r"[^.]+\.local\.?", nm, re.I)), None)
    if resp_names or qry_names:
        adv = set()
        qry = set()
        for nm in resp_names:
            for m in SERVICE_RE.finditer(nm):
                adv.add(m.group(1))
        for nm in qry_names:
            for m in SERVICE_RE.finditer(nm):
                qry.add(m.group(1))
        if not adv and not qry and not hostname:
            return []
        ip = _first(fields[F["ip.src"]]) or _first(fields[F["ipv6.src"]])
        mac = eth_src
        details = {}
        if adv:
            details["services_adv"] = sorted(adv)
        if qry:
            details["services_qry"] = sorted(qry)
        if adv or qry:
            details["services"] = sorted(adv | qry)
        # The TCP port of each service it announces, from its SRV records ("Living Room._airplay._tcp.local" on
        # 7000): what a port a scan finds open is, in the device's own words (portid.py, 2026-11-02). A Bonjour
        # Sleep Proxy answers for sleeping Macs: an SRV record pointing at another host is not this device's.
        srv_names = [nm for nm, t in zip(resp_names, resp_types) if t == "33"]
        srv_ports = _all(fields[F["dns.srv.port"]]) if is_response else []
        srv_targets = _all(fields[F["dns.srv.target"]]) if is_response else []
        service_ports = {}
        for i, (nm, port) in enumerate(zip(srv_names, srv_ports)):
            target = srv_targets[i].split(".")[0] if i < len(srv_targets) else None
            m = SERVICE_RE.search(nm)
            if m and m.group(1).endswith("._tcp") and port.isdigit() and not (hostname and target and
                                                                              target.lower() != hostname.lower()):
                service_ports[m.group(1)] = int(port)
        if service_ports:
            details["service_ports"] = service_ports
        # TXT records — RFC 6763 key=value pairs that identify exact products
        # (Sonos model, AirPlay device, HomeKit category, IPP printer model…).
        if txt_records:
            txt_kv = {}
            for record in txt_records:
                # Each TXT string is one occurrence (split on AGG above), so a comma is part
                # of the value ("fn=Living Room, upstairs"); some devices pack pairs with ";".
                for piece in re.split(r";\s*", record):
                    if "=" in piece:
                        k, v = piece.split("=", 1)
                        k = k.strip().lower()
                        v = v.strip()
                        if k and v and k not in txt_kv:
                            txt_kv[k] = v[:200]
            if txt_kv:
                # Surface useful keys at the top level for easy display.
                details["txt"] = txt_kv
                for friendly_key in ("model", "md", "mn", "ty", "pv",
                                     "product", "vers", "sw_ver"):
                    if friendly_key in txt_kv and "txt_model" not in details:
                        details["txt_model"] = txt_kv[friendly_key]
        return [("mdns", mac, ip, hostname, vendor_for(mac, oui), details)]

    return []


# ------------------------------------------------------------ main loop

def _proc_rss_mb(pid):
    """Resident-set-size in MB for a PID, or None on failure."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) // 1024  # KB → MB
    except OSError:
        return None
    return None


def _build_tshark_cmd(iface):
    cmd = ["tshark", "-i", iface, "-l", "-n", "-Q",
           "-T", "fields",
           "-E", f"separator={SEP}",
           "-E", f"aggregator={AGG}",
           "-E", "occurrence=a",
           "-E", "quote=n",
           "-f", CAPTURE_FILTER,
           "-Y", DISPLAY_FILTER]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    return cmd


def run_tshark_session(conn, oui, iface, commit_interval, stop, max_age_s, max_rss_mb):
    """Run one tshark capture session. Returns one of:
        ("stop",  None)   — stop signal received
        ("age",   seconds) — exceeded the age limit, restart wanted
        ("rss",   mb)     — exceeded the rss limit, restart wanted
        ("exit",  rc)     — tshark died on its own (unexpected)
    """
    cmd = _build_tshark_cmd(iface)
    print(f"[*] Starting tshark on {iface}", flush=True)
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1, errors="replace",
    )
    # Neither pipe may fill up and stall tshark: stderr is read all the time (its last
    # lines go in the exit message), and stdout goes through a queue that the loop
    # reads with a timeout, so stop, limits and the minute's flush also run when the
    # network is quiet.
    err_tail = collections.deque(maxlen=20)
    err_reader = threading.Thread(target=err_tail.extend, args=(proc.stderr,), daemon=True)
    err_reader.start()
    lines = queue.Queue(maxsize=10000)
    done = threading.Event()        # the session is over: the pump stops waiting for room

    def pump():
        for item in itertools.chain(proc.stdout, [None]):      # None: tshark has exited
            while not done.is_set():
                try:
                    lines.put(item, timeout=1)
                    break
                except queue.Full:  # the DB is slow; tshark waits and the kernel drops packets
                    pass

    threading.Thread(target=pump, daemon=True).start()
    started = time.monotonic()
    last_check = started
    seen = 0
    written = 0
    reason = ("exit", None)
    activity = {}               # (sender mac, local hour) -> packets heard, flushed every minute
    obs_counts = {}             # (source, mac, ip, local day) -> observations counted, flushed with activity
    arp_hours = {}              # (asker mac, target ip, local hour) -> arp_req asks, for the ghost rate
    me = common.own_mac(iface)

    try:
        while True:
            if stop["flag"]:
                reason = ("stop", None)
                break
            try:
                line = lines.get(timeout=1)
            except queue.Empty:
                line = ""
            if line is None:
                break
            line = line.rstrip("\n")
            if line:
                seen += 1
                fields = line.split(SEP)
                fields += [""] * (len(TSHARK_FIELDS) - len(fields))
                sender = (_first(fields[F["eth.src"]]) or "").lower()
                # LanWard's own ARP (scans, the watcher's pings) and the answers sent back to it
                # are LanWard talking, not the network (2026-10-27).
                ours = bool(me) and (_first(fields[F["eth.dst"]]) == me
                                     or (sender == me and bool(fields[F["arp.opcode"]])))
                if MAC_RE.match(sender) and not ours:
                    key = (sender, datetime.now().strftime("%Y-%m-%dT%H"))
                    activity[key] = activity.get(key, 0) + 1
                try:
                    results = parse_line(line, oui)
                except Exception as e:
                    print(f"[!] parse error: {e}", flush=True)
                    results = []
                if results:
                    now_iso = datetime.now().isoformat(timespec="seconds")
                    for source, mac, ip, hostname, vendor, details in results:
                        if not mac and not ip:
                            continue
                        try:
                            upsert(conn, source, mac.lower() if mac else None, ip, hostname, vendor,
                                   details, now_iso)
                            written += 1
                            bk = (source, mac.lower() if mac else "", ip or "", now_iso[:10])
                            obs_counts[bk] = obs_counts.get(bk, 0) + 1
                            if source == "arp_req":   # per-hour, for the rolling-24h ghost rate
                                hk = (mac.lower() if mac else "", ip or "", now_iso[:13])
                                arp_hours[hk] = arp_hours.get(hk, 0) + 1
                        except sqlite3.Error as e:
                            print(f"[!] DB error: {e}", flush=True)

            now = time.monotonic()
            if now - last_check >= RESOURCE_CHECK_SEC:
                last_check = now
                flush_activity(conn, activity)
                flush_obs_counts(conn, obs_counts)
                flush_arp_hours(conn, arp_hours)
                age = int(now - started)
                rss = _proc_rss_mb(proc.pid) or 0
                print(f"[*] heartbeat — seen {seen} pkts, wrote {written} rows, "
                      f"tshark age={age // 60}min RSS={rss}MB", flush=True)
                if age >= max_age_s:
                    print(f"[*] tshark age {age // 3600}h exceeds "
                          f"{max_age_s // 3600}h limit — recycling",
                          flush=True)
                    reason = ("age", age)
                    break
                if rss >= max_rss_mb:
                    print(f"[*] tshark RSS {rss}MB exceeds {max_rss_mb}MB "
                          f"limit — recycling", flush=True)
                    reason = ("rss", rss)
                    break
    finally:
        done.set()
        flush_activity(conn, activity)
        flush_obs_counts(conn, obs_counts)
        flush_arp_hours(conn, arp_hours)
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass
        except Exception:
            pass

    rc = proc.returncode
    if reason[0] == "exit":
        # tshark exited without us asking — surface the error and let the
        # outer loop respawn (don't sys.exit, so the container stays up).
        err_reader.join(timeout=2)
        err = "".join(err_tail).strip()[:400]
        print(f"[!] tshark exited {rc}: {err}", flush=True)
        reason = ("exit", rc)
    return reason


def run(iface, max_age_h=DEFAULT_MAX_AGE_H, max_rss_mb=DEFAULT_MAX_RSS_MB):
    conn = open_db()
    oui = None                  # vendor names come from common.vendor_for()
    commit_interval = 30        # unused: autocommit
    print(f"[*] tshark recycle limits: age={max_age_h}h, RSS={max_rss_mb}MB",
          flush=True)

    stop = {"flag": False}

    def handle_term(signum, _frame):
        print(f"[*] Signal {signum} — shutting down", flush=True)
        stop["flag"] = True

    signal.signal(signal.SIGTERM, handle_term)
    signal.signal(signal.SIGINT, handle_term)

    max_age_s = max_age_h * 3600
    restarts = 0
    try:
        while not stop["flag"]:
            reason, value = run_tshark_session(
                conn, oui, iface, commit_interval, stop, max_age_s, max_rss_mb,
            )
            if reason == "stop":
                break
            if reason in ("age", "rss"):
                restarts += 1
                print(f"[*] tshark recycle #{restarts} (reason={reason} "
                      f"value={value}); respawning in 2s", flush=True)
                time.sleep(2)
                continue
            if reason == "exit":
                # Unexpected exit — back off briefly and respawn.
                # If tshark is mis-configured this will look like a tight
                # loop; a watchdog or container-level restart should catch
                # truly persistent failures.
                print("[!] tshark exited unexpectedly; respawning in 5s",
                      flush=True)
                time.sleep(5)
                continue
    finally:
        conn.close()
    print("[*] Shutdown clean", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iface", default=common.IFACE, help="Interface to capture on")
    args = ap.parse_args()
    run(args.iface)


if __name__ == "__main__":
    main()
