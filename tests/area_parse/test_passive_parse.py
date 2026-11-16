"""Area C — passive-monitor.py field/packet parsing.

Build synthetic tshark field rows (via the `mkline`/`parse` fixtures) and assert the
(source, mac, ip, hostname, vendor, details) tuples parse_line() yields, plus the
upsert() merge logic and the small field helpers. No network, no real tshark.
"""
import json

import pytest

import common


# ───────────────────────── field helpers ─────────────────────────

def test_first_all_num_true(pm):
    agg = pm.AGG
    assert pm._first(f"a{agg}b") == "a"
    assert pm._first("  spaced  ") == "spaced"
    assert pm._first("") is None
    assert pm._first(f"{agg}b") is None          # empty first chunk
    assert pm._all(f"a{agg} b {agg}") == ["a", "b"]
    assert pm._all("") == []
    assert pm._num("134") == 134
    assert pm._num("0x86") == 134                # BASE_HEX field
    assert pm._num("") is None
    assert pm._num("nope") is None
    assert pm._num(None) is None
    assert pm._true("1") is True
    assert pm._true("True") is True
    assert pm._true("0") is False
    assert pm._true("") is False


def test_dhcp_fingerprint_label(pm):
    assert pm.dhcp_fingerprint_label("1,3,6,15") == "Espressif (ESP8266/ESP32 / Shelly)"
    assert pm.dhcp_fingerprint_label("1,3,6,15,119,252") == "iOS / iPadOS"
    assert pm.dhcp_fingerprint_label("999,998") is None
    assert pm.dhcp_fingerprint_label("") is None


# ───────────────────────── ARP ─────────────────────────

def test_arp_reply(parse, pm):
    out = parse({"arp.opcode": "2", "eth.src": "aa:bb:cc:dd:ee:00",
                 "arp.src.hw_mac": "aa:bb:cc:dd:ee:01", "arp.src.proto_ipv4": "192.168.10.5"})
    assert out == [("arp", "aa:bb:cc:dd:ee:01", "192.168.10.5", None, "V:aa:bb:cc:dd:ee:01", {})]


def test_arp_reply_falls_back_to_eth_src(parse):
    out = parse({"arp.opcode": "2", "eth.src": "aa:bb:cc:dd:ee:00",
                 "arp.src.proto_ipv4": "192.168.10.5"})
    assert out[0][:3] == ("arp", "aa:bb:cc:dd:ee:00", "192.168.10.5")


def test_arp_request_stores_target_and_own_ip(parse):
    out = parse({"arp.opcode": "1", "arp.src.hw_mac": "aa:bb:cc:dd:ee:01",
                 "arp.src.proto_ipv4": "192.168.10.5", "arp.dst.proto_ipv4": "192.168.10.9"})
    src, mac, ip, host, vend, det = out[0]
    assert (src, mac, ip, host) == ("arp_req", "aa:bb:cc:dd:ee:01", "192.168.10.9", None)
    assert det == {"own_ip": "192.168.10.5"}


def test_arp_request_probe_is_ignored(parse):
    # ARP probe / gratuitous with no (or 0.0.0.0) target yields nothing
    assert parse({"arp.opcode": "1", "arp.src.hw_mac": "aa:bb:cc:dd:ee:01"}) == []
    assert parse({"arp.opcode": "1", "arp.src.hw_mac": "aa:bb:cc:dd:ee:01",
                  "arp.dst.proto_ipv4": "0.0.0.0"}) == []


def test_arp_request_own_ip_zero_omitted(parse):
    out = parse({"arp.opcode": "1", "arp.src.hw_mac": "aa:bb:cc:dd:ee:01",
                 "arp.src.proto_ipv4": "0.0.0.0", "arp.dst.proto_ipv4": "192.168.10.9"})
    assert out[0][5] == {}


# ───────────────────────── DHCP ─────────────────────────

def test_dhcp_client_with_fingerprint_and_hostname(parse, pm):
    agg = pm.AGG
    fp = ["1", "3", "6", "15"]
    out = parse({"dhcp.hw.mac_addr": "aa:bb:cc:dd:ee:10", "dhcp.option.hostname": "shelly1",
                 "dhcp.option.vendor_class_id": "udhcp 1.0", "dhcp.ip.your": "192.168.10.20",
                 "dhcp.option.request_list_item": agg.join(fp), "dhcp.option.dhcp": "5"})
    assert len(out) == 1
    src, mac, ip, host, vend, det = out[0]
    assert (src, mac, ip, host) == ("dhcp", "aa:bb:cc:dd:ee:10", "192.168.10.20", "shelly1")
    assert det["vendor_class"] == "udhcp 1.0"
    assert det["dhcp_fingerprint"] == "1,3,6,15"
    assert det["fingerprint_match"] == "Espressif (ESP8266/ESP32 / Shelly)"


def test_dhcp_requested_ip_kept_when_different(parse):
    out = parse({"dhcp.hw.mac_addr": "aa:bb:cc:dd:ee:10", "dhcp.option.requested_ip_address": "192.168.10.30",
                 "dhcp.ip.your": "192.168.10.20", "dhcp.option.dhcp": "3"})
    det = out[0][5]
    assert det["requested_ip"] == "192.168.10.30"


def test_dhcp_offer_adds_server_observation(parse):
    out = parse({"eth.src": "aa:bb:cc:dd:ee:99", "dhcp.hw.mac_addr": "aa:bb:cc:dd:ee:10",
                 "dhcp.ip.your": "192.168.10.20", "dhcp.option.dhcp": "2",
                 "dhcp.option.dhcp_server_id": "192.168.10.1"})
    assert len(out) == 2
    client, server = out
    assert client[0] == "dhcp"
    assert server[0] == "dhcp_server"
    assert server[1] == "aa:bb:cc:dd:ee:99"           # server keyed on packet eth.src
    assert server[2] == "192.168.10.1"
    assert server[5]["server_id"] == "192.168.10.1"
    assert server[5]["acting_as_server"] is True


def test_dhcp_nak_yields_nothing(parse):
    # NAK (6) with no address says nothing about the client, and is not an OFFER/ACK → no rows
    out = parse({"eth.src": "aa:bb:cc:dd:ee:99", "dhcp.hw.mac_addr": "aa:bb:cc:dd:ee:10",
                 "dhcp.option.dhcp": "6", "dhcp.option.dhcp_server_id": "192.168.10.1"})
    assert out == []


# ───────────────────────── LLDP / CDP ─────────────────────────

def test_lldp_with_mac_chassis_and_ports(parse):
    out = parse({"eth.src": "aa:bb:cc:dd:ee:00", "lldp.tlv.system.name": "Switch, floor 2",
                 "lldp.chassis.id.mac": "11:22:33:44:55:66", "lldp.port.id": "Gi0/1",
                 "lldp.port.desc": "uplink"})
    src, mac, ip, host, vend, det = out[0]
    assert (src, mac, ip, host) == ("lldp", "11:22:33:44:55:66", None, "Switch, floor 2")
    assert det == {"port_id": "Gi0/1", "port_desc": "uplink"}


def test_lldp_non_mac_chassis_uses_eth_src(parse):
    out = parse({"eth.src": "aa:bb:cc:dd:ee:00", "lldp.chassis.id": "deadbeef",
                 "lldp.tlv.system.name": "AP-1"})
    assert out[0][1] == "aa:bb:cc:dd:ee:00"


def test_lldp_port_desc_only_still_fires(parse):
    out = parse({"eth.src": "aa:bb:cc:dd:ee:00", "lldp.port.desc": "uplink"})
    assert out[0][0] == "lldp"
    assert out[0][3] is None                            # no system name


def test_cdp(parse):
    out = parse({"eth.src": "aa:bb:cc:dd:ee:00", "cdp.deviceid": "sw-core.local",
                 "cdp.portid": "GigabitEthernet0/2"})
    src, mac, ip, host, vend, det = out[0]
    assert (src, mac, host) == ("cdp", "aa:bb:cc:dd:ee:00", "sw-core.local")
    assert det == {"port_id": "GigabitEthernet0/2"}


# ───────────────────────── NetBIOS / browser ─────────────────────────

def test_netbios_name_registration(parse):
    out = parse({"eth.src": "aa:bb:cc:dd:ee:20", "ip.src": "192.168.10.40",
                 "nbns.name": "DESKTOP-1A2B3C<20>", "nbns.flags.opcode": "5",
                 "nbns.flags.response": "0", "nbns.nb_flags.group": "0"})
    src, mac, ip, host, vend, det = out[0]
    assert (src, mac, ip, host) == ("netbios", "aa:bb:cc:dd:ee:20", "192.168.10.40", "DESKTOP-1A2B3C")


def test_netbios_group_name_skipped(parse):
    # a <00> group entry (the workgroup) is not the machine's own name
    out = parse({"eth.src": "aa:bb:cc:dd:ee:20", "ip.src": "192.168.10.40",
                 "nbns.name": "WORKGROUP<00>", "nbns.flags.opcode": "5",
                 "nbns.flags.response": "0", "nbns.nb_flags.group": "1"})
    assert out == []


def test_netbios_query_response_skipped(parse):
    # a response (not a registration) is a name being answered, not announced
    out = parse({"eth.src": "aa:bb:cc:dd:ee:20", "nbns.name": "DESKTOP-1A2B3C<20>",
                 "nbns.flags.opcode": "5", "nbns.flags.response": "1", "nbns.nb_flags.group": "0"})
    assert out == []


def test_browser_host_announcement(parse):
    out = parse({"eth.src": "aa:bb:cc:dd:ee:21", "ip.src": "192.168.10.41",
                 "browser.command": "1", "browser.server": "FILESERVER",
                 "browser.os_major": "10", "browser.os_minor": "0",
                 "browser.comment": "Samba 4.19"})
    src, mac, ip, host, vend, det = out[0]
    assert (src, mac, ip, host) == ("netbios", "aa:bb:cc:dd:ee:21", "192.168.10.41", "FILESERVER")
    assert det["os_version"] == "10.0"
    assert det["comment"] == "Samba 4.19"


# ───────────────────────── IPv6 RA ─────────────────────────

def test_ipv6_ra_basic(parse, pm):
    agg = pm.AGG
    out = parse({"eth.src": "aa:bb:cc:dd:ee:30", "ipv6.src": "fe80::1",
                 "icmpv6.type": "134", "icmpv6.nd.ra.router_lifetime": "1800",
                 "icmpv6.nd.ra.cur_hop_limit": "64",
                 "icmpv6.opt.prefix": f"2001:db8::{agg}fd00::",
                 "icmpv6.opt.type": f"3{agg}3{agg}25"})
    src, mac, ip, host, vend, det = out[0]
    assert (src, mac, ip) == ("ra", "aa:bb:cc:dd:ee:30", "fe80::1")
    assert det["router_lifetime"] == 1800
    assert det["hop_limit"] == 64
    assert det["prefixes"] == ["2001:db8::", "fd00::"]
    assert det["options"] == [3, 25]                    # deduped + sorted


def test_ipv6_ra_lifetime_zero_is_kept(parse):
    # lifetime 0 (Apple TV / HomePod Thread border router) must survive the "drop empties" filter
    out = parse({"eth.src": "aa:bb:cc:dd:ee:30", "ipv6.src": "fe80::1",
                 "icmpv6.type": "134", "icmpv6.nd.ra.router_lifetime": "0"})
    det = out[0][5]
    assert det["router_lifetime"] == 0


# ───────────────────────── mDNS ─────────────────────────

def test_mdns_advertised_services(parse):
    out = parse({"eth.src": "aa:bb:cc:dd:ee:40", "ip.src": "192.168.10.50",
                 "dns.flags.response": "1",
                 "dns.resp.name": "Living Room._airplay._tcp.local"})
    src, mac, ip, host, vend, det = out[0]
    assert (src, mac, ip) == ("mdns", "aa:bb:cc:dd:ee:40", "192.168.10.50")
    assert det["services_adv"] == ["_airplay._tcp"]
    assert det["services"] == ["_airplay._tcp"]
    assert "services_qry" not in det


def test_mdns_service_ports_from_srv_records(parse, pm):
    """The port of each announced TCP service (its SRV record), for naming a new open port (portid.py)."""
    agg = pm.AGG
    out = parse({"eth.src": "aa:bb:cc:dd:ee:47", "ip.src": "192.168.10.57", "dns.flags.response": "1",
                 "dns.resp.name": f"Living Room._airplay._tcp.local{agg}Living Room._raop._tcp.local{agg}x._hap._udp.local",
                 "dns.resp.type": f"33{agg}16{agg}33",
                 "dns.srv.port": f"7000{agg}51827", "dns.srv.target": f"LivingRoom.local{agg}LivingRoom.local"})
    assert out[0][5]["service_ports"] == {"_airplay._tcp": 7000}      # TXT (16) skipped, UDP left out


def test_mdns_queried_services_split(parse):
    # a query carries service types the asker is looking for → services_qry, never services_adv
    out = parse({"eth.src": "aa:bb:cc:dd:ee:41", "ip.src": "192.168.10.51",
                 "dns.flags.response": "0", "dns.qry.name": "_googlecast._tcp.local"})
    det = out[0][5]
    assert det["services_qry"] == ["_googlecast._tcp"]
    assert "services_adv" not in det


def test_mdns_txt_parsed_and_model_surfaced(parse):
    out = parse({"eth.src": "aa:bb:cc:dd:ee:42", "ip.src": "192.168.10.52",
                 "dns.flags.response": "1",
                 "dns.resp.name": "Apple TV._airplay._tcp.local",
                 "dns.txt": "md=AppleTV6,2;fn=Living Room, upstairs"})
    det = out[0][5]
    assert det["txt"] == {"md": "AppleTV6,2", "fn": "Living Room, upstairs"}   # comma kept in value
    assert det["txt_model"] == "AppleTV6,2"


def test_mdns_txt_multiple_records_and_dup_key(parse, pm):
    agg = pm.AGG
    out = parse({"eth.src": "aa:bb:cc:dd:ee:43", "ip.src": "192.168.10.53",
                 "dns.flags.response": "1", "dns.resp.name": "x._hap._tcp.local",
                 "dns.txt": f"md=First{agg}md=Second{agg}ci=2"})
    txt = out[0][5]["txt"]
    assert txt["md"] == "First"                         # first occurrence wins
    assert txt["ci"] == "2"


def test_mdns_txt_value_truncated_to_200(parse):
    out = parse({"eth.src": "aa:bb:cc:dd:ee:44", "ip.src": "192.168.10.54",
                 "dns.flags.response": "1", "dns.resp.name": "x._hap._tcp.local",
                 "dns.txt": "note=" + "z" * 300})
    assert len(out[0][5]["txt"]["note"]) == 200


def test_mdns_hostname_from_own_a_record(parse):
    out = parse({"eth.src": "aa:bb:cc:dd:ee:45", "ip.src": "192.168.10.55",
                 "dns.flags.response": "1", "dns.resp.name": "Alexs-MacBook.local",
                 "dns.resp.type": "1", "dns.a": "192.168.10.55"})
    src, mac, ip, host, vend, det = out[0]
    assert (src, host) == ("mdns", "Alexs-MacBook")


def test_mdns_hostname_not_borrowed_from_sleep_proxy(parse):
    # the A record is for an address the packet did NOT come from → not this sender's name
    out = parse({"eth.src": "aa:bb:cc:dd:ee:46", "ip.src": "192.168.10.56",
                 "dns.flags.response": "1", "dns.resp.name": "Sleeping-Mac.local",
                 "dns.resp.type": "1", "dns.a": "192.168.10.99"})
    assert out == []                                    # no service, no own hostname → nothing


# ───────────────────────── robustness ─────────────────────────

def test_empty_and_short_lines_do_not_crash(pm):
    assert pm.parse_line("", None) == []
    assert pm.parse_line("x", None) == []
    assert pm.parse_line("a\x1fb\x1fc", None) == []
    # a line longer than the field list must not raise either
    assert pm.parse_line(pm.SEP.join(["x"] * (len(pm.TSHARK_FIELDS) + 5)), None) is not None


def test_garbage_fields_do_not_crash(parse):
    assert parse({"icmpv6.type": "not-a-number"}) == []
    assert parse({"arp.opcode": "zzz"}) == []
    assert parse({"dhcp.option.dhcp": "weird", "dhcp.hw.mac_addr": "aa:bb:cc:dd:ee:10"})[0][0] == "dhcp"


# ───────────────────────── upsert merge ─────────────────────────

def test_upsert_mdns_merges_services_and_txt(pm, db):
    now = common.now_iso()
    pm.upsert(db, "mdns", "aa:bb:cc:00:00:01", "192.168.10.5", None, None,
              {"services_adv": ["_airplay._tcp"], "services": ["_airplay._tcp"], "txt": {"md": "X"}}, now)
    pm.upsert(db, "mdns", "aa:bb:cc:00:00:01", "192.168.10.5", None, None,
              {"services_adv": ["_raop._tcp"], "services": ["_raop._tcp"], "txt": {"fn": "Y"}}, now)
    row = db.execute("SELECT details, count FROM observations WHERE source='mdns'").fetchone()
    d = json.loads(row["details"])
    assert d["services_adv"] == ["_airplay._tcp", "_raop._tcp"]
    assert d["services"] == ["_airplay._tcp", "_raop._tcp"]
    assert d["txt"] == {"md": "X", "fn": "Y"}
    assert row["count"] == 2


def test_upsert_mdns_newer_txt_value_wins(pm, db):
    now = common.now_iso()
    pm.upsert(db, "mdns", "aa:bb:cc:00:00:04", "192.168.10.9", None, None, {"txt": {"md": "Old"}}, now)
    pm.upsert(db, "mdns", "aa:bb:cc:00:00:04", "192.168.10.9", None, None, {"txt": {"md": "New"}}, now)
    d = json.loads(db.execute("SELECT details FROM observations WHERE mac='aa:bb:cc:00:00:04'").fetchone()["details"])
    assert d["txt"]["md"] == "New"


def test_upsert_prev_txt_nondict_is_ignored(pm, db):
    now = common.now_iso()
    db.execute("INSERT INTO observations (source, mac, ip, details, first_seen, last_seen, count) "
               "VALUES ('mdns','aa:bb:cc:00:00:02','192.168.10.6', ?, ?, ?, 1)",
               (json.dumps({"txt": "not-a-dict", "services_adv": ["_a._tcp"]}), now, now))
    pm.upsert(db, "mdns", "aa:bb:cc:00:00:02", "192.168.10.6", None, None,
              {"txt": {"md": "Z"}, "services_adv": ["_b._tcp"]}, now)
    d = json.loads(db.execute("SELECT details FROM observations WHERE mac='aa:bb:cc:00:00:02'").fetchone()["details"])
    assert d["txt"] == {"md": "Z"}                       # prev non-dict dropped by isinstance guard
    assert d["services_adv"] == ["_a._tcp", "_b._tcp"]


def test_upsert_dhcp_new_fingerprint_drops_stale_match(pm, db):
    now = common.now_iso()
    pm.upsert(db, "dhcp", "aa:bb:cc:00:00:05", "192.168.10.7", None, None,
              {"dhcp_fingerprint": "1,3,6,15", "fingerprint_match": "Espressif (ESP8266/ESP32 / Shelly)"}, now)
    pm.upsert(db, "dhcp", "aa:bb:cc:00:00:05", "192.168.10.7", None, None,
              {"dhcp_fingerprint": "99,98"}, now)
    d = json.loads(db.execute("SELECT details FROM observations WHERE source='dhcp'").fetchone()["details"])
    assert d["dhcp_fingerprint"] == "99,98"
    assert "fingerprint_match" not in d                  # stale label removed


def test_upsert_new_txt_nondict_does_not_crash(pm, db):
    now = common.now_iso()
    pm.upsert(db, "mdns", "aa:bb:cc:00:00:03", "192.168.10.8", None, None, {"txt": {"md": "A"}}, now)
    # a non-dict new txt is never produced by parse_line, but prev is defended and now new is too —
    # the non-dict incoming txt is ignored like the prev case instead of raising TypeError.
    pm.upsert(db, "mdns", "aa:bb:cc:00:00:03", "192.168.10.8", None, None, {"txt": "bare-string"}, now)
    d = json.loads(db.execute("SELECT details FROM observations WHERE source='mdns'").fetchone()["details"])
    assert d["txt"] == {"md": "A"}                       # non-dict incoming txt ignored, prev kept


# ── per-day observation counts (for real Traffic period totals) ──

def test_flush_obs_counts_accumulates(pm, db):
    """flush_obs_counts writes the pending (source, mac, ip, day) -> n deltas and clears the dict; a later
    flush adds to the existing day's count."""
    pending = {("arp_req", "aa", "1.2.3.4", "2026-10-29"): 3, ("mdns", "bb", "", "2026-10-29"): 1}
    pm.flush_obs_counts(db, pending)
    assert pending == {}                                  # cleared after a successful flush
    rows = {(r["source"], r["mac"], r["ip"], r["day"]): r["n"]
            for r in db.execute("SELECT * FROM observation_counts")}
    assert rows[("arp_req", "aa", "1.2.3.4", "2026-10-29")] == 3
    assert rows[("mdns", "bb", "", "2026-10-29")] == 1
    pm.flush_obs_counts(db, {("arp_req", "aa", "1.2.3.4", "2026-10-29"): 2})
    assert db.execute("SELECT n FROM observation_counts WHERE source='arp_req'").fetchone()[0] == 5
