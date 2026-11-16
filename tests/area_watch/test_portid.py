"""portid.py: what is behind a new port (2026-11-02), and how a new-port alert says it."""
import json
import struct

import common
import homechecks
import portid


# ───────────────────────── the RPC port directory ─────────────────────────

def _dump_reply(xid, entries):
    body = struct.pack(">6I", xid, 1, 0, 0, 0, 0)              # REPLY, accepted, no verifier, SUCCESS
    for prog, vers, prot, port in entries:
        body += struct.pack(">5I", 1, prog, vers, prot, port)
    return body + struct.pack(">I", 0)


def test_rpc_dump_names_the_nfs_helpers():
    """Proxmox host's directory: mountd and nlockmgr on random TCP ports; UDP entries are left out."""
    reply = _dump_reply(7, [(100000, 2, 6, 111), (100005, 3, 6, 33575), (100024, 1, 17, 36183),
                            (100021, 4, 6, 45191), (100003, 3, 6, 2049)])
    assert portid.parse_rpc_dump(reply, 7) == {111: "RPC port directory (rpcbind)",
                                               33575: "NFS mount service (mountd)",
                                               45191: "NFS file locking (nlockmgr)", 2049: "NFS file sharing"}


def test_rpc_dump_wrong_xid_or_refusal_is_nothing():
    assert portid.parse_rpc_dump(_dump_reply(7, [(100005, 3, 6, 33575)]), 8) == {}
    refused = struct.pack(">6I", 7, 1, 0, 0, 0, 1)             # accept_stat PROG_UNAVAIL
    assert portid.parse_rpc_dump(refused, 7) == {}


# ───────────────────────── identify: the most reliable source first ─────────────────────────

def test_identify_uses_what_the_device_announces(db, make):
    mac = "aa:bb:cc:00:00:30"
    make.observation("mdns", mac=mac, ip="192.168.10.30",
                     details={"services_adv": ["_airplay._tcp"], "service_ports": {"_airplay._tcp": 7000}})
    ids = portid.identify(db, mac, "192.168.10.30", [7000])
    assert ids[7000] == {"what": "AirPlay", "how": "the device's own announcement (mDNS)", "sure": True}


def test_identify_asks_the_port_directory_when_111_is_open(db, monkeypatch):
    asked = []
    monkeypatch.setattr(portid, "rpc_directory", lambda ip: asked.append(ip) or {33575: "NFS mount service (mountd)"})
    ids = portid.identify(db, "a4:bb:6d:00:00:21", "192.168.10.21", [33575], open_ports=[22, 111, 2049, 33575])
    assert asked == ["192.168.10.21"]
    assert ids[33575]["what"] == "NFS mount service (mountd)"
    assert ids[33575]["how"] == "its own port directory (rpcbind)"


def test_identify_leaves_the_directory_alone_without_111(db, monkeypatch):
    monkeypatch.setattr(portid, "rpc_directory", lambda ip: (_ for _ in ()).throw(AssertionError("asked")))
    portid.identify(db, "aa:bb:cc:00:00:31", "192.168.10.31", [40000], open_ports=[22, 40000])


def test_identify_web_title_then_version_check(db, monkeypatch):
    checked = []
    monkeypatch.setattr(portid, "version_check",
                        lambda ip, ports: checked.append(list(ports)) or {2222: ("SSH login", "OpenSSH 9.2")})
    ids = portid.identify(db, "aa:bb:cc:00:00:32", "192.168.10.32", [2222, 8090],
                          web={"8090": {"status": 200, "title": "Grafana"}})
    assert ids[8090]["what"] == 'a web page, "Grafana"'
    assert checked == [[2222]]                                   # only the port the web page did not explain
    assert ids[2222] == {"what": "SSH login (OpenSSH 9.2)", "how": "its own answer to a light check", "sure": True}


def test_identify_a_nameless_web_server(db):
    """HA VM's 44913: answers 404 and gives no name, and the light check did not recognise it either."""
    ids = portid.identify(db, "02:00:00:aa:00:88", "192.168.10.88", [44913], web={"44913": {"status": 404}})
    assert ids[44913]["what"] == "a web server that answers 404 on its front page and gives no name"
    assert ids[44913]["sure"] is True


def test_identify_falls_back_to_a_marked_guess(db):
    ids = portid.identify(db, "aa:bb:cc:00:00:33", "192.168.10.33", [5000, 41234])
    assert ids[5000] == {"what": "UPnP", "how": "the usual service on that port number; the port didn't say",
                         "sure": False}
    assert 41234 not in ids                                      # nothing named it: not guessed either


# ───────────────────────── the alert ─────────────────────────

def _router(db, **state):
    common.kv_set(db, "router_upnp", json.dumps({"at": common.now_iso(), **state}))
    db.commit()


def test_alert_says_what_each_port_is_and_how_it_knows(db, alert_spy):
    _router(db, state="on", complete=True, forwards=[])
    ids = {33575: {"what": "NFS mount service (mountd)", "how": "its own port directory (rpcbind)", "sure": True},
           5000: {"what": "UPnP", "how": "the usual service on that port number; the port didn't say", "sure": False}}
    common.alert_new_ports(db, "a4:bb:6d:00:00:21", "Proxmox host", "192.168.10.21", [5000, 33575, 41234], ids=ids)
    d = alert_spy.calls[0]["details"]
    assert "- 33575: NFS mount service (mountd), from its own port directory (rpcbind)" in d
    assert "- 5000: probably UPnP (the usual service on that port number; the port didn't say)" in d
    assert "- 41234: not identified: it didn't answer LanWard's questions, and Proxmox host doesn't announce it" in d
    assert "Open to the internet? Not by UPnP: your router has no UPnP forward to it." in d


def test_alert_title_names_a_single_identified_port(db, alert_spy):
    ids = {7000: {"what": "AirPlay", "how": "the device's own announcement (mDNS)", "sure": True}}
    common.alert_new_ports(db, "aa:bb:cc:00:00:34", "Living room TV", "192.168.10.34", [7000], ids=ids)
    assert alert_spy.calls[0]["title"] == "New open port on Living room TV: 7000 (AirPlay)"


def test_internet_exposure_forward_off_and_unknown(db):
    _router(db, state="on", complete=True, forwards=[["192.168.10.20", 443, 8443, "TCP"]])
    assert common.internet_exposure(db, "192.168.10.20", [443]).startswith("Yes: your router forwards 443 (outside port 8443)")
    _router(db, state="off")
    assert common.internet_exposure(db, "192.168.10.20", [443]).startswith("Not by UPnP: your router doesn't let")
    _router(db, state="on", complete=False, forwards=[])
    assert common.internet_exposure(db, "192.168.10.20", [443]) is None          # the list was cut short
    common.kv_set(db, "router_upnp", json.dumps({"at": common.iso_ago(days=5), "state": "off"}))
    assert common.internet_exposure(db, "192.168.10.20", [443]) is None          # too old to say


def test_router_findings_remember_the_forwards(monkeypatch):
    homechecks.ROUTER_UPNP.clear()
    monkeypatch.setattr(homechecks, "upnp_port_mappings", lambda location: ([
        {"enabled": "1", "proto": "TCP", "external": "8443", "client": "192.168.10.20", "internal": "443",
         "description": "nginx"},
        {"enabled": "0", "proto": "TCP", "external": "9000", "client": "192.168.10.21", "internal": "9000",
         "description": "off"}], True))
    homechecks.router_findings({"st": ["urn:schemas-upnp-org:device:InternetGatewayDevice:1"], "location": "http://x"})
    assert homechecks.ROUTER_UPNP == {"state": "on", "complete": True, "forwards": [["192.168.10.20", 443, 8443, "TCP"]]}
    homechecks.ROUTER_UPNP.clear()
    homechecks.router_findings({"st": ["urn:schemas-upnp-org:device:Basic:1"]})
    assert homechecks.ROUTER_UPNP == {"state": "off"}


# ───────────────────────── names that cost nothing, and the scan's Phase P ─────────────────────────

def test_web_label_skips_titles_that_say_nothing():
    assert portid.web_label({"status": 403, "title": "Error 403", "server": "Linux UPnP/1.0 Sonos/97.2-81220 (ZPS14)"}) \
        == "Sonos speaker control"
    assert portid.web_label({"status": 404, "server": "2.6.36 DLNADOC/1.50 UPnP/1.0 MiniDLNA/1.2.1"}) \
        == "media server (MiniDLNA 1.2.1)"
    assert portid.web_label({"status": 200, "title": "Home Assistant"}) == 'a web page, "Home Assistant"'
    assert portid.web_label({"status": 405, "server": "Python/3.14 aiohttp/3.14.5"}) == "a web server (Python/3.14 aiohttp/3.14.5)"


def test_ssh_label():
    assert portid.ssh_label("SSH-2.0-OpenSSH_10.3") == "SSH login (OpenSSH 10.3)"
    assert portid.ssh_label("SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4") == "SSH login (OpenSSH 10.0p2)"
    assert portid.ssh_label(None) is None


def _seed_ports(db, mac, ports, first=None):
    first = first or common.iso_ago(days=10)
    db.executemany("INSERT INTO open_ports_seen (mac, port, first_seen, last_seen) VALUES (?,?,?,?)",
                   [(mac, p, first, common.now_iso()) for p in ports])
    db.commit()


def test_phase_names_ports_and_asks_only_the_unnamed(db, make, monkeypatch):
    sid = make.scan()
    mac = "02:00:00:aa:00:88"
    make.host(sid, ip="192.168.10.88", mac=mac, open_ports="[22, 1883, 8123, 44913, 55001]",
              ssh_banner="SSH-2.0-OpenSSH_10.3",
              web_info=json.dumps({"8123": {"status": 200, "title": "Home Assistant"}, "44913": {"status": 404}}))
    _seed_ports(db, mac, [22, 1883, 8123, 44913, 55001])
    asked = []
    monkeypatch.setattr(portid, "version_check",
                        lambda ip, ports: asked.append(list(ports)) or {1883: ("smart home messages (MQTT)", "Mosquitto")})
    portid.run_phase(db, sid)
    assert asked == [[1883]]                                          # 55001 is a temporary port: never asked
    got = portid.stored(db, mac)
    assert got[22]["what"] == "SSH login (OpenSSH 10.3)"
    assert got[8123]["what"] == 'a web page, "Home Assistant"'
    assert got[1883] == {"what": "smart home messages (MQTT) (Mosquitto)", "how": portid.HOW_CHECK, "sure": True}
    assert got[44913]["what"].startswith("a web server that answers 404")
    checked = dict(db.execute("SELECT port, checked_at FROM open_ports_seen WHERE mac=?", (mac,)).fetchall())
    assert checked[1883] and not checked[22]                          # only what the network was asked is stamped
    asked.clear()
    portid.run_phase(db, sid)                                         # the next scan: nothing left to ask
    assert asked == []


def test_phase_keeps_a_sure_answer_over_a_guess(db, make):
    sid = make.scan()
    mac = "aa:bb:cc:00:00:40"
    make.host(sid, ip="192.168.10.40", mac=mac, open_ports="[5000]")
    _seed_ports(db, mac, [5000])
    portid.save(db, mac, {5000: {"what": "UPnP device control (MiniUPnP)", "how": portid.HOW_CHECK, "sure": True}}, [5000])
    portid.run_phase(db, sid)
    assert portid.stored(db, mac)[5000]["what"] == "UPnP device control (MiniUPnP)"


def test_phase_respects_the_per_scan_budget_new_ports_first(db, make, monkeypatch):
    monkeypatch.setattr(portid, "PHASE_MAX_PORTS", 2)
    sid = make.scan()
    old, new = "aa:bb:cc:00:00:41", "aa:bb:cc:00:00:42"
    make.host(sid, ip="192.168.10.41", mac=old, open_ports="[7001, 7002]")
    make.host(sid, ip="192.168.10.42", mac=new, open_ports="[7003, 7004]")
    _seed_ports(db, old, [7001, 7002])
    _seed_ports(db, new, [7003, 7004], first=common.iso_ago(hours=2))
    asked = []
    monkeypatch.setattr(portid, "version_check", lambda ip, ports: asked.append((ip, list(ports))) or {})
    portid.run_phase(db, sid)
    assert asked == [("192.168.10.42", [7003, 7004])]                  # the device with new ports went first
