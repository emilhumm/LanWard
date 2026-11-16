"""Area B — scan.py: scan helpers (run_nmap / discovery mocked throughout)."""
import json
import sys
import types
import xml.etree.ElementTree as ET

import pytest

import common
import scan


# ───────────────────────────── nmap XML helpers ─────────────────────────────

def _host_xml(ip, ports=(), mac=None, timedout=False, start=None, end=None):
    addrs = f'<address addr="{ip}" addrtype="ipv4"/>'
    if mac:
        addrs += f'<address addr="{mac}" addrtype="mac" vendor="Acme"/>'
    portxml = "".join(f'<port portid="{p}"><state state="open"/></port>' for p in ports)
    times = ""
    if start is not None and end is not None:
        times = f' starttime="{start}" endtime="{end}"'
    td = ' timedout="true"' if timedout else ""
    return (f'<host{times}{td}><status state="up"/>{addrs}<ports>{portxml}</ports></host>')


def nmap_root(hosts_xml):
    return ET.fromstring(f"<nmaprun>{''.join(hosts_xml)}<runstats><finished exit='success'/></runstats></nmaprun>")


# ───────────────────────────── device_ids ─────────────────────────────

def test_device_ids_plain_macs():
    hosts = {"192.168.10.9": {"mac": "aa:bb:cc:dd:ee:01", "vendor": None, "hostname": None},
             "192.168.10.10": {"mac": "aa:bb:cc:dd:ee:02", "vendor": None, "hostname": None}}
    ids = scan.device_ids(hosts, shared=set())
    assert ids == {"192.168.10.9": "aa:bb:cc:dd:ee:01", "192.168.10.10": "aa:bb:cc:dd:ee:02"}


def test_device_ids_drops_macless():
    hosts = {"192.168.10.9": {"mac": None, "vendor": None, "hostname": None}}
    assert scan.device_ids(hosts, shared=set()) == {}


def test_device_ids_sonos_bridge(monkeypatch):
    # Two addresses share the bridge MAC; each resolves to its own RINCON MAC via enrich.
    bridge = "aa:bb:cc:dd:ee:bb"
    hosts = {
        "192.168.10.20": {"mac": bridge, "vendor": "Sonos", "hostname": None},
        "192.168.10.21": {"mac": bridge, "vendor": "Sonos", "hostname": None},
    }
    own = {"192.168.10.20": "11:11:11:11:11:01", "192.168.10.21": "11:11:11:11:11:02"}
    fake = types.ModuleType("enrich")
    fake.follow_upnp_location = lambda url: {"url": url}
    fake.sonos_mac = lambda info: own[info["url"].split("//")[1].split(":")[0]]
    monkeypatch.setitem(sys.modules, "enrich", fake)
    ids = scan.device_ids(hosts, shared={bridge})
    assert ids == own


def test_device_ids_sonos_unknown_left_out(monkeypatch):
    bridge = "aa:bb:cc:dd:ee:bb"
    hosts = {"192.168.10.20": {"mac": bridge, "vendor": "Sonos", "hostname": None}}
    fake = types.ModuleType("enrich")
    fake.follow_upnp_location = lambda url: {}
    fake.sonos_mac = lambda info: None          # no RINCON id → no own MAC
    monkeypatch.setitem(sys.modules, "enrich", fake)
    assert scan.device_ids(hosts, shared={bridge}) == {}


# ───────────────────────────── known_ports ─────────────────────────────

def test_known_ports_non_label_only(db):
    now = common.now_iso()
    db.executemany("INSERT INTO open_ports_seen (mac, port, first_seen, last_seen) VALUES (?,?,?,?)",
                   [("aa:bb:cc:dd:ee:01", 80, now, now),       # in PORT_LABELS → excluded
                    ("aa:bb:cc:dd:ee:01", 5555, now, now),     # not a label → kept
                    ("aa:bb:cc:dd:ee:02", 7000, now, now)])
    db.commit()
    ids = {"192.168.10.9": "aa:bb:cc:dd:ee:01", "192.168.10.10": "aa:bb:cc:dd:ee:02"}
    known = scan.known_ports(db, ids)
    assert known == {"192.168.10.9": {5555}, "192.168.10.10": {7000}}


def test_known_ports_ignores_old(db):
    old = common.iso_ago(days=scan.KNOWN_PORT_DAYS + 5)
    db.execute("INSERT INTO open_ports_seen (mac, port, first_seen, last_seen) VALUES (?,?,?,?)",
               ("aa:bb:cc:dd:ee:01", 5555, old, old))
    db.commit()
    assert scan.known_ports(db, {"192.168.10.9": "aa:bb:cc:dd:ee:01"}) == {}


# ───────────────────────────── scans_per_day ─────────────────────────────

@pytest.mark.parametrize("hours,expect", [
    ("0,6,12,18", 4),
    ("", 1),
    ("25,99", 1),          # out of range → none valid → 1
    ("6,6,6", 1),          # deduped
    ("8", 1),
])
def test_scans_per_day(monkeypatch, hours, expect):
    monkeypatch.setattr(common, "setting", lambda name: hours if name == "SCAN_HOURS" else "")
    assert scan.scans_per_day() == expect


# ───────────────────────────── record_ports ─────────────────────────────

def test_record_ports_writes_history_and_new(monkeypatch, db, make):
    s = make.scan()
    make.host(s, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:01", open_ports=None)
    ids = {"192.168.10.9": "aa:bb:cc:dd:ee:01"}
    scan.record_ports(db, s, ids, {"192.168.10.9": [80, 443]}, fully_checked={"192.168.10.9"}, me_ip="192.168.10.1")
    seen = {r[0] for r in db.execute("SELECT port FROM open_ports_seen WHERE mac=?", ("aa:bb:cc:dd:ee:01",))}
    assert seen == {80, 443}


def test_record_ports_skips_none_and_macless(db, make):
    s = make.scan()
    make.host(s, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:01", open_ports=None)
    # found None (unchecked) and an ip with no id → nothing recorded
    scan.record_ports(db, s, {}, {"192.168.10.9": None, "192.168.10.8": [80]}, fully_checked=set(), me_ip="x")
    assert db.execute("SELECT COUNT(*) FROM open_ports_seen").fetchone()[0] == 0


def test_record_ports_new_ports_column(monkeypatch, db, make):
    # Make a device whose baseline is past, then a scan finds a brand-new port → hosts.new_ports set.
    mac = "aa:bb:cc:dd:ee:01"
    old = common.iso_ago(days=2)
    db.execute("INSERT INTO port_checks (mac, full_checked_at, full_tried_at, first_full_at) VALUES (?,?,?,?)",
               (mac, old, old, old))
    db.execute("INSERT INTO open_ports_seen (mac, port, first_seen, last_seen) VALUES (?,?,?,?)",
               (mac, 80, old, old))
    db.commit()
    s = make.scan()
    make.host(s, ip="192.168.10.9", mac=mac, open_ports=None)
    scan.record_ports(db, s, {"192.168.10.9": mac}, {"192.168.10.9": [80, 8443]},
                      fully_checked=set(), me_ip="192.168.10.1")
    row = db.execute("SELECT new_ports FROM hosts WHERE scan_id=? AND ip=?", (s, "192.168.10.9")).fetchone()
    assert json.loads(row["new_ports"]) == [8443]


# ──────────────────── random high ports that moved after a restart (2026-11-02) ────────────────────

def _history(db, mac, ports, days_ago):
    """A device past its baseline, with `ports` last seen `days_ago` days back."""
    old, last = common.iso_ago(days=30), common.iso_ago(days=days_ago)
    db.execute("INSERT OR IGNORE INTO port_checks (mac, full_checked_at, full_tried_at, first_full_at) VALUES (?,?,?,?)",
               (mac, old, old, old))
    db.executemany("INSERT INTO open_ports_seen (mac, port, first_seen, last_seen) VALUES (?,?,?,?)",
                   [(mac, p, old, last) for p in ports])
    db.commit()


def _seen(db, mac):
    return {r[0] for r in db.execute("SELECT port FROM open_ports_seen WHERE mac=?", (mac,))}


def test_moved_random_ports_are_not_new(db):
    """Proxmox host, 1-2 Nov: NFS's 5 helpers came back on 5 new random ports after a restart."""
    mac = "a4:bb:6d:00:00:21"
    _history(db, mac, [22, 111, 2049], 0)
    _history(db, mac, [37187, 42965, 44181, 46693, 58049], 1)       # closed since yesterday
    now = [22, 111, 2049, 33575, 36183, 36579, 45191, 56045]
    assert common.record_open_ports(db, mac, now, full=True) == []
    moved = dict(db.execute("SELECT port, moved_to FROM open_ports_seen WHERE mac=? AND moved_to IS NOT NULL", (mac,)))
    assert set(moved) == {37187, 42965, 44181, 46693, 58049}         # kept, marked as moved
    assert moved[37187] == "33575,36183,36579,45191,56045"
    moved_from = db.execute("SELECT moved_from FROM open_ports_seen WHERE mac=? AND port=33575", (mac,)).fetchone()[0]
    assert moved_from == "37187,42965,44181,46693,58049"


def test_one_moved_port_with_a_web_server(db):
    """HA VM: an integration's callback server moved from 43123 to 44913."""
    mac = "02:00:00:aa:00:88"
    _history(db, mac, [22, 8123], 0)
    _history(db, mac, [43123], 1)
    assert common.record_open_ports(db, mac, [22, 8123, 44913], full=True) == []


def test_more_new_random_ports_than_closed_are_all_new(db):
    mac = "aa:bb:cc:dd:ee:02"
    _history(db, mac, [22], 0)
    _history(db, mac, [40001], 1)
    assert common.record_open_ports(db, mac, [22, 40500, 41500], full=True) == [40500, 41500]
    assert db.execute("SELECT moved_to FROM open_ports_seen WHERE mac=? AND port=40001", (mac,)).fetchone()[0] is None


def test_a_low_port_stays_new_next_to_a_moved_one(db):
    mac = "aa:bb:cc:dd:ee:03"
    _history(db, mac, [22], 0)
    _history(db, mac, [43123], 1)
    assert common.record_open_ports(db, mac, [22, 5000, 44913], full=True) == [5000]


def test_a_random_port_closed_long_ago_does_not_count(db):
    mac = "aa:bb:cc:dd:ee:04"
    _history(db, mac, [22], 0)
    _history(db, mac, [43123], common.MOVED_DAYS + 3)
    assert common.record_open_ports(db, mac, [22, 44913], full=True) == [44913]


def test_a_closed_port_excuses_only_once(db):
    """After one move the closed number is marked as moved, so a later new random port is new again."""
    mac = "aa:bb:cc:dd:ee:05"
    _history(db, mac, [22], 0)
    _history(db, mac, [43123], 1)
    assert common.record_open_ports(db, mac, [22, 44913], full=True) == []
    assert common.record_open_ports(db, mac, [22, 44913, 50111], full=True) == [50111]


# ───────────────────────────── second_chance ─────────────────────────────

def test_second_chance_heard_only_gets_none_ports(monkeypatch, db, make):
    # Previous scan had a device that is missing now; it was heard recently → counted, ports not checked.
    mac = "aa:bb:cc:dd:ee:07"
    prev = make.scan(subnet="192.168.10.0/24")
    make.host(prev, ip="192.168.10.7", mac=mac)
    make.observation("mdns", mac, ip="192.168.10.7", last_seen=common.now_iso())
    monkeypatch.setattr(scan, "run_nmap", lambda args, timeout: nmap_root([]))   # nobody answers the retry
    hosts = {}
    heard = scan.second_chance(db, "192.168.10.0/24", hosts, me_ip="192.168.10.1")
    assert heard == {"192.168.10.7"}
    assert hosts["192.168.10.7"]["mac"] == mac           # added to hosts so it is counted


def test_second_chance_answered_joins_hosts(monkeypatch, db, make):
    mac = "aa:bb:cc:dd:ee:07"
    prev = make.scan(subnet="192.168.10.0/24")
    make.host(prev, ip="192.168.10.7", mac=mac)
    monkeypatch.setattr(scan, "run_nmap",
                        lambda args, timeout: nmap_root([_host_xml("192.168.10.7", mac=mac)]))
    hosts = {}
    heard = scan.second_chance(db, "192.168.10.0/24", hosts, me_ip="192.168.10.1")
    assert heard == set()                                # it answered → not "heard only"
    assert "192.168.10.7" in hosts


def test_second_chance_nothing_missing(monkeypatch, db, make):
    called = []
    monkeypatch.setattr(scan, "run_nmap", lambda args, timeout: called.append(1) or nmap_root([]))
    assert scan.second_chance(db, "192.168.10.0/24", {}, me_ip="192.168.10.1") == set()
    assert called == []                                  # no nmap run when nothing is missing


# ───────────────────────────── port_scan ─────────────────────────────

def test_port_scan_usual_batch_size_and_args(monkeypatch):
    seen = {}

    def fake_run(args, timeout):
        seen["args"], seen["timeout"] = args, timeout
        return nmap_root([_host_xml(ip, ports=[80]) for ip in args if ip.count(".") == 3])

    monkeypatch.setattr(scan, "run_nmap", fake_run)
    ips = [f"192.168.10.{i}" for i in range(1, 4)]
    result = scan.port_scan(ips)
    assert seen["args"][0] == "-Pn"
    assert "--min-hostgroup" in seen["args"] and "-sT" in seen["args"]
    assert seen["timeout"] == 900
    assert all(result[ip] == [80] for ip in ips)


def test_port_scan_full_uses_full_timing(monkeypatch):
    seen = {}

    def fake_run(args, timeout):
        seen["args"], seen["timeout"] = args, timeout
        return nmap_root([_host_xml("192.168.10.9", ports=[22, 8443])])

    monkeypatch.setattr(scan, "run_nmap", fake_run)
    result = scan.port_scan(["192.168.10.9"], full=True)
    assert "1-65535" in seen["args"]
    assert "--min-rate" in seen["args"]            # FULL_TIMING
    assert seen["timeout"] == 1200
    assert result["192.168.10.9"] == [22, 8443]


def test_port_scan_batches(monkeypatch):
    batches = []

    def fake_run(args, timeout):
        hostargs = [a for a in args if a.count(".") == 3 and a.replace(".", "").isdigit()]
        batches.append(len(hostargs))
        return nmap_root([_host_xml(ip, ports=[]) for ip in hostargs])

    monkeypatch.setattr(scan, "run_nmap", fake_run)
    ips = [f"192.168.10.{i}" for i in range(1, 11)]     # 10 hosts, full batch size 6 → 6 + 4
    scan.port_scan(ips, full=True)
    assert batches == [6, 4]


def test_port_scan_unknown_vs_none_open(monkeypatch):
    def fake_run(args, timeout):
        # .9 answered with no open ports; .10 timed out; .11 missing from the XML entirely
        return nmap_root([_host_xml("192.168.10.9", ports=[]),
                          _host_xml("192.168.10.10", ports=[], timedout=True)])

    monkeypatch.setattr(scan, "run_nmap", fake_run)
    result = scan.port_scan(["192.168.10.9", "192.168.10.10", "192.168.10.11"])
    assert result["192.168.10.9"] == []            # answered, nothing open
    assert result["192.168.10.10"] is None         # timed out → unknown
    assert result["192.168.10.11"] is None         # not in XML → unknown


def test_port_scan_nmap_failed_all_none(monkeypatch):
    monkeypatch.setattr(scan, "run_nmap", lambda args, timeout: None)
    result = scan.port_scan(["192.168.10.9", "192.168.10.10"])
    assert result == {"192.168.10.9": None, "192.168.10.10": None}


def test_port_scan_known_ports_in_args(monkeypatch):
    seen = {}
    monkeypatch.setattr(scan, "run_nmap",
                        lambda args, timeout: seen.update(args=args) or nmap_root([]))
    scan.port_scan(["192.168.10.9"], known={"192.168.10.9": {5555}})
    pspec = seen["args"][seen["args"].index("-p") + 1]
    assert "5555" in pspec.split(",")


# ───────────────────────────── save_scan ─────────────────────────────

def test_save_scan_ports_and_labels(db):
    hosts = {"192.168.10.9": {"mac": "aa:bb:cc:dd:ee:01", "vendor": "Acme", "hostname": "nas"}}
    ports = {"192.168.10.9": [80, 443, 5555]}
    sid = scan.save_scan(db, "192.168.10.0/24", common.now_iso(), hosts, ports)
    row = db.execute("SELECT ports, open_ports FROM hosts WHERE scan_id=?", (sid,)).fetchone()
    assert json.loads(row["open_ports"]) == [80, 443, 5555]
    labels = row["ports"].split(",")
    assert "http" in labels and "https" in labels and "5555" in labels   # unknown port → number


def test_save_scan_unchecked_is_null(db):
    hosts = {"192.168.10.9": {"mac": "aa:bb:cc:dd:ee:01", "vendor": None, "hostname": None}}
    sid = scan.save_scan(db, "192.168.10.0/24", common.now_iso(), hosts, {"192.168.10.9": None})
    row = db.execute("SELECT ports, open_ports FROM hosts WHERE scan_id=?", (sid,)).fetchone()
    assert row["open_ports"] is None and row["ports"] is None


def test_save_scan_empty_open_ports(db):
    # Checked, nothing open: open_ports is "[]" (known), but the label column is NULL.
    hosts = {"192.168.10.9": {"mac": "aa:bb:cc:dd:ee:01", "vendor": None, "hostname": None}}
    sid = scan.save_scan(db, "192.168.10.0/24", common.now_iso(), hosts, {"192.168.10.9": []})
    row = db.execute("SELECT ports, open_ports FROM hosts WHERE scan_id=?", (sid,)).fetchone()
    assert row["open_ports"] == "[]" and row["ports"] is None


def test_save_scan_host_count(db):
    hosts = {f"192.168.10.{i}": {"mac": None, "vendor": None, "hostname": None} for i in range(1, 4)}
    sid = scan.save_scan(db, "192.168.10.0/24", common.now_iso(), hosts, {})
    assert db.execute("SELECT host_count FROM scans WHERE id=?", (sid,)).fetchone()[0] == 3


# ───────────────────────────── up_hosts (discovery parse) ─────────────────────────────

def test_up_hosts_parses(monkeypatch):
    root = nmap_root([_host_xml("192.168.10.9", mac="AA:BB:CC:DD:EE:01")])
    found = scan.up_hosts(root)
    assert "192.168.10.9" in found
    assert found["192.168.10.9"]["mac"] == "aa:bb:cc:dd:ee:01"      # normalised lower-case
    assert found["192.168.10.9"]["vendor"] == "Acme"


def test_up_hosts_skips_down():
    root = ET.fromstring('<nmaprun><host><status state="down"/>'
                         '<address addr="192.168.10.9" addrtype="ipv4"/></host></nmaprun>')
    assert scan.up_hosts(root) == {}
