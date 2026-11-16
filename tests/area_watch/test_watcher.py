"""AREA E - watcher.py: offline/online, gateway spoof, rogue DHCP, scanners, rogue IPv6 RA."""
import json

import pytest

import common
import watcher


def _label(db, mac, label="Dev", watch=0):
    db.execute("INSERT INTO host_labels (mac, label, note, watch_offline, created_at, updated_at) "
               "VALUES (?,?,?,?,?,?)", (mac, label, "", watch, common.now_iso(), common.now_iso()))
    db.commit()


def _n(db, kind):
    return db.execute("SELECT COUNT(*) FROM alerts WHERE kind = ?", (kind,)).fetchone()[0]


# ───────────────────────── watched device: offline then back online ─────────────────────────

@pytest.fixture
def clock(monkeypatch):
    """A controllable time.monotonic() for watcher (offline time is measured on it)."""
    t = [1000.0]
    monkeypatch.setattr(watcher.time, "monotonic", lambda: t[0])
    return t


def test_watched_goes_offline_after_threshold(db, make, monkeypatch, clock, alert_spy, ago):
    mac = "aa:bb:cc:dd:ee:10"
    _label(db, mac, "Hallway cam", watch=1)
    # Known IP, last heard 3 min ago (so "recent" = 2 min does not cover it).
    make.observation("dhcp", mac=mac, ip="192.168.10.60",
                     first_seen=ago(minutes=30), last_seen=ago(minutes=3))
    monkeypatch.setattr(watcher, "arping", lambda ip: set())        # never answers
    state = {}

    # First check: found down, state recorded, no alert yet.
    watcher.check_watched(db, state)
    st = db.execute("SELECT state, alerted FROM watch_state WHERE mac=?", (mac,)).fetchone()
    assert st["state"] == "down" and st["alerted"] == 0
    assert _n(db, "offline") == 0

    # 10 minutes pass on the monotonic clock -> offline alert.
    clock[0] += 600
    watcher.check_watched(db, state)
    assert _n(db, "offline") == 1
    assert any(c["kind"] == "offline" and c["severity"] == "warning" for c in alert_spy.calls)
    st = db.execute("SELECT state, alerted FROM watch_state WHERE mac=?", (mac,)).fetchone()
    assert st["alerted"] == 1
    # The outage is recorded.
    assert db.execute("SELECT COUNT(*) FROM outages WHERE mac=? AND alerted=1", (mac,)).fetchone()[0] == 1


def test_watched_no_offline_before_threshold(db, make, monkeypatch, clock, alert_spy, ago):
    mac = "aa:bb:cc:dd:ee:11"
    _label(db, mac, "Doorbell", watch=1)
    make.observation("dhcp", mac=mac, ip="192.168.10.61",
                     first_seen=ago(minutes=30), last_seen=ago(minutes=3))
    monkeypatch.setattr(watcher, "arping", lambda ip: set())
    state = {}
    watcher.check_watched(db, state)
    clock[0] += 120            # only 2 minutes
    watcher.check_watched(db, state)
    assert _n(db, "offline") == 0


def _seed_back_online(db, make, monkeypatch, ago, mac, ip):
    """A watched device that was down+alerted and is now heard again."""
    _label(db, mac, "NAS", watch=1)
    make.observation("dhcp", mac=mac, ip=ip, first_seen=ago(minutes=30), last_seen=common.now_iso())
    monkeypatch.setattr(watcher, "arping", lambda i: {mac})
    db.execute("INSERT INTO watch_state (mac, state, since, last_ok, last_ip, alerted, pushed) "
               "VALUES (?, 'down', ?, ?, ?, 1, 1)", (mac, ago(minutes=20), ago(minutes=25), ip))
    db.commit()


def test_back_online_pushes_by_default(db, make, monkeypatch, alert_spy, ago):
    # INFO_PUSH_ONLINE defaults to on: a watched device coming back pushes.
    mac = "aa:bb:cc:dd:ee:12"
    _seed_back_online(db, make, monkeypatch, ago, mac, "192.168.10.62")
    watcher.check_watched(db, {})
    back = [c for c in alert_spy.calls if c["kind"] == "online"]
    assert len(back) == 1
    assert back[0]["force_push"] is True
    assert db.execute("SELECT state FROM watch_state WHERE mac=?", (mac,)).fetchone()["state"] == "up"


def test_back_online_dashboard_only_when_push_off(db, make, monkeypatch, alert_spy, ago, set_setting):
    # Push turned off: still written (dashboard), but not pushed.
    set_setting("INFO_PUSH_ONLINE", "off")
    _seed_back_online(db, make, monkeypatch, ago, "aa:bb:cc:dd:ee:13", "192.168.10.63")
    watcher.check_watched(db, {})
    back = [c for c in alert_spy.calls if c["kind"] == "online"]
    assert len(back) == 1
    assert back[0]["push"] is False and back[0]["force_push"] is False


# ───────────────────────── gateway impersonation ─────────────────────────

def test_gateway_impersonation_alert_and_once_a_day(db, make, monkeypatch, alert_spy, ago, set_memory):
    gw_ip, gw_mac, attacker = "192.168.10.1", "aa:bb:cc:00:00:01", "bb:bb:bb:00:00:02"
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    common.kv_set(db, "gateway_mac", gw_mac)
    db.commit()
    make.observation("arp", mac=attacker, ip=gw_ip, last_seen=common.now_iso())
    state = {"gw_ip": gw_ip}

    watcher.check_gateway(db, state)
    assert _n(db, "gateway") == 1
    assert any(c["kind"] == "gateway" and c["severity"] == "alert" for c in alert_spy.calls)

    # Same day: deduped (repeat=True, once a day).
    watcher.check_gateway(db, state)
    assert _n(db, "gateway") == 1

    # Two days later: alerts again.
    set_memory(f"gateway:{attacker}", ago(days=2))
    watcher.check_gateway(db, state)
    assert _n(db, "gateway") == 2


def test_gateway_own_mac_no_alert(db, make, monkeypatch, alert_spy):
    gw_ip, gw_mac = "192.168.10.1", "aa:bb:cc:00:00:01"
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    common.kv_set(db, "gateway_mac", gw_mac)
    db.commit()
    make.observation("arp", mac=gw_mac, ip=gw_ip, last_seen=common.now_iso())
    watcher.check_gateway(db, {"gw_ip": gw_ip})
    assert _n(db, "gateway") == 0


# ───────────────────────── second DHCP server ─────────────────────────

def test_second_dhcp_server_alert(db, make, monkeypatch, alert_spy):
    gw_ip, gw_mac, rogue = "192.168.10.1", "aa:bb:cc:00:00:01", "cc:cc:cc:00:00:03"
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    common.kv_set(db, "gateway_mac", gw_mac)
    db.commit()
    make.observation("dhcp_server", mac=rogue, ip="192.168.10.9", last_seen=common.now_iso())
    watcher.check_gateway(db, {"gw_ip": gw_ip})
    assert _n(db, "dhcp") == 1
    assert any(c["kind"] == "dhcp" and c["severity"] == "alert" for c in alert_spy.calls)


def test_second_dhcp_server_allowlisted(db, make, monkeypatch, alert_spy, set_setting):
    gw_ip, gw_mac, ok = "192.168.10.1", "aa:bb:cc:00:00:01", "cc:cc:cc:00:00:04"
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    common.kv_set(db, "gateway_mac", gw_mac)
    db.commit()
    set_setting("DHCP_SERVERS_OK", ok)
    make.observation("dhcp_server", mac=ok, ip="192.168.10.9", last_seen=common.now_iso())
    watcher.check_gateway(db, {"gw_ip": gw_ip})
    assert _n(db, "dhcp") == 0


# ───────────────────────── network-scan / scanner detection ─────────────────────────

def _seed_scan(make, mac, n=50, when=None):
    when = when or common.now_iso()
    for i in range(n):
        make.observation("arp_req", mac=mac, ip=f"192.168.10.{i + 1}", last_seen=when)


def test_scanner_unnamed_warns_and_pushes(db, make, monkeypatch, alert_spy):
    mac = "dd:dd:dd:00:00:05"
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    _seed_scan(make, mac, 50)
    watcher.check_scanners(db, {})
    assert _n(db, "scanning") == 1
    c = next(c for c in alert_spy.calls if c["kind"] == "scanning")
    assert c["severity"] == "warning" and c["push"] is True


def test_scanner_named_is_info_no_push(db, make, monkeypatch, alert_spy):
    mac = "dd:dd:dd:00:00:06"
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    _label(db, mac, "My laptop")
    _seed_scan(make, mac, 50)
    watcher.check_scanners(db, {})
    c = next(c for c in alert_spy.calls if c["kind"] == "scanning")
    assert c["severity"] == "info" and c["push"] is False


def test_scanner_named_push_when_enabled(db, make, monkeypatch, alert_spy, set_setting):
    # A named device's info scan alert still shows on the dashboard; turning Push on also pushes it.
    set_setting("INFO_PUSH_SCANNING", "on")
    mac = "dd:dd:dd:00:00:09"
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    _label(db, mac, "My laptop")
    _seed_scan(make, mac, 50)
    watcher.check_scanners(db, {})
    c = next(c for c in alert_spy.calls if c["kind"] == "scanning")
    assert c["severity"] == "info" and c["push"] is True and c["force_push"] is True


def test_scanner_allowlisted(db, make, monkeypatch, alert_spy, set_setting):
    mac = "dd:dd:dd:00:00:07"
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    set_setting("SCANNERS_OK", mac)
    _seed_scan(make, mac, 50)
    watcher.check_scanners(db, {})
    assert _n(db, "scanning") == 0


def test_scanner_below_threshold(db, make, monkeypatch, alert_spy):
    mac = "dd:dd:dd:00:00:08"
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    _seed_scan(make, mac, 40)          # under SCAN_TARGETS = 50
    watcher.check_scanners(db, {})
    assert _n(db, "scanning") == 0


def test_scanner_silent_while_learning(db, make, monkeypatch, alert_spy):
    mac = "dd:dd:dd:00:00:09"
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    common.kv_set(db, "learning_until", (__import__("datetime").datetime.now()
                                         + __import__("datetime").timedelta(hours=1)).isoformat(timespec="seconds"))
    db.commit()
    _seed_scan(make, mac, 50)
    watcher.check_scanners(db, {})
    assert _n(db, "scanning") == 0


# ───────────────────────── rogue IPv6 router advertisement ─────────────────────────

def test_rogue_ra_alerts(db, make, monkeypatch, alert_spy):
    gw_mac, rogue = "aa:bb:cc:00:00:01", "ee:ee:ee:00:00:0a"
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    common.kv_set(db, "gateway_mac", gw_mac)
    db.commit()
    make.observation("ra", mac=rogue, ip="fe80::1", details={"router_lifetime": 1800},
                     last_seen=common.now_iso())
    watcher.check_ipv6_routers(db, {})
    assert _n(db, "ipv6_router") == 1
    assert any(c["kind"] == "ipv6_router" and c["severity"] == "alert" for c in alert_spy.calls)


def test_ra_lifetime_zero_never_alerts(db, make, monkeypatch, alert_spy):
    gw_mac, rogue = "aa:bb:cc:00:00:01", "ee:ee:ee:00:00:0b"
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    common.kv_set(db, "gateway_mac", gw_mac)
    db.commit()
    make.observation("ra", mac=rogue, ip="fe80::2", details={"router_lifetime": 0},
                     last_seen=common.now_iso())
    watcher.check_ipv6_routers(db, {})
    assert _n(db, "ipv6_router") == 0


def test_ra_from_the_router_itself_ignored(db, make, monkeypatch, alert_spy):
    gw_mac = "aa:bb:cc:00:00:01"
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    common.kv_set(db, "gateway_mac", gw_mac)
    db.commit()
    make.observation("ra", mac=gw_mac, ip="fe80::3", details={"router_lifetime": 1800},
                     last_seen=common.now_iso())
    watcher.check_ipv6_routers(db, {})
    assert _n(db, "ipv6_router") == 0


def test_ra_no_baseline_no_alert(db, make, monkeypatch, alert_spy):
    """No gateway baseline yet -> check_ipv6_routers does nothing."""
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    make.observation("ra", mac="ee:ee:ee:00:00:0c", ip="fe80::4",
                     details={"router_lifetime": 1800}, last_seen=common.now_iso())
    watcher.check_ipv6_routers(db, {})
    assert _n(db, "ipv6_router") == 0


# ───────────────────────── own machine: don't alert on LanWard's own dashboard port ─────────────────────────

def _baseline_own(db, mac, hours_ago=2):
    """Pre-seed port_checks so a later read counts as past the baseline grace (new ports can be reported)."""
    old = common.iso_ago(hours=hours_ago)
    db.execute("INSERT INTO port_checks (mac, full_checked_at, full_tried_at, first_full_at) VALUES (?,?,?,?)",
               (mac, old, old, old))
    db.commit()


def test_own_dashboard_port_not_alerted(db, monkeypatch, alert_spy):
    """LanWard's own machine opening its dashboard port (8080) is itself, not a surprise -> no alert,
    but a genuinely new port alongside it still is."""
    mac = "aa:bb:cc:00:00:aa"
    _baseline_own(db, mac)
    monkeypatch.setattr(common, "own_listening_ports", lambda: [22, 8080])
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: mac)
    monkeypatch.setattr(common, "own_ip", lambda *a, **k: "192.168.10.250")
    monkeypatch.setattr(watcher, "device_name", lambda conn, m: "Mini PC")
    watcher.check_own_ports(db, {})
    assert len(alert_spy.calls) == 1
    assert "22" in alert_spy.calls[0]["details"]
    assert "8080" not in alert_spy.calls[0]["details"]


def test_own_dashboard_port_alone_is_silent(db, monkeypatch, alert_spy):
    mac = "aa:bb:cc:00:00:ab"
    _baseline_own(db, mac)
    monkeypatch.setattr(common, "own_listening_ports", lambda: [8080])
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: mac)
    monkeypatch.setattr(common, "own_ip", lambda *a, **k: "192.168.10.250")
    monkeypatch.setattr(watcher, "device_name", lambda conn, m: "Mini PC")
    watcher.check_own_ports(db, {})
    assert alert_spy.calls == []
