"""AREA E - alerts.py: scan-based alerts, grouping, is_new dedupe, the push flag."""
import json

import pytest

import alerts
import common


def _n_alerts(db, kind=None):
    if kind:
        return db.execute("SELECT COUNT(*) FROM alerts WHERE kind = ?", (kind,)).fetchone()[0]
    return db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]


# ───────────────────────── check_findings: grouping ─────────────────────────

def test_findings_group_into_one_alert(db, host, alert_spy):
    hosts = [host(mac="aa:bb:cc:00:00:01", ip="192.168.10.11",
                  findings=[{"id": "telnet", "severity": "warning", "title": "Telnet is open"}]),
             host(mac="aa:bb:cc:00:00:02", ip="192.168.10.12",
                  findings=[{"id": "http-admin", "severity": "info", "title": "Admin page without login"}])]
    assert alerts.check_findings(db, 7, hosts) == 1
    assert _n_alerts(db, "finding") == 1
    c = alert_spy.calls[0]
    assert c["severity"] == "warning"           # worst of warning + info
    assert c["title"] == "2 new security findings"
    assert "Telnet is open" in c["details"] and "Admin page without login" in c["details"]


def test_findings_push_only_when_warning_or_worse(db, host, alert_spy):
    # info-only group: no push
    hosts = [host(findings=[{"id": "x", "severity": "info", "title": "Just a note"}])]
    alerts.check_findings(db, 1, hosts)
    assert alert_spy.calls[-1]["push"] is False
    # a warning in the group: push on
    hosts = [host(mac="aa:bb:cc:00:00:09", ip="192.168.10.19",
                  findings=[{"id": "y", "severity": "warning", "title": "Weak thing"}])]
    alerts.check_findings(db, 2, hosts)
    assert alert_spy.calls[-1]["push"] is True


def test_findings_single_uses_device_title(db, host, alert_spy):
    db.execute("INSERT INTO host_labels (mac, label, note, watch_offline, created_at, updated_at) "
               "VALUES (?,?,?,?,?,?)", ("aa:bb:cc:00:00:01", "Front camera", "", 0,
                                       common.now_iso(), common.now_iso()))
    db.commit()
    hosts = [host(mac="aa:bb:cc:00:00:01", ip="192.168.10.11",
                  findings=[{"id": "telnet", "severity": "warning", "title": "Telnet is open"}])]
    alerts.check_findings(db, 1, hosts)
    assert alert_spy.calls[0]["title"] == "Front camera: Telnet is open"


# ───────────────────────── check_findings: is_new dedupe ─────────────────────────

def test_findings_dedupe_same_finding_once(db, host, alert_spy, ago, set_memory):
    h = host(findings=[{"id": "telnet", "severity": "warning", "title": "Telnet is open"}])
    assert alerts.check_findings(db, 1, [h]) == 1
    # Same finding, next scan: already in alert_memory -> no new alert.
    assert alerts.check_findings(db, 2, [h]) == 0
    assert _n_alerts(db, "finding") == 1


def test_findings_realert_after_30_days(db, host, alert_spy, ago, set_memory):
    h = host(mac="aa:bb:cc:00:00:03", ip="192.168.10.13",
             findings=[{"id": "telnet", "severity": "warning", "title": "Telnet is open"}])
    assert alerts.check_findings(db, 1, [h]) == 1
    # Pretend the condition last alerted 31 days ago: it is "new" again.
    set_memory("finding:aa:bb:cc:00:00:03:telnet", ago(days=31))
    assert alerts.check_findings(db, 2, [h]) == 1
    assert _n_alerts(db, "finding") == 2


def test_findings_bridge_dedupe(db, host, alert_spy, ago, set_memory):
    """A finding alerted under the SonosNet bridge's MAC in the last 30 days is not new now that the
    speaker has its own MAC (_seen_at_bridge)."""
    set_memory("finding:bridge-mac:telnet", ago(days=2))
    h = host(mac="speaker-mac", bridge_mac="bridge-mac",
             findings=[{"id": "telnet", "severity": "warning", "title": "Telnet is open"}])
    assert alerts.check_findings(db, 1, [h]) == 0
    assert _n_alerts(db, "finding") == 0


def test_findings_none_returns_zero(db, host, alert_spy):
    assert alerts.check_findings(db, 1, [host(findings=[])]) == 0
    assert alert_spy.calls == []


# ───────────────────────── check_new_ports ─────────────────────────

def test_new_ports_one_alert_per_device(db, host, alert_spy):
    h = host(mac="aa:bb:cc:00:00:05", ip="192.168.10.15", new_ports=[22, 8080],
             web_info={"8080": {"title": "Router admin"}})
    assert alerts.check_new_ports(db, 1, [h]) == 1
    c = alert_spy.calls[0]
    assert c["kind"] == "new_port"
    assert "8080" in c["details"] and "Router admin" in c["details"]
    assert c["severity"] == "warning"           # 22 is below the ephemeral range


def test_new_ports_ephemeral_only_is_info(db, host, alert_spy):
    h = host(mac="aa:bb:cc:00:00:06", ip="192.168.10.16", new_ports=[55000])
    alerts.check_new_ports(db, 1, [h])
    assert alert_spy.calls[0]["severity"] == "info"


def test_new_ports_none(db, host, alert_spy):
    assert alerts.check_new_ports(db, 1, [host(new_ports=[])]) == 0


def test_new_ports_names_known_service(db, host, alert_spy):
    """A recognised port is named in plain words next to its number (7000 -> AirPlay)."""
    alerts.check_new_ports(db, 1, [host(mac="aa:bb:cc:00:00:07", ip="192.168.10.17", new_ports=[7000, 80])])
    details = alert_spy.calls[0]["details"]
    assert "7000: probably AirPlay" in details
    assert "80: probably web" in details


def test_new_ports_ephemeral_reads_calm(db, host, alert_spy):
    """All-ephemeral (info) ports get the 'almost always nothing' explanation, not the old scary line."""
    alerts.check_new_ports(db, 1, [host(mac="aa:bb:cc:00:00:08", ip="192.168.10.18", new_ports=[55000, 62078])])
    c = alert_spy.calls[0]
    assert c["severity"] == "info"
    assert "almost always nothing" in c["details"]
    assert "62078: probably iPhone Wi-Fi sync" in c["details"]
    assert "have a look at what it is" not in c["details"]      # the old wording is gone


def test_new_ports_service_reads_as_wake(db, host, alert_spy):
    """A service port (below the ephemeral range) gets the 'wakes up / you used a feature' explanation."""
    alerts.check_new_ports(db, 1, [host(mac="aa:bb:cc:00:00:09", ip="192.168.10.19", new_ports=[7000])])
    c = alert_spy.calls[0]
    assert c["severity"] == "warning"
    assert "wake up" in c["details"] or "wakes up" in c["details"]


# ───────────────────────── check_tls_changes ─────────────────────────

def _web(port, fp, cn="dev.local", not_after="2027-01-01"):
    return {str(port): {"cert": {"fingerprint": fp, "cn": cn, "not_after": not_after}}}


def test_tls_change_fires_once(db, host, alert_spy):
    history = [host(mac="aa:bb:cc:00:00:07", ip="192.168.10.17", web_info=_web(443, "OLDFP"))]
    cur = [host(mac="aa:bb:cc:00:00:07", ip="192.168.10.17", web_info=_web(443, "NEWFP"))]
    assert alerts.check_tls_changes(db, 2, 1, cur, history) == 1
    assert alert_spy.calls[0]["severity"] == "warning"
    assert alert_spy.calls[0]["kind"] == "tls"
    # Same new fingerprint again -> deduped.
    assert alerts.check_tls_changes(db, 3, 2, cur, history) == 0


def test_tls_no_change_when_fingerprint_same(db, host, alert_spy):
    history = [host(mac="m", ip="192.168.10.17", web_info=_web(443, "SAME"))]
    cur = [host(mac="m", ip="192.168.10.17", web_info=_web(443, "SAME"))]
    assert alerts.check_tls_changes(db, 2, 1, cur, history) == 0


def test_tls_new_port_is_not_a_change(db, host, alert_spy):
    """A second port with its own cert must not look 'replaced' (keyed per port)."""
    history = [host(mac="m", ip="192.168.10.17", web_info=_web(443, "A"))]
    cur = [host(mac="m", ip="192.168.10.17",
                web_info={**_web(443, "A"), **_web(8443, "B")})]
    assert alerts.check_tls_changes(db, 2, 1, cur, history) == 0


# ───────────────────────── check_firmware ─────────────────────────

def test_firmware_change_info_no_push(db, host, alert_spy):
    history = [host(mac="aa:bb:cc:00:00:08", firmware="1.0.0")]
    cur = [host(mac="aa:bb:cc:00:00:08", firmware="1.1.0")]
    assert alerts.check_firmware(db, 2, 1, cur, history) == 1
    c = alert_spy.calls[0]
    assert c["severity"] == "info"
    assert c["push"] is False
    assert "1.0.0 -> 1.1.0" in c["details"]


def test_firmware_same_version_no_alert(db, host, alert_spy):
    history = [host(mac="m", firmware="1.0.0")]
    cur = [host(mac="m", firmware="1.0.0")]
    assert alerts.check_firmware(db, 2, 1, cur, history) == 0


def test_firmware_push_when_enabled(db, host, alert_spy, set_setting):
    set_setting("INFO_PUSH_FIRMWARE", "on")
    history = [host(mac="aa:bb:cc:00:00:0a", firmware="1.0.0")]
    cur = [host(mac="aa:bb:cc:00:00:0a", firmware="1.1.0")]
    alerts.check_firmware(db, 2, 1, cur, history)
    c = next(c for c in alert_spy.calls if c["kind"] == "firmware")
    assert c["push"] is True and c["force_push"] is True


# ───────────────────────── ghost targets ─────────────────────────

def test_ghost_targets_blocked_without_subnet(db, make):
    """No SUBNET -> ghost_targets returns {} (fresh install, nothing to compare against)."""
    assert common.SUBNET == "" or common.SUBNET  # just read it
    # Force empty subnet regardless of the host machine's real config.
    import common as _c
    old = _c.SUBNET
    try:
        _c.SUBNET = ""
        assert alerts.ghost_targets(db) == {}
    finally:
        _c.SUBNET = old


def _count_day(db, source, mac, ip, day, n):
    db.execute("INSERT INTO observation_counts (source, mac, ip, day, n) VALUES (?,?,?,?,?)",
               (source, mac, ip, day, n))
    db.commit()


def _ask_hour(db, mac, ip, hours_ago, n):
    """Seed arp_ask_hours: `n` ARP asks for `ip` by `mac` in the hour `hours_ago` hours back."""
    db.execute("INSERT INTO arp_ask_hours (mac, ip, hour, n) VALUES (?,?,?,?)",
               (mac, ip, common.iso_ago(hours=hours_ago)[:13], n))
    db.commit()


def test_ghost_targets_flags_unclaimed_address(db, make, monkeypatch, alert_spy, ago):
    monkeypatch.setattr(common, "SUBNET", "192.168.10.0/24")
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    # An asker still ARP-ing for .240 every hour of the last 24 (12 an hour, a lookup every ~15 min); nobody ever
    # used .240.
    make.observation("arp_req", mac="de:ad:be:ef:00:01", ip="192.168.10.240",
                     details={"own_ip": "192.168.10.30"},
                     first_seen=ago(days=10), last_seen=ago(hours=1), count=600)
    for h in range(1, 25):
        _ask_hour(db, "de:ad:be:ef:00:01", "192.168.10.240", h, 12)
    g = alerts.ghost_targets(db)
    assert "192.168.10.240" in g
    assert g["192.168.10.240"]["total"] == 288      # asks in the last 24h, not the lifetime count
    assert alerts.check_ghost_targets(db, 1) == 1
    assert alert_spy.calls[0]["kind"] == "ghost"
    assert alert_spy.calls[0]["push"] is False


def test_ghost_targets_ignores_claimed_address(db, make, monkeypatch, ago):
    monkeypatch.setattr(common, "SUBNET", "192.168.10.0/24")
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    # .241 is both asked for AND used by a device (its own DHCP address) -> not a ghost.
    make.observation("arp_req", mac="de:ad:be:ef:00:02", ip="192.168.10.241",
                     details={"own_ip": "192.168.10.31"},
                     first_seen=ago(days=10), last_seen=ago(hours=1), count=60)
    make.observation("dhcp", mac="11:22:33:44:55:66", ip="192.168.10.241",
                     first_seen=ago(days=1), last_seen=ago(hours=2), count=1)
    assert "192.168.10.241" not in alerts.ghost_targets(db)


def test_ghost_targets_needs_a_week_of_listening(db, make, monkeypatch, ago):
    monkeypatch.setattr(common, "SUBNET", "192.168.10.0/24")
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    # Only 2 days of history -> the "nobody used it for a week" claim can't be made yet.
    make.observation("arp_req", mac="de:ad:be:ef:00:03", ip="192.168.10.242",
                     details={"own_ip": "192.168.10.32"},
                     first_seen=ago(days=2), last_seen=ago(hours=1), count=60)
    assert alerts.ghost_targets(db) == {}


def test_ghost_rate_uses_recent_not_lifetime(db, make, monkeypatch, ago):
    """The reported rate is the RECENT 24h ask rate (arp_ask_hours), not the lifetime average."""
    monkeypatch.setattr(common, "SUBNET", "192.168.10.0/24")
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    # A million asks over 90 days (lifetime avg ~11,000/day), but only 200 in the last 24h (10 an hour for 20 hours).
    make.observation("arp_req", mac="de:ad:be:ef:00:04", ip="192.168.10.243",
                     details={"own_ip": "192.168.10.50"},
                     first_seen=ago(days=90), last_seen=ago(hours=1), count=1_000_000)
    for h in range(1, 21):
        _ask_hour(db, "de:ad:be:ef:00:04", "192.168.10.243", h, 10)
    g = alerts.ghost_targets(db)
    assert "192.168.10.243" in g
    assert g["192.168.10.243"]["per_day"] == 200     # asks in the last 24h, NOT the lifetime ~11,000/day


def test_ghost_ignores_an_hourly_is_it_on_check(db, make, monkeypatch, ago):
    """Home Assistant pinging a PC that is off once an hour to see whether it is on (2026-11-01, .215): each
    unanswered lookup goes out 3 times, 72 asks a day, plus a burst each time HA restarts. Not a ghost."""
    monkeypatch.setattr(common, "SUBNET", "192.168.10.0/24")
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    make.observation("arp_req", mac="de:ad:be:ef:00:06", ip="192.168.10.245",
                     details={"own_ip": "192.168.10.88"},
                     first_seen=ago(days=90), last_seen=ago(hours=1), count=10_000_000)
    for h in range(1, 24):
        _ask_hour(db, "de:ad:be:ef:00:06", "192.168.10.245", h, 48 if h in (2, 14) else 3)  # HA restarting twice
    assert "192.168.10.245" not in alerts.ghost_targets(db)


def test_ghost_flags_a_heavy_poller_even_for_part_of_the_day(db, make, monkeypatch, ago):
    """A poller hammering a dead address for 8 hours (2,000 asks an hour) is a ghost, and the rate shown is the
    real count, not the burst-capped one used for the test."""
    monkeypatch.setattr(common, "SUBNET", "192.168.10.0/24")
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    make.observation("arp_req", mac="de:ad:be:ef:00:07", ip="192.168.10.246",
                     details={"own_ip": "192.168.10.88"},
                     first_seen=ago(days=30), last_seen=ago(hours=1), count=500_000)
    for h in range(1, 9):
        _ask_hour(db, "de:ad:be:ef:00:07", "192.168.10.246", h, 2000)
    g = alerts.ghost_targets(db)
    assert g["192.168.10.246"]["per_day"] == 16_000


def test_ghost_drops_off_when_asking_stops(db, make, monkeypatch, ago):
    """A poller that has essentially stopped (almost nothing in the last 24h) is not a ghost."""
    monkeypatch.setattr(common, "SUBNET", "192.168.10.0/24")
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: None)
    # Still within the 24h last_seen gate, but only a couple of asks in the last 24h.
    make.observation("arp_req", mac="de:ad:be:ef:00:05", ip="192.168.10.244",
                     details={"own_ip": "192.168.10.51"},
                     first_seen=ago(days=90), last_seen=ago(hours=2), count=500_000)
    _ask_hour(db, "de:ad:be:ef:00:05", "192.168.10.244", 1, 2)
    assert "192.168.10.244" not in alerts.ghost_targets(db)


# ───────────────────────── compute_alerts end to end ─────────────────────────

def test_compute_alerts_end_to_end(db, make, alert_spy):
    sid = make.scan(notes="lanward home v2")
    make.host(sid, ip="192.168.10.21", mac="aa:bb:cc:00:00:21",
              findings=json.dumps([{"id": "telnet", "severity": "warning", "title": "Telnet is open"}]))
    n = alerts.compute_alerts(sid)
    assert n >= 1
    assert db.execute("SELECT COUNT(*) FROM alerts WHERE kind='finding'").fetchone()[0] == 1


def test_compute_alerts_no_scan(db, alert_spy):
    assert alerts.compute_alerts(99999) == 0
