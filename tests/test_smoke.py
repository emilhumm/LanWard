"""Smoke tests: prove the harness works end to end, and lock in a few bugs fixed this cycle.
A senior-engineer seed the team extends; see tests/FRAMEWORK.md.
"""
import common
import supportcheck


# ── harness sanity ──

def test_db_fixture_is_migrated(db):
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"scans", "hosts", "observations", "alerts", "host_labels", "kv"} <= tables


def test_factories_and_settings(db, make):
    sid = make.scan()
    make.host(sid, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:ff", vendor="Acme")
    assert db.execute("SELECT COUNT(*) FROM hosts WHERE scan_id=?", (sid,)).fetchone()[0] == 1
    make.kv("setting:SUPPORT_CHECK", "off")
    assert common.setting_on("SUPPORT_CHECK") is False


# ── regression: mdns model must not become the platform word (today's bug) ──

def test_mdns_model_skips_platform_word():
    assert common.mdns_txt_model({"md": "WEBOS", "model": "OLED65C9PLA"}) == "OLED65C9PLA"
    assert common.mdns_txt_model({"md": "Hue bridge"}) == "Hue bridge"   # real model in md kept
    assert common.mdns_txt_model("not-a-dict") is None


# ── regression: Tapo KEV matcher must not match TP-Link Archer routers ──

def test_tapo_kev_matcher_is_specific():
    tapo = next(p for p in supportcheck.PRODUCTS if p["key"] == "tplink-tapo-cam")
    archer = [{"vendor": "tp-link", "product": "archer c2300", "cve": "CVE-X", "ransomware": False}]
    real = [{"vendor": "tp-link", "product": "tapo c210", "cve": "CVE-Y", "ransomware": False}]
    assert supportcheck.kev_hits(tapo, archer) == []
    assert len(supportcheck.kev_hits(tapo, real)) == 1


# ── harness: the dashboard renders on an empty DB ──

def test_overview_renders_empty(client):
    assert client.get("/").status_code == 200
