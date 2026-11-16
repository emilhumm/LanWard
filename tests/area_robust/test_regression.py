"""Area F — the regression list (FRAMEWORK.md).

One focused test per bug fixed this cycle, concentrating on the ones other areas won't obviously
own: CISA KEV cache poisoning, settings hidden-tab fields still submit, _saved_override reads a
page-set IFACE/SUBNET, and the carried-findings dedup on ports-unscanned hosts.
"""
import json

import common
import supportcheck


# ───────────────────── CISA KEV cache poisoning ─────────────────────

class _FakeResp:
    def __init__(self, body, headers=None):
        self._body = body
        self.headers = headers or {}

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _point_kev_at(tmp_path, monkeypatch):
    feed_dir = tmp_path / "feeds"
    feed_dir.mkdir()
    kev_file = feed_dir / "cisa_kev.json"
    monkeypatch.setattr(supportcheck, "FEED_DIR", feed_dir)
    monkeypatch.setattr(supportcheck, "KEV_FILE", kev_file)
    return kev_file


GOOD_KEV = {"title": "CISA KEV", "vulnerabilities": [
    {"vendorProject": "ASUS", "product": "RT-AC68U", "cveID": "CVE-2024-0001",
     "dateAdded": "2024-01-01", "knownRansomwareCampaignUse": "Known"}]}


def test_kev_non_json_200_keeps_good_copy(db, tmp_path, monkeypatch):
    """A 200 whose body is not the KEV catalogue (captcha / maintenance page) must NOT overwrite the
    last good file. Regression: a non-JSON 200 used to poison the cache."""
    kev_file = _point_kev_at(tmp_path, monkeypatch)
    kev_file.write_text(json.dumps(GOOD_KEV), encoding="utf-8")
    # make the cached copy look stale so refresh_kev actually attempts a download
    common.kv_set(db, "kev_fetched_at", common.iso_ago(days=2))
    db.commit()
    monkeypatch.setattr(supportcheck.urllib.request, "urlopen",
                        lambda *a, **k: _FakeResp(b"<html>maintenance in progress</html>"))

    assert supportcheck.refresh_kev(db) is True          # a usable copy is still present
    assert json.loads(kev_file.read_text(encoding="utf-8")) == GOOD_KEV
    hits = supportcheck.kev_hits(
        next(p for p in supportcheck.PRODUCTS if p["key"] == "asus-rt-ac68u"),
        supportcheck.load_kev())
    assert len(hits) == 1                                 # the good list still matches


def test_kev_json_that_is_not_the_catalogue_is_rejected(db, tmp_path, monkeypatch):
    """Valid JSON but the wrong shape (a list, or a dict without 'vulnerabilities') is also refused."""
    kev_file = _point_kev_at(tmp_path, monkeypatch)
    kev_file.write_text(json.dumps(GOOD_KEV), encoding="utf-8")
    common.kv_set(db, "kev_fetched_at", common.iso_ago(days=2))
    db.commit()
    monkeypatch.setattr(supportcheck.urllib.request, "urlopen",
                        lambda *a, **k: _FakeResp(json.dumps([1, 2, 3]).encode()))
    assert supportcheck.refresh_kev(db) is True
    assert json.loads(kev_file.read_text(encoding="utf-8")) == GOOD_KEV


def test_kev_valid_new_catalogue_is_written(db, tmp_path, monkeypatch):
    """Control: a genuine new catalogue IS written (so the guard isn't rejecting everything)."""
    kev_file = _point_kev_at(tmp_path, monkeypatch)
    new = {"vulnerabilities": [{"vendorProject": "Acme", "product": "Widget", "cveID": "CVE-9"}]}
    monkeypatch.setattr(supportcheck.urllib.request, "urlopen",
                        lambda *a, **k: _FakeResp(json.dumps(new).encode()))
    assert supportcheck.refresh_kev(db) is True
    assert json.loads(kev_file.read_text(encoding="utf-8")) == new


# ───────────────────── settings sub-tabs: hidden-section fields still submit ─────────────────────

def test_hidden_tab_field_still_saves(post, db):
    """A field whose tab isn't the active one (e.g. the MAC allow-lists) must still be read from the
    POST and saved. Regression: a hidden section used to be dropped. Server-side, _read_settings_form
    processes every field present, so a valid POST that carries dhcp_ok/scanners_ok persists them."""
    form = {
        "severity": "warning", "retain_days": "365", "backup_days": "14",
        "offline_minutes": "10", "full_days": "1", "status_allow": "127.0.0.1",
        "scan_hour": ["0", "6", "12", "18"], "support_check": "on", "auto_logout": "0",
        "dhcp_ok": "aa:bb:cc:dd:ee:ff",            # lives on a different sub-tab than the one shown
        "scanners_ok": "11:22:33:44:55:66",
    }
    resp = post("/settings", data=form)
    assert resp.status_code in (302, 303)
    assert common.kv_get(db, "setting:DHCP_SERVERS_OK") == "aa:bb:cc:dd:ee:ff"
    assert common.kv_get(db, "setting:SCANNERS_OK") == "11:22:33:44:55:66"


def test_support_check_checkbox_in_hidden_tab_turns_off(post, db):
    """The SUPPORT_CHECK checkbox (a hidden-tab control) submits: its absence means 'off', not
    'unchanged'. Default is on, so omitting it must persist 'off'."""
    form = {
        "severity": "warning", "retain_days": "365", "backup_days": "14",
        "offline_minutes": "10", "full_days": "1", "status_allow": "127.0.0.1",
        "scan_hour": ["0"], "auto_logout": "0",   # no support_check key -> off
    }
    resp = post("/settings", data=form)
    assert resp.status_code in (302, 303)
    assert common.kv_get(db, "setting:SUPPORT_CHECK") == "off"


# ───────────────────── _saved_override reads a page-set IFACE/SUBNET ─────────────────────

def test_saved_override_reads_page_value(db):
    """A value saved on the Settings page (kv setting:IFACE/SUBNET) is read at startup by
    _saved_override, straight from the file (read-only), ahead of .env. Regression: it used to be
    ignored at boot."""
    common.kv_set(db, "setting:IFACE", "eno1")
    common.kv_set(db, "setting:SUBNET", "192.168.10.0/24")
    db.commit()
    assert common._saved_override("IFACE") == "eno1"
    assert common._saved_override("SUBNET") == "192.168.10.0/24"


def test_saved_override_blank_and_missing(db):
    """Blank / whitespace-only / missing -> None, so the next source (.env, auto-detect) wins."""
    common.kv_set(db, "setting:IFACE", "   ")
    db.commit()
    assert common._saved_override("IFACE") is None
    assert common._saved_override("NOPE") is None


def test_saved_override_no_db_file(data_dir):
    """No scanner.db yet -> None, not a crash (fresh install before migrate)."""
    assert not common.DB_PATH.exists()
    assert common._saved_override("IFACE") is None


# ───────────────────── carried-findings dedup on ports-unscanned hosts ─────────────────────

def test_carried_findings_no_duplicate_eol(db, make, monkeypatch):
    """A host whose open_ports is NULL (nmap didn't finish) carries its last scan's findings forward.
    If those already include an eol finding, the support pass must NOT add a second copy of the same
    id. Regression: duplicate eol/kev findings on carried-forward hosts."""
    import homechecks

    monkeypatch.setattr("common.default_gateway", lambda: None)
    mac = "aa:bb:cc:dd:ee:ff"
    eol = {"id": "eol:samsung-tab-s5e", "severity": "info",
           "title": "No more security updates: Samsung Galaxy Tab S5e", "detail": "..."}

    # scan 1: ports fully checked ([] = none open), and it already carries the eol finding
    s1 = make.scan()
    make.host(s1, ip="192.168.10.9", mac=mac, hostname="galaxy-tab-s5e",
              open_ports="[]", findings=json.dumps([eol]))
    # scan 2 (newer): nmap did not finish -> open_ports NULL; homechecks carries s1's findings forward
    s2 = make.scan()
    make.host(s2, ip="192.168.10.9", mac=mac, hostname="galaxy-tab-s5e", open_ports=None)

    homechecks.run(s2)

    row = db.execute("SELECT findings FROM hosts WHERE scan_id=? AND ip='192.168.10.9'", (s2,)).fetchone()
    found = json.loads(row[0]) if row[0] else []
    eol_ids = [f for f in found if f.get("id") == "eol:samsung-tab-s5e"]
    assert len(eol_ids) == 1, f"expected one eol finding, got {len(eol_ids)}: {found}"
    # and it is marked as carried forward from scan 1
    assert eol_ids[0].get("from_scan") == s1
