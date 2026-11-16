"""Area A — supportcheck.py: device identification, CISA KEV cache, EOL / KEV findings, lazy KEV load.

Network fully mocked: refresh_kev's urllib.request.urlopen is replaced; the Support-lazy tests replace
refresh_kev itself. KEV_FILE / FEED_DIR are redirected to a tmp dir so nothing touches the real feed dir.
"""
import json
import urllib.error

import pytest

import common
import supportcheck


# ─────────────────────────── host-dict helper ───────────────────────────

def host(**over):
    """A minimal hosts-row-shaped dict; _signals reads exactly these keys plus mac."""
    base = {"mac": "aa:bb:cc:dd:ee:ff", "vendor": "", "hostname": "", "http_server": "",
            "http_title": "", "firmware": "", "mdns_services": "", "upnp_info": ""}
    base.update(over)
    return base


def prod(key):
    return next(p for p in supportcheck.PRODUCTS if p["key"] == key)


# ─────────────────────────── identify / _matches / _signals ───────────────────────────

def test_identify_asus():
    assert supportcheck.identify(host(vendor="ASUSTeK", hostname="RT-AC68U"), "")["key"] == "asus-rt-ac68u"


def test_identify_tapo_by_name_and_model():
    assert supportcheck.identify(host(vendor="TP-Link", hostname="Tapo-Camera"), "")["key"] == "tplink-tapo-cam"
    assert supportcheck.identify(host(vendor="TP-Link", hostname="IPCam C210"), "")["key"] == "tplink-tapo-cam"


def test_identify_rejects_archer_as_tapo():
    # An Archer C2300 router must NOT be identified as a Tapo camera (\bc2\d\d\b must not match c2300).
    assert supportcheck.identify(host(vendor="TP-Link", hostname="Archer-C2300"), "") is None


def test_identify_samsung_tab():
    assert supportcheck.identify(host(hostname="Galaxy-Tab-S5e"), "")["key"] == "samsung-tab-s5e"
    assert supportcheck.identify(host(hostname="SM-T720"), "")["key"] == "samsung-tab-s5e"


def test_identify_ipad():
    assert supportcheck.identify(host(hostname="J71bAP"), "")["key"] == "apple-ipad-6"
    assert supportcheck.identify(host(hostname="iPad7,5"), "")["key"] == "apple-ipad-6"


def test_identify_lg_webos():
    assert supportcheck.identify(host(vendor="LG Electronics", hostname="webOS TV"), "")["key"] == "lg-webos-tv"


def test_identify_lg_webos_vendor_word_boundary():
    # vendor r"lg\b" matches the exact "LG Innotek" OUI string + a webos signal...
    assert supportcheck.identify(host(vendor="LG Innotek", hostname="webOS TV"), "")["key"] == "lg-webos-tv"
    # ...but an unrelated "lgup" vendor is not the LG TV, even with a webos signal present.
    assert supportcheck.identify(host(vendor="lgup", hostname="webOS TV"), "") is None


def test_identify_none_for_unknown():
    assert supportcheck.identify(host(vendor="Dell", hostname="DESKTOP-ABC"), "") is None


def test_identify_uses_obs_text():
    # Nothing in the host row, but the passive blob carries the model.
    assert supportcheck.identify(host(), "random lldp tradfri galaxy-tab-s5e stuff")["key"] == "samsung-tab-s5e"


def test_matches_vendor_gate():
    # asus needs a matching vendor; the right name but wrong vendor must not match.
    assert supportcheck.identify(host(vendor="Netgear", hostname="RT-AC68U"), "") is None


def test_signals_non_string_upnp_does_not_crash():
    # regression: a non-string UPnP field used to raise TypeError and abort the whole support pass.
    h = host(vendor="TP-Link",
             upnp_info=json.dumps({"modelNumber": 12345, "modelName": {"nested": 1}, "manufacturer": None}))
    vendor, text = supportcheck._signals(h, "")
    assert vendor == "tp-link"
    assert "12345" in text          # the numeric field was stringified, not dropped with a crash


def test_signals_bad_upnp_json():
    h = host(upnp_info="{not valid json")
    vendor, text = supportcheck._signals(h, "obs blob")
    assert "obs blob" in text       # no crash, obs_text still appended


def test_signals_upnp_list_not_dict():
    h = host(upnp_info=json.dumps(["a", "b"]))
    vendor, text = supportcheck._signals(h, "")
    assert isinstance(text, str)    # a JSON list is ignored, no crash


# ─────────────────────────── kev_hits ───────────────────────────

def test_kev_hits_tapo_rejects_archer_accepts_tapo():
    tapo = prod("tplink-tapo-cam")
    archer = [{"vendor": "tp-link", "product": "archer c2300", "cve": "CVE-X", "ransomware": False}]
    real = [{"vendor": "tp-link", "product": "tapo c210", "cve": "CVE-Y", "ransomware": False}]
    assert supportcheck.kev_hits(tapo, archer) == []
    assert len(supportcheck.kev_hits(tapo, real)) == 1


def test_kev_hits_asus():
    asus = prod("asus-rt-ac68u")
    rows = [{"vendor": "asus", "product": "rt-ac68u", "cve": "CVE-1", "ransomware": False},
            {"vendor": "asus", "product": "rtac68u", "cve": "CVE-2", "ransomware": False},
            {"vendor": "asus", "product": "rt-ax88u", "cve": "CVE-3", "ransomware": False}]
    hits = supportcheck.kev_hits(asus, rows)
    assert {h["cve"] for h in hits} == {"CVE-1", "CVE-2"}


def test_kev_hits_empty_matchers():
    samsung = prod("samsung-tab-s5e")               # has no "kev" key
    assert supportcheck.kev_hits(samsung, [{"vendor": "samsung", "product": "tab", "cve": "X"}]) == []


# ─────────────────────────── eol_finding / kev_finding ───────────────────────────

def test_eol_finding_ended():
    f = supportcheck.eol_finding(prod("asus-rt-ac68u"))
    assert f["severity"] == "info"
    assert f["id"] == "eol:asus-rt-ac68u"
    assert f["title"].startswith("No more security updates:")
    assert "probably" not in f["detail"].lower()    # how == announced -> no probably note


def test_eol_finding_aged():
    f = supportcheck.eol_finding(prod("lg-webos-tv"))
    assert f["title"].startswith("Check it still gets updates:")
    assert f["severity"] == "info"


def test_eol_finding_probably_note():
    f = supportcheck.eol_finding(prod("samsung-tab-s5e"))
    assert "likely match" in f["detail"]            # how == probably


def test_eol_finding_none_when_no_eol():
    assert supportcheck.eol_finding(prod("tplink-tapo-cam")) is None


def test_kev_finding_shape_and_ransomware():
    hits = [{"cve": "CVE-2026-1", "ransomware": True},
            {"cve": "CVE-2026-2", "ransomware": False}]
    f = supportcheck.kev_finding(prod("asus-rt-ac68u"), hits)
    assert f["severity"] == "alert"
    assert f["id"] == "kev:asus-rt-ac68u"
    assert f["title"] == "Attackers are using a known flaw in ASUS RT-AC68U"
    assert "CVE-2026-1" in f["detail"] and "CVE-2026-2" in f["detail"]
    assert "2 flaws" in f["detail"]
    assert "ransomware" in f["detail"].lower()


def test_kev_finding_no_ransomware_note():
    hits = [{"cve": "CVE-2026-9", "ransomware": False}]
    f = supportcheck.kev_finding(prod("asus-rt-ac68u"), hits)
    assert "ransomware" not in f["detail"].lower()
    assert "1 flaw " in f["detail"] or "1 flaw." in f["detail"]


def test_kev_finding_probably_note():
    hits = [{"cve": "CVE-2026-3", "ransomware": False}]
    f = supportcheck.kev_finding(prod("tplink-tapo-cam"), hits)
    assert "likely match" in f["detail"]            # tapo is how == probably


# ─────────────────────────── load_kev ───────────────────────────

@pytest.fixture
def kev_file(tmp_path, monkeypatch):
    """Point supportcheck's KEV_FILE / FEED_DIR at a throwaway dir."""
    feed = tmp_path / "feeds"
    monkeypatch.setattr(supportcheck, "FEED_DIR", feed)
    monkeypatch.setattr(supportcheck, "KEV_FILE", feed / "cisa_kev.json")
    return feed / "cisa_kev.json"


VALID_KEV = {
    "vulnerabilities": [
        {"vendorProject": "ASUS", "product": "RT-AC68U", "cveID": "CVE-2026-1",
         "dateAdded": "2026-01-02", "knownRansomwareCampaignUse": "Known"},
        {"vendorProject": "TP-Link", "product": "Tapo C210", "cveID": "CVE-2026-2",
         "dateAdded": "2026-01-03", "knownRansomwareCampaignUse": "Unknown"},
    ]
}


def test_load_kev_missing_file(kev_file):
    assert supportcheck.load_kev() == []


def test_load_kev_corrupt(kev_file):
    kev_file.parent.mkdir(parents=True)
    kev_file.write_text("{ not json", encoding="utf-8")
    assert supportcheck.load_kev() == []


def test_load_kev_valid(kev_file):
    kev_file.parent.mkdir(parents=True)
    kev_file.write_text(json.dumps(VALID_KEV), encoding="utf-8")
    rows = supportcheck.load_kev()
    assert len(rows) == 2
    asus = next(r for r in rows if r["cve"] == "CVE-2026-1")
    assert asus["vendor"] == "asus" and asus["product"] == "rt-ac68u"
    assert asus["ransomware"] is True
    tapo = next(r for r in rows if r["cve"] == "CVE-2026-2")
    assert tapo["ransomware"] is False


# ─────────────────────────── refresh_kev ───────────────────────────

class FakeResp:
    def __init__(self, data=b"", headers=None):
        self._data = data
        self.headers = headers or {}

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _patch_urlopen(monkeypatch, fn):
    monkeypatch.setattr(urllib.request, "urlopen", fn)


def test_refresh_kev_valid_200_caches(db, kev_file, monkeypatch):
    body = json.dumps(VALID_KEV).encode()
    _patch_urlopen(monkeypatch, lambda req, timeout=None: FakeResp(
        body, {"ETag": '"abc"', "Last-Modified": "Mon, 01 Jan 2026 00:00:00 GMT"}))
    assert supportcheck.refresh_kev(db) is True
    assert kev_file.read_bytes() == body
    assert common.kv_get(db, "kev_fetched_at") is not None
    assert common.kv_get(db, "kev_etag") == '"abc"'
    assert common.kv_get(db, "kev_modified") == "Mon, 01 Jan 2026 00:00:00 GMT"


def test_refresh_kev_200_not_catalogue_keeps_copy(db, kev_file, monkeypatch):
    # regression: a captcha/maintenance 200 that is not the KEV must not overwrite the good copy.
    kev_file.parent.mkdir(parents=True)
    good = json.dumps(VALID_KEV).encode()
    kev_file.write_bytes(good)
    old_fetched = common.iso_ago(hours=13)              # old enough to pass the 12h age gate
    common.kv_set(db, "kev_fetched_at", old_fetched)
    db.commit()
    _patch_urlopen(monkeypatch, lambda req, timeout=None: FakeResp(b"<html>maintenance</html>"))
    assert supportcheck.refresh_kev(db) is True
    assert kev_file.read_bytes() == good                # unchanged
    assert common.kv_get(db, "kev_fetched_at") == old_fetched   # not refreshed


def test_refresh_kev_200_json_without_vulnerabilities_keeps_copy(db, kev_file, monkeypatch):
    kev_file.parent.mkdir(parents=True)
    good = json.dumps(VALID_KEV).encode()
    kev_file.write_bytes(good)
    common.kv_set(db, "kev_fetched_at", common.iso_ago(hours=13))
    db.commit()
    _patch_urlopen(monkeypatch, lambda req, timeout=None: FakeResp(json.dumps({"title": "hi"}).encode()))
    assert supportcheck.refresh_kev(db) is True
    assert kev_file.read_bytes() == good


def test_refresh_kev_304_keeps_copy(db, kev_file, monkeypatch):
    kev_file.parent.mkdir(parents=True)
    good = json.dumps(VALID_KEV).encode()
    kev_file.write_bytes(good)
    common.kv_set(db, "kev_fetched_at", common.iso_ago(hours=13))
    db.commit()

    def raise_304(req, timeout=None):
        raise urllib.error.HTTPError(supportcheck.KEV_URL, 304, "Not Modified", {}, None)
    _patch_urlopen(monkeypatch, raise_304)
    assert supportcheck.refresh_kev(db) is True
    assert kev_file.read_bytes() == good
    assert common.kv_get(db, "kev_fetched_at") is not None


def test_refresh_kev_network_error_keeps_copy(db, kev_file, monkeypatch):
    kev_file.parent.mkdir(parents=True)
    good = json.dumps(VALID_KEV).encode()
    kev_file.write_bytes(good)
    common.kv_set(db, "kev_fetched_at", common.iso_ago(hours=13))
    db.commit()

    def boom(req, timeout=None):
        raise urllib.error.URLError("offline")
    _patch_urlopen(monkeypatch, boom)
    assert supportcheck.refresh_kev(db) is True
    assert kev_file.read_bytes() == good


def test_refresh_kev_network_error_no_file_returns_false(db, kev_file, monkeypatch):
    def boom(req, timeout=None):
        raise urllib.error.URLError("offline")
    _patch_urlopen(monkeypatch, boom)
    assert supportcheck.refresh_kev(db) is False


def test_refresh_kev_age_short_circuits(db, kev_file, monkeypatch):
    kev_file.parent.mkdir(parents=True)
    kev_file.write_bytes(json.dumps(VALID_KEV).encode())
    common.kv_set(db, "kev_fetched_at", common.now_iso())   # fresh -> must not download
    db.commit()

    def must_not_call(req, timeout=None):
        raise AssertionError("urlopen must not be called when the cache is fresh")
    _patch_urlopen(monkeypatch, must_not_call)
    assert supportcheck.refresh_kev(db) is True


# ─────────────────────────── Support lazy KEV ───────────────────────────

def test_support_no_matcher_does_not_refresh(db, monkeypatch):
    calls = {"refresh": 0}
    monkeypatch.setattr(supportcheck, "refresh_kev", lambda conn: calls.__setitem__("refresh", calls["refresh"] + 1))
    monkeypatch.setattr(supportcheck, "load_kev", lambda: [])
    # Samsung tablet matches a product, but that product has no kev matcher.
    h = host(hostname="Galaxy-Tab-S5e", mac="aa:bb:cc:dd:ee:20")
    support = supportcheck.Support(db, [h])
    findings = support.findings_for(h)
    assert any(f["id"].startswith("eol:") for f in findings)
    assert calls["refresh"] == 0                 # the CISA list was never touched
    assert support._kev is None


def test_support_with_matcher_refreshes_once(db, monkeypatch):
    calls = {"refresh": 0}
    monkeypatch.setattr(supportcheck, "refresh_kev", lambda conn: calls.__setitem__("refresh", calls["refresh"] + 1))
    monkeypatch.setattr(supportcheck, "load_kev",
                        lambda: [{"vendor": "asus", "product": "rt-ac68u", "cve": "CVE-2026-1",
                                  "date": "2026-01-01", "ransomware": False}])
    h = host(vendor="ASUSTeK", hostname="RT-AC68U", mac="aa:bb:cc:dd:ee:21")
    support = supportcheck.Support(db, [h])
    findings = support.findings_for(h)
    assert calls["refresh"] == 1
    assert any(f["id"] == "kev:asus-rt-ac68u" for f in findings)


def test_support_obs_text_feeds_identify(db, make):
    # Support pulls passive observation text; a model known only passively should still identify.
    mac = "aa:bb:cc:dd:ee:22"
    make.observation("dhcp", mac, hostname="Galaxy-Tab-S5e")
    h = host(mac=mac)
    support = supportcheck.Support(db, [h])
    findings = support.findings_for(h)
    assert any(f["id"] == "eol:samsung-tab-s5e" for f in findings)
