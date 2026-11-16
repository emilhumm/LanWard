"""Area F — robustness / fuzz.

Malformed or hostile data must never make a page 500 or a parse helper crash. We put corrupt /
unexpected values in the host columns the dashboard reads (upnp_info, web_info, findings,
open_ports) and in observation details, then drive them through decorate() (via the devices and
host pages), supportcheck, and the common.* parsers; and we throw junk at /host/<mac>, /search,
/devices filters and the Settings POST.

Where a page actually crashes today the test is marked xfail(BUG: ...) so the suite stays green
while the bug is tracked (FRAMEWORK.md, dimension 5).
"""
import json

import pytest

import common
import supportcheck


HOSTILE_JSON = [
    ("invalid", "{not json"),
    ("truncated", '{"a":'),
    ("number", "12345"),
    ("string", '"just a string"'),
    ("list", "[1,2,3]"),
    ("bool", "true"),
    ("null", "null"),
    ("empty", ""),
    ("huge", json.dumps({"friendlyName": "A" * 200000})),
    ("unicode", json.dumps({"friendlyName": "Ünïcödé \U0001F4A9 ‮\u0000"})),
]


# ───────────────────── common parsers are hard by contract ─────────────────────

@pytest.mark.parametrize("name,raw", HOSTILE_JSON)
def test_details_dict_never_raises(name, raw):
    out = common.details_dict(raw)
    assert isinstance(out, dict)        # {} for anything that is not a JSON object


def test_details_dict_non_string():
    for bad in (None, 123, 4.5, [], {}, b"bytes"):
        assert isinstance(common.details_dict(bad), dict)


@pytest.mark.parametrize("txt", [
    None, 123, "not-a-dict", [1, 2], {"md": 5}, {"md": ["x"]}, {"model": None},
    {"md": "WEBOS"}, {"md": "WEBOS", "model": "OLED65C9PLA"}, {"fn": "A" * 100000},
])
def test_mdns_txt_model_never_raises(txt):
    out = common.mdns_txt_model(txt)
    assert out is None or isinstance(out, str)


def test_mdns_txt_model_truncates_and_skips_platform():
    # "A" is a hex digit, so an all-A string reads as an address and is rejected; use a non-hex letter
    assert common.mdns_txt_model({"fn": "Z" * 100000}) == "Z" * 60       # capped at 60 chars
    assert common.mdns_txt_model({"md": "WEBOS", "model": "OLED65C9PLA"}) == "OLED65C9PLA"


# ───────────────────── supportcheck handles hostile host rows ─────────────────────

def _host(**cols):
    base = {"mac": "aa:bb:cc:dd:ee:ff", "vendor": None, "hostname": None, "http_server": None,
            "http_title": None, "firmware": None, "mdns_services": None, "upnp_info": None,
            "open_ports": None, "web_info": None, "findings": None, "ip": "192.168.10.9",
            "scan_id": 1, "bridge_mac": None}
    base.update(cols)
    return base


@pytest.mark.parametrize("name,raw", HOSTILE_JSON)
def test_signals_never_raises_on_bad_upnp(name, raw):
    """Regression (FRAMEWORK): _signals must not TypeError on a non-string / non-dict UPnP field; a
    broken row for one device must not abort the whole support pass."""
    vendor, text = supportcheck._signals(_host(upnp_info=raw), "")
    assert isinstance(vendor, str) and isinstance(text, str)


def test_signals_non_string_upnp_values():
    """UPnP JSON whose modelName etc. are numbers / lists (a misbehaving device) must still fold
    into the text blob."""
    upnp = json.dumps({"friendlyName": 1234, "modelName": ["a", "b"], "manufacturer": None})
    vendor, text = supportcheck._signals(_host(vendor="TP-Link", upnp_info=upnp), "")
    assert "tp-link" in vendor


@pytest.mark.parametrize("name,raw", HOSTILE_JSON)
def test_findings_for_never_raises(db, monkeypatch, name, raw):
    """A device whose announced text is hostile JSON still yields a (possibly empty) list, no crash.
    KEV download is stubbed so nothing touches the network."""
    monkeypatch.setattr(supportcheck, "refresh_kev", lambda conn: False)
    monkeypatch.setattr(supportcheck, "load_kev", lambda: [])
    support = supportcheck.Support(db, [])
    out = support.findings_for(_host(upnp_info=raw, hostname=raw, http_title=raw))
    assert isinstance(out, list)


# ───────────────────── decorate() via the dashboard pages ─────────────────────
#
# decorate() clearly tries to be defensive (parse_json swallows bad JSON, with `or {}` / `or []`
# fallbacks), but it only guards against broken JSON, not valid JSON of the WRONG TYPE. A column
# holding e.g. `12345`, `"text"`, `true` or a JSON array parses fine, slips past `or {}` (it is
# truthy), and then blows up on `.get(...)` / iteration. Each such input is marked xfail(BUG: ...)
# below; the rest must render. See the FINDINGS in the Area F report.

def _scan_with_host(make, **cols):
    sid = make.scan()
    make.host(sid, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:ff", **cols)
    return sid


def _params(bug_names, reason):
    """HOSTILE_JSON as pytest params, xfailing the named cases with `reason`."""
    out = []
    for name, raw in HOSTILE_JSON:
        marks = [pytest.mark.xfail(reason=reason, strict=False)] if name in bug_names else []
        out.append(pytest.param(name, raw, marks=marks, id=name))
    return out


def test_devices_empty_db_ok(client):
    assert client.get("/devices").status_code == 200


# upnp_info -> decorate() identity line: `u.get("friendlyName")` when u is a truthy non-dict.
# FIXED: decorate() now coerces upnp_info to a dict (else {}), so these render.
_UPNP_BUG = set()


@pytest.mark.parametrize("name,raw", _params(
    _UPNP_BUG, "BUG: decorate() crashes when upnp_info is truthy non-dict JSON (AttributeError on u.get)"))
def test_devices_survives_bad_upnp_info(client, make, name, raw):
    """A host whose upnp_info is corrupt/unexpected must not 500 the devices table."""
    _scan_with_host(make, upnp_info=raw)
    assert client.get("/devices").status_code < 500


# findings -> decorate() `any(f["severity"] ... for f in findings_list)` when it is not a list of dicts.
# FIXED: decorate() now keeps only dict items of a list, else []; non-list findings become [].
_FINDINGS_BUG = set()


@pytest.mark.parametrize("name,raw", _params(
    _FINDINGS_BUG, "BUG: decorate() crashes when findings is valid JSON but not a list of dicts"))
def test_devices_survives_bad_findings(client, make, name, raw):
    _scan_with_host(make, findings=raw)
    assert client.get("/devices").status_code < 500


# open_ports -> decorate() `enumerate(parse_json(...) or [])` when it is a non-iterable scalar.
# FIXED: decorate() now coerces open_ports to a list (else []) before enumerate.
_OPEN_PORTS_BUG = set()


@pytest.mark.parametrize("name,raw", _params(
    _OPEN_PORTS_BUG, "BUG: decorate() crashes when open_ports is a JSON number/bool (enumerate on non-iterable)"))
def test_host_page_survives_bad_open_ports(client, make, name, raw):
    """open_ports is read as a JSON list for the port chips; junk must not 500 the host page."""
    _scan_with_host(make, open_ports=raw)
    assert client.get("/host/aa:bb:cc:dd:ee:ff").status_code < 500


# web_info -> decorate() `web.get(str(port))` when web is a truthy non-dict (needs an open port).
# FIXED: decorate() now coerces web_info to a dict (else {}) before web.get.
_WEB_INFO_BUG = set()


@pytest.mark.parametrize("name,raw", _params(
    _WEB_INFO_BUG, "BUG: decorate() crashes when web_info is truthy non-dict JSON (AttributeError on web.get)"))
def test_host_page_survives_bad_web_info(client, make, name, raw):
    _scan_with_host(make, open_ports="[80]", ports="http", web_info=raw)
    assert client.get("/host/aa:bb:cc:dd:ee:ff").status_code < 500


def test_host_page_survives_hostile_observation_details(client, make):
    """A device known only from listening, with corrupt observation details, still renders."""
    make.observation("mdns", "aa:bb:cc:dd:ee:ff", details="{not json")
    make.observation("dhcp", "aa:bb:cc:dd:ee:ff", details='["unexpected","list"]')
    resp = client.get("/host/aa:bb:cc:dd:ee:ff")
    assert resp.status_code in (200, 404)       # never 500


# ───────────────────── /host/<mac> path traversal & junk ─────────────────────

@pytest.mark.parametrize("bad", [
    "../etc/passwd", "..%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "not-a-mac", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ",
    "x" * 5000, "aa:bb:cc:dd:ee:ff'; DROP TABLE hosts;--",
])
def test_host_path_rejects_junk(client, bad):
    """A non-MAC path must return 400/404 (or a redirect), never 500 and never read a file."""
    resp = client.get("/host/" + bad)
    assert resp.status_code in (400, 404, 301, 308), f"{bad!r} -> {resp.status_code}"


def test_host_tables_survive_traversal_attempt(client, make):
    """A traversal attempt must not have dropped/altered the hosts table."""
    _scan_with_host(make)
    client.get("/host/aa:bb:cc:dd:ee:ff'; DROP TABLE hosts;--")
    assert common.connect().execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 1


# ───────────────────── search / filter query params ─────────────────────

@pytest.mark.parametrize("q", [
    "' OR '1'='1", "100%", "a_b", "50% off", "\\", "%'; DROP TABLE hosts;--",
    "(.*)+", "[", "\U0001F4A9", "Ünïcödé", "x" * 3000, "aa:bb:cc",
])
def test_search_is_injection_safe(client, make, q):
    _scan_with_host(make, hostname="living-room")
    resp = client.get("/search", query_string={"q": q})
    assert resp.status_code == 200
    # the table is still there afterwards
    assert common.connect().execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 1


@pytest.mark.parametrize("params", [
    {"scan": "99999999"}, {"scan": "not-an-int"}, {"sort": "'; DROP TABLE hosts;--"},
    {"show": "../"}, {"show": "look"}, {"scan": "-1"},
])
def test_devices_filter_params_are_safe(client, make, params):
    _scan_with_host(make)
    resp = client.get("/devices", query_string=params)
    assert resp.status_code == 200


# ───────────────────── Settings POST: extreme / empty / huge ─────────────────────

def _valid_settings_form(**over):
    form = {
        "send_warnings": "on", "retain_days": "365", "backup_days": "14",
        "offline_minutes": "10", "full_days": "1", "status_allow": "127.0.0.1",
        "scan_hour": ["0", "6", "12", "18"], "support_check": "on", "auto_logout": "0",
    }
    form.update(over)
    return form


def test_settings_valid_post_saves(post, db):
    resp = post("/settings", data=_valid_settings_form())
    assert resp.status_code in (302, 303)


@pytest.mark.parametrize("over", [
    {"retain_days": ""}, {"retain_days": "0"}, {"retain_days": "99999999"},
    {"retain_days": "-5"}, {"retain_days": "3.5"}, {"retain_days": "A" * 5000},
    {"offline_minutes": "1"}, {"full_days": "999"}, {"status_allow": "not-an-ip"},
    {"status_allow": "'; DROP TABLE kv;--"},
])
def test_settings_bad_values_rejected_cleanly(post, db, over):
    """Extreme/empty/huge values are rejected with a 400 re-render, never a crash, and nothing is
    saved."""
    resp = post("/settings", data=_valid_settings_form(**over))
    assert resp.status_code == 400
    # the whole form was invalid-rejected: no setting row was written
    assert db.execute("SELECT COUNT(*) FROM kv WHERE key LIKE 'setting:%'").fetchone()[0] == 0


def test_settings_empty_post_is_rejected(post, db):
    """A completely empty POST (no fields at all) must 400, not 500."""
    resp = post("/settings", data={})
    assert resp.status_code == 400
