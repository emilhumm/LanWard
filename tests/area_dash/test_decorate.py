"""decorate(): port_chips, identity, category, findings_list — and the fuzz case where upnp_info /
web_info / findings / open_ports hold corrupt JSON (must never raise). classify() unit checks."""
import contextlib

import pytest


@pytest.fixture
def ctx(db):
    """An app + request context so decorate()'s _labels_map() can reach the (test) DB via g."""
    import app
    with app.app.test_request_context():
        yield app


def test_decorate_port_chips(ctx):
    row = {"mac": "24:5e:be:11:22:33", "ip": "192.168.10.30", "scan_id": 1,
           "ports": "http,https", "open_ports": "[80, 443]",
           "web_info": '{"80": {"status": 200, "title": "Dashboard", "tls": false}, '
                       '"443": {"status": 200, "title": "Secure", "tls": true}}'}
    d = ctx.decorate(row)
    chips = {c["port"]: c for c in d["port_chips"]}
    assert chips[80]["name"] == "Dashboard"
    assert chips[80]["url"] == "http://192.168.10.30:80/"
    assert chips[443]["url"] == "https://192.168.10.30:443/"


def test_decorate_identity_prefers_cert_then_upnp(ctx):
    assert ctx.decorate({"mac": "", "tls_cert_cn": "box.local",
                         "upnp_info": '{"friendlyName": "Living Room"}'})["identity"] == "box.local"
    assert ctx.decorate({"mac": "", "upnp_info": '{"friendlyName": "Living Room"}'})["identity"] == "Living Room"


def test_decorate_bare_wildcard_cert_is_ignored(ctx):
    d = ctx.decorate({"mac": "", "tls_cert_cn": "*", "http_title": "Hi"})
    assert d["identity"] == "Hi"


def test_decorate_category_from_ports(ctx):
    assert ctx.decorate({"mac": "", "vendor": "Reolink", "ports": "rtsp,http"})["category"] == "camera"


def test_decorate_risky_from_findings_and_telnet(ctx):
    risky = ctx.decorate({"mac": "", "ports": "telnet"})
    assert risky["risky"] is True
    alert = ctx.decorate({"mac": "", "findings": '[{"severity": "alert"}]'})
    assert alert["risky"] is True


def test_decorate_ports_unknown(ctx):
    d = ctx.decorate({"mac": "", "scan_id": 5, "open_ports": None})
    assert d["ports_unknown"] is True
    d2 = ctx.decorate({"mac": "", "scan_id": 5, "open_ports": "[80]"})
    assert d2["ports_unknown"] is False


@pytest.mark.parametrize("field", ["upnp_info", "web_info", "findings", "open_ports"])
def test_decorate_corrupt_json_does_not_raise(ctx, field):
    row = {"mac": "24:5e:be:11:22:33", "ip": "192.168.10.1", "scan_id": 1,
           "ports": "http", "open_ports": "[80]",
           "upnp_info": '{"friendlyName": "ok"}', "web_info": "{}", "findings": "[]"}
    row[field] = "{not valid json at all"
    d = ctx.decorate(row)                 # must not raise
    assert d["findings_list"] == [] or isinstance(d["findings_list"], list)
    assert isinstance(d["port_chips"], list)


def test_decorate_non_dict_json_values(ctx):
    # web_info / upnp_info that parse to a list (not an object) must be tolerated
    d = ctx.decorate({"mac": "", "ip": "1.1.1.1", "scan_id": 1, "ports": "http",
                      "open_ports": "[80]", "web_info": "[1,2,3]", "upnp_info": "42"})
    assert isinstance(d["port_chips"], list)
    assert d["identity"] is None


def test_route_tolerates_non_dict_web_info(client, db, make):
    sid = make.scan(host_count=1)
    make.host(sid, ip="192.168.10.9", mac="24:5e:be:11:22:33",
              ports="http", open_ports="[80]", web_info="[1,2,3]")
    assert client.get("/devices").status_code == 200


def test_decorate_uses_label(ctx, make):
    make.label("24:5e:be:aa:aa:aa", "My NAS")
    d = ctx.decorate({"mac": "24:5E:BE:AA:AA:AA"})    # case-insensitive match
    assert d["label"] == "My NAS"


# ── classify() ──

@pytest.mark.parametrize("vendor,ports,hostname,label,expected", [
    ("Reolink", "rtsp,http", None, None, "camera"),
    (None, None, "Alexs-iPhone", None, "phone"),
    (None, None, None, "Kims Ipad", "phone"),
    ("Espressif", None, None, None, "iot"),
    ("TP-Link", None, None, None, "network"),
    ("HP Inc.", None, None, None, "printer"),
    ("Intel", "rdp", None, None, "computer"),
    ("Nobody", None, None, None, "other"),
])
def test_classify(ctx, vendor, ports, hostname, label, expected):
    assert ctx.classify(vendor, ports, hostname, label) == expected
