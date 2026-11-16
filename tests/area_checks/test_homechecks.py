"""Area B — homechecks.py: finding logic (every network probe mocked)."""
import json
from datetime import datetime, timedelta, timezone

import pytest

import common
import homechecks as hc
from conftest import fake_urlopen, http_error


# ───────────────────────────── finding() shape ─────────────────────────────

def test_finding_shape():
    f = hc.finding("x-id", "warning", "A title", "A detail")
    assert f == {"id": "x-id", "severity": "warning", "title": "A title", "detail": "A detail"}
    assert list(f.keys()) == ["id", "severity", "title", "detail"]


# ───────────────────────────── RISKY_PORTS via check_host ─────────────────────────────

def _no_probes(monkeypatch):
    """Silence every network probe so check_host exercises only the RISKY_PORTS/web logic."""
    monkeypatch.setattr(hc, "verified_service_findings", lambda ip, ports: {})
    monkeypatch.setattr(hc, "smb_findings", lambda h, ports: [])
    monkeypatch.setattr(hc, "shelly_info", lambda ip: None)


@pytest.mark.parametrize("port,sev", [
    (23, "alert"), (2323, "alert"), (2375, "alert"),
    (21, "warning"), (3389, "warning"), (5900, "warning"), (6379, "warning"),
    (27017, "warning"), (11211, "warning"), (7547, "warning"),
    (1883, "info"), (554, "info"), (8554, "info"), (873, "info"),
])
def test_risky_port_makes_the_right_finding(monkeypatch, H, port, sev):
    _no_probes(monkeypatch)
    out, _fw = hc.check_host(H(open_ports=json.dumps([port])), gateway_ip="192.168.10.1")
    ids = {f["id"]: f for f in out}
    assert f"port-{port}" in ids
    assert ids[f"port-{port}"]["severity"] == sev
    assert ids[f"port-{port}"]["title"] == hc.RISKY_PORTS[port][1]


def test_non_risky_port_makes_no_finding(monkeypatch, H):
    _no_probes(monkeypatch)
    out, _ = hc.check_host(H(open_ports=json.dumps([22, 443, 8123])), gateway_ip="192.168.10.1")
    assert out == []


def test_telnet_web_on_2323_suppresses_the_finding(monkeypatch, H):
    _no_probes(monkeypatch)
    # Fully Kiosk's remote admin answers as a web page on 2323: not Telnet.
    h = H(open_ports=json.dumps([2323]), web_info=json.dumps({"2323": {"title": "Fully"}}))
    out, _ = hc.check_host(h, gateway_ip="192.168.10.1")
    assert not any(f["id"] == "port-2323" for f in out)


def test_telnet_web_on_23_suppresses_only_23(monkeypatch, H):
    _no_probes(monkeypatch)
    h = H(open_ports=json.dumps([23, 2323]), web_info=json.dumps({"23": {"title": "web"}}))
    out, _ = hc.check_host(h, gateway_ip="192.168.10.1")
    got = {f["id"] for f in out}
    assert "port-23" not in got and "port-2323" in got


# ───────────────────────────── verified_service_findings ─────────────────────────────

@pytest.mark.parametrize("anon,expect_id,expect_sev", [
    (True, "mqtt-anonymous", "warning"),
    (False, "port-1883", "info"),
    (None, None, None),
])
def test_verified_mqtt(monkeypatch, anon, expect_id, expect_sev):
    monkeypatch.setattr(hc, "mqtt_allows_anonymous", lambda ip, **k: anon)
    out = hc.verified_service_findings("10.0.0.5", {1883})
    if expect_id is None:
        assert 1883 not in out
    else:
        assert out[1883]["id"] == expect_id and out[1883]["severity"] == expect_sev


@pytest.mark.parametrize("needs,expect_id,expect_sev", [
    (False, "vnc-no-password", "alert"),
    (True, "port-5900", "info"),
    (None, None, None),
])
def test_verified_vnc(monkeypatch, needs, expect_id, expect_sev):
    monkeypatch.setattr(hc, "vnc_needs_password", lambda ip, **k: needs)
    out = hc.verified_service_findings("10.0.0.5", {5900})
    if expect_id is None:
        assert 5900 not in out
    else:
        assert out[5900]["id"] == expect_id and out[5900]["severity"] == expect_sev


@pytest.mark.parametrize("port", [554, 8554])
@pytest.mark.parametrize("needs,expect_id,expect_sev", [
    (False, "rtsp-open:{p}", "warning"),
    (True, "port-{p}", "info"),
    (None, None, None),
])
def test_verified_rtsp(monkeypatch, port, needs, expect_id, expect_sev):
    monkeypatch.setattr(hc, "rtsp_needs_password", lambda ip, p, **k: needs)
    out = hc.verified_service_findings("10.0.0.5", {port})
    if expect_id is None:
        assert port not in out
    else:
        assert out[port]["id"] == expect_id.format(p=port)
        assert out[port]["severity"] == expect_sev


def test_verified_only_touches_open_ports(monkeypatch):
    called = []
    monkeypatch.setattr(hc, "mqtt_allows_anonymous", lambda ip, **k: called.append("mqtt") or True)
    monkeypatch.setattr(hc, "vnc_needs_password", lambda ip, **k: called.append("vnc"))
    out = hc.verified_service_findings("10.0.0.5", {80, 443})
    assert out == {} and called == []


# ───────────────────────────── SMB ─────────────────────────────

def _smb(monkeypatch, responder):
    """responder(args, smb1) -> (code, output)."""
    monkeypatch.setattr(hc, "_smbclient", responder)


def test_smb_shares_list(monkeypatch):
    out = "Disk|photos|Family photos\nDisk|backup|\nIPC|IPC$|remote ipc\nPrinter|hp|the printer\n"
    _smb(monkeypatch, lambda args, smb1=False: (0, out))
    state, shares = hc.smb_shares("10.0.0.5")
    assert state == "list"
    assert ("Disk", "photos", "Family photos") in shares
    assert ("Disk", "backup", "") in shares
    assert ("IPC", "IPC$", "remote ipc") in shares


def test_smb_shares_denied(monkeypatch):
    _smb(monkeypatch, lambda args, smb1=False: (1, "tree connect failed: NT_STATUS_ACCESS_DENIED"))
    assert hc.smb_shares("10.0.0.5") == ("denied", None)


def test_smb_shares_old_protocol(monkeypatch):
    _smb(monkeypatch, lambda args, smb1=False: (1, "protocol negotiation failed: NT_STATUS_IO_TIMEOUT"))
    assert hc.smb_shares("10.0.0.5") == ("old", None)


def test_smb_shares_empty_but_ok(monkeypatch):
    _smb(monkeypatch, lambda args, smb1=False: (0, "\n"))
    assert hc.smb_shares("10.0.0.5") == ("list", [])


def test_smb_shares_cannot_tell(monkeypatch):
    _smb(monkeypatch, lambda args, smb1=False: (None, "smbclient is not installed"))
    code, why = hc.smb_shares("10.0.0.5")
    assert code is None and why == "smbclient is not installed"


def test_smb_share_opens_true(monkeypatch):
    _smb(monkeypatch, lambda args, smb1=False: (0, "  .                 D        0  Mon\n  65536 blocks of size 1024."))
    assert hc.smb_share_opens("10.0.0.5", "photos") is True


def test_smb_share_opens_denied(monkeypatch):
    _smb(monkeypatch, lambda args, smb1=False: (1, "NT_STATUS_ACCESS_DENIED listing \\*"))
    assert hc.smb_share_opens("10.0.0.5", "photos") is False


def test_smb_share_opens_unknown(monkeypatch):
    _smb(monkeypatch, lambda args, smb1=False: (None, "no answer in 20 s"))
    assert hc.smb_share_opens("10.0.0.5", "photos") is None


# smb_findings branches

def test_smb_findings_no_port(H):
    assert hc.smb_findings(H(), set()) == []


def test_smb_findings_guest_open(monkeypatch, H):
    monkeypatch.setattr(hc, "smb_shares", lambda ip, smb1=False: ("list", [("Disk", "photos", "")]))
    monkeypatch.setattr(hc, "smb_share_opens", lambda ip, share, smb1=False: True)
    out = hc.smb_findings(H(vendor="Synology"), {445})
    assert [f["id"] for f in out] == ["smb-guest"]
    assert out[0]["severity"] == "warning" and "photos" in out[0]["title"]


def test_smb_findings_list_only(monkeypatch, H):
    monkeypatch.setattr(hc, "smb_shares", lambda ip, smb1=False: ("list", [("Disk", "photos", "")]))
    monkeypatch.setattr(hc, "smb_share_opens", lambda ip, share, smb1=False: False)
    out = hc.smb_findings(H(), {445})
    assert [f["id"] for f in out] == ["smb-list"]
    assert out[0]["severity"] == "info"


def test_smb_findings_denied(monkeypatch, H):
    monkeypatch.setattr(hc, "smb_shares", lambda ip, smb1=False: ("denied", None))
    out = hc.smb_findings(H(), {445})
    assert [f["id"] for f in out] == ["port-445"] and out[0]["severity"] == "info"


def test_smb_findings_none_open(monkeypatch, H):
    monkeypatch.setattr(hc, "smb_shares", lambda ip, smb1=False: ("list", []))
    out = hc.smb_findings(H(), {445})
    assert [f["id"] for f in out] == ["port-445"]


def test_smb_findings_smb1_upgrade(monkeypatch, H):
    calls = []

    def shares(ip, smb1=False):
        calls.append(smb1)
        if not smb1:
            return "old", None
        return "list", [("Disk", "photos", "")]

    monkeypatch.setattr(hc, "smb_shares", shares)
    monkeypatch.setattr(hc, "smb_share_opens", lambda ip, share, smb1=False: False)
    out = hc.smb_findings(H(), {445})
    ids = [f["id"] for f in out]
    assert "smb1" in ids and out[0]["severity"] == "warning"
    assert calls == [False, True]           # tried normally, then with SMB1


def test_smb_findings_old_even_with_smb1(monkeypatch, H):
    monkeypatch.setattr(hc, "smb_shares", lambda ip, smb1=False: ("old", None))
    out = hc.smb_findings(H(), {445})
    assert out == []                         # couldn't tell, nothing reported


def test_smb_findings_hidden_shares_skipped(monkeypatch, H):
    monkeypatch.setattr(hc, "smb_shares", lambda ip, smb1=False:
                        ("list", [("Disk", "C$", ""), ("Disk", "ADMIN$", ""), ("Printer", "print$", "")]))
    opened = []
    monkeypatch.setattr(hc, "smb_share_opens", lambda ip, share, smb1=False: opened.append(share) or True)
    out = hc.smb_findings(H(), {445})
    assert opened == []                      # $-shares never tried
    assert [f["id"] for f in out] == ["port-445"]


# smb_remedy branches

def test_smb_remedy_windows(H):
    shares = [("Disk", "C$", ""), ("Disk", "Users", "")]
    assert "Windows" in hc.smb_remedy(H(), {445}, shares)


def test_smb_remedy_home_assistant(H):
    shares = [("Disk", "config", ""), ("Disk", "addons", ""), ("Disk", "ssl", "")]
    assert "Home Assistant" in hc.smb_remedy(H(), {8123}, shares)


def test_smb_remedy_asus(H):
    shares = [("Disk", "usbdisk", "")]
    assert "Asus" in hc.smb_remedy(H(vendor="ASUSTeK Computer"), {445}, shares)


def test_smb_remedy_generic(H):
    assert "guest access" in hc.smb_remedy(H(vendor="Nobody"), {445}, [("Disk", "x", "")])


# ───────────────────────────── login_remedy ─────────────────────────────

def test_login_remedy_fully(H):
    assert "Fully Kiosk" in hc.login_remedy(H(), "2323", {"title": "Fully Kiosk Admin"})


def test_login_remedy_own_dashboard(monkeypatch, H):
    monkeypatch.setattr(common, "own_ip", lambda: "192.168.10.50")
    assert "LanWard" in hc.login_remedy(H(ip="192.168.10.50"), "80", {"title": "login"})


def test_login_remedy_generic(monkeypatch, H):
    monkeypatch.setattr(common, "own_ip", lambda: "192.168.10.1")
    out = hc.login_remedy(H(ip="192.168.10.99"), "80", {"title": "Router"})
    assert "unencrypted" in out and "LanWard" not in out


# ───────────────────────────── _short_fw ─────────────────────────────

@pytest.mark.parametrize("raw,expect", [
    ("20230913-112003/v1.14.0-gcb84623", "1.14.0"),
    ("v1.0.0", "1.0.0"),
    ("1.2.3", "1.2.3"),
    ("20231219-134356/1.0.0-gfa1bc73", "1.0.0"),
    ("", ""),
    (None, ""),
    ("garbage", "garbage"),
])
def test_short_fw(raw, expect):
    assert hc._short_fw(raw) == expect


# ───────────────────────────── shelly_info / shelly_findings ─────────────────────────────

def _http_json(monkeypatch, table):
    """table: {path: (status, data)}; unknown paths return (None, None)."""
    monkeypatch.setattr(common, "http_json", lambda ip, port, path, timeout=4: table.get(path, (None, None)))


def test_shelly_info_not_a_shelly(monkeypatch):
    _http_json(monkeypatch, {"/shelly": (200, {"foo": "bar"})})
    assert hc.shelly_info("10.0.0.5") is None


def test_shelly_info_gen1_no_auth_with_update(monkeypatch):
    _http_json(monkeypatch, {
        "/shelly": (200, {"type": "SHSW-1", "auth": False, "fw": "20230913/v1.14.0-gcb"}),
        "/status": (200, {"update": {"has_update": True, "new_version": "20240101/v1.15.0-g1"}}),
    })
    info = hc.shelly_info("10.0.0.5")
    assert info == {"gen": 1, "auth": False, "model": "SHSW-1", "fw": "1.14.0", "update": "1.15.0"}
    out = hc.shelly_findings(info)
    ids = {f["id"] for f in out}
    assert "shelly-no-password" in ids and "shelly-update:1.15.0" in ids


def test_shelly_info_gen2_auth_on(monkeypatch):
    _http_json(monkeypatch, {"/shelly": (200, {"gen": 2, "auth_en": True, "app": "Plus1PM", "ver": "1.0.0"})})
    info = hc.shelly_info("10.0.0.5")
    assert info == {"gen": 2, "auth": True, "model": "Plus1PM", "fw": "1.0.0"}
    assert hc.shelly_findings(info) == []        # auth on, no pending update → nothing


def test_shelly_info_gen2_update(monkeypatch):
    _http_json(monkeypatch, {
        "/shelly": (200, {"gen": 2, "auth_en": False, "app": "Plus1", "ver": "1.0.0"}),
        "/rpc/Sys.GetStatus": (200, {"available_updates": {"stable": {"version": "1.1.0"}}}),
    })
    info = hc.shelly_info("10.0.0.5")
    assert info["update"] == "1.1.0"
    out = hc.shelly_findings(info)
    assert any(f["id"] == "shelly-update:1.1.0" for f in out)


def test_shelly_info_auth_on_skips_update_probe(monkeypatch):
    # With a password the /status and /rpc endpoints answer 401; shelly_info must not even consult them.
    probed = []
    def hj(ip, port, path, timeout=4):
        probed.append(path)
        if path == "/shelly":
            return 200, {"gen": 1, "auth": True, "type": "SHSW-1", "fw": "v1.0.0"}
        return None, None
    monkeypatch.setattr(common, "http_json", hj)
    info = hc.shelly_info("10.0.0.5")
    assert "update" not in info and probed == ["/shelly"]


# ───────────────────────────── _cert_date + TLS findings ─────────────────────────────

@pytest.mark.parametrize("value,ok", [
    ("Nov 15 18:28:52 2026 GMT", True),
    ("Jan  1 00:00:00 2030 GMT", True),
    ("not a date", False),
    ("", False),
    (None, False),
])
def test_cert_date(value, ok):
    got = hc._cert_date(value)
    assert (got is not None) == ok
    if ok:
        assert isinstance(got, datetime)


def _future(days):
    return (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=days)).strftime("%b %d %H:%M:%S %Y GMT")


def test_tls_expired_finding(monkeypatch, H):
    _no_probes(monkeypatch)
    h = H(open_ports="[]", tls_cert_not_after=_future(-1), tls_cert_fingerprint="ab:cd", tls_cert_cn="host")
    out, _ = hc.check_host(h, gateway_ip="192.168.10.1")
    f = next(f for f in out if f["id"].startswith("tls-"))
    assert f["id"] == "tls-expiry:ab:cd" and f["title"] == "TLS certificate has expired"


def test_tls_expiring_soon_finding(monkeypatch, H):
    _no_probes(monkeypatch)
    h = H(open_ports="[]", tls_cert_not_after=_future(10), tls_cert_fingerprint="ab:cd", tls_cert_cn="host")
    out, _ = hc.check_host(h, gateway_ip="192.168.10.1")
    f = next(f for f in out if f["id"].startswith("tls-"))
    assert f["id"] == "tls-expiring:ab:cd" and "expires in" in f["title"]


def test_tls_far_future_no_finding(monkeypatch, H):
    _no_probes(monkeypatch)
    h = H(open_ports="[]", tls_cert_not_after=_future(200), tls_cert_fingerprint="ab:cd")
    out, _ = hc.check_host(h, gateway_ip="192.168.10.1")
    assert not any(f["id"].startswith("tls-") for f in out)


def test_tls_shortlived_notice_is_quarter_life(monkeypatch, H):
    _no_probes(monkeypatch)
    # 90-day cert, 20 days left: a quarter-life notice (22.5d) fires, where the flat 30-day one also would.
    h = H(open_ports="[]", tls_cert_not_before=_future(-70), tls_cert_not_after=_future(20),
          tls_cert_fingerprint="ab:cd")
    out, _ = hc.check_host(h, gateway_ip="192.168.10.1")
    assert any(f["id"] == "tls-expiring:ab:cd" for f in out)


def test_tls_shortlived_no_notice_when_fresh(monkeypatch, H):
    _no_probes(monkeypatch)
    # 90-day cert, 40 days left: past the quarter-life (22.5d) notice → nothing yet.
    h = H(open_ports="[]", tls_cert_not_before=_future(-50), tls_cert_not_after=_future(40),
          tls_cert_fingerprint="ab:cd")
    out, _ = hc.check_host(h, gateway_ip="192.168.10.1")
    assert not any(f["id"].startswith("tls-") for f in out)


# ───────────────────────────── UPnP / router ─────────────────────────────

_ROOT_DESC = """<?xml version="1.0"?><root><device><serviceList>
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL></service>
</serviceList></device></root>"""


def test_upnp_control_url(monkeypatch):
    monkeypatch.setattr(hc.urllib.request, "urlopen",
                        fake_urlopen(lambda req: _ROOT_DESC.encode()))
    st, url = hc._upnp_control_url("http://192.168.10.1:5000/rootDesc.xml")
    assert "WANIPConnection" in st
    assert url == "http://192.168.10.1:5000/ctl/IPConn"


def test_upnp_control_url_rejects_other_host(monkeypatch):
    desc = _ROOT_DESC.replace("/ctl/IPConn", "http://evil.example/ctl")
    monkeypatch.setattr(hc.urllib.request, "urlopen", fake_urlopen(lambda req: desc.encode()))
    assert hc._upnp_control_url("http://192.168.10.1:5000/rootDesc.xml") == (None, None)


def test_upnp_control_url_no_wan_service(monkeypatch):
    desc = _ROOT_DESC.replace("WANIPConnection", "Layer3Forwarding")
    monkeypatch.setattr(hc.urllib.request, "urlopen", fake_urlopen(lambda req: desc.encode()))
    assert hc._upnp_control_url("http://192.168.10.1:5000/rootDesc.xml") == (None, None)


def _mapping_soap(ext, client, proto="TCP", internal="80", desc="web", enabled="1"):
    return (f'<?xml version="1.0"?><s:Envelope><s:Body><u:GetGenericPortMappingEntryResponse>'
            f'<NewProtocol>{proto}</NewProtocol><NewExternalPort>{ext}</NewExternalPort>'
            f'<NewInternalClient>{client}</NewInternalClient><NewInternalPort>{internal}</NewInternalPort>'
            f'<NewPortMappingDescription>{desc}</NewPortMappingDescription><NewEnabled>{enabled}</NewEnabled>'
            f'</u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>').encode()


def test_mapping_entry_parses(monkeypatch):
    monkeypatch.setattr(hc.urllib.request, "urlopen",
                        fake_urlopen(lambda req: _mapping_soap("8080", "192.168.10.9")))
    e = hc._mapping_entry("http://192.168.10.1/ctl", "svc", 0)
    assert e["proto"] == "TCP" and e["external"] == "8080" and e["client"] == "192.168.10.9"
    assert e["enabled"] == "1"


def test_mapping_entry_end(monkeypatch):
    monkeypatch.setattr(hc.urllib.request, "urlopen",
                        fake_urlopen(lambda req: http_error(500, b"<errorCode>713</errorCode>")))
    assert hc._mapping_entry("http://192.168.10.1/ctl", "svc", 9) == "end"


def test_mapping_entry_fault_is_none(monkeypatch):
    monkeypatch.setattr(hc.urllib.request, "urlopen",
                        fake_urlopen(lambda req: http_error(500, b"<errorCode>606</errorCode>")))
    assert hc._mapping_entry("http://192.168.10.1/ctl", "svc", 0) is None


def test_upnp_port_mappings_lists_then_ends(monkeypatch):
    seq = [_mapping_soap("8080", "192.168.10.9"),
           _mapping_soap("9090", "192.168.10.8"),
           http_error(500, b"<errorCode>713</errorCode>")]
    calls = {"i": 0}

    def responder(req):
        # _upnp_control_url is the first GET (no data); mapping calls are POSTs (have data)
        if getattr(req, "data", None) is None:
            return _ROOT_DESC.encode()
        out = seq[calls["i"]]
        calls["i"] += 1
        return out

    monkeypatch.setattr(hc.urllib.request, "urlopen", fake_urlopen(responder))
    mappings, complete = hc.upnp_port_mappings("http://192.168.10.1:5000/rootDesc.xml")
    assert complete is True
    assert [m["external"] for m in mappings] == ["8080", "9090"]


def test_router_findings_open_ports(monkeypatch):
    monkeypatch.setattr(hc, "upnp_port_mappings",
                        lambda loc: ([{"proto": "TCP", "external": "8080", "client": "192.168.10.9",
                                       "internal": "80", "description": "cam", "enabled": "1"}], True))
    upnp = {"st": ["urn:schemas-upnp-org:service:WANIPConnection:1"], "location": "http://192.168.10.1/d.xml"}
    out = hc.router_findings(upnp)
    assert [f["id"] for f in out] == ["upnp-open"] and out[0]["severity"] == "warning"
    assert "8080" in out[0]["detail"]


def test_router_findings_disabled_mapping_is_enabled_only(monkeypatch):
    monkeypatch.setattr(hc, "upnp_port_mappings",
                        lambda loc: ([{"proto": "TCP", "external": "8080", "client": "x",
                                       "internal": "80", "description": "", "enabled": "0"}], True))
    upnp = {"st": ["urn:schemas-upnp-org:service:WANIPConnection:1"], "location": "http://192.168.10.1/d.xml"}
    out = hc.router_findings(upnp)
    assert [f["id"] for f in out] == ["upnp-enabled"] and out[0]["severity"] == "info"


def test_router_findings_not_a_router(monkeypatch):
    assert hc.router_findings({"st": ["urn:schemas-upnp-org:service:RenderingControl:1"]}) == []


def test_router_findings_incomplete_list(monkeypatch):
    monkeypatch.setattr(hc, "upnp_port_mappings", lambda loc: (None, False))
    upnp = {"st": ["urn:schemas-upnp-org:device:InternetGatewayDevice:1"], "location": "http://192.168.10.1/d.xml"}
    out = hc.router_findings(upnp)
    assert [f["id"] for f in out] == ["upnp-enabled"]
    assert "could not read" in out[0]["detail"]


# ───────────────────────────── check_host integration ─────────────────────────────

def test_check_host_frigate_5000(monkeypatch, H):
    _no_probes(monkeypatch)
    h = H(open_ports=json.dumps([5000]), web_info=json.dumps({"5000": {"title": "Frigate"}}))
    out, _ = hc.check_host(h, gateway_ip="192.168.10.1")
    assert any(f["id"] == "frigate-5000" for f in out)


def test_check_host_http_login_plain(monkeypatch, H):
    _no_probes(monkeypatch)
    h = H(open_ports=json.dumps([80]),
          web_info=json.dumps({"80": {"login": "form", "tls": False, "status": 200, "title": "Login"}}))
    monkeypatch.setattr(common, "own_ip", lambda: "192.168.10.1")
    out, _ = hc.check_host(h, gateway_ip="192.168.10.1")
    assert any(f["id"] == "http-login:80" for f in out)


def test_check_host_http_login_suppressed_by_tls(monkeypatch, H):
    _no_probes(monkeypatch)
    h = H(open_ports=json.dumps([443]),
          web_info=json.dumps({"443": {"login": "form", "tls": True, "status": 200}}))
    out, _ = hc.check_host(h, gateway_ip="192.168.10.1")
    assert not any(f["id"].startswith("http-login") for f in out)


def test_check_host_shelly_firmware(monkeypatch, H):
    monkeypatch.setattr(hc, "verified_service_findings", lambda ip, ports: {})
    monkeypatch.setattr(hc, "smb_findings", lambda h, ports: [])
    monkeypatch.setattr(hc, "shelly_info",
                        lambda ip: {"gen": 1, "auth": False, "model": "SHSW-1", "fw": "1.14.0"})
    h = H(open_ports=json.dumps([80]))
    out, fw = hc.check_host(h, gateway_ip="192.168.10.1")
    assert fw == "Shelly SHSW-1 1.14.0"
    assert any(f["id"] == "shelly-no-password" for f in out)


def test_check_host_router_only_at_gateway(monkeypatch, H):
    _no_probes(monkeypatch)
    called = []
    monkeypatch.setattr(hc, "router_findings", lambda upnp: called.append(1) or [])
    upnp = json.dumps({"st": ["InternetGatewayDevice"], "location": "http://x/d.xml"})
    # Not the gateway → router_findings not called.
    hc.check_host(H(ip="192.168.10.50", open_ports="[]", upnp_info=upnp), gateway_ip="192.168.10.1")
    assert called == []
    # Is the gateway → called.
    hc.check_host(H(ip="192.168.10.1", open_ports="[]", upnp_info=upnp), gateway_ip="192.168.10.1")
    assert called == [1]


def test_check_host_malformed_upnp_swallowed(monkeypatch, H):
    _no_probes(monkeypatch)
    out, _ = hc.check_host(H(ip="192.168.10.1", open_ports="[]", upnp_info="{not json"),
                           gateway_ip="192.168.10.1")
    assert out == []            # ValueError on bad JSON is caught


def test_check_host_empty_ports_no_findings(monkeypatch, H):
    _no_probes(monkeypatch)
    out, fw = hc.check_host(H(open_ports=None), gateway_ip="192.168.10.1")
    assert out == [] and fw is None


# ───────────────────────────── carried_findings ─────────────────────────────

def test_carried_findings_carries_last_scanned(db, make):
    f = [hc.finding("eol:foo", "warning", "End of life", "x")]
    s1 = make.scan()
    make.host(s1, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:01",
              open_ports=json.dumps([80]), findings=json.dumps(f))
    s2 = make.scan()
    make.host(s2, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:01", open_ports=None)
    row = db.execute("SELECT * FROM hosts WHERE scan_id=? AND ip=?", (s2, "192.168.10.9")).fetchone()
    carried = hc.carried_findings(db, row, s2)
    assert [c["id"] for c in carried] == ["eol:foo"]
    assert carried[0]["from_scan"] == s1


def test_carried_findings_skips_unscanned_prior(db, make):
    f = [hc.finding("eol:foo", "warning", "End of life", "x")]
    s1 = make.scan()
    make.host(s1, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:01",
              open_ports=json.dumps([80]), findings=json.dumps(f))
    s2 = make.scan()            # prior scan but ports not checked → must be skipped
    make.host(s2, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:01", open_ports=None, findings=None)
    s3 = make.scan()
    make.host(s3, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:01", open_ports=None)
    row = db.execute("SELECT * FROM hosts WHERE scan_id=? AND ip=?", (s3, "192.168.10.9")).fetchone()
    carried = hc.carried_findings(db, row, s3)
    assert [c["id"] for c in carried] == ["eol:foo"] and carried[0]["from_scan"] == s1


def test_carried_findings_none_when_no_prior(db, make):
    s1 = make.scan()
    make.host(s1, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:01", open_ports=None)
    row = db.execute("SELECT * FROM hosts WHERE scan_id=? AND ip=?", (s1, "192.168.10.9")).fetchone()
    assert hc.carried_findings(db, row, s1) == []


def test_carried_findings_by_ip_when_no_mac(db, make):
    f = [hc.finding("port-23", "alert", "Telnet", "x")]
    s1 = make.scan()
    make.host(s1, ip="192.168.10.9", mac=None, open_ports=json.dumps([23]), findings=json.dumps(f))
    s2 = make.scan()
    make.host(s2, ip="192.168.10.9", mac=None, open_ports=None)
    row = db.execute("SELECT * FROM hosts WHERE scan_id=? AND ip=?", (s2, "192.168.10.9")).fetchone()
    carried = hc.carried_findings(db, row, s2)
    assert [c["id"] for c in carried] == ["port-23"]


# ───────────────────────────── run() ─────────────────────────────

def _enable_support(db, make, monkeypatch):
    make.kv("setting:SUPPORT_CHECK", "on")
    common._SETTINGS_CACHE["at"] = float("-inf")
    monkeypatch.setattr(common, "default_gateway", lambda: "192.168.10.1")


def test_run_writes_findings(monkeypatch, db, make):
    monkeypatch.setattr(common, "default_gateway", lambda: "192.168.10.1")
    make.kv("setting:SUPPORT_CHECK", "off")
    common._SETTINGS_CACHE["at"] = float("-inf")
    monkeypatch.setattr(hc, "verified_service_findings", lambda ip, ports: {})
    monkeypatch.setattr(hc, "smb_findings", lambda h, ports: [])
    monkeypatch.setattr(hc, "shelly_info", lambda ip: None)
    s = make.scan()
    make.host(s, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:01", open_ports=json.dumps([23]))
    hc.run(s)
    row = db.execute("SELECT findings FROM hosts WHERE scan_id=? AND ip=?", (s, "192.168.10.9")).fetchone()
    found = json.loads(row["findings"])
    assert any(f["id"] == "port-23" for f in found)


def test_run_empty_findings_written_as_null(monkeypatch, db, make):
    monkeypatch.setattr(common, "default_gateway", lambda: "192.168.10.1")
    make.kv("setting:SUPPORT_CHECK", "off")
    common._SETTINGS_CACHE["at"] = float("-inf")
    monkeypatch.setattr(hc, "verified_service_findings", lambda ip, ports: {})
    monkeypatch.setattr(hc, "smb_findings", lambda h, ports: [])
    monkeypatch.setattr(hc, "shelly_info", lambda ip: None)
    s = make.scan()
    make.host(s, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:01", open_ports=json.dumps([443]))
    hc.run(s)
    row = db.execute("SELECT findings FROM hosts WHERE scan_id=? AND ip=?", (s, "192.168.10.9")).fetchone()
    assert row["findings"] is None          # empty list stored as NULL, not "[]"


def test_run_support_dedup_no_duplicate_eol(monkeypatch, db, make):
    """Regression: a carried-forward host already holding an eol finding must not get a second one from the
    support pass (FRAMEWORK regression list: duplicate eol/kev on ports-unscanned hosts)."""
    import supportcheck
    _enable_support(db, make, monkeypatch)
    eol = hc.finding("eol:acme-router", "warning", "This device is end of life", "x")
    s1 = make.scan()
    make.host(s1, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:01",
              open_ports=json.dumps([80]), findings=json.dumps([eol]))
    s2 = make.scan()
    make.host(s2, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:01", open_ports=None)   # carried forward

    class FakeSupport:
        def __init__(self, conn, hosts):
            pass

        def findings_for(self, h):
            return [hc.finding("eol:acme-router", "warning", "This device is end of life", "x")]

    monkeypatch.setattr(supportcheck, "Support", FakeSupport)
    hc.run(s2)
    row = db.execute("SELECT findings FROM hosts WHERE scan_id=? AND ip=?", (s2, "192.168.10.9")).fetchone()
    found = json.loads(row["findings"])
    assert [f["id"] for f in found].count("eol:acme-router") == 1


def test_run_support_adds_new_finding(monkeypatch, db, make):
    import supportcheck
    _enable_support(db, make, monkeypatch)
    monkeypatch.setattr(hc, "verified_service_findings", lambda ip, ports: {})
    monkeypatch.setattr(hc, "smb_findings", lambda h, ports: [])
    monkeypatch.setattr(hc, "shelly_info", lambda ip: None)
    s = make.scan()
    make.host(s, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:01", open_ports=json.dumps([443]))

    class FakeSupport:
        def __init__(self, conn, hosts):
            pass

        def findings_for(self, h):
            return [hc.finding("eol:acme", "warning", "EOL", "x")]

    monkeypatch.setattr(supportcheck, "Support", FakeSupport)
    hc.run(s)
    row = db.execute("SELECT findings FROM hosts WHERE scan_id=? AND ip=?", (s, "192.168.10.9")).fetchone()
    assert any(f["id"] == "eol:acme" for f in json.loads(row["findings"]))


def test_run_support_failure_never_breaks_scan(monkeypatch, db, make):
    import supportcheck
    _enable_support(db, make, monkeypatch)
    monkeypatch.setattr(hc, "verified_service_findings", lambda ip, ports: {})
    monkeypatch.setattr(hc, "smb_findings", lambda h, ports: [])
    monkeypatch.setattr(hc, "shelly_info", lambda ip: None)
    s = make.scan()
    make.host(s, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:01", open_ports=json.dumps([23]))

    class Boom:
        def __init__(self, conn, hosts):
            raise RuntimeError("kaboom")

    monkeypatch.setattr(supportcheck, "Support", Boom)
    hc.run(s)       # must not raise
    row = db.execute("SELECT findings FROM hosts WHERE scan_id=? AND ip=?", (s, "192.168.10.9")).fetchone()
    assert any(f["id"] == "port-23" for f in json.loads(row["findings"]))


def test_run_marks_homechecks_done_for_whole_lan(monkeypatch, db, make):
    monkeypatch.setattr(common, "default_gateway", lambda: "192.168.10.1")
    make.kv("setting:SUPPORT_CHECK", "off")
    common._SETTINGS_CACHE["at"] = float("-inf")
    monkeypatch.setattr(hc, "verified_service_findings", lambda ip, ports: {})
    monkeypatch.setattr(hc, "smb_findings", lambda h, ports: [])
    monkeypatch.setattr(hc, "shelly_info", lambda ip: None)
    monkeypatch.setattr(common, "SUBNET", "192.168.10.0/24")
    s = make.scan(subnet="192.168.10.0/24")
    make.host(s, ip="192.168.10.9", mac="aa:bb:cc:dd:ee:01", open_ports=json.dumps([443]))
    hc.run(s)
    assert common.kv_get(db, "homechecks_done") == str(s)
