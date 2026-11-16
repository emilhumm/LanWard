"""Area C — db/enrich.py pure parsers.

UPnP/SSDP XML, follow_upnp_location, sonos_mac, TLS cert DN/field parsing, HTTP banner/
title parsing, ipv6_to_mac. Every network call is mocked; nothing touches the LAN.
"""
import socket
import urllib.request

import pytest

import common


# ───────────────────────── sonos_mac ─────────────────────────

def test_sonos_mac_from_udn(enrich):
    mac = enrich.sonos_mac({"UDN": "uuid:RINCON_542A1B00AA0101400"})
    assert mac == "54:2a:1b:00:aa:01"


def test_sonos_mac_from_friendly_name(enrich):
    mac = enrich.sonos_mac({"friendlyName": "Living Room - RINCON_B8E937ABCDEF01400"})
    assert mac == "b8:e9:37:ab:cd:ef"


def test_sonos_mac_none_for_non_sonos(enrich):
    assert enrich.sonos_mac({"UDN": "uuid:1234", "friendlyName": "Printer"}) is None
    assert enrich.sonos_mac({}) is None


# ───────────────────────── follow_upnp_location (urlopen mocked) ─────────────────────────

class _FakeResp:
    def __init__(self, body):
        self._body = body if isinstance(body, bytes) else body.encode()

    def read(self, n=-1):
        return self._body[:n] if n and n > 0 else self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _patch_urlopen(monkeypatch, body=None, exc=None):
    def _fake(req, timeout=None):
        if exc:
            raise exc
        return _FakeResp(body)
    monkeypatch.setattr(urllib.request, "urlopen", _fake)


def test_follow_upnp_location_extracts_fields(enrich, monkeypatch):
    xml = ("<root><device>"
           "<friendlyName>Office Printer</friendlyName>"
           "<manufacturer>Brother</manufacturer>"
           "<modelName>HL-L2350DW</modelName>"
           "<modelNumber>1</modelNumber>"
           "<UDN>uuid:abc-123</UDN>"
           "</device></root>")
    _patch_urlopen(monkeypatch, body=xml)
    info = enrich.follow_upnp_location("http://192.168.10.1/desc.xml")
    assert info == {"friendlyName": "Office Printer", "manufacturer": "Brother",
                    "modelName": "HL-L2350DW", "modelNumber": "1", "UDN": "uuid:abc-123"}


def test_follow_upnp_location_missing_tags(enrich, monkeypatch):
    _patch_urlopen(monkeypatch, body="<root><device><friendlyName>Only Name</friendlyName></device></root>")
    assert enrich.follow_upnp_location("http://192.168.10.1/d.xml") == {"friendlyName": "Only Name"}


def test_follow_upnp_location_network_error_returns_empty(enrich, monkeypatch):
    _patch_urlopen(monkeypatch, exc=OSError("boom"))
    assert enrich.follow_upnp_location("http://192.168.10.1/d.xml") == {}


def test_follow_upnp_location_malformed_xml_returns_empty(enrich, monkeypatch):
    _patch_urlopen(monkeypatch, body="<<<not xml at all>>>")
    assert enrich.follow_upnp_location("http://192.168.10.1/d.xml") == {}


# ───────────────────────── _own_url ─────────────────────────

def test_own_url(enrich):
    assert enrich._own_url("http://192.168.10.1/d.xml", "192.168.10.1") is True
    assert enrich._own_url("https://192.168.10.1:8443/d.xml", "192.168.10.1") is True
    assert enrich._own_url("http://evil.example/x", "192.168.10.1") is False      # not the responder
    assert enrich._own_url("ftp://192.168.10.1/x", "192.168.10.1") is False       # not http(s)
    assert enrich._own_url("::::", "192.168.10.1") is False                       # unparseable


# ───────────────────────── ssdp_discover (socket mocked) ─────────────────────────

class _FakeUDP:
    """A UDP socket whose recvfrom replays a queue of (data, addr), then times out."""
    def __init__(self, packets):
        self._packets = list(packets)

    def setsockopt(self, *a):
        pass

    def settimeout(self, *a):
        pass

    def sendto(self, *a):
        return len(a[0]) if a else 0

    def recvfrom(self, n):
        if self._packets:
            return self._packets.pop(0)
        raise socket.timeout("done")

    def close(self):
        pass


def test_ssdp_discover_parses_and_prefers_igd(enrich, monkeypatch):
    addr = ("192.168.10.1", 1900)
    media = ("HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:MediaServer:1\r\n"
             "SERVER: Linux/5 UPnP/1.0\r\nLOCATION: http://192.168.10.1/media.xml\r\n\r\n").encode()
    igd = ("HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
           "LOCATION: http://192.168.10.1/igd.xml\r\n\r\n").encode()
    monkeypatch.setattr(enrich.socket, "socket", lambda *a, **k: _FakeUDP([(media, addr), (igd, addr)]))
    found = enrich.ssdp_discover(timeout=1)
    entry = found["192.168.10.1"]
    assert entry["server"] == "Linux/5 UPnP/1.0"
    assert entry["location"] == "http://192.168.10.1/igd.xml"          # IGD location wins over media server
    assert "urn:schemas-upnp-org:device:InternetGatewayDevice:1" in entry["st"]


def test_ssdp_discover_rejects_foreign_location(enrich, monkeypatch):
    addr = ("192.168.10.2", 1900)
    pkt = ("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n"
           "LOCATION: http://10.0.0.5/desc.xml\r\n\r\n").encode()    # not the responder's own IP
    monkeypatch.setattr(enrich.socket, "socket", lambda *a, **k: _FakeUDP([(pkt, addr)]))
    entry = enrich.ssdp_discover(timeout=1)["192.168.10.2"]
    assert "location" not in entry


# ───────────────────────── _dn_value (TLS cert DN parsing) ─────────────────────────

def test_dn_value_plain(enrich):
    assert enrich._dn_value("subject=CN=nas,O=Acme") == "nas"
    assert enrich._dn_value("issuer=CN=My CA,O=Acme", "CN") == "My CA"


def test_dn_value_escaped_comma(enrich):
    # RFC2253: "\," is a literal comma inside the value, not a field separator
    assert enrich._dn_value(r"subject=O=Acme\, Inc,CN=nas", "O") == "Acme, Inc"


def test_dn_value_hex_escape(enrich):
    # "\C3\98" is two UTF-8 bytes (Ø)
    assert enrich._dn_value(r"subject=CN=\C3\98resund") == "Øresund"


def test_dn_value_absent(enrich):
    assert enrich._dn_value("subject=O=Acme") is None


# ───────────────────────── get_tls_cert (openssl stdout parsing) ─────────────────────────

def test_get_tls_cert_parses_openssl_output(enrich, monkeypatch):
    class _TLSSock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def getpeercert(self, binary_form=False):
            return b"DERBYTES"

    class _RawSock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Ctx:
        def wrap_socket(self, raw, **k):
            return _TLSSock()

    monkeypatch.setattr(enrich.socket, "create_connection", lambda *a, **k: _RawSock())
    monkeypatch.setattr(enrich, "_tls_context", lambda: _Ctx())
    monkeypatch.setattr(enrich.ssl, "DER_cert_to_PEM_cert", lambda der: "-----PEM-----")

    class _Proc:
        stdout = ("subject=CN=nas.local,O=Acme\n"
                  "issuer=CN=Acme Root CA\n"
                  "notBefore=Jan  1 00:00:00 2025 GMT\n"
                  "notAfter=Jan  1 00:00:00 2030 GMT\n"
                  "SHA256 Fingerprint=AA:BB:CC:DD\n"
                  "X509v3 Subject Alternative Name:\n"
                  "    DNS:nas.local, DNS:nas, IP Address:192.168.10.60\n")
    monkeypatch.setattr(enrich.subprocess, "run", lambda *a, **k: _Proc())

    out = enrich.get_tls_cert("192.168.10.60", 443)
    assert out["cn"] == "nas.local"
    assert out["issuer"] == "Acme Root CA"
    assert out["not_before"].startswith("Jan")
    assert out["not_after"].startswith("Jan")
    assert out["fingerprint"] == "aabbccdd"                 # colons stripped, lowercased
    assert out["sans"] == "nas.local,nas,192.168.10.60"


def test_get_tls_cert_empty_der_returns_empty(enrich, monkeypatch):
    class _TLSSock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def getpeercert(self, binary_form=False):
            return b""

    class _RawSock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(enrich.socket, "create_connection", lambda *a, **k: _RawSock())
    monkeypatch.setattr(enrich, "_tls_context", lambda: type("C", (), {"wrap_socket": lambda s, raw, **k: _TLSSock()})())
    assert enrich.get_tls_cert("192.168.10.60", 443) == {}


# ───────────────────────── grab_ssh_banner ─────────────────────────

class _BannerSock:
    def __init__(self, data):
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def settimeout(self, *a):
        pass

    def recv(self, n):
        return self._data


def test_grab_ssh_banner_picks_ssh_line(enrich, monkeypatch):
    monkeypatch.setattr(enrich.socket, "create_connection",
                        lambda *a, **k: _BannerSock(b"\r\nsome preamble\r\nSSH-2.0-OpenSSH_9.6\r\n"))
    assert enrich.grab_ssh_banner("192.168.10.70") == "SSH-2.0-OpenSSH_9.6"


def test_grab_ssh_banner_blank_lines_no_crash(enrich, monkeypatch):
    # regression (2026-10-26): blank-only reply used to raise IndexError and abort enrichment
    monkeypatch.setattr(enrich.socket, "create_connection", lambda *a, **k: _BannerSock(b"\r\n\r\n   \r\n"))
    assert enrich.grab_ssh_banner("192.168.10.70") is None


def test_grab_ssh_banner_connection_refused(enrich, monkeypatch):
    def _boom(*a, **k):
        raise OSError("refused")
    monkeypatch.setattr(enrich.socket, "create_connection", _boom)
    assert enrich.grab_ssh_banner("192.168.10.70") is None


# ───────────────────────── web_page (http_get mocked) ─────────────────────────

def test_web_page_title_and_server(enrich, monkeypatch):
    monkeypatch.setattr(common, "http_get",
                        lambda ip, port, **k: (200, {"server": "nginx/1.25"},
                                               "<html><head><title>  NAS   Login </title></head></html>"))
    info = enrich.web_page("192.168.10.80", 80, tls=False)
    assert info["status"] == 200
    assert info["server"] == "nginx/1.25"
    assert info["title"] == "NAS Login"                      # whitespace collapsed


def test_web_page_basic_auth_login(enrich, monkeypatch):
    monkeypatch.setattr(common, "http_get",
                        lambda ip, port, **k: (401, {"www-authenticate": 'Basic realm="x"'}, ""))
    info = enrich.web_page("192.168.10.80", 80, tls=False)
    assert info["login"] == "basic"


def test_web_page_form_login(enrich, monkeypatch):
    monkeypatch.setattr(common, "http_get",
                        lambda ip, port, **k: (200, {}, '<form><input type="password" name="pw"></form>'))
    assert enrich.web_page("192.168.10.80", 80, tls=False)["login"] == "form"


def test_web_page_redirect_title_followed(enrich, monkeypatch):
    calls = []

    def _http_get(ip, port, tls=False, path="/", timeout=4):
        calls.append(path)
        if path == "/":
            return (302, {"location": "/login"}, "")
        return (200, {}, "<title>Login Page</title>")
    monkeypatch.setattr(common, "http_get", _http_get)
    info = enrich.web_page("192.168.10.80", 80, tls=False)
    assert info["title"] == "Login Page"
    assert "/login" in calls


def test_web_page_no_answer_is_none(enrich, monkeypatch):
    monkeypatch.setattr(common, "http_get", lambda *a, **k: (None, {}, ""))
    assert enrich.web_page("192.168.10.80", 80, tls=False) is None


# ───────────────────────── ipv6_to_mac ─────────────────────────

def test_ipv6_to_mac_eui64(enrich):
    assert enrich.ipv6_to_mac("fe80::0211:22ff:fe33:4455") == "00:11:22:33:44:55"


def test_ipv6_to_mac_rejects_non_eui64(enrich):
    assert enrich.ipv6_to_mac("fe80::0211:2233:4455:6677") is None    # no ff:fe marker
    assert enrich.ipv6_to_mac("2001:db8::1") is None                  # not link-local
    assert enrich.ipv6_to_mac("garbage") is None
