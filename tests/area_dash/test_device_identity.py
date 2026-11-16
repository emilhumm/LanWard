"""Regression: the device page's identity chain (bug list in FRAMEWORK.md).

A host plus an mDNS observation whose TXT is {md:'WEBOS', model:'OLED65C9PLA', fv:'p20.05.50.00'}
must show the real model OLED65C9PLA (not the platform word WEBOS), an mDNS firmware line, and
"Runs: webOS"."""
import json


def _tv(db, make):
    tv_mac = "10:68:38:aa:bb:cc"
    sid = make.scan(host_count=1)
    make.host(sid, ip="192.168.10.30", mac=tv_mac, vendor="LG Electronics",
              hostname="LGwebOSTV", ports="http", open_ports="[80]", firmware="3.4.0")
    make.observation("mdns", tv_mac, ip="192.168.10.30",
                     details={"txt": {"md": "WEBOS", "model": "OLED65C9PLA", "fv": "p20.05.50.00"}})
    return tv_mac


def test_device_page_shows_real_model_not_platform(client, db, make):
    mac = _tv(db, make)
    html = client.get(f"/host/{mac}").get_data(as_text=True)
    assert "OLED65C9PLA" in html, "the real model is missing"
    # the chain row is labelled "mDNS model"; WEBOS must not masquerade as the model there
    assert "mDNS model:</span> OLED65C9PLA" in html or "OLED65C9PLA" in html


def test_device_page_shows_mdns_firmware_line(client, db, make):
    mac = _tv(db, make)
    html = client.get(f"/host/{mac}").get_data(as_text=True)
    assert "mDNS firmware" in html
    # the AirPlay "p20." protocol prefix is stripped
    assert "05.50.00" in html


def test_device_page_shows_runs_webos(client, db, make):
    mac = _tv(db, make)
    html = client.get(f"/host/{mac}").get_data(as_text=True)
    assert "webOS" in html
    assert "Runs" in html


def test_device_page_non_dict_txt_tolerated(client, db, make):
    """A legacy/corrupt non-dict mDNS txt must not break the page or surface a model."""
    mac = "10:68:38:00:00:01"
    sid = make.scan(host_count=1)
    make.host(sid, ip="192.168.10.31", mac=mac, vendor="LG Electronics", ports="http", open_ports="[80]")
    make.observation("mdns", mac, ip="192.168.10.31", details={"txt": "not-a-dict"})
    r = client.get(f"/host/{mac}")
    assert r.status_code == 200
