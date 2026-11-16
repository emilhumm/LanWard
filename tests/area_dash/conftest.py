"""Fixtures local to AREA D (dashboard/app.py + templates).

Only what the shared harness (tests/conftest.py) does not already give: a populated database the
route tests reuse, and an auth-enabled Flask client for the API-key / allow-list tests (the shared
`client` fixture deliberately strips auth away).
"""
import json

import pytest


# ───────────────────────────── a populated database ─────────────────────────────

@pytest.fixture
def populated(db, make):
    """A realistic snapshot: one scan with several hosts (findings JSON, upnp_info, web_info, mdns txt),
    a spread of observations, a label, a watched device, a couple of alerts and the kv a live box has.
    Returns {"scan_id": ...} and leaves `db`/`make` usable for extra rows."""
    import common

    gw_ip, gw_mac = "192.168.10.1", "aa:bb:cc:00:00:01"
    cam_mac = "24:5e:be:aa:bb:cc"
    tv_mac = "10:68:38:11:22:33"

    sid = make.scan(host_count=4)

    # router
    make.host(sid, ip=gw_ip, mac=gw_mac, vendor="AVM", hostname="fritz.box",
              ports="http,https", open_ports="[80,443]",
              web_info=json.dumps({"80": {"status": 200, "title": "FRITZ!Box", "tls": False}}))
    # a camera with a serious finding and a telnet port
    make.host(sid, ip="192.168.10.20", mac=cam_mac, vendor="Reolink", hostname="camera1",
              ports="rtsp,telnet,http", open_ports="[23,80,554]",
              findings=json.dumps([{"id": "telnet-open", "severity": "alert", "name": "Camera",
                                    "title": "Telnet is open", "detail": "Port 23 answers."}]),
              upnp_info=json.dumps({"friendlyName": "Front door camera", "modelName": "RLC-520"}),
              web_info=json.dumps({"80": {"status": 401, "title": "Login", "tls": False}}),
              tls_cert_cn="camera.local")
    # a webOS TV announcing itself over mDNS (identity regression lives on this one)
    make.host(sid, ip="192.168.10.30", mac=tv_mac, vendor="LG Electronics", hostname="LGwebOSTV",
              ports="http", open_ports="[80]", firmware="3.4.0")
    # an unlabelled private-MAC phone
    make.host(sid, ip="192.168.10.40", mac="a2:11:22:33:44:55", vendor=None, hostname=None)

    # observations across the sources the pages read
    make.observation("arp", gw_mac, ip=gw_ip)
    make.observation("arp", cam_mac, ip="192.168.10.20")
    make.observation("arp_req", cam_mac, ip=gw_ip, details={"own_ip": "192.168.10.20"})
    make.observation("dhcp", tv_mac, ip="0.0.0.0", hostname="LGwebOSTV",
                     details={"requested_ip": "192.168.10.30", "vendor_class": "webos"})
    make.observation("mdns", tv_mac, ip="192.168.10.30",
                     details={"txt": {"md": "WEBOS", "model": "OLED65C9PLA", "fv": "p20.05.50.00"},
                              "services_adv": ["_airplay._tcp", "_googlecast._tcp"],
                              "services_qry": ["_companion-link._tcp"]})
    make.observation("mdns", cam_mac, ip="192.168.10.20",
                     details={"services_adv": ["_rtsp._tcp"]})

    make.label(cam_mac, "Front door camera", note="porch", watch_offline=1)

    now = common.now_iso()
    db.execute("INSERT INTO alerts (created_at, scan_id, severity, title, details, kind) VALUES (?,?,?,?,?,?)",
               (now, sid, "alert", "Telnet is open", "- Port 23 answers\nmore detail", "finding"))
    db.execute("INSERT INTO alerts (created_at, scan_id, severity, title, details, kind) VALUES (?,?,?,?,?,?)",
               (now, sid, "info", "New device", "A new device appeared", "new_device"))
    db.commit()

    make.kv("gateway_ip", gw_ip)
    make.kv("gateway_mac", gw_mac)
    make.kv("homechecks_done", str(sid))
    make.kv("watcher_heartbeat", now)

    common._SETTINGS_CACHE["at"] = float("-inf")
    return {"scan_id": sid, "gw_mac": gw_mac, "cam_mac": cam_mac, "tv_mac": tv_mac, "gw_ip": gw_ip}


# ───────────────────────────── an auth-enabled client ─────────────────────────────

@pytest.fixture
def auth_client(db, make, monkeypatch):
    """A Flask test client with require_auth in force. The test env sets DASHBOARD_PASSWORD=off, which
    hard-disables login, so we flip that module flag off and turn the Settings tickbox on; a stored
    password then gates the dashboard. The known password is "secret"; the API key is common.api_key(db).
    Log in with auth_client.post("/login", {"password": "secret"}, headers={"Origin": "http://localhost"})."""
    import app
    import common

    monkeypatch.setattr(app, "AUTH_OFF_ENV", False)         # .env would otherwise turn login off in tests
    monkeypatch.setattr(app, "AUTH_PASSWORD", "")           # no env/default password: the stored one gates
    monkeypatch.setattr(app, "PW_IS_DEFAULT", False)
    make.kv("dashboard_password", app._hash_password("secret"))
    make.kv("require_password", "on")
    monkeypatch.setattr(app, "get_db", lambda: common.connect(), raising=False)

    funcs = app.app.before_request_funcs.setdefault(None, [])
    if app.require_auth not in funcs:
        funcs.append(app.require_auth)
    app.app.config["TESTING"] = True
    common._SETTINGS_CACHE["at"] = float("-inf")
    return app.app.test_client()


@pytest.fixture
def logged_in(auth_client):
    """auth_client with a live login cookie (signed in with the known password "secret")."""
    auth_client.post("/login", data={"password": "secret"}, headers={"Origin": "http://localhost"})
    return auth_client
