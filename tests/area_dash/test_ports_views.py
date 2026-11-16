"""The device page's "Open ports", Traffic's "What's running", the ports CSV and APIs (2026-11-02)."""
import common


def _ports(db, mac, rows):
    """Port history rows: (port, first_seen, last_seen, what, how, sure, moved_to, moved_from)."""
    db.executemany("INSERT INTO open_ports_seen (mac, port, first_seen, last_seen, what, how, sure, moved_to, moved_from) "
                   "VALUES (?,?,?,?,?,?,?,?,?)", [(mac, *r) for r in rows])
    db.commit()


def _history(db, populated):
    cam, base = populated["cam_mac"], common.iso_ago(days=20)
    now, earlier = common.now_iso(), common.iso_ago(days=2)
    db.execute("INSERT INTO port_checks (mac, full_checked_at, full_tried_at, first_full_at) VALUES (?,?,?,?)",
               (cam, now, now, base))
    _ports(db, cam, [
        (23, base, now, "Telnet login", "its own answer to a light check", 1, None, None),
        (80, base, now, 'a web page, "Login"', "its web page", 1, None, None),
        (554, base, now, "camera or media stream (RTSP)", "the usual service on that port number; the port didn't say", 0, None, None),
        (44913, common.iso_ago(hours=3), now, None, None, None, None, "43123"),
        (43123, base, earlier, "a web server (aiohttp)", "its web page", 1, "44913", None),
    ])
    return cam


def test_device_page_lists_open_ports_with_how_lanward_knows(client, db, populated):
    cam = _history(db, populated)
    html = client.get(f"/host/{cam}").get_data(as_text=True)
    assert "Open ports" in html
    assert "from its own answer to a light check" in html
    assert "probably camera or media stream (RTSP)" in html and "a guess: the usual service on that number" in html
    assert "Moved here from 43123 after a restart" in html
    assert "Closed in the last 30 days" in html and "it came back on 44913" in html
    assert "New " in html                                             # 44913 opened after the baseline, this week


def test_running_groups_ports_by_what_they_are(client, db, populated):
    _history(db, populated)
    html = client.get("/traffic/running").get_data(as_text=True)
    assert "What&#39;s running" in html or "What's running" in html
    assert "Remote access" in html and "Telnet login" in html          # 23 on the camera
    assert "Web pages" in html
    assert "Smart home and devices" in html                           # the RTSP guess
    assert "Not identified" in html                                   # the TV's port 80 has no answer stored


def test_ports_csv_is_every_port_in_the_history(client, db, populated):
    _history(db, populated)
    r = client.get("/traffic/running?format=csv")
    assert r.status_code == 200 and r.mimetype == "text/csv"
    text = r.get_data(as_text=True)
    assert text.splitlines()[0].startswith("Device,MAC,IP,Kind,Port,Open now,What it is,How LanWard knows")
    assert "Telnet login" in text and "43123" in text and "Front door camera" in text


def test_api_ports_and_devices_say_what_each_port_is(client, db, populated):
    cam = _history(db, populated)
    ports = client.get("/api/ports").get_json()["ports"]
    telnet = next(p for p in ports if p["mac"] == cam and p["port"] == 23)
    assert telnet["what"] == "Telnet login" and telnet["open_now"] is True and telnet["group"] == "Remote access"
    moved = next(p for p in ports if p["port"] == 43123)
    assert moved["open_now"] is False and moved["moved_to"] == "44913"
    devices = client.get("/api/devices").get_json()["devices"]
    camera = next(d for d in devices if d["mac"] == cam)
    assert {"port": 23, "what": "Telnet login", "how": "its own answer to a light check"} in camera["services"]


def test_settings_offers_the_ports_export(client, populated):
    html = client.get("/settings").get_data(as_text=True)
    assert "Ports and services" in html and "/traffic/running?format=csv" in html
