"""The remaining POST actions: gateway accept, alert ack, label set/delete, run-scan validation."""
import common


# ── gateway/accept ──

def test_gateway_accept_sets_baseline(post, db, populated):
    new_mac = "aa:bb:cc:00:00:02"
    r = post("/gateway/accept", {"mac": new_mac})
    assert r.status_code == 302
    assert common.kv_get(db, "gateway_mac") == new_mac


def test_gateway_accept_bad_mac_400(post):
    assert post("/gateway/accept", {"mac": "not-a-mac"}).status_code == 400


# ── alerts ack ──

def test_alert_ack(post, db, populated):
    aid = db.execute("SELECT id FROM alerts ORDER BY id LIMIT 1").fetchone()[0]
    r = post(f"/alerts/{aid}/ack")
    assert r.status_code == 302
    assert db.execute("SELECT acknowledged FROM alerts WHERE id=?", (aid,)).fetchone()[0] == 1


def test_alert_ack_all(post, db, populated):
    r = post("/alerts/ack-all")
    assert r.status_code == 302
    assert db.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0] == 0


# ── labels ──

def test_label_set_creates(post, db):
    r = post("/labels/set", {"mac": "24:5e:be:12:34:56", "label": "Office printer", "watch": "on"})
    assert r.status_code == 302
    row = db.execute("SELECT label, watch_offline FROM host_labels WHERE mac=?",
                     ("24:5e:be:12:34:56",)).fetchone()
    assert row["label"] == "Office printer" and row["watch_offline"] == 1


def test_label_set_empty_label_deletes(post, db, make):
    make.label("24:5e:be:12:34:56", "Temp")
    r = post("/labels/set", {"mac": "24:5e:be:12:34:56", "label": ""})
    assert r.status_code == 302
    assert db.execute("SELECT COUNT(*) FROM host_labels WHERE mac=?",
                      ("24:5e:be:12:34:56",)).fetchone()[0] == 0


def test_label_set_rejects_open_redirect(post):
    r = post("/labels/set", {"mac": "24:5e:be:12:34:56", "label": "x", "redirect_to": "//evil.example"})
    assert r.status_code == 400


def test_label_set_rejects_crlf_redirect(post):
    r = post("/labels/set", {"mac": "24:5e:be:12:34:56", "label": "x",
                             "redirect_to": "/ok\r\nSet-Cookie: x=1"})
    assert r.status_code == 400


def test_label_set_bad_mac_400(post):
    assert post("/labels/set", {"mac": "nope", "label": "x"}).status_code == 400


def test_label_delete(post, db, make):
    make.label("24:5e:be:12:34:56", "Gone")
    r = post("/labels/24:5e:be:12:34:56/delete")
    assert r.status_code == 302
    assert db.execute("SELECT COUNT(*) FROM host_labels WHERE mac=?",
                      ("24:5e:be:12:34:56",)).fetchone()[0] == 0


def test_label_delete_bad_mac_400(post):
    assert post("/labels/zzzz/delete").status_code == 400


# ── run scan: no user-supplied range any more; it scans the detected network (common.SUBNET) ──

def test_run_scan_without_a_known_network_shows_hint(post, monkeypatch):
    """No subnet found -> the POST does not launch anything and points at Settings."""
    import app, common
    monkeypatch.setattr(common, "SUBNET", "")
    monkeypatch.setattr(app, "_scan_proc", None)
    called = []
    monkeypatch.setattr(app.subprocess, "Popen", lambda *a, **k: called.append(a))
    r = post("/run-scan", {})
    assert r.status_code == 400
    assert b"Settings" in r.data
    assert called == []                       # nothing was launched


def test_scan_start_launches_a_scan_of_the_detected_subnet(post, monkeypatch):
    """The popup's Start posts here; it launches scan.py for common.SUBNET, ignoring any form input."""
    import app, common
    monkeypatch.setattr(common, "SUBNET", "192.168.50.0/24")
    monkeypatch.setattr(app, "is_scan_running", lambda: False)
    monkeypatch.setattr(app, "_scan_proc", None)
    seen = {}
    class FakePopen:
        def __init__(self, args, **kw):
            seen["args"] = list(args)
            self.pid = 4321
        def poll(self):
            return None
    monkeypatch.setattr(app.subprocess, "Popen", FakePopen)
    r = post("/scan/start", {"subnet": "8.8.8.0/24"})     # a hostile form value must be ignored
    assert r.status_code == 200
    assert "scan.py" in " ".join(seen["args"])
    assert "192.168.50.0/24" in seen["args"] and "8.8.8.0/24" not in seen["args"]


def test_scan_stop_kills_the_process_and_clears_the_lock(post, monkeypatch, tmp_path):
    """Stop the scan: terminate the process group named in the lock and remove the lock file."""
    import os
    import signal
    import app
    import common
    lock = tmp_path / "scan.lock"
    lock.write_text("98765\n/tmp/x.log\n192.168.1.0/24\n")
    monkeypatch.setattr(common, "SCAN_LOCK", lock)
    monkeypatch.setattr(app, "is_scan_running", lambda: False)
    monkeypatch.setattr(app, "_scan_proc", None)
    killed = []
    monkeypatch.setattr(os, "getpgid", lambda pid: pid, raising=False)
    monkeypatch.setattr(os, "killpg", lambda pgid, sig: killed.append((pgid, sig)), raising=False)
    r = post("/scan/stop", {})
    assert r.status_code == 200
    assert killed == [(98765, signal.SIGTERM)]       # the scan's process group got SIGTERM
    assert not lock.exists()                          # and the lock was cleared
