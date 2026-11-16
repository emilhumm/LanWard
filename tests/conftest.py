"""Shared pytest fixtures for the LanWard test suite.

Everything runs on a throwaway SQLite database and with the network blocked, so the suite is safe to
run anywhere (Windows included) and never touches the real LAN or a machine running LanWard. See
tests/FRAMEWORK.md for the plan each test area follows.
"""
import json
import os
import socket
import sys
import tempfile
import types
from pathlib import Path

import pytest

# ── Windows: scan.py / watcher.py / passive-monitor.py import fcntl, which only exists on Unix ──
sys.modules.setdefault("fcntl", types.ModuleType("fcntl"))

REPO = Path(__file__).resolve().parents[1]
for _p in (REPO / "dashboard", REPO / "db", REPO):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

# Point LanWard at a throwaway data dir BEFORE common is imported anywhere (common reads LANWARD_DATA,
# DASHBOARD_PASSWORD etc. at import time). Each test still gets its own fresh DB via the `db` fixture.
_BASE = Path(tempfile.mkdtemp(prefix="lanward-tests-"))
os.environ["LANWARD_DATA"] = str(_BASE)
os.environ["DASHBOARD_PASSWORD"] = "off"
os.environ.setdefault("HA_WEBHOOK_URL", "http://192.0.2.1/never")


# ───────────────────────────── network isolation ─────────────────────────────

@pytest.fixture(autouse=True)
def _block_network(monkeypatch):
    """Fail loudly if a test reaches for the real network. Tests that exercise an HTTP/subprocess path
    mock the specific helper (common.http_get, scan.run_nmap, ...) themselves."""
    def _no_connect(*a, **k):
        raise RuntimeError("network blocked in tests — mock the call instead")
    monkeypatch.setattr(socket.socket, "connect", _no_connect, raising=False)
    import common
    monkeypatch.setattr(common, "http_get", lambda *a, **k: (None, {}, ""), raising=False)
    monkeypatch.setattr(common, "http_json", lambda *a, **k: (None, None), raising=False)
    # What is behind a new port (portid.py): the version check runs nmap and the RPC question opens a socket
    import portid
    monkeypatch.setattr(portid, "version_check", lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(portid, "rpc_directory", lambda *a, **k: {}, raising=False)


# ───────────────────────────── database ─────────────────────────────

@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    """A fresh per-test data directory; common.DATA_DIR / DB_PATH are pointed at it."""
    import common
    d = tmp_path / "data"
    d.mkdir()
    monkeypatch.setattr(common, "DATA_DIR", d)
    monkeypatch.setattr(common, "DB_PATH", d / "scanner.db")
    common._SETTINGS_CACHE["at"] = float("-inf")           # drop any cached page settings
    return d


@pytest.fixture
def db(data_dir):
    """A migrated, empty scanner.db on the per-test data dir."""
    import common
    conn = common.connect()
    common.migrate(conn)
    conn.commit()
    yield conn
    conn.close()


# ───────────────────────────── row factories ─────────────────────────────

@pytest.fixture
def make(db):
    """Tiny builders for scans / hosts / observations / alerts, returning the ids they create.
    Only the columns a test cares about need to be passed; the rest take sensible defaults."""
    import common

    class Factory:
        def scan(self, subnet="192.168.10.0/24", started_at=None, host_count=None, notes="lanward test"):
            cur = db.execute("INSERT INTO scans (subnet, started_at, host_count, notes) VALUES (?,?,?,?)",
                             (subnet, started_at or common.now_iso(), host_count, notes))
            db.commit()
            return cur.lastrowid

        def host(self, scan_id, ip="192.168.10.50", mac="aa:bb:cc:dd:ee:ff", **cols):
            cols.setdefault("vendor", "Test Vendor")
            keys = ["scan_id", "ip", "mac", *cols.keys()]
            vals = [scan_id, ip, mac, *cols.values()]
            db.execute(f"INSERT INTO hosts ({','.join(keys)}) VALUES ({','.join('?' * len(keys))})", vals)
            db.commit()

        def observation(self, source, mac, ip=None, hostname=None, vendor=None, details=None,
                        first_seen=None, last_seen=None, count=1):
            now = common.now_iso()
            db.execute("INSERT INTO observations (source, mac, ip, hostname, vendor, details, first_seen, "
                       "last_seen, count) VALUES (?,?,?,?,?,?,?,?,?)",
                       (source, mac, ip, hostname, vendor,
                        json.dumps(details) if isinstance(details, (dict, list)) else details,
                        first_seen or now, last_seen or now, count))
            db.commit()

        def label(self, mac, label, note="", watch_offline=0):
            now = common.now_iso()
            db.execute("INSERT INTO host_labels (mac, label, note, watch_offline, created_at, updated_at) "
                       "VALUES (?,?,?,?,?,?)", (mac, label, note, watch_offline, now, now))
            db.commit()

        def kv(self, key, value):
            common.kv_set(db, key, value)
            db.commit()

    return Factory()


# ───────────────────────────── dashboard client ─────────────────────────────

@pytest.fixture
def client(db, monkeypatch):
    """A Flask test client with auth removed. Use client.post(...) via the `post` helper for same-origin."""
    import app
    monkeypatch.setattr(app, "get_db", lambda: __import__("common").connect(), raising=False)
    try:
        app.app.before_request_funcs[None].remove(app.require_auth)
    except (KeyError, ValueError):
        pass
    app.app.config["TESTING"] = True
    return app.app.test_client()


@pytest.fixture
def post(client):
    """POST to a dashboard route with the same-origin header the app requires."""
    def _post(path, data=None, **kw):
        headers = kw.pop("headers", {})
        headers.setdefault("Origin", "http://localhost")
        return client.post(path, data=data or {}, headers=headers, **kw)
    return _post
