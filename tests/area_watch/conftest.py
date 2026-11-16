"""Fixtures local to AREA E (watcher / alerts / activity / retention / backup).

Nothing here touches the real network or box. `alert_spy` records every call the code makes to
common.write_alert (so we can assert the severity / push / force_push the code *decided* on) while
still exercising the real dedupe path -- but it forces the actual push off, so the blocked network
is never reached. See tests/FRAMEWORK.md.
"""
import json
from datetime import datetime, timedelta

import pytest

import common


# ───────────────────────── alert capture ─────────────────────────

@pytest.fixture
def alert_spy(monkeypatch):
    """Wrap common.write_alert: record each call, delegate to the real one with push forced off.

    The real write_alert still runs (it inserts the alert row and records the dedupe key), so
    `is_new` / dedupe behaviour is exercised for real; only the network push is suppressed.
    `alert_spy.calls` is a list of dicts; `alert_spy.titles` the titles in order.
    """
    orig = common.write_alert
    calls = []

    def spy(conn, severity, title, details="", *, push=True, force_push=False, **kw):
        calls.append({"severity": severity, "title": title, "details": details,
                      "push": push, "force_push": force_push, **kw})
        return orig(conn, severity, title, details, push=False, force_push=False, **kw)

    monkeypatch.setattr(common, "write_alert", spy)
    spy.calls = calls
    spy.titles = [c["title"] for c in calls]   # note: snapshot, use [c['title'] for c in spy.calls]
    return spy


# ───────────────────────── settings helper ─────────────────────────

@pytest.fixture
def set_setting(db):
    """Save a Settings-page value and drop the 5 s settings cache so setting() sees it at once."""
    def _set(name, value):
        common.kv_set(db, f"setting:{name}", value)
        db.commit()
        common._SETTINGS_CACHE["at"] = float("-inf")
    return _set


# ───────────────────────── a plain host dict ─────────────────────────

@pytest.fixture
def host():
    """Build a host mapping with the columns the alert helpers read. The alert functions index rows
    by name (r["mac"], r["web_info"], ...), which a plain dict supports, so tests can pass these
    straight in without inserting a scan."""
    def _host(**over):
        base = {"scan_id": 1, "ip": "192.168.10.50", "mac": "aa:bb:cc:dd:ee:01",
                "vendor": "Acme", "hostname": None, "findings": "[]", "new_ports": "[]",
                "web_info": "{}", "firmware": None, "bridge_mac": None}
        base.update(over)
        if isinstance(base["findings"], (list, dict)):
            base["findings"] = json.dumps(base["findings"])
        if isinstance(base["web_info"], (dict, list)):
            base["web_info"] = json.dumps(base["web_info"])
        if isinstance(base["new_ports"], (list, dict)):
            base["new_ports"] = json.dumps(base["new_ports"])
        return base
    return _host


# ───────────────────────── time helpers (as fixtures, no cross-module import) ─────────────────────────

@pytest.fixture
def ago():
    """ago(days=400) -> ISO local time that far in the past."""
    def _ago(**delta):
        return (datetime.now() - timedelta(**delta)).isoformat(timespec="seconds")
    return _ago


@pytest.fixture
def set_memory(db):
    """set_memory(key, last_at): force an alert_memory row so is_new() sees `key` last alerted then."""
    def _set(key, last_at):
        db.execute("INSERT INTO alert_memory (key, first_at, last_at) VALUES (?, ?, ?) "
                   "ON CONFLICT(key) DO UPDATE SET last_at = excluded.last_at", (key, last_at, last_at))
        db.commit()
    return _set
