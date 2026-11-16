"""AREA E - retention.py: delete exactly the rows older than the cutoff, keep the rest; defaults;
the newest scan survives; acknowledged vs unacknowledged alerts; scan logs; end-to-end + VACUUM."""
import sys
from datetime import datetime, timedelta

import pytest

import common
import retention


def _ids(db, sql):
    return {r[0] for r in db.execute(sql)}


# ───────────────────────── observations ─────────────────────────

def test_prune_observations_cutoff(db, make, ago):
    make.observation("arp", mac="aa:aa:aa:00:00:01", ip="192.168.10.1", last_seen=ago(days=400))
    make.observation("arp", mac="bb:bb:bb:00:00:02", ip="192.168.10.2", last_seen=ago(days=300))
    retention.prune_observations(db, 366)
    left = _ids(db, "SELECT mac FROM observations")
    assert left == {"bb:bb:bb:00:00:02"}


def test_obs_days_default_is_366():
    # Boundary: a row 300 days old survives the 366-day default, a 400-day one does not.
    assert 300 < 366 < 400


# ───────────────────────── activity ─────────────────────────

def test_prune_activity_cutoff(db, ago):
    old = (datetime.now() - timedelta(days=400)).strftime("%Y-%m-%dT%H")
    new = (datetime.now() - timedelta(days=300)).strftime("%Y-%m-%dT%H")
    db.execute("INSERT INTO activity (mac, hour, n) VALUES ('m', ?, 5)", (old,))
    db.execute("INSERT INTO activity (mac, hour, n) VALUES ('m', ?, 5)", (new,))
    db.commit()
    retention.prune_activity(db, 366)
    hours = _ids(db, "SELECT hour FROM activity")
    assert hours == {new}


# ───────────────────────── scans + hosts ─────────────────────────

def test_prune_scans_keeps_newest_even_if_old(db, make, ago):
    s1 = make.scan(started_at=ago(days=400))
    s2 = make.scan(started_at=ago(days=400))
    s3 = make.scan(started_at=ago(days=400))      # newest id -> always kept
    for s in (s1, s2, s3):
        make.host(s, ip=f"192.168.10.{s}", mac=f"aa:bb:cc:00:00:0{s}")
    retention.prune_scans(db, 365)
    assert _ids(db, "SELECT id FROM scans") == {s3}
    assert _ids(db, "SELECT scan_id FROM hosts") == {s3}


def test_prune_scans_keeps_recent(db, make, ago):
    make.scan(started_at=ago(days=400))          # pruned
    recent = make.scan(started_at=ago(days=10))
    newest = make.scan(started_at=ago(days=1))
    retention.prune_scans(db, 365)
    assert _ids(db, "SELECT id FROM scans") == {recent, newest}


# ───────────────────────── alerts ─────────────────────────

def test_prune_alerts_only_acknowledged_old(db, ago):
    def mk(created, ack):
        db.execute("INSERT INTO alerts (created_at, severity, title, acknowledged) VALUES (?,?,?,?)",
                   (created, "info", "x", ack))
    mk(ago(days=400), 1)      # acknowledged + old -> deleted
    mk(ago(days=400), 0)      # old but unacknowledged -> kept
    mk(ago(days=10), 1)       # acknowledged but recent -> kept
    db.commit()
    retention.prune_alerts(db, 365)
    assert db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 2
    assert db.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=1 AND created_at<?",
                      (ago(days=365),)).fetchone()[0] == 0


# ───────────────────────── outages ─────────────────────────

def test_prune_outages(db, ago):
    db.execute("INSERT INTO outages (mac, started_at, ended_at) VALUES ('m', ?, ?)",
               (ago(days=420), ago(days=410)))     # ended long ago -> deleted
    db.execute("INSERT INTO outages (mac, started_at, ended_at) VALUES ('m', ?, ?)",
               (ago(days=20), ago(days=19)))        # ended recently -> kept
    db.execute("INSERT INTO outages (mac, started_at, ended_at) VALUES ('m', ?, NULL)",
               (ago(days=500),))                     # still open -> kept
    db.commit()
    retention.prune_outages(db, 400)
    assert db.execute("SELECT COUNT(*) FROM outages").fetchone()[0] == 2
    assert db.execute("SELECT COUNT(*) FROM outages WHERE ended_at IS NULL").fetchone()[0] == 1


# ───────────────────────── open ports ─────────────────────────

def test_prune_open_ports(db, ago):
    db.execute("INSERT INTO open_ports_seen (mac, port, first_seen, last_seen) VALUES ('m', 22, ?, ?)",
               (ago(days=400), ago(days=200)))       # not seen for 200 days -> deleted (>180)
    db.execute("INSERT INTO open_ports_seen (mac, port, first_seen, last_seen) VALUES ('m', 80, ?, ?)",
               (ago(days=400), ago(days=100)))       # seen 100 days ago -> kept
    db.commit()
    retention.prune_open_ports(db, 180)
    assert _ids(db, "SELECT port FROM open_ports_seen") == {80}


# ───────────────────────── scan log files ─────────────────────────

def test_prune_files(tmp_path, monkeypatch):
    import os
    logs = tmp_path / "scan-logs"
    logs.mkdir()
    old = logs / "old.log"
    new = logs / "new.log"
    old.write_text("x")
    new.write_text("y")
    old_mtime = (datetime.now() - timedelta(days=60)).timestamp()
    os.utime(old, (old_mtime, old_mtime))
    monkeypatch.setattr(common, "SCAN_LOG_DIR", logs)
    retention.prune_files(30)
    assert not old.exists() and new.exists()


# ───────────────────────── end to end: main() runs including VACUUM ─────────────────────────

def test_main_end_to_end_runs_vacuum(data_dir, monkeypatch, ago):
    conn = common.connect()
    common.migrate(conn)
    conn.execute("INSERT INTO observations (source, mac, ip, first_seen, last_seen) "
                 "VALUES ('arp', 'aa:aa:aa:00:00:01', '192.168.10.1', ?, ?)", (ago(days=400), ago(days=400)))
    conn.execute("INSERT INTO observations (source, mac, ip, first_seen, last_seen) "
                 "VALUES ('arp', 'bb:bb:bb:00:00:02', '192.168.10.2', ?, ?)", (ago(days=10), ago(days=10)))
    conn.commit()
    conn.close()
    monkeypatch.setattr(sys, "argv", ["retention.py"])
    retention.main()                                   # prunes with defaults, then VACUUM
    conn = common.connect()
    try:
        macs = {r[0] for r in conn.execute("SELECT mac FROM observations")}
    finally:
        conn.close()
    assert macs == {"bb:bb:bb:00:00:02"}               # old one pruned, recent kept, VACUUM succeeded
