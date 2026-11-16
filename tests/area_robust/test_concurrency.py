"""Area F — concurrency / locking.

LanWard runs several processes against one SQLite file (scanner.db) in WAL mode: the scanner, the
passive monitor, the watcher and the dashboard. These tests check that writers do not raise
"database is locked" on the normal paths, that migrate() survives another open connection, and that
the scan-lock file convention and is_scan_running() stay well-behaved. Everything is deterministic:
no real sleeps, and any thread is joined and its exception re-raised (FRAMEWORK.md, dimension 8).
"""
import threading

import common


# ───────────────────── WAL writers ─────────────────────

def test_two_connections_write_under_wal(db):
    """Two independent connections writing (committing between writes) do not raise."""
    c1 = common.connect()
    c2 = common.connect()
    try:
        assert c1.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        c1.execute("BEGIN IMMEDIATE")
        c1.execute("INSERT INTO kv (key, value, updated_at) VALUES ('a', '1', ?)", (common.now_iso(),))
        c1.commit()
        c2.execute("BEGIN IMMEDIATE")
        c2.execute("INSERT INTO kv (key, value, updated_at) VALUES ('b', '2', ?)", (common.now_iso(),))
        c2.commit()
        assert {r[0] for r in c1.execute("SELECT key FROM kv WHERE key IN ('a','b')")} == {"a", "b"}
    finally:
        c1.close()
        c2.close()


def test_reader_sees_committed_during_other_write(db):
    """WAL: a reader is never blocked by an open writer; it just sees the last commit."""
    writer = common.connect()
    reader = common.connect()
    try:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("INSERT INTO kv (key, value, updated_at) VALUES ('pending', 'x', ?)",
                       (common.now_iso(),))
        # reader must not hang or error while the writer holds the lock
        assert reader.execute("SELECT COUNT(*) FROM kv").fetchone()[0] >= 0
        writer.commit()
    finally:
        writer.close()
        reader.close()


def test_write_alert_from_two_connections(db):
    """common.write_alert (its own BEGIN IMMEDIATE + commit) from two connections, back to back,
    does not deadlock and both alerts land. Pushing is off (no destinations configured)."""
    c1 = common.connect()
    c2 = common.connect()
    try:
        assert common.write_alert(c1, "warning", "one", push=False) is True
        assert common.write_alert(c2, "warning", "two", push=False) is True
        assert db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 2
    finally:
        c1.close()
        c2.close()


def test_concurrent_writers_threaded(db):
    """Two threads each insert a batch of kv rows; with busy_timeout each waits rather than erroring.
    Threads are joined and any exception is surfaced."""
    errors = []

    def worker(prefix):
        conn = common.connect()
        try:
            for i in range(25):
                conn.execute("INSERT INTO kv (key, value, updated_at) VALUES (?, ?, ?)",
                             (f"{prefix}:{i}", str(i), common.now_iso()))
                conn.commit()
        except Exception as e:                  # noqa: BLE001 - report, don't swallow
            errors.append(e)
        finally:
            conn.close()

    t1 = threading.Thread(target=worker, args=("t1",))
    t2 = threading.Thread(target=worker, args=("t2",))
    t1.start(); t2.start()
    t1.join(30); t2.join(30)
    assert not t1.is_alive() and not t2.is_alive()
    assert not errors, f"writer raised: {errors}"
    assert db.execute("SELECT COUNT(*) FROM kv WHERE key LIKE 't1:%' OR key LIKE 't2:%'").fetchone()[0] == 50


# ───────────────────── migrate() under load ─────────────────────

def test_migrate_while_another_connection_open(db):
    """migrate() on a second connection while the first is open must not raise (the WAL pragma that
    might fail busy is caught; the rest runs)."""
    other = common.connect()
    try:
        other.execute("INSERT INTO kv (key, value, updated_at) VALUES ('held', '1', ?)",
                      (common.now_iso(),))
        other.commit()
        fresh = common.connect()
        try:
            common.migrate(fresh)               # must complete cleanly
            assert fresh.execute("SELECT value FROM kv WHERE key='held'").fetchone()[0] == "1"
        finally:
            fresh.close()
    finally:
        other.close()


# NOTE: migrate() against a connection while ANOTHER connection holds a write transaction open the
# whole time does raise "database is locked" — but that is inherent SQLite WAL single-writer
# behaviour, not a LanWard defect: migrate runs at process startup, where writers hold the lock only
# briefly and busy_timeout (30 s) absorbs the contention. The realistic case (an idle open
# connection) is covered by test_migrate_while_another_connection_open above, so we do not assert the
# pathological held-lock case here.


# ───────────────────── the scan lock ─────────────────────

def test_scan_lock_file_round_trips(db):
    """scan.py writes "pid\\nlog\\nsubnet" to common.SCAN_LOCK; is_scan_running() and scan-status read
    the first line as the pid. A bogus pid (no such /proc) reads back as not-running, never a crash."""
    import app
    common.SCAN_LOCK.parent.mkdir(parents=True, exist_ok=True)
    common.SCAN_LOCK.write_text("999999\n/tmp/scan.log\n192.168.10.0/24\n")
    assert common.SCAN_LOCK.read_text().split("\n", 1)[0] == "999999"
    # no live process with that pid -> not running; on Windows there is no /proc at all
    assert app.is_scan_running() is False


def test_is_scan_running_tolerates_junk_lock(db):
    """A corrupt lock file must not make is_scan_running() raise."""
    import app
    common.SCAN_LOCK.parent.mkdir(parents=True, exist_ok=True)
    for junk in ("", "not-a-pid\n", "\n\n\n", "garbage"):
        common.SCAN_LOCK.write_text(junk)
        assert app.is_scan_running() is False


def test_is_scan_running_without_lock(db):
    """No lock file at all -> not running."""
    import app
    if common.SCAN_LOCK.exists():
        common.SCAN_LOCK.unlink()
    assert app.is_scan_running() is False
