"""AREA E - backup.py: nightly online SQLite copy, quick_check, gzip, rotation (keep N days)."""
import gzip
import os
import time
from datetime import datetime, timedelta

import pytest

import backup
import common


def test_backup_creates_checked_gzip(db, data_dir, monkeypatch):
    dest = data_dir / "backups"
    monkeypatch.setattr(backup, "DEST", dest)
    assert backup.backup() == 0
    copies = list(dest.glob("scanner-*.db.gz"))
    assert len(copies) == 1
    assert not list(dest.glob("*.part"))           # no broken leftover
    # The gzip is valid and holds a real SQLite file.
    with gzip.open(copies[0], "rb") as f:
        assert f.read(16).startswith(b"SQLite format 3")


def test_backup_rotation_drops_old_copies(db, data_dir, monkeypatch):
    dest = data_dir / "backups"
    dest.mkdir(parents=True, exist_ok=True)
    stale = dest / "scanner-20200101-000000.db.gz"
    fresh = dest / "scanner-20260101-000000.db.gz"
    for p in (stale, fresh):
        p.write_bytes(b"old")
    old_mtime = (datetime.now() - timedelta(days=30)).timestamp()
    recent_mtime = (datetime.now() - timedelta(hours=1)).timestamp()
    os.utime(stale, (old_mtime, old_mtime))
    os.utime(fresh, (recent_mtime, recent_mtime))
    monkeypatch.setattr(backup, "DEST", dest)
    monkeypatch.setattr(backup, "KEEP_DAYS", 14)
    assert backup.backup() == 0
    names = {p.name for p in dest.glob("scanner-*.db.gz")}
    assert "scanner-20200101-000000.db.gz" not in names    # older than 14 days -> removed
    assert "scanner-20260101-000000.db.gz" in names        # within 14 days -> kept
    assert len([n for n in names]) >= 2                    # the fresh one + the new backup


def test_backup_quick_check_failure_writes_nothing(db, data_dir, monkeypatch):
    dest = data_dir / "backups"
    monkeypatch.setattr(backup, "DEST", dest)

    class FakeCur:
        def fetchone(self):
            return ("malformed",)

    class FakeDst:                              # the copy: its quick_check says "malformed"
        def execute(self, *a, **k):
            return FakeCur()

        def close(self):
            pass

    class FakeSrc:                              # the source: its online backup is a no-op here
        def backup(self, dst, **k):
            pass

        def close(self):
            pass

    monkeypatch.setattr(backup.sqlite3, "connect", lambda *a, **k: FakeDst())
    monkeypatch.setattr(common, "connect", lambda *a, **k: FakeSrc())
    assert backup.backup() == 1                 # quick_check != "ok"
    assert not list(dest.glob("scanner-*.db.gz"))
    assert not list(dest.glob("*.part"))
