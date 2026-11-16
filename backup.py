#!/usr/bin/env python3
"""Nightly copy of scanner.db inside the container (2026-10-27), so an install needs no
systemd units or sudo: an online SQLite backup (safe while the passive monitor writes),
checked with PRAGMA quick_check, gzipped into $LANWARD_DATA/backups/ as .part and then
renamed, so a failed run leaves no broken copy. Copies older than BACKUP_KEEP_DAYS go;
BACKUP_KEEP_DAYS=0 turns the job off (docker/entrypoint.py runs it daily at 03:30).

To keep copies on another disk or a NAS, sync that folder, or mount one there in
docker-compose.yml. The original install also has backup/backup-db.sh, a systemd timer
that copies to an SMB share.
"""
import gzip
import shutil
import sqlite3
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

import common
from common import log

KEEP_DAYS = int(common.setting("BACKUP_KEEP_DAYS") or 14)     # Settings page or .env
DEST = common.DATA_DIR / "backups"


def backup():
    DEST.mkdir(parents=True, exist_ok=True)
    final = DEST / f"scanner-{datetime.now():%Y%m%d-%H%M%S}.db.gz"
    part = final.with_name(final.name + ".part")
    with tempfile.TemporaryDirectory(dir=common.DATA_DIR) as tmp:
        snap = Path(tmp) / "scanner.db"
        src, dst = common.connect(), sqlite3.connect(str(snap))
        try:
            src.backup(dst)
            check = dst.execute("PRAGMA quick_check").fetchone()[0]
        finally:
            dst.close()
            src.close()
        if check != "ok":
            log(f"[!] backup: quick_check on the copy says {check!r}; nothing written")
            return 1
        try:
            with open(snap, "rb") as f, gzip.open(part, "wb", compresslevel=9) as out:
                shutil.copyfileobj(f, out)
            with gzip.open(part, "rb") as f:            # gzip -t
                while f.read(1 << 20):
                    pass
            part.rename(final)
        finally:
            part.unlink(missing_ok=True)
    log(f"[*] backup: {final.name} ({final.stat().st_size / 1e6:.1f} MB)")
    cutoff = time.time() - KEEP_DAYS * 86400
    for old in DEST.glob("scanner-*.db.gz"):
        if old.stat().st_mtime < cutoff:
            old.unlink()
            log(f"    removed {old.name} (older than {KEEP_DAYS} days)")
    return 0


if __name__ == "__main__":
    if KEEP_DAYS <= 0:
        log("[*] backup: off (BACKUP_KEEP_DAYS=0)")
        sys.exit(0)
    sys.exit(backup())
