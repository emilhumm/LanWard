#!/usr/bin/env bash
# Online consistent SQLite backup of LanWard's scanner.db to a share or disk
# mounted at /mnt/router-backup (SMB, NFS, USB...). Survives writes-in-flight from the running
# passive monitor (uses sqlite3 .backup, not raw cp).
#
# The copy is checked (PRAGMA quick_check, gzip -t) and compressed in /tmp, and
# lands on the share as .part first, then is renamed: a failed or interrupted
# run (say, the share's disk is full) leaves no truncated backup behind.
#
# Invoked by the lanward-backup.timer systemd unit (daily 02:30).
set -euo pipefail

DB=/srv/lanward/data/scanner.db
MNT=/mnt/router-backup
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
TS=$(date +%Y%m%d-%H%M%S)

log() { echo "[$(date -Iseconds)] $*"; }

[[ -f "$DB" ]] || { log "FATAL: $DB not found"; exit 1; }
mountpoint -q "$MNT" || { log "FATAL: $MNT is not a mountpoint (share down?)"; exit 1; }

TMP=$(mktemp /tmp/scanner-backup.XXXXXX.db)
DEST="$MNT/scanner-${TS}.db.gz"
trap 'rm -f "$TMP" "$TMP.gz" "$DEST.part"' EXIT

log "Online backup of $DB → $TMP"
sqlite3 "$DB" ".backup '$TMP'"
CHECK=$(sqlite3 "$TMP" "PRAGMA quick_check;")
[[ "$CHECK" == "ok" ]] || { log "FATAL: quick_check on the copy says: $CHECK"; exit 1; }
SIZE=$(du -h "$TMP" | cut -f1)
log "Local snapshot complete and checked ($SIZE), compressing + copying to share"

gzip -9 -c "$TMP" > "$TMP.gz"
gzip -t "$TMP.gz"
cp "$TMP.gz" "$DEST.part"
mv "$DEST.part" "$DEST"
DEST_SIZE=$(du -h "$DEST" | cut -f1)
log "Wrote $DEST ($DEST_SIZE)"

log "Pruning backups older than ${RETENTION_DAYS} days"
PRUNED=$(find "$MNT" -maxdepth 1 -name "scanner-*.db.gz" -mtime "+${RETENTION_DAYS}" -print -delete | wc -l)
log "Pruned $PRUNED old backup(s)"

# A short tail of what's on the share, for the journal
log "Current backups on share:"
ls -lh "$MNT"/scanner-*.db.gz 2>/dev/null | tail -10 | sed 's/^/    /'
log "Done."
