#!/usr/bin/env bash
# Deploy LanWard from a working copy to another machine over ssh, into the
# layout install/install.sh makes there (code in /srv/lanward/code, compose
# files in /srv/lanward). Not needed for a plain install, which runs
# `docker compose up -d` in its git clone (README.md).
#
# The target is REMOTE_HOST (user@host, with key-based ssh), from the
# environment or from .deploy.env next to this script (git-ignored):
#   REMOTE_HOST=me@192.168.1.50
#
# Run from the project root (bash; on Windows Git Bash, not PowerShell):
#   bash deploy.sh               # sync code + infra files, then restart the container
#   bash deploy.sh --build       # same, and rebuild the image first (Dockerfile changed)
#   bash deploy.sh --no-restart  # sync only (first install, before /srv/lanward exists)
#   bash deploy.sh --force       # deploy even if a scan is running (the restart kills it)
#
# Without --force nothing is synced while a scan runs: it would load new modules
# halfway through.
#
# The working copy is the source of truth: never edit code on the target.
# The staging dir ~/projects/lanward is recreated on every deploy, and files
# that no longer exist in the source are removed from /srv/lanward/code, so
# retired files don't linger.

set -euo pipefail

cd "$(dirname "$0")"
if [[ -z "${REMOTE_HOST:-}" && -f .deploy.env ]]; then
    REMOTE_HOST=$(sed -n 's/^REMOTE_HOST=//p' .deploy.env | tail -1 | tr -d "\"'\r")
fi
HOST="${REMOTE_HOST:-}"
[[ -n "$HOST" ]] || { echo "Set REMOTE_HOST=user@host in the environment or in .deploy.env" >&2; exit 2; }

BUILD=0; RESTART=1; FORCE=0
for arg in "$@"; do
    case "$arg" in
        --build) BUILD=1 ;;
        --no-restart) RESTART=0 ;;
        --force) FORCE=1 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

TARBALL=".deploy.tar.gz"
trap 'rm -f "$TARBALL"' EXIT

echo ">> Building deploy tarball..."
tar czf "$TARBALL" \
    --warning=no-file-changed \
    --exclude='.git' --exclude='.claude' --exclude="$TARBALL" \
    --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='.env' --exclude='.deploy.env' --exclude='*.db' --exclude='*.db-wal' --exclude='*.db-shm' \
    . || [[ $? -eq 1 ]]

echo ">> Copying to $HOST..."
ssh "$HOST" "mkdir -p projects"
scp -q "$TARBALL" "$HOST:projects/lanward-deploy.tar.gz"

echo ">> Syncing on $HOST..."
ssh "$HOST" bash -s -- "$BUILD" "$RESTART" "$FORCE" <<'REMOTE'
set -euo pipefail
BUILD=$1; RESTART=$2; FORCE=$3
STAGE="$HOME/projects/lanward"
SRV=/srv/lanward

rm -rf "$STAGE" && mkdir -p "$STAGE"
tar xzf "$HOME/projects/lanward-deploy.tar.gz" -C "$STAGE"
rm -f "$HOME/projects/lanward-deploy.tar.gz"
echo "  staged in $STAGE"

if [ ! -d "$SRV/code" ]; then
    echo "  $SRV does not exist yet. Install with:"
    echo "    cd $STAGE && sudo bash install/install.sh"
    exit 0
fi

# Before touching code/: a running scan imports enrich/homechecks/alerts only after its port
# check, and must not get new modules next to the old ones it already has.
if [ "$FORCE" != 1 ] && docker exec lanward sh -c \
    'p=$(head -1 /data/.scan.lock 2>/dev/null) \
       && grep -q scan.py /proc/$p/cmdline' 2>/dev/null; then
    echo "  A scan is running; nothing changed. Run deploy.sh again (with the same options, --build"
    echo "  too if you gave it) when it is done, or add --force (a restart kills the scan)."
    exit 0
fi

# Mirror the source into code/: delete what the source no longer has, then copy.
(cd "$SRV/code" && find . -type f) | while IFS= read -r f; do
    [ -e "$STAGE/$f" ] || rm -f "$SRV/code/$f"
done
find "$SRV/code" -mindepth 1 -type d -empty -delete
cp -a "$STAGE/." "$SRV/code/"
# compose reads these from /srv/lanward, not from code/
cp -a "$STAGE/Dockerfile" "$STAGE/docker-compose.yml" "$STAGE/.dockerignore" "$SRV/"
# docker-compose.yml mounts LANWARD_CODE (default: its own folder, as in a git clone); here
# the code is in code/. Only adds the line when missing; nothing else in .env is touched.
grep -q '^LANWARD_CODE=' "$SRV/.env" 2>/dev/null || echo 'LANWARD_CODE=./code' >> "$SRV/.env"
echo "  synced into $SRV/code and refreshed infra files"

[ "$RESTART" = 1 ] || exit 0
cd "$SRV"
if [ "$BUILD" = 1 ]; then
    docker compose build
fi
docker compose up -d --remove-orphans
docker compose restart lanward
echo "  container restarted"
REMOTE

echo ">> Done. Dashboard: http://${HOST#*@}:8080/ (or the DASHBOARD_PORT in its .env)"
