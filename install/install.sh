#!/usr/bin/env bash
# Install / enable / revert LanWard as a systemd-managed compose stack in
# /srv/lanward (fresh installs; an existing /srv/lanward is updated by
# deploy.sh and needs only `units` when a file in install/ or backup/ changed).
#
# Run with sudo from the account that runs Docker (it will own /srv/lanward and
# run the backup; or name another with LANWARD_USER=), in the staged copy
# (~/projects/lanward/ after `bash deploy.sh --no-restart`):
#   sudo bash install/install.sh           # provision /srv/lanward, build, start, install units
#   sudo bash install/install.sh enable    # start at boot + nightly DB backup
#   sudo bash install/install.sh units     # reinstall the units + backup script only (after they change)
#   sudo bash install/install.sh revert    # stop and remove the systemd units (keeps /srv/lanward)
#        bash install/install.sh scan      # run a scan now (no sudo)
#        bash install/install.sh status    # container + last log lines (no sudo)
#
# The backup timer copies scanner.db to /mnt/router-backup: a share or disk you
# mount there yourself (/etc/fstab, writable by that account). This script does
# not create it.
#
# Idempotent: re-running the default step is safe.

set -euo pipefail

PROJECT=lanward
SRV="/srv/${PROJECT}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
UNIT="/etc/systemd/system/${PROJECT}.service"
OWNER="${LANWARD_USER:-${SUDO_USER:-}}"

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "ERROR: run with sudo." >&2
        exit 1
    fi
}

require_owner() {
    if [[ -z "${OWNER}" || "${OWNER}" == root ]] || ! id "${OWNER}" >/dev/null 2>&1; then
        echo "ERROR: run with sudo from the account that runs Docker, or set LANWARD_USER=<account>." >&2
        exit 1
    fi
}

provision() {
    echo ">> Provisioning ${SRV}/{code,data}..."
    mkdir -p "${SRV}/code" "${SRV}/data"
    cp -a "${SRC}/." "${SRV}/code/"
    cp -a "${SRC}/Dockerfile" "${SRC}/docker-compose.yml" "${SRC}/.dockerignore" "${SRV}/"
    if [[ ! -f "${SRV}/.env" ]]; then
        cp -a "${SRC}/.env.example" "${SRV}/.env"
        echo "  wrote ${SRV}/.env from the template: set WEBHOOK_URLS or NOTIFY_URLS for alerts."
    fi
    # compose mounts LANWARD_CODE (default: its own folder); in this layout the code is in code/
    grep -q '^LANWARD_CODE=' "${SRV}/.env" || echo 'LANWARD_CODE=./code' >> "${SRV}/.env"
    chown -R "${OWNER}:$(id -gn "${OWNER}")" "${SRV}"
    chmod 600 "${SRV}/.env"
}

build_and_up() {
    echo ">> Building the image and starting the container..."
    cd "${SRV}"
    sudo -u "${OWNER}" docker compose build
    sudo -u "${OWNER}" docker compose up -d --remove-orphans
    local port
    port=$(grep -E '^DASHBOARD_PORT=' .env | cut -d= -f2 || true)     # no line: 8080 (grep must not end the script)
    sleep 8
    if curl -fsS "http://localhost:${port:-8080}/healthz" >/dev/null; then
        echo "  dashboard is up on port ${port:-8080}."
    else
        echo "  WARN: no answer on port ${port:-8080}. Check: docker logs lanward" >&2
    fi
}

install_units() {
    echo ">> Installing systemd units..."
    # root-owned: `cp -a` kept the deploying account as the owner of units that root runs
    install -o root -g root -m 0644 "${SRC}/install/${PROJECT}.service" "${UNIT}"
    install -o root -g root -m 0755 "${SRC}/backup/backup-db.sh" "/usr/local/bin/${PROJECT}-backup.sh"
    sed "s/@LANWARD_USER@/${OWNER}/" "${SRC}/backup/${PROJECT}-backup.service" \
        > "/etc/systemd/system/${PROJECT}-backup.service"
    chmod 0644 "/etc/systemd/system/${PROJECT}-backup.service"
    install -o root -g root -m 0644 -t /etc/systemd/system "${SRC}/backup/${PROJECT}-backup.timer"
    systemctl daemon-reload
    echo "  installed; systemd reloaded (units that were enabled stay enabled)."
}

case "${1:-default}" in
    default)
        require_root; require_owner; provision; build_and_up; install_units
        echo ">> Done. Check http://<this machine>:8080/ (or your DASHBOARD_PORT), then: sudo bash install/install.sh enable"
        ;;
    units)
        require_root; require_owner; install_units
        ;;
    enable)
        require_root
        systemctl enable --now "${PROJECT}.service"
        systemctl enable --now "${PROJECT}-backup.timer"
        systemctl --no-pager status "${PROJECT}.service" | head -12
        ;;
    revert)
        require_root
        read -rp "Stop LanWard and remove its systemd units? [y/N] " yn
        [[ "${yn,,}" == "y" ]] || { echo "aborted."; exit 1; }
        systemctl disable --now "${PROJECT}.service" "${PROJECT}-backup.timer" 2>/dev/null || true
        rm -f "${UNIT}" "/etc/systemd/system/${PROJECT}-backup.service" "/etc/systemd/system/${PROJECT}-backup.timer"
        systemctl daemon-reload
        echo "Units removed. ${SRV} left in place."
        ;;
    scan)
        docker exec lanward python3 scan.py
        ;;
    status)
        docker ps -a --filter "name=^${PROJECT}$" --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
        echo
        docker logs --tail 40 "${PROJECT}" 2>&1
        ;;
    *)
        echo "Usage: sudo bash install/install.sh [default|units|enable|revert]  |  bash install/install.sh [scan|status]" >&2
        exit 2
        ;;
esac
