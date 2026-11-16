# LanWard — image for the single lanward container (docker/entrypoint.py runs
# the dashboard, the passive monitor, the watcher and the scheduled scans).
# Source is bind-mounted at runtime, never COPY'd: rebuild only when this file
# changes.
#
# Slim image: only what the monitor needs at runtime. It ships no MAC vendor
# file of its own — nmap's built-in list is used.

FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1 \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# nmap: ARP sweep + port check. tshark: passive capture. iputils: IPv6 sweep
# and arping for watched devices. openssl: TLS certificate details. curl:
# healthcheck. tzdata: the host's /etc/localtime (compose) or TZ. apprise:
# alerts to ntfy, Telegram, email... (NOTIFY_URLS; 2026-10-27). waitress: the
# dashboard's web server. smbclient: the check for file shares open to guests.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-flask python3-waitress apprise \
        nmap tshark smbclient \
        iproute2 iputils-ping iputils-arping \
        openssl ca-certificates curl tzdata \
    && rm -rf /var/lib/apt/lists/*

# /app: the code (bind-mounted read-only), /data: scanner.db, logs, backups.
RUN mkdir -p /app /data
WORKDIR /app

# No CMD/ENTRYPOINT: compose starts docker/entrypoint.py from the bind-mounted code.
