#!/usr/bin/env python3
"""Weekly cleanup, run by docker/entrypoint.py on Sundays at 04:30.

- observations not seen for 366 days: deleted from the DB (the Traffic views go back 365 days)
- hourly activity counts older than 366 days: deleted (the Overview's activity goes back 365 days)
- scans older than RETAIN_SCAN_DAYS (Settings page or .env, 365) and their hosts rows: deleted,
  except the newest scan
- acknowledged alerts older than 365 days: deleted (alert_memory stays: it is
  what keeps an old condition from alerting again)
- outages of watched devices that ended over 400 days ago: deleted
- open ports not seen for 180 days: deleted from each device's port history (open_ports_seen)
- scan logs older than 30 days: deleted
- then VACUUM between two WAL checkpoints (TRUNCATE) so the files actually
  shrink: in WAL mode the vacuumed pages sit in the WAL until a checkpoint
"""
import argparse
from datetime import datetime, timedelta

import common
from common import log


def prune_scans(conn, days):
    """Scans older than `days` with their hosts rows (foreign keys are off, so no cascade).
    The newest scan always stays: the dashboard and the watcher read it."""
    old = "SELECT id FROM scans WHERE started_at < ? AND id < (SELECT MAX(id) FROM scans)"
    cutoff = common.iso_ago(days=days)
    nh = conn.execute(f"DELETE FROM hosts WHERE scan_id IN ({old})", (cutoff,)).rowcount
    ns = conn.execute(f"DELETE FROM scans WHERE id IN ({old})", (cutoff,)).rowcount
    conn.commit()
    log(f"scans: deleted {ns} scan(s) and {nh} host row(s) older than {days} days")


def prune_alerts(conn, days):
    n = conn.execute("DELETE FROM alerts WHERE acknowledged = 1 AND created_at < ?",
                     (common.iso_ago(days=days),)).rowcount
    conn.commit()
    log(f"alerts: deleted {n} acknowledged alert(s) older than {days} days")


def prune_outages(conn, days):
    """Outages that ended more than `days` ago (one still going on stays)."""
    n = conn.execute("DELETE FROM outages WHERE ended_at IS NOT NULL AND ended_at < ?",
                     (common.iso_ago(days=days),)).rowcount
    conn.commit()
    log(f"outages: deleted {n} outage(s) that ended over {days} days ago")


def prune_open_ports(conn, days):
    n = conn.execute("DELETE FROM open_ports_seen WHERE last_seen < ?", (common.iso_ago(days=days),)).rowcount
    conn.commit()
    log(f"open ports: deleted {n} not seen for {days} days")


def prune_observations(conn, days):
    n = conn.execute("DELETE FROM observations WHERE last_seen < ?",
                     (common.iso_ago(days=days),)).rowcount
    conn.commit()
    log(f"observations: deleted {n} row(s) not seen for {days} days")


def prune_activity(conn, days):
    n = conn.execute("DELETE FROM activity WHERE hour < ?", (common.iso_ago(days=days)[:13],)).rowcount
    conn.commit()
    log(f"activity: deleted {n} hourly row(s) older than {days} days")


def prune_observation_counts(conn, days):
    n = conn.execute("DELETE FROM observation_counts WHERE day < ?", (common.iso_ago(days=days)[:10],)).rowcount
    conn.commit()
    log(f"observation counts: deleted {n} daily row(s) older than {days} days")


def prune_arp_ask_hours(conn, days):
    """The ghost rate only needs the last 24 h; keep a few days' headroom and drop the rest."""
    n = conn.execute("DELETE FROM arp_ask_hours WHERE hour < ?", (common.iso_ago(days=days)[:13],)).rowcount
    conn.commit()
    log(f"arp-ask hours: deleted {n} hourly row(s) older than {days} days")


def prune_files(days):
    cutoff = (datetime.now() - timedelta(days=days)).timestamp()
    logs = common.SCAN_LOG_DIR
    deleted = 0
    for f in (logs.iterdir() if logs.is_dir() else []):
        try:
            if f.is_file() and f.stat().st_mtime < cutoff:
                f.unlink()
                deleted += 1
        except OSError:
            pass
    log(f"scan logs: deleted {deleted} file(s) older than {days} days")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--obs-days", type=int, default=366)
    ap.add_argument("--file-days", type=int, default=30)
    ap.add_argument("--activity-days", type=int, default=366)
    ap.add_argument("--scan-days", type=int, default=int(common.setting("RETAIN_SCAN_DAYS") or 365))
    ap.add_argument("--alert-days", type=int, default=365)
    ap.add_argument("--outage-days", type=int, default=400)
    args = ap.parse_args()

    log("[*] Retention cleanup")
    conn = common.connect()
    common.migrate(conn)
    prune_observations(conn, args.obs_days)
    prune_activity(conn, args.activity_days)
    prune_observation_counts(conn, args.activity_days)
    prune_arp_ask_hours(conn, 3)
    prune_scans(conn, args.scan_days)
    prune_alerts(conn, args.alert_days)
    prune_outages(conn, args.outage_days)
    prune_open_ports(conn, 180)
    prune_files(args.file_days)
    conn.isolation_level = None                     # VACUUM can't run in a transaction
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("VACUUM")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()
    log("[*] Retention done")


if __name__ == "__main__":
    main()
