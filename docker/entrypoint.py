"""The lanward container's main process (2026-10-06; replaced the dashboard +
passive + scheduler/cron trio).

Runs three long-lived children and restarts any that exit:
  dashboard   dashboard/app.py          web UI on $DASHBOARD_PORT
  passive     passive-monitor.py        tshark: ARP / DHCP / mDNS / LLDP / CDP
  watcher     watcher.py                new devices, router, offline devices
and three timed jobs, each a fresh subprocess so code changes apply next run:
  scan.py       at the hours in SCAN_HOURS (Settings page or .env; default
                0,6,12,18), plus once ~2 minutes after start when the last scan
                is over 12 h old; none: no scheduled scans (Run scan)
  retention.py  Sundays 04:30
  backup.py     daily 03:30, a checked copy of scanner.db in data/backups
                (BACKUP_KEEP_DAYS=0: off)

If the dashboard keeps dying (5 times in 10 minutes), this process exits and
Docker's restart policy brings the whole container back. All output goes
to the container log: `docker logs lanward`.
"""
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import common  # noqa: E402


def log(msg):
    print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "[entrypoint]", msg, flush=True)


def scan_hours(raw):
    """SCAN_HOURS ("0,6,12,18") as a sorted list; values that are not an hour 0-23 are
    logged and left out. Empty: no scheduled scans."""
    hours = set()
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit() and int(part) <= 23:
            hours.add(int(part))
        elif part:
            log(f"SCAN_HOURS: ignoring {part!r}, not an hour 0-23")
    return sorted(hours)


PY = sys.executable
CHILDREN = {
    "dashboard": [PY, "dashboard/app.py"],
    "passive": [PY, "passive-monitor.py", "--iface", common.IFACE],
    "watcher": [PY, "watcher.py"],
}
_HOURS = {"raw": None, "hours": []}


def current_hours():
    """SCAN_HOURS as it is now (the Settings page can change it); parsed again only when it changed."""
    raw = common.setting("SCAN_HOURS")
    if raw != _HOURS["raw"]:
        _HOURS.update(raw=raw, hours=scan_hours(raw))
    return _HOURS["hours"]


def settings_stamp():
    """When the Settings page last saved (kv settings_changed_at): the schedule is worked out again."""
    try:
        conn = common.connect()
        try:
            return common.kv_get(conn, "settings_changed_at")
        finally:
            conn.close()
    except Exception:
        return None


SCAN_HOURS = current_hours()
SCAN_TIMEOUT = 2 * 3600
CATCH_UP_AFTER_H = 12

_stopping = threading.Event()
_procs = {}


def supervise(name, cmd):
    """Keep one child running; back off when it crash-loops."""
    failures = []
    while not _stopping.is_set():
        try:
            proc = subprocess.Popen(cmd, cwd=ROOT)
        except OSError as e:                # e.g. fork fails under memory pressure: count it, try again
            code = f"not started: {e}"
        else:
            _procs[name] = proc
            code = proc.wait()
        if _stopping.is_set():
            return
        now = time.time()
        failures = [t for t in failures if now - t < 600] + [now]
        log(f"{name} exited ({code}); restart #{len(failures)} in the last 10 min")
        if name == "dashboard" and len(failures) >= 5:
            log("dashboard keeps failing; exiting so Docker restarts the container")
            os._exit(1)
        _stopping.wait(min(60, 5 * len(failures)))


def end_job(proc, grace=15):
    """Stop a timed-out job and everything it started (scan.py's nmap runs): SIGTERM to
    its process group, SIGKILL to whatever is left after `grace` seconds."""
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    except ProcessLookupError:
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def clear_scan_lock(pid):
    """Remove .scan.lock if it still names `pid` (a killed scan.py cannot remove its own)."""
    try:
        if common.SCAN_LOCK.read_text().split("\n", 1)[0].strip() == str(pid):
            common.SCAN_LOCK.unlink()
    except OSError:
        pass


def run_job(args, timeout):
    log(f"starting {' '.join(args)}")
    started = time.time()
    # Its own process group, so a timeout also ends the nmap runs it started.
    proc = subprocess.Popen([PY, *args], cwd=ROOT, start_new_session=True)
    _procs["job"] = proc
    try:
        code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        end_job(proc)
        code = proc.wait()
        clear_scan_lock(proc.pid)
        log(f"{args[0]} killed after {timeout // 60} minutes")
    finally:
        _procs.pop("job", None)
    log(f"{args[0]} finished, exit {code}, {time.time() - started:.0f}s")


def next_scan(now):
    """The next scheduled scan after `now`, or None when SCAN_HOURS is empty."""
    for day in range(2):
        for h in SCAN_HOURS:
            at = (now + timedelta(days=day)).replace(hour=h, minute=0, second=0, microsecond=0)
            if at > now:
                return at
    return None


def next_retention(now):
    at = now.replace(hour=4, minute=30, second=0, microsecond=0)
    at += timedelta(days=(6 - now.weekday()) % 7)          # Sunday
    return at if at > now else at + timedelta(days=7)


def next_backup(now):
    """Daily at 03:30 (between the 00:00 and 06:00 scans); None when BACKUP_KEEP_DAYS is 0."""
    if int(common.setting("BACKUP_KEEP_DAYS") or 14) <= 0:
        return None
    at = now.replace(hour=3, minute=30, second=0, microsecond=0)
    return at if at > now else at + timedelta(days=1)


def last_scan_age_hours():
    try:
        conn = common.connect()
        row = conn.execute("SELECT started_at FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()
        return (datetime.now() - datetime.fromisoformat(row[0])).total_seconds() / 3600
    except Exception:                       # no scans, or an old non-ISO timestamp
        return None


def shutdown(*_):
    _stopping.set()
    for proc in list(_procs.values()):
        if proc.poll() is None:
            proc.terminate()
    deadline = time.time() + 15
    for proc in list(_procs.values()):
        try:
            proc.wait(timeout=max(0.1, deadline - time.time()))
        except subprocess.TimeoutExpired:
            proc.kill()
    sys.exit(0)


def main():
    global SCAN_HOURS
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    conn = common.connect()
    common.migrate(conn)
    conn.close()
    log(f"watching {common.SUBNET or 'no network (none found on ' + common.IFACE + ': set SUBNET in .env)'} "
        f"on {common.IFACE}; dashboard {common.DASHBOARD_URL}; alerts to "
        f"{', '.join(common.notify_services()) or 'nowhere yet (Settings page)'}")
    for name, cmd in CHILDREN.items():
        threading.Thread(target=supervise, args=(name, cmd), daemon=True).start()

    age = last_scan_age_hours()
    catch_up = (datetime.now() + timedelta(minutes=2)
                if SCAN_HOURS and (age is None or age > CATCH_UP_AFTER_H) else None)
    log((f"scans at {SCAN_HOURS} h" if SCAN_HOURS else "no scheduled scans (SCAN_HOURS is empty)")
        + ("; no scan yet" if age is None else f"; last scan {age:.1f} h ago")
        + (f"; catch-up scan at {catch_up:%H:%M}" if catch_up else ""))

    while True:
        now = datetime.now()
        SCAN_HOURS = current_hours()
        due = [(at, job) for at, job in ((catch_up or next_scan(now), "scan"), (next_retention(now), "retention"),
                                         (next_backup(now), "backup")) if at]
        at, job = min(due)
        log(f"next: {job} at {at:%Y-%m-%d %H:%M}")
        stamp, replan = settings_stamp(), False
        while datetime.now() < at and not replan:
            time.sleep(min(30, max(0.2, (at - datetime.now()).total_seconds())))
            replan = settings_stamp() != stamp          # saved on the Settings page: plan again
        if replan:
            log("settings changed: planning again")
            continue
        if job == "scan":
            catch_up = None
            run_job(["scan.py"], SCAN_TIMEOUT)
        elif job == "backup":
            run_job(["backup.py"], 1800)
        else:
            run_job(["retention.py"], 3600)


if __name__ == "__main__":
    main()
