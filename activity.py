#!/usr/bin/env python3
"""How busy the network is compared with what is usual for the hour (2026-10-27). The Overview's
Network activity panel and /api/status read it.

passive-monitor.py counts, per device and hour, the broadcast and multicast packets every device
on the LAN hears (the activity table). Per hour that gives two numbers for the whole network:
how many devices spoke up and how many packets they sent ("chatter"). LanWard's own scans and
pings are not counted, and its own machine is left out of both numbers.

What is usual for an hour comes from the same hour of the day over the last 4 weeks, weekdays
against weekdays and weekends against weekends (every day while one kind has fewer than MIN_DAYS
of them): the 10th to the 90th percentile, so one odd day does not move it.

Devices out of their routine: a device heard on most days that has been quiet for over a day,
and a device that sent several times its busiest usual hour in the last hour (one that restarts
again and again, or misbehaves).
"""
import math
from datetime import datetime, timedelta

import common

WINDOW_DAYS = 28        # what is usual comes from the last 4 weeks
MIN_DAYS = 5            # days of the same hour before a usual range is shown
ROUTINE_DAYS = 14       # a device's routine: the 14 days up to when it was last heard
AWAY_AFTER_H = 24       # a device heard on most days is out of its routine after this long unheard...
AWAY_FOR_DAYS = 14      # ...until it has been gone this long
HOME_SHARE = 0.5        # "most days": at least half the days LanWard was listening
BUSY_MIN = 300          # a busy device sent at least this many packets more than its busiest usual hour...
BUSY_FACTOR = 3         # ...and this many times as many (its usual: the 90th percentile of its hours)
BUSY_HISTORY_H = 48     # hours heard from it before its usual counts


def hour_key(t):
    return t.strftime("%Y-%m-%dT%H")


def _hour(key):
    return datetime.strptime(key, "%Y-%m-%dT%H")


def _kind(t):
    return "weekend" if t.weekday() >= 5 else "weekday"


def _percentile(values, p):
    """The p-th quantile (0..1) of the sorted `values`, interpolated."""
    k = (len(values) - 1) * p
    i = int(k)
    j = min(i + 1, len(values) - 1)
    return values[i] + (values[j] - values[i]) * (k - i)


def _usual(values, min_half):
    """(low, high): the 10th to 90th percentile of `values`, at least `min_half` either side of the median."""
    v = sorted(values)
    mid = _percentile(v, 0.5)
    return min(_percentile(v, 0.1), mid - min_half), max(_percentile(v, 0.9), mid + min_half)


def hourly(conn, since, mac=None):
    """{hour: (devices heard, packets)} from the datetime `since` on, LanWard's own machine left out; with `mac`,
    that one device's (1, its packets) for the hours it was heard."""
    if mac:
        return {r[0]: (1, r[1]) for r in conn.execute(
            "SELECT hour, SUM(n) FROM activity WHERE hour >= ? AND mac = ? GROUP BY hour", (hour_key(since), mac))}
    return {r[0]: (r[1], r[2]) for r in conn.execute(
        "SELECT hour, COUNT(*), SUM(n) FROM activity WHERE hour >= ? AND mac IS NOT ? GROUP BY hour",
        (hour_key(since), common.own_mac()))}


def usual_ranges(totals, before, clean_since=None):
    """{(kind, hour of day): {"devices": (low, high), "packets": (low, high), "mid": {"devices", "packets"},
    "kind"}} from the hours in `totals` in the WINDOW_DAYS before the datetime `before`, and not before
    `clean_since` (an hour key). kind is weekday, weekend or any; mid is the median, the usual line."""
    start = max(hour_key(before - timedelta(days=WINDOW_DAYS)), clean_since or "")
    end = hour_key(before)
    samples = {}
    for key, value in totals.items():
        if start <= key < end:
            t = _hour(key)
            for kind in (_kind(t), "any"):
                samples.setdefault((kind, t.hour), []).append(value)
    return {k: _range_of(values, k[0]) for k, values in samples.items() if len(values) >= MIN_DAYS}


def _range_of(values, kind):
    """The usual range of (devices, packets) samples: {"devices": (low, high), "packets": (low, high),
    "mid": {"devices", "packets"}, "kind"}."""
    devices, packets = [v[0] for v in values], [v[1] for v in values]
    dlo, dhi = _usual(devices, 1)
    plo, phi = _usual(packets, 0.1 * _percentile(sorted(packets), 0.5))
    return {"devices": (max(0, math.floor(dlo)), math.ceil(dhi)),
            "packets": (max(0, int(plo // 10 * 10)), int(math.ceil(phi / 10) * 10)),
            "mid": {"devices": _percentile(sorted(devices), 0.5), "packets": _percentile(sorted(packets), 0.5)},
            "kind": kind}


def usual_at(ranges, t):
    """What is usual at the hour `t`, or None while LanWard is still learning it."""
    return ranges.get((_kind(t), t.hour)) or ranges.get(("any", t.hour))


def margin(field, usual):
    """How far outside the usual (low, high) range of `field` counts as "much" at least."""
    return 3 if field == "devices" else 0.25 * usual[1]


def verdict(value, usual, margin):
    """How `value` compares with the (low, high) range: much quieter, quieter, as usual, busier or
    much busier ("much": outside by more than the range is wide, and by at least `margin`)."""
    lo, hi = usual
    wide = max(hi - lo, margin)
    if value > hi:
        return "much busier" if value > hi + wide else "busier"
    if value < lo:
        return "much quieter" if value < lo - wide else "quieter"
    return "as usual"


def network(conn, now=None, hours=168, mac=None):
    """The network's last `hours` hours up to the current one, oldest first, and the last full hour
    against what is usual (with `mac`: one device's packets, against what is usual for it; an hour LanWard
    was counting in but did not hear it is 0, an hour nothing at all was counted stays empty):
    {"points": [{"t", "devices", "packets", "usual", "partial", "counted"}],
     "last": {"t", "devices", "packets", "usual", "devices_verdict", "packets_verdict"} or None,
     "learning_from": a date, when the last hour has no usual range yet, "first": the first hour counted or None}.
    The current hour is partial: its packets are scaled up to a full hour once 10 minutes have
    passed; its devices are left out, as more turn up while the hour goes on. `counted` is False
    for hours before counting began."""
    now = now or datetime.now()
    this_hour = now.replace(minute=0, second=0, microsecond=0)
    start = this_hour - timedelta(hours=hours - 1)
    since = min(start, this_hour - timedelta(days=WINDOW_DAYS))
    totals = hourly(conn, since)
    if mac:
        heard = hourly(conn, since, mac)
        totals = {key: heard.get(key, (0, 0)) for key in totals}
    clean_since = common.kv_get(conn, "activity_clean_since")
    ranges = usual_ranges(totals, this_hour, clean_since)
    first = conn.execute("SELECT MIN(hour) FROM activity").fetchone()[0]
    points = []
    for i in range(hours):
        t = start + timedelta(hours=i)
        devices, packets = totals.get(hour_key(t), (None, None))
        partial = t == this_hour
        if partial:
            elapsed = (now - this_hour).total_seconds() - 30         # the monitor writes once a minute
            devices = None
            packets = round(packets * 3600 / elapsed) if packets is not None and elapsed >= 600 else None
        points.append({"t": t, "devices": devices, "packets": packets, "usual": usual_at(ranges, t),
                       "partial": partial, "counted": bool(first) and hour_key(t) >= first})

    t = this_hour - timedelta(hours=1)
    devices, packets = totals.get(hour_key(t), (None, None))
    usual = usual_at(ranges, t)
    last = {"t": t, "devices": devices, "packets": packets, "usual": usual,
            "devices_verdict": verdict(devices, usual["devices"], margin("devices", usual["devices"])) if usual else None,
            "packets_verdict": verdict(packets, usual["packets"], margin("packets", usual["packets"])) if usual else None,
            } if devices is not None else None
    learning_from = None
    if not usual and (clean_since or first):
        learning_from = (_hour(clean_since or first) + timedelta(days=MIN_DAYS)).date()
        if learning_from <= now.date():          # that hour has simply not been counted on enough days
            learning_from = None
    return {"points": points, "last": last, "learning_from": learning_from, "first": _hour(first) if first else None}


def daily(conn, now=None, days=30, mac=None):
    """The month view (2026-10-27): the last `days` days up to today, oldest first, one point a day: devices heard
    that day and their packets, against what is usual for that kind of day (weekday or weekend; every day while one
    kind has fewer than MIN_DAYS), from the whole days in the WINDOW_DAYS before today. A day counts only when
    counting ran from its start (the day counting began, or the clean count began, is partial). Today is partial:
    its packets are scaled up to a whole day once 2 hours have passed, its devices left out. With `mac`: one
    device's packets per day (0 on a counted day it was not heard)."""
    now = now or datetime.now()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    start = today - timedelta(days=days - 1)
    since = min(start, today - timedelta(days=WINDOW_DAYS))
    totals = {r[0]: (r[1], r[2]) for r in conn.execute(
        "SELECT substr(hour, 1, 10), COUNT(DISTINCT mac), SUM(n) FROM activity WHERE hour >= ? AND mac IS NOT ? "
        "GROUP BY 1", (hour_key(since), common.own_mac()))}
    if mac:
        heard = {r[0]: (1, r[1]) for r in conn.execute(
            "SELECT substr(hour, 1, 10), SUM(n) FROM activity WHERE hour >= ? AND mac = ? GROUP BY 1",
            (hour_key(since), mac))}
        totals = {day: heard.get(day, (0, 0)) for day in totals}
    first = conn.execute("SELECT MIN(hour) FROM activity").fetchone()[0]
    clean = common.kv_get(conn, "activity_clean_since") or ""
    whole_from = max(first or "9", clean)           # the first hour a whole day can start at or after
    samples = {}
    for day, value in totals.items():
        t = datetime.strptime(day, "%Y-%m-%d")
        if f"{day}T00" >= whole_from and today - timedelta(days=WINDOW_DAYS) <= t < today:
            for kind in (_kind(t), "any"):
                samples.setdefault(kind, []).append(value)
    ranges = {k: _range_of(v, k) for k, v in samples.items() if len(v) >= MIN_DAYS}
    points = []
    for i in range(days):
        t = start + timedelta(days=i)
        day = t.strftime("%Y-%m-%d")
        counted = bool(first) and f"{day}T00" >= first
        devices, packets = totals.get(day, (None, None)) if counted else (None, None)
        partial = t == today
        if partial:
            hours = (now - today).total_seconds() / 3600
            devices = None
            packets = round(packets * 24 / hours) if packets is not None and hours >= 2 else None
        points.append({"t": t, "devices": devices, "packets": packets, "partial": partial, "counted": counted,
                       "usual": ranges.get(_kind(t)) or ranges.get("any"), "day": True})
    return points


_DEVICES = {"much busier": "far more devices", "busier": "more devices",
            "quieter": "fewer devices", "much quieter": "far fewer devices"}
_CHATTER = {"much busier": "far more chatter", "busier": "more chatter",
            "quieter": "less chatter", "much quieter": "far less chatter"}


def describe(data):
    """The last full hour in words: {"verdict", "title", "text"}. verdict is as usual, busier, much busier,
    quieter, much quieter, mixed, learning or None (nothing counted in the last hour)."""
    last = data["last"]
    if not last:
        return {"verdict": None, "title": "Nothing counted in the last hour",
                "text": "LanWard writes what it hears once a minute. If this stays empty, check Listening at the top."}
    t = last["t"]
    span = f"{t:%H}:00–{t + timedelta(hours=1):%H}:00"
    usual = last["usual"]
    if not usual:
        when = f", from about {data['learning_from']:%a %d %b}" if data["learning_from"] else ""
        return {"verdict": "learning", "title": "Learning what is usual",
                "text": f"{span}: {last['devices']} devices, {last['packets']:,} packets. The shaded range of what is "
                        f"usual for each hour shows after {MIN_DAYS} days of counting{when}."}
    dv, pv = last["devices_verdict"], last["packets_verdict"]
    text = (f"{span}: {last['devices']} devices heard, usually {usual['devices'][0]}–{usual['devices'][1]}; "
            f"{last['packets']:,} packets, usually {usual['packets'][0]:,}–{usual['packets'][1]:,}.")
    if dv == pv == "as usual":
        return {"verdict": "as usual", "title": "As usual", "text": text}
    directions = {v.split()[-1] for v in (dv, pv) if v != "as usual"}
    if len(directions) == 1 and "as usual" not in (dv, pv):
        word = directions.pop()
        overall = f"much {word}" if "much" in dv + pv else word
        title = f"{overall.capitalize()} than usual"
    else:
        overall = "mixed" if len(directions) > 1 else dv if dv != "as usual" else pv
        parts = [w[v] for w, v in ((_DEVICES, dv), (_CHATTER, pv)) if v != "as usual"]
        title = f"{' and '.join(parts).capitalize()} than usual"
    return {"verdict": overall, "title": title, "text": text}


def away_devices(conn, now, heard, macs):
    """Devices among `macs` heard on most days (HOME_SHARE of the days LanWard was listening in the
    ROUTINE_DAYS up to when they were last heard) that have been quiet for AWAY_AFTER_H hours, but not
    yet AWAY_FOR_DAYS days: [(mac, last heard)], quiet the longest first. `heard` is {mac: last heard}
    from listening; being found by a scan counts as heard too."""
    gone, recent = (now - timedelta(days=AWAY_FOR_DAYS)).isoformat(), (now - timedelta(hours=AWAY_AFTER_H)).isoformat()
    quiet = {m: heard[m] for m in macs if heard.get(m) and gone <= heard[m] < recent}
    if not quiet:
        return []
    marks = ",".join("?" * len(quiet))
    since = (now - timedelta(days=AWAY_FOR_DAYS + ROUTINE_DAYS)).strftime("%Y-%m-%d")
    days, scanned = {}, {}
    for mac, day in conn.execute(f"SELECT mac, substr(hour, 1, 10) FROM activity WHERE hour >= ? "
                                 f"AND mac IN ({marks}) GROUP BY 1, 2", (since, *quiet)):
        days.setdefault(mac, set()).add(day)
    for mac, day, last in conn.execute(
            f"SELECT h.mac, substr(s.started_at, 1, 10), MAX(s.started_at) FROM hosts h JOIN scans s ON s.id = h.scan_id "
            f"WHERE s.started_at >= ? AND h.mac IN ({marks}) GROUP BY 1, 2", (since, *quiet)):
        days.setdefault(mac, set()).add(day)
        scanned[mac] = max(scanned.get(mac, ""), last)
    listening = {r[0] for r in conn.execute("SELECT DISTINCT substr(hour, 1, 10) FROM activity WHERE hour >= ?", (since,))}
    listening |= {r[0] for r in conn.execute("SELECT DISTINCT substr(started_at, 1, 10) FROM scans WHERE started_at >= ?",
                                             (since,))}
    out = []
    for mac, last in quiet.items():
        last = max(last, scanned.get(mac, ""))
        if last >= recent:
            continue
        end = datetime.strptime(last[:10], "%Y-%m-%d")
        routine = {(end - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(ROUTINE_DAYS)}
        open_days = routine & listening | {last[:10]}
        here = routine & days.get(mac, set()) | {last[:10]}
        if len(open_days) >= MIN_DAYS and len(here) >= HOME_SHARE * len(open_days):
            out.append((mac, last))
    return sorted(out, key=lambda m: m[1])


def busy_devices(conn, now):
    """Devices that sent BUSY_FACTOR times their busiest usual hour, and BUSY_MIN packets more, in the last
    full hour: [(mac, packets, usual most)], busiest first. A device's busiest usual hour is the 90th
    percentile of its hours over the last ROUTINE_DAYS days (BUSY_HISTORY_H of them at least)."""
    this_hour = now.replace(minute=0, second=0, microsecond=0)
    last = hour_key(this_hour - timedelta(hours=1))
    since = max(hour_key(this_hour - timedelta(days=ROUTINE_DAYS)), common.kv_get(conn, "activity_clean_since") or "")
    out = []
    for mac, n in conn.execute("SELECT mac, n FROM activity WHERE hour = ? AND n >= ? AND mac IS NOT ?",
                               (last, BUSY_MIN, common.own_mac())).fetchall():
        history = sorted(r[0] for r in conn.execute(
            "SELECT n FROM activity WHERE mac = ? AND hour >= ? AND hour < ?", (mac, since, last)))
        if len(history) < BUSY_HISTORY_H:
            continue
        most = _percentile(history, 0.9)
        if n >= BUSY_FACTOR * most and n - most >= BUSY_MIN:
            out.append((mac, n, round(most)))
    return sorted(out, key=lambda m: -m[1])
