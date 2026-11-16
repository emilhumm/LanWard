"""AREA E - activity.py: period maths, usual-range learning, partial-hour/day extrapolation,
own-machine exclusion, away/busy devices."""
from datetime import datetime, timedelta

import pytest

import activity
import common


def add_activity(db, mac, hour_key, n):
    db.execute("INSERT INTO activity (mac, hour, n) VALUES (?,?,?) "
               "ON CONFLICT(mac, hour) DO UPDATE SET n = excluded.n", (mac, hour_key, n))
    db.commit()


# ───────────────────────── pure helpers ─────────────────────────

def test_hour_key_and_kind():
    assert activity.hour_key(datetime(2026, 10, 26, 17, 5, 9)) == "2026-10-26T17"
    assert activity._kind(datetime(2026, 10, 26)) == "weekday"      # Monday
    assert activity._kind(datetime(2026, 10, 24)) == "weekend"      # Saturday


def test_percentile_interpolates():
    assert activity._percentile([0, 10], 0.5) == 5.0
    assert activity._percentile([0, 10, 20, 30], 0.9) == 27.0
    assert activity._percentile([5], 0.9) == 5


def test_usual_spreads_at_least_min_half():
    lo, hi = activity._usual([1, 2, 3, 4, 5], 1)
    assert lo == pytest.approx(1.4) and hi == pytest.approx(4.6)
    # min_half widens a flat series around its median.
    lo, hi = activity._usual([10, 10, 10, 10, 10], 2)
    assert lo == 8 and hi == 12


def test_margin():
    assert activity.margin("devices", (1, 2)) == 3
    assert activity.margin("packets", (0, 80)) == 20.0


def test_verdict_bands():
    usual = (10, 20)                     # wide = max(10, margin)
    m = 3
    assert activity.verdict(15, usual, m) == "as usual"
    assert activity.verdict(25, usual, m) == "busier"
    assert activity.verdict(35, usual, m) == "much busier"
    assert activity.verdict(5, usual, m) == "quieter"
    assert activity.verdict(-5, usual, m) == "much quieter"


# ───────────────────────── usual ranges + learning period ─────────────────────────

def test_usual_ranges_needs_min_days():
    before = datetime(2026, 10, 28, 12)
    weekdays = ["2026-10-27T10", "2026-10-26T10", "2026-10-23T10", "2026-10-22T10", "2026-10-21T10"]
    totals = {k: (3, 100) for k in weekdays}
    ranges = activity.usual_ranges(totals, before)
    assert ("weekday", 10) in ranges and ("any", 10) in ranges

    # One sample short of MIN_DAYS -> still learning, no range.
    ranges4 = activity.usual_ranges({k: (3, 100) for k in weekdays[:4]}, before)
    assert ("weekday", 10) not in ranges4


def test_usual_ranges_respects_clean_since():
    before = datetime(2026, 10, 28, 12)
    weekdays = ["2026-10-27T10", "2026-10-26T10", "2026-10-23T10", "2026-10-22T10", "2026-10-21T10"]
    totals = {k: (3, 100) for k in weekdays}
    # clean_since after all the samples -> none counted (LanWard's own packets excluded era).
    ranges = activity.usual_ranges(totals, before, clean_since="2026-10-28T00")
    assert ranges == {}


# ───────────────────────── hourly: exclude LanWard's own machine ─────────────────────────

def test_hourly_excludes_own_mac(db, monkeypatch):
    monkeypatch.setattr(common, "own_mac", lambda *a, **k: "aa:aa:aa:aa:aa:aa")
    add_activity(db, "aa:aa:aa:aa:aa:aa", "2026-10-28T10", 500)   # own machine
    add_activity(db, "bb:bb:bb:bb:bb:bb", "2026-10-28T10", 50)
    out = activity.hourly(db, datetime(2026, 10, 28, 9))
    assert out == {"2026-10-28T10": (1, 50)}


# ───────────────────────── network: partial hour extrapolation ─────────────────────────

def test_network_partial_hour_scaled(db):
    now = datetime(2026, 10, 28, 12, 30)
    add_activity(db, "cc:cc:cc:cc:cc:cc", "2026-10-28T12", 100)   # the current (partial) hour
    data = activity.network(db, now=now, hours=6)
    part = next(p for p in data["points"] if p["partial"])
    assert part["t"] == datetime(2026, 10, 28, 12)
    assert part["devices"] is None                               # devices left out for the partial hour
    # elapsed = 1800 - 30 = 1770 s; 100 * 3600 / 1770 ~= 203
    assert part["packets"] == round(100 * 3600 / 1770)


def test_network_partial_hour_too_early_is_none(db):
    now = datetime(2026, 10, 28, 12, 5)        # only 5 min in (<10) -> not extrapolated
    add_activity(db, "cc:cc:cc:cc:cc:cc", "2026-10-28T12", 100)
    data = activity.network(db, now=now, hours=3)
    part = next(p for p in data["points"] if p["partial"])
    assert part["packets"] is None


def test_network_last_hour_learning(db):
    now = datetime(2026, 10, 28, 12, 30)
    add_activity(db, "cc:cc:cc:cc:cc:cc", "2026-10-28T11", 200)   # the last full hour
    data = activity.network(db, now=now, hours=6)
    assert data["last"] is not None
    assert data["last"]["usual"] is None                          # not enough days yet
    assert activity.describe(data)["verdict"] == "learning"


def test_describe_nothing_counted(db):
    now = datetime(2026, 10, 28, 12, 30)        # empty DB, nothing in the last hour
    data = activity.network(db, now=now, hours=6)
    assert data["last"] is None
    assert activity.describe(data)["verdict"] is None


# ───────────────────────── daily: partial day extrapolation ─────────────────────────

def test_daily_partial_day_scaled(db):
    now = datetime(2026, 10, 28, 6, 0)          # 6 h into today
    # Counting must have begun at or before today's midnight for the day to count (not partial-from-start).
    add_activity(db, "cc:cc:cc:cc:cc:cc", "2026-10-28T00", 120)
    points = activity.daily(db, now=now, days=5)
    today = next(p for p in points if p["partial"])
    assert today["devices"] is None
    assert today["packets"] == round(120 * 24 / 6)              # scaled to a whole day


# ───────────────────────── one device (the device page's chart) ─────────────────────────

def test_network_one_device_zero_when_not_heard(db):
    """With `mac`: the device's own packets; an hour LanWard counted in without hearing it is 0, an hour nothing at
    all was counted stays empty."""
    now = datetime(2026, 10, 28, 12, 30)
    dev, other = "dd:dd:dd:dd:dd:01", "dd:dd:dd:dd:dd:02"
    add_activity(db, dev, "2026-10-28T09", 40)
    add_activity(db, other, "2026-10-28T09", 900)
    add_activity(db, other, "2026-10-28T10", 700)                # counted, the device not heard
    data = activity.network(db, now=now, hours=6, mac=dev)       # 07 .. 12
    by_hour = {p["t"].hour: p["packets"] for p in data["points"]}
    assert by_hour[9] == 40                                      # its own packets, not the network's 940
    assert by_hour[10] == 0
    assert by_hour[8] is None and by_hour[11] is None            # nothing counted at all


def test_daily_one_device(db):
    now = datetime(2026, 10, 28, 12, 0)
    dev, other = "dd:dd:dd:dd:dd:01", "dd:dd:dd:dd:dd:02"
    add_activity(db, other, "2026-10-26T00", 10)                 # counting began here
    add_activity(db, dev, "2026-10-26T08", 30)
    add_activity(db, dev, "2026-10-26T09", 20)
    add_activity(db, other, "2026-10-27T05", 10)
    points = activity.daily(db, now=now, days=3, mac=dev)        # 26, 27, 28 (today)
    assert [p["packets"] for p in points[:2]] == [50, 0]


# ───────────────────────── busy / away devices ─────────────────────────

def test_busy_device_detected(db):
    now = datetime(2026, 10, 28, 12, 0)
    common.kv_set(db, "activity_clean_since", "2026-01-01T00")
    db.commit()
    mac = "cc:cc:cc:cc:cc:cc"
    add_activity(db, mac, "2026-10-28T11", 2000)               # last full hour: a spike
    base = datetime(2026, 10, 28, 10)
    for i in range(48):                                        # 48 h of quiet history (~10 each)
        add_activity(db, mac, activity.hour_key(base - timedelta(hours=i)), 10)
    busy = activity.busy_devices(db, now)
    assert any(m == mac and n == 2000 for m, n, most in busy)


def test_busy_device_needs_history(db):
    now = datetime(2026, 10, 28, 12, 0)
    common.kv_set(db, "activity_clean_since", "2026-01-01T00")
    db.commit()
    mac = "cc:cc:cc:cc:cc:cc"
    add_activity(db, mac, "2026-10-28T11", 2000)              # spike but no history
    assert activity.busy_devices(db, now) == []


def test_away_device_detected(db):
    now = datetime(2026, 10, 28, 12, 0)
    mac, other = "cc:cc:cc:cc:cc:aa", "cc:cc:cc:cc:cc:bb"
    # mac heard on 8 routine days, last two days ago (quiet > 24 h, < 14 d).
    for day in range(19, 27):            # 2026-10-19 .. 2026-10-26
        add_activity(db, mac, f"2026-10-{day:02d}T14", 5)
    add_activity(db, other, "2026-10-17T14", 5)
    add_activity(db, other, "2026-10-18T14", 5)
    heard = {mac: "2026-10-26T12:00:00"}
    out = activity.away_devices(db, now, heard, [mac])
    assert [m for m, _ in out] == [mac]


def test_away_device_not_when_recent(db):
    now = datetime(2026, 10, 28, 12, 0)
    mac = "cc:cc:cc:cc:cc:aa"
    for day in range(19, 29):
        add_activity(db, mac, f"2026-10-{day:02d}T14", 5)
    heard = {mac: now.isoformat(timespec="seconds")}          # heard just now
    assert activity.away_devices(db, now, heard, [mac]) == []
