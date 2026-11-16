"""Regression: the Overview's Network activity no longer shows "usually here but away since <day>"
notices (removed 2026-10-29). A labelled device that fits the old "away" criteria must produce no
'away' item; the "suddenly very chatty" ('busy') notices are kept."""
from datetime import datetime, timedelta

import common


def _add_activity(db, mac, hour_key, n):
    db.execute("INSERT INTO activity (mac, hour, n) VALUES (?,?,?) "
               "ON CONFLICT(mac, hour) DO UPDATE SET n = excluded.n", (mac, hour_key, n))
    db.commit()


def test_overview_has_no_away_notices(db, make):
    import activity
    import app

    now = datetime(2026, 10, 28, 12, 0)
    mac = "cc:cc:cc:cc:cc:aa"
    make.label(mac, "Kims Ipad")                        # a named device, so the old code would track it
    for day in range(19, 27):                             # heard on 8 routine days, last on the 26th
        _add_activity(db, mac, f"2026-10-{day:02d}T14", 5)
    heard = {mac: "2026-10-26T12:00:00"}

    # the underlying helper still flags it (it is kept for other uses)...
    assert [m for m, _ in activity.away_devices(db, now, heard, [mac])] == [mac]

    # ...but the Overview panel no longer surfaces any 'away' item.
    with app.app.test_request_context("/"):
        panel = app._activity_panel(db, now)
    assert all(u["kind"] != "away" for u in panel["unusual"])
    assert not any("usually here" in u["why"] for u in panel["unusual"])


def test_overview_still_shows_busy_notices(db, make):
    import app

    now = datetime(2026, 10, 28, 12, 0)
    common.kv_set(db, "activity_clean_since", "2026-01-01T00")
    db.commit()
    mac = "cc:cc:cc:cc:cc:bb"
    _add_activity(db, mac, "2026-10-28T11", 2000)         # last full hour: a spike
    base = datetime(2026, 10, 28, 10)
    for i in range(48):
        _add_activity(db, mac, f"{(base - timedelta(hours=i)):%Y-%m-%dT%H}", 10)

    with app.app.test_request_context("/"):
        panel = app._activity_panel(db, now)
    assert any(u["kind"] == "busy" for u in panel["unusual"])
