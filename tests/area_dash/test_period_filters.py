"""The ?range= period filter (24h / 7 days / 30 days / 365 days) on the Traffic views and Alerts: a row
whose last activity is older than the chosen period must drop out. Verifies the filter is actually
applied on every page that offers it."""
import common


def _seed_two(make, source, **extra):
    """One recent row and one from 10 days ago, of the given observation source."""
    make.observation(source, "aa:bb:cc:00:00:01", ip="192.168.10.5", last_seen=common.now_iso(), **extra)
    make.observation(source, "aa:bb:cc:00:00:02", ip="192.168.10.6",
                     last_seen=common.iso_ago(days=10), first_seen=common.iso_ago(days=10), **extra)


def test_observations_period_filters(client, make):
    _seed_two(make, "arp")
    day = client.get("/observations?range=day&format=csv").get_data(as_text=True)
    month = client.get("/observations?range=month&format=csv").get_data(as_text=True)
    # the 10-day-old device (…:02 / .6) is in 30 days but not 24 hours; the recent one is in both
    assert "192.168.10.5" in day and "192.168.10.6" not in day
    assert "192.168.10.5" in month and "192.168.10.6" in month


def test_flows_period_filters(client, make):
    # two ARP askers, one of them last heard 10 days ago; CSV carries every row (no top-25 cap)
    make.observation("arp_req", "aa:bb:cc:00:00:01", ip="192.168.10.90",
                     details={"own_ip": "192.168.10.5"}, last_seen=common.now_iso(), count=100)
    make.observation("arp_req", "aa:bb:cc:00:00:02", ip="192.168.10.91",
                     details={"own_ip": "192.168.10.6"}, first_seen=common.iso_ago(days=10),
                     last_seen=common.iso_ago(days=10), count=100)
    day = client.get("/flows?range=day&format=csv").get_data(as_text=True)
    month = client.get("/flows?range=month&format=csv").get_data(as_text=True)
    assert "192.168.10.90" in day and "192.168.10.91" not in day
    assert "192.168.10.90" in month and "192.168.10.91" in month


def test_services_period_filters(client, make):
    make.observation("mdns", "aa:bb:cc:00:00:01", ip="192.168.10.5",
                     details={"services_adv": ["_recent._tcp"]}, last_seen=common.now_iso())
    make.observation("mdns", "aa:bb:cc:00:00:02", ip="192.168.10.6",
                     details={"services_adv": ["_old._tcp"]}, first_seen=common.iso_ago(days=10),
                     last_seen=common.iso_ago(days=10))
    day = client.get("/services?range=day&format=csv").get_data(as_text=True)
    month = client.get("/services?range=month&format=csv").get_data(as_text=True)
    assert "_recent._tcp" in day and "_old._tcp" not in day
    assert "_recent._tcp" in month and "_old._tcp" in month


def test_alerts_period_filters(client, db):
    # an acknowledged alert from 10 days ago shows in 30 days, not in 24 hours; unacked always shows
    db.execute("INSERT INTO alerts (created_at, severity, title, details, kind, acknowledged) "
               "VALUES (?,?,?,?,?,1)", (common.iso_ago(days=10), "warning", "Old acked alert", "x", "finding"))
    db.execute("INSERT INTO alerts (created_at, severity, title, details, kind, acknowledged) "
               "VALUES (?,?,?,?,?,0)", (common.iso_ago(days=10), "warning", "Old unacked alert", "x", "finding"))
    db.commit()
    day = client.get("/alerts?range=day").get_data(as_text=True)
    month = client.get("/alerts?range=month").get_data(as_text=True)
    assert "Old acked alert" not in day and "Old acked alert" in month
    assert "Old unacked alert" in day            # unacknowledged shows regardless of period


# ── the displayed counts are the REAL measured per-day counts for the chosen window, no estimate ──

def _count_row(db, source, mac, ip, day, n):
    db.execute("INSERT INTO observation_counts (source, mac, ip, day, n) VALUES (?,?,?,?,?)",
               (source, mac, ip, day, n))


def test_period_total_is_measured_only(db):
    """_period_total returns the real measured count for the window — never a lifetime estimate."""
    import app
    _count_row(db, "arp_req", "m", "i", common.iso_ago(days=0)[:10], 5)
    _count_row(db, "arp_req", "m", "i", common.iso_ago(days=1)[:10], 5)
    db.commit()
    measured = app._measured_counts(db, common.iso_ago(days=1)[:10])       # today + yesterday
    assert app._period_total(measured, "arp_req", "m", "i") == 10          # the real 10, no estimate


def test_period_total_zero_before_any_counting(db):
    """No per-day rows for a key -> 0 for the window, not an estimate off the lifetime count."""
    import app
    measured = app._measured_counts(db, common.iso_ago(days=7)[:10])
    assert app._period_total(measured, "arp_req", "m", "i") == 0


def test_flows_number_grows_with_window(client, db, make):
    import csv
    import io
    make.observation("arp_req", "aa:bb:cc:00:00:01", ip="192.168.10.90",
                     details={"own_ip": "192.168.10.5"}, first_seen=common.iso_ago(days=100),
                     last_seen=common.now_iso(), count=700)
    for d in range(30):
        _count_row(db, "arp_req", "aa:bb:cc:00:00:01", "192.168.10.90", common.iso_ago(days=d)[:10], 10)
    db.commit()

    def in_period(rng):
        txt = client.get(f"/flows?range={rng}&format=csv").get_data(as_text=True)
        row = next(r for r in csv.DictReader(io.StringIO(txt)) if r.get("asker_ip") == "192.168.10.5")
        return int(row["in_period"])

    d, w, m = in_period("day"), in_period("week"), in_period("month")
    assert d < w < m                              # real counts, growing with the window
    assert d == 10 and w == 70                    # exact measured totals: today's 10, seven days' 70


def test_observations_number_grows_with_window(client, db, make):
    import csv
    import io
    make.observation("arp", "aa:bb:cc:00:00:02", ip="192.168.10.7",
                     first_seen=common.iso_ago(days=100), last_seen=common.now_iso(), count=1000)
    for d in range(30):
        _count_row(db, "arp", "aa:bb:cc:00:00:02", "192.168.10.7", common.iso_ago(days=d)[:10], 3)
    db.commit()

    def in_period(rng):
        txt = client.get(f"/observations?range={rng}&format=csv").get_data(as_text=True)
        row = next(r for r in csv.DictReader(io.StringIO(txt)) if r.get("ip") == "192.168.10.7")
        return int(row["in_period"])

    assert in_period("day") < in_period("week") < in_period("month")
    assert in_period("day") == 3 and in_period("week") == 21


def test_flows_in_period_is_measured_not_lifetime(client, db, make):
    import csv
    import io
    make.observation("arp_req", "aa:bb:cc:00:00:03", ip="192.168.10.95",
                     details={"own_ip": "192.168.10.8"}, first_seen=common.iso_ago(days=100),
                     last_seen=common.now_iso(), count=999999)
    _count_row(db, "arp_req", "aa:bb:cc:00:00:03", "192.168.10.95", common.iso_ago(days=0)[:10], 10)
    db.commit()
    txt = client.get("/flows?range=day&format=csv").get_data(as_text=True)
    row = next(r for r in csv.DictReader(io.StringIO(txt)) if r.get("asker_ip") == "192.168.10.8")
    assert int(row["in_period"]) == 10   # today's real 10, not the lifetime 999,999


# ── "Who is asking for whom" pages the list instead of a hard 25-row cap ──

def test_flows_pagination(client, make):
    for i in range(30):
        make.observation("arp_req", "aa:bb:cc:00:01:%02x" % i, ip="192.168.20.%d" % i,
                         details={"own_ip": "192.168.30.%d" % i}, first_seen=common.iso_ago(days=10),
                         last_seen=common.now_iso(), count=100 + i)
    p1 = client.get("/flows").get_data(as_text=True)
    assert p1.count('class="flow-row"') == 20                 # first page: 20 pairs
    assert "of 30" in p1 and "page=2" in p1                   # count shown, Next link present
    p2 = client.get("/flows?page=2").get_data(as_text=True)
    assert p2.count('class="flow-row"') == 10                 # second page: the remaining 10
    assert "page=1" in p2                                     # Previous link present
    # out-of-range page clamps to the last page, never errors
    assert client.get("/flows?page=99").status_code == 200


def test_observations_pagination(client, make):
    for i in range(30):
        make.observation("arp", "aa:bb:cc:00:02:%02x" % i, ip="192.168.22.%d" % i, last_seen=common.now_iso())
    p1 = client.get("/observations").get_data(as_text=True)
    assert p1.count('class="obs-row') == 20                   # first page: 20 rows
    assert "of 30" in p1 and "page=2" in p1
    p2 = client.get("/observations?page=2").get_data(as_text=True)
    assert p2.count('class="obs-row') == 10                   # second page: the remaining 10
    assert client.get("/observations?page=99").status_code == 200


# ── "Everything heard" search filters across all pages, not just the visible one ──

def test_observations_search_across_pages(client, make):
    for i in range(24):
        make.observation("arp", "aa:bb:cc:00:03:%02x" % i, ip="192.168.23.%d" % i, last_seen=common.now_iso())
    # a distinctive one that (by last_seen) would land on a later page
    make.observation("arp", "aa:bb:cc:00:03:ff", ip="192.168.23.99", hostname="needle-host",
                     last_seen=common.iso_ago(hours=2))
    r = client.get("/observations?q=needle").get_data(as_text=True)
    assert "needle-host" in r and "matching" in r          # found regardless of page
    assert "192.168.23.99" in client.get("/observations?q=192.168.23.99").get_data(as_text=True)
    assert "No matches" in client.get("/observations?q=zzznotfound").get_data(as_text=True)


def test_observations_search_by_label(client, make):
    make.observation("arp", "aa:bb:cc:00:04:01", ip="192.168.24.1", last_seen=common.now_iso())
    make.label("aa:bb:cc:00:04:01", "Kitchen Speaker")
    assert "192.168.24.1" in client.get("/observations?q=kitchen").get_data(as_text=True)   # matched via label
