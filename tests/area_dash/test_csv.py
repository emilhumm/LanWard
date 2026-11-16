"""CSV exports: text/csv, a header row, a body that tracks the data, and spreadsheet-formula
injection neutralised (_csv_cell)."""
import csv
import io
import json


def _rows(resp):
    assert resp.status_code == 200
    assert resp.mimetype == "text/csv", f"content-type was {resp.mimetype}"
    text = resp.get_data(as_text=True)
    return list(csv.reader(io.StringIO(text)))


def test_scan_export_header_and_rowcount(client, populated):
    rows = _rows(client.get(f"/scan/{populated['scan_id']}/export.csv"))
    header = rows[0]
    assert "ip" in header and "mac" in header and "label" in header
    # one line per host in the scan (4 created in `populated`)
    assert len(rows) - 1 == 4


def test_scan_export_missing_scan_404(client, populated):
    assert client.get("/scan/999999/export.csv").status_code == 404


def test_scan_export_disposition(client, populated):
    r = client.get(f"/scan/{populated['scan_id']}/export.csv")
    assert "attachment" in r.headers.get("Content-Disposition", "")
    assert f"scan-{populated['scan_id']}.csv" in r.headers["Content-Disposition"]


def test_flows_csv(client, populated):
    rows = _rows(client.get("/flows?format=csv"))
    assert rows[0] == ["asker", "asker_mac", "asker_ip", "asker_maker", "asks_for", "asks_for_mac",
                       "asks_for_ip", "in_period", "per_day_all_time", "times_all_time", "first_seen", "last_seen"]
    # the camera asks for the router's address (one arp_req pair in `populated`)
    assert len(rows) - 1 >= 1


def test_services_csv(client, populated):
    rows = _rows(client.get("/services?format=csv"))
    assert rows[0] == ["service", "what_it_is", "type", "offered_by", "looked_for_by"]
    # at least the TV's advertised services and the camera's rtsp show up
    assert len(rows) - 1 >= 1


def test_observations_csv(client, populated):
    rows = _rows(client.get("/observations?format=csv"))
    assert rows[0] == ["device", "mac", "ip", "kind", "protocol", "what_it_said", "details",
                       "in_period", "times_all_time", "first_seen", "last_seen"]
    # CSV is not capped at 500 like the page; every observation is exported
    import common
    conn = common.connect()
    n = conn.execute("SELECT COUNT(*) FROM observations WHERE NOT (source='arp_req' AND mac IS ?)",
                     (common.own_mac(),)).fetchone()[0]
    conn.close()
    assert len(rows) - 1 == n


def test_observations_csv_source_filter_rowcount(client, populated):
    rows = _rows(client.get("/observations?format=csv&source=mdns"))
    assert len(rows) - 1 == 2          # two mdns observations in `populated`


def test_csv_formula_injection_is_neutralised(client, db, make):
    """A host name that starts with '=' must be quoted so a spreadsheet will not run it."""
    sid = make.scan()
    make.host(sid, ip="192.168.10.77", mac="24:5e:be:de:ad:01",
              hostname="=cmd|'/c calc'!A1", vendor="+evil", ports="http", open_ports="[80]")
    rows = _rows(client.get(f"/scan/{sid}/export.csv"))
    body = rows[1]
    hostname_cell = body[rows[0].index("hostname")]
    vendor_cell = body[rows[0].index("vendor")]
    assert hostname_cell.startswith("'="), hostname_cell
    assert vendor_cell.startswith("'+"), vendor_cell


def test_csv_empty_scan(client, db, make):
    sid = make.scan()
    rows = _rows(client.get(f"/scan/{sid}/export.csv"))
    assert len(rows) == 1              # header only, no hosts
