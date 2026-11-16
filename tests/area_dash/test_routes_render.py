"""Every GET route renders on an empty DB and on a populated one: the right status, no 500, the
template actually produced HTML (dimension 4 in FRAMEWORK.md)."""
import pytest


# Routes that need no path parameter, each expected to return 200 on any DB.
SIMPLE_GET = [
    "/", "/network", "/devices", "/scans", "/flows", "/services", "/observations",
    "/alerts", "/settings", "/search", "/healthz", "/run-scan", "/scan-status",
    "/api/status", "/api/devices", "/api/alerts", "/traffic/running", "/api/ports",
]


@pytest.mark.parametrize("path", SIMPLE_GET)
def test_simple_get_empty_db(client, path):
    r = client.get(path)
    assert r.status_code == 200, f"{path} -> {r.status_code}"


@pytest.mark.parametrize("path", SIMPLE_GET)
def test_simple_get_populated_db(client, populated, path):
    r = client.get(path)
    assert r.status_code == 200, f"{path} -> {r.status_code}"
    assert r.data, f"{path} rendered nothing"


# ── pages that render HTML: confirm a real document came back ──

@pytest.mark.parametrize("path", ["/", "/network", "/devices", "/flows", "/services", "/traffic/running",
                                  "/observations", "/alerts", "/settings", "/search", "/run-scan"])
def test_pages_are_html(client, populated, path):
    r = client.get(path)
    assert r.status_code == 200
    assert b"<html" in r.data.lower() or b"<!doctype" in r.data.lower(), f"{path} is not an HTML page"


# ── the API routes answer JSON ──

@pytest.mark.parametrize("path", ["/api/status", "/api/devices", "/api/alerts", "/api/ports"])
def test_api_returns_json(client, populated, path):
    r = client.get(path)
    assert r.status_code == 200
    assert r.is_json, f"{path} did not return JSON"


def test_healthz_ok(client):
    assert client.get("/healthz").get_json() == {"ok": True}


# ── per-device and per-scan pages ──

def test_host_page_populated(client, populated):
    r = client.get(f"/host/{populated['cam_mac']}")
    assert r.status_code == 200
    assert b"<html" in r.data.lower()


def test_host_page_label_only_device(client, db, make):
    """A device known only by its label (no scan, no observation) still has a page."""
    make.label("24:5e:be:00:00:99", "Spare phone")
    r = client.get("/host/24:5e:be:00:00:99")
    assert r.status_code == 200


def test_host_page_unknown_mac_404(client):
    r = client.get("/host/24:5e:be:99:99:99")
    assert r.status_code == 404


def test_host_page_bad_mac_400(client):
    assert client.get("/host/not-a-mac").status_code == 400
    # path-traversal shaped input must never reach the DB as a MAC
    assert client.get("/host/..%2f..%2fetc").status_code in (400, 404)


def test_host_in_scan_populated(client, populated):
    r = client.get(f"/scan/{populated['scan_id']}/host/192.168.10.20")
    assert r.status_code == 200
    assert b"<html" in r.data.lower()


def test_host_in_scan_missing_404(client, populated):
    assert client.get(f"/scan/{populated['scan_id']}/host/10.9.9.9").status_code == 404


def test_devices_scan_param_missing(client, populated):
    """?scan=<unknown> falls back to the latest scan and flags it, still 200."""
    r = client.get("/devices?scan=999999")
    assert r.status_code == 200


def test_devices_sort_and_filter(client, populated):
    for qs in ("?sort=attention", "?show=look", "?show=tips", "?show=bogus"):
        assert client.get("/devices" + qs).status_code == 200


def test_alerts_filters_and_ranges(client, populated):
    for qs in ("", "?all=1", "?kind=security", "?kind=nope", "?range=day", "?range=year", "?range=junk"):
        assert client.get("/alerts" + qs).status_code == 200


def test_traffic_ranges(client, populated):
    for base in ("/flows", "/services", "/observations"):
        for rng in ("day", "week", "month", "year", "garbage"):
            assert client.get(f"{base}?range={rng}").status_code == 200


def test_observations_source_filter(client, populated):
    assert client.get("/observations?source=mdns").status_code == 200
    assert client.get("/observations?source=does-not-exist").status_code == 200


def test_flows_pairs_all(client, populated):
    assert client.get("/flows?pairs=all").status_code == 200


# ── search robustness (dimension 5) ──

@pytest.mark.parametrize("q", ["camera", "%", "_", "100%", "a'b\"c", "../etc/passwd",
                               "WEBOS", "192.168", "\\", "'; DROP TABLE hosts;--"])
def test_search_is_safe(client, populated, q):
    r = client.get("/search", query_string={"q": q})
    assert r.status_code == 200
    # the hosts table must still be there afterwards
    import common
    conn = common.connect()
    assert conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] >= 1
    conn.close()


def test_search_empty_query(client, populated):
    r = client.get("/search?q=")
    assert r.status_code == 200
