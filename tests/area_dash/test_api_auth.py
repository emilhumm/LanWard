"""The read-only API needs the key (bearer token) or an allow-listed address; browsers logged in with
the dashboard password may read it too. POSTs need a same-origin Origin."""
import common


OUTSIDE = {"REMOTE_ADDR": "192.0.2.50"}        # not in STATUS_ALLOW


def test_api_requires_key_from_outside(auth_client):
    r = auth_client.get("/api/status", environ_overrides=OUTSIDE)
    assert r.status_code == 401


def test_api_bearer_key_grants_access(auth_client, db):
    key = common.api_key(db)
    r = auth_client.get("/api/status", environ_overrides=OUTSIDE,
                        headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200


def test_api_wrong_key_rejected(auth_client):
    r = auth_client.get("/api/status", environ_overrides=OUTSIDE,
                        headers={"Authorization": "Bearer ns_not-the-key"})
    assert r.status_code == 401


def test_api_loopback_is_allow_listed(auth_client):
    # the test client's default REMOTE_ADDR is 127.0.0.1, always in STATUS_ALLOW
    assert auth_client.get("/api/status").status_code == 200


def test_api_status_allow_ip(auth_client, make):
    make.kv("setting:STATUS_ALLOW", "192.0.2.50")
    common._SETTINGS_CACHE["at"] = float("-inf")
    r = auth_client.get("/api/status", environ_overrides=OUTSIDE)
    assert r.status_code == 200


def test_api_password_login_grants_access(logged_in):
    # a browser that is logged in (the session cookie) may read the API
    r = logged_in.get("/api/devices", environ_overrides=OUTSIDE)
    assert r.status_code == 200


def test_pages_redirect_to_login_without_credentials(auth_client):
    r = auth_client.get("/", environ_overrides=OUTSIDE)
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_login_with_right_password_then_reaches_pages(logged_in):
    assert logged_in.get("/").status_code == 200


def test_login_with_wrong_password_rejected(auth_client):
    r = auth_client.post("/login", data={"password": "nope"}, headers={"Origin": "http://localhost"})
    assert r.status_code == 401
    assert auth_client.get("/", environ_overrides=OUTSIDE).status_code == 302   # still not signed in


def test_logout_clears_the_session(logged_in):
    assert logged_in.get("/").status_code == 200
    logged_in.post("/logout", headers={"Origin": "http://localhost"})
    assert logged_in.get("/", environ_overrides=OUTSIDE).status_code == 302


def test_bearer_does_not_unlock_html_pages(auth_client, db):
    key = common.api_key(db)
    r = auth_client.get("/", environ_overrides=OUTSIDE, headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 302        # the bearer path is GET /api/ only; pages go to /login


def test_post_without_origin_is_forbidden(client, populated):
    """same_origin_posts: a POST with no Origin/Referer is rejected (403) even with auth off."""
    r = client.post("/labels/set", data={"mac": populated["cam_mac"], "label": "x"})
    assert r.status_code == 403


def test_post_with_matching_origin_ok(post, populated):
    r = post("/labels/set", {"mac": populated["cam_mac"], "label": "Renamed",
                             "redirect_to": "/"})
    assert r.status_code in (302, 303)


def test_post_with_foreign_origin_is_forbidden(client, populated):
    r = client.post("/labels/set", data={"mac": populated["cam_mac"], "label": "x"},
                    headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


def test_status_says_whether_a_scan_is_running(auth_client):
    # Homelab Village's radar reads this (2026-11-13): scans only reach the `scans` table when they finish
    body = auth_client.get("/api/status").get_json()
    assert body["scan_running"] is False
