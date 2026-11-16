"""The session login that replaced Basic auth: the login page, the idle auto-logout, the
"require a password" tickbox, and the default-password banner."""
import common
import pytest


def _origin():
    return {"Origin": "http://localhost"}


def _clear_stored_password():
    c = common.connect()
    c.execute("DELETE FROM kv WHERE key = 'dashboard_password'")
    c.commit()
    c.close()
    common._SETTINGS_CACHE["at"] = float("-inf")


def test_login_page_renders_with_default_hint(auth_client):
    # PW_IS_DEFAULT is forced off in the auth_client fixture, so force it on for this one
    import app
    app.PW_IS_DEFAULT = True
    try:
        _clear_stored_password()                 # no stored password -> the "first time?" hint shows
        r = auth_client.get("/login")
        assert r.status_code == 200
        assert b"lanward" in r.data.lower()
    finally:
        app.PW_IS_DEFAULT = False


def test_login_redirects_back_to_next(auth_client):
    r = auth_client.post("/login", data={"password": "secret", "next": "/settings"}, headers=_origin())
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/settings")


@pytest.mark.parametrize("bad_next", ["//evil.example", "https://evil.example", "/\\evil.example",
                                      "http:evil.example"])
def test_login_rejects_open_redirect(auth_client, bad_next):
    r = auth_client.post("/login", data={"password": "secret", "next": bad_next}, headers=_origin())
    assert r.status_code == 302
    assert "evil.example" not in r.headers["Location"]       # bounced to home instead


def test_idle_timeout_logs_out(logged_in, make):
    make.kv("setting:AUTO_LOGOUT_MINUTES", "1")
    common._SETTINGS_CACHE["at"] = float("-inf")
    assert logged_in.get("/").status_code == 200             # fresh session is live
    with logged_in.session_transaction() as sess:
        sess["seen"] = 0                                     # pretend the last activity was in 1970
    r = logged_in.get("/", environ_overrides={"REMOTE_ADDR": "192.0.2.50"})
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_scan_status_poll_does_not_refresh_idle_clock(logged_in, make):
    """The scan-status page reloads itself every 5 s; that poll must not keep a walked-away session
    alive, so it must not bump the idle 'seen' timestamp."""
    import time
    make.kv("setting:AUTO_LOGOUT_MINUTES", "30")
    common._SETTINGS_CACHE["at"] = float("-inf")
    pinned = time.time() - 60               # recent enough not to be timed out, old enough to spot a bump
    with logged_in.session_transaction() as sess:
        sess["seen"] = pinned
    logged_in.get("/scan-status")
    with logged_in.session_transaction() as sess:
        assert sess["seen"] == pinned                        # the poll did not bump it
    logged_in.get("/")                                       # a real page visit does bump it
    with logged_in.session_transaction() as sess:
        assert sess["seen"] > pinned


def test_require_password_off_opens_dashboard(auth_client, make):
    make.kv("require_password", "off")
    common._SETTINGS_CACHE["at"] = float("-inf")
    r = auth_client.get("/", environ_overrides={"REMOTE_ADDR": "192.0.2.50"})
    assert r.status_code == 200                              # no login asked for


def test_default_password_banner_shows_on_pages(logged_in):
    import app
    app.PW_IS_DEFAULT = True
    try:
        _clear_stored_password()                 # the default is now what's in force
        r = logged_in.get("/")
        assert b"default password" in r.data.lower()
    finally:
        app.PW_IS_DEFAULT = False
