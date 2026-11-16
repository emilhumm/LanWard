"""The Settings POST: a valid form saves (302); each invalid field returns 400 with its error; the
support_check toggle, the IFACE/SUBNET override, and the password change."""
import common
import pytest


def valid_form(**over):
    """A form that passes every check; override one field to probe a single validation."""
    f = {
        "send_warnings": "on",
        "retain_days": "100",
        "backup_days": "14",
        "offline_minutes": "10",
        "full_days": "1",
        "status_allow": "127.0.0.1",
        "dhcp_ok": "",
        "scanners_ok": "",
        "scan_hour": "0",
        "iface": "",
        "subnet": "",
        "auto_logout": "0",
        "require_password": "on",
        "info_online": "on",       # info-alert push checkboxes: present = on; the others default off
    }
    f.update(over)
    return f


def _kv(db, key):
    return common.kv_get(db, key)


def test_valid_form_saves_and_redirects(post, db):
    r = post("/settings", valid_form())
    assert r.status_code == 302
    assert "saved=1" in r.headers["Location"]
    # a value different from the default is stored as a page override
    assert _kv(db, "setting:RETAIN_SCAN_DAYS") == "100"


@pytest.mark.parametrize("field,bad", [
    ("retain_days", {"retain_days": "10"}),        # below 30
    ("retain_days", {"retain_days": "99999"}),     # above 3650
    ("backup_days", {"backup_days": "400"}),       # above 365
    ("offline_minutes", {"offline_minutes": "1"}),  # below 2
    ("offline_minutes", {"offline_minutes": "9999"}),
    ("full_days", {"full_days": "99"}),            # above 30
    ("retain_days", {"retain_days": "abc"}),       # not a number
    ("status_allow", {"status_allow": "not.an.ip"}),
    ("dhcp_ok", {"dhcp_ok": "zz:zz:zz:zz:zz:zz"}),
    ("scanners_ok", {"scanners_ok": "nope"}),
    ("subnet", {"subnet": "999.1.1.1/24"}),
    ("subnet", {"subnet": "192.168.1.5"}),         # no CIDR prefix
    ("iface", {"iface": "bad iface!"}),
    ("webhook", {"webhook": "ftp://nope"}),
    ("new_password", {"new_password": "short", "new_password2": "short"}),   # < 8 chars
    ("new_password", {"new_password": "longenough", "new_password2": "different"}),
])
def test_invalid_field_returns_400(post, field, bad):
    r = post("/settings", valid_form(**bad))
    assert r.status_code == 400
    # the field name appears in the re-rendered form so the user sees where it went wrong
    assert field.encode() in r.data


def test_send_warnings_toggle_saved(post, db):
    # "Send warnings" unchecked -> alerts only (NOTIFY_MIN_SEVERITY=alert), stored as an override
    form = valid_form()
    del form["send_warnings"]
    assert post("/settings", form).status_code == 302
    assert _kv(db, "setting:NOTIFY_MIN_SEVERITY") == "alert"
    # checked -> "warning", which is the default, so it is not stored
    assert post("/settings", valid_form()).status_code == 302
    assert _kv(db, "setting:NOTIFY_MIN_SEVERITY") is None


def test_info_alert_push_saved(post, db):
    form = valid_form(info_ghost="on")     # ghost push ON (default off) -> stored
    del form["info_online"]                # online push OFF (default on) -> stored
    r = post("/settings", form)
    assert r.status_code == 302
    assert _kv(db, "setting:INFO_PUSH_GHOST") == "on"
    assert _kv(db, "setting:INFO_PUSH_ONLINE") == "off"
    # a value equal to the default is not stored
    assert _kv(db, "setting:INFO_PUSH_FIRMWARE") is None


def test_support_check_on(post, db):
    post("/settings", valid_form(support_check="on"))
    assert common.setting_on("SUPPORT_CHECK") is True


def test_support_check_off(post, db):
    # default is "on"; omitting the checkbox turns it off and stores that override
    post("/settings", valid_form())
    assert _kv(db, "setting:SUPPORT_CHECK") == "off"
    assert common.setting_on("SUPPORT_CHECK") is False


def test_iface_subnet_override_written(post, db):
    r = post("/settings", valid_form(iface="eno1", subnet="192.168.9.0/24"))
    assert r.status_code == 302
    assert _kv(db, "setting:IFACE") == "eno1"
    assert _kv(db, "setting:SUBNET") == "192.168.9.0/24"


def test_iface_subnet_cleared_when_blank(post, db, make):
    make.kv("setting:IFACE", "eth5")
    make.kv("setting:SUBNET", "10.0.0.0/24")
    post("/settings", valid_form(iface="", subnet=""))
    assert _kv(db, "setting:IFACE") is None
    assert _kv(db, "setting:SUBNET") is None


def test_password_change_is_hashed(post, db):
    post("/settings", valid_form(new_password="supersecret", new_password2="supersecret"))
    stored = _kv(db, "dashboard_password")
    assert stored and stored.startswith("pbkdf2_sha256$")
    assert "supersecret" not in stored


def test_dhcp_ok_normalised(post, db):
    post("/settings", valid_form(dhcp_ok="AA-BB-CC-DD-EE-FF"))
    assert _kv(db, "setting:DHCP_SERVERS_OK") == "aa:bb:cc:dd:ee:ff"


def test_settings_get_renders(client, populated):
    assert client.get("/settings").status_code == 200


def test_settings_subroutes(post, db):
    # new API key
    r = post("/settings/api-key")
    assert r.status_code == 302 and "key=new" in r.headers["Location"]
    # end the learning window
    r = post("/settings/end-learning")
    assert r.status_code == 302
    assert common.kv_get(db, "learning_until") is not None


def test_settings_test_alert(post, db, monkeypatch):
    import common as c
    monkeypatch.setattr(c, "send_test", lambda conn=None: [("Home Assistant", None)])
    r = post("/settings/test")
    assert r.status_code == 302
    saved = c.kv_get(db, "settings_test")
    assert saved and "Home Assistant" in saved
