"""Area A — common.py: MACs, settings precedence, model/name extraction, time helpers, ip helpers.

Unit + parsing + regression tests. No real network (conftest blocks it); DB is the per-test `db` fixture.
"""
from datetime import datetime

import pytest

import common


# ─────────────────────────────── norm_mac ───────────────────────────────

@pytest.mark.parametrize("raw,expect", [
    ("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"),
    ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),        # upper -> lower
    ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),        # dashes -> colons
    ("AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff"),        # upper + dashes
    ("  aa:bb:cc:dd:ee:ff  ", "aa:bb:cc:dd:ee:ff"),    # surrounding space
])
def test_norm_mac_valid(raw, expect):
    assert common.norm_mac(raw) == expect


@pytest.mark.parametrize("raw", [
    None, "", "not a mac", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00",
    "gg:bb:cc:dd:ee:ff", "aabbccddeeff", "aa:bb:cc:dd:ee:fff", "12345",
])
def test_norm_mac_invalid(raw):
    assert common.norm_mac(raw) is None


# ─────────────────────────────── mac helpers ───────────────────────────────

@pytest.mark.parametrize("mac,expect", [
    ("02:00:00:00:00:00", True),
    ("06:11:22:33:44:55", True),
    ("aa:bb:cc:dd:ee:ff", True),       # 0xaa bit1 set
    ("00:11:22:33:44:55", False),
    ("0c:11:22:33:44:55", False),      # 0x0c -> 1100, bit1 clear
])
def test_mac_is_randomized(mac, expect):
    assert common.mac_is_randomized(mac) is expect


def test_mac_is_randomized_bad_input():
    assert common.mac_is_randomized(None) is False
    assert common.mac_is_randomized("") is False


def test_mac_is_randomized_normalises_form():
    # a locally administered MAC is judged True whichever valid form it arrives in
    assert common.mac_is_randomized("02-00-00-00-00-00") is True   # dash form
    assert common.mac_is_randomized("02:00:00:00:00:00") is True   # colon form
    assert common.mac_is_randomized("not-a-mac") is False          # junk still False


@pytest.mark.parametrize("mac,expect", [
    ("aa:bb:cc:dd:ee:ff", True),       # unicast
    ("00:00:00:00:00:00", False),      # all-zero
    ("ff:ff:ff:ff:ff:ff", False),      # broadcast (multicast bit)
    ("01:00:5e:00:00:01", False),      # multicast
    ("02:11:22:33:44:55", True),       # locally administered but unicast
    (None, False),
    ("garbage", False),
])
def test_mac_is_device(mac, expect):
    assert common.mac_is_device(mac) is expect


# ─────────────────────────────── vendor_for ───────────────────────────────

def test_vendor_for_prefix_lookup(monkeypatch):
    monkeypatch.setattr(common, "_VENDORS", {"AABBCC": "Acme Corp"})
    assert common.vendor_for("aa:bb:cc:dd:ee:ff") == "Acme Corp"
    assert common.vendor_for("AA-BB-CC-11-22-33") == "Acme Corp"


def test_vendor_for_unknown_and_bad(monkeypatch):
    monkeypatch.setattr(common, "_VENDORS", {"AABBCC": "Acme Corp"})
    assert common.vendor_for("11:22:33:44:55:66") is None
    assert common.vendor_for(None) is None
    assert common.vendor_for("not-a-mac") is None


# ─────────────────────────── settings precedence ───────────────────────────

def _fresh_cache():
    common._SETTINGS_CACHE["at"] = float("-inf")


def test_setting_default(db):
    _fresh_cache()
    assert common.setting("BACKUP_KEEP_DAYS") == "14"           # the built-in default


def test_setting_env_over_default(db, monkeypatch):
    monkeypatch.setenv("BACKUP_KEEP_DAYS", "7")
    _fresh_cache()
    assert common.setting_base("BACKUP_KEEP_DAYS") == "7"
    assert common.setting("BACKUP_KEEP_DAYS") == "7"


def test_setting_kv_over_env_over_default(db, make, monkeypatch):
    monkeypatch.setenv("BACKUP_KEEP_DAYS", "7")
    make.kv("setting:BACKUP_KEEP_DAYS", "3")
    _fresh_cache()
    assert common.setting("BACKUP_KEEP_DAYS") == "3"            # kv wins over env + default


def test_setting_on(db, make):
    _fresh_cache()
    assert common.setting_on("SUPPORT_CHECK") is True           # default "on"
    make.kv("setting:SUPPORT_CHECK", "off")
    _fresh_cache()
    assert common.setting_on("SUPPORT_CHECK") is False
    for truthy in ("on", "1", "true", "YES", " On "):
        make.kv("setting:SUPPORT_CHECK", truthy)
        _fresh_cache()
        assert common.setting_on("SUPPORT_CHECK") is True


# ─────────────────────────── save_settings ───────────────────────────

def _kv_val(db, key):
    row = db.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def test_save_settings_stores_non_default(db):
    common.save_settings(db, {"BACKUP_KEEP_DAYS": "30"})
    db.commit()
    assert _kv_val(db, "setting:BACKUP_KEEP_DAYS") == "30"


def test_save_settings_value_equal_to_base_removes_kv_row(db):
    # First store an override, then save a value equal to the .env/default base -> row removed.
    common.save_settings(db, {"BACKUP_KEEP_DAYS": "30"})
    db.commit()
    assert _kv_val(db, "setting:BACKUP_KEEP_DAYS") == "30"
    common.save_settings(db, {"BACKUP_KEEP_DAYS": "14"})           # 14 == default base
    db.commit()
    assert _kv_val(db, "setting:BACKUP_KEEP_DAYS") is None


def test_save_settings_equal_to_env_base_removes_row(db, monkeypatch):
    monkeypatch.setenv("BACKUP_KEEP_DAYS", "9")
    common.save_settings(db, {"BACKUP_KEEP_DAYS": "30"})
    db.commit()
    assert _kv_val(db, "setting:BACKUP_KEEP_DAYS") == "30"
    common.save_settings(db, {"BACKUP_KEEP_DAYS": "9"})            # equals env base
    db.commit()
    assert _kv_val(db, "setting:BACKUP_KEEP_DAYS") is None


# ─────────────────────────── details_dict ───────────────────────────

@pytest.mark.parametrize("raw,expect", [
    ('{"a": 1}', {"a": 1}),
    ("{}", {}),
    ("", {}),
    (None, {}),
    ("not json", {}),
    ("[1, 2, 3]", {}),            # a JSON list is not an object -> {}
    ("123", {}),                  # a JSON number is not an object -> {}
    ('"text"', {}),               # a JSON string is not an object -> {}
    (123, {}),                    # non-str, non-None input must not crash
])
def test_details_dict(raw, expect):
    assert common.details_dict(raw) == expect


# ─────────────────────────── mdns_txt_model ───────────────────────────

def test_mdns_model_non_dict_is_none():
    assert common.mdns_txt_model("not-a-dict") is None
    assert common.mdns_txt_model(None) is None
    assert common.mdns_txt_model(["md", "x"]) is None


def test_mdns_model_skips_platform_word():
    # md carries the OS word; the real model in `model` must win (regression).
    assert common.mdns_txt_model({"md": "WEBOS", "model": "OLED65C9PLA"}) == "OLED65C9PLA"
    assert common.mdns_txt_model({"md": "tizen", "model": "QN90A"}) == "QN90A"


def test_mdns_model_keeps_real_md():
    assert common.mdns_txt_model({"md": "Hue bridge"}) == "Hue bridge"
    assert common.mdns_txt_model({"md": "TRADFRI gateway"}) == "TRADFRI gateway"


def test_mdns_model_key_priority():
    # md beats model; when md is only a platform word it is skipped in favour of later keys.
    assert common.mdns_txt_model({"md": "Real Model", "model": "Other"}) == "Real Model"
    assert common.mdns_txt_model({"am": "AudioAccessory5,1"}) == "AudioAccessory5,1"
    assert common.mdns_txt_model({"product": "Sonos One"}) == "Sonos One"


def test_mdns_model_nothing_useful():
    assert common.mdns_txt_model({"md": "webos"}) is None        # only a platform word, nothing else
    assert common.mdns_txt_model({"md": "ab"}) is None           # too short
    assert common.mdns_txt_model({"md": 1234}) is None           # non-string value, no crash
    assert common.mdns_txt_model({}) is None


# ─────────────────────────── host_name / _useful_name ───────────────────────────

@pytest.mark.parametrize("value,expect", [
    ("Alexs-MacBook", "Alexs-MacBook"),
    ("Galaxy-Tab-S5e", "Galaxy-Tab-S5e"),
    ("  Living Room TV ", "Living Room TV"),
])
def test_host_name_keeps_real(value, expect):
    assert common.host_name(value) == expect


@pytest.mark.parametrize("value", [
    "localhost", "unknown", "none", "SonosZP", "sonoszp",
    "esp32-1a2b3c", "ESP8266_aabbcc", "android-1234abcd", "espressif",
    "192-168-10-5.lan", "host-192-168-10-5", "192.168.10.5 - Sonos",
    "ab", "   ", "", None, 1234, "aa:bb:cc", "deadbeef",
])
def test_host_name_rejects(value):
    assert common.host_name(value) is None


def test_host_name_truncates():
    assert len(common.host_name("Zebra-" + "g" * 80)) == 60


# ─────────────────────────── plural / tidy_plural ───────────────────────────

def test_plural():
    assert common.plural(1, "firmware update") == "1 firmware update"
    assert common.plural(6, "firmware update") == "6 firmware updates"
    assert common.plural(0, "update") == "0 updates"
    assert common.plural(2, "address", "addresses") == "2 addresses"
    assert common.plural(1, "address", "addresses") == "1 address"


def test_tidy_plural():
    assert common.tidy_plural("1 firmware update(s)") == "1 firmware update"
    assert common.tidy_plural("6 firmware update(s)") == "6 firmware updates"
    assert common.tidy_plural("1 address(es)") == "1 address"
    assert common.tidy_plural("3 address(es)") == "3 addresses"
    assert common.tidy_plural("No number here(s)") == "No number heres"
    assert common.tidy_plural("") == ""


# ─────────────────────────── time helpers ───────────────────────────

def test_now_iso_parses_and_has_no_microseconds():
    s = common.now_iso()
    dt = datetime.fromisoformat(s)
    assert dt.microsecond == 0
    assert "." not in s


def test_iso_ago_ordering():
    past = common.iso_ago(days=1)
    now = common.now_iso()
    future = common.iso_ago(days=-1)
    assert past < now < future
    # same ISO format, so string ordering matches chronological ordering
    assert datetime.fromisoformat(past) < datetime.fromisoformat(now)


# ─────────────────────────── own_ip_of / claimed_ipv4s ───────────────────────────

def test_own_ip_of():
    assert common.own_ip_of("arp_req", "192.168.10.5", {"own_ip": "192.168.10.9"}) == "192.168.10.9"
    assert common.own_ip_of("dhcp", "0.0.0.0", {"requested_ip": "192.168.10.20"}) == "192.168.10.20"
    assert common.own_ip_of("dhcp", None, {"requested_ip": "192.168.10.21"}) == "192.168.10.21"
    assert common.own_ip_of("arp", "192.168.10.30", {}) == "192.168.10.30"
    assert common.own_ip_of("arp", "0.0.0.0", {}) is None
    assert common.own_ip_of("arp", None, None) is None           # non-dict details tolerated


def test_claimed_ipv4s(db, make):
    make.observation("arp", "aa:bb:cc:dd:ee:01", ip="192.168.10.40")
    make.observation("dhcp", "aa:bb:cc:dd:ee:02", ip="0.0.0.0",
                     details={"requested_ip": "192.168.10.41"})
    make.observation("arp_req", "aa:bb:cc:dd:ee:03", ip="192.168.10.99",
                     details={"own_ip": "192.168.10.42"})
    make.observation("mdns", "aa:bb:cc:dd:ee:04", ip="fe80::1")   # IPv6 must be dropped
    claimed = common.claimed_ipv4s(db, common.iso_ago(days=1))
    assert claimed == {"192.168.10.40", "192.168.10.41", "192.168.10.42"}


# ─────────────────────────── _saved_override ───────────────────────────

def test_saved_override_reads_kv(db, make):
    make.kv("setting:IFACE", "eth9")
    assert common._saved_override("IFACE") == "eth9"


def test_saved_override_strips_and_empty_is_none(db, make):
    make.kv("setting:SUBNET", "   192.168.50.0/24   ")
    assert common._saved_override("SUBNET") == "192.168.50.0/24"
    make.kv("setting:IFACE", "   ")
    assert common._saved_override("IFACE") is None


def test_saved_override_missing_key(db):
    assert common._saved_override("IFACE") is None


# ─────────────────────────── name_hint ───────────────────────────

MAC = "aa:bb:cc:dd:ee:10"


def test_name_hint_mdns_model(db, make):
    make.observation("mdns", MAC, details={"txt": {"md": "TRADFRI gateway"}})
    assert common.name_hint(db, MAC) == "TRADFRI gateway"


def test_name_hint_mdns_skips_platform_word(db, make):
    # regression: the model must be the real model, not the platform word WEBOS.
    make.observation("mdns", MAC, details={"txt": {"md": "WEBOS", "model": "OLED65C9PLA"}})
    assert common.name_hint(db, MAC) == "OLED65C9PLA"


def test_name_hint_apple_board_code_mapped(db, make):
    make.observation("mdns", MAC, details={"txt": {"md": "J71bAP"}})
    assert common.name_hint(db, MAC) == "iPad (6th gen) Wi-Fi"


def test_name_hint_apple_unknown_board_code(db, make):
    make.observation("mdns", MAC, details={"txt": {"md": "J999xAP"}})
    assert common.name_hint(db, MAC) == "Apple device (model J999xAP)"


def test_name_hint_dhcp_hostname_with_vendor_class_kind(db, make):
    make.observation("dhcp", MAC, hostname="Galaxy-Tab",
                     details={"vendor_class": "android-dhcp-11"})
    assert common.name_hint(db, MAC) == "Galaxy-Tab (Android device)"


def test_name_hint_prefers_model_over_hostname(db, make):
    make.observation("mdns", MAC, hostname="some-host",
                     details={"txt": {"md": "Hue bridge"}})
    make.observation("dhcp", MAC, hostname="Galaxy-Tab",
                     details={"vendor_class": "msft 5.0"})
    assert common.name_hint(db, MAC) == "Hue bridge"


def test_name_hint_generic_hostname_is_nothing(db, make):
    make.observation("dhcp", MAC, hostname="localhost")
    assert common.name_hint(db, MAC) is None


def test_name_hint_upnp_model_from_host_row(db, make):
    import json
    sid = make.scan()
    make.host(sid, ip="192.168.10.51", mac=MAC,
              upnp_info=json.dumps({"modelName": "Sonos One", "friendlyName": "Kitchen"}))
    assert common.name_hint(db, MAC) == "Sonos One"


def test_name_hint_none_when_nothing(db):
    assert common.name_hint(db, "aa:bb:cc:00:00:99") is None


def test_port_label_known_and_unknown():
    assert common.port_label(7000) == "AirPlay"
    assert common.port_label(62078) == "iPhone Wi-Fi sync"
    assert common.port_label(443) == "secure web"
    assert common.port_label(55000) is None          # a random ephemeral port has no name


def test_port_label_friendly_name_wins_over_os(monkeypatch):
    """The curated plain-words name is used even when the OS would return a terse one for that port."""
    import socket
    monkeypatch.setattr(socket, "getservbyport", lambda *a: "https")
    assert common.port_label(443) == "secure web"    # KNOWN_PORTS, not the OS "https"


def test_port_label_falls_back_to_os_service(monkeypatch):
    """A port LanWard hasn't curated still gets a name from the OS service database (other users' gear)."""
    import socket
    monkeypatch.setattr(socket, "getservbyport", lambda port, proto: "amqp" if port == 5672 else None)
    assert common.port_label(5672) == "amqp"


def test_port_label_none_when_os_has_no_name(monkeypatch):
    import socket
    def _raise(*a):
        raise OSError("not found")
    monkeypatch.setattr(socket, "getservbyport", _raise)
    assert common.port_label(40001) is None


def test_dashboard_port(monkeypatch):
    monkeypatch.delenv("PORT", raising=False)
    assert common.dashboard_port() == 8080                 # default
    monkeypatch.setenv("PORT", "5114")
    assert common.dashboard_port() == 5114
    monkeypatch.setenv("PORT", "not-a-number")
    assert common.dashboard_port() == 8080                 # falls back, never raises
