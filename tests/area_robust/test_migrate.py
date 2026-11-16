"""Area F — database / migration.

common.migrate() must be idempotent on a fresh DB, bring a legacy-shaped DB up to the current
schema without error, lower-case the MACs scans used to store upper-case, and seed the kv rows the
rest of LanWard relies on. See tests/FRAMEWORK.md (Regression list + dimension 3).
"""
import sqlite3

import common


# The columns common.migrate() is responsible for adding on top of db/schema.sql.
HOSTS_ADDED = {"http_server", "http_title", "ssh_banner", "tls_cert_cn", "tls_cert_issuer",
               "tls_cert_not_before", "tls_cert_not_after", "tls_cert_fingerprint", "tls_cert_san",
               "mdns_services", "upnp_info", "ipv6_addrs", "open_ports", "web_info", "findings",
               "bridge_mac", "new_ports"}
ALERTS_ADDED = {"acknowledged_at", "kind"}
EXPECTED_TABLES = {"scans", "hosts", "observations", "alerts", "alert_memory", "host_labels", "kv",
                   "activity", "open_ports_seen", "port_checks", "watch_state", "outages",
                   "notify_outbox"}


def _cols(conn, table):
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _tables(conn):
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


# ── idempotent on a fresh DB ──

def test_migrate_twice_is_clean(db):
    """migrate() on an already-migrated DB runs again with no error and the schema is intact."""
    common.migrate(db)
    common.migrate(db)                      # third time overall: must not raise
    tables = _tables(db)
    assert EXPECTED_TABLES <= tables
    assert HOSTS_ADDED <= _cols(db, "hosts")
    assert ALERTS_ADDED <= _cols(db, "alerts")
    assert "watch_offline" in _cols(db, "host_labels")
    assert "first_full_at" in _cols(db, "port_checks")


def test_migrate_fresh_seeds_kv(db):
    """The kv rows later code reads are created by migrate()."""
    assert common.kv_get(db, "outages_since") is not None
    assert common.kv_get(db, "activity_clean_since") is not None
    assert common.kv_get(db, "mac_lowercase_done") is not None


# ── a legacy-shaped DB (missing the columns migrate adds) ──

def _legacy_db(path):
    """A minimal pre-current scanner.db: hosts without the later columns, alerts without kind/
    acknowledged_at, and nothing else. migrate() must upgrade it in place."""
    conn = sqlite3.connect(str(path))
    conn.executescript("""
        CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, subnet TEXT NOT NULL,
                            started_at TEXT NOT NULL, host_count INTEGER, source_file TEXT, notes TEXT);
        CREATE TABLE hosts (scan_id INTEGER NOT NULL, ip TEXT NOT NULL, mac TEXT, vendor TEXT,
                            hostname TEXT, ports TEXT, firmware TEXT, PRIMARY KEY (scan_id, ip));
        CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
                             scan_id INTEGER, prev_scan_id INTEGER, severity TEXT NOT NULL,
                             title TEXT NOT NULL, details TEXT, acknowledged INTEGER DEFAULT 0);
        CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT);
    """)
    conn.commit()
    return conn


def test_migrate_upgrades_legacy_db(data_dir):
    """A legacy DB missing open_ports/findings/new_ports/bridge_mac and alerts.kind/acknowledged_at
    gains them and migrate() runs clean."""
    conn = _legacy_db(data_dir / "scanner.db")
    # sanity: the legacy shape really is missing the columns
    assert "open_ports" not in _cols(conn, "hosts")
    assert "kind" not in _cols(conn, "alerts")

    common.migrate(conn)

    assert HOSTS_ADDED <= _cols(conn, "hosts")
    assert ALERTS_ADDED <= _cols(conn, "alerts")
    assert EXPECTED_TABLES <= _tables(conn)
    common.migrate(conn)                    # and still idempotent after the upgrade
    conn.close()


# ── the mac-lowercase migration ──

def test_migrate_lowercases_macs(data_dir):
    """Scans used to store MACs upper-case; migrate() lower-cases hosts + observations exactly once."""
    conn = _legacy_db(data_dir / "scanner.db")
    # observations table too (legacy DBs had it); build it the way schema.sql does
    conn.executescript("""
        CREATE TABLE observations (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL,
            mac TEXT, ip TEXT, hostname TEXT, vendor TEXT, details TEXT, first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL, count INTEGER DEFAULT 1, UNIQUE(source, mac, ip));
    """)
    conn.execute("INSERT INTO scans (subnet, started_at) VALUES ('192.168.10.0/24', ?)", (common.now_iso(),))
    conn.execute("INSERT INTO hosts (scan_id, ip, mac) VALUES (1, '192.168.10.9', 'AA:BB:CC:DD:EE:FF')")
    conn.execute("INSERT INTO observations (source, mac, ip, first_seen, last_seen) "
                 "VALUES ('arp', 'AA:BB:CC:DD:EE:FF', '192.168.10.9', ?, ?)",
                 (common.now_iso(), common.now_iso()))
    conn.commit()

    common.migrate(conn)

    assert conn.execute("SELECT mac FROM hosts").fetchone()[0] == "aa:bb:cc:dd:ee:ff"
    assert conn.execute("SELECT mac FROM observations").fetchone()[0] == "aa:bb:cc:dd:ee:ff"
    assert common.kv_get(conn, "mac_lowercase_done") is not None
    conn.close()


def test_mac_lowercase_runs_only_once(db, make):
    """Once mac_lowercase_done is set, a later upper-case MAC is left untouched (the migration is a
    one-off, not a trigger)."""
    sid = make.scan()
    # insert a raw upper-case MAC AFTER the first migrate() (db fixture) has set the done-flag
    db.execute("INSERT INTO hosts (scan_id, ip, mac) VALUES (?, '192.168.10.5', 'DE:AD:BE:EF:00:11')", (sid,))
    db.commit()
    common.migrate(db)
    assert db.execute("SELECT mac FROM hosts WHERE ip='192.168.10.5'").fetchone()[0] == "DE:AD:BE:EF:00:11"
