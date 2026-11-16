-- scanner.db schema. Applied by common.migrate() at every process start, so
-- everything here must be idempotent (CREATE ... IF NOT EXISTS). Columns added
-- after a table first shipped are added in common.migrate() instead.

CREATE TABLE IF NOT EXISTS scans (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  subnet      TEXT NOT NULL,
  started_at  TEXT NOT NULL,        -- ISO local time
  host_count  INTEGER,
  source_file TEXT UNIQUE,          -- unused (always NULL)
  notes       TEXT                  -- scanner version, scan.SCAN_NOTES ("lanward home v2")
);

-- One row per device per scan.
CREATE TABLE IF NOT EXISTS hosts (
  scan_id              INTEGER NOT NULL,
  ip                   TEXT NOT NULL,
  mac                  TEXT,          -- lower-case
  vendor               TEXT,
  hostname             TEXT,
  ports                TEXT,          -- comma list of service labels: "ssh,http,mqtt"
  open_ports           TEXT,          -- JSON list of open TCP port numbers; NULL: nmap did not finish (unknown)
  firmware             TEXT,
  http_server          TEXT,
  http_title           TEXT,
  web_info             TEXT,          -- JSON {port: {status, server, title, tls, login, cert: {fingerprint, cn, not_after}}}
  ssh_banner           TEXT,
  tls_cert_cn          TEXT,
  tls_cert_issuer      TEXT,
  tls_cert_not_before  TEXT,
  tls_cert_not_after   TEXT,
  tls_cert_fingerprint TEXT,
  tls_cert_san         TEXT,
  mdns_services        TEXT,
  upnp_info            TEXT,          -- JSON
  ipv6_addrs           TEXT,          -- JSON list
  findings             TEXT,          -- JSON list of home-security findings (homechecks.py); from_scan
                                      -- on one = carried over from that scan (ports not checked this time)
  bridge_mac           TEXT,          -- the MAC ARP answered with when it is not the device's own (mac):
                                      -- Sonos speakers behind the SonosNet bridge (2026-10-27)
  PRIMARY KEY (scan_id, ip),
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alerts (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at      TEXT NOT NULL,
  scan_id         INTEGER,
  prev_scan_id    INTEGER,
  severity        TEXT NOT NULL,      -- alert | warning | info
  title           TEXT NOT NULL,
  details         TEXT,
  acknowledged    INTEGER DEFAULT 0,
  acknowledged_at TEXT,
  kind            TEXT                -- new_device, gateway, offline, finding, ...
);

-- "Fire once, then again only when something changes": see common.is_new().
CREATE TABLE IF NOT EXISTS alert_memory (
  key      TEXT PRIMARY KEY,
  first_at TEXT NOT NULL,
  last_at  TEXT NOT NULL
);

-- A label marks a device as known (approved). watch_offline: alert when it
-- stops answering.
CREATE TABLE IF NOT EXISTS host_labels (
  mac                 TEXT PRIMARY KEY,
  label               TEXT NOT NULL,
  note                TEXT,
  suppress_new_alert  INTEGER DEFAULT 1,   -- legacy, unused
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL,
  watch_offline       INTEGER DEFAULT 0
);

-- Written by passive-monitor.py (and the WS-Discovery probe in enrich.py).
CREATE TABLE IF NOT EXISTS observations (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  source      TEXT NOT NULL,            -- arp|arp_req|dhcp|dhcp_server|mdns|lldp|cdp|wsd|ra|netbios
  mac         TEXT,
  ip          TEXT,
  hostname    TEXT,
  vendor      TEXT,
  details     TEXT,                      -- JSON, protocol-specific
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  count       INTEGER DEFAULT 1,
  UNIQUE(source, mac, ip)
);

-- Broadcast/multicast packets heard from each device per hour (passive-monitor.py), for
-- the activity charts: observations keep only first/last seen and a running total.
-- LanWard's own ARP and the answers sent back to it are not counted (since kv
-- activity_clean_since). activity.py compares each hour with the same hour on earlier days;
-- retention.py keeps 366 days.
CREATE TABLE IF NOT EXISTS activity (
  mac   TEXT NOT NULL,                   -- lower-case sender (eth.src)
  hour  TEXT NOT NULL,                   -- local time, "2026-10-26T17"
  n     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (mac, hour)
);

-- Per-day counts of observations (2026-10-29), so the Traffic views can show, for real, how many times
-- something happened in the chosen period. The passive monitor increments (source, mac, ip, local day);
-- a missing mac/ip is stored as ''. retention.py drops days older than 366. For the window before this
-- existed, the Traffic views estimate from each rollup's lifetime rate.
CREATE TABLE IF NOT EXISTS observation_counts (
  source TEXT NOT NULL,
  mac    TEXT NOT NULL DEFAULT '',
  ip     TEXT NOT NULL DEFAULT '',
  day    TEXT NOT NULL,                  -- local "2026-10-29"
  n      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (source, mac, ip, day)
);

-- Hourly tally of ARP "who has <ip>" asks, per (asker mac, target ip), so the ghost-address rate
-- (alerts.ghost_targets) is a true rolling last-24-hours, not a calendar-day average. The monitor writes
-- it; retention.py prunes hours older than a few days (2026-10-31).
CREATE TABLE IF NOT EXISTS arp_ask_hours (
  mac  TEXT NOT NULL DEFAULT '',
  ip   TEXT NOT NULL DEFAULT '',
  hour TEXT NOT NULL,                    -- local "2026-10-31T14"
  n    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (mac, ip, hour)
);

-- Every TCP port found open on a device, ever (2026-10-27): scan.py and, for LanWard's own machine, the watcher.
-- A port a device never had open before, once it has had a full check, is alerted (kind new_port). Ports not in
-- scan.py's PORT_LABELS are checked again at every scan; retention.py drops ports not seen for 180 days.
CREATE TABLE IF NOT EXISTS open_ports_seen (
  mac         TEXT NOT NULL,
  port        INTEGER NOT NULL,
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  PRIMARY KEY (mac, port)
);

-- When each device last had every port (1-65535) checked, when that was last tried (a check can run out of
-- time) and when it first was. The hour after its first full check is the baseline: nothing found then is "new"
-- (services still starting after a reboot, or LanWard's own dashboard just after the container started).
CREATE TABLE IF NOT EXISTS port_checks (
  mac              TEXT PRIMARY KEY,
  full_checked_at  TEXT,
  full_tried_at    TEXT,
  first_full_at    TEXT
);

-- Online/offline state of watched devices (watcher.py).
CREATE TABLE IF NOT EXISTS watch_state (
  mac      TEXT PRIMARY KEY,
  state    TEXT NOT NULL,               -- up | down
  since    TEXT NOT NULL,
  last_ok  TEXT,
  last_ip  TEXT,
  alerted  INTEGER DEFAULT 0
);

-- Offline periods of watched devices (watcher.py), for uptime (common.uptime): one row per
-- outage from the first check that found the device down to the first that found it back;
-- ended_at NULL while it lasts. Local wall-clock times, corrected by the watcher when the
-- clock jumped during the outage. retention.py keeps 400 days (2026-10-27).
CREATE TABLE IF NOT EXISTS outages (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  mac         TEXT NOT NULL,             -- lower-case
  started_at  TEXT NOT NULL,
  ended_at    TEXT,
  alerted     INTEGER DEFAULT 0          -- 1: it lasted long enough for an offline alert
);

-- Small key/value store: gateway MAC baseline, process heartbeats, flags,
-- homechecks_done (the newest whole-LAN scan whose security checks finished).
CREATE TABLE IF NOT EXISTS kv (
  key        TEXT PRIMARY KEY,
  value      TEXT,
  updated_at TEXT
);

-- Pushes a service did not take (Home Assistant restarting, no internet for ntfy...),
-- sent again by the watcher every 30 s until they go through or are 48 h old (2026-10-13).
CREATE TABLE IF NOT EXISTS notify_outbox (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at  TEXT NOT NULL,
  payload     TEXT NOT NULL,           -- JSON {severity, kind, title, message, url}
  attempts    INTEGER DEFAULT 1,
  last_error  TEXT,
  target      TEXT                     -- "ha" or "apprise:<hash of the URL>"; NULL = "ha" (2026-10-27)
);

CREATE INDEX IF NOT EXISTS idx_hosts_mac    ON hosts(mac);
CREATE INDEX IF NOT EXISTS idx_hosts_vendor ON hosts(vendor);
CREATE INDEX IF NOT EXISTS idx_hosts_ip     ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_alerts_ack   ON alerts(acknowledged);
CREATE INDEX IF NOT EXISTS idx_alerts_scan  ON alerts(scan_id);
CREATE INDEX IF NOT EXISTS idx_obs_source   ON observations(source);
CREATE INDEX IF NOT EXISTS idx_obs_mac      ON observations(mac);
CREATE INDEX IF NOT EXISTS idx_obs_lastseen ON observations(last_seen);
CREATE INDEX IF NOT EXISTS idx_outages_mac  ON outages(mac, started_at);
CREATE INDEX IF NOT EXISTS idx_activity_hour ON activity(hour);
