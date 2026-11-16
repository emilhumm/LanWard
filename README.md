# LanWard: a security monitor for your home network

LanWard runs on an always-on Linux machine at home (a Raspberry Pi 4 or 5, a
mini PC, a NAS that runs Docker), plugged into the router or a switch by cable.
It listens to what devices announce on the network, scans them politely on a
schedule you choose (four times a day by default), and tells you when something
needs a look: a new device, a device
pretending to be your router, a camera stream without a password. It knows no
particular service: its alerts go to whatever you choose (Home Assistant, your
phone through ntfy or Telegram, Node-RED, a script), and anything can read its
report through a small API.

What it tells you, and how fast:

| You want to know | How | When |
|---|---|---|
| A **new device** joined the network (guest, neighbour on the Wi-Fi, new gadget) | listening to DHCP/ARP/mDNS | alert ~1 minute after it joins |
| Someone **pretends to be the router** (ARP spoofing, fake IPv6 router advertisements) or runs a **second DHCP server** | listening | alert within 30 s |
| Something **scans your network** (malware, an intruder, a scanner app) | listening to ARP | within 5 min: a warning for an unnamed device, a quiet note for a named one |
| A **watched device went offline** (camera, NAS, Home Assistant...) and back, and how often | ARP ping once a minute | alert after 10 min (configurable); uptime history per device |
| **Risky things on your devices**: Telnet/FTP/VNC/Docker API, Redis/MongoDB/Memcached reachable from the LAN, shared folders open to guests and SMB1-only file sharing, Shellys without a password or with an update pending, Frigate's open port 5000, logins over plain HTTP, certificates about to expire or expired, ports opened on the router by UPnP | polite scan on each scheduled run (every 6 h by default) | one grouped alert per scan with new findings, sent when one of them is a warning or worse (tips such as plain-HTTP logins, Shelly updates and "UPnP is on" stay on the dashboard) |
| A device starts **listening on a port it never had open** (a new service, or something that should not be there) | every port of every device once a day by default (configurable; can be off), spread over the scans; the ports found before at every scan; LanWard's own machine read every minute | a warning (a note for ports from 49152 up, which phones and computers open as apps run; nothing when a service comes back on a new random port after a restart, as NFS's helpers do); within a minute on LanWard's machine |
| A device is on **CISA's list of flaws being used in real attacks**, or its maker **no longer ships security updates** (end of life) | the model each device announces (LLDP/UPnP/mDNS/its own name), matched against CISA's list (downloaded daily) and a built-in support table | an alert for a flaw in active use; a quiet dashboard note for end-of-life. Only devices that announce a model; a model known from the device's own name is marked "probably". Turn it off in Settings |
| Inventory: who is on the network, makers, names, services and the web pages they show (each as a link), history | scans + listening | dashboard and API |
| Whether the network is **busier or quieter than usual** for the hour, and devices out of their routine (gone quiet for days, or suddenly far chattier) | listening, hour by hour | dashboard (Network activity) and API; learned over the first 5 days |

Every alert fires **once** per condition. Scan findings and "ghost" addresses
alert again only after the condition has been gone for 30 days; a replaced TLS
certificate or new firmware alerts once per new certificate or version. The
watcher repeats a router-impersonation or fake-IPv6-router alert once a day for as
long as it lasts (a router advertisement with lifetime 0, as Apple TVs and
HomePods send for their Thread network, offers no route and never alerts),
a second-DHCP-server alert when that server is back after a day away (servers in
`DHCP_SERVERS_OK` are fine), and a duplicate IP after 7 days; two devices count as
sharing an address only when both answered within 10 minutes of each other. A
watched device's "offline" is sent, and its "back online" only when that
"offline" was. A new device that uses the host name of a named device that is
away, from a private MAC, shows as "probably <name>" (info) and is still sent.
A device that asks for 50 or more addresses within 10 minutes is mapping the
network: phones with a scanner app, access points drawing their network map and
laptops do this now and then, so a named device gets a note on the dashboard and
an unnamed one a warning that is sent; at most once a month per device, never
for devices allowed to scan (Settings) or while a new install is still learning.

## Install

You need Linux with Docker and its compose plugin, on a machine wired to your
network. Docker Desktop on a Mac or Windows PC does not work: LanWard needs the
host's own network interface, which Docker Desktop does not give containers.

```bash
git clone https://github.com/emilhumm/LanWard.git lanward
cd lanward
docker compose up -d --build
docker logs lanward           # the network it found
```

Then open `http://<that machine's address>:8080` and log in with the default
password `lanward` (a banner reminds you to change it until you do). On the
**Settings** page you change it, choose where alerts go, send a test alert and
find the API key. No `.env` is needed (see Settings below).

The tabs: **Overview** (is all well, in one sentence and a line of small icons, and
how busy the network is against what is usual; what is worth a look, including
alerts nobody has seen yet, the watched devices and the security checks open as
popups from their item), **Network** (every
device around the router, grouped by kind), **Devices** (the same
devices as a table, each with its own page), **Alerts**, **Traffic** (who asks
for whom, the services devices offer, everything heard) and **Settings**.

- **The first day LanWard learns** what is already at home: devices it sees
  then raise no "new device" alert. Give the ones you know a name under *Name
  new devices* on the Overview; a name marks a device as yours. Tick *watch* on
  the ones you want an alert for when they go offline. (`LEARN_HOURS`, 24.)
- The first scan runs a couple of minutes after the start, then at the hours in
  `SCAN_HOURS` (00, 06, 12 and 18 by default; set it empty for no scheduled scans
  and run them by hand from the dashboard).
- Update: `git pull`, then `docker compose up -d --build` (the build only does
  something when the Dockerfile changed).

## Getting LanWard's data out

### Alerts, as they happen

All optional, any combination, set on the Settings page (*Alerts out*), where
*Send a test alert* tries them (or `docker exec lanward python3 common.py test-push`).

- **Webhooks** (`WEBHOOK_URLS`): every alert is POSTed as JSON to each of these
  URLs. For Home Assistant, Node-RED, n8n, your own script:
  ```json
  {"severity": "warning", "kind": "offline", "title": "NAS is offline",
   "message": "- NAS (192.168.1.20) has not answered for 10 minutes.",
   "time": "2026-10-27T14:05:44", "url": "http://192.168.1.50:8080/alerts"}
  ```
  `severity` is info, warning or alert; `kind` is new_device, gateway, dhcp,
  ip_conflict, offline, online, finding, tls, firmware or ghost.
- **Phone pushes** (`NOTIFY_URLS`): a message straight to your phone or inbox,
  no other system needed, through [Apprise](https://github.com/caronc/apprise/wiki): for example
  `ntfy://my-lanward-topic` (the free ntfy app), `tgram://bot-token/chat-id`
  (Telegram), `pover://user@token` (Pushover), `mailtos://user:pass@gmail.com`.
- **Send** (`NOTIFY_MIN_SEVERITY`): the lowest severity that is sent (warnings
  and alerts; info stays on the dashboard). "Back online" follows the "offline" it ends.

A destination that does not answer (Home Assistant restarting, no internet) gets
the alert again every 30 s for up to 48 hours, marked as delayed. The Overview
shows whether alerts are getting out.

### The report, whenever you ask (API)

Read-only JSON over HTTP, for anything that can fetch a URL:

| GET | What |
|---|---|
| `/api/status` | The summary: `level` (ok, warn, fail) and `summary` ("All well", "2 to look at"), `scan_running` (a scan is running now), open alerts, security findings, unnamed devices, watched devices up or down, the last hour's `activity` against what is usual (`verdict`: as usual, busier, quieter... or learning), whether LanWard's own processes and alerts keep up |
| `/api/devices` | Every device: name, IP, MAC, maker, kind, online now, open ports, findings |
| `/api/alerts` | The newest alerts (`?limit=`, default 100; `?open=1` for unacknowledged ones) |

Send the API key as a header. It is on the Settings page (*Get LanWard's
data*, with *New key* to replace it, which stops the old one), or
`docker exec lanward python3 common.py api-key`:

```bash
curl -H "Authorization: Bearer <key>" http://192.168.1.50:8080/api/status
```

Addresses listed under *Read the API without the key* on the Settings page
(`STATUS_ALLOW`) may read it without the key, and a browser logged in to the
dashboard may too.

### Example: Home Assistant

A sensor with the report, polled every minute (`configuration.yaml`):

```yaml
rest:
  - resource: http://192.168.1.50:8080/api/status
    headers:
      Authorization: Bearer YOUR_API_KEY
    scan_interval: 60
    sensor:
      - name: LanWard
        value_template: "{{ value_json.summary }}"
        json_attributes: [level, alerts_open, findings, unknown_devices, watched]
```

Alerts to your phone through the Home Assistant app: add
`http://<Home Assistant>:8123/api/webhook/lanward-<a long random ID>` as a
webhook (the ID works like a password), and add this automation
(Settings → Automations → new → ⋮ → Edit in YAML), with your phone's notify
action (Developer tools → Actions, search `notify.mobile_app`). Turn the
automation off whenever you don't want the notifications; LanWard keeps
recording alerts either way.

```yaml
alias: LanWard alerts to phone
mode: queued
triggers:
  - trigger: webhook
    webhook_id: lanward-YOUR-RANDOM-ID      # the ID at the end of the URL
    allowed_methods: [POST]
    local_only: true
actions:
  - action: notify.mobile_app_YOUR_PHONE    # your phone's notify action
    data:
      title: "{{ trigger.json.title }}"
      message: "{{ trigger.json.message }}"
      data:
        url: "{{ trigger.json.url }}"
        push:
          interruption-level: >-
            {{ 'time-sensitive' if trigger.json.severity == 'alert' else 'active' }}
```

Notifications through the Home Assistant app, ntfy or Telegram pass through
those services' servers on their way to the phone, so the alert text (device
names, addresses) does too. LanWard itself only talks to your network, and to
the services you list.

## Settings

The dashboard's **Settings** page holds what a home sets: the dashboard
password, where alerts go and from which severity, the scan hours, how long scan
history and backups are kept, how long a watched device may be silent, who may
read the API without the key, other DHCP servers that are meant to be there,
devices allowed to scan the network, how often every port of each device is checked.
A change applies at once, without a restart. The page also shows the network
LanWard found and ends the first day's learning early if you like.

`.env` (next to `docker-compose.yml`, template `.env.example`) is optional. Its
values are the starting point; whatever is saved on the Settings page wins. It
is the place only for what the dashboard needs before it starts, or rarely
matters: `DASHBOARD_PORT` (8080), `IFACE` / `SUBNET` / `DASHBOARD_URL` if
LanWard finds the wrong network or address, `TZ` (default: the host's time
zone), `LEARN_HOURS` (24), `LANWARD_CODE` / `LANWARD_DATA_DIR` (folders). After
editing it: `docker compose up -d`.

## How it works

One container, `lanward` (image `lanward-app`), host networking. Its main
process, `docker/entrypoint.py`, runs and supervises:

| Process | File | Does |
|---|---|---|
| dashboard | `dashboard/app.py` | web UI and API on `$DASHBOARD_PORT` (8080), served by Waitress |
| passive monitor | `passive-monitor.py` | tshark on the network interface, kernel-filtered to ARP, DHCP, mDNS, NetBIOS, LLDP, CDP and IPv6 router advertisements → `observations` table, and packets per device and hour → `activity` |
| watcher | `watcher.py` | every 30 s: new devices, router impersonation (ARP and IPv6), second DHCP server, duplicate IPs, network scans, watched devices offline (each outage goes in `outages`); resends alerts a destination did not take |
| scan (`SCAN_HOURS`; default 00, 06, 12, 18) | `scan.py` → `db/enrich.py` → `homechecks.py` → `alerts.py` | ARP sweep + port check, enrichment, home-security checks, alerts |
| backup (daily 03:30) | `backup.py` | a checked, gzipped copy of `scanner.db` in `data/backups/`, kept `BACKUP_KEEP_DAYS` (14) |
| retention (Sun 04:30) | `retention.py` | drop observations unseen for 366 days, hourly activity counts older than 366 days, scan logs older than 30 days, scans older than `RETAIN_SCAN_DAYS` (365) with their device rows (the newest scan always stays), acknowledged alerts older than 365 days; then VACUUM |

Shared code: `common.py` (paths, the network it watches, DB + schema migration,
alert de-duplication and delivery, vendor lookup). Schema: `db/schema.sql`;
`common.migrate()` upgrades any older `scanner.db` in place at start. The code
is mounted into the container read-only; everything LanWard keeps is in the data
folder (`./data`: `scanner.db`, `scan-logs/`, `backups/`).

**Known device = a device with a name.** Name unknown devices on the Overview;
tick *watch* to get offline/online alerts for one, and its uptime over the last
30 days (outages from the first check that finds it down until it answers again;
blips under 2 minutes and time LanWard itself was not running do not count).

An unnamed device is shown with what it says about itself, in this order: the
model in its mDNS records, its DHCP host name, its mDNS host name, its Windows /
Samba (NetBIOS) name, then the newest scan's UPnP model or name and reverse-DNS
name. Sonos speakers behind a SonosNet bridge answer with the bridge's MAC; a
scan gives each its own MAC from its UPnP RINCON id (the bridge's is kept as
`bridge_mac`), only where several addresses share one MAC, and the dashboard
counts such a speaker as heard when its own address is.

**Network activity** (Overview, `activity.py`). On a switched network LanWard
hears what every device hears: devices announcing themselves and looking for
each other (ARP, DHCP, mDNS...), not their downloads. Per hour it counts the
devices heard and their packets; LanWard's own scans and pings, and the answers
to them, are not counted, and its own machine is left out. What is usual for an
hour is the 10th to 90th percentile of the same hour of the day over the last 4
weeks, weekdays and weekends apart (all days together while either has fewer
than 5), so the shaded range shows after 5 days of counting; the grey "usual"
line through it is the median. The panel shows devices or chatter (a switch),
says how the last full hour compares and draws the last 24 hours or 7 days
against that range; a ring marks an hour far outside it (by more than the range
is wide). The 30-day view has one point per day: devices heard that day and all
their packets, against the same kind of day (weekday or weekend) over the 4
weeks before; a day shows once it is over (the day counting began is left out,
it is not whole), and today's chatter so far is drawn dashed. The 365-day view is
the same, one point per day, without the usual range (that is the last 4 weeks'
usual); hourly counts are kept 366 days. *Out of the ordinary* lists named devices heard on most days (half the
days LanWard listened, in the 14 days before they went quiet; a scan finding
them counts) that have not been heard for over a day, up to 14 days, and any
device that sent at least 3 times its usual busiest hour (90th percentile of its
hours over 14 days, once it has 48 of them) and 300 packets more. Watched devices
are left out: they have their own alerts.

### What a scan sends (safe, read-only)

- ARP sweep (`nmap -sn -T3`). Devices that should be there but miss it (in the
  previous scan, or heard in the last 30 minutes) are asked again, more patiently
  (`-sn -PR --max-retries 6 --max-rtt-timeout 2s`): a phone or tablet with its
  screen off can miss the sweep's one question. One that still does not answer but
  was heard in the last 10 minutes is counted anyway, its ports "not checked".
- TCP connect check of the home-relevant ports (`scan.py` `PORT_LABELS`) plus every
  port found open on the device in the last 30 days: `-sT -T3 --max-rate 100
  --max-retries 1 --host-timeout 300s`, all devices at once (up to 64), at most 100
  probes a second for the whole network. (It used to be one probe every half second
  per device, which made devices that ignore probes take 3–4 minutes; every device
  gets the far faster every-port check once a day anyway.) A device whose check does not finish is saved as
  "ports not checked" (not as "nothing open") and keeps the findings of its last
  checked scan.
- Every port (1–65535) of the devices whose turn it is: each scan takes its share,
  so every device gets one every `FULL_PORT_CHECK_DAYS` days (Settings, 1; 0: never)
  at however many scans a day are set. A half-open (SYN) scan, `-sS --send-ip -T3
  --max-retries 0 --min-rate 800 --max-rate 1000 --host-timeout 10m`, up to 6
  devices at a time: 800–1,000 probes a second shared by them, one per port (a port
  missed is found on the next turn). The minimum rate keeps nmap from slowing to a
  crawl on a device that answers nothing; such a device takes about 8 minutes at
  worst, and one that takes longer than 10 is tried again on its next turn. The
  scan log says how long each device took. A device that shows nothing open but had
  open ports in the last 30 days gets the usual check instead (it was more likely
  asleep). Sonos speakers behind a SonosNet bridge, which all answer with the
  bridge's MAC, take their turn under the MAC in their Sonos id (asked on port
  1400 at the start of the scan), and so have a port history and new-port alerts
  too. A device's first full check
  is its baseline; after that a port it never had open before is alerted.
- LanWard's own machine is not scanned: the ports it listens on (other containers'
  published ports included) are read from `/proc/net/tcp`, at every scan and by the
  watcher every minute.
- Per open web port, one `GET /`; on any other open port that is not a known
  non-web service, one `GET /` over HTTP, else HTTPS, so a dashboard on an unusual
  port shows with its page title (also on Telnet's ports 23 and 2323: a device that
  answers there with a web page, like Fully Kiosk's remote admin on 2323, is a web
  page, not Telnet); the TLS certificate of each HTTPS port; SSH banner; reverse DNS;
  one UPnP/SSDP search, a burst of mDNS queries, one WS-Discovery probe, an IPv6
  all-nodes ping.
- Shellys: `GET /shelly` (their public info endpoint) and, only when no password
  is set, `/status` or `/rpc/Sys.GetStatus` for pending updates.
- Router: if it offers UPnP, its device description and the read-only
  `GetGenericPortMappingEntry` call, only on the router's own address.
- MQTT (1883): one CONNECT without a user name, to see whether the broker refuses
  it (disconnects at once). RTSP (554/8554): one `DESCRIBE` without credentials per
  common stream path, to see whether the camera asks for its account. VNC (5900):
  the RFB handshake up to the server's list of security types, then it hangs up
  without picking one, to see whether "no password" is on offer. All three turn an
  "is open" finding into "needs a password" (fine) or a warning with the remedy.
- SMB (445): `smbclient` without a password lists the shares, then lists the top
  folder of each visible disk share (hidden `$` shares are skipped); a device that
  does not negotiate SMB2 or later is asked once more with SMB1 allowed. Result: a
  warning naming shares that open without a password (with the fix for Windows,
  Home Assistant's Samba add-on or an Asus router), info when only the names show
  or a password is needed, and a warning when the device speaks only SMB1.

No exploits, no logins, no password guessing, no changes to any device.

## Running it

```bash
docker logs -f lanward                          # everything: scans, watcher, tshark
docker exec lanward python3 scan.py             # scan now (or Run scan in the dashboard)
docker exec lanward python3 common.py test-push # try the alert destinations
docker exec lanward python3 common.py api-key   # the API key
docker compose up -d                            # after editing .env
ls data/scan-logs/ data/backups/                # one log per scan; nightly backups
```

The dashboard is meant for your home network only: nothing in LanWard opens a
port on the router. Use a VPN to reach it from outside.

**Restoring a backup.** The nightly copies are in `data/backups/` (checked,
gzipped, kept 14 days by default; keep them on another disk too if you can: they
share the machine's disk). In the folder with `docker-compose.yml`:

```bash
docker compose stop
gunzip -c data/backups/scanner-20261027-033000.db.gz > data/scanner.db
rm -f data/scanner.db-wal data/scanner.db-shm    # leftovers of the replaced database
docker compose start
```

### Deploying from another machine (optional)

Instead of `git pull` on the LanWard machine, you can keep the working copy
elsewhere and push it over ssh. Put `REMOTE_HOST=user@host` in `.deploy.env`
(git-ignored), then `bash deploy.sh` copies the code to `/srv/lanward/code` there
and restarts the container; `bash deploy.sh --build` also rebuilds the image.
The first time, run `bash deploy.sh --no-restart`, then on the target
`cd ~/projects/lanward && sudo bash install/install.sh` (as the account that runs
Docker). That sets up `/srv/lanward` (its `.env` gets `LANWARD_CODE=./code`) and
two systemd units: `lanward.service` (`docker compose up -d` at boot; Docker's
restart policy does the same for a plain install) and `lanward-backup.timer`,
which copies a checked `scanner.db` nightly (02:30–02:35) to a share you mount at
`/mnt/router-backup` and keeps 30 days; `sudo bash install/install.sh enable`
turns both on. After a change to `install/` or `backup/`: deploy, then on the
target `cd ~/projects/lanward && sudo bash install/install.sh units`. `deploy.sh` syncs
nothing while a scan is running (the scan would load new code halfway through);
run it again afterwards, or add `--force`.

## License

MIT, see [LICENSE](LICENSE). `dashboard/static/htmx.min.js` is
[htmx](https://htmx.org), under its own Zero-Clause BSD licence.
