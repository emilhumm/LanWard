# LanWard test framework

The goal is to surface **every class of bug** in LanWard — in the code and in what a user can do to it —
with a suite that runs anywhere in seconds and never touches the real network.

## How to run

```bash
python -m pytest                 # everything
python -m pytest tests/area_common -q
python -m pytest --cov=. --cov-report=term-missing    # with coverage (pytest-cov installed)
```

Everything runs on the Windows laptop. `conftest.py` stubs `fcntl`, points LanWard at a throwaway
SQLite DB per test, and **blocks the network** (an autouse fixture makes `socket.connect`,
`common.http_get`/`http_json` fail or return "no answer"). A test that exercises a network path
**mocks the specific call** (`common.http_get`, `scan.run_nmap`, `subprocess.run`, `smbclient`, the raw
socket) — it never reaches the LAN or a machine running LanWard.

## Hard rules for everyone

1. **Never** ssh to a machine running LanWard, scan the LAN, or run nmap/tshark/smbclient for real. Mock them.
2. **Never modify production code** while testing. A test that reveals a bug is a *finding* — report it,
   do not fix it. Fixes happen in a separate, reviewed pass.
3. **Never edit `conftest.py` or another area's files.** Need a fixture of your own? Add a
   `tests/<your-area>/conftest.py`.
4. Each test is isolated: use the `db`, `make`, `client`, `post` fixtures; never share state between tests.
5. When you reproduce a bug we already fixed this cycle, keep it as a **regression test** so it can't
   come back.

## The shared harness (`conftest.py`)

| Fixture | What it gives |
|---|---|
| `db` | a migrated, empty `scanner.db` on a per-test temp dir (`common.DB_PATH` is pointed at it) |
| `make` | builders: `make.scan()`, `make.host(scan_id, …)`, `make.observation(source, mac, …)`, `make.label(mac, …)`, `make.kv(k, v)` |
| `client` | a Flask test client with auth removed |
| `post` | `post(path, data)` with the same-origin `Origin` header the app requires |
| `_block_network` | autouse; fails loudly on real network use |

Schema reference: `db/schema.sql` (+ `common.migrate` adds later columns). `scans` has **no status
column** — a scan row *is* a finished scan. `host_labels.created_at/updated_at` are NOT NULL.

## The eight test dimensions

Every area covers the ones that apply to it:

1. **Unit** — pure functions with clear in→out. MAC/CIDR/time helpers, settings precedence, model
   extraction, fingerprints, finding builders, period maths, CSV cells.
2. **Parsing / fixtures** — feed known inputs (tshark field rows, mDNS TXT, UPnP/SSDP XML, DHCP options,
   TLS cert strings, CISA JSON) and assert the parsed result. Include **malformed** inputs.
3. **Database / migration** — `migrate()` is idempotent on a fresh DB *and* a legacy-shaped one; runs
   twice with no error; retention deletes exactly the right rows and keeps the rest; kv/WAL behave.
4. **Dashboard / routes** — every route returns the right status on an **empty** DB and a **populated**
   one; templates render without raising; CSV exports have correct headers/rows; the API needs the key
   (or an allow-listed IP); POSTs need same-origin.
5. **Robustness / fuzz** — malformed/hostile input must never 500 or crash a scan: corrupt JSON in
   `details`/`upnp_info`/`findings`/`web_info`, non-dict `txt`, huge/empty/unicode values, path
   traversal in `/host/<mac>`, injection in search/filter params, bad settings input.
6. **Behaviour / integration** — a finding flows to one alert; `is_new` dedupes (once per 30 days);
   offline→online; gateway spoof / rogue DHCP / network-scan / IPv6-RA detection; the EOL/known-flaw
   pipeline; carried-forward findings don't duplicate.
7. **Regression** — one test per bug found this cycle (see the list below).
8. **Concurrency / locking** — the scan lock; writers don't deadlock; `migrate` under load; no
   "database is locked" on the paths that hold a transaction.

## Reporting (what each tester hands back)

A short report:
- **Tests written:** count + the files, and the `pytest` pass/fail summary line.
- **Findings:** for each real bug, `file:line`, a one-line claim, a concrete repro (inputs → wrong
  output/crash), **severity** (crash/data-loss > wrong-result > cosmetic), and a suggested fix. A
  failing regression test that captures it is ideal.
- Keep tests that pass (they are the suite); mark tests that fail *because of a product bug* with
  `@pytest.mark.xfail(reason="BUG: …", strict=False)` so the suite stays green while the bug is tracked.

## Regression list (bugs fixed this cycle — keep them caught)

- Duplicate eol/kev findings on carried-forward (ports-unscanned) hosts.
- CISA KEV cache poisoning: a non-JSON 200 overwrote the good list.
- Tapo KEV matcher `tapo|c2\d\d` also matched TP-Link Archer C2### routers.
- `_signals` TypeError on a non-string UPnP field aborted the whole support pass.
- mDNS model shown as the platform word "WEBOS" instead of the real model; `name_hint` the same.
- firmware dedupe suppressed a distinct version by substring.
- settings sub-tabs: a hidden section leaked through; fields in a hidden tab must still submit.
- `_saved_override`: the page-set IFACE/SUBNET must be read at startup, ahead of `.env`.

## Area ownership (this cycle's team)

| Area | Modules | Lead focus |
|---|---|---|
| A | `common.py`, `supportcheck.py` | unit, parsing, regression |
| B | `homechecks.py`, `scan.py` | finding logic, scan helpers (mock the network) |
| C | `passive-monitor.py`, `db/enrich.py` | field/packet parsing from fixtures |
| D | `dashboard/app.py` + templates | routes, rendering, CSV, API, settings |
| E | `watcher.py`, `alerts.py`, `activity.py`, `retention.py`, `backup.py` | behaviour, dedup, retention |
| F | cross-cutting | robustness/fuzz, migration, concurrency, the regression list |
