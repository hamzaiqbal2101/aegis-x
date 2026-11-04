# AEGIS X Management API (Milestone M2)

FastAPI service that stores firewall policies in SQLite, validates and
applies them by shelling out to the prebuilt `aegis-linux` Rust CLI, and
keeps an append-only audit log. It never touches the host firewall unless
an apply/rollback request explicitly supplies a network namespace or the
`confirm_host_apply` flag.

## Setup

```bash
cd ~/workspace/aegis-x/api
python3 -m venv .venv
.venv/bin/pip install fastapi uvicorn httpx pytest
```

## Run

```bash
cd ~/workspace/aegis-x/api
AEGIS_API_TOKEN='<your-admin-token>' .venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000
```

If `AEGIS_API_TOKEN` is unset, the server generates a random token at
startup, prints it to stderr once, and uses it for the process lifetime.
There is no hardcoded default token.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `AEGIS_API_DB` | `api/aegis.db` | SQLite path. Tests must use a tmp path. Ignored when the Postgres backend is selected. |
| `AEGIS_API_DB_BACKEND` | `sqlite` | Storage backend: `sqlite` (default) or `postgres` (`postgresql`/`pg` also accepted). Any other value is a loud error at `get_conn()` time, never a silent fallback. |
| `AEGIS_API_DB_URL` | (unset) | Postgres DSN, required when `AEGIS_API_DB_BACKEND=postgres`, e.g. `postgresql://user:password@127.0.0.1:5432/aegis`. There is no default DSN: selecting Postgres without this variable fails fast rather than connecting to a wrong database. Driver: `psycopg` (v3) preferred, `psycopg2` accepted; install with `api/.venv/bin/pip install "psycopg[binary]"`. |
| `AEGIS_API_TOKEN` | (generated at startup) | Admin Bearer token (full access). |
| `AEGIS_API_READONLY_TOKEN` | (unset) | Optional readonly Bearer token: GET endpoints only; any POST/PUT/DELETE/PATCH returns 403. When unset, behavior is unchanged (admin token only). |
| `AEGIS_API_PORT` | `8000` | Port (used by the `__main__` runner). |
| `AEGIS_API_BIND` | `127.0.0.1` | Bind address. `0.0.0.0` only if explicitly set here, and then a warning is logged. |
| `AEGIS_API_CLI` | `../target/debug/aegis-linux` | Path to the `aegis-linux` binary. |
| `AEGIS_API_STATE_DIR` | (CLI default `/var/lib/aegis-x`) | Passed as `--state-dir` to apply/rollback when set. |
| `AEGIS_FEED_URL` | (unset) | Threat-feed URL. The background refresh task runs ONLY when this is set. HTTP/HTTPS only. |
| `AEGIS_FEED_ALLOW_PRIVATE` | (unset) | Set to `1` ONLY for a lab/air-gapped feed on a private address. By default a feed host resolving to a private, loopback, link-local, multicast, reserved, or unspecified address is refused before any request is sent (SSRF guard), and any redirect is refused. |
| `AEGIS_FEED_INTERVAL_SECS` | `3600` | Background refresh interval in seconds (invalid or ≤ 0 values fall back to 3600). |
| `AEGIS_TELEMETRY_NFT_BIN` | `nft` | Binary used by `GET /telemetry/counters` (run as `<bin> -j list ruleset`). Tests point this at a fake script; never point it at anything that mutates state. |

## Endpoints

All endpoints except `GET /status` require
`Authorization: Bearer <token>`; missing/wrong token → `401`. The admin
token has full access; the readonly token (when `AEGIS_API_READONLY_TOKEN`
is set) may use GET endpoints only — a mutating request with it → `403`.

| Method & path | Body | Notes |
|---|---|---|
| `GET /status` | — | No auth. API version, engine availability, DB ok. (No install path is returned.) |
| `GET /policies` | — | List stored policies (with hashes). `?limit=` (default 1000, max 10000) and `?offset=` (default 0) bound the result. |
| `POST /policies` | `{name, policy}` | `policy` must be an object with `version`, `name`, `default_action`, `rules` or → `400`. |
| `GET /policies/{id}` | — | |
| `PUT /policies/{id}` | `{name?, policy}` | Same write validation as POST. |
| `DELETE /policies/{id}` | — | |
| `POST /policies/{id}/validate` | `{no_conntrack?}` (default `false`) | Runs CLI `check --policy <tempfile>`; returns CLI stdout/stderr verbatim plus `pass`. |
| `POST /apply` | `{policy_id, netns?, confirm_host_apply? (false), no_conntrack?}` | 400 and no CLI call unless `netns` or `confirm_host_apply=true`. |
| `POST /rollback` | `{netns?, confirm_host_apply? (false)}` | Same 400 gate as apply. |
| `GET /audit` | — | Append-only audit rows. No PUT/DELETE route exists for audit rows. Same `?limit=`/`?offset=` bounds as `/policies`. |
| `GET /feeds/status` | — | Last refresh time, last outcome (`never`, `success`, `fetch_failed`, `invalid_feed`, `not_configured`), last detail, and current (unexpired) indicator count. |
| `POST /feeds/refresh` | — | Admin-only. Triggers an immediate feed refresh and returns its outcome (`{outcome, count, detail}`). |
| `GET /telemetry/counters` | — | Read-only `nft -j list ruleset` counter parse. On ANY failure returns HTTP 200 with `{"available": false, "reason": "..."}`; on success `{"available": true, "counters": [{table, chain, handle, name, packets, bytes}, ...]}` with values exactly as reported by nft. Never invents numbers. |

## Validation model

Write-time validation (POST/PUT) is deliberately shallow: it rejects a
policy that is not a JSON object or lacks `version`, `name`,
`default_action`, or `rules` (400). Full semantic validation — zone
expansion, duplicate-rule detection, nft rendering — happens in the
`validate` endpoint via the CLI `check`, because the Rust engine is the
authoritative validator and duplicating its rules in Python would drift.

## Integrity hash

Every stored policy version carries a SHA-256 hash. The canonical form
implemented here is: `json.dumps(policy, sort_keys=True,
separators=(",", ":"), ensure_ascii=False)`, hashed with SHA-256, over
the policy JSON exactly as stored.

**This is NOT the same hash as the Rust engine's `policy_hash`.** The
Rust function in `crates/aegis-core/src/integrity.rs` hashes the
*normalized* policy struct serialized by serde_json: struct field order
(not sorted keys), defaults filled in (`mode`, `protocol: "any"`,
empty lists), zones expanded into `src_addrs`/`dst_addrs`, and rules
sorted by priority. Reproducing that byte-for-byte in Python would mean
re-implementing the whole Rust normalization, which this API does not
do. Cross-language hash equivalence is therefore NOT claimed. What is
guaranteed and tested: determinism (same stored policy → same hash) and
change-sensitivity (any change → different hash). Do not compare an API
hash with a CLI `policy hash:` line and expect equality.

## Threat-feed auto-refresh

When `AEGIS_FEED_URL` is set, a background asyncio task (started by the
app lifespan, so plain `TestClient` use without entering the lifespan
starts nothing) refreshes the feed immediately and then every
`AEGIS_FEED_INTERVAL_SECS` seconds. `POST /feeds/refresh` (admin-only)
runs the same refresh on demand.

Strict feed shape — anything else is rejected as `invalid_feed`:

```json
{"indicators": [{"type": "ip", "value": "203.0.113.7",
                 "expires_at": 4102444800},
                {"type": "domain", "value": "bad.example.test",
                 "expires_at": null}]}
```

Rules: top level must be an object with an `indicators` list; each
indicator must have exactly the keys `type`, `value`, `expires_at`;
`type` is `ip` (value must parse as an IP address) or `domain` (no
whitespace, `/`, or `:`); `expires_at` is a unix timestamp int or
`null`. Sample file in exactly this shape:
`examples/threat-feed-sample-api.json` — same indicators as the
Rust-format `examples/threat-feed-sample.json`, minus that file's
`allowlist` (the API feed format has no allowlist field). Indicators live
in the `feed_indicators` table; refresh state
in `feed_meta` (single row).

FAIL SAFE: a fetch failure or an invalid shape NEVER touches
`feed_indicators` — old indicators stay until their own expiry, and
`GET /feeds/status` counts only unexpired rows. Only a fully validated
feed replaces the stored set, in one transaction. Every refresh outcome
(success count, fetch failure, invalid shape) is appended to the audit
log as a `feed_refresh` row (actor `system` for background runs,
`admin` for manual refreshes).

SSRF guard (Nov 3, 2026 review): before fetching, the feed host is
resolved and every address must be public, unless
`AEGIS_FEED_ALLOW_PRIVATE=1`; URLs with credentials are refused; any
redirect is refused (urllib follows redirects by default); the response
body is capped at 1 MiB and the indicator list at 10,000 entries;
duplicate indicators collapse to the first occurrence instead of
tripping the UNIQUE constraint into a 500. Residual gap: DNS-rebinding
TOCTOU — an address changing between the check and connect is not
closed; a feed origin is operator-configured and trusted, so this is
accepted, not fixed.

Tests use a local `http.server` on 127.0.0.1 serving valid / invalid
JSON / invalid shape / HTTP 500 feeds; no real external feed is ever
fetched in tests.

## Telemetry

`GET /telemetry/counters` shells out to the read-only nft path only
(`<AEGIS_TELEMETRY_NFT_BIN> -j list ruleset`, default binary `nft`) and
parses counter objects from the JSON output: rule-level counters from
`expr[].counter` plus named `counter` objects (which carry `name`).
Binary missing, nonzero exit, unparsable output, or an empty ruleset
all return HTTP 200 with `{"available": false, "reason": "<plain reason>"}`.
This endpoint never changes firewall state and never touches
apply/rollback behavior. The dashboard's Overview page wires this
endpoint into a counters table with an explicit
"telemetry unavailable: \<reason\>" state; live rendering of that page
against a running API stays untested (no browser click-through
available here) — the wiring is code-complete only.

## Audit log

Table `audit (id, timestamp, actor, action, policy_id, detail)`.
Every create, update, delete, validate, apply, and rollback writes one
row. There is no endpoint that updates or deletes audit rows (attempts
return 405); rows only accumulate.

## Security notes

- **Localhost-only by default.** The documented run command binds
  `127.0.0.1`. Setting `AEGIS_API_BIND=0.0.0.0` exposes the API (and its
  token-authenticated firewall control) beyond the host; it logs a
  warning and should only be done behind additional network controls.
- **Token auth.** An admin token, plus an optional readonly token
  (GET only, 403 on mutations); treat both like passwords. Never commit
  them, never use a hardcoded default (there is none). Tokens are
  compared with `secrets.compare_digest`, are never stored in the DB,
  and never appear in logs or error messages. Tokens have no expiry or
  revocation endpoint: rotating one means changing the env var and
  restarting the process. There is no login endpoint and no auth rate
  limit: the controls are the localhost bind plus token entropy
  (`secrets.token_urlsafe(32)` when generated). Do not expose this API
  to a network where unauthenticated callers can reach it.
- **Host-apply gate.** Apply/rollback refuse with 400 unless the caller
  names a netns or passes `confirm_host_apply=true`. The API itself
  never guesses a scope. `confirm_host_apply`, `no_conntrack`, and
  `netns` must have their JSON types (boolean / string): the string
  `"false"` previously counted as confirmation because `bool("false")`
  is True — that is now a 400.
- **Request limits (Nov 3, 2026 review).** Bodies over 1 MiB → 413;
  stored policies are capped at 100 nesting levels and 1000 rules
  (a deeper policy previously crashed response serialization with a
  500); list endpoints are bounded by `limit`/`offset`; policy ids
  outside SQLite's signed 64-bit range → 404 (previously a 500).
- **Docs disabled.** `/docs`, `/redoc`, and `/openapi.json` return 404:
  the auto-docs previously published the full endpoint/schema surface
  to unauthenticated callers. Responses carry `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, and `Cache-Control: no-store`.
- **Storage.** All SQL is parameterized (no string-built queries). A
  freshly created DB file is chmod 0600. The audit log is append-only
  via the API (no update/delete routes), but it has no hash chain:
  tamper evidence against an attacker who can already write the DB
  file is NOT provided — ship audit rows to an external log if that
  property is required.
- **Degraded mode.** This sandbox kernel has no `nf_conntrack`, so CLI
  `check`/`apply` of the default stateful policy fail closed unless
  `no_conntrack` is passed; `--no-conntrack` itself is refused for
  policies whose rules specify connection states. Pass
  `no_conntrack: true` to `validate`/`apply` only when that trade-off
  is explicitly intended.

## PostgreSQL backend

SQLite is the default and is unchanged when Postgres is not selected.
When `AEGIS_API_DB_BACKEND=postgres`, `app.get_conn()` delegates to
`api/pg_backend.py`, which wraps a real DBAPI connection
(`psycopg`/`psycopg2`) and translates at the boundary so no other
call site changes: SQLite `?` placeholders become Postgres `%s`
(literals, quoted identifiers, and comments left alone), rows behave
like `sqlite3.Row` (`row["col"]` and `row[0]`), and `cursor.lastrowid`
is served from an appended `RETURNING id`. All values still travel as
bound parameters — no SQL is built from user input. The Postgres
schema mirrors the SQLite tables column for column (`BIGSERIAL`
instead of `INTEGER PRIMARY KEY AUTOINCREMENT`); there are no new
tables or columns, and API responses are identical on either backend.

```bash
cd ~/workspace/aegis-x/api
.venv/bin/pip install "psycopg[binary]"
# Start a server first (example only -- this sandbox has none):
#   initdb -D /tmp/aegis-pgdata && pg_ctl -D /tmp/aegis-pgdata \
#     -o "-k /tmp -p 5433" -l /tmp/aegis-pg.log start
#   createdb -h /tmp -p 5433 aegis
AEGIS_API_DB_BACKEND=postgres \
AEGIS_API_DB_URL=postgresql://user:password@127.0.0.1:5433/aegis \
AEGIS_API_TOKEN=<redacted> \
.venv/bin/python -m app
```

**Live-server verification still pending (Nov 3, 2026).** No live
Postgres was available in the sandbox where this backend was built
(no `psql`/`pg_isready`/`postgres`/`initdb`/`docker` on PATH, no
`/usr/lib/postgresql` tree, no `psycopg`/`psycopg2` in the venv), so
the Postgres path is verified there only against a fake DBAPI
connection (`tests/test_postgres.py`: placeholder translation,
parameter binding, `RETURNING id`/`lastrowid`, row access, schema
DDL, dispatch, and end-to-end HTTP CRUD through the real app). Before
Postgres is trusted in production, run the steps above against a real
server and confirm: `GET /status` reports `db_ok: true`, a
create/list/get/update/delete cycle returns the same shapes as
SQLite, `GET /audit` shows the matching rows, and `GET /feeds/status`
plus a `POST /feeds/refresh` against a local feed behave identically.
Also confirm with a real driver that the `feed_meta` upsert
(`ON CONFLICT(id) DO UPDATE ... excluded.*`) and `BIGSERIAL` inserts
behave as the fake assumes. Until that run exists, Postgres support
is code-complete and fake-verified only — not live-verified.

## Tests

```bash
cd ~/workspace/aegis-x/api
.venv/bin/python -m pytest -q
```

Tests use a throwaway DB/state dir under `/tmp/aegis-api-test` and never
perform a real host apply. A successful apply inside a netns is NOT
covered by these tests: this sandbox cannot create netns
(`ip netns add` fails, CAP_NET_ADMIN dropped) and `nft --check` fails
with "Operation not permitted", so no CLI check can pass here. The
validate tests therefore verify that the API relays the CLI verdict and
output verbatim (compared against a direct CLI run) rather than
asserting a pass that the environment cannot produce.
