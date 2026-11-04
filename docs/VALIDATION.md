# AEGIS X — Validation Procedure (Milestone 1)

Every claim in the README's status table can be reproduced with the
commands below. No step modifies the host firewall.

## 1. Policy-engine unit tests (no privileges needed)

```bash
cargo test -p aegis-core -p aegis-windows
```

Expected: all tests pass. Coverage includes:

* CIDR containment (v4 + v6), port specs (single/range/list).
* First-match-wins by priority, independent of document order.
* Default deny when no rule matches.
* `invalid` connection state always denied (base policy).
* Zone expansion, and rejection of unknown zones, ICMP ports, and
  duplicate rule ids.
* Conflict detection: shadowing, duplicates, and no false positives on
  disjoint rules.
* Integrity hash: stable for identical policies, changes on any edit.
* nftables rendering: basic rules, TCP/UDP split for protocol-`Any` with
  ports, v4/v6 rule splitting, zone-expanded rules.
* WFP translation: weight inversion by priority, default-deny last,
  v4-only rules skipping v6 layers, both-family rules landing on all
  four ALE layers (regression test for a real silent-drop bug).
* Engine 2 IDS: port scans (window respected), brute force (only
  failures to one service count), known-bad matching, empty input.
* Engine 3 rate limiting: token-bucket burst/refill, per-source
  isolation, zero-refill behavior; `limit rate` rendering incl. burst.
* DNS: blocklist exact + subdomain matching, allowlist override,
  tunneling heuristics (length, label count, entropy).
* Threat intel: feed parsing, expiry, allowlist override, prune,
  malformed-feed rejection.
* Behavioral: volume anomalies (small baselines skipped),
  new-port detection, beaconing (regular vs irregular vs too few).
* Segmentation: matrix reflects rules + default, port specificity,
  unknown/empty zones are errors.

## 2. Render + syntax check (no privileges needed)

```bash
cargo run -q -p aegis-linux -- render --policy examples/standard.json
cargo run -q -p aegis-linux -- check --policy examples/standard.json
```

Expected: a complete `table inet aegis` script on stdout, then
`OK: policy "standard" renders and passes nft --check` plus the policy hash.

## 3. Real enforcement test (private user+network namespace, no sudo)

```bash
./tests/netns/run.sh
```

The script builds aegis-linux, then runs `tests/netns/inner.sh` inside
`unshare -Urn`: a private user+network namespace with its own nftables
tables, destroyed on exit. Nothing in it can see or change the host
firewall (this sandbox drops CAP_NET_ADMIN on the host, so host nftables
and `ip netns` do not work here at all; inside a user namespace the
test holds the needed capabilities over its own private network stack).

Expected output ends with `ALL LOOPBACK ENFORCEMENT TESTS PASSED`, after:

1. A real HTTP listener on port 8080 **inside** the namespace answers
   (HTTP 200) — the allowed port.
2. An identical listener on port 9090 does **not** answer (curl times
   out, exit 28) — the denied port, proving the drop is the firewall's
   doing and not an absent service.
3. nftables counters move: the allow rules (destination-port and
   return-port) and a default-deny rule are all ≥ 1.

### Why loopback, and what is degraded here (read before judging it)

* **Loopback topology.** This sandbox blocks client connections to
  non-loopback local addresses (connect fails with EPERM/refused even
  with no firewall loaded at all), while loopback connections work.
  Loopback traffic *is* filtered by the nftables input/output hooks, so
  this is a real enforcement test, not a simulation. On a normal host,
  the same CLI supports the veth/netns topology via
  `apply --netns <name>`.
* **`--no-conntrack`.** This kernel (7.0.0-39-generic) has no
  nf_conntrack module at all, so `ct` rules cannot be installed here.
  The adapter probes for conntrack and *refuses* the default policy
  rather than silently dropping stateful inspection (fail closed); the
  test therefore runs explicitly degraded. The test policy allows return
  traffic explicitly (a `src_port` rule), the way stateless firewalls
  must. On a normal distro kernel, drop the flag to test the full
  default policy, including stateful base rules.
* **`--no-loopback-accept`.** The shipped policy accepts loopback
  unconditionally (standard practice), which would bypass user rules on
  `lo`. The test omits that base rule so user rules actually decide
  loopback traffic.
* **Replace, not merge.** `nft -f` with a table definition merges into
  an existing table instead of replacing it — stale allow rules from a
  previous policy would silently survive a policy change. AEGIS X apply
  therefore deletes table `aegis` first (scoped to its own table only),
  then creates it fresh. Verified: apply A (8080) → apply B (8081) →
  only 8081 remains, no merged rules.

## 4. Single-packet evaluation (no privileges needed)

```bash
cargo run -q -p aegis-linux -- eval --policy examples/standard.json \
  --src 192.168.1.10 --dst 8.8.8.8 --dport 53 --proto udp --state new
```

Expected: `action: Allow`, `rule: allow-lan-dns`.

## 5. Rollback

The state dir keeps two slots: `current.nft` (last successfully applied)
and `previous.nft` (the one before it). Rollback applies the previous
policy and swaps the two files, so a second rollback undoes the first.
Verified sequence (inside a private namespace):

```
apply A (8080) → apply B (8081) → rollback → only 8080 → rollback → only 8081
```

```bash
# Inside the same scope used for apply (netns or --confirm-host-apply):
./target/debug/aegis-linux rollback --netns aegis-test \
  --state-dir /tmp/aegis-test-state
```

## 6. Windows (M4: VERIFIED on a real Windows host, Nov 3, 2026)

M4 enforcement is now proven on a real Windows 10/11 host (not just
compile-checked): native MSVC build passed, 4 translation tests
passed, and `verify-m4.ps1` installed a narrow test policy (default
allow + one block rule, TCP 18081) into the live WFP and probed it
over the LAN IP:

- port 18080 (unlisted, default allow): reachable = True
- port 18081 (blocked by rule): blocked = True
- port 18082 (unlisted, default allow): reachable = True
- `M4 WINDOWS ENFORCEMENT: PASS` — a real WFP block stopped real
  traffic.

CORRECTION (same evening, found by the service run): the M4 run's
finally-block cleanup did NOT actually remove the test policy. The
old `uninstall()` deleted the sublayer directly and ignored both
delete codes, so with 8 filters still inside it the sublayer delete
failed with FWP_E_IN_USE (0x8032000A) and the "removed" message
printed anyway — the whole test policy stayed live. The service's
first install then failed with ALREADY_EXISTS on the same sublayer,
which is how this was caught. Fixed the same evening: `uninstall()`
and install phase 1 now cascade (delete the sublayer's filters by ID
first, then the sublayer, then the provider, in separate committed
transactions) and treat any delete failure other than NOT_FOUND as
an error. The service's fail-fast behavior (never report RUNNING
while unprotected) worked exactly as designed throughout.

Three real-host lessons from that verification run, all fixed in
this tree: (1) PowerShell 5.1 `Set-Content -Encoding utf8` writes a
UTF-8 BOM that serde_json rejects — the script now writes BOM-less
UTF-8 and `Policy::from_json` strips a leading BOM. (2) Deleting and
re-adding the same sublayer key inside ONE WFP transaction fails with
FWP_E_ALREADY_EXISTS — install now uses two transactions (committed
delete, then a fresh transaction for provider+sublayer+filters).
(3) A stale sublayer cannot be deleted while it still contains
filters: the delete fails with FWP_E_IN_USE (0x8032000A) — so
`aegis-win remove-old` deletes the old sublayer's filters by ID
first, then the sublayer, then the provider, reporting every code.
The service loop (`aegis-service.rs`) is still unverified on a real
host, as are MSI/signing and the remaining roadmap items.

This environment has no Windows host, so the WFP engine installer
(`crates/aegis-windows/src/engine.rs`) and service loop
(`crates/aegis-windows/src/bin/aegis-service.rs`) cannot be linked
or run here. But they ARE compile-checked from Linux:

```sh
cargo check -p aegis-windows --target x86_64-pc-windows-gnu --all-targets
# zero errors, zero warnings (this check caught and fixed 30+ errors
# in the first drafts, including a missing Win32_Security feature,
# wrong struct shapes, and wrong return types)
```

That check proves the Windows API usage type-checks; it does not
prove linking (needs a Windows linker) or enforcement. The
translation model (58 tests total across the workspace) passes on
Linux, but that proves the filter *data*, not enforcement.

To verify on a Windows 10/11 host (Administrator PowerShell, from
the repo root):

```powershell
.\tools\windows\verify-m4.ps1
```

The script is the whole procedure: it builds (`cargo build` is the
compile check for `engine.rs` — fix any `WINDOWS-BUILD-CHECK` API
mismatches first), runs the unit tests, installs a narrow test policy
(default **allow**, one block rule for TCP port 18081 only), probes
the machine's LAN IP (loopback is exempt from WFP ALE, so 127.0.0.1
cannot prove anything), and always uninstalls at the end.

Pass criteria (all three, on real packets):

* Port 18081 blocked by the rule (listener up, connect fails).
* Unlisted ports 18080/18082 reachable (default allow intact —
  the test did not break normal traffic).
* `aegis-win uninstall` removes the sublayer and provider cleanly
  (re-running `verify-m4.ps1` from a clean slate passes again).

Until that run exists, every Windows enforcement claim stays marked
**not verified** in `docs/PLATFORM_MATRIX.md`. A default-deny
allow-rule proof belongs in a VM, not on a main PC (see
`crates/aegis-windows/README.md`). Note the cross-target check above
does not replace this run: it checks types, not behavior.

## 7. Management API (M2)

```bash
cd api
python3 -m venv .venv && .venv/bin/pip install fastapi uvicorn httpx pytest
AEGIS_API_TOKEN=test-token .venv/bin/python -m pytest tests/ -q
```

Expected: 27 passed (1 pre-existing Starlette deprecation
warning only). Coverage: auth rejection (no/wrong token),
CRUD round-trip, validate of a good policy (`examples/standard.json`)
and a bad policy (fail, with CLI output included), apply refusal
without netns/confirm (400, host untouched), audit accumulation +
no-delete, status endpoint, feed refresh against a local HTTP
server (valid / invalid-JSON / invalid-shape / HTTP-500, with
fail-safe preservation of old indicators), RBAC (admin mutates,
readonly GETs but gets 403 on mutations, no token gets 401),
telemetry counters against a fake nft script (canned counters,
nonzero exit, garbage output, empty ruleset, missing binary —
all returning the explicit unavailable state, never numbers).

NOT covered here (stated plainly): a successful `apply` through
the API. Host `ip netns add` fails in this environment
(CAP_NET_ADMIN dropped), so no namespace exists for the API to
apply into. The CLI-level apply is proven separately in §3.

## 8. Rate-limit rendering vs the sandbox kernel (M3, known gap)

A rate-limited rule renders as, e.g.:

```
tcp dport 80 limit rate 25/minute burst 5 packets counter accept
```

`nft --check` on that script in this environment fails with
`Could not process rule: No such file or directory` — but so does
a MINIMAL one-rule limit script, while the identical script without
`limit` passes. The kernel here lacks the `nft_limit` module
(the same way it lacks `nf_conntrack`): userspace parses the rule
(a syntax error would fail in userspace, not with kernel ENOENT),
but the kernel cannot install it. Conclusion, stated exactly:
limit rendering is implemented + unit-tested + userspace-parseable;
kernel-level limit enforcement is UNVERIFIED in this environment
and needs a normal distro kernel. The same caveat applies to the
`ct` base rules (§3).

## 9. Dashboard build (M7)

```bash
cd dashboard && npm install && npm run build
```

Expected: `tsc -b && vite build` succeeds (`✓ built in …`).
The build is the verification: no dev server is kept running, and
no live API fetch is claimed (the dashboard shows an explicit
"API offline" state when the API is not running).

## 10. Packaging (M8)

```bash
./packaging/deb/build-deb.sh packaging/deb/out
dpkg-deb --info packaging/deb/out/aegis-x_0.1.0_amd64.deb
dpkg-deb --contents packaging/deb/out/aegis-x_0.1.0_amd64.deb
```

Expected: a real `.deb` containing the release binaries
(`aegis-linux`, plus the Linux-built `aegis-win` STUB — it
enforces nothing on Linux and is included only for layout
completeness), the API tree, the dashboard `dist/` build, the
systemd unit, and the admin + validation guides. The package is
UNSIGNED (signing needs the operator's GPG key; the script prints
the `dpkg-sig` command but never fakes a signature). Checksums:

```bash
sha256sum packaging/deb/out/aegis-x_0.1.0_amd64.deb
# compare against packaging/SHA256SUMS
```

## 11. Finish-up items (Suricata ingestion, property tests, feeds, RBAC, telemetry, service loop)

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo test            # 60 passed (49 core + 7 linux + 4 windows), zero warnings
cd api && .venv/bin/python -m pytest -q   # 27 passed
cd dashboard && npm run build             # tsc -b && vite build succeeds
```

* Suricata ingestion (`crates/aegis-core/src/suricata.rs`): 7
  in-module tests over inline sample eve.json records (alerts,
  threshold boundary, non-alert flow/dns records, malformed
  lines, timestamp offsets, expiry math, dedup, prune). This
  proves ingestion only — live detection needs a Suricata binary
  + ruleset on the deployment host.
* Property tests (`crates/aegis-core/src/property_tests.rs`,
  fuzz-lite, NOT a fuzzer): 250 generated policies round-tripped
  plus malformed-input rejections. Deterministic xorshift PRNG,
  no new dependency.
* Feed refresh / RBAC / telemetry: covered by the API suite
  above (§7). The telemetry endpoint shells to `nft -j list
  ruleset` read-only; in this sandbox it returns the explicit
  unavailable state (host counters unreadable here).
* Service loop (`crates/aegis-windows/src/bin/aegis-service.rs`):
  NOT verified here — Linux builds a stub (clean error, exit 1).
  The Windows verification procedure is now authored as
  `tools/windows/verify-service.ps1` (admin check, native build of
  both binaries, service install via `sc.exe create`, start,
  RUNNING + `service.log` "initial policy installed" checks, LAN
  probes 18080/18081/18082, process-alive check, policy-change
  reload to block 18083, stop + delete + `aegis-win uninstall`,
  always-cleanup in finally). The RUN of that script on a real
  Windows host is still pending — it is the next PC step, and
  until it passes, the service loop is authored-but-unverified.
  The live API smoke test for this round is §13.

## 12. Known issues (not fixed in this pass)

* `Policy::from_json` is NOT idempotent for zone-referencing
  policies: `normalize` appends zone subnets on every parse, so
  re-parsing an already-normalized policy duplicates them. In
  practice the API and CLI always parse the original stored JSON,
  not normalized output, so nothing accumulates today — but any
  future serialize-then-parse round-trip of a normalized policy
  must account for this. Fixing `normalize` to dedupe is
  follow-up work (it changes hash inputs and needs its own test
  pass), not a silent patch.
* The API integrity hash and the Rust CLI hash are NOT
  equivalent (different canonical forms — see `api/README.md`).
  They are never compared against each other; each is
  deterministic and change-sensitive within its own side.

## 13. Live API smoke test (finish-up round 2, Nov 3, 2026)

A real FastAPI server was started on this VM (not TestClient) and
exercised with curl. DB pointed at a scratch file so the repo
stays clean; tokens were throwaway test values. Exact commands:

```bash
cd api
AEGIS_API_TOKEN=smoke-admin-token-123 \
AEGIS_API_READONLY_TOKEN=smoke-read-token-123 \
AEGIS_API_DB=/tmp/aegis-smoke/aegis.db \
AEGIS_API_PORT=8000 .venv/bin/python app.py
# (server binds 127.0.0.1:8000 by default — AEGIS_API_BIND unset)
```

Observed, exactly (no numbers invented):

* `GET /status` (no auth): `{"api_version":"0.2.0-m2",
  "engine_available":true,
  "engine_path":".../target/debug/aegis-linux","db_ok":true}`.
* `POST /policies` (admin): 201, id 1, SHA-256 hash
  `f814eeec…` (full hash in the smoke log below). `GET /policies`
  then listed the one policy; `GET /policies/1` with the readonly
  token returned 200.
* `PUT /policies/1` with only `{"name": …}`: 400
  `body.policy is required` — that is the API's contract, not a
  test failure. With name + policy: 200, new hash `1c9ccb50…`,
  `updated_at` bumped.
* `POST /policies` with the readonly token: 403
  `readonly token cannot mutate`. RBAC holds live, not just in
  TestClient.
* `POST /policies/1/validate` (admin): the endpoint works and
  shells to the CLI, but `pass=false` HERE for documented sandbox
  reasons, twice over: without flags the CLI refuses with
  `kernel lacks nf_conntrack`; with `{"no_conntrack":true}` the
  CLI proceeds to `nft --check`, which fails with
  `netlink: Error: cache initialization failed: Operation not
  permitted` (this sandbox drops CAP_NET_ADMIN). The validate
  PATH is proven live; the nft check itself cannot pass in this
  sandbox — CLI-level checking is proven separately in §3's
  namespace test. Do not read this as a validate bug.
* `GET /telemetry/counters` (admin): `{"available":false,
  "reason":"nft exited with code 1: Operation not permitted (you
  must be root)"}` — the explicit unavailable state, never
  invented counters.
* `GET /feeds/status` (admin): `{"last_refresh_at":null,
  "last_outcome":"never","indicator_count":0,
  "feed_url_configured":false}` — no feed configured, honestly
  reported.
* `GET /audit` (admin): 3 rows — create, update, validate — actor
  `admin`, with policy hashes. Append-only log works live.
* `DELETE /policies/1` (admin): `{"deleted":1}`, 200. Afterwards
  `GET /policies` returned `[]` and `GET /policies/1` returned 404
  `policy not found`.
* API pytest suite (unchanged code): 27 passed.
* Dashboard: `cd dashboard && npm run build` passes (tsc -b &&
  vite build, 23 modules, 435ms). The API client default
  (`src/lib/api.ts`, `VITE_API_URL` unset) is
  `http://127.0.0.1:8000`, matching the live API bind above.
  Live rendering against a running API in a browser is still NOT
  tested here (no browser in this environment) — wiring is
  code-complete plus build-verified only.
* NOT covered live: a successful `apply` through the API (same
  namespace reason as §7) and any browser click-through.
