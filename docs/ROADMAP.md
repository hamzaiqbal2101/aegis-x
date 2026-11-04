# AEGIS X — Implementation Roadmap

## Milestone 1 — Shared core + real Linux enforcement ✅ (this delivery)

* Policy model, matcher, priority ordering, conflict detection, default deny.
* nftables renderer + syntax validation.
* Linux adapter CLI: `render`, `check`, `apply` (netns-scoped or
  `--confirm-host-apply`), `rollback` (previous-policy swap), `eval`.
* Isolated user+net namespace enforcement test: real packets, real
  allow/deny (loopback topology; documented degradations where this
  kernel lacks nf_conntrack).
* Fail-closed conntrack probe; replace-not-merge apply semantics.
* Docs: architecture, threat model, platform matrix, validation procedure.
* Windows adapter: interface + translation design only (not verified).

## Milestone 2 — Management API ✅ (built, tested via TestClient)

* FastAPI service in `api/`: token auth (single admin token from
  env, generated if unset), policy CRUD over SQLite, SHA-256
  integrity hash on every stored version, append-only audit log,
  `validate` (shells to the Rust CLI `check`), `apply`/`rollback`
  with the CLI's own `--netns` / `--confirm-host-apply` gate
  (refuses without either — the host is never touched by default),
  `status`. Localhost bind by default. 8 TestClient tests pass.
* NOT done: roles/RBAC (single token only), PostgreSQL option,
  staged rollout with confirmation timer, backup/restore endpoints
  (backup is a documented file-copy procedure in the admin guide).
* Successful `apply` through the API was NOT tested end-to-end
  (host `ip netns add` fails here — CAP_NET_ADMIN dropped); only
  the refusal path + validate path were tested via the API. The
  CLI-level apply is proven separately in the netns test.

## Milestone 3 — Detection engines (partial ✅)

* Engine 2 IDS (built): event-based detection over connection
  records — port scans, brute force, known-bad matching. Pure
  functions, unit-tested. NOT Suricata, NOT inline DPI: it cannot
  see payloads.
* Suricata integration (built as INGESTION only,
  `crates/aegis-core/src/suricata.rs`): parses eve.json alert
  records into timed block decisions (IP + expiry + reason),
  unit-tested on sample records. Live detection still needs a real
  Suricata binary + ruleset on the deployment host — NOT installed
  here, and no live-detection claim is made.
* Engine 3 rate limiting (built): token-bucket limiter in core +
  per-rule `rate_limit` rendered as nftables `limit rate` lines.
  Render is unit-tested and userspace-parses, BUT this sandbox
  kernel lacks `nft_limit`, so kernel-level limit enforcement is
  unverified here (see VALIDATION.md). SYN flood controls and
  temporary blocks are still roadmap.
* IDS rule management UI + engine 2 rule testing: not done (the
  dashboard shows engine health only; no rule-testing UI).

## Milestone 4 — Windows enforcement (enforcement + service VERIFIED Nov 3, 2026)

Done (this environment, Linux host):

* WFP translation model (layers, weights, conditions) + `app` field
  on the shared Rule model (fail-closed in the packet matcher; Linux
  refuses app-scoped rules rather than silently broadening them).
* WFP engine installer written (`engine.rs`: provider + sublayer,
  transactional replace install, deterministic filter keys,
  direction-aware local/remote mapping, address/port expansion,
  ALE app-id resolution) + `aegis-win` CLI (install/uninstall/status).
* Windows verification + cleanup scripts (`tools/windows/`).
* One translation bug found and fixed: rules with both v4 and v6
  addresses previously emitted NO layers (silent drop).
* Windows code COMPILE-CHECKED from Linux via
  `cargo check -p aegis-windows --target x86_64-pc-windows-gnu
  --all-targets` (zero errors, zero warnings): that check caught
  and fixed 30+ first-draft errors in `engine.rs` (missing
  `Win32_Security` feature, wrong struct shapes, u32-vs-HRESULT
  returns, pointer-typed union fields) and 15+ in
  `aegis-service.rs` (missing `Win32_System_Services` /
  `Win32_System_Threading` features, Result-returning APIs,
  `SERVICE_STATUS_CURRENT_STATE` typing). Port ranges are now
  supported via FWP_RANGE0 (the check verified the range shapes).

Verified on a real Windows 10/11 host, Nov 3, 2026 (see
`docs/VALIDATION.md` §6):

* Native Windows link + build (`cargo build -p aegis-windows`).
* Real allow/deny probes via `tools/windows/verify-m4.ps1`:
  18080 reachable / 18081 blocked / 18082 reachable —
  `M4 WINDOWS ENFORCEMENT: PASS`, policy removed afterwards.

Still required (needs a Windows 10/11 host):

* Service loop verification: `tools/windows/verify-service.ps1`
  is authored (sc.exe create + start, RUNNING + service.log
  checks, probes, process-alive check, policy-change reload,
  stop/delete + always-cleanup) but its RUN is still pending.
* MSI build + signing: `packaging/windows/aegis-x.wxs` (WiX v4/v5
  source, XML-validated here) + `packaging/windows/build-msi.ps1`
  are authored, but `wix build` and signing with the operator's
  own certificate must happen on the PC. No MSI exists yet, and
  no certificate is invented anywhere in this repo.

## Milestone 5 — DNS + threat intelligence (partial ✅)

* DNS (built): name blocklist/allowlist matching (allowlist wins,
  subdomain-aware) + tunneling heuristics (label length, name
  length, label count, longest-label entropy). Analyzes names only;
  it does NOT intercept, proxy, or resolve DNS traffic.
* Threat intel (built): local JSON feed ingestion (IP/domain),
  expiry enforcement, allowlist override, prune. NO live
  commercial feed: the shipped sample feed
  (`examples/threat-feed-sample.json`) contains only TEST-NET
  addresses and example domains, labeled SAMPLE.
* Threat-feed auto-refresh (built, API): background task when
  `AEGIS_FEED_URL` is set (interval `AEGIS_FEED_INTERVAL_SECS`,
  default 3600), strict shape validation, fail-safe (a failed
  fetch or invalid shape NEVER wipes existing indicators),
  `GET /feeds/status` + admin-only `POST /feeds/refresh`, all
  outcomes in the audit log. Tested against a local HTTP server
  only — no real external feed is fetched in tests.
* NOT done: DNS query monitoring (live traffic), feed reputation
  scoring.

## Milestone 6 — Behavioral + segmentation (partial ✅)

* Behavioral (built): per-host baselines (bytes/flows/ports) +
  volume deviation, new-port, and beaconing detection over flow
  records. A flag means "unusual vs. this host's own past", not
  "malicious". Small baselines are refused, not guessed.
* Segmentation (built): zone-matrix validator — one representative
  packet per zone pair for one protocol + port, using the real
  matcher. A review aid, NOT a proof for every possible flow.
* NOT done: flow collection (the engine scores records the
  operator feeds it), lateral-movement indicators, segmentation UI
  beyond the dashboard's zone list.

## Milestone 7 — Dashboard (partial ✅)

* Vite + React + TypeScript + Tailwind app in `dashboard/`:
  Overview (engine health, honest labels), Policies (list, view,
  validate via the API), Events (real API audit rows, or an
  explicit empty/offline state), Zones (zones from real policies;
  matrix cells honestly say "unknown — not exposed by the API").
  `npm run build` passes. API client with graceful offline state.
* Telemetry (built): API `GET /telemetry/counters` parses real
  nftables counters via a read-only `nft -j list ruleset` call and
  returns an explicit `{"available": false, "reason": ...}` state
  when counters cannot be read (this sandbox cannot read host
  counters) — never invented numbers. The Overview page renders
  the counters table when available and the unavailable state
  otherwise. Live rendering against a running API is still
  untested (no browser click-through here) — wiring is
  code-complete only.
* API roles (built): admin token (full access) + readonly token
  (`AEGIS_API_READONLY_TOKEN`, GET endpoints only, 403 on
  mutating endpoints), tested for both roles.
* NOT done: 10 pages (4 built); conntrack + WFP flow events are
  still not exposed by the API, so no traffic numbers appear
  beyond real nft counters — by design, not by omission of a
  chart library.

## Milestone 8 — Hardening + release readiness (partial ✅)

* Done: systemd unit for the API (localhost-only, CAP_NET_ADMIN
  via ambient capabilities, token via root-only env file);
  `.deb` skeleton builder (`packaging/deb/build-deb.sh`, verified
  to produce a real unsigned .deb with the full file layout);
  SHA-256 checksums file for release artifacts;
  `docs/TAMPER_RESISTANCE.md` (integrity hashing, append-only
  audit, and the honest limits: no protection against root
  compromise, no remote log shipping yet);
  `docs/ADMIN_GUIDE.md` (install, configure, operate, uninstall,
  backup/restore, troubleshooting); Windows service loop
  STRUCTURE (cross-target compile-checked, then VERIFIED under the
  SCM on a real Windows host Nov 3, 2026: `SERVICE VERIFICATION:
  PASS` — installs, enforces, stays alive, reloads on policy change)
  + service verification script
  (`tools/windows/verify-service.ps1`, run passed on a PC) +
  WiX MSI source (`packaging/windows/aegis-x.wxs`,
  XML-validated here) + MSI BUILT on a PC (Nov 3, 2026,
  unsigned, SHA-256 recorded in README) + MSI
  install/uninstall cycle PASSED on a PC the same evening
  (service RUNNING + 8 filters on install; service gone +
  all WFP keys absent on uninstall) + bare-install retest
  with the shipped default policy PASSED the same evening
  (4 WFP filters = default-only, uninstall fully clean) +
  `docs/WINDOWS_PACKAGING.md` (WiX steps; signing
  still pending).
* Policy parser property tests (built, fuzz-lite NOT a fuzzer):
  250 generated policies round-tripped (serialize → parse →
  re-serialized JSON + hash equality) plus malformed-input
  rejection tests, in `crates/aegis-core/src/property_tests.rs`.
* NOT done (and therefore release readiness is NOT declared):
  signing with a user-obtained certificate, normal-kernel
  ct-rule + nft_limit verification, real-deployment
  Suricata/DNS/feed-reputation + dashboard live-API checks,
  coverage-guided fuzzing of the policy parser, API penetration
  test, independent review, performance benchmarks, signed
  installers, security assessment report, PostgreSQL support
  (SQLite remains the default; no server to test against here).
  Built here vs proven on a real machine vs release-ready are
  three different claims, and only the first two are partially
  met — the third is NOT declared.
* **Release readiness is declared only after M8 gates pass.** Not before.

## What will NOT be done

* No userspace packet forwarding as the default path.
* No TLS interception.
* No proprietary kernel driver.
* No fabricated statistics, test results, or feature claims.
