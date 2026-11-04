# AEGIS X — Enterprise Next-Generation Firewall

A cross-platform Next-Generation Firewall (NGFW) for Windows 10/11 and Linux:
native enforcement on each OS (Windows Filtering Platform / nftables-Netfilter),
one shared Rust policy engine, and one shared policy format.

> **Safety and honesty notice — read first.**
>
> * AEGIS X is under active development. Only the modules listed as
>   **implemented and verified** below may be treated as working.
> * No firewall is impossible to bypass. AEGIS X is designed for defense in
>   depth, verified enforcement, and resilience — not invulnerability.
> * **No host firewall is modified by the test suite.** All enforcement tests
>   run inside a private Linux user+network namespace (`unshare -Urn`),
>   which has its own network stack and its own nftables tables, and is
>   destroyed on exit. The host's firewall rules are never touched by any
>   command in this repository unless you explicitly run an `apply` command
>   yourself (which then requires `--netns` or `--confirm-host-apply`).
> * A homegrown firewall must not be the sole protection of a production
>   machine. Run it alongside, not instead of, your OS vendor's maintained
>   firewall until it has passed independent review.
> * No statistics shown by any AEGIS X component are fabricated: counters come
>   from the OS (nftables counters, conntrack) or are labelled as test data.

## Current status (Milestones M1–M8 — built; NOT release-ready)

| Component | Status |
|---|---|
| Shared Rust policy engine (`crates/aegis-core`) | ✅ Implemented, 58 unit tests pass (incl. Suricata ingestion + property tests) |
| Policy format (JSON, versioned, integrity hash) | ✅ Implemented |
| Engines 1 (stateful model) + 10 (conflict detection, integrity) | ✅ Core model implemented |
| Engine 2 IDS (event-based: scans, brute force, known-bad) | ✅ Implemented, unit-tested — NOT Suricata, NOT DPI |
| Engine 3 rate limiting (token bucket + nft `limit` rendering) | 🟡 Implemented + unit-tested; kernel enforcement unverified here (no `nft_limit` in this kernel) |
| Engine 4 app identity | 🟡 Windows-only model + installer written, uncompiled/unverified; Linux refuses app rules |
| Engine 5 DNS (name lists + tunneling heuristics) + threat intel (local feeds, expiry, allowlist) | ✅ Implemented, unit-tested — NO live feed, NO traffic interception |
| Engine 8 zone-matrix validation | ✅ Implemented, unit-tested (one representative packet per zone pair) |
| Engine 9 behavioral (baselines, volume/new-port/beaconing) | ✅ Implemented, unit-tested — scores records fed to it; no flow collection |
| Linux nftables adapter (`crates/aegis-linux`) | ✅ Implemented, verified in an isolated user+net namespace (loopback test; stateful base rules excluded — this kernel lacks nf_conntrack, see `docs/VALIDATION.md`) |
| Windows WFP adapter (`crates/aegis-windows`) | ✅ Enforcement **verified on a real Windows host (Nov 3, 2026)**: native MSVC build + 4 translation tests passed, test policy installed (8 filters), LAN probes 18080 reachable / 18081 blocked / 18082 reachable — `M4 WINDOWS ENFORCEMENT: PASS` (see `docs/VALIDATION.md` §6). Honest correction: that run's cleanup did NOT remove the policy (uninstall ignored an FWP_E_IN_USE failure); fixed the same evening with a filters-first cascade uninstall + install phase 1. Service **verified on a real Windows host (Nov 3, 2026)**: `SERVICE VERIFICATION: PASS` — service installs, enforces (18081 blocked), stays alive, and reloads on policy change (18083 blocked, 18081 reachable again), with genuine cascade cleanup afterwards. API security review **done (Nov 3, 2026 evening)**: 15 findings fixed in `api/app.py` (host-apply gate bypass via string booleans, feed SSRF via redirects/private hosts, duplicate-indicator 500, unbounded feed body, deeply-nested policy 500, body-size limit, id overflow, bool policy_id, auto-docs exposure, /status path leak, netns typing, CLI OSError, pagination, DB file perms, security headers) + 19 regression tests — **46 pytest passed** (verified here). Residuals documented, not fixed: audit hash chain, auth rate limiting, DNS-rebinding TOCTOU, token-on-stderr bootstrap, /status DB side effect. WiX MSI **built on the user's PC (Nov 3, 2026)**: `packaging/windows/aegis-x.msi`, 393,216 bytes — UNSIGNED (signing still pending). MSI install/uninstall cycle **PASSED the same evening**: install → service RUNNING + "initial policy installed: 8 WFP filters"; uninstall → service gone (SC 1060) + all WFP keys absent (old + new provider/sublayer). Follow-up fixed the same evening: the MSI now ships a default policy (`packaging/windows/default-policy.json`, allow-all with no rules, NeverOverwrite so upgrades never clobber a customized policy) installed to `%ProgramData%\AEGIS X\policy.json` — validated here (policy eval → Allow, default/base). Rebuilt MSI with the default policy (Nov 3, 2026 evening): 393,216 bytes, SHA-256 `F261AD076A629CC7C6494DC1C45420B5CC64A827DB8DB819CC7230621A1B87D9` — bare-install retest **PASSED the same evening**: service started on the MSI-shipped default policy alone ("initial policy installed: 4 WFP filters", vs 8 for the rule policy — the count difference confirms it was the default), and uninstall left everything clean (service gone, all WFP keys absent, policy file removed). Rebuilt again the same evening after a fresh zip extraction wiped the local MSI (393,216 bytes, SHA-256 `4F131512160C572FD83E46B62CD01A72340B1C5C0ABA061D94165719DFE6367D` — SHA differs only due to the .wxs header comment update, same functionality); **signed the same evening with the operator's self-signed test cert** (`Successfully signed: packaging\windows\aegis-x.msi`), signature verified attached, and cert imported to LocalMachine Root + TrustedPublisher → `Get-AuthenticodeSignature` Status **Valid** on the operator's PC. Self-signed trust is machine-local only — a public OV certificate (or SignPath) is still needed for trust on other machines. |
| Management API (`api/`, FastAPI) | ✅ Implemented, 27 tests pass (CRUD + auth + feed auto-refresh + RBAC roles + telemetry endpoint); successful API `apply` NOT tested here (no namespace available) |
| Dashboard (`dashboard/`, React+TS+Tailwind) | ✅ 4 pages built, `npm run build` passes; Overview wired to real nft telemetry (explicit unavailable state when unreadable), NO invented numbers; live-API rendering untested |
| Suricata ingestion (eve.json → timed block decisions) | ✅ Implemented, unit-tested — ingestion only, NO live detection here |
| Policy parser property tests (fuzz-lite, not a fuzzer) | ✅ 250 generated policies round-tripped + malformed-input rejections |
| Packaging (`packaging/`, systemd unit + unsigned .deb skeleton + SHA256SUMS) | ✅ .deb build verified; UNSIGNED — signing planned |
| MSI build/signing (source authored, runs pending on PC), live Suricata/DNS/feed reputation + dashboard live-API checks, normal-kernel ct/nft_limit verification, PostgreSQL, benchmarks, pen test, independent review, coverage-guided fuzzing | ⏳ Roadmap (see `docs/ROADMAP.md`) — release readiness is NOT declared |

## Repository layout

```
aegis-x/
├── README.md
├── api/                     # M2 management API (FastAPI + SQLite)
├── dashboard/               # M7 dashboard (Vite + React + TS + Tailwind)
├── docs/
│   ├── ADMIN_GUIDE.md       # Install, configure, operate, uninstall, backup, troubleshooting
│   ├── ARCHITECTURE.md      # Modules, data flow, trust boundaries
│   ├── TAMPER_RESISTANCE.md # Integrity hashing, audit log, honest limits
│   ├── THREAT_MODEL.md      # Assets, attackers, mitigations, residual risk
│   ├── PLATFORM_MATRIX.md   # Feature availability per OS (active/degraded/unsupported)
│   ├── ROADMAP.md           # Milestones M1–M8
│   ├── VALIDATION.md        # How to reproduce every test, incl. Windows
│   └── WINDOWS_PACKAGING.md # WiX MSI steps (documentation only — no MSI exists)
├── crates/
│   ├── aegis-core/          # Shared policy engine (no OS dependencies)
│   ├── aegis-linux/         # nftables adapter + netns test harness (Linux only)
│   └── aegis-windows/       # WFP adapter (workspace member; engine is Windows-only, stub on Linux)
├── examples/
│   ├── standard.json        # Example policy
│   ├── threat-feed-sample.json      # SAMPLE feed, Rust parser format (kind/source)
│   └── threat-feed-sample-api.json  # SAMPLE feed, API format (type/value/expires_at) — same indicators
├── packaging/
│   ├── systemd/aegis-api.service  # API unit (localhost-only, CAP_NET_ADMIN)
│   ├── deb/                 # .deb skeleton builder (unsigned) + SHA256SUMS
│   └── SHA256SUMS           # Release artifact checksums
├── tools/
│   └── windows/             # verify-m4.ps1 + cleanup-m4.ps1 (Windows host only)
└── tests/
    └── netns/               # Isolated enforcement test scripts
```

## Quick start (Linux, Milestone 1)

Requires: Rust (stable), `nft`, `ip` (iproute2), root for the netns tests only.

```bash
# Build and run all unit tests (no privileges needed)
cargo test

# Render a policy to an nftables ruleset without applying anything
cargo run -p aegis-linux -- render --policy examples/standard.json

# REAL enforcement test, isolated in a private user+network namespace
# (no sudo needed: the user namespace grants the capabilities inside it).
# Applies the policy there, probes allow/deny with real packets, then
# the namespace is destroyed. Host untouched.
./tests/netns/run.sh
```

See `docs/VALIDATION.md` for the full procedure and expected output.

## Benchmarks (policy engine hot paths, pure userspace)

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo bench -p aegis-core --bench policy_bench            # full criterion run
cargo bench -p aegis-core --bench policy_bench -- --sample-size 10   # short run
```

Benches live in `crates/aegis-core/benches/policy_bench.rs` (criterion, stable):
policy parse (small + zone-expanded), `evaluate` first-match and default-deny,
single `rule_matches`, and `policy_hash`. They touch no nftables/WFP/kernel state.

## Policy model (summary)

* **Default deny.** A packet/connection is allowed only if an explicit rule
  allows it. There is no implicit allow.
* **First-match-wins within a priority-ordered rule list**; rules carry a
  numeric priority (lower = evaluated first).
* **Zones** (e.g. `lan`, `wan`, `dmz`, `host`) segment traffic; a rule may
  restrict source/destination zones and interfaces.
* **Stateful inspection:** the engine models TCP/UDP/ICMP connection state
  (`new`, `established`, `related`, `invalid`); `invalid` packets are
  dropped by default policy.
* **Actions:** `allow`, `deny` (silent drop), `reject` (ICMP/TCP reset where
  applicable), `log` (allow + log), `alert` (deny + alert).
* **Conflict detection:** the engine reports shadowed rules (a rule that can
  never match because an earlier rule already covers it) and exact
  duplicates before a policy may be applied.
* **Integrity:** policies are versioned; the adapter refuses to apply a policy
  whose rule set changed after signing unless `--allow-unsigned` is given
  (development only). Rollback keeps the last known-good policy.

Full detail: `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`.

## License / attribution

Built as an independent project. nftables, Netfilter, WFP, and Suricata are
the property of their respective projects; AEGIS X integrates with them, it
does not re-implement them.
