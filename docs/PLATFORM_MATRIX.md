# AEGIS X — Platform Capability Matrix

Status values: **active** (implemented + verified) · **planned** (roadmap)
· **degraded** (works with documented limits) · **unsupported** (OS cannot
do this; the dashboard must say so, never fake it).

| Capability | Linux (nftables) | Windows (WFP) |
|---|---|---|
| Stateful filtering (TCP/UDP/ICMP, v4+v6) | active (M1) | planned |
| Default-deny policy | active (M1) | planned |
| Priority-ordered rules | active (M1) | planned |
| Rule conflict detection | active (M1, core) | active (M1, core — same code) |
| Policy integrity hash + rollback store | active (M1) | planned |
| Zones / segmentation (subnets, interfaces) | active (M1) | planned |
| Rate limiting / SYN controls | partial (M3: token bucket + `limit` rendering; kernel enforcement unverified here — no `nft_limit`; SYN controls planned) | planned (WFP + callout limits) |
| Application control | unsupported in M4 (adapter refuses app rules; no cgroupv2/owner match implemented) | planned (ALE app IDs — engine written, uncompiled/unverified) |
| Event-based IDS (engine 2) | active (M3, core — connection records only, NOT DPI) | active (M3, core — same code; no Windows host run yet) |
| IDS/IPS (Suricata) | partial (ingestion only: eve.json alerts → timed block decisions, unit-tested; live detection needs a Suricata binary + ruleset on the deployment host) | planned (Suricata Windows build) |
| Threat-intel blocklists | partial (M5: local feed ingestion + expiry + allowlist; API auto-refresh, fail-safe; NO live feed) | partial (M5, core — same code; WFP filter install planned) |
| DNS security | partial (M5: name lists + tunneling heuristics; NO traffic interception) | partial (M5, core — same code) |
| Behavioral anomaly detection | partial (M6: baselines + scoring over flow records; NO flow collection) | partial (M6, core — same code) |
| Zone-matrix validation (engine 8) | active (M6, core — one representative packet per zone pair) | active (M6, core — same code) |
| Anti-evasion (fragments, IPv6 parity) | active base policy (M1) | planned |
| eBPF/XDP acceleration | planned (optional) | unsupported (no eBPF/XDP on Windows) |
| Dashboard + API | partial (M2 API with RBAC roles + feed refresh + nft telemetry endpoint; 4-page M7 dashboard with Overview wired to telemetry; live-API rendering untested) | partial (shared; Windows API run not verified) |
| Secure updates (signed packages) | partial (M8: unsigned .deb skeleton + SHA256SUMS; signing planned) | planned (WiX steps documented; no MSI) |

## Honest differences the dashboard must show

* **Application identity:** Windows can identify an application by its
  signed executable (ALE app id); the M4 engine resolves `app` paths
  and fails the install if resolution fails. Linux nftables cannot
  reliably attribute a socket to an application identity (owner match
  is UID-based, and processes can be replaced), so the Linux adapter
  **refuses** app-scoped rules outright rather than silently broadening
  them to all apps. Linux app control is therefore **unsupported in
  M4** (not "degraded" — degraded would imply partial enforcement),
  and the dashboard must label it so. The Windows app implementation
  is written but uncompiled/unverified (see §6 of VALIDATION.md).
* **eBPF/XDP:** Linux-only. Windows gets no equivalent claim.
* **WFP callout drivers:** AEGIS X ships no kernel driver; it uses the
  built-in WFP ALE layers. Deep packet inspection beyond ALE on Windows
  requires a signed callout driver, which is out of scope for M1–M4.

## Verified-on matrix (M1–M8)

| Check | Linux | Windows |
|---|---|---|
| Policy engine unit tests (58 tests) | ✅ pass (`cargo test`) | Not run — core is OS-independent, but the Windows run is still required before claiming parity |
| nftables render + syntax check (`nft --check`) | ✅ pass inside a private user ns (degraded mode: no `ct` lines — this kernel has no nf_conntrack; the full script is shown by `render`) | n/a |
| Real allow/deny with real packets | ✅ pass — loopback test in a private user+net ns: 8080 → HTTP 200, 9090 → timeout, counters moved (see `docs/VALIDATION.md` §3 for the documented degradations) | n/a |
| Apply replaces (no merged stale rules) + rollback swap | ✅ pass — A (8080) → B (8081) → rollback → A only → rollback → B only | n/a |
| Full stateful (`ct`) base rules installed + enforced | ❌ Cannot verify here — kernel lacks nf_conntrack entirely; the adapter fail-closed refuses the default policy in this environment. Requires a normal distro kernel. | n/a |
| Rate-limit (`limit`) rules installed + enforced | ❌ Cannot verify here — kernel lacks `nft_limit`; userspace parses the rule (kernel ENOENT, not a syntax error). Requires a normal distro kernel. | n/a |
| Management API tests (27 tests) | ✅ pass (pytest, TestClient: CRUD + auth + feeds + RBAC + telemetry); successful API `apply` NOT tested — no namespace available for it here | n/a |
| Dashboard build | ✅ pass (`npm run build`; Overview wired to telemetry endpoint; live-API rendering untested) | n/a |
| Suricata ingestion + property tests | ✅ pass (7 ingestion + 2 property tests, 250 generated policies; fuzz-lite, not a fuzzer) | n/a (core code; Windows run still required for parity) |
| .deb skeleton build | ✅ pass (real unsigned .deb, full layout; signing planned) | n/a |
| WFP apply + allow/deny | n/a | ❌ Not verified — engine installer + service loop are compile-checked via cross-target check (zero errors/warnings), but linking + real probes still need a Windows host. See `docs/VALIDATION.md` §6. |
| Windows service loop | n/a | ❌ Not verified — loop structure written (`aegis-service.rs`: install + file-watch reinstall + uninstall on stop), but uncompiled and never run. See `docs/VALIDATION.md` §11. |
