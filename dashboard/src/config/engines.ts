/**
 * Engine status table — the SINGLE source of truth for the Overview page.
 *
 * HONESTY RULE: a status here means only what its label says, and the
 * note must say what was actually proven in this repo. Never add numbers,
 * traffic, or threat counts — this dashboard shows no telemetry it did
 * not fetch from the live API.
 *
 * NOTE FOR THE COORDINATOR (update applied Nov 2, 2026): the IDS /
 * rate limiting / DNS / threat-intel / behavioral / segmentation
 * engines have now landed in crates/aegis-core with passing tests, so
 * they are marked active below with honest scope notes. Do not mark
 * an engine active until its code is in the repo and its tests pass.
 *
 * Statuses:
 *   active      — implemented + unit-tested in this repo
 *   degraded    — works with documented limits
 *   unsupported — not available on this platform
 *   unverified  — written but never run on a real host
 *   unknown     — status cannot be determined from this repo alone
 */

export type EngineStatus =
  | 'active'
  | 'degraded'
  | 'unsupported'
  | 'unverified'
  | 'unknown';

export interface EngineInfo {
  id: string;
  name: string;
  status: EngineStatus;
  /** What was actually proven, or what is still missing. No invented data. */
  note: string;
}

export const ENGINES: EngineInfo[] = [
  {
    id: 'policy-engine',
    name: 'Policy engine',
    status: 'active',
    note: 'Rust shared policy engine (default-deny, priority first-match, conflict detection, integrity hash). 38 unit tests pass in aegis-core (M1 + M3 + M5 + M6).',
  },
  {
    id: 'linux-nftables',
    name: 'Linux nftables adapter',
    status: 'active',
    note: 'CLI render/check/apply/rollback/eval. Real allow/deny proven in an isolated user+net namespace loopback test. Sandbox kernel has no nf_conntrack, so stateful base rules fail closed there.',
  },
  {
    id: 'windows-wfp',
    name: 'Windows WFP adapter',
    status: 'unverified',
    note: 'Written, never compiled or run on Windows: engine.rs is cfg(windows)-gated and Linux builds a stub. The first Windows build + verify-m4.ps1 run on a Windows PC is still required before any Windows enforcement claim.',
  },
  {
    id: 'management-api',
    name: 'Management API',
    status: 'unknown',
    note: 'Status is determined live on the Overview page from GET /status — never hardcoded here. Until that fetch succeeds, this engine is unknown.',
  },
  {
    id: 'ids',
    name: 'IDS',
    status: 'active',
    note: 'Event-based detection (port scans, brute force, known-bad) over connection records. NOT Suricata and NOT inline DPI — it cannot see payloads. Unit-tested.',
  },
  {
    id: 'rate-limiting',
    name: 'Rate limiting',
    status: 'active',
    note: 'Token-bucket limiter in the core engine + nftables limit rendering per rule. Note: this sandbox kernel lacks nft_limit, so kernel-level limit enforcement is unverified here (see VALIDATION.md).',
  },
  {
    id: 'dns',
    name: 'DNS engine',
    status: 'active',
    note: 'Name blocklist/allowlist matching + tunneling heuristics (label length, entropy, subdomain count). Analyzes names only; it does not intercept DNS traffic.',
  },
  {
    id: 'threat-intel',
    name: 'Threat intelligence',
    status: 'active',
    note: 'Local JSON feed ingestion with expiry + allowlist override. NO live commercial feed: the shipped sample feed contains only TEST-NET addresses and example domains.',
  },
  {
    id: 'behavioral',
    name: 'Behavioral engine',
    status: 'active',
    note: 'Per-host baselines (bytes/flows/ports) + volume, new-port, and beaconing detection over flow records. A flag means unusual vs. this host’s own past, not malicious.',
  },
  {
    id: 'segmentation',
    name: 'Segmentation',
    status: 'active',
    note: 'Zone-matrix validator: one representative packet per zone pair (one protocol + port). A review aid, not a proof for every possible flow between zones.',
  },
];
