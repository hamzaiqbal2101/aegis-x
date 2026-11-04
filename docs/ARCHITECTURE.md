# AEGIS X — Architecture

## 1. Design principles (in priority order)

1. **Security** — default deny, least privilege, fail closed.
2. **Correctness** — a rule must mean the same thing on Windows and Linux;
   where an OS cannot express it, the feature is reported as
   unsupported/degraded, never silently approximated.
3. **Reliability** — every policy change is validated, staged, and
   rollback-able; a bad policy must never lock the operator out without a
   recovery path.
4. **Performance** — enforcement happens in the OS packet path (WFP
   callouts / nftables), never by routing packets through a userspace
   process. Userspace code manages policy; it does not forward packets.
5. **User experience** — the dashboard shows only real telemetry.

## 2. Module map

```
┌─────────────────────────────────────────────────────────────────┐
│ Dashboard (React + TypeScript + Tailwind) — ROADMAP             │
│  Overview · Live Traffic · Rules · Apps · IDS · Intel · DNS ·   │
│  Network · Events · Settings                                    │
└──────────────────────────────┬──────────────────────────────────┘
                               │ HTTPS (localhost, authenticated)
┌──────────────────────────────▼──────────────────────────────────┐
│ Management API (Python + FastAPI) — ROADMAP                     │
│  AuthN/Z (admin roles) · policy CRUD · versioning · audit log  │
│  backup/restore · health · update channel                       │
└──────────────────────────────┬──────────────────────────────────┘
                               │ validated policy document (JSON)
┌──────────────────────────────▼──────────────────────────────────┐
│ Shared security core — Rust (crates/aegis-core) — MILESTONE 1   │
│  Policy model · matcher · priority ordering · conflict          │
│  detection · state model · integrity hash · nft renderer        │
│  (Windows rendering is a separate WFP translation, same model)  │
└───────┬───────────────────────────────────┬─────────────────────┘
        │                                   │
┌───────▼───────────────────┐   ┌───────────▼───────────────────┐
│ Linux adapter (M1)        │   │ Windows adapter (ROADMAP)     │
│ nftables / Netfilter      │   │ Windows Filtering Platform    │
│ (optional eBPF/XDP later) │   │ (WFP callouts, ALE layers)    │
└───────────────────────────┘   └───────────────────────────────┘
        │                                   │
┌───────▼───────────────────┐   ┌───────────▼───────────────────┐
│ Detection (ROADMAP)       │   │ Detection (ROADMAP)           │
│ Suricata (IDS/IPS) ·      │   │ Suricata (Windows build) ·    │
│ conntrack telemetry ·     │   │ ETW / WFP flow events ·       │
│ threat-intel feeds        │   │ threat-intel feeds            │
└───────────────────────────┘   └───────────────────────────────┘
```

### Why Rust for the core

Memory safety without a garbage collector, no runtime, and a single
implementation of policy semantics shared by both adapters. The core crate
has **no OS dependencies** so its matcher and conflict detection can be
unit-tested identically on every platform.

### Why the OS does the filtering

WFP and nftables both filter in the kernel packet path. A userspace
packet pump (e.g. NFQUEUE for every packet) would add latency, CPU cost,
and a new failure mode: if the userspace process dies, traffic either
stalls or falls through. AEGIS X uses NFQUEUE only for *selected*
deep-inspection cases in later milestones, never as the default path.

## 3. Policy document (shared format)

Versioned JSON, one document per policy. Example (abridged):

```json
{
  "version": 1,
  "name": "standard",
  "mode": "standard",
  "default_action": "deny",
  "zones": [
    { "name": "lan", "subnets": ["192.168.0.0/16", "10.0.0.0/8"] },
    { "name": "wan", "subnets": ["0.0.0.0/0"] }
  ],
  "rules": [
    {
      "id": "allow-lan-dns",
      "priority": 10,
      "action": "allow",
      "protocol": "udp",
      "src_zone": "lan",
      "dst_port": 53,
      "state": ["new", "established"],
      "engines": ["stateful", "dns"],
      "log": true
    }
  ]
}
```

Semantics, enforced by `aegis-core`:

* Rules are evaluated in ascending `priority` order; the first matching
  rule decides. If no rule matches, `default_action` applies (`deny` in
  every shipped profile).
* A rule matches only if **all** specified fields match (protocol, ports,
  addresses/zones, interface, state, application on Windows). Unspecified
  fields match anything.
* `state: ["invalid"]` never matches an allow rule: invalid packets are
  dropped by the base policy before user rules are evaluated.
* Ports may be a single port, a range, or a list. Addresses may be CIDR
  (IPv4 and IPv6) or zone names.
* `engines` tags record which rule engines a rule belongs to; they do not
  change matching in M1 — they drive the dashboard and later engines.

## 4. The ten rule engines — where they live

| # | Engine | M1 | Later milestone |
|---|--------|----|-----------------|
| 1 | Stateful packet inspection | Model + nft `ct state` mapping | conntrack telemetry, invalid-packet counters |
| 2 | Intrusion detection/prevention | Signature-match data model (no signatures shipped) | Suricata integration, blocking via nft set / WFP |
| 3 | DDoS / traffic abuse | Rate-limit rule fields | nft `limit` + SYN proxy behaviour, adaptive thresholds |
| 4 | Application control | App-identity field in model | WFP ALE app IDs (Windows); Linux: cgroupv2/owner match (limited) |
| 5 | Zero Trust | Default-deny + zones + admin controls | Identity-aware rules, per-app least privilege |
| 6 | Threat intelligence | Blocklist set model (IP/CIDR/domain) | Feed ingestion, expiry, false-positive allowlist |
| 7 | DNS security | DNS rule tagging | DNS query monitor, tunneling heuristics, blocklists |
| 8 | Network segmentation | Zones + interface rules | Zone matrix UI, lateral-movement indicators |
| 9 | Behavioral detection | Connection-rate fields | Baseline + anomaly scoring from flow telemetry |
| 10 | Anti-evasion + integrity | Conflict detection, policy hash, rollback store | IPv6 parity checks, fragment policy, tamper alerts |

Each engine supports enable/disable, custom configuration, priority,
allow/deny actions, logging, alerts, rule testing, safe rollback, and
import/export — implemented incrementally per engine, not claimed in
advance. The dashboard reports each engine as **active / disabled /
unsupported / degraded** per OS (see `PLATFORM_MATRIX.md`).

## 5. Data flow — a packet's journey (Linux)

```
packet → nftables ingress hook (table inet aegis)
  → base chain: drop ct state invalid; drop fragments per policy
  → zone classification (iif/oif + address sets)
  → user chains in priority order (first match → verdict)
  → default: drop (counter increments)
  → accepted packets continue; connection tracked by conntrack
telemetry: nft counters + conntrack events → API → dashboard
```

Windows equivalent: WFP ALE_AUTH_CONNECT / ALE_AUTH_RECV_ACCEPT layers,
sublayers ordered by priority weight, default block.

## 6. Security modes

| Mode | Default | IDS | Threat intel | App control |
|------|---------|-----|--------------|-------------|
| monitor | allow + log everything new (observe only; no new blocks) | alert only | alert only | log only |
| standard | deny | on (alert) | on | basic |
| advanced | deny | on (block) | on | strict |
| strict | deny | on (block) | on | explicit allowlist only |

Mode is a profile: it sets engine defaults. Every engine remains
individually configurable afterwards. Applying a mode that adds blocking
rules requires explicit confirmation in the UI/API, with a warning that
connectivity may be interrupted, and an automatic rollback timer
(default 60 s: if the operator does not confirm, the previous policy is
restored). This is the anti-lockout mechanism.

## 7. Integrity, updates, recovery

* Policies are stored with a SHA-256 hash; the adapter refuses to apply a
  policy whose content differs from its recorded hash unless the operator
  re-signs (re-approves) it.
* The last known-good policy is always retained; `rollback` restores it.
* The management API requires authentication; admin actions are audit-logged
  (who, what, when, previous value).
* Updates to AEGIS X itself are delivered as signed packages; the updater
  verifies the signature before installing and keeps the previous version
  for rollback.
* Emergency recovery: a boot-time / service-start safe mode loads a
  minimal allow-management-only policy so a bad rule cannot permanently
  brick remote administration. (Implementation: later milestone; the
  mechanism is specified here so it is not an afterthought.)

## 8. What AEGIS X deliberately does NOT do

* No TLS interception / MITM decryption.
* No kernel driver of its own; it uses WFP and nftables.
* No packet forwarding through userspace on the default path.
* No "AI" verdicts without an auditable rule or signature behind them.
* No telemetry sent anywhere by default; all data stays local unless the
  operator configures a central deployment (PostgreSQL option).
