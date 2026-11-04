# AEGIS X — Threat Model

## 1. Assets

* The host itself (OS, services, user data) and the network it sits on.
* The firewall policy (its correctness *is* the security property).
* Management credentials and the audit log (tampering hides attacks).
* Telemetry data (connection history is sensitive metadata).

## 2. Attackers (assumed capabilities)

| Attacker | Capabilities | In scope? |
|---|---|---|
| Remote network attacker | Port scans, exploit attempts, spoofed packets, floods, DNS abuse, evasion (fragmentation, IPv6, TTL games) | Yes — primary |
| Malicious/compromised local application | Tries to phone home, pivot laterally, disable the firewall, change policy | Yes — app control + tamper detection |
| Malicious local user (non-admin) | Tries to alter policy, stop the service, read the audit log | Yes — admin-only management, RBAC |
| Admin account compromise | Full policy control | Partially — audit log + backups + signed updates limit silent persistence; cannot fully mitigate a compromised admin |
| Nation-state / kernel-level attacker | Kernel exploits, supply-chain compromise | No — out of scope; documented residual risk |

## 3. Threat → mitigation mapping

| Threat | Mitigation in AEGIS X | Residual risk |
|---|---|---|
| Unsolicited inbound connections | Default deny; stateful inspection; only established/related traffic returns | Misconfigured allow rule — mitigated by conflict detection + review UI |
| Port scans / brute force | IDS signatures (M3+), rate limits, temporary blocks | Slow scans under thresholds; accepted, logged |
| SYN flood / UDP flood | Rate limits, SYN controls, adaptive thresholds (M3) | Volumetric floods above link capacity cannot be fixed on-host |
| Malware phoning home | App control (Windows full; Linux limited), DNS blocklists, behavioral anomalies (M4+) | Linux app identity is weaker (see matrix); process can rename itself — mitigated by hash-based identity on Windows, partial on Linux |
| DNS tunneling / malicious domains | DNS security engine (M5): blocklists, query monitoring, tunneling heuristics | Encrypted DNS (DoH) to an allowed resolver bypasses DNS inspection — documented; endpoint controls are the backstop |
| Evasion: fragmentation, IPv6, overlapping segments | Anti-evasion engine: fragment policy, IPv6 parity checks, invalid-packet drop (M1 base policy) | OS reassembly differences are a known hard problem; defense in depth, not a guarantee |
| Rule shadowing / misconfiguration | Conflict detection before apply; rule testing; staged rollout + rollback timer | Human error in *intended* policy cannot be detected automatically |
| Tampering with policy/service | Policy hashing, signed updates, tamper alerts, audit log, admin-only access | A root/admin attacker can disable any host control — documented |
| Lockout by bad policy | Rollback timer, last-known-good policy, emergency recovery mode | Physical/console access may still be required in worst cases |
| Supply-chain (malicious update) | Signed packages, signature verification before install | Signing-key compromise — key rotation procedure required (ops doc, later) |

## 4. Explicit non-goals (do not claim these)

* AEGIS X does not make a host "unhackable". Any vendor claiming that is
  lying; this document exists precisely to avoid that claim.
* It does not inspect encrypted payloads (no TLS MITM).
* It does not protect against attacks that do not traverse the network
  (USB, physical access, malicious admin).
* It does not replace patching, endpoint protection, or backups.

## 5. Test environments

All attack simulations (scans, floods, evasion attempts) are performed
only in isolated environments: Linux network namespaces, dedicated VMs, or
lab networks with written authorization. Never against third-party systems.

## 6. Security assessment status

* M1: self-tested (unit tests + isolated netns enforcement tests).
* Independent review, fuzzing of the policy parser, and a penetration test
  of the management API are required before any release claim
  (see `ROADMAP.md` M8). Until then, AEGIS X is **not release-ready** and
  this document must not be quoted as an assessment.
