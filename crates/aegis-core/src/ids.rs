//! Engine 2 — event-based intrusion detection.
//!
//! HONEST SCOPE: this is NOT Suricata and NOT inline deep packet
//! inspection. It analyzes *connection-event records* (already observed
//! flows: who talked to whom, on which port, whether authentication
//! failed) and flags patterns that look like reconnaissance or
//! brute-force attacks. It cannot see packet payloads, so it cannot
//! detect exploits, malware content, or protocol anomalies — that is
//! what a real IDS (Suricata integration, still roadmap) is for.
//!
//! All functions here are pure: they take a slice of events and a
//! config and return findings. No I/O, no clocks, no global state.
//! Thresholds are tunable via `IdsConfig`; defaults are starting
//! points, not tuned values for any real network.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// One observed connection event. `failed` means the connection looked
/// like a failed authentication attempt (e.g. the service logged an
/// auth failure, or the handshake was rejected for credentials) — the
/// caller decides that classification; this engine only counts them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnEvent {
    /// Seconds since an arbitrary epoch (only ordering/differences matter).
    pub ts: u64,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub failed: bool,
}

/// What kind of suspicious pattern was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    /// One source touched many distinct ports in a short window.
    PortScan,
    /// Many failed attempts from one source to one service.
    BruteForce,
    /// Traffic to a known-bad port or address.
    KnownBad,
}

/// One detection result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: FindingKind,
    pub src: IpAddr,
    /// Human-readable detail (target, window, counts).
    pub detail: String,
    /// The count that tripped the threshold (ports, attempts, or hits).
    pub count: usize,
}

/// Tunable thresholds. Defaults are deliberately conservative
/// starting points; tune them against real traffic before alerting.
#[derive(Debug, Clone, Copy)]
pub struct IdsConfig {
    /// Sliding window in seconds for scan/brute-force detection.
    pub window_secs: u64,
    /// Distinct ports from one source within the window → port scan.
    pub scan_port_threshold: usize,
    /// Failed attempts from one source to one (dst, port) within
    /// the window → brute force.
    pub brute_attempt_threshold: usize,
}

impl Default for IdsConfig {
    fn default() -> Self {
        IdsConfig {
            window_secs: 60,
            scan_port_threshold: 20,
            brute_attempt_threshold: 15,
        }
    }
}

/// Group events by key, sorted by timestamp.
fn group_sorted<K: Eq + std::hash::Hash + Clone>(
    events: &[ConnEvent],
    key: impl Fn(&ConnEvent) -> K,
) -> HashMap<K, Vec<&ConnEvent>> {
    let mut map: HashMap<K, Vec<&ConnEvent>> = HashMap::new();
    for e in events {
        map.entry(key(e)).or_default().push(e);
    }
    for v in map.values_mut() {
        v.sort_by_key(|e| e.ts);
    }
    map
}

/// Port-scan detection: distinct destination ports from one source
/// inside any `window_secs` window.
pub fn detect_port_scans(events: &[ConnEvent], cfg: IdsConfig) -> Vec<Finding> {
    let mut out = Vec::new();
    for (src, evs) in group_sorted(events, |e| e.src) {
        // Sliding window with per-port counts (two pointers).
        let mut counts: HashMap<u16, usize> = HashMap::new();
        let mut left = 0usize;
        let mut worst = 0usize;
        let mut worst_end = 0u64;
        for right in 0..evs.len() {
            *counts.entry(evs[right].dst_port).or_insert(0) += 1;
            while evs[right].ts.saturating_sub(evs[left].ts) > cfg.window_secs {
                let c = counts.get_mut(&evs[left].dst_port).expect("counted");
                *c -= 1;
                if *c == 0 {
                    counts.remove(&evs[left].dst_port);
                }
                left += 1;
            }
            if counts.len() > worst {
                worst = counts.len();
                worst_end = evs[right].ts;
            }
        }
        if worst >= cfg.scan_port_threshold {
            out.push(Finding {
                kind: FindingKind::PortScan,
                src,
                detail: format!(
                    "{worst} distinct ports within {}s ending at t={worst_end}",
                    cfg.window_secs
                ),
                count: worst,
            });
        }
    }
    out
}

/// Brute-force detection: failed attempts from one source to one
/// (destination, port) inside any `window_secs` window. Successful
/// connections never count; failures to different services never
/// aggregate (each service is counted separately).
pub fn detect_brute_force(events: &[ConnEvent], cfg: IdsConfig) -> Vec<Finding> {
    let mut out = Vec::new();
    for ((src, dst, port), evs) in group_sorted(events, |e| (e.src, e.dst, e.dst_port)) {
        let failed: Vec<&ConnEvent> = evs.into_iter().filter(|e| e.failed).collect();
        let mut left = 0usize;
        let mut worst = 0usize;
        let mut worst_end = 0u64;
        for right in 0..failed.len() {
            while failed[right].ts.saturating_sub(failed[left].ts) > cfg.window_secs {
                left += 1;
            }
            let n = right - left + 1;
            if n > worst {
                worst = n;
                worst_end = failed[right].ts;
            }
        }
        if worst >= cfg.brute_attempt_threshold {
            out.push(Finding {
                kind: FindingKind::BruteForce,
                src,
                detail: format!(
                    "{worst} failed attempts to {dst}:{port} within {}s ending at t={worst_end}",
                    cfg.window_secs
                ),
                count: worst,
            });
        }
    }
    out
}

/// Known-bad matching: any event whose destination port is in
/// `bad_ports` or whose destination address is in `bad_ips` produces
/// one finding per (source, target), counting hits. This is only as
/// good as the list it is given — an empty list finds nothing, and a
/// stale list produces false positives. Lists are the operator's job.
pub fn detect_known_bad(
    events: &[ConnEvent],
    bad_ports: &[u16],
    bad_ips: &[IpAddr],
) -> Vec<Finding> {
    let bad_ports: HashSet<u16> = bad_ports.iter().copied().collect();
    let bad_ips: HashSet<IpAddr> = bad_ips.iter().copied().collect();
    let mut hits: HashMap<(IpAddr, String), usize> = HashMap::new();
    for e in events {
        if bad_ports.contains(&e.dst_port) {
            *hits.entry((e.src, format!("port {}", e.dst_port))).or_insert(0) += 1;
        }
        if bad_ips.contains(&e.dst) {
            *hits.entry((e.src, format!("host {}", e.dst))).or_insert(0) += 1;
        }
    }
    hits.into_iter()
        .map(|((src, target), count)| Finding {
            kind: FindingKind::KnownBad,
            src,
            detail: format!("{count} connection(s) to known-bad {target}"),
            count,
        })
        .collect()
}

/// Run all detectors.
pub fn detect_all(
    events: &[ConnEvent],
    cfg: IdsConfig,
    bad_ports: &[u16],
    bad_ips: &[IpAddr],
) -> Vec<Finding> {
    let mut out = detect_port_scans(events, cfg);
    out.extend(detect_brute_force(events, cfg));
    out.extend(detect_known_bad(events, bad_ports, bad_ips));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn ev(ts: u64, src: &str, dst: &str, port: u16, failed: bool) -> ConnEvent {
        ConnEvent {
            ts,
            src: ip(src),
            dst: ip(dst),
            dst_port: port,
            failed,
        }
    }

    #[test]
    fn port_scan_detected_and_window_respected() {
        let cfg = IdsConfig::default();
        // 25 distinct ports within 60s -> scan.
        let mut events: Vec<ConnEvent> = (0..25)
            .map(|i| ev(i, "10.0.0.5", "10.0.0.1", 1000 + i as u16, false))
            .collect();
        assert_eq!(detect_port_scans(&events, cfg).len(), 1);
        // Same 25 ports spread over 600s -> no window holds 20 -> clean.
        for (i, e) in events.iter_mut().enumerate() {
            e.ts = (i as u64) * 25;
        }
        assert!(detect_port_scans(&events, cfg).is_empty());
        // Below threshold (10 ports) -> clean.
        let few: Vec<ConnEvent> = (0..10)
            .map(|i| ev(i, "10.0.0.5", "10.0.0.1", 1000 + i as u16, false))
            .collect();
        assert!(detect_port_scans(&few, cfg).is_empty());
    }

    #[test]
    fn brute_force_counts_only_failures_to_one_service() {
        let cfg = IdsConfig::default();
        // 16 failed SSH attempts in 60s -> brute force.
        let mut events: Vec<ConnEvent> = (0..16)
            .map(|i| ev(i, "10.0.0.9", "10.0.0.1", 22, true))
            .collect();
        let f = detect_brute_force(&events, cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].count, 16);
        // 16 successes -> clean (successes never count).
        for e in events.iter_mut() {
            e.failed = false;
        }
        assert!(detect_brute_force(&events, cfg).is_empty());
        // 8 failed to SSH + 8 failed to FTP -> clean (no aggregation).
        let mut mixed: Vec<ConnEvent> = (0..8)
            .map(|i| ev(i, "10.0.0.9", "10.0.0.1", 22, true))
            .collect();
        mixed.extend((0..8).map(|i| ev(i, "10.0.0.9", "10.0.0.1", 21, true)));
        assert!(detect_brute_force(&mixed, cfg).is_empty());
    }

    #[test]
    fn known_bad_matches_port_and_host() {
        let events = vec![
            ev(0, "10.0.0.5", "10.0.0.1", 23, false),
            ev(1, "10.0.0.5", "10.0.0.1", 23, false),
            ev(2, "10.0.0.5", "203.0.113.7", 443, false),
            ev(3, "10.0.0.6", "10.0.0.1", 80, false),
        ];
        let f = detect_known_bad(&events, &[23], &["203.0.113.7".parse().unwrap()]);
        // (10.0.0.5, port 23) x2, (10.0.0.5, host 203.0.113.7) x1.
        assert_eq!(f.len(), 2);
        assert!(f.iter().any(|x| x.count == 2));
        // Empty lists find nothing.
        assert!(detect_known_bad(&events, &[], &[]).is_empty());
        // Empty input finds nothing.
        assert!(detect_all(&[], IdsConfig::default(), &[23], &[]).is_empty());
    }
}
