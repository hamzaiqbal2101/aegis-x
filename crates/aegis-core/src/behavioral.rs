//! Engine 9 (part) — behavioral baselining and anomaly scoring over
//! flow records.
//!
//! HONEST SCOPE: this scores *flow records the operator feeds it*
//! (bytes, packets, ports, timestamps). It does not collect flows, it
//! does not see payloads, and a flag here is "unusual compared with
//! this host's own past", not "malicious". Baselines built from too
//! little data are meaningless — volume scoring requires at least
//! `min_baseline_flows` flows for a host, and the code refuses to
//! score hosts below that instead of inventing a baseline.
//! Beaconing regularity also occurs in legitimate polling (updates,
//! keepalives); it is a triage signal, not a conviction.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// One observed flow (already aggregated by whatever collector the
/// operator runs — this engine does not collect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRecord {
    pub ts: u64,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub bytes: u64,
    pub packets: u64,
}

/// What kind of anomaly was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyKind {
    /// A flow far larger than the host's baseline (mean + k·std).
    VolumeDeviation,
    /// A destination port the host never used during baseline.
    NewPort,
    /// Suspiciously regular connections to one destination (low
    /// inter-arrival variance) — possible beaconing.
    Beaconing,
}

/// One anomaly result. `score` is a plain magnitude (e.g. how many
/// standard deviations, or 1 - CV for beaconing), not a probability.
#[derive(Debug, Clone)]
pub struct Anomaly {
    pub kind: AnomalyKind,
    pub src: IpAddr,
    pub detail: String,
    pub score: f64,
}

/// Tunable thresholds.
#[derive(Debug, Clone, Copy)]
pub struct BehaviorConfig {
    /// Volume flag threshold, in standard deviations above the mean.
    pub volume_std_threshold: f64,
    /// Minimum baseline flows before a host is volume-scored.
    pub min_baseline_flows: usize,
    /// Minimum repeated connections to consider beaconing.
    pub min_beacon_count: usize,
    /// Maximum coefficient of variation (std/mean of intervals) for
    /// beaconing. Lower = more regular.
    pub max_beacon_cv: f64,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        BehaviorConfig {
            volume_std_threshold: 3.0,
            min_baseline_flows: 5,
            min_beacon_count: 10,
            max_beacon_cv: 0.25,
        }
    }
}

/// A host's baseline, built from past flows.
#[derive(Debug, Clone)]
pub struct HostBaseline {
    pub mean_bytes_per_flow: f64,
    pub std_bytes_per_flow: f64,
    pub flow_count: usize,
    pub known_ports: HashSet<u16>,
}

fn mean_std(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let var = values
        .iter()
        .map(|v| (v - mean).powi(2))
        .sum::<f64>()
        / values.len() as f64;
    (mean, var.sqrt())
}

/// Build one baseline per source host from baseline-period flows.
pub fn build_baselines(flows: &[FlowRecord]) -> HashMap<IpAddr, HostBaseline> {
    let mut by_src: HashMap<IpAddr, Vec<&FlowRecord>> = HashMap::new();
    for f in flows {
        by_src.entry(f.src).or_default().push(f);
    }
    by_src
        .into_iter()
        .map(|(src, fs)| {
            let bytes: Vec<f64> = fs.iter().map(|f| f.bytes as f64).collect();
            let (mean, std) = mean_std(&bytes);
            let known_ports = fs.iter().map(|f| f.dst_port).collect();
            (
                src,
                HostBaseline {
                    mean_bytes_per_flow: mean,
                    std_bytes_per_flow: std,
                    flow_count: fs.len(),
                    known_ports,
                },
            )
        })
        .collect()
}

/// Flag new flows far larger than the host's baseline. Hosts with
/// fewer than `min_baseline_flows` baseline flows are skipped
/// (no baseline → no verdict, never a guessed one). When the
/// baseline std is 0 (perfectly uniform past flows), the threshold
/// falls back to twice the mean, so a doubling still flags.
pub fn detect_volume_anomalies(
    baselines: &HashMap<IpAddr, HostBaseline>,
    new_flows: &[FlowRecord],
    cfg: BehaviorConfig,
) -> Vec<Anomaly> {
    let mut out = Vec::new();
    for f in new_flows {
        let Some(base) = baselines.get(&f.src) else {
            continue;
        };
        if base.flow_count < cfg.min_baseline_flows {
            continue;
        }
        let threshold = if base.std_bytes_per_flow == 0.0 {
            base.mean_bytes_per_flow * 2.0
        } else {
            base.mean_bytes_per_flow + cfg.volume_std_threshold * base.std_bytes_per_flow
        };
        if (f.bytes as f64) > threshold {
            let score = if base.std_bytes_per_flow == 0.0 {
                f.bytes as f64 / base.mean_bytes_per_flow.max(1.0)
            } else {
                (f.bytes as f64 - base.mean_bytes_per_flow) / base.std_bytes_per_flow
            };
            out.push(Anomaly {
                kind: AnomalyKind::VolumeDeviation,
                src: f.src,
                detail: format!(
                    "flow of {} bytes to {}:{} exceeds baseline mean {:.0} (threshold {:.0})",
                    f.bytes, f.dst, f.dst_port, base.mean_bytes_per_flow, threshold
                ),
                score,
            });
        }
    }
    out
}

/// Flag new flows to ports the host never used during baseline.
/// One finding per (source, port), with a count.
pub fn detect_new_ports(
    baselines: &HashMap<IpAddr, HostBaseline>,
    new_flows: &[FlowRecord],
) -> Vec<Anomaly> {
    let mut counts: HashMap<(IpAddr, u16), usize> = HashMap::new();
    for f in new_flows {
        let Some(base) = baselines.get(&f.src) else {
            continue;
        };
        if !base.known_ports.contains(&f.dst_port) {
            *counts.entry((f.src, f.dst_port)).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .map(|((src, port), count)| Anomaly {
            kind: AnomalyKind::NewPort,
            src,
            detail: format!("{count} flow(s) to never-before-seen port {port}"),
            score: count as f64,
        })
        .collect()
}

/// Flag (source, destination, port) triples with suspiciously regular
/// inter-arrival times: at least `min_beacon_count` flows and a
/// coefficient of variation (std/mean of intervals) at or below
/// `max_beacon_cv`. Zero-mean intervals (identical timestamps) are
/// bursts, not beacons, and are skipped.
pub fn detect_beaconing(flows: &[FlowRecord], cfg: BehaviorConfig) -> Vec<Anomaly> {
    let mut by_key: HashMap<(IpAddr, IpAddr, u16), Vec<u64>> = HashMap::new();
    for f in flows {
        by_key
            .entry((f.src, f.dst, f.dst_port))
            .or_default()
            .push(f.ts);
    }
    let mut out = Vec::new();
    for ((src, dst, port), mut ts) in by_key {
        if ts.len() < cfg.min_beacon_count {
            continue;
        }
        ts.sort_unstable();
        let intervals: Vec<f64> = ts
            .windows(2)
            .map(|w| (w[1] - w[0]) as f64)
            .collect();
        let (mean, std) = mean_std(&intervals);
        if mean == 0.0 {
            continue;
        }
        let cv = std / mean;
        if cv <= cfg.max_beacon_cv {
            out.push(Anomaly {
                kind: AnomalyKind::Beaconing,
                src,
                detail: format!(
                    "{} connections to {dst}:{port} at ~{mean:.0}s intervals (CV {cv:.2})",
                    ts.len()
                ),
                score: 1.0 - cv,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn flow(ts: u64, src: &str, dst: &str, port: u16, bytes: u64) -> FlowRecord {
        FlowRecord {
            ts,
            src: ip(src),
            dst: ip(dst),
            dst_port: port,
            bytes,
            packets: bytes / 100 + 1,
        }
    }

    #[test]
    fn volume_anomaly_and_small_baseline_skip() {
        let cfg = BehaviorConfig::default();
        // Baseline: 10 flows ~1000 bytes each for host A.
        let baseline: Vec<FlowRecord> = (0..10)
            .map(|i| flow(i, "10.0.0.5", "10.0.0.1", 443, 1000 + (i % 3) * 10))
            .collect();
        let bases = build_baselines(&baseline);
        // A normal 1010-byte flow is clean; a 50000-byte flow flags.
        let normal = vec![flow(100, "10.0.0.5", "10.0.0.1", 443, 1010)];
        assert!(detect_volume_anomalies(&bases, &normal, cfg).is_empty());
        let big = vec![flow(100, "10.0.0.5", "10.0.0.1", 443, 50000)];
        let a = detect_volume_anomalies(&bases, &big, cfg);
        assert_eq!(a.len(), 1);
        assert!(a[0].score > cfg.volume_std_threshold);
        // Host B with only 2 baseline flows is never volume-scored.
        let thin: Vec<FlowRecord> = (0..2)
            .map(|i| flow(i, "10.0.0.6", "10.0.0.1", 443, 100))
            .collect();
        let thin_bases = build_baselines(&thin);
        let huge = vec![flow(100, "10.0.0.6", "10.0.0.1", 443, 999999)];
        assert!(detect_volume_anomalies(&thin_bases, &huge, cfg).is_empty());
    }

    #[test]
    fn new_port_detection() {
        let baseline: Vec<FlowRecord> = (0..10)
            .map(|i| flow(i, "10.0.0.5", "10.0.0.1", 443, 1000))
            .collect();
        let bases = build_baselines(&baseline);
        let new = vec![
            flow(100, "10.0.0.5", "10.0.0.1", 443, 1000),
            flow(101, "10.0.0.5", "10.0.0.1", 4444, 1000),
            flow(102, "10.0.0.5", "10.0.0.1", 4444, 1000),
        ];
        let a = detect_new_ports(&bases, &new);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].score, 2.0);
        assert!(a[0].detail.contains("4444"));
    }

    #[test]
    fn beaconing_regular_vs_irregular() {
        let cfg = BehaviorConfig::default();
        // Perfectly regular: every 60s, 20 times -> beacon.
        let regular: Vec<FlowRecord> = (0..20)
            .map(|i| flow(i * 60, "10.0.0.5", "203.0.113.9", 443, 200))
            .collect();
        assert_eq!(detect_beaconing(&regular, cfg).len(), 1);
        // Irregular intervals -> clean.
        let times = [0, 5, 90, 95, 300, 310, 700, 705, 1200, 1210, 2000, 2015];
        let irregular: Vec<FlowRecord> = times
            .iter()
            .map(|&t| flow(t, "10.0.0.5", "203.0.113.9", 443, 200))
            .collect();
        assert!(detect_beaconing(&irregular, cfg).is_empty());
        // Too few samples -> clean even if regular.
        let few: Vec<FlowRecord> = (0..5)
            .map(|i| flow(i * 60, "10.0.0.5", "203.0.113.9", 443, 200))
            .collect();
        assert!(detect_beaconing(&few, cfg).is_empty());
    }
}
