//! AEGIS X shared policy engine.
//!
//! OS-independent: policy model, first-match-wins evaluation, conflict
//! detection, and integrity hashing. Platform adapters (nftables, WFP)
//! translate a validated `Policy` into native enforcement; they never
//! re-implement matching semantics.

pub mod behavioral;
pub mod conflict;
pub mod dns;
pub mod ids;
pub mod integrity;
pub mod matcher;
pub mod policy;
pub mod ratelimit;
pub mod segmentation;
pub mod suricata;
pub mod threatintel;

#[cfg(test)]
mod property_tests;

pub use behavioral::{build_baselines, detect_beaconing, detect_new_ports, detect_volume_anomalies};
pub use behavioral::{Anomaly, AnomalyKind, BehaviorConfig, FlowRecord, HostBaseline};
pub use conflict::{detect_conflicts, Conflict, ConflictKind};
pub use dns::{analyze_name, entry_matches, normalize, DnsAnalysis, DnsConfig, DnsPolicy, DnsVerdict};
pub use ids::{detect_all, detect_brute_force, detect_known_bad, detect_port_scans};
pub use ids::{ConnEvent, Finding, FindingKind, IdsConfig};
pub use integrity::policy_hash;
pub use matcher::{evaluate, rule_matches, EvalPacket, Verdict};
pub use policy::{Action, Cidr, ConnState, Policy, PortSpec, Protocol, RateLimit, RateUnit, Rule, Zone};
pub use ratelimit::{RateLimiter, TokenBucket};
pub use segmentation::{zone_matrix, MatrixCell, ZoneMatrix};
pub use suricata::{
    deduplicate, ingest_eve_log, is_active, parse_eve_line, parse_eve_timestamp, prune_expired,
    BlockDecision, SuricataConfig,
};
pub use threatintel::{Feed, Indicator, IndicatorKind};
