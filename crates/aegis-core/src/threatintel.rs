//! Engine 5 (part) — threat intelligence: local feed ingestion with
//! expiry and allowlist override.
//!
//! HONEST SCOPE: this reads indicator lists from a LOCAL JSON FILE.
//! There is no live commercial feed, no automatic download, no
//! "threat level" scoring, and no claim that any indicator here is a
//! real current threat. The shipped sample feed
//! (`examples/threat-feed-sample.json`) contains only TEST-NET
//! addresses and example domains, clearly labeled SAMPLE, for format
//! demonstration and unit tests. A production deployment replaces it
//! with a feed the operator vets and refreshes themselves.
//!
//! Semantics:
//! * An indicator blocks only while it is NOT expired (`expires_at`
//!   absent = never expires; expired when `now > expires_at`).
//! * The allowlist is checked FIRST and always wins: an allowlisted
//!   value is never blocked, even if an indicator lists it. That is
//!   the false-positive management path — an operator who finds a
//!   bad block adds the value to the allowlist instead of editing the
//!   feed.
//! * Domain indicators match exactly or as a parent domain (same rule
//!   as DNS matching in `dns.rs`); IP indicators match exactly.

use crate::dns::entry_matches;
use serde::Deserialize;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

/// What an indicator describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndicatorKind {
    Ip,
    Domain,
}

/// One indicator from a feed file.
#[derive(Debug, Clone, Deserialize)]
pub struct Indicator {
    pub kind: IndicatorKind,
    pub value: String,
    /// Unix seconds; absent = never expires.
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub source: String,
}

impl Indicator {
    /// Validate the value shape (IP must parse; domain must be non-empty).
    fn validate(&self) -> Result<(), String> {
        match self.kind {
            IndicatorKind::Ip => IpAddr::from_str(&self.value)
                .map(|_| ())
                .map_err(|_| format!("bad IP indicator: {}", self.value)),
            IndicatorKind::Domain => {
                if self.value.trim().is_empty() {
                    Err("empty domain indicator".to_string())
                } else {
                    Ok(())
                }
            }
        }
    }

    fn expired(&self, now: u64) -> bool {
        self.expires_at.map(|e| now > e).unwrap_or(false)
    }

    fn matches(&self, kind: IndicatorKind, value: &str) -> bool {
        if self.kind != kind {
            return false;
        }
        match kind {
            IndicatorKind::Ip => {
                // Compare parsed addresses, not raw strings: a query
                // spelling like "203.0.113.05" must not slip past a
                // block on "203.0.113.5". The indicator value was
                // validated at load (it parses); the query is parsed
                // here. An unparseable query never matches.
                // (Review Nov 14, 2026.)
                match (IpAddr::from_str(&self.value), IpAddr::from_str(value)) {
                    (Ok(a), Ok(b)) => a == b,
                    _ => false,
                }
            }
            IndicatorKind::Domain => entry_matches(&self.value, value),
        }
    }
}

#[derive(Debug, Deserialize)]
struct FeedFile {
    #[serde(default)]
    #[allow(dead_code)]
    version: u32,
    #[serde(default)]
    indicators: Vec<Indicator>,
    #[serde(default)]
    allowlist: Vec<String>,
}

/// A loaded feed: indicators + operator allowlist.
#[derive(Debug, Clone, Default)]
pub struct Feed {
    pub indicators: Vec<Indicator>,
    pub allowlist: Vec<String>,
}

impl Feed {
    /// Parse a feed file. Unknown JSON fields are ignored; malformed
    /// indicators are errors (a feed must never load half-broken).
    pub fn from_json(json: &str) -> Result<Feed, String> {
        let file: FeedFile =
            serde_json::from_str(json).map_err(|e| format!("feed JSON: {e}"))?;
        for ind in &file.indicators {
            ind.validate()?;
        }
        Ok(Feed {
            indicators: file.indicators,
            allowlist: file.allowlist,
        })
    }

    /// True if `value` is blocked at time `now`: allowlist wins, then
    /// any unexpired matching indicator.
    pub fn is_blocked(&self, kind: IndicatorKind, value: &str, now: u64) -> bool {
        match kind {
            IndicatorKind::Ip => {
                // Canonical comparison for the allowlist too: an
                // allowlist entry must match the queried address
                // regardless of spelling. (Review Nov 14, 2026.)
                if let Ok(query) = IpAddr::from_str(value) {
                    if self.allowlist.iter().any(|a| {
                        IpAddr::from_str(a)
                            .map(|allowed| allowed == query)
                            .unwrap_or(false)
                    }) {
                        return false;
                    }
                }
            }
            IndicatorKind::Domain => {
                if self.allowlist.iter().any(|a| entry_matches(a, value)) {
                    return false;
                }
            }
        }
        self.indicators
            .iter()
            .any(|ind| !ind.expired(now) && ind.matches(kind, value))
    }

    /// Drop expired indicators. Returns how many were removed.
    pub fn prune_expired(&mut self, now: u64) -> usize {
        let before = self.indicators.len();
        self.indicators.retain(|ind| !ind.expired(now));
        before - self.indicators.len()
    }

    /// Values currently blocked (unexpired indicators only). Useful
    /// for review UIs; not a verdict by itself.
    pub fn active_values(&self, now: u64) -> HashSet<String> {
        self.indicators
            .iter()
            .filter(|ind| !ind.expired(now))
            .map(|ind| ind.value.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "version": 1,
        "indicators": [
            {"kind": "ip", "value": "203.0.113.5", "expires_at": 1893456000, "source": "sample"},
            {"kind": "ip", "value": "203.0.113.6", "expires_at": 1000, "source": "sample"},
            {"kind": "domain", "value": "evil.example.com", "source": "sample"}
        ],
        "allowlist": ["203.0.113.5", "ok.evil.example.com"]
    }"#;

    #[test]
    fn expiry_and_allowlist() {
        let feed = Feed::from_json(SAMPLE).unwrap();
        let now = 1700000000;
        // 203.0.113.5 is allowlisted -> never blocked despite indicator.
        assert!(!feed.is_blocked(IndicatorKind::Ip, "203.0.113.5", now));
        // 203.0.113.6 expired at t=1000 -> not blocked.
        assert!(!feed.is_blocked(IndicatorKind::Ip, "203.0.113.6", now));
        // evil.example.com blocks; its allowlisted subdomain does not.
        assert!(feed.is_blocked(IndicatorKind::Domain, "evil.example.com", now));
        assert!(feed.is_blocked(IndicatorKind::Domain, "sub.evil.example.com", now));
        assert!(!feed.is_blocked(IndicatorKind::Domain, "ok.evil.example.com", now));
        // Unlisted values are not blocked.
        assert!(!feed.is_blocked(IndicatorKind::Ip, "198.51.100.9", now));
    }

    #[test]
    fn prune_removes_only_expired() {
        let mut feed = Feed::from_json(SAMPLE).unwrap();
        assert_eq!(feed.prune_expired(1700000000), 1);
        assert_eq!(feed.indicators.len(), 2);
        assert!(feed.active_values(1700000000).contains("203.0.113.5"));
    }

    #[test]
    fn malformed_feed_rejected() {
        let bad_ip = r#"{"version":1,"indicators":[{"kind":"ip","value":"not-an-ip"}]}"#;
        assert!(Feed::from_json(bad_ip).is_err());
        let bad_kind = r#"{"version":1,"indicators":[{"kind":"url","value":"x"}]}"#;
        assert!(Feed::from_json(bad_kind).is_err());
        assert!(Feed::from_json("not json").is_err());
        // Empty feed loads fine (zero indicators).
        let empty = Feed::from_json(r#"{"version":1,"indicators":[]}"#).unwrap();
        assert!(!empty.is_blocked(IndicatorKind::Ip, "203.0.113.5", 0));
    }

    #[test]
    fn review_ip_matching_is_canonical_not_string() {
        // A non-canonical spelling of a blocked IP must still match.
        // Feed values are always canonical (validated at load), so
        // the IPv6 compressed-vs-expanded form is the case string
        // equality would miss; an unparseable query never matches.
        let feed = Feed::from_json(
            r#"{"indicators":[{"kind":"ip","value":"2001:db8::1"}]}"#,
        )
        .unwrap();
        assert!(feed.is_blocked(
            IndicatorKind::Ip,
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            1000
        ));
        assert!(!feed.is_blocked(IndicatorKind::Ip, "2001:db8::2", 1000));
        assert!(!feed.is_blocked(IndicatorKind::Ip, "not-an-ip", 1000));
    }
}
