//! Shared policy model for AEGIS X.
//!
//! A policy is a versioned JSON document. Semantics (enforced here, and
//! therefore identical on every platform):
//!
//! * Rules are evaluated in ascending `priority` order; the first matching
//!   rule decides. Ties keep document order (stable sort).
//! * If no rule matches, `default_action` applies (`deny` in every shipped
//!   profile).
//! * A rule matches only if *all* of its specified fields match. An
//!   unspecified field matches anything.
//! * Zone names are expanded to CIDR lists at load time; unknown zones are
//!   a load error, never silently ignored.
//! * Ports on an ICMP rule are a load error: ports are meaningless there.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

/// What happens when a rule (or the default) decides a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Let the packet through.
    Allow,
    /// Drop silently.
    Deny,
    /// Drop with an ICMP error / TCP reset where the OS supports it.
    Reject,
    /// Allow, and record the decision in the log.
    Log,
    /// Deny, and raise an alert in addition to logging.
    Alert,
}

/// Layer-4 protocol. `Any` means "no protocol restriction".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Any,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Any
    }
}

impl Protocol {
    pub fn is_icmp(self) -> bool {
        matches!(self, Protocol::Icmp | Protocol::Icmpv6)
    }
}

/// Connection state, mirroring conntrack / WFP ALE state concepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnState {
    New,
    Established,
    Related,
    Invalid,
}

/// A CIDR block, e.g. `192.168.0.0/16`. A bare IP parses as a /32 (v4)
/// or /128 (v6) host address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    pub network: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Cidr, String> {
        if let Some((addr_s, prefix_s)) = s.split_once('/') {
            let addr = IpAddr::from_str(addr_s)
                .map_err(|_| format!("invalid IP address in CIDR: {s}"))?;
            let prefix: u8 = prefix_s
                .parse()
                .map_err(|_| format!("invalid prefix in CIDR: {s}"))?;
            let max = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max {
                return Err(format!("prefix {prefix} out of range for {addr}"));
            }
            Ok(Cidr {
                network: mask(addr, prefix),
                prefix,
            })
        } else {
            let addr =
                IpAddr::from_str(s).map_err(|_| format!("invalid IP address: {s}"))?;
            let prefix = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Ok(Cidr {
                network: addr,
                prefix,
            })
        }
    }

    /// True if `ip` falls inside this block.
    ///
    /// The family check comes first on purpose: `mask()` shifts by
    /// `32 - prefix` (V4) / `128 - prefix` (V6), which underflows
    /// when a packet of one family is checked against a CIDR of the
    /// other family with a larger prefix (e.g. a V4 packet against
    /// a V6 /48). Short-circuiting here keeps that call unreachable
    /// for cross-family pairs; `mask()` itself is also saturating
    /// as a second line of defense.
    pub fn contains(&self, ip: IpAddr) -> bool {
        same_family(ip, self.network) && mask(ip, self.prefix) == self.network
    }

    /// True if `other` is fully contained in this block (network containment).
    pub fn contains_network(&self, other: &Cidr) -> bool {
        same_family(self.network, other.network)
            && self.prefix <= other.prefix
            && mask(other.network, self.prefix) == self.network
    }
}

fn same_family(a: IpAddr, b: IpAddr) -> bool {
    matches!(
        (a, b),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    // Saturating shifts: a prefix larger than the family's width
    // (only reachable from a cross-family call, which `contains`
    // already short-circuits) degrades to "no masking" instead of
    // an underflow panic in debug builds.
    match ip {
        IpAddr::V4(v4) => {
            let bits = if prefix == 0 {
                0u32
            } else {
                u32::MAX << 32u32.saturating_sub(prefix as u32)
            };
            IpAddr::V4(std::net::Ipv4Addr::from(u32::from(v4) & bits))
        }
        IpAddr::V6(v6) => {
            let bits = if prefix == 0 {
                0u128
            } else {
                u128::MAX << 128u32.saturating_sub(prefix as u32)
            };
            IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & bits))
        }
    }
}

impl Serialize for Cidr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{}/{}", self.network, self.prefix))
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Cidr, D::Error> {
        let text = String::deserialize(d)?;
        Cidr::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// A port selector: a single port, an inclusive range object
/// `{"range": [8000, 8100]}`, or a list `[53, 443]`.
/// (A bare two-element array is parsed as a list, not a range.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    Single(u16),
    Range { range: (u16, u16) },
    List(Vec<u16>),
}

impl PortSpec {
    pub fn contains(&self, port: u16) -> bool {
        match self {
            PortSpec::Single(p) => *p == port,
            PortSpec::Range { range: (lo, hi) } => *lo <= port && port <= *hi,
            PortSpec::List(ps) => ps.contains(&port),
        }
    }

    /// True if every port this spec can match is also matched by `other`.
    /// `None` (unrestricted) covers everything.
    pub fn subset_of(&self, other: &Option<PortSpec>) -> bool {
        let other = match other {
            None => return true,
            Some(o) => o,
        };
        match (self, other) {
            (PortSpec::Single(p), o) => o.contains(*p),
            (PortSpec::Range { range: (lo, hi) }, o) => {
                // Conservative: a range is a subset only if both ends match
                // and the other spec is a range/list covering the interval.
                // For list-typed others we require every port in the range
                // to be listed (only practical for small ranges).
                match o {
                    PortSpec::Range { range: (olo, ohi) } => olo <= lo && hi <= ohi,
                    PortSpec::Single(p) => lo == hi && lo == p,
                    PortSpec::List(ps) => {
                        lo <= hi
                            && hi - lo <= 1024
                            && (*lo..=*hi).all(|p| ps.contains(&p))
                    }
                }
            }
            (PortSpec::List(ps), o) => ps.iter().all(|p| o.contains(*p)),
        }
    }
}

/// Unit for an nftables `limit rate` (engine 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RateUnit {
    Second,
    Minute,
    Hour,
    Day,
}

/// Per-rule rate limit, rendered by the Linux adapter as nftables
/// `limit rate <rate>/<unit>` (plus optional `burst`). Semantics:
/// the rule only matches while under the rate. On an allow rule that
/// is the desired throttle (excess falls through to later rules,
/// ultimately default deny). On a deny rule it rate-limits the drop
/// itself, which is rarely intended — use with care.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    pub rate: u64,
    pub unit: RateUnit,
    #[serde(default)]
    pub burst: Option<u64>,
}

impl RateLimit {
    /// nftables fragment, e.g. `limit rate 25/minute burst 5 packets`.
    pub fn nft_fragment(&self) -> String {
        let unit = match self.unit {
            RateUnit::Second => "second",
            RateUnit::Minute => "minute",
            RateUnit::Hour => "hour",
            RateUnit::Day => "day",
        };
        match self.burst {
            Some(b) => format!("limit rate {}/{} burst {} packets", self.rate, unit, b),
            None => format!("limit rate {}/{}", self.rate, unit),
        }
    }
}

/// One firewall rule.
///
/// `deny_unknown_fields` is deliberate fail-closed behavior (pentest
/// Nov 3, 2026): without it, a typo such as `dst_ports` instead of
/// `dst_port` was silently dropped by serde, broadening the rule to
/// all ports while the author believed it was port-restricted. Any
/// unrecognized field is now a load error.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub priority: u32,
    pub action: Action,
    #[serde(default)]
    pub protocol: Protocol,
    /// Source CIDRs (after zone expansion; empty = any).
    #[serde(default)]
    pub src_addrs: Vec<Cidr>,
    /// Destination CIDRs (after zone expansion; empty = any).
    #[serde(default)]
    pub dst_addrs: Vec<Cidr>,
    /// Zone name resolved at load time into `src_addrs`.
    #[serde(default)]
    pub src_zone: Option<String>,
    /// Zone name resolved at load time into `dst_addrs`.
    #[serde(default)]
    pub dst_zone: Option<String>,
    #[serde(default)]
    pub src_port: Option<PortSpec>,
    #[serde(default)]
    pub dst_port: Option<PortSpec>,
    #[serde(default)]
    pub in_interface: Option<String>,
    #[serde(default)]
    pub out_interface: Option<String>,
    /// Application identity (Windows only, enforced by WFP ALE): the
    /// executable path, e.g. `C:\Program Files\App\app.exe`.
    /// The packet matcher carries no app identity, so an app-scoped rule
    /// never matches a bare packet (fail closed); it is enforced by the
    /// platform adapter. The Linux adapter refuses app-scoped rules
    /// outright (nftables has no reliable app attribution, and silently
    /// broadening the rule to all apps would be a security hole).
    #[serde(default)]
    pub app: Option<String>,
    /// Connection states this rule applies to (empty = any).
    #[serde(default)]
    pub states: Vec<ConnState>,
    /// Optional per-rule rate limit (engine 3; Linux `limit` rendering).
    #[serde(default)]
    pub rate_limit: Option<RateLimit>,
    #[serde(default)]
    pub log: bool,
    /// Which rule engines this rule belongs to (informational in M1).
    #[serde(default)]
    pub engines: Vec<String>,
    #[serde(default)]
    pub description: String,
}

/// A named network zone: a set of subnets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Zone {
    pub name: String,
    pub subnets: Vec<Cidr>,
}

/// A complete, loadable policy document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub name: String,
    #[serde(default = "default_mode")]
    pub mode: String,
    pub default_action: Action,
    #[serde(default)]
    pub zones: Vec<Zone>,
    pub rules: Vec<Rule>,
}

fn default_mode() -> String {
    "standard".to_string()
}

impl Policy {
    /// Parse JSON, expand zones, validate, and sort rules by priority
    /// (stable: document order breaks ties). Returns the normalized policy.
    pub fn from_json(json: &str) -> Result<Policy, String> {
        // Tolerate a UTF-8 BOM: Windows PowerShell 5.1 writes one with
        // Set-Content -Encoding utf8, and serde_json rejects it with
        // "expected value at line 1 column 1". This exact failure bit
        // the M4 verification run on a real Windows host (Nov 3, 2026);
        // the script now also writes BOM-less, but the loader stays
        // tolerant so any BOM'd file from an editor still loads.
        let json = json.strip_prefix('\u{feff}').unwrap_or(json);
        let mut policy: Policy =
            serde_json::from_str(json).map_err(|e| format!("policy JSON: {e}"))?;
        policy.normalize()?;
        Ok(policy)
    }

    /// Strings interpolated into the nftables script (policy name and
    /// mode go in the header comment; rule ids in comments and log
    /// prefixes; interface names in quoted matches) must not contain
    /// a quote, a backslash, or a control character: any of those
    /// breaks out of its quoting context and injects arbitrary nft
    /// script (pentest Nov 3, 2026: a policy name containing a newline
    /// injected a whole `table inet pwn { policy accept; }` table, and
    /// a rule id containing a quote/newline injected an accept rule).
    fn check_script_safe(field: &str, value: &str) -> Result<(), String> {
        if value
            .chars()
            .any(|c| c.is_control() || c == '"' || c == '\\')
        {
            return Err(format!(
                "{field} contains a quote, backslash, or control character, \
                 which would break out of the generated nftables script"
            ));
        }
        Ok(())
    }

    fn normalize(&mut self) -> Result<(), String> {
        Self::check_script_safe("policy name", &self.name)?;
        Self::check_script_safe("policy mode", &self.mode)?;
        // Duplicate zone names are a load error: previously the last
        // definition silently won for rule expansion (HashMap collect)
        // while zone_matrix used the first (Vec::find), so the
        // segmentation matrix and the enforced policy disagreed about
        // which subnets a zone meant.
        {
            let mut seen_zones = std::collections::HashSet::new();
            for zone in &self.zones {
                if !seen_zones.insert(zone.name.as_str()) {
                    return Err(format!("duplicate zone name: {}", zone.name));
                }
            }
        }
        let zones: HashMap<&str, &Zone> = self
            .zones
            .iter()
            .map(|z| (z.name.as_str(), z))
            .collect();
        let mut seen_ids = std::collections::HashSet::new();
        for rule in &mut self.rules {
            if !seen_ids.insert(rule.id.clone()) {
                return Err(format!("duplicate rule id: {}", rule.id));
            }
            Self::check_script_safe("rule id", &rule.id)?;
            if let Some(iif) = &rule.in_interface {
                Self::check_script_safe("in_interface", iif)?;
            }
            if let Some(oif) = &rule.out_interface {
                Self::check_script_safe("out_interface", oif)?;
            }
            if rule.protocol.is_icmp() && (rule.src_port.is_some() || rule.dst_port.is_some()) {
                return Err(format!(
                    "rule {}: ports are meaningless for ICMP",
                    rule.id
                ));
            }
            for spec in [&rule.src_port, &rule.dst_port].into_iter().flatten() {
                if let PortSpec::Range { range: (lo, hi) } = spec {
                    if lo > hi {
                        return Err(format!("rule {}: inverted port range", rule.id));
                    }
                }
            }
            if let Some(zone_name) = &rule.src_zone {
                let zone = zones
                    .get(zone_name.as_str())
                    .ok_or_else(|| format!("rule {}: unknown src_zone {zone_name}", rule.id))?;
                if zone.subnets.is_empty() {
                    // An empty zone expands to nothing, leaving the
                    // address list empty — which means "any". A rule
                    // meant to be restricted to that zone would
                    // silently allow traffic from everywhere.
                    return Err(format!(
                        "rule {}: src_zone {zone_name} has no subnets",
                        rule.id
                    ));
                }
                // Idempotent expansion: skip subnets already present, so
                // re-parsing an already-normalized policy does not duplicate
                // its zone addresses.
                for subnet in zone.subnets.iter() {
                    if !rule.src_addrs.contains(subnet) {
                        rule.src_addrs.push(subnet.clone());
                    }
                }
            }
            if let Some(zone_name) = &rule.dst_zone {
                let zone = zones
                    .get(zone_name.as_str())
                    .ok_or_else(|| format!("rule {}: unknown dst_zone {zone_name}", rule.id))?;
                if zone.subnets.is_empty() {
                    return Err(format!(
                        "rule {}: dst_zone {zone_name} has no subnets",
                        rule.id
                    ));
                }
                for subnet in zone.subnets.iter() {
                    if !rule.dst_addrs.contains(subnet) {
                        rule.dst_addrs.push(subnet.clone());
                    }
                }
            }
        }
        // Stable sort: ascending priority, document order breaks ties.
        self.rules.sort_by_key(|r| r.priority);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_contains() {
        let c = Cidr::parse("192.168.0.0/16").unwrap();
        assert!(c.contains("192.168.5.5".parse().unwrap()));
        assert!(!c.contains("10.0.0.1".parse().unwrap()));
        assert!(!c.contains("2001:db8::1".parse().unwrap()));
        let host = Cidr::parse("10.0.0.5").unwrap();
        assert_eq!(host.prefix, 32);
        assert!(host.contains("10.0.0.5".parse().unwrap()));
        assert!(!host.contains("10.0.0.6".parse().unwrap()));
    }

    #[test]
    fn cidr_network_containment() {
        let big = Cidr::parse("10.0.0.0/8").unwrap();
        let small = Cidr::parse("10.1.2.0/24").unwrap();
        assert!(big.contains_network(&small));
        assert!(!small.contains_network(&big));
        let other = Cidr::parse("11.0.0.0/8").unwrap();
        assert!(!big.contains_network(&other));
    }

    #[test]
    fn cidr_ipv6() {
        let c = Cidr::parse("2001:db8::/32").unwrap();
        assert!(c.contains("2001:db8:1::1".parse().unwrap()));
        assert!(!c.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn port_spec_forms() {
        let single = PortSpec::Single(53);
        assert!(single.contains(53) && !single.contains(54));
        let range = PortSpec::Range { range: (8000, 8100) };
        assert!(range.contains(8000) && range.contains(8100) && !range.contains(8101));
        let list = PortSpec::List(vec![53, 443]);
        assert!(list.contains(443) && !list.contains(80));
    }

    #[test]
    fn policy_zone_expansion_and_sorting() {
        let json = r#"{
            "version": 1, "name": "t", "default_action": "deny",
            "zones": [{"name": "lan", "subnets": ["192.168.0.0/16"]}],
            "rules": [
                {"id": "b", "priority": 20, "action": "allow", "protocol": "tcp",
                 "dst_zone": "lan", "dst_port": 443},
                {"id": "a", "priority": 10, "action": "deny", "protocol": "tcp",
                 "dst_port": 23}
            ]
        }"#;
        let p = Policy::from_json(json).unwrap();
        assert_eq!(p.rules[0].id, "a");
        assert_eq!(p.rules[1].id, "b");
        assert_eq!(p.rules[1].dst_addrs.len(), 1);
    }

    #[test]
    fn policy_zone_expansion_is_idempotent() {
        let json = r#"{
            "version": 1, "name": "t", "default_action": "deny",
            "zones": [{"name": "lan", "subnets": ["192.168.0.0/16"]}],
            "rules": [
                {"id": "b", "priority": 20, "action": "allow", "protocol": "tcp",
                 "dst_zone": "lan", "dst_port": 443}
            ]
        }"#;
        let p = Policy::from_json(json).unwrap();
        assert_eq!(p.rules[0].dst_addrs.len(), 1);
        let reparsed = Policy::from_json(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(reparsed.rules[0].dst_addrs.len(), 1);
        assert_eq!(
            serde_json::to_string(&reparsed).unwrap(),
            serde_json::to_string(&p).unwrap()
        );
    }

    #[test]
    fn policy_rejects_unknown_zone_and_icmp_ports() {
        let bad_zone = r#"{"version":1,"name":"t","default_action":"deny",
            "rules":[{"id":"x","priority":1,"action":"allow","src_zone":"nope"}]}"#;
        assert!(Policy::from_json(bad_zone).is_err());
        let icmp_ports = r#"{"version":1,"name":"t","default_action":"deny",
            "rules":[{"id":"x","priority":1,"action":"allow","protocol":"icmp","dst_port":8}]}"#;
        assert!(Policy::from_json(icmp_ports).is_err());
    }

    #[test]
    fn policy_accepts_utf8_bom_prefix() {
        // Regression test for the Nov 3, 2026 M4 run: PowerShell 5.1
        // writes a UTF-8 BOM, which serde_json rejects outright.
        let json = "\u{feff}{\"version\":1,\"name\":\"t\",\"default_action\":\"allow\",\"rules\":[]}";
        let p = Policy::from_json(json).unwrap();
        assert_eq!(p.name, "t");
    }

    #[test]
    fn policy_rejects_duplicate_ids() {
        let dup = r#"{"version":1,"name":"t","default_action":"deny",
            "rules":[
              {"id":"x","priority":1,"action":"allow"},
              {"id":"x","priority":2,"action":"deny"}]}"#;
        assert!(Policy::from_json(dup).is_err());
    }

    #[test]
    fn pentest_rejects_duplicate_zone_names() {
        let dup = r#"{"version":1,"name":"t","default_action":"deny",
            "zones":[{"name":"lan","subnets":["192.168.0.0/16"]},
                     {"name":"lan","subnets":["10.0.0.0/8"]}],
            "rules":[{"id":"r","priority":1,"action":"allow","src_zone":"lan"}]}"#;
        assert!(Policy::from_json(dup).is_err());
    }

    #[test]
    fn pentest_rejects_empty_referenced_zone_but_not_unused_empty_zone() {
        // Referenced empty zone previously expanded to "any" (fail open).
        let bad = r#"{"version":1,"name":"t","default_action":"deny",
            "zones":[{"name":"void","subnets":[]}],
            "rules":[{"id":"r","priority":1,"action":"allow","src_zone":"void"}]}"#;
        assert!(Policy::from_json(bad).is_err());
        // An empty zone nobody references still loads (the matrix
        // validator reports it separately when asked to use it).
        let unused = r#"{"version":1,"name":"t","default_action":"deny",
            "zones":[{"name":"void","subnets":[]}],"rules":[]}"#;
        assert!(Policy::from_json(unused).is_ok());
    }

    #[test]
    fn pentest_rejects_unknown_fields_instead_of_silently_dropping_them() {
        // Typo'd restriction fields must not broaden the rule.
        let typo_port = r#"{"version":1,"name":"t","default_action":"deny",
            "rules":[{"id":"r","priority":1,"action":"allow","protocol":"tcp","dst_ports":443}]}"#;
        assert!(Policy::from_json(typo_port).is_err());
        let typo_addr = r#"{"version":1,"name":"t","default_action":"deny",
            "rules":[{"id":"r","priority":1,"action":"allow","src_addr":"10.0.0.0/8"}]}"#;
        assert!(Policy::from_json(typo_addr).is_err());
        let bogus_top = r#"{"version":1,"name":"t","default_action":"deny",
            "comment":"hi","rules":[]}"#;
        assert!(Policy::from_json(bogus_top).is_err());
    }

    #[test]
    fn pentest_rejects_script_breaking_strings() {
        let bad_name = "{\"version\":1,\"name\":\"evil\\ntable inet pwn {}\",\"default_action\":\"deny\",\"rules\":[]}";
        assert!(Policy::from_json(bad_name).is_err());
        let bad_id = r#"{"version":1,"name":"t","default_action":"deny",
            "rules":[{"id":"bad\" counter accept","priority":1,"action":"deny"}]}"#;
        assert!(Policy::from_json(bad_id).is_err());
        let bad_iface = r#"{"version":1,"name":"t","default_action":"deny",
            "rules":[{"id":"r","priority":1,"action":"allow","in_interface":"eth0\""}]}"#;
        assert!(Policy::from_json(bad_iface).is_err());
        // Ordinary names, ids, and interfaces still load.
        let good = r#"{"version":1,"name":"prod policy","default_action":"deny",
            "rules":[{"id":"allow-web (v2)","priority":1,"action":"allow","in_interface":"eth0"}]}"#;
        assert!(Policy::from_json(good).is_ok());
    }
}
