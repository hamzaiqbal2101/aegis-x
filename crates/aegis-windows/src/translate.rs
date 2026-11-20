//! Policy-to-WFP filter translation model (pure data, unit-tested).
//!
//! This module translates a validated `Policy` into the *data* WFP needs
//! (layers, weights, conditions, actions). Installing those filters into
//! the live engine is `engine.rs`. Nothing in this module touches the OS.
//!
//! Translation rules:
//! * WFP resolves filters by weight: higher weight wins. AEGIS priority
//!   is inverted: lower priority number = evaluated first = higher weight.
//!   weight = WEIGHT_BASE - priority * WEIGHT_STEP (saturating), minus the
//!   rule's index in the policy so two rules with the same priority get
//!   distinct weights in document order (WFP does not guarantee an
//!   order for equal weights, so a same-priority allow/deny pair could
//!   otherwise diverge from the model). Priority must be < 100_000:
//!   at 100_000 the weight saturates to 0 and collides with the
//!   default-deny filter (enforced by `gate_policy`).
//! * Direction mirrors the Linux adapter: a rule renders to the connect
//!   layers (outbound) unless it specifies `in_interface` only, and to
//!   the recv-accept layers (inbound) unless it specifies `out_interface`
//!   only.
//! * Family: v4 addresses -> V4 layers, v6 -> V6 layers, no addresses ->
//!   both.
//! * A final block-all filter at weight 0 implements default deny.
//!   Note: WFP has NO sublayer-level default — when no filter matches,
//!   WFP permits. Default deny comes ONLY from this weight-0 filter,
//!   so it is the mechanism, not a belt-and-braces extra. (An earlier
//!   comment claimed the sublayer was "configured block-by-default";
//!   no code ever set that, and no such WFP setting exists.
//!   Review Nov 14, 2026.)
//! * Loopback is OS-handled by WFP (loopback traffic is not ALE-filtered
//!   by default) and is therefore not emitted here.

use aegis_core::policy::{Action, Cidr, ConnState, PortSpec, Protocol, Rule};
use aegis_core::Policy;
use sha2::{Digest, Sha256};
use std::net::IpAddr;

pub const WEIGHT_BASE: u64 = 1_000_000_000;
pub const WEIGHT_STEP: u64 = 10_000;
/// Priority must be below this: at 100_000 the weight saturates to 0
/// and collides with the default-deny filter (WEIGHT_BASE / WEIGHT_STEP).
pub const MAX_PRIORITY: u32 = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpLayer {
    /// Outbound connection authorization, IPv4.
    AleAuthConnectV4,
    /// Outbound connection authorization, IPv6.
    AleAuthConnectV6,
    /// Inbound connection authorization, IPv4.
    AleAuthRecvAcceptV4,
    /// Inbound connection authorization, IPv6.
    AleAuthRecvAcceptV6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpAction {
    Permit,
    Block,
}

/// One filter to be installed in the WFP engine (M4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFilter {
    pub id: String,
    pub layer: WfpLayer,
    /// Higher wins.
    pub weight: u64,
    pub protocol: Protocol,
    pub src_addrs: Vec<Cidr>,
    pub dst_addrs: Vec<Cidr>,
    pub src_port: Option<aegis_core::PortSpec>,
    pub dst_port: Option<aegis_core::PortSpec>,
    pub action: WfpAction,
    pub log: bool,
    /// Carried through for the engine's fail-closed checks: app scope
    /// (resolved to an ALE app id), interface scope (unsupported in M4),
    /// and connection states (ALE establishment-time semantics).
    pub app: Option<String>,
    pub in_interface: Option<String>,
    pub out_interface: Option<String>,
    pub states: Vec<aegis_core::ConnState>,
}

fn weight_for(priority: u32) -> u64 {
    WEIGHT_BASE.saturating_sub(priority as u64 * WEIGHT_STEP)
}

/// Windows install gate (pure, so it is unit-testable here and
/// callable from the engine). Refuses policies Windows cannot
/// enforce faithfully instead of installing a weakened version:
/// * interface-scoped rules (Windows interface naming differs from
///   Linux names; mapping is M4 follow-up),
/// * rules matching only `invalid` state (they can never fire),
/// * rate-limited rules (WFP has no per-rule rate limit; installing
///   one as an unthrottled rule would silently drop the throttle),
/// * priority >= MAX_PRIORITY (weight saturates to 0, colliding
///   with the default-deny filter).
/// (Review Nov 14, 2026: the rate-limit and priority checks are new;
/// the interface and invalid-state checks moved here from
/// `engine.rs` so they are testable on Linux.)
pub fn gate_policy(policy: &Policy) -> Result<(), String> {
    for rule in &policy.rules {
        if rule.in_interface.is_some() || rule.out_interface.is_some() {
            return Err(format!(
                "rule {} uses interface scoping, unsupported on Windows in M4",
                rule.id
            ));
        }
        if rule.states.len() == 1 && rule.states[0] == ConnState::Invalid {
            return Err(format!(
                "rule {} matches only invalid state and can never fire",
                rule.id
            ));
        }
        if rule.rate_limit.is_some() {
            return Err(format!(
                "rule {} has a rate limit, which Windows WFP cannot enforce \
                 (installing it unthrottled would silently drop the throttle)",
                rule.id
            ));
        }
        if rule.priority >= MAX_PRIORITY {
            return Err(format!(
                "rule {} priority {} is too large for Windows (must be < {}: \
                 higher priorities saturate to weight 0 and collide with default deny)",
                rule.id, rule.priority, MAX_PRIORITY
            ));
        }
    }
    Ok(())
}

/// Deterministic filter key material for one concrete filter:
/// SHA-256("aegis-x-filter-v1" || rule id || layer || expansion
/// index), first 16 bytes. The expansion index is load-bearing:
/// one rule expands into several concrete filters (one per
/// address/port combination), and WFP requires a unique key per
/// filter — the old key (rule id + layer only) collided for any
/// rule with a port list or multiple addresses, so the second
/// FwpmFilterAdd0 failed FWP_E_ALREADY_EXISTS and the whole
/// install aborted. (Review Nov 14, 2026.)
pub fn filter_key_bytes(rule_id: &str, layer: WfpLayer, expansion_index: usize) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"aegis-x-filter-v1");
    h.update(rule_id.as_bytes());
    h.update([layer as u8]);
    h.update((expansion_index as u64).to_be_bytes());
    let digest = h.finalize();
    digest[0..16].try_into().expect("sha256 is 32 bytes")
}

pub fn is_connect(layer: WfpLayer) -> bool {
    matches!(
        layer,
        WfpLayer::AleAuthConnectV4 | WfpLayer::AleAuthConnectV6
    )
}

pub fn is_v6(layer: WfpLayer) -> bool {
    matches!(
        layer,
        WfpLayer::AleAuthConnectV6 | WfpLayer::AleAuthRecvAcceptV6
    )
}

/// One port match choice for a single WFP filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortChoice {
    Any,
    Single(u16),
    Range(u16, u16),
}

/// One concrete combination of match values for a single WFP filter.
#[derive(Debug, Clone)]
pub struct Expanded {
    pub local_addr: Option<Cidr>,
    pub remote_addr: Option<Cidr>,
    pub local_port: PortChoice,
    pub remote_port: PortChoice,
}

fn port_options(spec: &Option<PortSpec>) -> Vec<PortChoice> {
    match spec {
        None => vec![PortChoice::Any],
        Some(PortSpec::Single(p)) => vec![PortChoice::Single(*p)],
        Some(PortSpec::List(ps)) => {
            ps.iter().map(|p| PortChoice::Single(*p)).collect()
        }
        Some(PortSpec::Range { range: (low, high) }) => {
            vec![PortChoice::Range(*low, *high)]
        }
    }
}

/// Expand one translated filter into concrete filters. Returns an
/// empty vec when the filter's family has no addresses on this layer
/// (the filter must be skipped, never broadened to "any").
/// (Moved here from `engine.rs` in the Nov 14, 2026 review so the
/// expansion — and the filter-key uniqueness that depends on it —
/// is unit-testable on Linux.)
pub fn expand(filter: &WfpFilter) -> Vec<Expanded> {
    let v6 = is_v6(filter.layer);
    let fam = |c: &Cidr| match (v6, c.network) {
        (true, IpAddr::V6(_)) => true,
        (false, IpAddr::V4(_)) => true,
        _ => false,
    };
    if !filter.src_addrs.is_empty() && !filter.src_addrs.iter().any(fam) {
        return vec![];
    }
    if !filter.dst_addrs.is_empty() && !filter.dst_addrs.iter().any(fam) {
        return vec![];
    }
    let srcs: Vec<Option<Cidr>> = {
        let kept: Vec<Cidr> = filter
            .src_addrs
            .iter()
            .filter(|c| fam(c))
            .cloned()
            .collect();
        if kept.is_empty() {
            vec![None]
        } else {
            kept.into_iter().map(Some).collect()
        }
    };
    let dsts: Vec<Option<Cidr>> = {
        let kept: Vec<Cidr> = filter
            .dst_addrs
            .iter()
            .filter(|c| fam(c))
            .cloned()
            .collect();
        if kept.is_empty() {
            vec![None]
        } else {
            kept.into_iter().map(Some).collect()
        }
    };
    let sport_opts = port_options(&filter.src_port);
    let dport_opts = port_options(&filter.dst_port);
    let connect = is_connect(filter.layer);
    let mut out = Vec::new();
    for s in &srcs {
        for d in &dsts {
            for sp in &sport_opts {
                for dp in &dport_opts {
                    // Local/remote mapping depends on direction.
                    let (local_addr, remote_addr) = if connect {
                        (s.clone(), d.clone())
                    } else {
                        (d.clone(), s.clone())
                    };
                    let (local_port, remote_port) = if connect {
                        (*sp, *dp)
                    } else {
                        (*dp, *sp)
                    };
                    out.push(Expanded {
                        local_addr,
                        remote_addr,
                        local_port,
                        remote_port,
                    });
                }
            }
        }
    }
    out
}

fn action_for(action: Action) -> WfpAction {
    match action {
        Action::Allow | Action::Log => WfpAction::Permit,
        Action::Deny | Action::Reject | Action::Alert => WfpAction::Block,
    }
}

fn layers_for(rule: &Rule) -> Vec<WfpLayer> {
    let outbound = !(rule.in_interface.is_some() && rule.out_interface.is_none());
    let inbound = !(rule.out_interface.is_some() && rule.in_interface.is_none());
    let has_v4 = rule
        .src_addrs
        .iter()
        .chain(rule.dst_addrs.iter())
        .any(|c| matches!(c.network, IpAddr::V4(_)));
    let has_v6 = rule
        .src_addrs
        .iter()
        .chain(rule.dst_addrs.iter())
        .any(|c| matches!(c.network, IpAddr::V6(_)));
    // V4 layers unless the rule is v6-only; V6 layers unless v4-only.
    // (An earlier version of this condition emitted NO layers for rules
    // with both families — a silent drop of the rule. Fixed + tested.)
    let want_v4 = !has_v6 || has_v4;
    let want_v6 = !has_v4 || has_v6;
    let mut layers = Vec::new();
    if outbound {
        if want_v4 {
            layers.push(WfpLayer::AleAuthConnectV4);
        }
        if want_v6 {
            layers.push(WfpLayer::AleAuthConnectV6);
        }
    }
    if inbound {
        if want_v4 {
            layers.push(WfpLayer::AleAuthRecvAcceptV4);
        }
        if want_v6 {
            layers.push(WfpLayer::AleAuthRecvAcceptV6);
        }
    }
    // ICMPv6 rules must not land on V4 layers and vice versa.
    layers.retain(|l| match rule.protocol {
        Protocol::Icmp => !matches!(
            l,
            WfpLayer::AleAuthConnectV6 | WfpLayer::AleAuthRecvAcceptV6
        ),
        Protocol::Icmpv6 => !matches!(
            l,
            WfpLayer::AleAuthConnectV4 | WfpLayer::AleAuthRecvAcceptV4
        ),
        _ => true,
    });
    layers
}

/// Translate a validated policy into WFP filters, ordered by weight
/// (highest first, i.e. evaluation order).
pub fn translate(policy: &Policy) -> Vec<WfpFilter> {
    let mut filters = Vec::new();
    for (idx, rule) in policy.rules.iter().enumerate() {
        // Tie-break by document order: two rules with the same
        // priority get distinct weights (earlier rule wins), because
        // WFP does not guarantee an order for equal weights. The
        // index is small relative to WEIGHT_STEP (10_000), so this
        // cannot push a weight into the next priority's band for any
        // realistic policy size; gate_policy caps priority so the
        // result stays above 0. (Review Nov 14, 2026.)
        let weight = weight_for(rule.priority).saturating_sub(idx as u64);
        for layer in layers_for(rule) {
            filters.push(WfpFilter {
                id: rule.id.clone(),
                layer,
                weight,
                protocol: rule.protocol,
                src_addrs: rule.src_addrs.clone(),
                dst_addrs: rule.dst_addrs.clone(),
                src_port: rule.src_port.clone(),
                dst_port: rule.dst_port.clone(),
                action: action_for(rule.action),
                log: rule.log || matches!(rule.action, Action::Log | Action::Alert),
                app: rule.app.clone(),
                in_interface: rule.in_interface.clone(),
                out_interface: rule.out_interface.clone(),
                states: rule.states.clone(),
            });
        }
    }
    // Default deny, lowest weight, on every layer.
    for layer in [
        WfpLayer::AleAuthConnectV4,
        WfpLayer::AleAuthConnectV6,
        WfpLayer::AleAuthRecvAcceptV4,
        WfpLayer::AleAuthRecvAcceptV6,
    ] {
        filters.push(WfpFilter {
            id: "aegis-default-deny".to_string(),
            layer,
            weight: 0,
            protocol: Protocol::Any,
            src_addrs: vec![],
            dst_addrs: vec![],
            src_port: None,
            dst_port: None,
            action: match policy.default_action {
                Action::Allow | Action::Log => WfpAction::Permit,
                _ => WfpAction::Block,
            },
            log: true,
            app: None,
            in_interface: None,
            out_interface: None,
            states: vec![],
        });
    }
    filters.sort_by_key(|f| std::cmp::Reverse(f.weight));
    filters
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::Policy;

    #[test]
    fn weight_inverts_priority() {
        assert!(weight_for(5) > weight_for(20));
        assert_eq!(weight_for(0), WEIGHT_BASE);
    }

    #[test]
    fn translation_orders_by_weight_and_ends_with_default_deny() {
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"web","priority":10,"action":"allow","protocol":"tcp","dst_port":443},
              {"id":"ssh","priority":20,"action":"allow","protocol":"tcp","dst_port":22}
            ]}"#,
        )
        .unwrap();
        let filters = translate(&p);
        // Each rule lands on 4 layers (no addresses -> both families, both
        // directions) + 4 default-deny filters.
        assert_eq!(filters.len(), 12);
        assert!(filters.windows(2).all(|w| w[0].weight >= w[1].weight));
        assert!(filters
            .iter()
            .rev()
            .take(4)
            .all(|f| f.id == "aegis-default-deny" && f.weight == 0));
        // The first filter must be the priority-10 rule.
        assert_eq!(filters[0].id, "web");
    }

    #[test]
    fn both_families_rule_lands_on_all_four_layers() {
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"both","priority":10,"action":"allow","protocol":"tcp",
               "src_addrs":["10.0.0.0/8","2001:db8::/32"],"dst_port":22}
            ]}"#,
        )
        .unwrap();
        let filters = translate(&p);
        let rule_filters: Vec<&WfpFilter> =
            filters.iter().filter(|f| f.id == "both").collect();
        // connect V4 + connect V6 + recv-accept V4 + recv-accept V6.
        assert_eq!(rule_filters.len(), 4);
        assert!(rule_filters.iter().any(|f| f.layer == WfpLayer::AleAuthConnectV4));
        assert!(rule_filters.iter().any(|f| f.layer == WfpLayer::AleAuthConnectV6));
        assert!(rule_filters.iter().any(|f| f.layer == WfpLayer::AleAuthRecvAcceptV4));
        assert!(rule_filters.iter().any(|f| f.layer == WfpLayer::AleAuthRecvAcceptV6));
    }

    #[test]
    fn v4_only_rule_skips_v6_layers() {
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"v4only","priority":10,"action":"allow","protocol":"tcp",
               "src_addrs":["10.0.0.0/8"],"dst_port":22}
            ]}"#,
        )
        .unwrap();
        let filters = translate(&p);
        let rule_filters: Vec<&WfpFilter> =
            filters.iter().filter(|f| f.id == "v4only").collect();
        assert_eq!(rule_filters.len(), 2); // connect V4 + recv-accept V4
        assert!(rule_filters
            .iter()
            .all(|f| matches!(
                f.layer,
                WfpLayer::AleAuthConnectV4 | WfpLayer::AleAuthRecvAcceptV4
            )));
    }

    // --- Review Nov 14, 2026: filter keys, weights, gate ---

    #[test]
    fn review_filter_keys_are_unique_per_expansion() {
        // A rule with a port list expands to several concrete
        // filters on the same layer; each must get a distinct key,
        // or the second FwpmFilterAdd0 fails FWP_E_ALREADY_EXISTS
        // and the whole install aborts. (This is the HIGH finding:
        // the old key was rule id + layer only.)
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"dns","priority":10,"action":"allow","protocol":"udp",
               "dst_port":[53,443]}
            ]}"#,
        )
        .unwrap();
        let filters = translate(&p);
        let f = filters
            .iter()
            .find(|f| f.id == "dns" && f.layer == WfpLayer::AleAuthConnectV4)
            .unwrap();
        let expanded = expand(f);
        assert_eq!(expanded.len(), 2);
        let k0 = filter_key_bytes(&f.id, f.layer, 0);
        let k1 = filter_key_bytes(&f.id, f.layer, 1);
        assert_ne!(k0, k1);
        // Same inputs give the same key (reinstall addresses the
        // same filters).
        assert_eq!(k0, filter_key_bytes(&f.id, f.layer, 0));
        // Different layers also differ.
        assert_ne!(
            k0,
            filter_key_bytes(&f.id, WfpLayer::AleAuthRecvAcceptV4, 0)
        );
    }

    #[test]
    fn review_expansion_cartesian_and_mixed_family_skip() {
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"multi","priority":10,"action":"allow","protocol":"tcp",
               "src_addrs":["10.0.0.0/8","192.168.0.0/16"],"dst_port":[80,443]}
            ]}"#,
        )
        .unwrap();
        let filters = translate(&p);
        let f = filters
            .iter()
            .find(|f| f.id == "multi" && f.layer == WfpLayer::AleAuthConnectV4)
            .unwrap();
        // 2 src addrs x 2 dst ports = 4 concrete filters.
        assert_eq!(expand(f).len(), 4);
        // Mixed-family: a rule with both v4 and v6 addresses lands
        // on all four layers; on the V6 layer only the v6 address
        // survives (the v4 address is skipped, never broadened to
        // "any").
        let p2 = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"both","priority":10,"action":"allow","protocol":"tcp",
               "src_addrs":["10.0.0.0/8","2001:db8::/32"],"dst_port":[80,443]}
            ]}"#,
        )
        .unwrap();
        let filters2 = translate(&p2);
        let v6 = filters2
            .iter()
            .find(|f| f.id == "both" && f.layer == WfpLayer::AleAuthConnectV6)
            .unwrap();
        let expanded = expand(v6);
        assert_eq!(expanded.len(), 2); // 1 v6 addr x 2 ports
        assert!(expanded.iter().all(|e| matches!(
            e.local_addr,
            Some(ref c) if matches!(c.network, IpAddr::V6(_))
        )));
    }

    #[test]
    fn review_same_priority_rules_get_distinct_weights_in_order() {
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"deny-web","priority":10,"action":"deny","protocol":"tcp","dst_port":443},
              {"id":"allow-web","priority":10,"action":"allow","protocol":"tcp","dst_port":443}
            ]}"#,
        )
        .unwrap();
        let filters = translate(&p);
        let deny = filters
            .iter()
            .find(|f| f.id == "deny-web" && f.layer == WfpLayer::AleAuthConnectV4)
            .unwrap();
        let allow = filters
            .iter()
            .find(|f| f.id == "allow-web" && f.layer == WfpLayer::AleAuthConnectV4)
            .unwrap();
        // Document order wins: the earlier (deny) rule has the
        // higher weight, so the model and WFP agree.
        assert!(deny.weight > allow.weight);
    }

    #[test]
    fn review_gate_refuses_rate_limited_and_huge_priority() {
        let limited = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"r","priority":10,"action":"allow","protocol":"tcp","dst_port":443,
               "rate_limit":{"rate":10,"unit":"second"}}
            ]}"#,
        )
        .unwrap();
        assert!(gate_policy(&limited).is_err());
        let huge = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"r","priority":100000,"action":"allow","protocol":"tcp","dst_port":443}
            ]}"#,
        )
        .unwrap();
        assert!(gate_policy(&huge).is_err());
        let ok = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"r","priority":99999,"action":"allow","protocol":"tcp","dst_port":443}
            ]}"#,
        )
        .unwrap();
        assert!(gate_policy(&ok).is_ok());
        // And the largest accepted priority still gets a weight
        // above the default-deny weight 0.
        let filters = translate(&ok);
        assert!(filters
            .iter()
            .filter(|f| f.id == "r")
            .all(|f| f.weight > 0));
    }

    #[test]
    fn review_gate_still_refuses_interface_and_invalid_only() {
        let iface = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"r","priority":10,"action":"allow","protocol":"tcp","dst_port":443,
               "in_interface":"eth0"}
            ]}"#,
        )
        .unwrap();
        assert!(gate_policy(&iface).is_err());
        // Invalid-only rules are rejected by core normalize at load,
        // so build one in-memory (bypassing from_json) to prove the
        // gate still catches it as defense in depth.
        let mut p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"r","priority":10,"action":"allow","protocol":"tcp","dst_port":443}
            ]}"#,
        )
        .unwrap();
        p.rules[0].states = vec![ConnState::Invalid];
        assert!(gate_policy(&p).is_err());
    }
}
