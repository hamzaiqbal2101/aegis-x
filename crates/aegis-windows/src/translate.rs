//! Policy-to-WFP filter translation model (pure data, unit-tested).
//!
//! This module translates a validated `Policy` into the *data* WFP needs
//! (layers, weights, conditions, actions). Installing those filters into
//! the live engine is `engine.rs`. Nothing in this module touches the OS.
//!
//! Translation rules:
//! * WFP resolves filters by weight: higher weight wins. AEGIS priority
//!   is inverted: lower priority number = evaluated first = higher weight.
//!   weight = WEIGHT_BASE - priority * WEIGHT_STEP (saturating).
//! * Direction mirrors the Linux adapter: a rule renders to the connect
//!   layers (outbound) unless it specifies `in_interface` only, and to
//!   the recv-accept layers (inbound) unless it specifies `out_interface`
//!   only.
//! * Family: v4 addresses -> V4 layers, v6 -> V6 layers, no addresses ->
//!   both.
//! * A final block-all filter at weight 0 implements default deny (the
//!   WFP sublayer itself is configured block-by-default in M4; this
//!   filter makes the intent explicit and auditable).
//! * Loopback is OS-handled by WFP (loopback traffic is not ALE-filtered
//!   by default) and is therefore not emitted here.

use aegis_core::policy::{Action, Cidr, Protocol, Rule};
use aegis_core::Policy;
use std::net::IpAddr;

pub const WEIGHT_BASE: u64 = 1_000_000_000;
pub const WEIGHT_STEP: u64 = 10_000;

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
    for rule in &policy.rules {
        for layer in layers_for(rule) {
            filters.push(WfpFilter {
                id: rule.id.clone(),
                layer,
                weight: weight_for(rule.priority),
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
}
