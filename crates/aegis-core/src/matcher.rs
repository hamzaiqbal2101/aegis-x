//! First-match-wins packet evaluation against a normalized policy.
//!
//! The base policy runs before user rules: `invalid` connection-state
//! packets are always denied, regardless of what user rules say.

use crate::policy::{Action, ConnState, Policy, Protocol, Rule};
use std::net::IpAddr;

/// A packet (or connection attempt) to evaluate. `src_port`/`dst_port` are
/// `None` for protocols without ports (ICMP).
#[derive(Debug, Clone)]
pub struct EvalPacket {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub state: ConnState,
    pub in_interface: Option<String>,
    pub out_interface: Option<String>,
}

/// The outcome of evaluating one packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub action: Action,
    /// The rule that decided, if any (`None` = default action or base policy).
    pub rule_id: Option<String>,
    pub reason: String,
}

pub fn rule_matches(rule: &Rule, pkt: &EvalPacket) -> bool {
    // Fail closed: a packet carries no application identity, so it can
    // never satisfy an app-scoped rule. App rules are enforced by the
    // platform adapter (WFP ALE on Windows), never by this matcher.
    if rule.app.is_some() {
        return false;
    }
    if rule.protocol != Protocol::Any && rule.protocol != pkt.protocol {
        return false;
    }
    if !rule.src_addrs.is_empty()
        && !rule.src_addrs.iter().any(|c| c.contains(pkt.src_ip))
    {
        return false;
    }
    if !rule.dst_addrs.is_empty()
        && !rule.dst_addrs.iter().any(|c| c.contains(pkt.dst_ip))
    {
        return false;
    }
    if let Some(spec) = &rule.src_port {
        match pkt.src_port {
            Some(p) if spec.contains(p) => {}
            _ => return false,
        }
    }
    if let Some(spec) = &rule.dst_port {
        match pkt.dst_port {
            Some(p) if spec.contains(p) => {}
            _ => return false,
        }
    }
    if let Some(iif) = &rule.in_interface {
        if pkt.in_interface.as_deref() != Some(iif.as_str()) {
            return false;
        }
    }
    if let Some(oif) = &rule.out_interface {
        if pkt.out_interface.as_deref() != Some(oif.as_str()) {
            return false;
        }
    }
    if !rule.states.is_empty() && !rule.states.contains(&pkt.state) {
        return false;
    }
    true
}

/// Evaluate a packet. Rules must already be normalized (see
/// `Policy::from_json`); this function does not re-sort.
pub fn evaluate(policy: &Policy, pkt: &EvalPacket) -> Verdict {
    // Base policy: invalid packets never pass, whatever the user rules say.
    if pkt.state == ConnState::Invalid {
        return Verdict {
            action: Action::Deny,
            rule_id: None,
            reason: "base policy: invalid connection state".to_string(),
        };
    }
    for rule in &policy.rules {
        if rule_matches(rule, pkt) {
            return Verdict {
                action: rule.action,
                rule_id: Some(rule.id.clone()),
                reason: format!("matched rule {} (priority {})", rule.id, rule.priority),
            };
        }
    }
    Verdict {
        action: policy.default_action,
        rule_id: None,
        reason: "no rule matched; default action".to_string(),
    }
}

// Re-export the packet type under the name used in policy docs.
pub use EvalPacket as Packet;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    fn pkt(dst_port: u16) -> EvalPacket {
        EvalPacket {
            src_ip: "203.0.113.7".parse().unwrap(),
            dst_ip: "10.0.0.5".parse().unwrap(),
            src_port: Some(40000),
            dst_port: Some(dst_port),
            protocol: Protocol::Tcp,
            state: ConnState::New,
            in_interface: None,
            out_interface: None,
        }
    }

    fn policy() -> Policy {
        Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"allow-web","priority":10,"action":"allow","protocol":"tcp","dst_port":443},
              {"id":"allow-ssh-lan","priority":20,"action":"allow","protocol":"tcp",
               "src_addrs":["192.168.0.0/16"],"dst_port":22}
            ]}"#,
        )
        .unwrap()
    }

    #[test]
    fn allow_match_and_default_deny() {
        let p = policy();
        let v = evaluate(&p, &pkt(443));
        assert_eq!(v.action, Action::Allow);
        assert_eq!(v.rule_id.as_deref(), Some("allow-web"));
        let v = evaluate(&p, &pkt(8080));
        assert_eq!(v.action, Action::Deny);
        assert_eq!(v.rule_id, None);
    }

    #[test]
    fn first_match_wins_by_priority_not_document_order() {
        // A deny rule with a *lower* priority number wins even if it is
        // written after the allow rule in the document.
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"allow-all-tcp","priority":20,"action":"allow","protocol":"tcp"},
              {"id":"deny-443","priority":5,"action":"deny","protocol":"tcp","dst_port":443}
            ]}"#,
        )
        .unwrap();
        let v = evaluate(&p, &pkt(443));
        assert_eq!(v.action, Action::Deny);
        assert_eq!(v.rule_id.as_deref(), Some("deny-443"));
    }

    #[test]
    fn invalid_state_always_denied() {
        let p = policy();
        let mut bad = pkt(443);
        bad.state = ConnState::Invalid;
        let v = evaluate(&p, &bad);
        assert_eq!(v.action, Action::Deny);
        assert_eq!(v.rule_id, None);
    }

    #[test]
    fn source_address_restriction() {
        let p = policy();
        // 203.0.113.7 is not in lan, so SSH must be denied.
        let v = evaluate(&p, &pkt(22));
        assert_eq!(v.action, Action::Deny);
        let mut lan_pkt = pkt(22);
        lan_pkt.src_ip = "192.168.1.9".parse().unwrap();
        let v = evaluate(&p, &lan_pkt);
        assert_eq!(v.action, Action::Allow);
    }

    #[test]
    fn app_scoped_rule_never_matches_bare_packet() {
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"app-rule","priority":10,"action":"allow","protocol":"tcp",
               "dst_port":443,"app":"C:\\Apps\\browser.exe"}
            ]}"#,
        )
        .unwrap();
        let v = evaluate(&p, &pkt(443));
        assert_eq!(v.action, Action::Deny);
        assert_eq!(v.rule_id, None);
    }

    #[test]
    fn ipv6_matching() {
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"v6-web","priority":10,"action":"allow","protocol":"tcp",
               "dst_addrs":["2001:db8::/32"],"dst_port":443}
            ]}"#,
        )
        .unwrap();
        let mut good = pkt(443);
        good.dst_ip = "2001:db8::5".parse().unwrap();
        assert_eq!(evaluate(&p, &good).action, Action::Allow);
        let mut bad = pkt(443);
        bad.dst_ip = "2001:db9::5".parse().unwrap();
        assert_eq!(evaluate(&p, &bad).action, Action::Deny);
    }
}
