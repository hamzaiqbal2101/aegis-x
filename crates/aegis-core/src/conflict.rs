//! Rule conflict detection.
//!
//! A rule is *shadowed* when an earlier (lower-priority) rule already
//! matches every packet it could match, so it can never decide anything.
//! A rule is a *duplicate* when its match space is identical to an earlier
//! rule's. Shadowing is reported regardless of action: a shadowed allow
//! rule behind a deny rule is exactly the misconfiguration this catches.
//!
//! The subset checks are conservative: they only report a conflict when
//! containment is proven from the rule fields. Anything uncertain is not
//! reported (no false positives), which is the safe direction for a
//! firewall: an unreported conflict is a missed hint, a false report
//! would train operators to ignore the check.

use crate::policy::{Cidr, Policy, PortSpec, Protocol, Rule};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictKind {
    Shadowed,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// The rule that can never fire.
    pub shadowed_id: String,
    /// The earlier rule covering it.
    pub shadowing_id: String,
    pub kind: ConflictKind,
}

fn protocol_subset(inner: Protocol, outer: Protocol) -> bool {
    outer == Protocol::Any || inner == outer
}

fn addrs_subset(inner: &[Cidr], outer: &[Cidr]) -> bool {
    if outer.is_empty() {
        return true;
    }
    if inner.is_empty() {
        return false;
    }
    inner
        .iter()
        .all(|c| outer.iter().any(|o| o.contains_network(c)))
}

fn iface_subset(inner: &Option<String>, outer: &Option<String>) -> bool {
    match outer {
        None => true,
        Some(o) => inner.as_deref() == Some(o.as_str()),
    }
}

/// Port subset with `Option` semantics: an unrestricted inner spec only
/// fits inside an unrestricted outer spec; a restricted inner spec must
/// fit inside whatever the outer spec allows.
fn port_subset(inner: &Option<PortSpec>, outer: &Option<PortSpec>) -> bool {
    match inner {
        None => outer.is_none(),
        Some(spec) => spec.subset_of(outer),
    }
}

fn states_subset(
    inner: &[crate::policy::ConnState],
    outer: &[crate::policy::ConnState],
) -> bool {
    if outer.is_empty() {
        return true;
    }
    // An unrestricted inner rule (empty = any state) is NOT a subset
    // of a state-restricted outer rule: `Iterator::all` on the empty
    // list is vacuously true, which previously reported any-state
    // rules as shadowed/duplicated behind new-only rules even though
    // established/related packets still reached them (and, via the
    // CLI duplicate gate, refused to apply such policies at all).
    if inner.is_empty() {
        return false;
    }
    inner.iter().all(|s| outer.contains(s))
}

/// True if every packet matching `inner` also matches `outer`.
pub fn match_space_subset(inner: &Rule, outer: &Rule) -> bool {
    // A rate-limited outer rule never covers every packet: packets
    // over its rate fall through to later rules, so a later rule
    // behind it can still fire. Treating it as covering was a false
    // shadow/duplicate (and, via the CLI duplicate gate, refused
    // legitimate policies whose rules differed only by rate limit).
    if outer.rate_limit.is_some() {
        return false;
    }
    protocol_subset(inner.protocol, outer.protocol)
        && addrs_subset(&inner.src_addrs, &outer.src_addrs)
        && addrs_subset(&inner.dst_addrs, &outer.dst_addrs)
        && port_subset(&inner.src_port, &outer.src_port)
        && port_subset(&inner.dst_port, &outer.dst_port)
        && iface_subset(&inner.in_interface, &outer.in_interface)
        && iface_subset(&inner.out_interface, &outer.out_interface)
        && states_subset(&inner.states, &outer.states)
}

/// Detect conflicts in priority order. `policy.rules` must be normalized
/// (priority-sorted); only earlier rules can shadow later ones.
/// Rules with an `app` scope are skipped: the packet model cannot reason
/// about application identity, so any verdict about them would be a guess.
pub fn detect_conflicts(policy: &Policy) -> Vec<Conflict> {
    let mut out = Vec::new();
    for (j, later) in policy.rules.iter().enumerate() {
        if later.app.is_some() {
            continue;
        }
        for earlier in &policy.rules[..j] {
            if earlier.app.is_some() {
                continue;
            }
            if match_space_subset(later, earlier) {
                let kind = if match_space_subset(earlier, later) {
                    ConflictKind::Duplicate
                } else {
                    ConflictKind::Shadowed
                };
                out.push(Conflict {
                    shadowed_id: later.id.clone(),
                    shadowing_id: earlier.id.clone(),
                    kind,
                });
                break; // one report per shadowed rule: the first cover wins
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[test]
    fn detects_shadowed_rule() {
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"deny-web","priority":10,"action":"deny","protocol":"tcp","dst_port":443},
              {"id":"allow-443-lan","priority":20,"action":"allow","protocol":"tcp",
               "src_addrs":["192.168.0.0/16"],"dst_port":443}
            ]}"#,
        )
        .unwrap();
        let c = detect_conflicts(&p);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].shadowed_id, "allow-443-lan");
        assert_eq!(c[0].shadowing_id, "deny-web");
        assert_eq!(c[0].kind, ConflictKind::Shadowed);
    }

    #[test]
    fn detects_duplicate_rule() {
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"a","priority":10,"action":"allow","protocol":"tcp","dst_port":53},
              {"id":"b","priority":20,"action":"allow","protocol":"tcp","dst_port":53}
            ]}"#,
        )
        .unwrap();
        let c = detect_conflicts(&p);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].kind, ConflictKind::Duplicate);
    }

    #[test]
    fn no_false_positive_on_disjoint_ports() {
        // Disjoint port sets: neither rule covers the other.
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"a","priority":10,"action":"allow","protocol":"tcp","dst_port":80},
              {"id":"b","priority":20,"action":"allow","protocol":"tcp","dst_port":443}
            ]}"#,
        )
        .unwrap();
        assert!(detect_conflicts(&p).is_empty());
    }

    #[test]
    fn cidr_subset_shadowing() {
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"deny-10","priority":10,"action":"deny","src_addrs":["10.0.0.0/8"]},
              {"id":"allow-10-1","priority":20,"action":"allow","src_addrs":["10.1.0.0/16"]}
            ]}"#,
        )
        .unwrap();
        let c = detect_conflicts(&p);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].kind, ConflictKind::Shadowed);
    }

    #[test]
    fn app_rules_skipped_in_conflict_detection() {
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"a","priority":10,"action":"allow","protocol":"tcp","dst_port":443},
              {"id":"b","priority":20,"action":"allow","protocol":"tcp","dst_port":443,
               "app":"C:\\Apps\\browser.exe"}
            ]}"#,
        )
        .unwrap();
        assert!(detect_conflicts(&p).is_empty());
    }

    #[test]
    fn pentest_any_state_rule_is_not_subset_of_state_restricted_rule() {
        // Earlier: deny new-only on 443. Later: allow any-state on 443.
        // Established packets reach the later rule, so it is neither
        // shadowed nor a duplicate.
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"deny-new","priority":10,"action":"deny","protocol":"tcp","dst_port":443,"states":["new"]},
              {"id":"allow-any","priority":20,"action":"allow","protocol":"tcp","dst_port":443}
            ]}"#,
        )
        .unwrap();
        assert!(detect_conflicts(&p).is_empty());
        // And the reverse direction still works: a new-only rule
        // behind an any-state rule with the same match IS shadowed.
        let p2 = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"deny-any","priority":10,"action":"deny","protocol":"tcp","dst_port":443},
              {"id":"allow-new","priority":20,"action":"allow","protocol":"tcp","dst_port":443,"states":["new"]}
            ]}"#,
        )
        .unwrap();
        let c = detect_conflicts(&p2);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].kind, ConflictKind::Shadowed);
    }

    #[test]
    fn pentest_rate_limited_earlier_rule_does_not_shadow() {
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"allow-limited","priority":10,"action":"allow","protocol":"tcp","dst_port":443,"rate_limit":{"rate":1,"unit":"second"}},
              {"id":"deny-443","priority":20,"action":"deny","protocol":"tcp","dst_port":443}
            ]}"#,
        )
        .unwrap();
        assert!(detect_conflicts(&p).is_empty());
    }

    #[test]
    fn pentest_rate_limit_difference_is_not_a_duplicate() {
        // Unlimited earlier + limited later with the same match: the
        // later rule is shadowed (the earlier rule always decides
        // first), but it is not a duplicate — the rate limit differs.
        let p = Policy::from_json(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"a","priority":10,"action":"allow","protocol":"tcp","dst_port":443},
              {"id":"b","priority":20,"action":"allow","protocol":"tcp","dst_port":443,"rate_limit":{"rate":1,"unit":"second"}}
            ]}"#,
        )
        .unwrap();
        let c = detect_conflicts(&p);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].kind, ConflictKind::Shadowed);
    }

    #[test]
    fn port_spec_subset() {
        assert!(PortSpec::Single(53).subset_of(&None));
        assert!(PortSpec::Single(53).subset_of(&Some(PortSpec::List(vec![53, 443]))));
        assert!(!PortSpec::Single(80).subset_of(&Some(PortSpec::List(vec![53, 443]))));
        let range = PortSpec::Range { range: (8000, 8010) };
        assert!(range.subset_of(&Some(PortSpec::Range { range: (8000, 9000) })));
        assert!(!range.subset_of(&Some(PortSpec::Range { range: (8005, 9000) })));
    }
}
