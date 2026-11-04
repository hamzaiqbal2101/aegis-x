//! Engine 8 (part) — zone-matrix validation: which zone-to-zone
//! flows does a policy allow vs deny?
//!
//! HONEST SCOPE, READ FIRST: each matrix cell evaluates ONE
//! representative packet — the network address of the source zone's
//! first subnet to the network address of the destination zone's
//! first subnet, for ONE caller-chosen protocol and destination port.
//! A cell therefore answers "what happens to this representative
//! flow", NOT "what happens to every possible flow between these
//! zones". A zone with many subnets, or rules keyed on ports other
//! than the one queried, can differ from the cell. The matrix is a
//! review aid for policy authors, not a proof of segmentation.
//! Unknown zone names are errors, never silently skipped.

use crate::matcher::{evaluate, EvalPacket};
use crate::policy::{Action, ConnState, Policy, Protocol};
use std::net::IpAddr;

/// One matrix cell: the verdict for the representative flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixCell {
    pub action: Action,
    /// The deciding rule, if any (`None` = default action decided).
    pub rule_id: Option<String>,
    /// True when no rule matched and the default action decided.
    pub via_default: bool,
}

/// The full matrix: `cells[src_zone_idx][dst_zone_idx]`.
#[derive(Debug, Clone)]
pub struct ZoneMatrix {
    pub zones: Vec<String>,
    pub protocol: Protocol,
    pub dst_port: Option<u16>,
    pub cells: Vec<Vec<MatrixCell>>,
}

impl ZoneMatrix {
    pub fn cell(&self, src_zone: &str, dst_zone: &str) -> Option<&MatrixCell> {
        let si = self.zones.iter().position(|z| z == src_zone)?;
        let di = self.zones.iter().position(|z| z == dst_zone)?;
        Some(&self.cells[si][di])
    }
}

/// Evaluate one representative flow between two zones.
fn representative(
    policy: &Policy,
    src_zone: &str,
    dst_zone: &str,
    protocol: Protocol,
    dst_port: Option<u16>,
) -> Result<MatrixCell, String> {
    let src = policy
        .zones
        .iter()
        .find(|z| z.name == src_zone)
        .ok_or_else(|| format!("unknown zone: {src_zone}"))?;
    let dst = policy
        .zones
        .iter()
        .find(|z| z.name == dst_zone)
        .ok_or_else(|| format!("unknown zone: {dst_zone}"))?;
    let src_ip: IpAddr = src
        .subnets
        .first()
        .map(|c| c.network)
        .ok_or_else(|| format!("zone {src_zone} has no subnets"))?;
    let dst_ip: IpAddr = dst
        .subnets
        .first()
        .map(|c| c.network)
        .ok_or_else(|| format!("zone {dst_zone} has no subnets"))?;
    let verdict = evaluate(
        policy,
        &EvalPacket {
            src_ip,
            dst_ip,
            src_port: None,
            dst_port,
            protocol,
            state: ConnState::New,
            in_interface: None,
            out_interface: None,
        },
    );
    Ok(MatrixCell {
        action: verdict.action,
        via_default: verdict.rule_id.is_none(),
        rule_id: verdict.rule_id,
    })
}

/// Build the matrix for all zones in the policy (in policy order),
/// for one protocol and destination port.
pub fn zone_matrix(
    policy: &Policy,
    protocol: Protocol,
    dst_port: Option<u16>,
) -> Result<ZoneMatrix, String> {
    let zones: Vec<String> = policy.zones.iter().map(|z| z.name.clone()).collect();
    let mut cells = Vec::new();
    for sz in &zones {
        let mut row = Vec::new();
        for dz in &zones {
            row.push(representative(policy, sz, dz, protocol, dst_port)?);
        }
        cells.push(row);
    }
    Ok(ZoneMatrix {
        zones,
        protocol,
        dst_port,
        cells,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::from_json(
            r#"{"version":1,"name":"seg","default_action":"deny",
            "zones":[
              {"name":"lan","subnets":["192.168.0.0/16"]},
              {"name":"dmz","subnets":["10.1.0.0/16"]},
              {"name":"wan","subnets":["0.0.0.0/0"]}
            ],
            "rules":[
              {"id":"lan-web","priority":10,"action":"allow","protocol":"tcp",
               "src_zone":"lan","dst_zone":"dmz","dst_port":443},
              {"id":"dmz-nothing","priority":20,"action":"deny","protocol":"tcp",
               "src_zone":"dmz","dst_zone":"lan"}
            ]}"#,
        )
        .unwrap()
    }

    #[test]
    fn matrix_reflects_rules_and_default() {
        let m = zone_matrix(&policy(), Protocol::Tcp, Some(443)).unwrap();
        assert_eq!(m.zones, vec!["lan", "dmz", "wan"]);
        // lan -> dmz on 443: allowed by lan-web.
        let c = m.cell("lan", "dmz").unwrap();
        assert_eq!(c.action, Action::Allow);
        assert_eq!(c.rule_id.as_deref(), Some("lan-web"));
        assert!(!c.via_default);
        // dmz -> lan: denied by dmz-nothing.
        let c = m.cell("dmz", "lan").unwrap();
        assert_eq!(c.action, Action::Deny);
        assert_eq!(c.rule_id.as_deref(), Some("dmz-nothing"));
        // lan -> wan: no rule matches -> default deny.
        let c = m.cell("lan", "wan").unwrap();
        assert_eq!(c.action, Action::Deny);
        assert!(c.via_default);
        // Same-zone cell exists and is decided (here: default deny).
        let c = m.cell("lan", "lan").unwrap();
        assert_eq!(c.action, Action::Deny);
        assert!(c.via_default);
    }

    #[test]
    fn matrix_port_specificity() {
        // On port 80 the lan-web rule (443-only) does not apply.
        let m = zone_matrix(&policy(), Protocol::Tcp, Some(80)).unwrap();
        let c = m.cell("lan", "dmz").unwrap();
        assert_eq!(c.action, Action::Deny);
        assert!(c.via_default);
    }

    #[test]
    fn unknown_zone_and_empty_zone_are_errors() {
        let p = policy();
        assert!(representative(&p, "nope", "lan", Protocol::Tcp, None).is_err());
        let empty = Policy::from_json(
            r#"{"version":1,"name":"e","default_action":"deny",
            "zones":[{"name":"void","subnets":[]}],"rules":[]}"#,
        )
        .unwrap();
        assert!(zone_matrix(&empty, Protocol::Tcp, None).is_err());
    }
}
