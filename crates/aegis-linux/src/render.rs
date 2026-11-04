//! Translation of a validated `Policy` into an nftables ruleset.
//!
//! Design decisions (all documented, all deliberate):
//!
//! * One `inet` table, so a single ruleset covers IPv4 and IPv6.
//! * Base rules first: loopback accept, `ct state invalid` drop,
//!   established/related accept. User rules follow in priority order.
//!   The `ct` base rules require kernel conntrack (nf_conntrack). When
//!   `conntrack` is false, they are omitted — but ONLY together with an
//!   explicit operator opt-in (`--no-conntrack`), because a policy that
//!   silently loses stateful inspection would be a lie. Callers must also
//!   refuse stateful user rules (non-empty `states`) in that mode; the
//!   CLI enforces this. See `RenderOptions`.
//! * The chain policy is `drop` (unreachable backstop), and a final
//!   explicit rule implements the policy's `default_action` (with a
//!   counter for telemetry) so rendered enforcement agrees with the
//!   matcher's verdict for unmatched packets.
//! * Direction: a rule renders into the `input` chain unless it specifies
//!   `out_interface` only, and into the `output` chain unless it
//!   specifies `in_interface` only. A rule with no interface renders in
//!   both. (An explicit `direction` field is M2 work.)
//! * A rule with ports and protocol `Any` renders as two rules (TCP +
//!   UDP), because nftables cannot match a port without a layer-4
//!   protocol.
//! * A rule with both IPv4 and IPv6 addresses renders as two rules, one
//!   per family. A rule with no addresses renders once, family-agnostic.

use aegis_core::policy::{Action, Cidr, PortSpec, Protocol, Rule};
use aegis_core::{policy_hash, Policy};
use std::net::IpAddr;

fn fmt_cidr(c: &Cidr) -> String {
    format!("{}/{}", c.network, c.prefix)
}

fn fmt_addrs(addrs: &[Cidr]) -> String {
    if addrs.len() == 1 {
        fmt_cidr(&addrs[0])
    } else {
        let inner: Vec<String> = addrs.iter().map(fmt_cidr).collect();
        format!("{{ {} }}", inner.join(", "))
    }
}

fn fmt_ports(keyword: &str, spec: &PortSpec) -> String {
    match spec {
        PortSpec::Single(p) => format!("{keyword} {p}"),
        PortSpec::Range { range: (lo, hi) } => format!("{keyword} {lo}-{hi}"),
        PortSpec::List(ps) => {
            let inner: Vec<String> = ps.iter().map(|p| p.to_string()).collect();
            format!("{keyword} {{ {} }}", inner.join(", "))
        }
    }
}

fn verdict(action: Action, id: &str) -> String {
    match action {
        Action::Allow => "counter accept".to_string(),
        Action::Deny => "counter drop".to_string(),
        Action::Reject => "counter reject".to_string(),
        Action::Log => format!("counter log prefix \"aegis: {id} \" accept"),
        Action::Alert => format!("counter log prefix \"aegis-alert: {id} \" drop"),
    }
}

struct ProtoVariant {
    keyword: Option<&'static str>, // None = any protocol
    family: Option<bool>,          // None = both, Some(true) = v4, Some(false) = v6
}

/// Expand one rule into (protocol, family) variants for rendering.
fn variants(rule: &Rule) -> Vec<ProtoVariant> {
    let protos: Vec<Option<&'static str>> = match rule.protocol {
        Protocol::Tcp => vec![Some("tcp")],
        Protocol::Udp => vec![Some("udp")],
        Protocol::Icmp => vec![Some("icmp")],
        Protocol::Icmpv6 => vec![Some("icmpv6")],
        Protocol::Any => {
            if rule.src_port.is_some() || rule.dst_port.is_some() {
                vec![Some("tcp"), Some("udp")]
            } else {
                vec![None]
            }
        }
    };
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
    let families: Vec<Option<bool>> = match (has_v4, has_v6) {
        (true, false) => vec![Some(true)],
        (false, true) => vec![Some(false)],
        (true, true) => vec![Some(true), Some(false)],
        (false, false) => vec![None],
    };
    let mut out = Vec::new();
    for p in &protos {
        for f in &families {
            // ICMP is v4-only; ICMPv6 is v6-only; skip impossible combos.
            if *p == Some("icmp") && *f == Some(false) {
                continue;
            }
            if *p == Some("icmpv6") && *f == Some(true) {
                continue;
            }
            out.push(ProtoVariant {
                keyword: *p,
                family: *f,
            });
        }
    }
    out
}

fn render_rule(rule: &Rule, variant: &ProtoVariant) -> String {
    let mut parts: Vec<String> = Vec::new();
    // Addresses, split by the variant's family.
    let srcs: Vec<&Cidr> = rule
        .src_addrs
        .iter()
        .filter(|c| match variant.family {
            Some(true) => matches!(c.network, IpAddr::V4(_)),
            Some(false) => matches!(c.network, IpAddr::V6(_)),
            None => true,
        })
        .collect();
    let dsts: Vec<&Cidr> = rule
        .dst_addrs
        .iter()
        .filter(|c| match variant.family {
            Some(true) => matches!(c.network, IpAddr::V4(_)),
            Some(false) => matches!(c.network, IpAddr::V6(_)),
            None => true,
        })
        .collect();
    if !srcs.is_empty() {
        let kw = match variant.family {
            Some(false) => "ip6 saddr",
            _ => "ip saddr",
        };
        let owned: Vec<Cidr> = srcs.into_iter().cloned().collect();
        parts.push(format!("{kw} {}", fmt_addrs(&owned)));
    }
    if !dsts.is_empty() {
        let kw = match variant.family {
            Some(false) => "ip6 daddr",
            _ => "ip daddr",
        };
        let owned: Vec<Cidr> = dsts.into_iter().cloned().collect();
        parts.push(format!("{kw} {}", fmt_addrs(&owned)));
    }
    if let Some(iif) = &rule.in_interface {
        parts.push(format!("iif \"{iif}\""));
    }
    if let Some(oif) = &rule.out_interface {
        parts.push(format!("oif \"{oif}\""));
    }
    if !rule.states.is_empty() {
        let states: Vec<String> = rule
            .states
            .iter()
            .map(|s| format!("{s:?}").to_lowercase())
            .collect();
        parts.push(format!("ct state {}", states.join(",")));
    }
    if let Some(kw) = variant.keyword {
        // A port match already implies the protocol; otherwise the
        // protocol must be stated explicitly (bare `tcp accept` is not
        // valid nftables syntax, and omitting it would wrongly match
        // every protocol).
        let mut proto_emitted = false;
        if !rule.protocol.is_icmp() {
            if let Some(spec) = &rule.src_port {
                parts.push(fmt_ports(&format!("{kw} sport"), spec));
                proto_emitted = true;
            }
            if let Some(spec) = &rule.dst_port {
                parts.push(fmt_ports(&format!("{kw} dport"), spec));
                proto_emitted = true;
            }
        }
        if !proto_emitted {
            parts.push(format!("meta l4proto {kw}"));
        }
    }
    // Engine 3: rate limit goes after the match conditions and before
    // the verdict (`tcp dport 80 limit rate 25/minute counter accept`).
    // The limit gates the rule: over-rate packets fall through to
    // later rules (ultimately default deny on an allow rule).
    if let Some(lim) = &rule.rate_limit {
        parts.push(lim.nft_fragment());
    }
    let match_text = if parts.is_empty() {
        String::new()
    } else {
        format!("{} ", parts.join(" "))
    };
    format!(
        "    {}{} comment \"aegis: {} prio {}\"",
        match_text,
        verdict(rule.action, &rule.id),
        rule.id,
        rule.priority
    )
}

/// Renderer switches. Defaults are the shipped behavior; the `false`
/// values exist for testing on kernels/hosts that lack the capability
/// (see the CLI flags) and must be used explicitly, never by default.
#[derive(Debug, Clone, Copy)]
pub struct RenderOptions {
    /// Emit `ct` base rules (requires nf_conntrack).
    pub conntrack: bool,
    /// Emit the loopback accept base rule. Disabling it is test-only:
    /// it makes loopback traffic subject to user rules, which is how
    /// the loopback enforcement test verifies allow/deny.
    pub loopback_accept: bool,
}

impl Default for RenderOptions {
    fn default() -> Self {
        RenderOptions {
            conntrack: true,
            loopback_accept: true,
        }
    }
}

/// True when this (protocol, family) variant can actually match a
/// packet of the rule. A variant whose family has addresses on one
/// side but none on the other must be dropped, not rendered with the
/// missing side unrestricted: previously a rule with a v4 source and
/// a v6 destination (which the matcher can never match — one packet
/// cannot be both families) rendered as two rules, `ip saddr 10/8
/// ... accept` and `ip6 daddr 2001:db8::/32 ... accept`, each
/// dropping the other side's restriction and allowing traffic the
/// policy model denies. Dropping the variant keeps render and
/// matcher in agreement; such a rule renders no rule at all.
fn variant_viable(rule: &Rule, variant: &ProtoVariant) -> bool {
    let family_ok = |addrs: &[Cidr]| -> bool {
        if addrs.is_empty() {
            return true;
        }
        match variant.family {
            Some(true) => addrs.iter().any(|c| matches!(c.network, IpAddr::V4(_))),
            Some(false) => addrs.iter().any(|c| matches!(c.network, IpAddr::V6(_))),
            None => true,
        }
    };
    family_ok(&rule.src_addrs) && family_ok(&rule.dst_addrs)
}

fn render_chain(
    name: &str,
    hook: &str,
    policy: &Policy,
    input: bool,
    opts: RenderOptions,
) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "  chain {name} {{\n    type filter hook {hook} priority filter; policy drop;\n"
    ));
    if opts.loopback_accept {
        if input {
            out.push_str("    iif \"lo\" counter accept comment \"aegis: base loopback\"\n");
        } else {
            out.push_str("    oif \"lo\" counter accept comment \"aegis: base loopback\"\n");
        }
    }
    if opts.conntrack {
        out.push_str("    ct state invalid counter drop comment \"aegis: base invalid\"\n");
        out.push_str(
            "    ct state established,related counter accept comment \"aegis: base established\"\n",
        );
    }
    for rule in &policy.rules {
        // Direction filter (see module docs).
        if input && rule.out_interface.is_some() && rule.in_interface.is_none() {
            continue;
        }
        if !input && rule.in_interface.is_some() && rule.out_interface.is_none() {
            continue;
        }
        for variant in variants(rule) {
            if !variant_viable(rule, &variant) {
                continue;
            }
            out.push_str(&render_rule(rule, &variant));
            out.push('\n');
        }
    }
    // The final rule must implement the policy's default_action, not
    // a hardcoded drop: previously a policy with default_action
    // "allow" evaluated (via `eval`) as allow-all but rendered as
    // drop-all, so the model and the enforcement disagreed. The chain
    // policy stays `drop` as an unreachable backstop.
    let default_verdict = verdict(policy.default_action, "default");
    let default_label = format!("{:?}", policy.default_action).to_lowercase();
    out.push_str(&format!(
        "    {default_verdict} comment \"aegis: default {default_label}\"\n  }}\n"
    ));
    out
}

/// Render the full nftables script for a policy, with stateful
/// (`ct`) base rules. This is the shipped default.
pub fn render(policy: &Policy) -> String {
    render_opts(policy, RenderOptions::default())
}

/// Render with full options (see `RenderOptions`).
pub fn render_opts(policy: &Policy, opts: RenderOptions) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# AEGIS X policy \"{}\" v{} mode={} hash={} conntrack={} loopback_accept={}\n",
        policy.name,
        policy.version,
        policy.mode,
        policy_hash(policy),
        opts.conntrack,
        opts.loopback_accept
    ));
    out.push_str("table inet aegis {\n");
    out.push_str(&render_chain("input", "input", policy, true, opts));
    out.push_str(&render_chain("output", "output", policy, false, opts));
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::Policy;

    fn policy(json: &str) -> Policy {
        Policy::from_json(json).unwrap()
    }

    #[test]
    fn renders_basic_allow_rule() {
        let p = policy(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"web","priority":10,"action":"allow","protocol":"tcp","dst_port":443}]}"#,
        );
        let script = render(&p);
        assert!(script.contains("table inet aegis"));
        assert!(script.contains("tcp dport 443 counter accept"));
        assert!(script.contains("ct state invalid counter drop"));
        assert!(script.contains("counter drop comment \"aegis: default deny\""));
    }

    #[test]
    fn any_protocol_with_ports_splits_tcp_udp() {
        let p = policy(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"dns","priority":10,"action":"allow","dst_port":53}]}"#,
        );
        let script = render(&p);
        assert!(script.contains("tcp dport 53"));
        assert!(script.contains("udp dport 53"));
    }

    #[test]
    fn mixed_family_rule_splits() {
        let p = policy(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"both","priority":10,"action":"allow","protocol":"tcp",
               "src_addrs":["10.0.0.0/8","2001:db8::/32"],"dst_port":22}]}"#,
        );
        let script = render(&p);
        assert!(script.contains("ip saddr 10.0.0.0/8"));
        assert!(script.contains("ip6 saddr 2001:db8::/32"));
    }

    #[test]
    fn render_without_loopback_accept_omits_lo_rules() {
        let p = policy(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"web","priority":10,"action":"allow","protocol":"tcp","dst_port":443}]}"#,
        );
        let script = render_opts(
            &p,
            RenderOptions {
                conntrack: true,
                loopback_accept: false,
            },
        );
        assert!(!script.contains("base loopback"));
        assert!(script.contains("ct state invalid counter drop"));
    }

    #[test]
    fn render_without_conntrack_omits_ct_rules() {
        let p = policy(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"web","priority":10,"action":"allow","protocol":"tcp","dst_port":443}]}"#,
        );
        let script = render_opts(
            &p,
            RenderOptions {
                conntrack: false,
                loopback_accept: true,
            },
        );
        assert!(!script.contains("ct state"));
        assert!(script.contains("tcp dport 443 counter accept"));
        assert!(script.contains("conntrack=false"));
    }

    #[test]
    fn rate_limited_rule_renders_limit_before_verdict() {
        let p = policy(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"web","priority":10,"action":"allow","protocol":"tcp","dst_port":80,
               "rate_limit":{"rate":25,"unit":"minute","burst":5}}]}"#,
        );
        let script = render(&p);
        assert!(script.contains("tcp dport 80 limit rate 25/minute burst 5 packets counter accept"));
        let p2 = policy(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"web","priority":10,"action":"allow","protocol":"tcp","dst_port":80,
               "rate_limit":{"rate":10,"unit":"second"}}]}"#,
        );
        let script2 = render(&p2);
        assert!(script2.contains("tcp dport 80 limit rate 10/second counter accept"));
        // A rule without a limit renders no limit text.
        let p3 = policy(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"web","priority":10,"action":"allow","protocol":"tcp","dst_port":80}]}"#,
        );
        assert!(!render(&p3).contains("limit rate"));
    }

    #[test]
    fn pentest_mixed_family_rule_renders_nothing() {
        // Matcher: a packet cannot be v4-sourced AND v6-destined, so
        // this rule never matches. Render must not broaden it into
        // two half-restricted accept rules.
        let p = policy(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"v4src-v6dst","priority":10,"action":"allow","protocol":"tcp",
               "src_addrs":["10.0.0.0/8"],"dst_addrs":["2001:db8::/32"],"dst_port":22}]}"#,
        );
        let script = render(&p);
        assert!(!script.contains("v4src-v6dst"));
        assert!(!script.contains("tcp dport 22 counter accept"));
    }

    #[test]
    fn pentest_partial_mixed_family_renders_only_viable_variant() {
        // v4 variant keeps both restrictions; the v6 variant would
        // drop the v4-only destination and must not render.
        let p = policy(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"both-src-v4dst","priority":10,"action":"allow","protocol":"tcp",
               "src_addrs":["10.0.0.0/8","2001:db8::/32"],"dst_addrs":["192.168.0.0/16"],"dst_port":22}]}"#,
        );
        let script = render(&p);
        assert!(script.contains("ip saddr 10.0.0.0/8 ip daddr 192.168.0.0/16 tcp dport 22 counter accept"));
        assert!(!script.contains("ip6 saddr 2001:db8::/32 tcp dport 22 counter accept"));
    }

    #[test]
    fn pentest_default_action_is_rendered_not_hardcoded_drop() {
        let allow = policy(
            r#"{"version":1,"name":"t","default_action":"allow","rules":[]}"#,
        );
        assert!(render(&allow).contains("counter accept comment \"aegis: default allow\""));
        let reject = policy(
            r#"{"version":1,"name":"t","default_action":"reject","rules":[]}"#,
        );
        assert!(render(&reject).contains("counter reject comment \"aegis: default reject\""));
        let deny = policy(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[]}"#,
        );
        assert!(render(&deny).contains("counter drop comment \"aegis: default deny\""));
    }

    #[test]
    fn zone_expanded_rule_renders() {
        let p = policy(
            r#"{"version":1,"name":"t","default_action":"deny",
               "zones":[{"name":"lan","subnets":["192.168.0.0/16"]}],
               "rules":[{"id":"lan-dns","priority":10,"action":"allow","protocol":"udp",
               "src_zone":"lan","dst_port":53}]}"#,
        );
        let script = render(&p);
        assert!(script.contains("ip saddr 192.168.0.0/16"));
        assert!(script.contains("udp dport 53"));
    }
}
