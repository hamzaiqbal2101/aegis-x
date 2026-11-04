//! Property tests / fuzz-lite for the policy parser.
//!
//! LABEL, STATED PLAINLY: this is property-style testing with a small
//! deterministic pseudo-random generator, NOT a fuzzer. There is no
//! coverage-guided mutation, no crash harness, no external corpus,
//! and no new dependency: the generator below is a hand-written
//! xorshift PRNG driven by fixed seeds, so every run generates the
//! exact same policies.
//!
//! The real coverage-guided fuzzer now lives separately in
//! `fuzz/` (`cargo +nightly fuzz run policy_parser`, libFuzzer,
//! Nov 3, 2026). It found a genuine panic that is now FIXED in
//! `policy.rs` (`contains` checks family before masking, and
//! `mask()` uses saturating shifts): a V4 packet checked against
//! a V6 CIDR with prefix > 32 used to panic on `32 - prefix`
//! underflow. The regression test
//! `cross_family_cidr_match_v6_prefix_above_32` pins the fixed
//! behavior, including the fuzzer's exact reproducer policy.
//!
//! What is checked here:
//! * Round-trip: each generated policy serializes to JSON, parses
//!   back through `Policy::from_json`, and must equal the policy
//!   that `from_json`'s own normalization should produce from it
//!   (zone expansion + stable priority sort, applied here by the
//!   test's `expected_normalized` helper). Equality is checked on
//!   the full re-serialized JSON string AND on `policy_hash` —
//!   never weakened to "it parses". `Policy` does not implement
//!   `PartialEq`, so JSON/hash equality is the equality this
//!   codebase already supports (see `integrity::policy_hash`).
//! * Rejection: malformed inputs that `Policy::from_json` is known
//!   to reject (checked against `policy.rs` first — truncated JSON,
//!   wrong JSON types, unknown action/protocol strings, invalid
//!   CIDRs) must return `Err`. No rejection is asserted for
//!   validation that does not exist in `policy.rs`.
//!
//! Generator scope, also stated plainly: generated policies use
//! only constructs `policy.rs` accepts — unique rule ids, ICMP
//! rules without ports (ports on ICMP are a load error), port
//! ranges never inverted (only `Single`/`List` are generated),
//! and every referenced zone is defined in the same policy (an
//! unknown zone is a load error). That is what makes the
//! round-trip assertion meaningful instead of accidentally testing
//! the rejection paths.

use crate::integrity::policy_hash;
use crate::policy::{Action, Cidr, ConnState, Policy, PortSpec, Protocol, RateLimit, RateUnit, Rule, Zone};
use std::collections::HashMap;

/// Deterministic xorshift64* PRNG. Fixed seeds only; no `rand` and
/// no `proptest` dependency is added for these tests.
struct Prng(u64);

impl Prng {
    fn new(seed: u64) -> Prng {
        // Zero state would be stuck at zero; fold any zero seed away.
        Prng(if seed == 0 { 0x9e3779b97f4a7c15 } else { seed })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }

    fn bool(&mut self) -> bool {
        self.next_u64() % 2 == 0
    }

    fn pick<'a, T>(&mut self, pool: &'a [T]) -> &'a T {
        &pool[self.below(pool.len())]
    }
}

const ACTIONS: [Action; 5] = [
    Action::Allow,
    Action::Deny,
    Action::Reject,
    Action::Log,
    Action::Alert,
];

const PROTOCOLS: [Protocol; 5] = [
    Protocol::Tcp,
    Protocol::Udp,
    Protocol::Icmp,
    Protocol::Icmpv6,
    Protocol::Any,
];

const CIDR_POOL: [&str; 8] = [
    "10.0.0.0/8",
    "192.168.0.0/16",
    "172.16.0.0/12",
    "203.0.113.0/24",
    "198.51.100.0/24",
    "192.0.2.0/24",
    "2001:db8::/32",
    "2001:db8:1::/48",
];

const PORT_POOL: [u16; 6] = [22, 53, 80, 443, 8080, 8443];

const ZONE_DEFS: [(&str, &str); 3] = [
    ("lan", "192.168.0.0/16"),
    ("dmz", "203.0.113.0/24"),
    ("v6net", "2001:db8::/32"),
];

const INTERFACES: [&str; 2] = ["eth0", "wlan0"];

fn gen_cidrs(rng: &mut Prng) -> Vec<Cidr> {
    let n = rng.below(3); // 0, 1, or 2 CIDRs.
    (0..n)
        .map(|_| Cidr::parse(rng.pick(&CIDR_POOL)).expect("pool CIDRs are valid"))
        .collect()
}

fn gen_port(rng: &mut Prng) -> Option<PortSpec> {
    match rng.below(3) {
        0 => None,
        1 => Some(PortSpec::Single(*rng.pick(&PORT_POOL))),
        _ => {
            // A list of 1-3 distinct pool ports, in pool order.
            let mut ports: Vec<u16> = Vec::new();
            for p in PORT_POOL {
                if rng.bool() && !ports.contains(&p) {
                    ports.push(p);
                }
            }
            if ports.is_empty() {
                ports.push(*rng.pick(&PORT_POOL));
            }
            Some(PortSpec::List(ports))
        }
    }
}

fn gen_zone_ref(rng: &mut Prng) -> Option<String> {
    if rng.bool() {
        Some(rng.pick(&ZONE_DEFS).0.to_string())
    } else {
        None
    }
}

fn gen_rule(rng: &mut Prng, policy_idx: usize, rule_idx: usize) -> Rule {
    let protocol = *rng.pick(&PROTOCOLS);
    // Ports on ICMP are a load error, so ICMP rules get no ports.
    let (src_port, dst_port) = if protocol.is_icmp() {
        (None, None)
    } else {
        (gen_port(rng), gen_port(rng))
    };
    let rate_limit = if rng.below(4) == 0 {
        Some(RateLimit {
            rate: (rng.below(100) + 1) as u64,
            unit: match rng.below(4) {
                0 => RateUnit::Second,
                1 => RateUnit::Minute,
                2 => RateUnit::Hour,
                _ => RateUnit::Day,
            },
            burst: if rng.bool() {
                Some((rng.below(10) + 1) as u64)
            } else {
                None
            },
        })
    } else {
        None
    };
    let states = if rng.bool() {
        vec![ConnState::New, ConnState::Established]
    } else {
        Vec::new()
    };
    Rule {
        id: format!("r-{policy_idx}-{rule_idx}"),
        priority: rng.below(1000) as u32,
        action: *rng.pick(&ACTIONS),
        protocol,
        src_addrs: gen_cidrs(rng),
        dst_addrs: gen_cidrs(rng),
        src_zone: gen_zone_ref(rng),
        dst_zone: gen_zone_ref(rng),
        src_port,
        dst_port,
        in_interface: if rng.below(4) == 0 {
            Some(rng.pick(&INTERFACES).to_string())
        } else {
            None
        },
        out_interface: None,
        app: if rng.below(5) == 0 {
            Some(r"C:\Program Files\App\app.exe".to_string())
        } else {
            None
        },
        states,
        rate_limit,
        log: rng.bool(),
        engines: if rng.bool() {
            vec!["linux".to_string()]
        } else {
            Vec::new()
        },
        description: format!("generated rule {rule_idx}"),
    }
}

fn gen_policy(rng: &mut Prng, policy_idx: usize) -> Policy {
    let zones: Vec<Zone> = ZONE_DEFS
        .iter()
        .map(|(name, subnet)| Zone {
            name: name.to_string(),
            subnets: vec![Cidr::parse(subnet).expect("zone CIDRs are valid")],
        })
        .collect();
    let n_rules = rng.below(5) + 1; // 1-5 rules.
    let rules = (0..n_rules)
        .map(|i| gen_rule(rng, policy_idx, i))
        .collect();
    Policy {
        version: 1,
        name: format!("generated-{policy_idx}"),
        mode: "standard".to_string(),
        default_action: *rng.pick(&ACTIONS),
        zones,
        rules,
    }
}

/// The policy `Policy::from_json` should produce from `policy`:
/// zones expanded into src/dst addrs, then a stable sort by
/// priority. This mirrors `policy.rs`'s `normalize` (expansion +
/// sort only — validation is `from_json`'s own job, and the
/// generator only produces valid policies, so no validation error
/// is expected here).
fn expected_normalized(policy: &Policy) -> Policy {
    let mut out = policy.clone();
    let zones: HashMap<&str, &Zone> = out.zones.iter().map(|z| (z.name.as_str(), z)).collect();
    for rule in &mut out.rules {
        if let Some(zone_name) = &rule.src_zone {
            let zone = zones[zone_name.as_str()];
            for subnet in zone.subnets.iter() {
                if !rule.src_addrs.contains(subnet) {
                    rule.src_addrs.push(subnet.clone());
                }
            }
        }
        if let Some(zone_name) = &rule.dst_zone {
            let zone = zones[zone_name.as_str()];
            for subnet in zone.subnets.iter() {
                if !rule.dst_addrs.contains(subnet) {
                    rule.dst_addrs.push(subnet.clone());
                }
            }
        }
    }
    out.rules.sort_by_key(|r| r.priority);
    out
}

#[test]
fn round_trip_at_least_200_generated_policies() {
    // 5 fixed seeds x 50 policies = 250 policies, all deterministic.
    const SEEDS: [u64; 5] = [1, 42, 1234, 20261102, 987654321];
    let mut total = 0usize;
    for (seed_idx, seed) in SEEDS.iter().enumerate() {
        let mut rng = Prng::new(*seed);
        for i in 0..50 {
            let policy_idx = seed_idx * 1000 + i;
            let policy = gen_policy(&mut rng, policy_idx);
            let json = serde_json::to_string(&policy).expect("policy must serialize");
            let parsed = Policy::from_json(&json).unwrap_or_else(|e| {
                panic!("generated policy {policy_idx} (seed {seed}) failed to parse: {e}\n{json}")
            });
            let expected = expected_normalized(&policy);
            let expected_json =
                serde_json::to_string(&expected).expect("expected policy must serialize");
            let parsed_json =
                serde_json::to_string(&parsed).expect("parsed policy must serialize");
            assert_eq!(
                parsed_json, expected_json,
                "round-trip JSON mismatch for policy {policy_idx} (seed {seed})"
            );
            assert_eq!(
                policy_hash(&parsed),
                policy_hash(&expected),
                "round-trip hash mismatch for policy {policy_idx} (seed {seed})"
            );
            // `from_json` is now idempotent for zone-referencing
            // policies: `normalize` skips zone subnets already present,
            // so re-parsing an already-normalized policy must return
            // the same policy, with no duplicated addresses.
            let reparsed = Policy::from_json(&parsed_json).expect("reparse must succeed");
            assert_eq!(
                serde_json::to_string(&reparsed).expect("reparsed must serialize"),
                parsed_json,
                "second parse of policy {policy_idx} is not identical to the first"
            );
            total += 1;
        }
    }
    assert!(
        total >= 200,
        "expected at least 200 generated policies, got {total}"
    );
}

#[test]
fn malformed_inputs_are_rejected() {
    // Truncated JSON.
    assert!(Policy::from_json(r#"{"version":1,"name":"t","#).is_err());
    assert!(Policy::from_json("").is_err());
    assert!(Policy::from_json("not json").is_err());
    // Wrong JSON type: priority as a string.
    let priority_string = r#"{"version":1,"name":"t","default_action":"deny",
        "rules":[{"id":"x","priority":"high","action":"allow"}]}"#;
    assert!(Policy::from_json(priority_string).is_err());
    // Wrong JSON type: version as a string.
    let version_string = r#"{"version":"one","name":"t","default_action":"deny","rules":[]}"#;
    assert!(Policy::from_json(version_string).is_err());
    // Unknown action string.
    let bad_action = r#"{"version":1,"name":"t","default_action":"deny",
        "rules":[{"id":"x","priority":1,"action":"block"}]}"#;
    assert!(Policy::from_json(bad_action).is_err());
    // Unknown default action string.
    let bad_default = r#"{"version":1,"name":"t","default_action":"maybe","rules":[]}"#;
    assert!(Policy::from_json(bad_default).is_err());
    // Invalid protocol string.
    let bad_protocol = r#"{"version":1,"name":"t","default_action":"deny",
        "rules":[{"id":"x","priority":1,"action":"allow","protocol":"sctp"}]}"#;
    assert!(Policy::from_json(bad_protocol).is_err());
    // Invalid CIDR: bad address.
    let bad_cidr = r#"{"version":1,"name":"t","default_action":"deny",
        "rules":[{"id":"x","priority":1,"action":"allow","src_addrs":["not-a-cidr"]}]}"#;
    assert!(Policy::from_json(bad_cidr).is_err());
    // Invalid CIDR: prefix out of range for IPv4.
    let bad_prefix = r#"{"version":1,"name":"t","default_action":"deny",
        "rules":[{"id":"x","priority":1,"action":"allow","src_addrs":["10.0.0.0/33"]}]}"#;
    assert!(Policy::from_json(bad_prefix).is_err());
    // Invalid CIDR in a zone definition.
    let bad_zone_cidr = r#"{"version":1,"name":"t","default_action":"deny",
        "zones":[{"name":"lan","subnets":["999.0.0.0/8"]}],"rules":[]}"#;
    assert!(Policy::from_json(bad_zone_cidr).is_err());
}

/// Adversarial inputs added with the Nov 3, 2026 fuzz setup.
/// Every case was probed against the live parser before being
/// written here, so each Ok/Err below is observed behaviour, not
/// an assumption — and every case must at minimum not panic.
/// Categories: empty/whitespace, wrong top-level types, duplicate
/// JSON keys, unknown fields (now a load error since the pentest
/// agent added `deny_unknown_fields` to `policy.rs` the same day),
/// unicode strings, extreme numbers/ports, inverted/malformed
/// port ranges, CIDR edges, case sensitivity, huge inputs, deep
/// bracket nesting, and the invalid-UTF-8 boundary (see below).
#[test]
fn adversarial_inputs_never_panic_and_reject_as_expected() {
    // (label, json, must_parse). `must_parse` is the probed result.
    let cases: Vec<(&str, String, bool)> = vec![
        ("empty", "".to_string(), false),
        ("whitespace-only", "  \n\t ".to_string(), false),
        ("top-level null", "null".to_string(), false),
        ("top-level array", "[]".to_string(), false),
        ("top-level number", "123".to_string(), false),
        ("empty object", "{}".to_string(), false),
        ("truncated object", r#"{"version":1,"name":"t","#.to_string(), false),
        // Duplicate JSON keys: serde rejects them, it does not
        // silently take the last one.
        (
            "duplicate version key",
            r#"{"version":1,"version":2,"name":"t","default_action":"deny","rules":[]}"#.to_string(),
            false,
        ),
        (
            "duplicate action key",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","action":"deny"}]}"#.to_string(),
            false,
        ),
        // Unknown fields: fail closed (pentest change, Nov 3, 2026).
        (
            "unknown rule field (typo, e.g. dst_povt)",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","bogus":1}]}"#.to_string(),
            false,
        ),
        (
            "unknown policy field",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[],"extra":1}"#.to_string(),
            false,
        ),
        // Unicode: accented, CJK, emoji, and a BOM *inside* a string
        // (only a leading BOM is stripped; an interior one is data).
        (
            "unicode name",
            "{\"version\":1,\"name\":\"té中😀\",\"default_action\":\"deny\",\"rules\":[]}".to_string(),
            true,
        ),
        (
            "emoji description",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","description":"🔥 test"}]}"#.to_string(),
            true,
        ),
        (
            "bom inside string is data, not a prefix",
            "{\"version\":1,\"name\":\"t\u{feff}\",\"default_action\":\"allow\",\"rules\":[]}".to_string(),
            true,
        ),
        // A second leading BOM is NOT stripped: only one is.
        (
            "double bom",
            "\u{feff}\u{feff}{\"version\":1,\"name\":\"t\",\"default_action\":\"allow\",\"rules\":[]}".to_string(),
            false,
        ),
        // Extreme numbers: u32/u16 maxima parse; one past them does not.
        (
            "priority u32 max",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":4294967295,"action":"allow"}]}"#.to_string(),
            true,
        ),
        (
            "priority u32 overflow",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":4294967296,"action":"allow"}]}"#.to_string(),
            false,
        ),
        (
            "priority negative",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":-1,"action":"allow"}]}"#.to_string(),
            false,
        ),
        (
            "version u32 max",
            r#"{"version":4294967295,"name":"t","default_action":"deny","rules":[]}"#.to_string(),
            true,
        ),
        (
            "port u16 max",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","dst_port":65535}]}"#.to_string(),
            true,
        ),
        (
            "port u16 overflow",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","dst_port":65536}]}"#.to_string(),
            false,
        ),
        (
            "port float",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","dst_port":443.5}]}"#.to_string(),
            false,
        ),
        (
            "port string",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","dst_port":"443"}]}"#.to_string(),
            false,
        ),
        (
            "rate u64 max",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","rate_limit":{"rate":18446744073709551615,"unit":"second"}}]}"#.to_string(),
            true,
        ),
        // Port ranges: inverted is a validation error; a
        // one- or three-element range is a type error; equal ends
        // (a single-port range) parses.
        (
            "inverted port range",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","dst_port":{"range":[8100,8000]}}]}"#.to_string(),
            false,
        ),
        (
            "one-element range",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","dst_port":{"range":[8000]}}]}"#.to_string(),
            false,
        ),
        (
            "three-element range",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","dst_port":{"range":[8000,8100,8200]}}]}"#.to_string(),
            false,
        ),
        (
            "equal-ends range",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","dst_port":{"range":[8000,8000]}}]}"#.to_string(),
            true,
        ),
        // CIDR edges.
        (
            "ipv4 /0",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","src_addrs":["0.0.0.0/0"]}]}"#.to_string(),
            true,
        ),
        (
            "ipv6 /0",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","src_addrs":["::/0"]}]}"#.to_string(),
            true,
        ),
        (
            "ipv6 /128 host",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","src_addrs":["2001:db8::1/128"]}]}"#.to_string(),
            true,
        ),
        (
            "prefix with leading zero",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","src_addrs":["10.0.0.0/08"]}]}"#.to_string(),
            true,
        ),
        (
            "double slash cidr",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","src_addrs":["10.0.0.0//8"]}]}"#.to_string(),
            false,
        ),
        (
            "empty cidr string",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","src_addrs":[""]}]}"#.to_string(),
            false,
        ),
        // Wrong container types and ICMP port rules.
        (
            "rules as object",
            r#"{"version":1,"name":"t","default_action":"deny","rules":{}}"#.to_string(),
            false,
        ),
        (
            "rules null",
            r#"{"version":1,"name":"t","default_action":"deny","rules":null}"#.to_string(),
            false,
        ),
        (
            "icmpv6 with ports",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","protocol":"icmpv6","dst_port":8}]}"#.to_string(),
            false,
        ),
        // Enums are lowercase-only.
        (
            "uppercase action",
            r#"{"version":1,"name":"t","default_action":"DENY","rules":[]}"#.to_string(),
            false,
        ),
        (
            "uppercase protocol",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"x","priority":1,"action":"allow","protocol":"TCP"}]}"#.to_string(),
            false,
        ),
        // Duplicate zone names and duplicate rule ids (case-sensitive
        // ids: "X" and "x" are distinct and both parse).
        (
            "duplicate zone name",
            r#"{"version":1,"name":"t","default_action":"deny","zones":[{"name":"lan","subnets":["10.0.0.0/8"]},{"name":"lan","subnets":["192.168.0.0/16"]}],"rules":[{"id":"x","priority":1,"action":"allow","dst_zone":"lan"}]}"#.to_string(),
            false,
        ),
        (
            "rule ids differing only by case",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"X","priority":1,"action":"allow"},{"id":"x","priority":2,"action":"deny"}]}"#.to_string(),
            true,
        ),
        (
            "empty rule id",
            r#"{"version":1,"name":"t","default_action":"deny","rules":[{"id":"","priority":1,"action":"allow"}]}"#.to_string(),
            true,
        ),
        // Weird nesting: 1000 opening brackets, unclosed, and a
        // 200-deep array where a port list is expected. Both must
        // be Err, never a panic or a hang.
        ("1000 unclosed brackets", "[".repeat(1000), false),
        (
            "200-deep array as port list",
            format!(
                r#"{{"version":1,"name":"t","default_action":"deny","rules":[{{"id":"x","priority":1,"action":"allow","dst_port":{}}}}}]"#,
                "[".repeat(200)
            ),
            false,
        ),
    ];
    for (label, json, must_parse) in &cases {
        let result = Policy::from_json(json);
        assert_eq!(
            result.is_ok(),
            *must_parse,
            "adversarial case {label} (must_parse={must_parse}) gave {:?}",
            result.as_ref().map(|_| "Ok").map_err(|e| e.as_str())
        );
    }

    // Huge inputs: 2000 rules and a 100 000-char name both parse.
    let mut rules = String::new();
    for i in 0..2000 {
        if i > 0 {
            rules.push(',');
        }
        rules.push_str(&format!(r#"{{"id":"r{i}","priority":{i},"action":"allow"}}"#));
    }
    let huge_rules = format!(
        r#"{{"version":1,"name":"t","default_action":"deny","rules":[{rules}]}}"#
    );
    let parsed = Policy::from_json(&huge_rules).expect("2000-rule policy must parse");
    assert_eq!(parsed.rules.len(), 2000);
    let huge_name = format!(
        r#"{{"version":1,"name":"{}","default_action":"deny","rules":[]}}"#,
        "a".repeat(100_000)
    );
    assert!(Policy::from_json(&huge_name).is_ok());

    // Invalid-UTF-8 boundary, stated plainly: `Policy::from_json`
    // takes `&str`, so bytes that are not valid UTF-8 can never
    // reach the parser at all — the boundary is the caller's
    // `str::from_utf8` check, not a parser branch. Assert that
    // boundary here (a lone 0xFF byte is not valid UTF-8), and
    // that the fuzzer target likewise skips non-UTF-8 inputs
    // instead of lossy-converting them into different input.
    // Built at runtime (not as literals) so the compiler does not
    // lint these as "always an error" — the point is the runtime
    // boundary check, not the literal.
    let bad_bytes: Vec<u8> = vec![0xff, 0xfe, b'{'];
    assert!(std::str::from_utf8(&bad_bytes).is_err());
    let bad_bytes: Vec<u8> = vec![0xc3, 0x28];
    assert!(std::str::from_utf8(&bad_bytes).is_err());
}

/// Cross-family CIDR matching at the *safe* boundary only.
///
/// A V4 address checked against a V6 CIDR (or vice versa) must
/// simply not match. At prefix <= 32 this holds: `mask()` is
/// called with a prefix valid for the packet's family, the masked
/// address can never equal the other family's network, and
/// `same_family` is false. This test pins that safe boundary.
///
/// DELIBERATELY NOT TESTED HERE: prefix > 32 (e.g. a V6 /48,
/// /64 or /128 zone checked against a V4 packet). That path
/// panics in `policy.rs:137` (`32 - prefix` underflow in
/// `mask()`, because `Cidr::contains` calls `mask()` before
/// checking `same_family`). It was found by the libFuzzer target
/// in `fuzz/` on Nov 3, 2026, is reproduced by
/// `fuzz/artifacts/policy_parser/crash-f5368f7eb905a2fbf88627efa34c8d0b0a2d1ff5`
/// and by the minimal JSON in `fuzz/README.md`, and must be
/// fixed in `policy.rs` (e.g. check `same_family` first in
/// `contains`/`contains_network`) before any test asserts it.
/// Adding such a test now would turn this suite red, so the
/// finding is reported, not encoded as a failing test.
#[test]
fn cross_family_cidr_match_is_safe_at_prefix_32() {
    use std::net::IpAddr;
    let v6_32 = Cidr::parse("2001:db8::/32").unwrap();
    let v4: IpAddr = "10.0.0.5".parse().unwrap();
    assert!(!v6_32.contains(v4));
    let v4_16 = Cidr::parse("192.168.0.0/16").unwrap();
    let v6: IpAddr = "2001:db8::5".parse().unwrap();
    assert!(!v4_16.contains(v6));
    assert!(!v6_32.contains_network(&v4_16));
    assert!(!v4_16.contains_network(&v6_32));
}

/// Regression for the fuzzer finding (Nov 3, 2026): a V4 packet
/// checked against a V6 CIDR with prefix > 32 used to panic in
/// `mask()` (`32 - prefix` underflow in debug builds). It must now
/// simply not match, at both the `contains` level and the full
/// `evaluate` level with the fuzzer's exact reproducer policy.
#[test]
fn cross_family_cidr_match_v6_prefix_above_32() {
    use crate::matcher::{evaluate, EvalPacket};
    use crate::policy::{Action, ConnState, Protocol};
    use std::net::IpAddr;
    let v4: IpAddr = "10.0.0.5".parse().unwrap();
    for cidr in ["2001:db8::/48", "2001:db8::/64", "2001:db8::/128"] {
        let block = Cidr::parse(cidr).unwrap();
        assert!(!block.contains(v4), "{cidr} must not contain a V4 packet");
        assert!(!block.contains_network(&Cidr::parse("192.168.0.0/16").unwrap()));
    }
    // The fuzzer's reproducer: V6 zone /48, V4 packet, TCP/443.
    let policy = Policy::from_json(
        r#"{"version":1,"name":"t","default_action":"deny",
            "zones":[{"name":"lan","subnets":["2001:db8::/48"]}],
            "rules":[{"id":"web","priority":10,"action":"allow","protocol":"tcp",
                      "dst_zone":"lan","dst_port":443}]}"#,
    )
    .expect("reproducer policy must parse");
    let verdict = evaluate(
        &policy,
        &EvalPacket {
            src_ip: "203.0.113.7".parse().unwrap(),
            dst_ip: "10.0.0.5".parse().unwrap(),
            src_port: Some(40000),
            dst_port: Some(443),
            protocol: Protocol::Tcp,
            state: ConnState::New,
            in_interface: None,
            out_interface: None,
        },
    );
    assert_eq!(verdict.action, Action::Deny);
}
