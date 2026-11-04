//! Criterion benchmarks for the aegis-core policy-engine hot paths.
//!
//! Pure userspace only: no nftables, WFP, kernel, network, or filesystem
//! access. Policies are small and fixed so a run finishes quickly.
//! `black_box` is used on inputs/outputs so the optimizer cannot
//! eliminate the work being measured.

use aegis_core::{
    evaluate, policy_hash, rule_matches, ConnState, EvalPacket, Policy, Protocol,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

/// Small fixed policy: 3 rules (allow web, allow LAN SSH, deny telnet).
const SMALL_POLICY_JSON: &str = r#"{"version":1,"name":"bench","default_action":"deny","rules":[
  {"id":"allow-web","priority":10,"action":"allow","protocol":"tcp","dst_port":443},
  {"id":"allow-ssh-lan","priority":20,"action":"allow","protocol":"tcp",
   "src_addrs":["192.168.0.0/16"],"dst_port":22},
  {"id":"deny-telnet","priority":30,"action":"deny","protocol":"tcp","dst_port":23}
]}"#;

/// Same shape as SMALL_POLICY_JSON, but with a zone expanded at load time.
const ZONE_POLICY_JSON: &str = r#"{"version":1,"name":"bench-zone","default_action":"deny",
  "zones":[{"name":"lan","subnets":["192.168.0.0/16","10.0.0.0/8"]}],
  "rules":[
    {"id":"allow-web-lan","priority":10,"action":"allow","protocol":"tcp",
     "src_zone":"lan","dst_port":443},
    {"id":"deny-telnet","priority":20,"action":"deny","protocol":"tcp","dst_port":23}
  ]}"#;

fn small_policy() -> Policy {
    Policy::from_json(SMALL_POLICY_JSON).expect("bench policy must parse")
}

fn packet(dst_port: u16, src_ip: &str) -> EvalPacket {
    EvalPacket {
        src_ip: src_ip.parse().unwrap(),
        dst_ip: "10.0.0.5".parse().unwrap(),
        src_port: Some(40000),
        dst_port: Some(dst_port),
        protocol: Protocol::Tcp,
        state: ConnState::New,
        in_interface: None,
        out_interface: None,
    }
}

fn bench_parse(c: &mut Criterion) {
    c.bench_function("policy_parse_small", |b| {
        b.iter(|| Policy::from_json(black_box(SMALL_POLICY_JSON)).unwrap());
    });
    c.bench_function("policy_parse_zone", |b| {
        b.iter(|| Policy::from_json(black_box(ZONE_POLICY_JSON)).unwrap());
    });
}

fn bench_evaluate(c: &mut Criterion) {
    let policy = small_policy();
    // Matches the first rule: cheapest evaluate path.
    let first = packet(443, "203.0.113.7");
    c.bench_function("evaluate_first_match", |b| {
        b.iter(|| evaluate(black_box(&policy), black_box(&first)));
    });
    // Matches no rule: scans all rules, then falls to default deny.
    let nomatch = packet(8080, "203.0.113.7");
    c.bench_function("evaluate_default_deny", |b| {
        b.iter(|| evaluate(black_box(&policy), black_box(&nomatch)));
    });
    // Single-rule matcher, bypassing the evaluate loop.
    let rule = &policy.rules[0];
    c.bench_function("rule_matches_single", |b| {
        b.iter(|| rule_matches(black_box(rule), black_box(&first)));
    });
}

fn bench_hash(c: &mut Criterion) {
    let policy = small_policy();
    c.bench_function("policy_hash_small", |b| {
        b.iter(|| policy_hash(black_box(&policy)));
    });
}

criterion_group!(benches, bench_parse, bench_evaluate, bench_hash);
criterion_main!(benches);
