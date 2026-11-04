#![no_main]

//! Coverage-guided fuzz target for the AEGIS X policy parser.
//!
//! This is the real fuzzer counterpart to the deterministic
//! property tests in `crates/aegis-core/src/property_tests.rs`
//! (which are explicitly fuzz-lite, not a fuzzer).
//!
//! What it exercises, on every input:
//!   1. `Policy::from_json` on arbitrary bytes that are valid UTF-8
//!      (the parser takes `&str`, so invalid UTF-8 can never reach
//!      it — that boundary is a caller/serde concern, not a parser
//!      bug, and is covered by property tests instead).
//!   2. If parsing succeeds, `matcher::evaluate` / `rule_matches`
//!      on a small fixed packet set (TCP/UDP/ICMP, v4/v6, valid and
//!      invalid connection states), plus re-serialization of the
//!      parsed policy (exercises `Cidr` / `PortSpec` serializers).
//!
//! Deliberately a no-panic oracle only: it asserts no invariant
//! beyond "parsing, matching and serializing must not panic, hang
//! or crash". Stronger invariants (round-trip equality,
//! idempotent re-parse) live in `property_tests.rs`, where a
//! failure is a readable test failure rather than a fuzzer crash,
//! and where a concurrent edit to the parser cannot turn this
//! target into a false-positive crash report.
//!
//! Run (nightly required, libFuzzer):
//!   export PATH="$HOME/.cargo/bin:$PATH"
//!   cd ~/workspace/aegis-x
//!   cargo fuzz run policy_parser -- -max_total_time=180
//! Reproduce a crash:
//!   cargo fuzz run policy_parser fuzz/artifacts/policy_parser/<file>

use aegis_core::policy::Policy;
use aegis_core::{evaluate, ConnState, EvalPacket, Protocol};
use libfuzzer_sys::fuzz_target;
use std::net::IpAddr;

fn packets() -> Vec<EvalPacket> {
    let v4_src: IpAddr = "203.0.113.7".parse().unwrap();
    let v4_dst: IpAddr = "10.0.0.5".parse().unwrap();
    let v6_dst: IpAddr = "2001:db8::5".parse().unwrap();
    let mut pkts = Vec::new();
    for protocol in [Protocol::Tcp, Protocol::Udp, Protocol::Icmp, Protocol::Any] {
        for state in [ConnState::New, ConnState::Established, ConnState::Invalid] {
            pkts.push(EvalPacket {
                src_ip: v4_src,
                dst_ip: v4_dst,
                src_port: Some(40000),
                dst_port: Some(443),
                protocol,
                state,
                in_interface: None,
                out_interface: None,
            });
        }
    }
    // One IPv6 packet (exercises the v6 CIDR mask path in matching).
    pkts.push(EvalPacket {
        src_ip: v4_src,
        dst_ip: v6_dst,
        src_port: Some(40000),
        dst_port: Some(443),
        protocol: Protocol::Tcp,
        state: ConnState::New,
        in_interface: None,
        out_interface: None,
    });
    // One port-less packet (ICMP-shaped).
    pkts.push(EvalPacket {
        src_ip: v4_src,
        dst_ip: v4_dst,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Icmp,
        state: ConnState::New,
        in_interface: None,
        out_interface: None,
    });
    pkts
}

fuzz_target!(|data: &[u8]| {
    // Boundary: Policy::from_json takes &str. Non-UTF-8 bytes are
    // rejected before the parser; skipping them is correct, not a
    // coverage hole in the parser itself.
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Guard against pathological inputs spending the whole fuzz run
    // in one parse: serde_json itself caps recursion (128) and
    // returns Err on deep nesting, but a multi-MB flat array of
    // rules is still legal input, so cap at 1 MiB — well above any
    // real policy — to keep executions/second meaningful.
    if text.len() > 1_048_576 {
        return;
    }
    if let Ok(policy) = Policy::from_json(text) {
        let pkts = packets();
        for pkt in &pkts {
            let _verdict = evaluate(&policy, pkt);
        }
        // Exercise serializers (Cidr, PortSpec, Zone) on real output.
        let _ = serde_json::to_string(&policy);
    }
});
