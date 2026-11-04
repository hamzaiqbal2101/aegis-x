//! DNS policy + tunneling-heuristic demo on realistic names.
//! Test tooling only — this analyzes name strings, it does not
//! intercept, proxy, or resolve DNS.
//!
//! Usage: cargo run -p aegis-core --example dns_check

use aegis_core::dns::{analyze_name, DnsConfig, DnsPolicy};

fn main() {
    let policy = DnsPolicy {
        blocklist: vec!["evil.example.com".to_string()],
        allowlist: vec!["ok.evil.example.com".to_string()],
    };
    let names = [
        "evil.example.com",
        "sub.evil.example.com",
        "ok.evil.example.com",
        "good.example.com",
        "EVIL.EXAMPLE.COM.",
    ];
    for name in names {
        println!("{name} -> {:?}", policy.verdict(name));
    }
    let cfg = DnsConfig::default();
    let probe = [
        "www.google.com",
        "aGVsbG9Xb3JsZEhJSjEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg.example.com",
        "a.b.c.d.e.f.g.example.com",
    ];
    for name in probe {
        let a = analyze_name(name, cfg);
        println!(
            "{name} -> suspicious: {} reasons: {:?} labels: {} longest-label entropy: {:.2}",
            a.suspicious, a.reasons, a.label_count, a.longest_label_entropy
        );
    }
}
