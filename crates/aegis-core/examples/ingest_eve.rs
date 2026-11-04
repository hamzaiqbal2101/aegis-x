//! Ingest a real eve.json file through the Suricata module and print
//! the resulting timed block decisions. Test tooling only — this does
//! not enforce anything, it only shows what the module would block.
//!
//! Usage: cargo run -p aegis-core --example ingest_eve -- /path/to/eve.json

use aegis_core::suricata::{ingest_eve_log, is_active, SuricataConfig};
use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let path = env::args()
        .nth(1)
        .expect("usage: ingest_eve <eve.json path>");
    let log = fs::read_to_string(&path).expect("cannot read eve.json");
    let total_lines = log.lines().filter(|l| !l.trim().is_empty()).count();
    let cfg = SuricataConfig::default();
    match ingest_eve_log(&log, cfg) {
        Ok(decisions) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock before epoch")
                .as_secs();
            println!("lines: {total_lines}");
            println!("decisions: {}", decisions.len());
            for d in &decisions {
                println!(
                    "BLOCK {} until {} (active now: {}) reason: {} signature: {}",
                    d.ip,
                    d.expires_at_unix,
                    is_active(d, now),
                    d.reason,
                    d.signature
                );
            }
        }
        Err(e) => {
            println!("INGEST ERROR: {e}");
            std::process::exit(1);
        }
    }
}
