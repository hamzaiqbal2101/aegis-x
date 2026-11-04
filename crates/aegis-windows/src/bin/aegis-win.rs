//! aegis-win — Windows WFP installer CLI.
//!
//! Usage (Administrator PowerShell on Windows 10/11):
//!   aegis-win install --policy FILE     Install a policy into WFP
//!   aegis-win uninstall                 Remove all AEGIS filters/provider
//!   aegis-win status                    Check WFP engine access
//!   aegis-win diag                      Read-only: report what holds the
//!                                       provider/sublayer keys
//!   aegis-win remove-old                Delete the old (pre-Nov-3) keys,
//!                                       reporting every Win32 code
//!
//! On non-Windows platforms every command reports "Windows only".
//! Install refuses duplicate rule ids and warns on shadowed rules,
//! mirroring the Linux CLI's gates.

use aegis_core::{detect_conflicts, Policy};
use aegis_windows::engine;
use std::env;
use std::fs;
use std::process::ExitCode;

struct Args {
    cmd: String,
    policy: Option<String>,
}

fn parse() -> Result<Args, String> {
    let argv: Vec<String> = env::args().skip(1).collect();
    if argv.is_empty() {
        return Err("usage: aegis-win <install --policy FILE | uninstall | status>".into());
    }
    let cmd = argv[0].clone();
    let mut policy = None;
    let mut i = 1;
    while i < argv.len() {
        if argv[i] == "--policy" && i + 1 < argv.len() {
            policy = Some(argv[i + 1].clone());
            i += 2;
        } else {
            return Err(format!("unknown argument: {}", argv[i]));
        }
    }
    Ok(Args { cmd, policy })
}

fn load_policy(path: &str) -> Result<Policy, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("cannot read policy {path}: {e}"))?;
    Policy::from_json(&text)
}

fn gate(policy: &Policy) -> Result<(), String> {
    let mut ids = std::collections::HashSet::new();
    for rule in &policy.rules {
        if !ids.insert(rule.id.as_str()) {
            return Err(format!("duplicate rule id: {}", rule.id));
        }
    }
    for c in detect_conflicts(policy) {
        eprintln!(
            "WARNING: rule {} is shadowed by {} ({:?})",
            c.shadowed_id, c.shadowing_id, c.kind
        );
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let a = parse()?;
    match a.cmd.as_str() {
        "install" => {
            let path = a
                .policy
                .ok_or("install requires --policy FILE")?;
            let policy = load_policy(&path)?;
            gate(&policy)?;
            let report = engine::install_policy(&policy)?;
            println!(
                "installed {} WFP filters (provider {}, sublayer {})",
                report.filters_installed, report.provider_key, report.sublayer_key
            );
            Ok(())
        }
        "uninstall" => {
            engine::uninstall()?;
            println!("AEGIS filters and provider removed from WFP");
            Ok(())
        }
        "status" => {
            println!("{}", engine::status()?);
            Ok(())
        }
        "diag" => {
            println!("{}", engine::diag()?);
            Ok(())
        }
        "remove-old" => {
            println!("{}", engine::remove_old()?);
            Ok(())
        }
        other => Err(format!("unknown command: {other}")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aegis-win: {e}");
            ExitCode::FAILURE
        }
    }
}
