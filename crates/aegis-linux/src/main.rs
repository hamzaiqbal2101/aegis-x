//! AEGIS X Linux adapter CLI.
//!
//! Commands:
//!   render   --policy FILE                 Print the nftables script.
//!   check    --policy FILE [--no-conntrack]
//!                                      Render + `nft --check` (no changes).
//!   apply    --policy FILE [--netns NS | --confirm-host-apply]
//!             [--no-conntrack]           Apply the policy. Refuses to touch
//!                                      the host firewall unless
//!                                      --confirm-host-apply is given; the
//!                                      normal path is a network namespace.
//!                                      By default the adapter probes for
//!                                      kernel conntrack and REFUSES to
//!                                      apply if it is missing (fail closed:
//!                                      a policy must not silently lose
//!                                      stateful inspection). Pass
//!                                      --no-conntrack to explicitly apply
//!                                      a degraded policy without `ct`
//!                                      base rules; stateful user rules
//!                                      are then rejected as well.
//!   rollback [--netns NS | --confirm-host-apply]
//!                                      Re-apply the PREVIOUS policy and swap
//!                                      current/previous, so a second rollback
//!                                      undoes the first. Requires at least
//!                                      two successful applies in the state dir.
//!   eval     --policy FILE --src IP --dst IP [--sport N] [--dport N]
//!            [--proto tcp|udp|icmp|icmpv6|any] [--state new|established|related|invalid]
//!            [--iif NAME] [--oif NAME]       Evaluate one packet against the
//!                                      policy model (no OS interaction).
//!                                      NOTE: eval models the USER rules and
//!                                      the default action only. It does NOT
//!                                      model the base rules (established/
//!                                      related accept, loopback accept, ct
//!                                      invalid drop) or rate limits: an
//!                                      established packet denied by a rule
//!                                      evaluates as "deny" but is accepted
//!                                      by enforcement, and a rate-limited
//!                                      rule evaluates as if unthrottled.
//!                                      Treat eval as a rule-match check,
//!                                      not a full enforcement prediction.
//!
//! State (last known-good script + hash) lives in `--state-dir`
//! (default `/var/lib/aegis-x`). Rollback restores exactly that script.
//! Applies are atomic: the delete of the old table and the create of
//! the new one happen in a single `nft -f` transaction (see
//! `apply_script`), so a failed apply never leaves the namespace/host
//! without an aegis table.

mod render;

use aegis_core::matcher::EvalPacket;
use aegis_core::policy::{ConnState, Protocol};
use aegis_core::{
    detect_conflicts, evaluate, policy_hash, sha256_hex, ConflictKind, Policy,
};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};

const DEFAULT_STATE_DIR: &str = "/var/lib/aegis-x";

struct Args {
    cmd: String,
    policy: Option<PathBuf>,
    netns: Option<String>,
    confirm_host: bool,
    no_conntrack: bool,
    no_loopback_accept: bool,
    state_dir: PathBuf,
    // eval options
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    sport: Option<u16>,
    dport: Option<u16>,
    proto: Protocol,
    state: ConnState,
    iif: Option<String>,
    oif: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        return Err("usage: aegis-linux <render|check|apply|rollback|eval> [options]".into());
    }
    let mut a = Args {
        cmd: argv[0].clone(),
        policy: None,
        netns: None,
        confirm_host: false,
        no_conntrack: false,
        no_loopback_accept: false,
        state_dir: PathBuf::from(DEFAULT_STATE_DIR),
        src: None,
        dst: None,
        sport: None,
        dport: None,
        proto: Protocol::Any,
        state: ConnState::New,
        iif: None,
        oif: None,
    };
    let mut i = 1;
    while i < argv.len() {
        let flag = argv[i].as_str();
        let take = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            argv.get(*i)
                .cloned()
                .ok_or_else(|| format!("missing value for {flag}"))
        };
        match flag {
            "--policy" => a.policy = Some(PathBuf::from(take(&mut i)?)),
            "--netns" => a.netns = Some(take(&mut i)?),
            "--confirm-host-apply" => a.confirm_host = true,
            "--no-conntrack" => a.no_conntrack = true,
            "--no-loopback-accept" => a.no_loopback_accept = true,
            "--state-dir" => a.state_dir = PathBuf::from(take(&mut i)?),
            "--src" => {
                a.src = Some(
                    take(&mut i)?
                        .parse()
                        .map_err(|_| "invalid --src IP".to_string())?,
                )
            }
            "--dst" => {
                a.dst = Some(
                    take(&mut i)?
                        .parse()
                        .map_err(|_| "invalid --dst IP".to_string())?,
                )
            }
            "--sport" => {
                a.sport = Some(
                    take(&mut i)?
                        .parse()
                        .map_err(|_| "invalid --sport".to_string())?,
                )
            }
            "--dport" => {
                a.dport = Some(
                    take(&mut i)?
                        .parse()
                        .map_err(|_| "invalid --dport".to_string())?,
                )
            }
            "--proto" => {
                a.proto = match take(&mut i)?.as_str() {
                    "tcp" => Protocol::Tcp,
                    "udp" => Protocol::Udp,
                    "icmp" => Protocol::Icmp,
                    "icmpv6" => Protocol::Icmpv6,
                    "any" => Protocol::Any,
                    other => return Err(format!("invalid --proto {other}")),
                }
            }
            "--state" => {
                a.state = match take(&mut i)?.as_str() {
                    "new" => ConnState::New,
                    "established" => ConnState::Established,
                    "related" => ConnState::Related,
                    "invalid" => ConnState::Invalid,
                    other => return Err(format!("invalid --state {other}")),
                }
            }
            "--iif" => a.iif = Some(take(&mut i)?),
            "--oif" => a.oif = Some(take(&mut i)?),
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }
    Ok(a)
}

fn load_policy(path: &Path) -> Result<Policy, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Policy::from_json(&text)
}

/// Refuse app-scoped rules: the Linux adapter cannot enforce
/// application identity (nftables has no reliable app attribution), and
/// rendering such a rule without its app scope would silently broaden
/// it to all applications — a security hole. Fail closed instead:
/// app control is Windows-only until a real Linux mechanism exists.
fn gate_app_rules(policy: &Policy) -> Result<(), String> {
    for rule in &policy.rules {
        if let Some(app) = &rule.app {
            return Err(format!(
                "rule {} specifies app {app}; application control is Windows-only (WFP ALE) — refusing to apply on Linux",
                rule.id
            ));
        }
    }
    Ok(())
}

/// Refuse duplicates; warn on shadowing. Returns Err on duplicates.
fn gate_conflicts(policy: &Policy) -> Result<(), String> {
    let conflicts = detect_conflicts(policy);
    let mut fatal = false;
    for c in &conflicts {
        match c.kind {
            ConflictKind::Duplicate => {
                eprintln!(
                    "ERROR: rule {} duplicates earlier rule {} — refusing to apply",
                    c.shadowed_id, c.shadowing_id
                );
                fatal = true;
            }
            ConflictKind::Shadowed => {
                eprintln!(
                    "WARNING: rule {} is shadowed by earlier rule {}",
                    c.shadowed_id, c.shadowing_id
                );
            }
        }
    }
    if fatal {
        Err("duplicate rules present; fix the policy and retry".into())
    } else {
        Ok(())
    }
}

/// Write a script to a private temp file. The old code used a
/// predictable name (`aegis-<pid>.nft`) with `fs::write`, which
/// follows symlinks: an attacker who pre-created
/// `/tmp/aegis-<pid>.nft` as a symlink could get the CLI (often run
/// as root for nftables) to overwrite the link target. Now the file
/// is created with `create_new` (never following an existing path),
/// mode 0600, and a numeric suffix if the pid name is already taken.
fn write_temp(script: &str) -> Result<PathBuf, String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = std::env::temp_dir();
    for suffix in 0..100 {
        let path = if suffix == 0 {
            dir.join(format!("aegis-{}.nft", std::process::id()))
        } else {
            dir.join(format!("aegis-{}-{}.nft", std::process::id(), suffix))
        };
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut f) => {
                f.write_all(script.as_bytes())
                    .map_err(|e| format!("cannot write temp file: {e}"))?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot write temp file: {e}")),
        }
    }
    Err("cannot allocate temp file: all candidate names taken".into())
}

/// Resolve a system binary to an absolute path, preferring the
/// standard locations over PATH lookup (a hostile or accidental
/// PATH entry must not redirect the firewall's own tooling).
/// Falls back to the bare name (PATH lookup) only when none of the
/// known locations exists. (Review Nov 14, 2026: previously bare
/// "nft"/"ip" were PATH-resolved.)
fn resolve_bin(name: &str, candidates: &[&str]) -> String {
    for c in candidates {
        if Path::new(c).exists() {
            return c.to_string();
        }
    }
    name.to_string()
}

fn nft_bin() -> String {
    resolve_bin("nft", &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"])
}

fn ip_bin() -> String {
    resolve_bin("ip", &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"])
}

/// True if the `inet aegis` table currently exists in the target
/// scope. Used to pick the atomic replace variant (delete+create in
/// one transaction, which only works when the table exists) versus
/// create-only for a first apply.
fn table_exists(netns: &Option<String>) -> bool {
    let mut cmd = match netns {
        Some(ns) => {
            let mut c = Command::new(ip_bin());
            c.arg("netns").arg("exec").arg(ns).arg(nft_bin());
            c
        }
        None => Command::new(nft_bin()),
    };
    cmd.arg("list")
        .arg("table")
        .arg("inet")
        .arg("aegis")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// --check then apply one script file; the temp file is removed in
/// all paths.
fn check_and_apply(script: &str, netns: &Option<String>) -> Result<(), String> {
    let tmp = write_temp(script)?;
    let checked = run_nft_check(&tmp, netns);
    if let Err(e) = checked {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    let applied = run_nft(&tmp, netns);
    let _ = fs::remove_file(&tmp);
    applied.map(|_| ())
}

/// Apply a rendered script, choosing the variant that matches the
/// live state. The delete+create file only works when the table
/// exists; create-only only works when it does not (it MERGES into
/// an existing table, leaving stale rules). Probe first, then
/// --check the exact variant that will be applied, then apply it
/// once. If the apply fails, re-probe and retry once with the other
/// variant (covers a table deleted or created between probe and
/// apply). A failed apply leaves the previous ruleset untouched:
/// nft applies a whole -f file as one transaction.
/// (Review Nov 14, 2026: replaced the old delete-then-apply
/// two-step, which left a fail-open window with no aegis table
/// when the apply failed after the delete.)
fn apply_script(create_only: &str, replace: &str, netns: &Option<String>) -> Result<(), String> {
    let use_replace = table_exists(netns);
    let (first, second) = if use_replace {
        (replace, create_only)
    } else {
        (create_only, replace)
    };
    match check_and_apply(first, netns) {
        Ok(()) => Ok(()),
        Err(e) => {
            // The live state may have changed between probe and
            // apply (or the variant choice was wrong): re-probe and
            // try the other variant once.
            if table_exists(netns) == use_replace {
                return Err(e);
            }
            check_and_apply(second, netns)
                .map_err(|e2| format!("apply failed with both variants ({e}; retry: {e2})"))
        }
    }
}

/// Run nft (optionally inside a netns). Returns stdout on success.
fn run_nft(script_path: &Path, netns: &Option<String>) -> Result<String, String> {
    let mut cmd = match netns {
        Some(ns) => {
            let mut c = Command::new(ip_bin());
            c.arg("netns").arg("exec").arg(ns).arg(nft_bin());
            c
        }
        None => Command::new(nft_bin()),
    };
    let out = cmd
        .arg("-f")
        .arg(script_path)
        .output()
        .map_err(|e| format!("failed to run nft: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(format!(
            "nft failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// `nft --check` in the target scope (inside the netns when given).
/// Note: even `--check` talks to the kernel, so it needs the same
/// privileges as applying (CAP_NET_ADMIN in the target namespace).
fn run_nft_check(script_path: &Path, netns: &Option<String>) -> Result<(), String> {
    let mut cmd = match netns {
        Some(ns) => {
            let mut c = Command::new(ip_bin());
            c.arg("netns").arg("exec").arg(ns).arg(nft_bin());
            c
        }
        None => Command::new(nft_bin()),
    };
    let out = cmd
        .arg("--check")
        .arg("-f")
        .arg(script_path)
        .output()
        .map_err(|e| format!("failed to run nft --check: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "nft --check failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Probe whether the target kernel supports conntrack (`ct`) rules.
/// Returns false on any failure (fail closed: an unproven kernel is
/// treated as lacking conntrack).
fn conntrack_available(netns: &Option<String>) -> bool {
    let probe = "table inet aegis-probe {\n  chain c {\n    type filter hook input priority filter; policy drop;\n    ct state established accept\n  }\n}\n";
    let tmp = match write_temp(probe) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let ok = run_nft_check(&tmp, netns).is_ok();
    let _ = fs::remove_file(&tmp);
    ok
}

/// Decide the conntrack mode for check/apply, fail-closed.
/// Returns the mode to render with.
fn resolve_conntrack(a: &Args, policy: &Policy) -> Result<bool, String> {
    if a.no_conntrack {
        if policy.rules.iter().any(|r| !r.states.is_empty()) {
            return Err(
                "--no-conntrack cannot be used with rules that specify connection \
                 states; remove the states or run on a kernel with nf_conntrack"
                    .into(),
            );
        }
        eprintln!(
            "WARNING: applying WITHOUT stateful (ct) base rules — degraded mode, \
             explicitly requested via --no-conntrack"
        );
        return Ok(false);
    }
    if !conntrack_available(&a.netns) {
        return Err(
            "kernel lacks nf_conntrack (stateful inspection unavailable). Refusing \
             to apply a policy that claims stateful protection. Re-run with \
             --no-conntrack to explicitly apply a degraded policy without `ct` \
             base rules"
                .into(),
        );
    }
    Ok(true)
}

fn require_scope(a: &Args) -> Result<(), String> {
    if a.netns.is_none() && !a.confirm_host {
        return Err(
            "refusing to touch the host firewall: pass --netns <name> or \
             --confirm-host-apply"
                .into(),
        );
    }
    Ok(())
}

/// Ensure the state dir exists, owned by root, mode 0700: it holds
/// the live firewall's source of truth (the scripts rollback will
/// apply), so no other user may read or write it.
fn ensure_state_dir(a: &Args) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(&a.state_dir)
        .map_err(|e| format!("cannot create state dir: {e}"))?;
    fs::set_permissions(&a.state_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("cannot restrict state dir: {e}"))?;
    Ok(())
}

/// Write `contents` to `dir/name` atomically: create a temp file in
/// the same directory (O_EXCL, mode 0600), write, then rename over
/// the destination. Never follows a pre-existing symlink at the
/// destination (rename replaces the link itself), and a crash
/// mid-write cannot leave a half-written script.
/// (Review Nov 14, 2026: previously `fs::write` followed symlinks
/// and wrote in place.)
fn write_state_file(dir: &Path, name: &str, contents: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dest = dir.join(name);
    for suffix in 0..100 {
        let tmp = if suffix == 0 {
            dir.join(format!(".{name}.tmp-{}", std::process::id()))
        } else {
            dir.join(format!(".{name}.tmp-{}-{suffix}", std::process::id()))
        };
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(mut f) => {
                f.write_all(contents)
                    .map_err(|e| format!("cannot write state file {name}: {e}"))?;
                drop(f);
                fs::rename(&tmp, &dest)
                    .map_err(|e| format!("cannot install state file {name}: {e}"))?;
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot write state file {name}: {e}")),
        }
    }
    Err(format!("cannot allocate state temp file for {name}"))
}

/// State layout: `current.nft` (last successfully applied policy)
/// and `previous.nft` (the one before it), plus `current.hash` /
/// `previous.hash` (policy hashes) and `current.script_hash` /
/// `previous.script_hash` (SHA-256 of the script itself — rollback
/// verifies it before applying, so a tampered state file cannot
/// smuggle arbitrary nft script into the firewall). A successful
/// apply rotates current -> previous, then writes the new current.
/// Rollback applies previous and swaps the two files, so rollback
/// is itself reversible. Rotation is by rename (never copy: a copy
/// follows symlinks).
fn save_current(a: &Args, script: &str, hash: &str) -> Result<(), String> {
    ensure_state_dir(a)?;
    let current = a.state_dir.join("current.nft");
    if current.exists() {
        fs::rename(&current, a.state_dir.join("previous.nft"))
            .map_err(|e| format!("cannot rotate previous policy: {e}"))?;
        let current_hash = a.state_dir.join("current.hash");
        if current_hash.exists() {
            fs::rename(&current_hash, a.state_dir.join("previous.hash"))
                .map_err(|e| format!("cannot rotate previous hash: {e}"))?;
        }
        let current_script_hash = a.state_dir.join("current.script_hash");
        if current_script_hash.exists() {
            fs::rename(
                &current_script_hash,
                a.state_dir.join("previous.script_hash"),
            )
            .map_err(|e| format!("cannot rotate previous script hash: {e}"))?;
        }
    }
    write_state_file(&a.state_dir, "current.nft", script.as_bytes())?;
    write_state_file(&a.state_dir, "current.hash", hash.as_bytes())?;
    write_state_file(
        &a.state_dir,
        "current.script_hash",
        sha256_hex(script.as_bytes()).as_bytes(),
    )?;
    Ok(())
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            exit(2);
        }
    };
    let result = match args.cmd.as_str() {
        "render" => cmd_render(&args),
        "check" => cmd_check(&args),
        "apply" => cmd_apply(&args),
        "rollback" => cmd_rollback(&args),
        "eval" => cmd_eval(&args),
        other => Err(format!("unknown command: {other}")),
    };
    if let Err(e) = result {
        eprintln!("ERROR: {e}");
        exit(1);
    }
}

fn need_policy(a: &Args) -> Result<PathBuf, String> {
    a.policy
        .clone()
        .ok_or_else(|| "--policy FILE is required".to_string())
}

fn cmd_render(a: &Args) -> Result<(), String> {
    let policy = load_policy(&need_policy(a)?)?;
    // Render used to skip the gates check/apply enforce, so it
    // printed a deployable-looking script for app-scoped rules
    // (broadened to all apps: the app scope was simply dropped) and
    // for duplicate policies that check/apply refuse. A printed
    // script that an operator pipes into `nft -f` is an enforcement
    // path, so render gates exactly like check/apply.
    gate_app_rules(&policy)?;
    gate_conflicts(&policy)?;
    // Honor --no-conntrack so operators can preview the degraded
    // script (the default render includes `ct` base rules, which fail
    // on kernels without nf_conntrack), and --no-loopback-accept,
    // which render previously ignored in both branches (the preview
    // then disagreed with what check/apply would install).
    print!(
        "{}",
        render::render_opts(
            &policy,
            render::RenderOptions {
                conntrack: !a.no_conntrack,
                loopback_accept: !a.no_loopback_accept,
            }
        )
    );
    Ok(())
}

fn cmd_check(a: &Args) -> Result<(), String> {
    let policy = load_policy(&need_policy(a)?)?;
    gate_app_rules(&policy)?;
    gate_conflicts(&policy)?;
    let conntrack = resolve_conntrack(a, &policy)?;
    let script = render::render_opts(
        &policy,
        render::RenderOptions {
            conntrack,
            loopback_accept: !a.no_loopback_accept,
        },
    );
    let tmp = write_temp(&script)?;
    let checked = run_nft_check(&tmp, &a.netns);
    let _ = fs::remove_file(&tmp);
    checked?;
    println!("OK: policy \"{}\" renders and passes nft --check", policy.name);
    println!("policy hash: {}", policy_hash(&policy));
    println!("conntrack: {conntrack}");
    Ok(())
}

fn cmd_apply(a: &Args) -> Result<(), String> {
    require_scope(a)?;
    let policy = load_policy(&need_policy(a)?)?;
    gate_app_rules(&policy)?;
    gate_conflicts(&policy)?;
    let conntrack = resolve_conntrack(a, &policy)?;
    let opts = render::RenderOptions {
        conntrack,
        loopback_accept: !a.no_loopback_accept,
    };
    // Atomic replace: the delete of the old table and the create of
    // the new one happen in one nft transaction (see apply_script),
    // so a failed apply leaves the previous ruleset in place.
    let create_only = render::render_opts(&policy, opts);
    let replace = render::render_replace(&policy, opts);
    apply_script(&create_only, &replace, &a.netns)?;
    let hash = policy_hash(&policy);
    save_current(a, &create_only, &hash)?;
    match &a.netns {
        Some(ns) => println!("OK: policy \"{}\" applied in netns {ns}", policy.name),
        None => println!(
            "OK: policy \"{}\" applied to host (explicitly confirmed)",
            policy.name
        ),
    }
    println!("policy hash: {hash}");
    Ok(())
}

fn cmd_rollback(a: &Args) -> Result<(), String> {
    require_scope(a)?;
    // --policy is silently ignored by rollback (it restores the
    // previous applied policy from --state-dir), so accepting it
    // would let an operator believe they rolled back to a chosen
    // file when they did not. Reject it outright.
    if a.policy.is_some() {
        return Err(
            "--policy is not used by rollback: rollback restores the previous \
             applied policy from --state-dir"
                .into(),
        );
    }
    let previous = a.state_dir.join("previous.nft");
    let script = fs::read_to_string(&previous).map_err(|_| {
        format!(
            "no previous policy in {} — nothing to roll back to (apply at least twice first)",
            a.state_dir.display()
        )
    })?;
    // Verify the stored script before applying it: the state dir is
    // the firewall's source of truth, and until now nothing checked
    // that the script in it was the one apply wrote. A tampered
    // previous.nft could have contained arbitrary nft script
    // (including flushing other tables). The hash file must exist
    // and match; state dirs created by older versions have no
    // script hash — re-apply twice to re-establish verified state.
    // (Review Nov 14, 2026.)
    let expected_hash = fs::read_to_string(a.state_dir.join("previous.script_hash"))
        .map_err(|_| {
            "previous.script_hash is missing — refusing to apply an \
             unauthenticated stored script (state dir from an older \
             version: apply twice to re-establish verified state)"
                .to_string()
        })?;
    if expected_hash.trim() != sha256_hex(script.as_bytes()) {
        return Err(
            "previous script hash mismatch — the stored rollback script \
             has been modified; refusing to apply it"
                .into(),
        );
    }
    // The swap below must have a real current policy to move into
    // "previous": previously a missing current.nft was replaced with
    // an empty byte string, poisoning "previous" so the next rollback
    // would apply an empty script (deleting the aegis table with no
    // replacement). Check before touching the firewall.
    let current = a.state_dir.join("current.nft");
    if !current.exists() {
        return Err(format!(
            "no current policy in {} — refusing to roll back with nowhere to swap to",
            a.state_dir.display()
        ));
    }
    // Read all swap values before writing any of them.
    let old_current = fs::read(&current).map_err(|e| format!("cannot read current: {e}"))?;
    let old_current_hash = fs::read(a.state_dir.join("current.hash")).unwrap_or_default();
    let old_current_script_hash =
        fs::read(a.state_dir.join("current.script_hash")).unwrap_or_default();
    let prev_hash = fs::read(a.state_dir.join("previous.hash")).unwrap_or_default();
    let prev_script_hash = fs::read(a.state_dir.join("previous.script_hash")).unwrap_or_default();
    // Apply the stored (create-only) script atomically.
    let replace = format!("delete table inet aegis\n{script}");
    apply_script(&script, &replace, &a.netns)?;
    // Swap so rollback is reversible: the policy we just replaced
    // becomes the new "previous". Atomic writes (temp + rename).
    write_state_file(&a.state_dir, "current.nft", script.as_bytes())?;
    write_state_file(&a.state_dir, "current.hash", &prev_hash)?;
    write_state_file(&a.state_dir, "current.script_hash", &prev_script_hash)?;
    write_state_file(&a.state_dir, "previous.nft", &old_current)?;
    write_state_file(&a.state_dir, "previous.hash", &old_current_hash)?;
    write_state_file(&a.state_dir, "previous.script_hash", &old_current_script_hash)?;
    println!("OK: rolled back to previous policy (rollback again to undo)");
    Ok(())
}

fn cmd_eval(a: &Args) -> Result<(), String> {
    let policy = load_policy(&need_policy(a)?)?;
    let src = a.src.ok_or("--src IP is required for eval")?;
    let dst = a.dst.ok_or("--dst IP is required for eval")?;
    let pkt = EvalPacket {
        src_ip: src,
        dst_ip: dst,
        src_port: a.sport,
        dst_port: a.dport,
        protocol: a.proto,
        state: a.state,
        in_interface: a.iif.clone(),
        out_interface: a.oif.clone(),
    };
    let verdict = evaluate(&policy, &pkt);
    println!("action: {:?}", verdict.action);
    println!(
        "rule: {}",
        verdict.rule_id.as_deref().unwrap_or("(default/base)")
    );
    println!("reason: {}", verdict.reason);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: &str) -> Policy {
        Policy::from_json(json).unwrap()
    }

    #[test]
    fn pentest_gate_app_rules_refuses_app_scoped_policy() {
        let p = policy(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"app-only","priority":10,"action":"allow","protocol":"tcp",
               "dst_port":443,"app":"C:\\Apps\\browser.exe"}]}"#,
        );
        assert!(gate_app_rules(&p).is_err());
        let clean = policy(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"web","priority":10,"action":"allow","protocol":"tcp","dst_port":443}]}"#,
        );
        assert!(gate_app_rules(&clean).is_ok());
    }

    #[test]
    fn pentest_gate_conflicts_refuses_duplicates_but_warns_on_shadowed() {
        let dup = policy(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"a","priority":10,"action":"allow","protocol":"tcp","dst_port":53},
              {"id":"b","priority":20,"action":"allow","protocol":"tcp","dst_port":53}]}"#,
        );
        assert!(gate_conflicts(&dup).is_err());
        let shadowed = policy(
            r#"{"version":1,"name":"t","default_action":"deny","rules":[
              {"id":"deny-web","priority":10,"action":"deny","protocol":"tcp","dst_port":443},
              {"id":"allow-lan","priority":20,"action":"allow","protocol":"tcp",
               "src_addrs":["192.168.0.0/16"],"dst_port":443}]}"#,
        );
        assert!(gate_conflicts(&shadowed).is_ok());
    }

    #[test]
    fn pentest_write_temp_never_follows_a_precreated_symlink() {
        // Pre-create the exact pid-named path as a symlink to a victim
        // file, as an attacker would. write_temp must not overwrite
        // the victim; it must fall through to a fresh suffixed path.
        let dir = std::env::temp_dir();
        let victim = dir.join(format!("aegis-victim-{}.txt", std::process::id()));
        let link = dir.join(format!("aegis-{}.nft", std::process::id()));
        let _ = fs::remove_file(&victim);
        let _ = fs::remove_file(&link);
        fs::write(&victim, "do not overwrite").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let out = write_temp("table inet aegis {}");
        let path = out.expect("write_temp must succeed via a suffixed name");
        assert_ne!(path, link);
        assert_eq!(fs::read_to_string(&victim).unwrap(), "do not overwrite");
        assert_eq!(fs::read_to_string(&path).unwrap(), "table inet aegis {}");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&victim);
        let _ = fs::remove_file(&link);
    }

    // --- Review Nov 14, 2026: atomic state writes ---

    #[test]
    fn review_write_state_file_never_follows_a_symlink() {
        // Pre-create the destination as a symlink to a victim file.
        // write_state_file must replace the LINK, not write through
        // it into the victim.
        let dir = std::env::temp_dir().join(format!("aegis-state-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim.txt");
        fs::write(&victim, "do not overwrite").unwrap();
        let link = dir.join("current.nft");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        write_state_file(&dir, "current.nft", b"new script").unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "do not overwrite");
        // The destination is now a real file with the new content
        // (the symlink was replaced by rename).
        assert_eq!(fs::read_to_string(&link).unwrap(), "new script");
        assert!(!fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn review_save_current_writes_script_hash() {
        let dir = std::env::temp_dir().join(format!("aegis-save-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let args = Args {
            cmd: "apply".to_string(),
            policy: None,
            netns: None,
            confirm_host: false,
            no_conntrack: false,
            no_loopback_accept: false,
            state_dir: dir.clone(),
            src: None,
            dst: None,
            sport: None,
            dport: None,
            proto: Protocol::Any,
            state: ConnState::New,
            iif: None,
            oif: None,
        };
        let script = "table inet aegis {\n  chain input {\n    type filter hook input priority filter; policy drop;\n  }\n}\n";
        save_current(&args, script, "deadbeef").unwrap();
        assert_eq!(fs::read_to_string(dir.join("current.nft")).unwrap(), script);
        assert_eq!(fs::read_to_string(dir.join("current.hash")).unwrap(), "deadbeef");
        assert_eq!(
            fs::read_to_string(dir.join("current.script_hash")).unwrap(),
            sha256_hex(script.as_bytes())
        );
        // State dir is locked down.
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        // A second save rotates current -> previous, including the
        // script hash.
        let script2 = "table inet aegis {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    tcp dport 80 counter accept\n  }\n}\n";
        save_current(&args, script2, "cafe").unwrap();
        assert_eq!(fs::read_to_string(dir.join("previous.nft")).unwrap(), script);
        assert_eq!(
            fs::read_to_string(dir.join("previous.script_hash")).unwrap(),
            sha256_hex(script.as_bytes())
        );
        assert_eq!(fs::read_to_string(dir.join("current.nft")).unwrap(), script2);
        let _ = fs::remove_dir_all(&dir);
    }
}
