//! Suricata eve.json alert ingestion — timed blocks from IDS alerts.
//!
//! PLAIN-WORDS SCOPE: this module only READS alert records that a
//! Suricata instance has already written to its `eve.json` log file
//! (one JSON object per line) and turns qualifying alerts into timed
//! block decisions (an IP to block, until an expiry time, with a
//! reason). It does NOT run Suricata, it does NOT inspect packets,
//! and it does NOT detect anything on its own.
//!
//! Live detection still needs a real Suricata binary plus a ruleset
//! installed and running on the deployment host, writing eve.json
//! that this code then ingests. No Suricata binary or ruleset is
//! installed in this sandbox, and nothing here claims otherwise.
//! The caller is responsible for feeding this module real eve.json
//! lines and for handing the resulting `BlockDecision`s to an
//! enforcement adapter; this module performs no blocking itself.
//!
//! Semantics:
//! * Only records with `event_type == "alert"` can produce a decision.
//!   Any other event type (e.g. `flow`, `dns`) parses to `None`
//!   ("not an alert"), never an error.
//! * A line that is not valid JSON, or an alert record missing the
//!   fields a decision needs, is an `Err`. Nothing here panics on
//!   input data: bad input is reported, never crashed on.
//! * Suricata severity runs 1 (most severe) to higher numbers (less
//!   severe). Only alerts with `severity <= threshold` produce a
//!   block; a higher (less severe) number is skipped, not an error.
//! * Expiry is the alert's timestamp plus the configured block
//!   duration, in whole Unix seconds. Fractional seconds in the
//!   timestamp are truncated (a block measured in seconds does not
//!   need sub-second precision).
//! * A decision is active while `now < expires_at_unix` and expired
//!   once `now >= expires_at_unix`.
//!
//! All functions here are pure: they take text and a config and
//! return decisions. No I/O, no clocks, no global state. The caller
//! supplies `now` wherever time matters, so tests can pin it exactly.

use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

/// How alert ingestion turns alerts into timed blocks.
#[derive(Debug, Clone, Copy)]
pub struct SuricataConfig {
    /// How long a block lasts, in seconds, from the alert timestamp.
    pub block_duration_secs: u64,
    /// Only alerts with `severity <= severity_threshold` are blocked.
    /// Lower Suricata severity numbers are MORE severe.
    pub severity_threshold: u8,
}

impl Default for SuricataConfig {
    fn default() -> Self {
        SuricataConfig {
            block_duration_secs: 3600,
            severity_threshold: 2,
        }
    }
}

/// A timed block decision derived from one Suricata alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDecision {
    /// The alert's source address: the host to block.
    pub ip: IpAddr,
    /// Unix seconds; the block is active while `now < expires_at_unix`.
    pub expires_at_unix: u64,
    /// Human-readable reason, e.g. the alert category and signature.
    pub reason: String,
    /// The Suricata rule signature that fired.
    pub signature: String,
}

/// The `alert` object inside an eve.json alert record.
#[derive(Debug, Deserialize)]
struct RawAlert {
    #[serde(default)]
    signature: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    severity: Option<u8>,
}

/// One eve.json line. Every field is optional at this layer on
/// purpose: a non-alert record must be skippable even if it lacks
/// alert fields, and missing alert fields are reported as errors
/// only once the record is known to be an alert.
#[derive(Debug, Deserialize)]
struct RawEve {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    event_type: Option<String>,
    #[serde(default)]
    src_ip: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    dest_ip: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    dest_port: Option<u16>,
    #[serde(default)]
    #[allow(dead_code)]
    proto: Option<String>,
    #[serde(default)]
    alert: Option<RawAlert>,
}

/// Parse one eve.json line.
///
/// * `Ok(None)` — valid JSON, but not an alert (other event type),
///   or an alert whose severity is above (less severe than) the
///   threshold. Both are "no block", not errors.
/// * `Ok(Some(decision))` — an alert that qualifies for a block.
/// * `Err(...)` — malformed JSON, or an alert record missing or
///   mangling a field a decision needs (timestamp, source IP,
///   signature, severity). Never a panic.
pub fn parse_eve_line(line: &str, cfg: SuricataConfig) -> Result<Option<BlockDecision>, String> {
    let raw: RawEve =
        serde_json::from_str(line).map_err(|e| format!("eve JSON: {e}"))?;
    if raw.event_type.as_deref() != Some("alert") {
        return Ok(None);
    }
    let alert = raw
        .alert
        .ok_or_else(|| "alert record has no alert object".to_string())?;
    let severity = alert
        .severity
        .ok_or_else(|| "alert record has no alert.severity".to_string())?;
    if severity > cfg.severity_threshold {
        return Ok(None);
    }
    if alert.signature.is_empty() {
        return Err("alert record has no alert.signature".to_string());
    }
    let ts_text = raw
        .timestamp
        .ok_or_else(|| "alert record has no timestamp".to_string())?;
    let ts = parse_eve_timestamp(&ts_text)?;
    let src_text = raw
        .src_ip
        .ok_or_else(|| "alert record has no src_ip".to_string())?;
    let ip = IpAddr::from_str(&src_text)
        .map_err(|_| format!("invalid src_ip in alert record: {src_text}"))?;
    let expires_at_unix = ts
        .checked_add(cfg.block_duration_secs)
        .ok_or_else(|| "block expiry overflows u64".to_string())?;
    let reason = if alert.category.is_empty() {
        alert.signature.clone()
    } else {
        format!("{}: {}", alert.category, alert.signature)
    };
    Ok(Some(BlockDecision {
        ip,
        expires_at_unix,
        reason,
        signature: alert.signature,
    }))
}

/// Ingest a whole eve.json log (lines separated by `\n`).
/// Blank lines are skipped. Non-alert lines and below-threshold
/// alerts contribute nothing. Decisions are deduplicated by IP,
/// keeping the latest expiry, and returned sorted by IP address
/// string so output order is deterministic. The first malformed
/// line aborts the whole ingest with an `Err`.
pub fn ingest_eve_log(log: &str, cfg: SuricataConfig) -> Result<Vec<BlockDecision>, String> {
    let mut decisions = Vec::new();
    for line in log.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(d) = parse_eve_line(line, cfg)? {
            decisions.push(d);
        }
    }
    Ok(deduplicate(decisions))
}

/// Deduplicate decisions by IP, keeping the latest expiry for each
/// IP. On an exact expiry tie the later decision wins, so the
/// freshest reason/signature is the one kept. Output is sorted by
/// IP address string for deterministic ordering.
pub fn deduplicate(decisions: Vec<BlockDecision>) -> Vec<BlockDecision> {
    let mut by_ip: HashMap<IpAddr, BlockDecision> = HashMap::new();
    for d in decisions {
        match by_ip.get(&d.ip) {
            Some(existing) if existing.expires_at_unix > d.expires_at_unix => {}
            _ => {
                by_ip.insert(d.ip, d);
            }
        }
    }
    let mut out: Vec<BlockDecision> = by_ip.into_values().collect();
    out.sort_by_key(|d| d.ip.to_string());
    out
}

/// Drop expired decisions in place. A decision is expired once
/// `now >= expires_at_unix` (active only while `now < expires`).
/// Returns how many decisions were removed.
pub fn prune_expired(decisions: &mut Vec<BlockDecision>, now: u64) -> usize {
    let before = decisions.len();
    decisions.retain(|d| now < d.expires_at_unix);
    before - decisions.len()
}

/// True if this decision is still active at `now`.
pub fn is_active(decision: &BlockDecision, now: u64) -> bool {
    now < decision.expires_at_unix
}

/// Parse a Suricata eve timestamp into Unix seconds.
///
/// Accepted shape (Suricata's format): `2026-11-02T19:00:00.123456+0000`,
/// with the fractional part optional and the timezone as `Z`,
/// `+HHMM`, `-HHMM`, `+HH:MM`, or `-HH:MM`. Anything else — a missing
/// timezone, an out-of-range month/day/hour/minute/second, a bad
/// offset — is an `Err`, never a panic. Implemented by hand (days
/// from civil date) so this crate needs no date/time dependency.
pub fn parse_eve_timestamp(text: &str) -> Result<u64, String> {
    let err = || format!("unparseable eve timestamp: {text}");
    // Split off the timezone suffix first.
    let (dt, offset_secs): (&str, i64) = if let Some(stripped) = text.strip_suffix('Z') {
        (stripped, 0)
    } else {
        // Find the last '+' or '-' after the 'T': that starts the offset.
        let t_pos = text.find('T').ok_or_else(err)?;
        let rest = &text[t_pos..];
        let off_pos = rest
            .rfind(['+', '-'])
            .ok_or_else(err)?
            .checked_add(t_pos)
            .ok_or_else(err)?;
        let offset_text = &text[off_pos..];
        let sign: i64 = if offset_text.starts_with('-') { -1 } else { 1 };
        let digits: String = offset_text[1..].chars().filter(|c| *c != ':').collect();
        if digits.len() != 4 || !digits.chars().all(|c| c.is_ascii_digit()) {
            return Err(err());
        }
        let oh: i64 = digits[..2].parse().map_err(|_| err())?;
        let om: i64 = digits[2..].parse().map_err(|_| err())?;
        if oh > 23 || om > 59 {
            return Err(err());
        }
        (&text[..off_pos], sign * (oh * 3600 + om * 60))
    };
    // dt is now "YYYY-MM-DDTHH:MM:SS[.fraction]".
    let (date_part, time_part) = dt.split_once('T').ok_or_else(err)?;
    let mut date_iter = date_part.split('-');
    let year: i64 = date_iter.next().ok_or_else(err)?.parse().map_err(|_| err())?;
    let month: i64 = date_iter.next().ok_or_else(err)?.parse().map_err(|_| err())?;
    let day: i64 = date_iter.next().ok_or_else(err)?.parse().map_err(|_| err())?;
    if date_iter.next().is_some() {
        return Err(err());
    }
    let time_main = time_part.split('.').next().ok_or_else(err)?;
    let mut time_iter = time_main.split(':');
    let hour: i64 = time_iter.next().ok_or_else(err)?.parse().map_err(|_| err())?;
    let minute: i64 = time_iter.next().ok_or_else(err)?.parse().map_err(|_| err())?;
    let second: i64 = time_iter.next().ok_or_else(err)?.parse().map_err(|_| err())?;
    if time_iter.next().is_some() {
        return Err(err());
    }
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return Err(err());
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if day < 1 || day > days_in_month[(month - 1) as usize] {
        return Err(err());
    }
    // Days from civil (Howard Hinnant's algorithm), epoch 1970-01-01.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let local = days * 86400 + hour * 3600 + minute * 60 + second;
    let unix = local - offset_secs;
    if unix < 0 {
        return Err(err());
    }
    Ok(unix as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: SuricataConfig = SuricataConfig {
        block_duration_secs: 3600,
        severity_threshold: 2,
    };
    /// 2026-11-02T19:00:00Z in Unix seconds.
    const BASE: u64 = 1793646000;

    fn port_scan_line() -> String {
        format!(
            r#"{{"timestamp":"2026-11-02T19:00:00.123456+0000","event_type":"alert","src_ip":"203.0.113.9","dest_ip":"10.0.0.1","dest_port":22,"proto":"TCP","alert":{{"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2}}}}"#
        )
    }

    fn high_severity_line() -> String {
        r#"{"timestamp":"2026-11-02T19:00:00.000000+0000","event_type":"alert","src_ip":"198.51.100.7","dest_ip":"10.0.0.1","dest_port":445,"proto":"TCP","alert":{"signature":"ET EXPLOIT SMB Exploit Attempt","category":"Attempted Administrator Privilege Gain","severity":1}}"#.to_string()
    }

    fn low_severity_line() -> String {
        r#"{"timestamp":"2026-11-02T19:00:00.000000+0000","event_type":"alert","src_ip":"192.0.2.44","dest_ip":"10.0.0.1","dest_port":80,"proto":"TCP","alert":{"signature":"ET INFO Suspicious User-Agent","category":"Misc activity","severity":3}}"#.to_string()
    }

    fn flow_line() -> String {
        r#"{"timestamp":"2026-11-02T19:00:00.000000+0000","event_type":"flow","src_ip":"10.0.0.5","dest_ip":"10.0.0.1","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":10}}"#.to_string()
    }

    #[test]
    fn port_scan_alert_blocks_with_correct_expiry() {
        let d = parse_eve_line(&port_scan_line(), CFG)
            .unwrap()
            .expect("port-scan alert must block");
        assert_eq!(d.ip.to_string(), "203.0.113.9");
        assert_eq!(d.signature, "ET SCAN Potential SSH Scan");
        assert!(d.reason.contains("Attempted Information Leak"));
        // Expiry = alert time + duration; fractional seconds truncated.
        assert_eq!(d.expires_at_unix, BASE + 3600);
        assert!(is_active(&d, BASE + 3599));
        assert!(!is_active(&d, BASE + 3600));
    }

    #[test]
    fn high_severity_blocks_and_threshold_boundary_holds() {
        // Severity 1 (most severe) blocks.
        let d = parse_eve_line(&high_severity_line(), CFG)
            .unwrap()
            .expect("severity 1 must block");
        assert_eq!(d.expires_at_unix, BASE + 3600);
        // Severity exactly at the threshold blocks too.
        let at_threshold = parse_eve_line(&port_scan_line(), CFG)
            .unwrap()
            .expect("severity == threshold must block");
        assert_eq!(at_threshold.expires_at_unix, BASE + 3600);
        // Severity above the threshold (less severe) does not block.
        assert_eq!(parse_eve_line(&low_severity_line(), CFG).unwrap(), None);
        // With a stricter threshold of 1, a severity-2 alert no longer blocks.
        let strict = SuricataConfig {
            severity_threshold: 1,
            ..CFG
        };
        assert_eq!(parse_eve_line(&port_scan_line(), strict).unwrap(), None);
        assert!(parse_eve_line(&high_severity_line(), strict)
            .unwrap()
            .is_some());
    }

    #[test]
    fn non_alert_flow_record_is_not_an_error() {
        assert_eq!(parse_eve_line(&flow_line(), CFG).unwrap(), None);
        let dns_line = r#"{"timestamp":"2026-11-02T19:00:00.000000+0000","event_type":"dns","src_ip":"10.0.0.5","dns":{"query":"example.com"}}"#;
        assert_eq!(parse_eve_line(dns_line, CFG).unwrap(), None);
    }

    #[test]
    fn malformed_lines_are_errors_not_panics() {
        assert!(parse_eve_line("{not json", CFG).is_err());
        assert!(parse_eve_line("", CFG).is_err());
        assert!(parse_eve_line(r#"{"event_type":"alert"}"#, CFG).is_err());
        // Alert with an unparseable timestamp is an error for that record.
        let bad_ts = r#"{"timestamp":"yesterday-ish","event_type":"alert","src_ip":"203.0.113.9","alert":{"signature":"X","category":"C","severity":1}}"#;
        assert!(parse_eve_line(bad_ts, CFG).is_err());
        // Alert with a bad source IP is an error, not a panic.
        let bad_ip = r#"{"timestamp":"2026-11-02T19:00:00.000000+0000","event_type":"alert","src_ip":"not-an-ip","alert":{"signature":"X","category":"C","severity":1}}"#;
        assert!(parse_eve_line(bad_ip, CFG).is_err());
        // Alert missing severity is an error.
        let no_sev = r#"{"timestamp":"2026-11-02T19:00:00.000000+0000","event_type":"alert","src_ip":"203.0.113.9","alert":{"signature":"X","category":"C"}}"#;
        assert!(parse_eve_line(no_sev, CFG).is_err());
    }

    #[test]
    fn timestamp_parsing_handles_offsets_and_rejects_bad_dates() {
        // +0000 (no colon) and fractional seconds.
        assert_eq!(
            parse_eve_timestamp("2026-11-02T19:00:00.123456+0000").unwrap(),
            BASE
        );
        // Zulu.
        assert_eq!(parse_eve_timestamp("2026-11-02T19:00:00Z").unwrap(), BASE);
        // Colon offset: 19:00 at +02:00 is 17:00 UTC.
        assert_eq!(
            parse_eve_timestamp("2026-11-02T19:00:00+02:00").unwrap(),
            BASE - 7200
        );
        // Negative offset without colon: 19:00 at -05:00 is 00:00 next day UTC.
        assert_eq!(
            parse_eve_timestamp("2026-11-02T19:00:00-0500").unwrap(),
            BASE + 5 * 3600
        );
        // No timezone at all is unparseable.
        assert!(parse_eve_timestamp("2026-11-02T19:00:00").is_err());
        // Impossible dates/times are errors.
        assert!(parse_eve_timestamp("2026-13-02T19:00:00Z").is_err());
        assert!(parse_eve_timestamp("2026-02-30T19:00:00Z").is_err());
        assert!(parse_eve_timestamp("2026-11-02T25:00:00Z").is_err());
        // Leap day is valid in a leap year.
        assert!(parse_eve_timestamp("2024-02-29T00:00:00Z").is_ok());
        assert!(parse_eve_timestamp("2026-02-29T00:00:00Z").is_err());
    }

    #[test]
    fn dedup_keeps_latest_expiry_and_prune_drops_expired() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let mk = |exp: u64| BlockDecision {
            ip,
            expires_at_unix: exp,
            reason: "r".to_string(),
            signature: "s".to_string(),
        };
        // Older decision first, newer second: latest wins.
        let deduped = deduplicate(vec![mk(BASE + 100), mk(BASE + 3600)]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].expires_at_unix, BASE + 3600);
        // Order reversed: latest still wins.
        let deduped = deduplicate(vec![mk(BASE + 3600), mk(BASE + 100)]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].expires_at_unix, BASE + 3600);
        // Distinct IPs are all kept.
        let other: IpAddr = "198.51.100.7".parse().unwrap();
        let mut mixed = vec![mk(BASE + 3600)];
        mixed.push(BlockDecision {
            ip: other,
            expires_at_unix: BASE + 3600,
            reason: "r".to_string(),
            signature: "s".to_string(),
        });
        assert_eq!(deduplicate(mixed).len(), 2);

        // Prune: expired at exactly expiry, active one second before.
        let mut decisions = vec![mk(BASE + 3600), mk(BASE + 100)];
        let deduped = deduplicate(decisions.clone());
        decisions = deduped;
        assert_eq!(prune_expired(&mut decisions, BASE + 3599), 0);
        assert_eq!(prune_expired(&mut decisions, BASE + 3600), 1);
        assert!(decisions.is_empty());
    }

    #[test]
    fn ingest_log_skips_non_alerts_and_dedups() {
        let log = format!(
            "{}\n{}\n{}\n\n{}",
            port_scan_line(),
            flow_line(),
            low_severity_line(),
            // Same IP again, one hour later: later expiry must win.
            port_scan_line().replace("19:00:00", "20:00:00"),
        );
        let decisions = ingest_eve_log(&log, CFG).unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].ip.to_string(), "203.0.113.9");
        assert_eq!(decisions[0].expires_at_unix, BASE + 7200);
        // A malformed line aborts ingestion with an error.
        assert!(ingest_eve_log("{broken\n", CFG).is_err());
    }
}
