//! Engine 5 (part) — DNS security: blocklist/allowlist matching and
//! DNS-tunneling heuristics over queried names.
//!
//! HONEST SCOPE: this analyzes *names* (strings), not DNS traffic. It
//! does not intercept, proxy, or resolve DNS, and it cannot see query
//! payloads or timing. A name flagged here is "worth a closer look",
//! not proof of exfiltration — high-entropy labels also occur in
//! CDNs, anti-malware lookups, and legitimate encoded subdomains.
//! Thresholds are tunable via `DnsConfig`; defaults are starting
//! points, not tuned values.
//!
//! Matching rules (both lists, case-insensitive, trailing dots
//! ignored): an entry matches a name exactly, or matches any
//! subdomain of it (`bad.example.com` also covers
//! `sub.bad.example.com`). The allowlist is checked FIRST: an
//! allowlisted name is allowed even if it also appears on the
//! blocklist (the operator's explicit override wins).

/// Normalize a DNS name for comparison: lowercase, strip one trailing dot.
pub fn normalize(name: &str) -> String {
    let n = name.trim().to_ascii_lowercase();
    n.strip_suffix('.').unwrap_or(&n).to_string()
}

/// True if `entry` matches `name` (exact or parent-domain match).
pub fn entry_matches(entry: &str, name: &str) -> bool {
    let e = normalize(entry);
    let n = normalize(name);
    if e.is_empty() || n.is_empty() {
        return false;
    }
    n == e || (n.len() > e.len() && n.ends_with(&format!(".{e}")))
}

/// Verdict for one queried name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsVerdict {
    /// Explicitly allowlisted (overrides the blocklist).
    Allow,
    /// Blocklisted.
    Block,
    /// On neither list.
    Unlisted,
}

/// A DNS name policy: two lists, allowlist wins.
#[derive(Debug, Clone, Default)]
pub struct DnsPolicy {
    pub blocklist: Vec<String>,
    pub allowlist: Vec<String>,
}

impl DnsPolicy {
    pub fn verdict(&self, name: &str) -> DnsVerdict {
        if self.allowlist.iter().any(|e| entry_matches(e, name)) {
            return DnsVerdict::Allow;
        }
        if self.blocklist.iter().any(|e| entry_matches(e, name)) {
            return DnsVerdict::Block;
        }
        DnsVerdict::Unlisted
    }
}

/// Tunable tunneling thresholds.
#[derive(Debug, Clone, Copy)]
pub struct DnsConfig {
    /// Flag any single label longer than this (DNS allows 63).
    pub max_label_len: usize,
    /// Flag any full name longer than this (DNS allows 253).
    pub max_name_len: usize,
    /// Flag names with more labels than this.
    pub max_labels: usize,
    /// Flag a longest-label Shannon entropy above this (bits/char).
    pub entropy_threshold: f64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            max_label_len: 40,
            max_name_len: 100,
            max_labels: 6,
            entropy_threshold: 4.0,
        }
    }
}

/// Shannon entropy (bits per character) of a string.
pub fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total as f64;
            -p * p.log2()
        })
        .sum()
}

/// Heuristic analysis of one queried name.
#[derive(Debug, Clone)]
pub struct DnsAnalysis {
    pub suspicious: bool,
    pub reasons: Vec<String>,
    pub max_label_len: usize,
    pub label_count: usize,
    pub longest_label_entropy: f64,
}

/// Flag tunneling-looking names. `suspicious` means "at least one
/// threshold tripped" — it is a triage signal, not a conviction.
pub fn analyze_name(name: &str, cfg: DnsConfig) -> DnsAnalysis {
    let n = normalize(name);
    let labels: Vec<&str> = n.split('.').filter(|l| !l.is_empty()).collect();
    let max_label_len = labels.iter().map(|l| l.len()).max().unwrap_or(0);
    let longest = labels
        .iter()
        .max_by_key(|l| l.len())
        .copied()
        .unwrap_or("");
    let entropy = shannon_entropy(longest);
    let mut reasons = Vec::new();
    if max_label_len > cfg.max_label_len {
        reasons.push(format!(
            "label length {max_label_len} exceeds {}",
            cfg.max_label_len
        ));
    }
    if n.len() > cfg.max_name_len {
        reasons.push(format!(
            "name length {} exceeds {}",
            n.len(),
            cfg.max_name_len
        ));
    }
    if labels.len() > cfg.max_labels {
        reasons.push(format!(
            "label count {} exceeds {}",
            labels.len(),
            cfg.max_labels
        ));
    }
    if entropy > cfg.entropy_threshold {
        reasons.push(format!(
            "longest-label entropy {entropy:.2} exceeds {:.2}",
            cfg.entropy_threshold
        ));
    }
    DnsAnalysis {
        suspicious: !reasons.is_empty(),
        reasons,
        max_label_len,
        label_count: labels.len(),
        longest_label_entropy: entropy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocklist_exact_and_subdomain() {
        let p = DnsPolicy {
            blocklist: vec!["bad.example.com".to_string()],
            allowlist: vec![],
        };
        assert_eq!(p.verdict("bad.example.com"), DnsVerdict::Block);
        assert_eq!(p.verdict("deep.sub.bad.example.com"), DnsVerdict::Block);
        // A merely similar name is NOT a subdomain match.
        assert_eq!(p.verdict("notbad.example.com"), DnsVerdict::Unlisted);
        assert_eq!(p.verdict("example.com"), DnsVerdict::Unlisted);
        assert_eq!(p.verdict("good.example.org"), DnsVerdict::Unlisted);
    }

    #[test]
    fn allowlist_overrides_blocklist_case_and_dot_insensitive() {
        let p = DnsPolicy {
            blocklist: vec!["bad.example.com".to_string()],
            allowlist: vec!["ok.bad.example.com".to_string()],
        };
        assert_eq!(p.verdict("ok.bad.example.com"), DnsVerdict::Allow);
        assert_eq!(p.verdict("OK.BAD.EXAMPLE.COM."), DnsVerdict::Allow);
        assert_eq!(p.verdict("other.bad.example.com"), DnsVerdict::Block);
    }

    #[test]
    fn tunneling_heuristics() {
        let cfg = DnsConfig::default();
        // Ordinary name: clean on every signal.
        let a = analyze_name("www.example.com", cfg);
        assert!(!a.suspicious, "ordinary name flagged: {:?}", a.reasons);
        // Long encoded-looking label: flagged (length + entropy).
        let exfil = "aGVsbG9Xb3JsZEhvdyBhcmUgeW91IGRvaW5nIFRvZGF5IFRoZQ.example.com";
        let b = analyze_name(exfil, cfg);
        assert!(b.suspicious);
        assert!(b.max_label_len > cfg.max_label_len);
        // Many labels: flagged on count.
        let c = analyze_name("a.b.c.d.e.f.g.example.com", cfg);
        assert!(c.suspicious);
        assert!(c.label_count > cfg.max_labels);
        // Pure entropy signal: a short-but-random label under the
        // length limit still trips entropy if it is random enough.
        let d = analyze_name("x9f2k7qz4w8m1.example.com", cfg);
        assert!(d.longest_label_entropy > 3.0);
    }
}
