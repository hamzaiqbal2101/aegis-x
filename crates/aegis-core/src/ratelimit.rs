//! Engine 3 — per-source rate limiting (token bucket) + policy model
//! for nftables `limit` rendering.
//!
//! Two halves that share semantics but not code paths:
//! * `TokenBucket` / `RateLimiter`: in-memory, per-source buckets for
//!   the API/daemon side (e.g. throttling connection attempts before
//!   they reach the firewall). Pure logic, unit-tested.
//! * `RateLimit` on `Rule` (see policy.rs): rendered by the Linux
//!   adapter as nftables `limit rate ...` lines. That is kernel
//!   enforcement, not this module's bookkeeping — the two must not be
//!   confused. A rule's `limit` means "this rule only matches while
//!   under the rate"; on an allow rule, excess packets fall through to
//!   later rules (ultimately default deny). On a deny rule it means
//!   the *drop* is rate-limited, which is rarely what anyone wants —
//!   the renderer emits it verbatim and the docs say so.

use std::collections::HashMap;
use std::net::IpAddr;

/// Token bucket: `capacity` tokens max, refilled at `refill_per_sec`.
/// Time is seconds as f64 (the caller supplies the clock; tests use
/// fake times, production passes real time).
#[derive(Debug, Clone)]
pub struct TokenBucket {
    pub capacity: f64,
    pub refill_per_sec: f64,
    tokens: f64,
    last_ts: f64,
}

impl TokenBucket {
    pub fn new(capacity: f64, refill_per_sec: f64) -> TokenBucket {
        assert!(capacity > 0.0, "capacity must be positive");
        assert!(refill_per_sec >= 0.0, "refill rate must be non-negative");
        TokenBucket {
            capacity,
            refill_per_sec,
            tokens: capacity,
            last_ts: 0.0,
        }
    }

    /// Refill from elapsed time, then try to spend one token.
    pub fn allow(&mut self, now: f64) -> bool {
        if now > self.last_ts {
            let gained = (now - self.last_ts) * self.refill_per_sec;
            self.tokens = (self.tokens + gained).min(self.capacity);
            self.last_ts = now;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Tokens currently available (after refill to `now`, no spend).
    pub fn available(&mut self, now: f64) -> f64 {
        if now > self.last_ts {
            let gained = (now - self.last_ts) * self.refill_per_sec;
            self.tokens = (self.tokens + gained).min(self.capacity);
            self.last_ts = now;
        }
        self.tokens
    }
}

/// Per-source buckets with one shared shape.
#[derive(Debug, Default)]
pub struct RateLimiter {
    buckets: HashMap<IpAddr, TokenBucket>,
    capacity: f64,
    refill_per_sec: f64,
}

impl RateLimiter {
    pub fn new(capacity: f64, refill_per_sec: f64) -> RateLimiter {
        RateLimiter {
            buckets: HashMap::new(),
            capacity,
            refill_per_sec,
        }
    }

    /// One token for `src` at time `now`. Sources are independent:
    /// one abusive source cannot starve another.
    pub fn allow(&mut self, src: IpAddr, now: f64) -> bool {
        let bucket = self
            .buckets
            .entry(src)
            .or_insert_with(|| TokenBucket::new(self.capacity, self.refill_per_sec));
        bucket.allow(now)
    }

    pub fn source_count(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_burst_then_refill() {
        let mut b = TokenBucket::new(5.0, 1.0);
        // Full burst of 5 at t=0.
        for _ in 0..5 {
            assert!(b.allow(0.0));
        }
        // 6th at t=0 denied.
        assert!(!b.allow(0.0));
        // 1s later exactly 1 token refilled.
        assert!(b.allow(1.0));
        assert!(!b.allow(1.0));
        // 10s later the bucket is full again (clamped to capacity).
        assert!(b.available(11.0) == 5.0);
    }

    #[test]
    fn limiter_isolates_sources() {
        let mut lim = RateLimiter::new(2.0, 0.0);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(lim.allow(a, 0.0));
        assert!(lim.allow(a, 0.0));
        assert!(!lim.allow(a, 0.0));
        // B is unaffected by A's exhaustion.
        assert!(lim.allow(b, 0.0));
        assert_eq!(lim.source_count(), 2);
    }

    #[test]
    fn zero_refill_never_recovers() {
        let mut b = TokenBucket::new(1.0, 0.0);
        assert!(b.allow(0.0));
        assert!(!b.allow(1000.0));
    }
}
