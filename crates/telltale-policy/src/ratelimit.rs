//! Per-client rate limiting with token buckets (REQ: DNS-014).
//!
//! Sharded maps keyed by the client's address prefix. A known client's check is a shard lock,
//! a hash lookup, and a few float operations — no allocation. New clients allocate a map slot;
//! idle buckets (full again) are pruned when a shard grows past its cap.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use parking_lot::Mutex;
use telltale_config::{Cidr, RateLimitConfig};

const SHARDS: usize = 32;
/// Max tracked clients per shard before idle buckets are pruned.
const MAX_PER_SHARD: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Token-bucket limiter: each client may burst up to `queries` and refills at
/// `queries / window` per second.
#[derive(Debug)]
pub struct RateLimiter {
    shards: Box<[Mutex<HashMap<u128, Bucket>>]>,
    capacity: f64,
    per_sec: f64,
    exempt: Vec<Cidr>,
    v4_prefix: u8,
    v6_prefix: u8,
}

impl RateLimiter {
    /// `None` when rate limiting is disabled.
    pub fn new(cfg: &RateLimitConfig) -> Option<Self> {
        if !cfg.enabled || cfg.queries == 0 || cfg.window_secs == 0 {
            return None;
        }
        Some(Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            capacity: f64::from(cfg.queries),
            per_sec: f64::from(cfg.queries) / f64::from(cfg.window_secs),
            exempt: cfg.exempt.clone(),
            v4_prefix: cfg.ipv4_prefix.min(32),
            v6_prefix: cfg.ipv6_prefix.min(128),
        })
    }

    /// Bucket key: the client address masked to the configured prefix. IPv4 keys carry a
    /// marker bit so they never collide with IPv6 keys.
    fn key(&self, ip: IpAddr) -> u128 {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            IpAddr::V4(_) => ip,
        };
        match ip {
            IpAddr::V4(v4) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.v4_prefix))
                    .unwrap_or(0);
                (1u128 << 127) | u128::from(u32::from(v4) & mask)
            }
            IpAddr::V6(v6) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.v6_prefix))
                    .unwrap_or(0);
                (u128::from(v6) & mask) & !(1u128 << 127)
            }
        }
    }

    /// True if the query is allowed; consumes one token.
    pub fn check(&self, ip: IpAddr, now: Instant) -> bool {
        if self.exempt.iter().any(|n| n.contains(ip)) {
            return true;
        }
        let key = self.key(ip);
        // Fibonacci hashing of the key's halves picks the shard.
        let bytes = key.to_le_bytes();
        let half = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap_or([0; 8]));
        let h = (half(&bytes[..8]) ^ half(&bytes[8..])).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let shard = &self.shards[usize::try_from(h >> 59).unwrap_or(0) % SHARDS];
        let mut map = shard.lock();
        if let Some(b) = map.get_mut(&key) {
            let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
            b.tokens = (b.tokens + elapsed * self.per_sec).min(self.capacity);
            b.last = now;
            if b.tokens >= 1.0 {
                b.tokens -= 1.0;
                return true;
            }
            return false;
        }
        if map.len() >= MAX_PER_SHARD {
            let (cap, rate) = (self.capacity, self.per_sec);
            // Drop clients whose bucket would be full by now (idle long enough).
            map.retain(|_, b| {
                b.tokens + now.saturating_duration_since(b.last).as_secs_f64() * rate < cap
            });
        }
        map.insert(
            key,
            Bucket {
                tokens: self.capacity - 1.0,
                last: now,
            },
        );
        true
    }

    /// Tracked clients (for metrics).
    pub fn tracked(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn limiter(queries: u32, window: u32) -> RateLimiter {
        RateLimiter::new(&RateLimitConfig {
            queries,
            window_secs: window,
            ..RateLimitConfig::default()
        })
        .unwrap()
    }

    #[test]
    fn dns_014_burst_then_refill() {
        let rl = limiter(10, 10); // 10 burst, 1/s refill
        let ip: IpAddr = "192.168.1.5".parse().unwrap();
        let t = Instant::now();
        assert!((0..10).all(|_| rl.check(ip, t)));
        assert!(!rl.check(ip, t), "11th query in the burst is limited");
        assert!(!rl.check(ip, t + Duration::from_millis(500)));
        assert!(
            rl.check(ip, t + Duration::from_millis(1600)),
            "refilled after ~1 s"
        );
        let other: IpAddr = "192.168.1.6".parse().unwrap();
        assert!(rl.check(other, t), "limits are per client");
    }

    #[test]
    fn dns_014_exempt_and_ipv6_prefix_grouping() {
        let rl = limiter(2, 60);
        let t = Instant::now();
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(
            (0..100).all(|_| rl.check(lo, t)),
            "loopback exempt by default"
        );
        // Two privacy addresses in the same /64 share a bucket.
        assert!(rl.check("2001:db8:1:1::a".parse().unwrap(), t));
        assert!(rl.check("2001:db8:1:1::b".parse().unwrap(), t));
        assert!(!rl.check("2001:db8:1:1::c".parse().unwrap(), t));
        assert!(
            rl.check("2001:db8:1:2::a".parse().unwrap(), t),
            "different /64"
        );
    }

    #[test]
    fn dns_014_disabled_returns_none() {
        let cfg = RateLimitConfig {
            enabled: false,
            ..RateLimitConfig::default()
        };
        assert!(RateLimiter::new(&cfg).is_none());
    }
}
