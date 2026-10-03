//! T1.4 AC: S3-FIFO hit ratio on a Zipf corpus is at least the LRU baseline's.

#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap};

use telltale_cache::s3fifo::S3Fifo;

/// Deterministic xorshift64* RNG (no external deps, reproducible corpus).
struct Rng(u64);
impl Rng {
    fn next_f64(&mut self) -> f64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Zipf(s) over `n` items via an inverse-CDF table.
fn zipf_trace(n: usize, s: f64, len: usize, seed: u64) -> Vec<u32> {
    let mut cdf = Vec::with_capacity(n);
    let mut acc = 0.0;
    for k in 1..=n {
        acc += 1.0 / (k as f64).powf(s);
        cdf.push(acc);
    }
    let total = acc;
    let mut rng = Rng(seed);
    (0..len)
        .map(|_| {
            let u = rng.next_f64() * total;
            cdf.partition_point(|&c| c < u) as u32
        })
        .collect()
}

fn lru_hit_ratio(trace: &[u32], cap: usize) -> f64 {
    let mut last: HashMap<u32, u64> = HashMap::new();
    let mut order: BTreeMap<u64, u32> = BTreeMap::new();
    let mut hits = 0u64;
    for (t, &k) in trace.iter().enumerate() {
        let t = t as u64;
        if let Some(old) = last.insert(k, t) {
            order.remove(&old);
            hits += 1;
        } else if last.len() > cap {
            let (_, victim) = order.pop_first().unwrap();
            last.remove(&victim);
        }
        order.insert(t, k);
    }
    hits as f64 / trace.len() as f64
}

fn s3fifo_hit_ratio(trace: &[u32], cap: usize) -> f64 {
    let mut c: S3Fifo<u32, (), RandomState> = S3Fifo::new(cap, 0, RandomState::new());
    let mut hits = 0u64;
    for &k in trace {
        if c.get_mut(&k).is_some() {
            hits += 1;
        } else {
            c.insert(k, (), 1);
        }
    }
    hits as f64 / trace.len() as f64
}

#[test]
fn dns_006_s3fifo_beats_or_matches_lru_on_zipf() {
    // spec/09 §2 `cache-hot`-like corpus: Zipf s=1.0; plus a flatter s=0.8 variant.
    for (s, cap_pct) in [(1.0, 1), (1.0, 10), (0.8, 1), (0.8, 10)] {
        let n = 100_000;
        let trace = zipf_trace(n, s, 1_000_000, 0x5eed);
        let cap = n * cap_pct / 100;
        let lru = lru_hit_ratio(&trace, cap);
        let s3 = s3fifo_hit_ratio(&trace, cap);
        println!("zipf s={s} cache={cap_pct}%: LRU {lru:.4}  S3-FIFO {s3:.4}");
        assert!(
            s3 >= lru,
            "S3-FIFO {s3:.4} < LRU {lru:.4} at s={s}, cap={cap_pct}%"
        );
    }
}
