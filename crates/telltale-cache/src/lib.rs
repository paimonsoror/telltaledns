//! Sharded S3-FIFO cache of wire-format DNS responses.
//!
//! Part of TelltaleDNS. See `spec/02-architecture.md` §2 and `spec/03` §4.
//!
//! REQ: DNS-006 (wire storage, ID/TTL rewrite on hit, TTL clamps, negative caching),
//! DNS-007 (serve-stale lookups), DNS-008 (prefetch signal), NFR-002 (allocation-free hits).
//!
//! Filtering happens *before* the cache, so entries are policy-neutral; answers from
//! different upstream groups are kept apart by the key's `view`.

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]

mod entry;
mod persist;
pub mod s3fifo;
mod singleflight;

use std::hash::{BuildHasherDefault, Hash, Hasher};
use std::time::Instant;

use parking_lot::Mutex;
use telltale_proto::{NameBuf, Query};

pub use entry::{Client, Uncacheable};
pub use singleflight::{Flight, FlightGuard, Singleflight};

use crate::entry::Entry;
use crate::s3fifo::S3Fifo;

/// Cache settings (mirrors `[cache]` in `telltale.toml`).
#[derive(Clone, Debug)]
pub struct CachePolicy {
    pub max_bytes: usize,
    /// 0 = limited by bytes only.
    pub max_entries: usize,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub negative_ttl_max: u32,
    pub servfail_ttl: u32,
    pub serve_stale: bool,
    /// Seconds past expiry an entry may still be served stale.
    pub stale_max_age: u32,
    /// TTL written into stale answers (RFC 8767 recommends 30 s).
    pub stale_answer_ttl: u32,
    pub prefetch: bool,
    pub prefetch_threshold_pct: u8,
    pub prefetch_min_hits: u32,
    /// Number of shards (rounded up to a power of two).
    pub shards: usize,
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self {
            max_bytes: 32 << 20,
            max_entries: 0,
            min_ttl: 0,
            max_ttl: 86_400,
            negative_ttl_max: 3_600,
            servfail_ttl: 5,
            serve_stale: true,
            stale_max_age: 86_400,
            stale_answer_ttl: 30,
            prefetch: true,
            prefetch_threshold_pct: 10,
            prefetch_min_hits: 3,
            shards: 64,
        }
    }
}

/// Cache key: `(qname hash, qtype, qclass, DO, CD, upstream view)` per `spec/03` §4.
/// The full name is stored in the entry and verified on every hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheKey {
    mixed: u64,
    qtype: u16,
    qclass: u16,
    flags: u8,
    view: u16,
}

impl CacheKey {
    /// `name_hash` is the per-process seeded hash of the normalized qname (`NameBuf::hash64`).
    pub fn new(q: &Query<'_>, name_hash: u64, view: u16) -> Self {
        let dnssec_ok = q.edns.is_some_and(|e| e.dnssec_ok);
        let flags = u8::from(dnssec_ok) | (u8::from(q.header.flags.cd()) << 1);
        Self::from_parts(name_hash, q.qtype, q.qclass, flags, view)
    }

    pub(crate) fn from_parts(
        name_hash: u64,
        qtype: u16,
        qclass: u16,
        flags: u8,
        view: u16,
    ) -> Self {
        let tag = u64::from(qtype)
            | (u64::from(qclass) << 16)
            | (u64::from(flags) << 32)
            | (u64::from(view) << 40);
        Self {
            mixed: fmix64(name_hash ^ tag.wrapping_mul(0x9E37_79B9_7F4A_7C15)),
            qtype,
            qclass,
            flags,
            view,
        }
    }
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.mixed);
    }
}

/// `MurmurHash3` finalizer: spreads bits so shard and bucket selection are independent.
const fn fmix64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^= h >> 33;
    h
}

/// Hasher that passes a precomputed `u64` through (keys are already well-mixed).
#[derive(Default, Clone, Copy, Debug)]
pub struct PassThroughHasher(u64);

impl Hasher for PassThroughHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(b);
        }
    }
    fn write_u64(&mut self, n: u64) {
        self.0 = n;
    }
}

type BuildPassThrough = BuildHasherDefault<PassThroughHasher>;

/// Result of a cache lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Fresh answer written to `out`. `prefetch` is true once per entry when it is hot and
    /// close to expiry (DNS-008): the caller should refresh it in the background.
    Hit {
        len: usize,
        prefetch: bool,
    },
    /// Expired but still within the serve-stale window: resolve upstream, and fall back to
    /// [`Cache::get_stale`] if that fails or is too slow (DNS-007).
    Expired,
    Miss,
}

/// Aggregate counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub stale_served: u64,
    pub inserts: u64,
    pub uncacheable: u64,
    pub evictions: u64,
    /// Hits that triggered a background refresh (DNS-008).
    pub prefetches: u64,
    pub entries: usize,
    pub bytes: usize,
}

#[derive(Debug)]
struct Shard {
    fifo: S3Fifo<CacheKey, Entry, BuildPassThrough>,
    stats: CacheStats,
}

/// Cache-line aligned so neighboring shard locks don't false-share.
#[derive(Debug)]
#[repr(align(64))]
struct PaddedShard(Mutex<Shard>);

/// The response cache. Share it as `Arc<Cache>` across workers.
#[derive(Debug)]
pub struct Cache {
    shards: Box<[PaddedShard]>,
    shard_shift: u32,
    policy: CachePolicy,
}

impl Cache {
    pub fn new(policy: CachePolicy) -> Self {
        let n = policy.shards.max(1).next_power_of_two();
        let per_bytes = (policy.max_bytes / n).max(1);
        let per_entries = if policy.max_entries == 0 {
            0
        } else {
            (policy.max_entries / n).max(1)
        };
        let shards = (0..n)
            .map(|_| {
                PaddedShard(Mutex::new(Shard {
                    fifo: S3Fifo::new(per_bytes, per_entries, BuildPassThrough::default()),
                    stats: CacheStats::default(),
                }))
            })
            .collect();
        Self {
            shards,
            shard_shift: 64 - n.trailing_zeros(),
            policy,
        }
    }

    pub fn policy(&self) -> &CachePolicy {
        &self.policy
    }

    fn shard(&self, key: &CacheKey) -> &Mutex<Shard> {
        // High bits pick the shard; the map inside uses the low bits.
        let idx = key.mixed.checked_shr(self.shard_shift).unwrap_or(0);
        &self.shards[usize::try_from(idx).unwrap_or(0)].0
    }

    /// Looks up a fresh answer and writes it for `client` into `out`. Allocation-free.
    pub fn get(
        &self,
        key: &CacheKey,
        qname: &NameBuf,
        client: &Client<'_>,
        now: Instant,
        out: &mut [u8],
    ) -> Lookup {
        let mut guard = self.shard(key).lock();
        let shard = &mut *guard;
        let p = &self.policy;
        let outcome = match shard.fifo.get_mut(key) {
            Some(e) if *e.name == *qname.as_wire() => {
                let age = e.elapsed_secs(now);
                if age < e.ttl {
                    e.hits = e.hits.saturating_add(1);
                    let remaining = e.ttl - age;
                    let prefetch = p.prefetch
                        && !e.prefetch_signaled
                        && e.hits >= p.prefetch_min_hits
                        && u64::from(remaining) * 100
                            < u64::from(e.ttl) * u64::from(p.prefetch_threshold_pct);
                    if prefetch {
                        e.prefetch_signaled = true;
                    }
                    match entry::write(e, client, now, None, out) {
                        Some(len) => Lookup::Hit { len, prefetch },
                        None => Lookup::Miss,
                    }
                } else if p.serve_stale && age - e.ttl < p.stale_max_age {
                    Lookup::Expired
                } else {
                    shard.fifo.remove(key);
                    Lookup::Miss
                }
            }
            _ => Lookup::Miss,
        };
        match outcome {
            Lookup::Hit { prefetch, .. } => {
                shard.stats.hits += 1;
                // REQ: DNS-008, OBS-005 — prefetches triggered (`telltale_cache_prefetch_total`).
                shard.stats.prefetches += u64::from(prefetch);
            }
            _ => shard.stats.misses += 1,
        }
        outcome
    }

    /// Writes an expired entry with every TTL set to `stale_answer_ttl` (RFC 8767). The caller
    /// adds EDE 3 (Stale Answer) through `client.edns`. Returns the length, or `None`.
    pub fn get_stale(
        &self,
        key: &CacheKey,
        qname: &NameBuf,
        client: &Client<'_>,
        now: Instant,
        out: &mut [u8],
    ) -> Option<usize> {
        if !self.policy.serve_stale {
            return None;
        }
        let mut guard = self.shard(key).lock();
        let shard = &mut *guard;
        let e = shard.fifo.peek(key)?;
        if *e.name != *qname.as_wire() {
            return None;
        }
        let age = e.elapsed_secs(now);
        if age >= e.ttl.saturating_add(self.policy.stale_max_age) {
            return None;
        }
        let len = entry::write(e, client, now, Some(self.policy.stale_answer_ttl), out)?;
        shard.stats.stale_served += 1;
        Some(len)
    }

    /// Caches `resp` (an upstream answer to `q`) if it is cacheable. Replaces any entry with
    /// the same key.
    pub fn insert(
        &self,
        key: &CacheKey,
        q: &Query<'_>,
        resp: &[u8],
        now: Instant,
    ) -> Result<(), Uncacheable> {
        let prepared = entry::prepare(q, resp, Some(&self.policy), now);
        let mut guard = self.shard(key).lock();
        let shard = &mut *guard;
        match prepared {
            Ok(e) => {
                let w = e.weight();
                shard.fifo.insert(*key, e, w);
                shard.stats.inserts += 1;
                Ok(())
            }
            Err(why) => {
                shard.stats.uncacheable += 1;
                Err(why)
            }
        }
    }

    /// Renders an upstream answer to `q` for `client` without caching it (fresh ID, client's
    /// question case, per-client OPT). Works for uncacheable answers too (REFUSED, TTL 0, ...).
    /// Returns `None` if the answer doesn't match the question or `out` is too small.
    pub fn render(
        q: &Query<'_>,
        resp: &[u8],
        client: &Client<'_>,
        out: &mut [u8],
    ) -> Option<usize> {
        let now = Instant::now();
        let e = entry::prepare(q, resp, None, now).ok()?;
        entry::write(&e, client, now, None, out)
    }

    /// Removes everything.
    pub fn flush_all(&self) {
        for s in &self.shards {
            s.0.lock().fifo.clear();
        }
    }

    /// Removes entries for `name` (and, if `subtree`, every name below it). Returns the count.
    pub fn flush_name(&self, name: &NameBuf, subtree: bool) -> usize {
        let mut removed = 0;
        for s in &self.shards {
            s.0.lock().fifo.retain(|_, e| {
                let hit = if subtree {
                    let mut n = NameBuf::default();
                    telltale_proto::read_name_uncompressed(&e.name, 0, &mut n)
                        .is_ok_and(|_| n.is_subdomain_of(name))
                } else {
                    *e.name == *name.as_wire()
                };
                removed += usize::from(hit);
                !hit
            });
        }
        removed
    }

    /// Sums counters across shards (takes each shard lock briefly).
    pub fn stats(&self) -> CacheStats {
        let mut t = CacheStats::default();
        for s in &self.shards {
            let s = s.0.lock();
            t.hits += s.stats.hits;
            t.prefetches += s.stats.prefetches;
            t.misses += s.stats.misses;
            t.stale_served += s.stats.stale_served;
            t.inserts += s.stats.inserts;
            t.uncacheable += s.stats.uncacheable;
            t.evictions += s.fifo.evictions();
            t.entries += s.fifo.len();
            t.bytes += s.fifo.weight();
        }
        t
    }
}
