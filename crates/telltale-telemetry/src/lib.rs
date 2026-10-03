//! `QueryEvent`, ring buffers, aggregator, rollups, histograms, exporters.
//!
//! Part of TelltaleDNS. See `spec/02-architecture.md` §2 and `spec/06`.
//!
//! This first slice (T1.9) is the counter/histogram core: every query bumps counters in a
//! per-thread, cache-line-aligned slot with relaxed atomics (REQ: OBS-002 — the hot path never
//! blocks on telemetry, and counters never drop), and [`Metrics::render`] sums the slots into the
//! Prometheus text format (REQ: OBS-005).

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]

pub mod prom;

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

/// How a query was answered (the `status` label).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// Fresh cache hit.
    Cached,
    /// Answered by an upstream.
    Forwarded,
    /// Expired answer served because upstreams failed (RFC 8767).
    Stale,
    /// Local record.
    Local,
    /// Special name (localhost, canary, ANY, private PTR, ...).
    Special,
    /// Refused by access control.
    Refused,
    RateLimited,
    /// Malformed or unsupported (FORMERR / NOTIMP / BADVERS).
    Malformed,
    /// No upstream could answer, or overloaded.
    ServFail,
    /// Not answered at all (runt, QR=1, loop, rate-limit drop).
    Dropped,
}

impl Status {
    pub const ALL: [Self; 10] = [
        Self::Cached,
        Self::Forwarded,
        Self::Stale,
        Self::Local,
        Self::Special,
        Self::Refused,
        Self::RateLimited,
        Self::Malformed,
        Self::ServFail,
        Self::Dropped,
    ];
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cached => "cached",
            Self::Forwarded => "forwarded",
            Self::Stale => "stale",
            Self::Local => "local",
            Self::Special => "special",
            Self::Refused => "refused",
            Self::RateLimited => "rate_limited",
            Self::Malformed => "malformed",
            Self::ServFail => "servfail",
            Self::Dropped => "dropped",
        }
    }
    /// Latency path this status belongs to (the histogram `path` label).
    pub const fn path(self) -> Path {
        match self {
            Self::Cached => Path::Cache,
            Self::Forwarded | Self::Stale | Self::ServFail => Path::Upstream,
            Self::Local => Path::Local,
            _ => Path::Synthesized,
        }
    }
}

/// Histogram `path` label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Path {
    Cache,
    Upstream,
    Local,
    /// Answers built without data: refusals, special names, errors.
    Synthesized,
}

impl Path {
    pub const ALL: [Self; 4] = [Self::Cache, Self::Upstream, Self::Local, Self::Synthesized];
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Upstream => "upstream",
            Self::Local => "local",
            Self::Synthesized => "synthesized",
        }
    }
}

/// Transport label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Proto {
    Udp,
    Tcp,
}

impl Proto {
    pub const ALL: [Self; 2] = [Self::Udp, Self::Tcp];
    pub const fn label(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

/// Histogram bucket upper bounds in microseconds (06 §5: 50 µs … 5 s).
pub const BUCKETS_US: [u64; 16] = [
    50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
    1_000_000, 2_500_000, 5_000_000,
];

/// Query types with their own series; everything else is `other` (06 §5: top 12 + other).
pub const QTYPES: [(u16, &str); 12] = [
    (1, "A"),
    (28, "AAAA"),
    (65, "HTTPS"),
    (5, "CNAME"),
    (12, "PTR"),
    (16, "TXT"),
    (33, "SRV"),
    (15, "MX"),
    (6, "SOA"),
    (2, "NS"),
    (64, "SVCB"),
    (255, "ANY"),
];
const N_QTYPE: usize = QTYPES.len() + 1;
const N_RCODE: usize = 17; // 0..=15, then "other" (extended)
const N_STATUS: usize = Status::ALL.len();
const N_PATH: usize = Path::ALL.len();
const N_BUCKET: usize = BUCKETS_US.len() + 1; // + Inf

/// One writer's counters. Aligned so neighboring slots never share a cache line.
#[derive(Debug)]
#[repr(align(128))]
struct Slot {
    queries: [[AtomicU64; N_STATUS]; 2],
    rcodes: [AtomicU64; N_RCODE],
    qtypes: [AtomicU64; N_QTYPE],
    buckets: [[AtomicU64; N_BUCKET]; N_PATH],
    sum_us: [AtomicU64; N_PATH],
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            queries: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            rcodes: std::array::from_fn(|_| AtomicU64::new(0)),
            qtypes: std::array::from_fn(|_| AtomicU64::new(0)),
            buckets: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            sum_us: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

/// Query metrics, written by many threads without locks and summed on scrape.
#[derive(Debug)]
pub struct Metrics {
    slots: Box<[Slot]>,
    next: AtomicUsize,
}

thread_local! {
    /// This thread's slot index (assigned round-robin on first use).
    static SLOT: Cell<usize> = const { Cell::new(usize::MAX) };
}

impl Metrics {
    /// `slots` should be at least the number of writer threads (extra threads share slots,
    /// which is still correct — just with a little more cache traffic).
    pub fn new(slots: usize) -> Self {
        Self {
            slots: (0..slots.max(1)).map(|_| Slot::default()).collect(),
            next: AtomicUsize::new(0),
        }
    }

    fn slot(&self) -> &Slot {
        let idx = SLOT.with(|s| {
            let mut i = s.get();
            if i == usize::MAX {
                i = self.next.fetch_add(1, Ordering::Relaxed);
                s.set(i);
            }
            i
        });
        &self.slots[idx % self.slots.len()]
    }

    /// Records one answered (or dropped) query. Allocation-free, lock-free.
    pub fn record(
        &self,
        proto: Proto,
        status: Status,
        rcode: Option<u16>,
        qtype: u16,
        elapsed: Duration,
    ) {
        let s = self.slot();
        s.queries[proto as usize][status as usize].fetch_add(1, Ordering::Relaxed);
        if let Some(rc) = rcode {
            let i = usize::from(rc).min(N_RCODE - 1);
            s.rcodes[i].fetch_add(1, Ordering::Relaxed);
        }
        let q = QTYPES
            .iter()
            .position(|(t, _)| *t == qtype)
            .unwrap_or(N_QTYPE - 1);
        s.qtypes[q].fetch_add(1, Ordering::Relaxed);
        if status != Status::Dropped {
            let p = status.path() as usize;
            let us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
            let b = BUCKETS_US
                .iter()
                .position(|&ub| us <= ub)
                .unwrap_or(N_BUCKET - 1);
            s.buckets[p][b].fetch_add(1, Ordering::Relaxed);
            s.sum_us[p].fetch_add(us, Ordering::Relaxed);
        }
    }

    /// Point-in-time totals across all slots.
    pub fn snapshot(&self) -> Snapshot {
        let mut snap = Snapshot::default();
        for s in &*self.slots {
            for (p, row) in s.queries.iter().enumerate() {
                for (i, c) in row.iter().enumerate() {
                    snap.queries[p][i] += c.load(Ordering::Relaxed);
                }
            }
            for (i, c) in s.rcodes.iter().enumerate() {
                snap.rcodes[i] += c.load(Ordering::Relaxed);
            }
            for (i, c) in s.qtypes.iter().enumerate() {
                snap.qtypes[i] += c.load(Ordering::Relaxed);
            }
            for (p, row) in s.buckets.iter().enumerate() {
                for (b, c) in row.iter().enumerate() {
                    snap.buckets[p][b] += c.load(Ordering::Relaxed);
                }
                snap.sum_us[p] += s.sum_us[p].load(Ordering::Relaxed);
            }
        }
        snap
    }
}

/// Summed counters (see [`Metrics::snapshot`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub queries: [[u64; N_STATUS]; 2],
    pub rcodes: [u64; N_RCODE],
    pub qtypes: [u64; N_QTYPE],
    /// Non-cumulative per-bucket counts; the last bucket is +Inf.
    pub buckets: [[u64; N_BUCKET]; N_PATH],
    pub sum_us: [u64; N_PATH],
}

impl Snapshot {
    pub fn total_queries(&self) -> u64 {
        self.queries.iter().flatten().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obs_005_record_and_snapshot_across_threads() {
        let m = std::sync::Arc::new(Metrics::new(4));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let m = std::sync::Arc::clone(&m);
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        m.record(
                            Proto::Udp,
                            Status::Cached,
                            Some(0),
                            1,
                            Duration::from_micros(30),
                        );
                    }
                    m.record(
                        Proto::Tcp,
                        Status::Forwarded,
                        Some(3),
                        28,
                        Duration::from_millis(20),
                    );
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let s = m.snapshot();
        assert_eq!(s.total_queries(), 8008);
        assert_eq!(
            s.queries[Proto::Udp as usize][Status::Cached as usize],
            8000
        );
        assert_eq!(s.rcodes[3], 8);
        assert_eq!(s.qtypes[0], 8000, "A");
        assert_eq!(
            s.buckets[Path::Cache as usize][0],
            8000,
            "30 µs lands in the 50 µs bucket"
        );
        assert_eq!(
            s.buckets[Path::Upstream as usize][8],
            8,
            "20 ms lands in the 25 ms bucket"
        );
    }
}
