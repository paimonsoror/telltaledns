//! REQ: OBS-003, DNS-009 (T6.15) — the last hour of this node's cache, for the Cache page: the
//! cache's counters sampled every 15 s (a few hundred bytes per sample, off the query path),
//! and what happened to the cache dump at the last start.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use telltale_api::model::{CachePoint, CacheWarmStart};
use telltale_cache::{Cache, CacheStats};

/// How often the counters are sampled.
pub(crate) const INTERVAL: Duration = Duration::from_secs(15);
/// Samples kept: one hour.
const KEEP: usize = 241;

#[derive(Debug, Clone, Copy)]
struct Sample {
    ts_ms: u64,
    hits: u64,
    misses: u64,
    stale_served: u64,
    prefetches: u64,
    evictions: u64,
    entries: u64,
    bytes: u64,
}

impl Sample {
    fn of(s: &CacheStats, ts_ms: u64) -> Self {
        Self {
            ts_ms,
            hits: s.hits,
            misses: s.misses,
            stale_served: s.stale_served,
            prefetches: s.prefetches,
            evictions: s.evictions,
            entries: s.entries as u64,
            bytes: s.bytes as u64,
        }
    }
}

/// This node's cache history and warm-start record.
#[derive(Debug, Default)]
pub(crate) struct CacheHistory {
    samples: Mutex<VecDeque<Sample>>,
    warm: Option<CacheWarmStart>,
}

impl CacheHistory {
    pub(crate) fn new(warm: Option<CacheWarmStart>) -> Self {
        Self {
            samples: Mutex::default(),
            warm,
        }
    }

    pub(crate) fn warm_start(&self) -> Option<CacheWarmStart> {
        self.warm.clone()
    }

    /// Samples `cache` every [`INTERVAL`] until `stop`.
    pub(crate) fn spawn(
        self: &Arc<Self>,
        cache: Arc<Cache>,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                me.record(Sample::of(&cache.stats(), now_ms()));
                tokio::select! {
                    _ = stop.changed() => return,
                    () = tokio::time::sleep(INTERVAL) => {}
                }
            }
        });
    }

    fn record(&self, s: Sample) {
        let mut q = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        q.push_back(s);
        while q.len() > KEEP {
            q.pop_front();
        }
    }

    /// One point per interval between samples, oldest first. A counter that went down (the
    /// cache was flushed or the node restarted) counts from zero.
    pub(crate) fn points(&self) -> Vec<CachePoint> {
        let q = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
        q.iter()
            .zip(q.iter().skip(1))
            .map(|(a, b)| {
                let d = |x: u64, y: u64| if y >= x { y - x } else { y };
                let hits = d(a.hits, b.hits);
                let lookups = hits + d(a.misses, b.misses);
                #[allow(clippy::cast_precision_loss)] // a percentage for display
                let hit_percent =
                    (lookups > 0).then(|| (hits as f64 * 1000.0 / lookups as f64).round() / 10.0);
                let stale = d(a.stale_served, b.stale_served);
                // REQ: DNS-007 — fresh hits and expired entries answered (refreshed or stale).
                #[allow(clippy::cast_precision_loss)]
                let answered_percent = (lookups > 0).then(|| {
                    ((hits + stale).min(lookups) as f64 * 1000.0 / lookups as f64).round() / 10.0
                });
                CachePoint {
                    at: telltale_api::time::format_us(b.ts_ms.saturating_mul(1000)),
                    hit_percent,
                    answered_percent,
                    lookups,
                    stale_served: d(a.stale_served, b.stale_served),
                    prefetches: d(a.prefetches, b.prefetches),
                    evictions: d(a.evictions, b.evictions),
                    entries: b.entries,
                    bytes: b.bytes,
                }
            })
            .collect()
    }
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(ts_ms: u64, hits: u64, misses: u64, entries: u64) -> Sample {
        Sample {
            ts_ms,
            hits,
            misses,
            stale_served: 0,
            prefetches: 0,
            evictions: 0,
            entries,
            bytes: entries * 100,
        }
    }

    /// REQ: OBS-003 (T6.15) — points are per interval, a reset counts from zero, and only the
    /// last hour is kept.
    #[test]
    fn obs_003_cache_history_points() {
        let h = CacheHistory::new(None);
        assert!(h.points().is_empty());
        h.record(s(0, 100, 100, 10));
        h.record(s(15_000, 190, 110, 20)); // 90 hits, 10 misses
        h.record(s(30_000, 5, 5, 3)); // flushed or restarted: counts from zero
        h.record(s(45_000, 5, 5, 3)); // no lookups
        let p = h.points();
        assert_eq!(p.len(), 3);
        assert_eq!(
            (p[0].lookups, p[0].hit_percent, p[0].entries),
            (100, Some(90.0), 20)
        );
        assert_eq!((p[1].lookups, p[1].hit_percent), (10, Some(50.0)));
        assert_eq!((p[2].lookups, p[2].hit_percent), (0, None));
        for i in 0..400 {
            h.record(s(60_000 + i * 15_000, 0, 0, 0));
        }
        assert_eq!(h.points().len(), KEEP - 1);
    }

    /// REQ: DNS-007 — an expired entry answered at once (refreshed, or stale) is a miss to the
    /// cache's counters but an answer from the cache: `answered_percent` counts both.
    #[test]
    fn dns_007_answered_percent_counts_refreshed_answers() {
        let h = CacheHistory::new(None);
        h.record(s(0, 0, 0, 10));
        let mut b = s(15_000, 20, 80, 10); // 20 fresh hits, 80 misses...
        b.stale_served = 40; // ...of which 40 were answered from expired entries
        h.record(b);
        let p = h.points();
        assert_eq!(p[0].hit_percent, Some(20.0));
        assert_eq!(p[0].answered_percent, Some(60.0));
        assert_eq!(h.points().len(), 1);
    }
}
