//! REQ: OBS-021 (T11.2, ADR-106) — whether the cache is the right size, from the cache's own
//! counters: the estimated extra hits a 1.25×, 1.5×, and 2× cache would have served (a sampled
//! ghost list of evicted keys, `telltale_cache::s3fifo`), and its peak use. Pure: the numbers in,
//! the advice out; nothing here touches the query path.

use telltale_api::model::{CacheSizing, CacheSizingStep};
use telltale_cache::CacheStats;

/// Lookups needed before any advice (fewer say too little).
pub(crate) const MIN_LOOKUPS: u64 = 10_000;
/// Lookups needed before suggesting a smaller cache (it must have had a chance to fill).
pub(crate) const MIN_LOOKUPS_SHRINK: u64 = 100_000;
/// Extra hits (percentage points of lookups) worth growing for.
pub(crate) const GROW_POINTS: f64 = 1.0;
/// Never suggest less than this.
const FLOOR_BYTES: u64 = 4 << 20;

#[allow(clippy::cast_precision_loss)] // counts and byte sizes as shares
fn points(extra: u64, lookups: u64) -> f64 {
    if lookups == 0 {
        0.0
    } else {
        (extra as f64 * 1000.0 / lookups as f64).round() / 10.0
    }
}

fn mib(b: u64) -> String {
    if b >= 1 << 30 {
        #[allow(clippy::cast_precision_loss)]
        let g = b as f64 / f64::from(1u32 << 30);
        format!("{g:.1} GiB")
    } else {
        format!("{} MiB", b.div_ceil(1 << 20))
    }
}

/// The advice for one node's cache with a memory budget of `max_bytes`.
pub(crate) fn advise(s: &CacheStats, max_bytes: u64) -> CacheSizing {
    let lookups = s.hits + s.misses;
    let steps: Vec<CacheSizingStep> = telltale_cache::s3fifo::SIZING_STEPS
        .iter()
        .zip(s.ghost_hits)
        .map(|(pct, extra)| CacheSizingStep {
            size_percent: 100 + u32::try_from(*pct).unwrap_or(0),
            extra_hits: extra,
            extra_hit_percent: points(extra, lookups),
            extra_bytes: max_bytes * pct / 100,
        })
        .collect();
    let peak = s.peak_bytes as u64;
    let (verdict, advice, suggested) = if lookups < MIN_LOOKUPS {
        (
            "learning",
            format!(
                "Not enough lookups yet to judge ({lookups} of {MIN_LOOKUPS}): check back after some traffic."
            ),
            None,
        )
    } else if let Some(step) = steps.iter().find(|x| x.extra_hit_percent >= GROW_POINTS) {
        let biggest = steps.last().map_or(0.0, |x| x.extra_hit_percent);
        let more = if step.size_percent < 200 {
            format!(" (doubling it: about {biggest:.1}% more)")
        } else {
            String::new()
        };
        (
            "grow",
            format!(
                "A cache {}% larger (+{}) would have answered about {:.1}% more lookups from memory{more}. Raise [cache] max_bytes to {} if the memory is there.",
                step.size_percent - 100,
                mib(step.extra_bytes),
                step.extra_hit_percent,
                mib(max_bytes + step.extra_bytes),
            ),
            Some(max_bytes + step.extra_bytes),
        )
    } else if s.evictions == 0 && lookups >= MIN_LOOKUPS_SHRINK && peak * 2 < max_bytes {
        let target = (peak + peak / 2).max(FLOOR_BYTES).next_multiple_of(1 << 20);
        (
            "shrink",
            format!(
                "The cache never filled: at most {} of its {} were used, and nothing was evicted. [cache] max_bytes = \"{}\" would leave room to spare and free memory.",
                mib(peak),
                mib(max_bytes),
                mib(target).replace(' ', "")
            ),
            Some(target),
        )
    } else {
        let biggest = steps.last().map_or(0.0, |x| x.extra_hit_percent);
        (
            "ok",
            format!(
                "The size fits: doubling the cache would answer about {biggest:.1}% more lookups from memory."
            ),
            None,
        )
    };
    CacheSizing {
        verdict: verdict.to_owned(),
        advice,
        lookups,
        steps,
        peak_bytes: peak,
        suggested_max_bytes: suggested,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(hits: u64, misses: u64, ghost: [u64; 3], evictions: u64, peak: usize) -> CacheStats {
        CacheStats {
            hits,
            misses,
            ghost_hits: ghost,
            evictions,
            peak_bytes: peak,
            ..CacheStats::default()
        }
    }

    // REQ: OBS-021 — too few lookups: no advice yet.
    #[test]
    fn obs_021_learning_first() {
        let a = advise(&stats(100, 50, [10, 20, 30], 5, 1 << 20), 32 << 20);
        assert_eq!(a.verdict, "learning");
        assert_eq!(a.suggested_max_bytes, None);
    }

    // REQ: OBS-021 — the smallest size that adds at least a point of hits is suggested.
    #[test]
    fn obs_021_grow_to_the_smallest_step_that_helps() {
        // 100k lookups: +25% adds 0.5 points, +50% 1.5, +100% 4.
        let a = advise(
            &stats(60_000, 40_000, [500, 1500, 4000], 9000, 32 << 20),
            32 << 20,
        );
        assert_eq!(a.verdict, "grow");
        assert_eq!(a.steps[1].size_percent, 150);
        assert_eq!(a.steps[1].extra_hit_percent, 1.5);
        assert_eq!(a.suggested_max_bytes, Some(48 << 20));
        assert!(a.advice.contains("50% larger (+16 MiB)"), "{}", a.advice);
        assert!(
            a.advice.contains("doubling it: about 4.0% more"),
            "{}",
            a.advice
        );
    }

    // REQ: OBS-021 — a cache that never filled can shrink (to its peak plus half, at least
    // 4 MiB); a full one that a bigger size wouldn't help is fine as it is.
    #[test]
    fn obs_021_shrink_and_ok() {
        let a = advise(&stats(150_000, 50_000, [0, 0, 0], 0, 5 << 20), 64 << 20);
        assert_eq!(a.verdict, "shrink");
        assert_eq!(a.suggested_max_bytes, Some(8 << 20));
        assert!(
            a.advice.contains("at most 5 MiB of its 64 MiB"),
            "{}",
            a.advice
        );
        let a = advise(&stats(150_000, 50_000, [0, 0, 0], 0, 1 << 20), 64 << 20);
        assert_eq!(a.suggested_max_bytes, Some(4 << 20), "the floor");
        // Too early to shrink: the cache may not have had time to fill.
        let a = advise(&stats(15_000, 5_000, [0, 0, 0], 0, 1 << 20), 64 << 20);
        assert_eq!(a.verdict, "ok");
        let a = advise(
            &stats(150_000, 50_000, [100, 200, 300], 70_000, 64 << 20),
            64 << 20,
        );
        assert_eq!(a.verdict, "ok");
        assert!(a.advice.contains("about 0.2% more"), "{}", a.advice);
    }
}
