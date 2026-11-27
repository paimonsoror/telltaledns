//! REQ: DNS-020, DNS-003 (ADR-039, ADR-194) — the one limiter for the listeners' log lines about
//! PROXY headers and forwarded addresses: a line is written the first time, then at most once a
//! minute. Each line (a listener and a reason or level) has a gate of its own, so one line never
//! takes another's minute. The caller brings the clock, so tests move it by hand.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// How often a line may be written.
const EVERY_MS: u64 = 60_000;

/// One line's gate.
#[derive(Debug, Default)]
pub(crate) struct OncePerMinute {
    /// The clock at the last line, plus one: zero is "never".
    last: AtomicU64,
}

impl OncePerMinute {
    /// Whether the line is due at `now_ms`: the first time, then once a minute has passed. Of
    /// any number of threads that find it due together, exactly one is told so.
    pub(crate) fn due(&self, now_ms: u64) -> bool {
        let stamp = now_ms.saturating_add(1);
        let last = self.last.load(Ordering::Acquire);
        if last != 0 && stamp.saturating_sub(last) < EVERY_MS {
            return false;
        }
        self.last
            .compare_exchange(last, stamp, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

/// Milliseconds on a monotonic clock that starts with the first call (the DoH listener's
/// refusal lines; a listener's no-address lines keep a clock of their own).
pub(crate) fn now_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: DNS-003 (ADR-194) — a refusal's log line: the first one, then at most one a minute,
    /// and exactly one of several callers that find it due at once.
    #[test]
    fn dns_003_refusal_lines_at_most_once_a_minute() {
        let once = OncePerMinute::default();
        assert!(once.due(0));
        assert!(!once.due(1));
        assert!(!once.due(59_999));
        assert!(once.due(60_000));
        assert!(!once.due(60_001));
        assert!(once.due(500_000));
        let late = OncePerMinute::default();
        assert!(late.due(1_000_000), "the first line is never held back");
        let shared = OncePerMinute::default();
        let told: usize = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| s.spawn(|| usize::from(shared.due(5))))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap_or(0)).sum()
        });
        assert_eq!(told, 1);
    }
}
