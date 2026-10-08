//! The election's clock (REQ: CLU-005; ADR-056, amended after review 05-05).
//!
//! Leases are local durations: a voter promises not to vote for anyone else for
//! [`crate::election::LEASE_MS`], and a primary writes only until its own lease ends. Timing
//! them on the wall clock let a clock step break that promise: a Raspberry Pi has no RTC, starts
//! on the time it shut down with, and is stepped by NTP minutes or hours later, which made every
//! lease it had granted look expired at once. So leases are timed on a clock that never steps:
//! on Linux `CLOCK_BOOTTIME`, which also counts time spent suspended (a resumed VM must not
//! believe its lease still runs), elsewhere [`std::time::Instant`].
//!
//! Neither clock means anything in another process, so a ballot records which process's clock
//! its lease is on ([`id`]). A ballot from another process (a restart, or an older build that
//! used the wall clock) is taken as having granted a full lease just now
//! ([`crate::election::Ballot::adopt`]): never shorter than what was promised.

use std::sync::OnceLock;

/// Milliseconds on this node's election clock. Never steps; only differences mean anything.
pub fn now_ms() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let t = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let secs = u64::try_from(t.tv_sec).unwrap_or(0);
        let ms = u64::try_from(t.tv_nsec).unwrap_or(0) / 1_000_000;
        secs.saturating_mul(1000).saturating_add(ms)
    }
    #[cfg(not(target_os = "linux"))]
    {
        static START: OnceLock<std::time::Instant> = OnceLock::new();
        let start = *START.get_or_init(std::time::Instant::now);
        u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// This process's election clock, as recorded in its ballots. Never 0, which marks a ballot
/// whose lease is on the wall clock (written by a build from before this module).
pub fn id() -> u64 {
    static ID: OnceLock<u64> = OnceLock::new();
    *ID.get_or_init(|| rand::random::<u64>() | 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: CLU-005 — the election clock moves forward only, and a process keeps one clock.
    #[test]
    fn clu_005_the_election_clock_never_goes_back() {
        let a = now_ms();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let b = now_ms();
        assert!(b >= a + 4, "{a} then {b}");
        assert_eq!(id(), id());
        assert_ne!(id(), 0);
    }
}
