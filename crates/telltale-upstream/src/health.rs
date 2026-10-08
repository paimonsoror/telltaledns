//! Per-upstream health: EWMA latency, rolling outcome window, and a circuit breaker.
//!
//! REQ: UPS-006, `spec/04` §5 — rolling window of the last 50 outcomes; > 50% errors with
//! ≥ 10 samples opens the breaker for 10 s (doubling to 5 min), then half-open (one probe).
//! Addition (ADR-013): 3 consecutive failures also open it, so a dead upstream stops costing
//! client latency after 3 queries instead of 10.

use std::time::{Duration, Instant};

use parking_lot::Mutex;

const WINDOW: usize = 50;
const WINDOW_U32: u32 = 50;
const MIN_SAMPLES: u32 = 10;
const CONSECUTIVE_TO_OPEN: u32 = 3;
const BASE_BACKOFF: Duration = Duration::from_secs(10);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// EWMA smoothing factor α (`spec/04` §4).
const ALPHA: f64 = 0.2;

/// Circuit breaker state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Breaker {
    Closed,
    Open,
    /// One probe allowed; its outcome closes or re-opens the breaker.
    HalfOpen,
}

/// REQ: UPS-006, OBS-011 — what an attempt came to. NOERROR and NXDOMAIN are successes;
/// everything else is a failure, counted by kind so that a failure rate can be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    /// No answer within the attempt's timeout.
    Timeout,
    /// A connection, TLS, or socket error.
    Network,
    /// An answer that didn't match the query or didn't parse.
    BadResponse,
    /// The upstream's hostname couldn't be resolved.
    Unresolved,
    ServFail,
    Refused,
    /// Any other RCODE (FORMERR, NOTIMP, ...).
    OtherRcode,
}

/// How many failure kinds [`Outcome`] has.
pub const FAILURE_KINDS: usize = 7;

impl Outcome {
    /// The failure kinds, in the order of [`HealthSnapshot::failures_by_kind`].
    pub const FAILURES: [Self; FAILURE_KINDS] = [
        Self::Timeout,
        Self::Network,
        Self::BadResponse,
        Self::Unresolved,
        Self::ServFail,
        Self::Refused,
        Self::OtherRcode,
    ];

    /// The metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Timeout => "timeout",
            Self::Network => "network",
            Self::BadResponse => "bad_response",
            Self::Unresolved => "unresolved",
            Self::ServFail => "servfail",
            Self::Refused => "refused",
            Self::OtherRcode => "other_rcode",
        }
    }

    fn index(self) -> Option<usize> {
        Self::FAILURES.iter().position(|k| *k == self)
    }

    /// REQ: UPS-006 — SERVFAIL and REFUSED are answers: the upstream is up and said no, which
    /// is often the domain's doing (a lame or DNSSEC-broken name that a browser retries). They
    /// still count in the rolling error window (an upstream that SERVFAILs half of everything
    /// is unhealthy) and still send the query to the next member, but they are not the
    /// upstream being *down*: they don't count toward the consecutive failures that open the
    /// breaker, and their latency is the real one, not the attempt's timeout.
    pub fn is_answer(self) -> bool {
        matches!(self, Self::ServFail | Self::Refused)
    }
}

/// A point-in-time view for metrics and the API (OBS-011).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HealthSnapshot {
    pub breaker: Breaker,
    pub ewma: Option<Duration>,
    /// Error share over the rolling window (0.0–1.0).
    pub error_rate: f64,
    pub requests: u64,
    pub failures: u64,
    /// `failures` by kind, in the order of [`Outcome::FAILURES`].
    pub failures_by_kind: [u64; FAILURE_KINDS],
}

#[derive(Debug)]
struct Inner {
    window: [bool; WINDOW],
    pos: usize,
    filled: u32,
    errors: u32,
    consecutive_failures: u32,
    breaker: Breaker,
    open_until: Option<Instant>,
    backoff: Duration,
    probe_in_flight: bool,
    ewma_us: Option<f64>,
    last_failure: Option<Instant>,
    last_used: Option<Instant>,
    requests: u64,
    failures: u64,
    by_kind: [u64; FAILURE_KINDS],
}

/// Thread-safe health tracker for one upstream.
#[derive(Debug)]
pub struct Health(Mutex<Inner>);

impl Default for Health {
    fn default() -> Self {
        Self(Mutex::new(Inner {
            window: [true; WINDOW],
            pos: 0,
            filled: 0,
            errors: 0,
            consecutive_failures: 0,
            breaker: Breaker::Closed,
            open_until: None,
            backoff: BASE_BACKOFF,
            probe_in_flight: false,
            ewma_us: None,
            last_failure: None,
            last_used: None,
            requests: 0,
            failures: 0,
            by_kind: [0; FAILURE_KINDS],
        }))
    }
}

/// Whether an upstream may be used for a query right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Healthy.
    Yes,
    /// Breaker half-open: this query is the probe (callers hedge it).
    Probe,
    No,
}

impl Health {
    /// Decides admission; transitions `Open` → `HalfOpen` when the backoff has elapsed.
    pub fn admit(&self, now: Instant) -> Admission {
        let mut h = self.0.lock();
        match h.breaker {
            Breaker::Closed => Admission::Yes,
            Breaker::Open if h.open_until.is_some_and(|t| now >= t) => {
                h.breaker = Breaker::HalfOpen;
                h.probe_in_flight = true;
                Admission::Probe
            }
            Breaker::HalfOpen if !h.probe_in_flight => {
                h.probe_in_flight = true;
                Admission::Probe
            }
            Breaker::Open | Breaker::HalfOpen => Admission::No,
        }
    }

    /// REQ: UPS-006, OBS-011 — records an attempt with what went wrong, so that failures can
    /// be told apart (`telltale_upstream_failures_total{kind}`); then as [`Self::record`].
    pub fn record_outcome(&self, outcome: Outcome, latency: Duration, now: Instant) {
        let mut h = self.0.lock();
        if let Some(i) = outcome.index() {
            h.by_kind[i] += 1;
        }
        let ok = outcome == Outcome::Ok;
        h.observe(ok, !ok && !outcome.is_answer(), latency, now);
    }

    /// Records an attempt's outcome. Failures count as `latency` toward the EWMA too, so a
    /// slow or dead upstream sorts behind healthy ones under `fastest`.
    pub fn record(&self, ok: bool, latency: Duration, now: Instant) {
        self.0.lock().observe(ok, !ok, latency, now);
    }
}

impl Inner {
    /// One attempt. `ok` goes into the rolling window; `down` (a failure that isn't an answer,
    /// see [`Outcome::is_answer`]) is what counts toward the consecutive failures that open the
    /// breaker, and an attempt that was answered ends the streak.
    fn observe(&mut self, ok: bool, down: bool, latency: Duration, now: Instant) {
        self.requests += 1;
        self.last_used = Some(now);
        let us = latency.as_secs_f64() * 1e6;
        self.ewma_us = Some(self.ewma_us.map_or(us, |e| ALPHA * us + (1.0 - ALPHA) * e));

        let pos = self.pos;
        if self.filled == WINDOW_U32 && !self.window[pos] {
            self.errors -= 1;
        }
        self.window[pos] = ok;
        self.pos = (pos + 1) % WINDOW;
        self.filled = (self.filled + 1).min(WINDOW_U32);
        if !ok {
            self.errors += 1;
            self.failures += 1;
        }
        if down {
            self.consecutive_failures += 1;
            self.last_failure = Some(now);
        } else {
            self.consecutive_failures = 0;
        }

        match self.breaker {
            Breaker::HalfOpen => {
                self.probe_in_flight = false;
                if ok {
                    self.breaker = Breaker::Closed;
                    self.backoff = BASE_BACKOFF;
                    self.reset_window();
                } else {
                    let next = (self.backoff * 2).min(MAX_BACKOFF);
                    self.backoff = next;
                    self.breaker = Breaker::Open;
                    self.open_until = Some(now + next);
                }
            }
            Breaker::Closed => {
                let too_many = self.filled >= MIN_SAMPLES && self.errors * 2 > self.filled;
                if too_many || self.consecutive_failures >= CONSECUTIVE_TO_OPEN {
                    self.breaker = Breaker::Open;
                    self.open_until = Some(now + self.backoff);
                    self.reset_window();
                }
            }
            Breaker::Open => {}
        }
    }
}

impl Health {
    /// Marks the upstream used (for active-check scheduling) without recording an outcome.
    pub fn touch(&self, now: Instant) {
        self.0.lock().last_used = Some(now);
    }

    pub fn ewma(&self) -> Option<Duration> {
        self.0
            .lock()
            .ewma_us
            .map(|us| Duration::from_secs_f64(us / 1e6))
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.0.lock().consecutive_failures
    }

    pub fn last_failure(&self) -> Option<Instant> {
        self.0.lock().last_failure
    }

    pub fn last_used(&self) -> Option<Instant> {
        self.0.lock().last_used
    }

    pub fn snapshot(&self) -> HealthSnapshot {
        let h = self.0.lock();
        HealthSnapshot {
            breaker: h.breaker,
            ewma: h.ewma_us.map(|us| Duration::from_secs_f64(us / 1e6)),
            error_rate: if h.filled == 0 {
                0.0
            } else {
                f64::from(h.errors) / f64::from(h.filled)
            },
            requests: h.requests,
            failures: h.failures,
            failures_by_kind: h.by_kind,
        }
    }
}

impl Inner {
    fn reset_window(&mut self) {
        self.window = [true; WINDOW];
        self.pos = 0;
        self.filled = 0;
        self.errors = 0;
        self.consecutive_failures = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn ups_006_three_consecutive_failures_open_then_half_open_probe_closes() {
        let h = Health::default();
        let t = Instant::now();
        for _ in 0..3 {
            assert_eq!(h.admit(t), Admission::Yes);
            h.record(false, 400 * MS, t);
        }
        assert_eq!(h.snapshot().breaker, Breaker::Open);
        assert_eq!(h.admit(t + Duration::from_secs(5)), Admission::No);
        // After the 10 s backoff: exactly one probe.
        let later = t + Duration::from_secs(11);
        assert_eq!(h.admit(later), Admission::Probe);
        assert_eq!(h.admit(later), Admission::No);
        h.record(true, MS, later);
        assert_eq!(h.snapshot().breaker, Breaker::Closed);
        assert_eq!(h.admit(later), Admission::Yes);
    }

    #[test]
    fn ups_006_failed_probe_doubles_backoff() {
        let h = Health::default();
        let t = Instant::now();
        for _ in 0..3 {
            h.record(false, MS, t);
        }
        let p1 = t + Duration::from_secs(10);
        assert_eq!(h.admit(p1), Admission::Probe);
        h.record(false, MS, p1);
        assert_eq!(
            h.admit(p1 + Duration::from_secs(15)),
            Admission::No,
            "backoff now 20 s"
        );
        assert_eq!(h.admit(p1 + Duration::from_secs(21)), Admission::Probe);
    }

    #[test]
    fn ups_006_error_rate_over_window_opens() {
        let h = Health::default();
        let t = Instant::now();
        // Alternate ok/fail (never 3 in a row) until > 50% with >= 10 samples.
        for i in 0..20 {
            h.record(i % 3 != 0, MS, t);
        }
        assert_eq!(
            h.snapshot().breaker,
            Breaker::Closed,
            "33% errors stays closed"
        );
        let h = Health::default();
        for i in 0..12 {
            h.record(i % 3 == 0, MS, t); // 2 of 3 fail, never 3 in a row
        }
        assert_eq!(h.snapshot().breaker, Breaker::Open);
    }

    /// REQ: UPS-006, OBS-011 — failures are counted by kind, and the total still matches.
    #[test]
    fn ups_006_failures_are_counted_by_kind() {
        let h = Health::default();
        let t = Instant::now();
        h.record_outcome(Outcome::Ok, MS, t);
        h.record_outcome(Outcome::ServFail, MS, t);
        h.record_outcome(Outcome::ServFail, MS, t);
        h.record_outcome(Outcome::Timeout, 400 * MS, t);
        let s = h.snapshot();
        assert_eq!((s.requests, s.failures), (4, 3));
        let by: Vec<(&str, u64)> = Outcome::FAILURES
            .iter()
            .zip(s.failures_by_kind)
            .filter(|(_, n)| *n > 0)
            .map(|(k, n)| (k.label(), n))
            .collect();
        assert_eq!(by, vec![("timeout", 1), ("servfail", 2)]);
    }

    /// REQ: UPS-006 (review 03-04) — SERVFAIL and REFUSED are answers: three in a row leave the
    /// breaker closed and end a streak of timeouts, but a resolver that answers them to more
    /// than half of everything still opens, and three timeouts open it.
    #[test]
    fn ups_006_servfail_does_not_open_the_breaker_by_itself() {
        let t = Instant::now();
        let h = Health::default();
        for _ in 0..3 {
            h.record_outcome(Outcome::ServFail, MS, t);
        }
        assert_eq!(h.snapshot().breaker, Breaker::Closed);
        assert_eq!(h.consecutive_failures(), 0);
        assert_eq!(
            h.snapshot().failures,
            3,
            "still failures, and counted by kind"
        );
        for _ in 0..3 {
            h.record_outcome(Outcome::Refused, MS, t);
        }
        assert_eq!(h.snapshot().breaker, Breaker::Closed);

        let h = Health::default();
        for _ in 0..3 {
            h.record_outcome(Outcome::Timeout, 400 * MS, t);
        }
        assert_eq!(h.snapshot().breaker, Breaker::Open);

        // An answer between two timeouts ends the streak.
        let h = Health::default();
        for o in [
            Outcome::Timeout,
            Outcome::ServFail,
            Outcome::Timeout,
            Outcome::Timeout,
        ] {
            h.record_outcome(o, MS, t);
        }
        assert_eq!(h.snapshot().breaker, Breaker::Closed);
        assert_eq!(h.consecutive_failures(), 2);

        // Half of everything SERVFAILing is unhealthy: the rolling window still counts it.
        let h = Health::default();
        for i in 0..40 {
            let o = if i % 3 == 0 {
                Outcome::Ok
            } else {
                Outcome::ServFail
            };
            h.record_outcome(o, MS, t);
        }
        assert_eq!(h.snapshot().breaker, Breaker::Open);
    }

    #[test]
    fn ups_005_ewma_tracks_latency() {
        let h = Health::default();
        let t = Instant::now();
        h.record(true, 10 * MS, t);
        assert_eq!(h.ewma(), Some(10 * MS));
        h.record(true, 20 * MS, t);
        let e = h.ewma().unwrap().as_secs_f64() * 1000.0;
        assert!((e - 12.0).abs() < 0.01, "{e}");
    }
}
