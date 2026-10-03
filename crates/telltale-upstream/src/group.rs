//! Upstream groups: selection strategies, retries within a time budget, and hedging.
//!
//! REQ: UPS-005 (`failover`, `round_robin`, `weighted`, `fastest`, `parallel`), UPS-006 (failover within
//! one query, never SERVFAIL without at least one attempt). ADR-013 (hedged attempts).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use telltale_proto::{rcode, summarize};
use tokio::task::JoinSet;

use crate::health::Admission;
use crate::upstream::{ExchangeError, Question, Upstream};

/// Selection strategy (`spec/04` §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    Failover,
    RoundRobin,
    Weighted,
    Fastest,
    Parallel { fanout: usize },
}

/// Probability that `fastest` explores another member (`spec/04` §4: ε = 5%).
const EPSILON: f64 = 0.05;

/// A successful resolution.
#[derive(Clone, Debug)]
pub struct Answer {
    pub bytes: Vec<u8>,
    /// Upstream that answered.
    pub upstream_id: u16,
    pub attempts: u8,
}

/// Why resolution failed entirely.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("all upstreams failed ({attempts} attempts); last error: {last}")]
    AllFailed { attempts: u8, last: String },
    #[error("time budget exhausted after {attempts} attempts")]
    Budget { attempts: u8 },
    #[error("group has no members")]
    Empty,
}

/// A named set of upstreams with a strategy.
#[derive(Debug)]
pub struct Group {
    pub name: String,
    members: Vec<Arc<Upstream>>,
    strategy: Strategy,
    rr: AtomicUsize,
    /// Smooth weighted round-robin state (current weights).
    wrr: Mutex<Vec<i64>>,
}

impl Group {
    pub fn new(name: impl Into<String>, members: Vec<Arc<Upstream>>, strategy: Strategy) -> Self {
        let n = members.len();
        Self {
            name: name.into(),
            members,
            strategy,
            rr: AtomicUsize::new(0),
            wrr: Mutex::new(vec![0; n]),
        }
    }

    pub fn members(&self) -> &[Arc<Upstream>] {
        &self.members
    }

    pub fn strategy(&self) -> Strategy {
        self.strategy
    }

    /// Attempt order: admitted members in strategy order (probes marked), then the rest
    /// least-recently-failed first as a last resort. Each entry: `(upstream, must_hedge)`.
    fn attempt_order(&self, now: Instant) -> Vec<(Arc<Upstream>, bool)> {
        let mut ready = Vec::with_capacity(self.members.len());
        let mut rest = Vec::new();
        for (i, m) in self.members.iter().enumerate() {
            match m.health.admit(now) {
                // Hedge right away behind a member whose last attempt failed.
                Admission::Yes => ready.push((i, m.health.consecutive_failures() > 0)),
                Admission::Probe => ready.push((i, true)),
                Admission::No => rest.push(i),
            }
        }
        match self.strategy {
            Strategy::RoundRobin if !ready.is_empty() => {
                let k = self.rr.fetch_add(1, Ordering::Relaxed) % ready.len();
                ready.rotate_left(k);
            }
            Strategy::Weighted if !ready.is_empty() => {
                let first = self.pick_weighted(&ready);
                ready.retain(|&(i, _)| i != first.0);
                ready.sort_by_key(|&(i, _)| std::cmp::Reverse(self.members[i].weight));
                ready.insert(0, first);
            }
            Strategy::Fastest | Strategy::Parallel { .. } => {
                // Unknown latency sorts first so new members get measured (hedged anyway).
                ready
                    .sort_by_key(|&(i, _)| self.members[i].health.ewma().unwrap_or(Duration::ZERO));
                if ready.len() > 1 && rand::random::<f64>() < EPSILON {
                    let j = 1 + rand::random_range(0..ready.len() - 1);
                    ready.swap(0, j);
                    // An exploratory pick must not cost the client latency.
                    ready[0].1 = true;
                }
            }
            Strategy::Failover | Strategy::RoundRobin | Strategy::Weighted => {}
        }
        rest.sort_by_key(|&i| self.members[i].health.last_failure());
        ready
            .into_iter()
            .map(|(i, hedge)| (Arc::clone(&self.members[i]), hedge))
            .chain(
                rest.into_iter()
                    .map(|i| (Arc::clone(&self.members[i]), true)),
            )
            .collect()
    }

    /// Smooth weighted round robin (nginx algorithm) over the admitted members.
    fn pick_weighted(&self, ready: &[(usize, bool)]) -> (usize, bool) {
        let mut cur = self.wrr.lock();
        let total: i64 = ready
            .iter()
            .map(|&(i, _)| i64::from(self.members[i].weight))
            .sum();
        let mut best = ready[0];
        let mut best_w = i64::MIN;
        for &(i, h) in ready {
            cur[i] += i64::from(self.members[i].weight);
            if cur[i] > best_w {
                best_w = cur[i];
                best = (i, h);
            }
        }
        cur[best.0] -= total;
        best
    }

    /// Resolves `q` within `budget`.
    ///
    /// Attempts run in strategy order. If an attempt hasn't answered within its upstream's
    /// hedge delay, the next one starts in parallel; the first good answer wins and the rest
    /// are cancelled. Probes and exploration are always hedged immediately behind a known-good
    /// member, so they never add client latency. SERVFAIL/REFUSED answers are kept as a
    /// fallback while other members are tried.
    pub async fn resolve(&self, q: Question, budget: Duration) -> Result<Answer, ResolveError> {
        let start = Instant::now();
        let order = self.attempt_order(start);
        if order.is_empty() {
            return Err(ResolveError::Empty);
        }
        let deadline = tokio::time::Instant::now() + budget;
        let mut set: JoinSet<(u16, Result<Vec<u8>, ExchangeError>)> = JoinSet::new();
        let mut next = 0usize;
        let mut attempts = 0u8;
        let mut fallback: Option<Answer> = None;
        let mut last_err = String::new();
        let mut next_hedge = tokio::time::Instant::now();

        let launch = |set: &mut JoinSet<_>,
                      next: &mut usize,
                      attempts: &mut u8|
         -> Option<(Duration, bool)> {
            let (up, hedge_now) = order.get(*next)?.clone();
            *next += 1;
            *attempts = attempts.saturating_add(1);
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let timeout = up.attempt_timeout().min(remaining);
            let delay = if hedge_now {
                Duration::ZERO
            } else {
                up.hedge_delay()
            };
            set.spawn(async move { (up.id, up.exchange(&q, timeout).await) });
            Some((delay, hedge_now))
        };

        // Initial launches: `fanout` members for parallel, else one (plus whatever follows a
        // must-hedge probe immediately).
        let initial = match self.strategy {
            Strategy::Parallel { fanout } => fanout.max(1),
            _ => 1,
        };
        for _ in 0..initial {
            if let Some((d, _)) = launch(&mut set, &mut next, &mut attempts) {
                next_hedge = tokio::time::Instant::now() + d;
            }
        }

        loop {
            // A zero hedge delay means "start the next one right away".
            while next_hedge <= tokio::time::Instant::now() && next < order.len() {
                match launch(&mut set, &mut next, &mut attempts) {
                    Some((d, _)) => next_hedge = tokio::time::Instant::now() + d,
                    None => break,
                }
            }
            if set.is_empty() {
                if next >= order.len() {
                    break;
                }
                next_hedge = tokio::time::Instant::now();
                continue;
            }
            let hedge_sleep = if next < order.len() {
                next_hedge
            } else {
                deadline
            };
            tokio::select! {
                joined = set.join_next() => {
                    let Some(Ok((upstream_id, res))) = joined else { continue };
                    match res {
                        Ok(bytes) => {
                            let rc = summarize(&bytes).map_or(rcode::SERVFAIL, |s| s.rcode);
                            let answer = Answer { bytes, upstream_id, attempts };
                            if rc == rcode::NOERROR || rc == rcode::NXDOMAIN {
                                // Let losing attempts finish in the background so their real
                                // outcome (often a timeout) reaches the health tracker. Aborting
                                // them would hide a dead upstream forever.
                                set.detach_all();
                                return Ok(answer);
                            }
                            fallback.get_or_insert(answer);
                            last_err = format!("rcode {rc}");
                        }
                        Err(e) => last_err = e.to_string(),
                    }
                    // A failure ends the wait for this attempt: start the next one now.
                    next_hedge = tokio::time::Instant::now();
                }
                () = tokio::time::sleep_until(hedge_sleep) => {
                    if tokio::time::Instant::now() >= deadline {
                        break;
                    }
                }
            }
        }
        match fallback {
            Some(mut a) => {
                a.attempts = attempts;
                Ok(a)
            }
            None if tokio::time::Instant::now() >= deadline => {
                Err(ResolveError::Budget { attempts })
            }
            None => Err(ResolveError::AllFailed {
                attempts,
                last: last_err,
            }),
        }
    }
}
