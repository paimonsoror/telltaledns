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

/// One position of a query's attempt order.
#[derive(Clone, Debug)]
struct Attempt {
    up: Arc<Upstream>,
    /// Start the next attempt at once rather than after this one's hedge delay: a probe, an
    /// exploratory pick, a last resort, or a member whose last attempt failed.
    hedge_now: bool,
    /// REQ: UPS-006 (ADR-165) — no member to hand over to: the attempt may use the rest of the
    /// query's budget ([`Upstream::timeout_for`]).
    patient: bool,
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
    /// REQ: DNS-015 (T9.9) — a member sends clients' subnets, so answers are cached per subnet.
    ecs_client: bool,
}

impl Group {
    pub fn new(name: impl Into<String>, members: Vec<Arc<Upstream>>, strategy: Strategy) -> Self {
        let n = members.len();
        let ecs_client = members.iter().any(|u| u.ecs_client);
        Self {
            ecs_client,
            name: name.into(),
            members,
            strategy,
            rr: AtomicUsize::new(0),
            wrr: Mutex::new(vec![0; n]),
        }
    }

    /// REQ: DNS-015 (T9.9) — true if answers depend on the client's subnet.
    pub fn ecs_client(&self) -> bool {
        self.ecs_client
    }

    pub fn members(&self) -> &[Arc<Upstream>] {
        &self.members
    }

    pub fn strategy(&self) -> Strategy {
        self.strategy
    }

    /// REQ: UPS-005 — how many members `parallel` starts at once; none for the strategies that
    /// try one member at a time.
    fn racing(&self) -> usize {
        match self.strategy {
            Strategy::Parallel { fanout } => fanout.max(1),
            _ => 0,
        }
    }

    /// Attempt order: admitted members in strategy order (probes marked), then the rest
    /// least-recently-failed first as a last resort. An attempt is patient
    /// ([`Upstream::timeout_for`], ADR-165) when its member's breaker is closed and it has no
    /// member to hand over to: the last such member, and for `parallel` each one among the
    /// first `fanout`, which start together. None is patient when every breaker is open or
    /// probing.
    fn attempt_order(&self, now: Instant) -> Vec<Attempt> {
        let mut ready = Vec::with_capacity(self.members.len());
        let mut rest = Vec::new();
        let mut closed = Vec::with_capacity(self.members.len());
        for (i, m) in self.members.iter().enumerate() {
            match m.health.admit(now) {
                // Hedge right away behind a member whose last attempt failed.
                Admission::Yes => {
                    closed.push(i);
                    ready.push((i, m.health.consecutive_failures() > 0));
                }
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
        let last_closed = ready.iter().rposition(|(i, _)| closed.contains(i));
        // REQ: UPS-005, UPS-006 (ADR-165) — the adaptive timeout is there to give up on one
        // member and hand over to the next. `parallel` starts its first `fanout` members at
        // once, so none of them has anyone to hand over to: cutting one off only throws away
        // its answer (a name it had to resolve itself) while the other is still waiting.
        let racing = self.racing();
        ready
            .into_iter()
            .enumerate()
            .map(|(pos, (i, hedge_now))| Attempt {
                up: Arc::clone(&self.members[i]),
                hedge_now,
                patient: closed.contains(&i) && (pos < racing || Some(pos) == last_closed),
            })
            .chain(rest.into_iter().map(|i| Attempt {
                up: Arc::clone(&self.members[i]),
                hedge_now: true,
                patient: false,
            }))
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
            let Attempt {
                up,
                hedge_now,
                patient,
            } = order.get(*next)?.clone();
            // REQ: UPS-006 (ADR-165) — the last healthy member, and `parallel`'s racing ones,
            // have nobody to hand over to.
            let timeout = up.timeout_for(patient);
            *next += 1;
            *attempts = attempts.saturating_add(1);
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let timeout = timeout.min(remaining);
            let delay = if hedge_now {
                Duration::ZERO
            } else {
                up.hedge_delay()
            };
            set.spawn(async move { (up.id, up.exchange(&q, timeout).await) });
            Some((delay, hedge_now))
        };

        // Initial launches: `parallel`'s racing members, else one (plus whatever follows a
        // must-hedge probe immediately).
        let initial = self.racing().max(1);
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
        // REQ: UPS-006 (ADR-165) — attempts still running when the query ends (at its deadline,
        // or with only a SERVFAIL or REFUSED in hand) finish in the background, as the losers
        // above do, so their outcome reaches the health tracker: dropping the set would abort
        // them, and a silent member would never be benched. Each still ends at its own timeout,
        // set from what was left of the budget when it started (a retry after a truncated
        // answer has some time of its own).
        set.detach_all();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::Endpoint;
    use crate::health::Breaker;

    const MS: Duration = Duration::from_millis(1);

    /// A member these tests never ask: they only compute the attempt order.
    fn member(id: u16) -> Arc<Upstream> {
        // TEST-NET-1 (RFC 5737): nothing is sent to it.
        let ep = Endpoint::parse("udp://192.0.2.1:53").unwrap();
        Arc::new(Upstream::new(id, format!("u{id}"), ep, 400 * MS, 1).unwrap())
    }

    /// Members 1..=n with measured latencies of 10, 20, 30 ms, so `fastest` and `parallel`
    /// sort them in that order (apart from the 5% exploration).
    fn members(n: u16, t: Instant) -> Vec<Arc<Upstream>> {
        (1..=n)
            .zip([10, 20, 30])
            .map(|(id, latency)| {
                let m = member(id);
                m.health.record(true, latency * MS, t);
                m
            })
            .collect()
    }

    /// Opens a member's breaker with three failures in a row, for 10 s from `t`.
    fn open(m: &Upstream, t: Instant) {
        for _ in 0..3 {
            m.health.record(false, MS, t);
        }
        assert_eq!(m.health.snapshot().breaker, Breaker::Open);
    }

    /// `(member id, patient)` at each position of the attempt order.
    fn patience(g: &Group, now: Instant) -> Vec<(u16, bool)> {
        g.attempt_order(now)
            .iter()
            .map(|a| (a.up.id, a.patient))
            .collect()
    }

    /// REQ: UPS-005, UPS-006 (ADR-165) — `parallel` starts its first `parallel_fanout` members
    /// together, so none of them has another to hand over to: every racing member with a closed
    /// breaker is patient, in whatever order the EWMA (and its 5% exploration) put them. With
    /// three members and a fanout of 2, the third is patient too, as the last healthy member.
    #[test]
    fn ups_005_parallel_racing_members_are_patient() {
        let t = Instant::now();
        for n in [2, 3] {
            let g = Group::new("p", members(n, t), Strategy::Parallel { fanout: 2 });
            // 200 orders: the exploration swap (5% each) happens in almost every run.
            for _ in 0..200 {
                let p = patience(&g, t);
                assert_eq!(p.len(), usize::from(n));
                assert!(p.iter().all(|&(_, patient)| patient), "{n} members: {p:?}");
            }
        }
    }

    /// REQ: UPS-006 (ADR-165) — a member whose breaker is open (a last resort) or half-open
    /// (the probe) is never patient, also in one of `parallel`'s racing slots (with two members
    /// and a fanout of 2 both slots race, and the initial wave starts both); the members with a
    /// closed breaker are.
    #[test]
    fn ups_006_probe_and_last_resort_never_patient() {
        let t = Instant::now();
        for n in [2, 3] {
            let ups = members(n, t);
            open(&ups[0], t);
            let g = Group::new("p", ups, Strategy::Parallel { fanout: 2 });
            for _ in 0..50 {
                let p = patience(&g, t);
                assert_eq!(p.len(), usize::from(n));
                assert!(
                    p.iter().all(|&(id, patient)| patient == (id != 1)),
                    "{n} members, member 1 open: {p:?}"
                );
            }
            // After the 10 s backoff the breaker is half-open: member 1 is admitted once, as
            // the probe (its 1 ms failures sort it first), then is a last resort again while
            // that probe is out.
            let later = t + Duration::from_secs(11);
            for round in ["the probe", "probe in flight"] {
                let p = patience(&g, later);
                assert_eq!(p.len(), usize::from(n));
                assert!(
                    p.iter().all(|&(id, patient)| patient == (id != 1)),
                    "{n} members, member 1 {round}: {p:?}"
                );
            }
        }
    }

    /// REQ: UPS-006 (ADR-165) — the strategies that try one member at a time keep ADR-165 as it
    /// was: only the last member with a closed breaker is patient. `failover` exactly; `fastest`
    /// (which explores), `round_robin` and `weighted` reorder, so for them: exactly one patient
    /// member, and it is the last one whose breaker is closed.
    #[test]
    fn ups_006_one_at_a_time_strategies_patient_only_last_closed() {
        let t = Instant::now();
        let ups = members(3, t);
        let g = Group::new("f", ups.clone(), Strategy::Failover);
        assert_eq!(patience(&g, t), [(1, false), (2, false), (3, true)]);
        open(&ups[2], t);
        assert_eq!(patience(&g, t), [(1, false), (2, true), (3, false)]);

        for strategy in [Strategy::Fastest, Strategy::RoundRobin, Strategy::Weighted] {
            let ups = members(3, t);
            open(&ups[1], t);
            let g = Group::new("o", ups, strategy);
            for _ in 0..200 {
                let p = patience(&g, t);
                let patient: Vec<usize> = p
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| entry.1)
                    .map(|(pos, _)| pos)
                    .collect();
                let last_closed = p.iter().rposition(|&(id, _)| id != 2);
                assert_eq!(patient.len(), 1, "{strategy:?}: {p:?}");
                assert_eq!(patient.first().copied(), last_closed, "{strategy:?}: {p:?}");
            }
        }
    }
}
