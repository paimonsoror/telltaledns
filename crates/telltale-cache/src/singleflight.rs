//! In-flight deduplication: identical concurrent misses share one upstream request.
//!
//! REQ: DNS-006, `spec/03` §4 ("singleflight map keyed like the cache"). ADR-197: a query that
//! waits on a request takes its outcome, the answer or the failure; when the leader's own try
//! fails, it tries once more for the queries waiting on it, within the time they have left;
//! only a leader that goes away without an outcome leaves them to resolve on their own.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::watch;

use crate::CacheKey;

/// What a request in flight has come to so far.
#[derive(Clone, Debug)]
enum State {
    Pending,
    /// The shared answer and the upstream that gave it (REQ: OBS-001: coalesced clients are
    /// attributed to the leader's upstream).
    Answered(Arc<[u8]>, u16),
    /// No answer, after the leader's tries.
    Failed,
}

/// How a follower's wait ended ([`Waiter::wait`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The leader's answer, and the upstream that gave it.
    Answered(Arc<[u8]>, u16),
    /// The leader got no answer, after trying once more for its followers while one of them
    /// still had time ([`FlightGuard::retry_within`]): this query's outcome too.
    Failed,
    /// The leader went away without an outcome (cancelled with its caller): resolve on your
    /// own, within your own time.
    Abandoned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FlightKey {
    key: CacheKey,
    name: Box<[u8]>,
}

impl Hash for FlightKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

/// One request in flight.
#[derive(Debug)]
struct Entry {
    rx: watch::Receiver<State>,
    /// The latest deadline of the queries that joined it as followers.
    latest: Option<Instant>,
}

/// Map of in-flight upstream requests.
#[derive(Debug, Default)]
pub struct Singleflight {
    inflight: Mutex<HashMap<FlightKey, Entry>>,
}

/// Outcome of [`Singleflight::join`].
#[derive(Debug)]
pub enum Flight {
    /// No request in flight: you make it, then call [`FlightGuard::complete`] or
    /// [`FlightGuard::fail`].
    Leader(FlightGuard),
    /// Someone else is resolving it: await [`Waiter::wait`].
    Follower(Waiter),
}

/// A follower's side of a request in flight.
#[derive(Debug)]
pub struct Waiter(watch::Receiver<State>);

impl Waiter {
    /// Waits for the leader's outcome.
    pub async fn wait(mut self) -> Outcome {
        loop {
            match &*self.0.borrow_and_update() {
                State::Answered(answer, upstream) => {
                    return Outcome::Answered(Arc::clone(answer), *upstream);
                }
                State::Failed => return Outcome::Failed,
                State::Pending => {}
            }
            if self.0.changed().await.is_err() {
                return Outcome::Abandoned;
            }
        }
    }
}

impl Singleflight {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Becomes the leader for `(key, name)` or joins the request already in flight. `deadline`
    /// is when the joining query stops being wanted: a follower's counts toward the leader's
    /// second try ([`FlightGuard::retry_within`]).
    pub fn join(self: &Arc<Self>, key: CacheKey, name: &[u8], deadline: Instant) -> Flight {
        let fk = FlightKey {
            key,
            name: name.into(),
        };
        let mut map = self.inflight.lock();
        if let Some(e) = map.get_mut(&fk) {
            e.latest = Some(e.latest.map_or(deadline, |l| l.max(deadline)));
            return Flight::Follower(Waiter(e.rx.clone()));
        }
        let (tx, rx) = watch::channel(State::Pending);
        map.insert(fk.clone(), Entry { rx, latest: None });
        Flight::Leader(FlightGuard {
            owner: Arc::clone(self),
            key: Some(fk),
            tx,
        })
    }

    /// Number of distinct requests in flight.
    pub fn len(&self) -> usize {
        self.inflight.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Held by the leader. Dropping it without [`Self::complete`] or [`Self::fail`] releases the
/// followers with [`Outcome::Abandoned`].
#[derive(Debug)]
pub struct FlightGuard {
    owner: Arc<Singleflight>,
    key: Option<FlightKey>,
    tx: watch::Sender<State>,
}

impl FlightGuard {
    /// Publishes the answer, and the upstream that gave it, to all followers.
    pub fn complete(self, answer: Arc<[u8]>, upstream: u16) {
        let _ = self.tx.send(State::Answered(answer, upstream));
    }

    /// REQ: DNS-006 (ADR-197) — after the leader's own try failed: how long it may try once
    /// more for the queries waiting on it, the time left until the latest of their deadlines.
    /// `None` when no query waits, or less than `least` (or nothing) is left. The leader asks
    /// once and tries at most once more; queries that join meanwhile take that try's outcome,
    /// so a request makes at most two tries however many queries join it.
    pub fn retry_within(&self, now: Instant, least: Duration) -> Option<Duration> {
        let key = self.key.as_ref()?;
        let latest = self.owner.inflight.lock().get(key)?.latest?;
        Some(latest.saturating_duration_since(now)).filter(|left| !left.is_zero() && *left >= least)
    }

    /// Publishes that no answer came: every follower takes that outcome. The request leaves
    /// the map first, so a query that arrives after it makes a request of its own.
    pub fn fail(mut self) {
        if let Some(k) = self.key.take() {
            self.owner.inflight.lock().remove(&k);
        }
        let _ = self.tx.send(State::Failed);
    }

    /// How many queries wait on this request now.
    pub fn followers(&self) -> usize {
        // The map holds one receiver; each follower holds another.
        self.tx.receiver_count().saturating_sub(1)
    }
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        if let Some(k) = self.key.take() {
            self.owner.inflight.lock().remove(&k);
        }
    }
}
