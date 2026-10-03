//! In-flight deduplication: identical concurrent misses share one upstream request.
//!
//! REQ: DNS-006, `spec/03` §4 ("singleflight map keyed like the cache").

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::watch;

use crate::CacheKey;

type Answer = Option<Arc<[u8]>>;

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

/// Map of in-flight upstream requests.
#[derive(Debug, Default)]
pub struct Singleflight {
    inflight: Mutex<HashMap<FlightKey, watch::Receiver<Answer>>>,
}

/// Outcome of [`Singleflight::join`].
#[derive(Debug)]
pub enum Flight {
    /// No request in flight: you make it, then call [`FlightGuard::complete`].
    Leader(FlightGuard),
    /// Someone else is resolving it: await [`Flight::wait`].
    Follower(watch::Receiver<Answer>),
}

impl Flight {
    /// For followers: waits for the leader's answer. `None` means the leader gave up without
    /// an answer, so resolve independently.
    pub async fn wait(mut rx: watch::Receiver<Answer>) -> Answer {
        loop {
            if let Some(v) = rx.borrow_and_update().clone() {
                return Some(v);
            }
            rx.changed().await.ok()?;
        }
    }
}

impl Singleflight {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Becomes the leader for `(key, name)` or joins the request already in flight.
    pub fn join(self: &Arc<Self>, key: CacheKey, name: &[u8]) -> Flight {
        let fk = FlightKey {
            key,
            name: name.into(),
        };
        let mut map = self.inflight.lock();
        if let Some(rx) = map.get(&fk) {
            return Flight::Follower(rx.clone());
        }
        let (tx, rx) = watch::channel(None);
        map.insert(fk.clone(), rx);
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

/// Held by the leader. Dropping it without completing releases followers with `None`.
#[derive(Debug)]
pub struct FlightGuard {
    owner: Arc<Singleflight>,
    key: Option<FlightKey>,
    tx: watch::Sender<Answer>,
}

impl FlightGuard {
    /// Publishes the answer to all followers.
    pub fn complete(self, answer: Arc<[u8]>) {
        let _ = self.tx.send(Some(answer));
    }
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        if let Some(k) = self.key.take() {
            self.owner.inflight.lock().remove(&k);
        }
    }
}
