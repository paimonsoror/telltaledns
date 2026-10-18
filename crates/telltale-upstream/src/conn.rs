//! Pooled, pipelined stream connections for TCP and DoT upstreams.
//!
//! REQ: UPS-008 — connection reuse and pipelining (RFC 7766 §6.2.1.1), configurable pool size,
//! idle timeout. Each connection is one task that owns the stream: queries are written as they
//! arrive and responses are matched back by message ID, so many queries share one connection.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::upstream::ExchangeError;

/// A bidirectional byte stream (plain TCP or TLS).
pub(crate) trait Io: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Io for T {}
pub(crate) type BoxIo = Box<dyn Io>;

pub(crate) type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<BoxIo>> + Send>>;
/// Opens a new stream to the upstream.
pub(crate) type Connector = Arc<dyn Fn() -> ConnectFuture + Send + Sync>;

/// Queries queued on one connection before a new connection is opened (if the pool allows).
const BUSY_THRESHOLD: usize = 32;

/// A connection that has had a query waiting this long with no answer at all in that time is
/// dead (a silently dropped connection: no FIN, no reset). Longer than any attempt timeout, so a
/// slow answer on a quiet connection isn't mistaken for one.
const STALE: Duration = Duration::from_secs(3);

/// How often a connection with queries waiting checks for staleness and drops the waiters that
/// gave up.
const TICK: Duration = Duration::from_millis(500);

/// Why a pooled connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Close {
    /// Unused for the idle timeout.
    Idle,
    /// The server closed it (or reset it).
    Server,
    /// Writing a query failed.
    Write,
    /// Queries waited with no answer at all for [`STALE`]: dropped silently somewhere.
    Unanswered,
    /// The pool was dropped (a configuration change).
    Unused,
}

impl Close {
    pub const ALL: [Self; 5] = [
        Self::Idle,
        Self::Server,
        Self::Write,
        Self::Unanswered,
        Self::Unused,
    ];

    /// Metric label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Server => "server",
            Self::Write => "write_failed",
            Self::Unanswered => "unanswered",
            Self::Unused => "unused",
        }
    }
}

/// REQ: UPS-008, OBS-011 — connection counters for one upstream (`spec/04` §5): how often it
/// connects, how long that takes, whether TLS sessions resume, and why connections end.
#[derive(Debug, Default)]
pub struct ConnStats {
    opened: AtomicU64,
    open_failed: AtomicU64,
    /// Microseconds spent opening connections (TCP, and TLS if any), successful ones.
    connect_us: AtomicU64,
    tls_full: AtomicU64,
    tls_resumed: AtomicU64,
    closed: [AtomicU64; 5],
    /// Queries sent again on a fresh connection because the pooled one closed first.
    retried: AtomicU64,
    /// Live pooled connections (the pool's own count; DoH keeps one of its own).
    live: AtomicU64,
}

/// A copy of [`ConnStats`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnSnapshot {
    pub opened: u64,
    pub open_failed: u64,
    pub connect_us: u64,
    pub tls_full: u64,
    pub tls_resumed: u64,
    /// By [`Close::ALL`].
    pub closed: [u64; 5],
    pub retried: u64,
    pub live: u64,
}

impl ConnStats {
    pub fn snapshot(&self) -> ConnSnapshot {
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        ConnSnapshot {
            opened: get(&self.opened),
            open_failed: get(&self.open_failed),
            connect_us: get(&self.connect_us),
            tls_full: get(&self.tls_full),
            tls_resumed: get(&self.tls_resumed),
            closed: self.closed.each_ref().map(get),
            retried: get(&self.retried),
            live: get(&self.live),
        }
    }

    /// A TLS handshake finished, from a stored session or not.
    pub(crate) fn tls(&self, resumed: bool) {
        let c = if resumed {
            &self.tls_resumed
        } else {
            &self.tls_full
        };
        c.fetch_add(1, Ordering::Relaxed);
    }

    fn closed(&self, why: Close) {
        let i = Close::ALL.iter().position(|c| *c == why).unwrap_or(0);
        self.closed[i].fetch_add(1, Ordering::Relaxed);
    }
}

/// Counts and times every connection `c` opens.
pub(crate) fn counted(c: Connector, stats: Arc<ConnStats>) -> Connector {
    Arc::new(move || {
        let (c, stats) = (Arc::clone(&c), Arc::clone(&stats));
        Box::pin(async move {
            let start = Instant::now();
            let r = c().await;
            if r.is_ok() {
                stats.opened.fetch_add(1, Ordering::Relaxed);
                let us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                stats.connect_us.fetch_add(us, Ordering::Relaxed);
            } else {
                stats.open_failed.fetch_add(1, Ordering::Relaxed);
            }
            r
        })
    })
}

struct Request {
    msg: Vec<u8>,
    id: u16,
    reply: oneshot::Sender<Vec<u8>>,
}

#[derive(Debug)]
struct Conn {
    tx: mpsc::Sender<Request>,
    inflight: Arc<AtomicUsize>,
    dead: Arc<AtomicBool>,
}

/// A pool of pipelined connections to one upstream.
pub(crate) struct Pool {
    inner: Arc<Inner>,
}

struct Inner {
    connector: Connector,
    conns: Mutex<Vec<Arc<Conn>>>,
    max: usize,
    idle: Duration,
    stats: Arc<ConnStats>,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("max", &self.inner.max)
            .field("conns", &self.inner.conns.lock().len())
            .finish_non_exhaustive()
    }
}

impl Pool {
    /// A pool whose connections are counted in `stats` (closes, retries, live; the connector
    /// counts the opens, see [`counted`]).
    pub(crate) fn new(
        connector: Connector,
        max: usize,
        idle: Duration,
        stats: Arc<ConnStats>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                connector,
                conns: Mutex::new(Vec::new()),
                max: max.max(1),
                idle,
                stats,
            }),
        }
    }

    /// Live connections (for tests and metrics).
    pub(crate) fn len(&self) -> usize {
        let mut c = self.inner.conns.lock();
        c.retain(|c| !c.dead.load(Ordering::Acquire));
        c.len()
    }

    /// Sends `msg` (whose ID is `id`) and waits for the response with the same ID. The caller
    /// applies the timeout and validates the response.
    pub(crate) async fn exchange(
        &self,
        mut msg: Vec<u8>,
        id: u16,
    ) -> Result<Vec<u8>, ExchangeError> {
        // One retry on a fresh connection if the pooled one turns out to be closed: either
        // before the query is written, or (T10.9) after, when the server closes an idle
        // connection just as the query goes out and never answers. Queries are idempotent.
        for attempt in 0..2 {
            if attempt > 0 {
                self.inner.stats.retried.fetch_add(1, Ordering::Relaxed);
            }
            let conn = self.get(attempt > 0).await?;
            let (reply, rx) = oneshot::channel();
            let m = if attempt == 0 {
                msg.clone()
            } else {
                std::mem::take(&mut msg)
            };
            conn.inflight.fetch_add(1, Ordering::AcqRel);
            let _guard = Decrement(Arc::clone(&conn.inflight));
            if conn.tx.send(Request { msg: m, id, reply }).await.is_err() {
                conn.dead.store(true, Ordering::Release);
                continue;
            }
            if let Ok(resp) = rx.await {
                return Ok(resp);
            }
            conn.dead.store(true, Ordering::Release);
        }
        Err(ExchangeError::Io(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "upstream connection closed",
        )))
    }

    /// The least-loaded live connection, or a new one if there is none, all are busy and the
    /// pool has room, or `fresh` is requested.
    async fn get(&self, fresh: bool) -> Result<Arc<Conn>, ExchangeError> {
        {
            let mut conns = self.inner.conns.lock();
            conns.retain(|c| !c.dead.load(Ordering::Acquire));
            let best = conns
                .iter()
                .min_by_key(|c| c.inflight.load(Ordering::Acquire))
                .cloned();
            if let Some(c) = best
                && !fresh
                && (c.inflight.load(Ordering::Acquire) < BUSY_THRESHOLD
                    || conns.len() >= self.inner.max)
            {
                return Ok(c);
            }
        }
        // The connection is opened in a task of its own: if this query's time runs out during
        // the handshake, the connection still joins the pool for the next query, instead of
        // every query after a quiet spell starting (and abandoning) a handshake of its own.
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move { inner.open().await })
            .await
            .map_err(|e| ExchangeError::Io(io::Error::other(e)))?
    }
}

impl Inner {
    /// Opens a connection and adds it to the pool.
    async fn open(&self) -> Result<Arc<Conn>, ExchangeError> {
        let io = (self.connector)().await?;
        let (tx, rx) = mpsc::channel(256);
        let conn = Arc::new(Conn {
            tx,
            inflight: Arc::new(AtomicUsize::new(0)),
            dead: Arc::new(AtomicBool::new(false)),
        });
        self.stats.live.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(run_conn(
            io,
            rx,
            self.idle,
            Arc::clone(&conn.dead),
            Arc::clone(&self.stats),
        ));
        let mut conns = self.conns.lock();
        if conns.len() >= self.max {
            // Lost a race with another opener; evict the busiest to stay within the cap.
            if let Some((i, _)) = conns
                .iter()
                .enumerate()
                .max_by_key(|(_, c)| c.inflight.load(Ordering::Acquire))
            {
                conns.remove(i);
            }
        }
        conns.push(Arc::clone(&conn));
        Ok(conn)
    }
}

struct Decrement(Arc<AtomicUsize>);
impl Drop for Decrement {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Owns one stream: writes queued queries, routes responses to waiters by ID, closes when idle,
/// and when queries go unanswered for [`STALE`] with nothing at all coming back.
async fn run_conn(
    io: BoxIo,
    rx: mpsc::Receiver<Request>,
    idle: Duration,
    dead: Arc<AtomicBool>,
    stats: Arc<ConnStats>,
) {
    let why = serve_conn(io, rx, idle, &dead).await;
    dead.store(true, Ordering::Release);
    stats.closed(why);
    stats.live.fetch_sub(1, Ordering::Relaxed);
}

async fn serve_conn(
    io: BoxIo,
    mut rx: mpsc::Receiver<Request>,
    idle: Duration,
    dead: &AtomicBool,
) -> Close {
    let (mut rd, mut wr) = tokio::io::split(io);
    let (resp_tx, mut resp_rx) = mpsc::channel::<Vec<u8>>(64);
    // Reading isn't cancel-safe mid-frame, so it gets its own task.
    let reader = tokio::spawn(async move {
        loop {
            let mut len = [0u8; 2];
            if rd.read_exact(&mut len).await.is_err() {
                break;
            }
            let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
            if rd.read_exact(&mut buf).await.is_err() || resp_tx.send(buf).await.is_err() {
                break;
            }
        }
    });
    // Each waiter with when its query went out. One whose caller gave up (timed out) stays
    // until STALE has passed, so a connection that answers nothing at all is noticed.
    let mut pending: HashMap<u16, (oneshot::Sender<Vec<u8>>, Instant)> = HashMap::new();
    let (mut sent, mut answered) = (0u32, 0u32);
    let mut heard = Instant::now();
    // An interval, not a sleep made each turn: a busy connection must be checked too.
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let why = loop {
        let idle_timer = tokio::time::sleep(idle);
        tokio::select! {
            req = rx.recv() => {
                let Some(req) = req else { break Close::Unused };
                if req.reply.is_closed() {
                    continue; // the caller is gone
                }
                if let Some((w, _)) = pending.get(&req.id)
                    && !w.is_closed()
                {
                    continue; // ID collision: the waiter sees a closed channel
                }
                let Ok(len) = u16::try_from(req.msg.len()) else { continue };
                let mut framed = Vec::with_capacity(req.msg.len() + 2);
                framed.extend_from_slice(&len.to_be_bytes());
                framed.extend_from_slice(&req.msg);
                if wr.write_all(&framed).await.is_err() {
                    break Close::Write;
                }
                sent += 1;
                pending.insert(req.id, (req.reply, Instant::now()));
            }
            resp = resp_rx.recv() => {
                let Some(resp) = resp else { break Close::Server };
                heard = Instant::now();
                if resp.len() >= 2 {
                    let id = u16::from_be_bytes([resp[0], resp[1]]);
                    if let Some((w, _)) = pending.remove(&id) {
                        answered += 1;
                        let _ = w.send(resp);
                    }
                }
            }
            _ = ticker.tick(), if !pending.is_empty() => {
                let now = Instant::now();
                if now - heard >= STALE && pending.values().any(|(_, at)| now - *at >= STALE) {
                    // Stop handing it out now; the waiters still here get a closed channel
                    // and retry on a fresh connection.
                    dead.store(true, Ordering::Release);
                    break Close::Unanswered;
                }
                pending.retain(|_, (w, at)| !(w.is_closed() && now - *at >= STALE));
            }
            () = idle_timer, if pending.is_empty() => break Close::Idle,
        }
    };
    tracing::debug!(
        why = why.label(),
        sent,
        answered,
        unanswered = pending.len(),
        "upstream connection ended"
    );
    reader.abort();
    let _ = wr.shutdown().await;
    why
}
