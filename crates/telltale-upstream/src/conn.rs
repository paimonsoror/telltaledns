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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

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
    connector: Connector,
    conns: Mutex<Vec<Arc<Conn>>>,
    max: usize,
    idle: Duration,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("max", &self.max)
            .field("conns", &self.conns.lock().len())
            .finish_non_exhaustive()
    }
}

impl Pool {
    pub(crate) fn new(connector: Connector, max: usize, idle: Duration) -> Self {
        Self {
            connector,
            conns: Mutex::new(Vec::new()),
            max: max.max(1),
            idle,
        }
    }

    /// Live connections (for tests and metrics).
    pub(crate) fn len(&self) -> usize {
        let mut c = self.conns.lock();
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
            let mut conns = self.conns.lock();
            conns.retain(|c| !c.dead.load(Ordering::Acquire));
            let best = conns
                .iter()
                .min_by_key(|c| c.inflight.load(Ordering::Acquire))
                .cloned();
            if let Some(c) = best
                && !fresh
                && (c.inflight.load(Ordering::Acquire) < BUSY_THRESHOLD || conns.len() >= self.max)
            {
                return Ok(c);
            }
        }
        let io = (self.connector)().await?;
        let (tx, rx) = mpsc::channel(256);
        let conn = Arc::new(Conn {
            tx,
            inflight: Arc::new(AtomicUsize::new(0)),
            dead: Arc::new(AtomicBool::new(false)),
        });
        tokio::spawn(run_conn(io, rx, self.idle, Arc::clone(&conn.dead)));
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

/// Owns one stream: writes queued queries, routes responses to waiters by ID, closes when idle.
async fn run_conn(
    io: BoxIo,
    mut rx: mpsc::Receiver<Request>,
    idle: Duration,
    dead: Arc<AtomicBool>,
) {
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
    let mut pending: HashMap<u16, oneshot::Sender<Vec<u8>>> = HashMap::new();
    let (mut sent, mut answered) = (0u32, 0u32);
    let why: &str;
    loop {
        let idle_timer = tokio::time::sleep(idle);
        tokio::select! {
            req = rx.recv() => {
                let Some(req) = req else { why = "unused"; break };
                // Drop waiters that already gave up (timed out), so a server that stopped
                // answering doesn't keep the connection alive forever.
                pending.retain(|_, w| !w.is_closed());
                if pending.contains_key(&req.id) || req.reply.is_closed() {
                    continue; // ID collision or caller gone: the waiter sees a closed channel
                }
                let Ok(len) = u16::try_from(req.msg.len()) else { continue };
                let mut framed = Vec::with_capacity(req.msg.len() + 2);
                framed.extend_from_slice(&len.to_be_bytes());
                framed.extend_from_slice(&req.msg);
                if wr.write_all(&framed).await.is_err() {
                    why = "write failed";
                    break;
                }
                sent += 1;
                pending.insert(req.id, req.reply);
            }
            resp = resp_rx.recv() => {
                let Some(resp) = resp else { why = "closed by the server"; break };
                if resp.len() >= 2 {
                    let id = u16::from_be_bytes([resp[0], resp[1]]);
                    if let Some(w) = pending.remove(&id) {
                        answered += 1;
                        let _ = w.send(resp);
                    }
                }
            }
            () = idle_timer, if pending.is_empty() => { why = "idle"; break },
        }
    }
    tracing::debug!(
        why,
        sent,
        answered,
        unanswered = pending.len(),
        "upstream connection ended"
    );
    dead.store(true, Ordering::Release);
    reader.abort();
    let _ = wr.shutdown().await;
}
