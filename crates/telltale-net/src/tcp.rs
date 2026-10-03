//! DNS over TCP (RFC 7766): pipelined, length-prefixed, with idle and concurrency limits.
//!
//! REQ: DNS-001; `spec/03` §1 — idle timeout 10 s, max 64 in-flight per connection, global
//! connection cap. Each connection has a reader and a writer task joined by a bounded channel,
//! so responses produced asynchronously (cache misses, later) can be written out of order.

use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::handler::{QueryHandler, RequestMeta, Response, Transport};

/// Prepends the RFC 7766 two-byte length.
fn framed(msg: &[u8]) -> Option<Vec<u8>> {
    let len = u16::try_from(msg.len()).ok()?;
    let mut v = Vec::with_capacity(msg.len() + 2);
    v.extend_from_slice(&len.to_be_bytes());
    v.extend_from_slice(msg);
    Some(v)
}

/// TCP listener settings.
#[derive(Clone, Debug)]
pub struct TcpConfig {
    pub addr: SocketAddr,
    /// Close a connection with no complete query for this long (RFC 7766 §6.2.3).
    pub idle_timeout: Duration,
    /// Max responses queued per connection before reading pauses.
    pub max_inflight: usize,
    /// Max concurrent connections; extra connections are closed immediately.
    pub max_connections: usize,
}

impl TcpConfig {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            idle_timeout: Duration::from_secs(10),
            max_inflight: 64,
            max_connections: 1024,
        }
    }
}

/// Listener counters.
#[derive(Debug, Default)]
pub struct TcpStats {
    pub accepted: AtomicU64,
    /// Connections refused because `max_connections` was reached.
    pub rejected: AtomicU64,
    pub queries: AtomicU64,
    pub replies: AtomicU64,
    pub idle_closed: AtomicU64,
}

/// A running TCP DNS listener.
#[derive(Debug)]
pub struct TcpServer {
    local_addr: SocketAddr,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
    stats: Arc<TcpStats>,
}

/// Largest DNS message (2-byte length prefix).
const MAX_MSG: usize = u16::MAX as usize;

thread_local! {
    /// Response scratch space, one per runtime thread rather than per connection, so idle
    /// connections cost almost nothing. Never held across an `.await`.
    static SCRATCH: RefCell<Vec<u8>> = RefCell::new(vec![0; MAX_MSG]);
}

impl TcpServer {
    /// Binds and starts accepting. Must be called from within a Tokio runtime.
    pub fn bind<H: QueryHandler>(cfg: TcpConfig, handler: Arc<H>) -> io::Result<Self> {
        let sock = socket2::Socket::new(
            socket2::Domain::for_address(cfg.addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        if cfg.addr.is_ipv6() {
            sock.set_only_v6(true)?;
        }
        sock.set_reuse_address(true)?;
        sock.set_nonblocking(true)?;
        sock.bind(&cfg.addr.into())?;
        sock.listen(1024)?;
        let listener = TcpListener::from_std(sock.into())?;
        let local_addr = listener.local_addr()?;
        let (stop, stop_rx) = watch::channel(false);
        let stats = Arc::new(TcpStats::default());
        let task = tokio::spawn(accept_loop(
            listener,
            cfg,
            handler,
            stop_rx,
            Arc::clone(&stats),
        ));
        Ok(Self {
            local_addr,
            stop,
            task,
            stats,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stats(&self) -> &TcpStats {
        &self.stats
    }

    /// Stops accepting and closes connections after their current query.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

async fn accept_loop<H: QueryHandler>(
    listener: TcpListener,
    cfg: TcpConfig,
    handler: Arc<H>,
    mut stop: watch::Receiver<bool>,
    stats: Arc<TcpStats>,
) {
    let slots = Arc::new(Semaphore::new(cfg.max_connections));
    let cfg = Arc::new(cfg);
    let mut conns = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            _ = stop.changed() => break,
            r = listener.accept() => r,
        };
        let Ok((stream, peer)) = accepted else {
            // EMFILE and friends: back off briefly instead of spinning.
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            drop(stream);
            continue;
        };
        stats.accepted.fetch_add(1, Ordering::Relaxed);
        let _ = stream.set_nodelay(true);
        let (handler, cfg, stop, stats) = (
            Arc::clone(&handler),
            Arc::clone(&cfg),
            stop.clone(),
            Arc::clone(&stats),
        );
        conns.spawn(async move {
            serve_conn(stream, peer, &*handler, &cfg, stop, &stats).await;
            drop(permit);
        });
        // Reap finished connections so the set doesn't grow without bound.
        while conns.try_join_next().is_some() {}
    }
    // Let in-flight connections notice the stop signal and finish.
    while conns.join_next().await.is_some() {}
}

async fn serve_conn<H: QueryHandler + ?Sized>(
    stream: TcpStream,
    peer: SocketAddr,
    handler: &H,
    cfg: &TcpConfig,
    mut stop: watch::Receiver<bool>,
    stats: &Arc<TcpStats>,
) {
    let (mut rd, mut wr) = stream.into_split();
    let inflight = cfg.max_inflight.max(1);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(inflight);
    // Caps queries being answered at once on this connection (RFC 7766 §6.2.1.2).
    let slots = Arc::new(Semaphore::new(inflight));
    let meta = RequestMeta {
        peer,
        local: None,
        transport: Transport::Tcp,
    };
    let writer = tokio::spawn(async move {
        while let Some(buf) = rx.recv().await {
            if wr.write_all(&buf).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    let mut req = Vec::with_capacity(512);
    loop {
        let mut len = [0u8; 2];
        let read = tokio::select! {
            _ = stop.changed() => break,
            r = timeout(cfg.idle_timeout, rd.read_exact(&mut len)) => r,
        };
        match read {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => break, // EOF or reset
            Err(_) => {
                stats.idle_closed.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
        let n = usize::from(u16::from_be_bytes(len));
        if n < 12 {
            break; // shorter than a DNS header: the stream is out of sync
        }
        req.resize(n, 0);
        if !matches!(
            timeout(cfg.idle_timeout, rd.read_exact(&mut req)).await,
            Ok(Ok(_))
        ) {
            break;
        }
        stats.queries.fetch_add(1, Ordering::Relaxed);
        // Back-pressure: stop reading while `max_inflight` queries are unanswered.
        let Ok(permit) = Arc::clone(&slots).acquire_owned().await else {
            break;
        };
        let outcome = SCRATCH.with(|s| {
            let mut out = s.borrow_mut();
            match handler.handle(&req, &meta, &mut out[..]) {
                Response::Ready(len) => Outcome::Now(framed(&out[..len])),
                Response::Deferred(fut) => Outcome::Later(fut),
                Response::Drop => Outcome::Now(None),
            }
        });
        match outcome {
            Outcome::Now(Some(buf)) => {
                stats.replies.fetch_add(1, Ordering::Relaxed);
                drop(permit);
                if tx.send(buf).await.is_err() {
                    break;
                }
            }
            Outcome::Now(None) => drop(permit),
            Outcome::Later(fut) => {
                // Answered out of order whenever it completes (RFC 7766 §7).
                let (tx, stats) = (tx.clone(), Arc::clone(stats));
                tokio::spawn(async move {
                    if let Some(buf) = fut.await.as_deref().and_then(framed)
                        && tx.send(buf).await.is_ok()
                    {
                        stats.replies.fetch_add(1, Ordering::Relaxed);
                    }
                    drop(permit);
                });
            }
        }
    }
    // Wait for deferred answers still in flight, then close the writer.
    let _ = slots
        .acquire_many(u32::try_from(inflight).unwrap_or(u32::MAX))
        .await;
    drop(tx);
    let _ = writer.await;
}

enum Outcome {
    Now(Option<Vec<u8>>),
    Later(crate::handler::Deferred),
}
