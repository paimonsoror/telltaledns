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

/// Handles one DNS message received over a stream transport. Must not block.
pub trait StreamHandler: Send + Sync + 'static {
    /// Writes the response into `out` and returns its length, or `None` to send nothing.
    fn handle(&self, req: &[u8], peer: SocketAddr, out: &mut [u8]) -> Option<usize>;
}

impl<F> StreamHandler for F
where
    F: Fn(&[u8], SocketAddr, &mut [u8]) -> Option<usize> + Send + Sync + 'static,
{
    fn handle(&self, req: &[u8], peer: SocketAddr, out: &mut [u8]) -> Option<usize> {
        self(req, peer, out)
    }
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
    pub fn bind<H: StreamHandler>(cfg: TcpConfig, handler: Arc<H>) -> io::Result<Self> {
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

async fn accept_loop<H: StreamHandler>(
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

async fn serve_conn<H: StreamHandler + ?Sized>(
    stream: TcpStream,
    peer: SocketAddr,
    handler: &H,
    cfg: &TcpConfig,
    mut stop: watch::Receiver<bool>,
    stats: &TcpStats,
) {
    let (mut rd, mut wr) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(cfg.max_inflight.max(1));
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
        let reply = SCRATCH.with(|s| {
            let mut out = s.borrow_mut();
            let len = handler.handle(&req, peer, &mut out[2..])?;
            let len16 = u16::try_from(len).ok()?;
            out[..2].copy_from_slice(&len16.to_be_bytes());
            Some(out[..2 + len].to_vec())
        });
        if let Some(buf) = reply {
            stats.replies.fetch_add(1, Ordering::Relaxed);
            // Blocks when max_inflight responses are queued: natural back-pressure.
            if tx.send(buf).await.is_err() {
                break;
            }
        }
    }
    drop(tx);
    let _ = writer.await;
}
