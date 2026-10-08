//! DNS over TCP (RFC 7766): pipelined, length-prefixed, with idle and concurrency limits.
//!
//! REQ: DNS-001; `spec/03` §1 — idle timeout 10 s, max 64 in-flight per connection, global
//! connection cap. Each connection has a reader and a writer task joined by a bounded channel,
//! so responses produced asynchronously (cache misses, later) can be written out of order.
//!
//! The same code serves DNS over TLS (REQ: DNS-002, RFC 7858: ALPN `dot`, client ID from SNI)
//! and, on any of them, PROXY protocol v2 (REQ: DNS-020), which is read before the TLS
//! handshake, as a load balancer sends it.

use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::handler::{ClientId, QueryHandler, RequestMeta, Response, Transport};
use crate::tls::CertStore;

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
    /// `Tcp`, or `Dot` with `tls` set.
    pub transport: Transport,
    /// The certificate for DoT.
    pub tls: Option<Arc<CertStore>>,
    /// Every connection starts with a PROXY protocol v2 header (DNS-020).
    pub proxy_protocol: bool,
}

impl TcpConfig {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            idle_timeout: Duration::from_secs(10),
            max_inflight: 64,
            max_connections: 1024,
            transport: Transport::Tcp,
            tls: None,
            proxy_protocol: false,
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
    /// TLS handshakes that failed or timed out.
    pub tls_failed: AtomicU64,
    /// Connections closed for a missing or malformed PROXY header.
    pub proxy_rejected: AtomicU64,
    /// Connections closed because the client stopped reading its answers (a write stalled
    /// for the idle timeout).
    pub stalled_closed: AtomicU64,
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
/// Largest query accepted: the same bound as the UDP receive buffer. Queries are small; a
/// length prefix beyond this is junk, and reading it would buffer up to 64 KiB per
/// connection on the client's say-so.
const MAX_QUERY: usize = 4096;

thread_local! {
    /// Response scratch space, one per runtime thread rather than per connection, so idle
    /// connections cost almost nothing. Never held across an `.await`.
    static SCRATCH: RefCell<Vec<u8>> = RefCell::new(vec![0; MAX_MSG]);
}

/// A listening TCP socket (v6-only for IPv6 addresses, so v4 and v6 can bind separately).
pub(crate) fn listen(addr: SocketAddr) -> io::Result<TcpListener> {
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    TcpListener::from_std(sock.into())
}

/// Runs `f` with this thread's response buffer (never hold it across an `.await`).
pub(crate) fn with_scratch<R>(f: impl FnOnce(&mut [u8]) -> R) -> R {
    SCRATCH.with(|s| f(&mut s.borrow_mut()[..]))
}

impl TcpServer {
    /// Binds and starts accepting. Must be called from within a Tokio runtime.
    pub fn bind<H: QueryHandler>(cfg: TcpConfig, handler: Arc<H>) -> io::Result<Self> {
        if let Some(store) = &cfg.tls {
            store.server_config(&[b"dot"])?; // fail at bind, not per connection
        }
        let listener = listen(cfg.addr)?;
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

    /// Shared handle to the counters (for exporters that outlive a borrow).
    pub fn stats_handle(&self) -> Arc<TcpStats> {
        Arc::clone(&self.stats)
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
    // REQ: DNS-002 — RFC 7858 §3.2 ALPN "dot".
    let acceptor = match &cfg.tls {
        Some(store) => match store.server_config(&[b"dot"]) {
            Ok(c) => Some(tokio_rustls::TlsAcceptor::from(c)),
            Err(_) => return,
        },
        None => None,
    };
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
        let acceptor = acceptor.clone();
        conns.spawn(async move {
            open(stream, peer, acceptor, &*handler, &cfg, stop, &stats).await;
            drop(permit);
        });
        // Reap finished connections so the set doesn't grow without bound.
        while conns.try_join_next().is_some() {}
    }
    // Let in-flight connections notice the stop signal and finish.
    while conns.join_next().await.is_some() {}
}

/// Reads the PROXY header (if configured), completes the TLS handshake (if any), then serves.
async fn open<H: QueryHandler + ?Sized>(
    mut stream: TcpStream,
    mut peer: SocketAddr,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    handler: &H,
    cfg: &TcpConfig,
    stop: watch::Receiver<bool>,
    stats: &Arc<TcpStats>,
) {
    if cfg.proxy_protocol {
        match timeout(cfg.idle_timeout, crate::proxy::read_header(&mut stream)).await {
            Ok(Ok(Some(src))) => peer = src,
            Ok(Ok(None)) => {} // LOCAL: the balancer itself
            _ => {
                stats.proxy_rejected.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }
    let Some(acceptor) = acceptor else {
        serve_conn(stream, peer, None, handler, cfg, stop, stats).await;
        return;
    };
    let Ok(Ok(tls)) = timeout(cfg.idle_timeout, acceptor.accept(stream)).await else {
        stats.tls_failed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    // FLT-006 — the client ID in front of a wildcard name of our certificate.
    let client_id = match (&cfg.tls, tls.get_ref().1.server_name()) {
        (Some(store), Some(sni)) => store.client_id(sni),
        _ => None,
    };
    serve_conn(tls, peer, client_id, handler, cfg, stop, stats).await;
}

async fn serve_conn<S, H>(
    stream: S,
    peer: SocketAddr,
    client_id: Option<ClientId>,
    handler: &H,
    cfg: &TcpConfig,
    mut stop: watch::Receiver<bool>,
    stats: &Arc<TcpStats>,
) where
    S: AsyncRead + AsyncWrite + Send + 'static,
    H: QueryHandler + ?Sized,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let inflight = cfg.max_inflight.max(1);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(inflight);
    // Caps queries being answered at once on this connection (RFC 7766 §6.2.1.2).
    let slots = Arc::new(Semaphore::new(inflight));
    let meta = RequestMeta {
        peer,
        local: None,
        transport: cfg.transport,
        client_id,
    };
    // REQ: DNS-001 (RFC 7766 §6.2.3) — a client that stops reading its answers must not hold
    // the connection (and its slot) forever: a write that stalls for the idle timeout closes
    // it. Dropping `rx` then fails the reader's next send, so it stops too.
    let (write_timeout, wstats) = (cfg.idle_timeout, Arc::clone(stats));
    let writer = tokio::spawn(async move {
        while let Some(buf) = rx.recv().await {
            // TLS buffers records; push them out once nothing else is queued.
            let flush = rx.is_empty();
            if !written(&mut wr, &buf, flush, write_timeout, &wstats).await {
                break;
            }
        }
        let _ = timeout(write_timeout, wr.shutdown()).await;
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
        if !(12..=MAX_QUERY).contains(&n) {
            break; // shorter than a DNS header, or far longer than any query: out of sync
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

/// Writes `buf` (and flushes, if `flush`) within `limit`; false on an error. A stall for the
/// whole limit means the client stopped reading, and is counted (REQ: DNS-001).
async fn written<W: AsyncWrite + Unpin>(
    wr: &mut W,
    buf: &[u8],
    flush: bool,
    limit: Duration,
    stats: &TcpStats,
) -> bool {
    let io = async {
        wr.write_all(buf).await?;
        if flush {
            wr.flush().await?;
        }
        Ok::<(), io::Error>(())
    };
    match timeout(limit, io).await {
        Ok(Ok(())) => true,
        Ok(Err(_)) => false,
        Err(_) => {
            stats.stalled_closed.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}
