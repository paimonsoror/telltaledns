//! UDP DNS listener: one `SO_REUSEPORT` socket and one dedicated thread per worker.
//!
//! REQ: DNS-001; `spec/02` §3 — the fast path is synchronous per worker
//! (`recvmmsg → handle batch → sendmmsg`) with no cross-thread contention. Deferred answers
//! (cache misses) run on the Tokio runtime and reply through the same socket.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use crate::handler::{QueryHandler, RequestMeta, Response, Transport};

/// The local address a datagram arrived on (from `IP_PKTINFO`), used as the reply source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LocalAddr {
    pub ip: IpAddr,
    /// Interface index (needed for IPv6 link-local replies).
    pub ifindex: u32,
}

/// Sends deferred replies on a worker's socket from any thread.
#[derive(Clone, Debug)]
struct Replier {
    sock: Arc<Socket>,
}

impl Replier {
    fn send(&self, buf: &[u8], peer: SocketAddr, local: Option<LocalAddr>) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            crate::sys::send_one(self.sock.as_raw_fd(), buf, peer, local)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = local;
            self.sock.send_to(buf, &peer.into())
        }
    }
}

/// Per-worker counters (relaxed atomics, one cache line each; read by the metrics exporter).
#[derive(Debug, Default)]
#[repr(align(64))]
pub struct WorkerStats {
    pub received: AtomicU64,
    /// Replies sent from the worker thread (immediate answers).
    pub replied: AtomicU64,
    /// Replies sent later from the runtime (deferred answers).
    pub deferred_replied: AtomicU64,
    pub send_errors: AtomicU64,
    /// Oversized, truncated, or unparseable-address datagrams.
    pub dropped: AtomicU64,
    /// recvmmsg batches (received / batches = average batch size).
    pub batches: AtomicU64,
}

/// Configuration for one UDP listen address.
#[derive(Clone, Debug)]
pub struct UdpConfig {
    pub addr: SocketAddr,
    /// Number of worker threads (each with its own socket).
    pub workers: usize,
    /// Datagrams per recvmmsg/sendmmsg batch.
    pub batch: usize,
    /// Requested kernel receive buffer per socket (best effort).
    pub recv_buffer: usize,
}

impl UdpConfig {
    pub fn new(addr: SocketAddr, workers: usize) -> Self {
        Self {
            addr,
            workers: workers.max(1),
            batch: 32,
            recv_buffer: 4 << 20,
        }
    }
}

/// A running UDP listener. Dropping it does not stop the workers; call [`UdpListener::shutdown`].
#[derive(Debug)]
pub struct UdpListener {
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    stats: Vec<Arc<WorkerStats>>,
}

/// How often blocked workers wake to check for shutdown.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

impl UdpListener {
    /// Binds `cfg.workers` sockets to `cfg.addr` with `SO_REUSEPORT` and starts one thread per
    /// socket. Deferred answers are driven on `rt`. With port 0, the first socket picks the
    /// port and the rest share it.
    pub fn spawn<H: QueryHandler>(
        cfg: &UdpConfig,
        handler: &Arc<H>,
        rt: &tokio::runtime::Handle,
    ) -> io::Result<Self> {
        let first = bind_socket(cfg.addr, cfg)?;
        let local_addr = first
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("bound address is not an IP socket"))?;
        let mut sockets = vec![first];
        for _ in 1..cfg.workers {
            sockets.push(bind_socket(local_addr, cfg)?);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::with_capacity(cfg.workers);
        let mut stats = Vec::with_capacity(cfg.workers);
        for (i, sock) in sockets.into_iter().enumerate() {
            let sock = Arc::new(sock);
            let st = Arc::new(WorkerStats::default());
            stats.push(Arc::clone(&st));
            let w = Worker {
                sock,
                handler: Arc::clone(handler),
                stats: st,
                stop: Arc::clone(&stop),
                rt: rt.clone(),
                batch: cfg.batch.max(1),
            };
            let t = std::thread::Builder::new()
                .name(format!("udp-{}-{i}", local_addr.port()))
                .spawn(move || w.run())?;
            threads.push(t);
        }
        Ok(Self {
            local_addr,
            stop,
            threads,
            stats,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stats(&self) -> &[Arc<WorkerStats>] {
        &self.stats
    }

    /// Signals workers to stop and waits for them (at most ~`POLL_INTERVAL`).
    pub fn shutdown(self) {
        self.stop.store(true, Ordering::Release);
        for t in self.threads {
            let _ = t.join();
        }
    }
}

fn bind_socket(addr: SocketAddr, cfg: &UdpConfig) -> io::Result<Socket> {
    let domain = Domain::for_address(addr);
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        // Separate v4 and v6 listeners (DNS-001), so v6 sockets must not claim v4.
        sock.set_only_v6(true)?;
    }
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    sock.set_reuse_port(true)?;
    let _ = sock.set_recv_buffer_size(cfg.recv_buffer);
    sock.set_read_timeout(Some(POLL_INTERVAL))?;
    #[cfg(target_os = "linux")]
    if addr.ip().is_unspecified() {
        crate::sys::enable_pktinfo(&sock, addr.is_ipv6())?;
    }
    sock.bind(&addr.into())?;
    Ok(sock)
}

struct Worker<H> {
    sock: Arc<Socket>,
    handler: Arc<H>,
    stats: Arc<WorkerStats>,
    stop: Arc<AtomicBool>,
    rt: tokio::runtime::Handle,
    batch: usize,
}

impl<H: QueryHandler> Worker<H> {
    /// Hands a deferred answer to the runtime; it replies through this worker's socket.
    fn defer(&self, fut: crate::handler::Deferred, peer: SocketAddr, local: Option<LocalAddr>) {
        let replier = Replier {
            sock: Arc::clone(&self.sock),
        };
        let stats = Arc::clone(&self.stats);
        self.rt.spawn(async move {
            if let Some(buf) = fut.await {
                match replier.send(&buf, peer, local) {
                    Ok(_) => stats.deferred_replied.fetch_add(1, Ordering::Relaxed),
                    Err(_) => stats.send_errors.fetch_add(1, Ordering::Relaxed),
                };
            }
        });
    }

    #[cfg(target_os = "linux")]
    fn run(&self) {
        use std::os::fd::AsRawFd;

        use crate::sys::Batch;

        let fd = self.sock.as_raw_fd();
        let st = &*self.stats;
        let mut b = Batch::new(self.batch);
        while !self.stop.load(Ordering::Acquire) {
            let n = match b.recv(fd) {
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(_) => {
                    st.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            st.batches.fetch_add(1, Ordering::Relaxed);
            st.received.fetch_add(n as u64, Ordering::Relaxed);
            for i in 0..n {
                let rx = b.rx_meta(i);
                let Some(peer) = rx.peer.filter(|_| !rx.truncated) else {
                    st.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let (data, tx) = b.rx_and_next_tx(i, rx.len);
                let Some(tx) = tx else { break };
                let meta = RequestMeta {
                    peer,
                    local: rx.local,
                    transport: Transport::Udp,
                };
                match self.handler.handle(data, &meta, tx) {
                    Response::Ready(len) => {
                        b.queue_tx(len, peer, rx.local);
                    }
                    Response::Deferred(fut) => self.defer(fut, peer, rx.local),
                    Response::Drop => {}
                }
            }
            let (sent, failed) = b.flush(fd);
            st.replied.fetch_add(sent as u64, Ordering::Relaxed);
            st.send_errors.fetch_add(failed as u64, Ordering::Relaxed);
        }
    }

    /// Portable fallback (macOS etc., `spec/02` §3): one datagram at a time, no PKTINFO.
    #[cfg(not(target_os = "linux"))]
    fn run(&self) {
        let Ok(clone) = self.sock.try_clone() else {
            return;
        };
        let udp: std::net::UdpSocket = clone.into();
        let st = &*self.stats;
        let mut rx = [0u8; 4096];
        let mut tx = [0u8; 4096];
        while !self.stop.load(Ordering::Acquire) {
            let Ok((len, peer)) = udp.recv_from(&mut rx) else {
                continue;
            };
            st.received.fetch_add(1, Ordering::Relaxed);
            let meta = RequestMeta {
                peer,
                local: None,
                transport: Transport::Udp,
            };
            match self.handler.handle(&rx[..len], &meta, &mut tx) {
                Response::Ready(n) => {
                    match udp.send_to(&tx[..n], peer) {
                        Ok(_) => st.replied.fetch_add(1, Ordering::Relaxed),
                        Err(_) => st.send_errors.fetch_add(1, Ordering::Relaxed),
                    };
                }
                Response::Deferred(fut) => self.defer(fut, peer, None),
                Response::Drop => {}
            }
        }
    }
}
