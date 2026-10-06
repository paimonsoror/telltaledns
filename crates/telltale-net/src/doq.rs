//! DNS over QUIC (REQ: DNS-004, RFC 9250; T7.7).
//!
//! One query per bidirectional stream: the client writes a 2-byte length and the message (with
//! ID 0) and finishes its side; the answer goes back the same way. Each stream is its own task,
//! so a slow upstream answer never holds up the others on the connection. The certificate comes
//! from the same [`CertStore`] as DoT and DoH (reloaded on change), with ALPN `doq`; a wildcard
//! certificate's first label in the SNI is the client ID, as for DoT.

use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use quinn::crypto::rustls::QuicServerConfig;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::debug;

use crate::handler::{ClientId, QueryHandler, RequestMeta, Response, Transport};
use crate::tls::CertStore;

/// RFC 9250 §4.3 error codes.
const DOQ_NO_ERROR: u32 = 0x0;
const DOQ_PROTOCOL_ERROR: u32 = 0x2;
/// A query is at most a 2-byte length and 65,535 bytes.
const MAX_STREAM: usize = 2 + 65_535;

/// Listener settings.
#[derive(Debug, Clone)]
pub struct DoqConfig {
    pub addr: SocketAddr,
    pub tls: Arc<CertStore>,
    /// A connection with no traffic for this long is closed (RFC 9250 §5.5: 30 s or more).
    pub idle_timeout: Duration,
    /// Streams (queries) one connection may have open at once.
    pub max_streams: u32,
}

impl DoqConfig {
    pub fn new(addr: SocketAddr, tls: Arc<CertStore>) -> Self {
        Self {
            addr,
            tls,
            idle_timeout: Duration::from_secs(30),
            max_streams: 100,
        }
    }
}

/// DoQ counters for `/metrics`.
#[derive(Debug, Default)]
pub struct DoqStats {
    pub connections: AtomicU64,
    pub queries: AtomicU64,
    /// Streams that broke RFC 9250 (bad length, a non-zero message ID): the connection closes.
    pub protocol_errors: AtomicU64,
}

/// A running DoQ listener.
#[derive(Debug)]
pub struct DoqServer {
    endpoint: quinn::Endpoint,
    local: SocketAddr,
    stats: Arc<DoqStats>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

thread_local! {
    /// The synchronous answer is written here (the handler never awaits while holding it).
    static SCRATCH: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 65_535]);
}

impl DoqServer {
    /// Binds `cfg.addr` (UDP) and starts accepting connections. Must run inside a tokio runtime.
    pub fn bind<H: QueryHandler>(cfg: &DoqConfig, handler: Arc<H>) -> io::Result<Self> {
        let tls = cfg.tls.server_config(&[b"doq"])?;
        let crypto = QuicServerConfig::try_from(tls)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_idle_timeout(quinn::IdleTimeout::try_from(cfg.idle_timeout).ok())
            .max_concurrent_bidi_streams(cfg.max_streams.into())
            .max_concurrent_uni_streams(0u8.into());
        server.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(server, cfg.addr)?;
        let local = endpoint.local_addr()?;
        let stats = Arc::new(DoqStats::default());
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(accept_loop(
            endpoint.clone(),
            Arc::clone(&cfg.tls),
            handler,
            Arc::clone(&stats),
            rx,
        ));
        Ok(Self {
            endpoint,
            local,
            stats,
            stop,
            task,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub fn stats_handle(&self) -> Arc<DoqStats> {
        Arc::clone(&self.stats)
    }

    /// Stops accepting, lets open streams finish briefly, then closes every connection.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        self.endpoint.set_server_config(None);
        let _ = tokio::time::timeout(Duration::from_secs(2), self.endpoint.wait_idle()).await;
        self.endpoint
            .close(quinn::VarInt::from_u32(DOQ_NO_ERROR), b"shutting down");
        self.task.abort();
    }
}

async fn accept_loop<H: QueryHandler>(
    endpoint: quinn::Endpoint,
    certs: Arc<CertStore>,
    handler: Arc<H>,
    stats: Arc<DoqStats>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        let incoming = tokio::select! {
            _ = stop.changed() => return,
            i = endpoint.accept() => i,
        };
        let Some(incoming) = incoming else { return };
        let (certs, handler, stats) =
            (Arc::clone(&certs), Arc::clone(&handler), Arc::clone(&stats));
        tokio::spawn(async move {
            let peer = incoming.remote_address();
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    debug!(%peer, error = %e, "doq handshake failed");
                    return;
                }
            };
            stats.connections.fetch_add(1, Ordering::Relaxed);
            let client_id = conn
                .handshake_data()
                .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|d| d.server_name.clone())
                .and_then(|sni| certs.client_id(&sni));
            serve_conn(conn, peer, client_id, handler, stats).await;
        });
    }
}

async fn serve_conn<H: QueryHandler>(
    conn: quinn::Connection,
    peer: SocketAddr,
    client_id: Option<ClientId>,
    handler: Arc<H>,
    stats: Arc<DoqStats>,
) {
    let meta = RequestMeta {
        peer,
        local: None,
        transport: Transport::Doq,
        client_id,
    };
    while let Ok((send, recv)) = conn.accept_bi().await {
        let (conn, handler, stats) = (conn.clone(), Arc::clone(&handler), Arc::clone(&stats));
        tokio::spawn(async move {
            if serve_stream(send, recv, &meta, handler.as_ref(), &stats)
                .await
                .is_err()
            {
                stats.protocol_errors.fetch_add(1, Ordering::Relaxed);
                conn.close(
                    quinn::VarInt::from_u32(DOQ_PROTOCOL_ERROR),
                    b"protocol error",
                );
            }
        });
    }
}

/// One query on one stream; `Err` is a protocol violation (the connection is closed).
async fn serve_stream<H: QueryHandler + ?Sized>(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    meta: &RequestMeta,
    handler: &H,
    stats: &DoqStats,
) -> Result<(), ()> {
    let Ok(data) = recv.read_to_end(MAX_STREAM).await else {
        return Err(());
    };
    // RFC 9250 §4.2: a 2-byte length, the message, nothing more; the ID must be 0.
    let Some((len, msg)) = data.split_first_chunk::<2>() else {
        return Err(());
    };
    if usize::from(u16::from_be_bytes(*len)) != msg.len() || msg.len() < 12 || msg[..2] != [0, 0] {
        return Err(());
    }
    stats.queries.fetch_add(1, Ordering::Relaxed);
    let answer = match SCRATCH.with(|s| {
        let mut out = s.borrow_mut();
        match handler.handle(msg, meta, &mut out[..]) {
            Response::Ready(n) => Ok(Some(out[..n].to_vec())),
            Response::Deferred(fut) => Err(fut),
            Response::Drop => Ok(None),
        }
    }) {
        Ok(a) => a,
        Err(fut) => fut.await,
    };
    let Some(answer) = answer else {
        // Nothing to say (refused upstream of us, or dropped): reset the stream.
        let _ = send.reset(quinn::VarInt::from_u32(DOQ_NO_ERROR));
        return Ok(());
    };
    let Ok(n) = u16::try_from(answer.len()) else {
        let _ = send.reset(quinn::VarInt::from_u32(DOQ_NO_ERROR));
        return Ok(());
    };
    let mut framed = Vec::with_capacity(2 + answer.len());
    framed.extend_from_slice(&n.to_be_bytes());
    framed.extend_from_slice(&answer);
    if send.write_all(&framed).await.is_ok() {
        let _ = send.finish();
    }
    Ok(())
}
