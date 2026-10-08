//! DNS over HTTPS over HTTP/3 (REQ: DNS-004, RFC 8484 over RFC 9114; T7.8).
//!
//! The same requests as the HTTP/2 listener (`GET ?dns=`, `POST application/dns-message`, the
//! path and `<path>/<client-id>`), answered by the same code ([`crate::doh`]), over QUIC with
//! ALPN `h3`. The certificate comes from the shared [`CertStore`]; a wildcard certificate's
//! first SNI label is the client ID. An HTTP/2 listener on the same name advertises this one
//! with `Alt-Svc`.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::{Buf, Bytes};
use hyper::header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE, HeaderValue};
use hyper::{Method, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::debug;

use crate::doh::{DNS_MESSAGE, DohStats, MAX_MSG, get_message, is_dns_message, resolve, route};
use crate::handler::{ClientId, QueryHandler, RequestMeta, Transport};
use crate::tls::CertStore;

/// Listener settings.
#[derive(Debug, Clone)]
pub struct Doh3Config {
    pub addr: SocketAddr,
    pub tls: Arc<CertStore>,
    /// URL path (default `/dns-query`); `<path>/<client-id>` also matches.
    pub path: String,
    pub idle_timeout: Duration,
    /// Max concurrent connections; beyond it, new ones are refused.
    pub max_connections: usize,
    /// Max concurrent connections from one client address (an IPv6 /64), once its handshake
    /// proved the address; 0 = no limit (review 01 q2).
    pub max_connections_per_address: usize,
}

impl Doh3Config {
    pub fn new(addr: SocketAddr, tls: Arc<CertStore>) -> Self {
        Self {
            addr,
            tls,
            path: "/dns-query".to_owned(),
            idle_timeout: Duration::from_secs(30),
            max_connections: 1024,
            max_connections_per_address: crate::peer_limit::DEFAULT_PER_ADDRESS,
        }
    }
}

/// A running HTTP/3 DoH listener.
#[derive(Debug)]
pub struct Doh3Server {
    endpoint: quinn::Endpoint,
    local: SocketAddr,
    stats: Arc<DohStats>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

impl Doh3Server {
    /// Binds `cfg.addr` (UDP) and starts accepting. Must run inside a tokio runtime.
    pub fn bind<H: QueryHandler>(cfg: &Doh3Config, handler: Arc<H>) -> io::Result<Self> {
        let tls = cfg.tls.server_config(&[b"h3"])?;
        let crypto = QuicServerConfig::try_from(tls)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(quinn::IdleTimeout::try_from(cfg.idle_timeout).ok());
        server.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(server, cfg.addr)?;
        let local = endpoint.local_addr()?;
        let stats = Arc::new(DohStats::default());
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(accept_loop(
            endpoint.clone(),
            Arc::new(cfg.clone()),
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

    /// The same counters as the HTTP/2 listener (summed into `telltale_doh_*`).
    pub fn stats_handle(&self) -> Arc<DohStats> {
        Arc::clone(&self.stats)
    }

    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        self.endpoint.set_server_config(None);
        let _ = tokio::time::timeout(Duration::from_secs(2), self.endpoint.wait_idle()).await;
        self.endpoint
            .close(quinn::VarInt::from_u32(0x100), b"shutting down");
        self.task.abort();
    }
}

async fn accept_loop<H: QueryHandler>(
    endpoint: quinn::Endpoint,
    cfg: Arc<Doh3Config>,
    handler: Arc<H>,
    stats: Arc<DohStats>,
    mut stop: watch::Receiver<bool>,
) {
    // REQ: DNS-004 — the same cap as the HTTP/2 listener: refused beyond it, not accepted
    // without bound.
    let slots = Arc::new(tokio::sync::Semaphore::new(cfg.max_connections.max(1)));
    let per_address = crate::peer_limit::PeerLimit::new(cfg.max_connections_per_address);
    loop {
        let incoming = tokio::select! {
            _ = stop.changed() => return,
            i = endpoint.accept() => i,
        };
        let Some(incoming) = incoming else { return };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            incoming.refuse();
            continue;
        };
        let (cfg, handler, stats) = (Arc::clone(&cfg), Arc::clone(&handler), Arc::clone(&stats));
        let per_address = Arc::clone(&per_address);
        tokio::spawn(async move {
            let peer = incoming.remote_address();
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    stats.tls_failed.fetch_add(1, Ordering::Relaxed);
                    debug!(%peer, error = %e, "doh3 handshake failed");
                    return;
                }
            };
            // The handshake proved the address (it can't be spoofed any more).
            let Some(_place) = per_address.acquire(conn.remote_address().ip()) else {
                stats.rejected_per_address.fetch_add(1, Ordering::Relaxed);
                conn.close(quinn::VarInt::from_u32(0x100), b"too many connections");
                return;
            };
            stats.accepted.fetch_add(1, Ordering::Relaxed);
            let sni_id = conn
                .handshake_data()
                .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|d| d.server_name.clone())
                .and_then(|sni| cfg.tls.client_id(&sni));
            let Ok(mut h3) = h3::server::builder()
                .build::<_, Bytes>(h3_quinn::Connection::new(conn))
                .await
            else {
                return;
            };
            while let Ok(Some(resolver)) = h3.accept().await {
                let (cfg, handler, stats) =
                    (Arc::clone(&cfg), Arc::clone(&handler), Arc::clone(&stats));
                tokio::spawn(async move {
                    let Ok((req, stream)) = resolver.resolve_request().await else {
                        return;
                    };
                    serve(req, stream, &cfg, peer, sni_id, handler.as_ref(), &stats).await;
                });
            }
            drop(permit);
        });
    }
}

async fn serve<H: QueryHandler + ?Sized>(
    req: hyper::Request<()>,
    mut stream: H3Stream,
    cfg: &Doh3Config,
    peer: SocketAddr,
    sni_id: Option<ClientId>,
    handler: &H,
    stats: &DohStats,
) {
    stats.requests.fetch_add(1, Ordering::Relaxed);
    let result = answer(&req, &mut stream, cfg, peer, sni_id, handler).await;
    let resp = match result {
        Ok((body, max_age)) => {
            stats.replies.fetch_add(1, Ordering::Relaxed);
            let mut r = hyper::Response::new(());
            let h = r.headers_mut();
            h.insert(CONTENT_TYPE, HeaderValue::from_static(DNS_MESSAGE));
            if let Ok(v) = HeaderValue::from_str(&format!("max-age={max_age}")) {
                h.insert(CACHE_CONTROL, v);
            }
            Some((r, Some(body)))
        }
        Err(code) => {
            if code.is_client_error() {
                stats.bad_requests.fetch_add(1, Ordering::Relaxed);
            }
            let mut r = hyper::Response::new(());
            *r.status_mut() = code;
            if code == StatusCode::METHOD_NOT_ALLOWED {
                r.headers_mut()
                    .insert(ALLOW, HeaderValue::from_static("GET, POST"));
            }
            Some((r, None))
        }
    };
    if let Some((r, body)) = resp
        && stream.send_response(r).await.is_ok()
    {
        if let Some(b) = body {
            let _ = stream.send_data(Bytes::from(b)).await;
        }
        let _ = stream.finish().await;
    }
}

/// The DNS answer for a request, or the status to send.
async fn answer<H: QueryHandler + ?Sized>(
    req: &hyper::Request<()>,
    stream: &mut H3Stream,
    cfg: &Doh3Config,
    peer: SocketAddr,
    sni_id: Option<ClientId>,
    handler: &H,
) -> Result<(Vec<u8>, u32), StatusCode> {
    let path_id = route(&cfg.path, req.uri().path())?;
    let msg = match *req.method() {
        Method::GET => get_message(req.uri().query())?,
        Method::POST => {
            let ct = req
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok());
            if !is_dns_message(ct) {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
            let mut body = Vec::new();
            while let Ok(Some(mut chunk)) = stream.recv_data().await {
                if body.len() + chunk.remaining() > MAX_MSG {
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
                while chunk.has_remaining() {
                    let part = chunk.chunk();
                    body.extend_from_slice(part);
                    let n = part.len();
                    chunk.advance(n);
                }
            }
            body
        }
        _ => return Err(StatusCode::METHOD_NOT_ALLOWED),
    };
    let meta = RequestMeta {
        peer,
        local: None,
        transport: Transport::Doh,
        client_id: path_id.or(sni_id),
    };
    resolve(handler, &msg, &meta).await
}
