//! DNS over HTTPS (REQ: DNS-003, RFC 8484; `spec/03` §1).
//!
//! HTTP/2 (ALPN `h2`) and HTTP/1.1 over TLS. `GET <path>?dns=<base64url>` and `POST <path>`
//! with `Content-Type: application/dns-message`, on the configured path and on
//! `<path>/<client-id>` (FLT-006; the path's ID wins over one from SNI). Answers carry
//! `Cache-Control: max-age` = the smallest TTL in the answer (RFC 8484 §5.1). PROXY protocol
//! v2 (DNS-020) is read before the TLS handshake when configured.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE, HeaderValue};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::handler::{ClientId, QueryHandler, RequestMeta, Response, Transport};
use crate::tls::CertStore;

pub(crate) const DNS_MESSAGE: &str = "application/dns-message";
/// Largest DNS message.
pub(crate) const MAX_MSG: usize = u16::MAX as usize;

/// DoH listener settings.
#[derive(Clone, Debug)]
pub struct DohConfig {
    pub addr: SocketAddr,
    /// URL path (default `/dns-query`); `<path>/<client-id>` also matches.
    pub path: String,
    pub tls: Arc<CertStore>,
    /// Every connection starts with a PROXY protocol v2 header (DNS-020).
    pub proxy_protocol: bool,
    /// Time allowed for the PROXY header and the TLS handshake, and idle keep-alive.
    pub handshake_timeout: Duration,
    pub max_connections: usize,
    /// Max concurrent connections from one client address (an IPv6 /64), after the PROXY
    /// header if there is one; 0 = no limit (review 01 q2).
    pub max_connections_per_address: usize,
    /// REQ: DNS-004 (T7.8) — `Alt-Svc` to send (`h3=":443"`) when an HTTP/3 DoH listener serves the
    /// same name.
    pub alt_svc: Option<String>,
}

impl DohConfig {
    pub fn new(addr: SocketAddr, tls: Arc<CertStore>) -> Self {
        Self {
            addr,
            path: "/dns-query".to_owned(),
            tls,
            proxy_protocol: false,
            handshake_timeout: Duration::from_secs(10),
            max_connections: 1024,
            max_connections_per_address: crate::peer_limit::DEFAULT_PER_ADDRESS,
            alt_svc: None,
        }
    }
}

/// Listener counters.
#[derive(Debug, Default)]
pub struct DohStats {
    pub accepted: AtomicU64,
    /// Connections refused because `max_connections` was reached.
    pub rejected: AtomicU64,
    /// Connections refused because their client address already held the per-address maximum.
    pub rejected_per_address: AtomicU64,
    pub requests: AtomicU64,
    pub replies: AtomicU64,
    /// Requests refused with a 4xx status (bad path, method, media type, or message).
    pub bad_requests: AtomicU64,
    pub tls_failed: AtomicU64,
    pub proxy_rejected: AtomicU64,
}

/// A running DoH listener.
#[derive(Debug)]
pub struct DohServer {
    local_addr: SocketAddr,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
    stats: Arc<DohStats>,
}

impl DohServer {
    /// Binds and starts accepting. Must be called from within a Tokio runtime.
    pub fn bind<H: QueryHandler>(cfg: DohConfig, handler: Arc<H>) -> io::Result<Self> {
        let tls = cfg.tls.server_config(&[b"h2", b"http/1.1"])?;
        let listener = crate::tcp::listen(cfg.addr)?;
        let local_addr = listener.local_addr()?;
        let (stop, stop_rx) = watch::channel(false);
        let stats = Arc::new(DohStats::default());
        let task = tokio::spawn(accept_loop(
            listener,
            tokio_rustls::TlsAcceptor::from(tls),
            Arc::new(cfg),
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

    pub fn stats_handle(&self) -> Arc<DohStats> {
        Arc::clone(&self.stats)
    }

    /// Stops accepting; open connections finish their requests (graceful HTTP shutdown).
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

async fn accept_loop<H: QueryHandler>(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    cfg: Arc<DohConfig>,
    handler: Arc<H>,
    mut stop: watch::Receiver<bool>,
    stats: Arc<DohStats>,
) {
    let slots = Arc::new(Semaphore::new(cfg.max_connections));
    let per_address = crate::peer_limit::PeerLimit::new(cfg.max_connections_per_address);
    let mut conns = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            _ = stop.changed() => break,
            r = listener.accept() => r,
        };
        let Ok((stream, peer)) = accepted else {
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        stats.accepted.fetch_add(1, Ordering::Relaxed);
        let _ = stream.set_nodelay(true);
        let (acceptor, cfg, handler, stop, stats) = (
            acceptor.clone(),
            Arc::clone(&cfg),
            Arc::clone(&handler),
            stop.clone(),
            Arc::clone(&stats),
        );
        let per_address = Arc::clone(&per_address);
        conns.spawn(async move {
            serve_conn(
                stream,
                peer,
                acceptor,
                cfg,
                handler,
                (stop, stats),
                &per_address,
            )
            .await;
            drop(permit);
        });
        while conns.try_join_next().is_some() {}
    }
    while conns.join_next().await.is_some() {}
}

async fn serve_conn<H: QueryHandler>(
    mut stream: TcpStream,
    mut peer: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    cfg: Arc<DohConfig>,
    handler: Arc<H>,
    (mut stop, stats): (watch::Receiver<bool>, Arc<DohStats>),
    per_address: &Arc<crate::peer_limit::PeerLimit>,
) {
    if cfg.proxy_protocol {
        match timeout(
            cfg.handshake_timeout,
            crate::proxy::read_header(&mut stream),
        )
        .await
        {
            Ok(Ok(Some(src))) => peer = src,
            Ok(Ok(None)) => {}
            _ => {
                stats.proxy_rejected.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }
    // REQ: DNS-003 (review 01 q2) — one client address can't hold every slot; the address is
    // the client's, after the PROXY header.
    let Some(_place) = per_address.acquire(peer.ip()) else {
        stats.rejected_per_address.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let Ok(Ok(tls)) = timeout(cfg.handshake_timeout, acceptor.accept(stream)).await else {
        stats.tls_failed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let (sni_id, h2) = {
        let conn = tls.get_ref().1;
        (
            conn.server_name().and_then(|s| cfg.tls.client_id(s)),
            conn.alpn_protocol() == Some(b"h2"),
        )
    };
    let ctx = Arc::new(Ctx {
        handler,
        cfg: Arc::clone(&cfg),
        peer,
        sni_id,
        stats,
    });
    let svc = hyper::service::service_fn(move |req| {
        let ctx = Arc::clone(&ctx);
        async move { Ok::<_, Infallible>(ctx.answer(req).await) }
    });
    let io = TokioIo::new(tls);
    if h2 {
        let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .timer(hyper_util::rt::TokioTimer::new())
            .keep_alive_interval(Some(Duration::from_secs(30)))
            .serve_connection(io, svc);
        tokio::pin!(conn);
        tokio::select! {
            _ = conn.as_mut() => {}
            _ = stop.changed() => {
                conn.as_mut().graceful_shutdown();
                let _ = conn.await;
            }
        }
    } else {
        let conn = hyper::server::conn::http1::Builder::new()
            .header_read_timeout(cfg.handshake_timeout)
            .timer(hyper_util::rt::TokioTimer::new())
            .serve_connection(io, svc);
        tokio::pin!(conn);
        tokio::select! {
            _ = conn.as_mut() => {}
            _ = stop.changed() => {
                conn.as_mut().graceful_shutdown();
                let _ = conn.await;
            }
        }
    }
}

/// Per-connection request context.
struct Ctx<H> {
    handler: Arc<H>,
    cfg: Arc<DohConfig>,
    peer: SocketAddr,
    sni_id: Option<ClientId>,
    stats: Arc<DohStats>,
}

type HttpResponse = hyper::Response<Full<Bytes>>;

fn status(code: StatusCode) -> HttpResponse {
    let mut r = hyper::Response::new(Full::new(Bytes::new()));
    *r.status_mut() = code;
    r
}

impl<H: QueryHandler> Ctx<H> {
    async fn answer(&self, req: Request<Incoming>) -> HttpResponse {
        self.stats.requests.fetch_add(1, Ordering::Relaxed);
        let r = self.answer_inner(req).await;
        if r.status().is_client_error() {
            self.stats.bad_requests.fetch_add(1, Ordering::Relaxed);
        } else if r.status() == StatusCode::OK {
            self.stats.replies.fetch_add(1, Ordering::Relaxed);
        }
        r
    }

    async fn answer_inner(&self, req: Request<Incoming>) -> HttpResponse {
        let path_id = match route(&self.cfg.path, req.uri().path()) {
            Ok(id) => id,
            Err(code) => return status(code),
        };
        let msg = match *req.method() {
            Method::GET => match get_message(req.uri().query()) {
                Ok(m) => m,
                Err(code) => return status(code),
            },
            Method::POST => {
                let ct = req
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok());
                if !is_dns_message(ct) {
                    return status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
                }
                match Limited::new(req.into_body(), MAX_MSG).collect().await {
                    Ok(b) => b.to_bytes().to_vec(),
                    Err(_) => return status(StatusCode::PAYLOAD_TOO_LARGE),
                }
            }
            _ => {
                let mut r = status(StatusCode::METHOD_NOT_ALLOWED);
                r.headers_mut()
                    .insert(ALLOW, HeaderValue::from_static("GET, POST"));
                return r;
            }
        };
        let meta = RequestMeta {
            peer: self.peer,
            local: None,
            transport: Transport::Doh,
            client_id: path_id.or(self.sni_id),
        };
        let (answer, max_age) = match resolve(self.handler.as_ref(), &msg, &meta).await {
            Ok(a) => a,
            Err(code) => return status(code),
        };
        let mut r = hyper::Response::new(Full::new(Bytes::from(answer)));
        let h = r.headers_mut();
        h.insert(CONTENT_TYPE, HeaderValue::from_static(DNS_MESSAGE));
        if let Ok(v) = HeaderValue::from_str(&format!("max-age={max_age}")) {
            h.insert(CACHE_CONTROL, v);
        }
        // REQ: DNS-004 (T7.8) — clients may switch to HTTP/3 on the same name.
        if let Some(alt) = self
            .cfg
            .alt_svc
            .as_deref()
            .and_then(|a| HeaderValue::from_str(a).ok())
        {
            h.insert(hyper::header::ALT_SVC, alt);
        }
        r
    }
}

/// REQ: DNS-003, DNS-004 — a DoH request, whatever its HTTP version: `<base>` or
/// `<base>/<client-id>`; anything else is a 404.
pub(crate) fn route(base: &str, path: &str) -> Result<Option<ClientId>, StatusCode> {
    match path.strip_prefix(base) {
        Some("" | "/") => Ok(None),
        Some(rest) => rest
            .strip_prefix('/')
            .and_then(ClientId::new)
            .map(Some)
            .ok_or(StatusCode::NOT_FOUND),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// The message of a GET (`?dns=` in base64url).
pub(crate) fn get_message(query: Option<&str>) -> Result<Vec<u8>, StatusCode> {
    query
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("dns=")))
        .and_then(base64url_decode)
        .ok_or(StatusCode::BAD_REQUEST)
}

/// Whether a POST's content type is `application/dns-message`.
pub(crate) fn is_dns_message(content_type: Option<&str>) -> bool {
    content_type.map(|c| c.split(';').next().unwrap_or("").trim()) == Some(DNS_MESSAGE)
}

/// Answers `msg`: the answer and its `max-age` (the smallest TTL), or the status to send.
pub(crate) async fn resolve<H: QueryHandler + ?Sized>(
    handler: &H,
    msg: &[u8],
    meta: &RequestMeta,
) -> Result<(Vec<u8>, u32), StatusCode> {
    if msg.len() < 12 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let outcome = crate::tcp::with_scratch(|out| match handler.handle(msg, meta, out) {
        Response::Ready(len) => Pending::Now(Some(out[..len].to_vec())),
        Response::Deferred(f) => Pending::Later(f),
        Response::Drop => Pending::Now(None),
    });
    let answer = match outcome {
        Pending::Now(a) => a,
        Pending::Later(f) => f.await,
    };
    // Nothing to send (e.g. a rate-limited client): HTTP must still say something.
    let answer = answer.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let max_age = telltale_proto::summarize(&answer)
        .ok()
        .and_then(|s| match (s.min_ttl, s.negative_ttl) {
            (Some(a), Some(n)) => Some(a.min(n)),
            (a, n) => a.or(n),
        })
        .unwrap_or(0);
    Ok((answer, max_age))
}

enum Pending {
    Now(Option<Vec<u8>>),
    Later(crate::handler::Deferred),
}

/// RFC 4648 §5 base64url without padding (padding tolerated); `None` on bad input.
pub fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    if s.len() > (MAX_MSG * 4).div_ceil(3) {
        return None;
    }
    let val = |c: u8| -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        }))
    };
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.as_bytes().chunks(4) {
        let mut acc = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            acc |= val(*c)? << (18 - 6 * i);
        }
        let bytes = acc.to_be_bytes();
        match chunk.len() {
            4 => out.extend_from_slice(&bytes[1..4]),
            3 => out.extend_from_slice(&bytes[1..3]),
            2 => out.push(bytes[1]),
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_003_base64url() {
        // RFC 8484 §4.1.1's example query for www.example.com A.
        let q = "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB";
        let m = base64url_decode(q).unwrap();
        assert_eq!(&m[..4], &[0, 0, 1, 0]);
        assert_eq!(m.len(), 33);
        assert_eq!(base64url_decode("_-8").unwrap(), [0xFF, 0xEF]);
        assert_eq!(base64url_decode("AQ==").unwrap(), [1]);
        assert!(base64url_decode("A").is_none());
        assert!(
            base64url_decode("AA+/").is_none(),
            "standard alphabet is not base64url"
        );
    }
}
