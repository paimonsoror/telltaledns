//! DNS-003, DNS-020 (ADR-194): a `doh` listener behind proxies the operator lists
//! (`trusted_proxies`, `x_forwarded_for`), end to end against real listeners with a test CA.
//! Clients connect from chosen loopback addresses (`127.0.0.2`) to stand for a listed proxy and
//! for anyone else.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use telltale_net::forwarded::Network;
use telltale_net::proxy::{NoAddress, SIGNATURE, encode, read_header};
use telltale_net::{CertStore, DohConfig, DohServer, DohStats, RequestMeta, Response};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

/// How long a test waits for something that should happen at once.
const SOON: Duration = Duration::from_secs(5);

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name)
}

/// The client address and client ID the handler saw for each query.
type Seen = Arc<Mutex<Vec<(SocketAddr, Option<String>)>>>;

/// Answers every query for `www.example.com A` with 1.2.3.4, recording what it saw.
fn handler(seen: Seen) -> impl Fn(&[u8], &RequestMeta, &mut [u8]) -> Response + Send + Sync {
    move |req: &[u8], meta: &RequestMeta, out: &mut [u8]| {
        seen.lock()
            .unwrap()
            .push((meta.peer, meta.client_id.map(|c| c.as_str().to_owned())));
        let mut r = vec![req[0], req[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        r.extend_from_slice(&req[12..]);
        r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 1, 2, 3, 4]);
        out[..r.len()].copy_from_slice(&r);
        Response::Ready(r.len())
    }
}

fn query(id: u16) -> Vec<u8> {
    let mut m = vec![(id >> 8) as u8, id as u8, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    m.extend_from_slice(b"\x03www\x07example\x03com\x00\x00\x01\x00\x01");
    m
}

fn b64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            s.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    s
}

fn at(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn net(s: &str) -> Network {
    let (a, p) = s.split_once('/').unwrap();
    Network {
        addr: a.parse().unwrap(),
        prefix: p.parse().unwrap(),
    }
}

/// A DoH listener on `127.0.0.1` with `set` applied. The handshake timeout is long, so that a
/// connection the listener keeps open is never mistaken for one it closed.
fn server(set: impl FnOnce(&mut DohConfig)) -> (DohServer, Seen, Arc<DohStats>) {
    let store = CertStore::load(fixture("a.crt"), fixture("a.key")).unwrap();
    let seen = Seen::default();
    let mut cfg = DohConfig::new("127.0.0.1:0".parse().unwrap(), store);
    cfg.handshake_timeout = Duration::from_secs(60);
    set(&mut cfg);
    let server = DohServer::bind(cfg, Arc::new(handler(Arc::clone(&seen)))).unwrap();
    let stats = server.stats_handle();
    (server, seen, stats)
}

/// Behind `X-Forwarded-For` from the listed proxy `127.0.0.2`.
fn xff(c: &mut DohConfig) {
    c.x_forwarded_for = true;
    c.trusted_proxies = vec![net("127.0.0.2/32")];
}

/// Behind PROXY-protocol balancers, only `listed` of them.
fn proxied(listed: &'static str) -> impl FnOnce(&mut DohConfig) {
    move |c: &mut DohConfig| {
        c.proxy_protocol = true;
        c.trusted_proxies = vec![net(listed)];
    }
}

/// A TCP connection to `to` from the loopback address `from`.
async fn tcp_from(from: &str, to: SocketAddr) -> TcpStream {
    let sock = TcpSocket::new_v4().unwrap();
    sock.bind(format!("{from}:0").parse().unwrap()).unwrap();
    sock.connect(to).await.unwrap()
}

fn tls_client(alpn: &[u8]) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(fixture("ca.crt")).unwrap())
        .unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
}

async fn tls_from(
    from: &str,
    to: SocketAddr,
    sni: &str,
    alpn: &[u8],
    preamble: &[u8],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut tcp = tcp_from(from, to).await;
    tcp.write_all(preamble).await.unwrap();
    tls_client(alpn)
        .connect(ServerName::try_from(sni.to_owned()).unwrap(), tcp)
        .await
        .unwrap()
}

type H2 = hyper::client::conn::http2::SendRequest<Full<Bytes>>;

/// An HTTP/2 client, and the task that runs its connection (it ends when the connection does).
async fn h2_from(
    from: &str,
    to: SocketAddr,
    sni: &str,
    preamble: &[u8],
) -> (H2, tokio::task::JoinHandle<()>) {
    let tls = tls_from(from, to, sni, b"h2", preamble).await;
    let (send, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    let task = tokio::spawn(async move {
        let _ = conn.await;
    });
    (send, task)
}

/// A GET for `path` carrying `headers`.
fn get(path: &str, headers: &[(&str, &str)]) -> hyper::Request<Full<Bytes>> {
    let mut b = hyper::Request::get(format!("https://dns.test{path}?dns={}", b64url(&query(0))));
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Full::new(Bytes::new())).unwrap()
}

async fn send(c: &mut H2, req: hyper::Request<Full<Bytes>>) -> (u16, hyper::HeaderMap) {
    let r = c.send_request(req).await.unwrap();
    let (parts, body) = r.into_parts();
    let _ = body.collect().await.unwrap();
    (parts.status.as_u16(), parts.headers)
}

/// Whether the other side closes the stream (end of stream or reset) within [`SOON`], without
/// sending anything first.
async fn closes<S: AsyncRead + Unpin>(s: &mut S) -> bool {
    let mut b = [0u8; 1];
    matches!(timeout(SOON, s.read(&mut b)).await, Ok(Ok(0) | Err(_)))
}

/// Waits (at most [`SOON`]) until `f` holds.
async fn until(f: impl Fn() -> bool) -> bool {
    let end = tokio::time::Instant::now() + SOON;
    while !f() {
        if tokio::time::Instant::now() > end {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    true
}

/// A PROXY v2 header without an address: `LOCAL`, or `PROXY` over `AF_UNSPEC` or `AF_UNIX`.
fn addressless() -> [(&'static str, Vec<u8>); 3] {
    let with = |rest: &[u8]| {
        let mut h = SIGNATURE.to_vec();
        h.extend_from_slice(rest);
        h
    };
    let mut unix = vec![0x21, 0x31, 0x00, 0xD8];
    unix.extend_from_slice(&[0u8; 216]);
    [
        ("LOCAL", with(&[0x20, 0x00, 0, 0])),
        ("AF_UNSPEC", with(&[0x21, 0x00, 0, 0])),
        ("AF_UNIX", with(&unix)),
    ]
}

/// REQ: DNS-003 (ADR-194, R4) — behind `X-Forwarded-For` only the listed proxy connects: any
/// other peer is closed at accept, before a byte is read, takes no slot and is counted; from the
/// proxy, the client is the forwarded one.
#[tokio::test]
async fn dns_003_xff_only_from_listed_peers() {
    let (server, seen, stats) = server(xff);
    let addr = server.local_addr();

    let mut other = tcp_from("127.0.0.1", addr).await;
    assert!(closes(&mut other).await, "an unlisted peer is closed");
    assert!(until(|| stats.unlisted_peer.load(Relaxed) == 1).await);
    assert_eq!(stats.accepted.load(Relaxed), 0, "no slot taken");

    let (mut c, _conn) = h2_from("127.0.0.2", addr, "dns.test", b"").await;
    let (st, _) = send(
        &mut c,
        get("/dns-query", &[("x-forwarded-for", "192.0.2.7")]),
    )
    .await;
    assert_eq!(st, 200);
    assert_eq!(*seen.lock().unwrap(), [(at("192.0.2.7:0"), None::<String>)]);
    assert_eq!(stats.unlisted_peer.load(Relaxed), 1);
    server.shutdown().await;
}

/// REQ: DNS-020 (ADR-194, R4) — with `trusted_proxies` a PROXY-protocol listener accepts only
/// the listed balancer: another peer is closed even with a well-formed header, and the listed one
/// names its client.
#[tokio::test]
async fn dns_020_proxy_v2_only_from_listed_peers() {
    let (server, seen, stats) = server(proxied("127.0.0.2/32"));
    let addr = server.local_addr();
    let client: SocketAddr = "192.0.2.7:4000".parse().unwrap();

    let mut other = tcp_from("127.0.0.1", addr).await;
    other.write_all(&encode(client, addr)).await.unwrap();
    assert!(closes(&mut other).await, "an unlisted balancer is closed");
    assert!(until(|| stats.unlisted_peer.load(Relaxed) == 1).await);

    let (mut c, _conn) = h2_from("127.0.0.2", addr, "dns.test", &encode(client, addr)).await;
    assert_eq!(send(&mut c, get("/dns-query", &[])).await.0, 200);
    assert_eq!(*seen.lock().unwrap(), [(client, None::<String>)]);
    server.shutdown().await;
}

/// REQ: DNS-020 (ADR-194, R5) — once `trusted_proxies` is set, a PROXY header that names no
/// client (`LOCAL`, `AF_UNSPEC`, `AF_UNIX`) closes the connection instead of serving the socket's
/// address, which is loopback here; the handler is never called, and each one is counted.
#[tokio::test]
async fn dns_020_local_refused_once_trusted_proxies_is_set() {
    let (server, seen, stats) = server(proxied("127.0.0.1/32"));
    let addr = server.local_addr();
    for (n, (what, header)) in addressless().into_iter().enumerate() {
        let mut s = tcp_from("127.0.0.1", addr).await;
        s.write_all(&header).await.unwrap();
        assert!(closes(&mut s).await, "{what}");
        assert!(
            until(|| stats.no_client_address.load(Relaxed) == n as u64 + 1).await,
            "{what}"
        );
    }
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(stats.proxy_rejected.load(Relaxed), 0, "well-formed headers");
    server.shutdown().await;
}

/// REQ: DNS-020 (ADR-194, ADR-039) — a header without an address that a listener behind listed
/// proxies refuses is counted as a refusal only, never in the no-address counter, which counts
/// the connections that keep the socket's address. Without the keys the same headers are
/// counted there and answered, as before.
#[tokio::test]
async fn dns_020_refused_headers_are_counted_as_refusals_only() {
    let (strict, seen, stats) = server(proxied("127.0.0.1/32"));
    let addr = strict.local_addr();
    for (n, (what, header)) in addressless().into_iter().enumerate() {
        let mut s = tcp_from("127.0.0.1", addr).await;
        s.write_all(&header).await.unwrap();
        assert!(closes(&mut s).await, "{what}");
        assert!(
            until(|| stats.no_client_address.load(Relaxed) == n as u64 + 1).await,
            "{what}"
        );
    }
    for kind in NoAddress::ALL {
        assert_eq!(
            stats.proxy_no_address.counter(kind).load(Relaxed),
            0,
            "{kind:?}: refused, not kept"
        );
    }
    assert!(seen.lock().unwrap().is_empty());
    strict.shutdown().await;

    let (plain, seen, stats) = server(|c| c.proxy_protocol = true);
    let addr = plain.local_addr();
    for (what, header) in addressless() {
        let (mut c, _conn) = h2_from("127.0.0.1", addr, "dns.test", &header).await;
        assert_eq!(send(&mut c, get("/dns-query", &[])).await.0, 200, "{what}");
    }
    for kind in NoAddress::ALL {
        assert_eq!(
            stats.proxy_no_address.counter(kind).load(Relaxed),
            1,
            "{kind:?}: kept and counted"
        );
    }
    assert_eq!(stats.no_client_address.load(Relaxed), 0);
    assert_eq!(seen.lock().unwrap().len(), 3);
    plain.shutdown().await;
}

/// REQ: DNS-020 (ADR-039, ADR-194 R18) — without the new keys nothing changes: `LOCAL` (a
/// balancer's health check) still keeps the socket's address.
#[tokio::test]
async fn dns_020_local_keeps_socket_address_without_new_keys() {
    let (server, seen, stats) = server(|c| c.proxy_protocol = true);
    let addr = server.local_addr();
    let [(_, local), _, _] = addressless();
    let (mut c, _conn) = h2_from("127.0.0.1", addr, "dns.test", &local).await;
    assert_eq!(send(&mut c, get("/dns-query", &[])).await.0, 200);
    let peer = seen.lock().unwrap()[0].0;
    assert_eq!(peer.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
    assert_ne!(peer.port(), 0, "the socket's own address");
    assert_eq!(stats.no_client_address.load(Relaxed), 0);
    server.shutdown().await;
}

/// REQ: DNS-020, DNS-003 (ADR-194, R5) — behind listed proxies an unspecified or a loopback
/// client is refused, from a PROXY header (the connection closes) and from `X-Forwarded-For`
/// (403); the handler is never called.
#[tokio::test]
async fn dns_020_forwarded_unspecified_or_loopback_refused() {
    let sources = ["0.0.0.0", "::", "127.0.0.5", "::1", "::ffff:127.0.0.1"];

    let (balanced, seen, stats) = server(proxied("127.0.0.1/32"));
    let addr = balanced.local_addr();
    for (n, ip) in sources.iter().enumerate() {
        let src = SocketAddr::new(ip.parse().unwrap(), 0);
        let mut s = tcp_from("127.0.0.1", addr).await;
        s.write_all(&encode(src, addr)).await.unwrap();
        assert!(closes(&mut s).await, "PROXY {ip}");
        assert!(
            until(|| stats.no_client_address.load(Relaxed) == n as u64 + 1).await,
            "{ip}"
        );
    }
    assert!(seen.lock().unwrap().is_empty());
    balanced.shutdown().await;

    let (forwarded, seen, stats) = server(xff);
    let addr = forwarded.local_addr();
    for ip in sources {
        let (mut c, _conn) = h2_from("127.0.0.2", addr, "dns.test", b"").await;
        let (st, _) = send(&mut c, get("/dns-query", &[("x-forwarded-for", ip)])).await;
        assert_eq!(st, 403, "X-Forwarded-For {ip}");
    }
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(stats.no_client_address.load(Relaxed), sources.len() as u64);
    forwarded.shutdown().await;
}

/// REQ: DNS-020 (ADR-194, R6) — the header a proxy sends over a Unix socket (TCP4 or TCP6, source
/// port 0, an all-zero destination) parses to the source with port 0, and a listener behind
/// listed proxies answers it as that client.
#[tokio::test]
async fn dns_020_proxy_v2_port_zero_and_empty_destination_accepted() {
    for (src, dst) in [
        ("127.0.0.1:0", "0.0.0.0:0"),
        ("192.0.2.7:0", "0.0.0.0:0"),
        ("[2001:db8::7]:0", "[::]:0"),
    ] {
        let (src, dst): (SocketAddr, SocketAddr) = (src.parse().unwrap(), dst.parse().unwrap());
        let mut r = &encode(src, dst)[..];
        assert_eq!(read_header(&mut r).await.unwrap(), Some(src));
    }

    let (balanced, seen, _) = server(proxied("127.0.0.1/32"));
    let addr = balanced.local_addr();
    let clients = [at("192.0.2.7:0"), at("[2001:db8::7]:0")];
    for client in clients {
        let zero = if client.is_ipv4() {
            at("0.0.0.0:0")
        } else {
            at("[::]:0")
        };
        let (mut c, _conn) = h2_from("127.0.0.1", addr, "dns.test", &encode(client, zero)).await;
        assert_eq!(
            send(&mut c, get("/dns-query", &[])).await.0,
            200,
            "{client}"
        );
    }
    let seen: Vec<SocketAddr> = seen.lock().unwrap().iter().map(|s| s.0).collect();
    assert_eq!(seen, clients);
    balanced.shutdown().await;
}

/// REQ: DNS-003 (ADR-194, R5, R8) — a request from the listed proxy without a usable
/// `X-Forwarded-For` client gets 403: no header, only listed proxies, an unreadable entry where
/// the client should be, and a client named only in `X-Real-IP` or `Forwarded` (never read).
/// The handler is never called; each refusal is counted.
#[tokio::test]
async fn dns_003_xff_missing_or_unusable_refused() {
    let (server, seen, stats) = server(xff);
    let addr = server.local_addr();
    let cases: [&[(&str, &str)]; 5] = [
        &[],
        &[("x-forwarded-for", "127.0.0.2")],
        &[("x-forwarded-for", "192.0.2.7, unknown")],
        &[("x-real-ip", "192.0.2.9")],
        &[("forwarded", "for=192.0.2.9")],
    ];
    for headers in cases {
        let (mut c, _conn) = h2_from("127.0.0.2", addr, "dns.test", b"").await;
        let (st, h) = send(&mut c, get("/dns-query", headers)).await;
        assert_eq!(st, 403, "{headers:?}");
        assert!(
            h.get("connection").is_none(),
            "HTTP/2 has no Connection header"
        );
    }
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(stats.no_client_address.load(Relaxed), cases.len() as u64);
    assert_eq!(stats.bad_requests.load(Relaxed), cases.len() as u64);
    server.shutdown().await;
}

/// REQ: DNS-003 (ADR-194, R8, R18) — without `x_forwarded_for` no forwarded-address header is
/// read: the client is the connection's peer.
#[tokio::test]
async fn dns_003_xff_ignored_without_the_key() {
    let (server, seen, _) = server(|_| {});
    let addr = server.local_addr();
    let (mut c, _conn) = h2_from("127.0.0.2", addr, "dns.test", b"").await;
    let headers = [
        ("x-forwarded-for", "192.0.2.7"),
        ("x-real-ip", "192.0.2.8"),
        ("forwarded", "for=192.0.2.9"),
    ];
    assert_eq!(send(&mut c, get("/dns-query", &headers)).await.0, 200);
    let peer = seen.lock().unwrap()[0].0;
    assert_eq!(peer.ip(), "127.0.0.2".parse::<std::net::IpAddr>().unwrap());
    server.shutdown().await;
}

/// The raw HTTP/1.1 text of a GET with `x-forwarded-for` lines `xff`.
fn h1_get(xff: &[&str]) -> String {
    let mut r = format!(
        "GET /dns-query?dns={} HTTP/1.1\r\nhost: dns.test\r\n",
        b64url(&query(0))
    );
    for v in xff {
        r.push_str("x-forwarded-for: ");
        r.push_str(v);
        r.push_str("\r\n");
    }
    r.push_str("\r\n");
    r
}

/// Everything the server sends until it closes (at most [`SOON`]).
async fn read_to_close<S: AsyncRead + Unpin>(s: &mut S) -> Option<String> {
    let mut all = Vec::new();
    timeout(SOON, s.read_to_end(&mut all)).await.ok()?.ok()?;
    Some(String::from_utf8_lossy(&all).into_owned())
}

/// REQ: DNS-003 (ADR-194, R13) — a refused request ends an HTTP/1.1 connection: the 403 says
/// `Connection: close` and a request pipelined behind it is never read. HTTP/2 frames each
/// request on its own, so there the refusal is answered and the connection, which carries the
/// proxy's other clients, stays: the next request on it is answered as its own client.
#[tokio::test]
async fn dns_003_forwarded_listener_closes_after_a_refused_request() {
    let (server, seen, _) = server(xff);
    let addr = server.local_addr();

    let mut s = tls_from("127.0.0.2", addr, "dns.test", b"http/1.1", b"").await;
    let two = format!("{}{}", h1_get(&[]), h1_get(&["192.0.2.7"]));
    s.write_all(two.as_bytes()).await.unwrap();
    let got = read_to_close(&mut s).await.expect("the connection closes");
    assert_eq!(got.matches("HTTP/1.1 ").count(), 1, "{got}");
    assert!(got.starts_with("HTTP/1.1 403"), "{got}");
    assert!(
        got.to_ascii_lowercase().contains("connection: close"),
        "{got}"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "the second request is never read"
    );

    let (mut c, mut conn) = h2_from("127.0.0.2", addr, "dns.test", b"").await;
    assert_eq!(send(&mut c, get("/dns-query", &[])).await.0, 403);
    // A shutdown would end the connection well within this bound; the answer below doesn't
    // depend on it.
    assert!(
        timeout(Duration::from_millis(500), &mut conn)
            .await
            .is_err(),
        "the HTTP/2 connection stays open after the refusal"
    );
    let (st, _) = send(
        &mut c,
        get("/dns-query", &[("x-forwarded-for", "192.0.2.7")]),
    )
    .await;
    assert_eq!(st, 200, "the next request on it is answered");
    assert_eq!(
        *seen.lock().unwrap(),
        [(at("192.0.2.7:0"), None::<String>)],
        "as its own client"
    );
    server.shutdown().await;
}

/// REQ: DNS-003 (ADR-194, R13) — a request that states its length both ways (`Content-Length`
/// and `Transfer-Encoding`, in either order) is framed by `Transfer-Encoding`, answered, and
/// its connection closed: a request a proxy might have counted inside its body is never read.
#[tokio::test]
async fn dns_003_xff_listener_closes_after_conflicting_framing() {
    let (server, seen, _) = server(xff);
    let addr = server.local_addr();
    let q = query(9);
    let chunked = format!("{:x}\r\n", q.len());
    let behind = h1_get(&["198.51.100.9"]);
    for te_first in [false, true] {
        let mut body = chunked.clone().into_bytes();
        body.extend_from_slice(&q);
        body.extend_from_slice(b"\r\n0\r\n\r\n");
        let counted = body.len() + behind.len();
        let (a, b) = (
            format!("content-length: {counted}\r\n"),
            "transfer-encoding: chunked\r\n".to_owned(),
        );
        let framing = if te_first { b + &a } else { a + &b };
        let mut req = format!(
            "POST /dns-query HTTP/1.1\r\nhost: dns.test\r\ncontent-type: application/dns-message\r\nx-forwarded-for: 192.0.2.7\r\n{framing}\r\n"
        )
        .into_bytes();
        req.extend_from_slice(&body);
        req.extend_from_slice(behind.as_bytes());

        let mut s = tls_from("127.0.0.2", addr, "dns.test", b"http/1.1", b"").await;
        s.write_all(&req).await.unwrap();
        let got = read_to_close(&mut s).await.expect("the connection closes");
        assert_eq!(
            got.matches("HTTP/1.1 ").count(),
            1,
            "te_first={te_first}: {got}"
        );
    }
    let answered: Vec<SocketAddr> = seen.lock().unwrap().iter().map(|s| s.0).collect();
    assert_eq!(
        answered,
        [at("192.0.2.7:0"), at("192.0.2.7:0")],
        "the request behind is never answered"
    );
    server.shutdown().await;
}

/// REQ: DNS-003, DNS-004 (ADR-194, R14) — clients reach the proxy, not this listener: no
/// `Alt-Svc`, even with an HTTP/3 listener configured.
#[tokio::test]
async fn dns_003_plain_and_xff_listeners_send_no_alt_svc() {
    let (server, _, _) = server(|c| {
        xff(c);
        c.alt_svc = Some("h3=\":443\"; ma=86400".into());
    });
    let (mut c, _conn) = h2_from("127.0.0.2", server.local_addr(), "dns.test", b"").await;
    let (st, h) = send(
        &mut c,
        get("/dns-query", &[("x-forwarded-for", "192.0.2.7")]),
    )
    .await;
    assert_eq!(st, 200);
    assert!(h.get("alt-svc").is_none(), "{h:?}");
    server.shutdown().await;
}

/// REQ: DNS-003, FLT-006 (ADR-194, R15) — behind `X-Forwarded-For` the SNI is the proxy's: a
/// wildcard certificate's name gives no client ID.
#[tokio::test]
async fn dns_003_xff_listener_ignores_sni_client_ids() {
    let (server, seen, _) = server(xff);
    let (mut c, _conn) = h2_from("127.0.0.2", server.local_addr(), "phone.dns.test", b"").await;
    let (st, _) = send(
        &mut c,
        get("/dns-query", &[("x-forwarded-for", "192.0.2.7")]),
    )
    .await;
    assert_eq!(st, 200);
    assert_eq!(seen.lock().unwrap()[0].1, None);
    server.shutdown().await;
}

/// REQ: DNS-003, FLT-006 (ADR-194, R15) — a client ID in the path goes through the proxy with
/// the client's address.
#[tokio::test]
async fn dns_003_client_id_from_path_survives_forwarding() {
    let (server, seen, _) = server(xff);
    let (mut c, _conn) = h2_from("127.0.0.2", server.local_addr(), "phone.dns.test", b"").await;
    let (st, _) = send(
        &mut c,
        get(
            "/dns-query/kids-tablet",
            &[("x-forwarded-for", "192.0.2.7")],
        ),
    )
    .await;
    assert_eq!(st, 200);
    assert_eq!(
        *seen.lock().unwrap(),
        [(at("192.0.2.7:0"), Some("kids-tablet".to_owned()))]
    );
    server.shutdown().await;
}

/// REQ: DNS-003 (ADR-099, ADR-194 R10) — behind `X-Forwarded-For` the per-address connection
/// limit counts the proxy: every connection is its own, whichever clients it names.
#[tokio::test]
async fn dns_003_per_address_limit_counts_the_proxy_with_xff() {
    let (server, seen, stats) = server(|c| {
        xff(c);
        c.max_connections_per_address = 1;
    });
    let addr = server.local_addr();
    let (mut held, _conn) = h2_from("127.0.0.2", addr, "dns.test", b"").await;
    let (st, _) = send(
        &mut held,
        get("/dns-query", &[("x-forwarded-for", "192.0.2.7")]),
    )
    .await;
    assert_eq!(st, 200);
    let mut second = tcp_from("127.0.0.2", addr).await;
    assert!(
        closes(&mut second).await,
        "a second connection from the proxy"
    );
    assert_eq!(stats.rejected_per_address.load(Relaxed), 1);
    let (st, _) = send(
        &mut held,
        get("/dns-query", &[("x-forwarded-for", "198.51.100.9")]),
    )
    .await;
    assert_eq!(st, 200, "the first one still serves");
    assert_eq!(seen.lock().unwrap().len(), 2);
    server.shutdown().await;
}
