//! DNS-002 (DoT), DNS-003 (DoH), DNS-020 (PROXY protocol v2), and FLT-006 client IDs, end to
//! end against real listeners with a test CA.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use telltale_net::{
    CertStore, DohConfig, DohServer, RequestMeta, Response, TcpConfig, TcpServer, Transport,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name)
}

/// What the handler saw for each query.
type Seen = Arc<Mutex<Vec<(SocketAddr, Option<String>, Transport)>>>;

/// Answers every query for `www.example.com A` with 1.2.3.4, TTL 300, recording the meta.
fn handler(seen: Seen) -> impl Fn(&[u8], &RequestMeta, &mut [u8]) -> Response + Send + Sync {
    move |req: &[u8], meta: &RequestMeta, out: &mut [u8]| {
        seen.lock().unwrap().push((
            meta.peer,
            meta.client_id.map(|c| c.as_str().to_owned()),
            meta.transport,
        ));
        let q = &req[12..];
        let mut r = vec![req[0], req[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        r.extend_from_slice(q);
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

async fn connect_tls(
    addr: SocketAddr,
    sni: &str,
    alpn: &[u8],
    preamble: &[u8],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(preamble).await.unwrap();
    tls_client(alpn)
        .connect(ServerName::try_from(sni.to_owned()).unwrap(), tcp)
        .await
        .unwrap()
}

async fn dot_exchange<S: AsyncReadExt + AsyncWriteExt + Unpin>(s: &mut S, id: u16) -> Vec<u8> {
    let q = query(id);
    let mut f = (q.len() as u16).to_be_bytes().to_vec();
    f.extend_from_slice(&q);
    s.write_all(&f).await.unwrap();
    s.flush().await.unwrap();
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await.unwrap();
    let mut buf = vec![0; usize::from(u16::from_be_bytes(len))];
    s.read_exact(&mut buf).await.unwrap();
    buf
}

#[tokio::test]
async fn dns_002_dot_answers_with_sni_client_id_and_reloads_cert() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = (dir.path().join("tls.crt"), dir.path().join("tls.key"));
    std::fs::copy(fixture("a.crt"), &cert).unwrap();
    std::fs::copy(fixture("a.key"), &key).unwrap();
    let store = CertStore::load(&cert, &key).unwrap();
    let seen = Seen::default();
    let mut cfg = TcpConfig::new("127.0.0.1:0".parse().unwrap());
    cfg.transport = Transport::Dot;
    cfg.tls = Some(Arc::clone(&store));
    let server = TcpServer::bind(cfg, Arc::new(handler(Arc::clone(&seen)))).unwrap();

    let mut s = connect_tls(server.local_addr(), "kids-tablet.dns.test", b"dot", b"").await;
    assert_eq!(s.get_ref().1.alpn_protocol(), Some(&b"dot"[..]));
    let first_cert = s.get_ref().1.peer_certificates().unwrap()[0].clone();
    for id in [7, 8] {
        let r = dot_exchange(&mut s, id).await;
        assert_eq!(u16::from_be_bytes([r[0], r[1]]), id);
    }
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].1.as_deref(), Some("kids-tablet"));
        assert_eq!(seen[0].2, Transport::Dot);
    }

    // Renewal: new handshakes get the new certificate; no client ID for the bare name.
    std::fs::copy(fixture("b.crt"), &cert).unwrap();
    std::fs::copy(fixture("b.key"), &key).unwrap();
    assert!(store.reload_if_changed().unwrap());
    let mut s2 = connect_tls(server.local_addr(), "dns.test", b"dot", b"").await;
    assert_ne!(s2.get_ref().1.peer_certificates().unwrap()[0], first_cert);
    dot_exchange(&mut s2, 9).await;
    assert_eq!(seen.lock().unwrap()[2].1, None);
    server.shutdown().await;
}

#[tokio::test]
async fn dns_020_proxy_header_sets_the_client_address() {
    let seen = Seen::default();
    let mut cfg = TcpConfig::new("127.0.0.1:0".parse().unwrap());
    cfg.proxy_protocol = true;
    let server = TcpServer::bind(cfg, Arc::new(handler(Arc::clone(&seen)))).unwrap();
    let client: SocketAddr = "192.168.1.77:40000".parse().unwrap();

    let mut s = TcpStream::connect(server.local_addr()).await.unwrap();
    s.write_all(&telltale_net::proxy::encode(client, server.local_addr()))
        .await
        .unwrap();
    dot_exchange(&mut s, 1).await;
    assert_eq!(seen.lock().unwrap()[0].0, client);

    // Without the header the connection is closed and nothing is answered.
    let mut bare = TcpStream::connect(server.local_addr()).await.unwrap();
    let q = query(2);
    let mut f = (q.len() as u16).to_be_bytes().to_vec();
    f.extend_from_slice(&q);
    bare.write_all(&f).await.unwrap();
    let mut buf = [0u8; 1];
    let n = bare.read(&mut buf).await.unwrap_or(0);
    assert_eq!(n, 0);
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert_eq!(
        server
            .stats()
            .proxy_rejected
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    server.shutdown().await;
}

fn doh_server(proxy: bool) -> (DohServer, Seen) {
    let store = CertStore::load(fixture("a.crt"), fixture("a.key")).unwrap();
    let seen = Seen::default();
    let mut cfg = DohConfig::new("127.0.0.1:0".parse().unwrap(), store);
    cfg.proxy_protocol = proxy;
    let server = DohServer::bind(cfg, Arc::new(handler(Arc::clone(&seen)))).unwrap();
    (server, seen)
}

async fn h2(
    addr: SocketAddr,
    sni: &str,
    preamble: &[u8],
) -> hyper::client::conn::http2::SendRequest<Full<Bytes>> {
    let tls = connect_tls(addr, sni, b"h2", preamble).await;
    let (send, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    send
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

async fn send(
    c: &mut hyper::client::conn::http2::SendRequest<Full<Bytes>>,
    req: hyper::Request<Full<Bytes>>,
) -> (hyper::StatusCode, hyper::HeaderMap, Vec<u8>) {
    let r = c.send_request(req).await.unwrap();
    let (parts, body) = r.into_parts();
    let body = body.collect().await.unwrap().to_bytes().to_vec();
    (parts.status, parts.headers, body)
}

#[tokio::test]
async fn dns_003_doh_get_post_client_ids_and_errors() {
    let (server, seen) = doh_server(false);
    let addr = server.local_addr();
    let mut c = h2(addr, "phone.dns.test", b"").await;
    let url = |p: &str| format!("https://dns.test{p}");

    // GET ?dns= (base64url, no padding).
    let req = hyper::Request::get(url(&format!("/dns-query?dns={}", b64url(&query(0)))))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (st, h, body) = send(&mut c, req).await;
    assert_eq!(st, 200);
    assert_eq!(h["content-type"], "application/dns-message");
    assert_eq!(h["cache-control"], "max-age=300");
    assert_eq!(&body[body.len() - 4..], &[1, 2, 3, 4]);

    // POST, with a client ID in the path (wins over the SNI one).
    let req = hyper::Request::post(url("/dns-query/Kids-Laptop"))
        .header("content-type", "application/dns-message")
        .body(Full::new(Bytes::from(query(5))))
        .unwrap();
    let (st, _, body) = send(&mut c, req).await;
    assert_eq!(st, 200);
    assert_eq!(&body[..2], &[0, 5]);
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].1.as_deref(), Some("phone"), "from SNI");
        assert_eq!(seen[1].1.as_deref(), Some("kids-laptop"), "from the path");
        assert_eq!(seen[1].2, Transport::Doh);
    }

    // Errors: wrong path, bad client ID, wrong media type, bad method, bad base64, short message.
    for (req, want) in [
        (
            hyper::Request::get(url("/other"))
                .body(Full::default())
                .unwrap(),
            404,
        ),
        (
            hyper::Request::get(url("/dns-query/bad_id!"))
                .body(Full::default())
                .unwrap(),
            404,
        ),
        (
            hyper::Request::post(url("/dns-query"))
                .header("content-type", "text/plain")
                .body(Full::new(Bytes::from(query(1))))
                .unwrap(),
            415,
        ),
        (
            hyper::Request::put(url("/dns-query"))
                .body(Full::default())
                .unwrap(),
            405,
        ),
        (
            hyper::Request::get(url("/dns-query?dns=!!!"))
                .body(Full::default())
                .unwrap(),
            400,
        ),
        (
            hyper::Request::get(url("/dns-query?dns=AAAA"))
                .body(Full::default())
                .unwrap(),
            400,
        ),
    ] {
        assert_eq!(send(&mut c, req).await.0, want);
    }
    assert_eq!(
        seen.lock().unwrap().len(),
        2,
        "errors never reach the resolver"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn dns_003_doh_http1_and_proxy_protocol() {
    let (server, seen) = doh_server(true);
    let addr = server.local_addr();
    let client: SocketAddr = "[2001:db8::42]:5555".parse().unwrap();
    let preamble = telltale_net::proxy::encode(client, addr);

    // HTTP/1.1 (ALPN http/1.1) through a PROXY header.
    let tls = connect_tls(addr, "dns.test", b"http/1.1", &preamble).await;
    let (mut send1, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = hyper::Request::post("/dns-query")
        .header("host", "dns.test")
        .header("content-type", "application/dns-message")
        .body(Full::new(Bytes::from(query(3))))
        .unwrap();
    let r = send1.send_request(req).await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(seen.lock().unwrap()[0].0, client);
    server.shutdown().await;
}
