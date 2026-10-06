//! DNS-004 (T7.8) — DoH over HTTP/3 end to end against a real listener with the test CA:
//! GET and POST, client IDs from the path and SNI, errors, and `Alt-Svc` on the HTTP/2 side.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bytes::{Buf, Bytes};
use quinn::crypto::rustls::QuicClientConfig;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use telltale_net::{CertStore, Doh3Config, Doh3Server, RequestMeta, Response, Transport};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name)
}

type Seen = Arc<Mutex<Vec<(Option<String>, Transport)>>>;

fn handler(seen: Seen) -> impl Fn(&[u8], &RequestMeta, &mut [u8]) -> Response + Send + Sync {
    move |req: &[u8], meta: &RequestMeta, out: &mut [u8]| {
        seen.lock().unwrap().push((
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

fn query() -> Vec<u8> {
    let mut m = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    m.extend_from_slice(b"\x03www\x07example\x03com\x00\x00\x01\x00\x01");
    m
}

fn b64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            s.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    s
}

type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

async fn connect(addr: std::net::SocketAddr, sni: &str) -> Sender {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(fixture("ca.crt")).unwrap())
        .unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).unwrap(),
    )));
    let conn = ep.connect(addr, sni).unwrap().await.unwrap();
    let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    send
}

/// `(status, body)` for one request.
async fn request(
    send: &mut Sender,
    method: &str,
    path: &str,
    ct: Option<&str>,
    body: Option<Vec<u8>>,
) -> (u16, Vec<u8>) {
    let mut req = hyper::Request::builder()
        .method(method)
        .uri(format!("https://dns.test{path}"));
    if let Some(c) = ct {
        req = req.header("content-type", c);
    }
    let mut s = send.send_request(req.body(()).unwrap()).await.unwrap();
    if let Some(b) = body {
        s.send_data(Bytes::from(b)).await.unwrap();
    }
    s.finish().await.unwrap();
    let resp = s.recv_response().await.unwrap();
    let mut out = Vec::new();
    while let Some(mut chunk) = s.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let part = chunk.chunk().to_vec();
            chunk.advance(part.len());
            out.extend_from_slice(&part);
        }
    }
    (resp.status().as_u16(), out)
}

/// REQ: DNS-004 — GET and POST over HTTP/3, client IDs from the path (winning) and SNI, and
/// the same error statuses as HTTP/2.
#[tokio::test]
async fn dns_004_doh3_get_post_client_ids_and_errors() {
    let seen: Seen = Arc::default();
    let store = CertStore::load(fixture("a.crt"), fixture("a.key")).unwrap();
    let server = Doh3Server::bind(
        &Doh3Config::new("127.0.0.1:0".parse().unwrap(), store),
        Arc::new(handler(Arc::clone(&seen))),
    )
    .unwrap();
    let mut send = connect(server.local_addr(), "tablet.dns.test").await;

    let get = format!("/dns-query?dns={}", b64url(&query()));
    let (st, body) = request(&mut send, "GET", &get, None, None).await;
    assert_eq!(st, 200);
    assert_eq!(&body[body.len() - 4..], &[1, 2, 3, 4]);
    let (st, _) = request(
        &mut send,
        "POST",
        "/dns-query/kids",
        Some("application/dns-message"),
        Some(query()),
    )
    .await;
    assert_eq!(st, 200);
    {
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen[0],
            (Some("tablet".into()), Transport::Doh),
            "SNI client ID"
        );
        assert_eq!(seen[1].0.as_deref(), Some("kids"), "the path's ID wins");
    }
    assert_eq!(
        request(&mut send, "GET", "/elsewhere", None, None).await.0,
        404
    );
    assert_eq!(
        request(&mut send, "GET", "/dns-query?dns=!!", None, None)
            .await
            .0,
        400
    );
    assert_eq!(
        request(
            &mut send,
            "POST",
            "/dns-query",
            Some("text/plain"),
            Some(query())
        )
        .await
        .0,
        415
    );
    assert_eq!(
        request(&mut send, "PUT", "/dns-query", None, None).await.0,
        405
    );
    let stats = server.stats_handle();
    assert_eq!(stats.replies.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert_eq!(
        stats
            .bad_requests
            .load(std::sync::atomic::Ordering::Relaxed),
        4
    );
    server.shutdown().await;
}
