//! DNS-004 (T7.7) — DNS over QUIC (RFC 9250) end to end against a real listener with the test
//! CA: answers, concurrent streams, client IDs from SNI, and protocol errors.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use quinn::crypto::rustls::QuicClientConfig;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use telltale_net::{CertStore, DoqConfig, DoqServer, RequestMeta, Response, Transport};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name)
}

type Seen = Arc<Mutex<Vec<(Option<String>, Transport)>>>;

/// Answers `www.example.com A` with 1.2.3.4, recording the client ID and transport.
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

fn framed_query(id: u16) -> Vec<u8> {
    let mut m = vec![(id >> 8) as u8, id as u8, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    m.extend_from_slice(b"\x03www\x07example\x03com\x00\x00\x01\x00\x01");
    let mut f = (m.len() as u16).to_be_bytes().to_vec();
    f.extend_from_slice(&m);
    f
}

fn client() -> quinn::Endpoint {
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
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).unwrap(),
    )));
    ep
}

async fn ask(conn: &quinn::Connection, id: u16) -> Result<Vec<u8>, String> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    send.write_all(&framed_query(id))
        .await
        .map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    let data = recv.read_to_end(70_000).await.map_err(|e| e.to_string())?;
    let n = usize::from(u16::from_be_bytes([data[0], data[1]]));
    assert_eq!(n, data.len() - 2, "length prefix");
    Ok(data[2..].to_vec())
}

fn server() -> (DoqServer, Seen, SocketAddr) {
    let seen: Seen = Arc::default();
    let store = CertStore::load(fixture("a.crt"), fixture("a.key")).unwrap();
    let s = DoqServer::bind(
        &DoqConfig::new("127.0.0.1:0".parse().unwrap(), store),
        Arc::new(handler(Arc::clone(&seen))),
    )
    .unwrap();
    let addr = s.local_addr();
    (s, seen, addr)
}

/// REQ: DNS-004 — answers on their own streams, concurrently, with the SNI client ID.
#[tokio::test]
async fn dns_004_doq_answers_streams_and_client_ids() {
    let (s, seen, addr) = server();
    let ep = client();
    let conn = ep.connect(addr, "kids.dns.test").unwrap().await.unwrap();
    let answers = futures_join(&conn).await;
    for a in &answers {
        assert_eq!(&a[..2], &[0, 0], "the answer keeps ID 0");
        assert_eq!(&a[a.len() - 4..], &[1, 2, 3, 4]);
    }
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 8);
    assert!(
        seen.iter()
            .all(|(id, t)| id.as_deref() == Some("kids") && *t == Transport::Doq)
    );
    assert_eq!(
        s.stats_handle()
            .queries
            .load(std::sync::atomic::Ordering::Relaxed),
        8
    );
    s.shutdown().await;
}

/// Eight queries at once on one connection.
async fn futures_join(conn: &quinn::Connection) -> Vec<Vec<u8>> {
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let c = conn.clone();
            tokio::spawn(async move { ask(&c, 0).await.unwrap() })
        })
        .collect();
    let mut out = Vec::new();
    for t in tasks {
        out.push(t.await.unwrap());
    }
    out
}

/// REQ: DNS-004 — RFC 9250 §4.2.1: a message ID other than 0 is a protocol error that closes
/// the connection (`DOQ_PROTOCOL_ERROR`).
#[tokio::test]
async fn dns_004_doq_nonzero_id_closes_the_connection() {
    let (s, _seen, addr) = server();
    let ep = client();
    let conn = ep.connect(addr, "dns.test").unwrap().await.unwrap();
    assert!(ask(&conn, 7).await.is_err());
    let reason = conn.closed().await;
    assert!(
        matches!(&reason, quinn::ConnectionError::ApplicationClosed(c) if c.error_code == quinn::VarInt::from_u32(2)),
        "{reason:?}"
    );
    assert_eq!(
        s.stats_handle()
            .protocol_errors
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    s.shutdown().await;
}
