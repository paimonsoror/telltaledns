//! UPS-002 (T7.7) — DoQ upstreams (RFC 9250) against a local QUIC server with a throwaway
//! certificate: answers, verification, reconnecting after the server goes away.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use telltale_proto::{NameBuf, ResponseBuilder, parse_query, rcode, rtype, summarize};
use telltale_upstream::{Endpoint, Question, TlsOptions, Upstream, UpstreamOptions};

struct Cert {
    der: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn cert() -> Cert {
    let c = rcgen::generate_simple_self_signed(vec!["dns.test".into()]).unwrap();
    Cert {
        der: c.cert.der().clone(),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(c.signing_key.serialize_der())),
    }
}

fn answer(req: &[u8]) -> Option<Vec<u8>> {
    let q = parse_query(req).ok()?;
    let mut out = [0u8; 512];
    let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).ok()?;
    b.answer_a(300, Ipv4Addr::new(192, 0, 2, 9)).ok()?;
    let len = b.finish(None).ok()?;
    Some(out[..len].to_vec())
}

type Conns = Arc<std::sync::Mutex<Vec<quinn::Connection>>>;

/// A DoQ server that answers every query; counts the IDs it saw that weren't 0, and keeps its
/// connections (so a test can close them).
fn doq_server(c: &Cert, bad_ids: Arc<AtomicU32>) -> (Conns, SocketAddr) {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![c.der.clone()], c.key.clone_key())
    .unwrap();
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let cfg = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
    let ep = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = ep.local_addr().unwrap();
    let conns: Conns = Arc::default();
    let kept = Arc::clone(&conns);
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let bad_ids = Arc::clone(&bad_ids);
            let kept = Arc::clone(&kept);
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                kept.lock().unwrap().push(conn.clone());
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let bad_ids = Arc::clone(&bad_ids);
                    tokio::spawn(async move {
                        let data = recv.read_to_end(70_000).await.unwrap();
                        let msg = &data[2..];
                        if msg[..2] != [0, 0] {
                            bad_ids.fetch_add(1, Ordering::Relaxed);
                        }
                        let a = answer(msg).unwrap();
                        let mut f = (a.len() as u16).to_be_bytes().to_vec();
                        f.extend_from_slice(&a);
                        send.write_all(&f).await.unwrap();
                        send.finish().unwrap();
                    });
                }
            });
        }
    });
    (conns, addr)
}

fn question() -> Question {
    Question {
        name: NameBuf::from_presentation("example.com").unwrap(),
        qtype: rtype::A,
        qclass: 1,
        dnssec_ok: false,
        checking_disabled: false,
    }
}

fn opts(name: &str) -> UpstreamOptions {
    UpstreamOptions {
        timeout: Duration::from_secs(2),
        tls_server_name: Some(name.into()),
        ..UpstreamOptions::default()
    }
}

/// REQ: UPS-002 — `quic://` upstreams answer over one connection (ID 0 on every query),
/// verify the certificate, and reconnect when the server goes away.
#[tokio::test]
async fn ups_002_doq_upstream() {
    let c = cert();
    let bad_ids = Arc::new(AtomicU32::new(0));
    let (conns, addr) = doq_server(&c, Arc::clone(&bad_ids));
    let ep = Endpoint::parse(&format!("quic://{addr}")).unwrap();
    assert_eq!(ep.protocol, telltale_upstream::Protocol::Quic);
    assert_eq!(Endpoint::parse("quic://9.9.9.9").unwrap().port, 853);
    let trusted = TlsOptions {
        extra_roots: vec![c.der.clone()],
    };
    let up = Upstream::build(1, "doq", ep.clone(), &opts("dns.test"), &trusted).unwrap();
    for _ in 0..5 {
        let resp = up
            .exchange(&question(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(summarize(&resp).unwrap().answers, 1);
    }
    assert_eq!(bad_ids.load(Ordering::Relaxed), 0, "DoQ queries carry ID 0");

    // The wrong name, or an unknown issuer: refused.
    let wrong = Upstream::build(2, "doq", ep.clone(), &opts("other.test"), &trusted).unwrap();
    assert!(
        wrong
            .exchange(&question(), Duration::from_secs(2))
            .await
            .is_err()
    );
    let untrusted = Upstream::build(
        3,
        "doq",
        ep.clone(),
        &opts("dns.test"),
        &TlsOptions::default(),
    )
    .unwrap();
    assert!(
        untrusted
            .exchange(&question(), Duration::from_secs(2))
            .await
            .is_err()
    );

    // The server closes the connection (say, a restart): the next queries reconnect.
    let before = conns.lock().unwrap().len();
    for conn in conns.lock().unwrap().iter() {
        conn.close(quinn::VarInt::from_u32(0), b"restart");
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut ok = 0;
    for _ in 0..3 {
        ok += usize::from(
            up.exchange(&question(), Duration::from_secs(2))
                .await
                .is_ok(),
        );
    }
    assert!(
        ok >= 2,
        "reconnected after the server closed the connection ({ok}/3)"
    );
    assert!(
        conns.lock().unwrap().len() > before,
        "a new connection was made"
    );
}
