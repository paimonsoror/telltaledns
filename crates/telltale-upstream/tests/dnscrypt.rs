//! REQ: UPS-003 (T7.24) — the DNSCrypt upstream against a test resolver on loopback: the
//! certificate fetched and checked, queries boxed both ways, with `XChaCha20` and `XSalsa20`.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use telltale_proto::{NameBuf, ResponseBuilder, parse_query, rcode, rtype, summarize};
use telltale_upstream::dnscrypt::server::TestResolver;
use telltale_upstream::{
    Endpoint, Host, Protocol, Question, TlsOptions, Upstream, UpstreamOptions,
};
use tokio::net::UdpSocket;

const PROVIDER: &str = "2.dnscrypt-cert.test";

/// The TXT answer carrying `cert` (one character-string per 255 bytes).
fn cert_answer(req: &[u8], cert: &[u8]) -> Vec<u8> {
    let q = parse_query(req).unwrap();
    let mut rdata = Vec::new();
    for chunk in cert.chunks(255) {
        rdata.push(u8::try_from(chunk.len()).unwrap());
        rdata.extend_from_slice(chunk);
    }
    let mut out = vec![0u8; 1024];
    let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
    b.answer_rdata(None, rtype::TXT, 3600, &rdata).unwrap();
    let len = b.finish(None).unwrap();
    out.truncate(len);
    out
}

/// A plain answer: A 10.9.9.9.
fn answer(req: &[u8]) -> Vec<u8> {
    let q = parse_query(req).unwrap();
    let mut out = vec![0u8; 512];
    let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
    b.answer_a(60, std::net::Ipv4Addr::new(10, 9, 9, 9))
        .unwrap();
    let len = b.finish(None).unwrap();
    out.truncate(len);
    out
}

/// Serves `served` (the certificate) and answers with `r`'s keys.
async fn serve(r: Arc<TestResolver>, served: Vec<u8>) -> std::net::SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, from)) = s.recv_from(&mut buf).await else {
                return;
            };
            let pkt = &buf[..n];
            let reply = if let Some((q, pk, half)) = r.open(pkt) {
                r.seal(&answer(&q), &pk, &half)
            } else if parse_query(pkt).is_ok() {
                Some(cert_answer(pkt, &served))
            } else {
                None
            };
            if let Some(reply) = reply {
                let _ = s.send_to(&reply, from).await;
            }
        }
    });
    addr
}

fn upstream(addr: std::net::SocketAddr, provider: [u8; 32]) -> Upstream {
    upstream_via(addr, provider, None)
}

fn upstream_via(
    addr: std::net::SocketAddr,
    provider: [u8; 32],
    relay: Option<std::net::SocketAddr>,
) -> Upstream {
    let ep = Endpoint {
        protocol: Protocol::DnsCrypt,
        host: Host::Ip(addr.ip()),
        port: addr.port(),
        path: String::new(),
    };
    let opts = UpstreamOptions {
        timeout: Duration::from_secs(2),
        dnscrypt: Some((provider, PROVIDER.to_owned())),
        dnscrypt_relay: relay,
        ..UpstreamOptions::default()
    };
    Upstream::build(1, "dnscrypt", ep, &opts, &TlsOptions::default()).unwrap()
}

fn question() -> Question {
    Question {
        name: NameBuf::from_presentation("example.com").unwrap(),
        qtype: rtype::A,
        qclass: 1,
        dnssec_ok: false,
        checking_disabled: false,
        client_subnet: 0,
    }
}

/// REQ: UPS-003 — both constructions answer through the box.
#[tokio::test]
async fn ups_003_dnscrypt_round_trip() {
    for xchacha in [true, false] {
        let r = Arc::new(TestResolver::new(xchacha));
        let pk = r.provider.verifying_key().to_bytes();
        let addr = serve(Arc::clone(&r), r.cert.clone()).await;
        let up = upstream(addr, pk);
        for _ in 0..3 {
            let resp = up
                .exchange(&question(), Duration::from_secs(2))
                .await
                .unwrap();
            let s = summarize(&resp).unwrap();
            assert_eq!(
                (s.rcode, s.answers),
                (rcode::NOERROR, 1),
                "xchacha {xchacha}"
            );
            assert!(resp.ends_with(&[10, 9, 9, 9]));
        }
    }
}

/// REQ: UPS-003 — a certificate not signed by the stamp's provider key is refused.
#[tokio::test]
async fn ups_003_dnscrypt_rejects_a_foreign_certificate() {
    let r = Arc::new(TestResolver::new(true));
    let other = TestResolver::new(true);
    let addr = serve(Arc::clone(&r), r.cert.clone()).await;
    // The stamp names another provider's key.
    let up = upstream(addr, other.provider.verifying_key().to_bytes());
    assert!(
        up.exchange(&question(), Duration::from_secs(2))
            .await
            .is_err()
    );
}

/// A fake anonymized relay: checks the header, forwards the rest to the address it names,
/// and passes the reply back. Counts what it relayed.
async fn relay(count: Arc<std::sync::atomic::AtomicUsize>) -> std::net::SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, from)) = s.recv_from(&mut buf).await else {
                return;
            };
            let pkt = &buf[..n];
            assert_eq!(
                &pkt[..10],
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0]
            );
            let ip: [u8; 16] = pkt[10..26].try_into().unwrap();
            let ip = std::net::Ipv6Addr::from(ip).to_ipv4_mapped().unwrap();
            let port = u16::from_be_bytes([pkt[26], pkt[27]]);
            up.send_to(&pkt[28..], (ip, port)).await.unwrap();
            let mut rb = vec![0u8; 4096];
            let (m, _) = up.recv_from(&mut rb).await.unwrap();
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _ = s.send_to(&rb[..m], from).await;
        }
    });
    addr
}

/// REQ: UPS-003 (T9.9) — anonymized DNSCrypt: the certificate fetch and the encrypted
/// queries all go through the relay, which forwards to the resolver its header names.
#[tokio::test]
async fn ups_003_dnscrypt_through_a_relay() {
    let r = Arc::new(TestResolver::new(true));
    let pk = r.provider.verifying_key().to_bytes();
    let server = serve(Arc::clone(&r), r.cert.clone()).await;
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let via = relay(Arc::clone(&count)).await;
    let up = upstream_via(server, pk, Some(via));
    for _ in 0..2 {
        let resp = up
            .exchange(&question(), Duration::from_secs(2))
            .await
            .unwrap();
        assert!(resp.ends_with(&[10, 9, 9, 9]));
    }
    // One certificate fetch and two queries.
    assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 3);
    assert_eq!(
        telltale_upstream::dnscrypt::parse_relay("sdns://gQ0xMjcuMC4wLjE6NDQz").unwrap(),
        "127.0.0.1:443".parse().unwrap()
    );
    assert_eq!(
        telltale_upstream::dnscrypt::parse_relay("203.0.113.7:8443").unwrap(),
        "203.0.113.7:8443".parse().unwrap()
    );
    assert!(telltale_upstream::dnscrypt::parse_relay(&format!("sdns://{}", "AQ")).is_err());
}
