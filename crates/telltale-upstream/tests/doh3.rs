//! UPS-002 (T7.8) — DoH over HTTP/3 upstreams (`h3://`) against TelltaleDNS's own HTTP/3
//! listener with the test CA: answers, ID 0, custom paths, certificate checks.

#![allow(clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use telltale_net::{CertStore, Doh3Config, Doh3Server, RequestMeta, Response};
use telltale_proto::{NameBuf, ResponseBuilder, parse_query, rcode, rtype, summarize};
use telltale_upstream::{Endpoint, Protocol, Question, TlsOptions, Upstream, UpstreamOptions};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../telltale-net/testdata")
        .join(name)
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

/// REQ: UPS-002 — `h3://` upstreams answer (ID 0), on the URL's path, and verify the
/// certificate.
#[tokio::test]
async fn ups_002_doh3_upstream() {
    let nonzero = Arc::new(AtomicU32::new(0));
    let seen = Arc::clone(&nonzero);
    let handler = move |req: &[u8], _: &RequestMeta, out: &mut [u8]| {
        if req[..2] != [0, 0] {
            seen.fetch_add(1, Ordering::Relaxed);
        }
        let q = parse_query(req).unwrap();
        let mut b = ResponseBuilder::new(&q, out, rcode::NOERROR).unwrap();
        b.answer_a(60, Ipv4Addr::new(192, 0, 2, 33)).unwrap();
        Response::Ready(b.finish(None).unwrap())
    };
    let store = CertStore::load(fixture("a.crt"), fixture("a.key")).unwrap();
    let mut cfg = Doh3Config::new("127.0.0.1:0".parse().unwrap(), store);
    cfg.path = "/custom".into();
    let server = Doh3Server::bind(&cfg, Arc::new(handler)).unwrap();
    let addr = server.local_addr();

    let trusted = TlsOptions {
        extra_roots: vec![CertificateDer::from_pem_file(fixture("ca.crt")).unwrap()],
    };
    let ep = Endpoint::parse(&format!("h3://{addr}/custom")).unwrap();
    assert_eq!(ep.protocol, Protocol::H3);
    let up = Upstream::build(1, "h3", ep.clone(), &opts("dns.test"), &trusted).unwrap();
    for _ in 0..3 {
        let resp = up
            .exchange(&question(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(summarize(&resp).unwrap().answers, 1);
    }
    assert_eq!(nonzero.load(Ordering::Relaxed), 0, "DoH queries carry ID 0");

    // The wrong path is a 404: an error, not an answer.
    let wrong_path = Endpoint::parse(&format!("h3://{addr}/dns-query")).unwrap();
    let up = Upstream::build(2, "h3", wrong_path, &opts("dns.test"), &trusted).unwrap();
    assert!(
        up.exchange(&question(), Duration::from_secs(2))
            .await
            .is_err()
    );
    // An unknown issuer or the wrong name: refused.
    let untrusted = Upstream::build(
        3,
        "h3",
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
    let wrong = Upstream::build(4, "h3", ep, &opts("other.test"), &trusted).unwrap();
    assert!(
        wrong
            .exchange(&question(), Duration::from_secs(2))
            .await
            .is_err()
    );
    server.shutdown().await;
}
