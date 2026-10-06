//! UPS-001 (DoT, DoH/h2), UPS-008 (pooling/pipelining), UPS-009 (bootstrap), loop tagging —
//! against local TLS servers with a throwaway self-signed certificate.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use telltale_proto::{NameBuf, ResponseBuilder, parse_query, rcode, rtype, summarize};
use telltale_upstream::{Bootstrap, Endpoint, Question, TlsOptions, Upstream, UpstreamOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

struct Cert {
    der: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn cert() -> Cert {
    let c =
        rcgen::generate_simple_self_signed(vec!["dns.test".into(), "127.0.0.1".into()]).unwrap();
    Cert {
        der: c.cert.der().clone(),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(c.signing_key.serialize_der())),
    }
}

/// Answers any query with A 192.0.2.7 (or 127.0.0.1 for `dns.test`).
fn answer(req: &[u8]) -> Option<Vec<u8>> {
    let q = parse_query(req).ok()?;
    let ip = if q.qname.display().to_string() == "dns.test" {
        Ipv4Addr::LOCALHOST
    } else {
        Ipv4Addr::new(192, 0, 2, 7)
    };
    let mut out = [0u8; 512];
    let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).ok()?;
    if q.qtype == rtype::A {
        b.answer_a(300, ip).ok()?;
    }
    let len = b.finish(None).ok()?;
    Some(out[..len].to_vec())
}

fn acceptor(c: &Cert, alpn: &[&[u8]]) -> tokio_rustls::TlsAcceptor {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![c.der.clone()], c.key.clone_key())
        .unwrap();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
}

/// DoT server: pipelined; answers each query after a small random-ish delay so responses can
/// come back out of order.
async fn dot_server(c: &Cert) -> SocketAddr {
    dot_server_with(acceptor(c, &[])).await
}

async fn dot_server_with(tls: tokio_rustls::TlsAcceptor) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = l.accept().await {
            let tls = tls.clone();
            tokio::spawn(async move {
                let Ok(s) = tls.accept(tcp).await else { return };
                let (mut rd, wr) = tokio::io::split(s);
                let wr = Arc::new(tokio::sync::Mutex::new(wr));
                loop {
                    let mut len = [0u8; 2];
                    if rd.read_exact(&mut len).await.is_err() {
                        break;
                    }
                    let mut req = vec![0; usize::from(u16::from_be_bytes(len))];
                    if rd.read_exact(&mut req).await.is_err() {
                        break;
                    }
                    let wr = Arc::clone(&wr);
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(u64::from(req[1] % 5))).await;
                        let resp = answer(&req).unwrap();
                        let mut f = (resp.len() as u16).to_be_bytes().to_vec();
                        f.extend(resp);
                        let _ = wr.lock().await.write_all(&f).await;
                    });
                }
            });
        }
    });
    addr
}

/// GET requests the DoH test server answered (T9.9).
static GETS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn b64url_decode(s: &str) -> Vec<u8> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        _ => 63,
    };
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes() {
        acc = (acc << 6) | u32::from(val(c));
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).unwrap());
        }
    }
    out
}

async fn doh_server(c: &Cert) -> SocketAddr {
    let tls = acceptor(c, &[b"h2"]);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = l.accept().await {
            let tls = tls.clone();
            tokio::spawn(async move {
                let Ok(s) = tls.accept(tcp).await else { return };
                let Ok(mut conn) = h2::server::handshake(s).await else {
                    return;
                };
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    tokio::spawn(async move {
                        // POST with the message as the body, or (T9.9) GET with `?dns=`.
                        let get = req.method() == http::Method::GET;
                        let ok = req.uri().path() == "/dns-query"
                            && (get
                                || (req.method() == http::Method::POST
                                    && req.headers()[http::header::CONTENT_TYPE]
                                        == "application/dns-message"));
                        let mut msg = Vec::new();
                        if get {
                            let query = req.uri().query().unwrap_or_default();
                            let v = query.strip_prefix("dns=").unwrap_or_default();
                            msg = b64url_decode(v);
                            GETS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        } else {
                            let mut body = req.into_body();
                            while let Some(Ok(chunk)) = body.data().await {
                                let _ = body.flow_control().release_capacity(chunk.len());
                                msg.extend_from_slice(&chunk);
                            }
                        }
                        let status = if ok { 200 } else { 400 };
                        let resp = http::Response::builder()
                            .status(status)
                            .header("content-type", "application/dns-message")
                            .body(())
                            .unwrap();
                        let mut send = respond.send_response(resp, false).unwrap();
                        let _ = send.send_data(Bytes::from(answer(&msg).unwrap_or_default()), true);
                    });
                }
            });
        }
    });
    addr
}

fn question(name: &str) -> Question {
    Question {
        name: NameBuf::from_presentation(name).unwrap(),
        qtype: rtype::A,
        qclass: 1,
        dnssec_ok: false,
        checking_disabled: false,
        client_subnet: 0,
    }
}

fn opts(server_name: &str) -> UpstreamOptions {
    UpstreamOptions {
        timeout: Duration::from_secs(2),
        pool_size: 1,
        tls_server_name: Some(server_name.into()),
        ..UpstreamOptions::default()
    }
}

#[tokio::test]
async fn ups_001_dot_verifies_certificates() {
    let c = cert();
    let addr = dot_server(&c).await;
    let ep = Endpoint::parse(&format!("tls://{addr}")).unwrap();
    let trusted = TlsOptions {
        extra_roots: vec![c.der.clone()],
    };

    let up = Upstream::build(1, "dot", ep.clone(), &opts("dns.test"), &trusted).unwrap();
    let resp = up
        .exchange(&question("example.com"), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(summarize(&resp).unwrap().answers, 1);

    // Unknown issuer: rejected.
    let untrusted = Upstream::build(
        2,
        "dot",
        ep.clone(),
        &opts("dns.test"),
        &TlsOptions::default(),
    )
    .unwrap();
    assert!(
        untrusted
            .exchange(&question("example.com"), Duration::from_secs(2))
            .await
            .is_err()
    );

    // Wrong name: rejected even with the right root.
    let wrong = Upstream::build(3, "dot", ep.clone(), &opts("other.test"), &trusted).unwrap();
    assert!(
        wrong
            .exchange(&question("example.com"), Duration::from_secs(2))
            .await
            .is_err()
    );

    // tls_insecure_skip_verify accepts anything.
    let mut o = opts("anything");
    o.tls_insecure_skip_verify = true;
    let insecure = Upstream::build(4, "dot", ep, &o, &TlsOptions::default()).unwrap();
    assert!(
        insecure
            .exchange(&question("example.com"), Duration::from_secs(2))
            .await
            .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ups_008_dot_pipelines_many_queries_on_one_connection() {
    let c = cert();
    let addr = dot_server(&c).await;
    let ep = Endpoint::parse(&format!("tls://{addr}")).unwrap();
    let up = Arc::new(
        Upstream::build(
            1,
            "dot",
            ep,
            &opts("dns.test"),
            &TlsOptions {
                extra_roots: vec![c.der.clone()],
            },
        )
        .unwrap(),
    );
    let mut tasks = Vec::new();
    for i in 0..50 {
        let up = Arc::clone(&up);
        tasks.push(tokio::spawn(async move {
            up.exchange(&question(&format!("q{i}.example")), Duration::from_secs(5))
                .await
        }));
    }
    for t in tasks {
        let resp = t.await.unwrap().unwrap();
        assert_eq!(summarize(&resp).unwrap().rcode, rcode::NOERROR);
    }
    assert_eq!(
        up.pooled_connections(),
        1,
        "pool_size = 1: everything pipelined on one connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ups_001_doh_h2_round_trip_and_multiplexing() {
    let c = cert();
    let addr = doh_server(&c).await;
    let ep = Endpoint::parse(&format!("https://{addr}/dns-query")).unwrap();
    let up = Arc::new(
        Upstream::build(
            1,
            "doh",
            ep,
            &opts("dns.test"),
            &TlsOptions {
                extra_roots: vec![c.der.clone()],
            },
        )
        .unwrap(),
    );
    let mut tasks = Vec::new();
    for i in 0..20 {
        let up = Arc::clone(&up);
        tasks.push(tokio::spawn(async move {
            up.exchange(&question(&format!("h{i}.example")), Duration::from_secs(5))
                .await
        }));
    }
    for t in tasks {
        let resp = t.await.unwrap().unwrap();
        assert_eq!(summarize(&resp).unwrap().answers, 1);
    }
}

/// Plain-DNS bootstrap server answering `dns.test` → 127.0.0.1.
async fn bootstrap_server() -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            if let Some(r) = answer(&buf[..n]) {
                let _ = sock.send_to(&r, peer).await;
            }
        }
    });
    addr
}

#[tokio::test]
async fn ups_009_hostname_upstream_resolves_through_bootstrap() {
    let c = cert();
    let dot = dot_server(&c).await;
    let bs = Arc::new(Bootstrap::new(vec![bootstrap_server().await]));
    let ep = Endpoint::parse(&format!("tls://dns.test:{}", dot.port())).unwrap();
    let o = UpstreamOptions {
        timeout: Duration::from_secs(2),
        bootstrap: Some(Arc::clone(&bs)),
        ..UpstreamOptions::default()
    };
    let up = Upstream::build(
        1,
        "dot-by-name",
        ep.clone(),
        &o,
        &TlsOptions {
            extra_roots: vec![c.der.clone()],
        },
    )
    .unwrap();
    let resp = up
        .exchange(&question("example.com"), Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(summarize(&resp).unwrap().answers, 1);
    assert_eq!(
        bs.resolve("dns.test").await.unwrap(),
        vec![std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)]
    );

    // Hostname without bootstrap is a build error, not a silent failure.
    assert!(
        Upstream::build(
            2,
            "x",
            ep,
            &UpstreamOptions::default(),
            &TlsOptions::default()
        )
        .is_err()
    );
}

#[test]
fn loop_detection_tag_round_trips() {
    telltale_upstream::set_node_tag(0x1234_5678_9abc_def0);
    let mut buf = [0u8; 512];
    let len = telltale_upstream::encode_query(&question("example.com"), 7, &mut buf).unwrap();
    let q = parse_query(&buf[..len]).unwrap();
    assert!(
        telltale_upstream::is_own_loop_tag(&q),
        "our own tag must be recognized"
    );
    assert_eq!(
        q.edns.unwrap().loop_tag(),
        Some(&0x1234_5678_9abc_def0u64.to_be_bytes()[..])
    );
}

/// REQ: UPS-011 (T7.16) — SPKI pins: the right key passes (also with verification off, for a
/// self-signed server), any other key fails; the pin is SHA-256 of the key's SPKI.
#[tokio::test]
async fn ups_011_spki_pins() {
    let made = rcgen::generate_simple_self_signed(vec!["dns.test".into()]).unwrap();
    let c = Cert {
        der: made.cert.der().clone(),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(made.signing_key.serialize_der())),
    };
    let pin = telltale_upstream::spki_pin(c.der.as_ref()).unwrap();
    assert_eq!(pin.len(), 44);
    let addr = dot_server(&c).await;
    let ep = Endpoint::parse(&format!("tls://{addr}")).unwrap();
    let trusted = TlsOptions {
        extra_roots: vec![c.der.clone()],
    };
    let with_pin = |pins: Vec<String>, insecure: bool| {
        let mut o = opts("dns.test");
        o.tls_insecure_skip_verify = insecure;
        o.tls.pins = pins;
        o
    };
    let other = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned();
    for (pins, insecure, roots, ok) in [
        (vec![pin.clone()], false, &trusted, true),
        (vec![other.clone(), pin.clone()], false, &trusted, true),
        (vec![other.clone()], false, &trusted, false),
        (vec![pin.clone()], true, &TlsOptions::default(), true),
        (vec![other.clone()], true, &TlsOptions::default(), false),
    ] {
        let up = Upstream::build(
            1,
            "dot",
            ep.clone(),
            &with_pin(pins.clone(), insecure),
            roots,
        )
        .unwrap();
        let r = up
            .exchange(&question("example.com"), Duration::from_secs(2))
            .await;
        assert_eq!(r.is_ok(), ok, "pins {pins:?}, insecure {insecure}");
    }
}

/// REQ: UPS-011 (T7.16) — mTLS: a server that requires a client certificate answers only
/// when the upstream presents one it trusts.
#[tokio::test]
async fn ups_011_client_certificates() {
    let server = cert();
    let client = rcgen::generate_simple_self_signed(vec!["client.test".into()]).unwrap();
    let client_der = client.cert.der().clone();
    let client_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client.signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(client_der.clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::clone(&provider),
    )
    .build()
    .unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server.der.clone()], server.key.clone_key())
        .unwrap();
    let addr = dot_server_with(tokio_rustls::TlsAcceptor::from(Arc::new(cfg))).await;
    let ep = Endpoint::parse(&format!("tls://{addr}")).unwrap();
    let trusted = TlsOptions {
        extra_roots: vec![server.der.clone()],
    };
    let without = Upstream::build(1, "dot", ep.clone(), &opts("dns.test"), &trusted).unwrap();
    assert!(
        without
            .exchange(&question("example.com"), Duration::from_secs(2))
            .await
            .is_err()
    );
    let mut o = opts("dns.test");
    o.tls.client = Some(Arc::new((vec![client_der], client_key)));
    let with = Upstream::build(2, "dot", ep, &o, &trusted).unwrap();
    let resp = with
        .exchange(&question("example.com"), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(summarize(&resp).unwrap().answers, 1);
}

/// REQ: UPS-011 (T9.9) — `doh_method = "get"`: the query travels in `?dns=` and the answer
/// comes back the same.
#[tokio::test]
async fn ups_011_doh_get() {
    let c = cert();
    let addr = doh_server(&c).await;
    let ep = Endpoint::parse(&format!("https://{addr}/dns-query")).unwrap();
    let mut o = opts("dns.test");
    o.doh_get = true;
    let up = Upstream::build(
        1,
        "doh-get",
        ep,
        &o,
        &TlsOptions {
            extra_roots: vec![c.der.clone()],
        },
    )
    .unwrap();
    let before = GETS.load(std::sync::atomic::Ordering::Relaxed);
    let resp = up
        .exchange(&question("get.example"), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(summarize(&resp).unwrap().answers, 1);
    assert!(
        GETS.load(std::sync::atomic::Ordering::Relaxed) > before,
        "sent as GET"
    );
}
