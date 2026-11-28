//! REQ: UPS-009 (ADR-192) — the loop-detection EDNS option (code 65429, `spec/04` §7) per
//! upstream: sent by default, with the same bytes as before the switch existed, and left out of
//! every query to an upstream with `loop_tag = false`. Each upstream here is a UDP mock on
//! 127.0.0.1 that records the queries it is sent.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use telltale_proto::{NameBuf, ResponseBuilder, parse_query, rcode, rtype};
use telltale_upstream::{Endpoint, Question, Router, Upstream};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

/// This test binary's node tag. A process sets it once (the first call wins), so every test here
/// sets this one.
const TAG: u64 = 0x0123_4567_89ab_cdef;
/// The loop-detection option's code.
const LOOP: u16 = 65429;
/// The ECS option's code (RFC 7871).
const ECS: u16 = 8;
const WAIT: Duration = Duration::from_secs(2);

fn node_tag() {
    telltale_upstream::set_node_tag(TAG);
}

/// The option this node's queries carry at the default: the code and the tag.
fn our_tag() -> (u16, Vec<u8>) {
    (LOOP, TAG.to_be_bytes().to_vec())
}

/// A UDP upstream that answers every query (an A record for an A question, no record for any
/// other) and hands over each query exactly as it arrived.
async fn mock() -> (SocketAddr, UnboundedReceiver<Vec<u8>>) {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    let (tx, rx) = unbounded_channel();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = s.recv_from(&mut buf).await {
            let req = buf[..n].to_vec();
            let mut out = [0u8; 512];
            let len = {
                let q = parse_query(&req).unwrap();
                let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
                if q.qtype == rtype::A {
                    b.answer_a(300, Ipv4Addr::new(192, 0, 2, 1)).unwrap();
                }
                b.finish(None).unwrap()
            };
            let _ = tx.send(req);
            let _ = s.send_to(&out[..len], from).await;
        }
    });
    (addr, rx)
}

/// The next query a mock received, within a bounded wait: a test whose query never leaves fails
/// instead of hanging.
async fn next(rx: &mut UnboundedReceiver<Vec<u8>>) -> Vec<u8> {
    tokio::time::timeout(WAIT, rx.recv())
        .await
        .expect("the mock received a query in time")
        .unwrap()
}

fn load(toml: &str) -> telltale_config::Config {
    telltale_config::Loader::new()
        .toml_str("t.toml", toml)
        .env(Vec::<(String, String)>::new())
        .load()
        .map_err(|e| format!("{e:?}"))
        .unwrap()
        .config
}

fn router(toml: &str) -> Router {
    Router::from_config(&load(toml)).unwrap()
}

/// A router from `toml` with the named upstreams sent to `at` (a mock) once the configuration
/// is loaded and checked: validation refuses `loop_tag = false` toward a loopback address
/// (`ups_009_loop_tag_off_is_refused_toward_this_node`), and the mocks listen on loopback.
fn router_at(toml: &str, at: &[(&str, SocketAddr)]) -> Router {
    let mut cfg = load(toml);
    for (name, addr) in at {
        let u = cfg
            .upstream
            .iter_mut()
            .find(|u| u.name.as_str() == *name)
            .unwrap();
        u.url = telltale_config::SafeString::new(format!("udp://{addr}")).unwrap();
    }
    Router::from_config(&cfg).unwrap()
}

fn upstream<'r>(r: &'r Router, name: &str) -> &'r Upstream {
    r.upstreams().iter().find(|u| u.name == name).unwrap()
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

/// The EDNS options of a query as it was sent, in order. Every query to an upstream carries
/// this node's own OPT record.
fn options(query: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let q = parse_query(query).unwrap();
    q.edns
        .unwrap()
        .iter()
        .map(|(code, value)| (code, value.to_vec()))
        .collect()
}

/// REQ: UPS-009 (ADR-192) — with `loop_tag = false`, an upstream's queries, its health checks
/// included, carry no loop-detection option; an ECS subnet it is set to send still goes, alone.
/// An upstream beside it at the default still sends this node's tag.
#[tokio::test]
async fn ups_009_loop_tag_false_leaves_the_option_out() {
    node_tag();
    let (plain_at, mut plain) = mock().await;
    let (ecs_at, mut ecs) = mock().await;
    let (tagged_at, mut tagged) = mock().await;
    // Loaded with documentation addresses (TEST-NET-2), then sent to the mocks.
    let r = router_at(
        r#"[[upstream]]
name = "plain"
url = "udp://198.51.100.1"
loop_tag = false

[[upstream]]
name = "plain-ecs"
url = "udp://198.51.100.2"
loop_tag = false
ecs = "203.0.113.0/24"

[[upstream]]
name = "tagged"
url = "udp://198.51.100.3"

[[upstream_group]]
name = "default"
members = ["plain", "plain-ecs", "tagged"]
"#,
        &[
            ("plain", plain_at),
            ("plain-ecs", ecs_at),
            ("tagged", tagged_at),
        ],
    );

    let up = upstream(&r, "plain");
    up.exchange(&question("a.example"), WAIT).await.unwrap();
    let o = options(&next(&mut plain).await);
    assert!(o.is_empty(), "a query carries no option: {o:?}");
    // The health check's question (the root's NS) goes the same way, whatever its outcome.
    up.health_check().await;
    let o = options(&next(&mut plain).await);
    assert!(o.is_empty(), "a health check carries no option: {o:?}");

    upstream(&r, "plain-ecs")
        .exchange(&question("a.example"), WAIT)
        .await
        .unwrap();
    // Family 1, source /24, scope 0, and the subnet's three bytes.
    assert_eq!(
        options(&next(&mut ecs).await),
        [(ECS, vec![0, 1, 24, 0, 203, 0, 113])],
        "the subnet alone"
    );

    upstream(&r, "tagged")
        .exchange(&question("a.example"), WAIT)
        .await
        .unwrap();
    assert_eq!(options(&next(&mut tagged).await), [our_tag()]);
}

/// REQ: UPS-009 (ADR-192) — the switch is on by default: an upstream from the configuration that
/// doesn't set it (its queries and its health checks) and one built in code send this node's tag,
/// and no other option.
#[tokio::test]
async fn ups_009_loop_tag_is_on_by_default() {
    node_tag();
    let (at, mut seen) = mock().await;
    let r = router(&format!(
        "[[upstream]]\nname = \"u\"\nurl = \"udp://{at}\"\n\n[[upstream_group]]\nname = \"default\"\nmembers = [\"u\"]\n"
    ));
    let up = upstream(&r, "u");
    up.exchange(&question("a.example"), WAIT).await.unwrap();
    assert_eq!(options(&next(&mut seen).await), [our_tag()], "a query");
    up.health_check().await;
    assert_eq!(
        options(&next(&mut seen).await),
        [our_tag()],
        "a health check"
    );

    let ep = Endpoint::parse(&format!("udp://{at}")).unwrap();
    let code = Upstream::new(2, "code", ep, Duration::from_millis(400), 1).unwrap();
    code.exchange(&question("b.example"), WAIT).await.unwrap();
    assert_eq!(
        options(&next(&mut seen).await),
        [our_tag()],
        "built in code"
    );
}

/// `golden.example. A IN` at the default, after its ID: what the base (`e73d2e87`) sends.
#[rustfmt::skip]
const GOLDEN: &[u8] = &[
    // Flags (RD), QDCOUNT 1, ANCOUNT 0, NSCOUNT 0, ARCOUNT 1 (the OPT record).
    0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1,
    // golden.example. A IN
    6, b'g', b'o', b'l', b'd', b'e', b'n', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
    0, 1, 0, 1,
    // OPT: the root, type 41, UDP payload 1232, extended RCODE 0, version 0, no DO, RDLENGTH 12.
    0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 12,
    // Option 65429, length 8: this node's tag.
    0xff, 0x95, 0, 8, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];

/// REQ: UPS-009 (ADR-192) — at the default a query leaves byte for byte as it did before the
/// switch existed: after the ID (random per query over UDP), the same header, question, and OPT
/// record, the tag first and an ECS subnet after it. The golden bytes are the base's
/// (`e73d2e87`), for `encode_query` (what a bootstrap lookup at the default sends) and for an
/// upstream's exchange.
#[tokio::test]
async fn ups_009_default_query_bytes_are_unchanged() {
    node_tag();
    let mut buf = [0u8; 512];
    let n = telltale_upstream::encode_query(&question("golden.example"), 0x4242, &mut buf).unwrap();
    assert_eq!(buf[..2], [0x42, 0x42]);
    assert_eq!(&buf[2..n], GOLDEN, "encode_query");

    // DO and CD set: the CD flag in the header and the DO bit in the OPT record, nothing else.
    let mut golden_do = GOLDEN.to_vec();
    golden_do[1] = 0x10;
    golden_do[37] = 0x80;
    let mut q = question("golden.example");
    q.dnssec_ok = true;
    q.checking_disabled = true;
    let n = telltale_upstream::encode_query(&q, 0x4242, &mut buf).unwrap();
    assert_eq!(&buf[2..n], golden_do.as_slice(), "encode_query, DO and CD");

    // An upstream's exchange, from the configuration at the default, and one built in code.
    let (at, mut seen) = mock().await;
    let (ecs_at, mut ecs_seen) = mock().await;
    let r = router(&format!(
        r#"[[upstream]]
name = "u"
url = "udp://{at}"

[[upstream]]
name = "with-ecs"
url = "udp://{ecs_at}"
ecs = "203.0.113.0/24"

[[upstream_group]]
name = "default"
members = ["u", "with-ecs"]
"#
    ));
    upstream(&r, "u")
        .exchange(&question("golden.example"), WAIT)
        .await
        .unwrap();
    assert_eq!(
        &next(&mut seen).await[2..],
        GOLDEN,
        "from the configuration"
    );
    let ep = Endpoint::parse(&format!("udp://{at}")).unwrap();
    let code = Upstream::new(2, "code", ep, Duration::from_millis(400), 1).unwrap();
    code.exchange(&question("golden.example"), WAIT)
        .await
        .unwrap();
    assert_eq!(&next(&mut seen).await[2..], GOLDEN, "built in code");

    // With an ECS subnet: the tag, then the subnet (option 8, length 7), in one OPT record.
    let mut golden_ecs = GOLDEN.to_vec();
    golden_ecs[40] = 12 + 11;
    golden_ecs.extend_from_slice(&[0, 8, 0, 7, 0, 1, 24, 0, 203, 0, 113]);
    upstream(&r, "with-ecs")
        .exchange(&question("golden.example"), WAIT)
        .await
        .unwrap();
    assert_eq!(
        &next(&mut ecs_seen).await[2..],
        golden_ecs.as_slice(),
        "with an ECS subnet"
    );
}
