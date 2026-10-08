//! UPS-001/005/006 against in-process fake upstreams, plus the T1.5 chaos acceptance test.

#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use telltale_proto::{NameBuf, ResponseBuilder, parse_query, rcode, rtype, summarize};
use telltale_upstream::health::Breaker;
use telltale_upstream::{Endpoint, Group, Question, Strategy, Upstream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

#[derive(Clone, Copy)]
enum Fake {
    /// Answers A 192.0.2.<tag>, after `delay`.
    Healthy {
        tag: u8,
        delay: Duration,
    },
    ServFail,
    /// Never answers.
    Blackhole,
    /// Answers over UDP with TC=1 and properly over TCP on the same port.
    Truncating,
}

fn answer(req: &[u8], rc: u16, tag: u8, tc: bool) -> Option<Vec<u8>> {
    let q = parse_query(req).ok()?;
    let mut out = [0u8; 512];
    let mut b = ResponseBuilder::new(&q, &mut out, rc).ok()?;
    if rc == rcode::NOERROR && !tc {
        b.answer_a(300, Ipv4Addr::new(192, 0, 2, tag)).ok()?;
    }
    let len = b.finish(None).ok()?;
    if tc {
        out[2] |= 0x02;
    }
    Some(out[..len].to_vec())
}

/// Starts a fake upstream on 127.0.0.1 and returns its UDP address.
async fn fake(kind: Fake) -> SocketAddr {
    // The truncating fake needs TCP on the same port as UDP: a random UDP port's TCP twin can
    // be taken by something else, so try a few.
    let mut bound = None;
    for _ in 0..50 {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        if !matches!(kind, Fake::Truncating) {
            bound = Some((sock, None));
            break;
        }
        if let Ok(tcp) = TcpListener::bind(addr).await {
            bound = Some((sock, Some(tcp)));
            break;
        }
    }
    let (sock, tcp) = bound.unwrap();
    let sock = Arc::new(sock);
    let addr = sock.local_addr().unwrap();
    if let Some(tcp) = tcp {
        tokio::spawn(async move {
            while let Ok((mut s, _)) = tcp.accept().await {
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    s.read_exact(&mut len).await.ok()?;
                    let mut req = vec![0; usize::from(u16::from_be_bytes(len))];
                    s.read_exact(&mut req).await.ok()?;
                    let resp = answer(&req, rcode::NOERROR, 99, false)?;
                    let mut framed = (resp.len() as u16).to_be_bytes().to_vec();
                    framed.extend(resp);
                    s.write_all(&framed).await.ok()
                });
            }
        });
    }
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let req = buf[..n].to_vec();
            let sock = Arc::clone(&sock);
            tokio::spawn(async move {
                let resp = match kind {
                    Fake::Healthy { tag, delay } => {
                        tokio::time::sleep(delay).await;
                        answer(&req, rcode::NOERROR, tag, false)
                    }
                    Fake::ServFail => answer(&req, rcode::SERVFAIL, 0, false),
                    Fake::Blackhole => None,
                    Fake::Truncating => answer(&req, rcode::NOERROR, 0, true),
                };
                if let Some(r) = resp {
                    let _ = sock.send_to(&r, peer).await;
                }
            });
        }
    });
    addr
}

fn upstream(id: u16, addr: SocketAddr, weight: u32) -> Arc<Upstream> {
    let ep = Endpoint::parse(&format!("udp://{addr}")).unwrap();
    Arc::new(Upstream::new(id, format!("u{id}"), ep, Duration::from_millis(400), weight).unwrap())
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

fn answer_tag(bytes: &[u8]) -> u8 {
    // Last byte of the single A record.
    bytes[bytes.len() - 1]
}

const HEALTHY: Fake = Fake::Healthy {
    tag: 1,
    delay: Duration::ZERO,
};

#[tokio::test]
async fn ups_001_udp_exchange_validates_and_tc_falls_back_to_tcp() {
    let up = upstream(1, fake(HEALTHY).await, 1);
    let resp = up
        .exchange(&question("example.com"), Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(summarize(&resp).unwrap().answers, 1);

    let tc = upstream(2, fake(Fake::Truncating).await, 1);
    let resp = tc
        .exchange(&question("big.example"), Duration::from_secs(1))
        .await
        .unwrap();
    assert!(!telltale_proto::header::flags(&resp).tc());
    assert_eq!(answer_tag(&resp), 99, "answer came over TCP");
}

#[tokio::test]
async fn ups_005_failover_prefers_first_healthy_member() {
    let a = upstream(1, fake(HEALTHY).await, 1);
    let b = upstream(
        2,
        fake(Fake::Healthy {
            tag: 2,
            delay: Duration::ZERO,
        })
        .await,
        1,
    );
    let g = Group::new("default", vec![a, b], Strategy::Failover);
    for _ in 0..10 {
        let ans = g
            .resolve(question("x.example"), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(ans.upstream_id, 1);
    }
}

#[tokio::test]
async fn ups_005_round_robin_and_weighted_distribute() {
    let a = upstream(1, fake(HEALTHY).await, 3);
    let b = upstream(
        2,
        fake(Fake::Healthy {
            tag: 2,
            delay: Duration::ZERO,
        })
        .await,
        1,
    );
    let rr = Group::new(
        "rr",
        vec![Arc::clone(&a), Arc::clone(&b)],
        Strategy::RoundRobin,
    );
    let mut counts = [0u32; 3];
    for _ in 0..40 {
        counts[usize::from(
            rr.resolve(question("x.example"), Duration::from_secs(2))
                .await
                .unwrap()
                .upstream_id,
        )] += 1;
    }
    assert_eq!((counts[1], counts[2]), (20, 20));

    let w = Group::new("w", vec![a, b], Strategy::Weighted);
    let mut counts = [0u32; 3];
    for _ in 0..40 {
        counts[usize::from(
            w.resolve(question("x.example"), Duration::from_secs(2))
                .await
                .unwrap()
                .upstream_id,
        )] += 1;
    }
    assert_eq!((counts[1], counts[2]), (30, 10), "smooth WRR 3:1");
}

#[tokio::test]
async fn ups_005_fastest_prefers_lower_latency() {
    let slow = upstream(
        1,
        fake(Fake::Healthy {
            tag: 1,
            delay: Duration::from_millis(30),
        })
        .await,
        1,
    );
    let fast = upstream(
        2,
        fake(Fake::Healthy {
            tag: 2,
            delay: Duration::ZERO,
        })
        .await,
        1,
    );
    let g = Group::new("f", vec![slow, fast], Strategy::Fastest);
    let mut fast_wins = 0;
    for _ in 0..50 {
        if g.resolve(question("x.example"), Duration::from_secs(2))
            .await
            .unwrap()
            .upstream_id
            == 2
        {
            fast_wins += 1;
        }
    }
    assert!(
        fast_wins >= 45,
        "fastest picked the fast upstream {fast_wins}/50 times"
    );
}

#[tokio::test]
async fn ups_005_parallel_races_and_first_answer_wins() {
    let slow = upstream(
        1,
        fake(Fake::Healthy {
            tag: 1,
            delay: Duration::from_millis(200),
        })
        .await,
        1,
    );
    let fast = upstream(
        2,
        fake(Fake::Healthy {
            tag: 2,
            delay: Duration::from_millis(5),
        })
        .await,
        1,
    );
    let g = Group::new("p", vec![slow, fast], Strategy::Parallel { fanout: 2 });
    let t = Instant::now();
    let ans = g
        .resolve(question("x.example"), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(ans.upstream_id, 2);
    assert!(
        t.elapsed() < Duration::from_millis(150),
        "did not wait for the slow member"
    );
}

#[tokio::test]
async fn ups_006_servfail_retries_next_member_and_is_kept_as_fallback() {
    let bad = upstream(1, fake(Fake::ServFail).await, 1);
    let good = upstream(2, fake(HEALTHY).await, 1);
    let g = Group::new("g", vec![Arc::clone(&bad), good], Strategy::Failover);
    let ans = g
        .resolve(question("x.example"), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(ans.upstream_id, 2);
    assert_eq!(summarize(&ans.bytes).unwrap().rcode, rcode::NOERROR);

    let only_bad = Group::new("b", vec![bad], Strategy::Failover);
    let ans = only_bad
        .resolve(question("x.example"), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        summarize(&ans.bytes).unwrap().rcode,
        rcode::SERVFAIL,
        "upstream SERVFAIL passed through"
    );
}

#[tokio::test]
async fn ups_006_all_dead_still_attempts_and_reports() {
    let dead = upstream(1, fake(Fake::Blackhole).await, 1);
    let g = Group::new("d", vec![dead], Strategy::Failover);
    let err = g
        .resolve(question("x.example"), Duration::from_millis(600))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("attempt") || err.to_string().contains("budget"),
        "{err}"
    );
}

fn p99(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[(v.len() * 99 / 100).min(v.len() - 1)]
}

async fn run_load(g: &Group, n: usize) -> (Vec<Duration>, usize) {
    let mut lat = Vec::with_capacity(n);
    let mut failures = 0;
    for i in 0..n {
        let t = Instant::now();
        match g
            .resolve(question(&format!("q{i}.example")), Duration::from_secs(2))
            .await
        {
            Ok(a) if summarize(&a.bytes).is_ok_and(|s| s.rcode == rcode::NOERROR) => {}
            _ => failures += 1,
        }
        lat.push(t.elapsed());
    }
    (lat, failures)
}

/// T1.5 AC: one upstream at 100% loss → no client-visible failures; p99 within 1.5× of the
/// healthy baseline. (In-process stand-in for the toxiproxy chaos test, which needs Docker.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ups_006_chaos_one_upstream_blackholed() {
    const N: usize = 1000;
    let healthy_addr = fake(HEALTHY).await;
    let baseline = Group::new(
        "base",
        vec![upstream(1, healthy_addr, 1)],
        Strategy::Fastest,
    );
    let (base_lat, base_fail) = run_load(&baseline, N).await;
    assert_eq!(base_fail, 0);
    let base_p99 = p99(base_lat);

    for strategy in [
        Strategy::Fastest,
        Strategy::Failover,
        Strategy::RoundRobin,
        Strategy::Parallel { fanout: 2 },
    ] {
        // Latency on shared CI runners is noisy: a strategy passes if one of three measurements
        // (each against a fresh baseline) is within bounds. Failures must be zero every time.
        let mut results = Vec::new();
        for attempt in 0..3 {
            let base_p99 = if attempt == 0 {
                base_p99
            } else {
                p99(run_load(&baseline, N).await.0)
            };
            let dead = upstream(10, fake(Fake::Blackhole).await, 1);
            let live = upstream(11, healthy_addr, 1);
            let g = Group::new("chaos", vec![dead, live], strategy);
            let (lat, failures) = run_load(&g, N).await;
            let chaos_p99 = p99(lat);
            println!(
                "{strategy:?} #{attempt}: baseline p99 {base_p99:?}, chaos p99 {chaos_p99:?}, failures {failures}"
            );
            assert_eq!(failures, 0, "{strategy:?}: client-visible failures");
            // 1.5× plus 1 ms absolute slack for scheduler noise.
            let limit = base_p99.mul_f64(1.5) + Duration::from_millis(1);
            if chaos_p99 <= limit {
                results.clear();
                break;
            }
            results.push(format!("p99 {chaos_p99:?} > {limit:?}"));
        }
        assert!(results.is_empty(), "{strategy:?}: {results:?}");
    }
}

/// REQ: UPS-006, OBS-011 — what went wrong is counted by kind, not only as "failure".
#[tokio::test]
async fn ups_006_failure_kinds_are_counted() {
    use telltale_upstream::health::Outcome;
    let kind = |u: &Upstream, k: Outcome| {
        let s = u.health.snapshot();
        Outcome::FAILURES
            .iter()
            .zip(s.failures_by_kind)
            .find(|(x, _)| **x == k)
            .map_or(0, |(_, n)| n)
    };
    let bad = upstream(1, fake(Fake::ServFail).await, 1);
    let _ = bad
        .exchange(&question("x.example"), Duration::from_millis(400))
        .await;
    let dead = upstream(2, fake(Fake::Blackhole).await, 1);
    let _ = dead
        .exchange(&question("x.example"), Duration::from_millis(100))
        .await;
    assert_eq!(
        (kind(&bad, Outcome::ServFail), kind(&bad, Outcome::Timeout)),
        (1, 0)
    );
    assert_eq!(
        (
            kind(&dead, Outcome::Timeout),
            kind(&dead, Outcome::ServFail)
        ),
        (1, 0)
    );
    assert_eq!(dead.health.snapshot().failures, 1);
}

/// REQ: UPS-006 — a healthy upstream that answers SERVFAIL (a broken domain a browser keeps
/// retrying) stays in service, with its real latency; a dead one is benched after three.
#[tokio::test]
async fn ups_006_servfail_is_an_answer_not_a_dead_upstream() {
    let timeout = Duration::from_millis(500);
    let healthy = upstream(1, fake(Fake::ServFail).await, 1);
    for _ in 0..5 {
        let _ = healthy.exchange(&question("broken.example"), timeout).await;
    }
    let s = healthy.health.snapshot();
    assert_eq!((s.failures, s.breaker), (5, Breaker::Closed));
    assert_eq!(healthy.health.consecutive_failures(), 0);
    assert!(
        healthy.health.ewma().unwrap() < timeout / 2,
        "SERVFAIL is recorded at its real latency, not the timeout: {:?}",
        healthy.health.ewma()
    );
    let dead = upstream(2, fake(Fake::Blackhole).await, 1);
    for _ in 0..3 {
        let _ = dead
            .exchange(&question("x.example"), Duration::from_millis(50))
            .await;
    }
    assert_eq!(dead.health.snapshot().breaker, Breaker::Open);
}

/// REQ: DNS-015 (T9.9) — `ecs = "client"`: the query carries the client's /24, and a
/// question without a subnet (a private client) carries none.
#[tokio::test]
async fn dns_015_ecs_client_reaches_the_upstream() {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = s.recv_from(&mut buf).await {
            let q = parse_query(&buf[..n]).unwrap();
            let _ = tx.send(q.edns.and_then(|e| e.client_subnet()).map(<[u8]>::to_vec));
            if let Some(r) = answer(&buf[..n], rcode::NOERROR, 1, false) {
                let _ = s.send_to(&r, from).await;
            }
        }
    });
    let ep = Endpoint::parse(&format!("udp://{addr}")).unwrap();
    let opts = telltale_upstream::UpstreamOptions {
        ecs_client: true,
        ..telltale_upstream::UpstreamOptions::default()
    };
    let up = Upstream::build(
        1,
        "ecs",
        ep,
        &opts,
        &telltale_upstream::TlsOptions::default(),
    )
    .unwrap();
    let mut q = question("cdn.example");
    q.client_subnet = telltale_upstream::client_subnet("198.51.100.77".parse().unwrap());
    up.exchange(&q, Duration::from_secs(2)).await.unwrap();
    // family 1, source /24, scope 0, three address bytes.
    assert_eq!(
        rx.recv().await.unwrap().unwrap(),
        vec![0, 1, 24, 0, 198, 51, 100]
    );
    let q = question("cdn.example");
    up.exchange(&q, Duration::from_secs(2)).await.unwrap();
    assert_eq!(rx.recv().await.unwrap(), None);
}

/// REQ: OBS-007 (T9.19) — the exchange observer sees the query exactly as sent, the answer,
/// the upstream's address, and its protocol.
#[tokio::test]
async fn obs_007_exchange_observer() {
    use std::sync::Mutex;
    type Seen = Vec<(
        Vec<u8>,
        Option<Vec<u8>>,
        Option<SocketAddr>,
        telltale_upstream::Protocol,
    )>;
    static SEEN: Mutex<Seen> = Mutex::new(Vec::new());
    telltale_upstream::set_exchange_observer(Box::new(|e| {
        SEEN.lock().unwrap().push((
            e.query.to_vec(),
            e.response.map(<[u8]>::to_vec),
            e.addr,
            e.protocol,
        ));
    }));
    let addr = fake(Fake::Healthy {
        tag: 7,
        delay: Duration::ZERO,
    })
    .await;
    let up = upstream(1, addr, 1);
    let resp = up
        .exchange(&question("seen.example"), Duration::from_secs(2))
        .await
        .unwrap();
    let seen = SEEN.lock().unwrap();
    let (q, r, a, p) = seen.iter().find(|x| x.2 == Some(addr)).expect("observed");
    assert_eq!(&q[..2], &resp[..2], "the query as sent (same ID)");
    assert_eq!(r.as_deref(), Some(resp.as_slice()));
    assert_eq!((*a, *p), (Some(addr), telltale_upstream::Protocol::Udp));
}
