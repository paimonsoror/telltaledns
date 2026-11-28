//! REQ: DNS-006 (ADR-197) — queries that wait on one upstream resolution take its outcome, or
//! resolve within the budget of the query they answer. Through the pipeline, with upstreams on
//! 127.0.0.1.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use telltale_cache::{Cache, CacheKey, CachePolicy, Flight, Outcome};
use telltale_net::{QueryHandler, RequestMeta, Response, Transport};
use telltale_policy::ClientTable;
use telltale_proto::{
    EdnsOut, NameBuf, ResponseBuilder, build_query, parse_query, rcode, rtype, summarize,
};
use telltale_upstream::{Question, Router};
use tokio::net::UdpSocket;

use super::{Handler, Pipeline, Policy, Settings};

/// The query budget in these tests: short, so each runs in about a second.
const BUDGET: Duration = Duration::from_millis(300);

/// How long a test waits for something that should happen well within it.
const PATIENCE: Duration = Duration::from_secs(10);

fn query(name: &str, id: u16) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let n = NameBuf::from_presentation(name).unwrap();
    let len = build_query(
        &mut buf,
        id,
        &n,
        rtype::A,
        1,
        true,
        Some(EdnsOut::new(1232)),
    )
    .unwrap();
    buf[..len].to_vec()
}

fn meta(peer: SocketAddr) -> RequestMeta {
    RequestMeta {
        peer,
        local: None,
        transport: Transport::Udp,
        client_id: None,
    }
}

/// A pipeline with the test budget whose default group is the one upstream at `up`.
fn pipeline(up: SocketAddr) -> Arc<Pipeline> {
    pipeline_with_budget(up, BUDGET)
}

/// A pipeline with query budget `budget` whose default group is the one upstream at `up`.
fn pipeline_with_budget(up: SocketAddr, budget: Duration) -> Arc<Pipeline> {
    let toml = format!(
        "[[upstream]]\nname = \"u\"\nurl = \"udp://{up}\"\n\
         [[upstream_group]]\nname = \"default\"\nmembers = [\"u\"]\n"
    );
    let cfg: telltale_config::Config = telltale_config::Loader::new()
        .toml_str("t.toml", toml)
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    Pipeline::new(
        Settings {
            budget,
            ..Settings::default()
        },
        Arc::new(Cache::new(CachePolicy::default())),
        Arc::new(Router::from_config(&cfg).unwrap()),
        Policy {
            clients: Arc::new(ClientTable::from_config(&cfg)),
            ..Policy::open()
        },
    )
}

/// Resolutions holding an in-flight permit now.
fn in_flight(p: &Pipeline) -> usize {
    p.settings.max_inflight - p.inflight.available_permits()
}

/// A client's query for `name` A, spawned: its answer, if any.
fn ask(p: &Arc<Pipeline>, name: &str, id: u16) -> tokio::task::JoinHandle<Option<Vec<u8>>> {
    let mut out = [0u8; 4096];
    let peer: SocketAddr = format!("10.0.0.{}:1000", id % 200 + 1).parse().unwrap();
    match Handler(Arc::clone(p)).handle(&query(name, id), &meta(peer), &mut out) {
        Response::Deferred(answer) => tokio::spawn(answer),
        _ => panic!("a miss goes upstream"),
    }
}

/// Waits (at most [`PATIENCE`]) until `done` holds; whether it did.
async fn wait_until(mut done: impl FnMut() -> bool) -> bool {
    let start = tokio::time::Instant::now();
    while !done() {
        if start.elapsed() > PATIENCE {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    true
}

fn rcode_of(answer: &[u8]) -> u16 {
    summarize(answer).unwrap().rcode
}

fn has_address(answer: &[u8], ip: Ipv4Addr) -> bool {
    answer.windows(4).any(|w| w == ip.octets())
}

/// An upstream on 127.0.0.1 that sends every question back to this node as a client of its
/// own: it builds its own query (the same question and RD, CD and DO bits, none of the options
/// this node sent), asks the pipeline, and answers with what the pipeline answers, as a
/// forwarder in front of this node would. `asked` counts the questions it got; `busy` the ones
/// whose answer it still waits for.
struct SendsBack {
    asked: Arc<AtomicUsize>,
    busy: Arc<AtomicUsize>,
}

impl SendsBack {
    /// The pipeline whose only upstream sends every question back to it.
    async fn start() -> (Arc<Pipeline>, Self) {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let p = pipeline(sock.local_addr().unwrap());
        let (asked, busy) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let (pipe, count, pending) = (Arc::clone(&p), Arc::clone(&asked), Arc::clone(&busy));
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, from)) = sock.recv_from(&mut buf).await {
                count.fetch_add(1, Ordering::SeqCst);
                let Some(req) = own_query(&buf[..len]) else {
                    continue;
                };
                let mut out = [0u8; 4096];
                match Handler(Arc::clone(&pipe)).handle(&req, &meta(from), &mut out) {
                    Response::Ready(at) => {
                        let _ = sock.send_to(&out[..at], from).await;
                    }
                    Response::Deferred(answer) => {
                        pending.fetch_add(1, Ordering::SeqCst);
                        let (reply_on, pending) = (Arc::clone(&sock), Arc::clone(&pending));
                        tokio::spawn(async move {
                            if let Some(reply) = answer.await {
                                let _ = reply_on.send_to(&reply, from).await;
                            }
                            pending.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                    _ => {}
                }
            }
        });
        (p, Self { asked, busy })
    }

    fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }

    /// Nothing more can happen: no resolution holds a permit, and every question it got has
    /// been answered.
    fn settled(&self, p: &Pipeline) -> bool {
        in_flight(p) == 0 && self.busy.load(Ordering::SeqCst) == 0
    }
}

/// The query a forwarder builds for the question in `msg`: same ID, question, RD, CD and DO,
/// and an OPT with no options.
fn own_query(msg: &[u8]) -> Option<Vec<u8>> {
    let q = parse_query(msg).ok()?;
    let edns = EdnsOut {
        udp_payload: 1232,
        dnssec_ok: q.edns.is_some_and(|e| e.dnssec_ok),
        ede: None,
    };
    let mut buf = [0u8; 512];
    let len = build_query(
        &mut buf,
        q.header.id,
        &q.qname,
        q.qtype,
        q.qclass,
        q.header.flags.rd(),
        Some(edns),
    )
    .ok()?;
    if q.header.flags.cd() {
        // CD is bit 4 of the flags' second byte.
        buf[3] |= 0x10;
    }
    Some(buf[..len].to_vec())
}

/// The most upstream queries the tests below allow for one miss of the upstream that sends
/// questions back. A request makes at most two tries: the miss's own, and one more for the
/// question that came back when it still has 100 ms (it has about that, so it is sent or not).
/// A runner stalled for longer than that margin at the wrong moment can let a question that
/// came back arrive after its request ended; it then leads a request of its own, bounded by
/// the same rule. Six leaves room for two such.
const MAX_ASKED: usize = 6;

/// REQ: DNS-006 (ADR-197) — an upstream that sends every question back to this node, with
/// nothing that tells its query apart from a client's: the question that comes back waits on
/// the miss that sent it. The miss makes at most two tries, and every resolution then ends.
#[tokio::test]
async fn dns_006_an_upstream_that_sends_questions_back_ends_with_the_miss() {
    let (p, up) = SendsBack::start().await;
    let answer = tokio::time::timeout(PATIENCE, ask(&p, "back.example", 1))
        .await
        .expect("the client is answered within its wait")
        .unwrap()
        .expect("an answer");
    assert_eq!(rcode_of(&answer), rcode::SERVFAIL);
    let settled = wait_until(|| up.settled(&p)).await;
    assert!(
        settled,
        "every resolution ends: {} in flight, the upstream asked {} times so far",
        in_flight(&p),
        up.asked()
    );
    let asked = up.asked();
    assert!((1..=MAX_ASKED).contains(&asked), "asked {asked} times");
}

/// REQ: DNS-006 (ADR-197) — the same upstream, with many clients asking one name at once: they
/// all wait on one request, every client is answered within its wait, and every resolution
/// ends, with no more upstream queries than for one client.
#[tokio::test]
async fn dns_006_many_queries_for_one_name_share_one_request() {
    let (p, up) = SendsBack::start().await;
    let clients: Vec<_> = (1..=20).map(|i| ask(&p, "many.example", i)).collect();
    for c in clients {
        let answer = tokio::time::timeout(PATIENCE, c)
            .await
            .expect("each client is answered within its wait")
            .unwrap()
            .expect("an answer");
        assert_eq!(rcode_of(&answer), rcode::SERVFAIL);
    }
    let settled = wait_until(|| up.settled(&p)).await;
    assert!(
        settled,
        "every resolution ends: {} in flight, the upstream asked {} times so far",
        in_flight(&p),
        up.asked()
    );
    let asked = up.asked();
    assert!(
        (1..=MAX_ASKED).contains(&asked),
        "asked {asked} times for the twenty clients"
    );
}

/// An upstream on 127.0.0.1 that answers every question with 192.0.2.7, except the first one
/// when `lose_first` (it never answers that). `first` is notified when the first question
/// arrives; `asked` counts them.
async fn upstream(lose_first: bool) -> (SocketAddr, Arc<AtomicUsize>, Arc<tokio::sync::Notify>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let asked = Arc::new(AtomicUsize::new(0));
    let first = Arc::new(tokio::sync::Notify::new());
    let (count, first_seen) = (Arc::clone(&asked), Arc::clone(&first));
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, from)) = sock.recv_from(&mut buf).await {
            if count.fetch_add(1, Ordering::SeqCst) == 0 {
                first_seen.notify_one();
                if lose_first {
                    continue;
                }
            }
            let Ok(question) = parse_query(&buf[..len]) else {
                continue;
            };
            let mut out = [0u8; 512];
            let mut reply = ResponseBuilder::new(&question, &mut out, rcode::NOERROR).unwrap();
            reply.answer_a(60, Ipv4Addr::new(192, 0, 2, 7)).unwrap();
            let size = reply.finish(None).unwrap();
            let _ = sock.send_to(&out[..size], from).await;
        }
    });
    (addr, asked, first)
}

/// Leads the request for `name` with the pipeline's own resolution (spawned), once the
/// upstream has its first question; then waits on it with a deadline `past` the budget from
/// when the leader started. The leader's result and the waiting query's outcome.
async fn lead_then_wait(
    p: &Arc<Pipeline>,
    first: &tokio::sync::Notify,
    name: &str,
    past: Duration,
) -> (Option<(Arc<[u8]>, u16)>, Outcome) {
    let (req, key, view) = keyed(p, name);
    let wire = parse_query(&req).unwrap().qname.as_wire().to_vec();
    let start = Instant::now();
    let permit = Arc::clone(&p.inflight).try_acquire_owned().unwrap();
    let deadline = start + p.settings.budget;
    let leader = tokio::spawn(Arc::clone(p).resolve_shared(req, key, view, deadline, permit));
    first.notified().await;
    // The leader's request is in flight (its question reached the upstream): wait on it.
    let Flight::Follower(waiter) = p.flights.join(key, &wire, start + p.settings.budget + past)
    else {
        panic!("the leader's request is in flight")
    };
    let outcome = tokio::time::timeout(PATIENCE, waiter.wait())
        .await
        .expect("the request ends");
    let led = tokio::time::timeout(PATIENCE, leader)
        .await
        .expect("the leader ends")
        .unwrap();
    (led, outcome)
}

/// REQ: DNS-006 (ADR-197) — the leader's only try waits the whole budget for a question the
/// upstream lost, and fails; a query that waits on it still has time (1.5 s past the budget),
/// so the leader tries once more for it, and both have that answer. Two questions go out: the
/// waiting query doesn't ask on its own. Holds on a slow runner: the second try has over a
/// second, and the leader's result is read from its own resolution, not a client's wait.
#[tokio::test]
async fn dns_006_a_follower_whose_leader_ran_out_of_time_gets_the_second_try() {
    let (up, asked, first) = upstream(true).await;
    let p = pipeline(up);
    let (led, outcome) =
        lead_then_wait(&p, &first, "lost.example", Duration::from_millis(1500)).await;
    let ip = Ipv4Addr::new(192, 0, 2, 7);
    assert!(
        matches!(&outcome, Outcome::Answered(a, _) if has_address(a, ip)),
        "the waiting query: {outcome:?}"
    );
    assert!(led.is_some_and(|(a, _)| has_address(&a, ip)), "the leader");
    assert_eq!(asked.load(Ordering::SeqCst), 2);
}

/// REQ: DNS-006 (ADR-197) — a second try starts only with 100 ms left: a query that waits with
/// 50 ms past the leader's budget takes the leader's failure, and no second question goes out.
/// Holds on a slow runner: a stall only leaves less time.
#[tokio::test]
async fn dns_006_no_second_try_with_less_than_100_ms_left() {
    let (up, asked, first) = upstream(true).await;
    let p = pipeline(up);
    let (led, outcome) =
        lead_then_wait(&p, &first, "short.example", Duration::from_millis(50)).await;
    assert_eq!(outcome, Outcome::Failed);
    assert!(led.is_none(), "the leader fails too");
    assert_eq!(asked.load(Ordering::SeqCst), 1, "no second question");
}

/// An upstream on 127.0.0.1 that never answers. `first` is notified when its first question
/// arrives; `asked` counts them.
async fn mute_upstream() -> (SocketAddr, Arc<AtomicUsize>, Arc<tokio::sync::Notify>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let asked = Arc::new(AtomicUsize::new(0));
    let first = Arc::new(tokio::sync::Notify::new());
    let (count, first_seen) = (Arc::clone(&asked), Arc::clone(&first));
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while sock.recv_from(&mut buf).await.is_ok() {
            if count.fetch_add(1, Ordering::SeqCst) == 0 {
                first_seen.notify_one();
            }
        }
    });
    (addr, asked, first)
}

/// REQ: DNS-006 (ADR-197) — a second try ends with the waiting queries' time: with the
/// configured 2 s budget and an upstream that never answers, the leader's own try takes the
/// whole budget, and the second one, for a query waiting 300 ms past it, ends at that query's
/// deadline, not a budget later. Holds on a slow runner: a stall only makes the second try
/// shorter (or leaves it out under 100 ms), and the bound allows 700 ms of lag past the
/// deadline, where a try run with the whole budget would take 1.7 s more.
#[tokio::test]
async fn dns_006_a_second_try_ends_with_the_waiting_queries_time() {
    let (up, asked, first) = mute_upstream().await;
    let p = pipeline_with_budget(up, Settings::default().budget);
    let (budget, past) = (p.settings.budget, Duration::from_millis(300));
    let began = Instant::now();
    let (led, outcome) = lead_then_wait(&p, &first, "mute.example", past).await;
    let took = began.elapsed();
    assert_eq!(outcome, Outcome::Failed);
    assert!(led.is_none(), "the leader fails too");
    assert!(
        took >= budget,
        "the leader's own try takes its budget: {took:?}"
    );
    assert!(
        took <= budget + past + Duration::from_millis(700),
        "the second try ends at the waiting query's deadline: {took:?}"
    );
    let asked = asked.load(Ordering::SeqCst);
    assert!((1..=2).contains(&asked), "asked {asked} times");
}

/// The query for `name` A and its cache key and view, as the pipeline computes them.
fn keyed(p: &Pipeline, name: &str) -> (Vec<u8>, CacheKey, u16) {
    let req = query(name, 1);
    let q = parse_query(&req).unwrap();
    let view = p
        .current()
        .router
        .select(&Question::from_query(&q), &["default"])
        .unwrap()
        .view;
    let key = p.key(&q, view);
    (req, key, view)
}

/// REQ: DNS-006 (ADR-197) — a query that waits on a request takes its answer, and asks no
/// upstream (as before). The test leads the request itself.
#[tokio::test]
async fn dns_006_a_follower_takes_its_leaders_answer() {
    let (up, asked, _) = upstream(false).await;
    let p = pipeline(up);
    let (req, key, _) = keyed(&p, "shared.example");
    let q = parse_query(&req).unwrap();
    let Flight::Leader(guard) = p.flights.join(key, q.qname.as_wire(), Instant::now()) else {
        panic!("nothing else is in flight")
    };
    let follower = ask(&p, "shared.example", 2);
    assert!(
        wait_until(|| guard.followers() == 1).await,
        "the client waits on the request"
    );
    let mut out = [0u8; 512];
    let mut r = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
    r.answer_a(60, Ipv4Addr::new(192, 0, 2, 8)).unwrap();
    let len = r.finish(None).unwrap();
    guard.complete(Arc::from(&out[..len]), 0);
    let answer = tokio::time::timeout(PATIENCE, follower)
        .await
        .expect("answered within its wait")
        .unwrap()
        .expect("an answer");
    assert_eq!(rcode_of(&answer), rcode::NOERROR);
    assert!(has_address(&answer, Ipv4Addr::new(192, 0, 2, 8)));
    assert_eq!(asked.load(Ordering::SeqCst), 0, "no upstream was asked");
}

/// REQ: DNS-006 (ADR-197) — a leader that goes away without an outcome (cancelled with its
/// caller) leaves the query waiting on it to resolve on its own, within the time it has left:
/// with 300 ms left it asks the upstream and has the answer; with under 100 ms, it asks
/// nothing.
#[tokio::test]
async fn dns_006_a_follower_of_an_abandoned_leader_resolves_within_its_own_time() {
    let (up, asked, _) = upstream(false).await;
    let p = pipeline(up);
    let (req, key, view) = keyed(&p, "gone.example");
    let name = parse_query(&req).unwrap().qname.as_wire().to_vec();
    let permit = || Arc::clone(&p.inflight).try_acquire_owned().unwrap();
    for (left, answered) in [(BUDGET, true), (Duration::from_millis(50), false)] {
        let Flight::Leader(guard) = p.flights.join(key, &name, Instant::now()) else {
            panic!("nothing else is in flight")
        };
        let follower = tokio::spawn(Arc::clone(&p).resolve_shared(
            req.clone(),
            key,
            view,
            Instant::now() + left,
            permit(),
        ));
        assert!(
            wait_until(|| guard.followers() == 1).await,
            "it waits on the request"
        );
        drop(guard);
        let got = tokio::time::timeout(PATIENCE, follower)
            .await
            .expect("done within its time")
            .unwrap();
        assert_eq!(got.is_some(), answered, "{left:?} left");
        if let Some((answer, _)) = got {
            assert!(has_address(&answer, Ipv4Addr::new(192, 0, 2, 7)));
        }
    }
    assert_eq!(
        asked.load(Ordering::SeqCst),
        1,
        "asked once: not by the query with under 100 ms left"
    );
}

/// How long the validated tests' upstream takes to answer the first A question for a name
/// that starts with `slow`: more than a shortened try has, well within the query budget.
const SLOW: Duration = Duration::from_millis(800);

/// An upstream on 127.0.0.1 for the validated tests. When `lose_first`, it never answers the
/// first question it gets; `first` is notified when that one arrives. It answers A questions
/// with 192.0.2.7 (the first one for a name that starts with `slow` after [`SLOW`]) and every
/// other type with no records.
async fn validating_upstream(lose_first: bool) -> (SocketAddr, Arc<tokio::sync::Notify>) {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let first = Arc::new(tokio::sync::Notify::new());
    let first_seen = Arc::clone(&first);
    tokio::spawn(async move {
        let mut seen = std::collections::HashSet::new();
        let mut count = 0usize;
        let mut buf = [0u8; 4096];
        while let Ok((len, from)) = sock.recv_from(&mut buf).await {
            count += 1;
            if count == 1 {
                first_seen.notify_one();
                if lose_first {
                    continue;
                }
            }
            let Ok(question) = parse_query(&buf[..len]) else {
                continue;
            };
            let name = question.qname.display().to_string().to_ascii_lowercase();
            let delay =
                if question.qtype == rtype::A && name.starts_with("slow") && seen.insert(name) {
                    SLOW
                } else {
                    Duration::ZERO
                };
            let mut out = [0u8; 512];
            let mut reply = ResponseBuilder::new(&question, &mut out, rcode::NOERROR).unwrap();
            if question.qtype == rtype::A {
                reply.answer_a(60, Ipv4Addr::new(192, 0, 2, 7)).unwrap();
            }
            let size = reply.finish(None).unwrap();
            let (bytes, reply_on) = (out[..size].to_vec(), Arc::clone(&sock));
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = reply_on.send_to(&bytes, from).await;
            });
        }
    });
    (addr, first)
}

/// A pipeline with the configured budget and DNSSEC validation on (permissive, so an answer the
/// test upstream can't prove is still served), whose default group is the one upstream at `up`;
/// and its configuration, to turn validation on again (a reload's fresh validator).
fn validating_pipeline(up: SocketAddr) -> (Arc<Pipeline>, telltale_config::Config) {
    let toml = format!(
        "[[upstream]]\nname = \"u\"\nurl = \"udp://{up}\"\n\
         [[upstream_group]]\nname = \"default\"\nmembers = [\"u\"]\n\
         [dnssec]\nmode = \"permissive\"\n"
    );
    let cfg: telltale_config::Config = telltale_config::Loader::new()
        .toml_str("t.toml", toml)
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    let p = Pipeline::new(
        Settings::default(),
        Arc::new(Cache::new(CachePolicy::default())),
        Arc::new(Router::from_config(&cfg).unwrap()),
        Policy {
            clients: Arc::new(ClientTable::from_config(&cfg)),
            ..Policy::open()
        },
    );
    p.set_dnssec(&cfg);
    (p, cfg)
}

/// A validated client query for a name the upstream answers after [`SLOW`]: answered within
/// the configured budget, as the group's validated lookups always are.
async fn slow_name_is_answered(p: &Arc<Pipeline>, name: &str) {
    let answer = tokio::time::timeout(PATIENCE, ask(p, name, 9))
        .await
        .expect("answered within its wait")
        .unwrap()
        .expect("an answer");
    assert_eq!(
        rcode_of(&answer),
        rcode::NOERROR,
        "{name}: the group's validated lookups keep the configured budget"
    );
    assert!(has_address(&answer, Ipv4Addr::new(192, 0, 2, 7)), "{name}");
}

/// REQ: DNS-006, DNS-011 (ADR-197) — with validation on, a second try made for a waiting query
/// with a few hundred milliseconds left, as the first validated lookup of a fresh validator
/// (one a reload made while the leader's own try was out), leaves the group's validated lookups
/// with the configured budget: a later name that takes longer than that try had is answered.
#[tokio::test]
async fn dns_006_a_second_try_leaves_the_validation_budget_as_configured() {
    let (up, first) = validating_upstream(true).await;
    let (p, cfg) = validating_pipeline(up);
    let (req, key, view) = keyed(&p, "lost.example");
    let name = parse_query(&req).unwrap().qname.as_wire().to_vec();
    let permit = Arc::clone(&p.inflight).try_acquire_owned().unwrap();
    let deadline = Instant::now() + p.settings.budget;
    let leader =
        tokio::spawn(Arc::clone(&p).resolve_shared(req.clone(), key, view, deadline, permit));
    first.notified().await;
    // The leader's own try is out (the upstream lost its question): wait on it with 300 ms past
    // its budget, then let a reload make a fresh validator.
    let Flight::Follower(waiter) = p.flights.join(
        key,
        &name,
        Instant::now() + p.settings.budget + Duration::from_millis(300),
    ) else {
        panic!("the leader's request is in flight")
    };
    p.set_dnssec(&cfg);
    let _ = tokio::time::timeout(PATIENCE, waiter.wait())
        .await
        .expect("the request ends");
    let _ = leader.await;
    slow_name_is_answered(&p, "slow.example").await;
}

/// REQ: DNS-006, DNS-011 (ADR-197) — the same for a follower of a leader that went away: its
/// own lookup, with 300 ms left, as the first validated lookup of the validator, leaves the
/// group's validated lookups with the configured budget.
#[tokio::test]
async fn dns_006_an_abandoned_follower_leaves_the_validation_budget_as_configured() {
    let (up, _) = validating_upstream(false).await;
    let (p, _) = validating_pipeline(up);
    let (req, key, view) = keyed(&p, "gone.example");
    let name = parse_query(&req).unwrap().qname.as_wire().to_vec();
    let Flight::Leader(guard) = p.flights.join(key, &name, Instant::now()) else {
        panic!("nothing else is in flight")
    };
    let permit = Arc::clone(&p.inflight).try_acquire_owned().unwrap();
    let follower = tokio::spawn(Arc::clone(&p).resolve_shared(
        req.clone(),
        key,
        view,
        Instant::now() + Duration::from_millis(300),
        permit,
    ));
    assert!(
        wait_until(|| guard.followers() == 1).await,
        "it waits on the request"
    );
    drop(guard);
    let _ = tokio::time::timeout(PATIENCE, follower)
        .await
        .expect("done within its time");
    slow_name_is_answered(&p, "slow.example").await;
}
