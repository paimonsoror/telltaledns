//! DNS-006/007/008 behavior of the response cache.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use telltale_cache::{
    Cache, CacheKey, CachePolicy, Client, Flight, Lookup, Singleflight, Uncacheable,
};
use telltale_proto::{
    EdnsOut, NameBuf, Query, ResponseBuilder, build_query, ede, parse_query, rcode, records, rtype,
    summarize, ttl_at,
};

const SEED: u64 = 0x00C0_FFEE;

fn query_bytes(name: &str, qtype: u16, edns: Option<EdnsOut<'_>>, id: u16) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let n = NameBuf::from_presentation(name).unwrap();
    let len = build_query(&mut buf, id, &n, qtype, 1, true, edns).unwrap();
    buf[..len].to_vec()
}

/// An upstream answer with A records at the given TTLs, carrying an upstream OPT + EDE.
fn upstream_a(q: &Query<'_>, ttls: &[u32]) -> Vec<u8> {
    let mut out = [0u8; 1500];
    let mut b = ResponseBuilder::new(q, &mut out, rcode::NOERROR).unwrap();
    for (i, t) in ttls.iter().enumerate() {
        b.answer_a(*t, Ipv4Addr::new(192, 0, 2, i as u8)).unwrap();
    }
    let opt = EdnsOut {
        udp_payload: 4096,
        dnssec_ok: false,
        ede: Some((ede::OTHER, "from upstream")),
    };
    let len = b.finish(Some(opt)).unwrap();
    let mut v = out[..len].to_vec();
    v[0] = 0x55; // upstream ID differs from the client's
    v
}

fn upstream_negative(q: &Query<'_>, rc: u16, soa_ttl: Option<u32>) -> Vec<u8> {
    let mut out = [0u8; 512];
    let mut b = ResponseBuilder::new(q, &mut out, rc).unwrap();
    if let Some(t) = soa_ttl {
        b.authority_soa(t).unwrap();
    }
    let len = b.finish(None).unwrap();
    out[..len].to_vec()
}

fn key(q: &Query<'_>) -> CacheKey {
    CacheKey::new(q, q.qname.hash64(SEED), 0)
}

fn answer_ttls(resp: &[u8]) -> Vec<u32> {
    records(resp)
        .unwrap()
        .map(Result::unwrap)
        .filter(|r| !r.is_opt())
        .map(|r| ttl_at(resp, r.ttl_off).unwrap())
        .collect()
}

#[test]
fn dns_006_hit_rewrites_id_case_and_counts_down_ttls() {
    let cache = Cache::new(CachePolicy::default());
    let t0 = Instant::now();
    let msg = query_bytes("cdn.example.com", rtype::A, Some(EdnsOut::new(1232)), 1);
    let q = parse_query(&msg).unwrap();
    cache
        .insert(&key(&q), &q, &upstream_a(&q, &[300, 60]), t0)
        .unwrap();

    // A different client asks with 0x20 mixed case and a different ID.
    let mut msg2 = query_bytes(
        "cdn.example.com",
        rtype::A,
        Some(EdnsOut::new(1232)),
        0xBEEF,
    );
    msg2[13] = b'C';
    let q2 = parse_query(&msg2).unwrap();
    let mut out = [0u8; 1500];
    let client = Client::from_query(&q2, Some(EdnsOut::new(1232)));
    let Lookup::Hit { len, prefetch } = cache.get(
        &key(&q2),
        &q2.qname,
        &client,
        t0 + Duration::from_secs(20),
        &mut out,
    ) else {
        panic!("expected hit");
    };
    assert!(!prefetch);
    let resp = &out[..len];
    assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0xBEEF);
    assert_eq!(resp[13], b'C', "client's question case echoed");
    assert_eq!(answer_ttls(resp), vec![280, 40]);
    let s = summarize(resp).unwrap();
    assert_eq!(s.answers, 2);
    // Upstream OPT (4096, EDE "from upstream") replaced by ours (1232, no EDE).
    let opt = records(resp)
        .unwrap()
        .map(Result::unwrap)
        .find(telltale_proto::Record::is_opt)
        .unwrap();
    assert_eq!(opt.rclass, 1232);
    assert_eq!(opt.rdlen, 0);

    // Non-EDNS client: no OPT at all.
    let msg3 = query_bytes("cdn.example.com", rtype::A, Some(EdnsOut::new(1232)), 3);
    let q3 = parse_query(&msg3).unwrap();
    let client = Client::from_query(&q3, None);
    let Lookup::Hit { len, .. } = cache.get(&key(&q3), &q3.qname, &client, t0, &mut out) else {
        panic!()
    };
    assert!(summarize(&out[..len]).unwrap().opt_off.is_none());
}

#[test]
fn dns_006_key_separates_do_bit_and_view() {
    let cache = Cache::new(CachePolicy::default());
    let t0 = Instant::now();
    let msg = query_bytes("example.com", rtype::A, None, 1);
    let q = parse_query(&msg).unwrap();
    cache
        .insert(&key(&q), &q, &upstream_a(&q, &[300]), t0)
        .unwrap();

    let mut d = EdnsOut::new(1232);
    d.dnssec_ok = true;
    let msg_do = query_bytes("example.com", rtype::A, Some(d), 2);
    let q_do = parse_query(&msg_do).unwrap();
    let mut out = [0u8; 1500];
    let c = Client::from_query(&q_do, None);
    assert_eq!(
        cache.get(&key(&q_do), &q_do.qname, &c, t0, &mut out),
        Lookup::Miss
    );

    let view1 = CacheKey::new(&q, q.qname.hash64(SEED), 1);
    let c = Client::from_query(&q, None);
    assert_eq!(cache.get(&view1, &q.qname, &c, t0, &mut out), Lookup::Miss);
}

#[test]
fn dns_006_hash_collision_is_a_miss_not_a_wrong_answer() {
    let cache = Cache::new(CachePolicy::default());
    let t0 = Instant::now();
    let a = query_bytes("a.example", rtype::A, None, 1);
    let qa = parse_query(&a).unwrap();
    let b = query_bytes("b.example", rtype::A, None, 1);
    let qb = parse_query(&b).unwrap();
    // Force identical keys for different names.
    let ka = CacheKey::new(&qa, 42, 0);
    let kb = CacheKey::new(&qb, 42, 0);
    assert_eq!(ka, kb);
    cache
        .insert(&ka, &qa, &upstream_a(&qa, &[300]), t0)
        .unwrap();
    let mut out = [0u8; 1500];
    let c = Client::from_query(&qb, None);
    assert_eq!(cache.get(&kb, &qb.qname, &c, t0, &mut out), Lookup::Miss);
}

#[test]
fn dns_006_ttl_clamps() {
    let policy = CachePolicy {
        min_ttl: 60,
        max_ttl: 600,
        ..CachePolicy::default()
    };
    let cache = Cache::new(policy);
    let t0 = Instant::now();
    let msg = query_bytes("example.com", rtype::A, None, 1);
    let q = parse_query(&msg).unwrap();
    cache
        .insert(&key(&q), &q, &upstream_a(&q, &[5, 999_999]), t0)
        .unwrap();
    let mut out = [0u8; 1500];
    let c = Client::from_query(&q, None);
    let Lookup::Hit { len, .. } = cache.get(&key(&q), &q.qname, &c, t0, &mut out) else {
        panic!()
    };
    assert_eq!(answer_ttls(&out[..len]), vec![60, 600]);
    // Entry lifetime follows the clamped minimum (60 s).
    assert!(matches!(
        cache.get(
            &key(&q),
            &q.qname,
            &c,
            t0 + Duration::from_secs(59),
            &mut out
        ),
        Lookup::Hit { .. }
    ));
    assert_eq!(
        cache.get(
            &key(&q),
            &q.qname,
            &c,
            t0 + Duration::from_secs(61),
            &mut out
        ),
        Lookup::Expired
    );
}

#[test]
fn dns_006_negative_and_servfail_caching() {
    let cache = Cache::new(CachePolicy::default());
    let t0 = Instant::now();
    let msg = query_bytes("nope.example", rtype::A, None, 1);
    let q = parse_query(&msg).unwrap();

    // RFC 2308: negative answers without SOA are not cached.
    assert_eq!(
        cache.insert(
            &key(&q),
            &q,
            &upstream_negative(&q, rcode::NXDOMAIN, None),
            t0
        ),
        Err(Uncacheable::NegativeWithoutSoa)
    );
    // With SOA: cached for min(SOA ttl, minimum, negative_ttl_max).
    cache
        .insert(
            &key(&q),
            &q,
            &upstream_negative(&q, rcode::NXDOMAIN, Some(120)),
            t0,
        )
        .unwrap();
    let mut out = [0u8; 512];
    let c = Client::from_query(&q, None);
    let Lookup::Hit { len, .. } = cache.get(
        &key(&q),
        &q.qname,
        &c,
        t0 + Duration::from_secs(100),
        &mut out,
    ) else {
        panic!()
    };
    assert_eq!(summarize(&out[..len]).unwrap().rcode, rcode::NXDOMAIN);
    assert_eq!(
        cache.get(
            &key(&q),
            &q.qname,
            &c,
            t0 + Duration::from_secs(121),
            &mut out
        ),
        Lookup::Expired
    );

    // RFC 9520: SERVFAIL cached briefly (5 s default).
    let sf = query_bytes("broken.example", rtype::A, None, 1);
    let qs = parse_query(&sf).unwrap();
    cache
        .insert(
            &key(&qs),
            &qs,
            &upstream_negative(&qs, rcode::SERVFAIL, None),
            t0,
        )
        .unwrap();
    let c = Client::from_query(&qs, None);
    assert!(matches!(
        cache.get(
            &key(&qs),
            &qs.qname,
            &c,
            t0 + Duration::from_secs(4),
            &mut out
        ),
        Lookup::Hit { .. }
    ));
    assert_eq!(
        cache.get(
            &key(&qs),
            &qs.qname,
            &c,
            t0 + Duration::from_secs(6),
            &mut out
        ),
        Lookup::Expired
    );

    // REFUSED and truncated answers are never cached.
    assert_eq!(
        cache.insert(
            &key(&q),
            &q,
            &upstream_negative(&q, rcode::REFUSED, Some(60)),
            t0
        ),
        Err(Uncacheable::Rcode(rcode::REFUSED))
    );
    let mut tc = upstream_a(&q, &[60]);
    tc[2] |= 0x02;
    assert_eq!(
        cache.insert(&key(&q), &q, &tc, t0),
        Err(Uncacheable::Truncated)
    );
}

#[test]
fn dns_006_rejects_mismatched_question() {
    let cache = Cache::new(CachePolicy::default());
    let a = query_bytes("asked.example", rtype::A, None, 1);
    let qa = parse_query(&a).unwrap();
    let b = query_bytes("other.example", rtype::A, None, 1);
    let qb = parse_query(&b).unwrap();
    let resp_for_b = upstream_a(&qb, &[300]);
    assert_eq!(
        cache.insert(&key(&qa), &qa, &resp_for_b, Instant::now()),
        Err(Uncacheable::QuestionMismatch)
    );
}

#[test]
fn dns_007_serve_stale_window() {
    let policy = CachePolicy {
        stale_max_age: 100,
        ..CachePolicy::default()
    };
    let cache = Cache::new(policy);
    let t0 = Instant::now();
    let msg = query_bytes("stale.example", rtype::A, Some(EdnsOut::new(1232)), 1);
    let q = parse_query(&msg).unwrap();
    cache
        .insert(&key(&q), &q, &upstream_a(&q, &[60]), t0)
        .unwrap();
    let mut out = [0u8; 1500];
    let edns = EdnsOut {
        udp_payload: 1232,
        dnssec_ok: false,
        ede: Some((ede::STALE_ANSWER, "")),
    };
    let c = Client::from_query(&q, Some(edns));
    let t = t0 + Duration::from_secs(90);
    assert_eq!(
        cache.get(&key(&q), &q.qname, &c, t, &mut out),
        Lookup::Expired
    );
    let len = cache
        .get_stale(&key(&q), &q.qname, &c, t, &mut out)
        .unwrap();
    assert_eq!(
        answer_ttls(&out[..len]),
        vec![30],
        "RFC 8767: stale TTL 30 s"
    );
    assert!(
        out[..len]
            .windows(2)
            .any(|w| w == ede::STALE_ANSWER.to_be_bytes())
    );
    // Beyond the stale window: gone.
    let late = t0 + Duration::from_secs(161);
    assert!(
        cache
            .get_stale(&key(&q), &q.qname, &c, late, &mut out)
            .is_none()
    );
    assert_eq!(
        cache.get(&key(&q), &q.qname, &c, late, &mut out),
        Lookup::Miss
    );
}

#[test]
fn dns_008_prefetch_signal_fires_once_when_hot_and_near_expiry() {
    let cache = Cache::new(CachePolicy::default());
    let t0 = Instant::now();
    let msg = query_bytes("hot.example", rtype::A, None, 1);
    let q = parse_query(&msg).unwrap();
    cache
        .insert(&key(&q), &q, &upstream_a(&q, &[100]), t0)
        .unwrap();
    let c = Client::from_query(&q, None);
    let get = |secs| {
        cache.get(
            &key(&q),
            &q.qname,
            &c,
            t0 + Duration::from_secs(secs),
            &mut [0u8; 1500],
        )
    };
    // Hot but far from expiry: no prefetch.
    for _ in 0..3 {
        assert!(matches!(
            get(10),
            Lookup::Hit {
                prefetch: false,
                ..
            }
        ));
    }
    assert!(
        matches!(get(95), Lookup::Hit { prefetch: true, .. }),
        "hot + <10% TTL left"
    );
    assert!(
        matches!(
            get(96),
            Lookup::Hit {
                prefetch: false,
                ..
            }
        ),
        "only once"
    );
}

#[test]
fn dns_008_cold_entries_are_not_prefetched() {
    let cache = Cache::new(CachePolicy::default());
    let t0 = Instant::now();
    let msg = query_bytes("cold.example", rtype::A, None, 1);
    let q = parse_query(&msg).unwrap();
    cache
        .insert(&key(&q), &q, &upstream_a(&q, &[100]), t0)
        .unwrap();
    let c = Client::from_query(&q, None);
    let r = cache.get(
        &key(&q),
        &q.qname,
        &c,
        t0 + Duration::from_secs(95),
        &mut [0u8; 1500],
    );
    assert!(matches!(
        r,
        Lookup::Hit {
            prefetch: false,
            ..
        }
    ));
}

#[test]
fn dns_006_flush_by_name_and_subtree() {
    let cache = Cache::new(CachePolicy::default());
    let t0 = Instant::now();
    for n in [
        "a.example.com",
        "b.example.com",
        "example.com",
        "example.net",
    ] {
        let m = query_bytes(n, rtype::A, None, 1);
        let q = parse_query(&m).unwrap();
        cache
            .insert(&key(&q), &q, &upstream_a(&q, &[300]), t0)
            .unwrap();
    }
    let ex = NameBuf::from_presentation("example.com").unwrap();
    assert_eq!(cache.flush_name(&ex, false), 1);
    assert_eq!(cache.flush_name(&ex, true), 2);
    assert_eq!(cache.stats().entries, 1);
    cache.flush_all();
    assert_eq!(cache.stats().entries, 0);
}

#[test]
fn dns_006_byte_budget_is_respected() {
    let policy = CachePolicy {
        max_bytes: 64 * 1024,
        shards: 4,
        ..CachePolicy::default()
    };
    let cache = Cache::new(policy);
    let t0 = Instant::now();
    for i in 0..5000 {
        let m = query_bytes(&format!("host{i}.example.com"), rtype::A, None, 1);
        let q = parse_query(&m).unwrap();
        cache
            .insert(&key(&q), &q, &upstream_a(&q, &[300]), t0)
            .unwrap();
    }
    let s = cache.stats();
    assert!(s.bytes <= 64 * 1024, "{} bytes", s.bytes);
    assert!(s.evictions > 0);
}

#[tokio::test]
async fn dns_006_singleflight_coalesces_identical_misses() {
    let sf = Singleflight::new();
    let msg = query_bytes("example.com", rtype::A, None, 1);
    let q = parse_query(&msg).unwrap();
    let k = key(&q);
    let Flight::Leader(guard) = sf.join(k, q.qname.as_wire()) else {
        panic!("first is leader")
    };
    let Flight::Follower(rx) = sf.join(k, q.qname.as_wire()) else {
        panic!("second follows")
    };
    let waiter = tokio::spawn(Flight::wait(rx));
    guard.complete(Arc::from(&b"answer"[..]));
    assert_eq!(waiter.await.unwrap().as_deref(), Some(&b"answer"[..]));
    assert!(sf.is_empty());

    // A leader that gives up releases followers with None.
    let Flight::Leader(guard) = sf.join(k, q.qname.as_wire()) else {
        panic!()
    };
    let Flight::Follower(rx) = sf.join(k, q.qname.as_wire()) else {
        panic!()
    };
    drop(guard);
    assert_eq!(Flight::wait(rx).await, None);
}
