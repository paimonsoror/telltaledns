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

/// REQ: DNS-006 (T6.13) — inspecting a name lists each cached variant with its TTL and age,
/// without counting as a hit; the counted flush reports how many entries went.
#[test]
fn dns_006_inspect_and_counted_flush() {
    let cache = Cache::new(CachePolicy::default());
    let t0 = Instant::now();
    for (n, t) in [
        ("www.example.com", rtype::A),
        ("www.example.com", rtype::AAAA),
        ("other.example", rtype::A),
    ] {
        let m = query_bytes(n, t, None, 1);
        let q = parse_query(&m).unwrap();
        cache
            .insert(&key(&q), &q, &upstream_a(&q, &[300]), t0)
            .unwrap();
    }
    let name = NameBuf::from_presentation("WWW.Example.com").unwrap();
    let later = t0 + std::time::Duration::from_secs(40);
    let seen = cache.inspect(&name, later);
    assert_eq!(seen.len(), 2, "A and AAAA, not the other name");
    assert_eq!(seen[0].qtype, rtype::A);
    assert_eq!(seen[1].qtype, rtype::AAAA);
    assert!(
        seen.iter()
            .all(|e| e.ttl == 300 && e.age_secs == 40 && e.rcode == 0)
    );
    assert_eq!(cache.stats().hits, 0, "inspection isn't a hit");
    let none = cache.inspect(
        &NameBuf::from_presentation("nothing.example").unwrap(),
        later,
    );
    assert_eq!(none.len(), 0);
    assert_eq!(cache.flush_all_counted(), 3);
    assert_eq!(cache.stats().entries, 0);
}

/// REQ: DNS-006, OBS-003 (T6.15) — the top entries by hits, size, and nearest expiry, bounded
/// by the limit, and the makeup by kind (positive, NXDOMAIN, NODATA, stale) in one pass.
#[test]
fn dns_006_top_entries_and_makeup() {
    use telltale_cache::{Makeup, TopBy};
    let cache = Cache::new(CachePolicy::default());
    let t0 = Instant::now();
    let mut out = [0u8; 512];
    // a: TTL 300, 5 hits; b: TTL 60, 2 hits; c: TTL 600, no hits.
    for (n, ttl, hits) in [
        ("a.example", 300, 5),
        ("b.example", 60, 2),
        ("c.example", 600, 0),
    ] {
        let m = query_bytes(n, rtype::A, None, 1);
        let q = parse_query(&m).unwrap();
        cache
            .insert(&key(&q), &q, &upstream_a(&q, &[ttl]), t0)
            .unwrap();
        let c = Client::from_query(&q, None);
        for _ in 0..hits {
            assert!(matches!(
                cache.get(&key(&q), &q.qname, &c, t0, &mut out),
                Lookup::Hit { .. }
            ));
        }
    }
    let m = query_bytes("gone.example", rtype::A, None, 1);
    let q = parse_query(&m).unwrap();
    cache
        .insert(
            &key(&q),
            &q,
            &upstream_negative(&q, rcode::NXDOMAIN, Some(30)),
            t0,
        )
        .unwrap();
    let hits_before = cache.stats().hits;
    let names = |v: &[telltale_cache::TopEntry]| -> Vec<String> {
        v.iter()
            .map(|e| {
                let mut n = NameBuf::default();
                telltale_proto::read_name_uncompressed(&e.name, 0, &mut n).unwrap();
                n.display().to_string()
            })
            .collect()
    };
    let later = t0 + std::time::Duration::from_secs(45);
    let (top, makeup) = cache.top(TopBy::Hits, 2, later);
    assert_eq!(names(&top), ["a.example", "b.example"]);
    assert_eq!(top[0].info.hits, 5);
    assert_eq!(
        makeup,
        Makeup {
            positive: 3,
            nxdomain: 1,
            nodata: 0,
            servfail: 0,
            stale: 1,
            validated: 0
        },
        "gone.example (NXDOMAIN, TTL 30) is stale at 45 s"
    );
    // Nearest expiry: only fresh entries; b (60 s) before a (300 s) before c (600 s).
    let (top, _) = cache.top(TopBy::Expiring, 10, later);
    assert_eq!(names(&top), ["b.example", "a.example", "c.example"]);
    let (top, _) = cache.top(TopBy::Bytes, 10, later);
    assert_eq!(top.len(), 4);
    assert!(top.windows(2).all(|w| w[0].info.bytes >= w[1].info.bytes));
    // limit 0: the makeup alone.
    let (top, m0) = cache.top(TopBy::Hits, 0, later);
    assert!(top.is_empty() && m0 == makeup);
    assert_eq!(cache.stats().hits, hits_before, "looking isn't a hit");
}

/// REQ: DNS-006 (T6.15) — what a full scan costs: run with
/// `cargo test --release -p telltale-cache --test cache dns_006_top_cost -- --ignored --nocapture`.
#[test]
#[ignore = "timing: run by hand"]
fn dns_006_top_cost() {
    use telltale_cache::TopBy;
    let cache = Cache::new(CachePolicy {
        max_bytes: 256 << 20,
        ..CachePolicy::default()
    });
    let t0 = Instant::now();
    for i in 0..100_000 {
        let m = query_bytes(&format!("host{i}.example.com"), rtype::A, None, 1);
        let q = parse_query(&m).unwrap();
        cache
            .insert(&key(&q), &q, &upstream_a(&q, &[300]), t0)
            .unwrap();
    }
    let entries = cache.stats().entries;
    let start = Instant::now();
    let (top, _) = cache.top(TopBy::Hits, 50, t0);
    let took = start.elapsed();
    println!(
        "top 50 of {entries} entries: {took:?} ({} returned)",
        top.len()
    );
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

/// REQ: DNS-015 (T9.9) — keys scoped to different client subnets never share an entry; an
/// unscoped key is unchanged by `with_ecs(0)`.
#[test]
fn dns_015_ecs_scoped_keys() {
    let req = query_bytes("cdn.example", rtype::A, None, 1);
    let q = parse_query(&req).unwrap();
    let base = CacheKey::new(&q, q.qname.hash64(SEED), 0);
    assert_eq!(base.with_ecs(0), base);
    assert_eq!(base.ecs(), 0);
    let (a, b) = (
        base.with_ecs((1 << 62) | 0xCB_0071),
        base.with_ecs((1 << 62) | 0xCB_0072),
    );
    assert_ne!(a, b);
    assert_ne!(a, base);
    let cache = Cache::new(CachePolicy::default());
    let client = Client::from_query(&q, None);
    let resp = upstream_a(&q, &[300]);
    let now = Instant::now();
    cache.insert(&a, &q, &resp, now).unwrap();
    let mut out = [0u8; 1500];
    assert!(matches!(
        cache.get(&a, &q.qname, &client, now, &mut out),
        Lookup::Hit { .. }
    ));
    assert!(matches!(
        cache.get(&b, &q.qname, &client, now, &mut out),
        Lookup::Miss
    ));
    assert!(matches!(
        cache.get(&base, &q.qname, &client, now, &mut out),
        Lookup::Miss
    ));
}

/// An upstream answer whose only record is an OPT counted as an answer is unusable: neither
/// rendered (it used to come out with ANCOUNT 1, no records, and ARCOUNT underflowed) nor
/// cached.
#[test]
fn dns_006_opt_counted_as_an_answer_is_unusable() {
    let req = query_bytes("opt.example", rtype::A, None, 7);
    let q = parse_query(&req).unwrap();
    let mut resp = [0u8; 512];
    let b = ResponseBuilder::new(&q, &mut resp, rcode::NOERROR).unwrap();
    let len = b.finish(Some(EdnsOut::new(1232))).unwrap();
    resp[7] = 1; // ANCOUNT
    resp[11] = 0; // ARCOUNT
    let client = Client::from_query(&q, None);
    let mut out = [0u8; 512];
    assert!(Cache::render(&q, &resp[..len], &client, &mut out).is_none());
    let cache = Cache::new(CachePolicy::default());
    assert_eq!(
        cache.insert(&key(&q), &q, &resp[..len], Instant::now()),
        Err(Uncacheable::Malformed)
    );
}
