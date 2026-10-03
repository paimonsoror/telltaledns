//! NFR-002: zero heap allocations on the steady-state cache-hit and blocked-answer paths.
//!
//! Its own test binary (one test) so no other test's allocations are counted.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use telltale_cache::{Cache, CacheKey, CachePolicy, Client, Lookup};
use telltale_proto::{
    EdnsOut, NameBuf, ResponseBuilder, build_query, ede, parse_query, rcode, response_edns, rtype,
};

#[test]
fn nfr_002_cache_hit_and_blocked_paths_do_not_allocate() {
    let cache = Cache::new(CachePolicy::default());
    let t0 = Instant::now();
    let seed = 7;

    // Warm the cache with 1000 names.
    let mut queries = Vec::new();
    for i in 0..1000u32 {
        let mut buf = [0u8; 512];
        let n = NameBuf::from_presentation(&format!("host{i}.example.com")).unwrap();
        let len =
            build_query(&mut buf, 1, &n, rtype::A, 1, true, Some(EdnsOut::new(1232))).unwrap();
        let msg = buf[..len].to_vec();
        let q = parse_query(&msg).unwrap();
        let mut out = [0u8; 512];
        let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
        b.answer_a(300, Ipv4Addr::new(192, 0, 2, (i % 250) as u8))
            .unwrap();
        let rlen = b.finish(None).unwrap();
        cache
            .insert(
                &CacheKey::new(&q, q.qname.hash64(seed), 0),
                &q,
                &out[..rlen],
                t0,
            )
            .unwrap();
        queries.push(msg);
    }

    let mut out = [0u8; 1500];
    let now = t0 + Duration::from_secs(5);
    let info = allocation_counter::measure(|| {
        for i in 0..100_000usize {
            let msg = &queries[i % queries.len()];
            // Full hot path as the pipeline runs it: parse → hash → key → cache hit.
            let q = parse_query(msg).unwrap();
            let key = CacheKey::new(&q, q.qname.hash64(seed), 0);
            let client = Client::from_query(&q, response_edns(&q, 1232, None));
            assert!(matches!(
                cache.get(&key, &q.qname, &client, now, &mut out),
                Lookup::Hit { .. }
            ));
        }
        for i in 0..100_000usize {
            // Blocked-answer synthesis (null IP + EDE).
            let q = parse_query(&queries[i % queries.len()]).unwrap();
            let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
            b.answer_a(10, Ipv4Addr::UNSPECIFIED).unwrap();
            let edns = response_edns(&q, 1232, Some((ede::BLOCKED, "blocked by list#1")));
            b.finish(edns).unwrap();
        }
    });
    assert_eq!(info.count_total, 0, "hot paths allocated: {info:?}");
}
