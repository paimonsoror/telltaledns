//! Full cache-hit path: parse → hash → key → shard lock → copy + patch → OPT.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation, missing_docs)]

use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use telltale_cache::{Cache, CacheKey, CachePolicy, Client, Lookup};
use telltale_proto::{
    EdnsOut, NameBuf, ResponseBuilder, build_query, parse_query, rcode, response_edns, rtype,
};

fn setup(n: u32) -> (Arc<Cache>, Vec<Vec<u8>>, Instant) {
    let cache = Arc::new(Cache::new(CachePolicy::default()));
    let t0 = Instant::now();
    let mut qs = Vec::new();
    for i in 0..n {
        let mut buf = [0u8; 512];
        let name = NameBuf::from_presentation(&format!("host{i}.example.com")).unwrap();
        let len = build_query(
            &mut buf,
            1,
            &name,
            rtype::A,
            1,
            true,
            Some(EdnsOut::new(1232)),
        )
        .unwrap();
        let msg = buf[..len].to_vec();
        let q = parse_query(&msg).unwrap();
        let mut out = [0u8; 512];
        let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
        for j in 0..3u8 {
            b.answer_a(300, Ipv4Addr::new(192, 0, 2, j)).unwrap();
        }
        let rlen = b.finish(None).unwrap();
        cache
            .insert(
                &CacheKey::new(&q, q.qname.hash64(1), 0),
                &q,
                &out[..rlen],
                t0,
            )
            .unwrap();
        qs.push(msg);
    }
    (cache, qs, t0)
}

fn hit(cache: &Cache, msg: &[u8], now: Instant, out: &mut [u8]) -> usize {
    let q = parse_query(msg).unwrap();
    let key = CacheKey::new(&q, q.qname.hash64(1), 0);
    let client = Client::from_query(&q, response_edns(&q, 1232, None));
    match cache.get(&key, &q.qname, &client, now, out) {
        Lookup::Hit { len, .. } => len,
        _ => 0,
    }
}

fn bench(c: &mut Criterion) {
    let (cache, qs, t0) = setup(10_000);
    let now = t0 + Duration::from_secs(10);
    let mut g = c.benchmark_group("cache");
    g.throughput(Throughput::Elements(1));
    g.bench_function("hit_single_thread", |b| {
        let mut out = [0u8; 1500];
        let mut i = 0;
        b.iter(|| {
            i = (i + 1) % qs.len();
            black_box(hit(&cache, &qs[i], now, &mut out))
        });
    });
    g.finish();

    // 4 threads hammering shared shards: per-op latency under contention.
    c.bench_function("hit_4_threads_x10k", |b| {
        b.iter(|| {
            std::thread::scope(|s| {
                for t in 0..4 {
                    let (cache, qs) = (&cache, &qs);
                    s.spawn(move || {
                        let mut out = [0u8; 1500];
                        for i in 0..10_000 {
                            black_box(hit(
                                cache,
                                &qs[(i * 7 + t * 2503) % qs.len()],
                                now,
                                &mut out,
                            ));
                        }
                    });
                }
            });
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
