//! Micro-benchmarks for the per-query wire work (NFR-001 budget: <= 250 µs p99 added latency
//! for the *whole* pipeline; the wire layer should cost well under 1 µs).

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation, missing_docs)]

use std::hint::black_box;
use std::net::Ipv4Addr;

use criterion::{Criterion, criterion_group, criterion_main};
use telltale_proto::{
    EdnsOut, NameBuf, ResponseBuilder, build_query, ede, parse_query, patch_ttls, rcode,
    response_edns, rtype,
};

fn query_bytes() -> Vec<u8> {
    let mut buf = [0u8; 512];
    let name = NameBuf::from_presentation("www.googletagmanager.example.com").unwrap();
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
    buf[..len].to_vec()
}

fn bench(c: &mut Criterion) {
    let msg = query_bytes();

    c.bench_function("parse_query+hash", |b| {
        b.iter(|| {
            let q = parse_query(black_box(&msg)).unwrap();
            black_box(q.qname.hash64(0x5eed))
        });
    });

    c.bench_function("blocked_answer_synthesis", |b| {
        let mut out = [0u8; 1232];
        b.iter(|| {
            let q = parse_query(black_box(&msg)).unwrap();
            let mut r = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
            r.answer_a(10, Ipv4Addr::UNSPECIFIED).unwrap();
            let edns = response_edns(&q, 1232, Some((ede::BLOCKED, "blocked by oisd#1234")));
            black_box(r.finish(edns).unwrap())
        });
    });

    c.bench_function("cache_hit_patch", |b| {
        // Simulates a cache hit: copy stored bytes, set ID, patch 3 TTLs.
        let q = parse_query(&msg).unwrap();
        let mut stored = [0u8; 1232];
        let mut r = ResponseBuilder::new(&q, &mut stored, rcode::NOERROR).unwrap();
        for i in 0..3 {
            r.answer_a(300, Ipv4Addr::new(192, 0, 2, i)).unwrap();
        }
        let len = r.finish(Some(EdnsOut::new(1232))).unwrap();
        let offsets: Vec<u16> = telltale_proto::records(&stored[..len])
            .unwrap()
            .filter_map(Result::ok)
            .filter(|r| !r.is_opt())
            .map(|r| r.ttl_off as u16)
            .collect();
        let mut out = [0u8; 1232];
        b.iter(|| {
            out[..len].copy_from_slice(&stored[..len]);
            telltale_proto::header::set_id(&mut out, black_box(0x1234));
            patch_ttls(&mut out, &offsets, black_box(17), 0);
            black_box(&out);
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
