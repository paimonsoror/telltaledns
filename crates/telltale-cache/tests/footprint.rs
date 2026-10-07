//! NFR-002 (T10.2): the cache's live heap per entry, for the `spec/00` §5 RSS gate
//! (1M blocked names + 100k cache entries ≤ 64 MiB).
//!
//! Its own test binary (one test) so no other test's allocations are counted. Run with
//! `--nocapture` to see the numbers.

#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::print_stdout
)]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use telltale_cache::{Cache, CacheKey, CachePolicy, CacheStats};
use telltale_proto::{NameBuf, ResponseBuilder, build_query, parse_query, rcode, rtype};

const ENTRIES: u32 = 100_000;

/// A name like the bench's miss corpus: a unique label under one of 1000 parents.
fn name(i: u32) -> String {
    format!("m{i:x}q7w.host{}.example-domain.com", i % 1000)
}

#[test]
fn nfr_002_cache_heap_per_entry() {
    let policy = CachePolicy {
        max_entries: 0,
        max_bytes: usize::MAX / 4,
        ..CachePolicy::default()
    };
    let cache = Cache::new(policy);
    let t0 = Instant::now();
    let mut wire_bytes = 0usize;
    let info = allocation_counter::measure(|| {
        for i in 0..ENTRIES {
            let mut buf = [0u8; 512];
            let n = NameBuf::from_presentation(&name(i)).unwrap();
            let qtype = if i % 3 == 0 { rtype::AAAA } else { rtype::A };
            let len = build_query(&mut buf, 1, &n, qtype, 1, true, None).unwrap();
            let q = parse_query(&buf[..len]).unwrap();
            let mut out = [0u8; 512];
            let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
            if qtype == rtype::A {
                b.answer_a(300, Ipv4Addr::new(192, 0, 2, (i % 250) as u8))
                    .unwrap();
            } else {
                b.answer_aaaa(300, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i as u16))
                    .unwrap();
            }
            let rlen = b.finish(None).unwrap();
            wire_bytes += rlen;
            cache
                .insert(
                    &CacheKey::new(&q, q.qname.hash64(7), 0),
                    &q,
                    &out[..rlen],
                    t0,
                )
                .unwrap();
        }
    });
    let CacheStats { entries, bytes, .. } = cache.stats();
    assert_eq!(entries, ENTRIES as usize);
    let live = usize::try_from(info.bytes_current).unwrap();
    let per_entry = live / entries;
    println!(
        "{entries} entries: {} KiB live heap, {per_entry} B per entry ({} B of answer), budget counts {} B per entry",
        live / 1024,
        wire_bytes / entries,
        bytes / entries,
    );
    // The byte budget (`[cache] max_bytes`) must not undercount real memory by much.
    assert!(
        bytes * 5 >= live * 4,
        "the budget counts {} B per entry, the heap holds {per_entry}",
        bytes / entries
    );
    assert!(
        per_entry <= 288,
        "{per_entry} B per entry (260 measured 2026-10-07)"
    );
}
