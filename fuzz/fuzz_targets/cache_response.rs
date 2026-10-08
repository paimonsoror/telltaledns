//! NFR-004 (review 01-11): an arbitrary upstream response, as an answer to a fixed valid query,
//! through the cache's render, insert, and get, and the UDP truncation. Nothing may panic, and
//! whatever comes out must parse again: the class of bug 01-05 was (an OPT outside the
//! additional section underflowed a count) lived here, where `parse_response` never reaches.
#![no_main]

use std::time::Instant;

use libfuzzer_sys::fuzz_target;
use telltale_cache::{Cache, CacheKey, CachePolicy, Client, Lookup};
use telltale_proto::{
    EdnsOut, NameBuf, build_query, parse_query, response_edns, rtype, summarize, truncate_for_udp,
};

fn reparses(msg: &[u8], what: &str) {
    assert!(summarize(msg).is_ok(), "{what} produced a message that does not parse");
}

fuzz_target!(|data: &[u8]| {
    let name = NameBuf::from_presentation("fuzz.example.com").expect("a valid name");
    let mut qbuf = [0u8; 512];
    let Ok(len) = build_query(
        &mut qbuf,
        7,
        &name,
        rtype::A,
        1,
        true,
        Some(EdnsOut::new(1232)),
    ) else {
        return;
    };
    let Ok(q) = parse_query(&qbuf[..len]) else {
        return;
    };
    let client = Client::from_query(&q, response_edns(&q, 1232, None));
    let mut out = vec![0u8; 4096];

    if let Some(n) = Cache::render(&q, data, &client, &mut out) {
        reparses(&out[..n], "render");
    }

    let cache = Cache::new(CachePolicy::default());
    let key = CacheKey::new(&q, q.qname.hash64(1), 0);
    if cache.insert(&key, &q, data, Instant::now()).is_ok() {
        if let Lookup::Hit { len, .. } = cache.get(&key, &q.qname, &client, Instant::now(), &mut out)
        {
            reparses(&out[..len], "get");
            let cut = truncate_for_udp(&mut out, len, 512);
            reparses(&out[..cut], "truncate_for_udp");
        }
    }
});
