//! NFR-004: query parsing plus every response path a client query can reach.
#![no_main]

use std::net::Ipv4Addr;

use libfuzzer_sys::fuzz_target;
use telltale_proto::{
    QueryError, ResponseBuilder, ede, error_from_raw, parse_query, rcode, response_edns, summarize,
    truncate_for_udp, udp_limit,
};

fuzz_target!(|data: &[u8]| {
    let mut out = [0u8; 4096];
    match parse_query(data) {
        Ok(q) => {
            let _ = q.qname.hash64(1);
            let _ = q.qname.display().to_string();
            if let Some(e) = q.edns {
                for _ in e.iter() {}
                let _ = (e.client_mac(), e.client_subnet(), e.cookie(), e.loop_tag());
            }
            let Ok(mut b) = ResponseBuilder::new(&q, &mut out, rcode::NOERROR) else {
                return;
            };
            let _ = b.answer_a(10, Ipv4Addr::UNSPECIFIED);
            let _ = b.authority_soa(10);
            let edns = response_edns(&q, 1232, Some((ede::BLOCKED, "blocked by fuzz#1")));
            if let Ok(len) = b.finish(edns) {
                // Our own output must always re-parse.
                assert!(summarize(&out[..len]).is_ok(), "synthesized response must parse");
                let limit = udp_limit(q.edns.as_ref(), 1232).min(len.saturating_sub(1)).max(12);
                let n = truncate_for_udp(&mut out, len, limit);
                assert!(n <= len);
            }
        }
        Err(QueryError::Drop) => {}
        Err(_) => {
            if let Some(len) = error_from_raw(data, rcode::FORMERR, &mut out) {
                assert!(summarize(&out[..len]).is_ok(), "error response must parse");
            }
        }
    }
});
