//! T1.1 acceptance: proptest round-trips, differential tests against hickory-proto
//! (ADR-002: both parsers must agree on header, question, and EDNS), and validity of every
//! synthesized response as judged by hickory.

// Test helpers outside #[test] fns may unwrap; terse names mirror the RFC field names.
#![allow(
    clippy::unwrap_used,
    clippy::many_single_char_names,
    clippy::assert_is_empty
)]

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Edns as HEdns, Message, MessageType, OpCode, Query as HQuery};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use proptest::prelude::*;
use telltale_proto::{
    EdnsOut, NameBuf, ResponseBuilder, build_query, ede, error_from_raw, parse_query, patch_ttls,
    rcode, records, response_edns, rtype, summarize, truncate_for_udp, ttl_at,
};

// ---------- strategies ----------

fn label() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_-]{1,20}"
}

fn name() -> impl Strategy<Value = String> {
    prop::collection::vec(label(), 1..6).prop_map(|v| v.join("."))
}

/// Hostname-shaped names for the hickory differential (hickory rejects a leading `-`).
fn host_name() -> impl Strategy<Value = String> {
    prop::collection::vec("[a-zA-Z0-9][a-zA-Z0-9_-]{0,19}", 1..6).prop_map(|v| v.join("."))
}

fn edns_params() -> impl Strategy<Value = Option<(u16, bool)>> {
    prop::option::of((512u16..=4096, any::<bool>()))
}

fn build(
    name: &str,
    id: u16,
    qtype: u16,
    qclass: u16,
    rd: bool,
    e: Option<(u16, bool)>,
) -> Vec<u8> {
    let n = NameBuf::from_presentation(name).unwrap();
    let edns = e.map(|(p, d)| EdnsOut {
        udp_payload: p,
        dnssec_ok: d,
        ede: None,
    });
    let mut buf = [0u8; 600];
    let len = build_query(&mut buf, id, &n, qtype, qclass, rd, edns).unwrap();
    buf[..len].to_vec()
}

fn hickory_query(name: &str, id: u16, qtype: u16, rd: bool, e: Option<(u16, bool)>) -> Vec<u8> {
    let mut m = Message::new(id, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = rd;
    m.add_query(HQuery::query(
        Name::from_ascii(name).unwrap(),
        RecordType::from(qtype),
    ));
    if let Some((payload, dnssec_ok)) = e {
        let mut edns = HEdns::new();
        edns.set_max_payload(payload);
        edns.set_dnssec_ok(dnssec_ok);
        m.set_edns(edns);
    }
    m.to_vec().unwrap()
}

// ---------- round-trips ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn dns_005_query_roundtrip(
        n in name(), id in any::<u16>(), qtype in any::<u16>(), qclass in any::<u16>(),
        rd in any::<bool>(), e in edns_params(),
    ) {
        let msg = build(&n, id, qtype, qclass, rd, e);
        let q = parse_query(&msg).unwrap();
        prop_assert_eq!(q.header.id, id);
        prop_assert_eq!(q.header.flags.rd(), rd);
        prop_assert_eq!(q.qname.display().to_string(), n.to_ascii_lowercase());
        prop_assert_eq!(q.qtype, qtype);
        prop_assert_eq!(q.qclass, qclass);
        prop_assert_eq!(q.edns.map(|e| (e.udp_payload, e.dnssec_ok)), e);
        // Question bytes are echoed with the client's original case.
        prop_assert_eq!(&q.question_bytes()[1..2], &msg[13..14]);
    }

    #[test]
    fn dns_005_differential_hickory_to_telltale(
        n in host_name(), id in any::<u16>(), qtype in 1u16..=300, rd in any::<bool>(), e in edns_params(),
    ) {
        let msg = hickory_query(&n, id, qtype, rd, e);
        let q = parse_query(&msg).unwrap();
        prop_assert_eq!(q.header.id, id);
        prop_assert_eq!(q.header.flags.rd(), rd);
        prop_assert_eq!(q.qname.display().to_string(), n.to_ascii_lowercase());
        prop_assert_eq!(q.qtype, qtype);
        prop_assert_eq!(q.qclass, 1);
        prop_assert_eq!(q.edns.map(|e| (e.udp_payload, e.dnssec_ok)), e);
    }

    #[test]
    fn dns_005_differential_telltale_to_hickory(
        n in host_name(), id in any::<u16>(), qtype in 1u16..=300, rd in any::<bool>(), e in edns_params(),
    ) {
        let msg = build(&n, id, qtype, 1, rd, e);
        let m = Message::from_vec(&msg).unwrap();
        prop_assert_eq!(m.metadata.id, id);
        prop_assert_eq!(m.metadata.recursion_desired, rd);
        let hq = &m.queries[0];
        let hname = hq.name.to_lowercase().to_ascii();
        prop_assert_eq!(hname.trim_end_matches('.'), n.to_ascii_lowercase());
        prop_assert_eq!(u16::from(hq.query_type), qtype);
        prop_assert_eq!(hq.query_class, DNSClass::IN);
        let he = m.edns.as_ref().map(|x| (x.max_payload(), x.flags().dnssec_ok));
        prop_assert_eq!(he, e);
    }

    /// DNS-019: arbitrary input never panics any entry point.
    #[test]
    fn dns_019_arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..600)) {
        let _ = parse_query(&bytes);
        let _ = summarize(&bytes);
        if let Ok(it) = records(&bytes) { for _ in it {} }
        let mut out = [0u8; 700];
        let _ = error_from_raw(&bytes, rcode::FORMERR, &mut out);
        let mut copy = bytes.clone();
        let len = copy.len();
        let _ = truncate_for_udp(&mut copy, len, 64);
    }

    /// Valid queries with random bit flips never panic and either parse or reject cleanly.
    #[test]
    fn dns_019_mutated_queries_never_panic(
        n in name(), flips in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
    ) {
        let mut msg = build(&n, 1, 1, 1, true, Some((1232, false)));
        for (i, b) in flips {
            let at = i.index(msg.len());
            msg[at] ^= b;
        }
        let _ = parse_query(&msg);
        let mut out = [0u8; 700];
        let _ = error_from_raw(&msg, rcode::FORMERR, &mut out);
    }
}

// ---------- synthesis validated by hickory ----------

fn query(name: &str, qtype: u16, edns: bool) -> Vec<u8> {
    build(name, 0xABCD, qtype, 1, true, edns.then_some((1232, true)))
}

#[test]
fn flt_008_blocked_a_and_aaaa_null_answers() {
    let mut msg = query("ads.example.com", rtype::A, true);
    msg[13] = b'A'; // a 0x20-randomizing client sends mixed case
    let q = parse_query(&msg).unwrap();
    assert_eq!(q.qname.display().to_string(), "ads.example.com");
    let mut out = [0u8; 512];
    let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
    b.answer_a(10, Ipv4Addr::UNSPECIFIED).unwrap();
    let edns = response_edns(&q, 1232, Some((ede::BLOCKED, "blocked by oisd#42")));
    let len = b.finish(edns).unwrap();

    let m = Message::from_vec(&out[..len]).unwrap();
    assert_eq!(m.metadata.id, 0xABCD);
    assert_eq!(m.metadata.message_type, MessageType::Response);
    assert!(m.metadata.recursion_available && m.metadata.recursion_desired);
    // hickory lowercases on decode, so check the raw question bytes.
    assert_eq!(
        &out[13..16],
        b"Ads",
        "question echoed with the client's case"
    );
    assert_eq!(m.answers.len(), 1);
    assert_eq!(m.answers[0].ttl, 10);
    assert!(matches!(&m.answers[0].data, RData::A(a) if a.0 == Ipv4Addr::UNSPECIFIED));
    let e = m.edns.as_ref().unwrap();
    assert!(e.flags().dnssec_ok, "DO bit echoed");
    // EDE option: code 15, info-code BLOCKED + text.
    let raw = &out[..len];
    let pos = raw
        .windows(4)
        .position(|w| w == [0x00, 0x0F, 0x00, 0x14])
        .expect("EDE option present");
    assert_eq!(&raw[pos + 4..pos + 6], &ede::BLOCKED.to_be_bytes());
    assert_eq!(&raw[pos + 6..pos + 24], b"blocked by oisd#42");

    let msg = query("ads.example.com", rtype::AAAA, false);
    let q = parse_query(&msg).unwrap();
    let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
    b.answer_aaaa(10, Ipv6Addr::UNSPECIFIED).unwrap();
    let len = b
        .finish(response_edns(&q, 1232, Some((ede::BLOCKED, "x"))))
        .unwrap();
    let m = Message::from_vec(&out[..len]).unwrap();
    assert!(m.edns.is_none(), "no OPT for a non-EDNS client");
    assert!(matches!(&m.answers[0].data, RData::AAAA(a) if a.0 == Ipv6Addr::UNSPECIFIED));
}

#[test]
fn flt_008_nxdomain_and_nodata_with_soa() {
    for rc in [rcode::NXDOMAIN, rcode::NOERROR] {
        let msg = query("tracker.example", rtype::HTTPS, true);
        let q = parse_query(&msg).unwrap();
        let mut out = [0u8; 512];
        let mut b = ResponseBuilder::new(&q, &mut out, rc).unwrap();
        b.authority_soa(10).unwrap();
        let len = b.finish(response_edns(&q, 1232, None)).unwrap();
        let m = Message::from_vec(&out[..len]).unwrap();
        assert_eq!(u16::from(m.metadata.response_code), rc);
        assert!(m.answers.is_empty());
        assert_eq!(m.authorities.len(), 1);
        assert!(matches!(&m.authorities[0].data, RData::SOA(s) if s.minimum == 10));
        let s = summarize(&out[..len]).unwrap();
        assert_eq!(s.negative_ttl, Some(10));
        assert_eq!(s.rcode, rc);
    }
}

#[test]
fn dns_019_any_gets_rfc8482_hinfo() {
    let msg = query("example.com", rtype::ANY, false);
    let q = parse_query(&msg).unwrap();
    assert!(q.is_any());
    let mut out = [0u8; 512];
    let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
    b.answer_any_refusal(3600).unwrap();
    let len = b.finish(None).unwrap();
    let m = Message::from_vec(&out[..len]).unwrap();
    assert!(matches!(&m.answers[0].data, RData::HINFO(h) if h.cpu.as_ref() == b"RFC8482"));
}

#[test]
fn dns_005_badvers_uses_extended_rcode() {
    let msg = query("example.com", rtype::A, true);
    let q = parse_query(&msg).unwrap();
    let mut out = [0u8; 512];
    let b = ResponseBuilder::new(&q, &mut out, rcode::BADVERS).unwrap();
    let len = b.finish(Some(EdnsOut::new(1232))).unwrap();
    let s = summarize(&out[..len]).unwrap();
    assert_eq!(s.rcode, rcode::BADVERS);
    let m = Message::from_vec(&out[..len]).unwrap();
    assert_eq!(u16::from(m.metadata.response_code), rcode::BADVERS);
}

#[test]
fn dns_005_truncation_keeps_question_and_opt() {
    let msg = query("big.example.com", rtype::A, true);
    let q = parse_query(&msg).unwrap();
    let mut out = [0u8; 4096];
    let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
    for i in 0..100u8 {
        b.answer_a(300, Ipv4Addr::new(10, 0, 0, i)).unwrap();
    }
    let len = b.finish(response_edns(&q, 1232, None)).unwrap();
    assert!(len > 1232);
    let new_len = truncate_for_udp(&mut out, len, 1232);
    assert!(new_len <= 1232);
    let m = Message::from_vec(&out[..new_len]).unwrap();
    assert!(m.metadata.truncation);
    assert!(m.answers.is_empty());
    assert_eq!(m.queries.len(), 1);
    assert!(m.edns.is_some(), "OPT preserved");

    // Under the limit: untouched.
    assert_eq!(truncate_for_udp(&mut out, 100, 1232), 100);
}

#[test]
fn dns_006_ttl_offsets_and_patching() {
    let msg = query("cdn.example.com", rtype::A, true);
    let q = parse_query(&msg).unwrap();
    let mut out = [0u8; 512];
    let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
    b.answer_a(300, Ipv4Addr::new(192, 0, 2, 1)).unwrap();
    b.answer_a(60, Ipv4Addr::new(192, 0, 2, 2)).unwrap();
    let len = b.finish(response_edns(&q, 1232, None)).unwrap();
    let resp = &mut out[..len];

    let s = summarize(resp).unwrap();
    assert_eq!(s.min_ttl, Some(60));
    let offsets: Vec<u16> = records(resp)
        .unwrap()
        .map(Result::unwrap)
        .filter(|r| !r.is_opt())
        .map(|r| u16::try_from(r.ttl_off).unwrap())
        .collect();
    assert_eq!(offsets.len(), 2, "OPT TTL field is excluded");
    patch_ttls(resp, &offsets, 100, 0);
    assert_eq!(ttl_at(resp, usize::from(offsets[0])), Some(200));
    assert_eq!(
        ttl_at(resp, usize::from(offsets[1])),
        Some(0),
        "saturates at the floor"
    );
    telltale_proto::header::set_id(resp, 0x7777);
    let m = Message::from_vec(resp).unwrap();
    assert_eq!(m.metadata.id, 0x7777);
    assert_eq!(m.answers[0].ttl, 200);
    assert!(m.edns.as_ref().unwrap().flags().dnssec_ok, "OPT untouched");
}

#[test]
fn dns_019_error_from_raw() {
    let msg = query("example.com", rtype::A, false);
    let mut out = [0u8; 512];
    let len = error_from_raw(&msg, rcode::REFUSED, &mut out).unwrap();
    let m = Message::from_vec(&out[..len]).unwrap();
    assert_eq!(u16::from(m.metadata.response_code), rcode::REFUSED);
    assert_eq!(m.queries.len(), 1);

    // Garbage question: header-only FORMERR.
    let mut bad = msg[..12].to_vec();
    bad.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
    let len = error_from_raw(&bad, rcode::FORMERR, &mut out).unwrap();
    assert_eq!(len, 12);
    let m = Message::from_vec(&out[..len]).unwrap();
    assert_eq!(u16::from(m.metadata.response_code), rcode::FORMERR);
    assert!(m.queries.is_empty());

    // Responses and runts get no reply.
    let mut resp = msg.clone();
    resp[2] |= 0x80;
    assert_eq!(error_from_raw(&resp, rcode::FORMERR, &mut out), None);
    assert_eq!(error_from_raw(&msg[..5], rcode::FORMERR, &mut out), None);
}

#[test]
fn flt_007_cname_targets_readable_from_hickory_response() {
    use hickory_proto::rr::{Record as HRecord, rdata::CNAME};
    let mut m = Message::new(1, MessageType::Response, OpCode::Query);
    let owner = Name::from_ascii("www.example.com.").unwrap();
    m.add_query(HQuery::query(owner.clone(), RecordType::A));
    m.add_answer(HRecord::from_rdata(
        owner,
        300,
        RData::CNAME(CNAME(Name::from_ascii("Tracker.Ads.example.net.").unwrap())),
    ));
    let bytes = m.to_vec().unwrap();
    let cname = records(&bytes)
        .unwrap()
        .map(Result::unwrap)
        .find(|r| r.rtype == rtype::CNAME)
        .unwrap();
    let mut target = NameBuf::default();
    telltale_proto::read_name(&bytes, cname.rdata_off, &mut target).unwrap();
    assert_eq!(target.display().to_string(), "tracker.ads.example.net");
}

/// RFC 6891 §6.1.1 — an OPT anywhere but the additional section is a malformed response:
/// the cache strips the OPT as additional data, so counting it elsewhere would leave the
/// stored answer claiming records it doesn't have.
#[test]
fn dns_005_opt_outside_additional_is_malformed() {
    let msg = query("example.com", rtype::A, false);
    let q = parse_query(&msg).unwrap();
    let mut out = [0u8; 512];
    let b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
    let len = b.finish(Some(EdnsOut::new(1232))).unwrap();
    assert!(summarize(&out[..len]).is_ok());
    out[7] = 1; // ANCOUNT = 1: the only record (the OPT) counted as an answer
    out[11] = 0; // ARCOUNT = 0
    assert_eq!(
        summarize(&out[..len]),
        Err(telltale_proto::ParseError::BadOpt)
    );
}
