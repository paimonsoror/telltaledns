//! ADR-002 differential fuzz: when both telltale-proto and hickory-proto accept a query, they
//! must agree on header, question, and EDNS.
#![no_main]

use hickory_proto::op::{Message, MessageType};
use hickory_proto::serialize::binary::BinEncodable;
use libfuzzer_sys::fuzz_target;
use telltale_proto::parse_query;

fuzz_target!(|data: &[u8]| {
    let Ok(ours) = parse_query(data) else { return };
    let Ok(theirs) = Message::from_vec(data) else { return };
    if theirs.metadata.message_type != MessageType::Query || theirs.queries.len() != 1 {
        return;
    }
    assert_eq!(ours.header.id, theirs.metadata.id);
    assert_eq!(ours.header.flags.rd(), theirs.metadata.recursion_desired);
    assert_eq!(ours.header.flags.cd(), theirs.metadata.checking_disabled);

    let q = &theirs.queries[0];
    let their_name = q.name.to_lowercase().to_bytes().unwrap_or_default();
    assert_eq!(ours.qname.as_wire(), &their_name[..], "qname");
    assert_eq!(ours.qtype, u16::from(q.query_type), "qtype");
    assert_eq!(ours.qclass, u16::from(q.query_class), "qclass");

    match (ours.edns, theirs.edns.as_ref()) {
        (Some(a), Some(b)) => {
            assert_eq!(a.udp_payload, b.max_payload(), "udp payload");
            assert_eq!(a.dnssec_ok, b.flags().dnssec_ok, "DO bit");
            assert_eq!(a.version, b.version(), "EDNS version");
        }
        (None, None) => {}
        (a, b) => panic!("EDNS presence differs: ours={a:?} theirs={b:?}"),
    }
});
