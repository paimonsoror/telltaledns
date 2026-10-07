//! REQ: DNS-011 — DNSSEC validation offline, against a signed test root (T9.24): the root's
//! key is the trust anchor (an anchors file), and a fake upstream serves the zone's records with
//! their signatures, NSEC denials, and one forged signature. Covers the validator's secure,
//! NODATA, NXDOMAIN, bogus, and wrong-anchor paths, and RFC 8198 answering from cached NSEC
//! ranges without another upstream query.

#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_net::proto::dnssec::crypto::Ed25519SigningKey;
use hickory_net::proto::dnssec::rdata::{DNSKEY, DNSSECRData, NSEC, RRSIG};
use hickory_net::proto::dnssec::{DnssecSigner, PublicKey as _, SigningKey};
use hickory_net::proto::op::{Message, OpCode, ResponseCode};
use hickory_net::proto::rr::rdata::{A, NS, SOA};
use hickory_net::proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType};
use telltale_proto::{NameBuf, rtype};
use telltale_upstream::dnssec::{Stats, Validator, Verdict};
use telltale_upstream::{
    Endpoint, Group, Question, Strategy, TlsOptions, Upstream, UpstreamOptions,
};
use tokio::net::UdpSocket;

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

/// The signed test root: record sets with their signatures, by (owner, type).
struct Zone {
    sets: BTreeMap<(Name, RecordType), Vec<Record>>,
    /// The DNSKEY's RDATA, for the anchors file.
    key: Vec<u8>,
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in data.chunks(3) {
        let v = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                s.push(char::from(
                    T[usize::try_from((v >> (18 - 6 * i)) & 63).unwrap()],
                ));
            } else {
                s.push('=');
            }
        }
    }
    s
}

fn zone() -> Zone {
    let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
    let key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
    let public = key.to_public_key().unwrap();
    let dnskey = DNSKEY::new(true, true, false, public.clone());
    let signer = DnssecSigner::new(
        dnskey.clone(),
        Box::new(key),
        n("."),
        Duration::from_hours(24),
    );
    let inception = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    let ttl = 3600;
    let soa = SOA::new(
        n("a.root-servers.test."),
        n("nstld.test."),
        1,
        1800,
        900,
        604_800,
        600,
    );
    let rrsets: Vec<(Name, Vec<RData>)> = vec![
        (n("."), vec![RData::SOA(soa)]),
        (n("."), vec![RData::NS(NS(n("ns.a.")))]),
        (n("."), vec![RData::DNSSEC(DNSSECRData::DNSKEY(dnskey))]),
        (
            n("."),
            vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                n("a."),
                [
                    RecordType::NS,
                    RecordType::SOA,
                    RecordType::RRSIG,
                    RecordType::NSEC,
                    RecordType::DNSKEY,
                ],
            )))],
        ),
        (n("a."), vec![RData::A(A::new(192, 0, 2, 1))]),
        (
            n("a."),
            vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                n("bad."),
                [RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            )))],
        ),
        (n("bad."), vec![RData::A(A::new(192, 0, 2, 66))]),
        (
            n("bad."),
            vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                n("."),
                [RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            )))],
        ),
    ];
    let mut sets = BTreeMap::new();
    for (name, datas) in rrsets {
        let rtype = datas[0].record_type();
        let mut rs = RecordSet::new(name.clone(), rtype, 0);
        let records: Vec<Record> = datas
            .into_iter()
            .map(|d| Record::from_rdata(name.clone(), ttl, d))
            .collect();
        for r in &records {
            rs.insert(r.clone(), 0);
        }
        let mut sig = RRSIG::from_rrset(&rs, DNSClass::IN, inception, &signer).unwrap();
        if name == n("bad.") && rtype == RecordType::A {
            // A forged signature: the record set is bogus.
            let input = sig.input().clone();
            let mut bytes = sig.sig().to_vec();
            bytes[0] ^= 0xff;
            sig = RRSIG::from_sig(input, bytes);
        }
        let mut all = records;
        all.push(Record::from_rdata(
            name.clone(),
            ttl,
            RData::DNSSEC(DNSSECRData::RRSIG(sig)),
        ));
        sets.insert((name, rtype), all);
    }
    let mut key_rdata = vec![1u8, 1, 3, 15]; // flags 257, protocol 3, algorithm 15 (Ed25519)
    key_rdata.extend_from_slice(public.public_bytes());
    Zone {
        sets,
        key: key_rdata,
    }
}

/// The fake root server: answers from the zone (with signatures), NODATA or NXDOMAIN with the
/// SOA and the NSEC records that prove it. Counts the questions it gets.
async fn serve(z: Arc<Zone>, asked: Arc<AtomicUsize>) -> std::net::SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, from)) = s.recv_from(&mut buf).await else {
                return;
            };
            let Ok(q) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let Some(question) = q.queries.first().cloned() else {
                continue;
            };
            asked.fetch_add(1, Ordering::Relaxed);
            let (qn, qt) = (question.name().clone(), question.query_type());
            let mut m = Message::response(q.metadata.id, OpCode::Query);
            m.metadata.recursion_desired = true;
            m.metadata.recursion_available = true;
            m.add_query(question);
            let authority = |m: &mut Message, owner: &Name| {
                m.add_authorities(z.sets[&(n("."), RecordType::SOA)].clone());
                m.add_authorities(z.sets[&(owner.clone(), RecordType::NSEC)].clone());
            };
            if let Some(rs) = z.sets.get(&(qn.clone(), qt)) {
                m.add_answers(rs.clone());
            } else if z.sets.keys().any(|(o, _)| *o == qn) {
                authority(&mut m, &qn);
            } else {
                // NXDOMAIN: the NSEC covering the name (the greatest owner before it), and the
                // root's own NSEC, which covers the wildcard `*.`.
                m.metadata.response_code = ResponseCode::NXDomain;
                let owners: Vec<&Name> = z
                    .sets
                    .keys()
                    .filter(|(_, t)| *t == RecordType::NSEC)
                    .map(|(o, _)| o)
                    .collect();
                let cover = owners
                    .iter()
                    .filter(|o| ***o < qn)
                    .max()
                    .map_or(n("."), |o| (*o).clone());
                authority(&mut m, &cover);
                if cover != n(".") {
                    m.add_authorities(z.sets[&(n("."), RecordType::NSEC)].clone());
                }
            }
            let mut edns = hickory_net::proto::op::Edns::new();
            edns.set_dnssec_ok(true);
            edns.set_max_payload(4096);
            m.set_edns(edns);
            if let Ok(out) = m.to_vec() {
                let _ = s.send_to(&out, from).await;
            }
        }
    });
    addr
}

fn question(name: &str, qtype: u16) -> Question {
    Question {
        name: NameBuf::from_presentation(name).unwrap(),
        qtype,
        qclass: 1,
        dnssec_ok: true,
        checking_disabled: false,
        client_subnet: 0,
    }
}

async fn setup(
    anchor: bool,
) -> (
    Validator,
    Arc<Group>,
    Arc<AtomicUsize>,
    Arc<Stats>,
    tempfile::TempDir,
) {
    let z = Arc::new(zone());
    let asked = Arc::new(AtomicUsize::new(0));
    let addr = serve(Arc::clone(&z), Arc::clone(&asked)).await;
    let dir = tempfile::tempdir().unwrap();
    let anchors = dir.path().join("root.key");
    std::fs::write(
        &anchors,
        format!(". 3600 IN DNSKEY 257 3 15 {}\n", b64(&z.key[4..])),
    )
    .unwrap();
    let stats = Arc::new(Stats::default());
    let mut v = Validator::new(&[], Arc::clone(&stats));
    if anchor {
        v = v.with_anchors_file(Some(anchors.to_str().unwrap()));
    }
    let ep = Endpoint::parse(&format!("udp://{addr}")).unwrap();
    let up = Upstream::build(
        1,
        "root",
        ep,
        &UpstreamOptions::default(),
        &TlsOptions::default(),
    )
    .unwrap();
    let group = Arc::new(Group::new(
        "default",
        vec![Arc::new(up)],
        Strategy::Failover,
    ));
    (v, group, asked, stats, dir)
}

fn rcode(bytes: &[u8]) -> u16 {
    telltale_proto::summarize(bytes).unwrap().rcode
}

/// REQ: DNS-011 — secure answers (AD for DO clients), signed NODATA and NXDOMAIN, a forged
/// signature is bogus (EDE 6).
#[tokio::test]
async fn dns_011_offline_signed_root() {
    let (v, g, _, _, _dir) = setup(true).await;
    let budget = Duration::from_secs(5);
    let r = v
        .resolve(&g, question("a", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Secure, "a. A");
    assert!(
        telltale_proto::Header::parse(&r.bytes).unwrap().flags.ad(),
        "AD for a DO client"
    );

    let r = v
        .resolve(&g, question("a", rtype::AAAA), budget, true, false)
        .await
        .unwrap();
    assert_eq!(
        (r.verdict, rcode(&r.bytes)),
        (Verdict::Secure, telltale_proto::rcode::NOERROR),
        "NODATA"
    );

    let r = v
        .resolve(&g, question("zz-nope", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(
        (r.verdict, rcode(&r.bytes)),
        (Verdict::Secure, telltale_proto::rcode::NXDOMAIN),
        "NXDOMAIN"
    );

    let r = v
        .resolve(&g, question("bad", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Bogus, "forged signature");
    assert_eq!(r.ede, telltale_proto::ede::DNSSEC_BOGUS);

    // Without DO (and AD not asked): no DNSSEC records, no AD.
    let r = v
        .resolve(&g, question("a", rtype::A), budget, false, false)
        .await
        .unwrap();
    assert!(!telltale_proto::Header::parse(&r.bytes).unwrap().flags.ad());
}

/// REQ: DNS-011 (T9.16) — RFC 8198: after one signed NXDOMAIN, another name in the same range is
/// answered from the cached NSEC records: no upstream query, counted as synthesized, NXDOMAIN
/// with AD.
#[tokio::test]
async fn dns_011_offline_aggressive_nsec() {
    let (v, g, asked, stats, _dir) = setup(true).await;
    let budget = Duration::from_secs(5);
    let r = v
        .resolve(&g, question("zz-one", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(rcode(&r.bytes), telltale_proto::rcode::NXDOMAIN);
    let before = asked.load(Ordering::Relaxed);
    let r = v
        .resolve(&g, question("zz-two", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(
        (r.verdict, rcode(&r.bytes)),
        (Verdict::Secure, telltale_proto::rcode::NXDOMAIN)
    );
    assert!(telltale_proto::Header::parse(&r.bytes).unwrap().flags.ad());
    assert_eq!(
        asked.load(Ordering::Relaxed),
        before,
        "answered without asking upstream"
    );
    assert_eq!(stats.synthesized.load(Ordering::Relaxed), 1);
    // Switched off: it asks.
    let (v, g, asked, stats, _dir2) = setup(true).await;
    let v = v.with_aggressive_nsec(false);
    v.resolve(&g, question("zz-one", rtype::A), budget, true, false)
        .await
        .unwrap();
    let before = asked.load(Ordering::Relaxed);
    v.resolve(&g, question("zz-two", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert!(asked.load(Ordering::Relaxed) > before);
    assert_eq!(stats.synthesized.load(Ordering::Relaxed), 0);
}

/// REQ: DNS-011 — with the real root's anchors (not the test key), the test root's answers
/// can't be proven: bogus.
#[tokio::test]
async fn dns_011_offline_wrong_anchor_is_bogus() {
    let (v, g, _, _, _dir) = setup(false).await;
    let r = v
        .resolve(
            &g,
            question("a", rtype::A),
            Duration::from_secs(5),
            true,
            false,
        )
        .await
        .unwrap();
    assert_ne!(r.verdict, Verdict::Secure);
}
