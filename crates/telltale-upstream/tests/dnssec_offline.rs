//! REQ: DNS-011 — DNSSEC validation offline, against a signed test root (T9.24): the root's
//! key is the trust anchor (an anchors file), and a fake upstream serves the zone's records with
//! their signatures, NSEC denials, and one forged signature. Covers the validator's secure,
//! NODATA, NXDOMAIN, bogus, and wrong-anchor paths, and RFC 8198 answering from cached NSEC
//! ranges without another upstream query. The root also delegates `u.` without a DS: an
//! unsigned zone with a CNAME chain (T10.9).

#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use hickory_net::proto::dnssec::crypto::Ed25519SigningKey;
use hickory_net::proto::dnssec::rdata::{DNSKEY, DNSSECRData, NSEC, RRSIG};
use hickory_net::proto::dnssec::{DnssecSigner, PublicKey as _, SigningKey};
use hickory_net::proto::op::{Message, OpCode, ResponseCode};
use hickory_net::proto::rr::rdata::{A, CNAME, NS, SOA};
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
    /// T10.9 — the unsigned zone `u.`, delegated from the root without a DS.
    plain: BTreeMap<(Name, RecordType), Vec<Record>>,
    /// The DNSKEY's RDATA, for the anchors file.
    key: Vec<u8>,
    /// ADR-098 — spoof `b.a.`: answer its A and SOA unsigned (an attacker's forgery for a
    /// name inside the signed root, with a made-up SOA so that it looks like a zone apex).
    forge: AtomicBool,
    /// NFR-004 — milliseconds every answer is held back (a slow upstream).
    lag_ms: AtomicU64,
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
                n("b.a."),
                [RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            )))],
        ),
        // An ordinary name inside the root (not a zone cut): its NSEC has no NS.
        (n("b.a."), vec![RData::A(A::new(192, 0, 2, 7))]),
        (
            n("b.a."),
            vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                n("bad."),
                [RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            )))],
        ),
        (n("bad."), vec![RData::A(A::new(192, 0, 2, 66))]),
        (
            n("bad."),
            vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                n("u."),
                [RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            )))],
        ),
        // T10.9 — `u.` is delegated without a DS: the NSEC proves NS and no DS.
        (
            n("u."),
            vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                n("."),
                [RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
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
    // The unsigned zone: `www.u.` is a CNAME to `cdn.u.`, which has an address.
    let u_soa = SOA::new(n("ns.u."), n("admin.u."), 1, 1800, 900, 604_800, 300);
    let plain_sets: Vec<(Name, RData)> = vec![
        (n("u."), RData::SOA(u_soa)),
        (n("u."), RData::NS(NS(n("ns.u.")))),
        (n("www.u."), RData::CNAME(CNAME(n("cdn.u.")))),
        (n("cdn.u."), RData::A(A::new(192, 0, 2, 80))),
    ];
    let mut plain = BTreeMap::new();
    for (name, d) in plain_sets {
        let t = d.record_type();
        plain.insert((name.clone(), t), vec![Record::from_rdata(name, ttl, d)]);
    }
    Zone {
        sets,
        plain,
        key: key_rdata,
        forge: AtomicBool::new(false),
        lag_ms: AtomicU64::new(0),
    }
}

/// T10.9 — `name` is in the unsigned zone `u.` (the delegation's DS question goes to the root).
fn in_plain(qn: &Name, qt: RecordType) -> bool {
    let u = n("u.");
    (*qn == u && qt != RecordType::DS) || (qn != &u && u.zone_of(qn))
}

/// T10.9 — an answer from the unsigned zone, chasing a CNAME the way a recursive resolver
/// does (also for a DS question about the CNAME's owner).
fn plain_answer(z: &Zone, m: &mut Message, qn: &Name, qt: RecordType) {
    let mut name = qn.clone();
    for _ in 0..4 {
        if let Some(rs) = z.plain.get(&(name.clone(), qt)) {
            m.add_answers(rs.clone());
            return;
        }
        let Some(c) = z.plain.get(&(name.clone(), RecordType::CNAME)) else {
            break;
        };
        m.add_answers(c.clone());
        let RData::CNAME(CNAME(target)) = c[0].data.clone() else {
            break;
        };
        name = target;
    }
    if m.answers.is_empty() {
        m.add_authorities(z.plain[&(n("u."), RecordType::SOA)].clone());
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
            let lag = z.lag_ms.load(Ordering::Relaxed);
            if lag > 0 {
                tokio::time::sleep(Duration::from_millis(lag)).await;
            }
            let (qn, qt) = (question.name().clone(), question.query_type());
            let mut m = Message::response(q.metadata.id, OpCode::Query);
            m.metadata.recursion_desired = true;
            m.metadata.recursion_available = true;
            m.add_query(question);
            let authority = |m: &mut Message, owner: &Name| {
                m.add_authorities(z.sets[&(n("."), RecordType::SOA)].clone());
                m.add_authorities(z.sets[&(owner.clone(), RecordType::NSEC)].clone());
            };
            if z.forge.load(Ordering::Relaxed)
                && qn == n("b.a.")
                && matches!(qt, RecordType::A | RecordType::SOA)
            {
                let data = if qt == RecordType::A {
                    RData::A(A::new(192, 0, 2, 66))
                } else {
                    RData::SOA(SOA::new(
                        n("ns.b.a."),
                        n("x.b.a."),
                        1,
                        1800,
                        900,
                        604_800,
                        300,
                    ))
                };
                m.add_answers(vec![Record::from_rdata(qn.clone(), 300, data)]);
            } else if in_plain(&qn, qt) {
                plain_answer(&z, &mut m, &qn, qt);
            } else if let Some(rs) = z.sets.get(&(qn.clone(), qt)) {
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
    setup_zone(anchor, Arc::new(zone())).await
}

async fn setup_zone(
    anchor: bool,
    z: Arc<Zone>,
) -> (
    Validator,
    Arc<Group>,
    Arc<AtomicUsize>,
    Arc<Stats>,
    tempfile::TempDir,
) {
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

/// REQ: DNS-011 (T10.9, ADR-098) — an answer in a zone delegated without a DS, reached through
/// a CNAME, is insecure (served, no AD), not bogus. Real resolvers answer the validator's DS
/// question about a CNAME's owner with the CNAME, as the fake root does.
#[tokio::test]
async fn dns_011_offline_unsigned_zone_through_cname_is_insecure() {
    let (v, g, _, stats, _dir) = setup(true).await;
    let budget = Duration::from_secs(5);
    let r = v
        .resolve(&g, question("www.u", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(
        r.verdict,
        Verdict::Insecure,
        "www.u. A (CNAME into the unsigned zone)"
    );
    assert_ne!(r.bytes.len(), 0, "an answer to serve");
    assert!(!telltale_proto::Header::parse(&r.bytes).unwrap().flags.ad());
    let r = v
        .resolve(&g, question("cdn.u", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Insecure, "cdn.u. A");
    // The signed root is unaffected: a forged signature is still bogus.
    let r = v
        .resolve(&g, question("bad", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Bogus);
    assert_eq!(
        stats.bogus.load(Ordering::Relaxed),
        1,
        "only the forged signature"
    );
}

/// REQ: DNS-011 (ADR-098) — a spoofed, unsigned answer for a name inside the signed root
/// stays bogus even when the spoofer also forges an SOA for it. The root's secure denial of a
/// DS at `b.a.` proves there is no DS there, not that `b.a.` is a zone cut (its NSEC has no
/// NS), so the unsigned-zone proof must not accept it, and must not remember `b.a.` as an
/// unsigned zone for the questions that follow.
#[tokio::test]
async fn dns_011_offline_forged_apex_inside_signed_zone_stays_bogus() {
    let z = Arc::new(zone());
    let budget = Duration::from_secs(5);
    let (v, g, _, _, _dir) = setup_zone(true, Arc::clone(&z)).await;
    let r = v
        .resolve(&g, question("b.a", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Secure, "b.a. A, signed");

    z.forge.store(true, Ordering::Relaxed);
    let (v, g, _, stats, _dir2) = setup_zone(true, Arc::clone(&z)).await;
    for round in 1..=2 {
        let r = v
            .resolve(&g, question("b.a", rtype::A), budget, true, false)
            .await
            .unwrap();
        assert_eq!(
            r.verdict,
            Verdict::Bogus,
            "an unsigned answer inside the signed root (question {round})"
        );
    }
    assert_eq!(
        stats.insecure.load(Ordering::Relaxed),
        0,
        "never judged insecure"
    );
}

/// REQ: DNS-011, NFR-004 (ADR-098, review 03-05) — a validation that can't finish ends within
/// two query budgets whatever the upstream does (it holds an in-flight permit meanwhile): with
/// every answer taking two thirds of a budget, the lookup is cut off and the proof that would have
/// rescued it gets only what the deadline leaves. The verdict is the conservative one (no
/// answer: stale or SERVFAIL), and a name that couldn't be proven isn't walked again at once.
#[tokio::test]
async fn nfr_004_offline_slow_upstream_ends_within_two_budgets() {
    let z = Arc::new(zone());
    z.forge.store(true, Ordering::Relaxed);
    // Each answer takes two thirds of a budget: every attempt succeeds, but the chain of
    // lookups (the answer, the keys, the proof's SOA and DS) adds up to far more than two.
    z.lag_ms.store(200, Ordering::Relaxed);
    let (v, g, _, stats, _dir) = setup_zone(true, Arc::clone(&z)).await;
    let budget = Duration::from_millis(300);
    let started = std::time::Instant::now();
    let r = v
        .resolve(&g, question("b.a", rtype::A), budget, true, false)
        .await;
    let took = started.elapsed();
    assert!(r.is_err(), "no verdict from an upstream this slow: {r:?}");
    assert!(
        took < budget * 2 + Duration::from_millis(250),
        "ended after {took:?}, more than two budgets of {budget:?}"
    );
    assert_eq!(stats.insecure.load(Ordering::Relaxed), 0);
    // Asking again once the upstream is quick: the forged answer is still bogus, and the name
    // that couldn't be proven is not walked again (the proof is skipped for a minute).
    z.lag_ms.store(0, Ordering::Relaxed);
    let r = v
        .resolve(&g, question("b.a", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Bogus, "the forged answer, still bogus");
    assert_eq!(stats.insecure.load(Ordering::Relaxed), 0);
}
