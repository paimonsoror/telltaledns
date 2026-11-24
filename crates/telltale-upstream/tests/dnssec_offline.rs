//! REQ: DNS-011 — DNSSEC validation offline, against a signed test root (T9.24): the root's
//! key is the trust anchor (an anchors file), and a fake upstream serves the zone's records with
//! their signatures, NSEC denials, and one forged signature. Covers the validator's secure,
//! NODATA, NXDOMAIN, bogus, and wrong-anchor paths, and RFC 8198 answering from cached NSEC
//! ranges without another upstream query. The root also delegates `u.` without a DS: an
//! unsigned zone with a CNAME chain (T10.9). And it delegates `t.`, a top-level domain signed
//! with NSEC3 Opt-Out like `.com` and `.org` (ADR-184), with unsigned and signed delegations
//! below it.

#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use hickory_net::proto::dnssec::crypto::Ed25519SigningKey;
use hickory_net::proto::dnssec::rdata::{DNSKEY, DNSSECRData, DS, NSEC, NSEC3, RRSIG};
use hickory_net::proto::dnssec::{
    DigestType, DnssecSigner, Nsec3HashAlgorithm, PublicKey as _, SigningKey,
};
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
    /// ADR-184 — the NSEC3 Opt-Out top-level domain `t.` and the zones below it.
    tld: Tld,
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
    zone_with(3600)
}

/// The test root, with `t.`'s denials made of records with TTL `proof_ttl`.
fn zone_with(proof_ttl: u32) -> Zone {
    let tld = tld(proof_ttl);
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
                n("t."),
                [RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            )))],
        ),
        // ADR-184 — `t.` is a signed delegation: its DS, and the NSEC that lists it.
        (
            n("t."),
            vec![RData::DNSSEC(DNSSECRData::DS(tld.ds.clone()))],
        ),
        (
            n("t."),
            vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                n("u."),
                [
                    RecordType::NS,
                    RecordType::DS,
                    RecordType::RRSIG,
                    RecordType::NSEC,
                ],
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
        tld,
    }
}

/// ADR-184 — the top-level domain `t.`, signed under its own key (its DS is in the root) with
/// NSEC3 Opt-Out as `.com` and `.org` are: SHA-1, no salt, no extra iterations, and the Opt-Out
/// flag on every NSEC3.
/// - `s.t.` is a signed delegation: a DS, an NSEC3 at its hash, and its own key and NSEC chain.
/// - `u.t.` and `v.t.` are delegations without a DS and without an NSEC3 of their own: they lie
///   inside Opt-Out spans (`v.t.`'s is the apex record's own span).
/// - `x.t.` is an ordinary name, so that the span covering `u.t.` isn't the apex's record.
///
/// `u.t.`'s server answers like a parked domain's: every name has an SOA and NS of its own,
/// which makes the validation library judge its answers bogus. `v.t.` is an ordinary unsigned
/// zone.
struct Tld {
    /// `t.`'s record sets with their signatures, by (owner, type), its NSEC3 chain included.
    sets: BTreeMap<(Name, RecordType), Vec<Record>>,
    /// The NSEC3 chain: each record's hash and owner, in hash order.
    chain: Vec<(Vec<u8>, Name)>,
    /// `s.t.`'s zone, signed with its own key.
    child: BTreeMap<(Name, RecordType), Vec<Record>>,
    /// The records of `u.t.` and `v.t.` (unsigned).
    plain: BTreeMap<(Name, RecordType), Vec<Record>>,
    /// The DS for `t.`, in the root.
    ds: DS,
    /// `dns_011_offline_signed_delegation_stays_validated`: `s.t. DS` is answered without the
    /// DS.
    no_ds: AtomicBool,
    /// The same test: `www.s.t.` is answered from other names' records.
    replay: AtomicBool,
    /// The same test: as `replay`, with a DS answer whose insecure record is another zone's.
    other_soa: AtomicBool,
}

/// `name`'s NSEC3 hash with `t.`'s parameters.
fn h3(name: &Name) -> Vec<u8> {
    Nsec3HashAlgorithm::SHA1
        .hash(&[], name, 0)
        .unwrap()
        .as_ref()
        .to_vec()
}

/// Base32 with the extended hex alphabet, lowercase, unpadded (RFC 4648 §7): NSEC3 owners.
fn b32hex(data: &[u8]) -> String {
    const T: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut out = String::new();
    for chunk in data.chunks(5) {
        let mut block = [0u8; 8];
        block[3..3 + chunk.len()].copy_from_slice(chunk);
        let v = u64::from_be_bytes(block);
        for i in 0..(chunk.len() * 8).div_ceil(5) {
            out.push(char::from(
                T[usize::try_from((v >> (35 - 5 * i)) & 31).unwrap()],
            ));
        }
    }
    out
}

/// The owner of `name`'s NSEC3 in `t.`.
fn h3_owner(name: &Name) -> Name {
    n(&format!("{}.t.", b32hex(&h3(name))))
}

fn soa_of(zone: &str) -> SOA {
    SOA::new(
        n(&format!("ns.{zone}")),
        n(&format!("admin.{zone}")),
        1,
        1800,
        900,
        604_800,
        300,
    )
}

/// A new key for `zone`: its signer and its DNSKEY.
fn zone_signer(zone: &Name) -> (DnssecSigner, DNSKEY) {
    let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
    let key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
    let dnskey = DNSKEY::new(true, true, false, key.to_public_key().unwrap());
    let signer = DnssecSigner::new(
        dnskey.clone(),
        Box::new(key),
        zone.clone(),
        Duration::from_hours(24),
    );
    (signer, dnskey)
}

/// Record sets with their signatures, by (owner, type), each record with the given TTL.
fn signed(
    rrsets: Vec<(Name, Vec<RData>)>,
    signer: &DnssecSigner,
    ttl: u32,
) -> BTreeMap<(Name, RecordType), Vec<Record>> {
    let inception = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    let mut sets = BTreeMap::new();
    for (name, datas) in rrsets {
        let rtype = datas[0].record_type();
        let mut rs = RecordSet::new(name.clone(), rtype, 0);
        let mut all: Vec<Record> = datas
            .into_iter()
            .map(|d| Record::from_rdata(name.clone(), ttl, d))
            .collect();
        for r in &all {
            rs.insert(r.clone(), 0);
        }
        let sig = RRSIG::from_rrset(&rs, DNSClass::IN, inception, signer).unwrap();
        all.push(Record::from_rdata(
            name.clone(),
            ttl,
            RData::DNSSEC(DNSSECRData::RRSIG(sig)),
        ));
        sets.insert((name, rtype), all);
    }
    sets
}

/// `t.`, its SOA and NSEC3 records (what its denials are made of) with TTL `proof_ttl`, the
/// rest with an hour.
fn tld(proof_ttl: u32) -> Tld {
    let t = n("t.");
    let (signer, dnskey) = zone_signer(&t);
    let (child_signer, child_key) = zone_signer(&n("s.t."));
    let ds = DS::from_key(dnskey.public_key(), &t, DigestType::SHA256).unwrap();
    let child_ds = DS::from_key(child_key.public_key(), &n("s.t."), DigestType::SHA256).unwrap();
    // The names with an NSEC3 of their own, and the types each lists; in hash order, each
    // record's next hash is the following one's (the last wraps around to the first).
    let mut chain = [
        (
            t.clone(),
            vec![
                RecordType::NS,
                RecordType::SOA,
                RecordType::RRSIG,
                RecordType::DNSKEY,
                RecordType::NSEC3PARAM,
            ],
        ),
        (
            n("s.t."),
            vec![RecordType::NS, RecordType::DS, RecordType::RRSIG],
        ),
        (n("x.t."), vec![RecordType::A, RecordType::RRSIG]),
    ];
    chain.sort_by_key(|(name, _)| h3(name));
    let mut denials: Vec<(Name, Vec<RData>)> = vec![(t.clone(), vec![RData::SOA(soa_of("t."))])];
    let rrsets: Vec<(Name, Vec<RData>)> = vec![
        (t.clone(), vec![RData::NS(NS(n("ns.t.")))]),
        (t.clone(), vec![RData::DNSSEC(DNSSECRData::DNSKEY(dnskey))]),
        (n("x.t."), vec![RData::A(A::new(192, 0, 2, 20))]),
        (n("s.t."), vec![RData::DNSSEC(DNSSECRData::DS(child_ds))]),
    ];
    for (i, (name, types)) in chain.iter().enumerate() {
        let next = h3(&chain[(i + 1) % chain.len()].0);
        let nsec3 = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            true,
            0,
            Vec::new(),
            next,
            types.iter().copied(),
        );
        denials.push((
            h3_owner(name),
            vec![RData::DNSSEC(DNSSECRData::NSEC3(nsec3))],
        ));
    }
    let mut sets = signed(rrsets, &signer, 3600);
    sets.extend(signed(denials, &signer, proof_ttl));
    let child = signed(
        vec![
            (n("s.t."), vec![RData::SOA(soa_of("s.t."))]),
            (n("s.t."), vec![RData::NS(NS(n("ns.s.t.")))]),
            (
                n("s.t."),
                vec![RData::DNSSEC(DNSSECRData::DNSKEY(child_key))],
            ),
            (
                n("s.t."),
                vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                    n("www.s.t."),
                    [
                        RecordType::NS,
                        RecordType::SOA,
                        RecordType::RRSIG,
                        RecordType::NSEC,
                        RecordType::DNSKEY,
                    ],
                )))],
            ),
            (n("www.s.t."), vec![RData::A(A::new(192, 0, 2, 30))]),
            (
                n("www.s.t."),
                vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                    n("s.t."),
                    [RecordType::A, RecordType::RRSIG, RecordType::NSEC],
                )))],
            ),
        ],
        &child_signer,
        3600,
    );
    let mut plain = BTreeMap::new();
    for (name, d) in [
        (n("v.t."), RData::SOA(soa_of("v.t."))),
        (n("v.t."), RData::NS(NS(n("ns.v.t.")))),
        (n("x.l.v.t."), RData::A(A::new(192, 0, 2, 40))),
        (n("www.u.t."), RData::A(A::new(192, 0, 2, 50))),
        (n("mtalk.u.t."), RData::CNAME(CNAME(n("x.l.v.t.")))),
    ] {
        let rtype = d.record_type();
        plain.insert(
            (name.clone(), rtype),
            vec![Record::from_rdata(name, 3600, d)],
        );
    }
    Tld {
        sets,
        chain: chain
            .iter()
            .map(|(name, _)| (h3(name), h3_owner(name)))
            .collect(),
        child,
        plain,
        ds,
        no_ds: AtomicBool::new(false),
        replay: AtomicBool::new(false),
        other_soa: AtomicBool::new(false),
    }
}

impl Tld {
    /// The NSEC3 (with its signature) matching `name`, if it has one.
    fn matching(&self, name: &Name) -> Option<Vec<Record>> {
        self.sets.get(&(h3_owner(name), RecordType::NSEC3)).cloned()
    }

    /// The NSEC3 whose span covers `name`'s hash (the greatest hash below it, or the last).
    fn covering(&self, name: &Name) -> Vec<Record> {
        let h = h3(name);
        let (_, owner) = self
            .chain
            .iter()
            .rev()
            .find(|(hash, _)| *hash < h)
            .unwrap_or_else(|| self.chain.last().unwrap());
        self.sets[&(owner.clone(), RecordType::NSEC3)].clone()
    }

    fn soa(&self) -> Vec<Record> {
        self.sets[&(n("t."), RecordType::SOA)].clone()
    }
}

/// Adds `records` to the authority section unless that record set is there already.
fn add_once(m: &mut Message, records: Vec<Record>) {
    let fresh = records.first().is_some_and(|r| {
        !m.authorities
            .iter()
            .any(|a| a.name == r.name && a.record_type() == r.record_type())
    });
    if fresh {
        m.add_authorities(records);
    }
}

/// ADR-184 — an answer from `t.` or a zone below it (a delegation's DS question goes to `t.`).
fn tld_answer(z: &Tld, m: &mut Message, qn: &Name, qt: RecordType) {
    let below = |zone: &str| {
        let zone = n(zone);
        zone.zone_of(qn) && !(*qn == zone && qt == RecordType::DS)
    };
    if below("s.t.") {
        child_answer(z, m, qn, qt);
    } else if below("u.t.") {
        parked_answer(z, m, qn, qt);
    } else if below("v.t.") {
        if !chase(&z.plain, m, qn, qt) {
            m.add_authorities(z.plain[&(n("v.t."), RecordType::SOA)].clone());
        }
    } else if *qn == n("s.t.") && qt == RecordType::DS && z.no_ds.load(Ordering::Relaxed) {
        // The DS left out: the apex's NSEC3 (the closest encloser) and another name's span.
        m.add_authorities(z.soa());
        m.add_authorities(z.matching(&n("t.")).unwrap());
        add_once(m, z.covering(&n("u.t.")));
    } else if let Some(rs) = z.sets.get(&(qn.clone(), qt)) {
        m.add_answers(rs.clone());
    } else {
        tld_denial(z, m, qn);
    }
}

/// A negative answer from `t.` (RFC 5155 §7.2): its SOA, and the NSEC3 matching the name
/// (NODATA), or else the closest encloser's, the one covering the next closer name and, for
/// NXDOMAIN (any name but the delegations without an NSEC3), the one covering the wildcard.
fn tld_denial(z: &Tld, m: &mut Message, qn: &Name) {
    m.add_authorities(z.soa());
    if let Some(rs) = z.matching(qn) {
        m.add_authorities(rs);
        return;
    }
    let (mut encloser, mut next_closer) = (qn.base_name(), qn.clone());
    while z.matching(&encloser).is_none() {
        next_closer = encloser.clone();
        encloser = encloser.base_name();
    }
    m.add_authorities(z.matching(&encloser).unwrap());
    add_once(m, z.covering(&next_closer));
    if ![n("u.t."), n("v.t.")].contains(&next_closer) {
        m.metadata.response_code = ResponseCode::NXDomain;
        add_once(m, z.covering(&n(&format!("*.{encloser}"))));
    }
}

/// `s.t.`'s signed zone. With `replay`, `www.s.t.`'s address, SOA and DS come from elsewhere:
/// an unsigned address, an SOA of its own, and, for the DS, the records of `t.`'s chain that
/// match `s.t.` and cover `www.s.t.` (with `other_soa`, another zone's SOA instead).
fn child_answer(z: &Tld, m: &mut Message, qn: &Name, qt: RecordType) {
    let other_soa = z.other_soa.load(Ordering::Relaxed);
    if other_soa && *qn == n("www.s.t.") && qt == RecordType::DS {
        m.add_authorities(vec![Record::from_rdata(
            n("u.t."),
            300,
            RData::SOA(soa_of("parked.test.")),
        )]);
        return;
    }
    if (other_soa || z.replay.load(Ordering::Relaxed)) && *qn == n("www.s.t.") {
        match qt {
            RecordType::A => {
                m.add_answers(vec![Record::from_rdata(
                    qn.clone(),
                    300,
                    RData::A(A::new(192, 0, 2, 66)),
                )]);
                return;
            }
            RecordType::SOA => {
                m.add_answers(vec![Record::from_rdata(
                    qn.clone(),
                    300,
                    RData::SOA(soa_of("www.s.t.")),
                )]);
                return;
            }
            RecordType::DS => {
                m.add_authorities(z.soa());
                m.add_authorities(z.matching(&n("s.t.")).unwrap());
                add_once(m, z.covering(qn));
                return;
            }
            _ => {}
        }
    }
    let apex = n("s.t.");
    if let Some(rs) = z.child.get(&(qn.clone(), qt)) {
        m.add_answers(rs.clone());
        return;
    }
    m.add_authorities(z.child[&(apex.clone(), RecordType::SOA)].clone());
    if let Some(rs) = z.child.get(&(qn.clone(), RecordType::NSEC)) {
        m.add_authorities(rs.clone());
    } else {
        // The zone has two names: their two NSEC records cover every other name, and the
        // wildcard.
        m.metadata.response_code = ResponseCode::NXDomain;
        m.add_authorities(z.child[&(apex, RecordType::NSEC)].clone());
        m.add_authorities(z.child[&(n("www.s.t."), RecordType::NSEC)].clone());
    }
}

/// `u.t.`'s server, like a parked domain's: every name has an SOA and NS of its own, a DS
/// question gets NODATA with that SOA, and the rest comes from `u.t.`'s records (a CNAME is
/// followed into `v.t.`).
fn parked_answer(z: &Tld, m: &mut Message, qn: &Name, qt: RecordType) {
    let soa = Record::from_rdata(qn.clone(), 300, RData::SOA(soa_of("parked.test.")));
    match qt {
        RecordType::SOA => {
            m.add_answers(vec![soa]);
        }
        RecordType::NS => {
            m.add_answers(vec![Record::from_rdata(
                qn.clone(),
                300,
                RData::NS(NS(n("ns.parked.test."))),
            )]);
        }
        RecordType::DS => {
            m.add_authorities(vec![soa]);
        }
        _ => {
            if !chase(&z.plain, m, qn, qt) {
                m.add_authorities(vec![soa]);
            }
        }
    }
}

/// Answers `qn`/`qt` from `records`, following CNAMEs as a recursive resolver does; false
/// when there is nothing to answer with.
fn chase(
    records: &BTreeMap<(Name, RecordType), Vec<Record>>,
    m: &mut Message,
    qn: &Name,
    qt: RecordType,
) -> bool {
    let mut name = qn.clone();
    for _ in 0..4 {
        if let Some(rs) = records.get(&(name.clone(), qt)) {
            m.add_answers(rs.clone());
            return true;
        }
        let Some(c) = records.get(&(name.clone(), RecordType::CNAME)) else {
            break;
        };
        m.add_answers(c.clone());
        let RData::CNAME(CNAME(target)) = c[0].data.clone() else {
            break;
        };
        name = target;
    }
    !m.answers.is_empty()
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
            } else if n("t.").zone_of(&qn) && !(qn == n("t.") && qt == RecordType::DS) {
                tld_answer(&z.tld, &mut m, &qn, qt);
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

/// ADR-184 — validates `x.t. A` through `g` first, so that `t.`'s keys are in the group's
/// validation cache, as they are once a node has been running. (On a cold cache, the validation
/// library's own walk through a parked domain's answers can reach its depth limit while it
/// checks `t.`'s key, and then keeps a failure for `t.`'s DS denials for up to a minute; that
/// is a separate matter, left out here.)
async fn warm_tld(v: &Validator, g: &Arc<Group>) {
    let r = v
        .resolve(
            g,
            question("x.t", rtype::A),
            Duration::from_secs(5),
            true,
            false,
        )
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Secure, "x.t. A, signed");
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
    // REQ: DNS-011 — in resolution order: the CNAME before the address it leads to.
    let m = Message::from_vec(&r.bytes).unwrap();
    let types: Vec<RecordType> = m.answers.iter().map(Record::record_type).collect();
    assert_eq!(types, vec![RecordType::CNAME, RecordType::A], "chain order");
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

/// REQ: DNS-011 (ADR-098, ADR-184) — a name below a delegation that has no DS and lies inside an
/// NSEC3 Opt-Out span (`u.t.`, whose server answers like a parked domain's, so the validation
/// library judges the answer bogus) is insecure: served, without AD. `t.`'s denial of the DS
/// proves it: the NSEC3 matching `t.` (the closest encloser) and an Opt-Out NSEC3 covering
/// `u.t.`'s hash.
#[tokio::test]
async fn dns_011_offline_opt_out_unsigned_delegation_is_insecure() {
    let (v, g, _, stats, _dir) = setup(true).await;
    let budget = Duration::from_secs(5);
    warm_tld(&v, &g).await;
    let r = v
        .resolve(&g, question("www.u.t", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Insecure, "www.u.t. A");
    assert_ne!(r.bytes.len(), 0, "an answer to serve");
    assert!(!telltale_proto::Header::parse(&r.bytes).unwrap().flags.ad());
    assert_eq!(stats.bogus.load(Ordering::Relaxed), 0);
}

/// REQ: DNS-011 (ADR-098, ADR-184) — a CNAME chain across two such zones (`mtalk.u.t.` to
/// `x.l.v.t.`; the span covering `v.t.` is `t.`'s apex record itself) is insecure: both zones
/// are proven unsigned.
#[tokio::test]
async fn dns_011_offline_cname_chain_across_opt_out_unsigned_zones_is_insecure() {
    let (v, g, _, stats, _dir) = setup(true).await;
    let budget = Duration::from_secs(5);
    warm_tld(&v, &g).await;
    let r = v
        .resolve(&g, question("mtalk.u.t", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Insecure, "mtalk.u.t. A");
    assert_eq!(
        telltale_proto::summarize(&r.bytes).unwrap().answers,
        2,
        "the CNAME and the address"
    );
    // REQ: DNS-011 (issue #78) — in resolution order: the CNAME before the address it leads to.
    let m = Message::from_vec(&r.bytes).unwrap();
    let types: Vec<RecordType> = m.answers.iter().map(Record::record_type).collect();
    assert_eq!(types, vec![RecordType::CNAME, RecordType::A], "chain order");
    assert!(!telltale_proto::Header::parse(&r.bytes).unwrap().flags.ad());
    assert_eq!(stats.bogus.load(Ordering::Relaxed), 0);
}

/// REQ: DNS-011 (ADR-184) — what the validation library makes of an Opt-Out DS denial: an
/// ordinary secure NODATA (not the insecure proof of RFC 5155 §9.2). The unsigned-zone proof is
/// built around that; if a library upgrade changes it, this test fails and the proof needs
/// another look.
#[tokio::test]
async fn dns_011_offline_hickory_opt_out_ds_denial_is_secure() {
    let (v, g, _, _, _dir) = setup(true).await;
    let r = v
        .resolve(
            &g,
            question("u.t", rtype::DS),
            Duration::from_secs(5),
            true,
            false,
        )
        .await
        .unwrap();
    assert_eq!(
        (r.verdict, rcode(&r.bytes)),
        (Verdict::Secure, telltale_proto::rcode::NOERROR),
        "u.t. DS"
    );
    assert_eq!(
        telltale_proto::summarize(&r.bytes).unwrap().answers,
        0,
        "no DS"
    );
}

/// REQ: DNS-011 (ADR-184) — a signed delegation (`s.t.`: a DS, and an NSEC3 of its own in
/// `t.`) stays validated when the answers for its subtree don't come from it:
/// 1. `s.t. DS` answered without the DS (`t.`'s apex record and another name's span instead):
///    bogus.
/// 2. `www.s.t.` answered from other names' records: an unsigned address, an SOA of its own (so
///    that it looks like a zone apex), and, for its DS, the records of `t.`'s chain matching
///    `s.t.` and covering `www.s.t.`'s hash. They are `t.`'s, but the record matching `s.t.` is
///    a delegation's, which is no closest encloser for names below it (RFC 6840 §4.1): bogus.
/// 3. A DS answer whose insecure record is another zone's: bogus.
///
/// Over two questions each, nothing is judged insecure. The second question is bogus anyway
/// (the proof gate doesn't walk a name that failed again for a minute): what counts is that
/// nothing was judged insecure.
#[tokio::test]
async fn dns_011_offline_signed_delegation_stays_validated() {
    let z = Arc::new(zone());
    let budget = Duration::from_secs(5);
    let (v, g, _, _, _dir) = setup_zone(true, Arc::clone(&z)).await;
    let r = v
        .resolve(&g, question("www.s.t", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Secure, "www.s.t. A, signed");
    for (flag, what, name) in [
        (&z.tld.no_ds, "s.t. DS without the DS", "www.s.t"),
        (&z.tld.replay, "www.s.t. from other names", "www.s.t"),
        (&z.tld.other_soa, "another zone's insecure SOA", "www.s.t"),
    ] {
        flag.store(true, Ordering::Relaxed);
        let (v, g, _, stats, _dir) = setup_zone(true, Arc::clone(&z)).await;
        warm_tld(&v, &g).await;
        for round in 1..=2 {
            let r = v
                .resolve(&g, question(name, rtype::A), budget, true, false)
                .await
                .unwrap();
            assert_eq!(r.verdict, Verdict::Bogus, "{what} (question {round})");
        }
        assert_eq!(
            stats.insecure.load(Ordering::Relaxed),
            0,
            "{what}: never judged insecure"
        );
        flag.store(false, Ordering::Relaxed);
    }
}

/// REQ: DNS-011 (ADR-184) — a zone proven unsigned is remembered per upstream group, and no
/// longer than the TTL of the records that proved it (15 minutes at most): through the group
/// that proved it a later question isn't validated again (no bytes: the pipeline fetches it),
/// through another group it is; and when `t.`'s denials have TTL 0, nothing is remembered.
#[tokio::test]
async fn dns_011_offline_insecure_zone_proof_is_per_group_and_ttl_bounded() {
    let budget = Duration::from_secs(5);
    let z = Arc::new(zone());
    let (v, g1, _, _, _d1) = setup_zone(true, Arc::clone(&z)).await;
    let (_, g2, asked2, _, _d2) = setup_zone(true, Arc::clone(&z)).await;
    for g in [&g1, &g2] {
        warm_tld(&v, g).await;
    }
    let www = question("www.u.t", rtype::A);
    let r = v.resolve(&g1, www, budget, true, false).await.unwrap();
    assert_eq!(r.verdict, Verdict::Insecure);
    assert_ne!(r.bytes.len(), 0, "validated, and the zone proven unsigned");
    let r = v.resolve(&g1, www, budget, true, false).await.unwrap();
    assert_eq!(
        (r.verdict, r.bytes.len()),
        (Verdict::Insecure, 0),
        "remembered for the group that proved it"
    );
    let before = asked2.load(Ordering::Relaxed);
    let r = v.resolve(&g2, www, budget, true, false).await.unwrap();
    assert_eq!(r.verdict, Verdict::Insecure);
    assert_ne!(r.bytes.len(), 0, "another group proves it itself");
    assert!(
        asked2.load(Ordering::Relaxed) > before,
        "and asks its upstream"
    );
    // Denials with TTL 0: proven each time, never remembered.
    let (v, g, _, _, _d3) = setup_zone(true, Arc::new(zone_with(0))).await;
    warm_tld(&v, &g).await;
    for round in 1..=2 {
        let r = v.resolve(&g, www, budget, true, false).await.unwrap();
        assert_eq!(r.verdict, Verdict::Insecure, "TTL 0 (question {round})");
        assert_ne!(
            r.bytes.len(),
            0,
            "TTL 0: validated again (question {round})"
        );
    }
}
