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
use hickory_net::proto::rr::rdata::{A, CNAME, NS, NULL, SOA};
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
    /// NFR-004 (ADR-188) — milliseconds the answers to CNAME questions, which only link-by-link
    /// validation asks, are held back, without holding up the other questions.
    link_lag_ms: AtomicU64,
    /// DNS-011 — the denials of [`UNRELATED_DENIALS`] carry only another zone's unsigned SOA, in
    /// place of their own zone's SOA and NSEC records.
    unrelated_soa: AtomicBool,
    /// ADR-184 — the NSEC3 Opt-Out top-level domain `t.` and the zones below it.
    tld: Tld,
}

/// `dns_011_offline_denial_beside_an_unrelated_unsigned_soa_is_bogus`: questions for names in the
/// signed zones (the root, `s.t.`), each with the unsigned zone (`u.`, `v.t.`) whose SOA alone
/// its denial carries with `unrelated_soa`, and whether that is an NXDOMAIN (else a NODATA).
const UNRELATED_DENIALS: [(&str, RecordType, &str, bool); 4] = [
    ("a.", RecordType::AAAA, "u.", false),
    ("zz-nope.", RecordType::A, "u.", true),
    ("www.s.t.", RecordType::AAAA, "v.t.", false),
    ("nope.s.t.", RecordType::A, "v.t.", true),
];

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
        link_lag_ms: AtomicU64::new(0),
        unrelated_soa: AtomicBool::new(false),
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
/// - `s.t.` delegates `steer.s.t.` without a DS, and `dns.s.t.` is a CNAME to it (issue #115).
///
/// `u.t.`'s server answers like a parked domain's: every name has an SOA and NS of its own (the
/// validation library judged its answers bogus up to hickory-net 0.26.3). `old.u.t.`'s address
/// still has a signature of `u.t.`'s, whose key is gone: the library judges that one bogus.
/// `v.t.` is an ordinary unsigned zone.
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
    /// `dns_011_offline_links_that_do_not_hold_stay_bogus`: what `s.t.`'s answers are changed to
    /// ([`tamper`]).
    tamper: AtomicUsize,
    /// A signature of `*.w.s.t.`'s address by another key of `s.t.`, one that isn't in its key set
    /// ([`tampering::SECOND_SIGNATURE`]).
    second_signature: Record,
    /// `z3.s.t.`'s zone ([`hashed_zone`]): signed with NSEC3 under its own key, its NSEC3 chain
    /// included.
    hashed: BTreeMap<(Name, RecordType), Vec<Record>>,
    /// That chain: each record's hash and owner, in hash order.
    hashed_chain: Vec<(Vec<u8>, Name)>,
    /// Issue #115 (`dns.nextdns.io`) — `s.t.`'s records for its unsigned child `steer.s.t.`, with
    /// their signatures: `dns.s.t.`'s CNAME to it, and the NSEC owned by the delegation (`NS RRSIG
    /// NSEC`, a delegation without a DS) whose next name is `steer\000.s.t.`, the name right after
    /// it. They stand outside the zone's NSEC chain, as an online signer's records covering just
    /// one name do: no test asks for a name that the chain's records around them cover.
    steer_cut: BTreeMap<(Name, RecordType), Vec<Record>>,
    /// `steer.s.t.`'s zone, unsigned: its SOA and address, at its apex.
    steer: BTreeMap<(Name, RecordType), Vec<Record>>,
}

/// Ways to tamper with `s.t.`'s answers.
mod tampering {
    /// Nothing is changed.
    pub(super) const NONE: usize = 0;
    /// `www.s.t. A` is denied with another name's records.
    pub(super) const HIDE_TARGET: usize = 1;
    /// `www.s.t.` is an unsigned CNAME to `own.w.s.t.`, with that name's genuine denial.
    pub(super) const INJECT_CNAME: usize = 2;
    /// `own.w.s.t. A` is answered with the wildcard's address.
    pub(super) const REPLAY_WILDCARD: usize = 3;
    /// A wildcard's answers come without NSEC records.
    pub(super) const NO_WILDCARD_PROOF: usize = 4;
    /// A wildcard's answers come with another name's NSEC.
    pub(super) const OTHER_WILDCARD_PROOF: usize = 5;
    /// A wildcard's address is another one, under the genuine signature and NSEC.
    pub(super) const FORGE_WILDCARD: usize = 6;
    /// `ent.w.s.t. A` (an empty non-terminal) is answered with the wildcard's address and the
    /// NSEC that covers the name.
    pub(super) const REPLAY_WILDCARD_AT_ENT: usize = 7;
    /// `www.s.t. AAAA` (NODATA) comes with another name's signed address in the answer section.
    pub(super) const EXTRA_RECORD: usize = 8;
    /// `alias.s.t. NSEC` is answered as if the CNAME were followed: the CNAME, and the target's
    /// NSEC in the authority section.
    pub(super) const CNAME_FOR_NSEC: usize = 9;
    /// `a.own.w.s.t. A` is answered from `*.w.s.t.`, with the NSEC that covers the name (the one of
    /// `own.w.s.t.`, the name between them).
    pub(super) const REPLAY_WILDCARD_BELOW_NAME: usize = 10;
    /// As `REPLAY_WILDCARD_BELOW_NAME`, with an unsigned NSEC3 record owned directly below `s.t.`
    /// beside the NSEC.
    pub(super) const BESIDE_UNSIGNED_NSEC3: usize = 11;
    /// A wildcard's answers come with only an unsigned NSEC3 record of the unsigned zone `u.`, and
    /// `own.w.s.t. A` is answered with the wildcard's address.
    pub(super) const UNSIGNED_ZONE_NSEC3_PROOF: usize = 12;
    /// A wildcard's answers come with only `t.`'s signed NSEC3 record covering the name, and
    /// `own.w.s.t. A` is answered with the wildcard's address.
    pub(super) const OTHER_ZONE_NSEC3_PROOF: usize = 13;
    /// `*.w.s.t.`'s address comes with a second signature, by another key of `s.t.` that isn't in
    /// its key set (as during a key rollover).
    pub(super) const SECOND_SIGNATURE: usize = 14;
    /// `a.b.c.s.t. A` is answered with the wildcard's CNAME, its signature and NSEC only: the chain
    /// stops there, without the target's records.
    pub(super) const CHAIN_CUT_SHORT: usize = 15;
    /// `alias.s.t. A` is answered with its CNAME and the CNAME's signature only: nothing of the
    /// target, and nothing in the authority section.
    pub(super) const CNAME_ALONE: usize = 16;
    /// `twice.s.t. A` is answered with its CNAME and `www.s.t.`'s address, without the second
    /// link, `alias.s.t.`'s CNAME, between them.
    pub(super) const SECOND_LINK_LEFT_OUT: usize = 17;
    /// `twice.s.t. A` is answered with both CNAMEs of its chain, without `www.s.t.`'s address.
    pub(super) const LAST_RECORD_LEFT_OUT: usize = 18;
    /// A name below `k3.z3.s.t.` is answered with the wildcard CNAME and the NSEC3 record covering
    /// its next closer name only: nothing of the target.
    pub(super) const WILDCARD_CNAME_ALONE: usize = 19;
    /// An A question for a name `*.z3.s.t.` serves, or for `nope.t.`, is answered with NOERROR, the
    /// zone's SOA and its signature in the answer section, and the NSEC3 record covering the name
    /// (its next closer name): no record of the name.
    pub(super) const SOA_IN_ANSWER: usize = 20;
    /// `out.s.t. AAAA` is answered with its CNAME and the unsigned SOA of `v.t.`, the target's zone.
    pub(super) const CNAME_AND_UNSIGNED_SOA: usize = 21;
    /// `h.z3.s.t. A`, asked or after the wildcard CNAME `*.k3.z3.s.t.`, is answered with the address
    /// of `*.z3.s.t.` made for that name, in place of its own.
    pub(super) const OTHER_WILDCARD_FOR_TARGET: usize = 22;
    /// `x.h.z3.s.t. A` is answered with `h.z3.s.t.`'s address and signature first, then the address
    /// of `*.z3.s.t.` made for the name, beside the NSEC3 record covering the name.
    pub(super) const EXISTING_NAME_FIRST: usize = 23;
    /// `x.k3.z3.s.t. A` is answered with the target's address before the wildcard CNAME.
    pub(super) const TARGET_FIRST: usize = 24;
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

/// The owner of `name`'s NSEC3 in `zone`, with `t.`'s parameters.
fn hashed_owner(name: &Name, zone: &str) -> Name {
    n(&format!("{}.{zone}", b32hex(&h3(name))))
}

/// An NSEC3 record without a signature, owned directly below `zone` at `name`'s hash.
fn unsigned_nsec3(name: &Name, zone: &str) -> Record {
    let nsec3 = NSEC3::try_new(
        Nsec3HashAlgorithm::SHA1,
        false,
        0,
        Vec::new(),
        vec![0xff; 20],
        [RecordType::A, RecordType::RRSIG],
    )
    .unwrap();
    Record::from_rdata(
        hashed_owner(name, zone),
        300,
        RData::DNSSEC(DNSSECRData::NSEC3(nsec3)),
    )
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

/// A DNAME to `target`, as hickory reads one from the wire (it has no type of its own for it).
fn dname(target: &str) -> RData {
    let mut wire = Vec::new();
    for label in target.split('.').filter(|l| !l.is_empty()) {
        wire.push(u8::try_from(label.len()).unwrap());
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    RData::Unknown {
        code: RecordType::DNAME,
        rdata: NULL::with(wire),
    }
}

/// The CNAMEs in `s.t.`'s signed zone.
const ALIASES: [(&str, &str); 13] = [
    ("alias.s.t.", "www.s.t."),
    ("twice.s.t.", "alias.s.t."),
    ("gone.s.t.", "nope.s.t."),
    ("wild.s.t.", "any.w.s.t."),
    ("via.s.t.", "any.c.s.t."),
    ("forged.s.t.", "www.s.t."),
    ("loop1.s.t.", "loop2.s.t."),
    ("loop2.s.t.", "loop1.s.t."),
    // Into `t.`, signed with NSEC3, and into `v.t.`, unsigned.
    ("up.s.t.", "x.t."),
    ("out.s.t.", "x.l.v.t."),
    // Through `v.t.` and back.
    ("round.s.t.", "back.v.t."),
    // Into `u.t.`, at a name whose answer the validation library judges bogus.
    ("stale.s.t.", "old.u.t."),
    // Into `z3.s.t.`, signed with NSEC3, at a name its wildcard `*.z3.s.t.` serves.
    ("wz.s.t.", "q.z3.s.t."),
];

/// [`hashed_zone`]: the zone's record sets with their signatures (the NSEC3 chain included), that
/// chain (each record's hash and owner, in hash order), and the DS for it.
struct HashedZone {
    sets: BTreeMap<(Name, RecordType), Vec<Record>>,
    chain: Vec<(Vec<u8>, Name)>,
    ds: DS,
}

/// The zone `z3.s.t.`, delegated from `s.t.` with a DS: signed with NSEC3 under its own key (`t.`'s
/// parameters, without Opt-Out), with a wildcard address right below its apex. `h.z3.s.t.` has an
/// address, and `*.k3.z3.s.t.`, below the empty non-terminal `k3.z3.s.t.`, is a wildcard CNAME to
/// it; `*.k4.z3.s.t.`, below `k4.z3.s.t.`, is one to `q.z3.s.t.`, which `*.z3.s.t.` serves.
fn hashed_zone() -> HashedZone {
    let apex = n("z3.s.t.");
    let (signer, dnskey) = zone_signer(&apex);
    let ds = DS::from_key(dnskey.public_key(), &apex, DigestType::SHA256).unwrap();
    let mut chain = [
        (
            apex.clone(),
            vec![
                RecordType::NS,
                RecordType::SOA,
                RecordType::RRSIG,
                RecordType::DNSKEY,
                RecordType::NSEC3PARAM,
            ],
        ),
        (n("*.z3.s.t."), vec![RecordType::A, RecordType::RRSIG]),
        (n("h.z3.s.t."), vec![RecordType::A, RecordType::RRSIG]),
        (n("k3.z3.s.t."), vec![]),
        (
            n("*.k3.z3.s.t."),
            vec![RecordType::CNAME, RecordType::RRSIG],
        ),
        (n("k4.z3.s.t."), vec![]),
        (
            n("*.k4.z3.s.t."),
            vec![RecordType::CNAME, RecordType::RRSIG],
        ),
    ];
    chain.sort_by_key(|(name, _)| h3(name));
    let mut rrsets: Vec<(Name, Vec<RData>)> = vec![
        (apex.clone(), vec![RData::SOA(soa_of("z3.s.t."))]),
        (apex.clone(), vec![RData::NS(NS(n("ns.z3.s.t.")))]),
        (
            apex.clone(),
            vec![RData::DNSSEC(DNSSECRData::DNSKEY(dnskey))],
        ),
        (n("*.z3.s.t."), vec![RData::A(A::new(192, 0, 2, 34))]),
        (n("h.z3.s.t."), vec![RData::A(A::new(192, 0, 2, 35))]),
        (n("*.k3.z3.s.t."), vec![RData::CNAME(CNAME(n("h.z3.s.t.")))]),
        (n("*.k4.z3.s.t."), vec![RData::CNAME(CNAME(n("q.z3.s.t.")))]),
    ];
    for (i, (name, types)) in chain.iter().enumerate() {
        let next = h3(&chain[(i + 1) % chain.len()].0);
        let nsec3 = NSEC3::try_new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            next,
            types.iter().copied(),
        )
        .unwrap();
        rrsets.push((
            hashed_owner(name, "z3.s.t."),
            vec![RData::DNSSEC(DNSSECRData::NSEC3(nsec3))],
        ));
    }
    HashedZone {
        sets: signed(rrsets, &signer, 3600),
        chain: chain
            .iter()
            .map(|(name, _)| (h3(name), hashed_owner(name, "z3.s.t.")))
            .collect(),
        ds,
    }
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
        let nsec3 = NSEC3::try_new(
            Nsec3HashAlgorithm::SHA1,
            true,
            0,
            Vec::new(),
            next,
            types.iter().copied(),
        )
        .unwrap();
        denials.push((
            h3_owner(name),
            vec![RData::DNSSEC(DNSSECRData::NSEC3(nsec3))],
        ));
    }
    let mut sets = signed(rrsets, &signer, 3600);
    sets.extend(signed(denials, &signer, proof_ttl));
    let HashedZone {
        sets: hashed,
        chain: hashed_chain,
        ds: hashed_ds,
    } = hashed_zone();
    let mut child_sets = vec![
        (n("s.t."), vec![RData::SOA(soa_of("s.t."))]),
        (n("s.t."), vec![RData::NS(NS(n("ns.s.t.")))]),
        (
            n("s.t."),
            vec![RData::DNSSEC(DNSSECRData::DNSKEY(child_key))],
        ),
        (n("www.s.t."), vec![RData::A(A::new(192, 0, 2, 30))]),
        // Wildcards right below the apex's children: an address, and a CNAME.
        (n("*.w.s.t."), vec![RData::A(A::new(192, 0, 2, 31))]),
        (n("*.c.s.t."), vec![RData::CNAME(CNAME(n("www.s.t.")))]),
        (n("*.o.s.t."), vec![RData::CNAME(CNAME(n("out.s.t.")))]),
        // A wildcard CNAME to a name that doesn't exist, below one that does.
        (n("*.k.s.t."), vec![RData::CNAME(CNAME(n("a.own.w.s.t.")))]),
        // A name below `w.s.t.` that exists, and one below that makes an empty non-terminal.
        (n("own.w.s.t."), vec![RData::A(A::new(192, 0, 2, 32))]),
        (n("x.ent.w.s.t."), vec![RData::A(A::new(192, 0, 2, 33))]),
        // A signed delegation to `z3.s.t.`, a zone signed with NSEC3. It sorts after every other
        // name, so of their NSEC records only the last one's (`www.s.t.`'s) changes.
        (n("z3.s.t."), vec![RData::NS(NS(n("ns.z3.s.t.")))]),
        (
            n("z3.s.t."),
            vec![RData::DNSSEC(DNSSECRData::DS(hashed_ds))],
        ),
        // RFC 6672 — names below `dn.s.t.` are names below `s.t.` (`www.dn.s.t.` is `www.s.t.`).
        (n("dn.s.t."), vec![dname("s.t.")]),
    ];
    for (alias, target) in ALIASES {
        child_sets.push((n(alias), vec![RData::CNAME(CNAME(n(target)))]));
    }
    // The NSEC chain: every name in canonical order, the last one pointing to the apex.
    let mut types: BTreeMap<Name, Vec<RecordType>> = BTreeMap::new();
    for (name, datas) in &child_sets {
        types
            .entry(name.clone())
            .or_default()
            .push(datas[0].record_type());
    }
    let names: Vec<Name> = types.keys().cloned().collect();
    for (i, (name, mut listed)) in types.into_iter().enumerate() {
        listed.extend([RecordType::RRSIG, RecordType::NSEC]);
        let next = names[(i + 1) % names.len()].clone();
        child_sets.push((
            name,
            vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(next, listed)))],
        ));
    }
    let mut child = signed(child_sets, &child_signer, 3600);
    // Issue #115 — the unsigned child `steer.s.t.`, and a signed CNAME into it.
    let steer = n("steer.s.t.");
    let after_steer = Name::from_labels([&b"steer\0"[..], &b"s"[..], &b"t"[..]]).unwrap();
    let steer_cut = signed(
        vec![
            (n("dns.s.t."), vec![RData::CNAME(CNAME(steer.clone()))]),
            (
                steer.clone(),
                vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                    after_steer,
                    [RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
                )))],
            ),
        ],
        &child_signer,
        3600,
    );
    let mut steer_zone = BTreeMap::new();
    for d in [
        RData::SOA(soa_of("steer.s.t.")),
        RData::A(A::new(192, 0, 2, 60)),
    ] {
        steer_zone.insert(
            (steer.clone(), d.record_type()),
            vec![Record::from_rdata(steer.clone(), 3600, d)],
        );
    }
    // `forged.s.t.`'s signature doesn't verify.
    for r in child
        .get_mut(&(n("forged.s.t."), RecordType::CNAME))
        .unwrap()
    {
        if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = &r.data {
            let mut bytes = sig.sig().to_vec();
            bytes[0] ^= 0xff;
            r.data = RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(
                sig.input().clone(),
                bytes,
            )));
        }
    }
    // A second signature of `*.w.s.t.`'s address, by another key of `s.t.` (not in its key set).
    let (other_signer, _) = zone_signer(&n("s.t."));
    let second_signature = signed(
        vec![(n("*.w.s.t."), vec![RData::A(A::new(192, 0, 2, 31))])],
        &other_signer,
        3600,
    )
    .into_values()
    .flatten()
    .find(|r| r.record_type() == RecordType::RRSIG)
    .unwrap();
    let mut plain = BTreeMap::new();
    for (name, d) in [
        (n("v.t."), RData::SOA(soa_of("v.t."))),
        (n("v.t."), RData::NS(NS(n("ns.v.t.")))),
        (n("x.l.v.t."), RData::A(A::new(192, 0, 2, 40))),
        (n("back.v.t."), RData::CNAME(CNAME(n("www.s.t.")))),
        (n("www.u.t."), RData::A(A::new(192, 0, 2, 50))),
        (n("mtalk.u.t."), RData::CNAME(CNAME(n("x.l.v.t.")))),
    ] {
        let rtype = d.record_type();
        plain.insert(
            (name.clone(), rtype),
            vec![Record::from_rdata(name, 3600, d)],
        );
    }
    plain.extend(signed(
        vec![(n("old.u.t."), vec![RData::A(A::new(192, 0, 2, 51))])],
        &zone_signer(&n("u.t.")).0,
        3600,
    ));
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
        tamper: AtomicUsize::new(tampering::NONE),
        second_signature,
        hashed,
        hashed_chain,
        steer_cut,
        steer: steer_zone,
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

    /// The NSEC3 of `z3.s.t.` whose span covers `name`'s hash.
    fn hashed_covering(&self, name: &Name) -> Vec<Record> {
        let h = h3(name);
        let (_, owner) = self
            .hashed_chain
            .iter()
            .rev()
            .find(|(hash, _)| *hash < h)
            .unwrap_or_else(|| self.hashed_chain.last().unwrap());
        self.hashed[&(owner.clone(), RecordType::NSEC3)].clone()
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
    if below("z3.s.t.") {
        hashed_answer(z, m, qn, qt);
    } else if below("s.t.") {
        child_answer(z, m, qn, qt);
    } else if below("u.t.") {
        parked_answer(z, m, qn, qt);
    } else if below("v.t.") {
        if !chase(&z.plain, m, qn, qt) {
            if unsigned_nxdomain(qn) {
                m.metadata.response_code = ResponseCode::NXDomain;
            }
            m.add_authorities(z.plain[&(n("v.t."), RecordType::SOA)].clone());
        }
    } else if *qn == n("s.t.") && qt == RecordType::DS && z.no_ds.load(Ordering::Relaxed) {
        // The DS left out: the apex's NSEC3 (the closest encloser) and another name's span.
        m.add_authorities(z.soa());
        m.add_authorities(z.matching(&n("t.")).unwrap());
        add_once(m, z.covering(&n("u.t.")));
    } else if let Some(rs) = z.sets.get(&(qn.clone(), qt)) {
        m.add_answers(rs.clone());
    } else if z.tamper.load(Ordering::Relaxed) == tampering::SOA_IN_ANSWER
        && *qn == n("nope.t.")
        && qt == RecordType::A
    {
        m.add_answers(z.soa());
        add_once(m, z.covering(qn));
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
    let tamper = z.tamper.load(Ordering::Relaxed);
    if tamper == tampering::INJECT_CNAME && *qn == n("www.s.t.") && qt == RecordType::AAAA {
        let cname = RData::CNAME(CNAME(n("own.w.s.t.")));
        m.add_answers(vec![Record::from_rdata(qn.clone(), 300, cname)]);
        m.add_authorities(z.child[&(n("s.t."), RecordType::SOA)].clone());
        m.add_authorities(z.child[&(n("own.w.s.t."), RecordType::NSEC)].clone());
        return;
    }
    if tamper == tampering::CNAME_FOR_NSEC && *qn == n("alias.s.t.") && qt == RecordType::NSEC {
        m.add_answers(z.child[&(qn.clone(), RecordType::CNAME)].clone());
        m.add_authorities(z.child[&(n("www.s.t."), RecordType::NSEC)].clone());
        return;
    }
    // As a recursive resolver: CNAMEs are followed, out of the zone too (into `z3.s.t.`, below its
    // apex, included).
    let z3 = n("z3.s.t.");
    let mut name = qn.clone();
    for _ in 0..4 {
        if !n("s.t.").zone_of(&name) || (name != z3 && z3.zone_of(&name)) {
            let Some(rs) = z.plain.get(&(name.clone(), RecordType::CNAME)) else {
                tld_answer(z, m, &name, qt);
                return;
            };
            m.add_answers(rs.clone());
            let RData::CNAME(CNAME(target)) = &rs[0].data else {
                return;
            };
            name = target.clone();
            continue;
        }
        let twice_a = *qn == n("twice.s.t.") && qt == RecordType::A;
        if tamper == tampering::SECOND_LINK_LEFT_OUT && twice_a && name == n("alias.s.t.") {
            name = n("www.s.t.");
            continue;
        }
        if n("steer.s.t.").zone_of(&name)
            || z.steer_cut.contains_key(&(name.clone(), RecordType::CNAME))
        {
            let Some(target) = steer_link(z, m, &name, qt) else {
                return;
            };
            name = target;
            continue;
        }
        let next = child_link(z, m, &name, qt, tamper);
        match next {
            Some(_)
                if tamper == tampering::CHAIN_CUT_SHORT
                    && *qn == n("a.b.c.s.t.")
                    && qt == RecordType::A =>
            {
                return;
            }
            Some(_)
                if tamper == tampering::CNAME_ALONE
                    && *qn == n("alias.s.t.")
                    && qt == RecordType::A =>
            {
                return;
            }
            Some(target)
                if tamper == tampering::LAST_RECORD_LEFT_OUT
                    && twice_a
                    && target == n("www.s.t.") =>
            {
                return;
            }
            Some(_)
                if tamper == tampering::CNAME_AND_UNSIGNED_SOA
                    && *qn == n("out.s.t.")
                    && qt == RecordType::AAAA =>
            {
                m.add_authorities(z.plain[&(n("v.t."), RecordType::SOA)].clone());
                return;
            }
            Some(target) => name = target,
            None => return,
        }
    }
}

/// Issue #115 — `dns.s.t.`, or a name at or below `steer.s.t.`: what `s.t.` and its unsigned child
/// answer (`steer.s.t. DS` is the parent's question); the CNAME's target when that is to be
/// followed.
fn steer_link(z: &Tld, m: &mut Message, qn: &Name, qt: RecordType) -> Option<Name> {
    let steer = n("steer.s.t.");
    if *qn == steer && qt == RecordType::DS {
        // The parent's denial: its SOA, and the NSEC owned by the delegation.
        m.add_authorities(z.child[&(n("s.t."), RecordType::SOA)].clone());
        m.add_authorities(z.steer_cut[&(steer, RecordType::NSEC)].clone());
        return None;
    }
    if steer.zone_of(qn) {
        steer_answer(z, m, qn, qt);
        return None;
    }
    m.add_answers(z.steer_cut[&(qn.clone(), RecordType::CNAME)].clone());
    (qt != RecordType::CNAME).then_some(steer)
}

/// Issue #115 — `steer.s.t.`'s server, like `steering.nextdns.io`'s: its SOA and address at its
/// apex, unsigned; any other question gets an empty NOERROR answer, as that server answers an NS
/// question (the validation library looks for zone cuts with NS questions).
fn steer_answer(z: &Tld, m: &mut Message, qn: &Name, qt: RecordType) {
    if let Some(rs) = z.steer.get(&(qn.clone(), qt)) {
        m.add_answers(rs.clone());
    }
}

/// One name of `s.t.`'s zone: what answers the question, with the proofs; the target when that
/// is a CNAME to follow.
fn child_link(z: &Tld, m: &mut Message, qn: &Name, qt: RecordType, tamper: usize) -> Option<Name> {
    // RFC 6672 §3.2 — below a DNAME's owner: the DNAME with its signature, then the CNAME made from
    // it (with the DNAME's TTL, and no signature of its own), whose target is followed unless the
    // question is for the CNAME.
    if let Some(target) = dname_synthesis(z, m, qn) {
        return (qt != RecordType::CNAME).then_some(target);
    }
    let apex = n("s.t.");
    let nsec = |m: &mut Message, owner: &Name| {
        add_once(m, z.child[&(owner.clone(), RecordType::NSEC)].clone());
    };
    // The greatest owner before `name`: its NSEC covers it.
    let covering = |name: &Name| -> Name {
        z.child
            .keys()
            .filter(|(o, t)| *t == RecordType::NSEC && o < name)
            .map(|(o, _)| o.clone())
            .max()
            .unwrap_or_else(|| apex.clone())
    };
    let hidden = tamper == tampering::HIDE_TARGET && *qn == n("www.s.t.") && qt == RecordType::A;
    let replayed = matches!(
        tamper,
        tampering::REPLAY_WILDCARD
            | tampering::UNSIGNED_ZONE_NSEC3_PROOF
            | tampering::OTHER_ZONE_NSEC3_PROOF
    ) && *qn == n("own.w.s.t.")
        && qt == RecordType::A;
    let exists = z.child.contains_key(&(qn.clone(), RecordType::NSEC));
    if exists && !hidden && !replayed {
        for t in [qt, RecordType::CNAME] {
            if let Some(rs) = z.child.get(&(qn.clone(), t)) {
                m.add_answers(rs.clone());
                return match (&rs[0].data, t == qt) {
                    (RData::CNAME(CNAME(target)), false) => Some(target.clone()),
                    _ => None,
                };
            }
        }
        add_once(m, z.child[&(apex.clone(), RecordType::SOA)].clone());
        nsec(m, qn);
        if tamper == tampering::EXTRA_RECORD && *qn == n("www.s.t.") && qt == RecordType::AAAA {
            m.add_answers(z.child[&(n("own.w.s.t."), RecordType::A)].clone());
        }
        return None;
    }
    // The wildcard at the closest encloser, the nearest name above that exists (RFC 4592 §3.3.1),
    // unless the name exists as an empty non-terminal.
    let mut encloser = qn.base_name();
    while encloser != apex && !z.child.keys().any(|(o, _)| encloser.zone_of(o)) {
        encloser = encloser.base_name();
    }
    let below_name = matches!(
        tamper,
        tampering::REPLAY_WILDCARD_BELOW_NAME | tampering::BESIDE_UNSIGNED_NSEC3
    ) && *qn == n("a.own.w.s.t.")
        && qt == RecordType::A;
    let wildcard = if below_name {
        n("*.w.s.t.")
    } else {
        encloser.prepend_label("*").unwrap()
    };
    let at_ent = tamper == tampering::REPLAY_WILDCARD_AT_ENT
        && *qn == n("ent.w.s.t.")
        && qt == RecordType::A;
    let non_terminal = !at_ent && z.child.keys().any(|(o, _)| qn.zone_of(o) && o != qn);
    if !hidden && !non_terminal {
        for t in [qt, RecordType::CNAME] {
            let Some(rs) = z.child.get(&(wildcard.clone(), t)) else {
                continue;
            };
            m.add_answers(rs.iter().cloned().map(|mut r| {
                r.name = qn.clone();
                if tamper == tampering::FORGE_WILDCARD
                    && let RData::A(a) = &mut r.data
                {
                    *a = A::new(192, 0, 2, 66);
                }
                r
            }));
            if tamper == tampering::SECOND_SIGNATURE
                && wildcard == n("*.w.s.t.")
                && t == RecordType::A
            {
                let mut second = z.second_signature.clone();
                second.name = qn.clone();
                m.add_answers(vec![second]);
            }
            match tamper {
                tampering::NO_WILDCARD_PROOF => {}
                tampering::OTHER_WILDCARD_PROOF => nsec(m, &n("www.s.t.")),
                tampering::UNSIGNED_ZONE_NSEC3_PROOF => {
                    m.add_authorities(vec![unsigned_nsec3(qn, "u.")]);
                }
                tampering::OTHER_ZONE_NSEC3_PROOF => {
                    m.add_authorities(z.covering(qn));
                }
                _ => nsec(m, &covering(qn)),
            }
            if tamper == tampering::BESIDE_UNSIGNED_NSEC3 {
                m.add_authorities(vec![unsigned_nsec3(qn, "s.t.")]);
            }
            return match (&rs[0].data, t == qt) {
                (RData::CNAME(CNAME(target)), false) => Some(target.clone()),
                _ => None,
            };
        }
    }
    add_once(m, z.child[&(apex.clone(), RecordType::SOA)].clone());
    if hidden {
        nsec(m, &n("alias.s.t."));
    } else if non_terminal {
        nsec(m, &covering(qn));
    } else if z.child.contains_key(&(wildcard.clone(), RecordType::NSEC)) {
        // The wildcard exists without the type (RFC 4035 §3.1.3.4): NODATA, with the NSEC that
        // shows no closer name exists and the wildcard's own.
        nsec(m, &covering(qn));
        nsec(m, &wildcard);
    } else {
        m.metadata.response_code = ResponseCode::NXDomain;
        nsec(m, &covering(qn));
        nsec(m, &covering(&wildcard));
    }
    None
}

/// For `qn` below `dn.s.t.` (a DNAME to `s.t.`): adds the DNAME, its signature and the CNAME made
/// from it to `m`'s answer section, and returns the CNAME's target.
fn dname_synthesis(z: &Tld, m: &mut Message, qn: &Name) -> Option<Name> {
    let owner = n("dn.s.t.");
    if *qn == owner || !owner.zone_of(qn) {
        return None;
    }
    let records = z.child.get(&(owner.clone(), RecordType::DNAME))?;
    m.add_answers(records.clone());
    let keep = usize::from(qn.num_labels() - owner.num_labels());
    let prefix: Vec<String> = qn
        .iter()
        .take(keep)
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .collect();
    let target = n(&format!("{}.s.t.", prefix.join(".")));
    m.add_answers(vec![Record::from_rdata(
        qn.clone(),
        3600,
        RData::CNAME(CNAME(target.clone())),
    )]);
    Some(target)
}

/// `z3.s.t.`'s zone, signed with NSEC3: its records; for a name below the apex that has none, the
/// wildcard's (RFC 4592) with the NSEC3 record covering the next closer name (RFC 5155 §7.2.6);
/// anything else, the SOA.
fn hashed_answer(z: &Tld, m: &mut Message, qn: &Name, qt: RecordType) {
    let apex = n("z3.s.t.");
    let tamper = z.tamper.load(Ordering::Relaxed);
    // `*.z3.s.t.`'s address made for `name`.
    let from_wildcard = |name: &Name| {
        z.hashed[&(n("*.z3.s.t."), RecordType::A)]
            .iter()
            .cloned()
            .map(|mut r| {
                r.name = name.clone();
                r
            })
            .collect::<Vec<_>>()
    };
    let h = n("h.z3.s.t.");
    if tamper == tampering::OTHER_WILDCARD_FOR_TARGET && *qn == h && qt == RecordType::A {
        m.add_answers(from_wildcard(qn));
        return;
    }
    if let Some(rs) = z.hashed.get(&(qn.clone(), qt)) {
        m.add_answers(rs.clone());
        return;
    }
    // Below the empty non-terminals `k3.z3.s.t.` and `k4.z3.s.t.`, the wildcard CNAMEs below them
    // with the NSEC3 record covering the next closer name (RFC 5155 §7.2.6), then the target:
    // `h.z3.s.t.`'s address, or for another type the zone's SOA and the target's own NSEC3 record
    // (§7.2.3); `q.z3.s.t.` as `*.z3.s.t.` serves it.
    for (ent, wildcard) in [
        ("k3.z3.s.t.", "*.k3.z3.s.t."),
        ("k4.z3.s.t.", "*.k4.z3.s.t."),
    ] {
        let ent = n(ent);
        if qt == RecordType::DS || *qn == ent || !ent.zone_of(qn) {
            continue;
        }
        let records = &z.hashed[&(n(wildcard), RecordType::CNAME)];
        let RData::CNAME(CNAME(target)) = records[0].data.clone() else {
            return;
        };
        m.add_answers(records.iter().cloned().map(|mut r| {
            r.name = qn.clone();
            r
        }));
        add_once(
            m,
            z.hashed_covering(&qn.trim_to(usize::from(ent.num_labels()) + 1)),
        );
        if qt == RecordType::CNAME || tamper == tampering::WILDCARD_CNAME_ALONE {
            return;
        }
        if tamper == tampering::OTHER_WILDCARD_FOR_TARGET && target == h && qt == RecordType::A {
            m.add_answers(from_wildcard(&target));
        } else if target != h {
            hashed_answer(z, m, &target, qt);
        } else if let Some(rs) = z.hashed.get(&(target.clone(), qt)) {
            m.add_answers(rs.clone());
        } else {
            add_once(m, z.hashed[&(apex.clone(), RecordType::SOA)].clone());
            add_once(
                m,
                z.hashed[&(hashed_owner(&target, "z3.s.t."), RecordType::NSEC3)].clone(),
            );
        }
        if tamper == tampering::TARGET_FIRST && qt == RecordType::A {
            let (at_name, others): (Vec<_>, Vec<_>) = std::mem::take(&mut m.answers)
                .into_iter()
                .partition(|r| r.name == *qn);
            m.answers = others;
            m.answers.extend(at_name);
        }
        return;
    }
    let exists = *qn == apex || z.hashed.keys().any(|(o, _)| o == qn);
    // Below a name that exists, other than the apex: no wildcard of the apex serves it (RFC 4592
    // §3.3.1). NXDOMAIN, with the NSEC3 records of the closest encloser, of the next closer name
    // and of the wildcard below the encloser (RFC 5155 §7.2.2).
    let has_nsec3 = |name: &Name| {
        z.hashed
            .contains_key(&(hashed_owner(name, "z3.s.t."), RecordType::NSEC3))
    };
    let (mut encloser, mut next_closer) = (qn.base_name(), qn.clone());
    while encloser != apex && !has_nsec3(&encloser) {
        next_closer = encloser.clone();
        encloser = encloser.base_name();
    }
    if !exists && qt != RecordType::DS && encloser != apex {
        if tamper == tampering::EXISTING_NAME_FIRST
            && *qn == n("x.h.z3.s.t.")
            && qt == RecordType::A
        {
            m.add_answers(z.hashed[&(encloser.clone(), RecordType::A)].clone());
            m.add_answers(from_wildcard(qn));
            add_once(m, z.hashed_covering(qn));
            return;
        }
        m.metadata.response_code = ResponseCode::NXDomain;
        add_once(m, z.hashed[&(apex.clone(), RecordType::SOA)].clone());
        add_once(
            m,
            z.hashed[&(hashed_owner(&encloser, "z3.s.t."), RecordType::NSEC3)].clone(),
        );
        add_once(m, z.hashed_covering(&next_closer));
        add_once(m, z.hashed_covering(&encloser.prepend_label("*").unwrap()));
        return;
    }
    if !exists && let Some(rs) = z.hashed.get(&(n("*.z3.s.t."), qt)) {
        if tamper == tampering::SOA_IN_ANSWER && qt == RecordType::A {
            m.add_answers(z.hashed[&(apex.clone(), RecordType::SOA)].clone());
        } else {
            m.add_answers(rs.iter().cloned().map(|mut r| {
                r.name = qn.clone();
                r
            }));
        }
        let next_closer = qn.trim_to(usize::from(apex.num_labels()) + 1);
        add_once(m, z.hashed_covering(&next_closer));
        return;
    }
    m.add_authorities(z.hashed[&(apex, RecordType::SOA)].clone());
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
        if unsigned_nxdomain(qn) {
            m.metadata.response_code = ResponseCode::NXDomain;
        }
        m.add_authorities(z.plain[&(n("u."), RecordType::SOA)].clone());
    }
}

/// DNS-011 — names at or below these don't exist in the unsigned zones `u.` and `v.t.`: they are
/// answered NXDOMAIN (any other name without records there, NODATA).
const UNSIGNED_NXDOMAIN: [&str; 2] = ["nx.u.", "nx.v.t."];

fn unsigned_nxdomain(qn: &Name) -> bool {
    UNSIGNED_NXDOMAIN.iter().any(|zone| n(zone).zone_of(qn))
}

/// DNS-011 — with `unrelated_soa`, the denial of a question of [`UNRELATED_DENIALS`]: the other
/// zone's unsigned SOA, and whether it is an NXDOMAIN.
fn unrelated_denial(z: &Zone, qn: &Name, qt: RecordType) -> Option<(Vec<Record>, bool)> {
    if !z.unrelated_soa.load(Ordering::Relaxed) {
        return None;
    }
    let &(_, _, zone, nxdomain) = UNRELATED_DENIALS
        .iter()
        .find(|&&(name, t, _, _)| *qn == n(name) && t == qt)?;
    let key = (n(zone), RecordType::SOA);
    let soa = z.plain.get(&key).or_else(|| z.tld.plain.get(&key))?;
    Some((soa.clone(), nxdomain))
}

/// The fake root server: answers from the zone (with signatures), NODATA or NXDOMAIN with the
/// SOA and the NSEC records that prove it. Counts the questions it gets.
async fn serve(z: Arc<Zone>, asked: Arc<AtomicUsize>) -> std::net::SocketAddr {
    let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
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
            } else if let Some((soa, nxdomain)) = unrelated_denial(&z, &qn, qt) {
                if nxdomain {
                    m.metadata.response_code = ResponseCode::NXDomain;
                }
                m.add_authorities(soa);
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
            let Ok(out) = m.to_vec() else {
                continue;
            };
            let late = if qt == RecordType::CNAME {
                z.link_lag_ms.load(Ordering::Relaxed)
            } else {
                0
            };
            if late > 0 {
                let s = Arc::clone(&s);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(late)).await;
                    let _ = s.send_to(&out, from).await;
                });
            } else {
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
/// NSEC3 Opt-Out span (`u.t.`, whose server answers like a parked domain's) is insecure: served,
/// without AD, also when the validation library judges the answer bogus (`old.u.t.`, with a
/// signature left over). `t.`'s denial of the DS proves it: the NSEC3 matching `t.` (the closest
/// encloser) and an Opt-Out NSEC3 covering `u.t.`'s hash.
#[tokio::test]
async fn dns_011_offline_opt_out_unsigned_delegation_is_insecure() {
    let (v, g, _, stats, _dir) = setup(true).await;
    let budget = Duration::from_secs(5);
    warm_tld(&v, &g).await;
    for name in ["www.u.t", "old.u.t"] {
        let r = v
            .resolve(&g, question(name, rtype::A), budget, true, false)
            .await
            .unwrap();
        assert_eq!(r.verdict, Verdict::Insecure, "{name} A");
        assert_ne!(r.bytes.len(), 0, "an answer to serve: {name}");
        assert!(!telltale_proto::Header::parse(&r.bytes).unwrap().flags.ad());
    }
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

/// REQ: DNS-011 (RFC 4035 §5.4) — a denial is proven by the records of the name's own zone. A
/// negative answer for a name in a signed zone whose authority section holds only another zone's
/// unsigned SOA, and nothing of the name's zone, is bogus, never insecure: `validate` answers it
/// with SERVFAIL. NODATA and NXDOMAIN in the signed root, beside the SOA of `u.` (an
/// unsigned zone the root delegates), and in the signed zone `s.t.`, beside the SOA of `v.t.` (an
/// unsigned zone in `t.`). The genuine denials of the same questions are secure. The case checked
/// by hand in pull request #106, with a stub upstream.
#[tokio::test]
async fn dns_011_offline_denial_beside_an_unrelated_unsigned_soa_is_bogus() {
    let budget = Duration::from_secs(5);
    let z = Arc::new(zone());
    let (v, g, _, _, _dir) = setup_zone(true, Arc::clone(&z)).await;
    warm_tld(&v, &g).await;
    let ask = |name: &str, qtype: RecordType| question(name.trim_end_matches('.'), qtype.into());
    for (name, qtype, _, nxdomain) in UNRELATED_DENIALS {
        let r = v
            .resolve(&g, ask(name, qtype), budget, true, false)
            .await
            .unwrap();
        let code = if nxdomain {
            telltale_proto::rcode::NXDOMAIN
        } else {
            telltale_proto::rcode::NOERROR
        };
        assert_eq!(
            (r.verdict, rcode(&r.bytes)),
            (Verdict::Secure, code),
            "{name} {qtype}, its own zone's signed denial"
        );
    }
    z.unrelated_soa.store(true, Ordering::Relaxed);
    let (v, g, _, stats, _dir) = setup_zone(true, Arc::clone(&z)).await;
    warm_tld(&v, &g).await;
    let secure = stats.secure.load(Ordering::Relaxed);
    // Compared at the end, so that a failure shows every question's verdict.
    let (mut got, mut want) = (Vec::new(), Vec::new());
    for (name, qtype, other, _) in UNRELATED_DENIALS {
        for round in 1..=2 {
            let r = v.resolve(&g, ask(name, qtype), budget, true, false).await;
            let what =
                format!("{name} {qtype} beside the unsigned SOA of {other} (question {round})");
            got.push((what.clone(), r.map(|r| r.verdict).ok()));
            want.push((what, Some(Verdict::Bogus)));
        }
    }
    assert_eq!(got, want);
    assert_eq!(
        stats.insecure.load(Ordering::Relaxed),
        0,
        "never judged insecure"
    );
    assert_eq!(stats.secure.load(Ordering::Relaxed), secure, "nor secure");
}

/// REQ: DNS-011 (T10.9, ADR-098) — the control of the test above: a genuine denial in an unsigned
/// zone, with that zone's own SOA, stays insecure (served, without AD), never bogus. NODATA and
/// NXDOMAIN in `u.` (delegated from the signed root without a DS) and in `v.t.` (inside `t.`'s
/// NSEC3 Opt-Out span), one and five labels below the zone.
#[tokio::test]
async fn dns_011_offline_unsigned_zone_denials_stay_insecure() {
    use telltale_proto::rcode::{NOERROR, NXDOMAIN};
    let budget = Duration::from_secs(5);
    let (v, g, _, stats, _dir) = setup(true).await;
    warm_tld(&v, &g).await;
    let (mut got, mut want) = (Vec::new(), Vec::new());
    for (name, qtype, code) in [
        ("cdn.u", rtype::AAAA, NOERROR),
        ("nope.nx.u", rtype::A, NXDOMAIN),
        ("a.b.c.nope.nx.u", rtype::A, NXDOMAIN),
        ("x.l.v.t", rtype::AAAA, NOERROR),
        ("nope.nx.v.t", rtype::A, NXDOMAIN),
        ("a.b.c.nope.nx.v.t", rtype::A, NXDOMAIN),
    ] {
        for round in 1..=2 {
            let r = v
                .resolve(&g, question(name, qtype), budget, true, false)
                .await;
            let what = format!("{name} {qtype} (question {round})");
            got.push((what.clone(), r.ok().map(|r| (r.verdict, served(&r.bytes)))));
            want.push((what, Some((Verdict::Insecure, Some((code, false, vec![]))))));
        }
    }
    assert_eq!(got, want);
    assert_eq!(stats.bogus.load(Ordering::Relaxed), 0, "never judged bogus");
}

/// REQ: DNS-011, NFR-001 (ADR-196) — each upstream group's validation cache is bounded. Signed
/// names (wildcard answers in `s.t.`, about two cache entries each) asked twice in turn: while
/// their proofs fit, the second round costs one upstream question per name, the name's own; with
/// more names than the cache holds, every name is validated from scratch again and its zone's
/// keys are asked for again. The built-in bound holds the same names.
#[tokio::test]
async fn dns_011_offline_validation_cache_is_bounded() {
    /// The upstream questions of each round, with a cache of `entries` (`None`: the built-in
    /// bound).
    async fn rounds(entries: Option<usize>, names: usize) -> [usize; 2] {
        let (v, g, asked, _, _dir) = setup(true).await;
        let v = v.with_aggressive_nsec(false);
        let v = match entries {
            Some(n) => v.with_validation_cache_entries(n),
            None => v,
        };
        warm_tld(&v, &g).await;
        let mut out = [0; 2];
        for round in &mut out {
            let before = asked.load(Ordering::Relaxed);
            for i in 0..names {
                let r = v
                    .resolve(
                        &g,
                        question(&format!("c{i}.w.s.t"), rtype::A),
                        Duration::from_secs(5),
                        true,
                        false,
                    )
                    .await
                    .unwrap();
                assert_eq!(r.verdict, Verdict::Secure, "c{i}.w.s.t. A");
            }
            *round = asked.load(Ordering::Relaxed) - before;
        }
        out
    }
    let [_, again] = rounds(Some(64), 4).await;
    assert_eq!(
        again, 4,
        "4 names, a cache of 64 entries: their own questions only"
    );
    let [first, again] = rounds(Some(64), 100).await;
    assert!(
        again > 100,
        "100 names, a cache of 64 entries: validated again ({again} questions, {first} the first time)"
    );
    let [_, again] = rounds(None, 100).await;
    assert_eq!(again, 100, "100 names fit the built-in bound");
}

/// The answer's records, as (owner, type), without signatures and denials.
fn answered(bytes: &[u8]) -> Vec<(String, RecordType)> {
    Message::from_vec(bytes)
        .unwrap()
        .answers
        .iter()
        .filter(|r| r.record_type() != RecordType::RRSIG)
        .map(|r| (r.name.to_ascii(), r.record_type()))
        .collect()
}

/// What is served: the response code, the AD bit and [`answered`].
type Served = (u16, bool, Vec<(String, RecordType)>);

/// [`Served`]; `None` when there are no bytes.
fn served(bytes: &[u8]) -> Option<Served> {
    if bytes.is_empty() {
        return None;
    }
    let ad = telltale_proto::Header::parse(bytes).unwrap().flags.ad();
    Some((rcode(bytes), ad, answered(bytes)))
}

/// REQ: DNS-011 (RFC 4035 §5.3.4, §5.4) — a signed answer whose denial is about the target of a
/// CNAME is validated link by link: a missing type (NSEC, NSEC3, over two links), a missing name,
/// a wildcard's address behind a CNAME, a wildcard's CNAME; and insecure, not secure, when the
/// chain leaves for an unsigned zone. A wildcard's answer is validated without a CNAME too. The
/// same answers without the fix: bogus (all but `out.s.t. A` and the plain `www.s.t.`).
#[tokio::test]
async fn dns_011_offline_denials_behind_a_cname_are_validated() {
    use RecordType::{A, CNAME};
    let budget = Duration::from_secs(5);
    let (v, g, _, _, _dir) = setup(true).await;
    warm_tld(&v, &g).await;
    for (name, qtype, want, code, owners) in [
        ("www.s.t", rtype::AAAA, Verdict::Secure, 0, vec![]),
        (
            "alias.s.t",
            rtype::A,
            Verdict::Secure,
            0,
            vec![("alias.s.t.", CNAME), ("www.s.t.", A)],
        ),
        (
            "alias.s.t",
            rtype::AAAA,
            Verdict::Secure,
            0,
            vec![("alias.s.t.", CNAME)],
        ),
        (
            "twice.s.t",
            rtype::AAAA,
            Verdict::Secure,
            0,
            vec![("twice.s.t.", CNAME), ("alias.s.t.", CNAME)],
        ),
        (
            "up.s.t",
            rtype::AAAA,
            Verdict::Secure,
            0,
            vec![("up.s.t.", CNAME)],
        ),
        (
            "gone.s.t",
            rtype::A,
            Verdict::Secure,
            3,
            vec![("gone.s.t.", CNAME)],
        ),
        (
            "any.w.s.t",
            rtype::A,
            Verdict::Secure,
            0,
            vec![("any.w.s.t.", A)],
        ),
        (
            "wild.s.t",
            rtype::A,
            Verdict::Secure,
            0,
            vec![("wild.s.t.", CNAME), ("any.w.s.t.", A)],
        ),
        (
            "any.c.s.t",
            rtype::A,
            Verdict::Secure,
            0,
            vec![("any.c.s.t.", CNAME), ("www.s.t.", A)],
        ),
        (
            "via.s.t",
            rtype::AAAA,
            Verdict::Secure,
            0,
            vec![("via.s.t.", CNAME), ("any.c.s.t.", CNAME)],
        ),
        // Through a wildcard CNAME, then a signed CNAME into an unsigned zone without the type:
        // nothing signed says it's missing there.
        (
            "any.o.s.t",
            rtype::AAAA,
            Verdict::Insecure,
            0,
            vec![("any.o.s.t.", CNAME), ("out.s.t.", CNAME)],
        ),
        // An unsigned link between signed ones.
        (
            "round.s.t",
            rtype::AAAA,
            Verdict::Insecure,
            0,
            vec![("round.s.t.", CNAME), ("back.v.t.", CNAME)],
        ),
        (
            "out.s.t",
            rtype::A,
            Verdict::Insecure,
            0,
            vec![("out.s.t.", CNAME), ("x.l.v.t.", A)],
        ),
    ] {
        let r = v
            .resolve(&g, question(name, qtype), budget, true, false)
            .await
            .unwrap();
        assert_eq!(r.verdict, want, "{name} {qtype}");
        assert_eq!(rcode(&r.bytes), code, "{name} {qtype}");
        let got = answered(&r.bytes);
        let owners: Vec<(String, RecordType)> =
            owners.into_iter().map(|(o, t)| (o.to_owned(), t)).collect();
        assert_eq!(got, owners, "{name} {qtype}");
        let m = Message::from_vec(&r.bytes).unwrap();
        assert_eq!(
            m.metadata.authentic_data,
            want == Verdict::Secure,
            "AD: {name} {qtype}"
        );
        assert_eq!(m.queries[0].name().to_ascii(), format!("{name}."));
        // The proofs a validating client needs are still there.
        if got.last().is_some_and(|(_, t)| *t == CNAME) && want == Verdict::Secure {
            assert!(
                m.authorities
                    .iter()
                    .any(|r| matches!(r.record_type(), RecordType::NSEC | RecordType::NSEC3)),
                "a denial: {name} {qtype}"
            );
        }
        // Two: the wildcard's (no closer name) and the type's.
        if name == "via.s.t" {
            let nsecs = m
                .authorities
                .iter()
                .filter(|r| r.record_type() == RecordType::NSEC)
                .count();
            assert_eq!(nsecs, 2, "{name}");
        }
    }
}

/// REQ: DNS-011 — a link that isn't validated, or a wildcard without its proof, stays bogus: a
/// forged CNAME signature, a CNAME made up for a name that has none, a target hidden with
/// another name's denial, a loop, a wildcard's address for a name that exists, and a wildcard's
/// answer without its NSEC or with another name's.
#[tokio::test]
async fn dns_011_offline_links_that_do_not_hold_stay_bogus() {
    let budget = Duration::from_secs(5);
    let z = Arc::new(zone());
    for (tamper, name, qtype) in [
        (tampering::NONE, "forged.s.t", rtype::A),
        (tampering::NONE, "forged.s.t", rtype::AAAA),
        (tampering::NONE, "loop1.s.t", rtype::A),
        (tampering::HIDE_TARGET, "alias.s.t", rtype::A),
        (tampering::HIDE_TARGET, "twice.s.t", rtype::A),
        (tampering::INJECT_CNAME, "www.s.t", rtype::AAAA),
        (tampering::INJECT_CNAME, "alias.s.t", rtype::AAAA),
        (tampering::REPLAY_WILDCARD, "own.w.s.t", rtype::A),
        (tampering::NO_WILDCARD_PROOF, "any.w.s.t", rtype::A),
        (tampering::NO_WILDCARD_PROOF, "wild.s.t", rtype::A),
        (tampering::NO_WILDCARD_PROOF, "any.c.s.t", rtype::AAAA),
        (tampering::FORGE_WILDCARD, "any.w.s.t", rtype::A),
        (tampering::FORGE_WILDCARD, "wild.s.t", rtype::A),
        (tampering::OTHER_WILDCARD_PROOF, "any.w.s.t", rtype::A),
        (tampering::OTHER_WILDCARD_PROOF, "via.s.t", rtype::AAAA),
    ] {
        let (v, g, _, stats, _dir) = setup_zone(true, Arc::clone(&z)).await;
        warm_tld(&v, &g).await;
        let secure = stats.secure.load(Ordering::Relaxed);
        z.tld.tamper.store(tamper, Ordering::Relaxed);
        for round in 1..=2 {
            let r = v
                .resolve(&g, question(name, qtype), budget, true, false)
                .await;
            // Bogus: never secure or insecure, and never "no answer" (an upstream failure).
            assert_eq!(
                r.map(|r| r.verdict).ok(),
                Some(Verdict::Bogus),
                "{name} {qtype}, tampering {tamper} (question {round})"
            );
        }
        assert_eq!(stats.secure.load(Ordering::Relaxed), secure, "{name}");
        assert_eq!(stats.insecure.load(Ordering::Relaxed), 0, "{name}");
        z.tld.tamper.store(tampering::NONE, Ordering::Relaxed);
    }
}

/// REQ: DNS-011, NFR-004 (ADR-098, ADR-188) — a link of a link-by-link validation that gets no
/// answer in time proves nothing, and the answer stays bogus: `Ok` with EDE 6, as for any answer
/// that doesn't validate. So `validate` answers SERVFAIL with EDE 6 and never a stale answer, and
/// `permissive` serves the answer, as it does when the validation library refuses an answer itself
/// (an upstream failure would be stale or SERVFAIL with EDE 22 in both). Only the links' own
/// questions (CNAME) are slow here: the upstream gives up on them within the group's budget (the
/// first question's, 1 s), or the validation's deadline (two budgets of the question, 1.9 s) runs
/// out before the group's only member gives up on its attempt (2 s after it starts), the group's
/// budget being that of the question that warmed it (5 s). The question's main lookup may take
/// one and a half budgets (1.4 s). Both after the library refused a denial behind a CNAME, and
/// after it judged a chain into an unsigned zone bogus.
#[tokio::test]
async fn dns_011_offline_link_lookup_timeout_stays_bogus() {
    // Each case's outcome: the verdict and EDE (`None`: no verdict), then the bogus, insecure and
    // new secure verdicts counted.
    let (mut got, mut want) = (Vec::new(), Vec::new());
    for (name, qtype, first, budget_ms, what) in [
        (
            "gone.s.t",
            rtype::A,
            None,
            1000,
            "a denial behind a CNAME; the upstream gives up on the link",
        ),
        (
            "alias.s.t",
            rtype::AAAA,
            Some("www.s.t"),
            950,
            "a denial behind a CNAME; the deadline runs out",
        ),
        (
            "stale.s.t",
            rtype::A,
            Some("x.t"),
            950,
            "a chain into an unsigned zone; the deadline runs out",
        ),
    ] {
        let z = Arc::new(zone());
        z.link_lag_ms.store(60_000, Ordering::Relaxed);
        let (v, g, _, stats, _dir) = setup_zone(true, Arc::clone(&z)).await;
        if let Some(first) = first {
            let r = v
                .resolve(
                    &g,
                    question(first, rtype::A),
                    Duration::from_secs(5),
                    true,
                    false,
                )
                .await
                .unwrap();
            assert_eq!(r.verdict, Verdict::Secure, "{first} A, signed");
        }
        let secure = stats.secure.load(Ordering::Relaxed);
        let budget = Duration::from_millis(budget_ms);
        let r = v
            .resolve(&g, question(name, qtype), budget, true, false)
            .await;
        got.push((
            what,
            r.ok().map(|r| (r.verdict, r.ede)),
            stats.bogus.load(Ordering::Relaxed),
            stats.insecure.load(Ordering::Relaxed),
            stats.secure.load(Ordering::Relaxed) - secure,
        ));
        want.push((
            what,
            Some((Verdict::Bogus, telltale_proto::ede::DNSSEC_BOGUS)),
            1,
            0,
            0,
        ));
    }
    assert_eq!(got, want);
}

/// REQ: DNS-011, NFR-004 (ADR-188) — link-by-link validation runs on slots of its own, apart from
/// the unsigned-zone proofs, so the proof one of its links needs still finds one. `stale.s.t. A`
/// (a signed CNAME to `old.u.t.`, whose address the validation library judges bogus) needs that
/// proof for its second link:
/// 1. with every proof slot taken but one, it is insecure;
/// 2. with every proof slot taken, it stays bogus, and isn't remembered as failed for that: the
///    next question, with the slots free again, is insecure;
/// 3. with every slot of link-by-link validation taken, it stays bogus, and the next question,
///    with them free again, is insecure.
#[tokio::test]
async fn dns_011_link_validation_leaves_slots_for_its_proofs() {
    async fn round(v: &Validator, g: &Arc<Group>) -> Option<Verdict> {
        v.resolve(
            g,
            question("stale.s.t", rtype::A),
            Duration::from_secs(5),
            true,
            false,
        )
        .await
        .ok()
        .map(|r| r.verdict)
    }
    let (v, g, _, _, _dir) = setup(true).await;
    warm_tld(&v, &g).await;
    let held = v.hold_proof_slots(1);
    assert!(!held.is_empty(), "proof slots held");
    assert_eq!(
        round(&v, &g).await,
        Some(Verdict::Insecure),
        "every proof slot but one taken"
    );
    drop(held);

    let (v, g, _, _, _dir) = setup(true).await;
    warm_tld(&v, &g).await;
    let held = v.hold_proof_slots(0);
    assert_eq!(
        round(&v, &g).await,
        Some(Verdict::Bogus),
        "every proof slot taken"
    );
    drop(held);
    assert_eq!(
        round(&v, &g).await,
        Some(Verdict::Insecure),
        "the slots free again: not remembered as failed"
    );

    let (v, g, _, _, _dir) = setup(true).await;
    warm_tld(&v, &g).await;
    let held = v.hold_link_slots(0);
    assert!(!held.is_empty(), "link-by-link slots held");
    assert_eq!(
        round(&v, &g).await,
        Some(Verdict::Bogus),
        "every link-by-link slot taken"
    );
    drop(held);
    assert_eq!(
        round(&v, &g).await,
        Some(Verdict::Insecure),
        "the link-by-link slots free again"
    );
}

/// REQ: DNS-011 (ADR-188) — an answer validated link by link is made of the chain's records: of
/// the last answer, only those owned by the name it answers, and their signatures. With
/// `www.s.t. AAAA` (NODATA) answered with another name's signed address beside its NSEC,
/// `alias.s.t. AAAA` is still a secure NODATA behind the CNAME, without that address.
#[tokio::test]
async fn dns_011_offline_composed_answer_keeps_only_the_chain() {
    let z = Arc::new(zone());
    z.tld
        .tamper
        .store(tampering::EXTRA_RECORD, Ordering::Relaxed);
    let (v, g, _, _, _dir) = setup_zone(true, Arc::clone(&z)).await;
    warm_tld(&v, &g).await;
    let r = v
        .resolve(
            &g,
            question("alias.s.t", rtype::AAAA),
            Duration::from_secs(5),
            true,
            false,
        )
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Secure, "alias.s.t. AAAA");
    assert_eq!(rcode(&r.bytes), telltale_proto::rcode::NOERROR);
    assert_eq!(
        answered(&r.bytes),
        vec![("alias.s.t.".to_owned(), RecordType::CNAME)],
        "the CNAME only"
    );
    let msg = Message::from_vec(&r.bytes).unwrap();
    assert!(
        msg.answers.iter().all(|r| r.name == n("alias.s.t.")),
        "no signature of another name"
    );
    assert!(
        msg.authorities
            .iter()
            .any(|r| r.name == n("www.s.t.") && r.record_type() == RecordType::NSEC),
        "the target's denial"
    );
}

/// REQ: DNS-011 (RFC 4035 §2.3, §2.5; ADR-188) — a question for NSEC doesn't follow a CNAME: the
/// CNAME's owner has an NSEC of its own. `alias.s.t. NSEC` is secure, with that NSEC; answered as
/// if the CNAME were followed (the CNAME, and the target's NSEC beside it), it stays bogus: no
/// answer is made of the CNAME and another name's NSEC.
#[tokio::test]
async fn dns_011_offline_nsec_question_does_not_follow_a_cname() {
    let budget = Duration::from_secs(5);
    let z = Arc::new(zone());
    let (v, g, _, _, _dir) = setup_zone(true, Arc::clone(&z)).await;
    let r = v
        .resolve(&g, question("alias.s.t", rtype::NSEC), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Secure, "alias.s.t. NSEC");
    assert_eq!(
        answered(&r.bytes),
        vec![("alias.s.t.".to_owned(), RecordType::NSEC)],
        "its own NSEC"
    );
    z.tld
        .tamper
        .store(tampering::CNAME_FOR_NSEC, Ordering::Relaxed);
    let (v, g, _, stats, _dir) = setup_zone(true, Arc::clone(&z)).await;
    warm_tld(&v, &g).await;
    let secure = stats.secure.load(Ordering::Relaxed);
    for round in 1..=2 {
        let r = v
            .resolve(&g, question("alias.s.t", rtype::NSEC), budget, true, false)
            .await;
        assert_eq!(
            r.map(|r| r.verdict).ok(),
            Some(Verdict::Bogus),
            "alias.s.t. NSEC through the CNAME (question {round})"
        );
    }
    assert_eq!(stats.secure.load(Ordering::Relaxed), secure);
    assert_eq!(stats.insecure.load(Ordering::Relaxed), 0);
}

/// REQ: DNS-011 (ADR-098, ADR-184) — a signed CNAME into a zone that is unsigned but whose answers
/// the validation library judges bogus (`stale.s.t.` to `old.u.t.`, whose address has a signature
/// left over, without a key) is insecure: served, without AD. The library's verdict on the whole
/// answer is bogus; link by link, the CNAME validates and the target's zone is proven unsigned.
#[tokio::test]
async fn dns_011_offline_signed_cname_into_misjudged_unsigned_zone_is_insecure() {
    let (v, g, _, stats, _dir) = setup(true).await;
    let budget = Duration::from_secs(5);
    warm_tld(&v, &g).await;
    let secure = stats.secure.load(Ordering::Relaxed);
    let r = v
        .resolve(&g, question("stale.s.t", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Insecure, "stale.s.t. A");
    assert_eq!(rcode(&r.bytes), telltale_proto::rcode::NOERROR);
    assert_eq!(
        answered(&r.bytes),
        vec![
            ("stale.s.t.".to_owned(), RecordType::CNAME),
            ("old.u.t.".to_owned(), RecordType::A)
        ],
        "the CNAME, then the address"
    );
    assert!(!telltale_proto::Header::parse(&r.bytes).unwrap().flags.ad());
    assert_eq!(stats.bogus.load(Ordering::Relaxed), 0);
    assert_eq!(stats.secure.load(Ordering::Relaxed), secure);
}

/// REQ: DNS-011 (ADR-098, ADR-184, ADR-188; issue #115, `dns.nextdns.io`) — a signed CNAME in a zone
/// signed with NSEC, into a delegation without a DS that the parent's NSEC owned by the delegation
/// proves (`NS RRSIG NSEC`, its next name right after the delegation's), whose server answers its
/// SOA and address unsigned and nothing else: `dns.s.t.` to `steer.s.t.`. `dns.s.t. A` is insecure:
/// NOERROR without AD, the CNAME then the address. `dns.s.t. AAAA` (`steer.s.t.` has none) is served the
/// same way, the CNAME only and without AD, and is judged indeterminate (ADR-195): the chain stops short
/// of the asked type and the target's zone is unsigned, so nothing proves it either way. Nothing is
/// judged bogus or secure.
#[tokio::test]
async fn dns_011_offline_signed_cname_into_unsigned_child_of_nsec_zone_is_insecure() {
    let budget = Duration::from_secs(5);
    let (v, g, _, stats, _dir) = setup(true).await;
    warm_tld(&v, &g).await;
    let secure = stats.secure.load(Ordering::Relaxed);
    let (mut got, mut want) = (Vec::new(), Vec::new());
    for (what, qtype, verdict, records) in [
        (
            "dns.s.t. A",
            rtype::A,
            Verdict::Insecure,
            vec![
                ("dns.s.t.", RecordType::CNAME),
                ("steer.s.t.", RecordType::A),
            ],
        ),
        (
            "dns.s.t. AAAA",
            rtype::AAAA,
            Verdict::Indeterminate,
            vec![("dns.s.t.", RecordType::CNAME)],
        ),
    ] {
        let r = v
            .resolve(&g, question("dns.s.t", qtype), budget, true, false)
            .await;
        got.push((what, r.ok().map(|r| (r.verdict, served(&r.bytes)))));
        let records: Vec<(String, RecordType)> = records
            .into_iter()
            .map(|(owner, kind)| (owner.to_owned(), kind))
            .collect();
        want.push((
            what,
            Some((
                verdict,
                Some((telltale_proto::rcode::NOERROR, false, records)),
            )),
        ));
    }
    assert_eq!(got, want);
    assert_eq!(stats.bogus.load(Ordering::Relaxed), 0, "never judged bogus");
    assert_eq!(stats.secure.load(Ordering::Relaxed), secure, "nor secure");
}

/// REQ: DNS-011 (ADR-188; issue #115) — the test above holds through link-by-link validation. With
/// every slot of it taken, `dns.s.t. A` stays bogus (EDE 6): the validation library's verdict on the
/// whole answer, which the unsigned-zone proof of its owners doesn't correct (`dns.s.t.` is a name of
/// the signed `s.t.`). With the slots free again, the same question is insecure.
#[tokio::test]
async fn dns_011_offline_signed_cname_into_unsigned_child_needs_link_by_link() {
    let budget = Duration::from_secs(5);
    let (v, g, _, _, _dir) = setup(true).await;
    warm_tld(&v, &g).await;
    let held = v.hold_link_slots(0);
    assert!(!held.is_empty(), "link-by-link slots held");
    let r = v
        .resolve(&g, question("dns.s.t", rtype::A), budget, true, false)
        .await;
    drop(held);
    let without_a_walk = r.ok().map(|r| (r.verdict, r.ede));
    let r = v
        .resolve(&g, question("dns.s.t", rtype::A), budget, true, false)
        .await;
    let walked = r.ok().map(|r| r.verdict);
    assert_eq!(
        (without_a_walk, walked),
        (
            Some((Verdict::Bogus, telltale_proto::ede::DNSSEC_BOGUS)),
            Some(Verdict::Insecure)
        ),
        "dns.s.t. A, without and with link-by-link validation"
    );
}

/// REQ: DNS-011 (RFC 4035 §5.3.4) — a wildcard's address replayed for an empty non-terminal
/// (`ent.w.s.t.`, which exists because `x.ent.w.s.t.` does) stays bogus, with the NSEC that covers
/// the name: its next name is below it, so the name exists and no wildcard answers it. Answered as
/// the zone answers it, the same question is a secure NODATA.
#[tokio::test]
async fn dns_011_offline_wildcard_replayed_at_an_empty_non_terminal_stays_bogus() {
    let budget = Duration::from_secs(5);
    let z = Arc::new(zone());
    let (v, g, _, _, _dir) = setup_zone(true, Arc::clone(&z)).await;
    let r = v
        .resolve(&g, question("ent.w.s.t", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(
        (r.verdict, rcode(&r.bytes), answered(&r.bytes).len()),
        (Verdict::Secure, telltale_proto::rcode::NOERROR, 0),
        "ent.w.s.t. A, as the zone answers it: NODATA"
    );
    z.tld
        .tamper
        .store(tampering::REPLAY_WILDCARD_AT_ENT, Ordering::Relaxed);
    let (v, g, _, stats, _dir) = setup_zone(true, Arc::clone(&z)).await;
    warm_tld(&v, &g).await;
    let secure = stats.secure.load(Ordering::Relaxed);
    for round in 1..=2 {
        let r = v
            .resolve(&g, question("ent.w.s.t", rtype::A), budget, true, false)
            .await
            .unwrap();
        assert_eq!(
            (r.verdict, r.ede),
            (Verdict::Bogus, telltale_proto::ede::DNSSEC_BOGUS),
            "the wildcard's address at an empty non-terminal (question {round})"
        );
    }
    assert_eq!(stats.secure.load(Ordering::Relaxed), secure);
    assert_eq!(stats.insecure.load(Ordering::Relaxed), 0);
}

/// REQ: DNS-011 (RFC 4035 §5.3.4, RFC 4592; ADR-188) — wildcard answers with the zone's NSEC
/// showing that the next closer name doesn't exist are secure, with AD: one label below the
/// wildcard's parent (`any.w.s.t.`), two labels below it where the name between doesn't exist
/// (`a.b.w.s.t.`), and a wildcard's CNAME two labels below it (`a.b.c.s.t.`, to `www.s.t.`).
#[tokio::test]
async fn dns_011_offline_wildcard_answers_with_their_proof_are_secure() {
    use RecordType::{A, CNAME};
    let (v, g, _, stats, _dir) = setup(true).await;
    warm_tld(&v, &g).await;
    for (name, owners) in [
        ("any.w.s.t", vec![("any.w.s.t.", A)]),
        ("a.b.w.s.t", vec![("a.b.w.s.t.", A)]),
        ("a.b.c.s.t", vec![("a.b.c.s.t.", CNAME), ("www.s.t.", A)]),
    ] {
        let r = v
            .resolve(
                &g,
                question(name, rtype::A),
                Duration::from_secs(5),
                true,
                false,
            )
            .await
            .unwrap();
        assert_eq!(r.verdict, Verdict::Secure, "{name} A");
        assert_eq!(rcode(&r.bytes), telltale_proto::rcode::NOERROR, "{name} A");
        let owners: Vec<(String, RecordType)> =
            owners.into_iter().map(|(o, t)| (o.to_owned(), t)).collect();
        assert_eq!(answered(&r.bytes), owners, "{name} A");
        assert!(
            telltale_proto::Header::parse(&r.bytes).unwrap().flags.ad(),
            "AD: {name} A"
        );
    }
    assert_eq!(stats.bogus.load(Ordering::Relaxed), 0);
}

/// REQ: DNS-011 (RFC 4035 §5.3.4; ADR-188) — a wildcard's answer is authenticated only with an NSEC
/// showing that the next closer name doesn't exist (the name cut to one label below the wildcard's
/// parent). `a.own.w.s.t. A` answered from `*.w.s.t.` with the NSEC of `own.w.s.t.`, a name that
/// exists between them, is bogus; answered as the zone answers it, it is a secure NXDOMAIN.
#[tokio::test]
async fn dns_011_offline_wildcard_answer_needs_its_next_closer_name_to_be_absent() {
    let budget = Duration::from_secs(5);
    let z = Arc::new(zone());
    let (v, g, _, _, _dir) = setup_zone(true, Arc::clone(&z)).await;
    let r = v
        .resolve(&g, question("a.own.w.s.t", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(
        (r.verdict, rcode(&r.bytes)),
        (Verdict::Secure, telltale_proto::rcode::NXDOMAIN),
        "a.own.w.s.t. A, as the zone answers it"
    );
    z.tld
        .tamper
        .store(tampering::REPLAY_WILDCARD_BELOW_NAME, Ordering::Relaxed);
    let (v, g, _, stats, _dir) = setup_zone(true, Arc::clone(&z)).await;
    warm_tld(&v, &g).await;
    let secure = stats.secure.load(Ordering::Relaxed);
    for round in 1..=2 {
        let r = v
            .resolve(&g, question("a.own.w.s.t", rtype::A), budget, true, false)
            .await;
        assert_eq!(
            r.map(|r| (r.verdict, r.ede)).ok(),
            Some((Verdict::Bogus, telltale_proto::ede::DNSSEC_BOGUS)),
            "a.own.w.s.t. A from *.w.s.t. (question {round})"
        );
    }
    assert_eq!(stats.secure.load(Ordering::Relaxed), secure);
    assert_eq!(stats.insecure.load(Ordering::Relaxed), 0);
}

/// REQ: DNS-011 (RFC 4035 §3.1.3.4, §5.4) — a wildcard that exists without the type asked for
/// gives a signed NODATA (the NSEC that shows no closer name exists, and the wildcard's own,
/// without the type): secure when asked directly (`any.w.s.t. AAAA`), and behind a CNAME
/// (`wild.s.t. AAAA`), where the denial is about the CNAME's target.
#[tokio::test]
async fn dns_011_offline_wildcard_nodata_is_validated() {
    let (v, g, _, stats, _dir) = setup(true).await;
    let budget = Duration::from_secs(5);
    warm_tld(&v, &g).await;
    for (name, owners) in [
        ("any.w.s.t", vec![]),
        (
            "wild.s.t",
            vec![("wild.s.t.".to_owned(), RecordType::CNAME)],
        ),
    ] {
        let r = v
            .resolve(&g, question(name, rtype::AAAA), budget, true, false)
            .await
            .unwrap();
        assert_eq!(r.verdict, Verdict::Secure, "{name} AAAA");
        assert_eq!(
            rcode(&r.bytes),
            telltale_proto::rcode::NOERROR,
            "{name} AAAA"
        );
        assert_eq!(answered(&r.bytes), owners, "{name} AAAA");
        let m = Message::from_vec(&r.bytes).unwrap();
        assert!(m.metadata.authentic_data, "AD: {name} AAAA");
        assert!(
            m.authorities
                .iter()
                .any(|r| { r.name == n("*.w.s.t.") && r.record_type() == RecordType::NSEC }),
            "the wildcard's NSEC: {name} AAAA"
        );
    }
    assert_eq!(stats.bogus.load(Ordering::Relaxed), 0);
}

/// REQ: DNS-011 (RFC 4035 §5.3.4, RFC 5155 §8.8; ADR-188) — the wildcard rule of zones signed with
/// NSEC is left to NSEC3 only beside a verified NSEC3 record of the zone that signed the answer: an
/// NSEC3 record that isn't verified, or that is another zone's, doesn't switch the rule off. Each of
/// these answers stays bogus (EDE 6) over two questions, and nothing is counted secure or insecure:
/// - `a.own.w.s.t. A` from `*.w.s.t.` with `own.w.s.t.`'s NSEC, and an unsigned NSEC3 record owned
///   in `s.t.` beside it;
/// - `own.w.s.t. A` from `*.w.s.t.` with only an unsigned NSEC3 record of the unsigned zone `u.`;
/// - the same with only `t.`'s signed NSEC3 record covering the name;
/// - `a.b.c.s.t. A` from the wildcard CNAME `*.c.s.t.` with only that NSEC3 record of `u.`.
#[tokio::test]
async fn dns_011_offline_wildcard_rule_stays_on_beside_an_unverified_or_other_zone_nsec3() {
    let budget = Duration::from_secs(5);
    let z = Arc::new(zone());
    let bogus = Some((Verdict::Bogus, telltale_proto::ede::DNSSEC_BOGUS));
    let (mut got, mut want) = (Vec::new(), Vec::new());
    for (tamper, name, what) in [
        (
            tampering::BESIDE_UNSIGNED_NSEC3,
            "a.own.w.s.t",
            "an unsigned NSEC3 of s.t. beside the NSEC",
        ),
        (
            tampering::UNSIGNED_ZONE_NSEC3_PROOF,
            "own.w.s.t",
            "only an unsigned NSEC3 of u.",
        ),
        (
            tampering::OTHER_ZONE_NSEC3_PROOF,
            "own.w.s.t",
            "only a signed NSEC3 of t.",
        ),
        (
            tampering::UNSIGNED_ZONE_NSEC3_PROOF,
            "a.b.c.s.t",
            "a wildcard CNAME with only an unsigned NSEC3 of u.",
        ),
    ] {
        z.tld.tamper.store(tamper, Ordering::Relaxed);
        let (v, g, _, stats, _dir) = setup_zone(true, Arc::clone(&z)).await;
        warm_tld(&v, &g).await;
        let secure = stats.secure.load(Ordering::Relaxed);
        let mut verdicts = Vec::new();
        for _ in 1..=2 {
            let r = v
                .resolve(&g, question(name, rtype::A), budget, true, false)
                .await;
            verdicts.push(r.map(|r| (r.verdict, r.ede)).ok());
        }
        got.push((
            what,
            verdicts,
            stats.secure.load(Ordering::Relaxed) - secure,
            stats.insecure.load(Ordering::Relaxed),
        ));
        want.push((what, vec![bogus; 2], 0, 0));
    }
    z.tld.tamper.store(tampering::NONE, Ordering::Relaxed);
    assert_eq!(got, want);
}

/// REQ: DNS-011 (RFC 5155 §7.2.6, §8.8; ADR-188) — wildcard answers in a zone signed with NSEC3
/// (`z3.s.t.`), with the zone's signed NSEC3 record covering the next closer name, are secure, with
/// AD: one label below the wildcard's parent (`a.z3.s.t.`) and two (`a.b.z3.s.t.`).
#[tokio::test]
async fn dns_011_offline_wildcard_answers_in_an_nsec3_zone_are_secure() {
    let (v, g, _, stats, _dir) = setup(true).await;
    warm_tld(&v, &g).await;
    let (mut got, mut want) = (Vec::new(), Vec::new());
    for name in ["a.z3.s.t", "a.b.z3.s.t"] {
        let r = v
            .resolve(
                &g,
                question(name, rtype::A),
                Duration::from_secs(5),
                true,
                false,
            )
            .await;
        got.push((
            name,
            r.ok().map(|r| {
                let nsec3 = Message::from_vec(&r.bytes).is_ok_and(|msg| {
                    msg.authorities.iter().any(|rec| {
                        rec.record_type() == RecordType::NSEC3
                            && rec.name.base_name() == n("z3.s.t.")
                    })
                });
                (r.verdict, served(&r.bytes), nsec3)
            }),
        ));
        let records = vec![(format!("{name}."), RecordType::A)];
        want.push((
            name,
            Some((
                Verdict::Secure,
                Some((telltale_proto::rcode::NOERROR, true, records)),
                true,
            )),
        ));
    }
    assert_eq!(got, want);
    assert_eq!(stats.bogus.load(Ordering::Relaxed), 0);
}

/// REQ: DNS-011 (RFC 4035 §5.3.4, RFC 6840 §5.4; ADR-188) — a wildcard's answer whose record set has
/// a second signature that isn't verified (by another key of the zone, as during a key rollover) is
/// judged by the signature that is: with its NSEC it is indeterminate (served without AD), as an
/// answer with such a signature is, and not bogus. One label below the wildcard's parent
/// (`any.w.s.t.`) and two (`a.b.w.s.t.`).
#[tokio::test]
async fn dns_011_offline_wildcard_answer_with_a_second_signature_is_indeterminate() {
    let z = Arc::new(zone());
    z.tld
        .tamper
        .store(tampering::SECOND_SIGNATURE, Ordering::Relaxed);
    let (v, g, _, stats, _dir) = setup_zone(true, Arc::clone(&z)).await;
    warm_tld(&v, &g).await;
    let (mut got, mut want) = (Vec::new(), Vec::new());
    for name in ["any.w.s.t", "a.b.w.s.t"] {
        let r = v
            .resolve(
                &g,
                question(name, rtype::A),
                Duration::from_secs(5),
                true,
                false,
            )
            .await;
        got.push((name, r.ok().map(|r| (r.verdict, served(&r.bytes)))));
        let records = vec![(format!("{name}."), RecordType::A)];
        want.push((
            name,
            Some((
                Verdict::Indeterminate,
                Some((telltale_proto::rcode::NOERROR, false, records)),
            )),
        ));
    }
    assert_eq!(got, want);
    assert_eq!(stats.bogus.load(Ordering::Relaxed), 0);
}

/// REQ: DNS-011 (RFC 4035 §5.3.4; ADR-188) — wildcard answers with their proof are secure without
/// link-by-link validation: with every slot of it taken, `any.w.s.t. A`, `a.b.w.s.t. A` and
/// `a.b.c.s.t. A` (from the wildcard CNAME `*.c.s.t.`, two labels below its parent, to `www.s.t.`)
/// are secure, with AD. A wildcard CNAME at the question name that is the answer's only record made
/// from a wildcard is checked as the CNAME's own record set.
#[tokio::test]
async fn dns_011_offline_wildcard_answers_with_their_proof_need_no_link_by_link_validation() {
    use RecordType::{A, CNAME};
    let (v, g, _, stats, _dir) = setup(true).await;
    warm_tld(&v, &g).await;
    let held = v.hold_link_slots(0);
    assert!(!held.is_empty(), "link-by-link slots held");
    let (mut got, mut want) = (Vec::new(), Vec::new());
    for (name, owners) in [
        ("any.w.s.t", vec![("any.w.s.t.", A)]),
        ("a.b.w.s.t", vec![("a.b.w.s.t.", A)]),
        ("a.b.c.s.t", vec![("a.b.c.s.t.", CNAME), ("www.s.t.", A)]),
    ] {
        let r = v
            .resolve(
                &g,
                question(name, rtype::A),
                Duration::from_secs(5),
                true,
                false,
            )
            .await;
        got.push((name, r.ok().map(|r| (r.verdict, served(&r.bytes)))));
        let records: Vec<(String, RecordType)> = owners
            .into_iter()
            .map(|(owner, kind)| (owner.to_owned(), kind))
            .collect();
        want.push((
            name,
            Some((
                Verdict::Secure,
                Some((telltale_proto::rcode::NOERROR, true, records)),
            )),
        ));
    }
    drop(held);
    assert_eq!(got, want);
    assert_eq!(stats.bogus.load(Ordering::Relaxed), 0);
}

/// REQ: DNS-011 (RFC 4035 §5.3.4; ADR-188) — a wildcard CNAME at the question name with its proof
/// stands for itself only: when another record of the answer is made from a wildcard, each needs
/// its own proof. `a.b.k.s.t. A` (from the wildcard CNAME `*.k.s.t.`, to `a.own.w.s.t.`) with the
/// target answered from `*.w.s.t.` and the NSEC of `own.w.s.t.`, a name that exists between them,
/// stays bogus (EDE 6) over two questions, with nothing counted secure or insecure. Answered as the
/// zone answers it, it is a secure NXDOMAIN behind the CNAME.
#[tokio::test]
async fn dns_011_offline_wildcard_cname_to_another_wildcard_record_needs_each_proof() {
    let budget = Duration::from_secs(5);
    let z = Arc::new(zone());
    let (v, g, _, _, _dir) = setup_zone(true, Arc::clone(&z)).await;
    warm_tld(&v, &g).await;
    let r = v
        .resolve(&g, question("a.b.k.s.t", rtype::A), budget, true, false)
        .await;
    assert_eq!(
        r.ok().map(|r| (r.verdict, served(&r.bytes))),
        Some((
            Verdict::Secure,
            Some((
                telltale_proto::rcode::NXDOMAIN,
                true,
                vec![("a.b.k.s.t.".to_owned(), RecordType::CNAME)]
            ))
        )),
        "a.b.k.s.t. A, as the zone answers it"
    );
    z.tld
        .tamper
        .store(tampering::REPLAY_WILDCARD_BELOW_NAME, Ordering::Relaxed);
    let (v, g, _, stats, _dir) = setup_zone(true, Arc::clone(&z)).await;
    warm_tld(&v, &g).await;
    let secure = stats.secure.load(Ordering::Relaxed);
    let mut verdicts = Vec::new();
    for _ in 1..=2 {
        let r = v
            .resolve(&g, question("a.b.k.s.t", rtype::A), budget, true, false)
            .await;
        verdicts.push(r.map(|r| (r.verdict, r.ede)).ok());
    }
    z.tld.tamper.store(tampering::NONE, Ordering::Relaxed);
    let bogus = Some((Verdict::Bogus, telltale_proto::ede::DNSSEC_BOGUS));
    assert_eq!(
        (
            verdicts,
            stats.secure.load(Ordering::Relaxed) - secure,
            stats.insecure.load(Ordering::Relaxed)
        ),
        (vec![bogus; 2], 0, 0),
        "a.b.k.s.t. A to a wildcard's address without its proof"
    );
}

/// REQ: DNS-011 (RFC 4035 §5.3.4; ADR-188) — a wildcard CNAME at the question name is checked as its
/// own record set only when the chain in the answer ends in a record of the question's type.
/// `a.b.c.s.t. A` answered with the wildcard's CNAME to `www.s.t.`, its signature and NSEC, without
/// `www.s.t.`'s address, is validated link by link: secure, with AD, and the address is in the
/// answer, from the target's own question. With every slot of link-by-link validation taken, it
/// stays bogus (EDE 6).
#[tokio::test]
async fn dns_011_offline_wildcard_cname_chain_that_stops_short_is_validated_link_by_link() {
    use RecordType::{A, CNAME};
    let budget = Duration::from_secs(5);
    let z = Arc::new(zone());
    z.tld
        .tamper
        .store(tampering::CHAIN_CUT_SHORT, Ordering::Relaxed);
    let (v, g, _, _, _dir) = setup_zone(true, Arc::clone(&z)).await;
    warm_tld(&v, &g).await;
    let r = v
        .resolve(&g, question("a.b.c.s.t", rtype::A), budget, true, false)
        .await;
    let walked = r.ok().map(|r| (r.verdict, served(&r.bytes)));
    let (v, g, _, stats, _dir) = setup_zone(true, Arc::clone(&z)).await;
    warm_tld(&v, &g).await;
    let secure = stats.secure.load(Ordering::Relaxed);
    let held = v.hold_link_slots(0);
    assert!(!held.is_empty(), "link-by-link slots held");
    let r = v
        .resolve(&g, question("a.b.c.s.t", rtype::A), budget, true, false)
        .await;
    drop(held);
    let without_a_walk = (
        r.map(|r| (r.verdict, r.ede)).ok(),
        stats.secure.load(Ordering::Relaxed) - secure,
    );
    z.tld.tamper.store(tampering::NONE, Ordering::Relaxed);
    let records = vec![("a.b.c.s.t.".to_owned(), CNAME), ("www.s.t.".to_owned(), A)];
    assert_eq!(
        (walked, without_a_walk),
        (
            Some((
                Verdict::Secure,
                Some((telltale_proto::rcode::NOERROR, true, records))
            )),
            (Some((Verdict::Bogus, telltale_proto::ede::DNSSEC_BOGUS)), 0),
        ),
        "a.b.c.s.t. A, the chain stopping after the CNAME"
    );
}

/// REQ: DNS-011 (RFC 4035 §5.3.4, §5.4; ADR-188) — a NODATA behind a wildcard CNAME at the question
/// name, two labels below the wildcard's parent, is validated link by link: `a.b.c.s.t. AAAA` (from
/// `*.c.s.t.`, to `www.s.t.`, which has no AAAA) is a secure NODATA with AD, the CNAME in the answer
/// and `www.s.t.`'s NSEC in the authority section. With every slot of link-by-link validation taken,
/// it stays bogus (EDE 6).
#[tokio::test]
async fn dns_011_offline_nodata_behind_a_wildcard_cname_is_checked_through_the_walk() {
    let budget = Duration::from_secs(5);
    let (v, g, _, _, _dir) = setup(true).await;
    warm_tld(&v, &g).await;
    let r = v
        .resolve(&g, question("a.b.c.s.t", rtype::AAAA), budget, true, false)
        .await;
    let walked = r.ok().map(|r| {
        let denial = Message::from_vec(&r.bytes).is_ok_and(|msg| {
            msg.authorities
                .iter()
                .any(|rec| rec.name == n("www.s.t.") && rec.record_type() == RecordType::NSEC)
        });
        (r.verdict, served(&r.bytes), denial)
    });
    let (v, g, _, stats, _dir) = setup(true).await;
    warm_tld(&v, &g).await;
    let secure = stats.secure.load(Ordering::Relaxed);
    let held = v.hold_link_slots(0);
    assert!(!held.is_empty(), "link-by-link slots held");
    let r = v
        .resolve(&g, question("a.b.c.s.t", rtype::AAAA), budget, true, false)
        .await;
    drop(held);
    let without_a_walk = (
        r.map(|r| (r.verdict, r.ede)).ok(),
        stats.secure.load(Ordering::Relaxed) - secure,
    );
    let records = vec![("a.b.c.s.t.".to_owned(), RecordType::CNAME)];
    assert_eq!(
        (walked, without_a_walk),
        (
            Some((
                Verdict::Secure,
                Some((telltale_proto::rcode::NOERROR, true, records)),
                true
            )),
            (Some((Verdict::Bogus, telltale_proto::ede::DNSSEC_BOGUS)), 0),
        ),
        "a.b.c.s.t. AAAA, a NODATA behind the wildcard CNAME"
    );
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
    let old = question("old.u.t", rtype::A);
    let r = v.resolve(&g1, old, budget, true, false).await.unwrap();
    assert_eq!(r.verdict, Verdict::Insecure);
    assert_ne!(r.bytes.len(), 0, "validated, and the zone proven unsigned");
    let r = v.resolve(&g1, old, budget, true, false).await.unwrap();
    assert_eq!(
        (r.verdict, r.bytes.len()),
        (Verdict::Insecure, 0),
        "remembered for the group that proved it"
    );
    let before = asked2.load(Ordering::Relaxed);
    let r = v.resolve(&g2, old, budget, true, false).await.unwrap();
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
        let r = v.resolve(&g, old, budget, true, false).await.unwrap();
        assert_eq!(r.verdict, Verdict::Insecure, "TTL 0 (question {round})");
        assert_ne!(
            r.bytes.len(),
            0,
            "TTL 0: validated again (question {round})"
        );
    }
}

/// REQ: DNS-011 (ADR-195) — an answer that starts with a CNAME at the question name is secure only
/// when its chain reaches the question: a record of the asked type at the chain's last name, or a
/// proof that the last name has none. A validated answer whose chain stops before that is
/// indeterminate: served as it came, without AD (for a client that set DO, and for one that set only
/// AD), counted once as indeterminate and never as secure:
/// - (c) `alias.s.t. A` with its CNAME alone;
/// - (d) `twice.s.t. A` without its second link (its CNAME, then `www.s.t.`'s address), and with both
///   CNAMEs but without the last name's address;
/// - (g) `out.s.t. AAAA`, a signed CNAME into the unsigned zone `v.t.`, whose target has no AAAA,
///   with nothing in the authority section and with `v.t.`'s unsigned SOA there;
/// - (i) `x.k3.z3.s.t. A`, a wildcard CNAME in a zone signed with NSEC3, with its NSEC3 record only.
#[tokio::test]
async fn dns_011_offline_cname_answer_needs_its_chain_to_reach_the_question() {
    use RecordType::{A, CNAME};
    let budget = Duration::from_secs(5);
    let z = Arc::new(zone());
    let (mut got, mut want) = (Vec::new(), Vec::new());
    for (what, name, qtype, tamper, client, owners) in [
        (
            "c: the CNAME alone",
            "alias.s.t",
            rtype::A,
            tampering::CNAME_ALONE,
            (true, false),
            vec![("alias.s.t.", CNAME)],
        ),
        (
            "c: the CNAME alone, for a client that set only AD",
            "alias.s.t",
            rtype::A,
            tampering::CNAME_ALONE,
            (false, true),
            vec![("alias.s.t.", CNAME)],
        ),
        (
            "d: without the second link",
            "twice.s.t",
            rtype::A,
            tampering::SECOND_LINK_LEFT_OUT,
            (true, false),
            vec![("twice.s.t.", CNAME), ("www.s.t.", A)],
        ),
        (
            "d: without the last name's address",
            "twice.s.t",
            rtype::A,
            tampering::LAST_RECORD_LEFT_OUT,
            (true, false),
            vec![("twice.s.t.", CNAME), ("alias.s.t.", CNAME)],
        ),
        (
            "g: into an unsigned zone, to a name without the type",
            "out.s.t",
            rtype::AAAA,
            tampering::NONE,
            (true, false),
            vec![("out.s.t.", CNAME)],
        ),
        (
            "g: the same, with the target zone's unsigned SOA",
            "out.s.t",
            rtype::AAAA,
            tampering::CNAME_AND_UNSIGNED_SOA,
            (true, false),
            vec![("out.s.t.", CNAME)],
        ),
        (
            "i: a wildcard CNAME in a zone signed with NSEC3, alone",
            "x.k3.z3.s.t",
            rtype::A,
            tampering::WILDCARD_CNAME_ALONE,
            (true, false),
            vec![("x.k3.z3.s.t.", CNAME)],
        ),
    ] {
        z.tld.tamper.store(tamper, Ordering::Relaxed);
        let (v, g, _, stats, _dir) = setup_zone(true, Arc::clone(&z)).await;
        warm_tld(&v, &g).await;
        let secure = stats.secure.load(Ordering::Relaxed);
        let (client_do, client_ad) = client;
        let r = v
            .resolve(&g, question(name, qtype), budget, client_do, client_ad)
            .await;
        let result = r.ok().map(|r| (r.verdict, served(&r.bytes)));
        eprintln!("{what}: {name} {qtype}: {result:?}");
        got.push((
            what,
            result,
            stats.secure.load(Ordering::Relaxed) - secure,
            stats.indeterminate.load(Ordering::Relaxed),
        ));
        let records: Vec<(String, RecordType)> =
            owners.into_iter().map(|(o, t)| (o.to_owned(), t)).collect();
        want.push((
            what,
            Some((
                Verdict::Indeterminate,
                Some((telltale_proto::rcode::NOERROR, false, records)),
            )),
            0,
            1,
        ));
    }
    z.tld.tamper.store(tampering::NONE, Ordering::Relaxed);
    assert_eq!(got, want);
}

/// REQ: DNS-011 (ADR-195) — answers whose CNAME chain reaches the question keep their verdicts, and
/// so do those whose chain other rules decide: (a) a chain to an address, of one link and of two;
/// (b) a chain to a signed NODATA or NXDOMAIN, validated link by link (ADR-188), also into a zone
/// signed with NSEC3; (e) a question for the CNAME itself; (f) a CNAME made from a DNAME, which has
/// no signature of its own (bogus, as before: ADR-188 follows only CNAMEs); (g) a chain into an
/// unsigned zone, to an address; (h) a chain with an unsigned link between signed ones; (i) a
/// wildcard CNAME in a zone signed with NSEC (to an address; to a NODATA and stopping short, link by
/// link) and in one signed with NSEC3 (to an address; to a NODATA proven by the target's own NSEC3
/// record). AD only for the secure ones.
#[tokio::test]
async fn dns_011_offline_cname_answers_that_reach_the_question_keep_their_verdicts() {
    use Verdict::{Bogus, Insecure, Secure};
    use telltale_proto::rcode::{NOERROR, NXDOMAIN};
    let budget = Duration::from_secs(5);
    let z = Arc::new(zone());
    let (mut got, mut want) = (Vec::new(), Vec::new());
    for (what, name, qtype, tamper, verdict, code) in [
        (
            "a: a CNAME to an address",
            "alias.s.t",
            rtype::A,
            tampering::NONE,
            Secure,
            NOERROR,
        ),
        (
            "a: two CNAMEs to an address",
            "twice.s.t",
            rtype::A,
            tampering::NONE,
            Secure,
            NOERROR,
        ),
        (
            "b: a CNAME to a NODATA",
            "alias.s.t",
            rtype::AAAA,
            tampering::NONE,
            Secure,
            NOERROR,
        ),
        (
            "b: a CNAME to an NXDOMAIN",
            "gone.s.t",
            rtype::A,
            tampering::NONE,
            Secure,
            NXDOMAIN,
        ),
        (
            "b: a CNAME to a NODATA in a zone signed with NSEC3",
            "up.s.t",
            rtype::AAAA,
            tampering::NONE,
            Secure,
            NOERROR,
        ),
        (
            "e: a question for the CNAME",
            "alias.s.t",
            rtype::CNAME,
            tampering::NONE,
            Secure,
            NOERROR,
        ),
        (
            "f: a CNAME made from a DNAME",
            "www.dn.s.t",
            rtype::A,
            tampering::NONE,
            Bogus,
            NOERROR,
        ),
        (
            "g: into an unsigned zone, to an address",
            "out.s.t",
            rtype::A,
            tampering::NONE,
            Insecure,
            NOERROR,
        ),
        (
            "h: an unsigned link between signed ones, to an address",
            "round.s.t",
            rtype::A,
            tampering::NONE,
            Insecure,
            NOERROR,
        ),
        (
            "h: an unsigned link between signed ones, to a NODATA",
            "round.s.t",
            rtype::AAAA,
            tampering::NONE,
            Insecure,
            NOERROR,
        ),
        (
            "i: a wildcard CNAME to an address",
            "a.b.c.s.t",
            rtype::A,
            tampering::NONE,
            Secure,
            NOERROR,
        ),
        (
            "i: a wildcard CNAME to a NODATA",
            "a.b.c.s.t",
            rtype::AAAA,
            tampering::NONE,
            Secure,
            NOERROR,
        ),
        (
            "i: a wildcard CNAME whose chain stops after it",
            "a.b.c.s.t",
            rtype::A,
            tampering::CHAIN_CUT_SHORT,
            Secure,
            NOERROR,
        ),
        (
            "i: a wildcard CNAME in a zone signed with NSEC3, to an address",
            "x.k3.z3.s.t",
            rtype::A,
            tampering::NONE,
            Secure,
            NOERROR,
        ),
        (
            "i: a wildcard CNAME in a zone signed with NSEC3, to a NODATA",
            "x.k3.z3.s.t",
            rtype::AAAA,
            tampering::NONE,
            Secure,
            NOERROR,
        ),
    ] {
        z.tld.tamper.store(tamper, Ordering::Relaxed);
        let (v, g, _, _, _dir) = setup_zone(true, Arc::clone(&z)).await;
        warm_tld(&v, &g).await;
        let r = v
            .resolve(&g, question(name, qtype), budget, true, false)
            .await;
        let result = r.ok().map(|r| {
            let shown = (!r.bytes.is_empty()).then(|| {
                let ad = telltale_proto::Header::parse(&r.bytes).unwrap().flags.ad();
                (rcode(&r.bytes), ad)
            });
            (r.verdict, shown)
        });
        eprintln!("{what}: {name} {qtype}: {result:?}");
        got.push((what, result));
        want.push((what, Some((verdict, Some((code, verdict == Secure))))));
    }
    z.tld.tamper.store(tampering::NONE, Ordering::Relaxed);
    assert_eq!(got, want);
}

/// REQ: DNS-011 (ADR-195) — a positive answer is secure only when it holds the asked type at the
/// question name, or at the end of its CNAME chain, or a denial whose own proof is about that name.
/// Each question as the zone answers it, then with NOERROR and the zone's signed SOA in the answer
/// section beside the NSEC3 record covering the name, and no record of the name:
/// - (b) `a.z3.s.t. A`, a name the wildcard `*.z3.s.t.` serves: secure with its address, then
///   indeterminate, without AD;
/// - (b) `nope.t. A`, a name that doesn't exist in `t.`: a signed NXDOMAIN, then indeterminate,
///   without AD;
/// - (a) `wz.s.t. A`, a signed CNAME to `q.z3.s.t.`, which `*.z3.s.t.` serves, validated link by
///   link: secure with the CNAME and the address, then bogus (EDE 6, nothing served) when the last
///   link's answer holds no address.
#[tokio::test]
async fn dns_011_offline_answer_needs_the_asked_type_or_its_own_denial() {
    use RecordType::{A, CNAME, SOA};
    use Verdict::{Bogus, Indeterminate, Secure};
    use telltale_proto::rcode::{NOERROR, NXDOMAIN};
    let budget = Duration::from_secs(5);
    let z = Arc::new(zone());
    let records = |owners: &[(&str, RecordType)]| -> Vec<(String, RecordType)> {
        owners.iter().map(|(o, t)| ((*o).to_owned(), *t)).collect()
    };
    let (mut got, mut want) = (Vec::new(), Vec::new());
    for (what, name, tamper, verdict, ede, shown) in [
        (
            "b: a name a wildcard serves",
            "a.z3.s.t",
            tampering::NONE,
            Secure,
            0,
            Some((NOERROR, true, records(&[("a.z3.s.t.", A)]))),
        ),
        (
            "b: the same, with the zone's SOA in the answer section",
            "a.z3.s.t",
            tampering::SOA_IN_ANSWER,
            Indeterminate,
            0,
            Some((NOERROR, false, records(&[("z3.s.t.", SOA)]))),
        ),
        (
            "b: a name that doesn't exist",
            "nope.t",
            tampering::NONE,
            Secure,
            0,
            Some((NXDOMAIN, true, Vec::new())),
        ),
        (
            "b: the same, with the zone's SOA in the answer section",
            "nope.t",
            tampering::SOA_IN_ANSWER,
            Indeterminate,
            0,
            Some((NOERROR, false, records(&[("t.", SOA)]))),
        ),
        (
            "a: link by link, to a name a wildcard serves",
            "wz.s.t",
            tampering::NONE,
            Secure,
            0,
            Some((
                NOERROR,
                true,
                records(&[("wz.s.t.", CNAME), ("q.z3.s.t.", A)]),
            )),
        ),
        (
            "a: the same, the last link with the zone's SOA in its answer section",
            "wz.s.t",
            tampering::SOA_IN_ANSWER,
            Bogus,
            telltale_proto::ede::DNSSEC_BOGUS,
            None,
        ),
    ] {
        z.tld.tamper.store(tamper, Ordering::Relaxed);
        let (v, g, _, _, _dir) = setup_zone(true, Arc::clone(&z)).await;
        warm_tld(&v, &g).await;
        let r = v
            .resolve(&g, question(name, rtype::A), budget, true, false)
            .await;
        let result = r.ok().map(|r| (r.verdict, r.ede, served(&r.bytes)));
        eprintln!("{what}: {name} A: {result:?}");
        got.push((what, name, result));
        want.push((what, name, Some((verdict, ede, shown))));
    }
    z.tld.tamper.store(tampering::NONE, Ordering::Relaxed);
    assert_eq!(got, want);
}

/// REQ: DNS-011 (ADR-188, ADR-195) — a wildcard CNAME at the question name with its proof stands
/// for itself only: when another record of the answer is made from a wildcard, each is validated
/// for its own name, in a zone signed with NSEC3 too.
/// - `x.k3.z3.s.t. A` (from `*.k3.z3.s.t.`, to `h.z3.s.t.`, which has an address of its own) is
///   secure with that address; with the address of `*.z3.s.t.` made for `h.z3.s.t.` in its place,
///   it is bogus (EDE 6) over two questions, nothing counted secure or insecure.
/// - `x.k4.z3.s.t. A` (from `*.k4.z3.s.t.`, to `q.z3.s.t.`, which `*.z3.s.t.` serves), answered as
///   the zone answers it, is secure, validated link by link; with every slot of that taken, it is
///   bogus (EDE 6).
#[tokio::test]
async fn dns_011_offline_nsec3_wildcard_cname_to_another_wildcard_record_needs_each_proof() {
    use RecordType::{A, CNAME};
    use Verdict::{Bogus, Secure};
    let budget = Duration::from_secs(5);
    let z = Arc::new(zone());
    let bogus = (Bogus, telltale_proto::ede::DNSSEC_BOGUS, None);
    let secure_with = |owners: &[(&str, RecordType)]| {
        let records = owners.iter().map(|(o, t)| ((*o).to_owned(), *t)).collect();
        (
            Secure,
            0,
            Some((telltale_proto::rcode::NOERROR, true, records)),
        )
    };
    let (mut got, mut want) = (Vec::new(), Vec::new());
    for (what, name, tamper, hold, rounds, expected) in [
        (
            "the target's own address",
            "x.k3.z3.s.t",
            tampering::NONE,
            false,
            1,
            secure_with(&[("x.k3.z3.s.t.", CNAME), ("h.z3.s.t.", A)]),
        ),
        (
            "the target's address from another wildcard",
            "x.k3.z3.s.t",
            tampering::OTHER_WILDCARD_FOR_TARGET,
            false,
            2,
            bogus.clone(),
        ),
        (
            "to a name another wildcard serves",
            "x.k4.z3.s.t",
            tampering::NONE,
            false,
            1,
            secure_with(&[("x.k4.z3.s.t.", CNAME), ("q.z3.s.t.", A)]),
        ),
        (
            "to a name another wildcard serves, every link-by-link slot taken",
            "x.k4.z3.s.t",
            tampering::NONE,
            true,
            1,
            bogus.clone(),
        ),
    ] {
        z.tld.tamper.store(tamper, Ordering::Relaxed);
        let (v, g, _, stats, _dir) = setup_zone(true, Arc::clone(&z)).await;
        warm_tld(&v, &g).await;
        let (secure, insecure) = (
            stats.secure.load(Ordering::Relaxed),
            stats.insecure.load(Ordering::Relaxed),
        );
        let held = if hold {
            v.hold_link_slots(0)
        } else {
            Vec::new()
        };
        let mut results = Vec::new();
        for _ in 0..rounds {
            let r = v
                .resolve(&g, question(name, rtype::A), budget, true, false)
                .await;
            // What is served, for a secure answer only.
            results.push(r.ok().map(|r| {
                let shown = (r.verdict == Secure).then(|| served(&r.bytes)).flatten();
                (r.verdict, r.ede, shown)
            }));
        }
        drop(held);
        eprintln!("{what}: {name} A: {results:?}");
        let counted = (
            stats.secure.load(Ordering::Relaxed) - secure,
            stats.insecure.load(Ordering::Relaxed) - insecure,
        );
        got.push((what, results, counted));
        let counted = if expected.0 == Secure { (1, 0) } else { (0, 0) };
        want.push((what, vec![Some(expected); rounds], counted));
    }
    z.tld.tamper.store(tampering::NONE, Ordering::Relaxed);
    assert_eq!(got, want);
}

/// REQ: DNS-011 (ADR-195) — in a zone signed with NSEC3, a record set at the question name made from
/// a wildcard is secure only with its zone's NSEC3 record covering the next closer name for its own
/// signature's label count, whatever comes before it in the answer:
/// - `x.h.z3.s.t. A`, below `h.z3.s.t.`, which exists, is a signed NXDOMAIN as the zone answers it;
///   answered with `h.z3.s.t.`'s address first and the address of `*.z3.s.t.` made for the name, it
///   is bogus (EDE 6) over two questions, nothing counted secure or insecure;
/// - `a.z3.s.t. A`, which `*.z3.s.t.` serves, is secure with its address;
/// - `x.k3.z3.s.t. A`, through the wildcard CNAME `*.k3.z3.s.t.`, is secure also with the target's
///   address before the CNAME.
#[tokio::test]
async fn dns_011_offline_nsec3_wildcard_record_needs_the_cover_of_its_own_next_closer_name() {
    use RecordType::{A, CNAME};
    use Verdict::{Bogus, Secure};
    let budget = Duration::from_secs(5);
    let z = Arc::new(zone());
    let bogus = (Bogus, telltale_proto::ede::DNSSEC_BOGUS, None);
    let secure_with = |code: u16, owners: &[(&str, RecordType)]| {
        let records = owners.iter().map(|(o, t)| ((*o).to_owned(), *t)).collect();
        (Secure, 0, Some((code, true, records)))
    };
    let (noerror, nxdomain) = (
        telltale_proto::rcode::NOERROR,
        telltale_proto::rcode::NXDOMAIN,
    );
    let (mut got, mut want) = (Vec::new(), Vec::new());
    for (what, name, tamper, rounds, expected) in [
        (
            "below a name that exists, as the zone answers it",
            "x.h.z3.s.t",
            tampering::NONE,
            1,
            secure_with(nxdomain, &[]),
        ),
        (
            "the same, the existing name's address first and a wildcard's at the name",
            "x.h.z3.s.t",
            tampering::EXISTING_NAME_FIRST,
            2,
            bogus.clone(),
        ),
        (
            "a name the wildcard serves",
            "a.z3.s.t",
            tampering::NONE,
            1,
            secure_with(noerror, &[("a.z3.s.t.", A)]),
        ),
        (
            "a wildcard CNAME, the target's address first",
            "x.k3.z3.s.t",
            tampering::TARGET_FIRST,
            1,
            secure_with(noerror, &[("x.k3.z3.s.t.", CNAME), ("h.z3.s.t.", A)]),
        ),
    ] {
        z.tld.tamper.store(tamper, Ordering::Relaxed);
        let (v, g, _, stats, _dir) = setup_zone(true, Arc::clone(&z)).await;
        warm_tld(&v, &g).await;
        let (secure, insecure) = (
            stats.secure.load(Ordering::Relaxed),
            stats.insecure.load(Ordering::Relaxed),
        );
        let mut results = Vec::new();
        for _ in 0..rounds {
            let r = v
                .resolve(&g, question(name, rtype::A), budget, true, false)
                .await;
            // What is served, for a secure answer only.
            results.push(r.ok().map(|r| {
                let shown = (r.verdict == Secure).then(|| served(&r.bytes)).flatten();
                (r.verdict, r.ede, shown)
            }));
        }
        eprintln!("{what}: {name} A: {results:?}");
        let counted = (
            stats.secure.load(Ordering::Relaxed) - secure,
            stats.insecure.load(Ordering::Relaxed) - insecure,
        );
        got.push((what, results, counted));
        let counted = if expected.0 == Secure { (1, 0) } else { (0, 0) };
        want.push((what, vec![Some(expected); rounds], counted));
    }
    z.tld.tamper.store(tampering::NONE, Ordering::Relaxed);
    assert_eq!(got, want);
}

/// The TTLs of a validated answer as served: those of the answer section's records, those of the
/// authority section's, and the shortest of both, the one the cache keeps the answer for.
type Ttls = (
    std::collections::BTreeSet<u32>,
    std::collections::BTreeSet<u32>,
    Option<u32>,
);

fn ttls(bytes: &[u8]) -> Ttls {
    let m = Message::from_vec(bytes).unwrap();
    let set = |records: &[Record]| records.iter().map(|r| r.ttl).collect();
    (
        set(&m.answers),
        set(&m.authorities),
        telltale_proto::summarize(bytes).unwrap().min_ttl,
    )
}

/// REQ: DNS-011 (ADR-195) — an answer made indeterminate because it doesn't reach its question is
/// kept 300 s at most: each record of its answer section with a longer TTL is served, and so
/// cached, with 300 s; a shorter TTL, and the authority section, are left as they are. Every other
/// answer keeps its TTLs (3600 s in the test zones): secure, insecure, bogus, and indeterminate for
/// another reason. Also counts the upstream questions one more validation of the same answer
/// costs, which a shorter cache lifetime repeats.
#[tokio::test]
async fn dns_011_offline_answer_that_does_not_reach_its_question_is_kept_300_s_at_most() {
    use Verdict::{Bogus, Indeterminate, Insecure, Secure};
    let budget = Duration::from_secs(5);
    let set = |ttls: &[u32]| {
        ttls.iter()
            .copied()
            .collect::<std::collections::BTreeSet<u32>>()
    };
    let (mut got, mut want) = (Vec::new(), Vec::new());
    // (what, `t.`'s denial TTL, question, tamper, verdict, answer TTLs, authority TTLs, cache TTL)
    for (what, proof_ttl, name, qtype, tamper, verdict, answer, authority, kept) in [
        (
            "the CNAME alone",
            3600,
            "alias.s.t",
            rtype::A,
            tampering::CNAME_ALONE,
            Indeterminate,
            set(&[300]),
            set(&[]),
            Some(300),
        ),
        (
            "a CNAME into an unsigned zone without the type, with that zone's SOA",
            3600,
            "out.s.t",
            rtype::AAAA,
            tampering::CNAME_AND_UNSIGNED_SOA,
            Indeterminate,
            set(&[300]),
            set(&[3600]),
            Some(300),
        ),
        (
            "the zone's SOA in the answer section, with a TTL below 300 s",
            120,
            "nope.t",
            rtype::A,
            tampering::SOA_IN_ANSWER,
            Indeterminate,
            set(&[120]),
            set(&[120]),
            Some(120),
        ),
        (
            "secure: a CNAME to an address",
            3600,
            "alias.s.t",
            rtype::A,
            tampering::NONE,
            Secure,
            set(&[3600]),
            set(&[]),
            Some(3600),
        ),
        (
            "insecure: into an unsigned zone, to an address",
            3600,
            "out.s.t",
            rtype::A,
            tampering::NONE,
            Insecure,
            set(&[3600]),
            set(&[]),
            Some(3600),
        ),
        (
            "bogus: a CNAME made from a DNAME",
            3600,
            "www.dn.s.t",
            rtype::A,
            tampering::NONE,
            Bogus,
            set(&[3600]),
            set(&[]),
            Some(3600),
        ),
        (
            "indeterminate for another reason: a second signature",
            3600,
            "any.w.s.t",
            rtype::A,
            tampering::SECOND_SIGNATURE,
            Indeterminate,
            set(&[3600]),
            set(&[3600]),
            Some(3600),
        ),
    ] {
        let z = Arc::new(zone_with(proof_ttl));
        z.tld.tamper.store(tamper, Ordering::Relaxed);
        let (v, g, asked, _, _dir) = setup_zone(true, Arc::clone(&z)).await;
        warm_tld(&v, &g).await;
        let r = v
            .resolve(&g, question(name, qtype), budget, true, false)
            .await
            .unwrap();
        let before = asked.load(Ordering::Relaxed);
        v.resolve(&g, question(name, qtype), budget, true, false)
            .await
            .unwrap();
        let again = asked.load(Ordering::Relaxed) - before;
        eprintln!(
            "{what}: {name} {qtype}: {:?} {:?}; upstream questions to validate it again: {again}",
            r.verdict,
            ttls(&r.bytes)
        );
        got.push((what, r.verdict, ttls(&r.bytes)));
        want.push((what, verdict, (answer, authority, kept)));
    }
    assert_eq!(got, want);
}
