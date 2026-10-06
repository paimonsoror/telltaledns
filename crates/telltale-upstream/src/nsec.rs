//! REQ: DNS-011 (T9.16) — RFC 8198: aggressive use of DNSSEC-validated NSEC records.
//!
//! A validated, secure negative answer proves more than its own question: each NSEC record
//! says that no name exists between its owner and the next name (and which types its owner
//! has). Those ranges are kept, with the zone's SOA and every signature, and a later question
//! that falls inside one is answered here, without asking upstream:
//! - **NXDOMAIN** when the name is covered and so is the wildcard at its closest encloser
//!   (RFC 4035 §5.4); both NSEC records go into the answer.
//! - **NODATA** when an NSEC owned by the name lacks the type and CNAME (and isn't a
//!   delegation, unless the question is DS).
//!
//! Only NSEC (not NSEC3, whose hashed ranges need the zone's parameters for every lookup), and
//! only records the validator proved secure, signed by the zone whose SOA came with them.
//! Entries live for the smaller of the NSEC TTL and the SOA's negative TTL (RFC 8198 §5.4).
//! The cache is per upstream group and bounded; it's consulted on cache misses only.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use hickory_net::proto::dnssec::Proof;
use hickory_net::proto::dnssec::rdata::DNSSECRData;
use hickory_net::proto::op::{Message, ResponseCode};
use hickory_net::proto::rr::{Name, RData, Record, RecordType};

/// Ranges kept per upstream group at most; past it, the ones expiring first go.
const MAX_RANGES: usize = 20_000;
/// Zones (their SOA records) kept per upstream group at most.
const MAX_ZONES: usize = 2_000;

/// One NSEC range: no name exists strictly between its owner and `next`.
#[derive(Debug, Clone)]
struct Range {
    next: Name,
    /// The zone that signed it (its apex).
    zone: Name,
    types: Vec<RecordType>,
    /// The NSEC record and its signatures.
    records: Vec<Record>,
    expires: Instant,
}

/// A zone's SOA and its signatures (the authority of a synthesized answer).
#[derive(Debug, Clone)]
struct Soa {
    records: Vec<Record>,
    expires: Instant,
}

/// What a synthesized answer says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Denial {
    NxDomain,
    NoData,
}

/// A synthesized negative answer: its rcode and its authority section (SOA, NSEC records,
/// signatures), with TTLs counted down.
#[derive(Debug, Clone)]
pub(crate) struct Synth {
    pub(crate) denial: Denial,
    pub(crate) authorities: Vec<Record>,
}

/// The validated NSEC ranges of one upstream group.
#[derive(Debug, Default)]
pub(crate) struct Ranges {
    by_owner: BTreeMap<Name, Range>,
    soas: HashMap<Name, Soa>,
}

fn rrsigs(m: &Message, owner: &Name, covered: RecordType) -> Vec<Record> {
    m.authorities
        .iter()
        .filter(|r| {
            r.name == *owner
                && matches!(&r.data, RData::DNSSEC(DNSSECRData::RRSIG(s)) if s.input().type_covered == covered)
        })
        .cloned()
        .collect()
}

fn signer(sigs: &[Record]) -> Option<Name> {
    sigs.iter().find_map(|r| match &r.data {
        RData::DNSSEC(DNSSECRData::RRSIG(s)) => Some(s.input().signer_name.clone()),
        _ => None,
    })
}

/// The longest common ancestor of `a` and `b` (case-insensitive).
fn common_ancestor(a: &Name, b: &Name) -> Name {
    let n = a
        .iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(x, y)| x.eq_ignore_ascii_case(y))
        .count();
    a.trim_to(n)
}

impl Range {
    /// An NS without an SOA: a delegation point, so names below belong to another zone.
    fn delegation(&self) -> bool {
        self.types.contains(&RecordType::NS) && !self.types.contains(&RecordType::SOA)
    }

    /// Whether `q` (greater than `owner`) is strictly between `owner` and `next`. The last NSEC
    /// of a zone points back at the apex: it covers everything after its owner.
    fn covers(&self, owner: &Name, q: &Name) -> bool {
        q > owner && (*q < self.next || self.next == self.zone) && self.zone.zone_of(q)
    }
}

impl Ranges {
    /// REQ: DNS-011 (T9.16) — keeps the NSEC records of `m`, a validated negative answer.
    /// Records the validator didn't prove secure, or that another zone signed, are skipped.
    pub(crate) fn learn(&mut self, m: &Message, now: Instant) {
        let negative = m.answers.is_empty()
            && matches!(
                m.metadata.response_code,
                ResponseCode::NXDomain | ResponseCode::NoError
            );
        if !negative {
            return;
        }
        let Some(soa) = m
            .authorities
            .iter()
            .find(|r| r.record_type() == RecordType::SOA && r.proof == Proof::Secure)
        else {
            return;
        };
        let RData::SOA(s) = &soa.data else {
            return;
        };
        let zone = soa.name.clone();
        let negative_ttl = soa.ttl.min(s.minimum);
        if negative_ttl == 0 {
            return;
        }
        let mut learned = false;
        for r in &m.authorities {
            let RData::DNSSEC(DNSSECRData::NSEC(n)) = &r.data else {
                continue;
            };
            if r.proof != Proof::Secure || !zone.zone_of(&r.name) {
                continue;
            }
            let sigs = rrsigs(m, &r.name, RecordType::NSEC);
            if signer(&sigs).as_ref() != Some(&zone) {
                continue;
            }
            let ttl = r.ttl.min(negative_ttl);
            let mut records = vec![r.clone()];
            records.extend(sigs);
            self.by_owner.insert(
                r.name.clone(),
                Range {
                    next: n.next_domain_name().clone(),
                    zone: zone.clone(),
                    types: n.type_bit_maps().collect(),
                    records,
                    expires: now + Duration::from_secs(u64::from(ttl)),
                },
            );
            learned = true;
        }
        if learned {
            let mut records = vec![soa.clone()];
            records.extend(rrsigs(m, &zone, RecordType::SOA));
            self.soas.insert(
                zone,
                Soa {
                    records,
                    expires: now + Duration::from_secs(u64::from(negative_ttl)),
                },
            );
            self.trim(now);
        }
    }

    /// The range whose owner is the greatest name not after `q`, if it hasn't expired.
    fn find(&self, q: &Name, now: Instant) -> Option<(&Name, &Range)> {
        self.by_owner
            .range(..=q.clone())
            .next_back()
            .filter(|(_, r)| r.expires > now)
    }

    /// REQ: DNS-011 (T9.16) — a negative answer for `q`/`qtype` proven by cached ranges, or
    /// `None` when they don't prove one (then the question goes upstream as usual).
    pub(crate) fn synthesize(&self, q: &Name, qtype: RecordType, now: Instant) -> Option<Synth> {
        let (owner, range) = self.find(q, now)?;
        let soa = self.soas.get(&range.zone).filter(|s| s.expires > now)?;
        let mut parts: Vec<(&[Record], Instant)> = vec![(&soa.records, soa.expires)];
        let denial = if owner == q {
            // NODATA (RFC 4035 §3.1.3.1).
            let delegation = range.delegation() && *owner != range.zone;
            if range.types.contains(&qtype)
                || range.types.contains(&RecordType::CNAME)
                || (delegation && qtype != RecordType::DS)
            {
                return None;
            }
            parts.push((&range.records, range.expires));
            Denial::NoData
        } else {
            // NXDOMAIN (RFC 4035 §5.4): the name is covered, and so is the wildcard at the
            // closest encloser.
            if !range.covers(owner, q) {
                return None;
            }
            // Below a delegation or a DNAME, names belong elsewhere.
            if owner.zone_of(q) && (range.delegation() || range.types.contains(&RecordType::DNAME))
            {
                return None;
            }
            let a = common_ancestor(q, owner);
            let b = common_ancestor(q, &range.next);
            let encloser = if a.num_labels() >= b.num_labels() {
                a
            } else {
                b
            };
            let wildcard = encloser.prepend_label("*").ok()?;
            let (wowner, wrange) = self.find(&wildcard, now)?;
            if wrange.zone != range.zone || !wrange.covers(wowner, &wildcard) {
                return None;
            }
            parts.push((&range.records, range.expires));
            if wowner != owner {
                parts.push((&wrange.records, wrange.expires));
            }
            Denial::NxDomain
        };
        // Every record counts down to the earliest expiry among them.
        let left = parts
            .iter()
            .map(|(_, e)| e.saturating_duration_since(now).as_secs())
            .min()
            .unwrap_or(0);
        let left = u32::try_from(left).unwrap_or(u32::MAX).max(1);
        let authorities = parts
            .iter()
            .flat_map(|(rs, _)| rs.iter())
            .map(|r| {
                let mut r = r.clone();
                r.ttl = r.ttl.min(left);
                r
            })
            .collect();
        Some(Synth {
            denial,
            authorities,
        })
    }

    /// Drops expired entries, then the soonest-expiring ones past the bounds.
    fn trim(&mut self, now: Instant) {
        if self.by_owner.len() > MAX_RANGES {
            self.by_owner.retain(|_, r| r.expires > now);
        }
        while self.by_owner.len() > MAX_RANGES {
            let Some(k) = self
                .by_owner
                .iter()
                .min_by_key(|(_, r)| r.expires)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.by_owner.remove(&k);
        }
        if self.soas.len() > MAX_ZONES {
            self.soas.retain(|_, s| s.expires > now);
            while self.soas.len() > MAX_ZONES {
                let Some(k) = self
                    .soas
                    .iter()
                    .min_by_key(|(_, s)| s.expires)
                    .map(|(k, _)| k.clone())
                else {
                    break;
                };
                self.soas.remove(&k);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_owner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_net::proto::dnssec::rdata::{NSEC, RRSIG};
    use hickory_net::proto::dnssec::{Algorithm, rdata::sig::SigInput};
    use hickory_net::proto::rr::SerialNumber;
    use hickory_net::proto::rr::rdata::SOA;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn sig(owner: &str, covered: RecordType, signer: &str) -> Record {
        let input = SigInput {
            type_covered: covered,
            algorithm: Algorithm::ED25519,
            num_labels: 1,
            original_ttl: 86_400,
            sig_expiration: SerialNumber::new(u32::MAX),
            sig_inception: SerialNumber::new(0),
            key_tag: 1,
            signer_name: n(signer),
        };
        let mut r = Record::from_rdata(
            n(owner),
            86_400,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, vec![0; 64]))),
        );
        r.proof = Proof::Secure;
        r
    }

    fn nsec(owner: &str, next: &str, types: &[RecordType], ttl: u32) -> Record {
        let mut r = Record::from_rdata(
            n(owner),
            ttl,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(n(next), types.iter().copied()))),
        );
        r.proof = Proof::Secure;
        r
    }

    /// A secure denial from `zone` with these NSEC records.
    fn denial(zone: &str, rcode: ResponseCode, nsecs: &[Record]) -> Message {
        let mut m = Message::response(0, hickory_net::proto::op::OpCode::Query);
        m.metadata.response_code = rcode;
        let mut soa = Record::from_rdata(
            n(zone),
            86_400,
            RData::SOA(SOA::new(n("a.ns."), n("h.ns."), 1, 1, 1, 1, 3600)),
        );
        soa.proof = Proof::Secure;
        m.add_authority(soa);
        m.add_authority(sig(zone, RecordType::SOA, zone));
        for r in nsecs {
            m.add_authority(r.clone());
            m.add_authority(sig(&r.name.to_ascii(), RecordType::NSEC, zone));
        }
        m
    }

    /// REQ: DNS-011 (T9.16) — the root's NXDOMAIN for one made-up TLD proves the next: the
    /// name and the root wildcard are both covered; the answer carries both NSEC records,
    /// their signatures, and the SOA, with the negative TTL.
    #[test]
    fn dns_011_rfc8198_nxdomain_from_cached_ranges() {
        let t0 = Instant::now();
        let mut r = Ranges::default();
        let m = denial(
            ".",
            ResponseCode::NXDomain,
            &[
                nsec(
                    "zw.",
                    ".",
                    &[
                        RecordType::NS,
                        RecordType::DS,
                        RecordType::RRSIG,
                        RecordType::NSEC,
                    ],
                    86_400,
                ),
                nsec(
                    ".",
                    "aaa.",
                    &[
                        RecordType::NS,
                        RecordType::SOA,
                        RecordType::RRSIG,
                        RecordType::NSEC,
                        RecordType::DNSKEY,
                    ],
                    86_400,
                ),
            ],
        );
        r.learn(&m, t0);
        assert_eq!(r.len(), 2);
        let s = r
            .synthesize(&n("zz-telltale-2."), RecordType::A, t0)
            .expect("proven");
        assert_eq!(s.denial, Denial::NxDomain);
        let types: Vec<RecordType> = s.authorities.iter().map(Record::record_type).collect();
        assert_eq!(types.iter().filter(|t| **t == RecordType::NSEC).count(), 2);
        assert_eq!(types.iter().filter(|t| **t == RecordType::RRSIG).count(), 3);
        assert!(
            s.authorities.iter().all(|x| x.ttl <= 3600),
            "negative TTL caps all"
        );
        // Expired: nothing.
        assert!(
            r.synthesize(
                &n("zz-telltale-2."),
                RecordType::A,
                t0 + Duration::from_secs(3601)
            )
            .is_none()
        );
    }

    /// REQ: DNS-011 (T9.16) — what isn't proven goes upstream: a name below a delegation the
    /// range starts at, an existing name's other type with CNAME, a missing wildcard proof,
    /// another zone's signature, an insecure record.
    #[test]
    fn dns_011_rfc8198_only_what_is_proven() {
        let t0 = Instant::now();
        let mut r = Ranges::default();
        r.learn(
            &denial(
                ".",
                ResponseCode::NXDomain,
                &[nsec(
                    "com.",
                    "commbank.",
                    &[
                        RecordType::NS,
                        RecordType::DS,
                        RecordType::RRSIG,
                        RecordType::NSEC,
                    ],
                    86_400,
                )],
            ),
            t0,
        );
        // Inside com.'s span but below the delegation: com's own zone decides.
        assert!(
            r.synthesize(&n("nothing-here.com."), RecordType::A, t0)
                .is_none()
        );
        // Covered, but no NSEC proves the root wildcard absent.
        assert!(r.synthesize(&n("comm."), RecordType::A, t0).is_none());

        let mut r = Ranges::default();
        r.learn(
            &denial(
                "example.",
                ResponseCode::NoError,
                &[nsec(
                    "www.example.",
                    "zzz.example.",
                    &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
                    600,
                )],
            ),
            t0,
        );
        let s = r
            .synthesize(&n("www.example."), RecordType::AAAA, t0)
            .expect("NODATA");
        assert_eq!(s.denial, Denial::NoData);
        assert!(
            r.synthesize(&n("www.example."), RecordType::A, t0)
                .is_none(),
            "the type exists"
        );

        // Signed by another zone, or not proven secure: not learned.
        let mut r = Ranges::default();
        let mut m = denial("example.", ResponseCode::NoError, &[]);
        m.add_authority(nsec("a.example.", "b.example.", &[RecordType::A], 600));
        m.add_authority(sig("a.example.", RecordType::NSEC, "other."));
        let mut insecure = nsec("c.example.", "d.example.", &[RecordType::A], 600);
        insecure.proof = Proof::Insecure;
        m.add_authority(insecure);
        m.add_authority(sig("c.example.", RecordType::NSEC, "example."));
        r.learn(&m, t0);
        assert_eq!(r.len(), 0);
    }
}
