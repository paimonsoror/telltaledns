//! Reading authoritative responses and writing the final one (REQ: DNS-012).
//!
//! Records are copied out of each server's response with their names (and the names inside
//! RFC 1035 RDATA: CNAME, NS, PTR, MX, SOA, plus DNAME and SRV) written uncompressed, so
//! records from several servers can go into one message.

use telltale_proto::{
    HEADER_LEN, Header, NameBuf, Section, rcode, read_name, records, rtype, summarize,
};

/// One resource record, names uncompressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rr {
    pub name: NameBuf,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl Rr {
    /// The name in a CNAME, DNAME, or NS record's RDATA.
    pub fn target(&self) -> Option<NameBuf> {
        if !matches!(self.rtype, rtype::CNAME | rtype::DNAME | rtype::NS) {
            return None;
        }
        let mut n = NameBuf::default();
        read_name(&self.rdata, 0, &mut n).ok()?;
        Some(n)
    }

    /// The address in an A or AAAA record.
    pub fn addr(&self) -> Option<std::net::IpAddr> {
        match (self.rtype, self.rdata.len()) {
            (rtype::A, 4) => {
                let b: [u8; 4] = self.rdata[..4].try_into().ok()?;
                Some(std::net::IpAddr::from(b))
            }
            (rtype::AAAA, 16) => {
                let b: [u8; 16] = self.rdata[..16].try_into().ok()?;
                Some(std::net::IpAddr::from(b))
            }
            _ => None,
        }
    }

    /// The type an RRSIG covers.
    pub fn covered(&self) -> Option<u16> {
        (self.rtype == rtype::RRSIG && self.rdata.len() >= 2)
            .then(|| u16::from_be_bytes([self.rdata[0], self.rdata[1]]))
    }
}

/// Appends `name` (possibly compressed in `msg` at `pos`) uncompressed to `out`.
fn copy_name(msg: &[u8], pos: usize, out: &mut Vec<u8>) -> Option<usize> {
    let mut n = NameBuf::default();
    let end = read_name(msg, pos, &mut n).ok()?;
    out.extend_from_slice(n.as_wire());
    Some(end)
}

/// The RDATA at `off..off + len`, with compressed names expanded.
fn rdata(msg: &[u8], rt: u16, off: usize, len: usize) -> Option<Vec<u8>> {
    let raw = msg.get(off..off + len)?;
    let mut out = Vec::with_capacity(len + 16);
    match rt {
        rtype::CNAME | rtype::NS | rtype::PTR | rtype::DNAME => {
            copy_name(msg, off, &mut out)?;
        }
        rtype::MX => {
            out.extend_from_slice(raw.get(..2)?);
            copy_name(msg, off + 2, &mut out)?;
        }
        rtype::SRV => {
            out.extend_from_slice(raw.get(..6)?);
            copy_name(msg, off + 6, &mut out)?;
        }
        rtype::SOA => {
            let p = copy_name(msg, off, &mut out)?;
            let p = copy_name(msg, p, &mut out)?;
            out.extend_from_slice(msg.get(p..p + 20)?);
        }
        _ => out.extend_from_slice(raw),
    }
    Some(out)
}

/// A parsed response: its RCODE, AA bit, and sections.
#[derive(Debug, Clone, Default)]
pub struct Parsed {
    pub rcode: u16,
    pub aa: bool,
    pub answer: Vec<Rr>,
    pub authority: Vec<Rr>,
    pub additional: Vec<Rr>,
}

/// Parses `msg` (framing already checked by the network layer).
pub fn parse(msg: &[u8]) -> Option<Parsed> {
    let s = summarize(msg).ok()?;
    let mut p = Parsed {
        rcode: s.rcode,
        aa: s.header.flags.aa(),
        ..Parsed::default()
    };
    for r in records(msg).ok()?.flatten() {
        if r.is_opt() {
            continue;
        }
        let mut name = NameBuf::default();
        read_name(msg, r.name_off, &mut name).ok()?;
        let rr = Rr {
            name,
            rtype: r.rtype,
            class: r.rclass,
            ttl: r.ttl,
            rdata: rdata(msg, r.rtype, r.rdata_off, usize::from(r.rdlen))?,
        };
        match r.section {
            Section::Answer => p.answer.push(rr),
            Section::Authority => p.authority.push(rr),
            Section::Additional => p.additional.push(rr),
        }
    }
    Some(p)
}

/// What an authoritative server's response means for a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Records for the name (the CNAME chain from it and the final `RRset` with signatures);
    /// `next` is a CNAME target the response didn't answer, to resolve from scratch.
    Answer {
        records: Vec<Rr>,
        next: Option<NameBuf>,
    },
    /// The name exists without that type (authority: SOA, NSEC*, signatures).
    NoData { chain: Vec<Rr>, authority: Vec<Rr> },
    /// The name doesn't exist.
    NxDomain { chain: Vec<Rr>, authority: Vec<Rr> },
    /// A delegation to `child`'s servers (names, and glue the referring zone may vouch for).
    Referral {
        child: NameBuf,
        ns: Vec<NameBuf>,
        glue: Vec<(NameBuf, std::net::IpAddr)>,
        ttl: u32,
        /// The DS set (and its signatures) for a signed delegation, when DO was set.
        ds: Vec<Rr>,
    },
    /// Not usable from this server (lame, refused, out of bailiwick, garbled): ask another.
    Lame,
}

/// The CNAME chain from `qname` in `answer`, the final `RRset` of `qtype` (plus covering
/// signatures), and the unanswered target if the chain leaves the response.
fn chain(answer: &[Rr], qname: &NameBuf, qtype: u16, zone: &NameBuf) -> (Vec<Rr>, NameBuf, bool) {
    let mut out = Vec::new();
    let mut at = *qname;
    let mut done = false;
    for _ in 0..16 {
        // In bailiwick only: the server speaks for `zone` and below.
        if !at.is_subdomain_of(zone) {
            break;
        }
        let finals: Vec<&Rr> = answer
            .iter()
            .filter(|r| r.name == at && (r.rtype == qtype || r.covered() == Some(qtype)))
            .collect();
        if finals.iter().any(|r| r.rtype == qtype) && qtype != rtype::CNAME {
            out.extend(finals.into_iter().cloned());
            done = true;
            break;
        }
        // DNAMEs that rewrite this name come along with the synthesized CNAME.
        let dnames: Vec<Rr> = answer
            .iter()
            .filter(|r| {
                (r.rtype == rtype::DNAME || r.covered() == Some(rtype::DNAME))
                    && at.is_subdomain_of(&r.name)
                    && at != r.name
                    && !out.contains(r)
            })
            .cloned()
            .collect();
        out.extend(dnames);
        let Some(c) = answer
            .iter()
            .find(|r| r.name == at && r.rtype == rtype::CNAME)
        else {
            break;
        };
        out.extend(
            answer
                .iter()
                .filter(|r| {
                    r.name == at && (r.rtype == rtype::CNAME || r.covered() == Some(rtype::CNAME))
                })
                .cloned(),
        );
        if qtype == rtype::CNAME {
            done = true;
            break;
        }
        match c.target() {
            Some(t) => at = t,
            None => break,
        }
    }
    (out, at, done)
}

/// Negative-answer evidence: SOA, NSEC, NSEC3, and their signatures.
fn negative(authority: &[Rr], zone: &NameBuf) -> Vec<Rr> {
    authority
        .iter()
        .filter(|r| {
            r.name.is_subdomain_of(zone)
                && (matches!(r.rtype, rtype::SOA | rtype::NSEC | rtype::NSEC3)
                    || matches!(r.covered(), Some(rtype::SOA | rtype::NSEC | rtype::NSEC3)))
        })
        .cloned()
        .collect()
}

/// Classifies `p`, the answer of a server for `zone` to `qname`/`qtype`.
pub fn classify(p: &Parsed, qname: &NameBuf, qtype: u16, zone: &NameBuf) -> Outcome {
    if p.rcode != rcode::NOERROR && p.rcode != rcode::NXDOMAIN {
        return Outcome::Lame;
    }
    let (records, last, done) = chain(&p.answer, qname, qtype, zone);
    if p.rcode == rcode::NXDOMAIN {
        return Outcome::NxDomain {
            chain: records,
            authority: negative(&p.authority, zone),
        };
    }
    if done {
        return Outcome::Answer {
            records,
            next: None,
        };
    }
    if !records.is_empty() {
        // The chain went on to `last`, which this response doesn't answer.
        return if last.is_subdomain_of(zone)
            && p.aa
            && p.authority.iter().any(|r| r.rtype == rtype::SOA)
        {
            Outcome::NoData {
                chain: records,
                authority: negative(&p.authority, zone),
            }
        } else {
            Outcome::Answer {
                records,
                next: Some(last),
            }
        };
    }
    // A referral: NS for a zone strictly below `zone` that contains the name.
    let ns: Vec<&Rr> = p
        .authority
        .iter()
        .filter(|r| r.rtype == rtype::NS)
        .collect();
    if !p.aa
        && let Some(first) = ns.first()
    {
        let child = first.name;
        let ok = child != *zone && child.is_subdomain_of(zone) && qname.is_subdomain_of(&child);
        if !ok {
            return Outcome::Lame; // upward or sideways: not this server's to give
        }
        let names: Vec<NameBuf> = ns
            .iter()
            .filter(|r| r.name == child)
            .filter_map(|r| r.target())
            .collect();
        // Glue only for server names the referring zone is authoritative for.
        let glue = p
            .additional
            .iter()
            .filter(|r| names.contains(&r.name) && r.name.is_subdomain_of(zone))
            .filter_map(|r| r.addr().map(|a| (r.name, a)))
            .collect();
        let ttl = ns.iter().map(|r| r.ttl).min().unwrap_or(3600);
        let ds = p
            .authority
            .iter()
            .filter(|r| r.name == child && (r.rtype == rtype::DS || r.covered() == Some(rtype::DS)))
            .cloned()
            .collect();
        return Outcome::Referral {
            child,
            ns: names,
            glue,
            ttl,
            ds,
        };
    }
    if p.aa || p.authority.iter().any(|r| r.rtype == rtype::SOA) {
        return Outcome::NoData {
            chain: Vec::new(),
            authority: negative(&p.authority, zone),
        };
    }
    Outcome::Lame
}

/// The response to the client's `query`: its ID and question, RA set, `rc`, the records,
/// and an OPT record when the query had one.
pub fn encode(query: &[u8], rc: u16, answer: &[Rr], authority: &[Rr]) -> Option<Vec<u8>> {
    let qh = Header::parse(query)?;
    // The question as asked (name, type, class), and whether it carried OPT.
    let mut pos = HEADER_LEN;
    let mut name = NameBuf::default();
    let end = telltale_proto::read_name_uncompressed(query, pos, &mut name).ok()?;
    let qend = end + 4;
    let question = query.get(pos..qend)?;
    pos = qend;
    let (mut opt, mut dnssec_ok) = (false, false);
    if qh.arcount > 0
        && query.get(pos) == Some(&0)
        && query.get(pos + 1..pos + 3) == Some(&rtype::OPT.to_be_bytes())
    {
        opt = true;
        dnssec_ok = query.get(pos + 7).is_some_and(|b| b & 0x80 != 0);
    }
    let rd = qh.flags.rd();
    let mut flags: u16 = 0x8000 | 0x0080 | (rc & 0x0f); // QR, RA, RCODE
    if rd {
        flags |= 0x0100;
    }
    if qh.flags.cd() {
        flags |= 0x0010;
    }
    let count = |n: usize| u16::try_from(n).ok();
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&qh.id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&count(answer.len())?.to_be_bytes());
    out.extend_from_slice(&count(authority.len())?.to_be_bytes());
    out.extend_from_slice(&u16::from(opt).to_be_bytes());
    out.extend_from_slice(question);
    for r in answer.iter().chain(authority) {
        out.extend_from_slice(r.name.as_wire());
        out.extend_from_slice(&r.rtype.to_be_bytes());
        out.extend_from_slice(&r.class.to_be_bytes());
        out.extend_from_slice(&r.ttl.to_be_bytes());
        out.extend_from_slice(&u16::try_from(r.rdata.len()).ok()?.to_be_bytes());
        out.extend_from_slice(&r.rdata);
    }
    if opt {
        out.push(0);
        out.extend_from_slice(&rtype::OPT.to_be_bytes());
        out.extend_from_slice(&1232u16.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&(if dnssec_ok { 0x8000u16 } else { 0 }).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
    }
    Some(out)
}
