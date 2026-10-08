//! Walking resource records in a response without decoding them.
//!
//! Used to find TTL offsets for cache patching (DNS-006), CNAME targets for deep inspection
//! (FLT-007), answer IPs for response filtering (FLT-015), and the negative TTL (RFC 2308).

use crate::consts::rtype;
use crate::edns::Edns;
use crate::header::{HEADER_LEN, Header};
use crate::name::skip_name;
use crate::{ParseError, be16, be32};

/// Message section of a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    Answer,
    Authority,
    Additional,
}

/// A located resource record. Offsets index into the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub section: Section,
    /// Offset of the owner name (may be a compression pointer).
    pub name_off: usize,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    /// Offset of the 4-byte TTL field.
    pub ttl_off: usize,
    pub rdata_off: usize,
    pub rdlen: u16,
}

impl Record {
    pub fn rdata<'a>(&self, msg: &'a [u8]) -> &'a [u8] {
        &msg[self.rdata_off..self.rdata_off + usize::from(self.rdlen)]
    }

    /// True for the OPT pseudo-record, whose TTL field is not a TTL and must never be patched.
    pub fn is_opt(&self) -> bool {
        self.rtype == rtype::OPT
    }
}

/// Iterator over all records after the question section. Yields an error once and stops if
/// the message is malformed.
#[derive(Clone, Debug)]
pub struct RecordIter<'a> {
    msg: &'a [u8],
    pos: usize,
    left: [u16; 3],
    done: bool,
}

/// Starts a record walk over `msg`, skipping the header and all questions.
pub fn records(msg: &[u8]) -> Result<RecordIter<'_>, ParseError> {
    let h = Header::parse(msg).ok_or(ParseError::Truncated)?;
    let mut pos = HEADER_LEN;
    for _ in 0..h.qdcount {
        pos = skip_name(msg, pos)? + 4;
        if pos > msg.len() {
            return Err(ParseError::Truncated);
        }
    }
    Ok(RecordIter {
        msg,
        pos,
        left: [h.ancount, h.nscount, h.arcount],
        done: false,
    })
}

impl RecordIter<'_> {
    fn next_record(&mut self) -> Option<Result<Record, ParseError>> {
        let idx = self.left.iter().position(|&n| n > 0)?;
        self.left[idx] -= 1;
        let section = [Section::Answer, Section::Authority, Section::Additional][idx];
        let msg = self.msg;
        let name_off = self.pos;
        let rec = (|| {
            let p = skip_name(msg, name_off)?;
            let rtype = be16(msg, p).ok_or(ParseError::Truncated)?;
            let rclass = be16(msg, p + 2).ok_or(ParseError::Truncated)?;
            let ttl = be32(msg, p + 4).ok_or(ParseError::Truncated)?;
            let rdlen = be16(msg, p + 8).ok_or(ParseError::Truncated)?;
            let rdata_off = p + 10;
            if rdata_off + usize::from(rdlen) > msg.len() {
                return Err(ParseError::Truncated);
            }
            Ok(Record {
                section,
                name_off,
                rtype,
                rclass,
                ttl,
                ttl_off: p + 4,
                rdata_off,
                rdlen,
            })
        })();
        match rec {
            Ok(r) => {
                self.pos = r.rdata_off + usize::from(r.rdlen);
                Some(Ok(r))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

impl Iterator for RecordIter<'_> {
    type Item = Result<Record, ParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let item = self.next_record();
        if matches!(item, Some(Err(_)) | None) {
            self.done = true;
        }
        item
    }
}

/// What the cache and policy layers need to know about an upstream response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseSummary {
    pub header: Header,
    /// Full RCODE including the extended bits from OPT.
    pub rcode: u16,
    /// Minimum TTL across answer and authority records (excluding OPT); `None` if there are none.
    pub min_ttl: Option<u32>,
    /// Negative-caching TTL: min(SOA TTL, SOA MINIMUM) from the authority section (RFC 2308 §5).
    pub negative_ttl: Option<u32>,
    /// Number of answer records.
    pub answers: u16,
    /// Offset of the OPT record, if any.
    pub opt_off: Option<usize>,
}

/// Validates framing of an entire response and summarizes it.
pub fn summarize(msg: &[u8]) -> Result<ResponseSummary, ParseError> {
    let header = Header::parse(msg).ok_or(ParseError::Truncated)?;
    let mut s = ResponseSummary {
        header,
        rcode: u16::from(header.flags.rcode()),
        min_ttl: None,
        negative_ttl: None,
        answers: header.ancount,
        opt_off: None,
    };
    for r in records(msg)? {
        let r = r?;
        if r.is_opt() {
            // RFC 6891 §6.1.1: one OPT, in the additional section. Anywhere else it would be
            // stripped as if it were additional data, leaving ANCOUNT or NSCOUNT wrong.
            if s.opt_off.is_some() || r.section != Section::Additional {
                return Err(ParseError::BadOpt);
            }
            let e = Edns::from_parts(r.rclass, r.ttl, r.rdata(msg))?;
            s.rcode |= u16::from(e.ext_rcode) << 4;
            s.opt_off = Some(r.name_off);
            continue;
        }
        if r.section != Section::Additional {
            s.min_ttl = Some(s.min_ttl.map_or(r.ttl, |m| m.min(r.ttl)));
        }
        if r.section == Section::Authority && r.rtype == rtype::SOA {
            // SOA MINIMUM is the last 4 bytes of the RDATA.
            let rd = r.rdata(msg);
            if rd.len() >= 22 {
                let minimum = be32(rd, rd.len() - 4).unwrap_or(0);
                let ttl = r.ttl.min(minimum);
                s.negative_ttl = Some(s.negative_ttl.map_or(ttl, |n| n.min(ttl)));
            }
        }
    }
    Ok(s)
}

/// Subtracts `elapsed` seconds from each TTL at `offsets` (saturating at `floor`).
/// The cache stores TTL offsets at insert time and calls this on every hit. REQ: DNS-006.
pub fn patch_ttls(msg: &mut [u8], offsets: &[u16], elapsed: u32, floor: u32) {
    for &off in offsets {
        let off = usize::from(off);
        if let Some(b) = msg.get_mut(off..off + 4) {
            let ttl = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            let new = ttl.saturating_sub(elapsed).max(floor);
            b.copy_from_slice(&new.to_be_bytes());
        }
    }
}

/// [`patch_ttls`] with the offsets packed as little-endian `u16` pairs (how the cache stores
/// them, next to the answer in one allocation; REQ: NFR-002, T10.2).
pub fn patch_ttls_packed(msg: &mut [u8], offsets: &[u8], elapsed: u32, floor: u32) {
    for o in offsets.as_chunks::<2>().0 {
        let off = usize::from(u16::from_le_bytes(*o));
        if let Some(b) = msg.get_mut(off..off + 4) {
            let ttl = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            let new = ttl.saturating_sub(elapsed).max(floor);
            b.copy_from_slice(&new.to_be_bytes());
        }
    }
}

/// [`set_ttls`] with packed little-endian offsets.
pub fn set_ttls_packed(msg: &mut [u8], offsets: &[u8], ttl: u32) {
    for o in offsets.as_chunks::<2>().0 {
        let off = usize::from(u16::from_le_bytes(*o));
        if let Some(b) = msg.get_mut(off..off + 4) {
            b.copy_from_slice(&ttl.to_be_bytes());
        }
    }
}

/// Sets every TTL at `offsets` to `ttl` (used for stale answers, RFC 8767 §4).
pub fn set_ttls(msg: &mut [u8], offsets: &[u16], ttl: u32) {
    for &off in offsets {
        let off = usize::from(off);
        if let Some(b) = msg.get_mut(off..off + 4) {
            b.copy_from_slice(&ttl.to_be_bytes());
        }
    }
}
