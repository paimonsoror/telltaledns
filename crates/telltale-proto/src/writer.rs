//! Writing responses into caller-provided buffers (no allocation).
//!
//! REQ: DNS-005 (EDNS + TC truncation), DNS-013 (EDE), DNS-019 (RFC 8482 ANY), `spec/03` §7.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::consts::{MIN_UDP_PAYLOAD, class, opt, rtype};
use crate::edns::{Edns, EdnsOut};
use crate::header::{FlagBit, Flags, HEADER_LEN, Header};
use crate::name::{NameBuf, read_name_uncompressed};
use crate::query::Query;
use crate::record::records;
use crate::{be16, be32};

/// The output buffer was too small.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("output buffer too small")]
pub struct BufferTooSmall;

/// Bounds-checked big-endian writer over a byte slice.
#[derive(Debug)]
pub struct Writer<'b> {
    buf: &'b mut [u8],
    pos: usize,
}

impl<'b> Writer<'b> {
    pub fn new(buf: &'b mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn pos(&self) -> usize {
        self.pos
    }
    pub fn bytes(&mut self, b: &[u8]) -> Result<(), BufferTooSmall> {
        let end = self.pos.checked_add(b.len()).ok_or(BufferTooSmall)?;
        self.buf
            .get_mut(self.pos..end)
            .ok_or(BufferTooSmall)?
            .copy_from_slice(b);
        self.pos = end;
        Ok(())
    }
    pub fn u8(&mut self, v: u8) -> Result<(), BufferTooSmall> {
        self.bytes(&[v])
    }
    pub fn u16(&mut self, v: u16) -> Result<(), BufferTooSmall> {
        self.bytes(&v.to_be_bytes())
    }
    pub fn u32(&mut self, v: u32) -> Result<(), BufferTooSmall> {
        self.bytes(&v.to_be_bytes())
    }
    pub fn patch_u16(&mut self, at: usize, v: u16) -> Result<(), BufferTooSmall> {
        self.buf
            .get_mut(at..at + 2)
            .ok_or(BufferTooSmall)?
            .copy_from_slice(&v.to_be_bytes());
        Ok(())
    }
}

/// Compression pointer to the question name, which always starts at offset 12.
const PTR_QNAME: u16 = 0xC000 | HEADER_LEN as u16;

/// Builds a response to a parsed query: header, echoed question, then records.
#[derive(Debug)]
pub struct ResponseBuilder<'b> {
    w: Writer<'b>,
    flags: Flags,
    rcode: u16,
    counts: [u16; 3],
}

impl<'b> ResponseBuilder<'b> {
    /// Starts a response: same ID, QR=1, RA=1, RD and CD copied, question echoed as sent.
    pub fn new(q: &Query<'_>, out: &'b mut [u8], rcode: u16) -> Result<Self, BufferTooSmall> {
        let flags = Flags(0)
            .with(FlagBit::Qr, true)
            .with(FlagBit::Ra, true)
            .with(FlagBit::Rd, q.header.flags.rd())
            .with(FlagBit::Cd, q.header.flags.cd());
        let mut w = Writer::new(out);
        w.bytes(
            &Header {
                id: q.header.id,
                flags,
                qdcount: 1,
                ..Header::default()
            }
            .to_bytes(),
        )?;
        w.bytes(q.question_bytes())?;
        Ok(Self {
            w,
            flags,
            rcode,
            counts: [0; 3],
        })
    }

    /// Marks the answer authoritative (local data, DNS-010).
    pub fn authoritative(&mut self, on: bool) -> &mut Self {
        self.flags = self.flags.with(FlagBit::Aa, on);
        self
    }

    pub fn set_rcode(&mut self, rcode: u16) -> &mut Self {
        self.rcode = rcode;
        self
    }

    fn rr_header(&mut self, rtype: u16, ttl: u32, rdlen: u16) -> Result<(), BufferTooSmall> {
        self.w.u16(PTR_QNAME)?;
        self.w.u16(rtype)?;
        self.w.u16(class::IN)?;
        self.w.u32(ttl)?;
        self.w.u16(rdlen)
    }

    /// Adds an `A` answer owned by the question name.
    pub fn answer_a(&mut self, ttl: u32, ip: Ipv4Addr) -> Result<&mut Self, BufferTooSmall> {
        self.rr_header(rtype::A, ttl, 4)?;
        self.w.bytes(&ip.octets())?;
        self.counts[0] += 1;
        Ok(self)
    }

    /// Adds an `AAAA` answer owned by the question name.
    pub fn answer_aaaa(&mut self, ttl: u32, ip: Ipv6Addr) -> Result<&mut Self, BufferTooSmall> {
        self.rr_header(rtype::AAAA, ttl, 16)?;
        self.w.bytes(&ip.octets())?;
        self.counts[0] += 1;
        Ok(self)
    }

    /// Adds a `CNAME` answer (question name → `target`).
    pub fn answer_cname(
        &mut self,
        ttl: u32,
        target: &NameBuf,
    ) -> Result<&mut Self, BufferTooSmall> {
        let len = u16::try_from(target.wire_len()).map_err(|_| BufferTooSmall)?;
        self.rr_header(rtype::CNAME, ttl, len)?;
        self.w.bytes(target.as_wire())?;
        self.counts[0] += 1;
        Ok(self)
    }

    /// RFC 8482 §4.2 minimal response to `ANY`: a synthesized HINFO with CPU "RFC8482".
    /// REQ: DNS-019.
    pub fn answer_any_refusal(&mut self, ttl: u32) -> Result<&mut Self, BufferTooSmall> {
        const RDATA: &[u8] = b"\x07RFC8482\x00";
        self.rr_header(rtype::HINFO, ttl, RDATA.len() as u16)?;
        self.w.bytes(RDATA)?;
        self.counts[0] += 1;
        Ok(self)
    }

    /// Adds a synthetic SOA to the authority section so the client can cache a negative
    /// answer for `ttl` seconds (RFC 2308). Owner = question name; MNAME/RNAME = root.
    pub fn authority_soa(&mut self, ttl: u32) -> Result<&mut Self, BufferTooSmall> {
        // mname(1) rname(1) serial refresh retry expire minimum (5 × 4)
        self.rr_header(rtype::SOA, ttl, 22)?;
        self.w.bytes(&[0, 0])?;
        for v in [1u32, 3600, 600, 86_400, ttl] {
            self.w.u32(v)?;
        }
        self.counts[1] += 1;
        Ok(self)
    }

    /// Appends OPT (if `edns`), writes the final flags and counts, and returns the length.
    ///
    /// An extended RCODE (> 15) needs `edns`; without it, it is downgraded to SERVFAIL.
    pub fn finish(mut self, edns: Option<EdnsOut<'_>>) -> Result<usize, BufferTooSmall> {
        let mut rcode = self.rcode;
        if let Some(e) = edns {
            write_opt(&mut self.w, &e, (rcode >> 4) as u8)?;
            self.counts[2] += 1;
        } else if rcode > 0xF {
            rcode = crate::consts::rcode::SERVFAIL;
        }
        let flags = self.flags.with_rcode((rcode & 0xF) as u8);
        self.w.patch_u16(2, flags.0)?;
        self.w.patch_u16(6, self.counts[0])?;
        self.w.patch_u16(8, self.counts[1])?;
        self.w.patch_u16(10, self.counts[2])?;
        Ok(self.w.pos())
    }
}

fn write_opt(w: &mut Writer<'_>, e: &EdnsOut<'_>, ext_rcode: u8) -> Result<(), BufferTooSmall> {
    // EDE option = code(2) + length(2) + INFO-CODE(2) + EXTRA-TEXT (RFC 8914 §2).
    let ede_len = e.ede.map_or(0, |(_, text)| 6 + text.len());
    let rdlen = u16::try_from(ede_len).map_err(|_| BufferTooSmall)?;
    w.u8(0)?; // root owner
    w.u16(rtype::OPT)?;
    w.u16(e.udp_payload.max(MIN_UDP_PAYLOAD))?;
    w.u8(ext_rcode)?;
    w.u8(0)?; // version 0
    w.u16(if e.dnssec_ok { 0x8000 } else { 0 })?;
    w.u16(rdlen)?;
    if let Some((code, text)) = e.ede {
        w.u16(opt::EDE)?;
        w.u16(rdlen - 4)?;
        w.u16(code)?;
        w.bytes(text.as_bytes())?;
    }
    Ok(())
}

/// Appends an OPT record to the message in `buf[..len]` (which must not already have one),
/// increments ARCOUNT, and returns the new length. Used on cache hits, where responses are
/// stored without OPT and get one built for each client.
pub fn append_opt(buf: &mut [u8], len: usize, edns: &EdnsOut<'_>) -> Result<usize, BufferTooSmall> {
    let arcount = be16(buf, 10).ok_or(BufferTooSmall)?;
    let mut w = Writer { buf, pos: len };
    write_opt(&mut w, edns, 0)?;
    let end = w.pos();
    w.patch_u16(10, arcount.saturating_add(1))?;
    Ok(end)
}

/// EDNS for our response to `q`: present only if the client used EDNS (RFC 6891 §7),
/// echoing the DO bit.
pub fn response_edns<'t>(
    q: &Query<'_>,
    our_payload: u16,
    ede: Option<(u16, &'t str)>,
) -> Option<EdnsOut<'t>> {
    q.edns.map(|e| EdnsOut {
        udp_payload: our_payload,
        dnssec_ok: e.dnssec_ok,
        ede,
    })
}

/// Maximum UDP response size for a client: 512 without EDNS, else
/// min(client's size, our advertised size) but never below 512. REQ: DNS-005.
pub fn udp_limit(edns: Option<&Edns<'_>>, our_payload: u16) -> usize {
    usize::from(edns.map_or(MIN_UDP_PAYLOAD, |e| {
        e.udp_payload.min(our_payload).max(MIN_UDP_PAYLOAD)
    }))
}

/// If `len` exceeds `limit`, truncates the response in place to header + question (+ OPT if
/// it fits), sets TC=1, and returns the new length. Otherwise returns `len` unchanged.
/// REQ: DNS-005.
pub fn truncate_for_udp(resp: &mut [u8], len: usize, limit: usize) -> usize {
    if len <= limit || len > resp.len() {
        return len.min(resp.len());
    }
    let msg = &resp[..len];
    let Ok(mut iter) = records(msg) else {
        return header_only_tc(resp);
    };
    // Position after the question = where the first record starts.
    let question_end = iter
        .clone()
        .next()
        .and_then(Result::ok)
        .map_or(len, |r| r.name_off);
    let opt = iter.find_map(|r| r.ok().filter(crate::record::Record::is_opt));
    let mut new_len = question_end;
    let mut arcount = 0u16;
    if let Some(r) = opt {
        let start = r.name_off;
        let end = r.rdata_off + usize::from(r.rdlen);
        let opt_len = end - start;
        if question_end + opt_len <= limit {
            resp.copy_within(start..end, question_end);
            new_len += opt_len;
            arcount = 1;
        }
    }
    if new_len > limit {
        return header_only_tc(resp);
    }
    let flags = crate::header::flags(resp).with(FlagBit::Tc, true);
    crate::header::set_flags(resp, flags);
    resp[6..10].fill(0); // ANCOUNT, NSCOUNT
    resp[10..12].copy_from_slice(&arcount.to_be_bytes());
    new_len
}

fn header_only_tc(resp: &mut [u8]) -> usize {
    let flags = crate::header::flags(resp).with(FlagBit::Tc, true);
    crate::header::set_flags(resp, flags);
    resp[4..12].fill(0);
    HEADER_LEN
}

/// Synthesizes an error response (FORMERR, NOTIMP, REFUSED, SERVFAIL) from a raw request
/// that may not have parsed. Echoes the question when it can be parsed; never adds OPT.
/// Returns `None` if no response should be sent (shorter than a header, or QR=1).
pub fn error_from_raw(req: &[u8], rcode: u16, out: &mut [u8]) -> Option<usize> {
    error_response(req, rcode, None, out)
}

/// BADVERS response to a query with EDNS version > 0: OPT version 0, extended RCODE 16
/// (RFC 6891 §6.1.3). REQ: DNS-005.
pub fn badvers_from_raw(req: &[u8], our_payload: u16, out: &mut [u8]) -> Option<usize> {
    error_response(
        req,
        crate::consts::rcode::BADVERS,
        Some(EdnsOut::new(our_payload)),
        out,
    )
}

fn error_response(
    req: &[u8],
    rcode: u16,
    edns: Option<EdnsOut<'_>>,
    out: &mut [u8],
) -> Option<usize> {
    let h = Header::parse(req)?;
    if h.flags.qr() {
        return None;
    }
    let mut question_len = 0;
    if h.qdcount == 1 {
        let mut name = NameBuf::default();
        if let Ok(p) = read_name_uncompressed(req, HEADER_LEN, &mut name)
            && be16(req, p).is_some()
            && be16(req, p + 2).is_some()
        {
            question_len = p + 4 - HEADER_LEN;
        }
    }
    let flags = Flags(0)
        .with(FlagBit::Qr, true)
        .with(FlagBit::Ra, true)
        .with(FlagBit::Rd, h.flags.rd())
        .with_opcode(h.flags.opcode())
        .with_rcode((rcode & 0xF) as u8);
    let mut w = Writer::new(out);
    w.bytes(
        &Header {
            id: h.id,
            flags,
            qdcount: u16::from(question_len > 0),
            arcount: u16::from(edns.is_some()),
            ..Header::default()
        }
        .to_bytes(),
    )
    .ok()?;
    w.bytes(&req[HEADER_LEN..HEADER_LEN + question_len]).ok()?;
    if let Some(e) = edns {
        write_opt(&mut w, &e, (rcode >> 4) as u8).ok()?;
    }
    Some(w.pos())
}

/// Reads the TTL at `off` (helper for tests and cache code).
pub fn ttl_at(msg: &[u8], off: usize) -> Option<u32> {
    be32(msg, off)
}
