//! `QueryEvent` and `UpstreamEvent` (OBS-001), and their ring record encoding.
//!
//! A record is `len: u16 | kind: u8 | fields | name`, little-endian. Query records carry the
//! full wire-format qname (lowercased), so long names (the interesting ones for DGA and
//! anomaly detection) are never truncated; a typical record is ~85 bytes (ADR-026).

use crate::{Proto, Status};

/// Longest wire-format name (RFC 1035 §2.3.4).
pub const MAX_NAME: usize = 255;
/// Fixed part of a query record, including the length and kind bytes.
const QUERY_HEADER: usize = 61;
/// Size of an upstream record.
const UPSTREAM_LEN: usize = 19;
/// Largest record.
pub const MAX_RECORD: usize = QUERY_HEADER + MAX_NAME;

const KIND_QUERY: u8 = 1;
const KIND_UPSTREAM: u8 = 2;

/// What decided a filtered query (FLT-013 attribution).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub list: u16,
    pub kind: RuleKind,
    /// An allow rule (the query was resolved normally because of it).
    pub allow: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RuleKind {
    Domain = 1,
    Modifier = 2,
    Regex = 3,
    /// A CNAME target in the answer was blocked (FLT-007).
    Cname = 4,
}

impl RuleKind {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Domain,
            2 => Self::Modifier,
            3 => Self::Regex,
            4 => Self::Cname,
            _ => return None,
        })
    }
    pub const fn label(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Modifier => "modifier",
            Self::Regex => "regex",
            Self::Cname => "cname",
        }
    }
}

/// One client transaction (`spec/06` §1). The qname travels next to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryEvent {
    /// Wall clock at the start of processing, in microseconds since the Unix epoch.
    pub ts_us: u64,
    /// Client address, IPv4 mapped into IPv6.
    pub client_ip: [u8; 16],
    /// Configured client index + 1; 0 = unknown device.
    pub client_ref: u32,
    /// Primary group index.
    pub group: u16,
    pub qtype: u16,
    pub qclass: u16,
    /// Response RCODE; `None` when nothing was sent.
    pub rcode: Option<u8>,
    pub status: Status,
    pub proto: Proto,
    /// The response's header flags word (QR, opcode, AA, TC, RD, RA, AD, CD, RCODE).
    pub flags: u16,
    pub rule: Option<Rule>,
    /// Upstream that answered (0 = none or unknown) and attempts made.
    pub upstream: u16,
    pub attempts: u8,
    /// Receive → send.
    pub t_total_us: u32,
    /// Time spent waiting for upstreams (0 when none were asked).
    pub t_upstream_us: u32,
    pub resp_size: u16,
    pub answers: u16,
}

/// One upstream exchange (`spec/06` §1), including prefetches and coalesced misses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpstreamEvent {
    pub ts_us: u64,
    /// Upstream ID (config order, from 1) that answered; 0 when every attempt failed.
    pub upstream: u16,
    pub latency_us: u32,
    pub ok: bool,
    pub attempts: u8,
}

/// A decoded record.
// Decoded by value on the aggregator thread only; boxing the name would allocate per event.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record {
    Query(QueryEvent, Name),
    Upstream(UpstreamEvent),
}

/// A wire-format name, inline.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Name {
    len: u8,
    bytes: [u8; MAX_NAME],
}

impl Default for Name {
    fn default() -> Self {
        Self {
            len: 0,
            bytes: [0; MAX_NAME],
        }
    }
}

impl std::fmt::Debug for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.dotted())
    }
}

impl Name {
    /// Wire format (labels with length bytes, ending in the root), or empty if unknown.
    pub fn as_wire(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Presentation form without the trailing dot (`ads.example.com`; the root is `.`).
    pub fn dotted(&self) -> String {
        dotted(self.as_wire())
    }
}

/// Presentation form of a wire name (no escaping: names are stored as received, lowercased).
pub fn dotted(wire: &[u8]) -> String {
    let mut out = String::new();
    let mut pos = 0;
    while let Some(&len) = wire.get(pos) {
        let len = usize::from(len);
        if len == 0 {
            break;
        }
        let Some(label) = wire.get(pos + 1..pos + 1 + len) else {
            break;
        };
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(label));
        pos += 1 + len;
    }
    if out.is_empty() && !wire.is_empty() {
        out.push('.');
    }
    out
}

/// Length of the valid wire name at the start of `src` (including the root byte), or 0.
fn name_len(src: &[u8]) -> usize {
    let mut pos = 0;
    loop {
        let Some(&len) = src.get(pos) else {
            return 0;
        };
        let len = usize::from(len);
        if len == 0 {
            return pos + 1;
        }
        // Compression pointers can't appear in a question we accepted; anything else is junk.
        if len > 63 || pos + 1 + len + 1 > MAX_NAME {
            return 0;
        }
        pos += 1 + len;
    }
}

/// The question's qname and qclass in a raw DNS message (empty name if malformed).
pub fn question(msg: &[u8]) -> (&[u8], u16) {
    let Some(q) = msg.get(12..) else {
        return (&[], 0);
    };
    let n = name_len(q);
    let class = q
        .get(n + 2..n + 4)
        .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]));
    (&q[..n], if n == 0 { 0 } else { class })
}

/// Encodes a query record into `buf`, lowercasing `name`. Returns the record length.
pub fn encode_query(ev: &QueryEvent, name: &[u8], buf: &mut [u8; MAX_RECORD]) -> usize {
    let n = name_len(name);
    let len = QUERY_HEADER + n;
    let mut w = Writer { buf, pos: 0 };
    w.u16(u16::try_from(len).unwrap_or(u16::MAX));
    w.u8(KIND_QUERY);
    w.u64(ev.ts_us);
    w.bytes(&ev.client_ip);
    w.u32(ev.client_ref);
    w.u16(ev.group);
    w.u16(ev.qtype);
    w.u16(ev.qclass);
    w.u8(ev.rcode.unwrap_or(u8::MAX));
    w.u8(ev.status as u8);
    w.u8(ev.proto as u8);
    w.u16(ev.flags);
    let (list, kind) = ev.rule.map_or((0, 0), |r| {
        (r.list, r.kind as u8 | if r.allow { 0x80 } else { 0 })
    });
    w.u16(list);
    w.u8(kind);
    w.u16(ev.upstream);
    w.u8(ev.attempts);
    w.u32(ev.t_total_us);
    w.u32(ev.t_upstream_us);
    w.u16(ev.resp_size);
    w.u16(ev.answers);
    w.u8(u8::try_from(n).unwrap_or(0));
    debug_assert_eq!(w.pos, QUERY_HEADER);
    for (d, s) in w.buf[QUERY_HEADER..len].iter_mut().zip(&name[..n]) {
        *d = s.to_ascii_lowercase();
    }
    len
}

/// Encodes an upstream record into `buf`. Returns the record length.
pub fn encode_upstream(ev: &UpstreamEvent, buf: &mut [u8; MAX_RECORD]) -> usize {
    let mut w = Writer { buf, pos: 0 };
    w.u16(u16::try_from(UPSTREAM_LEN).unwrap_or(0));
    w.u8(KIND_UPSTREAM);
    w.u64(ev.ts_us);
    w.u16(ev.upstream);
    w.u32(ev.latency_us);
    w.u8(u8::from(ev.ok));
    w.u8(ev.attempts);
    debug_assert_eq!(w.pos, UPSTREAM_LEN);
    UPSTREAM_LEN
}

/// Length of the record at the start of `buf`, if its length prefix is complete and sane.
pub(crate) fn record_len(buf: &[u8]) -> Option<usize> {
    let len = usize::from(u16::from_le_bytes([*buf.first()?, *buf.get(1)?]));
    (3..=MAX_RECORD).contains(&len).then_some(len)
}

/// Decodes one complete record (`buf` is exactly one record).
pub(crate) fn decode(buf: &[u8]) -> Option<Record> {
    let mut r = Reader { buf, pos: 2 };
    match r.u8()? {
        KIND_QUERY => {
            let ts_us = r.u64()?;
            let client_ip: [u8; 16] = r.bytes(16)?.try_into().ok()?;
            let client_ref = r.u32()?;
            let group = r.u16()?;
            let qtype = r.u16()?;
            let qclass = r.u16()?;
            let rcode = r.u8()?;
            let status = Status::from_u8(r.u8()?)?;
            let proto = Proto::from_u8(r.u8()?)?;
            let flags = r.u16()?;
            let list = r.u16()?;
            let kind = r.u8()?;
            let rule = RuleKind::from_u8(kind & 0x7F).map(|k| Rule {
                list,
                kind: k,
                allow: kind & 0x80 != 0,
            });
            let upstream = r.u16()?;
            let attempts = r.u8()?;
            let t_total_us = r.u32()?;
            let t_upstream_us = r.u32()?;
            let resp_size = r.u16()?;
            let answers = r.u16()?;
            let n = usize::from(r.u8()?);
            let wire = r.bytes(n)?;
            let mut name = Name::default();
            name.bytes[..n].copy_from_slice(wire);
            name.len = u8::try_from(n).ok()?;
            Some(Record::Query(
                QueryEvent {
                    ts_us,
                    client_ip,
                    client_ref,
                    group,
                    qtype,
                    qclass,
                    rcode: (rcode != u8::MAX).then_some(rcode),
                    status,
                    proto,
                    flags,
                    rule,
                    upstream,
                    attempts,
                    t_total_us,
                    t_upstream_us,
                    resp_size,
                    answers,
                },
                name,
            ))
        }
        KIND_UPSTREAM => Some(Record::Upstream(UpstreamEvent {
            ts_us: r.u64()?,
            upstream: r.u16()?,
            latency_us: r.u32()?,
            ok: r.u8()? != 0,
            attempts: r.u8()?,
        })),
        _ => None,
    }
}

struct Writer<'a> {
    buf: &'a mut [u8; MAX_RECORD],
    pos: usize,
}

impl Writer<'_> {
    fn bytes(&mut self, b: &[u8]) {
        self.buf[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
    }
    fn u8(&mut self, v: u8) {
        self.bytes(&[v]);
    }
    fn u16(&mut self, v: u16) {
        self.bytes(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.bytes(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.bytes(&v.to_le_bytes());
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let b = self.buf.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(b)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.bytes(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.bytes(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.bytes(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.bytes(8)?.try_into().ok()?))
    }
}
