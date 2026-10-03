//! Turning an upstream response into a cache entry, and writing an entry back out on a hit.
//!
//! REQ: DNS-006 — wire-format storage with TTL offsets; TTL clamps; negative caching
//! (RFC 2308); SERVFAIL caching (RFC 9520). `spec/03` §4.

use std::time::Instant;

use telltale_proto::{
    EdnsOut, FlagBit, HEADER_LEN, NameBuf, Query, append_opt, header, rcode, read_name, records,
    set_ttls, summarize,
};

use crate::CachePolicy;

/// A cached response, stored with ID 0, without OPT, TTLs already clamped.
#[derive(Debug)]
pub(crate) struct Entry {
    /// Normalized qname (wire format); compared on every hit so a hash collision is a miss.
    pub(crate) name: Box<[u8]>,
    pub(crate) wire: Box<[u8]>,
    pub(crate) ttl_offsets: Box<[u16]>,
    /// End of the question section (start of answers).
    pub(crate) question_end: u16,
    pub(crate) inserted: Instant,
    /// Seconds the entry is fresh for.
    pub(crate) ttl: u32,
    pub(crate) hits: u32,
    pub(crate) prefetch_signaled: bool,
}

impl Entry {
    /// Approximate memory cost used for the byte budget.
    pub(crate) fn weight(&self) -> usize {
        const OVERHEAD: usize = 96; // struct, map slot, queue slot
        self.name.len() + self.wire.len() + self.ttl_offsets.len() * 2 + OVERHEAD
    }

    pub(crate) fn elapsed_secs(&self, now: Instant) -> u32 {
        u32::try_from(now.saturating_duration_since(self.inserted).as_secs()).unwrap_or(u32::MAX)
    }
}

/// Why a response was not cached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Uncacheable {
    Malformed,
    /// Question section doesn't match the query (wrong name/type/class or QDCOUNT != 1).
    QuestionMismatch,
    Truncated,
    /// REFUSED, NOTIMP, FORMERR, ...
    Rcode(u16),
    /// Negative answer without an SOA (RFC 2308 §5: SHOULD NOT be cached).
    NegativeWithoutSoa,
    ZeroTtl,
    /// OPT not the last record; stripping it could break compression pointers.
    OptNotLast,
    Disabled,
}

/// Builds a cache entry for `resp`, which answered `q` (qname already normalized).
/// With `policy = None` it only validates and normalizes (for rendering an uncacheable
/// answer to the client); no TTL rules apply.
pub(crate) fn prepare(
    q: &Query<'_>,
    resp: &[u8],
    policy: Option<&CachePolicy>,
    now: Instant,
) -> Result<Entry, Uncacheable> {
    let s = summarize(resp).map_err(|_| Uncacheable::Malformed)?;
    if policy.is_some() && s.header.flags.tc() {
        return Err(Uncacheable::Truncated);
    }
    if s.header.qdcount != 1 {
        return Err(Uncacheable::QuestionMismatch);
    }
    let mut name = NameBuf::default();
    let qend = read_name(resp, HEADER_LEN, &mut name).map_err(|_| Uncacheable::Malformed)?;
    let qtype = resp
        .get(qend..qend + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]));
    let qclass = resp
        .get(qend + 2..qend + 4)
        .map(|b| u16::from_be_bytes([b[0], b[1]]));
    // The stored question must be byte-for-byte the same length as the client's so the
    // client's question can be written over it on a hit (no compression in the question).
    let question_end = qend + 4;
    if name != q.qname
        || qtype != Some(q.qtype)
        || qclass != Some(q.qclass)
        || question_end != q.question_end
    {
        return Err(Uncacheable::QuestionMismatch);
    }

    // REQ: DNS-006 — TTL policy. `None` policy = relaxed: render only, no caching rules.
    let Some(policy) = policy else {
        return finish(q, resp, &s, 0, u32::MAX, 0, question_end, now);
    };
    let negative = s.rcode == rcode::NXDOMAIN || (s.rcode == rcode::NOERROR && s.answers == 0);
    let (ttl, cap) = match s.rcode {
        rcode::SERVFAIL => (policy.servfail_ttl, policy.servfail_ttl),
        _ if negative => {
            let neg = s.negative_ttl.ok_or(Uncacheable::NegativeWithoutSoa)?;
            let t = neg.min(policy.negative_ttl_max).max(policy.min_ttl);
            (t, t)
        }
        rcode::NOERROR => {
            // max-then-min rather than clamp(): never panics even if min_ttl > max_ttl.
            let t = s
                .min_ttl
                .unwrap_or(0)
                .max(policy.min_ttl)
                .min(policy.max_ttl);
            (t, policy.max_ttl)
        }
        other => return Err(Uncacheable::Rcode(other)),
    };
    if ttl == 0 {
        return Err(Uncacheable::ZeroTtl);
    }
    finish(q, resp, &s, ttl, cap, policy.min_ttl, question_end, now)
}

/// Strips OPT, collects TTL offsets, clamps TTLs into `[min_ttl, cap]`, and builds the entry.
#[allow(clippy::too_many_arguments)]
fn finish(
    q: &Query<'_>,
    resp: &[u8],
    s: &telltale_proto::ResponseSummary,
    ttl: u32,
    cap: u32,
    min_ttl: u32,
    question_end: usize,
    now: Instant,
) -> Result<Entry, Uncacheable> {
    // Strip OPT (only if it's the last record) and collect TTL offsets.
    let mut end = resp.len();
    let mut arcount = s.header.arcount;
    let mut offsets = Vec::new();
    let mut ttls = Vec::new();
    let mut seen_opt = false;
    for r in records(resp).map_err(|_| Uncacheable::Malformed)? {
        let r = r.map_err(|_| Uncacheable::Malformed)?;
        if seen_opt {
            return Err(Uncacheable::OptNotLast);
        }
        if r.is_opt() {
            seen_opt = true;
            end = r.name_off;
            arcount -= 1;
            continue;
        }
        offsets.push(u16::try_from(r.ttl_off).map_err(|_| Uncacheable::Malformed)?);
        ttls.push(r.ttl);
    }
    let mut wire: Box<[u8]> = resp[..end].into();
    header::set_id(&mut wire, 0);
    wire[10..12].copy_from_slice(&arcount.to_be_bytes());
    // Clamp each record's TTL into [min_ttl, cap] so clients never see more than we allow.
    for (&off, &t) in offsets.iter().zip(&ttls) {
        let clamped = t.max(min_ttl).min(cap);
        set_ttls(&mut wire, &[off], clamped);
    }
    Ok(Entry {
        name: q.qname.as_wire().into(),
        wire,
        ttl_offsets: offsets.into_boxed_slice(),
        question_end: u16::try_from(question_end).map_err(|_| Uncacheable::Malformed)?,
        inserted: now,
        ttl,
        hits: 0,
        prefetch_signaled: false,
    })
}

/// Client-specific parts of a response built from the cache.
#[derive(Clone, Copy, Debug)]
pub struct Client<'a> {
    pub id: u16,
    pub rd: bool,
    /// The client's question bytes exactly as sent (0x20 case preserved).
    pub question: &'a [u8],
    /// Whether the client may see AD=1 (it set DO or AD; RFC 6840 §5.8).
    pub ad_ok: bool,
    /// OPT to append (only for EDNS clients), possibly carrying an EDE.
    pub edns: Option<EdnsOut<'a>>,
}

impl<'a> Client<'a> {
    pub fn from_query(q: &Query<'a>, edns: Option<EdnsOut<'a>>) -> Self {
        Self {
            id: q.header.id,
            rd: q.header.flags.rd(),
            question: q.question_bytes(),
            ad_ok: q.header.flags.ad() || q.edns.is_some_and(|e| e.dnssec_ok),
            edns,
        }
    }
}

/// Writes `e` for `client` into `out`. `ttl_override` sets every TTL (serve-stale); otherwise
/// TTLs count down by the entry's age. Returns `None` if `out` is too small. Allocation-free.
pub(crate) fn write(
    e: &Entry,
    client: &Client<'_>,
    now: Instant,
    ttl_override: Option<u32>,
    out: &mut [u8],
) -> Option<usize> {
    let len = e.wire.len();
    let qend = usize::from(e.question_end);
    if client.question.len() != qend - HEADER_LEN {
        return None;
    }
    out.get_mut(..len)?.copy_from_slice(&e.wire);
    header::set_id(out, client.id);
    let mut flags = header::flags(out)
        .with(FlagBit::Rd, client.rd)
        .with(FlagBit::Aa, false);
    if !client.ad_ok {
        flags = flags.with(FlagBit::Ad, false);
    }
    header::set_flags(out, flags);
    out[HEADER_LEN..qend].copy_from_slice(client.question);
    match ttl_override {
        Some(t) => set_ttls(&mut out[..len], &e.ttl_offsets, t),
        None => telltale_proto::patch_ttls(&mut out[..len], &e.ttl_offsets, e.elapsed_secs(now), 0),
    }
    match &client.edns {
        Some(edns) => append_opt(out, len, edns).ok(),
        None => Some(len),
    }
}
