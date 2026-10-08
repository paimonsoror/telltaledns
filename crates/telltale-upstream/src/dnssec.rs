//! DNSSEC validation of forwarded answers (REQ: DNS-011; `spec/03` §5, T6.1, ADR-060).
//!
//! The chain of trust is checked with `hickory-net`'s validating handle (the `Validator` of
//! `spec/03` §5), over a [`DnsHandle`] that sends through one of our upstream groups: the
//! question itself, and every DNSKEY and DS lookup the proof needs, go to the same upstreams
//! with DO=1 and CD=1 (we check; the upstream mustn't drop what it thinks is bogus).
//! Validated results are cached by the handle, per group, for their TTLs.
//!
//! The verdict is the weakest proof among the answer records (or, for NXDOMAIN and NODATA,
//! the authority records that prove the denial):
//! - **secure** gets AD (for clients that asked);
//! - **insecure** is served without AD;
//! - **bogus** becomes SERVFAIL with EDE 6 (or is served, in permissive mode).
//!
//! Validation runs only on cache misses: the validated answer goes into the cache with its AD
//! bit, so hits cost nothing extra.
//!
//! (T9.16) Secure negative answers also teach the per-group NSEC cache (RFC 8198,
//! [`crate::nsec`]): a later miss inside a proven range is answered from it, signed, without
//! asking upstream.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures_util::StreamExt as _;
use futures_util::stream::{self, Stream};
use hickory_net::dnssec::DnssecDnsHandle;
use hickory_net::proto::dnssec::rdata::DNSSECRData;
use hickory_net::proto::dnssec::{Proof, TrustAnchors};
use hickory_net::proto::op::{
    DnsRequest, DnsRequestOptions, DnsResponse, Edns, Message, OpCode, Query, ResponseCode,
};
use hickory_net::proto::rr::{Name, RData, Record, RecordType, RecordTypeSet};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::{DnsHandle, NetError};
use parking_lot::Mutex;
use telltale_proto::NameBuf;

use crate::group::{Answer, Group, ResolveError};
use crate::upstream::Question;

/// What validation concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Secure,
    Insecure,
    Bogus,
    /// Couldn't decide (e.g. a DNSKEY lookup failed): served without AD.
    Indeterminate,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Secure => "secure",
            Self::Insecure => "insecure",
            Self::Bogus => "bogus",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// Validation counters, by verdict (for `/metrics`).
#[derive(Debug, Default)]
pub struct Stats {
    pub secure: AtomicU64,
    pub insecure: AtomicU64,
    pub bogus: AtomicU64,
    pub indeterminate: AtomicU64,
    /// REQ: DNS-011 (T9.16) — negative answers made from cached NSEC ranges (RFC 8198).
    pub synthesized: AtomicU64,
}

impl Stats {
    fn count(&self, v: Verdict) {
        match v {
            Verdict::Secure => &self.secure,
            Verdict::Insecure => &self.insecure,
            Verdict::Bogus => &self.bogus,
            Verdict::Indeterminate => &self.indeterminate,
        }
        .fetch_add(1, Ordering::Relaxed);
    }
}

/// A validated answer: the response to cache and serve, its verdict, and who answered.
#[derive(Debug)]
pub struct Validated {
    pub bytes: Vec<u8>,
    pub verdict: Verdict,
    /// REQ: DNS-013 (T9.8) — for a bogus answer, the EDE code saying why: 7 (a signature
    /// expired), 8 (not yet valid), 10 (no signatures), else 6.
    pub ede: u16,
    pub upstream_id: u16,
    pub attempts: u8,
}

/// Sends a hickory request through one of our upstream groups.
#[derive(Clone)]
struct GroupHandle {
    group: Arc<Group>,
    budget: Duration,
    /// The last upstream that answered (for telemetry).
    last: Arc<Mutex<(u16, u8)>>,
}

impl DnsHandle for GroupHandle {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let (group, budget, last) = (Arc::clone(&self.group), self.budget, Arc::clone(&self.last));
        Box::pin(stream::once(async move {
            let q = request
                .queries
                .first()
                .ok_or_else(|| NetError::from("no question".to_owned()))?;
            let name = NameBuf::from_presentation(&q.name().to_ascii())
                .map_err(|_| NetError::from(format!("unusable name {}", q.name())))?;
            let question = Question {
                name,
                qtype: u16::from(q.query_type()),
                qclass: u16::from(q.query_class()),
                dnssec_ok: true,
                checking_disabled: true,
                client_subnet: 0,
            };
            let a = group
                .resolve(question, budget)
                .await
                .map_err(|e| NetError::from(format!("upstream: {e}")))?;
            *last.lock() = (a.upstream_id, a.attempts);
            DnsResponse::from_buffer(a.bytes).map_err(|e| NetError::from(e.to_string()))
        }))
    }
}

/// A group's validating handle, and the last upstream that answered through it.
type Checked = (DnssecDnsHandle<GroupHandle>, Arc<Mutex<(u16, u8)>>);

/// Validates forwarded answers (one per pipeline state).
pub struct Validator {
    anchors: Arc<TrustAnchors>,
    /// Negative trust anchors: lowercase suffixes, no trailing dot.
    nta: Vec<String>,
    /// One validating handle (and validation cache) per upstream group, by its address.
    handles: Mutex<HashMap<usize, Checked>>,
    /// REQ: DNS-011 (T9.16) — validated NSEC ranges per upstream group, by its address.
    nsec: Mutex<HashMap<usize, crate::nsec::Ranges>>,
    /// Use them (RFC 8198; `[dnssec] aggressive_nsec`).
    aggressive: bool,
    /// REQ: DNS-011 (T10.9, ADR-098) — zones proven unsigned (a validated denial of their DS
    /// at the parent), lowercase without the trailing dot, until when the proof is trusted.
    insecure: Mutex<HashMap<String, std::time::Instant>>,
    pub stats: Arc<Stats>,
}

impl std::fmt::Debug for Validator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Validator")
            .field("nta", &self.nta)
            .finish_non_exhaustive()
    }
}

impl Validator {
    /// `nta`: domains never validated. `stats` survive configuration reloads.
    pub fn new(nta: &[String], stats: Arc<Stats>) -> Self {
        Self {
            anchors: Arc::new(TrustAnchors::default()),
            nta: nta
                .iter()
                .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            handles: Mutex::new(HashMap::new()),
            nsec: Mutex::new(HashMap::new()),
            aggressive: true,
            insecure: Mutex::new(HashMap::new()),
            stats,
        }
    }

    /// REQ: DNS-011 (T9.16) — RFC 8198 on (the default) or off.
    #[must_use]
    pub fn with_aggressive_nsec(mut self, on: bool) -> Self {
        self.aggressive = on;
        self
    }

    /// REQ: DNS-011 (T9.8) — root trust anchors from `path` (DNSKEY records in zone-file
    /// form) instead of the built-in ones. A file that can't be read or holds no key keeps the
    /// built-in anchors (and says so).
    #[must_use]
    pub fn with_anchors_file(mut self, path: Option<&str>) -> Self {
        let Some(path) = path else {
            return self;
        };
        match TrustAnchors::from_file(std::path::Path::new(path)) {
            Ok(a) if !a.is_empty() => {
                tracing::info!(path, keys = a.len(), "DNSSEC: trust anchors from file");
                self.anchors = Arc::new(a);
            }
            Ok(_) => {
                tracing::warn!(
                    path,
                    "DNSSEC: no keys in the trust anchors file; using the built-in anchors"
                );
            }
            Err(e) => {
                tracing::warn!(path, error = %e, "DNSSEC: can't read the trust anchors file; using the built-in anchors");
            }
        }
        self
    }

    /// Root trust anchors in use (tests, metrics).
    pub fn anchor_count(&self) -> usize {
        self.anchors.len()
    }

    /// Whether `name` (presentation form) is validated: not under a negative trust anchor.
    pub fn covers(&self, name: &str) -> bool {
        let n = name.trim_end_matches('.').to_ascii_lowercase();
        !self
            .nta
            .iter()
            .any(|a| n == *a || n.ends_with(&format!(".{a}")))
    }

    fn handle(
        &self,
        group: &Arc<Group>,
        budget: Duration,
    ) -> (DnssecDnsHandle<GroupHandle>, Arc<Mutex<(u16, u8)>>) {
        let key = Arc::as_ptr(group) as usize;
        let mut h = self.handles.lock();
        if h.len() > 64 {
            h.clear(); // groups of past configurations
        }
        h.entry(key)
            .or_insert_with(|| {
                let last = Arc::new(Mutex::new((0, 0)));
                let inner = GroupHandle {
                    group: Arc::clone(group),
                    budget,
                    last: Arc::clone(&last),
                };
                (
                    DnssecDnsHandle::with_trust_anchor(inner, Arc::clone(&self.anchors)),
                    last,
                )
            })
            .clone()
    }

    /// Resolves `q` through `group` and validates it. `client_do`/`client_ad`: what the
    /// client asked for (DNSSEC records kept, AD reported).
    pub async fn resolve(
        &self,
        group: &Arc<Group>,
        q: Question,
        budget: Duration,
        client_do: bool,
        client_ad: bool,
    ) -> Result<Validated, ResolveError> {
        let (handle, last) = self.handle(group, budget);
        // Fully qualified: the validator compares the question with the records' owner names.
        let mut text = q.name.display().to_string();
        if !text.ends_with('.') {
            text.push('.');
        }
        let name = Name::from_ascii(&text).map_err(|_| ResolveError::Empty)?;
        let group_key = Arc::as_ptr(group) as usize;
        if let Some(v) = self.nsec_answer(group_key, &name, &q, client_do, client_ad) {
            return Ok(v);
        }
        // REQ: DNS-011 (T10.9) — a name in a zone already proven unsigned isn't validated again
        // (hickory can loop on some of them); the pipeline fetches it unvalidated.
        let qkey = zone_key(&name);
        if self.known_insecure(&qkey) {
            self.stats.count(Verdict::Insecure);
            return Ok(insecure_unfetched());
        }
        let mut query = Query::query(name, RecordType::from(q.qtype));
        query.set_query_class(q.qclass.into());
        let mut opts = DnsRequestOptions::default();
        opts.use_edns = true;
        let request = DnsRequest::from_query(query, opts);
        let mut stream = handle.send(request);
        // A cold chain (root, TLD, zone keys) takes several sequential lookups: allow more than
        // one query budget. If the client gives up first, the result still lands in the cache.
        let result = tokio::time::timeout(budget * 3, stream.next()).await;
        let (upstream_id, attempts) = *last.lock();
        let response = match result {
            Ok(Some(Ok(r))) => r,
            // An upstream failure is an upstream failure (stale or SERVFAIL as usual).
            Ok(Some(Err(e))) if is_transport(&e) => return Err(ResolveError::Empty),
            Ok(Some(Err(e))) => {
                let mut verdict = error_verdict(&e);
                tracing::debug!(name = %q.name.display().to_string(), ?verdict, "DNSSEC: {e}");
                if self.proven_insecure(group, &handle, &qkey, budget).await {
                    verdict = Verdict::Insecure;
                }
                self.stats.count(verdict);
                return Ok(Validated {
                    bytes: Vec::new(),
                    verdict,
                    ede: telltale_proto::ede::DNSSEC_BOGUS,
                    upstream_id,
                    attempts,
                });
            }
            // Validation took too long (hickory can loop): unsigned after all?
            Err(_) if self.proven_insecure(group, &handle, &qkey, budget).await => {
                self.stats.count(Verdict::Insecure);
                return Ok(insecure_unfetched());
            }
            Ok(None) | Err(_) => return Err(ResolveError::Empty),
        };
        let mut verdict = verdict(&response);
        if verdict == Verdict::Bogus
            && self
                .all_unsigned(group, &handle, &response, &qkey, budget)
                .await
        {
            tracing::debug!(name = %qkey, "DNSSEC: bogus verdict corrected: the zone is unsigned");
            verdict = Verdict::Insecure;
        }
        self.stats.count(verdict);
        let mut message = response.into_message();
        // REQ: DNS-011 (T9.16) — a secure denial's NSEC ranges, for later questions.
        if self.aggressive && verdict == Verdict::Secure {
            let mut all = self.nsec.lock();
            if all.len() > 64 {
                all.clear(); // groups of past configurations
            }
            all.entry(group_key)
                .or_default()
                .learn(&message, std::time::Instant::now());
        }
        // Before DNSSEC records are stripped: why a bogus answer failed.
        let ede = if verdict == Verdict::Bogus {
            message
                .to_vec()
                .map_or(telltale_proto::ede::DNSSEC_BOGUS, |b| {
                    bogus_reason(&b, unix_now_u32())
                })
        } else {
            0
        };
        if !client_do {
            strip_dnssec(&mut message, q.qtype);
        }
        message.metadata.authentic_data = verdict == Verdict::Secure && (client_do || client_ad);
        message.metadata.checking_disabled = false;
        let bytes = message.to_vec().map_err(|_| ResolveError::Empty)?;
        Ok(Validated {
            bytes,
            verdict,
            ede,
            upstream_id,
            attempts,
        })
    }
}

fn unix_now_u32() -> u32 {
    let s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // RRSIG times are 32-bit serial numbers (RFC 4034 §3.1.5): the low 32 bits.
    #[allow(clippy::cast_possible_truncation)]
    let t = s as u32;
    t
}

/// REQ: DNS-013 (T9.8) — RFC 8914's code for why a bogus response failed, from its RRSIGs:
/// none for the records that answer (10), all expired (7), all not yet valid (8), else 6.
/// Times compare as serial numbers (RFC 1982), so they work across the 2106 wrap.
pub fn bogus_reason(msg: &[u8], now: u32) -> u16 {
    use telltale_proto::{Section, ede, records, rtype};
    let Ok(it) = records(msg) else {
        return ede::DNSSEC_BOGUS;
    };
    let all: Vec<_> = it.flatten().collect();
    let has_answer = all.iter().any(|r| r.section == Section::Answer);
    let section = if has_answer {
        Section::Answer
    } else {
        Section::Authority
    };
    let sigs: Vec<(u32, u32)> = all
        .iter()
        .filter(|r| r.section == section && r.rtype == rtype::RRSIG && r.rdlen >= 16)
        .map(|r| {
            let d = r.rdata(msg);
            let expiration = u32::from_be_bytes([d[8], d[9], d[10], d[11]]);
            let inception = u32::from_be_bytes([d[12], d[13], d[14], d[15]]);
            (expiration, inception)
        })
        .collect();
    // `a` is before `b` in serial-number order.
    let before = |a: u32, b: u32| a != b && b.wrapping_sub(a) < 0x8000_0000;
    if sigs.is_empty() {
        ede::RRSIGS_MISSING
    } else if sigs.iter().all(|&(exp, _)| before(exp, now)) {
        ede::SIGNATURE_EXPIRED
    } else if sigs.iter().all(|&(_, inc)| before(now, inc)) {
        ede::SIGNATURE_NOT_YET_VALID
    } else {
        ede::DNSSEC_BOGUS
    }
}

/// How many zone levels the unsigned-zone check looks at below the top-level domain.
const MAX_ZONE_LEVELS: usize = 6;
/// How long a proof that a zone is unsigned is trusted.
const INSECURE_FOR: Duration = Duration::from_mins(15);
/// Zones remembered as unsigned (the map is cleared beyond this).
const MAX_INSECURE_ZONES: usize = 4096;

/// `name` lowercase, without the trailing dot.
fn zone_key(name: &Name) -> String {
    name.to_ascii().trim_end_matches('.').to_ascii_lowercase()
}

/// The ancestors of `name` with at least two labels, shortest first, ending with `name`.
fn zone_candidates(name: &str) -> Vec<String> {
    let labels: Vec<&str> = name.split('.').filter(|l| !l.is_empty()).collect();
    (2..=labels.len())
        .map(|n| labels[labels.len() - n..].join("."))
        .collect()
}

/// A verdict without bytes: the caller fetches the answer unvalidated.
fn insecure_unfetched() -> Validated {
    Validated {
        bytes: Vec::new(),
        verdict: Verdict::Insecure,
        ede: 0,
        upstream_id: 0,
        attempts: 0,
    }
}

impl Validator {
    /// REQ: DNS-011 (T9.16) — a denial the cached NSEC ranges already prove (RFC 8198).
    fn nsec_answer(
        &self,
        group_key: usize,
        name: &Name,
        q: &Question,
        client_do: bool,
        client_ad: bool,
    ) -> Option<Validated> {
        if !self.aggressive || q.qclass != 1 {
            return None;
        }
        let synth = self.nsec.lock().get(&group_key).and_then(|r| {
            r.synthesize(name, RecordType::from(q.qtype), std::time::Instant::now())
        })?;
        let bytes = synthesized(name, q.qtype, synth, client_do, client_ad)?;
        self.stats.synthesized.fetch_add(1, Ordering::Relaxed);
        Some(Validated {
            bytes,
            verdict: Verdict::Secure,
            ede: 0,
            upstream_id: 0,
            attempts: 0,
        })
    }

    /// REQ: DNS-011 (T10.9, ADR-098) — hickory judges some answers in unsigned zones bogus
    /// (CNAME chains such as www.netflix.com): whether every owner in the answer, and the
    /// question, is in a zone proven unsigned.
    async fn all_unsigned(
        &self,
        group: &Arc<Group>,
        handle: &DnssecDnsHandle<GroupHandle>,
        response: &Message,
        qkey: &str,
        budget: Duration,
    ) -> bool {
        let mut owners: Vec<String> = response
            .answers
            .iter()
            .filter(|r| r.record_type() != RecordType::RRSIG)
            .map(|r| zone_key(&r.name))
            .collect();
        owners.push(qkey.to_owned());
        owners.sort();
        owners.dedup();
        for o in &owners {
            if !self.proven_insecure(group, handle, o, budget).await {
                return false;
            }
        }
        true
    }

    /// REQ: DNS-011 (T10.9) — `name` is in a zone already proven unsigned.
    fn known_insecure(&self, name: &str) -> bool {
        let now = std::time::Instant::now();
        let zones = self.insecure.lock();
        zone_candidates(name)
            .iter()
            .any(|z| zones.get(z).is_some_and(|until| *until > now))
    }

    /// REQ: DNS-011 (T10.9, ADR-098) — whether `name` is in an unsigned zone, proven the way a
    /// resolver proves it: walking down from the top, the first zone apex whose DS the parent
    /// validly denies (secure NSEC, or NSEC3 opt-out, which validates as insecure) is unsigned,
    /// and so is everything below it. Whether a name is an apex (it has its own SOA) comes from
    /// an ordinary query; that's safe because the DS denial is what's trusted, and a signed
    /// zone's DS can't be denied validly. Anything that can't be proven: `false`.
    async fn proven_insecure(
        &self,
        group: &Arc<Group>,
        handle: &DnssecDnsHandle<GroupHandle>,
        name: &str,
        budget: Duration,
    ) -> bool {
        if self.known_insecure(name) {
            return true;
        }
        let plain = GroupHandle {
            group: Arc::clone(group),
            budget,
            last: Arc::new(Mutex::new((0, 0))),
        };
        for zone in zone_candidates(name).into_iter().take(MAX_ZONE_LEVELS) {
            let Ok(apex) = Name::from_ascii(format!("{zone}.")) else {
                return false;
            };
            if !is_apex(&plain, &apex, budget).await {
                tracing::debug!(%zone, "DNSSEC: unsigned-zone proof: not an apex");
                continue;
            }
            let ds = ds_signed(handle, &apex, budget).await;
            tracing::debug!(%zone, ?ds, "DNSSEC: unsigned-zone proof: DS");
            match ds {
                Some(true) => {}
                Some(false) => {
                    let mut zones = self.insecure.lock();
                    if zones.len() >= MAX_INSECURE_ZONES {
                        zones.clear();
                    }
                    zones.insert(zone, std::time::Instant::now() + INSECURE_FOR);
                    return true;
                }
                None => return false,
            }
        }
        false
    }
}

fn request(name: &Name, rtype: RecordType) -> DnsRequest {
    let mut opts = DnsRequestOptions::default();
    opts.use_edns = true;
    DnsRequest::from_query(Query::query(name.clone(), rtype), opts)
}

/// `apex` has its own SOA (an unvalidated query).
async fn is_apex(plain: &GroupHandle, apex: &Name, budget: Duration) -> bool {
    let mut s = plain.send(request(apex, RecordType::SOA));
    match tokio::time::timeout(budget, s.next()).await {
        Ok(Some(Ok(r))) => {
            tracing::debug!(%apex, answers = ?r.answers.iter().map(|a| (a.name.to_ascii(), a.record_type())).collect::<Vec<_>>(), rcode = ?r.metadata.response_code, "DNSSEC: unsigned-zone proof: SOA response");
            r.answers
                .iter()
                .any(|a| a.record_type() == RecordType::SOA && a.name == *apex)
        }
        other => {
            tracing::debug!(%apex, ?other, "DNSSEC: unsigned-zone proof: no SOA answer");
            false
        }
    }
}

/// The validated DS answer for `apex`: `Some(true)` signed, `Some(false)` validly denied
/// (unsigned), `None` unknown.
async fn ds_signed(
    handle: &DnssecDnsHandle<GroupHandle>,
    apex: &Name,
    budget: Duration,
) -> Option<bool> {
    let mut s = handle.send(request(apex, RecordType::DS));
    let r = match tokio::time::timeout(budget, s.next()).await {
        Ok(Some(Ok(r))) => r,
        // hickory returns a negative answer whose proof isn't secure as an error carrying
        // the proof: for a DS, `Insecure` is NSEC3 opt-out (an unsigned delegation; a signed
        // one needs its own NSEC3 record, so an opt-out span can't cover it).
        Ok(Some(Err(NetError::Dns(hickory_net::DnsError::Nsec {
            proof, response, ..
        })))) => {
            let has_ds = response
                .answers
                .iter()
                .any(|a| a.record_type() == RecordType::DS);
            tracing::debug!(%apex, ?proof, has_ds, "DNSSEC: unsigned-zone proof: DS denial");
            return (!has_ds && matches!(proof, Proof::Secure | Proof::Insecure)).then_some(false);
        }
        other => {
            tracing::debug!(%apex, ?other, "DNSSEC: unsigned-zone proof: no DS answer");
            return None;
        }
    };
    tracing::debug!(%apex, verdict = ?verdict(&r), answers = r.answers.len(), "DNSSEC: unsigned-zone proof: DS response");
    let has_ds = r.answers.iter().any(|a| a.record_type() == RecordType::DS);
    let other = r
        .answers
        .iter()
        .any(|a| !matches!(a.record_type(), RecordType::DS | RecordType::RRSIG));
    // REQ: DNS-011 (ADR-098) — a secure denial of DS proves an unsigned delegation only when
    // the record that denies it also shows a zone cut: NS present, SOA and DS absent (RFC 4035
    // §5.2, RFC 5155 §8.9; what hickory's own insecure-delegation check asks for). Every name
    // inside a signed zone has a secure DS denial too, and whether `apex` has an SOA came from
    // an unvalidated answer, so the denial alone let a spoofed answer pass as insecure.
    let cut = r
        .authorities
        .iter()
        .any(|a| a.proof == Proof::Secure && denies_ds_at_cut(a, apex));
    match (has_ds, other, verdict(&r)) {
        (true, _, Verdict::Secure) => Some(true),
        (false, false, Verdict::Secure) if cut => Some(false),
        (false, false, Verdict::Insecure) => Some(false),
        _ => None,
    }
}

/// REQ: DNS-011 (ADR-098) — `rec` is an NSEC or NSEC3 that denies a DS at `apex` and shows it
/// as a zone cut (NS, no SOA, no DS). An NSEC3 is matched by hashing `apex` the way its owner
/// was hashed.
fn denies_ds_at_cut(rec: &Record, apex: &Name) -> bool {
    let cut = |types: &RecordTypeSet| {
        types.contains(RecordType::NS)
            && !types.contains(RecordType::SOA)
            && !types.contains(RecordType::DS)
    };
    match &rec.data {
        RData::DNSSEC(DNSSECRData::NSEC(n)) => rec.name == *apex && cut(n.type_set()),
        RData::DNSSEC(DNSSECRData::NSEC3(n)) => {
            cut(n.type_set())
                && n.hash_algorithm()
                    .hash(n.salt(), apex, n.iterations())
                    .is_ok_and(|h| {
                        rec.name.iter().next().is_some_and(|label| {
                            label.eq_ignore_ascii_case(base32hex(h.as_ref()).as_bytes())
                        })
                    })
        }
        _ => false,
    }
}

/// Base32 with the extended hex alphabet, no padding (RFC 4648 §7): NSEC3 owner labels.
fn base32hex(data: &[u8]) -> String {
    const T: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    for chunk in data.chunks(5) {
        let mut block = [0u8; 8];
        block[3..3 + chunk.len()].copy_from_slice(chunk);
        let v = u64::from_be_bytes(block);
        for i in 0..(chunk.len() * 8).div_ceil(5) {
            let idx = usize::try_from((v >> (35 - 5 * i)) & 31).unwrap_or(0);
            out.push(char::from(T[idx]));
        }
    }
    out
}

/// REQ: DNS-011 (ADR-098) — what a validation error says about the answer. Hitting the
/// validator's depth limit (hickory's default 26; raising it overflowed a runtime thread's
/// stack in testing) means the proof couldn't be finished, not that a signature failed:
/// indeterminate, served without AD in both modes. Seen with `prod.ftl.netflix.com`, where
/// hickory 0.26 repeats NS and DS lookups for the same name until the limit. Anything else
/// is bogus.
pub(crate) fn error_verdict(e: &NetError) -> Verdict {
    match e {
        NetError::Message(m) if m.contains("max validation depth") => Verdict::Indeterminate,
        _ => Verdict::Bogus,
    }
}

fn is_transport(e: &NetError) -> bool {
    let s = e.to_string();
    s.starts_with("upstream:") || matches!(e, NetError::Timeout)
}

/// The weakest proof among the records that answer the question.
fn verdict(m: &Message) -> Verdict {
    let records: Vec<_> = if m.answers.is_empty() {
        m.authorities.iter().collect()
    } else {
        m.answers.iter().collect()
    };
    if records.is_empty() {
        // An empty NOERROR/NXDOMAIN with nothing to prove anything: can't be secure.
        return if m.metadata.response_code == ResponseCode::ServFail {
            Verdict::Indeterminate
        } else {
            Verdict::Insecure
        };
    }
    let mut worst = Verdict::Secure;
    for r in records {
        let v = match r.proof {
            Proof::Secure => Verdict::Secure,
            Proof::Insecure => Verdict::Insecure,
            Proof::Bogus => Verdict::Bogus,
            Proof::Indeterminate => Verdict::Indeterminate,
        };
        worst = match (worst, v) {
            (Verdict::Bogus, _) | (_, Verdict::Bogus) => Verdict::Bogus,
            (Verdict::Indeterminate, _) | (_, Verdict::Indeterminate) => Verdict::Indeterminate,
            (Verdict::Insecure, _) | (_, Verdict::Insecure) => Verdict::Insecure,
            _ => Verdict::Secure,
        };
    }
    worst
}

/// REQ: DNS-011 (T9.16) — the response for a denial proven by cached ranges: NXDOMAIN or
/// NODATA, the SOA and NSEC records (with signatures for DO clients), AD as for any secure
/// answer.
fn synthesized(
    name: &Name,
    qtype: u16,
    s: crate::nsec::Synth,
    client_do: bool,
    client_ad: bool,
) -> Option<Vec<u8>> {
    let mut m = Message::response(0, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.metadata.recursion_available = true;
    m.metadata.response_code = match s.denial {
        crate::nsec::Denial::NxDomain => ResponseCode::NXDomain,
        crate::nsec::Denial::NoData => ResponseCode::NoError,
    };
    m.add_query(Query::query(name.clone(), RecordType::from(qtype)));
    m.add_authorities(s.authorities);
    if !client_do {
        strip_dnssec(&mut m, qtype);
    }
    m.metadata.authentic_data = client_do || client_ad;
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    edns.set_dnssec_ok(client_do);
    m.set_edns(edns);
    m.to_vec().ok()
}

/// Removes RRSIG, NSEC, and NSEC3 records a client didn't ask for (it sent no DO bit).
fn strip_dnssec(m: &mut Message, qtype: u16) {
    let dnssec = |t: RecordType| {
        matches!(t, RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3)
            && u16::from(t) != qtype
    };
    m.answers.retain(|r| !dnssec(r.record_type()));
    m.authorities.retain(|r| !dnssec(r.record_type()));
    m.additionals.retain(|r| !dnssec(r.record_type()));
}

/// The answer an upstream group gave, before validation existed (for callers that need the
/// unvalidated path's shape).
pub fn unvalidated(a: Answer) -> Validated {
    Validated {
        bytes: a.bytes,
        verdict: Verdict::Indeterminate,
        ede: 0,
        upstream_id: a.upstream_id,
        attempts: a.attempts,
    }
}

#[cfg(test)]
mod depth_tests {
    use super::*;

    /// REQ: DNS-011 (T10.9) — the zones an unsigned-zone proof walks, top down.
    #[test]
    fn dns_011_zone_candidates() {
        assert_eq!(
            zone_candidates("www.netflix.com"),
            vec!["netflix.com".to_owned(), "www.netflix.com".to_owned()]
        );
        assert_eq!(zone_candidates("com"), Vec::<String>::new());
        assert_eq!(zone_candidates("a.b.c.d"), vec!["c.d", "b.c.d", "a.b.c.d"]);
    }

    /// REQ: DNS-011 (ADR-098) — base32hex (RFC 4648 §10 vectors, lowercase, unpadded).
    #[test]
    fn dns_011_base32hex() {
        assert_eq!(base32hex(b""), "");
        assert_eq!(base32hex(b"f"), "co");
        assert_eq!(base32hex(b"fo"), "cpng");
        assert_eq!(base32hex(b"foo"), "cpnmu");
        assert_eq!(base32hex(b"foob"), "cpnmuog");
        assert_eq!(base32hex(b"fooba"), "cpnmuoj1");
        assert_eq!(base32hex(b"foobar"), "cpnmuoj1e8");
    }

    /// REQ: DNS-011 (ADR-098) — only a delegation's NSEC or NSEC3 (NS without SOA or DS)
    /// proves a zone unsigned: not the NSEC of an ordinary name inside a signed zone, nor
    /// another name's.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn dns_011_ds_denial_must_show_a_cut() {
        use RecordType::{A, DS, NS, NSEC as T_NSEC, NSEC3 as T_NSEC3, RRSIG, SOA};
        use hickory_net::proto::dnssec::Nsec3HashAlgorithm;
        use hickory_net::proto::dnssec::rdata::{NSEC, NSEC3};
        let apex = Name::from_ascii("child.example.").unwrap();
        let nsec = |owner: &str, types: &[RecordType]| {
            let next = Name::from_ascii("z.example.").unwrap();
            let data = RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(next, types.iter().copied())));
            let mut r = Record::from_rdata(Name::from_ascii(owner).unwrap(), 300, data);
            r.proof = Proof::Secure;
            r
        };
        assert!(denies_ds_at_cut(
            &nsec("child.example.", &[NS, RRSIG, T_NSEC]),
            &apex
        ));
        assert!(
            !denies_ds_at_cut(&nsec("child.example.", &[A, RRSIG, T_NSEC]), &apex),
            "a name inside the zone, not a cut"
        );
        assert!(
            !denies_ds_at_cut(&nsec("child.example.", &[NS, SOA, T_NSEC]), &apex),
            "the child's own NSEC"
        );
        assert!(
            !denies_ds_at_cut(&nsec("child.example.", &[NS, DS, T_NSEC]), &apex),
            "a signed delegation"
        );
        assert!(
            !denies_ds_at_cut(&nsec("other.example.", &[NS, T_NSEC]), &apex),
            "another owner"
        );
        // NSEC3: the owner is the hash of the apex.
        let salt = b"\xab\xcd";
        let hash = Nsec3HashAlgorithm::SHA1.hash(salt, &apex, 5).unwrap();
        let owner = Name::from_ascii(format!("{}.example.", base32hex(hash.as_ref()))).unwrap();
        let nsec3 = |owner: &Name, types: &[RecordType]| {
            let n = NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                5,
                salt.to_vec(),
                vec![0; 20],
                types.iter().copied(),
            );
            let mut r =
                Record::from_rdata(owner.clone(), 300, RData::DNSSEC(DNSSECRData::NSEC3(n)));
            r.proof = Proof::Secure;
            r
        };
        assert!(denies_ds_at_cut(
            &nsec3(&owner, &[NS, RRSIG, T_NSEC3]),
            &apex
        ));
        assert!(!denies_ds_at_cut(
            &nsec3(&owner, &[A, RRSIG, T_NSEC3]),
            &apex
        ));
        let wrong = Name::from_ascii("0123456789abcdefghijklmnopqrstuv.example.").unwrap();
        assert!(
            !denies_ds_at_cut(&nsec3(&wrong, &[NS, T_NSEC3]), &apex),
            "another name's hash"
        );
    }

    /// REQ: DNS-011 (ADR-098) — the depth limit is indeterminate; other errors stay bogus.
    #[test]
    fn dns_011_depth_limit_is_indeterminate() {
        assert_eq!(
            error_verdict(&NetError::from("exceeded max validation depth")),
            Verdict::Indeterminate
        );
        assert_eq!(
            error_verdict(&NetError::from("rrsig validation failed")),
            Verdict::Bogus
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: DNS-011 (T9.8) — both root KSKs are trusted: KSK-2017 (20326) and KSK-2024
    /// (38696), so the root's key rollover doesn't break validation.
    #[test]
    fn dns_011_root_trust_anchors() {
        use hickory_net::proto::dnssec::PublicKey as _;
        let anchors = TrustAnchors::default();
        let mut tags = Vec::new();
        for i in 0..anchors.len() {
            let key = anchors.get(i).unwrap();
            // DNSKEY RDATA: flags 257 (KSK), protocol 3, algorithm 8, the key.
            let mut rdata = vec![1, 1, 3, 8];
            rdata.extend_from_slice(key.public_bytes());
            // RFC 4034 Appendix B.
            let mut ac: u32 = 0;
            for (i, b) in rdata.iter().enumerate() {
                ac += if i % 2 == 0 {
                    u32::from(*b) << 8
                } else {
                    u32::from(*b)
                };
            }
            ac += (ac >> 16) & 0xFFFF;
            tags.push(ac & 0xFFFF);
        }
        tags.sort_unstable();
        assert_eq!(tags, vec![20326, 38696]);
    }

    /// REQ: DNS-011 (T9.8) — anchors from a file replace the built-in ones; a bad file
    /// doesn't.
    #[test]
    fn dns_011_trust_anchors_file() {
        use hickory_net::proto::dnssec::PublicKey as _;
        fn b64(data: &[u8]) -> String {
            const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut s = String::new();
            for c in data.chunks(3) {
                let n = (u32::from(c[0]) << 16)
                    | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                    | u32::from(*c.get(2).unwrap_or(&0));
                for i in 0..4 {
                    if i <= c.len() {
                        s.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
                    } else {
                        s.push('=');
                    }
                }
            }
            s
        }
        let ksk2024 = TrustAnchors::default()
            .get(1)
            .unwrap()
            .public_bytes()
            .to_vec();
        let dir = std::env::temp_dir().join(format!("tt-anchors-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("root.key");
        std::fs::write(
            &good,
            format!(". 172800 IN DNSKEY 257 3 8 {}\n", b64(&ksk2024)),
        )
        .unwrap();
        let stats = Arc::new(Stats::default());
        let v = Validator::new(&[], Arc::clone(&stats)).with_anchors_file(good.to_str());
        assert_eq!(v.anchor_count(), 1);
        let bad = dir.join("bad.key");
        std::fs::write(&bad, "not a zone file").unwrap();
        let v = Validator::new(&[], Arc::clone(&stats)).with_anchors_file(bad.to_str());
        assert_eq!(v.anchor_count(), 2, "the built-in anchors stay");
        let v = Validator::new(&[], stats).with_anchors_file(Some("/nonexistent/root.key"));
        assert_eq!(v.anchor_count(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// REQ: DNS-013 (T9.8) — why a bogus answer failed, from its signatures.
    #[test]
    fn dns_013_bogus_reasons() {
        // A response for example.com A: one A record and, optionally, an RRSIG with the given
        // expiration and inception.
        let msg = |sig: Option<(u32, u32)>| {
            let mut m = vec![
                0,
                1,
                0x81,
                0x80,
                0,
                1,
                0,
                if sig.is_some() { 2 } else { 1 },
                0,
                0,
                0,
                0,
            ];
            let name = [
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
            ];
            m.extend(name);
            m.extend([0, 1, 0, 1]);
            m.extend([0xC0, 12, 0, 1, 0, 1, 0, 0, 1, 0, 0, 4, 10, 0, 0, 1]);
            if let Some((exp, inc)) = sig {
                let mut rd = vec![0, 1, 8, 2, 0, 0, 1, 0];
                rd.extend(exp.to_be_bytes());
                rd.extend(inc.to_be_bytes());
                rd.extend([0x12, 0x34]);
                rd.extend(name);
                rd.extend([0xAA; 8]);
                m.extend([0xC0, 12, 0, 46, 0, 1, 0, 0, 1, 0]);
                m.extend(u16::try_from(rd.len()).unwrap().to_be_bytes());
                m.extend(rd);
            }
            m
        };
        let now = 1_791_300_000u32;
        assert_eq!(
            bogus_reason(&msg(None), now),
            telltale_proto::ede::RRSIGS_MISSING
        );
        assert_eq!(
            bogus_reason(&msg(Some((now - 10, now - 1000))), now),
            telltale_proto::ede::SIGNATURE_EXPIRED
        );
        assert_eq!(
            bogus_reason(&msg(Some((now + 1000, now + 10))), now),
            telltale_proto::ede::SIGNATURE_NOT_YET_VALID
        );
        assert_eq!(
            bogus_reason(&msg(Some((now + 1000, now - 1000))), now),
            telltale_proto::ede::DNSSEC_BOGUS
        );
        // Serial arithmetic: an expiration just past the 32-bit wrap is still in the future.
        assert_eq!(
            bogus_reason(&msg(Some((5, u32::MAX - 100))), u32::MAX - 10),
            telltale_proto::ede::DNSSEC_BOGUS
        );
        assert_eq!(
            bogus_reason(b"junk", now),
            telltale_proto::ede::DNSSEC_BOGUS
        );
    }
    use hickory_net::proto::rr::{RData, Record, rdata};

    fn rec(name: &str, data: RData, proof: Proof) -> Record {
        let mut r = Record::from_rdata(Name::from_ascii(name).unwrap(), 300, data);
        r.proof = proof;
        r
    }

    fn a(proof: Proof) -> Record {
        rec("example.com.", RData::A(rdata::A::new(192, 0, 2, 1)), proof)
    }

    // REQ: DNS-011 — the verdict is the weakest proof among the answers.
    #[test]
    fn dns_011_the_weakest_answer_decides() {
        let mut m = Message::response(1, hickory_net::proto::op::OpCode::Query);
        m.answers = vec![a(Proof::Secure), a(Proof::Secure)];
        assert_eq!(verdict(&m), Verdict::Secure);
        m.answers.push(a(Proof::Insecure));
        assert_eq!(verdict(&m), Verdict::Insecure);
        m.answers.push(a(Proof::Bogus));
        assert_eq!(verdict(&m), Verdict::Bogus);
        // Negative answers are judged by their proofs in the authority section.
        let mut n = Message::response(2, hickory_net::proto::op::OpCode::Query);
        n.authorities = vec![a(Proof::Secure)];
        assert_eq!(verdict(&n), Verdict::Secure);
        let empty = Message::response(3, hickory_net::proto::op::OpCode::Query);
        assert_eq!(
            verdict(&empty),
            Verdict::Insecure,
            "nothing to prove anything with"
        );
    }

    #[test]
    fn dns_011_negative_trust_anchors_cover_their_subtree() {
        let v = Validator::new(
            &["corp.example.".into(), "Home.Arpa".into()],
            Arc::default(),
        );
        assert!(!v.covers("corp.example"));
        assert!(!v.covers("nas.corp.example."));
        assert!(!v.covers("printer.home.arpa"));
        assert!(v.covers("notcorp.example"), "a suffix match is by label");
        assert!(v.covers("example.com"));
    }

    #[test]
    fn dns_011_dnssec_records_are_stripped_for_clients_without_do() {
        let sig = rec(
            "example.com.",
            RData::Unknown {
                code: RecordType::RRSIG,
                rdata: hickory_net::proto::rr::rdata::NULL::with(vec![0; 4]),
            },
            Proof::Secure,
        );
        let mut m = Message::response(1, hickory_net::proto::op::OpCode::Query);
        m.answers = vec![a(Proof::Secure), sig];
        strip_dnssec(&mut m, u16::from(RecordType::A));
        assert_eq!(m.answers.len(), 1);
        assert_eq!(m.answers[0].record_type(), RecordType::A);
    }
}
