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
//! An answer whose denial is about a CNAME's target, which the library checks for the name that
//! was asked, is validated link by link (`Validator::validate_links`).
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
use hickory_net::proto::dnssec::rdata::{DNSSECRData, NSEC, NSEC3};
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
    /// The weaker of the two.
    fn weakest(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bogus, _) | (_, Self::Bogus) => Self::Bogus,
            (Self::Indeterminate, _) | (_, Self::Indeterminate) => Self::Indeterminate,
            (Self::Insecure, _) | (_, Self::Insecure) => Self::Insecure,
            _ => Self::Secure,
        }
    }

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
                .map_err(upstream_failure)?;
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
    /// REQ: DNS-011 (T10.9, ADR-098, ADR-184) — zones proven unsigned (a validated denial of
    /// their DS at the parent), by upstream group (its address) and zone (lowercase, without
    /// the trailing dot), until when the proof is trusted: the smallest TTL of the records that
    /// proved it, at most `INSECURE_FOR`.
    insecure: Mutex<HashMap<(usize, String), std::time::Instant>>,
    /// REQ: DNS-011, NFR-004 (review 03-05) — bounds on the unsigned-zone proof.
    proofs: ProofGate,
    /// REQ: DNS-011, NFR-004 (ADR-188) — bounds on link-by-link validation, apart from `proofs`
    /// (which the proofs its links need take from).
    links: ProofGate,
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
            proofs: ProofGate::default(),
            links: ProofGate::with_slots(MAX_LINK_WALKS),
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

    /// Test support (`tests/`): takes every free slot of the unsigned-zone proofs but `leave`,
    /// until the permits are dropped.
    #[doc(hidden)]
    #[must_use]
    pub fn hold_proof_slots(&self, leave: usize) -> Vec<tokio::sync::SemaphorePermit<'_>> {
        self.proofs.hold(leave)
    }

    /// Test support (`tests/`): the same for the slots of link-by-link validation.
    #[doc(hidden)]
    #[must_use]
    pub fn hold_link_slots(&self, leave: usize) -> Vec<tokio::sync::SemaphorePermit<'_>> {
        self.links.hold(leave)
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
        // REQ: DNS-011, NFR-004 (review 03-05) — the whole validation (the lookup and any proof
        // that the zone is unsigned) ends within two query budgets: it holds one of the
        // pipeline's in-flight permits, and a name that can't be validated must not hold it
        // for tens of seconds.
        let deadline = std::time::Instant::now() + budget * VALIDATION_BUDGETS;
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
        if self.known_insecure(group_key, &qkey) {
            self.stats.count(Verdict::Insecure);
            return Ok(insecure_unfetched());
        }
        let mut query = Query::query(name.clone(), RecordType::from(q.qtype));
        query.set_query_class(q.qclass.into());
        let mut opts = DnsRequestOptions::default();
        opts.use_edns = true;
        let request = DnsRequest::from_query(query, opts);
        let mut stream = handle.send(request);
        // A cold chain (root, TLD, zone keys) takes several sequential lookups: allow more than
        // one query budget, but leave the rest of the deadline to the proof that rescues a
        // lookup that loops. If the client gives up first, the result still lands in the cache.
        let result =
            tokio::time::timeout(budget * LOOKUP_SHARE.0 / LOOKUP_SHARE.1, stream.next()).await;
        let (upstream_id, attempts) = *last.lock();
        let rtype = RecordType::from(q.qtype);
        let response = match result.map(|r| r.map(|r| or_wildcard(r, &name, rtype))) {
            Ok(Some(Ok(r))) => r,
            // An upstream failure is an upstream failure (stale or SERVFAIL as usual).
            Ok(Some(Err(e))) if is_transport(&e) => return Err(ResolveError::Empty),
            Ok(Some(Err(e))) => {
                let mut verdict = error_verdict(&e);
                tracing::debug!(name = %q.name.display().to_string(), ?verdict, "DNSSEC: {e}");
                if self
                    .proven_insecure(group, &handle, &qkey, budget, deadline)
                    .await
                {
                    verdict = Verdict::Insecure;
                } else if denied_through_cname(&e, &name, &q)
                    && let Some((verdict, message)) = self
                        .validate_links(group, &handle, &name, &q, budget, deadline)
                        .await
                {
                    tracing::debug!(name = %qkey, ?verdict, "DNSSEC: validated link by link");
                    self.stats.count(verdict);
                    let by = *last.lock();
                    return finish(message, verdict, &q, &name, (client_do, client_ad), by);
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
            Err(_)
                if self
                    .proven_insecure(group, &handle, &qkey, budget, deadline)
                    .await =>
            {
                self.stats.count(Verdict::Insecure);
                return Ok(insecure_unfetched());
            }
            Ok(None) | Err(_) => return Err(ResolveError::Empty),
        };
        let mut verdict = verdict(&response);
        if verdict == Verdict::Bogus
            && self
                .all_unsigned(group, &handle, &response, &qkey, budget, deadline)
                .await
        {
            tracing::debug!(name = %qkey, "DNSSEC: bogus verdict corrected: the zone is unsigned");
            verdict = Verdict::Insecure;
        }
        let mut message = response.into_message();
        // A chain from a signed zone into an unsigned one the library misjudges (as above).
        if verdict == Verdict::Bogus
            && follows_cname(&q)
            && starts_with_cname(&message, &name)
            && let Some(found) = self
                .validate_links(group, &handle, &name, &q, budget, deadline)
                .await
        {
            tracing::debug!(name = %qkey, verdict = ?found.0, "DNSSEC: validated link by link");
            (verdict, message) = found;
        }
        self.stats.count(verdict);
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
        let client = (client_do, client_ad);
        finish(message, verdict, &q, &name, client, (upstream_id, attempts))
    }
}

/// The validated answer to cache and serve, with its verdict. `client`: whether it set DO and
/// AD; `by`: the upstream that answered, and after how many attempts.
fn finish(
    mut message: Message,
    verdict: Verdict,
    q: &Question,
    name: &Name,
    client: (bool, bool),
    by: (u16, u8),
) -> Result<Validated, ResolveError> {
    let (client_do, client_ad) = client;
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
    tidy(&mut message, q.qtype, client_do, name);
    message.metadata.authentic_data = verdict == Verdict::Secure && (client_do || client_ad);
    message.metadata.checking_disabled = false;
    let bytes = message.to_vec().map_err(|_| ResolveError::Empty)?;
    Ok(Validated {
        bytes,
        verdict,
        ede,
        upstream_id: by.0,
        attempts: by.1,
    })
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

/// The most CNAMEs followed when an answer is validated link by link.
const MAX_LINKS: usize = 8;
/// How many zone levels the unsigned-zone check looks at below the top-level domain.
const MAX_ZONE_LEVELS: usize = 6;
/// How long a proof that a zone is unsigned is trusted at most (less when the TTLs of the
/// records that proved it are shorter).
const INSECURE_FOR: Duration = Duration::from_mins(15);
/// Zones remembered as unsigned (the map is cleared beyond this).
const MAX_INSECURE_ZONES: usize = 4096;

/// The whole validation (lookup and proof) may take this many query budgets.
const VALIDATION_BUDGETS: u32 = 2;
/// The share of that the lookup itself may use (3/4): a lookup that loops (hickory repeating
/// NS and DS queries) is cut off in time for the proof to rescue it.
const LOOKUP_SHARE: (u32, u32) = (3 * VALIDATION_BUDGETS, 4);
/// Unsigned-zone proofs running at once; a burst of names that can't be validated must not
/// take every in-flight permit (`spec/02` §8.4). A proof that finds no slot is "not proven".
const MAX_PROOFS: usize = 8;
/// REQ: DNS-011, NFR-004 (ADR-188) — link-by-link validations running at once, on slots of their
/// own: the unsigned-zone proofs their links need take one of `MAX_PROOFS`. One that finds no slot
/// is "not proven".
const MAX_LINK_WALKS: usize = 4;
/// How long a name whose zone couldn't be proven unsigned isn't walked again.
const UNPROVEN_FOR: Duration = Duration::from_mins(1);
/// Names remembered as unproven (the map is cleared beyond this).
const MAX_UNPROVEN: usize = 4096;

/// Limits for the unsigned-zone proof: how many run at once, and which names recently failed
/// to be proven (the failure cost is per name: names that can't be proven aren't cached as
/// zones). Both only ever make the answer more conservative (bogus stays bogus). Link-by-link
/// validation has a gate of its own (ADR-188).
#[derive(Debug)]
struct ProofGate {
    slots: tokio::sync::Semaphore,
    unproven: Mutex<HashMap<String, std::time::Instant>>,
}

impl Default for ProofGate {
    fn default() -> Self {
        Self::with_slots(MAX_PROOFS)
    }
}

/// Why [`ProofGate::try_enter`] gave no slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Skipped {
    /// The name failed within the last minute.
    Failed,
    /// Every slot is busy.
    Busy,
}

impl ProofGate {
    /// A gate with `slots` slots.
    fn with_slots(slots: usize) -> Self {
        Self {
            slots: tokio::sync::Semaphore::new(slots),
            unproven: Mutex::new(HashMap::new()),
        }
    }

    /// A slot to run a proof for `name`, or `None` when it failed within the last minute or
    /// every slot is busy.
    fn enter(&self, name: &str) -> Option<tokio::sync::SemaphorePermit<'_>> {
        self.try_enter(name).ok()
    }

    /// [`Self::enter`], saying why there is no slot.
    fn try_enter(&self, name: &str) -> Result<tokio::sync::SemaphorePermit<'_>, Skipped> {
        let now = std::time::Instant::now();
        if self
            .unproven
            .lock()
            .get(name)
            .is_some_and(|until| *until > now)
        {
            return Err(Skipped::Failed);
        }
        self.slots.try_acquire().map_err(|_| Skipped::Busy)
    }

    /// `name` couldn't be proven unsigned.
    fn failed(&self, name: &str) {
        let mut m = self.unproven.lock();
        if m.len() >= MAX_UNPROVEN {
            m.clear();
        }
        m.insert(name.to_owned(), std::time::Instant::now() + UNPROVEN_FOR);
    }

    /// Takes every free slot but `leave`, until the permits are dropped (tests).
    fn hold(&self, leave: usize) -> Vec<tokio::sync::SemaphorePermit<'_>> {
        let n = self.slots.available_permits().saturating_sub(leave);
        (0..n)
            .filter_map(|_| self.slots.try_acquire().ok())
            .collect()
    }
}

/// REQ: DNS-011 (ADR-098, ADR-188) — what an unsigned-zone proof came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unsigned {
    /// The zone is proven unsigned.
    Proven,
    /// It isn't: the proof failed, ran out of time, or failed within the last minute.
    NotProven,
    /// It wasn't tried: every slot was busy (nothing is remembered).
    Busy,
}

impl Unsigned {
    fn is_proven(self) -> bool {
        self == Self::Proven
    }
}

/// REQ: DNS-011, NFR-004 (ADR-188) — why link-by-link validation gave no verdict; either way the
/// answer stays bogus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoVerdict {
    /// A link doesn't hold, or couldn't be checked in time: the question isn't validated link by
    /// link again for a minute.
    Fails,
    /// A proof a link needed found every slot busy: the next question tries again.
    Busy,
}

/// What is left of `deadline`.
fn left(deadline: std::time::Instant) -> Duration {
    deadline.saturating_duration_since(std::time::Instant::now())
}

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
        deadline: std::time::Instant,
    ) -> bool {
        self.owners_unsigned(group, handle, response, qkey, budget, deadline)
            .await
            .is_proven()
    }

    /// [`Self::all_unsigned`], and when not, what the first owner not proven came to (ADR-188).
    async fn owners_unsigned(
        &self,
        group: &Arc<Group>,
        handle: &DnssecDnsHandle<GroupHandle>,
        response: &Message,
        qkey: &str,
        budget: Duration,
        deadline: std::time::Instant,
    ) -> Unsigned {
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
            match self
                .unsigned_proof(group, handle, o, budget, deadline)
                .await
            {
                Unsigned::Proven => {}
                other => return other,
            }
        }
        Unsigned::Proven
    }

    /// REQ: DNS-011 (RFC 4035 §5.4, RFC 5155 §8) — the validation library proves a denial for
    /// the name that was asked, but after a CNAME the answer's NSEC or NSEC3 records are about
    /// the last name of the chain (a missing type or name there, or a wildcard's expansion), so
    /// it calls a signed answer bogus. This validates such an answer one link at a time, each
    /// as a question of its own: the CNAME at a name, then the question at its target, until
    /// the target answers it. The verdict is the weakest of them, and the answer is made of
    /// their validated records only: nothing of the answer that failed is used, it is just the
    /// reason to look. `None`: not every link holds, or one couldn't be checked in time (the
    /// answer stays bogus).
    ///
    /// NFR-004 — bounded like the unsigned-zone proof: by `deadline`, by a handful at once (on
    /// slots of their own, ADR-188), and by a minute's memory of questions that failed; and by
    /// [`MAX_LINKS`].
    async fn validate_links(
        &self,
        group: &Arc<Group>,
        handle: &DnssecDnsHandle<GroupHandle>,
        name: &Name,
        q: &Question,
        budget: Duration,
        deadline: std::time::Instant,
    ) -> Option<(Verdict, Message)> {
        // One entry per question, its type and name, in this gate's own memory of failures.
        let key = format!("{} {}", q.qtype, zone_key(name));
        // No slot, or it failed within the last minute: not proven.
        let _slot = self.links.enter(&key)?;
        match self
            .follow_links(group, handle, name, q, budget, deadline)
            .await
        {
            Ok(found) => Some(found),
            // REQ: NFR-004 (ADR-188) — a proof skipped only for want of a slot: not remembered.
            Err(NoVerdict::Busy) => None,
            Err(NoVerdict::Fails) => {
                self.links.failed(&key);
                None
            }
        }
    }

    /// [`Self::validate_links`], without its limits on how often and how many.
    async fn follow_links(
        &self,
        group: &Arc<Group>,
        handle: &DnssecDnsHandle<GroupHandle>,
        name: &Name,
        q: &Question,
        budget: Duration,
        deadline: std::time::Instant,
    ) -> Result<(Verdict, Message), NoVerdict> {
        let qtype = RecordType::from(q.qtype);
        let mut worst = Verdict::Secure;
        let mut chain: Vec<Record> = Vec::new();
        // The proofs of wildcard-expanded links.
        let mut proofs: Vec<Record> = Vec::new();
        let mut seen = vec![name.clone()];
        let mut at = name.clone();
        for _ in 0..MAX_LINKS {
            // REQ: DNS-011 (ADR-188) — a link without an answer in time (a timeout, an upstream
            // failure) proves nothing: the answer stays bogus.
            let Some(Ok(link)) = ask(handle, &at, RecordType::CNAME, deadline).await else {
                return Err(NoVerdict::Fails);
            };
            let Some(target) = link.answers.iter().find_map(|r| match &r.data {
                RData::CNAME(c) if r.name == at => Some(c.0.clone()),
                _ => None,
            }) else {
                return Err(NoVerdict::Fails);
            };
            let v = self
                .link_verdict(group, handle, &link, &at, budget, deadline)
                .await?;
            worst = worst.weakest(v);
            let link = link.into_message();
            chain.extend(link.answers.into_iter().filter(|r| {
                r.name == at
                    && (r.record_type() == RecordType::CNAME || rrsig_covers(r, RecordType::CNAME))
            }));
            proofs.extend(link.authorities.into_iter().filter(is_denial));
            if seen.contains(&target) {
                return Err(NoVerdict::Fails);
            }
            seen.push(target.clone());
            at = target;
            let end = match ask(handle, &at, qtype, deadline).await {
                // Another link: what follows it is judged by the questions of its own, not by
                // this answer (which may end at a CNAME without a proof of what's missing).
                Some(Ok(end)) if starts_with_cname(&end, &at) => continue,
                Some(Ok(end)) => end,
                Some(Err(e)) if denied_through_cname(&e, &at, q) => continue,
                Some(Err(e)) => {
                    tracing::debug!(name = %zone_key(&at), "DNSSEC: link by link: {e}");
                    return Err(NoVerdict::Fails);
                }
                // REQ: DNS-011 (ADR-188) — no answer in time: as above.
                None => return Err(NoVerdict::Fails),
            };
            let v = self
                .link_verdict(group, handle, &end, &at, budget, deadline)
                .await?;
            let mut m = end.into_message();
            m.queries = vec![Query::query(name.clone(), qtype)];
            // REQ: DNS-011 (ADR-188) — of the last answer, the records of the name it answers and
            // their signatures: the chain's, nothing of other names.
            m.answers.retain(|r| r.name == at);
            chain.append(&mut m.answers);
            m.answers = chain;
            for r in proofs {
                if !m.authorities.contains(&r) {
                    m.authorities.push(r);
                }
            }
            return Ok((worst.weakest(v), m));
        }
        Err(NoVerdict::Fails)
    }

    /// What one link's answer is worth: secure, or insecure (also when its zone is proven
    /// unsigned); for anything else, why not.
    async fn link_verdict(
        &self,
        group: &Arc<Group>,
        handle: &DnssecDnsHandle<GroupHandle>,
        answer: &Message,
        owner: &Name,
        budget: Duration,
        deadline: std::time::Instant,
    ) -> Result<Verdict, NoVerdict> {
        match verdict(answer) {
            v @ (Verdict::Secure | Verdict::Insecure) => Ok(v),
            Verdict::Bogus => match self
                .owners_unsigned(group, handle, answer, &zone_key(owner), budget, deadline)
                .await
            {
                Unsigned::Proven => Ok(Verdict::Insecure),
                Unsigned::NotProven => Err(NoVerdict::Fails),
                Unsigned::Busy => Err(NoVerdict::Busy),
            },
            Verdict::Indeterminate => Err(NoVerdict::Fails),
        }
    }

    /// REQ: DNS-011 (T10.9, ADR-184) — `name` is in a zone already proven unsigned through the
    /// upstream group at address `group`.
    fn known_insecure(&self, group: usize, name: &str) -> bool {
        self.known_insecure_at(group, name, std::time::Instant::now())
    }

    /// [`Self::known_insecure`] at `now`.
    fn known_insecure_at(&self, group: usize, name: &str, now: std::time::Instant) -> bool {
        let zones = self.insecure.lock();
        zone_candidates(name)
            .into_iter()
            .any(|z| zones.get(&(group, z)).is_some_and(|until| *until > now))
    }

    /// REQ: DNS-011 (T10.9, ADR-184) — `zone` was proven unsigned through the upstream group at
    /// address `group`, by records that hold for `ttl`: names under it, through that group,
    /// aren't validated again until then (`INSECURE_FOR` at most).
    fn remember_insecure(&self, group: usize, zone: String, ttl: Duration) {
        self.remember_insecure_at(group, zone, ttl, std::time::Instant::now());
    }

    /// [`Self::remember_insecure`] at `now`.
    fn remember_insecure_at(
        &self,
        group: usize,
        zone: String,
        ttl: Duration,
        now: std::time::Instant,
    ) {
        let mut zones = self.insecure.lock();
        if zones.len() >= MAX_INSECURE_ZONES {
            zones.clear();
        }
        zones.insert((group, zone), now + ttl.min(INSECURE_FOR));
    }

    /// REQ: DNS-011 (T10.9, ADR-098, ADR-184) — whether `name` is in an unsigned zone, proven
    /// the way a resolver proves it: walking down from the top, the first zone apex whose DS
    /// the parent validly denies, with records of the parent zone that show a delegation there
    /// ([`ds_denial_verdict`]: its NSEC or NSEC3 at the name, or an NSEC3 Opt-Out span below
    /// a closest encloser that isn't a delegation), is unsigned, and so is everything below
    /// it. Whether a name is an apex (it has its own SOA) comes from an ordinary query, only
    /// to skip names that aren't: the DS denial is what's trusted. Anything that can't be
    /// proven: `false`.
    ///
    /// REQ: NFR-004 (review 03-05) — bounded by `deadline` (what is left of the validation's
    /// two query budgets, not a fresh budget per step), by a handful of concurrent proofs,
    /// and by a minute's memory of names that couldn't be proven.
    async fn proven_insecure(
        &self,
        group: &Arc<Group>,
        handle: &DnssecDnsHandle<GroupHandle>,
        name: &str,
        budget: Duration,
        deadline: std::time::Instant,
    ) -> bool {
        self.unsigned_proof(group, handle, name, budget, deadline)
            .await
            .is_proven()
    }

    /// [`Self::proven_insecure`], saying why not (ADR-188): a proof skipped because every slot
    /// was busy is [`Unsigned::Busy`], apart from one that failed, so that link-by-link
    /// validation doesn't remember it as a failure.
    async fn unsigned_proof(
        &self,
        group: &Arc<Group>,
        handle: &DnssecDnsHandle<GroupHandle>,
        name: &str,
        budget: Duration,
        deadline: std::time::Instant,
    ) -> Unsigned {
        if self.known_insecure(Arc::as_ptr(group) as usize, name) {
            return Unsigned::Proven;
        }
        let _slot = match self.proofs.try_enter(name) {
            Ok(slot) => slot,
            Err(skipped) => {
                tracing::debug!(%name, ?skipped, "DNSSEC: unsigned-zone proof skipped: recently failed, or too many running");
                return match skipped {
                    Skipped::Failed => Unsigned::NotProven,
                    Skipped::Busy => Unsigned::Busy,
                };
            }
        };
        let proven = tokio::time::timeout(
            left(deadline),
            self.walk_zones(group, handle, name, budget, deadline),
        )
        .await
        .unwrap_or(false);
        if !proven {
            self.proofs.failed(name);
            return Unsigned::NotProven;
        }
        Unsigned::Proven
    }

    /// The proof itself: the zone candidates from the top, each step limited to what the
    /// deadline leaves.
    async fn walk_zones(
        &self,
        group: &Arc<Group>,
        handle: &DnssecDnsHandle<GroupHandle>,
        name: &str,
        budget: Duration,
        deadline: std::time::Instant,
    ) -> bool {
        let plain = GroupHandle {
            group: Arc::clone(group),
            budget,
            last: Arc::new(Mutex::new((0, 0))),
        };
        for zone in zone_candidates(name).into_iter().take(MAX_ZONE_LEVELS) {
            let Ok(apex) = Name::from_ascii(format!("{zone}.")) else {
                return false;
            };
            let step = budget.min(left(deadline));
            if step.is_zero() {
                return false;
            }
            if !is_apex(&plain, &apex, step).await {
                tracing::debug!(%zone, "DNSSEC: unsigned-zone proof: not an apex");
                continue;
            }
            let ds = ds_signed(handle, &apex, budget.min(left(deadline))).await;
            tracing::debug!(%zone, ?ds, "DNSSEC: unsigned-zone proof: DS");
            match ds {
                Some((true, _)) => {}
                Some((false, ttl)) => {
                    self.remember_insecure(Arc::as_ptr(group) as usize, zone, ttl);
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

/// The validating handle's answer to a question of its own, within `deadline`: the answer, or
/// what the validator found wrong with it. `None`: no answer in time (a timeout, or the upstream
/// failed), which proves nothing.
async fn ask(
    handle: &DnssecDnsHandle<GroupHandle>,
    name: &Name,
    rtype: RecordType,
    deadline: std::time::Instant,
) -> Option<Result<DnsResponse, NetError>> {
    let mut s = handle.send(request(name, rtype));
    match tokio::time::timeout(left(deadline), s.next()).await {
        Ok(Some(Err(e))) if is_transport(&e) => None,
        Ok(Some(r)) => Some(or_wildcard(r, name, rtype)),
        Ok(None) | Err(_) => None,
    }
}

/// REQ: DNS-011 — the validator refused the denial in an answer for `name` that starts with a
/// CNAME at `name`: a reason to validate it link by link.
fn denied_through_cname(e: &NetError, name: &Name, q: &Question) -> bool {
    let NetError::Dns(hickory_net::DnsError::Nsec { response, .. }) = e else {
        return false;
    };
    follows_cname(q) && starts_with_cname(response, name)
}

/// Whether a CNAME is followed for this question (not for CNAME itself, DS, RRSIG or ANY; nor
/// for NSEC: a CNAME's owner has an NSEC of its own, RFC 4035 §2.3, §2.5).
fn follows_cname(q: &Question) -> bool {
    use RecordType::{ANY, CNAME, DS, RRSIG};
    q.qclass == 1
        && !matches!(
            RecordType::from(q.qtype),
            ANY | CNAME | DS | RecordType::NSEC | RRSIG
        )
}

/// `name` has a CNAME in the answer.
fn starts_with_cname(m: &Message, name: &Name) -> bool {
    m.answers
        .iter()
        .any(|r| r.record_type() == RecordType::CNAME && r.name == *name)
}

/// REQ: DNS-011 (RFC 4035 §5.3.4, ADR-188) — what the validator returned, with every wildcard
/// answer in a zone signed with NSEC checked against the rule itself ([`wildcard_proven`]) before
/// it is served: one the rule proves is accepted, also when its NSEC proof was refused, and one it
/// doesn't prove is bogus (its records' proofs say so, so it is handled as any bogus answer). An
/// answer that wasn't refused and starts with a wildcard CNAME at `name` may instead meet the rule
/// with the CNAME's record set ([`wildcard_cname_proven`]).
fn or_wildcard(
    r: Result<DnsResponse, NetError>,
    name: &Name,
    rtype: RecordType,
) -> Result<DnsResponse, NetError> {
    match r {
        Err(NetError::Dns(hickory_net::DnsError::Nsec { response, .. }))
            if wildcard_proven(&response, name, rtype) =>
        {
            tracing::debug!(name = %zone_key(name), "DNSSEC: wildcard expansion proven");
            Ok(*response)
        }
        Ok(mut response)
            if nsec_wildcard_answer(&response)
                && !wildcard_proven(&response, name, rtype)
                && !wildcard_cname_proven(&response, name, rtype) =>
        {
            tracing::debug!(name = %zone_key(name), "DNSSEC: wildcard expansion without its proof");
            for record in &mut response.answers {
                record.proof = Proof::Bogus;
            }
            Ok(response)
        }
        r => r,
    }
}

/// REQ: DNS-011 (RFC 4035 §5.3.4, RFC 5155 §8.8; ADR-188) — `m` answers from a wildcard (a secure
/// signature covering fewer labels than its owner has), and the wildcard rule of zones signed with
/// NSEC applies to it. Zones signed with NSEC3 are left to the library: the rule is left out only
/// when, for every zone that signed such a signature, the authority section has a verified NSEC3
/// record of that zone (owned directly below it).
fn nsec_wildcard_answer(m: &Message) -> bool {
    let mut signers = m.answers.iter().filter_map(expansion_signer).peekable();
    signers.peek().is_some() && !signers.all(|zone| has_nsec3_of(m, zone))
}

/// The signer of `r` when it is a secure signature over fewer labels than its owner has: that of a
/// record made from a wildcard (RFC 4035 §5.3.4).
fn expansion_signer(r: &Record) -> Option<&Name> {
    match &r.data {
        RData::DNSSEC(DNSSECRData::RRSIG(s))
            if r.proof == Proof::Secure && s.input().num_labels < r.name.num_labels() =>
        {
            Some(&s.input().signer_name)
        }
        _ => None,
    }
}

/// The authority section of `m` has a verified NSEC3 record of `zone`: owned directly below it.
fn has_nsec3_of(m: &Message, zone: &Name) -> bool {
    m.authorities.iter().any(|r| {
        r.proof == Proof::Secure
            && r.record_type() == RecordType::NSEC3
            && r.name.base_name() == *zone
    })
}

/// REQ: DNS-011 (RFC 4035 §5.3.4) — a wildcard's answer is authenticated by its signature and
/// an NSEC record showing that no closer name exists. The validation library also wants an NSEC
/// covering the wildcard, which can't be there when that wildcard gave the answer, so it calls
/// the answer bogus wherever the wildcard stands right above the name. This checks the rule
/// itself, over records the library validated. True only when:
/// - the answer is one record set, the question's, secure, with its signatures: at least one of
///   them verified, and a signature of it that isn't verified (a second key or algorithm during a
///   rollover, RFC 6840 §5.4) left out;
/// - every verified signature covers fewer labels than `name` has, all the same number of them, by
///   one signer, a zone `name` is in: the wildcard one label above that many;
/// - a secure NSEC signed by that zone covers the next closer name (`name`, cut to one label
///   more): it doesn't exist, nor does anything below it;
/// - and there is no NSEC3 beside it.
fn wildcard_proven(m: &Message, name: &Name, rtype: RecordType) -> bool {
    record_set_proven(m, &m.answers, name, rtype)
}

/// [`wildcard_proven`] with `answers` as the answer: records of `m`'s answer section, all of them
/// or those of one name ([`wildcard_cname_proven`]).
fn record_set_proven<'a>(
    m: &Message,
    answers: impl IntoIterator<Item = &'a Record>,
    name: &Name,
    rtype: RecordType,
) -> bool {
    if m.metadata.response_code != ResponseCode::NoError || name.is_wildcard() {
        return false;
    }
    let (mut sigs, mut answered) = (Vec::new(), false);
    for r in answers {
        if r.name != *name {
            return false;
        }
        match &r.data {
            // REQ: DNS-011 (RFC 6840 §5.4, ADR-188) — one verified signature proves the record set;
            // another one that isn't verified says nothing either way.
            RData::DNSSEC(DNSSECRData::RRSIG(s)) if s.input().type_covered == rtype => {
                if r.proof == Proof::Secure {
                    sigs.push((s.input().num_labels, &s.input().signer_name));
                }
            }
            _ if r.proof == Proof::Secure && r.record_type() == rtype => answered = true,
            _ => return false,
        }
    }
    let Some(&(labels, zone)) = sigs.first() else {
        return false;
    };
    if sigs.iter().any(|s| *s != (labels, zone))
        || !answered
        || labels >= name.num_labels()
        || zone.num_labels() > labels
        || !zone.zone_of(name)
    {
        return false;
    }
    let next_closer = name.trim_to(usize::from(labels) + 1);
    if m.authorities
        .iter()
        .any(|r| r.record_type() == RecordType::NSEC3)
    {
        return false;
    }
    m.authorities.iter().any(|r| {
        let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = &r.data else {
            return false;
        };
        r.proof == Proof::Secure
            && nsec_signed_by(m, &r.name, zone)
            && nsec_covers(&r.name, nsec, zone, &next_closer)
    })
}

/// REQ: DNS-011 (RFC 4035 §5.3.4, ADR-188) — `m` answers a question for another type than CNAME
/// with a CNAME at `name` made from a wildcard, and no record of another name in it is made from a
/// wildcard: the CNAME's record set at `name`, with its signatures, meets the rule as for a question
/// for the CNAME ([`record_set_proven`] over the answer's records owned by `name`). The rest of the
/// chain are records of names that exist, each validated by its own signature, and the chain ends
/// in a record of the question's type ([`chain_ends_in`]).
fn wildcard_cname_proven(m: &Message, name: &Name, rtype: RecordType) -> bool {
    rtype != RecordType::CNAME
        && !m
            .answers
            .iter()
            .any(|r| r.name != *name && expansion_signer(r).is_some())
        && record_set_proven(
            m,
            m.answers.iter().filter(|r| r.name == *name),
            name,
            RecordType::CNAME,
        )
        && chain_ends_in(m, name, rtype)
}

/// REQ: DNS-011 (ADR-188) — the CNAMEs of `m`'s answer section, followed from `name`, end in a
/// record of `rtype`: not at a name without one, and not in a loop. At most one step per answer
/// record.
fn chain_ends_in(m: &Message, name: &Name, rtype: RecordType) -> bool {
    let mut seen = vec![name];
    let mut owner = name;
    for _ in 0..m.answers.len() {
        let Some(target) = m.answers.iter().find_map(|r| match &r.data {
            RData::CNAME(c) if r.name == *owner => Some(&c.0),
            _ => None,
        }) else {
            break;
        };
        if seen.contains(&target) {
            return false;
        }
        seen.push(target);
        owner = target;
    }
    m.answers
        .iter()
        .any(|r| r.name == *owner && r.record_type() == rtype)
}

/// The NSEC owned by `owner` has a secure signature, in the authority section, by `zone`.
fn nsec_signed_by(m: &Message, owner: &Name, zone: &Name) -> bool {
    m.authorities.iter().any(|r| {
        matches!(&r.data, RData::DNSSEC(DNSSECRData::RRSIG(s))
            if r.proof == Proof::Secure
                && r.name == *owner
                && s.input().type_covered == RecordType::NSEC
                && s.input().signer_name == *zone)
    })
}

/// `zone`'s NSEC at `owner` shows that neither `name` nor anything below it exists: `name` lies
/// strictly between the owner and the next name (the zone's last NSEC points to its apex), it
/// isn't an ancestor of the next name (an empty non-terminal), and it isn't below a delegation
/// or a DNAME at the owner (RFC 6840 §4.1).
fn nsec_covers(owner: &Name, nsec: &NSEC, zone: &Name, name: &Name) -> bool {
    let next = nsec.next_domain_name();
    let types = nsec.type_set();
    let cut = types.contains(RecordType::NS) && !types.contains(RecordType::SOA);
    zone.zone_of(owner)
        && zone.zone_of(next)
        && zone.zone_of(name)
        && owner < name
        && (name < next || next == zone)
        && !name.zone_of(next)
        && !((cut || types.contains(RecordType::DNAME)) && owner.zone_of(name))
}

/// An NSEC or NSEC3 record, or the signature of one.
fn is_denial(r: &Record) -> bool {
    matches!(r.record_type(), RecordType::NSEC | RecordType::NSEC3)
        || rrsig_covers(r, RecordType::NSEC)
        || rrsig_covers(r, RecordType::NSEC3)
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
/// (unsigned), `None` unknown; with how long the answer's records hold ([`proof_ttl`]).
async fn ds_signed(
    handle: &DnssecDnsHandle<GroupHandle>,
    apex: &Name,
    budget: Duration,
) -> Option<(bool, Duration)> {
    let mut s = handle.send(request(apex, RecordType::DS));
    match tokio::time::timeout(budget, s.next()).await {
        Ok(Some(Ok(r))) => {
            tracing::debug!(%apex, verdict = ?verdict(&r), answers = r.answers.len(), "DNSSEC: unsigned-zone proof: DS response");
            ds_denial_verdict(DsAnswer::Response(&r), apex).map(|signed| (signed, proof_ttl(&r)))
        }
        Ok(Some(Err(NetError::Dns(hickory_net::DnsError::Nsec {
            proof, response, ..
        })))) => {
            tracing::debug!(%apex, ?proof, "DNSSEC: unsigned-zone proof: DS denial");
            ds_denial_verdict(
                DsAnswer::Denial {
                    proof,
                    response: &response,
                },
                apex,
            )
            .map(|signed| (signed, proof_ttl(&response)))
        }
        other => {
            tracing::debug!(%apex, ?other, "DNSSEC: unsigned-zone proof: no DS answer");
            None
        }
    }
}

/// REQ: DNS-011 (ADR-184) — how long the records of a DS answer hold: the smallest TTL in its
/// authority section (hickory lowers a validated record's TTL to what its signature allows).
fn proof_ttl(m: &Message) -> Duration {
    Duration::from_secs(u64::from(
        m.authorities.iter().map(|r| r.ttl).min().unwrap_or(0),
    ))
}

/// What the validating handle returned for a DS question, as the unsigned-zone proof reads it.
#[derive(Debug, Clone, Copy)]
enum DsAnswer<'a> {
    /// A response hickory accepted; each record carries its proof.
    Response(&'a Message),
    /// A negative answer whose proof isn't secure, which hickory returns as an error carrying
    /// that proof (`DnsError::Nsec`).
    Denial { proof: Proof, response: &'a Message },
}

/// REQ: DNS-011 (ADR-098, ADR-184) — what a DS answer for `apex` proves: `Some(true)` signed (a
/// secure DS), `Some(false)` an unsigned delegation, `None` nothing. The decision part of
/// [`ds_signed`], apart from the network so that answers can be built by hand in tests.
fn ds_denial_verdict(answer: DsAnswer<'_>, apex: &Name) -> Option<bool> {
    let r = match answer {
        DsAnswer::Response(r) => r,
        // REQ: DNS-011 (ADR-184) — hickory returns a negative answer whose proof isn't secure
        // as an error carrying that proof; such an answer is no proof of an unsigned zone. An
        // Opt-Out denial comes back as an ordinary response, above.
        DsAnswer::Denial { proof, response } => {
            tracing::debug!(%apex, ?proof, authorities = response.authorities.len(), "DNSSEC: unsigned-zone proof: a DS denial without a secure proof proves nothing");
            return None;
        }
    };
    let has_ds = r.answers.iter().any(|a| a.record_type() == RecordType::DS);
    let other = r
        .answers
        .iter()
        .any(|a| !matches!(a.record_type(), RecordType::DS | RecordType::RRSIG));
    // REQ: DNS-011 (ADR-098, ADR-184) — a secure denial of DS proves an unsigned delegation
    // only when its records, the parent zone's, also show that `apex` is a delegation: every
    // name inside a signed zone has a secure DS denial too, and whether `apex` has an SOA came
    // from an unvalidated answer.
    let cut = denies_ds_at_cut(&r.authorities, apex) || denies_ds_by_opt_out(&r.authorities, apex);
    match (has_ds, other, verdict(r)) {
        (true, _, Verdict::Secure) => Some(true),
        (false, false, Verdict::Secure) if cut => Some(false),
        (false, false, Verdict::Insecure) if insecure_tld(&r.authorities, apex) => Some(false),
        _ => None,
    }
}

/// REQ: DNS-011 (ADR-184) — an answer the validating handle found insecure proves that `apex`
/// is unsigned only through an insecure record owned by an unsigned top-level domain: a
/// one-label name that is `apex` itself or its top-level domain, whose status the root's
/// signed chain decides. A zone with two or more labels above `apex` is a candidate the walk
/// decides with the rest of this proof first. Every label counts, a leading `*` too (which
/// `Name::num_labels` leaves out).
fn insecure_tld(authorities: &[Record], apex: &Name) -> bool {
    authorities
        .iter()
        .any(|a| a.proof == Proof::Insecure && a.name.iter().count() == 1 && a.name.zone_of(apex))
}

/// The type set of a delegation without a DS, as its parent's NSEC or NSEC3 lists it: NS, and
/// neither SOA nor DS (RFC 4035 §5.2, RFC 5155 §8.9).
fn shows_unsigned_cut(types: &RecordTypeSet) -> bool {
    types.contains(RecordType::NS)
        && !types.contains(RecordType::SOA)
        && !types.contains(RecordType::DS)
}

/// REQ: DNS-011 (ADR-098, ADR-184) — the denial shows a delegation without a DS at `apex`: the
/// secure NSEC owned by `apex`, or the NSEC3 matching `apex`'s hash among the parent zone's
/// ([`parent_zone_nsec3s`]), lists NS and neither SOA nor DS.
fn denies_ds_at_cut(authorities: &[Record], apex: &Name) -> bool {
    let nsec = authorities.iter().any(|a| {
        a.proof == Proof::Secure
            && a.name == *apex
            && matches!(&a.data, RData::DNSSEC(DNSSECRData::NSEC(n)) if shows_unsigned_cut(n.type_set()))
    });
    nsec || parent_zone_nsec3s(authorities, apex).is_some_and(|set| {
        set.hash(apex).is_some_and(|target| {
            set.records
                .iter()
                .any(|(owner, n)| *owner == target && shows_unsigned_cut(n.type_set()))
        })
    })
}

/// REQ: DNS-011 (ADR-098, ADR-184) — an unsigned delegation in an NSEC3 Opt-Out zone (most of
/// `.com`, `.org`, ...) has no NSEC3 of its own: it lies inside an Opt-Out span. RFC 5155 §8.6:
/// a DS NODATA with no NSEC3 matching `apex` proves it unsigned through the closest-encloser
/// proof, here with records of the parent zone only ([`parent_zone_nsec3s`]):
/// - no NSEC3 there matches `apex` (one that does decides on its own, in [`denies_ds_at_cut`]);
/// - the NSEC3 matching the closest encloser, `apex`'s parent name, isn't a delegation's (not
///   NS without SOA, not DNAME: such a record says nothing about the names below it, RFC 6840
///   §4.1);
/// - an Opt-Out NSEC3 covers `apex`'s hash (the next closer name).
///
/// A closest encloser further up (an Opt-Out empty non-terminal between them) isn't accepted:
/// not proven. Seen with names below parked domains (`www.smithsonianmag.org`), whose servers
/// answer an SOA for every name, which the validation library judges bogus.
fn denies_ds_by_opt_out(authorities: &[Record], apex: &Name) -> bool {
    if apex.is_root() {
        return false;
    }
    let Some(set) = parent_zone_nsec3s(authorities, apex) else {
        return false;
    };
    let (Some(target), Some(encloser)) = (set.hash(apex), set.hash(&apex.base_name())) else {
        return false;
    };
    if set.records.iter().any(|(owner, _)| *owner == target) {
        return false;
    }
    let enclosers: Vec<&NSEC3> = set
        .records
        .iter()
        .filter(|(owner, _)| *owner == encloser)
        .map(|(_, n)| *n)
        .collect();
    !enclosers.is_empty()
        && enclosers.iter().all(|n| !n.is_ancestor_delegation())
        && set.records.iter().any(|(owner, n)| {
            n.opt_out() && hash_range_covers(owner, n.next_hashed_owner_name(), &target)
        })
}

/// REQ: DNS-011 (ADR-184) — the most NSEC3 iterations the proof hashes with (RFC 9276 §3.2): a
/// parent zone whose NSEC3 records use more proves nothing here.
const MAX_NSEC3_ITERATIONS: u16 = 100;

/// The NSEC3 records of a DS denial that can speak for the delegation's parent
/// ([`parent_zone_nsec3s`]), each with the hash its owner name encodes. They share one set of
/// hash parameters, so a name is hashed once per proof.
struct ParentNsec3s<'a> {
    records: Vec<(Vec<u8>, &'a NSEC3)>,
}

impl ParentNsec3s<'_> {
    /// `name` hashed with the set's parameters.
    fn hash(&self, name: &Name) -> Option<Vec<u8>> {
        self.records.first().and_then(|(_, n)| nsec3_hash(n, name))
    }
}

/// REQ: DNS-011 (ADR-184) — the NSEC3 records of a DS denial for `apex`, when they can speak for
/// `apex`'s parent: all owned under one zone, a proper ancestor of `apex` (the delegation's
/// parent zone, or a zone above it), all validated, with one hash algorithm, salt and iteration
/// count (at most [`MAX_NSEC3_ITERATIONS`]), and with no NSEC and no SOA of another zone beside
/// them. `None` otherwise: the proof is made of one parent zone's records.
fn parent_zone_nsec3s<'a>(authorities: &'a [Record], apex: &Name) -> Option<ParentNsec3s<'a>> {
    let mut zone: Option<Name> = None;
    let mut set = Vec::new();
    for r in authorities {
        match &r.data {
            RData::DNSSEC(DNSSECRData::NSEC3(n)) => {
                if r.proof != Proof::Secure {
                    return None;
                }
                let owner_zone = r.name.base_name();
                if *zone.get_or_insert_with(|| owner_zone.clone()) != owner_zone {
                    return None;
                }
                set.push((r.name.iter().next().and_then(base32hex_decode)?, n));
            }
            RData::DNSSEC(DNSSECRData::NSEC(_)) => return None,
            _ => {}
        }
    }
    let zone = zone?;
    if zone == *apex || !zone.zone_of(apex) {
        return None;
    }
    if authorities
        .iter()
        .any(|r| r.record_type() == RecordType::SOA && r.name != zone)
    {
        return None;
    }
    let (_, first) = set.first()?;
    let one_set = first.iterations() <= MAX_NSEC3_ITERATIONS
        && set.iter().all(|(_, n)| {
            n.hash_algorithm() == first.hash_algorithm()
                && n.iterations() == first.iterations()
                && n.salt() == first.salt()
        });
    one_set.then_some(ParentNsec3s { records: set })
}

#[cfg(test)]
thread_local! {
    /// Test-only: how many names [`nsec3_hash`] has hashed on this thread.
    static NSEC3_HASHES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// `name` hashed with an NSEC3's parameters.
fn nsec3_hash(n: &NSEC3, name: &Name) -> Option<Vec<u8>> {
    #[cfg(test)]
    NSEC3_HASHES.with(|c| c.set(c.get() + 1));
    n.hash_algorithm()
        .hash(n.salt(), name, n.iterations())
        .ok()
        .map(|h| h.as_ref().to_vec())
}

/// `h` lies strictly between an NSEC3's owner hash and its next hashed owner, compared as
/// bytes (hashes of one length; anything else covers nothing). The last NSEC3 of a chain wraps
/// around to the first, so a chain of one record covers every hash but its own.
fn hash_range_covers(owner: &[u8], next: &[u8], h: &[u8]) -> bool {
    if owner.len() != h.len() || next.len() != h.len() {
        return false;
    }
    if owner < next {
        owner < h && h < next
    } else {
        h > owner || h < next
    }
}

/// Base32 with the extended hex alphabet, no padding (RFC 4648 §7): NSEC3 owner labels (the
/// tests build them; the proof decodes them, [`base32hex_decode`]).
#[cfg(test)]
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

/// REQ: DNS-011 (ADR-184) — the bytes a base32hex label encodes (RFC 4648 §7, either case, no
/// padding, unused trailing bits zero): an NSEC3 owner's hash, compared as bytes. `None` for
/// anything else.
fn base32hex_decode(label: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(label.len() * 5 / 8);
    let (mut acc, mut bits) = (0u16, 0u8);
    for &c in label {
        let v = match c.to_ascii_lowercase() {
            d @ b'0'..=b'9' => d - b'0',
            l @ b'a'..=b'v' => l - b'a' + 10,
            _ => return None,
        };
        acc = (acc << 5) | u16::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(acc >> bits).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    (acc == 0).then_some(out)
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

/// REQ: DNS-011, DNS-013 (review 03-06) — the upstream group gave no answer (as opposed to
/// something the validator found wrong with the answers it got). Carried inside an I/O error so
/// the validator's `NetError` can be told apart by type, not by what its message happens to
/// start with.
#[derive(Debug)]
struct UpstreamFailure(String);

impl std::fmt::Display for UpstreamFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "upstream: {}", self.0)
    }
}

impl std::error::Error for UpstreamFailure {}

fn upstream_failure(e: impl std::fmt::Display) -> NetError {
    NetError::Io(Arc::new(std::io::Error::other(UpstreamFailure(
        e.to_string(),
    ))))
}

fn is_transport(e: &NetError) -> bool {
    match e {
        NetError::Timeout => true,
        NetError::Io(io) => matches!(io.get_ref(), Some(inner) if inner.is::<UpstreamFailure>()),
        _ => false,
    }
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
        worst = worst.weakest(v);
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

/// The validated answer as it is served: DNSSEC records only for clients that asked (DO),
/// records in resolution order.
fn tidy(m: &mut Message, qtype: u16, client_do: bool, qname: &Name) {
    if !client_do {
        strip_dnssec(m, qtype);
    }
    chain_order(&mut m.answers, qname);
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

/// REQ: DNS-011 — puts the answer section back in resolution order. hickory's validating
/// handle returns the validated record sets in no particular order, so an address could come
/// before the CNAME that leads to it. Stub resolvers such as glibc's read a chain top-down and
/// drop records whose owner isn't the current name yet, so those answers had no address at
/// all for them.
///
/// The order is the one a server builds its answer in (RFC 6672 §3.2): from the question name,
/// each owner's CNAME, its other data and its signatures, following CNAME targets (step 3.A);
/// a DNAME owned by an ancestor of the current name (a DNAME doesn't redirect its own owner,
/// §2.3), with its signatures, just before the CNAME synthesized from it (step 3.C). Records
/// off the chain keep their order, at the end. An answer without a CNAME or a DNAME has no
/// chain and is left as it is.
///
/// Cost: one pass over the record types when there is nothing to order. Otherwise one vector
/// the size of the answer and a name copy per link (on the stack for names of up to 32 bytes);
/// owners are compared as names, case-insensitively, without making strings.
fn chain_order(answers: &mut Vec<Record>, qname: &Name) {
    if answers.len() < 2
        || !answers
            .iter()
            .any(|r| matches!(r.record_type(), RecordType::CNAME | RecordType::DNAME))
    {
        return;
    }
    let rank = |r: &Record| match r.record_type() {
        RecordType::CNAME => 0,
        RecordType::RRSIG => 2,
        _ => 1,
    };
    let mut rest = std::mem::take(answers);
    answers.reserve_exact(rest.len());
    let mut owner = qname.clone();
    // Every link moves at least the CNAME it follows out of `rest`, so the walk ends within the
    // answer's length, a CNAME loop included; the bound only says so.
    for _ in 0..=rest.len() {
        let apex = rest
            .iter()
            .find(|r| {
                r.record_type() == RecordType::DNAME
                    && r.name.zone_of(&owner)
                    && !r.name.eq_ignore_root(&owner)
            })
            .map(|r| r.name.clone());
        if let Some(apex) = apex {
            let start = answers.len();
            answers.extend(rest.extract_if(.., |r| {
                r.name.eq_ignore_root(&apex)
                    && (r.record_type() == RecordType::DNAME || rrsig_covers(r, RecordType::DNAME))
            }));
            answers[start..].sort_by_key(rank);
        }
        let start = answers.len();
        answers.extend(rest.extract_if(.., |r| r.name.eq_ignore_root(&owner)));
        answers[start..].sort_by_key(rank);
        let next = answers[start..].iter().find_map(|r| match &r.data {
            RData::CNAME(c) => Some(c.0.clone()),
            _ => None,
        });
        match next {
            Some(n) if !n.eq_ignore_root(&owner) => owner = n,
            _ => break,
        }
    }
    answers.append(&mut rest);
}

/// Whether `r` is a signature over records of type `t`.
fn rrsig_covers(r: &Record, t: RecordType) -> bool {
    matches!(&r.data, RData::DNSSEC(DNSSECRData::RRSIG(s)) if s.input().type_covered == t)
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

    /// REQ: DNS-011, DNS-013 (review 03-06) — an error is an upstream failure by its type: the
    /// marker the handle puts on it (also through a clone), a timeout; not a validation error
    /// whose message begins `upstream:`, and not some other I/O error.
    #[test]
    fn dns_011_transport_errors_are_told_apart_by_type() {
        let marked = upstream_failure("all upstreams failed");
        assert!(is_transport(&marked));
        assert!(is_transport(&marked.clone()), "clones keep the marker");
        assert!(is_transport(&NetError::Timeout));
        assert!(
            marked
                .to_string()
                .contains("upstream: all upstreams failed")
        );
        let lookalike = NetError::from("upstream: but this is a validation message".to_owned());
        assert!(!is_transport(&lookalike), "a message is not a marker");
        let other_io = NetError::Io(Arc::new(std::io::Error::other("connection reset")));
        assert!(!is_transport(&other_io));
    }

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

    /// REQ: DNS-011, NFR-004 (review 03-05) — only `MAX_PROOFS` unsigned-zone proofs run at
    /// once (the next finds no slot), and a name that failed isn't walked again for a minute
    /// (other names are).
    #[test]
    fn dns_011_proofs_are_limited_and_failures_remembered() {
        let gate = ProofGate::default();
        let slots: Vec<_> = (0..MAX_PROOFS)
            .map(|i| gate.enter(&format!("n{i}.example")).expect("a free slot"))
            .collect();
        assert!(gate.enter("late.example").is_none(), "every slot is busy");
        drop(slots);
        assert!(gate.enter("late.example").is_some(), "slots come back");
        gate.failed("broken.example");
        assert!(gate.enter("broken.example").is_none(), "remembered");
        assert!(gate.enter("fine.example").is_some(), "other names are not");
        // Past its minute it may be tried again.
        gate.unproven
            .lock()
            .insert("broken.example".into(), std::time::Instant::now());
        assert!(gate.enter("broken.example").is_some());
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

    /// REQ: DNS-011 (RFC 4035 §5.3.4) — a wildcard's answer, built by hand: accepted with the
    /// signed zone's NSEC for the next closer name, and not when any part of that is missing.
    // One case per condition.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn dns_011_wildcard_answer_needs_its_proof() {
        use RecordType::{A, AAAA, NSEC as T_NSEC, RRSIG as T_RRSIG};
        use hickory_net::proto::dnssec::Algorithm;
        use hickory_net::proto::dnssec::Nsec3HashAlgorithm;
        use hickory_net::proto::dnssec::rdata::{RRSIG, SigInput};
        use hickory_net::proto::rr::SerialNumber;
        let n = |s: &str| Name::from_ascii(s).unwrap();
        let secure = |name: &str, data: RData| {
            let mut r = Record::from_rdata(n(name), 300, data);
            r.proof = Proof::Secure;
            r
        };
        let sig = |name: &str, covered: RecordType, labels: u8, signer: &str| {
            let input = SigInput {
                type_covered: covered,
                algorithm: Algorithm::ED25519,
                num_labels: labels,
                original_ttl: 300,
                sig_expiration: SerialNumber::new(2),
                sig_inception: SerialNumber::new(1),
                key_tag: 1,
                signer_name: n(signer),
            };
            secure(
                name,
                RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, vec![0]))),
            )
        };
        let address = || RData::A(hickory_net::proto::rr::rdata::A::new(192, 0, 2, 1));
        let nsec = |owner: &str, next: &str| {
            let data = NSEC::new(n(next), [A, T_RRSIG, T_NSEC]);
            secure(owner, RData::DNSSEC(DNSSECRData::NSEC(data)))
        };
        // `m.z.test.`, from `*.z.test.` (two labels), with `k`'s NSEC up to `p`.
        let good = || {
            let mut m = Message::response(0, OpCode::Query);
            m.answers = vec![
                secure("m.z.test.", address()),
                sig("m.z.test.", A, 2, "z.test."),
            ];
            m.authorities = vec![
                nsec("k.z.test.", "p.z.test."),
                sig("k.z.test.", T_NSEC, 3, "z.test."),
            ];
            m
        };
        let name = n("m.z.test.");
        assert!(wildcard_proven(&good(), &name, A));
        assert!(!wildcard_proven(&good(), &name, AAAA), "another type");
        assert!(
            !wildcard_proven(&good(), &n("l.z.test."), A),
            "another name"
        );
        let refused = |what: &str, change: &dyn Fn(&mut Message)| {
            let mut m = good();
            change(&mut m);
            assert!(!wildcard_proven(&m, &name, A), "{what}");
        };
        refused("NXDOMAIN", &|m| {
            m.metadata.response_code = ResponseCode::NXDomain;
        });
        refused("the address isn't secure", &|m| {
            m.answers[0].proof = Proof::Bogus;
        });
        refused("the signature isn't secure", &|m| {
            m.answers[1].proof = Proof::Indeterminate;
        });
        refused("no signature", &|m| {
            m.answers.pop();
        });
        refused("no address", &|m| {
            m.answers.remove(0);
        });
        refused("not a wildcard's signature", &|m| {
            m.answers[1] = sig("m.z.test.", A, 3, "z.test.");
        });
        refused("signatures of two wildcards", &|m| {
            m.answers.push(sig("m.z.test.", A, 1, "z.test."));
        });
        refused("signers of two zones", &|m| {
            m.answers.push(sig("m.z.test.", A, 2, "test."));
        });
        refused("a signer below the wildcard", &|m| {
            m.answers[1] = sig("m.z.test.", A, 1, "z.test.");
        });
        refused("a signer elsewhere", &|m| {
            m.answers[1] = sig("m.z.test.", A, 2, "y.test.");
        });
        refused("another record in the answer", &|m| {
            m.answers.push(secure("o.z.test.", address()));
        });
        refused("no NSEC", &|m| m.authorities.clear());
        refused("the NSEC isn't secure", &|m| {
            m.authorities[0].proof = Proof::Bogus;
        });
        refused("the NSEC isn't signed", &|m| {
            m.authorities.pop();
        });
        refused("the NSEC is another zone's", &|m| {
            m.authorities[1] = sig("k.z.test.", T_NSEC, 3, "test.");
        });
        refused("the NSEC doesn't cover the name", &|m| {
            m.authorities[0] = nsec("k.z.test.", "l.z.test.");
        });
        refused("an NSEC3 beside it", &|m| {
            let n3 = NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                0,
                Vec::new(),
                vec![0; 20],
                [A],
            );
            m.authorities
                .push(secure("x.z.test.", RData::DNSSEC(DNSSECRData::NSEC3(n3))));
        });
        refused("a signature of another type that isn't verified", &|m| {
            let mut extra = sig("m.z.test.", AAAA, 2, "z.test.");
            extra.proof = Proof::Indeterminate;
            m.answers.push(extra);
        });
        // RFC 6840 §5.4 — a second signature that isn't verified (a key or algorithm rollover) is
        // left out: neither its label count nor its signer counts, and it is no reason to refuse.
        // Without a verified one there is no proof ("the signature isn't secure", above).
        let unverified = |labels: u8, signer: &str, proof: Proof| {
            let mut m = good();
            let mut extra = sig("m.z.test.", A, labels, signer);
            extra.proof = proof;
            m.answers.push(extra);
            (labels, wildcard_proven(&m, &name, A))
        };
        assert_eq!(
            [
                unverified(2, "z.test.", Proof::Indeterminate),
                unverified(1, "test.", Proof::Indeterminate),
                unverified(3, "y.test.", Proof::Bogus),
            ],
            [(2, true), (1, true), (3, true)],
            "a second signature that isn't verified"
        );
        // Two labels below the wildcard: the NSEC must deny the one right below it.
        let deep = n("a.m.z.test.");
        let mut m = good();
        m.answers = vec![
            secure("a.m.z.test.", address()),
            sig("a.m.z.test.", A, 2, "z.test."),
        ];
        assert!(wildcard_proven(&m, &deep, A));
        m.authorities = vec![
            nsec("m.z.test.", "p.z.test."),
            sig("m.z.test.", T_NSEC, 3, "z.test."),
        ];
        assert!(
            !wildcard_proven(&m, &deep, A),
            "the name right below the wildcard exists"
        );
    }

    /// REQ: DNS-011 (RFC 4035 §5.3.4, RFC 6840 §4.1) — what an NSEC proves about the next closer
    /// name of a wildcard's answer.
    #[test]
    fn dns_011_nsec_covers_the_next_closer_name() {
        use RecordType::{A, DNAME, NS, NSEC as T_NSEC, RRSIG, SOA};
        let n = |s: &str| Name::from_ascii(s).unwrap();
        let zone = n("z.test.");
        let covers = |owner: &str, next: &str, types: &[RecordType], name: &str| {
            let nsec = NSEC::new(n(next), types.iter().copied());
            nsec_covers(&n(owner), &nsec, &zone, &n(name))
        };
        let plain = &[A, RRSIG, T_NSEC];
        assert!(covers("b.z.test.", "d.z.test.", plain, "c.z.test."));
        assert!(
            covers("B.z.test.", "D.z.test.", plain, "c.z.TEST."),
            "case doesn't matter"
        );
        // The zone's last NSEC points to the apex; another one doesn't wrap.
        assert!(covers("x.z.test.", "z.test.", plain, "y.z.test."));
        assert!(!covers("x.z.test.", "a.z.test.", plain, "y.z.test."));
        // The name itself exists, or is outside the span.
        assert!(!covers("c.z.test.", "d.z.test.", plain, "c.z.test."));
        assert!(!covers("b.z.test.", "c.z.test.", plain, "c.z.test."));
        assert!(!covers("b.z.test.", "d.z.test.", plain, "e.z.test."));
        assert!(!covers("x.z.test.", "z.test.", plain, "a.z.test."));
        // It exists as an empty non-terminal.
        assert!(!covers("b.z.test.", "x.c.z.test.", plain, "c.z.test."));
        // Another zone's records.
        assert!(!covers("b.y.test.", "d.y.test.", plain, "c.y.test."));
        assert!(!covers("y.test.", "zz.test.", plain, "c.z.test."));
        // Below a delegation or a DNAME the owner's zone says nothing; beside them it does.
        let cut = &[NS, RRSIG, T_NSEC];
        assert!(!covers("b.z.test.", "d.z.test.", cut, "a.b.z.test."));
        assert!(covers("b.z.test.", "d.z.test.", cut, "c.z.test."));
        assert!(!covers(
            "b.z.test.",
            "d.z.test.",
            &[DNAME, RRSIG, T_NSEC],
            "a.b.z.test."
        ));
        // The apex has NS and SOA: not a delegation.
        assert!(covers(
            "z.test.",
            "d.z.test.",
            &[NS, SOA, RRSIG, T_NSEC],
            "c.z.test."
        ));
    }

    /// REQ: DNS-011 (RFC 4035 §5.3.4, RFC 5155 §8.8; ADR-188) — the wildcard rule of zones signed
    /// with NSEC applies to an answer made from a wildcard (a secure signature over fewer labels
    /// than its owner has) unless a secure NSEC3 record of the zone that signed it, owned directly
    /// below that zone, is beside it: an NSEC3 record that isn't verified, or that is another
    /// zone's, doesn't switch the rule off.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn dns_011_wildcard_rule_is_left_to_nsec3_only_beside_the_signers_verified_nsec3() {
        use RecordType::A;
        use hickory_net::proto::dnssec::Algorithm;
        use hickory_net::proto::dnssec::Nsec3HashAlgorithm;
        use hickory_net::proto::dnssec::rdata::{RRSIG, SigInput};
        use hickory_net::proto::rr::SerialNumber;
        let owned = |owner: &str, data: RData, proof: Proof| {
            let mut r = Record::from_rdata(Name::from_ascii(owner).unwrap(), 300, data);
            r.proof = proof;
            r
        };
        let sig = |labels: u8, signer: &str, proof: Proof| {
            let input = SigInput {
                type_covered: A,
                algorithm: Algorithm::ED25519,
                num_labels: labels,
                original_ttl: 300,
                sig_expiration: SerialNumber::new(2),
                sig_inception: SerialNumber::new(1),
                key_tag: 1,
                signer_name: Name::from_ascii(signer).unwrap(),
            };
            let data = RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, vec![0])));
            owned("m.z.test.", data, proof)
        };
        let nsec3 = |owner: &str, proof: Proof| {
            let data = NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                0,
                Vec::new(),
                vec![0; 20],
                [A],
            );
            owned(owner, RData::DNSSEC(DNSSECRData::NSEC3(data)), proof)
        };
        // `m.z.test. A` with the given signatures, and the authority section.
        let answer = |sigs: Vec<Record>, authorities: Vec<Record>| {
            let address = RData::A(hickory_net::proto::rr::rdata::A::new(192, 0, 2, 1));
            let mut msg = Message::response(0, OpCode::Query);
            msg.answers = vec![owned("m.z.test.", address, Proof::Secure)];
            msg.answers.extend(sigs);
            msg.authorities = authorities;
            msg
        };
        let wildcard = || vec![sig(2, "z.test.", Proof::Secure)];
        let beside = |owner: &str, proof: Proof| answer(wildcard(), vec![nsec3(owner, proof)]);
        let cases = [
            ("no NSEC3", answer(wildcard(), Vec::new()), true),
            (
                "a verified NSEC3 of the signer's zone",
                beside("h.z.test.", Proof::Secure),
                false,
            ),
            (
                "the same, in capitals",
                beside("H.Z.TEST.", Proof::Secure),
                false,
            ),
            (
                "an NSEC3 that isn't verified",
                beside("h.z.test.", Proof::Indeterminate),
                true,
            ),
            ("a bogus NSEC3", beside("h.z.test.", Proof::Bogus), true),
            (
                "an insecure NSEC3",
                beside("h.z.test.", Proof::Insecure),
                true,
            ),
            (
                "a verified NSEC3 of the parent zone",
                beside("h.test.", Proof::Secure),
                true,
            ),
            (
                "a verified NSEC3 of another zone",
                beside("h.y.test.", Proof::Secure),
                true,
            ),
            (
                "a verified NSEC3 further below the signer",
                beside("h.k.z.test.", Proof::Secure),
                true,
            ),
            (
                "two signers, a verified NSEC3 of one",
                answer(
                    vec![
                        sig(2, "z.test.", Proof::Secure),
                        sig(1, "test.", Proof::Secure),
                    ],
                    vec![nsec3("h.z.test.", Proof::Secure)],
                ),
                true,
            ),
            (
                "not a wildcard's signature",
                answer(vec![sig(3, "z.test.", Proof::Secure)], Vec::new()),
                false,
            ),
            (
                "a wildcard's signature that isn't verified",
                answer(vec![sig(2, "z.test.", Proof::Indeterminate)], Vec::new()),
                false,
            ),
        ];
        let got: Vec<(&str, bool)> = cases
            .iter()
            .map(|(what, msg, _)| (*what, nsec_wildcard_answer(msg)))
            .collect();
        let want: Vec<(&str, bool)> = cases
            .iter()
            .map(|(what, _, applies)| (*what, *applies))
            .collect();
        assert_eq!(got, want);
    }

    /// REQ: DNS-011 (RFC 4035 §5.3.4; ADR-188) — a wildcard CNAME at the question name, for a
    /// question of another type, is checked as the CNAME's own record set when no record of another
    /// name in the answer is made from a wildcard: its verified signatures, and the zone's NSEC for
    /// its next closer name. The rest of the chain are records of names that exist, and the chain
    /// ends in a record of the question's type (a chain that stops short, or loops, doesn't).
    #[test]
    #[allow(clippy::too_many_lines)]
    fn dns_011_wildcard_cname_is_checked_as_its_own_record_set() {
        use RecordType::{A, AAAA, CNAME as T_CNAME, NSEC as T_NSEC, RRSIG as T_RRSIG};
        use hickory_net::proto::dnssec::Algorithm;
        use hickory_net::proto::dnssec::rdata::{RRSIG, SigInput};
        use hickory_net::proto::rr::SerialNumber;
        use hickory_net::proto::rr::rdata::CNAME;
        let n = |s: &str| Name::from_ascii(s).unwrap();
        let secure = |name: &str, data: RData| {
            let mut r = Record::from_rdata(n(name), 300, data);
            r.proof = Proof::Secure;
            r
        };
        let sig = |name: &str, covered: RecordType, labels: u8, signer: &str| {
            let input = SigInput {
                type_covered: covered,
                algorithm: Algorithm::ED25519,
                num_labels: labels,
                original_ttl: 300,
                sig_expiration: SerialNumber::new(2),
                sig_inception: SerialNumber::new(1),
                key_tag: 1,
                signer_name: n(signer),
            };
            secure(
                name,
                RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, vec![0]))),
            )
        };
        let address = || RData::A(hickory_net::proto::rr::rdata::A::new(192, 0, 2, 1));
        let alias = |owner: &str, target: &str| secure(owner, RData::CNAME(CNAME(n(target))));
        let nsec = |owner: &str, next: &str| {
            let data = NSEC::new(n(next), [T_CNAME, T_RRSIG, T_NSEC]);
            secure(owner, RData::DNSSEC(DNSSECRData::NSEC(data)))
        };
        // `m.z.test. CNAME t.z.test.` from `*.z.test.` (two labels), then `t.z.test. A`, with `k`'s
        // NSEC up to `p`.
        let good = || {
            let mut msg = Message::response(0, OpCode::Query);
            msg.answers = vec![
                secure("m.z.test.", RData::CNAME(CNAME(n("t.z.test.")))),
                sig("m.z.test.", T_CNAME, 2, "z.test."),
                secure("t.z.test.", address()),
                sig("t.z.test.", A, 3, "z.test."),
            ];
            msg.authorities = vec![
                nsec("k.z.test.", "p.z.test."),
                sig("k.z.test.", T_NSEC, 3, "z.test."),
            ];
            msg
        };
        let name = n("m.z.test.");
        assert!(
            !wildcard_proven(&good(), &name, A),
            "not the question's one record set"
        );
        let checked = |what: &'static str, rtype: RecordType, change: &dyn Fn(&mut Message)| {
            let mut msg = good();
            change(&mut msg);
            (what, wildcard_cname_proven(&msg, &name, rtype))
        };
        let got = [
            checked("the CNAME with its proof", A, &|_| {}),
            checked("for another type", AAAA, &|msg| {
                let aaaa =
                    hickory_net::proto::rr::rdata::AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
                msg.answers[2] = secure("t.z.test.", RData::AAAA(aaaa));
                msg.answers[3] = sig("t.z.test.", AAAA, 3, "z.test.");
            }),
            checked("a type the chain doesn't end in", AAAA, &|_| {}),
            checked("the target's records left out", A, &|msg| {
                msg.answers.truncate(2);
            }),
            checked("a chain that stops after its second link", A, &|msg| {
                msg.answers.truncate(2);
                msg.answers[0] = alias("m.z.test.", "t1.z.test.");
                msg.answers.push(alias("t1.z.test.", "t2.z.test."));
                msg.answers.push(sig("t1.z.test.", T_CNAME, 3, "z.test."));
            }),
            checked("a chain of two links that ends in the type", A, &|msg| {
                msg.answers.truncate(2);
                msg.answers[0] = alias("m.z.test.", "t1.z.test.");
                msg.answers.push(alias("t1.z.test.", "t2.z.test."));
                msg.answers.push(sig("t1.z.test.", T_CNAME, 3, "z.test."));
                msg.answers.push(secure("t2.z.test.", address()));
                msg.answers.push(sig("t2.z.test.", A, 3, "z.test."));
            }),
            checked("a CNAME loop", A, &|msg| {
                msg.answers.truncate(2);
                msg.answers.push(alias("t.z.test.", "m.z.test."));
                msg.answers.push(sig("t.z.test.", T_CNAME, 3, "z.test."));
            }),
            checked("a CNAME loop with an address beside it", A, &|msg| {
                msg.answers.push(alias("t.z.test.", "m.z.test."));
                msg.answers.push(sig("t.z.test.", T_CNAME, 3, "z.test."));
            }),
            checked("a second signature that isn't verified", A, &|msg| {
                let mut extra = sig("m.z.test.", T_CNAME, 1, "test.");
                extra.proof = Proof::Indeterminate;
                msg.answers.push(extra);
            }),
            checked("a question for the CNAME itself", T_CNAME, &|_| {}),
            checked("the target made from a wildcard", A, &|msg| {
                msg.answers[3] = sig("t.z.test.", A, 2, "z.test.");
            }),
            checked("no NSEC", A, &|msg| msg.authorities.clear()),
            checked("the NSEC doesn't cover the next closer name", A, &|msg| {
                msg.authorities[0] = nsec("k.z.test.", "l.z.test.");
            }),
            checked("another record at the name", A, &|msg| {
                msg.answers.push(secure("m.z.test.", address()));
            }),
            checked("the CNAME isn't verified", A, &|msg| {
                msg.answers[0].proof = Proof::Bogus;
            }),
            checked("its signature isn't verified", A, &|msg| {
                msg.answers[1].proof = Proof::Indeterminate;
            }),
            checked("not a wildcard's CNAME", A, &|msg| {
                msg.answers[1] = sig("m.z.test.", T_CNAME, 3, "z.test.");
            }),
        ];
        let want = [
            ("the CNAME with its proof", true),
            ("for another type", true),
            ("a type the chain doesn't end in", false),
            ("the target's records left out", false),
            ("a chain that stops after its second link", false),
            ("a chain of two links that ends in the type", true),
            ("a CNAME loop", false),
            ("a CNAME loop with an address beside it", false),
            ("a second signature that isn't verified", true),
            ("a question for the CNAME itself", false),
            ("the target made from a wildcard", false),
            ("no NSEC", false),
            ("the NSEC doesn't cover the next closer name", false),
            ("another record at the name", false),
            ("the CNAME isn't verified", false),
            ("its signature isn't verified", false),
            ("not a wildcard's CNAME", false),
        ];
        assert_eq!(got, want);
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
            &[nsec("child.example.", &[NS, RRSIG, T_NSEC])],
            &apex
        ));
        assert!(
            !denies_ds_at_cut(&[nsec("child.example.", &[A, RRSIG, T_NSEC])], &apex),
            "a name inside the zone, not a cut"
        );
        assert!(
            !denies_ds_at_cut(&[nsec("child.example.", &[NS, SOA, T_NSEC])], &apex),
            "the child's own NSEC"
        );
        assert!(
            !denies_ds_at_cut(&[nsec("child.example.", &[NS, DS, T_NSEC])], &apex),
            "a signed delegation"
        );
        assert!(
            !denies_ds_at_cut(&[nsec("other.example.", &[NS, T_NSEC])], &apex),
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
            &[nsec3(&owner, &[NS, RRSIG, T_NSEC3])],
            &apex
        ));
        assert!(!denies_ds_at_cut(
            &[nsec3(&owner, &[A, RRSIG, T_NSEC3])],
            &apex
        ));
        let wrong = Name::from_ascii("0123456789abcdefghijklmnopqrstuv.example.").unwrap();
        assert!(
            !denies_ds_at_cut(&[nsec3(&wrong, &[NS, T_NSEC3])], &apex),
            "another name's hash"
        );
    }

    /// REQ: DNS-011 (ADR-098) — RFC 5155 §8.6: in an Opt-Out zone, a DS NODATA with the
    /// closest-encloser proof (parent matched) and an Opt-Out NSEC3 covering the apex proves an
    /// unsigned delegation; every part of that proof is required.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn dns_011_ds_denial_by_nsec3_opt_out() {
        use RecordType::{NS, NSEC3 as T_NSEC3, RRSIG, SOA};
        use hickory_net::proto::dnssec::Nsec3HashAlgorithm;
        use hickory_net::proto::dnssec::rdata::NSEC3;
        let salt: &[u8] = b"";
        let apex = Name::from_ascii("smithsonianmag.org.").unwrap();
        let parent = Name::from_ascii("org.").unwrap();
        let h = |n: &Name| Nsec3HashAlgorithm::SHA1.hash(salt, n, 0).unwrap();
        let (apex_h, parent_h) = (h(&apex), h(&parent));
        // A raw hash next to `apex`'s, one step either way (the span that covers it).
        let step = |d: &[u8], up: bool| {
            let mut v = d.to_vec();
            for b in v.iter_mut().rev() {
                if up {
                    *b = b.wrapping_add(1);
                    if *b != 0 {
                        break;
                    }
                } else {
                    *b = b.wrapping_sub(1);
                    if *b != 0xff {
                        break;
                    }
                }
            }
            v
        };
        let rec = |owner_hash: &[u8], next: Vec<u8>, opt_out: bool, types: &[RecordType], proof| {
            let n = NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                opt_out,
                0,
                salt.to_vec(),
                next,
                types.iter().copied(),
            );
            let owner = Name::from_ascii(format!("{}.org.", base32hex(owner_hash))).unwrap();
            let mut r = Record::from_rdata(owner, 300, RData::DNSSEC(DNSSECRData::NSEC3(n)));
            r.proof = proof;
            r
        };
        let below = step(apex_h.as_ref(), false);
        let above = step(apex_h.as_ref(), true);
        // The parent's own NSEC3 (the closest encloser): without Opt-Out, and with a span that
        // ends at the next hash, so that it covers neither name here whatever their hashes are.
        let encloser_next = step(parent_h.as_ref(), true);
        let encloser = rec(
            parent_h.as_ref(),
            encloser_next.clone(),
            false,
            &[NS, SOA, RRSIG, T_NSEC3],
            Proof::Secure,
        );
        for name in [&apex, &Name::from_ascii("other.org.").unwrap()] {
            assert!(
                !hash_range_covers(parent_h.as_ref(), &encloser_next, h(name).as_ref()),
                "the encloser alone covers {name}"
            );
        }
        assert!(
            !denies_ds_by_opt_out(std::slice::from_ref(&encloser), &apex),
            "the encloser alone is no proof"
        );
        let covering = |opt_out, proof| rec(&below, above.clone(), opt_out, &[NS], proof);

        assert!(
            denies_ds_by_opt_out(&[encloser.clone(), covering(true, Proof::Secure)], &apex),
            "closest encloser + opt-out span: an unsigned delegation"
        );
        assert!(
            !denies_ds_by_opt_out(&[encloser.clone(), covering(false, Proof::Secure)], &apex),
            "a covering NSEC3 without Opt-Out proves the name doesn't exist, not an unsigned cut"
        );
        assert!(
            !denies_ds_by_opt_out(&[covering(true, Proof::Secure)], &apex),
            "no closest-encloser proof"
        );
        assert!(
            !denies_ds_by_opt_out(&[encloser.clone(), covering(true, Proof::Bogus)], &apex),
            "the span must validate"
        );
        let elsewhere = rec(&above, step(&above, true), true, &[NS], Proof::Secure);
        assert!(
            !denies_ds_by_opt_out(&[encloser.clone(), elsewhere], &apex),
            "an opt-out span that doesn't cover the apex"
        );
        assert!(
            !denies_ds_by_opt_out(
                &[encloser, covering(true, Proof::Secure)],
                &Name::from_ascii("other.org.").unwrap()
            ),
            "another name's span"
        );
    }

    /// REQ: DNS-011 (ADR-098, ADR-184) — a span covers the hashes strictly between its owner's
    /// and the next owner's, compared as bytes; the chain's last NSEC3 wraps around to the
    /// first.
    #[test]
    fn dns_011_hash_range_covers() {
        assert!(hash_range_covers(&[0xf0], &[0x10], &[0xf5]));
        assert!(hash_range_covers(&[0xf0], &[0x10], &[0x05]));
        assert!(!hash_range_covers(&[0xf0], &[0x10], &[0x50]));
        assert!(hash_range_covers(&[0x10], &[0xf0], &[0x50]));
        assert!(
            !hash_range_covers(&[0x10], &[0xf0], &[0x10]),
            "the owner itself isn't covered"
        );
        assert!(
            !hash_range_covers(&[0x10], &[0xf0], &[0xf0]),
            "nor the next owner"
        );
        // A chain of one record covers every hash but its own.
        assert!(hash_range_covers(&[0x10], &[0x10], &[0x50]));
        assert!(!hash_range_covers(&[0x10], &[0x10], &[0x10]));
        assert!(
            !hash_range_covers(&[0x10], &[0xf0], &[0x50, 0]),
            "hashes of another length"
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

/// REQ: DNS-011 (ADR-098, ADR-184) — what a DS answer proves ([`ds_denial_verdict`]), on
/// records built by hand. NSEC3 records use SHA-1 with no salt and no extra iterations (as
/// `.com` and `.org` do) unless a test says otherwise; each carries the proof the validating
/// handle would have given it.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod ds_proof_tests {
    use super::*;
    use RecordType::{A, DNSKEY, NS, NSEC3PARAM, RRSIG, SOA};
    use hickory_net::proto::dnssec::Nsec3HashAlgorithm;
    use hickory_net::proto::dnssec::rdata::NSEC3;

    /// What an apex's own NSEC3 lists.
    const APEX: &[RecordType] = &[NS, SOA, DNSKEY, NSEC3PARAM, RRSIG];

    fn name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn hash_with(n: &str, salt: &[u8], iterations: u16) -> Vec<u8> {
        Nsec3HashAlgorithm::SHA1
            .hash(salt, &name(n), iterations)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    fn h(n: &str) -> Vec<u8> {
        hash_with(n, &[], 0)
    }

    /// The hash one step above or below `hash`.
    fn step(hash: &[u8], up: bool) -> Vec<u8> {
        let mut v = hash.to_vec();
        for b in v.iter_mut().rev() {
            if up {
                *b = b.wrapping_add(1);
                if *b != 0 {
                    break;
                }
            } else {
                *b = b.wrapping_sub(1);
                if *b != 0xff {
                    break;
                }
            }
        }
        v
    }

    /// A secure NSEC3 owned by `hash` under `zone`, with the given hash parameters.
    fn nsec3_with(
        zone: &str,
        hash: &[u8],
        next: Vec<u8>,
        opt_out: bool,
        types: &[RecordType],
        (salt, iterations): (&[u8], u16),
    ) -> Record {
        let n = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            opt_out,
            iterations,
            salt.to_vec(),
            next,
            types.iter().copied(),
        );
        let owner = name(&format!("{}.{zone}", base32hex(hash)));
        let mut r = Record::from_rdata(owner, 300, RData::DNSSEC(DNSSECRData::NSEC3(n)));
        r.proof = Proof::Secure;
        r
    }

    fn nsec3(
        zone: &str,
        hash: &[u8],
        next: Vec<u8>,
        opt_out: bool,
        types: &[RecordType],
    ) -> Record {
        nsec3_with(zone, hash, next, opt_out, types, (&[], 0))
    }

    /// The NSEC3 matching `owner` in `zone`; its span ends at the next hash, so it covers nothing.
    fn matching(zone: &str, owner: &str, types: &[RecordType]) -> Record {
        let hash = h(owner);
        nsec3(zone, &hash, step(&hash, true), true, types)
    }

    /// An Opt-Out NSEC3 in `zone` whose span covers `n`'s hash and its neighbours only.
    fn span(zone: &str, n: &str) -> Record {
        let hash = h(n);
        nsec3(zone, &step(&hash, false), step(&hash, true), true, &[NS])
    }

    fn soa(owner: &str, proof: Proof) -> Record {
        let data = RData::SOA(hickory_net::proto::rr::rdata::SOA::new(
            name("ns.example."),
            name("admin.example."),
            1,
            1800,
            900,
            604_800,
            300,
        ));
        let mut r = Record::from_rdata(name(owner), 300, data);
        r.proof = proof;
        r
    }

    /// A NOERROR answer to a DS question with nothing in the answer section.
    fn nodata(authorities: Vec<Record>) -> Message {
        let mut m = Message::response(1, OpCode::Query);
        m.authorities = authorities;
        m
    }

    /// What a response with these authority records proves about `apex`.
    fn proves(authorities: Vec<Record>, apex: &str) -> Option<bool> {
        ds_denial_verdict(DsAnswer::Response(&nodata(authorities)), &name(apex))
    }

    /// REQ: DNS-011 (ADR-184) — the `.org` shape: `org.`'s SOA, its apex NSEC3 (the closest
    /// encloser of `smithsonianmag.org.`) and an Opt-Out NSEC3 covering the name's hash, all
    /// `org.`'s, prove an unsigned delegation; so do the same without the SOA, one record
    /// doing both jobs (the apex record's own span reaches past the name), and an ordinary
    /// name of the parent zone as the closest encloser (`b.org.` for `a.b.org.`).
    #[test]
    fn dns_011_opt_out_accepts_parent_apex_and_span() {
        let apex = "smithsonianmag.org.";
        let encloser = matching("org.", "org.", APEX);
        assert_eq!(
            proves(
                vec![
                    soa("org.", Proof::Secure),
                    encloser.clone(),
                    span("org.", apex)
                ],
                apex
            ),
            Some(false)
        );
        assert_eq!(
            proves(vec![encloser, span("org.", apex)], apex),
            Some(false),
            "without the SOA"
        );
        let wide = nsec3("org.", &h("org."), step(&h(apex), true), true, APEX);
        assert_eq!(
            proves(vec![soa("org.", Proof::Secure), wide], apex),
            Some(false),
            "one record for both"
        );
        assert_eq!(
            proves(
                vec![
                    soa("org.", Proof::Secure),
                    matching("org.", "b.org.", &[A, RRSIG]),
                    span("org.", "a.b.org.")
                ],
                "a.b.org."
            ),
            Some(false),
            "an ordinary name as the closest encloser"
        );
    }

    /// REQ: DNS-011 (ADR-184) — fails closed when the closest provable encloser is above the
    /// delegation's parent name (RFC 5155 §8.6 allows that, through an Opt-Out empty
    /// non-terminal): `b.org.` has no NSEC3 here, so `a.b.org.` isn't proven unsigned.
    #[test]
    fn dns_011_opt_out_closest_encloser_above_parent_is_not_proof() {
        let apex = "a.b.org.";
        let records = vec![
            soa("org.", Proof::Secure),
            matching("org.", "org.", APEX),
            span("org.", "b.org."),
            span("org.", apex),
        ];
        assert_eq!(proves(records, apex), None);
    }

    /// REQ: DNS-011 (ADR-184) — NSEC3 hashes: RFC 5155 Appendix A (salt `aabbccdd`, 12
    /// iterations), and an owner label read back as the hash it encodes, in either case
    /// (RFC 4648 §10's vectors too); anything that isn't base32hex is no hash.
    #[test]
    fn dns_011_nsec3_hash_rfc5155_vectors() {
        let salt = [0xaa, 0xbb, 0xcc, 0xdd];
        for (n, want) in [
            ("example.", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
            ("a.example.", "35mthgpgcu1qg68fab165klnsnk3dpvl"),
        ] {
            let hash = hash_with(n, &salt, 12);
            assert_eq!(base32hex(&hash), want, "H({n})");
            assert_eq!(base32hex_decode(want.as_bytes()), Some(hash.clone()));
            let upper = want.to_ascii_uppercase();
            assert_eq!(base32hex_decode(upper.as_bytes()), Some(hash));
        }
        for (data, text) in [
            (&b""[..], ""),
            (b"f", "co"),
            (b"fo", "cpng"),
            (b"foo", "cpnmu"),
            (b"foob", "cpnmuog"),
            (b"fooba", "cpnmuoj1"),
            (b"foobar", "cpnmuoj1e8"),
        ] {
            assert_eq!(
                base32hex_decode(text.as_bytes()),
                Some(data.to_vec()),
                "{text}"
            );
        }
        assert_eq!(base32hex_decode(b"0p9mhave-"), None, "not base32hex");
        assert_eq!(base32hex_decode(b"0w"), None, "w isn't base32hex");
        assert_eq!(base32hex_decode(b"cp"), None, "trailing bits set");
    }

    /// One case: what it is, the authority records, what they should prove.
    type Case = (&'static str, Vec<Record>, Option<bool>);

    /// The cases whose verdict for `apex` isn't what it should be (all of them are checked,
    /// so a failure lists every case that is wrong).
    fn wrong(apex: &str, cases: Vec<Case>) -> Vec<&'static str> {
        cases
            .into_iter()
            .filter(|(_, records, want)| proves(records.clone(), apex) != *want)
            .map(|(what, ..)| what)
            .collect()
    }

    /// REQ: DNS-011 (ADR-184) — the NSEC3 matching the closest encloser must not be a
    /// delegation's (NS without SOA, or DNAME; RFC 6840 §4.1): the parent's record at
    /// `bank.test.` says only that `bank.test.` is delegated, nothing about names below it.
    #[test]
    fn dns_011_opt_out_rejects_delegation_nsec3_as_encloser() {
        use RecordType::{DNAME, DS};
        let apex = "www.bank.test.";
        let with = |types: &[RecordType]| {
            vec![
                soa("test.", Proof::Secure),
                matching("test.", "bank.test.", types),
                span("test.", apex),
            ]
        };
        let cases = vec![
            ("an ordinary name: a proof", with(&[A, RRSIG]), Some(false)),
            ("a signed delegation's record", with(&[NS, DS, RRSIG]), None),
            ("an unsigned delegation's record", with(&[NS, RRSIG]), None),
            ("a DNAME", with(&[DNAME, RRSIG]), None),
        ];
        assert_eq!(wrong(apex, cases), Vec::<&str>::new());
    }

    /// REQ: DNS-011 (ADR-184) — every NSEC3 of the proof is owned under one zone, a proper
    /// ancestor of the delegation, with one set of hash parameters; an SOA in the answer is
    /// that zone's.
    #[test]
    fn dns_011_opt_out_requires_one_parent_zone() {
        let apex = "shop.example.";
        let encloser = |zone: &str| {
            let hash = h("example.");
            nsec3(zone, &hash, step(&hash, true), true, APEX)
        };
        let soa_ex = || soa("example.", Proof::Secure);
        let ok = vec![soa_ex(), encloser("example."), span("example.", apex)];
        let mut extra = ok.clone();
        extra.push(span("other.test.", "x.other.test."));
        // A span around the name's hash as the other records compute it, but with another salt.
        let salted = {
            let hash = h(apex);
            let (from, to) = (step(&hash, false), step(&hash, true));
            nsec3_with("example.", &from, to, true, &[NS], (&[0xab], 0))
        };
        let cases = vec![
            ("all of example.: a proof", ok, Some(false)),
            (
                "two zones",
                vec![encloser("example."), span("other.test.", apex)],
                None,
            ),
            (
                "a zone that isn't above the name",
                vec![encloser("other.test."), span("other.test.", apex)],
                None,
            ),
            (
                "under the name itself",
                vec![encloser("shop.example."), span("shop.example.", apex)],
                None,
            ),
            (
                "another zone's SOA",
                vec![
                    soa("other.test.", Proof::Secure),
                    encloser("example."),
                    span("example.", apex),
                ],
                None,
            ),
            ("an NSEC3 of another zone besides", extra, None),
            (
                "two sets of hash parameters",
                vec![soa_ex(), encloser("example."), salted],
                None,
            ),
        ];
        assert_eq!(wrong(apex, cases), Vec::<&str>::new());
    }

    /// REQ: DNS-011 (ADR-184) — when the parent zone has an NSEC3 matching the name itself,
    /// that record alone decides (the cut test), whatever span claims to cover the same hash.
    #[test]
    fn dns_011_opt_out_rejected_when_apex_has_own_nsec3() {
        use RecordType::DS;
        let apex = "shop.example.";
        let base = vec![
            soa("example.", Proof::Secure),
            matching("example.", "example.", APEX),
            span("example.", apex),
        ];
        let with = |types: &[RecordType]| {
            let mut v = base.clone();
            v.push(matching("example.", apex, types));
            v
        };
        let cases = vec![
            ("without it: a proof", base.clone(), Some(false)),
            ("an ordinary name", with(&[A, RRSIG]), None),
            ("a signed delegation", with(&[NS, DS, RRSIG]), None),
            ("an unsigned delegation", with(&[NS, RRSIG]), Some(false)),
        ];
        assert_eq!(wrong(apex, cases), Vec::<&str>::new());
    }

    /// REQ: DNS-011 (ADR-184) — the NSEC3 that shows the cut (NS, neither SOA nor DS, at the
    /// name's hash) must be the parent zone's: not a record with that hash as its first label
    /// under another zone, and not next to another zone's records.
    #[test]
    fn dns_011_cut_nsec3_must_be_in_parent_zone() {
        let apex = "www.bank.test.";
        let cut = |zone: &str| matching(zone, apex, &[NS, RRSIG]);
        let cases = vec![
            (
                "the parent zone's record: a proof",
                vec![soa("bank.test.", Proof::Secure), cut("bank.test.")],
                Some(false),
            ),
            ("another zone's", vec![cut("other.test.")], None),
            ("under the name itself", vec![cut("www.bank.test.")], None),
            (
                "an ordinary name's record, and a cut from another zone",
                vec![
                    matching("bank.test.", apex, &[A, RRSIG]),
                    cut("other.test."),
                ],
                None,
            ),
            (
                "another zone's SOA",
                vec![soa("other.test.", Proof::Secure), cut("bank.test.")],
                None,
            ),
        ];
        assert_eq!(wrong(apex, cases), Vec::<&str>::new());
    }

    /// REQ: DNS-011 (ADR-184) — an answer the validating handle calls insecure proves an
    /// unsigned zone only through an insecure record of an unsigned top-level domain: the
    /// name's own top-level domain, or the name itself when it has one label.
    #[test]
    fn dns_011_insecure_denial_needs_unsigned_tld() {
        let only = |owner: &str| vec![soa(owner, Proof::Insecure)];
        let apex = "bank.test.";
        let cases = vec![
            ("the name's top-level domain", only("test."), Some(false)),
            ("the name's own", only("bank.test."), None),
            ("an unrelated zone's", only("other.example."), None),
            ("an unrelated top-level domain's", only("other."), None),
            ("a name below", only("www.bank.test."), None),
            (
                "an unrelated zone's, next to secure records",
                vec![soa("other.example.", Proof::Insecure), span("test.", apex)],
                None,
            ),
            (
                "the top-level domain's signed SOA, next to an unrelated unsigned record",
                vec![
                    soa("test.", Proof::Secure),
                    soa("other.example.", Proof::Insecure),
                ],
                None,
            ),
        ];
        let deeper = vec![
            (
                "a deeper name: a two-label zone above it",
                only("bank.test."),
                None,
            ),
            (
                "a deeper name: a three-label zone above it",
                only("www.bank.test."),
                None,
            ),
            (
                "a deeper name: its top-level domain",
                only("test."),
                Some(false),
            ),
        ];
        let tld = vec![("a top-level domain: its own", only("xx."), Some(false))];
        let wildcard = vec![(
            "a wildcard below a top-level domain: its own (two labels)",
            only("*.com."),
            None,
        )];
        let mut all = wrong(apex, cases);
        all.extend(wrong("a.www.bank.test.", deeper));
        all.extend(wrong("xx.", tld));
        all.extend(wrong("*.com.", wildcard));
        assert_eq!(all, Vec::<&str>::new());
    }

    /// REQ: DNS-011 (ADR-184) — a negative answer the validating handle returns as an error with
    /// its proof (`DsAnswer::Denial`) proves nothing, whatever the proof and the records: that
    /// arm returns `None` for every one.
    #[test]
    fn dns_011_ds_denial_returned_as_error_is_not_proof() {
        let apex = name("shop.example.");
        // Records that prove an unsigned delegation in an ordinary response.
        let m = nodata(vec![
            soa("example.", Proof::Secure),
            matching("example.", "example.", APEX),
            span("example.", "shop.example."),
        ]);
        let all = [
            Proof::Secure,
            Proof::Insecure,
            Proof::Bogus,
            Proof::Indeterminate,
        ];
        let wrong: Vec<_> = all
            .into_iter()
            .filter(|&proof| {
                ds_denial_verdict(
                    DsAnswer::Denial {
                        proof,
                        response: &m,
                    },
                    &apex,
                )
                .is_some()
            })
            .collect();
        assert_eq!(wrong, Vec::<Proof>::new());
    }

    /// REQ: DNS-011 (ADR-184) — the proof reads NSEC3 records with at most 100 iterations
    /// (RFC 9276 §3.2); records with more prove nothing, for the cut check and the Opt-Out rule
    /// alike.
    #[test]
    fn dns_011_nsec3_iteration_cap_is_not_proof() {
        let cut = |iterations: u16| {
            let hash = hash_with("www.bank.test.", &[], iterations);
            let next = step(&hash, true);
            vec![
                soa("bank.test.", Proof::Secure),
                nsec3_with(
                    "bank.test.",
                    &hash,
                    next,
                    false,
                    &[NS, RRSIG],
                    (&[], iterations),
                ),
            ]
        };
        let cases = vec![
            ("a cut, 100 iterations", cut(100), Some(false)),
            ("a cut, 101 iterations", cut(101), None),
        ];
        let mut all = wrong("www.bank.test.", cases);
        let opt_out = |iterations: u16| {
            let (parent, apex) = (
                hash_with("example.", &[], iterations),
                hash_with("shop.example.", &[], iterations),
            );
            let params = (&[][..], iterations);
            vec![
                soa("example.", Proof::Secure),
                nsec3_with("example.", &parent, step(&parent, true), true, APEX, params),
                nsec3_with(
                    "example.",
                    &step(&apex, false),
                    step(&apex, true),
                    true,
                    &[NS],
                    params,
                ),
            ]
        };
        let cases = vec![
            ("an Opt-Out span, 100 iterations", opt_out(100), Some(false)),
            ("an Opt-Out span, 101 iterations", opt_out(101), None),
        ];
        all.extend(wrong("shop.example.", cases));
        assert_eq!(all, Vec::<&str>::new());
    }

    /// REQ: DNS-011 (ADR-184) — the proof hashes each name once, however many NSEC3 records the
    /// answer holds (they share one set of parameters): the name for the cut check, the name
    /// and its parent for the Opt-Out rule.
    #[test]
    fn dns_011_proof_hashes_each_name_once() {
        let apex = "www.bank.test.";
        let hash = h(apex);
        let mut records = vec![soa("bank.test.", Proof::Secure)];
        for i in 0..40 {
            records.push(span("bank.test.", &format!("n{i}.bank.test.")));
        }
        records.push(nsec3(
            "bank.test.",
            &hash,
            step(&hash, true),
            false,
            &[NS, RRSIG],
        ));
        let count = |f: &dyn Fn() -> bool| {
            NSEC3_HASHES.with(|c| c.set(0));
            let proven = f();
            (proven, NSEC3_HASHES.with(std::cell::Cell::get))
        };
        assert_eq!(
            count(&|| denies_ds_at_cut(&records, &name(apex))),
            (true, 1),
            "the cut check"
        );
        assert_eq!(
            count(&|| denies_ds_by_opt_out(&records, &name(apex))),
            (false, 2),
            "the Opt-Out rule (the name has an NSEC3 of its own: the cut check decides)"
        );
    }

    /// REQ: DNS-011 (ADR-184) — a zone proven unsigned is remembered for the smallest TTL of the
    /// records that proved it, 15 minutes at most, and for the group that proved it only.
    #[test]
    fn dns_011_proven_zone_is_remembered_for_its_proof_ttl() {
        let v = Validator::new(&[], Arc::default());
        let t0 = std::time::Instant::now();
        let at = |secs| t0 + Duration::from_secs(secs);
        v.remember_insecure_at(1, "u.test".into(), Duration::from_mins(5), t0);
        assert!(
            v.known_insecure_at(1, "www.u.test", at(299)),
            "within its TTL"
        );
        assert!(
            !v.known_insecure_at(1, "www.u.test", at(300)),
            "not past it"
        );
        assert!(
            !v.known_insecure_at(2, "www.u.test", at(1)),
            "another group"
        );
        v.remember_insecure_at(1, "v.test".into(), Duration::from_hours(24), t0);
        assert!(v.known_insecure_at(1, "www.v.test", at(899)), "a day's TTL");
        assert!(
            !v.known_insecure_at(1, "www.v.test", at(900)),
            "capped at 15 minutes"
        );
        // The TTL is the smallest of the answer's authority records.
        let with_ttl = |ttl| {
            let mut r = soa("test.", Proof::Secure);
            r.ttl = ttl;
            r
        };
        let mut m = Message::response(1, OpCode::Query);
        m.authorities = vec![with_ttl(900), with_ttl(300), with_ttl(3600)];
        assert_eq!(proof_ttl(&m), Duration::from_mins(5));
        assert_eq!(
            proof_ttl(&Message::response(2, OpCode::Query)),
            Duration::ZERO,
            "no records: nothing to remember"
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

    // REQ: DNS-011 — the validator's record sets come back in any order; the answer is
    // served in resolution order (glibc drops addresses that come before their CNAME).
    #[test]
    fn dns_011_answers_follow_the_cname_chain() {
        let cname = |from: &str, to: &str| {
            rec(
                from,
                RData::CNAME(rdata::CNAME(Name::from_ascii(to).unwrap())),
                Proof::Insecure,
            )
        };
        let addr = |owner: &str, last: u8| {
            rec(
                owner,
                RData::A(rdata::A::new(192, 0, 2, last)),
                Proof::Insecure,
            )
        };
        let order = |v: &[Record]| -> Vec<(String, RecordType)> {
            v.iter()
                .map(|r| (r.name.to_ascii().to_ascii_lowercase(), r.record_type()))
                .collect()
        };
        // Addresses first, chain links backwards, mixed case: put in order.
        let mut v = vec![
            addr("lb.example.net.", 1),
            cname("cdn.example.com.", "LB.example.net."),
            addr("lb.example.net.", 2),
            cname("WWW.example.com.", "cdn.example.com."),
        ];
        chain_order(&mut v, &Name::from_ascii("www.example.com").unwrap());
        assert_eq!(
            order(&v),
            vec![
                ("www.example.com.".into(), RecordType::CNAME),
                ("cdn.example.com.".into(), RecordType::CNAME),
                ("lb.example.net.".into(), RecordType::A),
                ("lb.example.net.".into(), RecordType::A),
            ]
        );
        // The addresses keep their own order.
        assert_eq!(v[2].data, RData::A(rdata::A::new(192, 0, 2, 1)));
        // Records off the chain stay, at the end; a CNAME loop ends.
        let mut v = vec![
            addr("other.example.", 9),
            cname("b.example.", "a.example."),
            cname("a.example.", "b.example."),
        ];
        chain_order(&mut v, &Name::from_ascii("a.example").unwrap());
        assert_eq!(
            order(&v),
            vec![
                ("a.example.".into(), RecordType::CNAME),
                ("b.example.".into(), RecordType::CNAME),
                ("other.example.".into(), RecordType::A),
            ]
        );
        // An answer already in order is unchanged.
        let mut v = vec![cname("x.example.", "y.example."), addr("y.example.", 3)];
        let before = v.clone();
        chain_order(&mut v, &Name::from_ascii("x.example").unwrap());
        assert_eq!(v, before);
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

/// REQ: DNS-011 (issue #78) — the order of a validated answer, case by case. hickory returns the
/// record sets in any order; the answer is served in the order a server builds it.
#[cfg(test)]
mod order_tests {
    use super::*;
    use hickory_net::proto::dnssec::Algorithm;
    use hickory_net::proto::dnssec::rdata::RRSIG;
    use hickory_net::proto::dnssec::rdata::sig::SigInput;
    use hickory_net::proto::rr::{SerialNumber, rdata};

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn record(owner: &str, data: RData) -> Record {
        let mut r = Record::from_rdata(n(owner), 300, data);
        r.proof = Proof::Secure;
        r
    }

    fn cname(owner: &str, target: &str) -> Record {
        record(owner, RData::CNAME(rdata::CNAME(n(target))))
    }

    fn addr(owner: &str, last: u8) -> Record {
        record(owner, RData::A(rdata::A::new(192, 0, 2, last)))
    }

    fn aaaa(owner: &str) -> Record {
        record(
            owner,
            RData::AAAA(rdata::AAAA(std::net::Ipv6Addr::LOCALHOST)),
        )
    }

    /// A DNAME as hickory reads one from the wire (it has no type of its own for it).
    fn dname(owner: &str, target: &str) -> Record {
        let mut wire = Vec::new();
        for label in target.split('.').filter(|l| !l.is_empty()) {
            wire.push(u8::try_from(label.len()).unwrap());
            wire.extend_from_slice(label.as_bytes());
        }
        wire.push(0);
        record(
            owner,
            RData::Unknown {
                code: RecordType::DNAME,
                rdata: rdata::NULL::with(wire),
            },
        )
    }

    /// An RRSIG owned by `owner` covering `covered` (the signature itself isn't looked at).
    fn sig(owner: &str, covered: RecordType) -> Record {
        let input = SigInput {
            type_covered: covered,
            algorithm: Algorithm::ED25519,
            num_labels: 2,
            original_ttl: 300,
            sig_expiration: SerialNumber::new(u32::MAX),
            sig_inception: SerialNumber::new(0),
            key_tag: 1,
            signer_name: n("example."),
        };
        record(
            owner,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, vec![0; 64]))),
        )
    }

    /// Each record as `owner TYPE`: `owner A address` for an address, `owner RRSIG(TYPE)` for
    /// a signature; owners lowercase.
    fn shape(v: &[Record]) -> Vec<String> {
        v.iter()
            .map(|r| {
                let owner = r.name.to_ascii().to_ascii_lowercase();
                match &r.data {
                    RData::DNSSEC(DNSSECRData::RRSIG(s)) => {
                        format!("{owner} RRSIG({})", s.input().type_covered)
                    }
                    RData::A(a) => format!("{owner} A {}", a.0),
                    _ => format!("{owner} {}", r.record_type()),
                }
            })
            .collect()
    }

    /// Whether `before` and `after` hold the same records, each as many times.
    fn same_records(before: &[Record], after: &[Record]) -> bool {
        let count = |records: &[Record], record: &Record| {
            records.iter().filter(|other| *other == record).count()
        };
        before.len() == after.len()
            && before
                .iter()
                .all(|record| count(before, record) == count(after, record))
    }

    /// `v` in chain order for the question `qname`, checked to hold the same records as before.
    fn ordered(mut v: Vec<Record>, qname: &str) -> Vec<String> {
        let before = v.clone();
        chain_order(&mut v, &n(qname));
        assert!(
            same_records(&before, &v),
            "nothing lost, added or duplicated: {:?}",
            shape(&v)
        );
        shape(&v)
    }

    /// `tidy` for an A question for `qname`.
    fn tidied(m: &mut Message, client_do: bool, qname: &str) {
        tidy(m, u16::from(RecordType::A), client_do, &n(qname));
    }

    /// A DO answer: each owner's signatures stay with it, after its data; the addresses keep
    /// their own order (a round-robin set isn't reshuffled).
    #[test]
    fn dns_011_order_signed_chain_keeps_each_signature_with_its_owner() {
        let v = vec![
            sig("lb.example.net.", RecordType::A),
            addr("lb.example.net.", 2),
            sig("www.example.com.", RecordType::CNAME),
            addr("lb.example.net.", 1),
            cname("www.example.com.", "lb.example.net."),
        ];
        assert_eq!(
            ordered(v, "www.example.com."),
            [
                "www.example.com. CNAME",
                "www.example.com. RRSIG(CNAME)",
                "lb.example.net. A 192.0.2.2",
                "lb.example.net. A 192.0.2.1",
                "lb.example.net. RRSIG(A)",
            ]
        );
    }

    /// A chain of four links is followed to its end.
    #[test]
    fn dns_011_order_long_chain_is_followed_to_its_end() {
        let v = vec![
            addr("e.example.", 5),
            cname("c.example.", "d.example."),
            cname("a.example.", "b.example."),
            cname("d.example.", "e.example."),
            cname("b.example.", "c.example."),
        ];
        assert_eq!(
            ordered(v, "a.example."),
            [
                "a.example. CNAME",
                "b.example. CNAME",
                "c.example. CNAME",
                "d.example. CNAME",
                "e.example. A 192.0.2.5",
            ]
        );
    }

    /// RFC 6672 §3.2 step 3.C: a DNAME above the question name comes before the CNAME
    /// synthesized from it, here at the start of the chain.
    #[test]
    fn dns_011_order_dname_at_the_start_comes_first() {
        let v = vec![
            addr("x.t.example.", 1),
            cname("x.d.example.", "x.t.example."),
            dname("d.example.", "t.example."),
        ];
        assert_eq!(
            ordered(v, "x.d.example."),
            [
                "d.example. DNAME",
                "x.d.example. CNAME",
                "x.t.example. A 192.0.2.1",
            ]
        );
    }

    /// Loops end; a name with two CNAMEs and a repeated record lose nothing.
    #[test]
    fn dns_011_order_loops_and_repeated_names_end_without_losing_records() {
        // A CNAME to itself (in another case).
        let v = vec![addr("other.example.", 9), cname("a.example.", "A.Example.")];
        assert_eq!(
            ordered(v, "a.example."),
            ["a.example. CNAME", "other.example. A 192.0.2.9"]
        );
        // A loop of three, entered at its second name.
        let v = vec![
            cname("c.example.", "a.example."),
            cname("a.example.", "b.example."),
            cname("b.example.", "c.example."),
        ];
        assert_eq!(
            ordered(v, "b.example."),
            ["b.example. CNAME", "c.example. CNAME", "a.example. CNAME"]
        );
        // Two CNAMEs at one name (not valid DNS, but nothing may be lost): the first is followed.
        let v = vec![
            addr("y.example.", 2),
            cname("a.example.", "x.example."),
            addr("x.example.", 1),
            cname("a.example.", "y.example."),
        ];
        assert_eq!(
            ordered(v, "a.example."),
            [
                "a.example. CNAME",
                "a.example. CNAME",
                "x.example. A 192.0.2.1",
                "y.example. A 192.0.2.2",
            ]
        );
        // The same record twice stays twice.
        let v = vec![
            addr("b.example.", 1),
            cname("a.example.", "b.example."),
            addr("b.example.", 1),
        ];
        assert_eq!(
            ordered(v, "a.example."),
            [
                "a.example. CNAME",
                "b.example. A 192.0.2.1",
                "b.example. A 192.0.2.1",
            ]
        );
    }

    /// Records that aren't on the chain are kept after it, in their own order.
    #[test]
    fn dns_011_order_records_off_the_chain_keep_their_order_at_the_end() {
        let v = vec![
            addr("z.example.", 26),
            addr("t.example.", 1),
            sig("z.example.", RecordType::A),
            cname("q.example.", "t.example."),
            addr("y.example.", 25),
        ];
        assert_eq!(
            ordered(v, "q.example."),
            [
                "q.example. CNAME",
                "t.example. A 192.0.2.1",
                "z.example. A 192.0.2.26",
                "z.example. RRSIG(A)",
                "y.example. A 192.0.2.25",
            ]
        );
    }

    /// Several types at the end of a chain (an ANY answer): the data in its own order, then
    /// the signatures.
    #[test]
    fn dns_011_order_several_types_at_the_end_of_a_chain() {
        let txt = record(
            "x.example.",
            RData::TXT(rdata::TXT::new(vec!["v=1".to_owned()])),
        );
        let v = vec![
            sig("x.example.", RecordType::AAAA),
            aaaa("x.example."),
            cname("q.example.", "x.example."),
            sig("x.example.", RecordType::A),
            addr("x.example.", 1),
            txt,
            sig("q.example.", RecordType::CNAME),
        ];
        assert_eq!(
            ordered(v, "q.example."),
            [
                "q.example. CNAME",
                "q.example. RRSIG(CNAME)",
                "x.example. AAAA",
                "x.example. A 192.0.2.1",
                "x.example. TXT",
                "x.example. RRSIG(AAAA)",
                "x.example. RRSIG(A)",
            ]
        );
    }

    /// Each of the 720 orders a signed two-link chain can come back in gives the same answer.
    #[test]
    fn dns_011_order_any_input_order_gives_the_same_chain() {
        let chain = vec![
            cname("www.example.com.", "cdn.example.net."),
            sig("www.example.com.", RecordType::CNAME),
            cname("cdn.example.net.", "lb.example.org."),
            sig("cdn.example.net.", RecordType::CNAME),
            addr("lb.example.org.", 1),
            sig("lb.example.org.", RecordType::A),
        ];
        let expected = shape(&chain);
        // Heap's algorithm: every permutation exactly once.
        let mut v = chain;
        assert_eq!(ordered(v.clone(), "www.example.com."), expected);
        let mut seen = 1;
        let mut c = vec![0usize; v.len()];
        let mut i = 1;
        while i < v.len() {
            if c[i] < i {
                if i % 2 == 0 {
                    v.swap(0, i);
                } else {
                    v.swap(c[i], i);
                }
                assert_eq!(
                    ordered(v.clone(), "WWW.Example.COM."),
                    expected,
                    "from {:?}",
                    shape(&v)
                );
                seen += 1;
                c[i] += 1;
                i = 1;
            } else {
                c[i] = 0;
                i += 1;
            }
        }
        assert_eq!(seen, 720);
    }

    /// `resolve`'s last step: DNSSEC records are stripped for a client without DO, then the
    /// chain is put in order; the other sections keep their order.
    #[test]
    fn dns_011_order_tidy_strips_then_orders() {
        let scrambled = vec![
            addr("lb.example.net.", 1),
            sig("lb.example.net.", RecordType::A),
            cname("www.example.com.", "lb.example.net."),
            sig("www.example.com.", RecordType::CNAME),
        ];
        let mut m = Message::response(1, OpCode::Query);
        m.answers = scrambled.clone();
        m.additionals = vec![addr("ns2.example.", 2), addr("ns1.example.", 1)];
        tidied(&mut m, false, "www.example.com.");
        assert_eq!(
            shape(&m.answers),
            ["www.example.com. CNAME", "lb.example.net. A 192.0.2.1"]
        );
        assert_eq!(
            shape(&m.additionals),
            ["ns2.example. A 192.0.2.2", "ns1.example. A 192.0.2.1"]
        );
        let mut m = Message::response(1, OpCode::Query);
        m.answers = scrambled;
        tidied(&mut m, true, "www.example.com.");
        assert_eq!(
            shape(&m.answers),
            [
                "www.example.com. CNAME",
                "www.example.com. RRSIG(CNAME)",
                "lb.example.net. A 192.0.2.1",
                "lb.example.net. RRSIG(A)",
            ]
        );
    }

    /// RFC 6672 §3.2 step 3.C: a DNAME met in the middle of a chain comes just before the CNAME
    /// synthesized from it, not at the top.
    #[test]
    fn dns_011_order_dname_goes_just_before_the_cname_it_synthesizes() {
        let v = vec![
            addr("x.t.example.", 1),
            dname("d.example.", "t.example."),
            cname("x.d.example.", "x.t.example."),
            cname("www.a.example.", "x.d.example."),
        ];
        assert_eq!(
            ordered(v, "www.a.example."),
            [
                "www.a.example. CNAME",
                "d.example. DNAME",
                "x.d.example. CNAME",
                "x.t.example. A 192.0.2.1",
            ]
        );
    }

    /// A DNAME's signatures go with it, before the synthesized CNAME (which is never signed,
    /// RFC 6672 §5.3.1). A signature of another type at the DNAME's owner isn't on the chain.
    #[test]
    fn dns_011_order_dname_signature_stays_with_the_dname() {
        let v = vec![
            sig("x.t.example.", RecordType::A),
            addr("x.t.example.", 1),
            sig("d.example.", RecordType::NS),
            cname("x.d.example.", "x.t.example."),
            sig("d.example.", RecordType::DNAME),
            dname("d.example.", "t.example."),
        ];
        assert_eq!(
            ordered(v, "x.d.example."),
            [
                "d.example. DNAME",
                "d.example. RRSIG(DNAME)",
                "x.d.example. CNAME",
                "x.t.example. A 192.0.2.1",
                "x.t.example. RRSIG(A)",
                "d.example. RRSIG(NS)",
            ]
        );
    }

    /// Nothing to order without a CNAME or a DNAME: the answer is left exactly as it is.
    #[test]
    fn dns_011_order_answer_without_an_alias_is_left_as_it_is() {
        for v in [
            // A signed address set, its signature first.
            vec![
                sig("q.example.", RecordType::A),
                addr("q.example.", 1),
                addr("q.example.", 2),
            ],
            // Another name's record before the question's.
            vec![addr("other.example.", 9), addr("q.example.", 1)],
            // Several types (ANY), each set followed by its signature.
            vec![
                addr("q.example.", 1),
                sig("q.example.", RecordType::A),
                aaaa("q.example."),
                sig("q.example.", RecordType::AAAA),
            ],
            // A single record.
            vec![cname("q.example.", "x.example.")],
        ] {
            let before = shape(&v);
            assert_eq!(ordered(v, "q.example."), before);
        }
    }
}
