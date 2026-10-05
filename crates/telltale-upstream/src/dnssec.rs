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

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures_util::StreamExt as _;
use futures_util::stream::{self, Stream};
use hickory_net::dnssec::DnssecDnsHandle;
use hickory_net::proto::dnssec::{Proof, TrustAnchors};
use hickory_net::proto::op::{
    DnsRequest, DnsRequestOptions, DnsResponse, Message, Query, ResponseCode,
};
use hickory_net::proto::rr::{Name, RecordType};
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
            stats,
        }
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
                tracing::debug!(name = %q.name.display().to_string(), "DNSSEC: {e}");
                self.stats.count(Verdict::Bogus);
                return Ok(Validated {
                    bytes: Vec::new(),
                    verdict: Verdict::Bogus,
                    upstream_id,
                    attempts,
                });
            }
            Ok(None) | Err(_) => return Err(ResolveError::Empty),
        };
        let verdict = verdict(&response);
        self.stats.count(verdict);
        let mut message = response.into_message();
        if !client_do {
            strip_dnssec(&mut message, q.qtype);
        }
        message.metadata.authentic_data = verdict == Verdict::Secure && (client_do || client_ad);
        message.metadata.checking_disabled = false;
        let bytes = message.to_vec().map_err(|_| ResolveError::Empty)?;
        Ok(Validated {
            bytes,
            verdict,
            upstream_id,
            attempts,
        })
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
        upstream_id: a.upstream_id,
        attempts: a.attempts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
