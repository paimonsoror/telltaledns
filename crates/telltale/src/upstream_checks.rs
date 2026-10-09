//! REQ: OBS-019 (T11.4, ADR-108, `spec/04` §9) — is each upstream telling the truth?
//!
//! - **Second opinions** (`[upstream_check]`, off by default): one forwarded question in
//!   `sample_every` is asked again of another upstream (another member of the answering group,
//!   or the `reference` group), in a background task after the client has its answer, and the two
//!   answers are compared ([`compare`]).
//! - **Answer quality** (always): the DNSSEC verdict of each validated answer and the Extended
//!   DNS Error codes upstreams put in their answers, per upstream.
//!
//! Everything runs on the asynchronous upstream path or in its own task: the cache-hit and
//! blocked paths never get here. With second opinions off, a forwarded answer costs one scan of
//! its records for an OPT EDE and an atomic increment for its DNSSEC verdict.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use telltale_api::model::{EdeCount, UpstreamChecks, UpstreamDisagreement, UpstreamQuality};
use telltale_proto::{Section, rcode, records, rtype};
use telltale_upstream::{Group, Question, Router};

/// Second opinions running at once; more are skipped (DNS never waits for them).
const MAX_IN_FLIGHT: usize = 8;
/// Distinct (upstream, EDE code) pairs counted; the rest are dropped (bounded memory).
const MAX_EDE_PAIRS: usize = 2048;
/// Upstream IDs with their own DNSSEC counters.
const MAX_UPSTREAMS: usize = 256;

/// How a second opinion compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Agreement {
    Same,
    /// Both had addresses, none in common (CDNs and geo-DNS answer per resolver).
    DifferentAddresses,
    /// Different response codes, neither side "filtered" (SERVFAIL vs NOERROR, REFUSED, ...).
    DifferentRcode,
    /// One side had addresses, the other none (NXDOMAIN, no data) or only sinkhole addresses
    /// (`0.0.0.0`, `::`, loopback): the signature of a filtering or censoring resolver.
    Filtered,
    /// The second upstream didn't answer.
    Unanswered,
}

impl Agreement {
    pub(crate) const ALL: [Self; 5] = [
        Self::Same,
        Self::DifferentAddresses,
        Self::DifferentRcode,
        Self::Filtered,
        Self::Unanswered,
    ];
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Same => "same",
            Self::DifferentAddresses => "different_addresses",
            Self::DifferentRcode => "different_rcode",
            Self::Filtered => "filtered",
            Self::Unanswered => "unanswered",
        }
    }
}

/// What an answer says, for comparing: its response code and its A/AAAA addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Gist {
    rcode: u16,
    addrs: BTreeSet<IpAddr>,
}

impl Gist {
    pub(crate) fn of(msg: &[u8]) -> Option<Self> {
        let rcode = u16::from(msg.get(3)? & 0x0F);
        let mut addrs = BTreeSet::new();
        for r in records(msg).ok()?.flatten() {
            if r.section != Section::Answer {
                continue;
            }
            let d = r.rdata(msg);
            match (r.rtype, d.len()) {
                (rtype::A, 4) => {
                    addrs.insert(IpAddr::from([d[0], d[1], d[2], d[3]]));
                }
                (rtype::AAAA, 16) => {
                    let b: [u8; 16] = d.try_into().ok()?;
                    addrs.insert(IpAddr::from(b));
                }
                _ => {}
            }
        }
        Some(Self { rcode, addrs })
    }

    /// Addresses that mean "nothing here": every one unspecified or loopback.
    fn sinkholed(&self) -> bool {
        !self.addrs.is_empty()
            && self
                .addrs
                .iter()
                .all(|a| a.is_unspecified() || a.is_loopback())
    }

    /// Real addresses (not a sinkhole).
    fn resolves(&self) -> bool {
        !self.addrs.is_empty() && !self.sinkholed()
    }

    /// `NOERROR 192.0.2.1, 192.0.2.2` (at most 4 addresses), `NXDOMAIN`, `NOERROR (no data)`.
    pub(crate) fn text(&self) -> String {
        let rc = crate::api_backend::rcode_name(u8::try_from(self.rcode).unwrap_or(u8::MAX));
        if self.addrs.is_empty() {
            return if self.rcode == rcode::NOERROR {
                format!("{rc} (no data)")
            } else {
                rc
            };
        }
        let mut shown: Vec<String> = self.addrs.iter().take(4).map(ToString::to_string).collect();
        if self.addrs.len() > 4 {
            shown.push(format!("+{}", self.addrs.len() - 4));
        }
        format!("{rc} {}", shown.join(", "))
    }
}

/// How two answers to the same question compare (see [`Agreement`]).
pub(crate) fn compare(a: &Gist, b: &Gist) -> Agreement {
    if a.resolves() != b.resolves() {
        return Agreement::Filtered;
    }
    if a.rcode != b.rcode {
        return Agreement::DifferentRcode;
    }
    if a.resolves() && a.addrs.is_disjoint(&b.addrs) {
        return Agreement::DifferentAddresses;
    }
    Agreement::Same
}

/// The first Extended DNS Error code in a message's OPT record (RFC 8914), if any.
pub(crate) fn first_ede(msg: &[u8]) -> Option<u16> {
    let opt = records(msg)
        .ok()?
        .flatten()
        .find(|r| r.section == Section::Additional && r.rtype == rtype::OPT)?;
    let mut d = opt.rdata(msg);
    while let [c0, c1, l0, l1, rest @ ..] = d {
        let (code, len) = (
            u16::from_be_bytes([*c0, *c1]),
            usize::from(u16::from_be_bytes([*l0, *l1])),
        );
        let body = rest.get(..len)?;
        if code == telltale_proto::opt::EDE {
            return body.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]]));
        }
        d = &rest[len..];
    }
    None
}

/// The RFC 8914 registry's name for an EDE info code.
pub(crate) fn ede_name(code: u16) -> &'static str {
    const NAMES: [&str; 30] = [
        "Other Error",
        "Unsupported DNSKEY Algorithm",
        "Unsupported DS Digest Type",
        "Stale Answer",
        "Forged Answer",
        "DNSSEC Indeterminate",
        "DNSSEC Bogus",
        "Signature Expired",
        "Signature Not Yet Valid",
        "DNSKEY Missing",
        "RRSIGs Missing",
        "No Zone Key Bit Set",
        "NSEC Missing",
        "Cached Error",
        "Not Ready",
        "Blocked",
        "Censored",
        "Filtered",
        "Prohibited",
        "Stale NXDOMAIN Answer",
        "Not Authoritative",
        "Not Supported",
        "No Reachable Authority",
        "Network Error",
        "Invalid Data",
        "Signature Expired before Valid",
        "Too Early",
        "Unsupported NSEC3 Iterations Value",
        "Unable to conform to policy",
        "Synthesized",
    ];
    NAMES.get(usize::from(code)).copied().unwrap_or("Unknown")
}

/// One recorded disagreement (names already as the privacy level allows).
#[derive(Debug, Clone)]
struct Disagreement {
    at_us: u64,
    name: String,
    qtype: u16,
    result: Agreement,
    upstream: u16,
    answer: String,
    reference: String,
    reference_answer: String,
}

/// Counters and history, per node, kept across reloads.
#[derive(Debug)]
pub(crate) struct Quality {
    /// By upstream ID: secure, insecure, bogus, indeterminate.
    dnssec: Box<[[AtomicU64; 4]]>,
    ede: Mutex<BTreeMap<(u16, u16), u64>>,
    /// By upstream ID: one count per [`Agreement`].
    checks: Mutex<BTreeMap<u16, [u64; 5]>>,
    recent: Mutex<VecDeque<Disagreement>>,
}

impl Default for Quality {
    fn default() -> Self {
        Self {
            dnssec: (0..MAX_UPSTREAMS)
                .map(|_| std::array::from_fn(|_| AtomicU64::new(0)))
                .collect(),
            ede: Mutex::default(),
            checks: Mutex::default(),
            recent: Mutex::default(),
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Quality {
    /// An upstream's answer: counts its EDE code, if it carries one (the lock only then).
    pub(crate) fn note_answer(&self, upstream: u16, msg: &[u8]) {
        if let Some(code) = first_ede(msg) {
            let mut ede = lock(&self.ede);
            let n = ede.len();
            if let Some(c) = ede.get_mut(&(upstream, code)) {
                *c += 1;
            } else if n < MAX_EDE_PAIRS {
                ede.insert((upstream, code), 1);
            }
        }
    }

    /// The DNSSEC verdict on an upstream's answer.
    pub(crate) fn note_dnssec(&self, upstream: u16, verdict: telltale_upstream::dnssec::Verdict) {
        use telltale_upstream::dnssec::Verdict;
        let i = match verdict {
            Verdict::Secure => 0,
            Verdict::Insecure => 1,
            Verdict::Bogus => 2,
            Verdict::Indeterminate => 3,
        };
        if let Some(row) = self.dnssec.get(usize::from(upstream)) {
            row[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    fn note_check(&self, upstream: u16, result: Agreement, keep: usize, d: Option<Disagreement>) {
        lock(&self.checks).entry(upstream).or_default()[result as usize] += 1;
        if let Some(d) = d {
            let mut recent = lock(&self.recent);
            recent.push_front(d);
            recent.truncate(keep);
        }
    }

    /// For `/metrics`: (upstream ID, counts by [`Agreement`]).
    pub(crate) fn check_counts(&self) -> Vec<(u16, [u64; 5])> {
        lock(&self.checks).iter().map(|(u, c)| (*u, *c)).collect()
    }

    /// For `/metrics`: ((upstream ID, code), count).
    pub(crate) fn ede_counts(&self) -> Vec<((u16, u16), u64)> {
        lock(&self.ede).iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// For `/metrics`: the DNSSEC verdicts of `upstream`.
    pub(crate) fn dnssec_counts(&self, upstream: u16) -> [u64; 4] {
        self.dnssec.get(usize::from(upstream)).map_or([0; 4], |r| {
            std::array::from_fn(|i| r[i].load(Ordering::Relaxed))
        })
    }

    /// The API's view; `names` maps upstream IDs to names.
    pub(crate) fn view(
        &self,
        settings: &telltale_config::UpstreamCheckConfig,
        names: &[(u16, String)],
    ) -> UpstreamChecks {
        let name = |id: u16| {
            names
                .iter()
                .find(|(i, _)| *i == id)
                .map_or_else(|| format!("#{id}"), |(_, n)| n.clone())
        };
        let checks = lock(&self.checks).clone();
        let ede = lock(&self.ede).clone();
        let mut upstreams = Vec::new();
        for (id, n) in names {
            let c = checks.get(id).copied().unwrap_or_default();
            let d = self.dnssec_counts(*id);
            let codes: Vec<EdeCount> = ede
                .iter()
                .filter(|((u, _), _)| u == id)
                .map(|((_, code), count)| EdeCount {
                    code: *code,
                    name: ede_name(*code).to_owned(),
                    count: *count,
                })
                .collect();
            if c.iter().sum::<u64>() + d.iter().sum::<u64>() == 0 && codes.is_empty() {
                continue;
            }
            upstreams.push(UpstreamQuality {
                upstream: n.clone(),
                same: c[0],
                different_addresses: c[1],
                different_rcode: c[2],
                filtered: c[3],
                unanswered: c[4],
                dnssec_secure: d[0],
                dnssec_insecure: d[1],
                dnssec_bogus: d[2],
                dnssec_indeterminate: d[3],
                ede: codes,
            });
        }
        let recent = lock(&self.recent)
            .iter()
            .map(|d| UpstreamDisagreement {
                at: telltale_api::time::format_us(d.at_us),
                name: d.name.clone(),
                qtype: crate::api_backend::qtype_name(d.qtype),
                result: d.result.label().to_owned(),
                upstream: name(d.upstream),
                answer: d.answer.clone(),
                reference: d.reference.clone(),
                reference_answer: d.reference_answer.clone(),
            })
            .collect();
        UpstreamChecks {
            node: None,
            enabled: settings.sample_every > 0,
            sample_every: settings.sample_every,
            reference: settings.reference.as_ref().map(ToString::to_string),
            upstreams,
            recent,
        }
    }
}

/// Decides which forwarded answers get a second opinion, and runs them.
#[derive(Debug)]
pub(crate) struct Checker {
    sample_every: u64,
    reference: Option<String>,
    keep: usize,
    /// The query log's privacy level: names in the history follow it.
    privacy: u8,
    seen: AtomicU64,
    in_flight: Arc<tokio::sync::Semaphore>,
}

impl Checker {
    /// `None` when second opinions are off.
    pub(crate) fn from_config(cfg: &telltale_config::Config) -> Option<Self> {
        let c = &cfg.upstream_check;
        (c.sample_every > 0).then(|| Self {
            sample_every: u64::from(c.sample_every),
            reference: c.reference.as_ref().map(ToString::to_string),
            keep: usize::try_from(c.keep).unwrap_or(100),
            privacy: cfg.telemetry.qlog.privacy_level,
            seen: AtomicU64::new(0),
            in_flight: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT)),
        })
    }

    /// One more forwarded answer: whether this one gets a second opinion.
    pub(crate) fn sample(&self) -> bool {
        self.seen
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(self.sample_every)
    }

    /// Asks the second upstream and records the comparison, in its own task on `rt`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn(
        self: &Arc<Self>,
        rt: &tokio::runtime::Handle,
        router: Arc<Router>,
        group: Arc<Group>,
        question: &Question,
        answer: &[u8],
        upstream: u16,
        quality: Arc<Quality>,
        at_us: u64,
    ) {
        let Ok(permit) = Arc::clone(&self.in_flight).try_acquire_owned() else {
            return;
        };
        let Some(first) = Gist::of(answer) else {
            return;
        };
        let this = Arc::clone(self);
        let question = *question;
        rt.spawn(async move {
            let _permit = permit;
            let Some((reference, second)) =
                this.ask_other(&router, &group, &question, upstream).await
            else {
                return;
            };
            let result = second
                .as_deref()
                .and_then(Gist::of)
                .map_or(Agreement::Unanswered, |g| compare(&first, &g));
            let d = matches!(
                result,
                Agreement::DifferentAddresses | Agreement::DifferentRcode | Agreement::Filtered
            )
            .then(|| Disagreement {
                at_us,
                name: this.shown_name(&question),
                qtype: question.qtype,
                result,
                upstream,
                answer: first.text(),
                reference,
                reference_answer: second
                    .as_deref()
                    .and_then(Gist::of)
                    .map_or_else(String::new, |g| g.text()),
            });
            quality.note_check(upstream, result, this.keep, d);
        });
    }

    /// The name as the privacy level lets it be kept.
    fn shown_name(&self, q: &Question) -> String {
        if self.privacy >= 1 {
            telltale_telemetry::event::dotted(&telltale_store::qlog::hidden_name(q.name.as_wire()))
        } else {
            q.name.display().to_string()
        }
    }

    /// The second opinion: `(who, the answer or None)`; `None` when there's nobody to ask.
    async fn ask_other(
        &self,
        router: &Router,
        group: &Group,
        q: &Question,
        answered_by: u16,
    ) -> Option<(String, Option<Vec<u8>>)> {
        if let Some(name) = &self.reference {
            let g = router.group(name)?;
            return Some(
                match g.resolve(*q, telltale_upstream::DEFAULT_BUDGET).await {
                    Ok(a) => {
                        let who = router
                            .upstreams()
                            .iter()
                            .find(|u| u.id == a.upstream_id)
                            .map_or_else(|| name.clone(), |u| u.name.clone());
                        (who, Some(a.bytes))
                    }
                    Err(_) => (name.clone(), None),
                },
            );
        }
        let other = group.members().iter().find(|u| u.id != answered_by)?;
        let r = other.exchange(q, Duration::from_secs(2)).await.ok();
        Some((other.name.clone(), r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use telltale_proto::{EdnsOut, NameBuf, ResponseBuilder, build_query, parse_query};

    /// An answer to `name` A with `rc` and these addresses, and optionally an EDE.
    fn answer(rc: u16, addrs: &[Ipv4Addr], ede: Option<u16>) -> Vec<u8> {
        let mut qb = [0u8; 512];
        let n = NameBuf::from_presentation("www.example.com").unwrap();
        let len = build_query(&mut qb, 1, &n, rtype::A, 1, true, None).unwrap();
        let q = parse_query(&qb[..len]).unwrap();
        let mut out = [0u8; 1024];
        let mut b = ResponseBuilder::new(&q, &mut out, rc).unwrap();
        for a in addrs {
            b.answer_a(60, *a).unwrap();
        }
        let len = b
            .finish(Some(EdnsOut {
                udp_payload: 1232,
                dnssec_ok: false,
                ede: ede.map(|c| (c, "")),
            }))
            .unwrap();
        out[..len].to_vec()
    }

    fn gist(rc: u16, addrs: &[Ipv4Addr]) -> Gist {
        Gist::of(&answer(rc, addrs, None)).unwrap()
    }

    const A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const B: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

    // REQ: OBS-019 — the comparison: same, CDN-style different addresses, filtered (no
    // addresses or a sinkhole on one side), different response codes.
    #[test]
    fn obs_019_answers_compare() {
        let ok = gist(rcode::NOERROR, &[A]);
        assert_eq!(
            compare(&ok, &gist(rcode::NOERROR, &[A, B])),
            Agreement::Same
        );
        assert_eq!(
            compare(&ok, &gist(rcode::NOERROR, &[B])),
            Agreement::DifferentAddresses
        );
        assert_eq!(
            compare(&ok, &gist(rcode::NXDOMAIN, &[])),
            Agreement::Filtered
        );
        assert_eq!(
            compare(&ok, &gist(rcode::NOERROR, &[Ipv4Addr::UNSPECIFIED])),
            Agreement::Filtered
        );
        assert_eq!(
            compare(&ok, &gist(rcode::NOERROR, &[])),
            Agreement::Filtered
        );
        assert_eq!(
            compare(&gist(rcode::NXDOMAIN, &[]), &gist(rcode::SERVFAIL, &[])),
            Agreement::DifferentRcode
        );
        assert_eq!(
            compare(&gist(rcode::NXDOMAIN, &[]), &gist(rcode::NXDOMAIN, &[])),
            Agreement::Same
        );
        assert_eq!(
            gist(rcode::NOERROR, &[A, B]).text(),
            "NOERROR 192.0.2.1, 198.51.100.7"
        );
        assert_eq!(gist(rcode::NOERROR, &[]).text(), "NOERROR (no data)");
    }

    // REQ: OBS-019 — EDE codes are read from the OPT record and counted per upstream; DNSSEC
    // verdicts per upstream; disagreements kept newest first, at most `keep`.
    #[test]
    fn obs_019_quality_counts() {
        assert_eq!(first_ede(&answer(rcode::NOERROR, &[A], Some(15))), Some(15));
        assert_eq!(first_ede(&answer(rcode::NOERROR, &[A], None)), None);
        assert_eq!(ede_name(15), "Blocked");
        assert_eq!(ede_name(999), "Unknown");
        let q = Quality::default();
        q.note_answer(2, &answer(rcode::NXDOMAIN, &[], Some(17)));
        q.note_answer(2, &answer(rcode::NXDOMAIN, &[], Some(17)));
        q.note_answer(3, &answer(rcode::NOERROR, &[A], None));
        q.note_dnssec(2, telltale_upstream::dnssec::Verdict::Bogus);
        assert_eq!(q.ede_counts(), vec![((2, 17), 2)]);
        assert_eq!(q.dnssec_counts(2), [0, 0, 1, 0]);
        for i in 0..5 {
            q.note_check(
                2,
                Agreement::Filtered,
                3,
                Some(Disagreement {
                    at_us: i,
                    name: format!("n{i}.example"),
                    qtype: 1,
                    result: Agreement::Filtered,
                    upstream: 2,
                    answer: "NXDOMAIN".into(),
                    reference: "quad9".into(),
                    reference_answer: "NOERROR 192.0.2.1".into(),
                }),
            );
        }
        q.note_check(2, Agreement::Same, 3, None);
        let v = q.view(
            &telltale_config::UpstreamCheckConfig {
                sample_every: 1000,
                ..telltale_config::UpstreamCheckConfig::default()
            },
            &[(2, "family-dns".into()), (3, "quad9".into())],
        );
        assert!(v.enabled);
        assert_eq!(v.upstreams.len(), 1, "quad9 has nothing to report");
        let f = &v.upstreams[0];
        assert_eq!((f.filtered, f.same, f.dnssec_bogus), (5, 1, 1));
        assert_eq!(f.ede[0].name, "Filtered");
        assert_eq!(v.recent.len(), 3, "kept at most 3");
        assert_eq!(v.recent[0].name, "n4.example", "newest first");
        assert_eq!(v.recent[0].upstream, "family-dns");
    }

    // REQ: OBS-019 — one forwarded answer in `sample_every` is sampled; off by default.
    #[test]
    fn obs_019_sampling() {
        let mut cfg = telltale_config::Config::default();
        assert!(Checker::from_config(&cfg).is_none(), "off by default");
        cfg.upstream_check.sample_every = 4;
        let c = Checker::from_config(&cfg).unwrap();
        let hits = (0..100).filter(|_| c.sample()).count();
        assert_eq!(hits, 25);
    }
}
