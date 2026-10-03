//! The per-query pipeline (`spec/03` §3), shared by every transport.
//!
//! Stages today: parse → reject (DNS-019) → cache (DNS-006) → upstream (UPS-*) with
//! singleflight, serve-stale (DNS-007), and prefetch (DNS-008). Policy, local data, and
//! filtering slot in before the cache as M1/M2 tasks land.
//!
//! The synchronous part (`handle`) runs on hot-path threads: a cache hit is answered without
//! allocating. Anything that needs I/O becomes a deferred future driven by the runtime.

use std::sync::Arc;
use std::time::{Duration, Instant};

use telltale_cache::{Cache, CacheKey, Client, Flight, Lookup, Singleflight};
use telltale_config::{Cidr, RateLimitAction, SpecialConfig};
use telltale_net::{QueryHandler, RequestMeta, Response, Transport};
use telltale_policy::{LocalData, RateLimiter, Special};
use telltale_proto::{
    EdnsOut, Query, QueryError, ResponseBuilder, badvers_from_raw, ede, error_from_raw,
    parse_query, rcode, response_edns, truncate_for_udp, udp_limit,
};
use telltale_upstream::{Question, Router};
use tokio::sync::Semaphore;

/// Settings derived from config.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    /// Our advertised EDNS UDP payload size (DNS-005).
    pub(crate) edns_payload: u16,
    /// Total upstream time budget per query (`spec/02` §8.3).
    pub(crate) budget: Duration,
    /// Serve stale data if upstreams haven't answered within this (RFC 8767).
    pub(crate) stale_answer_timeout: Duration,
    /// Max concurrent upstream resolutions; beyond it, serve stale or SERVFAIL (02 §8.4).
    pub(crate) max_inflight: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            edns_payload: telltale_proto::DEFAULT_EDNS_PAYLOAD,
            budget: telltale_upstream::DEFAULT_BUDGET,
            stale_answer_timeout: Duration::from_millis(1800),
            max_inflight: 4096,
        }
    }
}

/// Per-query policy inputs (`spec/03` §3 steps 2–5).
#[derive(Debug, Default)]
pub(crate) struct Policy {
    /// Clients outside these networks are refused (08 §6).
    pub(crate) allowed: Vec<Cidr>,
    /// Per-client token buckets (DNS-014); `None` = disabled.
    pub(crate) limiter: Option<RateLimiter>,
    pub(crate) limit_action: RateLimitAction,
    pub(crate) special: SpecialConfig,
    /// Local records (DNS-010), answered before cache and upstreams.
    pub(crate) local: Arc<LocalData>,
}

impl Policy {
    pub(crate) fn from_config(cfg: &telltale_config::Config, local: LocalData) -> Self {
        Self {
            allowed: cfg.access.allowed_networks.clone(),
            limiter: RateLimiter::new(&cfg.ratelimit),
            limit_action: cfg.ratelimit.action,
            special: cfg.special.clone(),
            local: Arc::new(local),
        }
    }

    /// Everything allowed, nothing limited (tests).
    #[cfg(test)]
    pub(crate) fn open() -> Self {
        Self {
            allowed: vec![
                telltale_config::Cidr::parse("0.0.0.0/0").unwrap(),
                telltale_config::Cidr::parse("::/0").unwrap(),
            ],
            ..Self::default()
        }
    }
}

/// Shared state for every query.
#[derive(Debug)]
pub(crate) struct Pipeline {
    settings: Settings,
    cache: Arc<Cache>,
    router: Arc<Router>,
    /// Access, rate limits, special names, local data (`spec/03` §3 steps 2–5).
    policy: Policy,
    flights: Arc<Singleflight>,
    inflight: Arc<Semaphore>,
    /// Queries dropped because they carried our own loop tag.
    loops: std::sync::atomic::AtomicU64,
    /// Per-process qname hash seed (keeps remote clients from precomputing collisions).
    seed: u64,
}

/// Largest response we build for a deferred answer (TCP may carry up to 64 KiB).
const MAX_RESPONSE: usize = u16::MAX as usize;

impl Pipeline {
    pub(crate) fn new(
        settings: Settings,
        cache: Arc<Cache>,
        router: Arc<Router>,
        policy: Policy,
    ) -> Arc<Self> {
        Arc::new(Self {
            inflight: Arc::new(Semaphore::new(settings.max_inflight.max(1))),
            settings,
            cache,
            router,
            policy,
            flights: Singleflight::new(),
            seed: rand::random(),
            loops: std::sync::atomic::AtomicU64::new(0),
        })
    }

    fn key(&self, q: &Query<'_>, view: u16) -> CacheKey {
        CacheKey::new(q, q.qname.hash64(self.seed), view)
    }

    fn finish(&self, q: &Query<'_>, out: &mut [u8], len: usize, transport: Transport) -> usize {
        match transport {
            Transport::Udp => truncate_for_udp(
                out,
                len,
                udp_limit(q.edns.as_ref(), self.settings.edns_payload),
            ),
            Transport::Tcp => len,
        }
    }

    /// The synchronous stage: parse, then answer from cache or defer.
    fn handle_sync(self: &Arc<Self>, req: &[u8], meta: &RequestMeta, out: &mut [u8]) -> Response {
        let q = match parse_query(req) {
            Ok(q) => q,
            Err(QueryError::Drop) => return Response::Drop,
            Err(QueryError::NotImp) => return ready(error_from_raw(req, rcode::NOTIMP, out)),
            Err(QueryError::FormErr(_)) => return ready(error_from_raw(req, rcode::FORMERR, out)),
            Err(QueryError::BadVers) => {
                return ready(badvers_from_raw(req, self.settings.edns_payload, out));
            }
        };
        // 08 §6 — never an open resolver: refuse clients outside allowed_networks.
        if !telltale_policy::is_allowed(&self.policy.allowed, meta.peer.ip()) {
            return self.simple(
                &q,
                out,
                rcode::REFUSED,
                Some((ede::PROHIBITED, "client not allowed")),
                meta,
            );
        }
        // REQ: DNS-014 — per-client rate limit.
        if let Some(rl) = &self.policy.limiter
            && !rl.check(meta.peer.ip(), Instant::now())
        {
            return match self.policy.limit_action {
                RateLimitAction::Drop => Response::Drop,
                RateLimitAction::Refused => self.simple(
                    &q,
                    out,
                    rcode::REFUSED,
                    Some((ede::PROHIBITED, "rate limited")),
                    meta,
                ),
            };
        }
        // `spec/04` §7: a query carrying our own loop tag means an upstream forwards back to
        // us. Answering would recurse forever; drop it and make noise.
        if telltale_upstream::is_own_loop_tag(&q) {
            let n = self
                .loops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n.is_multiple_of(1000) {
                tracing::error!(
                    qname = %q.qname.display(),
                    total = n + 1,
                    "forwarding loop detected: an upstream sends our own queries back to us; check upstream configuration"
                );
            }
            return Response::Drop;
        }
        // REQ: DNS-019 — answer ANY with the RFC 8482 minimal response (no amplification).
        if q.is_any() {
            let edns = response_edns(&q, self.settings.edns_payload, None);
            let len = ResponseBuilder::new(&q, out, rcode::NOERROR)
                .ok()
                .and_then(|mut b| {
                    b.answer_any_refusal(3600).ok()?;
                    b.finish(edns).ok()
                });
            return ready(len.map(|l| self.finish(&q, out, l, meta.transport)));
        }
        // DNS-019 / RFC 6761 — special names (ADR-014).
        let special = telltale_policy::classify(&q, &self.policy.special);
        match special {
            Some(Special::Refused) => return self.simple(&q, out, rcode::REFUSED, None, meta),
            Some(Special::Nxdomain) => return self.simple(&q, out, rcode::NXDOMAIN, None, meta),
            Some(Special::Localhost) => return self.localhost(&q, out, meta),
            Some(Special::PrivatePtr) | None => {}
        }
        // REQ: DNS-010 — local data is authoritative and answered before cache/upstreams.
        if let Some(len) =
            self.policy
                .local
                .answer(&q, out, response_edns(&q, self.settings.edns_payload, None))
        {
            return Response::Ready(self.finish(&q, out, len, meta.transport));
        }
        let question = Question::from_query(&q);
        let selection = self.router.select(&question, &[]);
        // Private reverse lookups stay local unless a route explicitly forwards them (RFC 6303).
        if special == Some(Special::PrivatePtr) && !selection.is_some_and(|s| s.routed) {
            return self.simple(&q, out, rcode::NXDOMAIN, None, meta);
        }
        let Some(sel) = selection else {
            // No upstream group applies (none configured): we can't resolve this.
            let edns = response_edns(
                &q,
                self.settings.edns_payload,
                Some((ede::NOT_READY, "no upstreams configured")),
            );
            let len = ResponseBuilder::new(&q, out, rcode::REFUSED)
                .ok()
                .and_then(|b| b.finish(edns).ok());
            return ready(len.map(|l| self.finish(&q, out, l, meta.transport)));
        };
        let key = self.key(&q, sel.view);
        let client = Client::from_query(&q, response_edns(&q, self.settings.edns_payload, None));
        match self.cache.get(&key, &q.qname, &client, Instant::now(), out) {
            Lookup::Hit { len, prefetch } => {
                if prefetch {
                    self.prefetch(req, key, sel.view);
                }
                Response::Ready(self.finish(&q, out, len, meta.transport))
            }
            Lookup::Expired => self.defer(req, meta, key, sel.view, true),
            Lookup::Miss => self.defer(req, meta, key, sel.view, false),
        }
    }

    /// Answers with `rc` and no records; NXDOMAIN/NOERROR carry a synthetic SOA so clients can
    /// cache the negative answer briefly.
    fn simple(
        &self,
        q: &Query<'_>,
        out: &mut [u8],
        rc: u16,
        ede: Option<(u16, &str)>,
        meta: &RequestMeta,
    ) -> Response {
        let edns = response_edns(q, self.settings.edns_payload, ede);
        let len = ResponseBuilder::new(q, out, rc).ok().and_then(|mut b| {
            if rc == rcode::NXDOMAIN {
                b.authoritative(true).authority_soa(300).ok()?;
            }
            b.finish(edns).ok()
        });
        ready(len.map(|l| self.finish(q, out, l, meta.transport)))
    }

    /// RFC 6761 §6.3: `localhost` names resolve to loopback.
    fn localhost(&self, q: &Query<'_>, out: &mut [u8], meta: &RequestMeta) -> Response {
        let edns = response_edns(q, self.settings.edns_payload, None);
        let len = ResponseBuilder::new(q, out, rcode::NOERROR)
            .ok()
            .and_then(|mut b| {
                b.authoritative(true);
                match q.qtype {
                    telltale_proto::rtype::A => {
                        b.answer_a(3600, std::net::Ipv4Addr::LOCALHOST).ok()?;
                    }
                    telltale_proto::rtype::AAAA => {
                        b.answer_aaaa(3600, std::net::Ipv6Addr::LOCALHOST).ok()?;
                    }
                    _ => {
                        b.authority_soa(3600).ok()?;
                    }
                }
                b.finish(edns).ok()
            });
        ready(len.map(|l| self.finish(q, out, l, meta.transport)))
    }

    fn defer(
        self: &Arc<Self>,
        req: &[u8],
        meta: &RequestMeta,
        key: CacheKey,
        view: u16,
        stale_ok: bool,
    ) -> Response {
        let this = Arc::clone(self);
        let req = req.to_vec();
        let transport = meta.transport;
        Response::Deferred(Box::pin(async move {
            this.resolve_for_client(req, key, view, stale_ok, transport)
                .await
        }))
    }

    /// The deferred stage: resolve upstream (shared via singleflight), then build the client's
    /// response from the answer, from stale data, or as SERVFAIL with an EDE.
    async fn resolve_for_client(
        self: Arc<Self>,
        req: Vec<u8>,
        key: CacheKey,
        view: u16,
        stale_ok: bool,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        let q = parse_query(&req).ok()?;
        let mut out = vec![0u8; MAX_RESPONSE];

        let Ok(permit) = Arc::clone(&self.inflight).try_acquire_owned() else {
            // Overloaded (02 §8.4): stale if we have it, else SERVFAIL + EDE 23.
            return self.fallback(
                &q,
                key,
                stale_ok,
                ede::NETWORK_ERROR,
                "resolver overloaded",
                &mut out,
                transport,
            );
        };
        // Run the resolution as its own task so that, if we give up waiting and serve stale,
        // it still completes and refreshes the cache (RFC 8767 §5).
        let task = tokio::spawn(Arc::clone(&self).resolve_shared(req.clone(), key, view, permit));
        let wait = if stale_ok {
            self.settings.stale_answer_timeout
        } else {
            self.settings.budget + Duration::from_millis(100)
        };
        let answer = match tokio::time::timeout(wait, task).await {
            Ok(Ok(Some(a))) => Some(a),
            _ => None,
        };
        match answer {
            Some(resp) => {
                let client =
                    Client::from_query(&q, response_edns(&q, self.settings.edns_payload, None));
                match Cache::render(&q, &resp, &client, &mut out) {
                    Some(len) => {
                        let len = self.finish(&q, &mut out, len, transport);
                        out.truncate(len);
                        Some(out)
                    }
                    None => self.fallback(
                        &q,
                        key,
                        stale_ok,
                        ede::OTHER,
                        "unusable upstream answer",
                        &mut out,
                        transport,
                    ),
                }
            }
            None => self.fallback(
                &q,
                key,
                stale_ok,
                ede::NO_REACHABLE_AUTHORITY,
                "no upstream answered",
                &mut out,
                transport,
            ),
        }
    }

    /// Resolves `req` upstream once per (key, name), inserting the answer into the cache.
    async fn resolve_shared(
        self: Arc<Self>,
        req: Vec<u8>,
        key: CacheKey,
        view: u16,
        _permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Option<Arc<[u8]>> {
        let q = parse_query(&req).ok()?;
        let guard = match self.flights.join(key, q.qname.as_wire()) {
            Flight::Leader(g) => g,
            Flight::Follower(rx) => {
                if let Some(a) = Flight::wait(rx).await {
                    return Some(a);
                }
                // The leader gave up; resolve without coalescing.
                return self.resolve_upstream(&q, key, view).await;
            }
        };
        let answer = self.resolve_upstream(&q, key, view).await?;
        guard.complete(Arc::clone(&answer));
        Some(answer)
    }

    async fn resolve_upstream(&self, q: &Query<'_>, key: CacheKey, view: u16) -> Option<Arc<[u8]>> {
        let question = Question::from_query(q);
        let group = self
            .router
            .select(&question, &[])
            .filter(|s| s.view == view)?
            .group;
        let answer = group.resolve(question, self.settings.budget).await.ok()?;
        let _ = self.cache.insert(&key, q, &answer.bytes, Instant::now());
        Some(answer.bytes.into())
    }

    /// Stale answer with EDE 3 if allowed and available; otherwise SERVFAIL with `code`.
    #[allow(clippy::too_many_arguments)]
    fn fallback(
        &self,
        q: &Query<'_>,
        key: CacheKey,
        stale_ok: bool,
        code: u16,
        text: &str,
        out: &mut Vec<u8>,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        let mut len = None;
        if stale_ok {
            let edns = response_edns(q, self.settings.edns_payload, Some((ede::STALE_ANSWER, "")));
            let client = Client::from_query(q, edns);
            len = self
                .cache
                .get_stale(&key, &q.qname, &client, Instant::now(), out);
        }
        let len = if let Some(l) = len {
            l
        } else {
            let edns: Option<EdnsOut<'_>> =
                response_edns(q, self.settings.edns_payload, Some((code, text)));
            ResponseBuilder::new(q, out, rcode::SERVFAIL)
                .ok()?
                .finish(edns)
                .ok()?
        };
        let len = self.finish(q, out, len, transport);
        out.truncate(len);
        Some(std::mem::take(out))
    }

    /// Refreshes a hot entry in the background before it expires (DNS-008).
    fn prefetch(self: &Arc<Self>, req: &[u8], key: CacheKey, view: u16) {
        let Ok(permit) = Arc::clone(&self.inflight).try_acquire_owned() else {
            return;
        };
        let this = Arc::clone(self);
        let req = req.to_vec();
        tokio::spawn(async move {
            let _ = this.resolve_shared(req, key, view, permit).await;
        });
    }
}

fn ready(len: Option<usize>) -> Response {
    len.map_or(Response::Drop, Response::Ready)
}

/// `Arc<Pipeline>` is the handler every listener shares.
#[derive(Debug, Clone)]
pub(crate) struct Handler(pub(crate) Arc<Pipeline>);

impl QueryHandler for Handler {
    fn handle(&self, req: &[u8], meta: &RequestMeta, out: &mut [u8]) -> Response {
        self.0.handle_sync(req, meta, out)
    }
}

#[cfg(test)]
mod tests {
    use telltale_cache::CachePolicy;
    use telltale_proto::{NameBuf, build_query, rtype, summarize};

    use super::*;

    fn pipeline() -> Arc<Pipeline> {
        let cache = Arc::new(Cache::new(CachePolicy::default()));
        Pipeline::new(
            Settings::default(),
            cache,
            Arc::new(Router::default()),
            Policy::open(),
        )
    }

    fn query(name: &str, qtype: u16, edns: bool) -> Vec<u8> {
        let mut buf = [0u8; 512];
        let n = NameBuf::from_presentation(name).unwrap();
        let e = edns.then(|| EdnsOut::new(1232));
        let len = build_query(&mut buf, 9, &n, qtype, 1, true, e).unwrap();
        buf[..len].to_vec()
    }

    fn meta() -> RequestMeta {
        RequestMeta {
            peer: "127.0.0.1:5353".parse().unwrap(),
            local: None,
            transport: Transport::Udp,
        }
    }

    fn rcode_of(p: &Arc<Pipeline>, req: &[u8]) -> Option<u16> {
        let mut out = [0u8; 4096];
        match p.handle_sync(req, &meta(), &mut out) {
            Response::Ready(len) => Some(summarize(&out[..len]).unwrap().rcode),
            _ => None,
        }
    }

    #[test]
    fn dns_019_rejections_and_errors() {
        let p = pipeline();
        let q = query("example.com", rtype::A, true);
        assert_eq!(rcode_of(&p, &q[..5]), None, "runt dropped");
        let mut notify = q.clone();
        notify[2] |= 4 << 3;
        assert_eq!(rcode_of(&p, &notify), Some(rcode::NOTIMP));
        let mut v1 = q.clone();
        let n = v1.len();
        v1[n - 11 + 6] = 1;
        assert_eq!(rcode_of(&p, &v1), Some(rcode::BADVERS));
    }

    #[test]
    fn dns_019_any_gets_minimal_answer_without_upstream() {
        let p = pipeline();
        let mut out = [0u8; 4096];
        let Response::Ready(len) =
            p.handle_sync(&query("example.com", rtype::ANY, false), &meta(), &mut out)
        else {
            panic!("ANY must be answered immediately");
        };
        let s = summarize(&out[..len]).unwrap();
        assert_eq!((s.rcode, s.answers), (rcode::NOERROR, 1));
    }

    #[test]
    fn no_upstreams_refuses_with_ede() {
        let p = pipeline();
        assert_eq!(
            rcode_of(&p, &query("example.com", rtype::A, true)),
            Some(rcode::REFUSED)
        );
    }

    #[test]
    fn loop_tagged_queries_are_dropped() {
        telltale_upstream::set_node_tag(0xABCD);
        let p = pipeline();
        let q = telltale_upstream::Question {
            name: NameBuf::from_presentation("example.com").unwrap(),
            qtype: rtype::A,
            qclass: 1,
            dnssec_ok: false,
            checking_disabled: false,
        };
        let mut buf = [0u8; 512];
        let len = telltale_upstream::encode_query(&q, 1, &mut buf).unwrap();
        let mut out = [0u8; 4096];
        assert!(matches!(
            p.handle_sync(&buf[..len], &meta(), &mut out),
            Response::Drop
        ));
    }
}

#[cfg(test)]
mod policy_tests {
    use telltale_cache::CachePolicy;
    use telltale_config::{Cidr, RateLimitConfig};
    use telltale_proto::{NameBuf, build_query, class, rtype, summarize};

    use super::*;

    fn pipeline(policy: Policy) -> Arc<Pipeline> {
        let cache = Arc::new(Cache::new(CachePolicy::default()));
        Pipeline::new(
            Settings::default(),
            cache,
            Arc::new(Router::default()),
            policy,
        )
    }

    fn ask(
        p: &Arc<Pipeline>,
        peer: &str,
        name: &str,
        qtype: u16,
        qclass: u16,
    ) -> Option<(u16, u16)> {
        let mut buf = [0u8; 512];
        let n = NameBuf::from_presentation(name).unwrap();
        let len = build_query(&mut buf, 3, &n, qtype, qclass, true, None).unwrap();
        let meta = RequestMeta {
            peer: peer.parse().unwrap(),
            local: None,
            transport: Transport::Udp,
        };
        let mut out = [0u8; 4096];
        match p.handle_sync(&buf[..len], &meta, &mut out) {
            Response::Ready(l) => summarize(&out[..l]).ok().map(|s| (s.rcode, s.answers)),
            _ => None,
        }
    }

    #[test]
    fn access_control_refuses_outside_networks() {
        let p = pipeline(Policy {
            allowed: vec![Cidr::parse("192.168.0.0/16").unwrap()],
            ..Policy::default()
        });
        assert_eq!(
            ask(&p, "203.0.113.9:5353", "localhost", rtype::A, 1),
            Some((rcode::REFUSED, 0))
        );
        assert_eq!(
            ask(&p, "192.168.1.9:5353", "localhost", rtype::A, 1),
            Some((rcode::NOERROR, 1))
        );
    }

    #[test]
    fn dns_014_rate_limited_clients_are_refused() {
        let mut policy = Policy::open();
        policy.limiter = RateLimiter::new(&RateLimitConfig {
            queries: 3,
            window_secs: 60,
            exempt: Vec::new(),
            ..RateLimitConfig::default()
        });
        let p = pipeline(policy);
        for _ in 0..3 {
            assert_eq!(
                ask(&p, "10.0.0.5:1000", "localhost", rtype::A, 1)
                    .unwrap()
                    .0,
                rcode::NOERROR
            );
        }
        assert_eq!(
            ask(&p, "10.0.0.5:1000", "localhost", rtype::A, 1)
                .unwrap()
                .0,
            rcode::REFUSED
        );
        assert_eq!(
            ask(&p, "10.0.0.6:1000", "localhost", rtype::A, 1)
                .unwrap()
                .0,
            rcode::NOERROR
        );
    }

    #[test]
    fn dns_019_special_names_in_pipeline() {
        let p = pipeline(Policy::open());
        let peer = "10.0.0.1:53";
        assert_eq!(
            ask(&p, peer, "use-application-dns.net", rtype::A, 1),
            Some((rcode::NXDOMAIN, 0))
        );
        assert_eq!(
            ask(&p, peer, "x.invalid", rtype::A, 1),
            Some((rcode::NXDOMAIN, 0))
        );
        assert_eq!(
            ask(&p, peer, "app.localhost", rtype::AAAA, 1),
            Some((rcode::NOERROR, 1))
        );
        assert_eq!(
            ask(&p, peer, "version.bind", rtype::TXT, class::CH),
            Some((rcode::REFUSED, 0))
        );
        assert_eq!(
            ask(&p, peer, "4.3.168.192.in-addr.arpa", rtype::PTR, 1),
            Some((rcode::NXDOMAIN, 0))
        );
    }
}
