//! The per-query pipeline (`spec/03` §3), shared by every transport.
//!
//! Stages today: parse → reject (DNS-019) → cache (DNS-006) → upstream (UPS-*) with
//! singleflight, serve-stale (DNS-007), and prefetch (DNS-008). Policy, local data, and
//! filtering slot in before the cache as M1/M2 tasks land.
//!
//! The synchronous part (`handle`) runs on hot-path threads: a cache hit is answered without
//! allocating. Anything that needs I/O becomes a deferred future driven by the runtime.

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use telltale_cache::{Cache, CacheKey, Client, Flight, Lookup, Singleflight};
use telltale_config::BlockMode;
use telltale_config::{Cidr, RateLimitAction, SpecialConfig};
use telltale_filter::matcher::{ClientCtx, Decision, ListMask, Matcher, Scratch};
use telltale_net::{QueryHandler, RequestMeta, Response, Transport};
use telltale_policy::{
    ClientTable, Group, Identity, LocalData, Neighbors, Pause, RateLimiter, Special,
};
use telltale_proto::{
    EdnsOut, Query, QueryError, ResponseBuilder, badvers_from_raw, ede, error_from_raw,
    parse_query, rcode, response_edns, truncate_for_udp, udp_limit,
};
use telltale_telemetry::{Hub, Metrics, Proto, QueryEvent, Rule, RuleKind, Status, UpstreamEvent};
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
    /// Event ring bytes per producing thread (OBS-002, ADR-026).
    pub(crate) ring_bytes: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            edns_payload: telltale_proto::DEFAULT_EDNS_PAYLOAD,
            budget: telltale_upstream::DEFAULT_BUDGET,
            stale_answer_timeout: Duration::from_millis(1800),
            max_inflight: 4096,
            ring_bytes: 4096 * 128,
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
    /// Groups and known clients (FLT-005, FLT-006).
    pub(crate) clients: Arc<ClientTable>,
}

impl Policy {
    pub(crate) fn from_config(cfg: &telltale_config::Config, local: LocalData) -> Self {
        Self {
            allowed: cfg.access.allowed_networks.clone(),
            limiter: RateLimiter::new(&cfg.ratelimit),
            limit_action: cfg.ratelimit.action,
            special: cfg.special.clone(),
            local: Arc::new(local),
            clients: Arc::new(ClientTable::from_config(cfg)),
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

/// The active filter (`spec/03` §3 step 6): a matcher plus, per client, which lists apply.
#[derive(Debug)]
pub(crate) struct FilterState {
    pub(crate) matcher: Arc<Matcher>,
    /// The client table the masks were computed for.
    pub(crate) clients: Arc<ClientTable>,
    /// Union of each configured client's groups' lists, by client index (FLT-005).
    pub(crate) client_masks: Vec<ListMask>,
    /// Lists for unknown clients (the `default` group).
    pub(crate) default_mask: ListMask,
    /// EDE text per list ID, built once so blocking doesn't allocate.
    pub(crate) reasons: Vec<String>,
    /// The same for blocks found through a CNAME target (FLT-007).
    pub(crate) cname_reasons: Vec<String>,
}

/// Who sent a query, as far as identification needs (carried into deferred answers).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Who {
    pub(crate) peer: IpAddr,
    pub(crate) mac: Option<[u8; 6]>,
    /// From the DoT SNI or the DoH path.
    pub(crate) client_id: Option<telltale_net::ClientId>,
}

/// Drops a swapped-out value on a background thread after a grace period (T2.7). Readers
/// hold short-lived guards, so after the pause this is the last reference, and freeing a
/// large snapshot (tens of MB of FST and index) never lands on a DNS worker mid-query.
fn retire<T: Send + 'static>(old: T) {
    let spawned = std::thread::Builder::new()
        .name("telltale-retire".into())
        .spawn(move || {
            telltale_net::background_thread();
            std::thread::sleep(Duration::from_secs(2));
            drop(old);
        });
    // If no thread can be started, the value is dropped here (correct, just not deferred).
    drop(spawned);
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl FilterState {
    pub(crate) fn new(matcher: Arc<Matcher>, clients: Arc<ClientTable>) -> Self {
        let names: Vec<String> = matcher
            .snapshot()
            .map(|s| s.manifest.lists.iter().map(|l| l.name.clone()).collect())
            .unwrap_or_default();
        // A group's lists → list IDs in this snapshot (a group naming a list that isn't
        // compiled yet simply doesn't get it until it is).
        let group_masks: Vec<ListMask> = clients
            .groups()
            .iter()
            .map(|g| match &g.lists {
                None => ListMask::all(names.len()),
                Some(lists) => {
                    let mut m = ListMask::default();
                    for (i, n) in names.iter().enumerate() {
                        if lists.iter().any(|l| **l == **n)
                            && let Ok(id) = u16::try_from(i)
                        {
                            m.set(id);
                        }
                    }
                    m
                }
            })
            .collect();
        let union = |groups: &[u16]| {
            let mut m = ListMask::default();
            for &g in groups {
                if let Some(gm) = group_masks.get(usize::from(g)) {
                    for i in 0..names.len() {
                        let Ok(id) = u16::try_from(i) else { break };
                        if gm.contains(id) {
                            m.set(id);
                        }
                    }
                }
            }
            m
        };
        let unknown = Identity {
            client: None,
            source: telltale_policy::IdSource::Default,
        };
        Self {
            client_masks: clients.clients().iter().map(|c| union(&c.groups)).collect(),
            default_mask: union(clients.group_ids(unknown)),
            reasons: names
                .iter()
                .map(|n| format!("blocked by list {n}"))
                .collect(),
            cname_reasons: names
                .iter()
                .map(|n| format!("CNAME target blocked by list {n}"))
                .collect(),
            clients,
            matcher,
        }
    }

    pub(crate) fn mask(&self, id: Identity) -> &ListMask {
        id.client
            .and_then(|c| self.client_masks.get(usize::from(c)))
            .unwrap_or(&self.default_mask)
    }
}

thread_local! {
    /// Per-thread regex caches for the matcher (allocated on first use and after swaps).
    static FILTER_SCRATCH: RefCell<Scratch> = RefCell::new(Scratch::default());
}

/// The part of the pipeline that a config reload replaces (OPS-009).
#[derive(Debug)]
pub(crate) struct Dynamic {
    pub(crate) router: Arc<Router>,
    pub(crate) policy: Policy,
}

/// Shared state for every query.
#[derive(Debug)]
pub(crate) struct Pipeline {
    settings: Settings,
    cache: Arc<Cache>,
    /// Routing and policy, swapped atomically on reload (OPS-009); readers never lock.
    state: ArcSwap<Dynamic>,
    /// The filter, swapped atomically whenever a snapshot is compiled or indexed (FLT-004).
    pub(crate) filter: ArcSwapOption<FilterState>,
    /// Serializes filter rebuilds (snapshot publish vs. config reload); never on the query path.
    filter_lock: std::sync::Mutex<()>,
    /// IP → MAC from the kernel neighbor table (FLT-006), refreshed by the server.
    pub(crate) neighbors: Arc<Neighbors>,
    /// Blocking paused globally or per group (FLT-009). Kept across reloads.
    pub(crate) pause: Pause,
    flights: Arc<Singleflight>,
    inflight: Arc<Semaphore>,
    /// Query counters and latency histograms (OBS-005).
    pub(crate) metrics: Arc<Metrics>,
    /// Per-query events and their aggregates (OBS-001, OBS-002, OBS-004).
    pub(crate) telemetry: Arc<Hub>,
    /// Queries dropped because they carried our own loop tag.
    loops: std::sync::atomic::AtomicU64,
    /// Per-process qname hash seed (keeps remote clients from precomputing collisions).
    seed: u64,
    /// The runtime background work (prefetch) is spawned on; `None` when built outside one.
    rt: Option<tokio::runtime::Handle>,
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
            metrics: Arc::new(Metrics::new(telltale_net::default_workers() * 2 + 4)),
            telemetry: Hub::new(settings.ring_bytes),
            settings,
            cache,
            state: ArcSwap::from_pointee(Dynamic { router, policy }),
            filter: ArcSwapOption::empty(),
            filter_lock: std::sync::Mutex::new(()),
            neighbors: Arc::new(Neighbors::default()),
            pause: Pause::default(),
            flights: Singleflight::new(),
            seed: rand::random(),
            loops: std::sync::atomic::AtomicU64::new(0),
            rt: tokio::runtime::Handle::try_current().ok(),
        })
    }

    /// Explains what this pipeline would do with a query, and why (FLT-013).
    pub(crate) fn explain(
        &self,
        req: &crate::explain::Request<'_>,
        source: impl Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<crate::explain::Explanation, String> {
        let dynamic = self.state.load();
        let filter = self.filter.load();
        let st = crate::explain::State {
            dynamic: &dynamic,
            filter: filter.as_deref(),
            neighbors: &self.neighbors,
            pause: &self.pause,
        };
        crate::explain::explain(&st, req, source)
    }

    /// Swaps in new routing/policy (OPS-009). In-flight queries finish with the state they
    /// started with; new queries see the new state immediately.
    pub(crate) fn reload(&self, router: Arc<Router>, policy: Policy) {
        retire(self.state.swap(Arc::new(Dynamic { router, policy })));
        // Group/client changes re-derive the per-client list masks for the current snapshot.
        self.set_filter(None);
    }

    /// Installs `matcher` (or, with `None`, re-installs the current one) with masks for the
    /// current client table. Called when a snapshot is published and on reload.
    pub(crate) fn set_filter(&self, matcher: Option<Arc<Matcher>>) {
        let _serialized = self
            .filter_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let matcher = match matcher {
            Some(m) => m,
            None => match self.filter.load_full() {
                Some(f) => Arc::clone(&f.matcher),
                None => return,
            },
        };
        let clients = Arc::clone(&self.state.load().policy.clients);
        retire(
            self.filter
                .swap(Some(Arc::new(FilterState::new(matcher, clients)))),
        );
    }

    /// The current routing/policy state.
    pub(crate) fn current(&self) -> Arc<Dynamic> {
        self.state.load_full()
    }

    /// Waits until no upstream resolution is in flight, or `timeout` passes (OPS-007 drain).
    /// Returns true if everything finished.
    pub(crate) async fn drain(&self, timeout: Duration) -> bool {
        let max = u32::try_from(self.settings.max_inflight.max(1)).unwrap_or(u32::MAX);
        matches!(
            tokio::time::timeout(timeout, self.inflight.acquire_many(max)).await,
            Ok(Ok(_))
        )
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
            Transport::Tcp | Transport::Dot | Transport::Doh => len,
        }
    }

    /// The synchronous stage: parse, then answer from cache or defer.
    fn handle_sync(
        self: &Arc<Self>,
        req: &[u8],
        meta: &RequestMeta,
        out: &mut [u8],
        start: Instant,
        oc: &mut Outcome,
    ) -> Response {
        let st = self.state.load();
        oc.status = Status::Malformed;
        let q = match parse_query(req) {
            Ok(q) => q,
            Err(QueryError::Drop) => {
                oc.status = Status::Dropped;
                return Response::Drop;
            }
            Err(QueryError::NotImp) => return ready(error_from_raw(req, rcode::NOTIMP, out)),
            Err(QueryError::FormErr(_)) => return ready(error_from_raw(req, rcode::FORMERR, out)),
            Err(QueryError::BadVers) => {
                return ready(badvers_from_raw(req, self.settings.edns_payload, out));
            }
        };
        oc.qtype = q.qtype;
        let special = match self.pre_checks(&q, meta, out, start, oc) {
            Ok(special) => special,
            Err(early) => return early,
        };
        // REQ: DNS-010 — local data is authoritative and answered before cache/upstreams.
        if let Some(len) =
            st.policy
                .local
                .answer(&q, out, response_edns(&q, self.settings.edns_payload, None))
        {
            oc.status = Status::Local;
            return Response::Ready(self.finish(&q, out, len, meta.transport));
        }
        // REQ: FLT-006 — client identification (`spec/03` §3 step 2), including client IDs from
        // the DoT SNI or the DoH path.
        let who = Who {
            peer: meta.peer.ip(),
            mac: q.edns.as_ref().and_then(telltale_proto::Edns::client_mac),
            client_id: meta.client_id,
        };
        let ident = st.policy.clients.identify(
            who.peer,
            who.client_id.as_ref().map(telltale_net::ClientId::as_str),
            who.mac,
            &self.neighbors,
        );
        oc.client_ref = ident.client.map_or(0, |c| u32::from(c) + 1);
        oc.group = st
            .policy
            .clients
            .group_ids(ident)
            .first()
            .copied()
            .unwrap_or(0);
        // REQ: FLT-003 — the filter decision (`spec/03` §3 step 6), before the cache.
        if let Some(blocked) = self.filter_block(&q, meta, out, oc, who) {
            return blocked;
        }
        let groups = st.policy.clients.group_names(ident);
        self.resolve_or_defer(req, &q, special, groups, who, meta, out, start, oc)
    }

    /// `spec/03` §3 steps 2–4: access, rate limit, loop tag, ANY, special names. Returns the
    /// special-name class to continue with, or the response to send right away.
    fn pre_checks(
        &self,
        q: &Query<'_>,
        meta: &RequestMeta,
        out: &mut [u8],
        start: Instant,
        oc: &mut Outcome,
    ) -> Result<Option<Special>, Response> {
        let st = self.state.load();
        let q = *q;
        oc.status = Status::Refused;
        // 08 §6 — never an open resolver: refuse clients outside allowed_networks.
        if !telltale_policy::is_allowed(&st.policy.allowed, meta.peer.ip()) {
            return Err(self.simple(
                &q,
                out,
                rcode::REFUSED,
                Some((ede::PROHIBITED, "client not allowed")),
                meta,
            ));
        }
        // REQ: DNS-014 — per-client rate limit.
        if let Some(rl) = &st.policy.limiter
            && !rl.check(meta.peer.ip(), start)
        {
            oc.status = Status::RateLimited;
            return Err(match st.policy.limit_action {
                RateLimitAction::Drop => Response::Drop,
                RateLimitAction::Refused => self.simple(
                    &q,
                    out,
                    rcode::REFUSED,
                    Some((ede::PROHIBITED, "rate limited")),
                    meta,
                ),
            });
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
            oc.status = Status::Dropped;
            return Err(Response::Drop);
        }
        oc.status = Status::Special;
        // REQ: DNS-019 — answer ANY with the RFC 8482 minimal response (no amplification).
        if q.is_any() {
            let edns = response_edns(&q, self.settings.edns_payload, None);
            let len = ResponseBuilder::new(&q, out, rcode::NOERROR)
                .ok()
                .and_then(|mut b| {
                    b.answer_any_refusal(3600).ok()?;
                    b.finish(edns).ok()
                });
            return Err(ready(len.map(|l| self.finish(&q, out, l, meta.transport))));
        }
        // DNS-019 / RFC 6761 — special names (ADR-014).
        let special = telltale_policy::classify(&q, &st.policy.special);
        match special {
            Some(Special::Refused) => Err(self.simple(&q, out, rcode::REFUSED, None, meta)),
            Some(Special::Nxdomain) => Err(self.simple(&q, out, rcode::NXDOMAIN, None, meta)),
            Some(Special::Localhost) => Err(self.localhost(&q, out, meta)),
            other => Ok(other),
        }
    }

    /// Routing, private-PTR handling, cache lookup, and deferral to upstreams.
    #[allow(clippy::too_many_arguments)]
    fn resolve_or_defer(
        self: &Arc<Self>,
        req: &[u8],
        q: &Query<'_>,
        special: Option<Special>,
        groups: &[Box<str>],
        who: Who,
        meta: &RequestMeta,
        out: &mut [u8],
        start: Instant,
        oc: &mut Outcome,
    ) -> Response {
        let st = self.state.load();
        let q = *q;
        let question = Question::from_query(&q);
        // REQ: FLT-005, UPS-007 — routes can match the client's groups.
        let selection = st.router.select(&question, groups);
        // Private reverse lookups stay local unless a route explicitly forwards them (RFC 6303).
        if special == Some(Special::PrivatePtr) && !selection.is_some_and(|s| s.routed) {
            return self.simple(&q, out, rcode::NXDOMAIN, None, meta);
        }
        let Some(sel) = selection else {
            // No upstream group applies (none configured): we can't resolve this.
            oc.status = Status::Refused;
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
        match self.cache.get(&key, &q.qname, &client, start, out) {
            Lookup::Hit { len, prefetch } => {
                if prefetch {
                    self.prefetch(req, key, sel.view);
                }
                oc.status = Status::Cached;
                let len = match self.cname_block(&q, who, out, len) {
                    Some((blocked, list)) => {
                        oc.status = Status::Blocked;
                        oc.rule = Some(cname_rule(list));
                        blocked
                    }
                    None => len,
                };
                Response::Ready(self.finish(&q, out, len, meta.transport))
            }
            Lookup::Expired => self.defer(req, meta, key, sel.view, true, start, *oc, who),
            Lookup::Miss => self.defer(req, meta, key, sel.view, false, start, *oc, who),
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

    /// Answers a blocked query (NXDOMAIN + EDE 15 naming the list; block modes are T2.6), or
    /// returns `None` to resolve normally. Allocation-free on the steady state.
    /// Runs the client's filter on `name` (wire format). `None` when there's no filter or
    /// blocking is paused for the client's group (FLT-009).
    fn decide_for(
        &self,
        f: &FilterState,
        who: Who,
        name: &[u8],
        qtype: u16,
    ) -> Option<(Identity, Decision)> {
        let ident = f.clients.identify(
            who.peer,
            who.client_id.as_ref().map(telltale_net::ClientId::as_str),
            who.mac,
            &self.neighbors,
        );
        let group = f.clients.primary_group(ident);
        if self.pause.is_paused(&group.name, unix_now) {
            return None;
        }
        let client = ClientCtx {
            ip: who.peer,
            name: f.clients.client(ident).map(|c| &*c.name),
            client_id: who.client_id.as_ref().map(telltale_net::ClientId::as_str),
        };
        let decision = FILTER_SCRATCH.with(|s| {
            f.matcher
                .decide(name, qtype, &client, f.mask(ident), &mut s.borrow_mut())
        });
        Some((ident, decision))
    }

    /// Builds the block answer for the client's group (FLT-008): null IP, NXDOMAIN, NODATA,
    /// REFUSED, or custom IPs, always with EDE 15/17 and (unless turned off) the list.
    fn block_answer(
        &self,
        q: &Query<'_>,
        out: &mut [u8],
        group: &Group,
        reason: &str,
    ) -> Option<usize> {
        let b = &group.block;
        let text = if b.ede_text { reason } else { "" };
        let edns = response_edns(q, self.settings.edns_payload, Some((b.ede_code, text)));
        let rc = match b.mode {
            BlockMode::Nxdomain => rcode::NXDOMAIN,
            BlockMode::Refused => rcode::REFUSED,
            BlockMode::NullIp | BlockMode::Nodata | BlockMode::CustomIp => rcode::NOERROR,
        };
        let mut r = ResponseBuilder::new(q, out, rc).ok()?;
        if b.mode != BlockMode::Refused {
            r.authoritative(true);
        }
        let (v4, v6): (&[Ipv4Addr], &[Ipv6Addr]) = match b.mode {
            BlockMode::NullIp => (&[Ipv4Addr::UNSPECIFIED], &[Ipv6Addr::UNSPECIFIED]),
            BlockMode::CustomIp => (&b.v4, &b.v6),
            _ => (&[], &[]),
        };
        let mut answered = false;
        match q.qtype {
            telltale_proto::rtype::A => {
                for ip in v4 {
                    r.answer_a(b.ttl, *ip).ok()?;
                    answered = true;
                }
            }
            telltale_proto::rtype::AAAA => {
                for ip in v6 {
                    r.answer_aaaa(b.ttl, *ip).ok()?;
                    answered = true;
                }
            }
            _ => {}
        }
        // NXDOMAIN and NODATA carry an SOA so clients cache the block for `ttl`.
        if !answered && b.mode != BlockMode::Refused {
            r.authority_soa(b.ttl).ok()?;
        }
        r.finish(edns).ok()
    }

    /// REQ: FLT-003, FLT-008 — answers a blocked query, or returns `None` to resolve normally.
    /// Allocation-free on the steady state.
    fn filter_block(
        &self,
        q: &Query<'_>,
        meta: &RequestMeta,
        out: &mut [u8],
        oc: &mut Outcome,
        who: Who,
    ) -> Option<Response> {
        let guard = self.filter.load();
        let f = guard.as_ref()?;
        let (ident, decision) = self.decide_for(f, who, q.qname.as_wire(), q.qtype)?;
        // REQ: FLT-013 — every block or allow decision is attributed in the event.
        let a = match decision {
            Decision::None => return None,
            Decision::Allow(a) => {
                oc.rule = Some(rule_of(&a, true));
                return None;
            }
            Decision::Block(a) => a,
        };
        oc.status = Status::Blocked;
        oc.rule = Some(rule_of(&a, false));
        let reason = f
            .reasons
            .get(usize::from(a.list))
            .map_or("blocked", String::as_str);
        let len = self.block_answer(q, out, f.clients.primary_group(ident), reason);
        Some(ready(len.map(|l| self.finish(q, out, l, meta.transport))))
    }

    /// REQ: FLT-007 — CNAME deep inspection: if any CNAME target in the answer is blocked for
    /// this client, replace the answer with the block answer and return its length. Runs on
    /// cache hits too, since cached answers are policy-neutral. Allocation-free.
    fn cname_block(
        &self,
        q: &Query<'_>,
        who: Who,
        out: &mut [u8],
        len: usize,
    ) -> Option<(usize, u16)> {
        let guard = self.filter.load();
        let f = guard.as_ref()?;
        let mut target = telltale_proto::NameBuf::default();
        let mut hit = None;
        for r in telltale_proto::records(out.get(..len)?).ok()?.flatten() {
            if r.section != telltale_proto::Section::Answer
                || r.rtype != telltale_proto::rtype::CNAME
            {
                continue;
            }
            if telltale_proto::read_name(&out[..len], r.rdata_off, &mut target).is_err() {
                continue;
            }
            match self.decide_for(f, who, target.as_wire(), q.qtype) {
                None => return None, // paused (or no filter): nothing to inspect
                Some((ident, Decision::Block(a))) => {
                    hit = Some((ident, a));
                    break;
                }
                Some(_) => {}
            }
        }
        let (ident, a) = hit?;
        let reason = f
            .cname_reasons
            .get(usize::from(a.list))
            .map_or("blocked", String::as_str);
        self.block_answer(q, out, f.clients.primary_group(ident), reason)
            .map(|len| (len, a.list))
    }

    /// FLT-007 for deferred (upstream or stale) answers: re-checks the final message.
    fn deferred_cname_block(
        &self,
        req: &[u8],
        who: Who,
        transport: Transport,
        mut bytes: Vec<u8>,
        status: Status,
    ) -> (Vec<u8>, Status, Option<u16>) {
        if !matches!(status, Status::Forwarded | Status::Stale) {
            return (bytes, status, None);
        }
        let Ok(q) = parse_query(req) else {
            return (bytes, status, None);
        };
        let len = bytes.len();
        bytes.resize(MAX_RESPONSE.max(len), 0);
        if let Some((l, list)) = self.cname_block(&q, who, &mut bytes, len) {
            let l = self.finish(&q, &mut bytes, l, transport);
            bytes.truncate(l);
            (bytes, Status::Blocked, Some(list))
        } else {
            bytes.truncate(len);
            (bytes, status, None)
        }
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

    #[allow(clippy::too_many_arguments)]
    fn defer(
        self: &Arc<Self>,
        req: &[u8],
        meta: &RequestMeta,
        key: CacheKey,
        view: u16,
        stale_ok: bool,
        start: Instant,
        mut oc: Outcome,
        who: Who,
    ) -> Response {
        let this = Arc::clone(self);
        let req = req.to_vec();
        let transport = meta.transport;
        let peer = meta.peer.ip();
        Response::Deferred(Box::pin(async move {
            let waited = Instant::now();
            let answer = Arc::clone(&this)
                .resolve_for_client(req.clone(), key, view, stale_ok, transport)
                .await
                .map(|(bytes, status)| {
                    this.deferred_cname_block(&req, who, transport, bytes, status)
                });
            let t_upstream = waited.elapsed();
            let (status, rcode) = match &answer {
                Some((bytes, status, list)) => {
                    if let Some(list) = list {
                        oc.rule = Some(cname_rule(*list));
                    }
                    (*status, Some(response_rcode(bytes)))
                }
                None => (Status::Dropped, None),
            };
            oc.status = status;
            this.metrics
                .record(proto(transport), status, rcode, oc.qtype, start.elapsed());
            let resp = answer.as_ref().map(|(bytes, _, _)| bytes.as_slice());
            this.emit(peer, transport, &req, resp, &oc, start, t_upstream);
            answer.map(|(bytes, _, _)| bytes)
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
    ) -> Option<(Vec<u8>, Status)> {
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
                        Some((out, Status::Forwarded))
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
        // A full Arc (not a borrowed guard): it's held across the upstream round trip.
        let st = self.state.load_full();
        let question = Question::from_query(q);
        // The view chosen at selection time (by qname, qtype, and client groups) names the group.
        let group = Arc::clone(st.router.group_by_view(view)?);
        let started = Instant::now();
        let result = group.resolve(question, self.settings.budget).await;
        // REQ: OBS-001 — one event per upstream exchange (prefetches and coalesced misses
        // included), for per-upstream analytics.
        let (upstream, attempts) = result
            .as_ref()
            .map_or((0, 0), |a| (a.upstream_id, a.attempts));
        self.telemetry.emit_upstream(&UpstreamEvent {
            ts_us: self.telemetry.ts_us(started),
            upstream,
            latency_us: micros(started.elapsed()),
            ok: result.is_ok(),
            attempts,
        });
        let answer = result.ok()?;
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
    ) -> Option<(Vec<u8>, Status)> {
        let mut len = None;
        if stale_ok {
            let edns = response_edns(q, self.settings.edns_payload, Some((ede::STALE_ANSWER, "")));
            let client = Client::from_query(q, edns);
            len = self
                .cache
                .get_stale(&key, &q.qname, &client, Instant::now(), out);
        }
        let status = if len.is_some() {
            Status::Stale
        } else {
            Status::ServFail
        };
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
        Some((std::mem::take(out), status))
    }

    /// Refreshes a hot entry in the background before it expires (DNS-008).
    fn prefetch(self: &Arc<Self>, req: &[u8], key: CacheKey, view: u16) {
        let Ok(permit) = Arc::clone(&self.inflight).try_acquire_owned() else {
            return;
        };
        // The cache-hit path runs on dedicated UDP worker threads with no ambient runtime:
        // spawn on the handle captured at construction, never `tokio::spawn` (it panics).
        let Some(rt) = &self.rt else {
            return;
        };
        let this = Arc::clone(self);
        let req = req.to_vec();
        rt.spawn(async move {
            let _ = this.resolve_shared(req, key, view, permit).await;
        });
    }
}

fn ready(len: Option<usize>) -> Response {
    len.map_or(Response::Drop, Response::Ready)
}

/// What the synchronous stage decided, for metrics.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Outcome {
    pub(crate) status: Status,
    pub(crate) qtype: u16,
    /// Configured client index + 1 (0 = unknown) and primary group (OBS-001).
    pub(crate) client_ref: u32,
    pub(crate) group: u16,
    /// The block or allow rule that decided (FLT-013).
    pub(crate) rule: Option<Rule>,
}

fn rule_of(a: &telltale_filter::matcher::Attribution, allow: bool) -> Rule {
    use telltale_filter::matcher::RuleRef;
    Rule {
        list: a.list,
        kind: match a.rule {
            RuleRef::Domain { .. } => RuleKind::Domain,
            RuleRef::ModRule { .. } => RuleKind::Modifier,
            RuleRef::Regex { .. } => RuleKind::Regex,
        },
        allow,
    }
}

fn cname_rule(list: u16) -> Rule {
    Rule {
        list,
        kind: RuleKind::Cname,
        allow: false,
    }
}

fn micros(d: Duration) -> u32 {
    u32::try_from(d.as_micros()).unwrap_or(u32::MAX)
}

impl Pipeline {
    /// REQ: OBS-001, OBS-002 — the query's event, into this thread's ring. Wait-free and
    /// allocation-free (after the thread's first event); reads the name from the request.
    #[allow(clippy::too_many_arguments)]
    fn emit(
        &self,
        peer: std::net::IpAddr,
        transport: Transport,
        req: &[u8],
        resp: Option<&[u8]>,
        oc: &Outcome,
        start: Instant,
        t_upstream: Duration,
    ) {
        let (name, qclass) = telltale_telemetry::event::question(req);
        let hdr = |i: usize| resp.and_then(|r| r.get(i)).copied().unwrap_or(0);
        let ip = match peer {
            std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            std::net::IpAddr::V6(v6) => v6,
        };
        let ev = QueryEvent {
            ts_us: self.telemetry.ts_us(start),
            client_ip: ip.octets(),
            client_ref: oc.client_ref,
            group: oc.group,
            qtype: oc.qtype,
            qclass,
            rcode: resp.map(|r| (response_rcode(r) & 0xFF) as u8),
            status: oc.status,
            proto: proto(transport),
            flags: u16::from_be_bytes([hdr(2), hdr(3)]),
            rule: oc.rule,
            upstream: 0,
            attempts: 0,
            t_total_us: micros(start.elapsed()),
            t_upstream_us: micros(t_upstream),
            resp_size: resp.map_or(0, |r| u16::try_from(r.len()).unwrap_or(u16::MAX)),
            answers: u16::from_be_bytes([hdr(6), hdr(7)]),
        };
        self.telemetry.emit_query(&ev, name);
    }
}

fn proto(t: Transport) -> Proto {
    match t {
        Transport::Udp => Proto::Udp,
        Transport::Tcp => Proto::Tcp,
        Transport::Dot => Proto::Dot,
        Transport::Doh => Proto::Doh,
    }
}

/// RCODE of a response (low 4 bits; extended RCODEs are rare and counted via their low bits).
fn response_rcode(msg: &[u8]) -> u16 {
    msg.get(3).map_or(0, |b| u16::from(b & 0x0F))
}

/// `Arc<Pipeline>` is the handler every listener shares.
#[derive(Debug, Clone)]
pub(crate) struct Handler(pub(crate) Arc<Pipeline>);

impl QueryHandler for Handler {
    fn handle(&self, req: &[u8], meta: &RequestMeta, out: &mut [u8]) -> Response {
        let start = Instant::now();
        let mut oc = Outcome {
            status: Status::Dropped,
            qtype: 0,
            client_ref: 0,
            group: 0,
            rule: None,
        };
        let resp = self.0.handle_sync(req, meta, out, start, &mut oc);
        // REQ: OBS-002 — counters on the hot path: lock-free, allocation-free. Deferred answers
        // are recorded when their future completes.
        match &resp {
            Response::Ready(len) => {
                let rc = response_rcode(&out[..*len]);
                self.0.metrics.record(
                    proto(meta.transport),
                    oc.status,
                    Some(rc),
                    oc.qtype,
                    start.elapsed(),
                );
                let resp = Some(&out[..*len]);
                self.0.emit(
                    meta.peer.ip(),
                    meta.transport,
                    req,
                    resp,
                    &oc,
                    start,
                    Duration::ZERO,
                );
            }
            Response::Drop => {
                self.0.metrics.record(
                    proto(meta.transport),
                    oc.status,
                    None,
                    oc.qtype,
                    start.elapsed(),
                );
                self.0.emit(
                    meta.peer.ip(),
                    meta.transport,
                    req,
                    None,
                    &oc,
                    start,
                    Duration::ZERO,
                );
            }
            Response::Deferred(_) => {}
        }
        resp
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
            client_id: None,
        }
    }

    fn rcode_of(p: &Arc<Pipeline>, req: &[u8]) -> Option<u16> {
        let mut out = [0u8; 4096];
        match Handler(Arc::clone(p)).handle(req, &meta(), &mut out) {
            Response::Ready(len) => Some(summarize(&out[..len]).unwrap().rcode),
            _ => None,
        }
    }

    /// Compiles `rules` into a snapshot and installs it as the pipeline's filter.
    fn install_filter(p: &Pipeline, rules: &str, lookup: telltale_filter::matcher::Lookup) {
        use telltale_filter::compile::{CompileOptions, ListData, ListInput, compile};
        use telltale_filter::matcher::Overlay;
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("snap");
        let input = ListInput {
            name: "ads".into(),
            options: telltale_filter::parse::ListOptions::default(),
            data: ListData::Bytes(rules.as_bytes().to_vec()),
            source_hash: telltale_filter::fetch::content_hash(rules.as_bytes()),
            size: rules.len() as u64,
        };
        compile(vec![input], &out, &CompileOptions::default()).unwrap();
        let snap = Arc::new(telltale_filter::snapshot::Snapshot::open(&out).unwrap());
        let m = Matcher::with_lookup(Some(snap), Overlay::default(), lookup).unwrap();
        p.set_filter(Some(Arc::new(m)));
    }

    #[test]
    fn flt_008_blocked_names_get_null_ip_with_ede() {
        use telltale_filter::matcher::Lookup;
        for lookup in [Lookup::Walk, Lookup::Indexed] {
            let p = pipeline();
            install_filter(&p, "||ads.example.com^\n@@||ok.ads.example.com^\n", lookup);
            let mut out = [0u8; 4096];
            let Response::Ready(len) = Handler(Arc::clone(&p)).handle(
                &query("x.ads.example.com", rtype::A, true),
                &meta(),
                &mut out,
            ) else {
                panic!("blocked queries are answered immediately");
            };
            let s = summarize(&out[..len]).unwrap();
            // Default block mode: null IP (0.0.0.0 for A).
            assert_eq!((s.rcode, s.answers), (rcode::NOERROR, 1), "{lookup:?}");
            let text = b"blocked by list ads";
            assert!(
                out[..len].windows(text.len()).any(|w| w == text),
                "EDE 15 names the list"
            );
            // Not blocked: allowed by @@, or unlisted. No upstreams here, so they're REFUSED.
            assert_eq!(
                rcode_of(&p, &query("ok.ads.example.com", rtype::A, true)),
                Some(rcode::REFUSED)
            );
            assert_eq!(
                rcode_of(&p, &query("example.com", rtype::A, true)),
                Some(rcode::REFUSED)
            );
            // Removing the filter stops blocking at once.
            p.filter.store(None);
            assert_eq!(
                rcode_of(&p, &query("ads.example.com", rtype::A, true)),
                Some(rcode::REFUSED)
            );
        }
    }

    #[test]
    fn flt_005_groups_select_lists_per_client() {
        use telltale_filter::matcher::Lookup;
        let cfg: telltale_config::Config = telltale_config::Loader::new()
            .toml_str(
                "t.toml",
                r#"
[[list]]
name = "ads"
rules = ["||x^"]

[[group]]
name = "default"
lists = []

[[group]]
name = "kids"
lists = ["ads"]
block_mode = "nxdomain"

[[client]]
name = "tablet"
match = ["10.0.0.5", "aa:bb:cc:dd:ee:01"]
groups = ["kids"]
"#,
            )
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config;
        let p = Pipeline::new(
            Settings::default(),
            Arc::new(Cache::new(CachePolicy::default())),
            Arc::new(Router::default()),
            Policy {
                clients: Arc::new(ClientTable::from_config(&cfg)),
                ..Policy::open()
            },
        );
        // The compiled snapshot names its one list "ads" (see install_filter).
        install_filter(&p, "||ads.example.com^\n", Lookup::Indexed);
        let ask = |peer: &str| {
            let mut out = [0u8; 4096];
            let meta = RequestMeta {
                peer: peer.parse().unwrap(),
                local: None,
                transport: Transport::Udp,
                client_id: None,
            };
            match Handler(Arc::clone(&p)).handle(
                &query("ads.example.com", rtype::A, true),
                &meta,
                &mut out,
            ) {
                Response::Ready(len) => summarize(&out[..len]).unwrap().rcode,
                _ => u16::MAX,
            }
        };
        assert_eq!(
            ask("10.0.0.5:1000"),
            rcode::NXDOMAIN,
            "kids group has the list"
        );
        assert_eq!(
            ask("10.0.0.9:1000"),
            rcode::REFUSED,
            "default group has no lists"
        );
        // Recognized by MAC from the neighbor table, at any address.
        p.neighbors.replace([(
            "10.0.0.77".parse().unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
        )]);
        assert_eq!(ask("10.0.0.77:1000"), rcode::NXDOMAIN);
    }

    /// A pipeline with the given config's clients/groups, a never-contacted upstream (so the
    /// cache path runs), and `rules` installed as list "ads".
    fn pipeline_with(cfg_toml: &str, rules: &str) -> Arc<Pipeline> {
        let cfg: telltale_config::Config = telltale_config::Loader::new()
            .toml_str("t.toml", cfg_toml)
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config;
        let router = Router::from_config(&cfg).unwrap();
        let p = Pipeline::new(
            Settings::default(),
            Arc::new(Cache::new(CachePolicy::default())),
            Arc::new(router),
            Policy {
                clients: Arc::new(ClientTable::from_config(&cfg)),
                ..Policy::open()
            },
        );
        install_filter(&p, rules, telltale_filter::matcher::Lookup::Indexed);
        p
    }

    fn ask_from(p: &Arc<Pipeline>, peer: &str, name: &str, qtype: u16) -> Vec<u8> {
        let mut out = [0u8; 4096];
        let meta = RequestMeta {
            peer: format!("{peer}:1000").parse().unwrap(),
            local: None,
            transport: Transport::Udp,
            client_id: None,
        };
        match Handler(Arc::clone(p)).handle(&query(name, qtype, true), &meta, &mut out) {
            Response::Ready(len) => out[..len].to_vec(),
            _ => Vec::new(),
        }
    }

    fn contains(msg: &[u8], needle: &[u8]) -> bool {
        msg.windows(needle.len()).any(|w| w == needle)
    }

    const UPSTREAM: &str = "[[upstream]]\nname = \"u\"\nurl = \"udp://127.0.0.1:9\"\n[[upstream_group]]\nname = \"default\"\nmembers = [\"u\"]\n";

    #[test]
    fn flt_008_block_modes_per_group() {
        let cfg = format!(
            r#"{UPSTREAM}
[[list]]
name = "ads"
rules = ["||x^"]
[[group]]
name = "nx"
block_mode = "nxdomain"
[[group]]
name = "nodata"
block_mode = "nodata"
[[group]]
name = "refused"
block_mode = "refused"
[[group]]
name = "custom"
block_mode = "custom_ip"
block_ips = ["192.0.2.7", "fd00::7"]
block_ttl = 300
[[group]]
name = "kids"
ede = "filtered"
ede_text = false
[[client]]
name = "a"
match = ["10.0.0.1"]
groups = ["nx"]
[[client]]
name = "b"
match = ["10.0.0.2"]
groups = ["nodata"]
[[client]]
name = "c"
match = ["10.0.0.3"]
groups = ["refused"]
[[client]]
name = "d"
match = ["10.0.0.4"]
groups = ["custom"]
[[client]]
name = "e"
match = ["10.0.0.5"]
groups = ["kids"]
"#
        );
        let p = pipeline_with(&cfg, "||ads.example.com^\n");
        let sum = |m: &[u8]| {
            let s = summarize(m).unwrap();
            (s.rcode, s.answers)
        };
        let name = "ads.example.com";
        assert_eq!(
            sum(&ask_from(&p, "10.0.0.1", name, rtype::A)),
            (rcode::NXDOMAIN, 0)
        );
        assert_eq!(
            sum(&ask_from(&p, "10.0.0.2", name, rtype::A)),
            (rcode::NOERROR, 0)
        );
        assert_eq!(
            sum(&ask_from(&p, "10.0.0.3", name, rtype::A)),
            (rcode::REFUSED, 0)
        );
        let a = ask_from(&p, "10.0.0.4", name, rtype::A);
        assert_eq!(sum(&a), (rcode::NOERROR, 1));
        assert!(contains(&a, &[192, 0, 2, 7]));
        let aaaa = ask_from(&p, "10.0.0.4", name, rtype::AAAA);
        assert!(contains(
            &aaaa,
            &"fd00::7".parse::<Ipv6Addr>().unwrap().octets()
        ));
        assert_eq!(
            sum(&ask_from(&p, "10.0.0.4", name, rtype::TXT)),
            (rcode::NOERROR, 0)
        );
        // Null IP (default mode) with EDE 17 and no list text: option 15, length 2, code 17.
        let e = ask_from(&p, "10.0.0.5", name, rtype::AAAA);
        assert_eq!(sum(&e), (rcode::NOERROR, 1));
        assert!(contains(&e, &[0, 15, 0, 2, 0, 17]));
        assert!(!contains(&e, b"blocked by list"));
    }

    #[test]
    fn flt_007_cname_targets_are_inspected_on_cache_hits() {
        let cfg = format!("{UPSTREAM}[[list]]\nname = \"ads\"\nrules = [\"||x^\"]\n");
        let p = pipeline_with(&cfg, "||tracker.ads.example.com^\n");
        // Cache an answer for www.example.com that CNAMEs into a blocked name.
        let cache_answer = |qname: &str, target: &str| {
            let req = query(qname, rtype::A, false);
            let q = parse_query(&req).unwrap();
            let mut out = [0u8; 512];
            let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
            b.answer_cname(300, &NameBuf::from_presentation(target).unwrap())
                .unwrap();
            b.answer_a(300, Ipv4Addr::new(203, 0, 113, 9)).unwrap();
            let len = b.finish(None).unwrap();
            let view = p
                .current()
                .router
                .select(&Question::from_query(&q), &["default"])
                .unwrap()
                .view;
            p.cache
                .insert(&p.key(&q, view), &q, &out[..len], Instant::now())
                .unwrap();
        };
        cache_answer("www.example.com", "tracker.ads.example.com");
        cache_answer("cdn.example.com", "edge.example.net");
        let blocked = ask_from(&p, "10.0.0.1", "www.example.com", rtype::A);
        let s = summarize(&blocked).unwrap();
        assert_eq!((s.rcode, s.answers), (rcode::NOERROR, 1));
        assert!(
            contains(&blocked, &[0, 0, 0, 0]),
            "null IP replaces the answer"
        );
        assert!(contains(&blocked, b"CNAME target blocked by list ads"));
        let fine = ask_from(&p, "10.0.0.1", "cdn.example.com", rtype::A);
        assert!(
            contains(&fine, &[203, 0, 113, 9]),
            "unlisted chain is served from cache"
        );
    }

    /// UDP workers are plain threads with no tokio context; a prefetch-eligible cache hit
    /// there used to `tokio::spawn` and panic, killing the server.
    #[test]
    fn dns_008_prefetch_from_a_non_runtime_thread() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let p = rt.block_on(async { pipeline_with(UPSTREAM, "||unrelated.example^\n") });
        let req = query("hot.example.com", rtype::A, false);
        let q = parse_query(&req).unwrap();
        let mut out = [0u8; 512];
        let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
        b.answer_a(100, Ipv4Addr::new(203, 0, 113, 7)).unwrap();
        let len = b.finish(None).unwrap();
        let view = p
            .current()
            .router
            .select(&Question::from_query(&q), &["default"])
            .unwrap()
            .view;
        // 95% of the TTL gone: past the prefetch threshold.
        let stored = Instant::now().checked_sub(Duration::from_secs(95)).unwrap();
        p.cache
            .insert(&p.key(&q, view), &q, &out[..len], stored)
            .unwrap();
        // This test thread is outside the runtime, like a UDP worker.
        assert!(tokio::runtime::Handle::try_current().is_err());
        for _ in 0..5 {
            let a = ask_from(&p, "10.0.0.1", "hot.example.com", rtype::A);
            assert!(contains(&a, &[203, 0, 113, 7]), "served from cache");
        }
        drop(p);
        rt.shutdown_timeout(Duration::from_secs(1));
    }

    /// Every answered query leaves an event with its client, status, rule, and name.
    #[test]
    fn obs_001_queries_emit_attributed_events() {
        use telltale_telemetry::event::Record;
        let cfg = format!(
            "{UPSTREAM}[[list]]\nname = \"ads\"\nrules = [\"||x^\"]\n\
             [[client]]\nname = \"tablet\"\nmatch = [\"10.0.0.5\"]\n"
        );
        let p = pipeline_with(&cfg, "||ads.example.com^\n@@||ok.ads.example.com^\n");

        // Blocked, from a configured client.
        let _ = ask_from(&p, "10.0.0.5", "X.Ads.Example.com", rtype::A);
        // Allowed by an allow rule: deferred to the upstream, so its event comes when the
        // deferred answer completes (not driven in this test).
        let _ = ask_from(&p, "10.0.0.9", "ok.ads.example.com", rtype::A);
        // A cache hit.
        let req = query("www.example.com", rtype::AAAA, false);
        let pq = parse_query(&req).unwrap();
        let mut out = [0u8; 512];
        let mut b = ResponseBuilder::new(&pq, &mut out, rcode::NOERROR).unwrap();
        b.answer_aaaa(300, Ipv6Addr::LOCALHOST).unwrap();
        let len = b.finish(None).unwrap();
        let view = p
            .current()
            .router
            .select(&Question::from_query(&pq), &["default"])
            .unwrap()
            .view;
        p.cache
            .insert(&p.key(&pq, view), &pq, &out[..len], Instant::now())
            .unwrap();
        let _ = ask_from(&p, "10.0.0.9", "www.example.com", rtype::AAAA);

        let mut drainer = p.telemetry.drainer();
        let mut got = Vec::new();
        drainer.drain(|r| got.push(r));
        let queries: Vec<_> = got
            .iter()
            .filter_map(|r| match r {
                Record::Query(e, n) => Some((*e, n.dotted())),
                Record::Upstream(_) => None,
            })
            .collect();
        assert_eq!(queries.len(), 2, "{queries:?}");
        let (blocked, name) = &queries[0];
        assert_eq!(name, "x.ads.example.com", "lowercased");
        assert_eq!(blocked.status, Status::Blocked);
        assert_eq!(blocked.client_ref, 1, "tablet");
        assert_eq!(
            blocked.rule,
            Some(Rule {
                list: 0,
                kind: RuleKind::Domain,
                allow: false
            })
        );
        assert_eq!(blocked.rcode, Some(0), "null IP answer");
        assert_eq!(blocked.answers, 1);
        assert_eq!(blocked.client_ip[10..], [0xff, 0xff, 10, 0, 0, 5]);
        let (hit, name) = &queries[1];
        assert_eq!(
            (name.as_str(), hit.status),
            ("www.example.com", Status::Cached)
        );
        assert_eq!((hit.qtype, hit.qclass, hit.client_ref), (rtype::AAAA, 1, 0));
        assert!(hit.resp_size > 0 && hit.flags & 0x8000 != 0, "QR set");
    }

    #[test]
    fn flt_009_pause_global_and_per_group() {
        let cfg = format!("{UPSTREAM}[[list]]\nname = \"ads\"\nrules = [\"||x^\"]\n");
        let p = pipeline_with(&cfg, "||ads.example.com^\n");
        let blocked = |p: &Arc<Pipeline>| {
            let m = ask_from(p, "10.0.0.1", "ads.example.com", rtype::A);
            // Unblocked queries go upstream (deferred), so no immediate answer.
            !m.is_empty() && contains(&m, b"blocked by list ads")
        };
        assert!(blocked(&p));
        p.pause.pause_all(unix_now() + 600);
        assert!(!blocked(&p), "global pause");
        p.pause.pause_all(0);
        assert!(blocked(&p));
        p.pause.pause_group("default", unix_now() + 600);
        assert!(!blocked(&p), "the client's group is paused");
        p.pause.pause_group("default", unix_now() - 1);
        assert!(blocked(&p), "an expired pause resumes on its own");
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
        let Response::Ready(len) = Handler(Arc::clone(&p)).handle(
            &query("example.com", rtype::ANY, false),
            &meta(),
            &mut out,
        ) else {
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
            Handler(Arc::clone(&p)).handle(&buf[..len], &meta(), &mut out),
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
            client_id: None,
        };
        let mut out = [0u8; 4096];
        match Handler(Arc::clone(p)).handle(&buf[..len], &meta, &mut out) {
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

#[cfg(test)]
mod reload_tests {
    use telltale_cache::CachePolicy;
    use telltale_proto::{NameBuf, build_query, rtype, summarize};

    use super::*;

    #[test]
    fn ops_009_reload_swaps_policy_for_new_queries() {
        let cache = Arc::new(Cache::new(CachePolicy::default()));
        let p = Pipeline::new(
            Settings::default(),
            cache,
            Arc::new(Router::default()),
            Policy::open(),
        );
        let mut buf = [0u8; 512];
        let n = NameBuf::from_presentation("nas.home.arpa").unwrap();
        let len = build_query(&mut buf, 1, &n, rtype::A, 1, true, None).unwrap();
        let meta = RequestMeta {
            peer: "10.0.0.2:5353".parse().unwrap(),
            local: None,
            transport: Transport::Udp,
            client_id: None,
        };
        let answer = |p: &Arc<Pipeline>| {
            let mut out = [0u8; 1024];
            match Handler(Arc::clone(p)).handle(&buf[..len], &meta, &mut out) {
                Response::Ready(l) => summarize(&out[..l]).map(|s| (s.rcode, s.answers)).ok(),
                _ => None,
            }
        };
        // No upstreams, no local record: REFUSED.
        assert_eq!(answer(&p), Some((rcode::REFUSED, 0)));
        let mut local = LocalData::default();
        local.add("nas.home.arpa", "A", "192.168.1.10", 60).unwrap();
        let mut policy = Policy::open();
        policy.local = Arc::new(local);
        p.reload(Arc::new(Router::default()), policy);
        assert_eq!(
            answer(&p),
            Some((rcode::NOERROR, 1)),
            "new local record answered after reload"
        );
    }
}
