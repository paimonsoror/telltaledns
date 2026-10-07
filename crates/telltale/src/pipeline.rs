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
    ClientTable, Group, Identity, LocalData, Neighbors, Pause, RateLimiter, RewriteTarget, Special,
};
use telltale_proto::{
    EdnsOut, NameBuf, Query, QueryError, ResponseBuilder, Section, badvers_from_raw, build_query,
    ede, error_from_raw, parse_query, rcode, records, response_edns, rtype, truncate_for_udp,
    udp_limit,
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
    /// Quick rules (T6.12, ADR-067), decided before the lists.
    pub(crate) quick: Arc<telltale_policy::QuickRules>,
    /// REQ: DNS-018 (T7.22) — authoritative zones, most specific first.
    pub(crate) zones: Arc<Vec<Zone>>,
}

/// REQ: DNS-018 (T7.22) — one authoritative zone.
#[derive(Debug, Default)]
pub(crate) struct Zone {
    pub(crate) apex: NameBuf,
    pub(crate) data: LocalData,
    /// Groups that see it (empty: everyone).
    pub(crate) groups: Vec<Box<str>>,
    pub(crate) negative_ttl: u32,
    /// REQ: DNS-018 (T9.18) — the apex's SOA (RDATA) and name servers: the zone file's, else
    /// made up (`localhost.`, as resolvers serving local zones do).
    pub(crate) soa: Vec<u8>,
    pub(crate) ns: Vec<NameBuf>,
    /// TTL of the SOA and NS answers.
    pub(crate) ttl: u32,
}

impl Policy {
    pub(crate) fn from_config(cfg: &telltale_config::Config, local: LocalData) -> Self {
        let clients = ClientTable::from_config(cfg);
        let quick = Arc::new(telltale_policy::QuickRules::from_config(cfg, &clients));
        Self {
            allowed: cfg.access.allowed_networks.clone(),
            limiter: RateLimiter::new(&cfg.ratelimit),
            limit_action: cfg.ratelimit.action,
            special: cfg.special.clone(),
            local: Arc::new(local),
            quick,
            clients: Arc::new(clients),
            zones: Arc::default(),
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

/// REQ: FLT-010 (T7.10) — which schedules are on, per group (`ClientTable` order), as the
/// 15-second ticker last computed it. Empty vectors when nothing is on.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ScheduleNow {
    /// Per group: the block-everything schedule that's on (its block reason and query-log
    /// reference).
    pub(crate) block_all: Vec<Option<(String, u16)>>,
    /// Per group: the lists (and `svc-` service lists) schedules add right now.
    pub(crate) extras: Vec<Vec<String>>,
    /// Lists and services that only schedules turn on: off for a group outside its windows,
    /// even when it uses every list.
    pub(crate) scheduled: Vec<String>,
    /// Every schedule's query-log reference and name.
    pub(crate) names: Vec<(u16, String)>,
}

impl ScheduleNow {
    /// The state at `now` for `groups` (`ClientTable` order).
    pub(crate) fn compute(
        cfg: &telltale_config::Config,
        compiled: &[telltale_config::schedule::Compiled],
        groups: &[telltale_policy::Group],
        now: i64,
    ) -> Self {
        let on: Vec<bool> = compiled.iter().map(|s| s.is_on(now)).collect();
        let mut block_all = vec![None; groups.len()];
        let mut extras = vec![Vec::new(); groups.len()];
        for (i, g) in groups.iter().enumerate() {
            let Some(gc) = cfg.group.iter().find(|x| x.name.as_str() == &*g.name) else {
                continue;
            };
            for (s, on) in compiled.iter().zip(&on) {
                if !*on || !gc.schedules.iter().any(|n| n.as_str() == s.name) {
                    continue;
                }
                if s.action == telltale_config::ScheduleAction::BlockAll {
                    if block_all[i].is_none() {
                        block_all[i] = Some((
                            format!("blocked by schedule {}", s.name),
                            telltale_policy::quick_ref(&s.name),
                        ));
                    }
                } else {
                    extras[i].extend(s.list_names());
                }
            }
        }
        let mut scheduled: Vec<String> = compiled
            .iter()
            .flat_map(telltale_config::schedule::Compiled::list_names)
            .collect();
        scheduled.sort();
        scheduled.dedup();
        Self {
            block_all: if block_all.iter().any(Option::is_some) {
                block_all
            } else {
                Vec::new()
            },
            extras: if extras.iter().any(|e| !e.is_empty()) {
                extras
            } else {
                Vec::new()
            },
            scheduled,
            names: compiled
                .iter()
                .map(|s| (telltale_policy::quick_ref(&s.name), s.name.clone()))
                .collect(),
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
    /// Lists per group, for devices that take their network's group (ADR-050).
    pub(crate) group_masks: Vec<ListMask>,
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
    pub(crate) fn new(
        matcher: Arc<Matcher>,
        clients: Arc<ClientTable>,
        sched: &ScheduleNow,
    ) -> Self {
        let names: Vec<String> = matcher
            .snapshot()
            .map(|s| s.manifest.lists.iter().map(|l| l.name.clone()).collect())
            .unwrap_or_default();
        // A group's lists → list IDs in this snapshot (a group naming a list that isn't
        // compiled yet simply doesn't get it until it is). REQ: FLT-012 (T7.9) — blocked
        // services (`svc-<id>` lists) apply only to the groups that name them, also when a
        // group uses every list.
        // REQ: FLT-010 (T7.10) — lists and services a schedule turns on apply during its
        // windows only (unless the group always uses them).
        let group_masks: Vec<ListMask> = clients
            .groups()
            .iter()
            .enumerate()
            .map(|(gi, g)| {
                let extra = sched.extras.get(gi);
                let mut m = ListMask::default();
                for (i, n) in names.iter().enumerate() {
                    let now = extra.is_some_and(|e| e.iter().any(|x| x == n));
                    let explicit = g
                        .lists
                        .as_ref()
                        .is_some_and(|l| l.iter().any(|l| **l == **n));
                    let wanted = now
                        || match telltale_config::services::of_list(n) {
                            Some(s) => g.services.iter().any(|x| **x == *s.id),
                            None if sched.scheduled.iter().any(|x| x == n) => explicit,
                            None => g.lists.is_none() || explicit,
                        };
                    if wanted && let Ok(id) = u16::try_from(i) {
                        m.set(id);
                    }
                }
                m
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
            net: None,
        };
        Self {
            client_masks: clients.clients().iter().map(|c| union(&c.groups)).collect(),
            default_mask: union(clients.group_ids(unknown)),
            group_masks: (0..clients.groups().len())
                .map(|g| union(&[u16::try_from(g).unwrap_or(0)]))
                .collect(),
            reasons: names
                .iter()
                .map(|n| match telltale_config::services::of_list(n) {
                    Some(s) => format!("blocked service {}", s.name),
                    None => format!("blocked by list {n}"),
                })
                .collect(),
            cname_reasons: names
                .iter()
                .map(|n| match telltale_config::services::of_list(n) {
                    Some(s) => format!("CNAME target blocked: service {}", s.name),
                    None => format!("CNAME target blocked by list {n}"),
                })
                .collect(),
            clients,
            matcher,
        }
    }

    pub(crate) fn mask(&self, id: Identity) -> &ListMask {
        if let Some(c) = id.client
            && self
                .clients
                .clients()
                .get(usize::from(c))
                .is_some_and(|c| !c.inherit)
            && let Some(m) = self.client_masks.get(usize::from(c))
        {
            return m;
        }
        id.net
            .and_then(|g| self.group_masks.get(usize::from(g)))
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
    /// REQ: FLT-010 (T7.10) — schedules on now (the ticker in `server` updates it).
    pub(crate) schedules: arc_swap::ArcSwap<ScheduleNow>,
    /// REQ: T8.2 — the routers' DHCP clients by address (names for devices; the API).
    pub(crate) router_leases: Arc<arc_swap::ArcSwap<crate::devices::Leases>>,
    /// REQ: T8.3 — the names devices announce over mDNS, by address.
    pub(crate) mdns_names: Arc<arc_swap::ArcSwap<crate::devices::Leases>>,
    /// REQ: OBS-007 (T7.18) — the dnstap tap, set once at startup (one atomic load per query
    /// when unset).
    pub(crate) dnstap: std::sync::OnceLock<Arc<crate::dnstap::Tap>>,
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
    /// DNSSEC validation (DNS-011), when `[dnssec] mode` isn't `off`; replaced on reload.
    dnssec: ArcSwapOption<Dnssec>,
    /// Validation counters, kept across reloads.
    pub(crate) dnssec_stats: Arc<telltale_upstream::dnssec::Stats>,
}

/// The validator and how strictly its verdict is applied.
#[derive(Debug)]
pub(crate) struct Dnssec {
    validator: telltale_upstream::dnssec::Validator,
    /// Serve bogus answers anyway (counted).
    permissive: bool,
}

/// Largest response we build for a deferred answer (TCP may carry up to 64 KiB).
const MAX_RESPONSE: usize = u16::MAX as usize;

/// REQ: DNS-013 (T9.8) — a bogus answer travels through the shared lookup as two bytes,
/// `[0xBE, code]`: shorter than any DNS message (at least 12), so nothing mistakes it for one.
fn bogus_marker(code: u16) -> Arc<[u8]> {
    Arc::from(vec![0xBE, u8::try_from(code).unwrap_or(6)])
}

fn bogus_code(resp: &[u8]) -> Option<u16> {
    match resp {
        [0xBE, c] => Some(u16::from(*c)),
        _ => None,
    }
}

fn bogus_text(code: u16) -> &'static str {
    match code {
        ede::SIGNATURE_EXPIRED => "DNSSEC validation failed: signature expired",
        ede::SIGNATURE_NOT_YET_VALID => "DNSSEC validation failed: signature not yet valid",
        ede::RRSIGS_MISSING => "DNSSEC validation failed: signatures missing",
        _ => "DNSSEC validation failed",
    }
}

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
            schedules: arc_swap::ArcSwap::from_pointee(ScheduleNow::default()),
            dnstap: std::sync::OnceLock::new(),
            router_leases: Arc::default(),
            mdns_names: Arc::default(),
            flights: Singleflight::new(),
            seed: rand::random(),
            loops: std::sync::atomic::AtomicU64::new(0),
            rt: tokio::runtime::Handle::try_current().ok(),
            dnssec: ArcSwapOption::empty(),
            dnssec_stats: Arc::default(),
        })
    }

    /// This process's cache hash of a wire-format name (for reloading a cache dump, DNS-009).
    pub(crate) fn name_hash(&self, wire: &[u8]) -> Option<u64> {
        let mut n = telltale_proto::NameBuf::default();
        telltale_proto::read_name_uncompressed(wire, 0, &mut n).ok()?;
        Some(n.hash64(self.seed))
    }

    /// REQ: DNS-011 — turns DNSSEC validation on or off for `cfg` (at start and on reload).
    pub(crate) fn set_dnssec(&self, cfg: &telltale_config::Config) {
        use telltale_config::DnssecMode;
        let permissive = match cfg.dnssec.mode {
            DnssecMode::Off => {
                self.dnssec.store(None);
                return;
            }
            DnssecMode::Validate => false,
            DnssecMode::Permissive => true,
        };
        // Negative trust anchors: configured, plus every route marked `dnssec_nta` (local
        // zones forwarded elsewhere are usually unsigned).
        let mut nta: Vec<String> = cfg
            .dnssec
            .negative_trust_anchors
            .iter()
            .map(ToString::to_string)
            .collect();
        for r in cfg.route.iter().filter(|r| r.dnssec_nta) {
            nta.extend(r.match_suffix.iter().map(ToString::to_string));
        }
        // REQ: DNS-011 (T9.8) — root anchors from a file when one is set.
        let validator =
            telltale_upstream::dnssec::Validator::new(&nta, Arc::clone(&self.dnssec_stats))
                .with_anchors_file(cfg.dnssec.trust_anchors_file.as_deref())
                .with_aggressive_nsec(cfg.dnssec.aggressive_nsec);
        self.dnssec.store(Some(Arc::new(Dnssec {
            validator,
            permissive,
        })));
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
        let sched = self.schedules.load();
        retire(
            self.filter
                .swap(Some(Arc::new(FilterState::new(matcher, clients, &sched)))),
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
            Transport::Tcp | Transport::Dot | Transport::Doh | Transport::Doq => len,
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
        // A query that can't be parsed has no device: it counts for `default`.
        oc.group = st.policy.clients.default_group_id();
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
        // REQ: FLT-006 — client identification (`spec/03` §3 step 2), including client IDs from
        // the DoT SNI or the DoH path. First, so every answer below (refusals, local records)
        // is logged with the device and its group (owner report 2026-10-07: local names were
        // logged under the first configured group).
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
        // REQ: DNS-018 (T7.22) — authoritative zones (per group), before any filtering.
        if !st.policy.zones.is_empty()
            && let Some(len) = self.zone_answer(&q, st.policy.clients.group_names(ident), out)
        {
            oc.status = Status::Local;
            return Response::Ready(self.finish(&q, out, len, meta.transport));
        }
        // REQ: FLT-005 (T6.12, ADR-067) — quick rules decide before any list.
        match self.quick_decision(&st.policy, q.qname.as_wire(), ident, who) {
            Some(m) if m.allow => oc.rule = Some(quick_rule(&st.policy, m)),
            Some(m) => {
                oc.status = Status::Blocked;
                oc.rule = Some(quick_rule(&st.policy, m));
                let len = self.block_answer(
                    &q,
                    out,
                    st.policy.clients.primary_group(ident),
                    "quick rule",
                );
                return ready(len.map(|l| self.finish(&q, out, l, meta.transport)));
            }
            // REQ: FLT-003 — the filter decision (`spec/03` §3 step 6), before the cache.
            None => {
                // REQ: FLT-010 (T7.10) — a schedule blocking everything for the group (bedtime).
                if let Some(len) = self.schedule_block(&q, out, &st.policy, ident, oc) {
                    return ready(Some(self.finish(&q, out, len, meta.transport)));
                }
                // REQ: FLT-014 (T9.20) — list rewrites (`$dnsrewrite`) win over blocking.
                if let Some(r) = self.list_rewrite(&q, who) {
                    let groups = st.policy.clients.group_names(ident);
                    return self.list_rewrite_answer(req, &q, r, groups, who, meta, out, start, oc);
                }
                if let Some(blocked) = self.filter_block(&q, meta, out, oc, who) {
                    return blocked;
                }
            }
        }
        let groups = st.policy.clients.group_names(ident);
        // REQ: DNS-016 (T9.10) — RFC 6147 §5.3.1: a reverse name inside the NAT64 prefix is
        // the IPv4 address's (a CNAME to its in-addr.arpa name, resolved like any other).
        if q.qtype == rtype::PTR
            && let Some(prefix) = st.policy.clients.primary_group(ident).dns64
            && let Some(target) = dns64_reverse_target(&q.qname, prefix)
        {
            return self.safe_search(req, &q, &target, groups, who, meta, out, start, oc);
        }
        // REQ: FLT-014 (T7.20) — the group's rewrites (blocks above still win).
        match st.policy.clients.primary_group(ident).rewrite_for(&q.qname) {
            Some(RewriteTarget::Addr(ip)) => {
                oc.status = Status::Local;
                return self.rewrite_answer(&q, ip, out, meta);
            }
            Some(RewriteTarget::Name(target)) => {
                return self.safe_search(req, &q, &target, groups, who, meta, out, start, oc);
            }
            None => {}
        }
        // REQ: FLT-011 (T7.11) — safe search: the engine's safe name instead.
        if let Some(target) = Self::safe_search_target(&q, st.policy.clients.primary_group(ident)) {
            return self.safe_search(req, &q, &target, groups, who, meta, out, start, oc);
        }
        self.resolve_or_defer(req, &q, special, groups, who, meta, out, start, oc)
    }

    /// REQ: DNS-018 (T7.22) — the answer from the most specific zone this client sees: its
    /// records, no data for the apex and empty non-terminals, else NXDOMAIN (authoritative,
    /// with an SOA).
    fn zone_answer(&self, q: &Query<'_>, groups: &[Box<str>], out: &mut [u8]) -> Option<usize> {
        let st = self.state.load();
        let z = st.policy.zones.iter().find(|z| {
            q.qname.is_subdomain_of(&z.apex)
                && (z.groups.is_empty() || z.groups.iter().any(|g| groups.contains(g)))
        })?;
        let edns = response_edns(q, self.settings.edns_payload, None);
        // REQ: DNS-018 (T9.18) — the apex's SOA and NS.
        if q.qname == z.apex && matches!(q.qtype, rtype::SOA | rtype::NS) {
            let mut b = ResponseBuilder::new(q, out, rcode::NOERROR).ok()?;
            b.authoritative(true);
            if q.qtype == rtype::SOA {
                b.answer_rdata(None, rtype::SOA, z.ttl, &z.soa).ok()?;
            } else {
                for ns in &z.ns {
                    b.answer_rdata(None, rtype::NS, z.ttl, ns.as_wire()).ok()?;
                }
            }
            return b.finish(edns).ok();
        }
        if let Some(len) = z.data.answer(q, out, edns) {
            return Some(len);
        }
        let exists = q.qname == z.apex || z.data.has_below(&q.qname);
        let rc = if exists {
            rcode::NOERROR
        } else {
            rcode::NXDOMAIN
        };
        let mut b = ResponseBuilder::new(q, out, rc).ok()?;
        // The zone's own SOA, owned by the apex (RFC 2308), with the negative TTL.
        b.authoritative(true)
            .authority_rdata(&z.apex, rtype::SOA, z.negative_ttl, &z.soa)
            .ok()?;
        b.finish(response_edns(q, self.settings.edns_payload, None))
            .ok()
    }

    /// REQ: DNS-016 (T7.21) — the client's group NAT64 prefix and (T9.10) exclusions, when
    /// it has DNS64.
    fn dns64_for(&self, policy: &Policy, who: Who) -> Option<(std::net::Ipv6Addr, Vec<Cidr>)> {
        let ident = policy.clients.identify(
            who.peer,
            who.client_id.as_ref().map(telltale_net::ClientId::as_str),
            who.mac,
            &self.neighbors,
        );
        let g = policy.clients.primary_group(ident);
        g.dns64.map(|p| (p, g.dns64_exclude.clone()))
    }

    /// REQ: DNS-016 — `name` answered from the cache, else resolved (coalesced and cached
    /// like any upstream answer), without a query event: DNS64's A lookup.
    fn cached_internal(&self, req: &[u8], groups: &[Box<str>]) -> Option<Internal> {
        let q = parse_query(req).ok()?;
        let st = self.state.load();
        let sel = st.router.select(&Question::from_query(&q), groups)?;
        let key = self.key(&q, sel.view);
        let client = Client::from_query(&q, response_edns(&q, self.settings.edns_payload, None));
        let mut out = vec![0u8; MAX_RESPONSE];
        match self
            .cache
            .get(&key, &q.qname, &client, Instant::now(), &mut out)
        {
            Lookup::Hit { len, .. } => {
                out.truncate(len);
                Some(Internal::Hit(out))
            }
            Lookup::Expired | Lookup::Miss => Some(Internal::Miss(key, sel.view)),
        }
    }

    pub(crate) async fn lookup_internal(
        self: &Arc<Self>,
        req: Vec<u8>,
        groups: &[Box<str>],
    ) -> Option<Vec<u8>> {
        let (key, view) = match self.cached_internal(&req, groups)? {
            Internal::Hit(bytes) => return Some(bytes),
            Internal::Miss(key, view) => (key, view),
        };
        let permit = Arc::clone(&self.inflight).try_acquire_owned().ok()?;
        let a = Arc::clone(self)
            .resolve_shared(req, key, view, permit)
            .await?;
        Some(a.to_vec())
    }

    /// The A query for the AAAA query `req` (same ID, RD, and DO).
    fn a_query(req: &[u8]) -> Option<Vec<u8>> {
        let q = parse_query(req).ok()?;
        let edns = q.edns.as_ref().map(|e| EdnsOut {
            udp_payload: e.udp_payload,
            dnssec_ok: e.dnssec_ok,
            ede: None,
        });
        let mut buf = [0u8; 512];
        let len = build_query(
            &mut buf,
            q.header.id,
            &q.qname,
            rtype::A,
            q.qclass,
            q.header.flags.rd(),
            edns,
        )
        .ok()?;
        Some(buf[..len].to_vec())
    }

    /// REQ: DNS-016 — the AAAA answer made from the name's A records (finished for the
    /// client's transport), or `None` when the name has no A records either.
    async fn dns64_synthesize(
        self: &Arc<Self>,
        req: &[u8],
        d: &Dns64,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        let a = self.lookup_internal(Self::a_query(req)?, &d.groups).await?;
        let mut out = vec![0u8; MAX_RESPONSE];
        let len = self.synthesize_aaaa(req, &a, d.prefix, &d.exclude, &mut out)?;
        let q = parse_query(req).ok()?;
        let len = self.finish(&q, &mut out, len, transport);
        out.truncate(len);
        Some(out)
    }

    /// RFC 6147 §5.1.7: the CNAMEs and A records of `a` (the A answer) as an answer to `req`
    /// (the AAAA query), each A turned into `prefix` + the IPv4 address. `None` if there's no
    /// A record to use.
    fn synthesize_aaaa(
        &self,
        req: &[u8],
        a: &[u8],
        prefix: std::net::Ipv6Addr,
        exclude: &[Cidr],
        out: &mut [u8],
    ) -> Option<usize> {
        let q = parse_query(req).ok()?;
        let recs: Vec<telltale_proto::Record> = records(a)
            .ok()?
            .flatten()
            .filter(|r| r.section == Section::Answer)
            .collect();
        let usable = |r: &telltale_proto::Record| {
            r.rtype == rtype::A
                && r.rdlen == 4
                && !matches!(r.rdata(a)[0], 0 | 127)
                && r.rdata(a)[..2] != [169, 254]
                // REQ: DNS-016 (T9.10) — and none in the exclusion set.
                && answer_ip(rtype::A, r.rdata(a)).is_none_or(|ip| !exclude.iter().any(|c| c.contains(ip)))
        };
        if !recs.iter().any(usable) {
            return None;
        }
        let mut b = ResponseBuilder::new(&q, out, rcode::NOERROR).ok()?;
        let p = prefix.octets();
        for r in &recs {
            let mut owner = NameBuf::default();
            telltale_proto::read_name(a, r.name_off, &mut owner).ok()?;
            if r.rtype == rtype::CNAME {
                let mut target = NameBuf::default();
                telltale_proto::read_name(a, r.rdata_off, &mut target).ok()?;
                b.answer_rdata(Some(&owner), rtype::CNAME, r.ttl, target.as_wire())
                    .ok()?;
            } else if usable(r) {
                let mut v6 = [0u8; 16];
                v6[..12].copy_from_slice(&p[..12]);
                v6[12..].copy_from_slice(r.rdata(a));
                b.answer_rdata(Some(&owner), rtype::AAAA, r.ttl, &v6).ok()?;
            }
        }
        b.finish(response_edns(&q, self.settings.edns_payload, None))
            .ok()
    }

    /// REQ: DNS-016 (T9.10) — `resp` (an AAAA answer) without its excluded AAAA records,
    /// when it has some and others remain (with none left, it's synthesized instead). The
    /// CNAMEs stay; signatures go, since the set they signed changed.
    fn dns64_filter(&self, req: &[u8], resp: &[u8], exclude: &[Cidr]) -> Option<Vec<u8>> {
        if response_rcode(resp) != rcode::NOERROR {
            return None;
        }
        let recs: Vec<telltale_proto::Record> = records(resp)
            .ok()?
            .flatten()
            .filter(|r| r.section == Section::Answer)
            .collect();
        let aaaa = |r: &&telltale_proto::Record| r.rtype == rtype::AAAA;
        let excluded = |r: &telltale_proto::Record| {
            answer_ip(rtype::AAAA, r.rdata(resp)).is_some_and(|ip| dns64_excluded(ip, exclude))
        };
        if !recs.iter().filter(aaaa).any(excluded) || recs.iter().filter(aaaa).all(excluded) {
            return None;
        }
        let q = parse_query(req).ok()?;
        let mut out = vec![0u8; MAX_RESPONSE];
        let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).ok()?;
        for r in &recs {
            let mut owner = NameBuf::default();
            telltale_proto::read_name(resp, r.name_off, &mut owner).ok()?;
            if r.rtype == rtype::CNAME {
                let mut target = NameBuf::default();
                telltale_proto::read_name(resp, r.rdata_off, &mut target).ok()?;
                b.answer_rdata(Some(&owner), rtype::CNAME, r.ttl, target.as_wire())
                    .ok()?;
            } else if r.rtype == rtype::AAAA && !excluded(r) {
                b.answer_rdata(Some(&owner), rtype::AAAA, r.ttl, r.rdata(resp))
                    .ok()?;
            }
        }
        let len = b
            .finish(response_edns(&q, self.settings.edns_payload, None))
            .ok()?;
        out.truncate(len);
        Some(out)
    }

    /// REQ: DNS-016 — a cached AAAA answer without addresses: made from a cached A answer
    /// now, or looked up first (the query event is recorded when it's done).
    #[allow(clippy::too_many_arguments)]
    fn dns64_after_cache(
        self: &Arc<Self>,
        req: &[u8],
        q: &Query<'_>,
        d: Dns64,
        meta: &RequestMeta,
        out: &mut [u8],
        len: usize,
        start: Instant,
        oc: Outcome,
    ) -> Response {
        let a_req = Self::a_query(req);
        if let Some(Internal::Hit(a)) = a_req
            .as_deref()
            .and_then(|r| self.cached_internal(r, &d.groups))
        {
            let mut tmp = vec![0u8; MAX_RESPONSE];
            if let Some(n) = self.synthesize_aaaa(req, &a, d.prefix, &d.exclude, &mut tmp)
                && n <= out.len()
            {
                out[..n].copy_from_slice(&tmp[..n]);
                return Response::Ready(self.finish(q, out, n, meta.transport));
            }
            return Response::Ready(self.finish(q, out, len, meta.transport));
        }
        let this = Arc::clone(self);
        let req = req.to_vec();
        let mut original = out[..len].to_vec();
        let (transport, peer) = (meta.transport, meta.peer.ip());
        Response::Deferred(Box::pin(async move {
            let waited = Instant::now();
            let q = parse_query(&req).ok()?;
            let bytes = if let Some(b) = this.dns64_synthesize(&req, &d, transport).await {
                b
            } else {
                let n = original.len();
                original.resize(MAX_RESPONSE.max(n), 0);
                let n = this.finish(&q, &mut original, n, transport);
                original.truncate(n);
                original
            };
            this.metrics.record(
                proto(transport),
                oc.status,
                Some(response_rcode(&bytes)),
                oc.qtype,
                start.elapsed(),
            );
            this.emit(
                peer,
                transport,
                &req,
                Some(&bytes),
                &oc,
                start,
                waited.elapsed(),
            );
            Some(bytes)
        }))
    }

    /// REQ: FLT-014 (T9.20) — the `$dnsrewrite` answer for this client, if a list it uses has
    /// one for the name. One bool check when no list has rewrites.
    fn list_rewrite(
        &self,
        q: &Query<'_>,
        who: Who,
    ) -> Option<(telltale_filter::rewrite::ListRewrite, u16)> {
        let guard = self.filter.load();
        let f = guard.as_ref()?;
        if !f.matcher.has_rewrites() {
            return None;
        }
        let ident = f.clients.identify(
            who.peer,
            who.client_id.as_ref().map(telltale_net::ClientId::as_str),
            who.mac,
            &self.neighbors,
        );
        if self
            .pause
            .is_paused(&f.clients.primary_group(ident).name, unix_now)
        {
            return None;
        }
        let client = ClientCtx {
            ip: who.peer,
            name: f.clients.client(ident).map(|c| &*c.name),
            client_id: who.client_id.as_ref().map(telltale_net::ClientId::as_str),
        };
        f.matcher
            .rewrites(q.qname.as_wire(), q.qtype, &client, f.mask(ident))
    }

    /// REQ: FLT-014 (T9.20) — answers with a list rewrite: addresses of the asked family (60 s),
    /// a CNAME resolved like any name, or an rcode with no records; attributed to the list.
    #[allow(clippy::too_many_arguments)] // the same inputs as resolve_or_defer
    fn list_rewrite_answer(
        self: &Arc<Self>,
        req: &[u8],
        q: &Query<'_>,
        (rewrite, list): (telltale_filter::rewrite::ListRewrite, u16),
        groups: &[Box<str>],
        who: Who,
        meta: &RequestMeta,
        out: &mut [u8],
        start: Instant,
        oc: &mut Outcome,
    ) -> Response {
        use telltale_filter::rewrite::ListRewrite;
        oc.status = Status::Local;
        oc.rule = Some(Rule {
            list,
            kind: RuleKind::Modifier,
            allow: false,
        });
        match rewrite {
            ListRewrite::Rcode(rc) => self.simple(q, out, rc, None, meta),
            ListRewrite::Cname(target) => match NameBuf::from_presentation(&target) {
                Ok(t) => self.safe_search(req, q, &t, groups, who, meta, out, start, oc),
                Err(_) => self.simple(q, out, rcode::SERVFAIL, None, meta),
            },
            ListRewrite::Addrs(ips) => {
                let edns = response_edns(q, self.settings.edns_payload, None);
                let built = ResponseBuilder::new(q, out, rcode::NOERROR)
                    .ok()
                    .and_then(|mut b| {
                        for ip in &ips {
                            match ip {
                                std::net::IpAddr::V4(a) => b.answer_a(60, *a).ok()?,
                                std::net::IpAddr::V6(a) => b.answer_aaaa(60, *a).ok()?,
                            };
                        }
                        b.finish(edns).ok()
                    });
                match built {
                    Some(len) => Response::Ready(self.finish(q, out, len, meta.transport)),
                    None => self.simple(q, out, rcode::SERVFAIL, None, meta),
                }
            }
        }
    }

    /// REQ: FLT-014 (T7.20) — a rewrite to an address: A or AAAA as asked (no data for the
    /// other family and other types).
    fn rewrite_answer(
        &self,
        q: &Query<'_>,
        ip: std::net::IpAddr,
        out: &mut [u8],
        meta: &RequestMeta,
    ) -> Response {
        let edns = response_edns(q, self.settings.edns_payload, None);
        let built = ResponseBuilder::new(q, out, rcode::NOERROR)
            .ok()
            .and_then(|mut b| {
                match (q.qtype, ip) {
                    (rtype::A, std::net::IpAddr::V4(v4)) => {
                        b.answer_a(60, v4).ok()?;
                    }
                    (rtype::AAAA, std::net::IpAddr::V6(v6)) => {
                        b.answer_aaaa(60, v6).ok()?;
                    }
                    _ => {}
                }
                b.finish(edns).ok()
            });
        match built {
            Some(len) => Response::Ready(self.finish(q, out, len, meta.transport)),
            None => self.simple(q, out, rcode::SERVFAIL, None, meta),
        }
    }

    /// REQ: FLT-011 (T7.11) — the safe-search name for this query, when the group has safe
    /// search and the name is an engine's. Nothing to do (no allocation) for other groups.
    fn safe_search_target(q: &Query<'_>, group: &Group) -> Option<NameBuf> {
        let youtube = group.safe_search?;
        let mut name = q.qname.display().to_string();
        name.make_ascii_lowercase();
        let target = telltale_config::safesearch::target(name.trim_end_matches('.'), youtube)?;
        NameBuf::from_presentation(target).ok()
    }

    /// REQ: FLT-011 (T7.11) — answers `q` as `CNAME target` plus the target's records of the
    /// asked type, resolving the target through the cache and upstreams like any name. HTTPS
    /// and SVCB get no data (so clients use the target's addresses, not hints for the
    /// original name).
    #[allow(clippy::too_many_arguments)] // the same inputs as resolve_or_defer
    fn safe_search(
        self: &Arc<Self>,
        req: &[u8],
        q: &Query<'_>,
        target: &NameBuf,
        groups: &[Box<str>],
        who: Who,
        meta: &RequestMeta,
        out: &mut [u8],
        start: Instant,
        oc: &mut Outcome,
    ) -> Response {
        if matches!(q.qtype, rtype::HTTPS | rtype::SVCB) {
            return self.simple(q, out, rcode::NOERROR, None, meta);
        }
        let edns = q.edns.as_ref().map(|e| EdnsOut {
            udp_payload: e.udp_payload,
            dnssec_ok: e.dnssec_ok,
            ede: None,
        });
        let mut buf = [0u8; 512];
        let Ok(len) = build_query(&mut buf, q.header.id, target, q.qtype, q.qclass, true, edns)
        else {
            return self.simple(q, out, rcode::SERVFAIL, None, meta);
        };
        let treq = buf[..len].to_vec();
        let Ok(tq) = parse_query(&treq) else {
            return self.simple(q, out, rcode::SERVFAIL, None, meta);
        };
        let orig = req.to_vec();
        let target = *target;
        let transport = meta.transport;
        // A private reverse name stays local (RFC 6303), as when asked directly (T9.10).
        let special = telltale_policy::classify(&tq, &self.state.load().policy.special)
            .filter(|s| *s == Special::PrivatePtr);
        match self.resolve_or_defer(&treq, &tq, special, groups, who, meta, out, start, oc) {
            Response::Ready(n) => {
                let resp = out[..n].to_vec();
                match self.safe_search_answer(&orig, &target, &resp, out) {
                    Some(len) => Response::Ready(self.finish(q, out, len, transport)),
                    None => self.simple(q, out, rcode::SERVFAIL, None, meta),
                }
            }
            Response::Deferred(f) => {
                let this = Arc::clone(self);
                Response::Deferred(Box::pin(async move {
                    let resp = f.await?;
                    let mut o = vec![0u8; MAX_RESPONSE];
                    let len = this.safe_search_answer(&orig, &target, &resp, &mut o)?;
                    let oq = parse_query(&orig).ok()?;
                    let len = this.finish(&oq, &mut o, len, transport);
                    o.truncate(len);
                    Some(o)
                }))
            }
            Response::Drop => Response::Drop,
        }
    }

    /// The answer to `orig` from the target's answer `resp`: `CNAME target` and the target's
    /// records of the asked type (owned by the target). A failed target fails the same way.
    fn safe_search_answer(
        &self,
        orig: &[u8],
        target: &NameBuf,
        resp: &[u8],
        out: &mut [u8],
    ) -> Option<usize> {
        let oq = parse_query(orig).ok()?;
        let rc = u16::from(resp.get(3)? & 0x0F);
        let mut b = ResponseBuilder::new(&oq, out, rc).ok()?;
        if rc == rcode::NOERROR {
            b.answer_rdata(None, rtype::CNAME, 300, target.as_wire())
                .ok()?;
            for r in records(resp).ok()?.flatten() {
                if r.section == Section::Answer && r.rtype == oq.qtype {
                    b.answer_rdata(Some(target), r.rtype, r.ttl, r.rdata(resp))
                        .ok()?;
                }
            }
        }
        b.finish(response_edns(&oq, self.settings.edns_payload, None))
            .ok()
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
        let mut key = self.key(&q, sel.view);
        // REQ: DNS-015 (T9.9) — a group passing clients' subnets on caches per subnet.
        if sel.group.ecs_client() {
            key = key.with_ecs(telltale_upstream::client_subnet(who.peer));
        }
        let client = Client::from_query(&q, response_edns(&q, self.settings.edns_payload, None));
        // REQ: DNS-016 (T7.21) — DNS64 for this client (AAAA only; a validating client that
        // sets CD gets the real answer).
        let dns64 =
            (q.qtype == rtype::AAAA && !q.header.flags.cd() && st.policy.clients.any_dns64())
                .then(|| self.dns64_for(&st.policy, who))
                .flatten()
                .map(|(prefix, exclude)| Dns64 {
                    prefix,
                    exclude,
                    groups: groups.to_vec(),
                });
        match self.cache.get(&key, &q.qname, &client, start, out) {
            Lookup::Hit { len, prefetch } => {
                if prefetch {
                    self.prefetch(req, key, sel.view);
                }
                oc.status = Status::Cached;
                let len = match self.cname_block(&q, who, out, len) {
                    Some((blocked, rule)) => {
                        oc.status = Status::Blocked;
                        oc.rule = Some(rule);
                        blocked
                    }
                    None => len,
                };
                if let Some(d) = &dns64
                    && oc.status == Status::Cached
                    && let Some(n) = self.dns64_filter(req, &out[..len], &d.exclude)
                    && n.len() <= out.len()
                {
                    // REQ: DNS-016 (T9.10) — real AAAA records left after the exclusions.
                    out[..n.len()].copy_from_slice(&n);
                    return Response::Ready(self.finish(&q, out, n.len(), meta.transport));
                }
                if let Some(d) = dns64
                    && oc.status == Status::Cached
                    && needs_dns64(&out[..len], &d.exclude)
                {
                    return self.dns64_after_cache(req, &q, d, meta, out, len, start, *oc);
                }
                Response::Ready(self.finish(&q, out, len, meta.transport))
            }
            Lookup::Expired => self.defer(req, meta, key, sel.view, true, start, *oc, who, dns64),
            Lookup::Miss => self.defer(req, meta, key, sel.view, false, start, *oc, who, dns64),
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

    /// REQ: FLT-010 (T7.10) — the block answer when a block-everything schedule is on for the
    /// client's group (and blocking isn't paused). One load and an index when nothing is on.
    fn schedule_block(
        &self,
        q: &Query<'_>,
        out: &mut [u8],
        policy: &Policy,
        ident: Identity,
        oc: &mut Outcome,
    ) -> Option<usize> {
        let now = self.schedules.load();
        if now.block_all.is_empty() {
            return None;
        }
        let g = *policy.clients.group_ids(ident).first()?;
        let (reason, r) = now.block_all.get(usize::from(g))?.as_ref()?;
        let group = policy.clients.primary_group(ident);
        if self.pause.is_paused(&group.name, unix_now) {
            return None;
        }
        oc.status = Status::Blocked;
        oc.rule = Some(Rule {
            list: *r,
            kind: RuleKind::Schedule,
            allow: false,
        });
        self.block_answer(q, out, group, reason)
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
    ) -> Option<(usize, Rule)> {
        let st = self.state.load();
        let guard = self.filter.load();
        let f = guard.as_ref();
        let answers_on = st.policy.clients.any_answers();
        if f.is_none() && st.policy.quick.is_empty() && !answers_on {
            return None;
        }
        // REQ: FLT-015 (T7.20) — the client's answer filter, if its group has one.
        let answer_filter = answers_on
            .then(|| {
                let ident = st.policy.clients.identify(
                    who.peer,
                    who.client_id.as_ref().map(telltale_net::ClientId::as_str),
                    who.mac,
                    &self.neighbors,
                );
                st.policy.clients.primary_group(ident)
            })
            .filter(|g| g.answers.is_some());
        let mut target = telltale_proto::NameBuf::default();
        for r in telltale_proto::records(out.get(..len)?).ok()?.flatten() {
            if r.section != telltale_proto::Section::Answer {
                continue;
            }
            if let Some(group) = answer_filter
                && let Some(af) = &group.answers
                && let Some(ip) = answer_ip(r.rtype, r.rdata(&out[..len]))
                && !self.paused_for(group)
            {
                let mut owner = telltale_proto::NameBuf::default();
                let _ = telltale_proto::read_name(&out[..len], r.name_off, &mut owner);
                let allowed = af.allow.iter().any(|a| q.qname.is_subdomain_of(a));
                if let Some(why) = af.refuses(&owner, ip).filter(|_| !allowed) {
                    let len = self.block_answer(q, out, group, why)?;
                    return Some((
                        len,
                        Rule {
                            list: 0,
                            kind: RuleKind::AnswerIp,
                            allow: false,
                        },
                    ));
                }
            }
            if r.rtype != telltale_proto::rtype::CNAME {
                continue;
            }
            if telltale_proto::read_name(&out[..len], r.rdata_off, &mut target).is_err() {
                continue;
            }
            // REQ: FLT-005 (ADR-067) — quick rules decide CNAME targets too, before the lists.
            if !st.policy.quick.is_empty() {
                let ident = st.policy.clients.identify(
                    who.peer,
                    who.client_id.as_ref().map(telltale_net::ClientId::as_str),
                    who.mac,
                    &self.neighbors,
                );
                if let Some(m) = self.quick_decision(&st.policy, target.as_wire(), ident, who) {
                    if m.allow {
                        continue;
                    }
                    let group = st.policy.clients.primary_group(ident);
                    let len = self.block_answer(q, out, group, "quick rule")?;
                    return Some((len, quick_rule(&st.policy, m)));
                }
            }
            let Some(f) = f else { continue };
            match self.decide_for(f, who, target.as_wire(), q.qtype) {
                None => return None, // paused: nothing to inspect
                Some((ident, Decision::Block(a))) => {
                    let reason = f
                        .cname_reasons
                        .get(usize::from(a.list))
                        .map_or("blocked", String::as_str);
                    let len = self.block_answer(q, out, f.clients.primary_group(ident), reason)?;
                    return Some((len, cname_rule(a.list)));
                }
                Some(_) => {}
            }
        }
        None
    }

    /// Blocking is paused for this group (FLT-009): no answer is refused either.
    fn paused_for(&self, group: &Group) -> bool {
        self.pause.is_paused(&group.name, unix_now)
    }

    /// REQ: FLT-005 (T6.12, ADR-067) — the quick rule deciding `name` (wire format) for this
    /// client, if any. A paused group (FLT-009) gets no blocks from quick rules either.
    fn quick_decision(
        &self,
        policy: &Policy,
        name: &[u8],
        ident: Identity,
        who: Who,
    ) -> Option<telltale_policy::QuickMatch> {
        if policy.quick.is_empty() {
            return None;
        }
        let now = i64::try_from(unix_now()).unwrap_or(i64::MAX);
        let m = policy
            .quick
            .decide(name, ident, who.peer, policy.clients.group_ids(ident), now)?;
        if !m.allow
            && self
                .pause
                .is_paused(&policy.clients.primary_group(ident).name, unix_now)
        {
            return None;
        }
        Some(m)
    }

    /// FLT-007 for deferred (upstream or stale) answers: re-checks the final message.
    fn deferred_cname_block(
        &self,
        req: &[u8],
        who: Who,
        transport: Transport,
        mut bytes: Vec<u8>,
        status: Status,
    ) -> (Vec<u8>, Status, Option<Rule>) {
        if !matches!(status, Status::Forwarded | Status::Stale) {
            return (bytes, status, None);
        }
        let Ok(q) = parse_query(req) else {
            return (bytes, status, None);
        };
        let len = bytes.len();
        bytes.resize(MAX_RESPONSE.max(len), 0);
        if let Some((l, rule)) = self.cname_block(&q, who, &mut bytes, len) {
            let l = self.finish(&q, &mut bytes, l, transport);
            bytes.truncate(l);
            (bytes, Status::Blocked, Some(rule))
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
        dns64: Option<Dns64>,
    ) -> Response {
        let this = Arc::clone(self);
        let req = req.to_vec();
        let transport = meta.transport;
        let peer = meta.peer.ip();
        Response::Deferred(Box::pin(async move {
            let waited = Instant::now();
            let mut answer = Arc::clone(&this)
                .resolve_for_client(req.clone(), key, view, stale_ok, transport)
                .await
                .map(|(bytes, status)| {
                    this.deferred_cname_block(&req, who, transport, bytes, status)
                });
            // REQ: DNS-016 (T7.21) — no AAAA: made from the name's A records.
            if let Some(d) = &dns64
                && let Some((bytes, _, None)) = &mut answer
            {
                if needs_dns64(bytes, &d.exclude) {
                    if let Some(synth) = this.dns64_synthesize(&req, d, transport).await {
                        *bytes = synth;
                    }
                } else if let Some(filtered) = this.dns64_filter(&req, bytes, &d.exclude) {
                    // REQ: DNS-016 (T9.10) — excluded AAAA records dropped.
                    *bytes = filtered;
                }
            }
            let t_upstream = waited.elapsed();
            let (status, rcode) = match &answer {
                Some((bytes, status, rule)) => {
                    if let Some(rule) = rule {
                        oc.rule = Some(*rule);
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
        // REQ: NFR-002 (T10.2) — the client's response buffer is allocated once the answer is
        // in, sized to it. Allocated here, a 64 KiB buffer per query waiting upstream added up
        // under load (12.5 MiB with 200 in flight) and stayed resident in the allocator after.
        // The fallbacks (stale, SERVFAIL) are rare and get the largest size.
        let full = || vec![0u8; MAX_RESPONSE];

        let Ok(permit) = Arc::clone(&self.inflight).try_acquire_owned() else {
            // Overloaded (02 §8.4): stale if we have it, else SERVFAIL + EDE 23.
            return self.fallback(
                &q,
                key,
                stale_ok,
                ede::NETWORK_ERROR,
                "resolver overloaded",
                &mut full(),
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
            // REQ: DNS-011 — validation failed: SERVFAIL with EDE 6 (or why: T9.8), never a
            // stale answer.
            Some(resp) if resp.is_empty() || bogus_code(&resp).is_some() => {
                let code = bogus_code(&resp).unwrap_or(ede::DNSSEC_BOGUS);
                self.fallback(
                    &q,
                    key,
                    false,
                    code,
                    bogus_text(code),
                    &mut full(),
                    transport,
                )
            }
            Some(resp) => {
                let client =
                    Client::from_query(&q, response_edns(&q, self.settings.edns_payload, None));
                // The answer plus our OPT (with room for an EDE and its text).
                let mut out = vec![0u8; (resp.len() + 512).min(MAX_RESPONSE)];
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
                        &mut full(),
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
                &mut full(),
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
        let mut question = Question::from_query(q);
        // REQ: DNS-015 (T9.9) — the subnet the key was scoped to (prefetches keep it too).
        question.client_subnet = key.ecs();
        // The view chosen at selection time (by qname, qtype, and client groups) names the group.
        let group = Arc::clone(st.router.group_by_view(view)?);
        let started = Instant::now();
        // REQ: DNS-011 — validate unless the client set CD or the name is under a negative
        // trust anchor.
        if let Some(d) = self.dnssec.load_full()
            && !q.header.flags.cd()
            && d.validator.covers(&q.qname.display().to_string())
        {
            return self
                .resolve_validated(q, key, &group, &question, &d, started)
                .await;
        }
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

    /// One upstream answer, DNSSEC-validated (DNS-011). Bogus answers come back as an empty
    /// marker (SERVFAIL + EDE 6) and are never cached; in permissive mode they're served.
    async fn resolve_validated(
        &self,
        q: &Query<'_>,
        key: CacheKey,
        group: &Arc<telltale_upstream::Group>,
        question: &Question,
        d: &Dnssec,
        started: Instant,
    ) -> Option<Arc<[u8]>> {
        use telltale_upstream::dnssec::Verdict;
        let client_do = q.edns.is_some_and(|e| e.dnssec_ok);
        let result = d
            .validator
            .resolve(
                group,
                *question,
                self.settings.budget,
                client_do,
                q.header.flags.ad(),
            )
            .await;
        let (upstream, attempts) = result
            .as_ref()
            .map_or((0, 0), |v| (v.upstream_id, v.attempts));
        self.telemetry.emit_upstream(&UpstreamEvent {
            ts_us: self.telemetry.ts_us(started),
            upstream,
            latency_us: micros(started.elapsed()),
            ok: result.is_ok(),
            attempts,
        });
        let v = result.ok()?;
        // REQ: DNS-011 (ADR-098) — which names fail, while trying validation out.
        if v.verdict == Verdict::Bogus && d.permissive {
            tracing::info!(
                name = %question.name.display(),
                qtype = question.qtype,
                ede = v.ede,
                "DNSSEC: bogus answer served (permissive mode)"
            );
        }
        if v.verdict == Verdict::Bogus && !d.permissive {
            return Some(bogus_marker(v.ede));
        }
        if v.bytes.is_empty() && matches!(v.verdict, Verdict::Bogus | Verdict::Indeterminate) {
            // Nothing validated to serve (permissive, or validation couldn't finish): fetch it
            // again, unvalidated.
            let a = group.resolve(*question, self.settings.budget).await.ok()?;
            let _ = self.cache.insert(&key, q, &a.bytes, Instant::now());
            return Some(a.bytes.into());
        }
        let _ = self.cache.insert(&key, q, &v.bytes, Instant::now());
        Some(v.bytes.into())
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

/// REQ: FLT-013 (ADR-067) — a quick rule's attribution: its stable reference as the "list".
fn quick_rule(policy: &Policy, m: telltale_policy::QuickMatch) -> Rule {
    let id = policy
        .quick
        .rules()
        .get(m.rule as usize)
        .map_or("", |r| &r.id);
    Rule {
        list: telltale_policy::quick_ref(id),
        kind: RuleKind::Quick,
        allow: m.allow,
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
        // REQ: OBS-007 — a sampled copy of both messages for dnstap, when it's on.
        if let Some(tap) = self.dnstap.get() {
            tap.offer(peer, transport, req, resp, ev.ts_us);
        }
    }
}

/// REQ: DNS-016 (T7.21) — DNS64 for one query: the prefix, and the client's groups (for the
/// A lookup's route).
#[derive(Debug, Clone)]
pub(crate) struct Dns64 {
    prefix: std::net::Ipv6Addr,
    /// REQ: DNS-016 (T9.10) — the exclusion set.
    exclude: Vec<Cidr>,
    groups: Vec<Box<str>>,
}

/// An internal lookup's cache result: the answer, or where to resolve it.
enum Internal {
    Hit(Vec<u8>),
    Miss(CacheKey, u16),
}

/// A NOERROR answer with no AAAA record (CNAMEs only, or none) outside the exclusion set
/// (T9.10): DNS64 applies.
fn needs_dns64(resp: &[u8], exclude: &[Cidr]) -> bool {
    if response_rcode(resp) != rcode::NOERROR {
        return false;
    }
    records(resp).is_ok_and(|mut it| {
        !it.any(|r| {
            r.is_ok_and(|r| {
                r.section == Section::Answer
                    && r.rtype == rtype::AAAA
                    && answer_ip(rtype::AAAA, r.rdata(resp))
                        .is_none_or(|ip| !dns64_excluded(ip, exclude))
            })
        })
    })
}

/// REQ: DNS-016 (T9.10) — an AAAA address in the exclusion set; IPv4-mapped addresses
/// (`::ffff:0:0/96`) always are (RFC 6147 §5.1.4).
fn dns64_excluded(ip: std::net::IpAddr, exclude: &[Cidr]) -> bool {
    matches!(ip, std::net::IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
        || exclude.iter().any(|c| c.contains(ip))
}

/// REQ: DNS-016 (T9.10) — RFC 6147 §5.3.1: for a reverse name inside the NAT64 /96
/// (`….b.9.f.f.4.6.0.0.ip6.arpa`), the embedded IPv4 address's `in-addr.arpa` name.
fn dns64_reverse_target(qname: &NameBuf, prefix: std::net::Ipv6Addr) -> Option<NameBuf> {
    let mut name = qname.display().to_string();
    name.make_ascii_lowercase();
    let body = name.trim_end_matches('.').strip_suffix(".ip6.arpa")?;
    let mut nibbles = [0u8; 32];
    let mut n = 0;
    for label in body.split('.') {
        let &[c] = label.as_bytes() else { return None };
        let v = char::from(c).to_digit(16)?;
        *nibbles.get_mut(31usize.checked_sub(n)?)? = u8::try_from(v).ok()?;
        n += 1;
    }
    if n != 32 {
        return None;
    }
    let mut addr = [0u8; 16];
    for (i, b) in addr.iter_mut().enumerate() {
        *b = (nibbles[2 * i] << 4) | nibbles[2 * i + 1];
    }
    if addr[..12] != prefix.octets()[..12] {
        return None;
    }
    NameBuf::from_presentation(&format!(
        "{}.{}.{}.{}.in-addr.arpa",
        addr[15], addr[14], addr[13], addr[12]
    ))
    .ok()
}

/// REQ: FLT-015 — the address in an A or AAAA record's RDATA.
fn answer_ip(rt: u16, rdata: &[u8]) -> Option<std::net::IpAddr> {
    match (rt, rdata.len()) {
        (rtype::A, 4) => Some(std::net::IpAddr::from([
            rdata[0], rdata[1], rdata[2], rdata[3],
        ])),
        (rtype::AAAA, 16) => {
            let b: [u8; 16] = rdata.try_into().ok()?;
            Some(std::net::IpAddr::from(b))
        }
        _ => None,
    }
}

fn proto(t: Transport) -> Proto {
    match t {
        Transport::Udp => Proto::Udp,
        Transport::Tcp => Proto::Tcp,
        Transport::Dot => Proto::Dot,
        Transport::Doh => Proto::Doh,
        Transport::Doq => Proto::Doq,
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

    /// Compiles several named lists into one snapshot and installs it.
    fn install_lists(p: &Pipeline, lists: &[(&str, &str)]) {
        use telltale_filter::compile::{CompileOptions, ListData, ListInput, compile};
        use telltale_filter::matcher::{Lookup, Overlay};
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("snap");
        let inputs = lists
            .iter()
            .map(|(name, rules)| ListInput {
                name: (*name).into(),
                options: telltale_filter::parse::ListOptions::default(),
                data: ListData::Bytes(rules.as_bytes().to_vec()),
                source_hash: telltale_filter::fetch::content_hash(rules.as_bytes()),
                size: rules.len() as u64,
            })
            .collect();
        compile(inputs, &out, &CompileOptions::default()).unwrap();
        let snap = Arc::new(telltale_filter::snapshot::Snapshot::open(&out).unwrap());
        let m = Matcher::with_lookup(Some(snap), Overlay::default(), Lookup::Indexed).unwrap();
        p.set_filter(Some(Arc::new(m)));
    }

    /// REQ: FLT-012 (T7.9) — a blocked service applies to the groups that name it only, also
    /// next to a group that uses every list, and says which service blocked the name.
    #[test]
    fn flt_012_blocked_services_apply_per_group() {
        let cfg: telltale_config::Config = telltale_config::Loader::new()
            .toml_str(
                "t.toml",
                r#"
[[list]]
name = "ads"
rules = ["||ads.example.com^"]

[[group]]
name = "default"

[[group]]
name = "kids"
networks = ["10.0.1.0/24"]
blocked_services = ["tiktok"]
"#,
            )
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config;
        let expanded = telltale_config::services::expand(&cfg);
        let svc = expanded
            .list
            .iter()
            .find(|l| l.name.as_str() == "svc-tiktok")
            .expect("the service became a list");
        let svc_rules = svc.rules.iter().fold(String::new(), |mut acc, r| {
            acc.push_str(r.as_str());
            acc.push('\n');
            acc
        });
        let p = Pipeline::new(
            Settings::default(),
            Arc::new(Cache::new(CachePolicy::default())),
            Arc::new(Router::default()),
            Policy {
                clients: Arc::new(ClientTable::from_config(&cfg)),
                ..Policy::open()
            },
        );
        install_lists(
            &p,
            &[("ads", "||ads.example.com^\n"), ("svc-tiktok", &svc_rules)],
        );
        let ask = |peer: &str, name: &str| {
            let mut out = [0u8; 4096];
            let meta = RequestMeta {
                peer: peer.parse().unwrap(),
                local: None,
                transport: Transport::Udp,
                client_id: None,
            };
            match Handler(Arc::clone(&p)).handle(&query(name, rtype::A, true), &meta, &mut out) {
                Response::Ready(len) => out[..len].to_vec(),
                _ => Vec::new(),
            }
        };
        let blocked =
            |r: &[u8]| summarize(r).is_ok_and(|s| s.rcode == rcode::NOERROR && s.answers == 1);
        let kid = ask("10.0.1.5:1000", "www.tiktok.com");
        assert!(blocked(&kid), "the kids group blocks TikTok");
        let text = b"blocked service TikTok";
        assert!(
            kid.windows(text.len()).any(|w| w == text),
            "EDE names the service"
        );
        assert!(
            !blocked(&ask("10.0.0.9:1000", "www.tiktok.com")),
            "other groups don't"
        );
        assert!(
            blocked(&ask("10.0.0.9:1000", "ads.example.com")),
            "every list still applies"
        );
        assert!(blocked(&ask("10.0.1.5:1000", "ads.example.com")));
    }

    /// REQ: FLT-010 (T7.10) — schedules: bedtime blocks everything for its group during the
    /// window (a quick allow still wins), and a list a schedule turns on is off outside it,
    /// even for a group that uses every list.
    #[test]
    #[allow(clippy::too_many_lines)] // one scenario across the week
    fn flt_010_schedules_block_all_and_enable_lists() {
        let cfg: telltale_config::Config = telltale_config::Loader::new()
            .toml_str(
                "t.toml",
                r#"
[[list]]
name = "ads"
rules = ["||ads.example.com^"]

[[list]]
name = "games"
rules = ["||game.example.com^"]

[[group]]
name = "default"
schedules = ["weekend-games"]

[[group]]
name = "kids"
networks = ["10.0.1.0/24"]
schedules = ["bedtime"]

[[schedule]]
name = "bedtime"
action = "block_all"
tz = "UTC"
window = [{ days = ["daily"], start = "21:00", end = "07:00" }]

[[schedule]]
name = "weekend-games"
action = "enable_lists"
lists = ["games"]
tz = "UTC"
window = [{ days = ["weekends"], start = "12:00", end = "18:00" }]

[[rule]]
id = "homework"
action = "allow"
domain = "school.example.com"
groups = ["kids"]
"#,
            )
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config;
        let clients = Arc::new(ClientTable::from_config(&cfg));
        let p = Pipeline::new(
            Settings::default(),
            Arc::new(Cache::new(CachePolicy::default())),
            Arc::new(Router::default()),
            Policy {
                clients: Arc::clone(&clients),
                quick: Arc::new(telltale_policy::QuickRules::from_config(&cfg, &clients)),
                ..Policy::open()
            },
        );
        install_lists(
            &p,
            &[
                ("ads", "||ads.example.com^\n"),
                ("games", "||game.example.com^\n"),
            ],
        );
        let compiled = telltale_config::schedule::compile(&cfg);
        let at = |now: i64| {
            p.schedules.store(Arc::new(ScheduleNow::compute(
                &cfg,
                &compiled,
                clients.groups(),
                now,
            )));
            p.set_filter(None);
        };
        let ask = |peer: &str, name: &str| {
            let mut out = [0u8; 4096];
            let meta = RequestMeta {
                peer: peer.parse().unwrap(),
                local: None,
                transport: Transport::Udp,
                client_id: None,
            };
            match Handler(Arc::clone(&p)).handle(&query(name, rtype::A, true), &meta, &mut out) {
                Response::Ready(len) => out[..len].to_vec(),
                _ => Vec::new(),
            }
        };
        let blocked =
            |r: &[u8]| summarize(r).is_ok_and(|s| s.rcode == rcode::NOERROR && s.answers == 1);
        // Monday 2026-10-05 22:00 UTC: bedtime is on.
        let monday_2200: i64 = 1_791_237_600;
        at(monday_2200);
        let r = ask("10.0.1.5:1000", "www.example.org");
        assert!(blocked(&r), "bedtime blocks everything for kids");
        let text = b"blocked by schedule bedtime";
        assert!(
            r.windows(text.len()).any(|w| w == text),
            "EDE names the schedule"
        );
        assert!(
            !blocked(&ask("10.0.1.5:1000", "school.example.com")),
            "a quick allow wins"
        );
        assert!(
            !blocked(&ask("10.0.0.9:1000", "www.example.org")),
            "other groups are unaffected"
        );
        // Noon: bedtime is off.
        at(monday_2200 - 10 * 3600);
        assert!(!blocked(&ask("10.0.1.5:1000", "www.example.org")));
        // The games list is off on a weekday, even for the every-list default group, and on
        // during its weekend window; the ads list applies throughout.
        assert!(!blocked(&ask("10.0.0.9:1000", "game.example.com")));
        assert!(blocked(&ask("10.0.0.9:1000", "ads.example.com")));
        let saturday_1300 = monday_2200 + 4 * 86_400 + 15 * 3600;
        at(saturday_1300);
        assert!(
            blocked(&ask("10.0.0.9:1000", "game.example.com")),
            "weekend games list on"
        );
        assert!(
            !blocked(&ask("10.0.1.5:1000", "game.example.com")),
            "only for its own group"
        );
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

    /// REQ: FLT-005 (T6.12, ADR-067) — quick rules decide before the lists, per device and
    /// per group; other clients are unaffected.
    #[test]
    fn flt_005_quick_rules_decide_before_the_lists() {
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
block_mode = "nxdomain"

[[group]]
name = "kids"
block_mode = "nxdomain"

[[client]]
name = "tablet"
match = ["10.0.0.5"]
groups = ["kids"]

[[client]]
name = "mom"
match = ["10.0.0.6"]

[[rule]]
id = "tablet-ads"
action = "allow"
domain = "ads.example.com"
devices = ["tablet"]

[[rule]]
id = "kids-videos"
action = "block"
domain = "videos.example"
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
                allowed: Policy::open().allowed,
                ..Policy::from_config(&cfg, LocalData::default())
            },
        );
        install_filter(
            &p,
            "||ads.example.com^
",
            Lookup::Indexed,
        );
        let ask = |peer: &str, name: &str| {
            let mut out = [0u8; 4096];
            let meta = RequestMeta {
                peer: peer.parse().unwrap(),
                local: None,
                transport: Transport::Udp,
                client_id: None,
            };
            match Handler(Arc::clone(&p)).handle(&query(name, rtype::A, true), &meta, &mut out) {
                Response::Ready(len) => summarize(&out[..len]).unwrap().rcode,
                _ => u16::MAX,
            }
        };
        // No upstream is configured: a query that isn't blocked ends in REFUSED.
        assert_eq!(
            ask("10.0.0.5:1000", "ads.example.com"),
            rcode::REFUSED,
            "the tablet's allow beats the list"
        );
        assert_eq!(
            ask("10.0.0.6:1000", "ads.example.com"),
            rcode::NXDOMAIN,
            "mom still gets the list's block"
        );
        assert_eq!(
            ask("10.0.0.5:1000", "cdn.videos.example"),
            rcode::NXDOMAIN,
            "the kids group's block, subdomains too"
        );
        assert_eq!(
            ask("10.0.0.6:1000", "videos.example"),
            rcode::REFUSED,
            "not in kids"
        );
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

    /// Puts `name A ip` in the cache, as an upstream answer would be.
    fn cache_a(p: &Pipeline, name: &str, ip: Ipv4Addr) {
        let req = query(name, rtype::A, false);
        let q = parse_query(&req).unwrap();
        let mut out = [0u8; 512];
        let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
        b.answer_a(300, ip).unwrap();
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
    }

    /// Caches `name`/`qtype` answered with `ip` (or no data).
    fn cache_answer(p: &Pipeline, name: &str, qtype: u16, ip: Option<std::net::IpAddr>) {
        let req = query(name, qtype, false);
        let q = parse_query(&req).unwrap();
        let mut out = [0u8; 512];
        let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
        match ip {
            Some(std::net::IpAddr::V4(v4)) => {
                b.answer_a(300, v4).unwrap();
            }
            Some(std::net::IpAddr::V6(v6)) => {
                b.answer_aaaa(300, v6).unwrap();
            }
            None => {
                b.authority_soa(60).unwrap();
            }
        }
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
    }

    /// REQ: DNS-018 (T7.22) — authoritative zones: a group's view answers its names, NXDOMAIN
    /// (authoritative, with an SOA) for names it doesn't have, no data for the apex and empty
    /// non-terminals; other groups don't see it; a zone file loads.
    #[test]
    fn dns_018_local_zones() {
        let dir = std::env::temp_dir().join(format!("tt-zone-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("lab.zone");
        std::fs::write(
            &file,
            "$ORIGIN lab.example.\n@ 900 IN SOA ns1 hostmaster 1 900 300 604800 900\n@ 3600 IN NS ns1\nweb 300 IN A 192.168.9.9\n",
        )
        .unwrap();
        let cfg_toml = format!(
            "{UPSTREAM}[[group]]\nname = \"office\"\nnetworks = [\"10.0.3.0/24\"]\n[[zone]]\nname = \"corp.example\"\ngroups = [\"office\"]\n[[zone.record]]\nname = \"intranet.corp.example\"\ntype = \"A\"\nvalue = \"10.10.0.5\"\n[[zone.record]]\nname = \"_sip._tcp.corp.example\"\ntype = \"SRV\"\nvalue = \"0 5 5060 pbx.corp.example\"\n[[zone]]\nname = \"lab.example\"\nfile = \"{}\"\n",
            file.display()
        );
        let cfg: telltale_config::Config = telltale_config::Loader::new()
            .toml_str("t.toml", &cfg_toml)
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config;
        let p = Pipeline::new(
            Settings::default(),
            Arc::new(Cache::new(CachePolicy::default())),
            Arc::new(Router::from_config(&cfg).unwrap()),
            Policy {
                clients: Arc::new(ClientTable::from_config(&cfg)),
                zones: Arc::new(crate::server::load_zones(&cfg).unwrap()),
                ..Policy::open()
            },
        );
        install_filter(
            &p,
            "||nothing.example^\n",
            telltale_filter::matcher::Lookup::Indexed,
        );
        cache_a(&p, "intranet.corp.example", Ipv4Addr::new(203, 0, 113, 5));
        let office = "10.0.3.5";
        let r = ask_from(&p, office, "intranet.corp.example", rtype::A);
        let s = summarize(&r).unwrap();
        assert!(
            s.header.flags.aa() && contains(&r, &[10, 10, 0, 5]),
            "the office view"
        );
        let nx = summarize(&ask_from(&p, office, "nope.corp.example", rtype::A)).unwrap();
        assert_eq!(
            (nx.rcode, nx.header.flags.aa(), nx.negative_ttl.is_some()),
            (rcode::NXDOMAIN, true, true)
        );
        let apex = summarize(&ask_from(&p, office, "corp.example", rtype::A)).unwrap();
        assert_eq!(
            (apex.rcode, apex.answers),
            (rcode::NOERROR, 0),
            "the apex exists"
        );
        let ent = summarize(&ask_from(&p, office, "_tcp.corp.example", rtype::SRV)).unwrap();
        assert_eq!(
            (ent.rcode, ent.answers),
            (rcode::NOERROR, 0),
            "an empty non-terminal exists"
        );
        assert!(
            contains(
                &ask_from(&p, "10.0.0.5", "intranet.corp.example", rtype::A),
                &[203, 0, 113, 5]
            ),
            "others: the public answer"
        );
        assert!(
            contains(
                &ask_from(&p, "10.0.0.5", "web.lab.example", rtype::A),
                &[192, 168, 9, 9]
            ),
            "the zone file, for everyone"
        );
        // REQ: DNS-018 (T9.18) — SOA and NS at the apex: the file's, else made up; negative
        // answers carry the zone's SOA, owned by the apex.
        let soa = ask_from(&p, "10.0.0.5", "lab.example", rtype::SOA);
        let s = summarize(&soa).unwrap();
        assert_eq!(
            (s.rcode, s.answers, s.header.flags.aa()),
            (rcode::NOERROR, 1, true)
        );
        let ns1 = NameBuf::from_presentation("ns1.lab.example").unwrap();
        assert!(contains(&soa, ns1.as_wire()), "the file's SOA (mname ns1)");
        let ns = ask_from(&p, "10.0.0.5", "lab.example", rtype::NS);
        assert_eq!(summarize(&ns).unwrap().answers, 1);
        assert!(contains(&ns, ns1.as_wire()), "the file's NS");
        let made = ask_from(&p, office, "corp.example", rtype::SOA);
        let localhost = NameBuf::from_presentation("localhost").unwrap();
        assert!(
            summarize(&made).unwrap().answers == 1 && contains(&made, localhost.as_wire()),
            "made up: localhost."
        );
        let nx = ask_from(&p, office, "nope.corp.example", rtype::A);
        let apex = NameBuf::from_presentation("corp.example").unwrap();
        let hostmaster = NameBuf::from_presentation("hostmaster.corp.example").unwrap();
        assert!(
            contains(&nx, apex.as_wire()) && contains(&nx, hostmaster.as_wire()),
            "the zone's SOA in the authority"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// REQ: DNS-016 (T7.21) — DNS64: a name without AAAA gets AAAA made from its A records
    /// (prefix + IPv4) for the group; a real AAAA is kept; other groups get no data.
    #[test]
    fn dns_016_dns64_synthesizes_aaaa() {
        let cfg = format!(
            "{UPSTREAM}[[group]]\nname = \"default\"\ndns64 = true\n[[group]]\nname = \"plain\"\nnetworks = [\"10.0.2.0/24\"]\n"
        );
        let p = pipeline_with(&cfg, "||nothing.example^\n");
        cache_answer(&p, "v4only.example", rtype::AAAA, None);
        cache_answer(
            &p,
            "v4only.example",
            rtype::A,
            Some("192.0.2.33".parse().unwrap()),
        );
        cache_answer(
            &p,
            "dual.example",
            rtype::AAAA,
            Some("2001:db8::7".parse().unwrap()),
        );
        let r = ask_from(&p, "10.0.0.5", "v4only.example", rtype::AAAA);
        let s = summarize(&r).unwrap();
        assert_eq!((s.rcode, s.answers), (rcode::NOERROR, 1));
        let want: std::net::Ipv6Addr = "64:ff9b::c000:221".parse().unwrap();
        assert!(contains(&r, &want.octets()), "64:ff9b::192.0.2.33");
        let real: std::net::Ipv6Addr = "2001:db8::7".parse().unwrap();
        assert!(contains(
            &ask_from(&p, "10.0.0.5", "dual.example", rtype::AAAA),
            &real.octets()
        ));
        let plain = summarize(&ask_from(&p, "10.0.2.5", "v4only.example", rtype::AAAA)).unwrap();
        assert_eq!(plain.answers, 0, "no DNS64 for the other group");
    }

    /// Caches `name`/`qtype` answered with these records (type, RDATA).
    fn cache_records(p: &Pipeline, name: &str, qtype: u16, recs: &[(u16, Vec<u8>)]) {
        let req = query(name, qtype, false);
        let q = parse_query(&req).unwrap();
        let mut out = [0u8; 1024];
        let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
        for (rt, rdata) in recs {
            b.answer_rdata(None, *rt, 300, rdata).unwrap();
        }
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
    }

    fn v6(s: &str) -> Vec<u8> {
        s.parse::<std::net::Ipv6Addr>().unwrap().octets().to_vec()
    }

    /// The `ip6.arpa` name of `s`.
    fn rev6(s: &str) -> String {
        let o = s.parse::<std::net::Ipv6Addr>().unwrap().octets();
        let mut parts = Vec::new();
        for b in o.iter().rev() {
            parts.push(format!("{:x}", b & 0xf));
            parts.push(format!("{:x}", b >> 4));
        }
        format!("{}.ip6.arpa", parts.join("."))
    }

    /// REQ: FLT-014 (T9.20) — `$dnsrewrite` in lists: an address for its family (empty
    /// NOERROR for the other), over a block of the same name, an rcode, a CNAME resolved like
    /// any name, and an exception that turns it off.
    #[test]
    fn flt_014_list_dnsrewrite() {
        let p = pipeline_with(
            UPSTREAM,
            "||rw.example^$dnsrewrite=192.0.2.55\n\
             ||both.example^\n||both.example^$dnsrewrite=NOERROR;A;192.0.2.66\n\
             ||nx.example^$dnsrewrite=NXDOMAIN\n\
             ||cn.example^$dnsrewrite=target.example\n\
             ||ex.example^$dnsrewrite=192.0.2.77\n@@||ex.example^$dnsrewrite\n",
        );
        let r = ask_from(&p, "10.0.0.5", "www.rw.example", rtype::A);
        assert!(contains(&r, &[192, 0, 2, 55]), "subtree rewrite");
        let s = summarize(&ask_from(&p, "10.0.0.5", "rw.example", rtype::AAAA)).unwrap();
        assert_eq!(
            (s.rcode, s.answers),
            (rcode::NOERROR, 0),
            "other family: empty"
        );
        assert!(
            contains(
                &ask_from(&p, "10.0.0.5", "both.example", rtype::A),
                &[192, 0, 2, 66]
            ),
            "over the block"
        );
        assert_eq!(
            summarize(&ask_from(&p, "10.0.0.5", "nx.example", rtype::A))
                .unwrap()
                .rcode,
            rcode::NXDOMAIN
        );
        cache_a(&p, "target.example", Ipv4Addr::new(198, 51, 100, 9));
        let r = ask_from(&p, "10.0.0.5", "cn.example", rtype::A);
        let s = summarize(&r).unwrap();
        assert_eq!(s.answers, 2, "CNAME + the target's A");
        assert!(contains(&r, &[198, 51, 100, 9]));
        assert!(
            !contains(
                &ask_from(&p, "10.0.0.5", "ex.example", rtype::A),
                &[192, 0, 2, 77]
            ),
            "the exception"
        );
    }

    /// REQ: DNS-016 (T9.10) — the exclusion set: an excluded (or IPv4-mapped) AAAA counts as
    /// missing, a mixed answer loses the excluded ones, an excluded A is never made into
    /// AAAA; reverse names in the prefix follow the IPv4 address's PTR (private ones stay
    /// local).
    #[test]
    fn dns_016_dns64_exclusions_and_reverse() {
        let cfg = format!(
            "{UPSTREAM}[[group]]\nname = \"default\"\ndns64 = true\ndns64_exclude = [\"2001:db8:bad::/48\", \"198.51.100.0/24\"]\n"
        );
        let p = pipeline_with(&cfg, "||nothing.example^\n");
        let synth = |last: &str| v6(&format!("64:ff9b::{last}"));
        // Only an excluded AAAA: made from the A record.
        cache_records(
            &p,
            "excl.example",
            rtype::AAAA,
            &[(rtype::AAAA, v6("2001:db8:bad::1"))],
        );
        cache_answer(
            &p,
            "excl.example",
            rtype::A,
            Some("192.0.2.44".parse().unwrap()),
        );
        let r = ask_from(&p, "10.0.0.5", "excl.example", rtype::AAAA);
        assert!(contains(&r, &synth("c000:22c")), "synthesized");
        assert!(!contains(&r, &v6("2001:db8:bad::1")));
        // IPv4-mapped: always excluded.
        cache_records(
            &p,
            "mapped.example",
            rtype::AAAA,
            &[(rtype::AAAA, v6("::ffff:192.0.2.45"))],
        );
        cache_answer(
            &p,
            "mapped.example",
            rtype::A,
            Some("192.0.2.45".parse().unwrap()),
        );
        assert!(contains(
            &ask_from(&p, "10.0.0.5", "mapped.example", rtype::AAAA),
            &synth("c000:22d")
        ));
        // Mixed: the real one stays, the excluded one goes.
        cache_records(
            &p,
            "mixed.example",
            rtype::AAAA,
            &[
                (rtype::AAAA, v6("2001:db8:bad::2")),
                (rtype::AAAA, v6("2001:db8::9")),
            ],
        );
        let r = ask_from(&p, "10.0.0.5", "mixed.example", rtype::AAAA);
        assert_eq!(summarize(&r).unwrap().answers, 1);
        assert!(contains(&r, &v6("2001:db8::9")));
        assert!(!contains(&r, &v6("2001:db8:bad::2")));
        // An excluded A: no AAAA made.
        cache_answer(&p, "v4ex.example", rtype::AAAA, None);
        cache_answer(
            &p,
            "v4ex.example",
            rtype::A,
            Some("198.51.100.7".parse().unwrap()),
        );
        let r = ask_from(&p, "10.0.0.5", "v4ex.example", rtype::AAAA);
        assert_eq!(summarize(&r).unwrap().answers, 0);
        // Reverse: 64:ff9b::192.0.2.33 → 33.2.0.192.in-addr.arpa's PTR.
        let host = NameBuf::from_presentation("host.example").unwrap();
        cache_records(
            &p,
            "33.2.0.192.in-addr.arpa",
            rtype::PTR,
            &[(rtype::PTR, host.as_wire().to_vec())],
        );
        let r = ask_from(&p, "10.0.0.5", &rev6("64:ff9b::c000:221"), rtype::PTR);
        let sr = summarize(&r).unwrap();
        assert_eq!((sr.rcode, sr.answers), (rcode::NOERROR, 2), "CNAME + PTR");
        assert!(contains(&r, host.as_wire()));
        // An embedded private address stays local (RFC 6303).
        let r = ask_from(&p, "10.0.0.5", &rev6("64:ff9b::c0a8:105"), rtype::PTR);
        assert_eq!(summarize(&r).unwrap().rcode, rcode::NXDOMAIN);
        // Outside the prefix: not ours.
        let other = NameBuf::from_presentation(&rev6("2001:db8::c000:221")).unwrap();
        assert!(dns64_reverse_target(&other, "64:ff9b::".parse().unwrap()).is_none());
    }

    /// REQ: FLT-015 (T7.20) — rebinding protection: a private address for a public name is
    /// refused (cache hits included), allowed under `rebinding_allow`, and for groups without
    /// it; `block_answer_ips` refuses a range for any name.
    #[test]
    fn flt_015_answer_ip_filter() {
        let cfg = format!(
            "{UPSTREAM}[[group]]\nname = \"default\"\nrebinding_protection = true\nrebinding_allow = [\"home.example\"]\nblock_answer_ips = [\"203.0.113.0/24\"]\n[[group]]\nname = \"open\"\nnetworks = [\"10.0.2.0/24\"]\n"
        );
        let p = pipeline_with(&cfg, "||nothing.example^\n");
        cache_a(&p, "evil.example", Ipv4Addr::new(192, 168, 1, 5));
        cache_a(&p, "nas.home.example", Ipv4Addr::new(192, 168, 1, 6));
        cache_a(&p, "bad.example", Ipv4Addr::new(203, 0, 113, 9));
        cache_a(&p, "ok.example", Ipv4Addr::new(93, 184, 216, 34));
        let evil = ask_from(&p, "10.0.0.5", "evil.example", rtype::A);
        assert!(
            !contains(&evil, &[192, 168, 1, 5]),
            "a private answer for a public name"
        );
        assert!(
            contains(
                &ask_from(&p, "10.0.0.5", "nas.home.example", rtype::A),
                &[192, 168, 1, 6]
            ),
            "allowed domain"
        );
        assert!(
            !contains(
                &ask_from(&p, "10.0.0.5", "bad.example", rtype::A),
                &[203, 0, 113, 9]
            ),
            "blocked range"
        );
        assert!(
            contains(
                &ask_from(&p, "10.0.0.5", "ok.example", rtype::A),
                &[93, 184, 216, 34]
            ),
            "public is fine"
        );
        assert!(
            contains(
                &ask_from(&p, "10.0.2.5", "evil.example", rtype::A),
                &[192, 168, 1, 5]
            ),
            "a group without it"
        );
    }

    /// REQ: FLT-014 (T7.20) — rewrites: an address (exact or wildcard) answered locally, a
    /// name answered as a CNAME with the name's addresses; only for the group.
    #[test]
    fn flt_014_rewrites() {
        let cfg = format!(
            "{UPSTREAM}[[group]]\nname = \"default\"\n[[group.rewrite]]\ndomain = \"nas.lan.example\"\nanswer = \"192.168.1.10\"\n[[group.rewrite]]\ndomain = \"*.dev.example\"\nanswer = \"10.1.1.1\"\n[[group.rewrite]]\ndomain = \"tv.example\"\nanswer = \"cdn.example\"\n[[group]]\nname = \"adults\"\nnetworks = [\"10.0.2.0/24\"]\n"
        );
        let p = pipeline_with(&cfg, "||nothing.example^\n");
        cache_a(&p, "cdn.example", Ipv4Addr::new(10, 9, 9, 9));
        cache_a(&p, "nas.lan.example", Ipv4Addr::new(1, 2, 3, 4));
        let nas = ask_from(&p, "10.0.0.5", "nas.lan.example", rtype::A);
        assert_eq!(summarize(&nas).unwrap().answers, 1);
        assert!(contains(&nas, &[192, 168, 1, 10]));
        let v6 = summarize(&ask_from(&p, "10.0.0.5", "nas.lan.example", rtype::AAAA)).unwrap();
        assert_eq!(
            (v6.rcode, v6.answers),
            (rcode::NOERROR, 0),
            "no data for the other family"
        );
        assert!(
            contains(
                &ask_from(&p, "10.0.0.5", "api.dev.example", rtype::A),
                &[10, 1, 1, 1]
            ),
            "wildcard"
        );
        let tv = ask_from(&p, "10.0.0.5", "tv.example", rtype::A);
        let target = NameBuf::from_presentation("cdn.example").unwrap();
        assert!(
            contains(&tv, target.as_wire()) && contains(&tv, &[10, 9, 9, 9]),
            "CNAME and its address"
        );
        assert!(
            contains(
                &ask_from(&p, "10.0.2.5", "nas.lan.example", rtype::A),
                &[1, 2, 3, 4]
            ),
            "other groups: the real answer"
        );
    }

    /// REQ: FLT-011 (T7.11) — safe search: an engine's name is answered as a CNAME to its
    /// safe-search name plus that name's addresses (resolved through the cache like any
    /// name); HTTPS records get no data; groups without safe search are untouched.
    #[test]
    fn flt_011_safe_search_rewrites_per_group() {
        let cfg = format!(
            "{UPSTREAM}[[group]]\nname = \"default\"\nsafe_search = true\n[[group]]\nname = \"adults\"\nnetworks = [\"10.0.2.0/24\"]\n"
        );
        let p = pipeline_with(&cfg, "||nothing.example^\n");
        let cache_a = |name: &str, ip: Ipv4Addr| {
            let req = query(name, rtype::A, false);
            let q = parse_query(&req).unwrap();
            let mut out = [0u8; 512];
            let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
            b.answer_a(300, ip).unwrap();
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
        cache_a(
            "forcesafesearch.google.com",
            Ipv4Addr::new(216, 239, 38, 120),
        );
        cache_a("www.google.com", Ipv4Addr::new(142, 250, 0, 1));
        let safe = ask_from(&p, "10.0.0.5", "www.google.com", rtype::A);
        let s = summarize(&safe).unwrap();
        assert_eq!(
            (s.rcode, s.answers),
            (rcode::NOERROR, 2),
            "CNAME and the target's A"
        );
        let target = NameBuf::from_presentation("forcesafesearch.google.com").unwrap();
        assert!(
            contains(&safe, target.as_wire()),
            "points at the safe-search name"
        );
        assert!(contains(&safe, &[216, 239, 38, 120]), "with its address");
        assert!(
            !contains(&safe, &[142, 250, 0, 1]),
            "not the normal address"
        );
        let rr: Vec<u16> = telltale_proto::records(&safe)
            .unwrap()
            .flatten()
            .filter(|r| r.section == telltale_proto::Section::Answer)
            .map(|r| r.rtype)
            .collect();
        assert_eq!(rr, vec![rtype::CNAME, rtype::A]);
        let https = ask_from(&p, "10.0.0.5", "www.google.com", rtype::HTTPS);
        let h = summarize(&https).unwrap();
        assert_eq!((h.rcode, h.answers), (rcode::NOERROR, 0), "no HTTPS hints");
        let adult = ask_from(&p, "10.0.2.5", "www.google.com", rtype::A);
        assert!(
            contains(&adult, &[142, 250, 0, 1]),
            "the adults group isn't rewritten"
        );
        assert!(!contains(&adult, target.as_wire()));
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
            client_subnet: 0,
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

    /// REQ: FLT-006, OBS-001 — every answer is logged with the device's group, also answers
    /// from local records and refusals, which return before filtering (owner report
    /// 2026-10-07: they were logged under the first configured group).
    #[test]
    fn flt_006_local_answers_keep_the_device_group() {
        let cfg: telltale_config::Config = telltale_config::Loader::new()
            .toml_str(
                "t.toml",
                r#"
[access]
allowed_networks = ["192.168.0.0/16"]

[[group]]
name = "Management"
networks = ["192.168.1.0/24"]

[[group]]
name = "LAB"
networks = ["192.168.5.0/24"]

[[record]]
name = "argo.example.test"
type = "A"
value = "192.168.5.100"
"#,
            )
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config;
        let (local, _) = LocalData::from_config(&cfg);
        let p = Pipeline::new(
            Settings::default(),
            Arc::new(Cache::new(CachePolicy::default())),
            Arc::new(Router::default()),
            Policy::from_config(&cfg, local),
        );
        let clients = Arc::clone(&p.current().policy.clients);
        let id = |name: &str| {
            u16::try_from(
                clients
                    .groups()
                    .iter()
                    .position(|g| &*g.name == name)
                    .unwrap(),
            )
            .unwrap()
        };
        let outcome = |name: &str, peer: &str, raw: Option<&[u8]>| {
            let mut buf = [0u8; 512];
            let n = NameBuf::from_presentation(name).unwrap();
            let len = build_query(&mut buf, 1, &n, rtype::A, 1, true, None).unwrap();
            let meta = RequestMeta {
                peer: format!("{peer}:5353").parse().unwrap(),
                local: None,
                transport: Transport::Udp,
                client_id: None,
            };
            let mut out = [0u8; 1024];
            let mut oc = Outcome {
                status: Status::Dropped,
                qtype: 0,
                client_ref: 0,
                group: 0,
                rule: None,
            };
            let req = raw.unwrap_or(&buf[..len]);
            let _ = p.handle_sync(req, &meta, &mut out, Instant::now(), &mut oc);
            (oc.status, oc.group)
        };
        assert_eq!(
            outcome("argo.example.test", "192.168.5.2", None),
            (Status::Local, id("LAB")),
            "a local record, from a LAB device"
        );
        assert_eq!(
            outcome("argo.example.test", "10.9.9.9", None),
            (Status::Refused, id("default")),
            "refused (not allowed): the device's group, default here"
        );
        assert_eq!(
            outcome("x", "192.168.5.2", Some(&[0u8; 3])).1,
            id("default"),
            "unparseable: default"
        );
    }
}
