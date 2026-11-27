//! Server lifecycle: startup, hot reload on SIGHUP, graceful shutdown.
//!
//! REQ: OPS-007 (drain on shutdown), OPS-009 (reload without dropping queries).

use crate::lists::Lists;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use telltale_cache::{Cache, CachePolicy};
use telltale_config::{Config, ListenProto, Listener, Loader};
use telltale_net::{
    CertStore, DohConfig, DohServer, TcpConfig, TcpServer, Transport, UdpConfig, UdpListener,
};
use telltale_policy::{LocalData, Neighbors};
use telltale_upstream::Router;
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::http;
use crate::pipeline::{Handler, Pipeline, Policy, Settings};

/// Loads and validates config from `files` + environment plus what the UI/API stored
/// (ADR-040), logging every problem.
/// REQ: NFR-001 (T10.2) — drops the executable's resident pages after work that runs once
/// (`telltale_net::trim_executable_pages`), off the query path.
pub(crate) fn trim_code_pages(after: &'static str) {
    std::thread::spawn(move || {
        telltale_net::background_thread();
        let bytes = telltale_net::trim_executable_pages();
        tracing::debug!(after, mib = bytes >> 20, "released code pages");
    });
}

pub(crate) fn load(files: &[PathBuf]) -> Option<Config> {
    load_files(files).map(|c| crate::replication::effective(&c))
}

/// Loads and validates `files` + environment only (without what the UI/API stored).
pub(crate) fn load_files(files: &[PathBuf]) -> Option<Config> {
    load_files_logging(files, true)
}

/// REQ: OBS-010 (ADR-179) — the config files as start-up keeps them (`file_config`), and whether
/// they couldn't be read: they were read once already to make `cfg`, and a change since can
/// make them unreadable. The running configuration then stands in for them until a reload reads
/// them, and the alert check counts nothing in it as this node's own (logged once, here).
pub(crate) fn files_at_start(files: &[PathBuf], cfg: &Config) -> (Config, bool) {
    if let Some(f) = load_files(files) {
        return (f, false);
    }
    warn!(
        "the config files couldn't be read again at start-up: until a reload reads them, every alert destination with a credential file is held to the folder rule (ADR-179)"
    );
    (cfg.clone(), true)
}

/// Like [`load_files`], logging only errors: for re-checking the node's own files on every
/// replicated change, where its warnings (a replica's file has no upstreams, by design)
/// would repeat what start-up already said.
pub(crate) fn load_files_quiet(files: &[PathBuf]) -> Option<Config> {
    load_files_logging(files, false)
}

fn load_files_logging(files: &[PathBuf], warnings: bool) -> Option<Config> {
    match files
        .iter()
        .fold(Loader::new(), Loader::file)
        .process_env()
        .load()
    {
        Ok(l) => {
            if warnings {
                for w in &l.warnings {
                    warn!("config: {w}");
                }
            }
            Some(l.config)
        }
        Err(errors) => {
            for e in &errors {
                error!("config: {e}");
            }
            None
        }
    }
}

/// Worker threads per UDP listener.
pub(crate) fn workers(cfg: &Config) -> usize {
    match cfg.node.workers {
        0 => telltale_net::default_workers(),
        n => usize::from(n),
    }
}

fn cache_policy(c: &telltale_config::CacheConfig, workers: usize) -> CachePolicy {
    CachePolicy {
        max_bytes: usize::try_from(c.max_bytes.bytes()).unwrap_or(usize::MAX),
        max_entries: c.max_entries as usize,
        min_ttl: c.min_ttl,
        max_ttl: c.max_ttl,
        negative_ttl_max: c.negative_ttl_max,
        servfail_ttl: c.servfail_ttl,
        serve_stale: c.serve_stale,
        stale_max_age: c.stale_max_age,
        stale_answer_ttl: c.stale_answer_ttl,
        prefetch: c.prefetch,
        prefetch_threshold_pct: c.prefetch_threshold_pct,
        prefetch_min_hits: c.prefetch_min_hits,
        // spec/03 §4: power of two >= 4 × workers, at least 64.
        shards: (workers * 4).max(64),
    }
}

/// Builds everything a reload can replace: upstreams/routes and policy (incl. local records).
pub(crate) fn build_dynamic(
    cfg: &Config,
    reuse: Option<Arc<Router>>,
) -> Result<(Arc<Router>, Policy), Vec<String>> {
    let router = match reuse {
        Some(r) => r,
        None => Arc::new(Router::from_config(cfg).map_err(|errs| {
            errs.into_iter()
                .map(|e| format!("upstreams: {e}"))
                .collect::<Vec<_>>()
        })?),
    };
    let (local, report) = LocalData::from_config(cfg);
    for w in &report.warnings {
        warn!("local records: {w}");
    }
    if !report.errors.is_empty() {
        return Err(report
            .errors
            .into_iter()
            .map(|e| format!("local records: {e}"))
            .collect());
    }
    for up in router.upstreams() {
        info!(name = %up.name, endpoint = %up.endpoint, "upstream");
    }
    if !local.is_empty() {
        info!(records = local.len(), "local records loaded");
    }
    let zones = load_zones(cfg)?;
    let mut policy = Policy::from_config(cfg, local);
    policy.zones = Arc::new(zones);
    Ok((router, policy))
}

/// REQ: OBS-024 (T13.1) — the policy and router a configuration would run with, built without
/// side effects or log lines (simulations build one per request, beside the serving state).
pub(crate) fn build_candidate(cfg: &Config) -> Result<(Arc<Router>, Policy), Vec<String>> {
    let router = Arc::new(Router::from_config(cfg).map_err(|errs| {
        errs.into_iter()
            .map(|e| format!("upstreams: {e}"))
            .collect::<Vec<_>>()
    })?);
    let (local, report) = LocalData::from_config(cfg);
    if !report.errors.is_empty() {
        return Err(report
            .errors
            .into_iter()
            .map(|e| format!("local records: {e}"))
            .collect());
    }
    let zones = load_zones(cfg)?;
    let mut policy = Policy::from_config(cfg, local);
    policy.zones = Arc::new(zones);
    Ok((router, policy))
}

/// REQ: DNS-018 (T7.22) — `[[zone]]`: each zone's file and records, most specific first.
pub(crate) fn load_zones(cfg: &Config) -> Result<Vec<crate::pipeline::Zone>, Vec<String>> {
    let mut zones = Vec::new();
    let mut errors = Vec::new();
    for (i, z) in cfg.zone.iter().enumerate() {
        let Ok(apex) = telltale_proto::NameBuf::from_presentation(z.name.as_str()) else {
            errors.push(format!("zone[{i}]: `{}` isn't a name", z.name.as_str()));
            continue;
        };
        let mut data = LocalData::default();
        let ttl = cfg.local.default_ttl;
        let mut apex_records = Vec::new();
        if let Some(f) = &z.file {
            match std::fs::read_to_string(f.as_str()) {
                Ok(text) => {
                    let mut im = crate::import::parse_zone(&text, Some(z.name.as_str()));
                    apex_records = std::mem::take(&mut im.apex);
                    for k in &im.skipped {
                        if !k.contains("SOA") && !k.contains(" NS") {
                            warn!(zone = %z.name.as_str(), "zone file: skipped {k}");
                        }
                    }
                    for r in &im.records {
                        if let Err(e) = data.add(&r.name, &r.rtype, &r.value, r.ttl.unwrap_or(ttl))
                        {
                            errors.push(format!("zone[{i}] {}: {e}", f.as_str()));
                        }
                    }
                }
                Err(e) => errors.push(format!("zone[{i}].file: {}: {e}", f.as_str())),
            }
        }
        for (j, r) in z.record.iter().enumerate() {
            if let Err(e) = data.add(&r.name, &r.rtype, &r.value, r.ttl.unwrap_or(ttl)) {
                errors.push(format!("zone[{i}].record[{j}]: {e}"));
            }
        }
        info!(zone = %z.name.as_str(), records = data.len(), "zone loaded");
        let (soa, ns) = apex_soa_ns(&apex, &apex_records, z.negative_ttl);
        zones.push(crate::pipeline::Zone {
            apex,
            data,
            groups: z.groups.iter().map(|g| g.as_str().into()).collect(),
            negative_ttl: z.negative_ttl,
            soa,
            ns,
            ttl,
        });
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    // Most specific first; group views before the zone for everyone.
    zones.sort_by_key(|z| (std::cmp::Reverse(z.apex.wire_len()), z.groups.is_empty()));
    Ok(zones)
}

/// A zone-file name: `@` is the apex, a name without a final dot is relative to it.
fn zone_name(token: &str, apex: &telltale_proto::NameBuf) -> Option<telltale_proto::NameBuf> {
    let text = if token == "@" {
        apex.display().to_string()
    } else if token.ends_with('.') {
        token.to_owned()
    } else {
        format!("{token}.{}", apex.display())
    };
    telltale_proto::NameBuf::from_presentation(text.trim_end_matches('.')).ok()
}

/// REQ: DNS-018 (T9.18) — a zone's SOA RDATA and name servers: the zone file's apex records,
/// or made up as resolvers serving local zones do (`localhost.`, `hostmaster.<apex>`, the
/// negative TTL as MINIMUM).
fn apex_soa_ns(
    apex: &telltale_proto::NameBuf,
    records: &[(String, Vec<String>)],
    negative_ttl: u32,
) -> (Vec<u8>, Vec<telltale_proto::NameBuf>) {
    let localhost = telltale_proto::NameBuf::from_presentation("localhost").unwrap_or_default();
    let soa = records
        .iter()
        .find(|(t, _)| t == "SOA")
        .and_then(|(_, d)| {
            let [mname, rname, nums @ ..] = d.as_slice() else {
                return None;
            };
            let nums: Vec<u32> = nums.iter().map(|n| n.parse().ok()).collect::<Option<_>>()?;
            if nums.len() != 5 {
                return None;
            }
            let mut out = zone_name(mname, apex)?.as_wire().to_vec();
            out.extend_from_slice(zone_name(rname, apex)?.as_wire());
            for n in nums {
                out.extend_from_slice(&n.to_be_bytes());
            }
            Some(out)
        })
        .unwrap_or_else(|| {
            let hostmaster = zone_name("hostmaster", apex).unwrap_or_default();
            let serial = u32::try_from(crate::pipeline::unix_now()).unwrap_or(1);
            let mut out = localhost.as_wire().to_vec();
            out.extend_from_slice(hostmaster.as_wire());
            for n in [serial, 3600, 600, 86_400, negative_ttl] {
                out.extend_from_slice(&n.to_be_bytes());
            }
            out
        });
    let mut ns: Vec<telltale_proto::NameBuf> = records
        .iter()
        .filter(|(t, _)| t == "NS")
        .filter_map(|(_, d)| zone_name(d.first()?, apex))
        .collect();
    if ns.is_empty() {
        ns.push(localhost);
    }
    (soa, ns)
}

/// REQ: FLT-006 (ADR-183) — how often the MAC table task looks at what the table is built from.
/// A look is a few atomic loads: whether anything changed is decided here, in the async loop,
/// and a blocking task runs only to read the kernel or to rebuild.
const MAC_TABLE_TICK: Duration = Duration::from_secs(5);

/// REQ: FLT-006 (ADR-183) — what the MAC table is built from, as of one look: whether a device is
/// named by its MAC, `[clients] router_macs`, this node's routers' view and the members'.
#[derive(Debug, Clone)]
pub(crate) struct MacInputs {
    uses_macs: bool,
    router_macs: bool,
    own: Arc<crate::devices::Leases>,
    peers: Arc<crate::devices::PeerMacs>,
}

impl MacInputs {
    /// A look at the pipeline: atomic loads only.
    pub(crate) fn load(p: &Pipeline) -> Self {
        let state = p.current();
        Self {
            uses_macs: state.policy.clients.uses_macs(),
            router_macs: state.policy.clients.router_macs(),
            own: p.router_leases.load_full(),
            peers: p.peer_router_macs.load_full(),
        }
    }

    /// Router and member entries enter the table only while a device is named by its MAC and
    /// the setting is on.
    fn uses_routers(&self) -> bool {
        self.uses_macs && self.router_macs
    }
}

/// REQ: FLT-006 (ADR-183) — whether the table has to be built again: the first time; after a
/// kernel read; when a device named by its MAC appears or goes, or `router_macs` changes (a
/// reload); and, only while router and member entries are in use, when this node's routers' view
/// or the members' bindings were replaced. Otherwise nothing runs.
pub(crate) fn should_rebuild(kernel_read: bool, last: Option<&MacInputs>, now: &MacInputs) -> bool {
    let Some(last) = last else {
        return true;
    };
    kernel_read
        || last.uses_macs != now.uses_macs
        || last.router_macs != now.router_macs
        || (now.uses_routers()
            && (!Arc::ptr_eq(&last.own, &now.own) || !Arc::ptr_eq(&last.peers, &now.peers)))
}

/// REQ: FLT-006 (ADR-183) — builds the table from the kernel's entries and, while they are in
/// use, the routers' and the members' bindings, swaps it in, and returns the old one for
/// [`crate::pipeline::retire`] to free: a table is never freed on a query worker.
pub(crate) fn rebuild_now(
    p: &Pipeline,
    kernel: &[(std::net::IpAddr, [u8; 6])],
    inputs: &MacInputs,
) -> Arc<telltale_policy::MacTable> {
    let bindings = inputs
        .uses_routers()
        .then(|| crate::devices::router_bindings(&inputs.own, &inputs.peers));
    p.neighbors
        .swap(crate::devices::build_table(kernel, bindings.as_ref()))
}

/// REQ: FLT-006, CLU-002 (ADR-183) — how long router MACs may be missing, with a device named by its
/// MAC, before the node says so: a node that has just started hasn't read its router or asked its
/// members yet.
const NO_BINDINGS_AFTER_S: u64 = 60;

/// REQ: FLT-006, CLU-002 (ADR-183) — whether to say that no router MAC reaches this node: said
/// once per spell, after [`NO_BINDINGS_AFTER_S`] seconds of a device being named by its MAC (and
/// `router_macs` on) with no router or member binding in the table, and again only after bindings
/// have come and gone.
#[derive(Debug, Default)]
struct NoBindings {
    since: Option<u64>,
    said: bool,
}

impl NoBindings {
    /// One look at `now_s` (seconds on the task's monotonic clock): `wanted` is whether router
    /// bindings are in use (a device is named by its MAC, `router_macs` is on), `router_here`
    /// whether a `[[router]]` is in this node's configuration (routers are shared settings, so in
    /// a cluster that has one every node, a resolver pod included, has it set), `bindings` how
    /// many rows of routers have reached it (this node's and the members': see
    /// `devices::bindings_reaching`). A node whose configuration has no router (a Pi with MAC
    /// clients from an import, or a cluster with none) is never told: there is nothing to read.
    /// True exactly once per spell.
    fn look(&mut self, wanted: bool, router_here: bool, bindings: usize, now_s: u64) -> bool {
        if !wanted || !router_here || bindings > 0 {
            *self = Self::default();
            return false;
        }
        let since = *self.since.get_or_insert(now_s);
        if self.said || now_s.saturating_sub(since) < NO_BINDINGS_AFTER_S {
            return false;
        }
        self.said = true;
        true
    }
}

/// REQ: FLT-006, CLU-002 (ADR-183) — what the node says when no router MAC reaches it: on a
/// resolver pod (an ephemeral member), which hears only the primary, that the primary's own router
/// is what it gets and so the key belongs there, unless the primary runs an earlier version or its
/// router is silent (the same message comes from those); elsewhere that no router of its own is
/// read and no member passes one on, and the other causes.
fn no_bindings_notice(ephemeral: bool) -> &'static str {
    if ephemeral {
        "devices are named by their MAC address, but no router MAC reaches this resolver pod: a pod hears only the primary, so the primary's own router view is all it can get, and the router key belongs on the primary (and on the node a failover would promote), unless it is there already: the primary may run an earlier version, or its router is silent (see its status). Until a MAC arrives those devices are recognized by their address, network or default group"
    } else {
        "devices are named by their MAC address, but no router MAC reaches this node: no router of its own is read here (its key may be missing, or its router is silent: see the router's status) and no other full cluster member passes one on (the members run an earlier version, or a member's router is silent, or they haven't sent their member list yet, or this node refuses its configuration and so keeps no member's bindings). Until one does those devices are recognized by their address, network or default group"
    }
}

/// What the MAC table task has said in the log, so each change is said once.
#[derive(Debug, Default)]
struct MacTableLog {
    routers_in_use: bool,
}

impl MacTableLog {
    /// REQ: FLT-006 (ADR-183) — says when router and member bindings start or stop being used.
    /// (That none reaches this node is [`NoBindings`]'s to say.)
    fn note(&mut self, table: &Neighbors) {
        let bindings = table.router_len() + table.peer_len();
        if bindings > 0 && !self.routers_in_use {
            info!(
                addresses = bindings,
                "client identification: {bindings} addresses recognized by the MAC their routers report"
            );
        } else if bindings == 0 && self.routers_in_use {
            info!(
                "client identification: no address is recognized by the MAC a router reports now"
            );
        }
        self.routers_in_use = bindings > 0;
    }
}

/// REQ: FLT-006 (ADR-183) — the one task that keeps the MAC table: the kernel's neighbor table
/// every `kernel_every` (`Some` while `[clients] neighbor_table` is on), and, while a device is
/// named by its MAC and `router_macs` is on, the routers' and the members' bindings after it. It
/// looks every [`MAC_TABLE_TICK`] and rebuilds, in a blocking task, only when [`should_rebuild`]
/// says so; the table it replaces is freed by `retire`. Off the query path: DNS never waits on it.
fn spawn_mac_table(
    pipeline: Arc<Pipeline>,
    kernel_every: Option<Duration>,
    cluster: Option<Arc<telltale_cluster::net::Cluster>>,
    routers_configured: impl Fn() -> bool + Send + 'static,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let started = tokio::time::Instant::now();
        let mut tick = tokio::time::interval(MAC_TABLE_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut kernel: Arc<Vec<(std::net::IpAddr, [u8; 6])>> = Arc::default();
        let mut kernel_at: Option<tokio::time::Instant> = None;
        let mut warned = false;
        let mut last: Option<MacInputs> = None;
        let mut log = MacTableLog::default();
        let mut none = NoBindings::default();
        loop {
            tick.tick().await;
            let mut kernel_read = false;
            if let Some(every) = kernel_every
                && kernel_at.is_none_or(|t| t.elapsed() >= every)
            {
                kernel_at = Some(tokio::time::Instant::now());
                match tokio::task::spawn_blocking(telltale_net::neighbors).await {
                    Ok(Ok(n)) => {
                        kernel = Arc::new(n.into_iter().map(|x| (x.ip, x.mac)).collect());
                        kernel_read = true;
                        warned = false;
                    }
                    Ok(Err(e)) if !warned => {
                        warn!(
                            "cannot read the neighbor table (MAC-based clients won't match): {e}"
                        );
                        warned = true;
                    }
                    _ => {}
                }
            }
            let now = MacInputs::load(&pipeline);
            // REQ: FLT-006, CLU-002 (ADR-183) — say once, after a minute, when a device is named by
            // its MAC and no router or member binding reaches this node, and why it may be so. A
            // few atomic loads each look; the registry is read only when it is about to be said.
            // What reached this node is counted from the data the bindings are made from, not from
            // table entries (a kernel entry that shadows a router entry hides nothing from it); and
            // only a node where a router could exist is told: one with a `[[router]]` in its
            // configuration (shared settings: in a cluster that has one, every node has it).
            let reached = crate::devices::bindings_reaching(&now.own, &now.peers);
            if none.look(
                now.uses_routers(),
                routers_configured(),
                reached,
                started.elapsed().as_secs(),
            ) {
                let ephemeral = match cluster.clone() {
                    Some(c) => tokio::task::spawn_blocking(move || c.is_ephemeral())
                        .await
                        .unwrap_or(false),
                    None => false,
                };
                info!("{}", no_bindings_notice(ephemeral));
            }
            if !should_rebuild(kernel_read, last.as_ref(), &now) {
                continue;
            }
            let (p, k, i) = (Arc::clone(&pipeline), Arc::clone(&kernel), now.clone());
            match tokio::task::spawn_blocking(move || rebuild_now(&p, &k, &i)).await {
                Ok(old) => crate::pipeline::retire(old),
                Err(e) => {
                    warn!("the MAC table could not be rebuilt: {e}");
                    continue;
                }
            }
            log.note(&pipeline.neighbors);
            last = Some(now);
        }
    })
}

fn spawn_health_checks(router: &Router) -> JoinHandle<()> {
    tokio::spawn(telltale_upstream::active_health_checks(
        router.upstreams().to_vec(),
        telltale_upstream::HEALTH_CHECK_INTERVAL,
    ))
}

/// The running DNS listeners: UDP keyed by address, stream listeners (TCP, DoT, DoH) by their
/// whole config entry.
struct Listeners {
    udp: Vec<(SocketAddr, UdpListener)>,
    streams: Vec<(Listener, Stream)>,
    workers: usize,
    handler: Arc<Handler>,
    rt: tokio::runtime::Handle,
}

/// A TCP-based listener, and the certificate watcher of a TLS one.
enum Stream {
    /// Plain TCP or DoT.
    Tcp(TcpServer, Option<JoinHandle<()>>),
    Doh(DohServer, JoinHandle<()>),
    /// REQ: DNS-004 (T7.7) — DNS over QUIC.
    Doq(telltale_net::DoqServer, JoinHandle<()>),
    /// REQ: DNS-004 (T7.8) — DoH over HTTP/3.
    Doh3(telltale_net::Doh3Server, JoinHandle<()>),
}

impl Stream {
    /// The address it's bound to (the port the OS chose, for port 0).
    fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Tcp(s, _) => s.local_addr(),
            Self::Doh(s, _) => s.local_addr(),
            Self::Doq(s, _) => s.local_addr(),
            Self::Doh3(s, _) => s.local_addr(),
        }
    }

    async fn shutdown(self) {
        match self {
            Self::Tcp(s, watch) => {
                if let Some(w) = watch {
                    w.abort();
                }
                s.shutdown().await;
            }
            Self::Doh(s, watch) => {
                watch.abort();
                s.shutdown().await;
            }
            Self::Doq(s, watch) => {
                watch.abort();
                s.shutdown().await;
            }
            Self::Doh3(s, watch) => {
                watch.abort();
                s.shutdown().await;
            }
        }
    }
}

/// REQ: FLT-010 (T7.10) — every 15 s: which schedules are on. A change rebuilds the filter's
/// list masks (no recompile) and turns block-everything on or off for the groups concerned.
async fn schedule_ticker(
    sources: Arc<crate::http::Sources>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut compiled_for: Option<Arc<Config>> = None;
    let mut compiled = Vec::new();
    loop {
        let cfg = sources.config.load_full();
        if compiled_for.as_ref().is_none_or(|c| !Arc::ptr_eq(c, &cfg)) {
            compiled = telltale_config::schedule::compile(&cfg);
            compiled_for = Some(Arc::clone(&cfg));
        }
        let clients = Arc::clone(&sources.pipeline.current().policy.clients);
        let now = i64::try_from(crate::pipeline::unix_now()).unwrap_or(i64::MAX);
        let state = crate::pipeline::ScheduleNow::compute(&cfg, &compiled, clients.groups(), now);
        if **sources.pipeline.schedules.load() != state {
            let on: Vec<&str> = compiled
                .iter()
                .filter(|s| s.is_on(now))
                .map(|s| s.name.as_str())
                .collect();
            info!(on = ?on, "schedules changed");
            sources.pipeline.schedules.store(Arc::new(state));
            sources.pipeline.set_filter(None);
        }
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(Duration::from_secs(15)) => {}
        }
    }
}

/// REQ: DNS-004 (T7.8) — the `Alt-Svc` an HTTP/2 DoH listener sends when an HTTP/3 DoH listener is
/// configured: clients that speak HTTP/3 switch to it for the same name.
fn alt_svc(listen: &[Listener]) -> Option<String> {
    listen
        .iter()
        .find(|l| l.proto == ListenProto::Doh3)
        .map(|l| format!("h3=\":{}\"; ma=86400", l.addr.port()))
}

/// REQ: DNS-002/003 — re-reads the certificate files every 10 s (cert-manager renewals). The
/// API listener's own files too (API-003, ADR-149).
pub(crate) fn watch_cert(store: Arc<CertStore>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        tick.tick().await;
        loop {
            tick.tick().await;
            match store.reload_if_changed() {
                Ok(true) => info!(cert = %store.cert_path().display(), "TLS certificate reloaded"),
                Ok(false) => {}
                Err(e) => warn!("TLS certificate reload failed (keeping the previous one): {e}"),
            }
        }
    })
}

/// REQ: OPS-004 — a listener that can't bind: `Udp 0.0.0.0:53: Address already in use (os error
/// 98)`, as before (scripts and log searches match it), then on the same line what to do, when
/// the cause is certain enough to say. `own_port`: this server holds that port itself (see
/// `Listeners::holds_port_of`). Start-up and reload only, never the query path.
fn bind_error(l: &Listener, e: &io::Error, own_port: bool) -> io::Error {
    let kind = e.kind();
    let msg = match bind_hint(l, kind, own_port) {
        Some(hint) => format!("{:?} {}: {e}; {hint}", l.proto, l.addr),
        None => format!("{:?} {}: {e}", l.proto, l.addr),
    };
    io::Error::new(kind, msg)
}

fn bind_hint(l: &Listener, kind: io::ErrorKind, own_port: bool) -> Option<String> {
    let port = l.addr.port();
    // The way the importers' notes name a docs section.
    let docs = "`docs/running.md`, Port 53 already in use";
    match kind {
        // On Linux a program listening on any one address of the machine blocks the wildcard
        // address on that port (systemd-resolved's stub, a dnsmasq such as libvirt's, ...).
        // `sudo`: without it, `ss -p` doesn't name another user's process.
        io::ErrorKind::AddrInUse if !own_port => {
            let ss = if l.proto.is_tcp_based() {
                "sudo ss -ltnp"
            } else {
                "sudo ss -lunp"
            };
            Some(if l.addr.ip().is_unspecified() {
                let any = if l.addr.is_ipv4() { "0.0.0.0" } else { "[::]" };
                format!(
                    "another program on this machine already uses port {port} (for {any}, one that \
                     listens on a single address of the machine is enough): {ss} 'sport = :{port}' \
                     shows which; to run beside it, set [[listen]] to this machine's own address \
                     ({docs})"
                )
            } else {
                format!(
                    "another program on this machine already uses port {port} on this address or \
                     on all of them: {ss} 'sport = :{port}' shows which ({docs})"
                )
            })
        }
        // Plain UDP and TCP only: a TLS listener's refusal can come from its certificate files.
        io::ErrorKind::PermissionDenied
            if port < 1024 && matches!(l.proto, ListenProto::Udp | ListenProto::Tcp) =>
        {
            Some(format!(
                "ports below 1024 need root or the CAP_NET_BIND_SERVICE capability, or the host \
                 setting net.ipv4.ip_unprivileged_port_start at {port} or lower (`docs/running.md`, \
                 Container image)"
            ))
        }
        _ => None,
    }
}

/// REQ: OPS-004 — whether this server's listener `held` (its protocol and bound address) takes
/// the port `l` wants: the same transport (UDP or TCP), the same port, and addresses that
/// overlap (the same one, or either a wildcard). Plain UDP and TCP on IPv6 are V6ONLY, so the
/// families stay apart for them; DoQ and DoH3 are bound by quinn without it, so on `[::]` (with
/// the usual `net.ipv6.bindv6only = 0`) either side being one of those takes the IPv4 port too.
fn takes_port(held: ListenProto, at: SocketAddr, l: &Listener) -> bool {
    let dual = |p: ListenProto, a: SocketAddr| {
        matches!(p, ListenProto::Doq | ListenProto::Doh3) && a.is_ipv6() && a.ip().is_unspecified()
    };
    held.is_tcp_based() == l.proto.is_tcp_based()
        && at.port() == l.addr.port()
        && (at.is_ipv4() == l.addr.is_ipv4() || dual(held, at) || dual(l.proto, l.addr))
        && (at.ip().is_unspecified() || l.addr.ip().is_unspecified() || at.ip() == l.addr.ip())
}

impl Listeners {
    /// Makes the running set match `listen`: binds additions first, then closes removals, so a
    /// changed address never leaves a gap (`spec/08` §5). A stream listener whose settings
    /// changed on the same address is closed just before its replacement binds.
    async fn apply(&mut self, listen: &[Listener]) -> io::Result<()> {
        for l in listen {
            match l.proto {
                ListenProto::Udp if !self.udp.iter().any(|(a, _)| *a == l.addr) => {
                    let listener = UdpListener::spawn(
                        &UdpConfig::new(l.addr, self.workers),
                        &self.handler,
                        &self.rt,
                    )
                    .map_err(|e| bind_error(l, &e, self.holds_port_of(l)))?;
                    info!(addr = %listener.local_addr(), workers = self.workers, "listening (udp)");
                    self.udp.push((l.addr, listener));
                }
                ListenProto::Tcp
                | ListenProto::Dot
                | ListenProto::Doh
                | ListenProto::Doq
                | ListenProto::Doh3
                    if !self.streams.iter().any(|(c, _)| c == l) =>
                {
                    // Same protocol and address with other settings: replace it.
                    if let Some(i) = self
                        .streams
                        .iter()
                        .position(|(c, _)| c.proto == l.proto && c.addr == l.addr)
                    {
                        let (_, old) = self.streams.remove(i);
                        old.shutdown().await;
                    }
                    let stream = self
                        .bind_stream(l, alt_svc(listen).as_deref())
                        .map_err(|e| bind_error(l, &e, self.holds_port_of(l)))?;
                    self.streams.push((l.clone(), stream));
                }
                ListenProto::Udp
                | ListenProto::Tcp
                | ListenProto::Dot
                | ListenProto::Doh
                | ListenProto::Doq
                | ListenProto::Doh3 => {}
            }
        }
        let (kept, gone): (Vec<_>, Vec<_>) = self.udp.drain(..).partition(|(a, _)| {
            listen
                .iter()
                .any(|l| l.proto == ListenProto::Udp && l.addr == *a)
        });
        self.udp = kept;
        for (addr, l) in gone {
            info!(%addr, "closing udp listener");
            l.shutdown();
        }
        let (kept, gone): (Vec<_>, Vec<_>) = self
            .streams
            .drain(..)
            .partition(|(c, _)| listen.contains(c));
        self.streams = kept;
        for (c, s) in gone {
            info!(addr = %c.addr, proto = ?c.proto, "closing listener");
            tokio::spawn(s.shutdown()); // drains its connections in the background
        }
        Ok(())
    }

    /// REQ: OPS-004 — whether one of this server's own listeners takes `l`'s port (`takes_port`).
    /// `apply` binds additions before it closes removals, so a reload that moves a listener
    /// between the wildcard address and one address on the same port finds the port busy with
    /// its own listener: the hint about another program would be wrong there. Start-up and
    /// reload only.
    fn holds_port_of(&self, l: &Listener) -> bool {
        self.udp
            .iter()
            .any(|(_, u)| takes_port(ListenProto::Udp, u.local_addr(), l))
            || self
                .streams
                .iter()
                .any(|(c, s)| takes_port(c.proto, s.local_addr(), l))
    }

    fn bind_stream(&self, l: &Listener, alt_svc: Option<&str>) -> io::Result<Stream> {
        let store = match &l.tls {
            Some(t) => Some(CertStore::load(t.cert.as_str(), t.key.as_str())?),
            None => None,
        };
        let handler = Arc::clone(&self.handler);
        match (l.proto, store) {
            (ListenProto::Doh, Some(store)) => {
                let mut cfg = DohConfig::new(l.addr, Arc::clone(&store));
                if let Some(p) = &l.path {
                    p.as_str().trim_end_matches('/').clone_into(&mut cfg.path);
                }
                cfg.proxy_protocol = l.proxy_protocol;
                cfg.alt_svc = alt_svc.map(str::to_owned);
                if let Some(n) = l.max_connections {
                    cfg.max_connections = n as usize;
                }
                if let Some(n) = l.max_connections_per_address {
                    cfg.max_connections_per_address = n as usize;
                }
                // REQ: DNS-003, DNS-020 (ADR-194)
                cfg.trusted_proxies = l
                    .trusted_proxies
                    .iter()
                    .map(|n| telltale_net::forwarded::Network {
                        addr: n.addr,
                        prefix: n.prefix,
                    })
                    .collect();
                cfg.x_forwarded_for = l.x_forwarded_for;
                let behind = cfg.behind_listed_proxies();
                let s = DohServer::bind(cfg, handler)?;
                if behind {
                    info!(
                        addr = %s.local_addr(),
                        proxy_protocol = l.proxy_protocol,
                        x_forwarded_for = l.x_forwarded_for,
                        trusted_proxies = l.trusted_proxies.len(),
                        "listening (doh)"
                    );
                } else {
                    info!(addr = %s.local_addr(), proxy_protocol = l.proxy_protocol, "listening (doh)");
                }
                Ok(Stream::Doh(s, watch_cert(store)))
            }
            (ListenProto::Doh3, Some(store)) => {
                let mut cfg = telltale_net::Doh3Config::new(l.addr, Arc::clone(&store));
                if let Some(p) = &l.path {
                    p.as_str().trim_end_matches('/').clone_into(&mut cfg.path);
                }
                if let Some(n) = l.max_connections {
                    cfg.max_connections = n as usize;
                }
                if let Some(n) = l.max_connections_per_address {
                    cfg.max_connections_per_address = n as usize;
                }
                let s = telltale_net::Doh3Server::bind(&cfg, handler)?;
                info!(addr = %s.local_addr(), "listening (doh3)");
                Ok(Stream::Doh3(s, watch_cert(store)))
            }
            (ListenProto::Doq, Some(store)) => {
                let mut cfg = telltale_net::DoqConfig::new(l.addr, Arc::clone(&store));
                if let Some(n) = l.max_connections {
                    cfg.max_connections = n as usize;
                }
                if let Some(n) = l.max_connections_per_address {
                    cfg.max_connections_per_address = n as usize;
                }
                let s = telltale_net::DoqServer::bind(&cfg, handler)?;
                info!(addr = %s.local_addr(), "listening (doq)");
                Ok(Stream::Doq(s, watch_cert(store)))
            }
            (proto, store) => {
                let mut cfg = TcpConfig::new(l.addr);
                cfg.proxy_protocol = l.proxy_protocol;
                if let Some(n) = l.max_connections {
                    cfg.max_connections = n as usize;
                }
                if let Some(n) = l.max_connections_per_address {
                    cfg.max_connections_per_address = n as usize;
                }
                if proto == ListenProto::Dot {
                    cfg.transport = Transport::Dot;
                    cfg.tls.clone_from(&store);
                }
                let s = TcpServer::bind(cfg, handler)?;
                let label = if proto == ListenProto::Dot {
                    "dot"
                } else {
                    "tcp"
                };
                info!(addr = %s.local_addr(), proxy_protocol = l.proxy_protocol, "listening ({label})");
                Ok(Stream::Tcp(s, store.map(watch_cert)))
            }
        }
    }

    fn stats(&self) -> ListenerStats {
        ListenerStats {
            udp: self
                .udp
                .iter()
                .flat_map(|(_, l)| l.stats().iter().cloned())
                .collect(),
            tcp: self
                .streams
                .iter()
                .filter_map(|(_, s)| match s {
                    Stream::Tcp(t, _) => Some(t.stats_handle()),
                    Stream::Doh(..) | Stream::Doq(..) | Stream::Doh3(..) => None,
                })
                .collect(),
            doh: self
                .streams
                .iter()
                .filter_map(|(_, s)| match s {
                    Stream::Doh(d, _) => Some(d.stats_handle()),
                    Stream::Doh3(d, _) => Some(d.stats_handle()),
                    Stream::Tcp(..) | Stream::Doq(..) => None,
                })
                .collect(),
            doq: self
                .streams
                .iter()
                .filter_map(|(_, s)| match s {
                    Stream::Doq(d, _) => Some(d.stats_handle()),
                    Stream::Tcp(..) | Stream::Doh(..) | Stream::Doh3(..) => None,
                })
                .collect(),
        }
    }
}

/// Listener counters for `/metrics`.
struct ListenerStats {
    udp: Vec<Arc<telltale_net::WorkerStats>>,
    tcp: Vec<Arc<telltale_net::TcpStats>>,
    doh: Vec<Arc<telltale_net::DohStats>>,
    doq: Vec<Arc<telltale_net::DoqStats>>,
}

/// Settings a reload can't change without a restart; returns what differs.
fn restart_only_changes(old: &Config, new: &Config) -> Vec<&'static str> {
    let mut v = Vec::new();
    if old.cache != new.cache {
        v.push("[cache]");
    }
    if old.telemetry != new.telemetry {
        v.push("[telemetry]");
    }
    // REQ: OPS-011 — the log files are opened once, at start.
    if old.support != new.support {
        v.push("[support]");
    }
    // REQ: OPS-012 — the watchdog thread reads its settings once, at start.
    if old.watchdog != new.watchdog {
        v.push("[watchdog]");
    }
    if old.node != new.node {
        v.push("[node]");
    }
    if old.filter != new.filter {
        v.push("[filter]");
    }
    if old.dns != new.dns {
        v.push("[dns]");
    }
    if old.clients.neighbor_table != new.clients.neighbor_table
        || old.clients.neighbor_refresh_secs != new.clients.neighbor_refresh_secs
    {
        v.push("[clients] neighbor_table / neighbor_refresh_secs");
    }
    if old.clients.mdns != new.clients.mdns || old.clients.mdns_port != new.clients.mdns_port {
        v.push("[clients] mdns / mdns_port");
    }
    // The API listener is started once (API-003, ADR-149).
    if old.api.enabled != new.api.enabled
        || old.api.listen != new.api.listen
        || old.api.tls != new.api.tls
    {
        v.push("[api] enabled / listen / tls");
    }
    v
}

/// REQ: OBS-003 — the query-log writer, fed by the aggregator thread. A failure to start
/// it is logged and DNS carries on without a query log (`spec/02` §8.5).
pub(crate) fn query_log(
    cfg: &Config,
) -> (
    Option<Box<dyn telltale_telemetry::ring::Sink>>,
    Option<Arc<telltale_store::qlog::Stats>>,
) {
    let q = &cfg.telemetry.qlog;
    if !q.enabled {
        return (None, None);
    }
    // REQ: CLU-007 — in ship mode the local log is only a buffer: bounded, and closed on a
    // timer so the shipper can deliver it (ADR-055).
    let ship = cfg.telemetry.mode == telltale_config::TelemetryMode::Ship;
    let settings = telltale_store::qlog::Settings {
        dir: std::path::Path::new(cfg.node.data_dir.as_str()).join("qlog"),
        // Cluster node IDs come with membership (T5.x); a standalone node is 0.
        node: 0,
        privacy: q.privacy_level,
        flush_interval: Duration::from_secs(u64::from(q.flush_interval_secs.max(1))),
        fsync: q.fsync,
        retention_days: q.retention_days,
        retention_bytes: if ship {
            q.retention_bytes
                .bytes()
                .min(cfg.telemetry.ship.buffer_bytes.bytes())
        } else {
            q.retention_bytes.bytes()
        },
        rotate_after: ship
            .then(|| Duration::from_secs(u64::from(cfg.telemetry.ship.interval_secs))),
    };
    match telltale_store::qlog::Builder::spawn(settings) {
        Ok(b) => {
            let stats = b.stats();
            (Some(Box::new(b)), Some(stats))
        }
        Err(e) => {
            warn!("query log disabled: cannot start its writer: {e}");
            (None, None)
        }
    }
}

/// The query pipeline for `cfg` (settings derived from config).
fn build_pipeline(
    cfg: &Config,
    cache: Arc<Cache>,
    router: Arc<Router>,
    policy: Policy,
) -> Arc<Pipeline> {
    let settings = Settings {
        edns_payload: cfg.dns.edns_payload,
        stale_answer_timeout: Duration::from_millis(u64::from(
            cfg.cache.stale_answer_client_timeout_ms,
        )),
        // `ring_slots` events of ~128 bytes (ADR-026).
        ring_bytes: usize::try_from(cfg.telemetry.ring_slots).unwrap_or(4096) * 128,
        ..Settings::default()
    };
    let p = Pipeline::new(settings, cache, router, policy);
    p.set_dnssec(cfg);
    // REQ: OBS-019 (T11.4)
    p.set_upstream_check(cfg);
    p
}

/// REQ: OBS-005 — per-client query series are opt-in and capped (`[telemetry.metrics]`).
/// REQ: OBS-022 (T12.1, ADR-111) — the exclusions the aggregator applies from its next drain
/// (at start and on every reload, a replica's included).
pub(crate) fn exclusions(cfg: &Config) -> Option<telltale_telemetry::exclude::Exclusions> {
    let x = &cfg.exclusions;
    if !x.active() {
        return None;
    }
    let names = x.names.iter().filter_map(|n| {
        let bare = n.trim().trim_start_matches("*.");
        telltale_proto::NameBuf::from_presentation(bare)
            .ok()
            .map(|b| b.as_wire().to_vec())
    });
    let nets: Vec<(std::net::IpAddr, u8)> = x.clients.iter().map(|c| (c.addr, c.prefix)).collect();
    Some(telltale_telemetry::exclude::Exclusions::new(names, &nets))
}

fn set_client_metrics(cfg: &Config, pipeline: &Pipeline) {
    pipeline.telemetry.set_exclusions(exclusions(cfg));
    let m = &cfg.telemetry.metrics;
    let mut agg = pipeline.telemetry.aggregates();
    agg.exported.client_cap = if m.per_client {
        usize::try_from(m.per_client_cap).unwrap_or(usize::MAX)
    } else {
        0
    };
    // REQ: OBS-016 (ADR-105) — the time buckets count answers slower than the latency
    // objective's threshold.
    agg.slo_latency_us = u64::from(cfg.slo.latency_ms) * 1000;
    agg.internal = internal_names(cfg);
}

/// REQ: OBS-037 (ADR-152) — the names the internal top list takes: reverse lookups of private
/// addresses, `cluster.local` when Kubernetes is on, and `[telemetry] internal_names`.
pub(crate) fn internal_names(cfg: &Config) -> telltale_telemetry::internal::InternalNames {
    let cluster = cfg.kubernetes.enabled.then_some("cluster.local");
    let names = cfg
        .telemetry
        .internal_names
        .iter()
        .map(|n| n.trim().trim_start_matches("*."))
        .chain(cluster)
        .filter_map(|n| {
            telltale_proto::NameBuf::from_presentation(n)
                .ok()
                .map(|b| b.as_wire().to_vec())
        });
    telltale_telemetry::internal::InternalNames::new(names, true)
}

/// Starts the metrics and API listeners; both stop when `stop` turns true.
async fn start_http(
    cfg: &Config,
    sources: &Arc<http::Sources>,
    stop: &tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    let stopped = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
        let _ = rx.wait_for(|s| *s).await;
    };
    if cfg.telemetry.metrics.enabled {
        let addr = cfg.telemetry.metrics.listen;
        let app = http::router(Arc::clone(sources));
        let bound = http::serve(addr, app, stopped(stop.clone()))
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("metrics {addr}: {e}")))?;
        info!(addr = %bound, "serving /metrics, /healthz, /readyz, /livez");
    }
    // REQ: API-001 — the REST API (and its OpenAPI document) on its own listener.
    // REQ: API-003 — behind sign-in. Rule 5: if state.db can't be opened, the API stays off
    // and DNS keeps answering.
    if cfg.api.enabled {
        let c = cfg.clone();
        let auth = match tokio::task::spawn_blocking(move || crate::auth_setup::open(&c)).await {
            Ok(Ok(a)) => a,
            Ok(Err(e)) => {
                error!("api disabled: cannot open the user database: {e}");
                return Ok(());
            }
            Err(e) => {
                error!("api disabled: {e}");
                return Ok(());
            }
        };
        let _purge =
            crate::auth_setup::spawn_purge(Arc::clone(&auth), cfg.auth.audit_retention_days);
        let addr = cfg.api.listen;
        auth.agents()
            .set(cfg.agents.enabled, cfg.agents.rate_per_minute);
        auth.agents()
            .set_require_approval(cfg.agents.require_approval);
        let _ = sources.auth.set(Arc::clone(&auth));
        // REQ: FLT-005 (ADR-067) — expired quick rules are removed and audit-logged.
        crate::api_backend::spawn_rule_sweep(Arc::clone(sources), Arc::clone(&auth), stop.clone());
        let app = http::api_router(Arc::clone(sources), auth);
        // REQ: API-003 (ADR-149) — HTTPS on the listener itself. Without a certificate the API
        // stays off rather than serving sign-ins in the clear; DNS keeps answering.
        let tls = match &cfg.api.tls {
            None => None,
            Some(t) => match crate::api_tls::setup(cfg, t) {
                Ok(s) => Some(s),
                Err(e) => {
                    error!("api disabled: its TLS certificate ([api] tls): {e}");
                    return Ok(());
                }
            },
        };
        let bound = match &tls {
            Some(t) => crate::api_tls::serve(addr, app, t, stopped(stop.clone())).await,
            None => http::serve(addr, app, stopped(stop.clone())).await,
        }
        .map_err(|e| io::Error::new(e.kind(), format!("api {addr}: {e}")))?;
        let scheme = if tls.is_some() { "https" } else { "http" };
        info!(addr = %bound, scheme, "serving the API at /api/v1 (OpenAPI: /api/v1/openapi.json)");
    }
    Ok(())
}

/// Runs until SIGTERM/SIGINT. SIGHUP reloads config from `files`.
// The startup sequence and the main loop read best in one place.
#[allow(clippy::too_many_lines)]
pub(crate) async fn serve(files: Vec<PathBuf>, cfg: Config) -> io::Result<()> {
    // REQ: OPS-007, OPS-009 — the signals are this process's from the start, before DNS answers
    // (review round 3, F2): one that arrives during start-up (a stop, `systemctl reload`) is kept
    // by the runtime and acted on once the node is up, a drained stop or a reload, rather than
    // ending the process by the signal's default action (systemd counts a death by SIGHUP as
    // clean, so `Restart=on-failure` wouldn't bring it back).
    let mut term = signal(SignalKind::terminate())?;
    let mut hup = signal(SignalKind::hangup())?;
    let mut usr1 = signal(SignalKind::user_defined1())?;
    let mut int = signal(SignalKind::interrupt())?;
    // spec/04 §7: tag outbound queries so a forwarding loop back to us is detectable.
    telltale_upstream::set_node_tag(rand::random());
    let workers = workers(&cfg);
    let (router, policy) = build_dynamic(&cfg, None).map_err(|errs| {
        for e in &errs {
            error!("{e}");
        }
        io::Error::other("invalid configuration")
    })?;
    let mut health = spawn_health_checks(&router);
    let neighbor_refresh = cfg
        .clients
        .neighbor_table
        .then_some(Duration::from_secs(u64::from(
            cfg.clients.neighbor_refresh_secs,
        )));
    let cache = Arc::new(Cache::new(cache_policy(&cfg.cache, workers)));
    let pipeline = build_pipeline(&cfg, Arc::clone(&cache), router, policy);
    // REQ: OBS-007 (T7.18) — dnstap (read at startup).
    if let Some(tap) = crate::dnstap::start(&cfg) {
        let _ = pipeline.dnstap.set(tap);
    }
    // REQ: DNS-009 — start warm: reload the cache dumped at the last shutdown.
    let warm = cfg
        .cache
        .persist
        .then(|| load_cache(&cfg, &cache, &pipeline));
    // REQ: OBS-002 — one aggregator thread drains the event rings (`spec/06` §2). It never
    // touches the query path: a stalled aggregator only means dropped (counted) events.
    let (qlog, qlog_stats) = query_log(&cfg);
    set_client_metrics(&cfg, &pipeline);
    // REQ: OBS-008 — the live tail is fed by the same aggregator pass as the query log.
    let tail = crate::tail::Tail::new(cfg.telemetry.qlog.privacy_level);
    // REQ: OBS-013 — the anomaly engine rides the same aggregator pass (off the query path).
    let anomalies = crate::anomaly::Anomalies::start(&cfg);
    // REQ: OBS-003 (review 04-05) — level 1's names are hashed with this node's (or, once a
    // primary's version arrives, the cluster's) key.
    crate::privacy::init(std::path::Path::new(cfg.node.data_dir.as_str()));
    // REQ: OBS-033 — change markers: this start, and a new build.
    let annotations = crate::annotations::init(
        std::path::Path::new(cfg.node.data_dir.as_str()),
        crate::annotations::now_ms(),
    );
    annotations.started(
        crate::build_info::VERSION,
        crate::build_info::COMMIT,
        crate::datadir::unclean_start(),
        crate::annotations::now_ms(),
    );
    // REQ: OBS-009 (review 04-04) — the in-memory analytics follow the privacy level.
    pipeline
        .telemetry
        .set_privacy(cfg.telemetry.qlog.privacy_level);
    let anomaly_sink = anomalies
        .as_ref()
        .map(|a| Box::new(a.sink()) as Box<dyn telltale_telemetry::ring::Sink>);
    // REQ: OBS-010 (T7.13) — event sinks (file, syslog, webhook) on the same pass.
    let events = crate::sinks::start(&cfg, &pipeline, &tokio::runtime::Handle::current());
    // REQ: OBS-018 (T11.5) — shadow lists and over-blocking suspects, on the same pass.
    let shadow = Arc::new(crate::shadow::Shadow::new(
        cfg.telemetry.qlog.privacy_level,
        pipeline.telemetry.ts_us(std::time::Instant::now()),
    ));
    let shadow_sink = Box::new(crate::shadow::ShadowSink::new(
        Arc::clone(&shadow),
        Arc::clone(&pipeline),
    )) as Box<dyn telltale_telemetry::ring::Sink>;
    // REQ: OBS-017 (T11.6) — latency exemplars and queries to trace, on the same pass.
    let traces = Arc::new(crate::traces::Traces::default());
    let trace_sink = Box::new(crate::traces::TraceSink::new(Arc::clone(&traces), &cfg))
        as Box<dyn telltale_telemetry::ring::Sink>;
    let extra: Vec<Box<dyn telltale_telemetry::ring::Sink>> = anomaly_sink
        .into_iter()
        .chain(events)
        .chain([shadow_sink, trace_sink])
        .collect();
    let extra =
        Some(Box::new(crate::tail::Fanout(extra)) as Box<dyn telltale_telemetry::ring::Sink>);
    let sink = crate::tail::combine(qlog, tail.as_deref(), extra);
    // REQ: FLT-017 (ADR-150) — with Kubernetes on, the analytics wait briefly for pod addresses
    // from the first query, before the first table arrives, and the workloads' counts carry on.
    if crate::kubernetes::wanted(&cfg) {
        pipeline
            .telemetry
            .set_workload_keys(Some(telltale_telemetry::workload::Keys::new()));
        crate::kubernetes::restore_counts(cfg.node.data_dir.as_str(), &pipeline.telemetry);
    }
    let _aggregator = pipeline
        .telemetry
        .spawn_aggregator(Duration::from_millis(25), sink)?;
    // REQ: OBS-004 (T6.16) — the current and previous hour's top lists come back after a
    // restart, from the query log (in the background; DNS doesn't wait).
    crate::replay::spawn(&cfg, &pipeline);
    let mut listeners = Listeners {
        udp: Vec::new(),
        streams: Vec::new(),
        workers,
        handler: Arc::new(Handler(Arc::clone(&pipeline))),
        rt: tokio::runtime::Handle::current(),
    };
    listeners.apply(&cfg.listen).await?;

    // REQ: OBS-004, `spec/06` §3 — rollups on disk, fed once a minute off the query path.
    let (rollups, _rollup_writer) = crate::rollups::start(&cfg, &pipeline);

    // REQ: OBS-005, OPS-006 — metrics and health probes. An ephemeral resolver pod is ready
    // only once it has the cluster's configuration too, so it never serves unfiltered (CLU-009).
    let readiness = Arc::new(crate::readiness::Readiness::new(cfg.cluster.ephemeral));
    let stats = listeners.stats();
    let (reload_tx, mut reload_rx) =
        tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<bool>>(8);
    let (stop_http, http_stopped) = tokio::sync::watch::channel(false);
    // REQ: CLU-009 — create or join the cluster on first start (the Helm chart's controller
    // and resolver pods). A resolver pod that can't join exits, so Kubernetes retries it.
    // REQ: OPS-007 (review round 4, N1) — a stop during the join (it waits up to two minutes)
    // ends the join and the node at once: nothing is ready yet, so there is nothing to drain,
    // and systemd's or Kubernetes' stop timeout would otherwise kill it first. A SIGHUP or
    // SIGUSR1 meanwhile stays queued for the loop. `biased`: with no join to make, the
    // bootstrap is ready at once and a stop already queued is drained by the loop as before.
    let joined = tokio::select! {
        biased;
        r = crate::cluster::bootstrap(&cfg, Duration::from_secs(120)) => Some(r),
        _ = term.recv() => {
            info!(signal = "SIGTERM", "shutting down during the cluster join");
            None
        }
        _ = int.recv() => {
            info!(signal = "SIGINT", "shutting down during the cluster join");
            None
        }
    };
    let Some(joined) = joined else {
        // What runs so far: the DNS listeners (stopped here), the health checks, the
        // aggregator thread (joined when its guard drops) and the rollups writer (a task the
        // runtime drops). Not yet opened or started: the state database, the API, the cluster
        // channel, the lists; a join that was cut short saved no identity (it saves only once
        // the primary has answered, in one step). The warm cache is kept, as on any stop.
        for (_, s) in listeners.streams.drain(..) {
            s.shutdown().await;
        }
        for (_, l) in listeners.udp.drain(..) {
            l.shutdown();
        }
        health.abort();
        if cfg.cache.persist {
            save_cache(&cfg, &cache);
        }
        return Ok(());
    };
    if let Err(e) = joined {
        if cfg.cluster.ephemeral {
            return Err(io::Error::other(format!("cluster: {e}")));
        }
        warn!("cluster: {e}; running standalone");
    }
    // REQ: CLU-001, CLU-004 — the cluster channel runs beside DNS and never gates it.
    let cluster = crate::cluster::start(&cfg, &http_stopped);
    // REQ: OPS-010 — a maintenance window from before a restart takes effect before the node
    // first reports ready: the operator or the clock, not a reboot, says when it's back.
    let maintenance = Arc::new(crate::maintenance::Maintenance::open(
        std::path::Path::new(cfg.node.data_dir.as_str()),
        Arc::clone(&readiness),
        cluster.clone(),
        crate::maintenance::now_ms(),
    ));
    let (own_files, files_unread) = files_at_start(&files, &cfg);
    // REQ: API-002, API-010, CLU-003 (GitHub issue #113) — what the API's entries were merged
    // onto (none while the files couldn't be read: the running configuration stands in for them).
    let managed_base = if files_unread {
        None
    } else {
        crate::replication::managed_base(&own_files).map(Arc::new)
    };
    let sources = Arc::new(http::Sources {
        metrics: Arc::clone(&pipeline.metrics),
        cache: Arc::clone(&cache),
        pipeline: Arc::clone(&pipeline),
        udp: ArcSwap::from_pointee(stats.udp),
        tcp: ArcSwap::from_pointee(stats.tcp),
        doh: ArcSwap::from_pointee(stats.doh),
        doq: ArcSwap::from_pointee(stats.doq),
        readiness: Arc::clone(&readiness),
        maintenance,
        drills: Arc::default(),
        identify: Arc::new(crate::identify::Identifier::open(std::path::Path::new(
            cfg.node.data_dir.as_str(),
        ))),
        rollout: Arc::default(),
        started: std::time::Instant::now(),
        allowed: cfg.access.allowed_networks.clone(),
        lists: ArcSwapOption::empty(),
        qlog: qlog_stats,
        config: ArcSwap::from_pointee(cfg.clone()),
        file_config: ArcSwap::from_pointee(own_files),
        managed_base: ArcSwapOption::new(managed_base),
        files_unread: std::sync::atomic::AtomicBool::new(files_unread),
        config_files: files.clone(),
        update: Arc::new(std::sync::Mutex::new(crate::updates::initial(
            cfg.updates.check,
        ))),
        rollups: rollups.clone(),
        tail,
        anomalies: anomalies.clone(),
        cache_history: {
            // REQ: OBS-003 (T6.15) — the cache's last hour, off the DNS path.
            let h = Arc::new(crate::cache_history::CacheHistory::new(warm));
            h.spawn(Arc::clone(&cache), http_stopped.clone());
            h
        },
        host: {
            // REQ: CLU-008 (T6.11) — host resources, off the DNS path.
            let h = Arc::new(crate::host::HostMonitor::default());
            h.spawn(std::path::PathBuf::from(cfg.node.data_dir.as_str()));
            h
        },
        auth: std::sync::OnceLock::new(),
        identities_applied: std::sync::Mutex::default(),
        alerts: std::sync::Mutex::default(),
        masking: crate::masking::Detector::default(),
        cluster,
        ship: Arc::default(),
        git_poke: Arc::default(),
        reload: reload_tx,
        config_writes: tokio::sync::Mutex::new(()),
        probes: Arc::default(),
        shadow,
        traces,
    });
    http::serve_peers(&sources);
    // REQ: OBS-025 — device identification, on a thread of its own.
    sources.identify.spawn(Arc::clone(&sources));
    // REQ: OPS-010 — the maintenance window ends by itself.
    crate::maintenance::spawn_expiry(Arc::clone(&sources), http_stopped.clone());
    // REQ: OBS-020 (T11.3) — synthetic probes of every listener, off the DNS path.
    crate::probes::spawn(Arc::clone(&sources), http_stopped.clone());
    // REQ: OPS-012 (ADR-163) — the watchdog: a thread outside the runtime that restarts a node
    // that stops answering, after a dump of why.
    crate::watchdog::spawn(
        &cfg,
        tokio::runtime::Handle::current(),
        http_stopped.clone(),
    );
    #[cfg(feature = "wedge-test")]
    crate::watchdog::wedge_for_test(&tokio::runtime::Handle::current());
    // REQ: OBS-033 — breaker markers and the daily compaction, off the DNS path.
    crate::annotations::spawn(Arc::clone(&sources), annotations, http_stopped.clone());
    // REQ: CLU-003 — the Git config source polls on the primary (ADR-049).
    if let Some(c) = &sources.cluster
        && cfg.cluster.git.is_some()
    {
        tokio::spawn(crate::gitsource::run(
            Arc::clone(c),
            Arc::clone(&sources),
            Arc::clone(&sources.git_poke),
            http_stopped.clone(),
        ));
    }
    // REQ: CLU-007 — ship mode delivers the query log to another node (ADR-055).
    if let Some(c) = &sources.cluster
        && cfg.telemetry.mode == telltale_config::TelemetryMode::Ship
        && cfg.telemetry.qlog.enabled
    {
        tokio::spawn(crate::ship::run(
            Arc::clone(c),
            std::path::Path::new(cfg.node.data_dir.as_str()).join("qlog"),
            cfg.telemetry.ship.to.as_ref().map(ToString::to_string),
            Arc::clone(&sources.ship),
            http_stopped.clone(),
        ));
    }
    // REQ: CLU-007 (T9.3) — ship mode also sends per-minute counts (dashboard history).
    if let (Some(c), Some(db)) = (&sources.cluster, &sources.rollups)
        && cfg.telemetry.mode == telltale_config::TelemetryMode::Ship
    {
        tokio::spawn(crate::ship::run_rollups(
            Arc::clone(c),
            Arc::clone(db),
            cfg.telemetry.ship.to.as_ref().map(ToString::to_string),
            // As often as query-log parts, at most once a minute (minutes complete then).
            std::time::Duration::from_secs(
                u64::from(cfg.telemetry.ship.interval_secs).clamp(5, 60),
            ),
            http_stopped.clone(),
        ));
    }
    // REQ: FLT-010 (T7.10) — schedules: which are on, every 15 s.
    tokio::spawn(schedule_ticker(Arc::clone(&sources), http_stopped.clone()));
    // REQ: OBS-010 (T7.12)
    tokio::spawn(crate::alerts::run(
        Arc::clone(&sources),
        http_stopped.clone(),
    ));
    // REQ: OBS-006 (T7.17)
    tokio::spawn(crate::otlp::run(Arc::clone(&sources), http_stopped.clone()));
    // REQ: OBS-017 (T11.6) — sampled and slow queries as OTLP traces.
    tokio::spawn(crate::traces::run(
        Arc::clone(&sources),
        http_stopped.clone(),
    ));
    // REQ: T8.2 — device names from the routers' DHCP (ADR-181: the routers in effect, so
    // ones added or changed in the UI are read without a restart).
    tokio::spawn(crate::routers::run(
        Arc::clone(&sources),
        Arc::clone(&pipeline.router_leases),
        http_stopped.clone(),
        cfg.cluster.ephemeral,
    ));
    // REQ: T8.3 — device names from mDNS announcements (read at startup).
    if cfg.clients.mdns {
        tokio::spawn(crate::mdns::run(
            cfg.clients.mdns_port,
            Arc::clone(&pipeline.mdns_names),
            http_stopped.clone(),
        ));
    }
    // REQ: CLU-002 (ADR-125) — the device names the other nodes know, so every node names a
    // client the same way.
    tokio::spawn(crate::devices::run(
        Arc::clone(&sources),
        http_stopped.clone(),
    ));
    // REQ: FLT-017 — Kubernetes workloads: the watcher (on its own thread) or the table from
    // the cluster; never on the DNS path.
    tokio::spawn(crate::kubernetes::run(
        Arc::clone(&sources),
        http_stopped.clone(),
    ));
    // REQ: CLU-014 — failover drills: expiry, windows, reports, the seen table's file.
    crate::drill::spawn(Arc::clone(&sources), http_stopped.clone());
    // REQ: CLU-011 (T8.1) — warm the cache from the cluster's hot names.
    tokio::spawn(crate::warm::run(Arc::clone(&sources), http_stopped.clone()));
    // REQ: OPS-004 (ADR-046) — a daily check of the signed release index (off: nothing leaves).
    tokio::spawn(crate::updates::run(
        Arc::clone(&sources.update),
        cfg.updates.check,
        cfg.updates.index_url.as_ref().map(ToString::to_string),
        http_stopped.clone(),
    ));
    start_http(&cfg, &sources, &http_stopped).await?;
    // REQ: FLT-006 (ADR-183) — the MAC table's task runs on every node: the kernel's neighbor table
    // while `neighbor_table` is on, and the routers' and members' bindings while a device is named
    // by its MAC.
    let mac_table = spawn_mac_table(
        Arc::clone(&pipeline),
        neighbor_refresh,
        sources.cluster.clone(),
        {
            let sources = Arc::clone(&sources);
            move || !sources.config.load().router.is_empty()
        },
    );
    // Every listener is bound: ready for traffic (OPS-006), unless in maintenance (OPS-010).
    // An ephemeral resolver pod waits for the cluster's configuration too, so it never serves
    // unfiltered (CLU-009).
    readiness.set_bound();
    // REQ: NFR-001 (T10.2) — once start-up has settled, the code that ran only for it (config
    // loading, the API router and OpenAPI document) stops counting as resident.
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(15)).await;
        trim_code_pages("start-up");
    });
    if let Some(c) = &sources.cluster
        && cfg.cluster.ephemeral
    {
        let (c, readiness) = (Arc::clone(c), Arc::clone(&readiness));
        tokio::spawn(async move {
            while c.sync_status().applied_ms == 0 {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            info!("cluster configuration applied: ready");
            readiness.set_synced();
        });
    }

    // REQ: FLT-004 — lists download in the background once DNS is up (rule 5: DNS never
    // waits for, or depends on, a list).
    // A synced replica gets them compiled from the primary instead (CLU-003).
    let mut lists = if crate::replication::follows_primary(&cfg) {
        None
    } else {
        Lists::start(&cfg, &pipeline)
    };
    sources
        .lists
        .store(lists.as_ref().map(|l| Arc::clone(&l.shared)));
    if let Some(c) = &sources.cluster {
        crate::replication::start(
            c,
            files.clone(),
            &sources,
            sources.reload.clone(),
            &http_stopped,
        );
    }

    let mut current = cfg;
    loop {
        tokio::select! {
            _ = term.recv() => { info!(signal = "SIGTERM", "shutting down"); break; }
            _ = int.recv() => { info!(signal = "SIGINT", "shutting down"); break; }
            _ = hup.recv() => { reload(&files, &mut current, &mut listeners, &mut health, &pipeline, &sources, &mut lists, false).await; }
            // ADR-040 — a change made through the API: re-read files + state.db and apply.
            Some(done) = reload_rx.recv() => {
                let ok = reload(&files, &mut current, &mut listeners, &mut health, &pipeline, &sources, &mut lists, true).await;
                let _ = done.send(ok);
            }
            _ = usr1.recv() => {
                // REQ: FLT-004 — refresh every list now (like `pihole -g`); the compiler
                // runs if anything changed.
                if let Some(l) = &lists {
                    info!(signal = "SIGUSR1", "refreshing lists");
                    l.shared.fetcher.request_refresh();
                }
            }
        }
    }

    // REQ: OPS-007 — not ready first (load balancers stop sending), stop taking new TCP
    // connections, let in-flight upstream lookups finish (bounded), then stop UDP workers.
    readiness.set_stopping();
    // REQ: OBS-025 — keep the device identities across the restart.
    sources.identify.save();
    // REQ: CLU-009 — a resolver pod leaves the cluster now rather than showing as down until
    // it expires (2 s at most; if the primary can't be reached, expiry still cleans up).
    // Before the stop signal: it closes the stream to the primary that the leave goes over.
    if let Some(c) = &sources.cluster
        && current.cluster.ephemeral
        && let Err(e) = c.leave(Duration::from_secs(2)).await
    {
        info!("cluster: leaving: {e}");
    }
    let _ = stop_http.send(true);
    // Keep answering while load balancers notice: a Kubernetes Service takes a moment to drop
    // a terminating pod, and queries sent to it meanwhile would otherwise be lost.
    let delay = current.node.drain_delay_secs.min(60);
    if delay > 0 {
        info!(
            seconds = delay,
            "shutdown: still answering while load balancers move away"
        );
        tokio::time::sleep(Duration::from_secs(u64::from(delay))).await;
    }
    for (_, s) in listeners.streams.drain(..) {
        s.shutdown().await;
    }
    if !pipeline.drain(Duration::from_secs(3)).await {
        warn!("shutdown: some upstream lookups were still in flight after 3 s");
    }
    for (_, l) in listeners.udp.drain(..) {
        l.shutdown();
    }
    health.abort();
    mac_table.abort();
    if let Some(l) = lists {
        l.stop();
    }
    if current.cache.persist {
        save_cache(&current, &cache);
    }
    Ok(())
}

/// Where the cache is dumped (DNS-009).
fn cache_dump_path(cfg: &Config) -> PathBuf {
    Path::new(cfg.node.data_dir.as_str()).join("cache.bin")
}

/// What the cached answers depend on besides the question: upstreams and routes (a "view"
/// is a position in them). A dump taken under other routing isn't loaded.
fn cache_fingerprint(cfg: &Config) -> u64 {
    let b =
        serde_json::to_vec(&(&cfg.upstream, &cfg.upstream_group, &cfg.route)).unwrap_or_default();
    let h = blake3::hash(&b);
    u64::from_le_bytes(h.as_bytes()[..8].try_into().unwrap_or([0; 8]))
}

/// REQ: DNS-009 — loads the dump, then removes it (a crash later shouldn't reload old data).
/// Returns what happened, for the Cache page (T6.15).
fn load_cache(
    cfg: &Config,
    cache: &Cache,
    pipeline: &Pipeline,
) -> telltale_api::model::CacheWarmStart {
    let at = telltale_api::time::format_us(crate::cache_history::now_ms().saturating_mul(1000));
    let path = cache_dump_path(cfg);
    let Ok(data) = std::fs::read(&path) else {
        return telltale_api::model::CacheWarmStart {
            at,
            loaded: None,
            note: Some(
                "no dump from the last shutdown (first start, or it didn't stop cleanly)".into(),
            ),
        };
    };
    let _ = std::fs::remove_file(&path);
    match cache.load(
        &data,
        std::time::Instant::now(),
        cache_fingerprint(cfg),
        |n| pipeline.name_hash(n),
    ) {
        Ok(n) => {
            info!(
                entries = n,
                "cache: reloaded the dump from the last shutdown"
            );
            telltale_api::model::CacheWarmStart {
                at,
                loaded: Some(n as u64),
                note: None,
            }
        }
        Err(e) => {
            warn!("cache: not reloading the dump: {e}");
            telltale_api::model::CacheWarmStart {
                at,
                loaded: None,
                note: Some(e.clone()),
            }
        }
    }
}

/// REQ: DNS-009 — dumps the cache on shutdown (owner-only: it reveals what was looked up).
fn save_cache(cfg: &Config, cache: &Cache) {
    let path = cache_dump_path(cfg);
    let tmp = path.with_extension("tmp");
    let mut buf = Vec::new();
    let result = cache
        .dump(std::time::Instant::now(), cache_fingerprint(cfg), &mut buf)
        .and_then(|n| {
            std::fs::write(&tmp, &buf)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
            }
            std::fs::rename(&tmp, &path)?;
            Ok(n)
        });
    match result {
        Ok(n) => info!(
            entries = n,
            bytes = buf.len(),
            "cache: dumped for the next start"
        ),
        Err(e) => warn!("cache: couldn't dump: {e}"),
    }
}

/// REQ: OPS-009 — validate the whole new config, then swap; on any error keep serving the
/// running configuration.
// Everything a reload swaps; grouping it would only rename the parameters.
#[allow(clippy::too_many_arguments)]
async fn reload(
    files: &[PathBuf],
    current: &mut Config,
    listeners: &mut Listeners,
    health: &mut JoinHandle<()>,
    pipeline: &Arc<Pipeline>,
    sources: &http::Sources,
    lists: &mut Option<Lists>,
    from_api: bool,
) -> bool {
    if from_api {
        info!("applying a configuration change made through the API");
    } else {
        info!(signal = "SIGHUP", "reloading configuration");
    }
    // An API or replicated change leaves the files as they were: their warnings (a replica's
    // file has no upstreams, by design) were logged at start-up or on the last SIGHUP.
    let loaded = if from_api {
        load_files_quiet(files)
    } else {
        load_files(files)
    };
    let Some(file) = loaded else {
        error!("reload failed: configuration invalid; still serving the previous configuration");
        return false;
    };
    let new = crate::replication::effective(&file);
    // Unchanged upstream config keeps the running router: its health state, pooled
    // connections, and bootstrap cache survive the reload (T2.7).
    let same_upstreams = current.upstream == new.upstream
        && current.upstream_group == new.upstream_group
        && current.route == new.route
        && current.listen == new.listen;
    let reuse = same_upstreams.then(|| Arc::clone(&pipeline.current().router));
    let (router, policy) = match build_dynamic(&new, reuse) {
        Ok(v) => v,
        Err(errs) => {
            for e in &errs {
                error!("{e}");
            }
            error!("reload failed; still serving the previous configuration");
            return false;
        }
    };
    set_client_metrics(&new, pipeline);
    if let Err(e) = listeners.apply(&new.listen).await {
        error!("reload: {e}; listeners unchanged where binding failed");
    }
    if !same_upstreams {
        health.abort();
        *health = spawn_health_checks(&router);
    }
    pipeline.reload(router, policy);
    pipeline.set_dnssec(&new);
    pipeline.set_upstream_check(&new);
    let stats = listeners.stats();
    sources.udp.store(Arc::new(stats.udp));
    sources.tcp.store(Arc::new(stats.tcp));
    sources.doh.store(Arc::new(stats.doh));
    sources.doq.store(Arc::new(stats.doq));
    if crate::replication::follows_primary(&new) {
        // REQ: CLU-003 — a synced replica serves the primary's compiled lists.
        if let Some(l) = lists.take() {
            info!("following the cluster primary: this node no longer downloads lists");
            l.stop();
            sources.lists.store(None);
        }
    } else if let Some(l) = lists {
        l.reload(&new);
    } else {
        *lists = Lists::start(&new, pipeline);
        sources
            .lists
            .store(lists.as_ref().map(|l| Arc::clone(&l.shared)));
    }
    let restart = restart_only_changes(current, &new);
    if !restart.is_empty() {
        warn!(sections = ?restart, "these changes take effect after a restart");
    }
    // API changes are audited by the API with their author.
    if !from_api {
        audit_reload(sources, files, current, &new);
    }
    if let Some(a) = &sources.anomalies {
        a.reconfigure(&new);
    }
    // REQ: AGT-009 — the agent kill switch follows the (cluster-shared) configuration.
    if let Some(a) = sources.auth.get() {
        a.agents()
            .set(new.agents.enabled, new.agents.rate_per_minute);
        a.agents().set_require_approval(new.agents.require_approval);
    }
    sources
        .pipeline
        .telemetry
        .set_privacy(new.telemetry.qlog.privacy_level);
    config_marker(sources, current, &new);
    // REQ: OBS-010 (ADR-179) — the files before the configuration made from them, so whoever
    // reads the new configuration also reads its files (the alert check compares the two); and
    // (REQ: API-002, CLU-003) what the API's entries were merged onto, for the write checks.
    sources.store_files(file);
    sources
        .files_unread
        .store(false, std::sync::atomic::Ordering::Release);
    sources.config.store(Arc::new(new.clone()));
    *current = new;
    // REQ: FLT-017 — a `[[kubernetes.map]]` rule or a group change reaches the workload table
    // before the next query, not on the watcher's next tick.
    sources.pipeline.kube.reconfigured.notify_one();
    info!("configuration reloaded");
    true
}

/// REQ: OBS-033 — the `config.applied` marker for a reload that changed the configuration (a
/// cluster's primary writes it when it publishes the version).
fn config_marker(sources: &http::Sources, old: &Config, new: &Config) {
    let Some(ann) = crate::annotations::get() else {
        return;
    };
    let sections = crate::annotations::changed_sections(old, new);
    let primary = !crate::replication::follows_primary(new)
        && sources.cluster.as_ref().is_some_and(|c| c.is_primary());
    let seq = || match &sources.cluster {
        Some(c) => Some(c.local_state().applied_seq).filter(|s| *s > 0),
        None => sources
            .auth
            .get()
            .and_then(|a| a.state().config_version().ok()),
    };
    ann.reloaded(sections, primary, seq, crate::annotations::now_ms());
}

/// REQ: API-006 — a reload that changed anything is audited with the changed settings'
/// paths (never their values: configs can hold secrets).
fn audit_reload(sources: &http::Sources, files: &[PathBuf], old: &Config, new: &Config) {
    let Some(auth) = sources.auth.get() else {
        return;
    };
    let (Ok(a), Ok(b)) = (serde_json::to_value(old), serde_json::to_value(new)) else {
        return;
    };
    let mut changed = Vec::new();
    changed_paths(&a, &b, String::new(), &mut changed);
    if changed.is_empty() {
        return;
    }
    let files: Vec<String> = files.iter().map(|f| f.display().to_string()).collect();
    let more = changed.len().saturating_sub(100);
    changed.truncate(100);
    let auth = Arc::clone(auth);
    let target = files.join(", ");
    let detail = serde_json::json!({ "changed": changed, "more": more, "files": files });
    tokio::task::spawn_blocking(move || {
        auth.record(
            &telltale_api::auth::Actor::system("reload"),
            "config.reload",
            &target,
            &detail,
        );
    });
}

/// Dotted paths whose values differ (arrays compare as a whole).
pub(crate) fn changed_paths(
    old: &serde_json::Value,
    new: &serde_json::Value,
    at: String,
    out: &mut Vec<String>,
) {
    use serde_json::Value::Object;
    match (old, new) {
        (Object(before), Object(after)) => {
            let mut keys: Vec<&String> = before.keys().chain(after.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let path = if at.is_empty() {
                    key.clone()
                } else {
                    format!("{at}.{key}")
                };
                match (before.get(key), after.get(key)) {
                    (Some(was), Some(now)) => changed_paths(was, now, path, out),
                    _ => out.push(path),
                }
            }
        }
        _ if old != new => out.push(if at.is_empty() { "(root)".into() } else { at }),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use telltale_net::{QueryHandler, RequestMeta, Response, Transport};
    use telltale_proto::{EdnsOut, NameBuf, build_query, records, rtype};

    use super::*;
    use crate::pipeline::{Handler, Policy};

    // REQ: OBS-037 — `cluster.local` is internal only with Kubernetes on; `[telemetry]
    // internal_names` adds suffixes; private reverse lookups always are; validation refuses a
    // name that isn't one.
    #[test]
    fn obs_037_internal_names_from_config() {
        let wire = |s: &str| NameBuf::from_presentation(s).unwrap().as_wire().to_vec();
        let parse = |t: &str| toml::from_str::<Config>(t).unwrap();
        let off = internal_names(&Config::default());
        assert!(!off.is_internal(&wire("kubernetes.default.svc.cluster.local")));
        assert!(off.is_internal(&wire("20.1.168.192.in-addr.arpa")));
        let on = internal_names(&parse(
            "[kubernetes]\nenabled = true\n[telemetry]\ninternal_names = [\"*.LAN\", \"home.arpa\"]\n",
        ));
        for name in [
            "kubernetes.default.svc.cluster.local",
            "nas.lan",
            "printer.home.arpa",
        ] {
            assert!(on.is_internal(&wire(name)), "{name}");
        }
        assert!(!on.is_internal(&wire("example.com")));
        let bad = parse("[telemetry]\ninternal_names = [\"not a name\"]\n");
        let errs = telltale_config::validate_config(&bad).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("telemetry.internal_names[0]")),
            "{errs:?}"
        );
    }

    /// The OPT record's UDP payload size in the answer to a `localhost A` query that carries EDNS.
    fn advertised(cfg: &Config) -> u16 {
        let p = build_pipeline(
            cfg,
            Arc::new(Cache::new(telltale_cache::CachePolicy::default())),
            Arc::new(Router::default()),
            Policy::open(),
        );
        let name = NameBuf::from_presentation("localhost").unwrap();
        let mut q = [0u8; 512];
        let len = build_query(
            &mut q,
            7,
            &name,
            rtype::A,
            1,
            true,
            Some(EdnsOut::new(4096)),
        )
        .unwrap();
        let meta = RequestMeta {
            peer: "127.0.0.1:1000".parse().unwrap(),
            local: None,
            transport: Transport::Udp,
            client_id: None,
        };
        let mut out = [0u8; 4096];
        let Response::Ready(n) = Handler(p).handle(&q[..len], &meta, &mut out) else {
            panic!("localhost is answered at once");
        };
        records(&out[..n])
            .unwrap()
            .map(Result::unwrap)
            .find(telltale_proto::Record::is_opt)
            .expect("an OPT record")
            .rclass
    }

    /// REQ: DNS-005 (review 01-12) — `[dns] edns_payload` is the size advertised in answers
    /// (default 1232), and it is bounded to what the UDP workers can send.
    #[test]
    fn dns_005_advertised_payload_size_is_configurable() {
        assert_eq!(advertised(&Config::default()), 1232);
        let mut cfg = Config::default();
        cfg.dns.edns_payload = 2048;
        assert_eq!(advertised(&cfg), 2048);
        for bad in [511, 4097] {
            let errs = telltale_config::Loader::new()
                .toml_str("t.toml", format!("[dns]\nedns_payload = {bad}\n"))
                .env(Vec::<(String, String)>::new())
                .load()
                .unwrap_err();
            assert!(
                errs.iter().any(|e| e.path == "dns.edns_payload"),
                "{bad}: {errs:?}"
            );
        }
    }

    const TABLET: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
    const STRANGER: [u8; 6] = [0x02, 0, 0, 0, 0, 0x99];
    /// A device named by its MAC.
    const BY_MAC: &str = "[[client]]\nname = \"tablet\"\nmatch = [\"aa:bb:cc:dd:ee:01\"]\n";

    fn config_of(toml: &str) -> Config {
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config
    }

    /// A pipeline made as `explain::run_cli` makes one: `build_dynamic`, then `Pipeline::new`.
    fn pipeline_of(toml: &str) -> Arc<Pipeline> {
        let (router, policy) = build_dynamic(&config_of(toml), None).unwrap();
        Pipeline::new(
            Settings::default(),
            Arc::new(Cache::new(telltale_cache::CachePolicy::default())),
            router,
            policy,
        )
    }

    fn lease_at(last: u8, mac: &str) -> crate::devices::Lease {
        crate::devices::Lease {
            mac: mac.into(),
            ip: std::net::Ipv4Addr::new(10, 0, 0, last),
            hostname: Some("x".into()),
            expires: 0,
            offline: false,
            unsure: false,
            stale: false,
        }
    }

    fn ip(last: u8) -> std::net::IpAddr {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, last))
    }

    /// Gives the pipeline this node's router view (`own`) and the members' bindings.
    fn give(p: &Pipeline, own: &[crate::devices::Lease], peers: &[(u8, [u8; 6])]) {
        p.router_leases
            .store(Arc::new(own.iter().map(|l| (l.ip, l.clone())).collect()));
        p.peer_router_macs.store(Arc::new(crate::devices::PeerMacs {
            macs: peers
                .iter()
                .map(|(last, mac)| (std::net::Ipv4Addr::new(10, 0, 0, *last), *mac))
                .collect(),
            ..Default::default()
        }));
    }

    // REQ: FLT-006 (ADR-183) — without a device named by its MAC, the table holds the kernel's
    // entries (they are read whenever `neighbor_table` is on, so a name can be offered for an
    // address before anyone names a device by its MAC) and nothing the routers or members say; the
    // moment one device is named by its MAC, their entries come in.
    #[test]
    fn flt_006_without_mac_clients_the_table_holds_kernel_entries_only() {
        let kernel = [(ip(50), TABLET), (ip(51), STRANGER)];
        let routers = [lease_at(5, "aa:bb:cc:dd:ee:01")];
        let peers = [(6, STRANGER)];

        let p = pipeline_of("[[client]]\nname = \"tv\"\nmatch = [\"192.168.1.30\"]\n");
        give(&p, &routers, &peers);
        let inputs = MacInputs::load(&p);
        assert!(!inputs.uses_macs);
        drop(rebuild_now(&p, &kernel, &inputs));
        let n = &p.neighbors;
        assert_eq!((n.kernel_len(), n.router_len(), n.peer_len()), (2, 0, 0));

        let p = pipeline_of(BY_MAC);
        give(&p, &routers, &peers);
        let inputs = MacInputs::load(&p);
        assert!(inputs.uses_macs && inputs.router_macs);
        drop(rebuild_now(&p, &kernel, &inputs));
        let n = &p.neighbors;
        assert_eq!((n.kernel_len(), n.router_len(), n.peer_len()), (2, 1, 1));
    }

    // REQ: FLT-006 (ADR-183, ADR-023) — the table a rebuild replaces is handed back for `retire` to
    // free off the query path: nothing but the caller holds it any more (the pipeline has swapped it
    // out, no reader has it), so dropping what `rebuild_now` returns frees it. No timers.
    #[test]
    fn flt_006_the_old_table_is_retired() {
        let p = pipeline_of(BY_MAC);
        drop(rebuild_now(&p, &[(ip(50), TABLET)], &MacInputs::load(&p)));
        let old = rebuild_now(&p, &[], &MacInputs::load(&p));
        assert_eq!(old.kernel(), 1, "the table that was in use");
        assert_eq!(p.neighbors.kernel_len(), 0, "and the new one is in");
        let weak = Arc::downgrade(&old);
        drop(old);
        assert!(
            weak.upgrade().is_none(),
            "something else still holds the replaced table"
        );
    }

    // REQ: FLT-006, CLU-010 (ADR-183) — `[clients] router_macs` is applied at reload: the table is
    // built again, and without the setting it holds no router entry; nothing is rebuilt while
    // nothing changed.
    #[test]
    fn flt_006_the_table_follows_the_setting() {
        let p = pipeline_of(BY_MAC);
        give(&p, &[lease_at(5, "aa:bb:cc:dd:ee:01")], &[(6, STRANGER)]);
        let on = MacInputs::load(&p);
        assert!(on.uses_routers());
        drop(rebuild_now(&p, &[], &on));
        assert_eq!((p.neighbors.router_len(), p.neighbors.peer_len()), (1, 1));
        assert!(!should_rebuild(false, Some(&on), &MacInputs::load(&p)));

        let (router, policy) = build_dynamic(
            &config_of(&format!("[clients]\nrouter_macs = false\n{BY_MAC}")),
            None,
        )
        .unwrap();
        p.reload(router, policy);
        let off = MacInputs::load(&p);
        assert!(!off.router_macs && !off.uses_routers());
        assert!(
            should_rebuild(false, Some(&on), &off),
            "the setting changed"
        );
        drop(rebuild_now(&p, &[], &off));
        assert_eq!((p.neighbors.router_len(), p.neighbors.peer_len()), (0, 0));
        assert!(!should_rebuild(false, Some(&off), &MacInputs::load(&p)));
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — "no router MAC reaches this node" is said once per spell,
    // after a minute (a node that has just started hasn't read its router or asked its members yet),
    // only while router bindings are in use, and whatever the kernel's table holds: a pod's table
    // has its network's gateway, and the old message never fired there.
    #[test]
    fn flt_006_no_router_macs_are_said_once_after_a_minute() {
        let mut s = NoBindings::default();
        // (A router is configured here; no cluster.)
        assert!(!s.look(true, true, 0, 0));
        assert!(!s.look(true, true, 0, NO_BINDINGS_AFTER_S - 1));
        assert!(s.look(true, true, 0, NO_BINDINGS_AFTER_S), "after a minute");
        assert!(!s.look(true, true, 0, NO_BINDINGS_AFTER_S + 1), "once");
        assert!(!s.look(true, true, 0, 3_600));
        // Bindings come: nothing to say, and the spell is over; gone again, it is said once more
        // after a minute.
        assert!(!s.look(true, true, 2, 3_601));
        assert!(!s.look(true, true, 0, 3_700));
        assert!(!s.look(true, true, 0, 3_700 + NO_BINDINGS_AFTER_S - 1));
        assert!(s.look(true, true, 0, 3_700 + NO_BINDINGS_AFTER_S));
        // Not in use (no device named by its MAC, or `router_macs` off): nothing, and the spell
        // starts again when it is.
        assert!(!s.look(false, true, 0, 4_000));
        assert!(!s.look(true, true, 0, 4_010));
        assert!(!s.look(true, true, 0, 4_010 + NO_BINDINGS_AFTER_S - 1));
        assert!(s.look(true, true, 0, 4_010 + NO_BINDINGS_AFTER_S));
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — the notice is for a node where a router MAC could reach it:
    // one with a `[[router]]` in its configuration (its key may be missing, its router silent). A
    // node with no router (a Pi with MAC clients from an import, say) is never told: there is
    // nothing to read.
    #[test]
    fn flt_006_the_no_router_macs_notice_is_silent_where_no_router_could_exist() {
        let said = |router_here: bool| {
            let mut s = NoBindings::default();
            let first = s.look(true, router_here, 0, 0);
            let later = s.look(true, router_here, 0, NO_BINDINGS_AFTER_S);
            let much_later = s.look(true, router_here, 0, 10 * NO_BINDINGS_AFTER_S);
            assert!(!first && !much_later, "never at once, and once");
            later
        };
        assert!(!said(false), "no router");
        assert!(said(true), "a router is configured here");
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — a cluster with no `[[router]]` anywhere stays silent too: the
    // routers are shared configuration (a pod carries them without their keys), so every node of a
    // cluster that has one has `router_here` set, and a cluster that has none gives every node
    // nothing to read. Being in a cluster is not a reason to say it.
    #[test]
    fn flt_006_the_no_router_macs_notice_is_silent_in_a_cluster_without_a_router() {
        let mut s = NoBindings::default();
        // Every node of a cluster without a router, over the first hour and a day: no router in the
        // configuration, no row from a member (they have none to give).
        for t in [
            0,
            NO_BINDINGS_AFTER_S,
            10 * NO_BINDINGS_AFTER_S,
            3_600,
            86_400,
        ] {
            assert!(!s.look(true, false, 0, t), "t = {t}");
        }
        // The same cluster once a router is added to the shared configuration: said, once.
        assert!(!s.look(true, true, 0, 86_401));
        assert!(s.look(true, true, 0, 86_401 + NO_BINDINGS_AFTER_S));
        assert!(!s.look(true, true, 0, 86_401 + 2 * NO_BINDINGS_AFTER_S));
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — the notice says what to do: on a resolver pod, whose only
    // peer is the primary, that the key belongs on the primary; elsewhere, what is missing here.
    #[test]
    fn flt_006_the_no_router_macs_notice_says_what_to_do() {
        let pod = no_bindings_notice(true);
        assert!(
            pod.contains("resolver pod") && pod.contains("primary"),
            "{pod}"
        );
        assert!(pod.contains("router key"), "{pod}");
        // The same message comes when the primary runs an earlier version or its router is silent:
        // the pod's text says so, so it doesn't send anyone to look for a key that is there.
        for cause in ["earlier version", "router is silent"] {
            assert!(pod.contains(cause), "{cause}: {pod}");
        }
        let node = no_bindings_notice(false);
        assert!(!node.contains("resolver pod"), "{node}");
        assert!(
            node.contains("no router") && node.contains("full cluster member"),
            "{node}"
        );
        // And the other causes, so the text doesn't point at the key alone.
        for cause in [
            "its router is silent",
            "a member's router is silent",
            "run an earlier version",
            "member list",
            "refuses its configuration",
        ] {
            assert!(node.contains(cause), "{cause}: {node}");
        }
        for n in [pod, node] {
            assert!(n.contains("named by their MAC address"), "{n}");
        }
    }

    // REQ: FLT-006 (ADR-183) — what makes the task build the table again, and what doesn't (it
    // runs no blocking task when nothing changed): the first look, a kernel read, a device named by
    // its MAC appearing or going, the setting, and — only while router and member entries are in
    // use — a replaced router view or members' bindings.
    #[test]
    fn flt_006_the_table_is_rebuilt_only_when_an_input_changed() {
        let base = MacInputs {
            uses_macs: true,
            router_macs: true,
            own: Arc::default(),
            peers: Arc::default(),
        };
        assert!(should_rebuild(false, None, &base), "the first look");
        assert!(!should_rebuild(false, Some(&base), &base.clone()), "idle");
        assert!(
            should_rebuild(true, Some(&base), &base),
            "the kernel was read"
        );
        let own = MacInputs {
            own: Arc::default(),
            ..base.clone()
        };
        assert!(
            should_rebuild(false, Some(&base), &own),
            "this node's routers"
        );
        let peers = MacInputs {
            peers: Arc::default(),
            ..base.clone()
        };
        assert!(should_rebuild(false, Some(&base), &peers), "the members'");
        for changed in [
            MacInputs {
                uses_macs: false,
                ..base.clone()
            },
            MacInputs {
                router_macs: false,
                ..base.clone()
            },
        ] {
            assert!(should_rebuild(false, Some(&base), &changed));
            assert!(should_rebuild(false, Some(&changed), &base));
        }
        // No router entries in use: a replaced router view changes nothing.
        let off = MacInputs {
            uses_macs: false,
            ..base.clone()
        };
        let off_newer = MacInputs {
            own: Arc::default(),
            peers: Arc::default(),
            ..off.clone()
        };
        assert!(!should_rebuild(false, Some(&off), &off_newer));
        let setting_off = MacInputs {
            router_macs: false,
            ..off_newer.clone()
        };
        assert!(!should_rebuild(
            false,
            Some(&setting_off),
            &MacInputs {
                own: Arc::default(),
                ..setting_off.clone()
            }
        ));
    }

    /// The DNS listeners as `serve` makes them (one UDP worker here), on an open pipeline.
    fn ops_listeners() -> Listeners {
        let p = build_pipeline(
            &Config::default(),
            Arc::new(Cache::new(telltale_cache::CachePolicy::default())),
            Arc::new(Router::default()),
            Policy::open(),
        );
        Listeners {
            udp: Vec::new(),
            streams: Vec::new(),
            workers: 1,
            handler: Arc::new(Handler(p)),
            rt: tokio::runtime::Handle::current(),
        }
    }

    fn listener(proto: ListenProto, addr: SocketAddr) -> Listener {
        Listener {
            proto,
            addr,
            path: None,
            tls: None,
            proxy_protocol: false,
            trusted_proxies: Vec::new(),
            x_forwarded_for: false,
            max_connections: None,
            max_connections_per_address: None,
        }
    }

    /// The error `apply` (start-up and reload) gives when `l` can't bind.
    async fn bind_failure(ls: &mut Listeners, l: Listener) -> io::Error {
        match ls.apply(std::slice::from_ref(&l)).await {
            Ok(()) => panic!("{:?} {} bound", l.proto, l.addr),
            Err(e) => e,
        }
    }

    // REQ: OPS-004 — another program holds the port on one address of the machine (127.0.0.1, a
    // port the OS picks), which on Linux is enough to block the wildcard address. Binding 0.0.0.0
    // on that port through the server's own listener code fails with the old text, unchanged and
    // first (scripts and log searches match it), then on the same line a hint that names the
    // failed port, how to see who holds it, and `[[listen]]`. UDP and TCP.
    #[tokio::test]
    async fn ops_004_busy_port_error_says_what_to_do() {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cases = [
            (
                ListenProto::Udp,
                udp.local_addr().unwrap().port(),
                "sudo ss -lunp",
            ),
            (
                ListenProto::Tcp,
                tcp.local_addr().unwrap().port(),
                "sudo ss -ltnp",
            ),
        ];
        for (proto, port, ss) in cases {
            let wild = SocketAddr::from(([0, 0, 0, 0], port));
            // The OS's own words for it, from a plain socket on the same address: the old text.
            let os = if proto == ListenProto::Udp {
                std::net::UdpSocket::bind(wild).map(drop)
            } else {
                std::net::TcpListener::bind(wild).map(drop)
            }
            .unwrap_err();
            assert_eq!(os.kind(), io::ErrorKind::AddrInUse, "{proto:?}: {os}");
            let mut ls = ops_listeners();
            let e = bind_failure(&mut ls, listener(proto, wild)).await;
            assert_eq!(
                e.kind(),
                io::ErrorKind::AddrInUse,
                "{proto:?}: the kind is kept"
            );
            let msg = e.to_string();
            let old = format!("{proto:?} {wild}: {os}");
            assert!(
                msg.starts_with(&format!("{old}; ")),
                "{proto:?}: the old text first, unchanged, then the hint: {msg}"
            );
            for want in [
                format!("already uses port {port}"),
                format!("{ss} 'sport = :{port}'"),
                "[[listen]]".to_owned(),
                "this machine's own address".to_owned(),
                "(`docs/running.md`, Port 53 already in use)".to_owned(),
            ] {
                assert!(msg.contains(&want), "{proto:?}: no `{want}` in: {msg}");
            }
            assert!(!msg.contains('\n'), "{proto:?}: one line: {msg}");
            assert!(ls.udp.is_empty() && ls.streams.is_empty());
        }
    }

    // REQ: OPS-004 — a reload binds new listeners before it closes old ones, so moving a TCP
    // listener from the wildcard address to one address on the same port finds the port held by
    // this server's own listener. A hint there would blame another program and suggest the very
    // change that failed: the message stays the old text, and the old listener keeps serving.
    #[tokio::test]
    async fn ops_004_busy_port_held_by_this_server_has_no_hint() {
        let mut ls = ops_listeners();
        ls.apply(&[listener(ListenProto::Tcp, "0.0.0.0:0".parse().unwrap())])
            .await
            .unwrap();
        let port = match &ls.streams[..] {
            [(_, Stream::Tcp(s, _))] => s.local_addr().port(),
            _ => panic!("one TCP listener"),
        };
        let one = SocketAddr::from(([127, 0, 0, 1], port));
        let os = std::net::TcpListener::bind(one).unwrap_err();
        assert_eq!(os.kind(), io::ErrorKind::AddrInUse, "{os}");
        let e = bind_failure(&mut ls, listener(ListenProto::Tcp, one)).await;
        assert_eq!(e.kind(), io::ErrorKind::AddrInUse);
        assert_eq!(e.to_string(), format!("Tcp {one}: {os}"));
        assert_eq!(ls.streams.len(), 1, "the wildcard listener still serves");
        for (_, s) in ls.streams.drain(..) {
            s.shutdown().await;
        }
    }

    // REQ: OPS-004 — with `[[listen]]` on two addresses, this server holding the port on the
    // first says nothing about the second: another program that holds the second still gets
    // the hint. Every address in 127.0.0.0/8 is local on Linux, so 127.0.0.2 always exists.
    #[tokio::test]
    async fn ops_004_busy_port_on_another_address_still_hints() {
        let udp = std::net::UdpSocket::bind("127.0.0.2:0").unwrap();
        let tcp = std::net::TcpListener::bind("127.0.0.2:0").unwrap();
        let cases = [
            (ListenProto::Udp, udp.local_addr().unwrap().port()),
            (ListenProto::Tcp, tcp.local_addr().unwrap().port()),
        ];
        for (proto, port) in cases {
            let mine = SocketAddr::from(([127, 0, 0, 1], port));
            let theirs = SocketAddr::from(([127, 0, 0, 2], port));
            let os = if proto == ListenProto::Udp {
                std::net::UdpSocket::bind(theirs).map(drop)
            } else {
                std::net::TcpListener::bind(theirs).map(drop)
            }
            .unwrap_err();
            let mut ls = ops_listeners();
            let e = ls
                .apply(&[listener(proto, mine), listener(proto, theirs)])
                .await
                .unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::AddrInUse, "{proto:?}: {e}");
            let msg = e.to_string();
            assert!(
                msg.starts_with(&format!("{proto:?} {theirs}: {os}; ")),
                "{proto:?}: the old text, then the hint: {msg}"
            );
            assert!(
                msg.contains(&format!("already uses port {port} on this address")),
                "{proto:?}: {msg}"
            );
            assert_eq!(
                ls.udp.len() + ls.streams.len(),
                1,
                "{proto:?}: the first address is bound"
            );
            for (_, u) in ls.udp.drain(..) {
                u.shutdown();
            }
            for (_, s) in ls.streams.drain(..) {
                s.shutdown().await;
            }
        }
    }

    // REQ: OPS-004 — any other failure keeps exactly the old text: a link-local IPv6 address
    // without an interface (the OS refuses it on any machine), and a DoT listener whose
    // certificate files don't exist (on port 853, below 1024, but nothing was bound).
    #[tokio::test]
    async fn ops_004_other_bind_errors_have_no_hint() {
        let mut ls = ops_listeners();
        let link_local: SocketAddr = "[fe80::1]:0".parse().unwrap();
        let os = std::net::UdpSocket::bind(link_local).unwrap_err();
        let e = bind_failure(&mut ls, listener(ListenProto::Udp, link_local)).await;
        assert_ne!(e.kind(), io::ErrorKind::AddrInUse, "{e}");
        assert_eq!(e.kind(), os.kind(), "{e}");
        assert_eq!(e.to_string(), format!("Udp {link_local}: {os}"));

        let mut dot = listener(ListenProto::Dot, "127.0.0.1:853".parse().unwrap());
        dot.tls = Some(telltale_config::TlsFiles {
            cert: "ops_004_no_such_dir/cert.pem".into(),
            key: "ops_004_no_such_dir/key.pem".into(),
        });
        let msg = bind_failure(&mut ls, dot).await.to_string();
        assert!(msg.starts_with("Dot 127.0.0.1:853: "), "{msg}");
        for hint in [
            "already uses port",
            "ss -l",
            "[[listen]]",
            "CAP_NET_BIND_SERVICE",
            "docs/running.md",
        ] {
            assert!(!msg.contains(hint), "`{hint}` in: {msg}");
        }
        assert!(ls.udp.is_empty() && ls.streams.is_empty());
    }

    // REQ: OPS-004 — each hint only where it is exact. A port below 1024 refused to plain UDP or
    // TCP: the capability or the sysctl, with the port; not above 1023, and not for a TLS
    // listener (its certificate files can be what was refused). A busy port: the `ss` line for
    // the listener's transport and port; `[[listen]]` advice only for a wildcard address; none
    // when this server holds the port itself. A real refusal can't be made deterministically (as
    // root, or with the sysctl lowered, every port binds), so this calls what `apply` calls.
    #[test]
    fn ops_004_bind_hints_only_where_exact() {
        let msg = |proto, addr: &str, kind: io::ErrorKind, own| {
            let l = listener(proto, addr.parse().unwrap());
            bind_error(&l, &io::Error::from(kind), own).to_string()
        };
        let denied = io::ErrorKind::PermissionDenied;
        let busy = io::ErrorKind::AddrInUse;
        for (proto, addr) in [
            (ListenProto::Udp, "0.0.0.0:53"),
            (ListenProto::Tcp, "[::]:53"),
        ] {
            let m = msg(proto, addr, denied, false);
            let old = format!("{proto:?} {addr}: {}", io::Error::from(denied));
            assert!(m.starts_with(&format!("{old}; ")), "{m}");
            for want in [
                "CAP_NET_BIND_SERVICE",
                "net.ipv4.ip_unprivileged_port_start at 53 or lower",
            ] {
                assert!(m.contains(want), "no `{want}` in: {m}");
            }
        }
        for (proto, addr, kind) in [
            (ListenProto::Udp, "0.0.0.0:5353", denied),
            (ListenProto::Dot, "0.0.0.0:853", denied),
            (ListenProto::Doh, "[::]:443", denied),
            (
                ListenProto::Udp,
                "192.0.2.1:53",
                io::ErrorKind::AddrNotAvailable,
            ),
            (ListenProto::Tcp, "0.0.0.0:53", io::ErrorKind::Other),
        ] {
            let want = format!("{proto:?} {addr}: {}", io::Error::from(kind));
            assert_eq!(msg(proto, addr, kind, false), want);
        }
        let m = msg(ListenProto::Udp, "192.168.1.5:53", busy, false);
        assert!(m.contains("sudo ss -lunp 'sport = :53'"), "{m}");
        assert!(!m.contains("[[listen]]"), "already one address: {m}");
        let m = msg(ListenProto::Doq, "[::]:853", busy, false);
        for want in ["sudo ss -lunp 'sport = :853'", "for [::]", "[[listen]]"] {
            assert!(m.contains(want), "no `{want}` in: {m}");
        }
        let m = msg(ListenProto::Dot, "0.0.0.0:853", busy, false);
        assert!(m.contains("sudo ss -ltnp 'sport = :853'"), "{m}");
        let m = msg(ListenProto::Tcp, "127.0.0.1:53", busy, true);
        assert_eq!(m, format!("Tcp 127.0.0.1:53: {}", io::Error::from(busy)));
        let m = msg(ListenProto::Udp, "0.0.0.0:53", denied, false);
        assert!(m.ends_with("(`docs/running.md`, Container image)"), "{m}");
    }

    /// Whether this server's `held` listener on `at` takes the port `want` asks for.
    fn takes(held: ListenProto, at: &str, want: ListenProto, addr: &str) -> bool {
        takes_port(
            held,
            at.parse().unwrap(),
            &listener(want, addr.parse().unwrap()),
        )
    }

    // REQ: OPS-004 — this server's own listener takes a port only where the addresses overlap:
    // the same address, or either one a wildcard. Another address on the same port is someone
    // else's, so its failure keeps the hint. Transport and port must match; plain UDP and TCP
    // on IPv6 are V6ONLY, so IPv4 and IPv6 stay apart for them.
    #[test]
    fn ops_004_own_port_needs_overlapping_addresses() {
        use ListenProto::{Dot, Tcp, Udp};
        for (held, at, want, addr) in [
            (Tcp, "0.0.0.0:53", Tcp, "192.168.1.2:53"),
            (Tcp, "192.168.1.2:53", Tcp, "0.0.0.0:53"),
            (Tcp, "192.168.1.2:53", Dot, "192.168.1.2:53"),
            (Udp, "[::]:53", Udp, "[fd00::2]:53"),
        ] {
            assert!(takes(held, at, want, addr), "{held:?} {at} takes {addr}");
        }
        for (held, at, want, addr) in [
            (Tcp, "192.168.1.2:53", Tcp, "10.8.0.1:53"),
            (Udp, "127.0.0.1:53", Udp, "127.0.0.2:53"),
            (Tcp, "0.0.0.0:53", Udp, "0.0.0.0:53"),
            (Tcp, "0.0.0.0:53", Tcp, "0.0.0.0:5353"),
            (Tcp, "[::]:53", Tcp, "0.0.0.0:53"),
            (Udp, "0.0.0.0:53", Udp, "[::]:53"),
        ] {
            assert!(!takes(held, at, want, addr), "{held:?} {at} leaves {addr}");
        }
    }

    // REQ: OPS-004 — DoQ and DoH3 bind through quinn without V6ONLY, so one on `[::]` is
    // dual-stack and takes the IPv4 port too (a config with DoQ on both `[::]:853` and
    // `0.0.0.0:853` fails on its own socket, and the hint about another program would be
    // wrong). Either side counts; plain UDP and TCP on `[::]` don't. A pure rule: binding a
    // real `[::]` socket depends on the machine having IPv6.
    #[test]
    fn ops_004_quic_on_the_ipv6_wildcard_takes_both_families() {
        use ListenProto::{Doh3, Doq, Tcp, Udp};
        for (held, at, want, addr) in [
            (Doq, "[::]:853", Doq, "0.0.0.0:853"),
            (Doh3, "[::]:443", Udp, "192.168.1.2:443"),
            (Udp, "0.0.0.0:853", Doq, "[::]:853"),
            (Doq, "0.0.0.0:853", Doh3, "[::]:853"),
        ] {
            assert!(takes(held, at, want, addr), "{held:?} {at} takes {addr}");
        }
        for (held, at, want, addr) in [
            (Udp, "[::]:853", Doq, "0.0.0.0:853"),
            (Doq, "[fd00::2]:853", Doq, "0.0.0.0:853"),
            (Doq, "[::]:853", Tcp, "0.0.0.0:853"),
        ] {
            assert!(!takes(held, at, want, addr), "{held:?} {at} leaves {addr}");
        }
    }
}

#[cfg(test)]
#[path = "server_doh_tests.rs"]
mod doh_tests;
