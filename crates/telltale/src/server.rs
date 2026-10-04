//! Server lifecycle: startup, hot reload on SIGHUP, graceful shutdown.
//!
//! REQ: OPS-007 (drain on shutdown), OPS-009 (reload without dropping queries).

use crate::lists::Lists;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use telltale_cache::{Cache, CachePolicy};
use telltale_config::{Config, ListenProto, Listener, Loader};
use telltale_net::{TcpConfig, TcpServer, UdpConfig, UdpListener};
use telltale_policy::LocalData;
use telltale_upstream::Router;
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::http;
use crate::pipeline::{Handler, Pipeline, Policy, Settings};

/// Loads and validates config from `files` + environment, logging every problem.
pub(crate) fn load(files: &[PathBuf]) -> Option<Config> {
    match files
        .iter()
        .fold(Loader::new(), Loader::file)
        .process_env()
        .load()
    {
        Ok(l) => {
            for w in &l.warnings {
                warn!("config: {w}");
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
    Ok((router, Policy::from_config(cfg, local)))
}

/// REQ: FLT-006 — keeps the IP → MAC map fresh while any client is identified by MAC.
fn spawn_neighbor_refresh(pipeline: Arc<Pipeline>, every: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut warned = false;
        loop {
            if pipeline.current().policy.clients.uses_macs() {
                match tokio::task::spawn_blocking(telltale_net::neighbors).await {
                    Ok(Ok(n)) => {
                        pipeline
                            .neighbors
                            .replace(n.into_iter().map(|x| (x.ip, x.mac)));
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
            tokio::time::sleep(every).await;
        }
    })
}

fn spawn_health_checks(router: &Router) -> JoinHandle<()> {
    tokio::spawn(telltale_upstream::active_health_checks(
        router.upstreams().to_vec(),
        telltale_upstream::HEALTH_CHECK_INTERVAL,
    ))
}

/// The running DNS listeners, keyed by (protocol, address).
struct Listeners {
    udp: Vec<(SocketAddr, UdpListener)>,
    tcp: Vec<(SocketAddr, TcpServer)>,
    workers: usize,
    handler: Arc<Handler>,
    rt: tokio::runtime::Handle,
}

impl Listeners {
    /// Makes the running set match `listen`: binds additions first, then closes removals, so a
    /// changed address never leaves a gap (`spec/08` §5).
    fn apply(&mut self, listen: &[Listener]) -> io::Result<()> {
        for l in listen {
            let ctx =
                |e: io::Error| io::Error::new(e.kind(), format!("{:?} {}: {e}", l.proto, l.addr));
            match l.proto {
                ListenProto::Udp if !self.udp.iter().any(|(a, _)| *a == l.addr) => {
                    let listener = UdpListener::spawn(
                        &UdpConfig::new(l.addr, self.workers),
                        &self.handler,
                        &self.rt,
                    )
                    .map_err(ctx)?;
                    info!(addr = %listener.local_addr(), workers = self.workers, "listening (udp)");
                    self.udp.push((l.addr, listener));
                }
                ListenProto::Tcp if !self.tcp.iter().any(|(a, _)| *a == l.addr) => {
                    let server = TcpServer::bind(TcpConfig::new(l.addr), Arc::clone(&self.handler))
                        .map_err(ctx)?;
                    info!(addr = %server.local_addr(), "listening (tcp)");
                    self.tcp.push((l.addr, server));
                }
                ListenProto::Udp | ListenProto::Tcp => {}
                other => {
                    warn!(addr = %l.addr, proto = ?other, "listener type not implemented yet; skipping");
                }
            }
        }
        let keep = |proto: ListenProto, addr: SocketAddr| {
            listen.iter().any(|l| l.proto == proto && l.addr == addr)
        };
        let (kept, gone): (Vec<_>, Vec<_>) = self
            .udp
            .drain(..)
            .partition(|(a, _)| keep(ListenProto::Udp, *a));
        self.udp = kept;
        for (addr, l) in gone {
            info!(%addr, "closing udp listener");
            l.shutdown();
        }
        let (kept, gone): (Vec<_>, Vec<_>) = self
            .tcp
            .drain(..)
            .partition(|(a, _)| keep(ListenProto::Tcp, *a));
        self.tcp = kept;
        for (addr, s) in gone {
            info!(%addr, "closing tcp listener");
            tokio::spawn(s.shutdown()); // drains its connections in the background
        }
        Ok(())
    }

    fn stats(
        &self,
    ) -> (
        Vec<Arc<telltale_net::WorkerStats>>,
        Vec<Arc<telltale_net::TcpStats>>,
    ) {
        (
            self.udp
                .iter()
                .flat_map(|(_, l)| l.stats().iter().cloned())
                .collect(),
            self.tcp.iter().map(|(_, s)| s.stats_handle()).collect(),
        )
    }
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
    if old.node != new.node {
        v.push("[node]");
    }
    if old.filter != new.filter {
        v.push("[filter]");
    }
    if old.clients.neighbor_table != new.clients.neighbor_table
        || old.clients.neighbor_refresh_secs != new.clients.neighbor_refresh_secs
    {
        v.push("[clients] neighbor_table / neighbor_refresh_secs");
    }
    v
}

/// REQ: OBS-003 — the query-log writer, fed by the aggregator thread. A failure to start
/// it is logged and DNS carries on without a query log (`spec/02` §8.5).
fn query_log(
    cfg: &Config,
) -> (
    Option<Box<dyn telltale_telemetry::ring::Sink>>,
    Option<Arc<telltale_store::qlog::Stats>>,
) {
    let q = &cfg.telemetry.qlog;
    if !q.enabled {
        return (None, None);
    }
    let settings = telltale_store::qlog::Settings {
        dir: std::path::Path::new(cfg.node.data_dir.as_str()).join("qlog"),
        // Cluster node IDs come with membership (T5.x); a standalone node is 0.
        node: 0,
        privacy: q.privacy_level,
        flush_interval: Duration::from_secs(u64::from(q.flush_interval_secs.max(1))),
        fsync: q.fsync,
        retention_days: q.retention_days,
        retention_bytes: q.retention_bytes.bytes(),
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
        stale_answer_timeout: Duration::from_millis(u64::from(
            cfg.cache.stale_answer_client_timeout_ms,
        )),
        // `ring_slots` events of ~128 bytes (ADR-026).
        ring_bytes: usize::try_from(cfg.telemetry.ring_slots).unwrap_or(4096) * 128,
        ..Settings::default()
    };
    Pipeline::new(settings, cache, router, policy)
}

/// REQ: OBS-005 — per-client query series are opt-in and capped (`[telemetry.metrics]`).
fn set_client_metrics(cfg: &Config, pipeline: &Pipeline) {
    let m = &cfg.telemetry.metrics;
    pipeline.telemetry.aggregates().exported.client_cap = if m.per_client {
        usize::try_from(m.per_client_cap).unwrap_or(usize::MAX)
    } else {
        0
    };
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
        let _purge = crate::auth_setup::spawn_purge(Arc::clone(&auth));
        let addr = cfg.api.listen;
        let app = http::api_router(Arc::clone(sources), auth);
        let bound = http::serve(addr, app, stopped(stop.clone()))
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("api {addr}: {e}")))?;
        info!(addr = %bound, "serving the API at /api/v1 (OpenAPI: /api/v1/openapi.json)");
    }
    Ok(())
}

/// Runs until SIGTERM/SIGINT. SIGHUP reloads config from `files`.
pub(crate) async fn serve(files: Vec<PathBuf>, cfg: Config) -> io::Result<()> {
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
    // REQ: OBS-002 — one aggregator thread drains the event rings (`spec/06` §2). It never
    // touches the query path: a stalled aggregator only means dropped (counted) events.
    let (qlog, qlog_stats) = query_log(&cfg);
    set_client_metrics(&cfg, &pipeline);
    // REQ: OBS-008 — the live tail is fed by the same aggregator pass as the query log.
    let tail = crate::tail::Tail::new(cfg.telemetry.qlog.privacy_level);
    let sink = crate::tail::combine(qlog, tail.as_deref());
    let _aggregator = pipeline
        .telemetry
        .spawn_aggregator(Duration::from_millis(25), sink)?;
    let mut listeners = Listeners {
        udp: Vec::new(),
        tcp: Vec::new(),
        workers,
        handler: Arc::new(Handler(Arc::clone(&pipeline))),
        rt: tokio::runtime::Handle::current(),
    };
    listeners.apply(&cfg.listen)?;

    // REQ: OBS-004, `spec/06` §3 — rollups on disk, fed once a minute off the query path.
    let rollups = crate::rollups::open(&cfg);
    let _rollup_writer = rollups
        .as_ref()
        .map(|db| crate::rollups::spawn(Arc::clone(db), Arc::clone(&pipeline)));

    // REQ: OBS-005, OPS-006 — metrics and health probes.
    let ready = Arc::new(AtomicBool::new(false));
    let (udp_stats, tcp_stats) = listeners.stats();
    let sources = Arc::new(http::Sources {
        metrics: Arc::clone(&pipeline.metrics),
        cache,
        pipeline: Arc::clone(&pipeline),
        udp: ArcSwap::from_pointee(udp_stats),
        tcp: ArcSwap::from_pointee(tcp_stats),
        ready: Arc::clone(&ready),
        started: std::time::Instant::now(),
        allowed: cfg.access.allowed_networks.clone(),
        lists: ArcSwapOption::empty(),
        qlog: qlog_stats,
        config: ArcSwap::from_pointee(cfg.clone()),
        rollups: rollups.clone(),
        tail,
    });
    let (stop_http, http_stopped) = tokio::sync::watch::channel(false);
    start_http(&cfg, &sources, &http_stopped).await?;
    let neighbors =
        neighbor_refresh.map(|every| spawn_neighbor_refresh(Arc::clone(&pipeline), every));
    // Every listener is bound: ready for traffic (OPS-006).
    ready.store(true, Ordering::Release);

    // REQ: FLT-004 — lists download in the background once DNS is up (rule 5: DNS never
    // waits for, or depends on, a list).
    let mut lists = Lists::start(&cfg, &pipeline);
    sources
        .lists
        .store(lists.as_ref().map(|l| Arc::clone(&l.shared)));

    let mut term = signal(SignalKind::terminate())?;
    let mut hup = signal(SignalKind::hangup())?;
    let mut usr1 = signal(SignalKind::user_defined1())?;
    let mut current = cfg;
    loop {
        tokio::select! {
            _ = term.recv() => { info!(signal = "SIGTERM", "shutting down"); break; }
            _ = tokio::signal::ctrl_c() => { info!(signal = "SIGINT", "shutting down"); break; }
            _ = hup.recv() => reload(&files, &mut current, &mut listeners, &mut health, &pipeline, &sources, &mut lists),
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
    ready.store(false, Ordering::Release);
    let _ = stop_http.send(true);
    for (_, s) in listeners.tcp.drain(..) {
        s.shutdown().await;
    }
    if !pipeline.drain(Duration::from_secs(3)).await {
        warn!("shutdown: some upstream lookups were still in flight after 3 s");
    }
    for (_, l) in listeners.udp.drain(..) {
        l.shutdown();
    }
    health.abort();
    if let Some(n) = neighbors {
        n.abort();
    }
    if let Some(l) = lists {
        l.stop();
    }
    Ok(())
}

/// REQ: OPS-009 — validate the whole new config, then swap; on any error keep serving the
/// running configuration.
fn reload(
    files: &[PathBuf],
    current: &mut Config,
    listeners: &mut Listeners,
    health: &mut JoinHandle<()>,
    pipeline: &Arc<Pipeline>,
    sources: &http::Sources,
    lists: &mut Option<Lists>,
) {
    info!(signal = "SIGHUP", "reloading configuration");
    let Some(new) = load(files) else {
        error!("reload failed: configuration invalid; still serving the previous configuration");
        return;
    };
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
            return;
        }
    };
    set_client_metrics(&new, pipeline);
    if let Err(e) = listeners.apply(&new.listen) {
        error!("reload: {e}; listeners unchanged where binding failed");
    }
    if !same_upstreams {
        health.abort();
        *health = spawn_health_checks(&router);
    }
    pipeline.reload(router, policy);
    let (u, t) = listeners.stats();
    sources.udp.store(Arc::new(u));
    sources.tcp.store(Arc::new(t));
    if let Some(l) = lists {
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
    sources.config.store(Arc::new(new.clone()));
    *current = new;
    info!("configuration reloaded");
}
