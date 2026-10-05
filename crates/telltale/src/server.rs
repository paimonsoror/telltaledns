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
use telltale_net::{
    CertStore, DohConfig, DohServer, TcpConfig, TcpServer, Transport, UdpConfig, UdpListener,
};
use telltale_policy::LocalData;
use telltale_upstream::Router;
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::http;
use crate::pipeline::{Handler, Pipeline, Policy, Settings};

/// Loads and validates config from `files` + environment plus what the UI/API stored
/// (ADR-040), logging every problem.
pub(crate) fn load(files: &[PathBuf]) -> Option<Config> {
    load_files(files).map(|c| crate::replication::effective(&c))
}

/// Loads and validates `files` + environment only (without what the UI/API stored).
pub(crate) fn load_files(files: &[PathBuf]) -> Option<Config> {
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
}

impl Stream {
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
        }
    }
}

/// REQ: DNS-002/003 — re-reads the certificate files every 10 s (cert-manager renewals).
fn watch_cert(store: Arc<CertStore>) -> JoinHandle<()> {
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

impl Listeners {
    /// Makes the running set match `listen`: binds additions first, then closes removals, so a
    /// changed address never leaves a gap (`spec/08` §5). A stream listener whose settings
    /// changed on the same address is closed just before its replacement binds.
    async fn apply(&mut self, listen: &[Listener]) -> io::Result<()> {
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
                ListenProto::Tcp | ListenProto::Dot | ListenProto::Doh
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
                    let stream = self.bind_stream(l).map_err(ctx)?;
                    self.streams.push((l.clone(), stream));
                }
                ListenProto::Udp | ListenProto::Tcp | ListenProto::Dot | ListenProto::Doh => {}
                other => {
                    warn!(addr = %l.addr, proto = ?other, "listener type not implemented yet; skipping");
                }
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

    fn bind_stream(&self, l: &Listener) -> io::Result<Stream> {
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
                let s = DohServer::bind(cfg, handler)?;
                info!(addr = %s.local_addr(), proxy_protocol = l.proxy_protocol, "listening (doh)");
                Ok(Stream::Doh(s, watch_cert(store)))
            }
            (proto, store) => {
                let mut cfg = TcpConfig::new(l.addr);
                cfg.proxy_protocol = l.proxy_protocol;
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
                    Stream::Doh(..) => None,
                })
                .collect(),
            doh: self
                .streams
                .iter()
                .filter_map(|(_, s)| match s {
                    Stream::Doh(d, _) => Some(d.stats_handle()),
                    Stream::Tcp(..) => None,
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
        stale_answer_timeout: Duration::from_millis(u64::from(
            cfg.cache.stale_answer_client_timeout_ms,
        )),
        // `ring_slots` events of ~128 bytes (ADR-026).
        ring_bytes: usize::try_from(cfg.telemetry.ring_slots).unwrap_or(4096) * 128,
        ..Settings::default()
    };
    let p = Pipeline::new(settings, cache, router, policy);
    p.set_dnssec(cfg);
    p
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
        let _ = sources.auth.set(Arc::clone(&auth));
        let app = http::api_router(Arc::clone(sources), auth);
        let bound = http::serve(addr, app, stopped(stop.clone()))
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("api {addr}: {e}")))?;
        info!(addr = %bound, "serving the API at /api/v1 (OpenAPI: /api/v1/openapi.json)");
    }
    Ok(())
}

/// Runs until SIGTERM/SIGINT. SIGHUP reloads config from `files`.
// The startup sequence and the main loop read best in one place.
#[allow(clippy::too_many_lines)]
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
    // REQ: OBS-013 — the anomaly engine rides the same aggregator pass (off the query path).
    let anomalies = crate::anomaly::Anomalies::start(&cfg);
    let anomaly_sink = anomalies
        .as_ref()
        .map(|a| Box::new(a.sink()) as Box<dyn telltale_telemetry::ring::Sink>);
    let sink = crate::tail::combine(qlog, tail.as_deref(), anomaly_sink);
    let _aggregator = pipeline
        .telemetry
        .spawn_aggregator(Duration::from_millis(25), sink)?;
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

    // REQ: OBS-005, OPS-006 — metrics and health probes.
    let ready = Arc::new(AtomicBool::new(false));
    let stats = listeners.stats();
    let (reload_tx, mut reload_rx) =
        tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<bool>>(8);
    let (stop_http, http_stopped) = tokio::sync::watch::channel(false);
    // REQ: CLU-009 — create or join the cluster on first start (the Helm chart's controller
    // and resolver pods). A resolver pod that can't join exits, so Kubernetes retries it.
    if let Err(e) = crate::cluster::bootstrap(&cfg, Duration::from_secs(120)).await {
        if cfg.cluster.ephemeral {
            return Err(io::Error::other(format!("cluster: {e}")));
        }
        warn!("cluster: {e}; running standalone");
    }
    // REQ: CLU-001, CLU-004 — the cluster channel runs beside DNS and never gates it.
    let cluster = crate::cluster::start(&cfg, &http_stopped);
    let sources = Arc::new(http::Sources {
        metrics: Arc::clone(&pipeline.metrics),
        cache,
        pipeline: Arc::clone(&pipeline),
        udp: ArcSwap::from_pointee(stats.udp),
        tcp: ArcSwap::from_pointee(stats.tcp),
        doh: ArcSwap::from_pointee(stats.doh),
        ready: Arc::clone(&ready),
        started: std::time::Instant::now(),
        allowed: cfg.access.allowed_networks.clone(),
        lists: ArcSwapOption::empty(),
        qlog: qlog_stats,
        config: ArcSwap::from_pointee(cfg.clone()),
        file_config: ArcSwap::from_pointee(load_files(&files).unwrap_or_else(|| cfg.clone())),
        rollups: rollups.clone(),
        tail,
        anomalies: anomalies.clone(),
        auth: std::sync::OnceLock::new(),
        masking: crate::masking::Detector::default(),
        cluster,
        ship: Arc::default(),
        git_poke: Arc::default(),
        reload: reload_tx,
    });
    http::serve_peers(&sources);
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
    start_http(&cfg, &sources, &http_stopped).await?;
    let neighbors =
        neighbor_refresh.map(|every| spawn_neighbor_refresh(Arc::clone(&pipeline), every));
    // Every listener is bound: ready for traffic (OPS-006). An ephemeral resolver pod waits
    // for the cluster's configuration too, so it never serves unfiltered (CLU-009).
    match &sources.cluster {
        Some(c) if cfg.cluster.ephemeral => {
            let (c, ready) = (Arc::clone(c), Arc::clone(&ready));
            tokio::spawn(async move {
                while c.sync_status().applied_ms == 0 {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                info!("cluster configuration applied: ready");
                ready.store(true, Ordering::Release);
            });
        }
        _ => ready.store(true, Ordering::Release),
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

    let mut term = signal(SignalKind::terminate())?;
    let mut hup = signal(SignalKind::hangup())?;
    let mut usr1 = signal(SignalKind::user_defined1())?;
    let mut current = cfg;
    loop {
        tokio::select! {
            _ = term.recv() => { info!(signal = "SIGTERM", "shutting down"); break; }
            _ = tokio::signal::ctrl_c() => { info!(signal = "SIGINT", "shutting down"); break; }
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
    ready.store(false, Ordering::Release);
    let _ = stop_http.send(true);
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
    let Some(file) = load_files(files) else {
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
    let stats = listeners.stats();
    sources.udp.store(Arc::new(stats.udp));
    sources.tcp.store(Arc::new(stats.tcp));
    sources.doh.store(Arc::new(stats.doh));
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
    sources.config.store(Arc::new(new.clone()));
    sources.file_config.store(Arc::new(file));
    *current = new;
    info!("configuration reloaded");
    true
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
