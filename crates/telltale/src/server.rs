//! Server lifecycle: startup, hot reload on SIGHUP, graceful shutdown.
//!
//! REQ: OPS-007 (drain on shutdown), OPS-009 (reload without dropping queries).

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
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
fn build_dynamic(cfg: &Config) -> Result<(Arc<Router>, Policy), Vec<String>> {
    let router = Router::from_config(cfg).map_err(|errs| {
        errs.into_iter()
            .map(|e| format!("upstreams: {e}"))
            .collect::<Vec<_>>()
    })?;
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
    Ok((Arc::new(router), Policy::from_config(cfg, local)))
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
    v
}

/// Runs until SIGTERM/SIGINT. SIGHUP reloads config from `files`.
pub(crate) async fn serve(files: Vec<PathBuf>, cfg: Config) -> io::Result<()> {
    // spec/04 §7: tag outbound queries so a forwarding loop back to us is detectable.
    telltale_upstream::set_node_tag(rand::random());
    let workers = workers(&cfg);
    let (router, policy) = build_dynamic(&cfg).map_err(|errs| {
        for e in &errs {
            error!("{e}");
        }
        io::Error::other("invalid configuration")
    })?;
    let mut health = spawn_health_checks(&router);
    let cache = Arc::new(Cache::new(cache_policy(&cfg.cache, workers)));
    let settings = Settings {
        stale_answer_timeout: Duration::from_millis(u64::from(
            cfg.cache.stale_answer_client_timeout_ms,
        )),
        ..Settings::default()
    };
    let pipeline = Pipeline::new(settings, Arc::clone(&cache), router, policy);
    let mut listeners = Listeners {
        udp: Vec::new(),
        tcp: Vec::new(),
        workers,
        handler: Arc::new(Handler(Arc::clone(&pipeline))),
        rt: tokio::runtime::Handle::current(),
    };
    listeners.apply(&cfg.listen)?;

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
    });
    let (stop_http, http_stopped) = tokio::sync::oneshot::channel::<()>();
    if cfg.telemetry.metrics.enabled {
        let addr = cfg.telemetry.metrics.listen;
        let bound = http::serve(addr, Arc::clone(&sources), async {
            let _ = http_stopped.await;
        })
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("metrics {addr}: {e}")))?;
        info!(addr = %bound, "serving /metrics, /healthz, /readyz, /livez");
    }
    // Every listener is bound: ready for traffic (OPS-006).
    ready.store(true, Ordering::Release);

    let mut term = signal(SignalKind::terminate())?;
    let mut hup = signal(SignalKind::hangup())?;
    let mut current = cfg;
    loop {
        tokio::select! {
            _ = term.recv() => { info!(signal = "SIGTERM", "shutting down"); break; }
            _ = tokio::signal::ctrl_c() => { info!(signal = "SIGINT", "shutting down"); break; }
            _ = hup.recv() => reload(&files, &mut current, &mut listeners, &mut health, &pipeline, &sources),
        }
    }

    // REQ: OPS-007 — not ready first (load balancers stop sending), stop taking new TCP
    // connections, let in-flight upstream lookups finish (bounded), then stop UDP workers.
    ready.store(false, Ordering::Release);
    let _ = stop_http.send(());
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
    Ok(())
}

/// REQ: OPS-009 — validate the whole new config, then swap; on any error keep serving the
/// running configuration.
fn reload(
    files: &[PathBuf],
    current: &mut Config,
    listeners: &mut Listeners,
    health: &mut JoinHandle<()>,
    pipeline: &Pipeline,
    sources: &http::Sources,
) {
    info!(signal = "SIGHUP", "reloading configuration");
    let Some(new) = load(files) else {
        error!("reload failed: configuration invalid; still serving the previous configuration");
        return;
    };
    let (router, policy) = match build_dynamic(&new) {
        Ok(v) => v,
        Err(errs) => {
            for e in &errs {
                error!("{e}");
            }
            error!("reload failed; still serving the previous configuration");
            return;
        }
    };
    if let Err(e) = listeners.apply(&new.listen) {
        error!("reload: {e}; listeners unchanged where binding failed");
    }
    health.abort();
    *health = spawn_health_checks(&router);
    pipeline.reload(router, policy);
    let (u, t) = listeners.stats();
    sources.udp.store(Arc::new(u));
    sources.tcp.store(Arc::new(t));
    let restart = restart_only_changes(current, &new);
    if !restart.is_empty() {
        warn!(sections = ?restart, "these changes take effect after a restart");
    }
    *current = new;
    info!("configuration reloaded");
}
