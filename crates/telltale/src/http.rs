//! HTTP endpoints for operators: Prometheus `/metrics` and health probes.
//!
//! REQ: OBS-005 (metrics; the core set for now), OPS-006 (`/healthz`, `/readyz`, `/livez`).
//! The same `allowed_networks` that guard DNS guard this listener until API auth (M3) exists.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use arc_swap::{ArcSwap, ArcSwapOption};
use axum::Router as HttpRouter;
use axum::extract::{ConnectInfo, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use telltale_cache::Cache;
use telltale_config::Cidr;
use telltale_filter::fetch::{Fetcher, ListMeta};

use crate::lists::ListsShared;
use telltale_net::{DohStats, TcpStats, WorkerStats};
use telltale_telemetry::Metrics;
use telltale_telemetry::prom::{CONTENT_TYPE, PromWriter};
use telltale_upstream::Router;
use telltale_upstream::health::{Breaker, Outcome};

/// Everything `/metrics` reads.
#[derive(Debug)]
pub(crate) struct Sources {
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) cache: Arc<Cache>,
    /// Current routing/policy (reloadable) comes from the pipeline.
    pub(crate) pipeline: Arc<crate::pipeline::Pipeline>,
    /// Listener counters; replaced when a reload adds or removes listeners.
    pub(crate) udp: ArcSwap<Vec<Arc<WorkerStats>>>,
    pub(crate) tcp: ArcSwap<Vec<Arc<TcpStats>>>,
    pub(crate) doh: ArcSwap<Vec<Arc<DohStats>>>,
    /// REQ: DNS-004 (T7.7) — DoQ listeners' counters.
    pub(crate) doq: ArcSwap<Vec<Arc<telltale_net::DoqStats>>>,
    /// REQ: OPS-006, OPS-010 — why `/readyz` says what it says: listeners bound, the
    /// cluster's configuration applied (resolver pods), not shutting down, not in maintenance.
    pub(crate) readiness: Arc<crate::readiness::Readiness>,
    /// REQ: OPS-010 — this node's maintenance window.
    pub(crate) maintenance: Arc<crate::maintenance::Maintenance>,
    /// REQ: CLU-014 — this node's failover drills.
    pub(crate) drills: Arc<crate::drill::Drills>,
    /// REQ: OBS-025 — what kind of device each address is.
    pub(crate) identify: Arc<crate::identify::Identifier>,
    /// REQ: CLU-013 — the operator's rollout and pin commands for the publish loop, and what
    /// it last reported.
    pub(crate) rollout: Arc<crate::rollout::Hub>,
    pub(crate) started: Instant,
    pub(crate) allowed: Vec<Cidr>,
    /// The list fetcher and compiler, when this node handles lists.
    pub(crate) lists: ArcSwapOption<ListsShared>,
    /// Query-log write counters, when the query log is on.
    pub(crate) qlog: Option<Arc<telltale_store::qlog::Stats>>,
    /// The running configuration (replaced on reload), for the API.
    pub(crate) config: ArcSwap<telltale_config::Config>,
    /// The config files alone (what the API's entries are merged onto; ADR-040).
    pub(crate) file_config: ArcSwap<telltale_config::Config>,
    /// REQ: API-002, API-010, CLU-003 (ADR-040, ADR-051, ADR-191; GitHub issue #113) — what the
    /// last reload merged the API's entries onto when that isn't `file_config` alone: on a primary
    /// promoted from replica, the files plus the cluster version it last applied. What the API
    /// lists reads it; a write's checks read the same merge again when the write is planned
    /// (`api_backend::write_base`), as this copy lags a promotion until its reload. `None`: the
    /// files alone.
    pub(crate) managed_base: ArcSwapOption<telltale_config::Config>,
    /// REQ: OBS-010 (ADR-179) — the files couldn't be read at start-up, so `file_config` holds
    /// the running configuration instead, until a reload reads them: nothing in it counts as this
    /// node's own when alert destinations' credential files are checked.
    pub(crate) files_unread: std::sync::atomic::AtomicBool,
    /// The config files' paths, for backups (ADR-063).
    pub(crate) config_files: Vec<std::path::PathBuf>,
    /// Update status from the signed release index (ADR-046).
    pub(crate) update: Arc<std::sync::Mutex<telltale_api::model::UpdateStatus>>,
    /// Minute/hour/day rollups on disk (spec/06 §3), when they could be opened.
    pub(crate) rollups: Option<Arc<telltale_store::rollup::Rollups>>,
    /// The live tail (OBS-008), unless the privacy level forbids it.
    pub(crate) tail: Option<Arc<crate::tail::Tail>>,
    /// The device anomaly engine (OBS-013), unless disabled.
    pub(crate) anomalies: Option<Arc<crate::anomaly::Anomalies>>,
    /// The machine this node runs on (T6.11), sampled every 15 s.
    pub(crate) host: Arc<crate::host::HostMonitor>,
    /// The cache's last hour and warm start (T6.15).
    pub(crate) cache_history: Arc<crate::cache_history::CacheHistory>,
    /// Sign-in and the audit log, once the API listener has opened `state.db`.
    pub(crate) auth: std::sync::OnceLock<Arc<telltale_api::auth::Auth>>,
    /// REQ: CLU-003 (T9.1) — the hash of the primary's identities this replica last took in.
    pub(crate) identities_applied: std::sync::Mutex<String>,
    /// REQ: OBS-010 (T9.6) — what the alert task last saw and sent.
    pub(crate) alerts: std::sync::Mutex<telltale_api::model::AlertsStatus>,
    /// Masked-client-IP detector state (OPS-003).
    pub(crate) masking: crate::masking::Detector,
    /// This node's cluster channel, when it's in a cluster (CLU-001).
    pub(crate) cluster: Option<Arc<telltale_cluster::net::Cluster>>,
    /// Query-log shipping, both directions (CLU-007).
    pub(crate) ship: Arc<crate::ship::Stats>,
    /// Wakes the Git source's poll at once (its webhook, ADR-049).
    pub(crate) git_poke: Arc<tokio::sync::Notify>,
    /// Asks the main loop to re-read the config files and state.db and apply them; answers
    /// whether it worked (ADR-040).
    pub(crate) reload: tokio::sync::mpsc::Sender<tokio::sync::oneshot::Sender<bool>>,
    /// REQ: API-002, API-010 (ADR-040) — configuration changes through the API run one at a
    /// time: a plan is checked against the configuration the store then changes.
    pub(crate) config_writes: tokio::sync::Mutex<()>,
    /// REQ: OBS-020 (T11.3) — the synthetic probes' latest results.
    pub(crate) probes: Arc<crate::probes::Probes>,
    /// REQ: OBS-018 (T11.5) — shadow lists' would-be blocks and over-blocking suspects.
    pub(crate) shadow: Arc<crate::shadow::Shadow>,
    /// REQ: OBS-017 (T11.6) — latency exemplars and the queries waiting to go out as traces.
    pub(crate) traces: Arc<crate::traces::Traces>,
}

impl Sources {
    /// REQ: OBS-010 (ADR-179), API-002, API-010, CLU-003 (ADR-040, ADR-051; GitHub issue #113) —
    /// keeps the config files a reload read, and what it merged the API's entries onto with them
    /// ([`crate::replication::managed_base`]).
    pub(crate) fn store_files(&self, file: telltale_config::Config) {
        self.managed_base
            .store(crate::replication::managed_base(&file).map(Arc::new));
        self.file_config.store(Arc::new(file));
    }

    /// REQ: OPS-003 — whether client IPs appear masked in the latest 10-minute window.
    pub(crate) fn masked_clients(&self) -> Option<crate::masking::Masked> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let cfg = self.config.load();
        // REQ: OPS-003, OBS-009 (review 04-04) — at privacy level 2 the analytics keep no client
        // addresses, so every query looks like one client: nothing to judge.
        if cfg.telemetry.qlog.privacy_level >= 2 {
            return None;
        }
        let window = self.pipeline.telemetry.aggregates().recent_clients(now);
        self.masking
            .check(window.as_ref(), &cfg.clients.infrastructure)
    }
}

pub(crate) fn router(src: Arc<Sources>) -> HttpRouter {
    HttpRouter::new()
        .route("/metrics", get(metrics))
        .route("/livez", get(|| async { "ok\n" }))
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/readyz", get(readyz))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&src),
            only_allowed,
        ))
        .with_state(src)
}

/// The API listener's app: `/api/v1/*`, `/metrics` for signed-in users (a viewer token or
/// opt-in HTTP Basic), and open probes (REQ: API-001, API-003, `spec/06` §5). Everything is
/// still limited to `allowed_networks` (ADR-029).
pub(crate) fn api_router(src: Arc<Sources>, auth: Arc<telltale_api::auth::Auth>) -> HttpRouter {
    use telltale_api::auth::routes::{authenticate, require_viewer};
    let local: telltale_api::Shared = Arc::new(crate::api_backend::ApiBackend {
        src: Arc::clone(&src),
    });
    // REQ: CLU-002 — in a cluster, reads cover every node (peers are answered by the
    // handler `serve_peers` installs, API or not).
    let backend: telltale_api::Shared = match &src.cluster {
        Some(c) => Arc::new(crate::federated::Federated::new(local, Arc::clone(c))),
        None => local,
    };
    let metrics = HttpRouter::new()
        .route("/metrics", get(metrics))
        .with_state(Arc::clone(&src))
        .route_layer(middleware::from_fn(require_viewer))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&auth),
            authenticate,
        ));
    telltale_api::router(backend, auth)
        .merge(metrics)
        .route("/livez", get(|| async { "ok\n" }))
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/readyz", get(readyz).with_state(Arc::clone(&src)))
        .layer(middleware::from_fn_with_state(src, only_allowed))
}

/// Serves `app` until `shutdown` resolves.
pub(crate) async fn serve(
    addr: SocketAddr,
    app: HttpRouter,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<SocketAddr> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let app = app.into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await;
    });
    Ok(bound)
}

async fn only_allowed(
    State(src): State<Arc<Sources>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    if telltale_policy::is_allowed(&src.allowed, peer.ip()) {
        next.run(req).await
    } else {
        StatusCode::FORBIDDEN.into_response()
    }
}

/// `/readyz?startup=1`: the Kubernetes startup probe's view.
#[derive(Debug, serde::Deserialize)]
struct ReadyQuery {
    #[serde(default)]
    startup: Option<String>,
}

/// REQ: OPS-006, OPS-010 — 200 when ready for traffic, 503 with the reason otherwise
/// (`{"ready":false,"reason":"maintenance"}`, handy in `kubectl describe`). With `startup=1`
/// maintenance doesn't count: a pod restarted inside its window has started, and the
/// startup probe mustn't kill it for being in maintenance (ADR-118, amended).
async fn readyz(
    State(src): State<Arc<Sources>>,
    axum::extract::Query(q): axum::extract::Query<ReadyQuery>,
) -> Response {
    let r = &src.readiness;
    let startup = q
        .startup
        .as_deref()
        .is_some_and(|v| v != "0" && v != "false");
    let ok = if startup { r.started() } else { r.ready() };
    let reason = (!ok).then(|| r.reason()).flatten();
    let body = match reason {
        None if ok => "{\"ready\":true}\n".to_owned(),
        None => "{\"ready\":false}\n".to_owned(),
        Some(why) => format!("{{\"ready\":false,\"reason\":\"{why}\"}}\n"),
    };
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

async fn metrics(State(src): State<Arc<Sources>>, headers: header::HeaderMap) -> Response {
    let text = render(&src);
    // REQ: OBS-017 (T11.6) — OpenMetrics with exemplars for a scraper that asks for it.
    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok());
    if src.config.load().telemetry.metrics.exemplars && crate::traces::wants_openmetrics(accept) {
        let body = crate::traces::openmetrics(&text, &src.traces.exemplars());
        return ([(header::CONTENT_TYPE, crate::traces::OPENMETRICS)], body).into_response();
    }
    ([(header::CONTENT_TYPE, CONTENT_TYPE)], text).into_response()
}

/// The node's name: `[node] name`, or the host name.
pub(crate) fn node_name(cfg: &telltale_config::Config) -> String {
    if cfg.node.name.is_empty() {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|h| h.trim().to_owned())
            .unwrap_or_default()
    } else {
        cfg.node.name.to_string()
    }
}

/// Resident set size from /proc (Linux), for the footprint gates in `spec/00` §5.
fn rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

/// REQ: CLU-001, CLU-008 — peers this node streams with, by state.
/// REQ: CLU-003 (ADR-049) — the Git source, on the node that polls it.
fn git_metrics(src: &Sources, w: &mut PromWriter) {
    let cfg = src.config.load();
    if cfg.cluster.git.is_none() {
        return;
    }
    let s = crate::gitsource::status(&cfg).unwrap_or_default();
    for (name, help, v) in [
        (
            "telltale_cluster_git_refused",
            "1 when the newest commit was refused (invalid, unsigned, or rewound); the cluster stays on the last good one.",
            u64::from(s.refused),
        ),
        (
            "telltale_cluster_git_failing",
            "1 when the last check of the repository failed (unreachable, auth, ...).",
            u64::from(s.error.is_some() && !s.refused),
        ),
        (
            "telltale_cluster_git_commit_timestamp_seconds",
            "Commit time of the configuration in use.",
            u64::try_from(s.time).unwrap_or(0),
        ),
        (
            "telltale_cluster_git_checked_timestamp_seconds",
            "When the repository was last checked.",
            s.checked_ms / 1000,
        ),
    ] {
        w.family(name, "gauge", help).sample(name, &[], v);
    }
}

/// REQ: CLU-008 (T6.14) — where each peer runs, its load, cache, and restarts (per pod in
/// Kubernetes: one series per member, which the expiry of gone pods bounds).
fn peer_detail_metrics(peers: &[telltale_cluster::net::Member], w: &mut PromWriter) {
    w.family(
        "telltale_cluster_peer_info",
        "gauge",
        "Always 1: the peer's Kubernetes node and pod (empty outside Kubernetes) and version.",
    );
    for p in peers {
        w.sample(
            "telltale_cluster_peer_info",
            &[
                ("node", &p.node_id),
                ("site", &p.site),
                ("kube_node", &p.kube_node),
                ("pod", &p.pod),
                ("version", &p.version),
            ],
            1,
        );
    }
    w.family(
        "telltale_cluster_peer_queries_per_second",
        "gauge",
        "Queries per second the peer answered over the last minute (from its heartbeats).",
    );
    for p in peers {
        w.sample(
            "telltale_cluster_peer_queries_per_second",
            &[("node", &p.node_id), ("site", &p.site)],
            crate::cluster::per_second(p.queries_last_minute),
        );
    }
    w.family(
        "telltale_cluster_peer_cache_hit_ratio",
        "gauge",
        "The share of the peer's forwardable answers that came from its cache (fresh, refreshed, or stale) over the last minute (absent without any).",
    );
    for p in peers {
        if let Some(h) = p.cache_hit_permille {
            w.sample(
                "telltale_cluster_peer_cache_hit_ratio",
                &[("node", &p.node_id), ("site", &p.site)],
                f64::from(h) / 1000.0,
            );
        }
    }
    w.family(
        "telltale_cluster_peer_restarts",
        "gauge",
        "Restarts of the peer this node has seen since it started itself.",
    );
    for p in peers {
        w.sample(
            "telltale_cluster_peer_restarts",
            &[("node", &p.node_id), ("site", &p.site)],
            p.restarts,
        );
    }
}

/// REQ: CLU-005 — role, epoch, and the election (ADR-056).
fn election_metrics(c: &telltale_cluster::net::Cluster, w: &mut PromWriter) {
    // ADR-049 — the Git commit this node serves (every node should show the same one).
    let commit = c.local_state().source_commit;
    if !commit.is_empty() {
        w.family(
            "telltale_cluster_config_commit",
            "gauge",
            "1 for the Git commit of the configuration this node serves.",
        )
        .sample("telltale_cluster_config_commit", &[("commit", &commit)], 1);
    }
    let (_, epoch) = c.role();
    let fv = c.failover_view();
    for (name, help, v) in [
        (
            "telltale_cluster_primary",
            "1 when this node is the primary (or an emergency primary).",
            u64::from(c.is_primary()),
        ),
        ("telltale_cluster_epoch", "This node's epoch.", epoch),
        (
            "telltale_cluster_failover_auto",
            "1 when automatic failover runs on this node (auto mode, 3+ voters).",
            u64::from(fv.active),
        ),
        (
            "telltale_cluster_lease_held",
            "1 when this node is the elected primary and its lease holds (it may publish).",
            u64::from(fv.leading.is_some() && c.may_publish()),
        ),
    ] {
        w.family(name, "gauge", help).sample(name, &[], v);
    }
}

/// REQ: CLU-013 — the staged rollout and the pin (the primary reports them).
fn rollout_metrics(src: &Sources, w: &mut PromWriter) {
    let s = src.rollout.status();
    if !s.primary {
        return;
    }
    w.family(
        "telltale_cluster_rollout_stage",
        "gauge",
        "1 while a staged rollout's canary version bakes, else 0 (the primary reports it).",
    )
    .sample(
        "telltale_cluster_rollout_stage",
        &[],
        u8::from(s.active.is_some()),
    );
    if let Some(a) = &s.active {
        let v = format!("{}.{}", a.version.0, a.version.1);
        let started = (a.started_ms / 1000).to_string();
        w.family(
            "telltale_cluster_rollout_info",
            "gauge",
            "1 for the version baking and when its bake began (Unix seconds).",
        )
        .sample(
            "telltale_cluster_rollout_info",
            &[("version", &v), ("started", &started)],
            1,
        );
    }
    w.family(
        "telltale_cluster_pinned",
        "gauge",
        "1 while the cluster is pinned to an older version (changes wait for the unpin).",
    )
    .sample("telltale_cluster_pinned", &[], u8::from(s.pinned.is_some()));
    if let Some(p) = &s.pinned {
        let v = format!("{}.{}", p.to.0, p.to.1);
        w.family(
            "telltale_cluster_pinned_to",
            "gauge",
            "1 for the version the cluster is pinned to.",
        )
        .sample("telltale_cluster_pinned_to", &[("version", &v)], 1);
    }
    w.family(
        "telltale_cluster_rollouts_total",
        "counter",
        "Staged rollouts since the primary's process started, by outcome (started, promoted, failed, aborted, skipped) and pins (pinned, unpinned).",
    );
    for outcome in [
        "started", "promoted", "failed", "aborted", "skipped", "pinned", "unpinned",
    ] {
        w.sample(
            "telltale_cluster_rollouts_total",
            &[("outcome", outcome)],
            s.counts.get(outcome).copied().unwrap_or(0),
        );
    }
}

/// REQ: OPS-010 — this node's maintenance: whether it's in it, until when, how many windows
/// were started since this process did.
fn render_maintenance(src: &Sources, w: &mut PromWriter) {
    let now = crate::maintenance::now_ms();
    let current = src.maintenance.current(now);
    w.family(
        "telltale_node_maintenance",
        "gauge",
        "1 while this node is in maintenance (not ready for new traffic; still answering).",
    )
    .sample(
        "telltale_node_maintenance",
        &[],
        u8::from(current.is_some()),
    );
    w.family(
        "telltale_node_maintenance_until_seconds",
        "gauge",
        "When this node's maintenance window ends (Unix seconds; 0 when it isn't in maintenance).",
    )
    .sample(
        "telltale_node_maintenance_until_seconds",
        &[],
        current.map_or(0, |m| m.until_ms / 1000),
    );
    w.family(
        "telltale_node_maintenance_total",
        "counter",
        "Maintenance windows started on this node since the process started.",
    )
    .sample(
        "telltale_node_maintenance_total",
        &[],
        src.maintenance.starts(),
    );
}

/// REQ: OPS-010 — peers' maintenance windows (kept while they're silent), so the chart's
/// peer-down alert can stay quiet for a node stopped during its window.
fn peer_maintenance_metrics(
    peers: &[telltale_cluster::net::Member],
    now_ms: u64,
    w: &mut PromWriter,
) {
    w.family(
        "telltale_cluster_peer_maintenance_until_seconds",
        "gauge",
        "When the peer's maintenance window ends (Unix seconds; 0 when it isn't in maintenance).",
    );
    for p in peers {
        w.sample(
            "telltale_cluster_peer_maintenance_until_seconds",
            &[("node", &p.node_id), ("site", &p.site)],
            p.in_maintenance(now_ms).map_or(0, |m| m.until_ms / 1000),
        );
    }
}

fn cluster_metrics(src: &Sources, w: &mut PromWriter) {
    if let Some(c) = &src.cluster {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let peers = c.members();
        let up = peers.iter().filter(|p| p.up(now)).count();
        w.family(
            "telltale_cluster_peers",
            "gauge",
            "Cluster peers this node has heard from, by whether they're up (heard within 15 s).",
        );
        w.sample("telltale_cluster_peers", &[("state", "up")], up);
        w.sample(
            "telltale_cluster_peers",
            &[("state", "down")],
            peers.len() - up,
        );
        // Per peer, labeled by node ID and site (a handful of nodes: bounded cardinality).
        let newest = c.newest_seq();
        w.family(
            "telltale_cluster_peer_up",
            "gauge",
            "1 when the peer was heard from within 15 s.",
        );
        for p in &peers {
            w.sample(
                "telltale_cluster_peer_up",
                &[("node", &p.node_id), ("site", &p.site)],
                u8::from(p.up(now)),
            );
        }
        w.family(
            "telltale_cluster_peer_rtt_seconds",
            "gauge",
            "Round-trip time to the peer over the cluster link (from heartbeat echoes).",
        );
        for p in &peers {
            if let Some(rtt) = p.rtt_ms {
                w.sample(
                    "telltale_cluster_peer_rtt_seconds",
                    &[("node", &p.node_id), ("site", &p.site)],
                    f64::from(rtt) / 1000.0,
                );
            }
        }
        peer_detail_metrics(&peers, w);
        peer_maintenance_metrics(&peers, now, w);
        w.family(
            "telltale_cluster_peer_config_lag",
            "gauge",
            "Configuration versions the peer is behind the newest known.",
        );
        for p in &peers {
            w.sample(
                "telltale_cluster_peer_config_lag",
                &[("node", &p.node_id), ("site", &p.site)],
                newest.saturating_sub(p.stable_seq()),
            );
        }
        let local = c.local_state();
        w.family(
            "telltale_cluster_config_seq",
            "gauge",
            "The configuration version this node published (primary) or applied (replica).",
        )
        .sample("telltale_cluster_config_seq", &[], local.applied_seq);
        election_metrics(c, w);
        rollout_metrics(src, w);
        git_metrics(src, w);
        // REQ: CLU-004 (ADR-174) — the federated reads this node refused, by reason.
        crate::federated::render_metrics(w);
        w.family(
            "telltale_cluster_behind_seconds",
            "gauge",
            "How long this node's configuration has been behind the newest known (0 in sync).",
        )
        .sample(
            "telltale_cluster_behind_seconds",
            &[],
            c.behind_since().map_or(0, |s| now.saturating_sub(s) / 1000),
        );
        w.family(
            "telltale_cluster_sync_error",
            "gauge",
            "1 while this node's last replication attempt failed.",
        )
        .sample(
            "telltale_cluster_sync_error",
            &[],
            u8::from(c.sync_status().error.is_some()),
        );
        w.family(
            "telltale_cluster_cert_expiry_timestamp_seconds",
            "gauge",
            "When this node's cluster certificate expires (Unix seconds).",
        )
        .sample(
            "telltale_cluster_cert_expiry_timestamp_seconds",
            &[],
            crate::cluster::cert_expiry_unix(c),
        );
    }
}

pub(crate) fn render(src: &Sources) -> String {
    let mut w = PromWriter::new();
    render_process(&mut w, src);
    if let Some(h) = src.host.latest() {
        crate::host::render(&mut w, &h);
    }
    w.queries(&src.metrics.snapshot());
    render_cache(&mut w, &src.cache);
    render_telemetry(&mut w, &src.pipeline.telemetry);
    render_dnssec(&mut w, &src.pipeline.dnssec_stats);
    if let Some(q) = &src.qlog {
        render_qlog(&mut w, q);
    }
    if src.cluster.is_some() {
        render_ship(&mut w, &src.ship);
    }
    let state = src.pipeline.current();
    render_upstreams(&mut w, &state.router);
    render_upstream_quality(&mut w, &src.pipeline.quality, &state.router);
    render_exported(&mut w, src);
    if let Some(l) = src.lists.load_full() {
        render_lists(&mut w, &l.fetcher, &src.config.load());
        render_filter(&mut w, &l);
    }
    render_shadow(&mut w, &src.shadow);
    render_traces(&mut w, src);
    render_lookup_mode(&mut w, src);
    // REQ: FLT-009 — active pauses (group="*" = everyone).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    w.family(
        "telltale_filter_paused_until_seconds",
        "gauge",
        "Unix time when a pause of blocking ends, per group (\"*\" = everyone).",
    );
    for (group, until) in src.pipeline.pause.active(now) {
        w.sample(
            "telltale_filter_paused_until_seconds",
            &[("group", group.as_deref().unwrap_or("*"))],
            until,
        );
    }
    render_mac_table(&mut w, &src.pipeline.neighbors);
    // REQ: OBS-013 — device anomaly findings (alert rules count their increase).
    if let Some(a) = &src.anomalies {
        let (totals, devices, evicted) = a.counters();
        w.family(
            "telltale_anomalies_total",
            "counter",
            "Device anomaly findings by kind (rate_spike, domain_volume, drift, beacon, nxdomain_storm, reverse_sweep, dga, chatty_loop).",
        );
        for (k, n) in totals {
            w.sample("telltale_anomalies_total", &[("kind", k.label())], n);
        }
        render_anomalies_muted(&mut w, a);
        w.family(
            "telltale_anomaly_devices",
            "gauge",
            "Devices the anomaly engine keeps baselines for.",
        )
        .sample("telltale_anomaly_devices", &[], devices);
        w.family(
            "telltale_anomaly_evicted_total",
            "counter",
            "Devices whose anomaly baselines were dropped to stay within max_clients.",
        )
        .sample("telltale_anomaly_evicted_total", &[], evicted);
    }
    w.family(
        "telltale_client_ips_masked",
        "gauge",
        "1 when > 90% of the last 10 minutes' queries came from ≤ 3 infrastructure addresses.",
    )
    .sample(
        "telltale_client_ips_masked",
        &[],
        u8::from(src.masked_clients().is_some()),
    );
    cluster_metrics(src, &mut w);
    render_maintenance(src, &mut w);
    crate::simulate::render(&mut w);
    src.identify.render(&mut w);
    // REQ: FLT-017 — the workload table's size, age, and the watcher's errors.
    src.pipeline.kube.render(&mut w, crate::kubernetes::now_s());
    // REQ: CLU-014 — drills: running, dropped, and the last report's numbers.
    crate::drill::render(src, &mut w);
    render_slo(&mut w, &src.config.load().slo);
    render_probes(&mut w, &src.probes);
    crate::watchdog::render(&mut w);
    render_filter_index(src, &mut w);
    render_listeners(&mut w, src);
    w.family("telltale_local_records", "gauge", "Local records loaded.")
        .sample("telltale_local_records", &[], state.policy.local.len());
    w.finish()
}

/// REQ: OBS-038 (ADR-161) — what an anomaly mute matched: recorded and listed, not counted in
/// `telltale_anomalies_total`.
fn render_anomalies_muted(w: &mut PromWriter, a: &crate::anomaly::Anomalies) {
    w.family(
        "telltale_anomalies_muted_total",
        "counter",
        "Device anomaly findings a mute matched when they were created, by kind: they are listed on the Anomalies page, marked muted, and not counted in telltale_anomalies_total.",
    );
    for (k, n) in a.muted_totals() {
        w.sample("telltale_anomalies_muted_total", &[("kind", k.label())], n);
    }
}

fn render_filter_index(src: &Sources, w: &mut PromWriter) {
    if let Some(f) = src.pipeline.filter.load_full() {
        w.family(
            "telltale_filter_lookup_index_bytes",
            "gauge",
            "Memory of the query-time hash index (0 while the FST walk serves lookups).",
        )
        .sample(
            "telltale_filter_lookup_index_bytes",
            &[],
            f.matcher.index_bytes(),
        );
    }
}

/// REQ: OBS-016 (ADR-105) — the objectives as configured, so dashboards and recording rules
/// can show them next to the SLIs they compute from `telltale_responses_total` and
/// `telltale_query_duration_seconds`.
fn render_slo(w: &mut PromWriter, s: &telltale_config::SloConfig) {
    if !s.enabled {
        return;
    }
    // Rounded to the configured precision, so 99.9 reads 0.999 and not 0.9990000000000001.
    let ratio = |pct: f64| (pct * 1000.0).round() / 100_000.0;
    let name = "telltale_slo_objective_ratio";
    w.family(
        name,
        "gauge",
        "Service-level objectives ([slo]): the share of answers that must be good (availability: not SERVFAIL; latency: within telltale_slo_latency_threshold_seconds).",
    );
    w.sample(
        name,
        &[("slo", "availability")],
        ratio(s.availability_target),
    );
    w.sample(name, &[("slo", "latency")], ratio(s.latency_target));
    w.family(
        "telltale_slo_latency_threshold_seconds",
        "gauge",
        "The latency objective's threshold (a telltale_query_duration_seconds bucket bound).",
    )
    .sample(
        "telltale_slo_latency_threshold_seconds",
        &[],
        f64::from(s.latency_ms) / 1000.0,
    );
}

/// REQ: OBS-018 (T11.5, ADR-109) — what the shadow lists would have blocked.
fn render_shadow(w: &mut PromWriter, shadow: &crate::shadow::Shadow) {
    let hits = shadow.hits();
    if hits.is_empty() {
        return;
    }
    w.family(
        "telltale_list_shadow_hits_total",
        "counter",
        "Queries a list in shadow mode would have blocked (it doesn't block; they were answered).",
    );
    for (list, n) in &hits {
        w.sample(
            "telltale_list_shadow_hits_total",
            &[("list", list.as_str())],
            *n,
        );
    }
}

/// REQ: OBS-017 (T11.6, ADR-110) — the trace export, while it's configured.
fn render_traces(w: &mut PromWriter, src: &Sources) {
    let cfg = src.config.load();
    let o = &cfg.telemetry.otlp;
    if o.endpoint.is_none() || (o.traces_sample_every == 0 && o.traces_slow_ms == 0) {
        return;
    }
    w.family(
        "telltale_traces_total",
        "counter",
        "Queries exported as OTLP traces, by result: sent, dropped (the queue was full), failed (the collector didn't take them).",
    );
    let t = &src.traces;
    for (result, n) in [
        ("sent", &t.sent),
        ("dropped", &t.dropped),
        ("failed", &t.failed),
    ] {
        w.sample(
            "telltale_traces_total",
            &[("result", result)],
            n.load(Ordering::Relaxed),
        );
    }
}

/// REQ: OBS-020 (T11.3, ADR-107) — the synthetic probes and the listeners' certificates.
fn render_probes(w: &mut PromWriter, probes: &crate::probes::Probes) {
    let results = probes.results();
    if results.is_empty() {
        return;
    }
    let asked: Vec<_> = results.iter().filter(|r| r.skipped.is_none()).collect();
    w.family(
        "telltale_probe_success",
        "gauge",
        "1 if the last synthetic probe of a listener (or [probe] target) got an answer through its protocol.",
    );
    for r in &asked {
        w.sample(
            "telltale_probe_success",
            &[("target", r.target.as_str()), ("proto", r.proto.as_str())],
            u8::from(r.ok),
        );
    }
    w.family(
        "telltale_probe_duration_seconds",
        "gauge",
        "How long the last successful probe took.",
    );
    for r in asked.iter().filter(|r| r.ok) {
        w.sample(
            "telltale_probe_duration_seconds",
            &[("target", r.target.as_str()), ("proto", r.proto.as_str())],
            r.latency_ms.unwrap_or(0.0) / 1000.0,
        );
    }
    w.family(
        "telltale_probe_failures_total",
        "counter",
        "Probes that got no answer, since start.",
    );
    for r in &asked {
        w.sample(
            "telltale_probe_failures_total",
            &[("target", r.target.as_str()), ("proto", r.proto.as_str())],
            probes.failures_total(&r.target),
        );
    }
    w.family(
        "telltale_listener_cert_expiry_timestamp_seconds",
        "gauge",
        "When a DoT/DoH/DoQ listener's certificate expires (Unix time); proto=\"api\": the web UI and API's ([api] tls).",
    );
    for r in &results {
        if let Some(at) = r.cert_expires_unix_seconds {
            w.sample(
                "telltale_listener_cert_expiry_timestamp_seconds",
                &[("target", r.target.as_str()), ("proto", r.proto.as_str())],
                at,
            );
        }
    }
}

/// REQ: OBS-033 — the configuration sequence and the change markers written.
fn render_annotations(w: &mut PromWriter, src: &Sources) {
    // REQ: OBS-033 — the configuration sequence (the cluster's, else state.db's version):
    // `changes(telltale_config_seq[5m]) > 0` marks a change in Grafana.
    let seq = match &src.cluster {
        Some(c) => c.local_state().applied_seq,
        None => src
            .auth
            .get()
            .and_then(|a| a.state().config_version().ok())
            .unwrap_or(0),
    };
    w.family(
        "telltale_config_seq",
        "gauge",
        "The configuration sequence this node applied (the cluster's; a standalone node's configuration version).",
    )
    .sample("telltale_config_seq", &[], seq);
    if let Some(a) = crate::annotations::get() {
        let f = w.family(
            "telltale_annotations_total",
            "counter",
            "Change markers written to this node's annotations.jsonl since start, by kind.",
        );
        for (kind, n) in a.counts() {
            f.sample("telltale_annotations_total", &[("kind", kind)], n);
        }
        w.family(
            "telltale_annotation_write_failures_total",
            "counter",
            "Change markers that couldn't be written (the data directory full or read-only).",
        )
        .sample(
            "telltale_annotation_write_failures_total",
            &[],
            a.failures().0,
        );
    }
}

fn render_process(w: &mut PromWriter, src: &Sources) {
    w.family("telltale_build_info", "gauge", "Build information.")
        .sample(
            "telltale_build_info",
            &[
                ("version", crate::build_info::VERSION),
                ("commit", crate::build_info::COMMIT),
                ("channel", crate::build_info::CHANNEL),
                ("target", crate::build_info::TARGET),
                ("node", node_name(&src.config.load()).as_str()),
            ],
            1,
        );
    render_annotations(w, src);
    // REQ: OPS-004 (ADR-046) — 1 when the release index lists a newer build on this channel.
    let available = src.update.lock().is_ok_and(|u| u.state == "available");
    w.family(
        "telltale_update_available",
        "gauge",
        "1 if a newer build exists on this build's channel (from the signed release index).",
    )
    .sample("telltale_update_available", &[], u64::from(available));
    // REQ: OBS-010 (T9.19) — events each sink dropped.
    let drops = crate::sinks::drops();
    if !drops.is_empty() {
        let f = w.family(
            "telltale_sink_dropped_total",
            "counter",
            "Query events an event sink dropped: its buffer was full, or its collector refused a batch (and it couldn't be kept on disk).",
        );
        for (name, n) in &drops {
            f.sample(
                "telltale_sink_dropped_total",
                &[("sink", name.as_str())],
                *n,
            );
        }
    }
    // REQ: OBS-007 (review 04-08) — dnstap copies that never reached the reader.
    if let Some(tap) = src.pipeline.dnstap.get() {
        w.family(
            "telltale_dnstap_dropped_total",
            "counter",
            "dnstap copies dropped: the queue was full, the reader couldn't be reached, or it stopped reading.",
        )
        .sample(
            "telltale_dnstap_dropped_total",
            &[],
            tap.dropped.load(std::sync::atomic::Ordering::Relaxed),
        );
    }
    // REQ: OBS-002 (T9.13) — restarts survive restarts: counted in the data directory.
    let runs = crate::datadir::runs();
    w.family(
        "telltale_process_starts_total",
        "counter",
        "Times a node started on this data directory.",
    )
    .sample("telltale_process_starts_total", &[], runs.starts);
    w.family(
        "telltale_process_unclean_starts_total",
        "counter",
        "Starts after a run that didn't stop cleanly (a crash, an OOM kill, a power cut).",
    )
    .sample("telltale_process_unclean_starts_total", &[], runs.unclean);
    w.family("telltale_uptime_seconds", "gauge", "Seconds since start.")
        .sample(
            "telltale_uptime_seconds",
            &[],
            src.started.elapsed().as_secs(),
        );
    if let Some(rss) = rss_bytes() {
        w.family(
            "telltale_resident_memory_bytes",
            "gauge",
            "Resident set size.",
        )
        .sample("telltale_resident_memory_bytes", &[], rss);
    }
}

/// REQ: OBS-002 — event rings: emitted and dropped per producing thread.
fn render_telemetry(w: &mut PromWriter, hub: &telltale_telemetry::Hub) {
    // Tokio's workers all carry the runtime's thread name: one series per name, summed. A
    // label set repeated within a scrape is a duplicate sample, and Prometheus keeps only
    // the first (so the other workers' drops were invisible).
    let mut rings: std::collections::BTreeMap<String, (u64, u64)> =
        std::collections::BTreeMap::new();
    for (ring, emitted, dropped) in hub.ring_stats() {
        let e = rings.entry(ring).or_default();
        e.0 += emitted;
        e.1 += dropped;
    }
    w.family(
        "telltale_telemetry_events_total",
        "counter",
        "Query and upstream events written to the event rings.",
    );
    for (ring, (emitted, _)) in &rings {
        w.sample(
            "telltale_telemetry_events_total",
            &[("ring", ring.as_str())],
            *emitted,
        );
    }
    w.family(
        "telltale_telemetry_dropped_total",
        "counter",
        "Events dropped because a ring was full (counters and histograms never drop).",
    );
    for (ring, (_, dropped)) in &rings {
        w.sample(
            "telltale_telemetry_dropped_total",
            &[("ring", ring.as_str())],
            *dropped,
        );
    }
    // REQ: OBS-022 (T12.1) — queries kept out of the log and analytics by `[exclusions]`.
    w.family(
        "telltale_queries_excluded_total",
        "counter",
        "Queries left out of the query log, analytics, and exports by [exclusions] (still in telltale_queries_total).",
    )
    .sample("telltale_queries_excluded_total", &[], hub.excluded_total());
    // REQ: OBS-001 — clock steps the event clock followed (NTP's first sync on a Pi).
    let (steps, latest_step_us) = hub.clock_steps();
    w.family(
        "telltale_clock_steps_total",
        "counter",
        "Times the event clock was moved to follow a step of the system clock (NTP's first sync after start, a resume from suspend).",
    )
    .sample("telltale_clock_steps_total", &[], steps);
    #[allow(clippy::cast_precision_loss)] // seconds for display
    let latest_step_seconds = latest_step_us as f64 / 1e6;
    w.family(
        "telltale_clock_last_step_seconds",
        "gauge",
        "The latest clock step the event clock followed, in seconds (0 if none).",
    )
    .sample("telltale_clock_last_step_seconds", &[], latest_step_seconds);
}

/// REQ: OBS-003 — query-log writer health.
fn render_qlog(w: &mut PromWriter, q: &telltale_store::qlog::Stats) {
    use std::sync::atomic::Ordering::Relaxed;
    for (name, help, v) in [
        (
            "telltale_qlog_rows_written_total",
            "Query-log rows written to segments.",
            &q.rows_written,
        ),
        (
            "telltale_qlog_rows_dropped_total",
            "Query-log rows dropped because the writer fell behind.",
            &q.rows_dropped,
        ),
        (
            "telltale_qlog_bytes_written_total",
            "Query-log bytes written.",
            &q.bytes_written,
        ),
        (
            "telltale_qlog_segments_removed_total",
            "Query-log segments removed by retention.",
            &q.segments_removed,
        ),
        (
            "telltale_qlog_write_errors_total",
            "Query-log write errors.",
            &q.write_errors,
        ),
    ] {
        w.family(name, "counter", help)
            .sample(name, &[], v.load(Relaxed));
    }
    // REQ: NFR-007 — the store's own health: how long block writes take, and how many
    // segments it holds.
    #[allow(clippy::cast_precision_loss)] // microsecond totals far below 2^52
    let secs = q.block_write_micros.load(Relaxed) as f64 / 1e6;
    w.family(
        "telltale_qlog_block_write_seconds",
        "summary",
        "Time spent encoding and writing query-log blocks (rate of sum over count: the average).",
    )
    .sample("telltale_qlog_block_write_seconds_sum", &[], secs)
    .sample(
        "telltale_qlog_block_write_seconds_count",
        &[],
        q.blocks_written.load(Relaxed),
    );
    w.family(
        "telltale_qlog_segments",
        "gauge",
        "Query-log segment files on disk.",
    )
    .sample("telltale_qlog_segments", &[], q.segments.load(Relaxed));
}

/// REQ: FLT-006, OBS-005 (ADR-183) — the MAC table by source: the kernel's neighbor table, and
/// the bindings the routers report (this node's, other full members'), with the ones withheld.
/// One table for the whole scrape: the counts are of one table, not of two swapped between them.
fn render_mac_table(w: &mut PromWriter, neighbors: &telltale_policy::Neighbors) {
    let macs = neighbors.table();
    w.family(
        "telltale_neighbors",
        "gauge",
        "Entries from the kernel's neighbor table (ARP/NDP), read every neighbor_refresh_secs while [clients] neighbor_table is on.",
    )
    .sample("telltale_neighbors", &[], macs.kernel());
    w.family(
        "telltale_router_macs",
        "gauge",
        "Address-to-MAC bindings in use that routers report, by whose router (router: this node's, peer: other full cluster members'). They enter the table only while a [[client]] matches by MAC address and [clients] router_macs is on.",
    )
    .sample("telltale_router_macs", &[("source", "router")], macs.router())
    .sample("telltale_router_macs", &[("source", "peer")], macs.peer());
    w.family(
        "telltale_router_macs_unsure",
        "gauge",
        "Router bindings withheld from identifying a device: this node's own that are not sure, addresses other members withdrew or disagree on, and MACs reported at more than one address.",
    )
    .sample("telltale_router_macs_unsure", &[], macs.unsure());
}

/// REQ: DNS-011 — DNSSEC verdicts on forwarded answers (`spec/06` §5).
fn render_dnssec(w: &mut PromWriter, s: &telltale_upstream::dnssec::Stats) {
    use std::sync::atomic::Ordering::Relaxed;
    let name = "telltale_dnssec_validation_total";
    let f = w.family(
        name,
        "counter",
        "Forwarded answers DNSSEC-validated, by verdict.",
    );
    for (result, v) in [
        ("secure", &s.secure),
        ("insecure", &s.insecure),
        ("bogus", &s.bogus),
        ("indeterminate", &s.indeterminate),
    ] {
        f.sample(name, &[("result", result)], v.load(Relaxed));
    }
    // REQ: DNS-011 (T9.16) — RFC 8198.
    w.family(
        "telltale_dnssec_synthesized_total",
        "counter",
        "Negative answers made from cached, validated NSEC ranges instead of asking upstream (RFC 8198).",
    )
    .sample("telltale_dnssec_synthesized_total", &[], s.synthesized.load(Relaxed));
}

/// REQ: CLU-007 — query-log ship mode, sending and receiving.
fn render_ship(w: &mut PromWriter, s: &crate::ship::Stats) {
    use std::sync::atomic::Ordering::Relaxed;
    for (name, kind, help, v) in [
        (
            "telltale_qlog_ship_segments_total",
            "counter",
            "Query-log parts delivered to the ship target.",
            &s.segments_shipped,
        ),
        (
            "telltale_qlog_ship_bytes_total",
            "counter",
            "Query-log bytes delivered to the ship target.",
            &s.bytes_shipped,
        ),
        (
            "telltale_qlog_ship_errors_total",
            "counter",
            "Failed query-log deliveries (retried).",
            &s.errors,
        ),
        (
            "telltale_qlog_ship_pending_segments",
            "gauge",
            "Closed query-log parts waiting to be delivered.",
            &s.pending,
        ),
        (
            "telltale_qlog_received_segments_total",
            "counter",
            "Query-log parts received from nodes in ship mode.",
            &s.segments_received,
        ),
    ] {
        w.family(name, kind, help)
            .sample(name, &[], v.load(Relaxed));
    }
}

/// Answers peers over the cluster channel (CLU-002, CLU-007): federated reads, forwarded
/// writes, and shipped query logs. Installed whether or not this node runs the API.
pub(crate) fn serve_peers(src: &Arc<Sources>) {
    if let Some(c) = &src.cluster {
        let local: telltale_api::Shared = Arc::new(crate::api_backend::ApiBackend {
            src: Arc::clone(src),
        });
        c.set_rpc_handler(crate::federated::rpc_handler(
            Arc::clone(src),
            local,
            Arc::clone(c),
        ));
    }
}

fn render_cache(w: &mut PromWriter, cache: &Cache) {
    let c = cache.stats();
    for (name, kind, help, v) in [
        (
            "telltale_cache_hits_total",
            "counter",
            "Fresh cache hits.",
            c.hits,
        ),
        (
            "telltale_cache_misses_total",
            "counter",
            "Cache misses (including expired).",
            c.misses,
        ),
        (
            "telltale_cache_stale_served_total",
            "counter",
            "Expired answers served (RFC 8767).",
            c.stale_served,
        ),
        (
            "telltale_cache_inserts_total",
            "counter",
            "Answers stored.",
            c.inserts,
        ),
        (
            "telltale_cache_uncacheable_total",
            "counter",
            "Answers not stored (TTL 0, REFUSED, ...).",
            c.uncacheable,
        ),
        (
            "telltale_cache_evictions_total",
            "counter",
            "Entries evicted to stay within budget.",
            c.evictions,
        ),
        (
            "telltale_cache_prefetch_total",
            "counter",
            "Hot entries refreshed before they expired (DNS-008).",
            c.prefetches,
        ),
        (
            "telltale_cache_entries",
            "gauge",
            "Entries in the cache.",
            c.entries as u64,
        ),
        (
            "telltale_cache_bytes",
            "gauge",
            "Approximate cache memory use.",
            c.bytes as u64,
        ),
    ] {
        w.family(name, kind, help).sample(name, &[], v);
    }
    // REQ: OBS-021 (T11.2, ADR-106) — whether the cache is the right size.
    let name = "telltale_cache_ghost_hits_total";
    w.family(
        name,
        "counter",
        "Estimated extra hits a larger cache would have served (from a 1-in-16 sample of evicted names; cumulative: size=\"1.5x\" includes \"1.25x\").",
    );
    for (size, n) in ["1.25x", "1.5x", "2x"].iter().zip(c.ghost_hits) {
        w.sample(name, &[("size", size)], n);
    }
    w.family(
        "telltale_cache_peak_bytes",
        "gauge",
        "The most memory the cache has held since start.",
    )
    .sample("telltale_cache_peak_bytes", &[], c.peak_bytes as u64);
}

/// Name, type, help, and value of one per-list gauge.
type ListGauge = (
    &'static str,
    &'static str,
    &'static str,
    fn(&ListMeta) -> Option<u64>,
);

/// REQ: FLT-004, OBS-005 (the chart's list alerts, `spec/06` §8): per-list fetch state, for the
/// lists the configuration enables. The fetcher keeps a disabled list's state (re-enabling it
/// needs no download), but a frozen failure count or last success would keep the list alerts
/// firing for a list nobody is fetching, so it is left out here, at export time. A list the
/// configuration doesn't hold (a blocked service's) has no `enabled = false` and stays.
fn render_lists(w: &mut PromWriter, fetcher: &Fetcher, cfg: &telltale_config::Config) {
    let mut status = fetcher.status();
    status.retain(|(name, _)| {
        !cfg.list
            .iter()
            .any(|l| !l.enabled && l.name.as_str() == name)
    });
    render_list_status(w, &status);
}

/// REQ: FLT-004 — inline rules are never fetched, so they have no last-success time: one would
/// stay at the last config change and trip the "> 48 h" alert two days after every edit.
fn render_list_status(w: &mut PromWriter, status: &[(String, ListMeta)]) {
    let families: [ListGauge; 4] = [
        (
            "telltale_list_source_bytes",
            "gauge",
            "Size of the stored list source.",
            |m| m.has_content().then_some(m.bytes),
        ),
        (
            "telltale_list_last_success_timestamp_seconds",
            "gauge",
            "When the list was last confirmed current (download, 304, or unchanged file). Not \
             reported for inline rules, which are never fetched.",
            |m| m.last_success.filter(|_| !m.is_inline()),
        ),
        (
            "telltale_list_last_change_timestamp_seconds",
            "gauge",
            "When the list content last changed.",
            |m| m.last_changed,
        ),
        (
            "telltale_list_fetch_consecutive_failures",
            "gauge",
            "Failed refreshes since the last success (0 = healthy).",
            |m| Some(u64::from(m.consecutive_failures)),
        ),
    ];
    for (name, kind, help, value) in families {
        w.family(name, kind, help);
        for (list, meta) in status {
            if let Some(v) = value(meta) {
                w.sample(name, &[("list", list)], v);
            }
        }
    }
}

/// REQ: FLT-003, OBS-011 (review 02-09) — which domain lookup the active filter uses: the hash
/// index, or the slower FST walk (before the index is ready, or when the snapshot has more list
/// combinations than the index holds).
fn render_lookup_mode(w: &mut PromWriter, src: &Sources) {
    let filter = src.pipeline.filter.load();
    let Some(f) = filter.as_ref() else { return };
    let indexed = f.matcher.lookup() == telltale_filter::matcher::Lookup::Indexed;
    let name = "telltale_filter_lookup_mode";
    w.family(
        name,
        "gauge",
        "The active filter's domain lookup: 1 for the mode in use (indexed: hash index; walk: FST walk, slower, with its pages resident).",
    );
    w.sample(name, &[("mode", "indexed")], u64::from(indexed));
    w.sample(name, &[("mode", "walk")], u64::from(!indexed));
}

/// REQ: FLT-003, OBS-005 (`spec/06` metric names): the current filter snapshot.
fn render_filter(w: &mut PromWriter, lists: &ListsShared) {
    let compiled = lists
        .compiled
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let Some(c) = compiled else {
        return;
    };
    let st = &c.manifest.stats;
    w.family(
        "telltale_filter_snapshot_version",
        "gauge",
        "Version of the newest compiled filter snapshot.",
    )
    .sample("telltale_filter_snapshot_version", &[], c.manifest.version);
    w.family(
        "telltale_filter_rules",
        "gauge",
        "Names, regexes, and modifier rules in the snapshot.",
    )
    .sample(
        "telltale_filter_rules",
        &[],
        st.subtree_names + st.exact_names + st.subdomains_names + st.regexes + st.modrules,
    );
    w.family(
        "telltale_filter_compile_seconds",
        "gauge",
        "Duration of the last compile (0 when the snapshot was already on disk).",
    )
    .sample("telltale_filter_compile_seconds", &[], c.seconds);
    w.family(
        "telltale_list_entries",
        "gauge",
        "Entries each list contributes to the snapshot.",
    );
    for (i, l) in st.per_list.iter().enumerate() {
        if let Some(m) = c.manifest.lists.get(i) {
            w.sample(
                "telltale_list_entries",
                &[("list", m.name.as_str())],
                l.entries,
            );
        }
    }
    w.family(
        "telltale_list_regex_skipped",
        "gauge",
        "Regex rules each list ships that the snapshot leaves out (over [filter] max_regexes, too large, or invalid).",
    );
    for (i, l) in st.per_list.iter().enumerate() {
        if let Some(m) = c.manifest.lists.get(i) {
            w.sample(
                "telltale_list_regex_skipped",
                &[("list", m.name.as_str())],
                l.regex_skipped,
            );
        }
    }
}

/// REQ: OBS-019 (T11.4, ADR-108) — what the upstreams' answers said: DNSSEC verdicts, EDE
/// codes, and second opinions, per upstream (bounded: upstreams × a few values).
fn render_upstream_quality(
    w: &mut PromWriter,
    q: &crate::upstream_checks::Quality,
    router: &Router,
) {
    let ups = router.upstreams();
    let name = |id: u16| {
        ups.iter()
            .find(|u| u.id == id)
            .map_or("unknown", |u| u.name.as_str())
    };
    w.family(
        "telltale_upstream_dnssec_total",
        "counter",
        "DNSSEC verdicts on each upstream's answers (when validating).",
    );
    for u in ups {
        let c = q.dnssec_counts(u.id);
        if c.iter().sum::<u64>() == 0 {
            continue;
        }
        for (result, n) in ["secure", "insecure", "bogus", "indeterminate"]
            .iter()
            .zip(c)
        {
            w.sample(
                "telltale_upstream_dnssec_total",
                &[("upstream", u.name.as_str()), ("result", result)],
                n,
            );
        }
    }
    w.family(
        "telltale_upstream_ede_total",
        "counter",
        "Answers from each upstream carrying an Extended DNS Error code (RFC 8914; 15 Blocked, 16 Censored, 17 Filtered: the upstream filters).",
    );
    for ((id, code), n) in q.ede_counts() {
        w.sample(
            "telltale_upstream_ede_total",
            &[("upstream", name(id)), ("code", code.to_string().as_str())],
            n,
        );
    }
    let checks = q.check_counts();
    if checks.is_empty() {
        return;
    }
    w.family(
        "telltale_upstream_check_total",
        "counter",
        "Second opinions ([upstream_check]) on each upstream's answers, by how they compared.",
    );
    for (id, counts) in checks {
        for (a, n) in crate::upstream_checks::Agreement::ALL.iter().zip(counts) {
            w.sample(
                "telltale_upstream_check_total",
                &[("upstream", name(id)), ("result", a.label())],
                n,
            );
        }
    }
}

/// REQ: OBS-011 (core): per-upstream health.
fn render_upstreams(w: &mut PromWriter, router: &Router) {
    let ups = router.upstreams();
    let snaps: Vec<_> = ups
        .iter()
        .map(|u| (u.name.as_str(), u.health.snapshot()))
        .collect();
    w.family(
        "telltale_upstream_requests_total",
        "counter",
        "Upstream attempts by outcome (failure: timeout, error, SERVFAIL/REFUSED).",
    );
    for (name, s) in &snaps {
        let ok = s.requests.saturating_sub(s.failures);
        w.sample(
            "telltale_upstream_requests_total",
            &[("upstream", name), ("outcome", "success")],
            ok,
        );
        w.sample(
            "telltale_upstream_requests_total",
            &[("upstream", name), ("outcome", "failure")],
            s.failures,
        );
    }
    // REQ: UPS-006, OBS-011 — the failures by kind, so a failure rate can be read.
    w.family(
        "telltale_upstream_failures_total",
        "counter",
        "Failed upstream attempts by kind: timeout, network, bad_response, unresolved, servfail, refused, other_rcode.",
    );
    for (name, s) in &snaps {
        for (kind, n) in Outcome::FAILURES.iter().zip(s.failures_by_kind) {
            w.sample(
                "telltale_upstream_failures_total",
                &[("upstream", name), ("kind", kind.label())],
                n,
            );
        }
    }
    w.family(
        "telltale_upstream_breaker_state",
        "gauge",
        "Circuit breaker: 0 closed, 1 half-open, 2 open.",
    );
    for (name, s) in &snaps {
        let v = match s.breaker {
            Breaker::Closed => 0,
            Breaker::HalfOpen => 1,
            Breaker::Open => 2,
        };
        w.sample("telltale_upstream_breaker_state", &[("upstream", name)], v);
    }
    w.family(
        "telltale_upstream_latency_ewma_seconds",
        "gauge",
        "Smoothed upstream latency.",
    );
    for (name, s) in &snaps {
        if let Some(e) = s.ewma {
            w.sample(
                "telltale_upstream_latency_ewma_seconds",
                &[("upstream", name)],
                e.as_secs_f64(),
            );
        }
    }
    render_upstream_connections(w, router);
}

/// REQ: UPS-008, OBS-011 — connections to stream upstreams (TCP, DoT, DoH, UDP's TCP
/// fallback): how often they open, how long that takes, TLS resumption, and why they end.
/// Upstreams that never opened one (UDP-only so far, DoQ, plugins) are left out.
fn render_upstream_connections(w: &mut PromWriter, router: &Router) {
    let snaps: Vec<_> = router
        .upstreams()
        .iter()
        .map(|u| (u.name.as_str(), u.connections().snapshot()))
        .filter(|(_, c)| c.opened + c.open_failed > 0)
        .collect();
    w.family(
        "telltale_upstream_connections_opened_total",
        "counter",
        "Connections opened to the upstream (outcome: ok, or failed to connect or handshake).",
    );
    for (name, c) in &snaps {
        for (outcome, n) in [("ok", c.opened), ("failed", c.open_failed)] {
            w.sample(
                "telltale_upstream_connections_opened_total",
                &[("upstream", name), ("outcome", outcome)],
                n,
            );
        }
    }
    w.family(
        "telltale_upstream_connect_seconds_total",
        "counter",
        "Time spent opening connections (TCP and TLS): divide by the ok opens for the mean.",
    );
    for (name, c) in &snaps {
        #[allow(clippy::cast_precision_loss)] // microseconds, far below 2^52
        w.sample(
            "telltale_upstream_connect_seconds_total",
            &[("upstream", name)],
            c.connect_us as f64 / 1e6,
        );
    }
    w.family(
        "telltale_upstream_tls_handshakes_total",
        "counter",
        "TLS handshakes with the upstream: full, or resumed from a stored session (one round trip fewer).",
    );
    for (name, c) in snaps.iter().filter(|(_, c)| c.tls_full + c.tls_resumed > 0) {
        for (kind, n) in [("full", c.tls_full), ("resumed", c.tls_resumed)] {
            w.sample(
                "telltale_upstream_tls_handshakes_total",
                &[("upstream", name), ("kind", kind)],
                n,
            );
        }
    }
    w.family(
        "telltale_upstream_connections_closed_total",
        "counter",
        "Pooled connections ended, by reason: idle, server (closed or reset by it), write_failed, unanswered (queries waited 3 s with nothing coming back), unused.",
    );
    for (name, c) in &snaps {
        for (why, n) in telltale_upstream::Close::ALL.iter().zip(c.closed) {
            w.sample(
                "telltale_upstream_connections_closed_total",
                &[("upstream", name), ("reason", why.label())],
                n,
            );
        }
    }
    w.family(
        "telltale_upstream_connection_retries_total",
        "counter",
        "Queries sent again on a fresh connection because the pooled one closed first.",
    );
    for (name, c) in &snaps {
        w.sample(
            "telltale_upstream_connection_retries_total",
            &[("upstream", name)],
            c.retried,
        );
    }
    w.family(
        "telltale_upstream_connections",
        "gauge",
        "Open pooled connections (TCP and DoT; DoH keeps one HTTP/2 connection outside the pool).",
    );
    for (name, c) in &snaps {
        w.sample(
            "telltale_upstream_connections",
            &[("upstream", name)],
            c.live,
        );
    }
}

/// REQ: OBS-005, OBS-011 — series built from events by the aggregator: upstream latency
/// histograms, the upstream-wait stage, blocks by group and list, opt-in per-client counts.
/// REQ: FLT-005 (ADR-050) — queries per group and status (bounded: at most 64 groups).
fn render_groups(
    w: &mut PromWriter,
    counts: &[[u64; telltale_telemetry::N_STATUS]],
    groups: &[telltale_policy::Group],
) {
    w.family(
        "telltale_group_queries_total",
        "counter",
        "Queries by the client's primary group and how they were answered.",
    );
    for (g, row) in counts.iter().enumerate() {
        let group = groups
            .get(g)
            .map_or_else(|| "other".to_owned(), |g| g.name.to_string());
        for (si, n) in row.iter().enumerate() {
            if *n > 0
                && let Some(st) = telltale_telemetry::Status::ALL.get(si)
            {
                w.sample(
                    "telltale_group_queries_total",
                    &[("group", group.as_str()), ("status", st.label())],
                    *n,
                );
            }
        }
    }
}

fn render_exported(w: &mut PromWriter, src: &Sources) {
    // REQ: OBS-005 (issue #108) — the rows and the group table they are numbered by, read
    // together: a reload moves the rows and swaps the table under this lock.
    let (ex, state) = {
        let agg = src.pipeline.telemetry.aggregates();
        (agg.exported.clone(), src.pipeline.current())
    };
    w.family(
        "telltale_stage_duration_seconds",
        "histogram",
        "Time spent in a pipeline stage, per query that went through it (stage=upstream: waiting for upstreams).",
    )
    .histogram(
        "telltale_stage_duration_seconds",
        &[("stage", "upstream")],
        &ex.stage_upstream,
    );

    w.family(
        "telltale_upstream_duration_seconds",
        "histogram",
        "Upstream exchange time, including prefetches.",
    );
    for u in state.router.upstreams() {
        if let Some(t) = ex.upstreams.get(usize::from(u.id)) {
            let endpoint = u.endpoint.to_string();
            let protocol = endpoint.split_once("://").map_or("udp", |(p, _)| p);
            w.histogram(
                "telltale_upstream_duration_seconds",
                &[("upstream", u.name.as_str()), ("protocol", protocol)],
                &t.latency,
            );
        }
    }

    let groups = state.policy.clients.groups();
    let lists: Vec<String> = src
        .pipeline
        .filter
        .load()
        .as_ref()
        .and_then(|f| f.matcher.snapshot().cloned())
        .map(|s| s.manifest.lists.iter().map(|l| l.name.clone()).collect())
        .unwrap_or_default();
    render_groups(w, &ex.groups, groups);
    w.family(
        "telltale_blocked_total",
        "counter",
        "Blocked queries by the client's primary group and the deciding list (quick, schedule, answer_ip: no list decided).",
    );
    let mut blocked: Vec<_> = ex.blocked.iter().collect();
    blocked.sort();
    for ((g, l), n) in blocked {
        let group = groups
            .get(usize::from(*g))
            .map_or_else(|| "unknown".to_owned(), |g| g.name.to_string());
        let list = telltale_telemetry::export::blocked_label(*l, &lists);
        w.sample(
            "telltale_blocked_total",
            &[("group", group.as_str()), ("list", list)],
            *n,
        );
    }
    if ex.blocked_other > 0 {
        w.sample(
            "telltale_blocked_total",
            &[("group", "other"), ("list", "other")],
            ex.blocked_other,
        );
    }

    if ex.client_cap > 0 {
        w.family(
            "telltale_client_queries_total",
            "counter",
            "Queries per client (opt-in: [telemetry.metrics] per_client; capped, the rest are client=\"other\").",
        );
        let mut clients: Vec<_> = ex.clients.iter().collect();
        clients.sort();
        for (ip, n) in clients {
            let ip = telltale_telemetry::agg::client_text(*ip);
            w.sample(
                "telltale_client_queries_total",
                &[("client", ip.as_str())],
                *n,
            );
        }
        w.sample(
            "telltale_client_queries_total",
            &[("client", "other")],
            ex.clients_other,
        );
    }

    // `spec/06` §5 names this separately; it equals queries_total{status="rate_limited"}.
    let s = src.metrics.snapshot();
    let limited: u64 = s
        .queries
        .iter()
        .map(|row| row[telltale_telemetry::Status::RateLimited as usize])
        .sum();
    w.family(
        "telltale_ratelimited_total",
        "counter",
        "Queries refused or dropped by per-client rate limiting (DNS-014).",
    )
    .sample("telltale_ratelimited_total", &[], limited);
}

/// REQ: DNS-004 (T7.7) — DoQ listener counters.
fn write_doq_metrics(w: &mut PromWriter, src: &Sources) {
    use std::sync::atomic::Ordering::Relaxed;
    // Queries are also in telltale_queries_total{proto="doq"}.
    let doq = src.doq.load();
    let qsum = |f: fn(&telltale_net::DoqStats) -> u64| doq.iter().map(|s| f(s)).sum::<u64>();
    for (name, help, v) in [
        (
            "telltale_doq_connections_total",
            "DoQ connections accepted.",
            qsum(|s| s.connections.load(Relaxed)),
        ),
        (
            "telltale_doq_rejected_total",
            "DoQ connections refused at the connection cap.",
            qsum(|s| s.rejected.load(Relaxed)),
        ),
        (
            "telltale_doq_rejected_per_address_total",
            "DoQ connections closed because their client address held the per-address maximum.",
            qsum(|s| s.rejected_per_address.load(Relaxed)),
        ),
        (
            "telltale_doq_queries_total",
            "DoQ queries received (one per stream).",
            qsum(|s| s.queries.load(Relaxed)),
        ),
        (
            "telltale_doq_protocol_errors_total",
            "DoQ streams that broke RFC 9250 (the connection was closed).",
            qsum(|s| s.protocol_errors.load(Relaxed)),
        ),
    ] {
        w.family(name, "counter", help).sample(name, &[], v);
    }
}

fn render_listeners(w: &mut PromWriter, src: &Sources) {
    use std::sync::atomic::Ordering::Relaxed;
    let udp = src.udp.load();
    let sum = |f: fn(&WorkerStats) -> u64| udp.iter().map(|s| f(s)).sum::<u64>();
    for (name, help, v) in [
        (
            "telltale_udp_received_total",
            "UDP datagrams received.",
            sum(|s| s.received.load(Relaxed)),
        ),
        (
            "telltale_udp_replied_total",
            "UDP replies sent from worker threads.",
            sum(|s| s.replied.load(Relaxed)),
        ),
        (
            "telltale_udp_deferred_replied_total",
            "UDP replies sent after an upstream round trip.",
            sum(|s| s.deferred_replied.load(Relaxed)),
        ),
        (
            "telltale_udp_send_errors_total",
            "UDP send failures.",
            sum(|s| s.send_errors.load(Relaxed)),
        ),
        (
            "telltale_udp_dropped_total",
            "Oversized or unreadable UDP datagrams.",
            sum(|s| s.dropped.load(Relaxed)),
        ),
    ] {
        w.family(name, "counter", help).sample(name, &[], v);
    }
    write_tcp_metrics(w, src);
    write_doq_metrics(w, src);
    write_doh_metrics(w, src);
}

/// REQ: DNS-001, DNS-002 — TCP and DoT listener counters (also DoH's TLS and PROXY failures).
fn write_tcp_metrics(w: &mut PromWriter, src: &Sources) {
    use std::sync::atomic::Ordering::Relaxed;
    let tcp = src.tcp.load();
    let tsum = |f: fn(&TcpStats) -> u64| tcp.iter().map(|s| f(s)).sum::<u64>();
    for (name, help, v) in [
        (
            "telltale_tcp_connections_total",
            "TCP connections accepted.",
            tsum(|s| s.accepted.load(Relaxed)),
        ),
        (
            "telltale_tcp_rejected_total",
            "TCP connections refused at the cap.",
            tsum(|s| s.rejected.load(Relaxed)),
        ),
        (
            "telltale_tcp_rejected_per_address_total",
            "TCP and DoT connections refused because their client address held the per-address maximum.",
            tsum(|s| s.rejected_per_address.load(Relaxed)),
        ),
        (
            "telltale_tcp_idle_closed_total",
            "TCP connections closed for idleness.",
            tsum(|s| s.idle_closed.load(Relaxed)),
        ),
        (
            "telltale_tcp_stalled_closed_total",
            "TCP connections closed because the client stopped reading answers.",
            tsum(|s| s.stalled_closed.load(Relaxed)),
        ),
        (
            "telltale_tls_handshake_failures_total",
            "DoT and DoH connections whose TLS handshake failed or timed out.",
            tsum(|s| s.tls_failed.load(Relaxed))
                + src
                    .doh
                    .load()
                    .iter()
                    .map(|s| s.tls_failed.load(Relaxed))
                    .sum::<u64>(),
        ),
        (
            "telltale_proxy_protocol_rejected_total",
            "Connections closed for a missing or malformed PROXY protocol v2 header.",
            tsum(|s| s.proxy_rejected.load(Relaxed))
                + src
                    .doh
                    .load()
                    .iter()
                    .map(|s| s.proxy_rejected.load(Relaxed))
                    .sum::<u64>(),
        ),
    ] {
        w.family(name, "counter", help).sample(name, &[], v);
    }
}

fn write_doh_metrics(w: &mut PromWriter, src: &Sources) {
    use std::sync::atomic::Ordering::Relaxed;
    // REQ: DNS-003 — DoH requests (queries are also in telltale_queries_total{proto="doh"}).
    let doh = src.doh.load();
    let dsum = |f: fn(&DohStats) -> u64| doh.iter().map(|s| f(s)).sum::<u64>();
    for (name, help, v) in [
        (
            "telltale_doh_connections_total",
            "DoH connections accepted.",
            dsum(|s| s.accepted.load(Relaxed)),
        ),
        (
            "telltale_doh_rejected_total",
            "DoH connections (HTTP/2 and HTTP/3) refused at the connection cap.",
            dsum(|s| s.rejected.load(Relaxed)),
        ),
        (
            "telltale_doh_rejected_per_address_total",
            "DoH connections (HTTP/2 and HTTP/3) refused because their client address held the per-address maximum.",
            dsum(|s| s.rejected_per_address.load(Relaxed)),
        ),
        (
            "telltale_doh_requests_total",
            "DoH HTTP requests received.",
            dsum(|s| s.requests.load(Relaxed)),
        ),
        (
            "telltale_doh_bad_requests_total",
            "DoH requests refused with a 4xx status (path, method, media type, message).",
            dsum(|s| s.bad_requests.load(Relaxed)),
        ),
    ] {
        w.family(name, "counter", help).sample(name, &[], v);
    }
}

#[cfg(test)]
#[path = "http_tests.rs"]
pub(crate) mod tests;
