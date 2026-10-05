//! HTTP endpoints for operators: Prometheus `/metrics` and health probes.
//!
//! REQ: OBS-005 (metrics; the core set for now), OPS-006 (`/healthz`, `/readyz`, `/livez`).
//! The same `allowed_networks` that guard DNS guard this listener until API auth (M3) exists.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
use telltale_upstream::health::Breaker;

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
    /// Set once every listener is bound; cleared at the start of shutdown.
    pub(crate) ready: Arc<AtomicBool>,
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
    /// Minute/hour/day rollups on disk (spec/06 §3), when they could be opened.
    pub(crate) rollups: Option<Arc<telltale_store::rollup::Rollups>>,
    /// The live tail (OBS-008), unless the privacy level forbids it.
    pub(crate) tail: Option<Arc<crate::tail::Tail>>,
    /// The device anomaly engine (OBS-013), unless disabled.
    pub(crate) anomalies: Option<Arc<crate::anomaly::Anomalies>>,
    /// Sign-in and the audit log, once the API listener has opened `state.db`.
    pub(crate) auth: std::sync::OnceLock<Arc<telltale_api::auth::Auth>>,
    /// Masked-client-IP detector state (OPS-003).
    pub(crate) masking: crate::masking::Detector,
    /// This node's cluster channel, when it's in a cluster (CLU-001).
    pub(crate) cluster: Option<Arc<telltale_cluster::net::Cluster>>,
    /// Query-log shipping, both directions (CLU-007).
    pub(crate) ship: Arc<crate::ship::Stats>,
    /// Asks the main loop to re-read the config files and state.db and apply them; answers
    /// whether it worked (ADR-040).
    pub(crate) reload: tokio::sync::mpsc::Sender<tokio::sync::oneshot::Sender<bool>>,
}

impl Sources {
    /// REQ: OPS-003 — whether client IPs appear masked in the latest 10-minute window.
    pub(crate) fn masked_clients(&self) -> Option<crate::masking::Masked> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let window = self.pipeline.telemetry.aggregates().recent_clients(now);
        let cfg = self.config.load();
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

async fn readyz(State(src): State<Arc<Sources>>) -> impl IntoResponse {
    if src.ready.load(Ordering::Acquire) {
        (StatusCode::OK, "ready\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
    }
}

async fn metrics(State(src): State<Arc<Sources>>) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, CONTENT_TYPE)], render(&src))
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
        w.family(
            "telltale_cluster_peer_config_lag",
            "gauge",
            "Configuration versions the peer is behind the newest known.",
        );
        for p in &peers {
            w.sample(
                "telltale_cluster_peer_config_lag",
                &[("node", &p.node_id), ("site", &p.site)],
                newest.saturating_sub(p.applied_seq),
            );
        }
        let local = c.local_state();
        w.family(
            "telltale_cluster_config_seq",
            "gauge",
            "The configuration version this node published (primary) or applied (replica).",
        )
        .sample("telltale_cluster_config_seq", &[], local.applied_seq);
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
    w.queries(&src.metrics.snapshot());
    render_cache(&mut w, &src.cache);
    render_telemetry(&mut w, &src.pipeline.telemetry);
    if let Some(q) = &src.qlog {
        render_qlog(&mut w, q);
    }
    if src.cluster.is_some() {
        render_ship(&mut w, &src.ship);
    }
    let state = src.pipeline.current();
    render_upstreams(&mut w, &state.router);
    render_exported(&mut w, src, &state);
    if let Some(l) = src.lists.load_full() {
        render_lists(&mut w, &l.fetcher);
        render_filter(&mut w, &l);
    }
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
    w.family(
        "telltale_neighbors",
        "gauge",
        "Entries in the IP-to-MAC neighbor table used to recognize clients.",
    )
    .sample("telltale_neighbors", &[], src.pipeline.neighbors.len());
    // REQ: OBS-013 — device anomaly findings (alert rules count their increase).
    if let Some(a) = &src.anomalies {
        let (totals, devices, evicted) = a.counters();
        w.family(
            "telltale_anomalies_total",
            "counter",
            "Device anomaly findings by kind (rate_spike, domain_volume, drift, beacon).",
        );
        for (k, n) in totals {
            w.sample("telltale_anomalies_total", &[("kind", k.label())], n);
        }
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
    render_listeners(&mut w, src);
    w.family("telltale_local_records", "gauge", "Local records loaded.")
        .sample("telltale_local_records", &[], state.policy.local.len());
    w.finish()
}

fn render_process(w: &mut PromWriter, src: &Sources) {
    w.family("telltale_build_info", "gauge", "Build information.")
        .sample(
            "telltale_build_info",
            &[
                ("version", env!("CARGO_PKG_VERSION")),
                ("node", node_name(&src.config.load()).as_str()),
            ],
            1,
        );
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
    let rings = hub.ring_stats();
    w.family(
        "telltale_telemetry_events_total",
        "counter",
        "Query and upstream events written to the event rings.",
    );
    for (ring, emitted, _) in &rings {
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
    for (ring, _, dropped) in &rings {
        w.sample(
            "telltale_telemetry_dropped_total",
            &[("ring", ring.as_str())],
            *dropped,
        );
    }
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
}

/// Name, type, help, and value of one per-list gauge.
type ListGauge = (
    &'static str,
    &'static str,
    &'static str,
    fn(&ListMeta) -> Option<u64>,
);

/// REQ: FLT-004, `spec/06` §6 alert "list fetch failing for > 48 h": per-list fetch state.
fn render_lists(w: &mut PromWriter, fetcher: &Fetcher) {
    let status = fetcher.status();
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
            "When the list was last confirmed current (download, 304, or unchanged file).",
            |m| m.last_success,
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
        for (list, meta) in &status {
            if let Some(v) = value(meta) {
                w.sample(name, &[("list", list)], v);
            }
        }
    }
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

fn render_exported(w: &mut PromWriter, src: &Sources, state: &crate::pipeline::Dynamic) {
    let ex = src.pipeline.telemetry.aggregates().exported.clone();
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
        "Blocked queries by the client's primary group and the deciding list.",
    );
    let mut blocked: Vec<_> = ex.blocked.iter().collect();
    blocked.sort();
    for ((g, l), n) in blocked {
        let group = groups
            .get(usize::from(*g))
            .map_or_else(|| "unknown".to_owned(), |g| g.name.to_string());
        let list = lists.get(usize::from(*l)).map_or("unknown", String::as_str);
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
            "telltale_tcp_idle_closed_total",
            "TCP connections closed for idleness.",
            tsum(|s| s.idle_closed.load(Relaxed)),
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
mod tests {
    use std::time::Duration;

    use telltale_cache::CachePolicy;
    use telltale_telemetry::{Proto, Status};

    use super::*;

    fn sources() -> Sources {
        let metrics = Arc::new(Metrics::new(2));
        metrics.record(
            Proto::Udp,
            Status::Cached,
            Some(0),
            1,
            Duration::from_micros(80),
        );
        let cache = Arc::new(Cache::new(CachePolicy::default()));
        Sources {
            metrics,
            cache: Arc::clone(&cache),
            pipeline: crate::pipeline::Pipeline::new(
                crate::pipeline::Settings::default(),
                cache,
                Arc::new(Router::default()),
                crate::pipeline::Policy::default(),
            ),
            udp: ArcSwap::from_pointee(Vec::new()),
            tcp: ArcSwap::from_pointee(Vec::new()),
            doh: ArcSwap::from_pointee(Vec::new()),
            ready: Arc::new(AtomicBool::new(true)),
            started: Instant::now(),
            lists: ArcSwapOption::empty(),
            qlog: None,
            config: ArcSwap::from_pointee(telltale_config::Config::default()),
            file_config: ArcSwap::from_pointee(telltale_config::Config::default()),
            rollups: None,
            tail: None,
            anomalies: None,
            auth: std::sync::OnceLock::new(),
            masking: crate::masking::Detector::default(),
            cluster: None,
            ship: Arc::default(),
            reload: tokio::sync::mpsc::channel(1).0,
            allowed: Vec::new(),
        }
    }

    #[test]
    fn obs_005_render_includes_core_families() {
        let src = sources();
        let text = render(&src);
        for family in [
            "telltale_build_info",
            "telltale_queries_total",
            "telltale_query_duration_seconds",
            "telltale_cache_hits_total",
            "telltale_upstream_requests_total",
            "telltale_udp_received_total",
            "telltale_tcp_connections_total",
        ] {
            assert!(
                text.contains(&format!("# TYPE {family} ")),
                "missing {family}"
            );
        }
        assert!(text.contains("telltale_queries_total{proto=\"udp\",status=\"cached\"} 1"));
        assert!(text.contains("telltale_local_records 0"));
    }

    #[test]
    fn ops_003_masked_client_ips_reach_metrics_and_api() {
        use telltale_telemetry::event::{Name, Record};
        let src = sources();
        assert!(render(&src).contains("telltale_client_ips_masked 0"));
        let now_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_micros())
            .try_into()
            .unwrap_or(0);
        let event = |last: u8| telltale_telemetry::QueryEvent {
            ts_us: now_us,
            client_ip: std::net::Ipv4Addr::new(127, 0, 0, last)
                .to_ipv6_mapped()
                .octets(),
            client_ref: 0,
            group: 0,
            qtype: 1,
            qclass: 1,
            rcode: Some(0),
            status: Status::Forwarded,
            proto: Proto::Udp,
            flags: 0x8180,
            rule: None,
            upstream: 1,
            attempts: 1,
            t_total_us: 100,
            t_upstream_us: 90,
            resp_size: 60,
            answers: 1,
        };
        {
            let mut agg = src.pipeline.telemetry.aggregates();
            for _ in 0..140 {
                agg.record(&Record::Query(event(1), Name::default()));
            }
            agg.record(&Record::Query(event(2), Name::default()));
        }
        assert!(render(&src).contains("telltale_client_ips_masked 1"));
        let m = src.masked_clients().unwrap();
        assert_eq!((m.share_percent, m.queries), (100, 141));
        assert_eq!(m.sources, ["127.0.0.1", "127.0.0.2"]);
    }
}
