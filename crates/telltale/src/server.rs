//! Server lifecycle: startup, hot reload on SIGHUP, graceful shutdown.
//!
//! REQ: OPS-007 (drain on shutdown), OPS-009 (reload without dropping queries).

use crate::lists::Lists;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
    load_files_logging(files, true)
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
    /// REQ: DNS-004 (T7.7) — DNS over QUIC.
    Doq(telltale_net::DoqServer, JoinHandle<()>),
    /// REQ: DNS-004 (T7.8) — DoH over HTTP/3.
    Doh3(telltale_net::Doh3Server, JoinHandle<()>),
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
                        .map_err(ctx)?;
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
                let s = DohServer::bind(cfg, handler)?;
                info!(addr = %s.local_addr(), proxy_protocol = l.proxy_protocol, "listening (doh)");
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
        cache: Arc::clone(&cache),
        pipeline: Arc::clone(&pipeline),
        udp: ArcSwap::from_pointee(stats.udp),
        tcp: ArcSwap::from_pointee(stats.tcp),
        doh: ArcSwap::from_pointee(stats.doh),
        doq: ArcSwap::from_pointee(stats.doq),
        ready: Arc::clone(&ready),
        started: std::time::Instant::now(),
        allowed: cfg.access.allowed_networks.clone(),
        lists: ArcSwapOption::empty(),
        qlog: qlog_stats,
        config: ArcSwap::from_pointee(cfg.clone()),
        file_config: ArcSwap::from_pointee(load_files(&files).unwrap_or_else(|| cfg.clone())),
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
    // REQ: OBS-020 (T11.3) — synthetic probes of every listener, off the DNS path.
    crate::probes::spawn(Arc::clone(&sources), http_stopped.clone());
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
    // REQ: T8.2 — device names from the routers' DHCP (read at startup).
    tokio::spawn(crate::routers::run(
        cfg.router.clone(),
        Arc::clone(&pipeline.router_leases),
        http_stopped.clone(),
    ));
    // REQ: T8.3 — device names from mDNS announcements (read at startup).
    if cfg.clients.mdns {
        tokio::spawn(crate::mdns::run(
            cfg.clients.mdns_port,
            Arc::clone(&pipeline.mdns_names),
            http_stopped.clone(),
        ));
    }
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
    if let Some(n) = neighbors {
        n.abort();
    }
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

#[cfg(test)]
mod tests {
    use telltale_net::{QueryHandler, RequestMeta, Response, Transport};
    use telltale_proto::{EdnsOut, NameBuf, build_query, records, rtype};

    use super::*;
    use crate::pipeline::{Handler, Policy};

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
}
