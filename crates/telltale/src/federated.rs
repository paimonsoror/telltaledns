//! Federated reads (REQ: CLU-002, OBS-012; T5.6): any node's dashboard and query log show the
//! whole cluster. Stats and query-log reads go to every reachable peer over the cluster
//! channel at once, with a deadline, and merge (`telltale_api::federation`); a node that
//! doesn't answer is listed in `missingNodes` instead of holding the read up. Everything else
//! — configuration, explain, the live tail — is this node's own (the tail stays node-local).
//!
//! Nothing here touches DNS answering (CLU-004). A read never waits on a runtime worker: it
//! starts its RPCs on the runtime and waits for them on its own thread (the blocking pool's, where
//! the API runs its backend calls) with a deadline of the OS's, not the runtime's: see
//! `federated_bridge.rs` (ADR-174).

use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use telltale_api::federation::{self, Bounds, NodePage};
use telltale_api::model::{
    AnomalyFinding, ClientChange, ClientInfo, ClusterView, ConfigChange, ExplainParams,
    Explanation, ForwardInfo, GroupInfo, Hour, LatencyBy, LatencyRow, ListInfo, LocalName,
    PromoteRequest, QueryPage, QueryParams, Step, SystemInfo, TailItem, TailParams, TimeBucket,
    TopItem, TopKind, UpstreamInfo,
};
use telltale_api::problem::Problem;
use telltale_api::{Backend, BoxFuture, ClientWrite, ManagedWrite, Shared};
use telltale_cluster::net::{Cluster, RpcHandler};

/// The RPC every federated read uses; its body is a JSON [`Read`].
const KIND: &str = "api.read";
/// How long a read waits for peers (CLU-002: a dead node costs at most this).
const DEADLINE: Duration = Duration::from_secs(2);
#[path = "federated_bridge.rs"]
mod bridge;
#[path = "federated_support.rs"]
mod support_cluster;
// REQ: CLU-004 (ADR-174) — the scan that keeps every federating backend call behind `blocking`.
#[cfg(test)]
#[path = "federated_guard_tests.rs"]
mod guard_tests;

/// How long a replica waits for the primary's configuration version before using its own.
const VERSION_DEADLINE: Duration = Duration::from_secs(1);

/// One read, as sent to peers (already-parsed arguments).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "read", rename_all = "snake_case")]
enum Read {
    Timeseries {
        step: Step,
        from_s: u64,
        to_s: u64,
    },
    Top {
        kind: TopKind,
        hour: Hour,
        limit: usize,
        client: Option<IpAddr>,
    },
    TopInGroup {
        kind: TopKind,
        hour: Hour,
        limit: usize,
        group: String,
    },
    /// REQ: API-005 (ADR-158) — the clients of the last hour (older peers don't know it).
    TopClientsRolling {
        limit: usize,
        group: Option<String>,
    },
    /// REQ: OBS-004 (ADR-160) — a top list over a window.
    TopRange {
        kind: TopKind,
        from_s: u64,
        to_s: u64,
        limit: usize,
    },
    Latency {
        by: LatencyBy,
        hour: Hour,
    },
    /// REQ: OBS-010 (T9.5) — devices first seen.
    NewDevices {
        since_s: u64,
    },
    /// REQ: OBS-025 — what each device looks like (older peers don't know it).
    Identities,
    /// REQ: OBS-025 — one device, with the evidence.
    Identity {
        client: String,
    },
    /// REQ: OBS-031 — one device's rhythm (older peers don't know it).
    ClientRhythm {
        client: String,
    },
    /// REQ: CLU-002 (T9.2) — the histograms behind `Latency` (older peers don't know it).
    LatencyHist {
        by: LatencyBy,
        hour: Hour,
    },
    /// REQ: OBS-008, CLU-002 (T9.2) — a live tail session on the peer for a cluster-wide
    /// tail: open it, poll it (what matched since), close it.
    TailOpen {
        params: Box<TailParams>,
    },
    /// REQ: OBS-003, OBS-008 (ADR-171) — `TailOpen` with a negated filter. A separate read, so an
    /// older peer (which would ignore the flags and tail what was not negated) doesn't know it.
    TailOpenNegated {
        params: Box<TailParams>,
    },
    TailPoll {
        id: u64,
    },
    TailClose {
        id: u64,
    },
    Queries {
        params: Box<QueryParams>,
        from_us: u64,
        to_us: u64,
        limit: usize,
    },
    /// REQ: OBS-003 (ADR-171) — `Queries` with a negated filter (older peers don't know it, so
    /// they are listed as missing instead of answering rows that were not negated).
    QueriesNegated {
        params: Box<QueryParams>,
        from_us: u64,
        to_us: u64,
        limit: usize,
    },
    /// The configuration version (a replica's `If-Match` and `ETag` use the primary's; T5.7).
    ConfigVersion,
    /// REQ: API-002, CLU-002 — the primary's configuration entries (what the settings
    /// editors list), for a replica's UI.
    ConfigEntries {
        kind: Option<String>,
    },
    /// REQ: DNS-006 (T6.13) — the peer's own cache: counters, a lookup, a flush.
    CacheStats,
    /// T7.1 — pauses.
    BlockingState,
    BlockingPause {
        group: Option<String>,
        minutes: u32,
    },
    BlockingResume {
        group: Option<String>,
    },
    /// T6.15 — the top entries and makeup.
    CacheEntries {
        sort: String,
        limit: usize,
    },
    CacheLookup {
        name: String,
    },
    CacheFlush {
        name: Option<String>,
        subtree: bool,
    },
    /// REQ: OBS-014, CLU-002 — the peer's own anomaly findings (older peers don't know it).
    Anomalies {
        since_s: u64,
    },
    /// REQ: OBS-015 — the peer's own health conditions.
    Health,
    /// REQ: OBS-020 — the peer's own probes (older peers don't know it).
    Probes,
    /// REQ: OBS-030 — the peer's own exemplars (older peers don't know it).
    Exemplars {
        from_us: u64,
        to_us: u64,
        path: Option<String>,
    },
    /// REQ: OBS-029 — the peer's own hours for a device or a name (older peers don't know it).
    HeatmapKey {
        q: telltale_api::heatmap::KeyQuery,
    },
    /// REQ: OBS-029 — the peer's own network slots (older peers don't know it).
    HeatmapNetwork {
        q: telltale_api::heatmap::NetworkQuery,
    },
    /// REQ: OBS-027 — the peer's own error-budget attribution part (older peers don't know it).
    SloParts {
        q: telltale_api::attribution::PartQuery,
    },
    /// REQ: OBS-033 — the peer's own change markers (older peers don't know it).
    Annotations {
        filter: telltale_api::model::AnnotationFilter,
    },
    /// REQ: OBS-019 — the peer's own upstream answer quality (older peers don't know it).
    UpstreamChecks,
    /// REQ: OBS-018 — the peer's own shadow-list counts and over-blocking suspects.
    ShadowLists,
    Overblocking {
        limit: usize,
    },
    /// REQ: FLT-017 — the peer's per-workload counts (older peers don't know it).
    WorkloadCounts,
    /// REQ: OBS-009 — the peer's own hits per list (older peers don't know it).
    ListHits,
    /// REQ: OPS-011 (ADR-172) — this node's part of a cluster support package, made and redacted
    /// here under the key the asking node made for it. The answer is gzip-compressed JSON, not a
    /// plain JSON value. Older peers don't know the read and are listed as missing.
    SupportCollect {
        req: Box<telltale_api::model::SupportCollectRequest>,
    },
}

/// The reads that change the answering node: operational actions a user asked for on the
/// entry node (T7.1 pauses, T6.13 flushes).
fn changes_state(r: &Read) -> bool {
    matches!(
        r,
        Read::BlockingPause { .. } | Read::BlockingResume { .. } | Read::CacheFlush { .. }
    )
}

/// Answers a peer's read from this node's own data.
fn answer(b: &dyn Backend, r: Read) -> Result<Vec<u8>, String> {
    let text = |p: Problem| p.detail;
    match r {
        Read::Timeseries { step, from_s, to_s } => {
            serde_json::to_vec(&b.timeseries(step, from_s, to_s))
        }
        Read::Top {
            kind,
            hour,
            limit,
            client,
        } => serde_json::to_vec(&b.top(kind, hour, limit, client)),
        Read::TopInGroup {
            kind,
            hour,
            limit,
            group,
        } => serde_json::to_vec(&b.top_in_group(kind, hour, limit, &group).map_err(text)?),
        Read::TopClientsRolling { limit, group } => serde_json::to_vec(
            &b.top_clients_rolling(limit, group.as_deref())
                .map_err(text)?,
        ),
        Read::TopRange {
            kind,
            from_s,
            to_s,
            limit,
        } => serde_json::to_vec(&b.top_range(kind, from_s, to_s, limit)),
        Read::Latency { by, hour } => serde_json::to_vec(&b.latency(by, hour)),
        Read::LatencyHist { by, hour } => serde_json::to_vec(&b.latency_hists(by, hour)),
        Read::NewDevices { since_s } => serde_json::to_vec(&b.new_devices(since_s)),
        Read::Identities => serde_json::to_vec(&b.identities()),
        // REQ: FLT-006, CLU-002 (ADR-183) — no `recognition` for a peer: the entry node keeps its own.
        Read::Identity { client } => serde_json::to_vec(&b.identity_for_peer(&client).ok()),
        Read::ClientRhythm { client } => serde_json::to_vec(&b.client_rhythm(&client).ok()),
        Read::TailOpen { params } | Read::TailOpenNegated { params } => {
            serde_json::to_vec(&tail_open(b, &params).map_err(text)?)
        }
        Read::TailPoll { id } => serde_json::to_vec(&tail_poll(id)),
        Read::TailClose { id } => {
            tail_sessions().remove(&id);
            serde_json::to_vec(&true)
        }
        Read::Queries {
            params,
            from_us,
            to_us,
            limit,
        }
        | Read::QueriesNegated {
            params,
            from_us,
            to_us,
            limit,
        } => {
            // REQ: OBS-003 — at most the API's own page (the asking node sends the API's `limit`).
            let limit = limit.min(telltale_api::MAX_QUERY_PAGE);
            serde_json::to_vec(&b.queries(&params, from_us, to_us, limit).map_err(text)?)
        }
        Read::ConfigVersion => serde_json::to_vec(&b.config_version()),
        Read::ConfigEntries { kind } => serde_json::to_vec(&b.config_entries(kind.as_deref())),
        Read::CacheStats => serde_json::to_vec(&b.cache_stats()),
        Read::BlockingState => serde_json::to_vec(&b.blocking_state()),
        Read::BlockingPause { group, minutes } => serde_json::to_vec(
            &b.blocking_pause(group.as_deref(), minutes, None)
                .map_err(text)?,
        ),
        Read::BlockingResume { group } => {
            serde_json::to_vec(&b.blocking_resume(group.as_deref(), None).map_err(text)?)
        }
        Read::CacheEntries { sort, limit } => {
            serde_json::to_vec(&b.cache_entries(&sort, limit, None).map_err(text)?)
        }
        Read::CacheLookup { name } => serde_json::to_vec(&b.cache_lookup(&name).map_err(text)?),
        Read::CacheFlush { name, subtree } => serde_json::to_vec(
            &b.cache_flush(name.as_deref(), subtree, None)
                .map_err(text)?,
        ),
        Read::Anomalies { since_s } => serde_json::to_vec(&b.anomalies(since_s)),
        Read::Health => serde_json::to_vec(&b.health()),
        Read::Probes => serde_json::to_vec(&b.probes()),
        Read::SloParts { q } => serde_json::to_vec(&b.slo_parts(&q)),
        Read::HeatmapKey { q } => serde_json::to_vec(&b.heatmap_key(&q).map_err(text)?),
        Read::HeatmapNetwork { q } => serde_json::to_vec(&b.heatmap_network(&q)),
        Read::Exemplars {
            from_us,
            to_us,
            path,
        } => serde_json::to_vec(&b.exemplars(from_us, to_us, path.as_deref())),
        Read::Annotations { filter } => serde_json::to_vec(&b.annotations(&filter)),
        Read::UpstreamChecks => serde_json::to_vec(&b.upstream_checks()),
        Read::ShadowLists => serde_json::to_vec(&b.shadow_lists()),
        Read::Overblocking { limit } => serde_json::to_vec(&b.overblocking(limit)),
        Read::WorkloadCounts => serde_json::to_vec(&b.workload_counts()),
        Read::ListHits => serde_json::to_vec(&b.list_hits()),
        // REQ: OPS-011 (ADR-172) — already compressed bytes, not a JSON value.
        Read::SupportCollect { req } => return b.support_part(&req).map_err(text),
    }
    .map_err(|e| e.to_string())
}

/// What answers peers: reads from this node's local backend (on a blocking thread), and
/// forwarded writes when this node is the primary (T5.7).
#[allow(clippy::too_many_lines)] // one branch per call
pub(crate) fn rpc_handler(
    src: Arc<crate::http::Sources>,
    local: Shared,
    cluster: Arc<Cluster>,
) -> RpcHandler {
    Arc::new(move |peer, kind, body| {
        let (src, local, cluster) = (Arc::clone(&src), Arc::clone(&local), Arc::clone(&cluster));
        Box::pin(async move {
            // REQ: CLU-002, CLU-009 (ADR-054, ADR-058) — an ephemeral member serves no UI, so
            // nothing a user did arrives through it: it never forwards a write, and never
            // pauses blocking or flushes caches on other nodes. REQ: CLU-005 (T10.7, ADR-143) —
            // a peer the registry doesn't list is treated the same.
            let ephemeral = !cluster
                .identity
                .registry()
                .iter()
                .any(|n| n.node_id == peer && !n.ephemeral);
            if ephemeral && kind == crate::forward::KIND {
                return Err("an ephemeral member can't forward configuration writes".into());
            }
            if kind == telltale_cluster::failover::KIND {
                // REQ: CLU-005 — a vote request (ADR-056); the ballot is written to disk first.
                return tokio::task::spawn_blocking(move || {
                    telltale_cluster::failover::answer(&cluster, &peer, &body)
                })
                .await
                .map_err(|e| format!("vote worker failed: {e}"))?;
            }
            if kind == telltale_cluster::failover::HANDOVER_KIND {
                // REQ: CLU-005 (ADR-154) — a Git-managed node asks this emergency primary to hand
                // over; refused unless the asker is an eligible, Git-managed node that is up.
                return tokio::task::spawn_blocking(move || {
                    telltale_cluster::failover::answer_handover(&cluster, &peer)
                })
                .await
                .map_err(|e| format!("handover worker failed: {e}"))?;
            }
            if kind == telltale_cluster::renew::KIND {
                // REQ: CLU-001 — a peer renewing its node certificate (T5.4c).
                return tokio::task::spawn_blocking(move || {
                    telltale_cluster::renew::answer(&cluster, &peer, &body)
                })
                .await
                .map_err(|e| format!("renewal worker failed: {e}"))?;
            }
            if kind == crate::forward::KIND {
                return crate::forward::handle(src, local, cluster, peer, body).await;
            }
            if kind == crate::maintenance::KIND_SET || kind == crate::maintenance::KIND_CLEAR {
                // REQ: OPS-010 — another node asks this node to start or end maintenance (a
                // user acted there). An ephemeral member serves no UI: nothing comes through it.
                if ephemeral {
                    return Err("an ephemeral member can't change this node's state".into());
                }
                return tokio::task::spawn_blocking(move || {
                    crate::maintenance::handle(&src, &cluster, &peer, &body)
                })
                .await
                .map_err(|e| format!("maintenance worker failed: {e}"))?;
            }
            if kind == crate::node_update::KIND {
                // REQ: OPS-014 (ADR-182) — another node asks this node to install a version, or
                // reads its update state (a user or `telltale ctl upgrade` acted there). An
                // ephemeral member serves no UI: it may read, and nothing it asks is installed.
                return tokio::task::spawn_blocking(move || {
                    crate::node_update::handle(&src, &cluster, &peer, &body, ephemeral)
                })
                .await
                .map_err(|e| format!("update worker failed: {e}"))?;
            }
            if kind == crate::drill::KIND {
                // REQ: CLU-014 — a drill started or ended here (a user acted elsewhere; never
                // through an ephemeral member), a drill's window to record, or a read.
                return crate::drill::handle(src, cluster, peer, body, ephemeral).await;
            }
            if kind == crate::rollout::surface::KIND {
                // REQ: CLU-013 — a replica's rollout request (a user acted there). An ephemeral
                // member serves no UI: nothing comes through it.
                if ephemeral {
                    return Err("an ephemeral member can't run rollout commands".into());
                }
                return crate::rollout::surface::handle(src, local, cluster, peer, body).await;
            }
            if kind == crate::node_removal::KIND {
                // REQ: CLU-001 (ADR-155) — a replica's request to remove a member (a user acted
                // there). An ephemeral member serves no UI: nothing comes through it.
                if ephemeral {
                    return Err("an ephemeral member can't remove cluster members".into());
                }
                return crate::node_removal::handle(src, cluster, peer, body).await;
            }
            if kind == crate::devices::KIND {
                // REQ: CLU-002 (ADR-125) — the device names this node's routers and mDNS know.
                return crate::devices::own(&src.pipeline);
            }
            if kind == crate::kubernetes::KIND {
                // REQ: FLT-017 — asked for this node's workload table, or given the watcher's.
                // Resolver pods (ephemeral) never watch, so they never send one.
                return tokio::task::spawn_blocking(move || {
                    crate::kubernetes::handle(&src, &body, !ephemeral)
                })
                .await
                .map_err(|e| format!("workload table worker failed: {e}"))?;
            }
            if kind == crate::simulate::KIND {
                // REQ: OBS-024 — another node simulating a change over the cluster's logs (a
                // user acted there). An ephemeral member serves no UI (T10.7).
                if ephemeral {
                    return Err("an ephemeral member can't run simulations".into());
                }
                return crate::simulate::handle(src, body).await;
            }
            if kind == crate::ship::KIND || kind == crate::ship::ROLLUP_KIND {
                // REQ: CLU-007 (T10.7) — only from a member the registry lists: a pod that
                // expired and came back with its certificate rejoins first.
                let known = cluster
                    .identity
                    .registry()
                    .iter()
                    .any(|n| n.node_id == peer);
                if !known {
                    return Err("this node isn't in the cluster's registry".into());
                }
            }
            if kind == crate::ship::KIND {
                // REQ: CLU-007 — a node in ship mode delivering its query log.
                return tokio::task::spawn_blocking(move || {
                    let cfg = src.config.load();
                    let q = &cfg.telemetry.qlog;
                    crate::ship::receive(
                        cfg.node.data_dir.as_str(),
                        &peer,
                        &body,
                        q.retention_days,
                        q.retention_bytes.bytes(),
                        &src.ship,
                    )
                })
                .await
                .map_err(|e| format!("receive worker failed: {e}"))?;
            }
            if kind == crate::ship::ROLLUP_KIND {
                // REQ: CLU-007 (T9.3) — a node in ship mode delivering its minutes.
                return tokio::task::spawn_blocking(move || {
                    let db = src.rollups.as_ref().ok_or("this node keeps no rollups")?;
                    crate::ship::receive_rollups(db, &peer, &body)
                })
                .await
                .map_err(|e| format!("receive worker failed: {e}"))?;
            }
            if kind != KIND {
                return Err(format!("unknown call `{kind}`"));
            }
            let read: Read = serde_json::from_slice(&body).map_err(|e| format!("bad read: {e}"))?;
            if ephemeral && changes_state(&read) {
                return Err("an ephemeral member can't change this node's state".into());
            }
            if ephemeral && matches!(read, Read::SupportCollect { .. }) {
                // REQ: OPS-011 (ADR-172) — a part is redacted under the asker's key, which lets the
                // asker undo the address permutation: only a member we trust to ask may have one.
                return Err("an ephemeral member can't ask for a support package".into());
            }
            tokio::task::spawn_blocking(move || answer(local.as_ref(), read))
                .await
                .map_err(|e| format!("read worker failed: {e}"))?
        })
    })
}

/// REQ: CLU-002 (ADR-125) — rows a peer sent without a client name (an older build, or a
/// node that doesn't know the device yet) get this node's name for it, so one page never
/// names the same device two ways. A name the row came with stays.
fn name_rows(rows: &mut [telltale_api::model::QueryRow], name: impl Fn(IpAddr) -> Option<String>) {
    let mut known: std::collections::HashMap<String, Option<String>> =
        std::collections::HashMap::new();
    for r in rows.iter_mut().filter(|r| r.client_name.is_none()) {
        r.client_name = known
            .entry(r.client.clone())
            .or_insert_with(|| r.client.parse().ok().and_then(&name))
            .clone();
    }
}

/// REQ: OBS-014 — every node's findings as one list, newest first: one entry per ID (nodes
/// behind one load balancer can each find the same device's spike), listing who found it.
fn merge_findings(parts: Vec<(String, Vec<AnomalyFinding>)>) -> Vec<AnomalyFinding> {
    let mut by_id: std::collections::HashMap<String, AnomalyFinding> =
        std::collections::HashMap::new();
    for (label, items) in parts {
        for mut f in items {
            if let Some(seen) = by_id.get_mut(&f.id) {
                if !seen.nodes.contains(&label) {
                    seen.nodes.push(label.clone());
                }
                // REQ: OBS-038 — muted if any node's mute matched (the mutes are shared, so
                // nodes agree unless one hasn't applied a change yet).
                let muted_by = seen.muted_by.clone().or_else(|| f.muted_by.clone());
                // The node that saw the most of it tells the story.
                if f.observed > seen.observed {
                    let nodes = std::mem::take(&mut seen.nodes);
                    *seen = f;
                    seen.nodes = nodes;
                }
                seen.muted_by = muted_by;
            } else {
                f.nodes = vec![label.clone()];
                by_id.insert(f.id.clone(), f);
            }
        }
    }
    let mut out: Vec<AnomalyFinding> = by_id.into_values().collect();
    for f in &mut out {
        f.nodes.sort();
    }
    out.sort_by(|a, b| {
        b.window_start
            .cmp(&a.window_start)
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}

fn no_lease() -> Problem {
    Problem::unavailable("this primary can't reach a majority of voters, so it isn't taking changes")
        .hint("DNS keeps answering. Changes resume when a majority of voters is reachable again; see the Cluster page.")
}

/// REQ: CLU-002 (T9.2) — one row per key from every node's histogram.
fn merge_hists(parts: Vec<Vec<telltale_api::model::LatencyHist>>) -> Vec<LatencyRow> {
    let mut by_key: std::collections::BTreeMap<String, Vec<Vec<(u64, u64)>>> =
        std::collections::BTreeMap::new();
    for h in parts.into_iter().flatten() {
        by_key.entry(h.key).or_default().push(h.buckets);
    }
    by_key
        .into_iter()
        .filter_map(|(key, hs)| {
            let refs: Vec<&[(u64, u64)]> = hs.iter().map(Vec::as_slice).collect();
            telltale_telemetry::agg::merged_percentiles(&refs)
                .map(|p| crate::api_backend::latency_row(key, p))
        })
        .collect()
}

/// A peer's live tail opened for another node (T9.2): what matched, waiting to be polled.
struct TailSession {
    rx: tokio::sync::mpsc::Receiver<TailItem>,
    polled: std::time::Instant,
}

/// Unpolled this long, a session is closed (its subscriber stops).
const TAIL_IDLE: Duration = Duration::from_secs(15);
/// Remote tail sessions a node holds at most (as many as its own live tails).
const TAIL_SESSIONS: usize = 16;

#[derive(Debug, Serialize, Deserialize)]
struct TailBatch {
    /// The session is gone (expired, or the peer restarted): open a new one.
    gone: bool,
    items: Vec<TailItem>,
}

fn tail_sessions() -> std::sync::MutexGuard<'static, std::collections::HashMap<u64, TailSession>> {
    static S: std::sync::OnceLock<Mutex<std::collections::HashMap<u64, TailSession>>> =
        std::sync::OnceLock::new();
    let mut m = S
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    m.retain(|_, s| s.polled.elapsed() < TAIL_IDLE);
    m
}

fn tail_open(b: &dyn Backend, params: &TailParams) -> Result<u64, Problem> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    if tail_sessions().len() >= TAIL_SESSIONS {
        return Err(Problem::unavailable(
            "too many remote live tails on this node",
        ));
    }
    let rx = b.tail(params)?;
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    tail_sessions().insert(
        id,
        TailSession {
            rx,
            polled: std::time::Instant::now(),
        },
    );
    Ok(id)
}

fn tail_poll(id: u64) -> TailBatch {
    let mut m = tail_sessions();
    let Some(s) = m.get_mut(&id) else {
        return TailBatch {
            gone: true,
            items: Vec::new(),
        };
    };
    s.polled = std::time::Instant::now();
    let mut items = Vec::new();
    let mut gone = false;
    while items.len() < 2000 {
        match s.rx.try_recv() {
            Ok(it) => items.push(it),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                gone = true;
                break;
            }
        }
    }
    if gone {
        m.remove(&id);
    }
    TailBatch { gone, items }
}

/// Names the node a row came from (a peer's rows arrive unlabelled).
fn label_item(it: &mut TailItem, label: &str) {
    if let TailItem::Query(row) = it
        && row.node.is_none()
    {
        row.node = Some(label.to_owned());
    }
}

/// Polls one peer's tail session into `tx` until the subscriber goes away; reopens it when
/// the peer restarts, and backs off while it's unreachable (or too old to tail).
async fn remote_tail(
    cluster: Arc<Cluster>,
    label: String,
    peer: String,
    params: TailParams,
    tx: tokio::sync::mpsc::Sender<TailItem>,
) {
    const POLL: Duration = Duration::from_millis(500);
    let mut id: Option<u64> = None;
    let mut backoff = Duration::from_secs(1);
    loop {
        let read = match id {
            None if params.negates() => Read::TailOpenNegated {
                params: Box::new(params.clone()),
            },
            None => Read::TailOpen {
                params: Box::new(params.clone()),
            },
            Some(id) => Read::TailPoll { id },
        };
        let Ok(body) = serde_json::to_vec(&read) else {
            return;
        };
        let wait = match cluster
            .call(&peer, KIND, body, Duration::from_secs(3))
            .await
        {
            Ok(b) if id.is_none() => {
                id = serde_json::from_slice::<u64>(&b).ok();
                backoff = Duration::from_secs(1);
                POLL
            }
            Ok(b) => {
                if let Ok(batch) = serde_json::from_slice::<TailBatch>(&b) {
                    if batch.gone {
                        id = None;
                    }
                    for mut it in batch.items {
                        label_item(&mut it, &label);
                        if tx.send(it).await.is_err() {
                            return close_remote_tail(&cluster, &peer, id).await;
                        }
                    }
                } else {
                    id = None;
                }
                POLL
            }
            Err(_) => {
                id = None;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                backoff
            }
        };
        tokio::select! {
            () = tx.closed() => return close_remote_tail(&cluster, &peer, id).await,
            () = tokio::time::sleep(wait) => {}
        }
    }
}

async fn close_remote_tail(cluster: &Cluster, peer: &str, id: Option<u64>) {
    if let Some(id) = id
        && let Ok(body) = serde_json::to_vec(&Read::TailClose { id })
    {
        let _ = cluster.call(peer, KIND, body, Duration::from_secs(2)).await;
    }
}

/// Where configuration writes go (T5.7).
enum WriteRoute {
    /// Applied on this node: it's the primary, or the cluster is configured from Git (which
    /// refuses API writes on every node).
    Here,
    /// Forwarded to the primary (`None`: it isn't reachable now).
    Primary(Option<String>),
    /// Refused: this primary's lease lapsed (ADR-056).
    NoLease,
}

/// The API backend of a clustered node: federated stats and query log over `local`.
pub(crate) struct Federated {
    local: Shared,
    cluster: Arc<Cluster>,
    /// Nodes the latest federated read couldn't reach (site labels).
    missing: Mutex<Vec<String>>,
    /// REQ: AGT-011, CLU-002 (T7.3) — a read's `scope` narrowed to some nodes; `None` is the
    /// whole cluster.
    only: Option<Only>,
    /// REQ: CLU-004 (ADR-174) — the bounds its reads share: the process's ([`bridge::WAITS`]);
    /// a test's own in tests.
    limiter: &'static bridge::Limiter,
}

/// REQ: CLU-004 (ADR-174) — `telltale_federated_refused_total{reason}`: the federated reads this
/// node did not send, or (`bytes`) did not keep whole, since it started.
pub(crate) fn render_metrics(w: &mut telltale_telemetry::prom::PromWriter) {
    render_refusals(&bridge::WAITS, w);
}

fn render_refusals(limiter: &bridge::Limiter, w: &mut telltale_telemetry::prom::PromWriter) {
    let name = "telltale_federated_refused_total";
    let help = format!(
        "Federated reads this node refused since it started, by reason: waits (too many reads \
         were already waiting for slow nodes), spent (the budget of {} calls was spent), ceiling \
         (over {} calls, or over {} windows of time a node), bytes (sent, but an answer was \
         dropped: it would have passed the {} MiB of answers a read may hold or the {} MiB all \
         may). The nodes they were for are in missingNodes.",
        bridge::CALL_BUDGET,
        bridge::MAX_READ_CALLS,
        federation::TIMESERIES_MAX_WINDOWS,
        bridge::READ_BYTES >> 20,
        bridge::HELD_BYTES >> 20,
    );
    w.family(name, "counter", &help);
    for (why, n) in limiter.refusals() {
        w.sample(name, &[("reason", why.label())], n);
    }
}

/// The nodes a scoped read covers.
#[derive(Debug, Clone)]
struct Only {
    /// This node is in scope.
    me: bool,
    /// Peer node IDs in scope.
    peers: Vec<String>,
}

impl std::fmt::Debug for Federated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Federated").finish_non_exhaustive()
    }
}

impl Federated {
    pub(crate) fn new(local: Shared, cluster: Arc<Cluster>) -> Self {
        Self {
            local,
            cluster,
            missing: Mutex::new(Vec::new()),
            only: None,
            limiter: &bridge::WAITS,
        }
    }

    /// REQ: OPS-010 — the same reads without the nodes `ids` names (the alert task leaves
    /// nodes in maintenance out of cluster-wide shares like SERVFAIL).
    pub(crate) fn excluding(&self, ids: &std::collections::HashSet<String>) -> Self {
        let me = !ids.contains(&self.cluster.identity.meta.node_id);
        let peers = self
            .cluster
            .members()
            .into_iter()
            .map(|m| m.node_id)
            .filter(|p| !ids.contains(p))
            .collect();
        Self {
            local: Arc::clone(&self.local),
            cluster: Arc::clone(&self.cluster),
            missing: Mutex::new(Vec::new()),
            only: Some(Only { me, peers }),
            limiter: self.limiter,
        }
    }

    /// Whether this node's own data is in the read's scope.
    fn with_me(&self) -> bool {
        self.only.as_ref().is_none_or(|o| o.me)
    }

    /// Whether a peer is in the read's scope.
    fn in_scope(&self, node_id: &str) -> bool {
        self.only
            .as_ref()
            .is_none_or(|o| o.peers.iter().any(|p| p == node_id))
    }

    /// The reachable peers in the read's scope.
    fn peers(&self) -> Vec<String> {
        self.cluster
            .reachable_peers()
            .into_iter()
            .filter(|p| self.in_scope(p))
            .collect()
    }

    /// REQ: AGT-011, CLU-002 (T7.3) — the nodes `site:<name>` or `node:<id, site, or pod>`
    /// names; an unknown one is the caller's mistake.
    fn narrow(&self, scope: &str) -> Result<Only, Problem> {
        let me = &self.cluster.identity.meta;
        if let Some(site) = scope.strip_prefix("site:") {
            let peers: Vec<String> = self
                .cluster
                .members()
                .into_iter()
                .filter(|m| m.site == site)
                .map(|m| m.node_id)
                .collect();
            let mine = me.site == site;
            if peers.is_empty() && !mine {
                return Err(
                    Problem::invalid(format!("`scope`: no site `{site}` in this cluster"))
                        .hint("The Cluster page (or cluster_status) lists each node's site."),
                );
            }
            return Ok(Only { me: mine, peers });
        }
        let node = scope.strip_prefix("node:").unwrap_or(scope);
        Ok(match self.resolve_node(node)? {
            None => Only {
                me: true,
                peers: Vec::new(),
            },
            Some(peer) => Only {
                me: false,
                peers: vec![peer],
            },
        })
    }

    fn label_of(&self, node: &str) -> String {
        self.cluster
            .members()
            .into_iter()
            .find(|m| m.node_id == node)
            .map(|m| if m.pod.is_empty() { m.site } else { m.pod })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| node.to_owned())
    }

    /// Where this node's configuration writes go.
    fn write_route(&self) -> WriteRoute {
        if self.cluster.is_primary() && !self.cluster.may_publish() {
            return WriteRoute::NoLease;
        }
        if self.cluster.is_primary()
            || self.cluster.identity.reload().meta.config_authority == "gitops"
        {
            return WriteRoute::Here;
        }
        WriteRoute::Primary(self.cluster.reachable_primary())
    }

    /// REQ: CLU-002, CLU-004 (ADR-174) — starts one RPC per `(peer, body)` as a task on `rt` and
    /// returns at once; the caller waits with [`bridge::Pending::wait`] on its own thread.
    fn start_calls(
        &self,
        rt: &tokio::runtime::Handle,
        calls: Vec<(String, Vec<u8>)>,
        timeout: Duration,
    ) -> bridge::Pending {
        let calls = calls
            .into_iter()
            .map(|(peer, body)| {
                let (cluster, to) = (Arc::clone(&self.cluster), peer.clone());
                (
                    peer,
                    async move { cluster.call(&to, KIND, body, timeout).await },
                )
            })
            .collect();
        bridge::start(self.limiter, rt, calls, timeout)
    }

    /// One RPC to one peer from synchronous code; `None` without a runtime. REQ: CLU-004
    /// (ADR-174) — the wait is `timeout` and a grace at most, whatever the runtime is doing, and
    /// never needs a worker: a peer the runtime couldn't ask in time is "didn't answer".
    fn call_one(
        &self,
        peer: &str,
        read: &Read,
        timeout: Duration,
    ) -> Option<Result<Vec<u8>, String>> {
        let body = serde_json::to_vec(read).ok()?;
        let rt = tokio::runtime::Handle::try_current().ok()?;
        self.start_calls(&rt, vec![(peer.to_owned(), body)], timeout)
            .wait()
            .pop()
            .map(|(_, answer)| answer)
    }

    fn own_label(&self) -> String {
        // T6.14 — Kubernetes pods share a site: their pod name tells them apart.
        let pod = self.cluster.local_state().pod;
        if !pod.is_empty() {
            return pod;
        }
        let m = &self.cluster.identity.meta;
        if m.site.is_empty() {
            m.node_id.clone()
        } else {
            m.site.clone()
        }
    }

    /// Sends `reads` (one per peer) concurrently and waits at most [`DEADLINE`] and the bridge's
    /// grace (REQ: CLU-004, ADR-174: on this thread, never on a worker). Records which known
    /// nodes didn't answer: those not connected, and those the runtime didn't get an answer from
    /// in time.
    fn gather(&self, reads: Vec<(String, Read)>) -> Vec<(String, Vec<u8>)> {
        let mut missing = self.unconnected();
        let calls: Vec<(String, Vec<u8>)> = reads
            .into_iter()
            .filter_map(|(peer, r)| serde_json::to_vec(&r).ok().map(|b| (peer, b)))
            .collect();
        // The calls run as tasks on the runtime and this thread waits on a `std` channel, so it
        // works from any caller: a blocking-pool thread, a worker (the wait then costs its
        // deadline: nothing else runs on it), or a current-thread runtime.
        let answers = match tokio::runtime::Handle::try_current() {
            Ok(rt) if !calls.is_empty() => self.start_calls(&rt, calls, DEADLINE).wait(),
            _ => Vec::new(),
        };
        let mut ok = Vec::new();
        // A peer is labelled once, however many of its calls failed (a refused range of time is
        // hundreds of calls to each peer, and a label reads the member list).
        let mut failed = std::collections::BTreeSet::new();
        for (peer, r) in answers {
            match r {
                Ok(body) => ok.push((peer, body)),
                Err(e) => {
                    tracing::debug!(peer, error = %e, "federated read failed");
                    failed.insert(peer);
                }
            }
        }
        missing.extend(failed.iter().map(|peer| self.label_of(peer)));
        self.record_missing(missing);
        ok
    }

    /// The in-scope members that aren't connected, by site (or ID).
    fn unconnected(&self) -> Vec<String> {
        self.cluster
            .members()
            .into_iter()
            .filter(|m| !m.connected && self.in_scope(&m.node_id))
            .map(|m| if m.site.is_empty() { m.node_id } else { m.site })
            .collect()
    }

    /// Sets the list of nodes that didn't answer, all at once: a reader never sees half of it.
    fn record_missing(&self, mut missing: Vec<String>) {
        missing.sort();
        missing.dedup();
        *self.missing.lock().unwrap_or_else(PoisonError::into_inner) = missing;
    }

    /// Asks every reachable peer the same read; decoded answers with each peer's label.
    fn everyone_labelled<T: serde::de::DeserializeOwned>(
        &self,
        read: impl Fn() -> Read,
    ) -> Vec<(String, T)> {
        let reads = self.peers().into_iter().map(|p| (p, read())).collect();
        self.gather(reads)
            .into_iter()
            .filter_map(|(peer, body)| {
                serde_json::from_slice(&body)
                    .ok()
                    .map(|v| (self.label_of(&peer), v))
            })
            .collect()
    }

    /// A node named by site or ID: `None` for this node, `Some(peer ID)` for a peer.
    fn resolve_node(&self, node: &str) -> Result<Option<String>, Problem> {
        let me = &self.cluster.identity.meta;
        if node == me.node_id || node == self.own_label() {
            return Ok(None);
        }
        self.cluster
            .members()
            .into_iter()
            .find(|m| {
                m.node_id == node
                    || (!m.pod.is_empty() && m.pod == node)
                    || (!m.site.is_empty() && m.site == node)
            })
            .map(|m| Some(m.node_id))
            .ok_or_else(|| Problem::invalid(format!("`node`: no cluster node `{node}`")))
    }

    /// REQ: OPS-010, OPS-014 — where a call about `node`'s own state (maintenance, an update)
    /// goes: here (`None`, for `local` and this node), a peer, or a problem: `node_unreachable`
    /// with `unreachable_hint` for a member of the registry this node hasn't heard from since it
    /// started, `node_unknown` otherwise.
    fn own_state_node(
        &self,
        node: &str,
        unreachable_hint: &'static str,
    ) -> Result<Option<String>, Problem> {
        use telltale_api::problem::Code;
        if node == "local" {
            return Ok(None);
        }
        self.resolve_node(node).map_err(|_| {
            if self
                .cluster
                .identity
                .registry()
                .iter()
                .any(|n| n.node_id == node)
            {
                Problem::new(
                    Code::NodeUnreachable,
                    format!("{node} isn't reachable over the cluster channel"),
                )
                .hint(unreachable_hint)
            } else {
                Problem::new(Code::NodeUnknown, format!("no cluster node `{node}`"))
                    .hint("Use `local`, or a node's ID, site, or pod name from the Cluster page (or cluster_status).")
            }
        })
    }

    /// REQ: CLU-014 — where a drill request for `node` goes: here (`None`), a peer, or a
    /// problem (`node_unknown`, or `node_unreachable` for a registered node not heard from).
    fn drill_node(&self, node: &str) -> Result<Option<String>, Problem> {
        use telltale_api::problem::Code;
        if node == "local" {
            return Ok(None);
        }
        self.resolve_node(node).map_err(|_| {
            if self
                .cluster
                .identity
                .registry()
                .iter()
                .any(|n| n.node_id == node)
            {
                Problem::new(
                    Code::NodeUnreachable,
                    format!("{node} isn't reachable over the cluster channel"),
                )
                .hint("A drill is the node's own state, so the node must be up to take it.")
            } else {
                Problem::new(Code::NodeUnknown, format!("no cluster node `{node}`"))
                    .hint("Use `local`, or a node's ID, site, or pod name from the Cluster page.")
            }
        })
    }

    /// T7.1 — runs `local` here and `read` on every reachable peer (or only on `node`), each
    /// row labelled with its node; connected peers that don't answer are listed with an error.
    fn blocking_fan(
        &self,
        node: Option<&str>,
        local: impl FnOnce(&dyn Backend) -> Result<Vec<telltale_api::model::BlockingNode>, Problem>,
        read: impl Fn() -> Read,
    ) -> Result<Vec<telltale_api::model::BlockingNode>, Problem> {
        use telltale_api::model::BlockingNode;
        let label = |mut v: Vec<BlockingNode>, l: &str| {
            for r in &mut v {
                r.node = Some(l.to_owned());
            }
            v
        };
        let failed = |l: String, e: String| BlockingNode {
            node: Some(l),
            error: Some(e),
            ..BlockingNode::default()
        };
        match node.map(|n| self.resolve_node(n)).transpose()? {
            Some(None) => Ok(label(local(self.local.as_ref())?, &self.own_label())),
            Some(Some(peer)) => {
                let l = self.label_of(&peer);
                Ok(match self.call_one(&peer, &read(), DEADLINE) {
                    Some(Ok(body)) => label(serde_json::from_slice(&body).unwrap_or_default(), &l),
                    Some(Err(e)) => vec![failed(l, e)],
                    None => vec![failed(l, "no runtime".into())],
                })
            }
            None => {
                let mut out = label(local(self.local.as_ref())?, &self.own_label());
                let answered = self.everyone_labelled::<Vec<BlockingNode>>(read);
                let names: Vec<String> = answered.iter().map(|(l, _)| l.clone()).collect();
                for (l, v) in answered {
                    out.extend(label(v, &l));
                }
                for m in self.cluster.members().into_iter().filter(|m| m.connected) {
                    let l = self.label_of(&m.node_id);
                    if !names.contains(&l) {
                        out.push(failed(
                            l,
                            "didn't answer (an older version can't pause)".into(),
                        ));
                    }
                }
                Ok(out)
            }
        }
    }

    /// REQ: CLU-002 — `peers`' time buckets over `[from_s, to_s)`, asked in windows of at most
    /// [`federation::TIMESERIES_CHUNK`] buckets, all at once: one answer for a busy node's day
    /// of minutes is over the cluster channel's 1 MiB frame, and was dropped whole. Returns
    /// each answered window's buckets, and each peer that answered any window (`true` when it
    /// answered every one). Windows that fail list the peer in `missingNodes`.
    ///
    /// REQ: CLU-004, CLU-002 (ADR-174, final review F1) — a range of more than
    /// [`federation::TIMESERIES_MAX_WINDOWS`] windows is asked of no peer: they are listed in
    /// `missingNodes` (this node's own data and shipped minutes still answer), and the log says
    /// so. The longest range any step documents is under half that.
    fn peer_timeseries(
        &self,
        peers: Vec<String>,
        step: Step,
        from_s: u64,
        to_s: u64,
    ) -> (Vec<Vec<TimeBucket>>, Vec<(String, bool)>) {
        // With nobody to ask there is nothing to chunk.
        let windows = if peers.is_empty() {
            Vec::new()
        } else if let Some(w) = federation::timeseries_chunks(step, from_s, to_s) {
            w
        } else {
            self.limiter.refused(bridge::Refused::TooBig);
            // REQ: CLU-004 (ADR-174) — lists who isn't connected, as a read does, and the peers
            // that weren't asked as ones that failed would be, in one step: two writes let
            // another request's reader see the list without the peers.
            let mut missing = self.unconnected();
            missing.extend(peers.iter().map(|p| self.label_of(p)));
            self.record_missing(missing);
            return (Vec::new(), Vec::new());
        };
        let reads = peers
            .iter()
            .flat_map(|p| {
                windows.iter().map(move |&(from_s, to_s)| {
                    (p.clone(), Read::Timeseries { step, from_s, to_s })
                })
            })
            .collect();
        let mut parts = Vec::new();
        let mut got: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (peer, body) in self.gather(reads) {
            if let Ok(v) = serde_json::from_slice::<Vec<TimeBucket>>(&body) {
                parts.push(v);
                *got.entry(peer).or_default() += 1;
            }
        }
        let answered = peers
            .into_iter()
            .filter_map(|p| got.get(&p).map(|n| (p, *n == windows.len())))
            .collect();
        (parts, answered)
    }

    /// Asks every reachable peer the same read; decoded answers.
    fn everyone<T: serde::de::DeserializeOwned>(&self, read: impl Fn() -> Read) -> Vec<T> {
        let reads = self.peers().into_iter().map(|p| (p, read())).collect();
        self.gather(reads)
            .into_iter()
            .filter_map(|(peer, body)| match serde_json::from_slice(&body) {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::debug!(peer, error = %e, "undecodable federated answer");
                    None
                }
            })
            .collect()
    }
}

impl Backend for Federated {
    fn now_unix_seconds(&self) -> u64 {
        self.local.now_unix_seconds()
    }
    fn system_info(&self) -> SystemInfo {
        self.local.system_info()
    }
    // REQ: AGT-011, CLU-002 (T7.3) — the same reads over some of the nodes.
    fn scoped(&self, scope: &str) -> Result<Shared, Problem> {
        let only = self.narrow(scope)?;
        if only.me && only.peers.is_empty() {
            return Ok(Arc::clone(&self.local));
        }
        Ok(Arc::new(Self {
            local: Arc::clone(&self.local),
            cluster: Arc::clone(&self.cluster),
            missing: Mutex::new(Vec::new()),
            only: Some(only),
            limiter: self.limiter,
        }))
    }
    fn local(&self) -> Option<Shared> {
        Some(Arc::clone(&self.local))
    }
    fn missing_nodes(&self) -> Vec<String> {
        self.missing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    fn promote(&self, req: PromoteRequest, by: String) -> Result<ClusterView, Problem> {
        self.local.promote(req, by)
    }
    // The services catalog is compiled in: the same everywhere.
    fn services(&self) -> Vec<telltale_api::model::ServiceInfo> {
        self.local.services()
    }
    // Updates are per node: the one serving the UI checks.
    fn check_updates(
        &self,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::UpdateStatus, Problem>> {
        self.local.check_updates()
    }
    fn promote_plan(
        &self,
        req: &PromoteRequest,
    ) -> Result<telltale_api::model::PromotePlan, Problem> {
        self.local.promote_plan(req)
    }
    fn cluster(&self) -> ClusterView {
        self.local.cluster()
    }
    fn git_hook(&self, signature: Option<String>, body: Vec<u8>) -> Result<(), Problem> {
        self.local.git_hook(signature, body)
    }
    // A backup is of this node (ADR-063).
    fn backup(&self) -> Result<(String, Vec<u8>), Problem> {
        self.local.backup()
    }
    // REQ: OPS-011 (ADR-156) — a support package is of this node: its own log and state, redacted on
    // it. With `cluster` (ADR-172) every reachable node makes and redacts its own part under one key
    // made here, and this node puts them together.
    fn support_package(
        &self,
        req: &telltale_api::model::SupportPackageRequest,
        dry_run: bool,
    ) -> Result<telltale_api::SupportPackageOutput, Problem> {
        if req.cluster {
            return self.cluster_support(req, dry_run);
        }
        self.local.support_package(req, dry_run)
    }
    // REQ: OPS-011 (ADR-172) — this node's part, for the node that is putting a package together.
    fn support_part(
        &self,
        req: &telltale_api::model::SupportCollectRequest,
    ) -> Result<Vec<u8>, Problem> {
        self.local.support_part(req)
    }
    fn support_map(&self, id: &str) -> Option<String> {
        self.local.support_map(id)
    }
    // REQ: OBS-016 — the objectives are configuration, the same on every node; the status is
    // worked out from the federated time buckets.
    fn slo_settings(&self) -> telltale_api::slo::Settings {
        self.local.slo_settings()
    }

    // REQ: OBS-030 (ADR-130) — every node's exemplars, labelled.
    fn exemplars(
        &self,
        from_us: u64,
        to_us: u64,
        path: Option<&str>,
    ) -> Vec<telltale_api::latency_heatmap::LatencyExemplar> {
        let own = self.own_label();
        let mut out: Vec<_> = if self.with_me() {
            self.local
                .exemplars(from_us, to_us, path)
                .into_iter()
                .map(|mut x| {
                    x.node = Some(own.clone());
                    x
                })
                .collect()
        } else {
            Vec::new()
        };
        for (label, rows) in self
            .everyone_labelled::<Vec<telltale_api::latency_heatmap::LatencyExemplar>>(|| {
                Read::Exemplars {
                    from_us,
                    to_us,
                    path: path.map(str::to_owned),
                }
            })
        {
            out.extend(rows.into_iter().map(|mut x| {
                x.node = Some(label.clone());
                x
            }));
        }
        out
    }
    // REQ: OBS-032 — the setting is the cluster's (replicated configuration): this node's.
    fn qlog_retention_days(&self) -> u32 {
        self.local.qlog_retention_days()
    }
    fn qlog_privacy_level(&self) -> u8 {
        self.local.qlog_privacy_level()
    }

    // REQ: OBS-029 (ADR-129) — every node's hours for a device or a name, summed; an hour is
    // covered when every node that answered had the key in its list.
    fn heatmap_key(
        &self,
        q: &telltale_api::heatmap::KeyQuery,
    ) -> Result<telltale_api::heatmap::KeyPart, Problem> {
        let n = usize::try_from((q.to_s - q.from_s).div_ceil(3600)).unwrap_or(0);
        let mut parts = Vec::new();
        if self.with_me() {
            parts.push(self.local.heatmap_key(q)?);
        }
        for (_, p) in self.everyone_labelled::<telltale_api::heatmap::KeyPart>(|| {
            Read::HeatmapKey { q: q.clone() }
        }) {
            parts.push(p);
        }
        Ok(telltale_api::heatmap::KeyPart::merge(parts, n))
    }
    // REQ: OBS-029, CLU-002 — every node's network slots, summed. Each peer sums its own
    // minutes into slots: a week of its minute buckets is several megabytes, over the cluster
    // channel's 1 MiB frame, so asking for those dropped every busy peer from the 15-minute
    // grid ("didn't answer"). A peer on an older build that doesn't know the read gives its
    // time buckets instead, a few hours at a time (`peer_timeseries`).
    fn heatmap_network(&self, q: &telltale_api::heatmap::NetworkQuery) -> Vec<u64> {
        use telltale_api::heatmap::add_slots;
        let mut out = vec![0; q.slot_count()];
        let peers = self.peers();
        let answers = self.gather(
            peers
                .iter()
                .map(|p| (p.clone(), Read::HeatmapNetwork { q: q.clone() }))
                .collect(),
        );
        let mut live: Vec<String> = vec![self.cluster.identity.meta.node_id.clone()];
        let mut answered = std::collections::HashSet::new();
        for (peer, body) in answers {
            if let Ok(v) = serde_json::from_slice::<Vec<u64>>(&body) {
                add_slots(&mut out, &v);
                answered.insert(peer.clone());
                live.push(peer);
            }
        }
        let missing_first = self.missing_nodes();
        let older: Vec<String> = peers
            .into_iter()
            .filter(|p| !answered.contains(p) && missing_first.contains(&self.label_of(p)))
            .collect();
        if !older.is_empty() {
            let (parts, answered) = self.peer_timeseries(older, q.step(), q.from_s, q.to_s);
            for buckets in parts {
                add_slots(&mut out, &q.slots_of(&buckets));
            }
            let recovered: Vec<String> = answered
                .iter()
                .filter(|(_, whole)| *whole)
                .map(|(p, _)| self.label_of(p))
                .collect();
            live.extend(answered.into_iter().map(|(p, _)| p));
            *self.missing.lock().unwrap_or_else(PoisonError::into_inner) = missing_first
                .into_iter()
                .filter(|m| !recovered.contains(m))
                .collect();
        }
        if self.with_me() {
            add_slots(&mut out, &self.local.heatmap_network(q));
        }
        // REQ: CLU-007 (T9.3) — minutes shipped here by nodes that aren't answering, for the
        // whole cluster's view only (as `timeseries`).
        if self.only.is_none() {
            let shipped = self
                .local
                .shipped_timeseries(q.step(), q.from_s, q.to_s, &live);
            add_slots(&mut out, &q.slots_of(&shipped));
        }
        out
    }
    // REQ: OBS-027 (ADR-127) — every node's part, labelled. A peer on an older build that can't
    // answer gives its hour buckets instead (a timeline, no lists: partial, not missing). Pods
    // that shipped minutes here and aren't answering count from those, for the whole cluster.
    fn slo_parts(
        &self,
        q: &telltale_api::attribution::PartQuery,
    ) -> Vec<telltale_api::attribution::Part> {
        let mine = telltale_api::attribution::PartQuery {
            live: Vec::new(),
            ..q.clone()
        };
        let peers = self.peers();
        let answers = self.gather(
            peers
                .iter()
                .map(|p| (p.clone(), Read::SloParts { q: mine.clone() }))
                .collect(),
        );
        let mut live: Vec<String> = vec![self.cluster.identity.meta.node_id.clone()];
        let mut out = Vec::new();
        let mut answered = std::collections::HashSet::new();
        for (peer, body) in answers {
            if let Ok(parts) = serde_json::from_slice::<Vec<telltale_api::attribution::Part>>(&body)
            {
                for mut p in parts {
                    p.node = Some(
                        p.node
                            .map_or_else(|| self.label_of(&peer), |id| self.label_of(&id)),
                    );
                    out.push(p);
                }
                answered.insert(peer.clone());
                live.push(peer);
            }
        }
        let missing_first = self.missing_nodes();
        // Older peers: their hour buckets.
        let older: Vec<String> = peers
            .into_iter()
            .filter(|p| !answered.contains(p) && missing_first.contains(&self.label_of(p)))
            .collect();
        let mut recovered = Vec::new();
        if !older.is_empty() {
            let reads = older
                .iter()
                .map(|p| {
                    (
                        p.clone(),
                        Read::Timeseries {
                            step: Step::Hour,
                            from_s: q.from_s,
                            to_s: q.to_s,
                        },
                    )
                })
                .collect();
            for (peer, body) in self.gather(reads) {
                if let Ok(hours) = serde_json::from_slice::<Vec<TimeBucket>>(&body) {
                    recovered.push(self.label_of(&peer));
                    out.push(telltale_api::attribution::Part {
                        node: Some(self.label_of(&peer)),
                        hours,
                        partial: true,
                        ..telltale_api::attribution::Part::default()
                    });
                    live.push(peer);
                }
            }
        }
        *self.missing.lock().unwrap_or_else(PoisonError::into_inner) = missing_first
            .into_iter()
            .filter(|m| !recovered.contains(m))
            .collect();
        if self.with_me() {
            let local_q = telltale_api::attribution::PartQuery {
                live: if self.only.is_none() {
                    live
                } else {
                    Vec::new()
                },
                ..q.clone()
            };
            for mut p in self.local.slo_parts(&local_q) {
                p.node = Some(
                    p.node
                        .map_or_else(|| self.own_label(), |id| self.label_of(&id)),
                );
                out.push(p);
            }
        }
        out
    }

    // REQ: CLU-002 — counters sum across nodes.
    fn timeseries(&self, step: Step, from_s: u64, to_s: u64) -> Vec<TimeBucket> {
        let (mut parts, answered) = self.peer_timeseries(self.peers(), step, from_s, to_s);
        let mut live: Vec<String> = vec![self.cluster.identity.meta.node_id.clone()];
        live.extend(answered.into_iter().map(|(p, _)| p));
        if self.with_me() {
            parts.push(self.local.timeseries(step, from_s, to_s));
        }
        // REQ: CLU-007 (T9.3) — minutes shipped here by nodes that aren't answering (an
        // ephemeral pod that restarted), for the whole cluster's view only.
        if self.only.is_none() {
            parts.push(self.local.shipped_timeseries(step, from_s, to_s, &live));
        }
        federation::merge_timeseries(parts)
    }
    // REQ: OBS-008, CLU-002 (T9.2) — the live tail covers the cluster: a session on each
    // peer (same filter, a share of the rate cap), polled twice a second.
    fn tail(&self, p: &TailParams) -> Result<tokio::sync::mpsc::Receiver<TailItem>, Problem> {
        let reachable = self.cluster.reachable_peers();
        let (me, peers): (bool, Vec<String>) = match p.scope.as_deref() {
            Some("node:local") => return self.local.tail(p),
            None | Some("" | "cluster") => (true, reachable),
            Some(s) => {
                let o = self.narrow(s)?;
                (
                    o.me,
                    o.peers
                        .into_iter()
                        .filter(|x| reachable.contains(x))
                        .collect(),
                )
            }
        };
        if peers.is_empty() {
            return self.local.tail(p);
        }
        let n = u32::try_from(peers.len() + usize::from(me)).unwrap_or(u32::MAX);
        let mut share = p.clone();
        share.rate = Some((p.rate.unwrap_or(500) / n).max(1));
        share.scope = Some("node:local".to_owned());
        let (tx, rx) = tokio::sync::mpsc::channel(4096);
        if me {
            let mut local = self.local.tail(&share)?;
            let (tx, label) = (tx.clone(), self.own_label());
            tokio::spawn(async move {
                while let Some(mut it) = local.recv().await {
                    label_item(&mut it, &label);
                    if tx.send(it).await.is_err() {
                        return;
                    }
                }
            });
        }
        for peer in peers {
            tokio::spawn(remote_tail(
                Arc::clone(&self.cluster),
                self.label_of(&peer),
                peer,
                share.clone(),
                tx.clone(),
            ));
        }
        Ok(rx)
    }
    // REQ: OBS-012 — Space-Saving lists merge by key.
    fn top(&self, kind: TopKind, hour: Hour, limit: usize, client: Option<IpAddr>) -> Vec<TopItem> {
        let mut parts: Vec<Vec<TopItem>> = self.everyone(|| Read::Top {
            kind,
            hour,
            limit,
            client,
        });
        if self.with_me() {
            parts.push(self.local.top(kind, hour, limit, client));
        }
        federation::merge_top(parts, limit)
    }
    // REQ: OBS-004 (ADR-160) — each node sums its own hours; the lists merge by key. A peer
    // one version behind doesn't know the read and is listed in `missingNodes`.
    fn top_range(&self, kind: TopKind, from_s: u64, to_s: u64, limit: usize) -> Vec<TopItem> {
        let mut parts: Vec<Vec<TopItem>> = self.everyone(|| Read::TopRange {
            kind,
            from_s,
            to_s,
            limit,
        });
        if self.with_me() {
            parts.push(self.local.top_range(kind, from_s, to_s, limit));
        }
        federation::merge_top(parts, limit)
    }
    fn top_in_group(
        &self,
        kind: TopKind,
        hour: Hour,
        limit: usize,
        group: &str,
    ) -> Result<Vec<TopItem>, Problem> {
        let own = if self.with_me() {
            self.local.top_in_group(kind, hour, limit, group)?
        } else {
            Vec::new()
        };
        let mut parts: Vec<Vec<TopItem>> = self.everyone(|| Read::TopInGroup {
            kind,
            hour,
            limit,
            group: group.to_owned(),
        });
        parts.push(own);
        Ok(federation::merge_top(parts, limit))
    }
    // REQ: API-005 (ADR-158) — exact counts that add up per client. Each node sends every
    // client it has (not just its top `limit`), so a client low on one node's list isn't
    // undercounted; the merged list is cut to `limit` afterwards.
    fn top_clients_rolling(
        &self,
        limit: usize,
        group: Option<&str>,
    ) -> Result<Vec<TopItem>, Problem> {
        let all = telltale_telemetry::last_hour::MAX_CLIENTS;
        let own = if self.with_me() {
            self.local.top_clients_rolling(all, group)?
        } else {
            Vec::new()
        };
        let mut parts: Vec<Vec<TopItem>> = self.everyone(|| Read::TopClientsRolling {
            limit: all,
            group: group.map(str::to_owned),
        });
        parts.push(own);
        Ok(federation::merge_top(parts, limit))
    }
    // REQ: CLU-002 (T9.2) — exact: the nodes' histograms merged; a peer on an older build
    // answers percentiles, blended approximately as before.
    fn latency(&self, by: LatencyBy, hour: Hour) -> Vec<LatencyRow> {
        let peers = self.peers();
        let answers = self.gather(
            peers
                .iter()
                .map(|p| (p.clone(), Read::LatencyHist { by, hour }))
                .collect(),
        );
        let mut hists: Vec<Vec<telltale_api::model::LatencyHist>> = Vec::new();
        let mut answered = std::collections::HashSet::new();
        for (peer, body) in answers {
            if let Ok(v) = serde_json::from_slice(&body) {
                hists.push(v);
                answered.insert(peer);
            }
        }
        if self.with_me() {
            hists.push(self.local.latency_hists(by, hour));
        }
        let mut rows = merge_hists(hists);
        let older: Vec<(String, Read)> = peers
            .into_iter()
            .filter(|p| !answered.contains(p))
            .map(|p| (p, Read::Latency { by, hour }))
            .collect();
        if !older.is_empty() {
            let mut parts: Vec<Vec<LatencyRow>> = self
                .gather(older)
                .into_iter()
                .filter_map(|(_, b)| serde_json::from_slice(&b).ok())
                .collect();
            if !parts.is_empty() {
                parts.push(rows);
                rows = federation::merge_latency(parts);
            }
        }
        rows
    }

    // REQ: CLU-002 — one query log across nodes, newest first, paged with a cursor that
    // remembers where each node stopped.
    fn queries(
        &self,
        q: &QueryParams,
        from_us: u64,
        to_us: u64,
        limit: usize,
    ) -> Result<QueryPage, Problem> {
        let prev: Bounds = match q.cursor.as_deref() {
            None => Bounds::new(),
            Some(c) => federation::decode_cursor(Some(c)).ok_or_else(|| {
                Problem::invalid("`cursor`: not a cursor from this API")
                    .hint("Pass the nextCursor value from the previous page unchanged.")
            })?,
        };
        let until = |node: &str| federation::until(&prev, node, to_us);
        let mut params = q.clone();
        params.cursor = None;
        let me = self.cluster.identity.meta.node_id.clone();
        let reads: Vec<(String, Read)> = self
            .peers()
            .into_iter()
            .filter_map(|p| {
                let to = until(&p)?;
                let (params, from_us, to_us) = (Box::new(params.clone()), from_us, to);
                let read = if params.negates() {
                    Read::QueriesNegated {
                        params,
                        from_us,
                        to_us,
                        limit,
                    }
                } else {
                    Read::Queries {
                        params,
                        from_us,
                        to_us,
                        limit,
                    }
                };
                Some((p, read))
            })
            .collect();
        let mut pages = Vec::new();
        for (peer, body) in self.gather(reads) {
            if let Ok(page) = serde_json::from_slice::<QueryPage>(&body) {
                pages.push(NodePage {
                    label: self.label_of(&peer),
                    node: peer,
                    page,
                    asked: limit,
                });
            }
        }
        let mut local_error = None;
        if let Some(to) = until(&me).filter(|_| self.with_me()) {
            match self.local.queries(&params, from_us, to, limit) {
                Ok(page) => pages.push(NodePage {
                    node: me,
                    label: self.own_label(),
                    page,
                    asked: limit,
                }),
                Err(e) => local_error = Some(e),
            }
        }
        let mut page = match local_error {
            // Only this node can say why its own log is unavailable; peers' rows still help.
            Some(e) if pages.is_empty() => return Err(e),
            Some(_) => {
                self.missing
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(self.own_label());
                federation::merge_queries(pages, limit, &prev)
            }
            None => federation::merge_queries(pages, limit, &prev),
        };
        name_rows(&mut page.items, |ip| self.local.client_name(ip));
        Ok(page)
    }

    fn explain(&self, p: &ExplainParams) -> Result<Explanation, Problem> {
        self.local.explain(p)
    }
    fn lists(&self) -> Vec<ListInfo> {
        self.local.lists()
    }
    // REQ: OBS-009 (T7.14) — every node's hits, added up by list name: the node serving the
    // API may answer few queries itself (replicas at other sites do).
    fn list_hits(&self) -> std::collections::BTreeMap<String, u64> {
        let mut parts = Vec::new();
        if self.with_me() {
            parts.push(self.local.list_hits());
        }
        parts.extend(self.everyone::<std::collections::BTreeMap<String, u64>>(|| Read::ListHits));
        telltale_api::federation::merge_list_hits(parts)
    }
    fn groups(&self) -> Vec<GroupInfo> {
        self.local.groups()
    }
    // REQ: OBS-025 — each named device with the cluster's most confident identity.
    fn clients(&self) -> Vec<ClientInfo> {
        let mut rows = self.local.clients();
        let merged: std::collections::HashMap<String, telltale_api::model::DeviceIdentity> = self
            .identities()
            .into_iter()
            .map(|i| (i.client.clone(), i))
            .collect();
        for r in &mut rows {
            let better = r.matches.iter().find_map(|m| {
                let m = m
                    .strip_suffix("/32")
                    .or_else(|| m.strip_suffix("/128"))
                    .unwrap_or(m);
                merged.get(m).cloned()
            });
            if better.is_some() {
                r.identity = better;
            }
        }
        rows
    }
    // REQ: OBS-025 — every node identifies the devices it sees; one per device, the most
    // confident (`identify::merge`), labelled with its node.
    fn identities(&self) -> Vec<telltale_api::model::DeviceIdentity> {
        let mut all = Vec::new();
        if self.with_me() {
            let me = self.own_label();
            all.extend(self.local.identities().into_iter().map(|mut i| {
                i.node = Some(me.clone());
                i
            }));
        }
        for (label, v) in
            self.everyone_labelled::<Vec<telltale_api::model::DeviceIdentity>>(|| Read::Identities)
        {
            all.extend(v.into_iter().map(|mut i| {
                i.node = Some(label.clone());
                i
            }));
        }
        crate::identify::merge(all)
    }
    // REQ: FLT-017 — every node holds the watcher's table: names and keys are this node's.
    fn workload(&self, client: &str) -> Option<(String, String)> {
        self.local.workload(client)
    }
    fn kubernetes_status(&self) -> telltale_api::model::KubernetesStatus {
        self.local.kubernetes_status()
    }
    fn workload_counts(&self) -> Vec<telltale_api::model::WorkloadCount> {
        self.local.workload_counts()
    }
    // REQ: FLT-017, CLU-002 — the list from this node's table; the counts summed over every
    // node that answers (each counts the queries it answered).
    fn kubernetes_workloads(&self) -> Result<Vec<telltale_api::model::WorkloadInfo>, Problem> {
        let mut items = self.local.kubernetes_workloads()?;
        if !self.with_me() {
            for w in &mut items {
                (w.queries_24h, w.blocked_24h, w.last_seen) = (0, 0, None);
            }
        }
        let mut sums: std::collections::HashMap<String, (u64, u64, u64)> =
            std::collections::HashMap::new();
        for counts in
            self.everyone::<Vec<telltale_api::model::WorkloadCount>>(|| Read::WorkloadCounts)
        {
            for c in counts {
                let e = sums.entry(c.key).or_default();
                e.0 += c.queries_24h;
                e.1 += c.blocked_24h;
                e.2 = e.2.max(c.last_seen_unix_seconds);
            }
        }
        // Workloads only other nodes counted, without pods now (a CronJob between runs).
        let known: std::collections::HashSet<String> =
            items.iter().map(|w| w.key.clone()).collect();
        for (key, (q, _, last)) in &sums {
            if *q == 0 || known.contains(key) {
                continue;
            }
            let Some((text, _)) = self.local.workload(key) else {
                continue;
            };
            let Some(info) = key
                .parse::<std::net::Ipv6Addr>()
                .ok()
                .and_then(|k| crate::api_backend::past_workload(&text, &k.octets()))
            else {
                continue;
            };
            items.push(telltale_api::model::WorkloadInfo {
                last_seen: Some(telltale_api::time::format_us(
                    last.saturating_mul(1_000_000),
                )),
                ..info
            });
        }
        for w in &mut items {
            if let Some((q, b, last)) = sums.get(&w.key) {
                w.queries_24h += q;
                w.blocked_24h += b;
                let mine = w
                    .last_seen
                    .as_deref()
                    .and_then(|t| telltale_api::time::parse_time(t, 0).ok())
                    .unwrap_or(0);
                if *last > mine {
                    w.last_seen = Some(telltale_api::time::format_us(
                        last.saturating_mul(1_000_000),
                    ));
                }
            }
        }
        Ok(items)
    }
    fn identity(&self, client: &str) -> Result<telltale_api::model::DeviceIdentity, Problem> {
        let mut local = self.local.identity(client)?;
        local.node = Some(self.own_label());
        let key = local.client.clone();
        let others = self
            .everyone_labelled::<Option<telltale_api::model::DeviceIdentity>>(|| Read::Identity {
                client: key.clone(),
            })
            .into_iter()
            .filter_map(|(label, v)| {
                v.map(|mut i| {
                    i.node = Some(label);
                    i
                })
            })
            .collect();
        Ok(merge_identity(local, others, &key))
    }
    // REQ: FLT-006, CLU-002 (ADR-183) — a peer's read of one device's identity is this node's own
    // answer, without `recognition`, and never the fan-out of `identity` above (a read that asks
    // every node must not ask every node again). `answer` calls it on the local backend; this
    // override only makes sure the trait's default can never be what runs here.
    fn identity_for_peer(
        &self,
        client: &str,
    ) -> Result<telltale_api::model::DeviceIdentity, Problem> {
        self.local.identity_for_peer(client)
    }
    // REQ: OBS-031 — every node's view of the device (it may roam), summed by domain.
    fn client_rhythm(
        &self,
        client: &str,
    ) -> Result<telltale_api::rhythm_api::ClientRhythm, Problem> {
        let local = self.local.client_rhythm(client)?;
        let key = local.client.clone();
        let mut available = local.available;
        let mut parts = vec![(Some(self.own_label()), local.domains)];
        for (label, v) in
            self.everyone_labelled::<Option<telltale_api::rhythm_api::ClientRhythm>>(|| {
                Read::ClientRhythm {
                    client: key.clone(),
                }
            })
        {
            if let Some(r) = v.filter(|r| r.available) {
                available = true;
                parts.push((Some(label), r.domains));
            }
        }
        Ok(telltale_api::rhythm_api::ClientRhythm {
            client: key,
            available,
            reason: (!available).then(|| "disabled".to_owned()),
            domains: telltale_api::rhythm_api::merge(parts),
            ..telltale_api::rhythm_api::ClientRhythm::default()
        })
    }
    fn upstreams(&self) -> Vec<UpstreamInfo> {
        self.local.upstreams()
    }
    // REQ: OBS-014, CLU-002 — every node's findings (each learns from the queries it answers):
    // one entry per finding ID, with the nodes that found it, acknowledged by this node's set
    // (the primary's).
    fn anomalies(&self, since_s: u64) -> Vec<AnomalyFinding> {
        let mut parts: Vec<(String, Vec<AnomalyFinding>)> = Vec::new();
        if self.with_me() {
            parts.push((self.own_label(), self.local.anomalies(since_s)));
        }
        parts.extend(self.everyone_labelled::<Vec<AnomalyFinding>>(|| Read::Anomalies { since_s }));
        let mut items = merge_findings(parts);
        self.local.annotate_acks(&mut items);
        items
    }
    fn annotate_acks(&self, items: &mut [AnomalyFinding]) {
        self.local.annotate_acks(items);
    }
    // REQ: OBS-014 (ADR-103) — the primary records acknowledgements; a replica forwards them
    // (also in a GitOps cluster: they aren't configuration) and records them at once itself,
    // so its own pages show them before the primary's next version arrives.
    fn anomaly_ack(
        &self,
        w: telltale_api::AnomalyAckWrite,
    ) -> BoxFuture<Result<telltale_api::model::AnomalyAckResult, Problem>> {
        if self.cluster.is_primary() {
            return self.local.anomaly_ack(w);
        }
        let cluster = Arc::clone(&self.cluster);
        let primary = self.cluster.reachable_primary();
        let local = Arc::clone(&self.local);
        Box::pin(async move {
            let r = crate::forward::anomaly_ack(cluster, primary, w.clone()).await?;
            let _ = local.anomaly_ack(w).await;
            Ok(r)
        })
    }
    // REQ: OBS-015 (ADR-104) — every node's own conditions, plus the cluster's (peers
    // unreachable or behind) as this node sees them.
    fn health(&self) -> telltale_api::model::Health {
        let now = self.local.now_unix_seconds();
        let mut reasons = Vec::new();
        let mut reporting = 0;
        if self.with_me() {
            let mut own = self.local.health().reasons;
            for r in &mut own {
                r.node = Some(self.own_label());
            }
            reasons.extend(own);
            reporting += 1;
        }
        for (label, h) in self.everyone_labelled::<telltale_api::model::Health>(|| Read::Health) {
            reporting += 1;
            reasons.extend(h.reasons.into_iter().map(|mut r| {
                r.node = Some(label.clone());
                r
            }));
        }
        let mut missing = self.missing_nodes();
        crate::health::soften_not_serving(&mut reasons, reporting);
        let view = self.local.cluster();
        reasons.extend(crate::health::cluster_reasons(&view));
        // REQ: OPS-010 (ADR-118) — nodes in maintenance: their conditions are left out (a
        // node that serves still counted as serving above) and they're listed instead.
        let maintenance = crate::health::exclude_maintenance(&mut reasons, &mut missing, &view);
        // REQ: OBS-016 (ADR-105) — an objective spending its budget fast, over every node.
        reasons.extend(crate::health::slo_reasons(self, now));
        let mut h = crate::health::summarize(
            reasons,
            missing,
            telltale_api::time::format_us(now.saturating_mul(1_000_000)),
        );
        h.maintenance = maintenance;
        h
    }
    // REQ: OPS-010 (ADR-118) — maintenance is the node's own state: a request for another
    // node goes to that node over the cluster channel (not to the primary).
    fn maintenance(
        &self,
        node: &str,
        w: telltale_api::MaintenanceWrite,
    ) -> BoxFuture<Result<telltale_api::model::MaintenanceResult, Problem>> {
        match self.own_state_node(
            node,
            "Maintenance is the node's own state, so the node must be up to take it.",
        ) {
            Ok(None) => self.local.maintenance("local", w),
            Ok(Some(peer)) => {
                let cluster = Arc::clone(&self.cluster);
                let label = self.label_of(&peer);
                Box::pin(crate::maintenance::send(cluster, peer, label, w))
            }
            Err(p) => Box::pin(async move { Err(p) }),
        }
    }
    // REQ: OPS-014 (ADR-182) — installing a version is the node's own business, like
    // maintenance: a request (or a read) for another node goes to that node.
    fn node_update(
        &self,
        node: &str,
        call: telltale_api::NodeUpdateCall,
    ) -> BoxFuture<Result<telltale_api::model::NodeUpdate, Problem>> {
        match self.own_state_node(
            node,
            "The node installs the version itself, so it must be up.",
        ) {
            Ok(None) => self.local.node_update("local", call),
            Ok(Some(peer)) => {
                let cluster = Arc::clone(&self.cluster);
                let label = self.label_of(&peer);
                Box::pin(crate::node_update::send(cluster, peer, label, call))
            }
            Err(p) => Box::pin(async move { Err(p) }),
        }
    }
    // REQ: CLU-014 (ADR-151) — a drill is the node's own state, like maintenance: a request for
    // another node goes to that node.
    fn drill(
        &self,
        node: &str,
        w: telltale_api::DrillWrite,
    ) -> BoxFuture<Result<telltale_api::model::DrillStart, Problem>> {
        match self.drill_node(node) {
            Ok(None) => self.local.drill("local", w),
            Ok(Some(peer)) => {
                let cluster = Arc::clone(&self.cluster);
                let label = self.label_of(&peer);
                Box::pin(crate::drill::send(cluster, peer, label, w))
            }
            Err(p) => Box::pin(async move { Err(p) }),
        }
    }
    fn drill_active(
        &self,
        node: &str,
    ) -> BoxFuture<Result<Option<telltale_api::model::ActiveDrill>, Problem>> {
        match self.drill_node(node) {
            Ok(None) => self.local.drill_active("local"),
            Ok(Some(peer)) => {
                let cluster = Arc::clone(&self.cluster);
                Box::pin(async move {
                    let body = serde_json::to_vec(&crate::drill::Op::Active)
                        .map_err(|e| Problem::internal(e.to_string()))?;
                    let reply = cluster
                        .call(&peer, crate::drill::KIND, body, Duration::from_secs(2))
                        .await
                        .map_err(|e| {
                            Problem::new(
                                telltale_api::problem::Code::NodeUnreachable,
                                format!("{peer} didn't answer: {e}"),
                            )
                        })?;
                    serde_json::from_slice(&reply)
                        .map_err(|e| Problem::internal(format!("unreadable answer: {e}")))
                })
            }
            Err(p) => Box::pin(async move { Err(p) }),
        }
    }
    // REQ: CLU-014 — every node keeps the reports of the drills it ran: merged, newest first.
    fn drills(
        &self,
        limit: usize,
        offset: usize,
    ) -> BoxFuture<Result<telltale_api::model::DrillPage, Problem>> {
        let (local, cluster) = (Arc::clone(&self.local), Arc::clone(&self.cluster));
        Box::pin(async move {
            let mut items = local
                .drills(50, 0)
                .await
                .map(|p| p.items)
                .unwrap_or_default();
            let (answers, missing) = crate::drill::ask_all(&cluster, &crate::drill::Op::List).await;
            for (_, body) in answers {
                if let Ok(v) =
                    serde_json::from_slice::<Vec<telltale_api::model::DrillSummary>>(&body)
                {
                    items.extend(v);
                }
            }
            Ok(crate::drill::page(items, limit, offset, missing))
        })
    }
    // REQ: CLU-014 — a report lives on the node that ran the drill.
    fn drill_report(
        &self,
        id: &str,
    ) -> BoxFuture<Result<telltale_api::model::DrillReport, Problem>> {
        let (local, cluster, id) = (
            Arc::clone(&self.local),
            Arc::clone(&self.cluster),
            id.to_owned(),
        );
        Box::pin(async move {
            if let Ok(r) = local.drill_report(&id).await {
                return Ok(r);
            }
            let (answers, missing) =
                crate::drill::ask_all(&cluster, &crate::drill::Op::Report { id: id.clone() }).await;
            for (_, body) in answers {
                if let Ok(Some(r)) =
                    serde_json::from_slice::<Option<telltale_api::model::DrillReport>>(&body)
                {
                    return Ok(r);
                }
            }
            let mut p = Problem::not_found(format!("no drill `{id}`"));
            p = if missing.is_empty() {
                p.hint("List them with GET /api/v1/drills.")
            } else {
                p.hint(format!(
                    "It may be on a node that didn't answer: {}.",
                    missing.join(", ")
                ))
            };
            Err(p)
        })
    }
    // REQ: CLU-014 — every node's seen table, merged per device.
    fn affinity(&self, days: u32) -> BoxFuture<Result<telltale_api::model::AffinityPage, Problem>> {
        let (local, cluster, own) = (
            Arc::clone(&self.local),
            Arc::clone(&self.cluster),
            self.own_label(),
        );
        Box::pin(async move {
            let mine = local.affinity(days).await?;
            let mut per_node = vec![(own, crate::drill::rows_of(&mine))];
            let (answers, missing) =
                crate::drill::ask_all(&cluster, &crate::drill::Op::Seen { days }).await;
            for (label, body) in answers {
                if let Ok(rows) = serde_json::from_slice::<Vec<crate::drill::SeenRow>>(&body) {
                    per_node.push((label, rows));
                }
            }
            Ok(crate::drill::affinity_page(days, per_node, missing))
        })
    }
    // REQ: CLU-013 (T13.2) — the primary runs rollouts and pins: another node asks it (and,
    // without a reachable primary, shows what the version it applied says).
    fn rollout_status(&self) -> BoxFuture<Result<telltale_api::model::RolloutStatus, Problem>> {
        if self.cluster.is_primary() {
            return self.local.rollout_status();
        }
        let cluster = Arc::clone(&self.cluster);
        let primary = self.cluster.reachable_primary();
        let local = Arc::clone(&self.local);
        Box::pin(async move {
            match crate::rollout::surface::send(
                cluster,
                primary,
                crate::rollout::surface::Call::Status,
            )
            .await
            {
                Ok(s) => Ok(s),
                Err(_) => local.rollout_status().await,
            }
        })
    }
    fn cluster_versions(&self) -> BoxFuture<Result<telltale_api::model::ClusterVersions, Problem>> {
        if self.cluster.is_primary() {
            return self.local.cluster_versions();
        }
        let cluster = Arc::clone(&self.cluster);
        let primary = self.cluster.reachable_primary();
        Box::pin(crate::rollout::surface::send(
            cluster,
            primary,
            crate::rollout::surface::Call::Versions,
        ))
    }
    fn rollout_command(
        &self,
        w: telltale_api::RolloutWrite,
    ) -> BoxFuture<Result<telltale_api::model::RolloutAction, Problem>> {
        if self.cluster.is_primary() {
            // ADR-056 — a primary without its lease publishes nothing.
            if !self.cluster.may_publish() {
                return Box::pin(async { Err(no_lease()) });
            }
            return self.local.rollout_command(w);
        }
        let cluster = Arc::clone(&self.cluster);
        let primary = self.cluster.reachable_primary();
        Box::pin(crate::rollout::surface::send(
            cluster,
            primary,
            crate::rollout::surface::Call::Command(w),
        ))
    }
    // REQ: CLU-001 (ADR-155, GitHub issue #5) — the primary keeps the member list: a replica
    // sends the request there.
    fn remove_node(
        &self,
        w: telltale_api::NodeRemoveWrite,
    ) -> BoxFuture<Result<telltale_api::model::NodeRemoval, Problem>> {
        let cluster = Arc::clone(&self.cluster);
        if cluster.is_primary() {
            return Box::pin(crate::node_removal::remove(cluster, w));
        }
        let primary = cluster.reachable_primary();
        Box::pin(crate::node_removal::send(cluster, primary, w))
    }
    // REQ: OBS-010 (T9.6) — alerts are evaluated here (the primary) or nowhere: this node's.
    fn alerts_status(&self) -> telltale_api::model::AlertsStatus {
        self.local.alerts_status()
    }
    fn alert_test(
        &self,
        name: &str,
        by_admin: bool,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::AlertTest, Problem>> {
        self.local.alert_test(name, by_admin)
    }
    // REQ: API-002 (T9.12) — checks run where the request landed.
    fn check_upstream(
        &self,
        body: serde_json::Value,
        by_admin: bool,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::CheckResult, Problem>> {
        self.local.check_upstream(body, by_admin)
    }
    fn check_list(
        &self,
        body: serde_json::Value,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::CheckResult, Problem>> {
        self.local.check_list(body)
    }
    // REQ: OBS-024 — the local backend asks the other nodes itself (`sim.run`).
    fn simulate(
        &self,
        config: serde_json::Value,
        opts: telltale_api::SimulateOpts,
        by_admin: bool,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::Simulation, Problem>> {
        self.local.simulate(config, opts, by_admin)
    }
    fn client_name(&self, ip: IpAddr) -> Option<String> {
        self.local.client_name(ip)
    }
    // REQ: OBS-010 (T9.5) — any node may meet a device first; the earliest sighting wins.
    fn new_devices(&self, since_s: u64) -> Vec<telltale_api::model::NewDevice> {
        let mut all: Vec<telltale_api::model::NewDevice> = self
            .everyone::<Vec<telltale_api::model::NewDevice>>(|| Read::NewDevices { since_s })
            .into_iter()
            .flatten()
            .collect();
        all.extend(self.local.new_devices(since_s));
        all.sort_by_key(|d| d.first_seen_unix_seconds);
        let mut seen = std::collections::HashSet::new();
        all.retain(|d| seen.insert(d.client.clone()));
        all
    }
    fn dhcp_leases(&self) -> Vec<telltale_api::model::DhcpLease> {
        self.local.dhcp_leases()
    }
    fn new_domains(
        &self,
        since_s: u64,
        client: Option<&str>,
        limit: usize,
    ) -> Vec<telltale_api::model::NewDomain> {
        self.local.new_domains(since_s, client, limit)
    }
    fn local_names(&self) -> Vec<LocalName> {
        self.local.local_names()
    }
    fn zones(&self) -> Vec<telltale_api::model::ZoneInfo> {
        self.local.zones()
    }
    // REQ: AGT-012 — this node's log and the logs shipped to it (CLU-007).
    fn vqlog(
        &self,
        q: &telltale_api::vqlog::Query,
        from_us: u64,
        to_us: u64,
        dry_run: bool,
    ) -> Result<telltale_api::model::VqlogResult, telltale_api::problem::Problem> {
        self.local.vqlog(q, from_us, to_us, dry_run)
    }
    fn forwards(&self) -> Vec<ForwardInfo> {
        self.local.forwards()
    }
    // REQ: OBS-018 (ADR-109) — every node's counts, merged by list.
    fn shadow_lists(&self) -> Vec<telltale_api::model::ShadowListStats> {
        let label = |rows: Vec<telltale_api::model::ShadowListStats>, node: &str| {
            rows.into_iter()
                .map(|mut r| {
                    r.nodes = vec![node.to_owned()];
                    r
                })
                .collect::<Vec<_>>()
        };
        let mut parts = Vec::new();
        if self.with_me() {
            parts.push(label(self.local.shadow_lists(), &self.own_label()));
        }
        for (node, rows) in self
            .everyone_labelled::<Vec<telltale_api::model::ShadowListStats>>(|| Read::ShadowLists)
        {
            parts.push(label(rows, &node));
        }
        telltale_api::federation::merge_shadow(parts)
    }
    // REQ: OBS-018 (ADR-109) — every node's suspects, merged by name.
    fn overblocking(&self, limit: usize) -> Vec<telltale_api::model::OverblockSuspect> {
        let label = |rows: Vec<telltale_api::model::OverblockSuspect>, node: &str| {
            rows.into_iter()
                .map(|mut r| {
                    r.nodes = vec![node.to_owned()];
                    r
                })
                .collect::<Vec<_>>()
        };
        let mut parts = Vec::new();
        if self.with_me() {
            parts.push(label(self.local.overblocking(limit), &self.own_label()));
        }
        for (node, rows) in
            self.everyone_labelled::<Vec<telltale_api::model::OverblockSuspect>>(|| {
                Read::Overblocking { limit }
            })
        {
            parts.push(label(rows, &node));
        }
        telltale_api::federation::merge_overblocking(parts, limit)
    }
    // REQ: OBS-019 (ADR-108) — each node asks its own upstreams: one entry per node.
    fn upstream_checks(&self) -> Vec<telltale_api::model::UpstreamChecks> {
        let own = self.own_label();
        let mut rows: Vec<_> = if self.with_me() {
            self.local
                .upstream_checks()
                .into_iter()
                .map(|mut r| {
                    r.node = Some(own.clone());
                    r
                })
                .collect()
        } else {
            Vec::new()
        };
        for (label, peer_rows) in self
            .everyone_labelled::<Vec<telltale_api::model::UpstreamChecks>>(|| Read::UpstreamChecks)
        {
            rows.extend(peer_rows.into_iter().map(|mut r| {
                r.node = Some(label.clone());
                r
            }));
        }
        rows
    }
    // REQ: OBS-020 (ADR-107) — each node probes its own listeners: every node's, labelled.
    fn probes(&self) -> Vec<telltale_api::model::ProbeResult> {
        let own = self.own_label();
        let mut rows: Vec<_> = if self.with_me() {
            self.local
                .probes()
                .into_iter()
                .map(|mut r| {
                    r.node = Some(own.clone());
                    r
                })
                .collect()
        } else {
            Vec::new()
        };
        for (label, peer_rows) in
            self.everyone_labelled::<Vec<telltale_api::model::ProbeResult>>(|| Read::Probes)
        {
            rows.extend(peer_rows.into_iter().map(|mut r| {
                r.node = Some(label.clone());
                r
            }));
        }
        rows
    }
    // REQ: OBS-033 (ADR-133) — each node keeps its own markers: every node's, labelled,
    // newest first.
    fn annotations(
        &self,
        f: &telltale_api::model::AnnotationFilter,
    ) -> Vec<telltale_api::model::Annotation> {
        let label = |rows: Vec<telltale_api::model::Annotation>, node: &str| {
            rows.into_iter()
                .map(|mut a| {
                    a.node = Some(node.to_owned());
                    a
                })
                .collect::<Vec<_>>()
        };
        let mut pages = Vec::new();
        if self.with_me() {
            pages.push(label(self.local.annotations(f), &self.own_label()));
        }
        for (node, rows) in self.everyone_labelled::<Vec<telltale_api::model::Annotation>>(|| {
            Read::Annotations { filter: f.clone() }
        }) {
            pages.push(label(rows, &node));
        }
        telltale_api::annotations_api::merge(pages, f.limit)
    }
    // REQ: OBS-033 — a note (or a pause or flush asked here) is this node's own marker.
    fn annotate(
        &self,
        a: telltale_api::model::Annotation,
    ) -> Result<telltale_api::model::Annotation, Problem> {
        let mut written = self.local.annotate(a)?;
        written.node = Some(self.own_label());
        Ok(written)
    }
    // REQ: DNS-006, CLU-002 (T6.13) — each node has its own cache: one row per node.
    fn cache_stats(&self) -> Vec<telltale_api::model::CacheNodeStats> {
        let own = self.own_label();
        let mut rows: Vec<_> = self
            .local
            .cache_stats()
            .into_iter()
            .map(|mut r| {
                r.node = Some(own.clone());
                r
            })
            .collect();
        for (label, peer_rows) in
            self.everyone_labelled::<Vec<telltale_api::model::CacheNodeStats>>(|| Read::CacheStats)
        {
            rows.extend(peer_rows.into_iter().map(|mut r| {
                r.node = Some(label.clone());
                r
            }));
        }
        rows
    }
    fn cache_lookup(&self, name: &str) -> Result<Vec<telltale_api::model::CacheEntry>, Problem> {
        let own = self.own_label();
        let mut rows: Vec<_> = self
            .local
            .cache_lookup(name)?
            .into_iter()
            .map(|mut r| {
                r.node = Some(own.clone());
                r
            })
            .collect();
        let n = name.to_owned();
        for (label, peer_rows) in
            self.everyone_labelled::<Vec<telltale_api::model::CacheEntry>>(|| Read::CacheLookup {
                name: n.clone(),
            })
        {
            rows.extend(peer_rows.into_iter().map(|mut r| {
                r.node = Some(label.clone());
                r
            }));
        }
        Ok(rows)
    }
    fn cache_flush(
        &self,
        name: Option<&str>,
        subtree: bool,
        node: Option<&str>,
    ) -> Result<Vec<telltale_api::model::CacheFlushNode>, Problem> {
        use telltale_api::model::CacheFlushNode;
        let label = |mut v: Vec<CacheFlushNode>, l: &str| {
            for r in &mut v {
                r.node = Some(l.to_owned());
            }
            v
        };
        let read = || Read::CacheFlush {
            name: name.map(str::to_owned),
            subtree,
        };
        match node.map(|n| self.resolve_node(n)).transpose()? {
            // One node: this one, or one peer.
            Some(None) => Ok(label(
                self.local.cache_flush(name, subtree, None)?,
                &self.own_label(),
            )),
            Some(Some(peer)) => {
                let l = self.label_of(&peer);
                Ok(match self.call_one(&peer, &read(), DEADLINE) {
                    Some(Ok(body)) => label(serde_json::from_slice(&body).unwrap_or_default(), &l),
                    Some(Err(e)) => vec![CacheFlushNode {
                        node: Some(l),
                        removed: None,
                        error: Some(e),
                    }],
                    None => vec![CacheFlushNode {
                        node: Some(l),
                        removed: None,
                        error: Some("no runtime".into()),
                    }],
                })
            }
            // Every node; those that don't answer are listed with an error.
            None => {
                let mut out = label(
                    self.local.cache_flush(name, subtree, None)?,
                    &self.own_label(),
                );
                let answered = self.everyone_labelled::<Vec<CacheFlushNode>>(read);
                let names: Vec<String> = answered.iter().map(|(l, _)| l.clone()).collect();
                for (l, v) in answered {
                    out.extend(label(v, &l));
                }
                // Labelled like the answers (pods by pod name, T6.14), so a pod that answered
                // isn't also listed as unreachable.
                for m in self.cluster.members() {
                    let l = self.label_of(&m.node_id);
                    if !names.contains(&l) {
                        out.push(CacheFlushNode {
                            node: Some(l),
                            removed: None,
                            error: Some("not reachable: flush it when it's back".into()),
                        });
                    }
                }
                Ok(out)
            }
        }
    }
    // REQ: FLT-009, CLU-002 (T7.1) — pauses on every node (or one).
    fn blocking_state(&self) -> Vec<telltale_api::model::BlockingNode> {
        self.blocking_fan(None, |b| Ok(b.blocking_state()), || Read::BlockingState)
            .unwrap_or_default()
    }
    fn blocking_pause(
        &self,
        group: Option<&str>,
        minutes: u32,
        node: Option<&str>,
    ) -> Result<Vec<telltale_api::model::BlockingNode>, Problem> {
        let g = group.map(str::to_owned);
        self.blocking_fan(
            node,
            |b| b.blocking_pause(group, minutes, None),
            || Read::BlockingPause {
                group: g.clone(),
                minutes,
            },
        )
    }
    fn blocking_resume(
        &self,
        group: Option<&str>,
        node: Option<&str>,
    ) -> Result<Vec<telltale_api::model::BlockingNode>, Problem> {
        let g = group.map(str::to_owned);
        self.blocking_fan(
            node,
            |b| b.blocking_resume(group, None),
            || Read::BlockingResume { group: g.clone() },
        )
    }
    // REQ: DNS-006, OBS-003, CLU-002 (T6.15) — each node's top entries and makeup. (Without
    // this, the trait's empty default left the Cache page's table empty on clustered nodes.)
    fn cache_entries(
        &self,
        sort: &str,
        limit: usize,
        node: Option<&str>,
    ) -> Result<Vec<telltale_api::model::CacheNodeEntries>, Problem> {
        use telltale_api::model::CacheNodeEntries;
        let label = |mut v: Vec<CacheNodeEntries>, l: &str| {
            for r in &mut v {
                r.node = Some(l.to_owned());
            }
            v
        };
        let read = || Read::CacheEntries {
            sort: sort.to_owned(),
            limit,
        };
        let failed = |l: String, e: String| CacheNodeEntries {
            node: Some(l),
            error: Some(e),
            ..CacheNodeEntries::default()
        };
        match node.map(|n| self.resolve_node(n)).transpose()? {
            Some(None) => Ok(label(
                self.local.cache_entries(sort, limit, None)?,
                &self.own_label(),
            )),
            Some(Some(peer)) => {
                let l = self.label_of(&peer);
                Ok(match self.call_one(&peer, &read(), DEADLINE) {
                    Some(Ok(body)) => label(serde_json::from_slice(&body).unwrap_or_default(), &l),
                    Some(Err(e)) => vec![failed(l, e)],
                    None => vec![failed(l, "no runtime".into())],
                })
            }
            None => {
                let mut out = label(
                    self.local.cache_entries(sort, limit, None)?,
                    &self.own_label(),
                );
                let answered = self.everyone_labelled::<Vec<CacheNodeEntries>>(read);
                let names: Vec<String> = answered.iter().map(|(l, _)| l.clone()).collect();
                for (l, v) in answered {
                    out.extend(label(v, &l));
                }
                for m in self.cluster.members().into_iter().filter(|m| m.connected) {
                    let l = self.label_of(&m.node_id);
                    if !names.contains(&l) {
                        out.push(failed(
                            l,
                            "didn't answer (an older version doesn't list its cache)".into(),
                        ));
                    }
                }
                Ok(out)
            }
        }
    }
    // REQ: FLT-005 (T6.12) — quick rules are shared configuration: this node's copy is the
    // cluster's. (Without this, the trait's empty default hid them on clustered nodes.)
    fn rules(&self) -> Vec<telltale_api::model::RuleInfo> {
        self.local.rules()
    }
    // REQ: CLU-002 — a replica forwards configuration writes to the primary (T5.7).
    fn write_managed(&self, w: ManagedWrite) -> BoxFuture<Result<ConfigChange, Problem>> {
        match self.write_route() {
            WriteRoute::Primary(primary) => Box::pin(crate::forward::managed(
                Arc::clone(&self.cluster),
                primary,
                w,
            )),
            WriteRoute::Here => self.local.write_managed(w),
            WriteRoute::NoLease => Box::pin(async { Err(no_lease()) }),
        }
    }
    fn config_version(&self) -> u64 {
        // A replica's ETags are the primary's version, so If-Match works through any node.
        if let WriteRoute::Primary(Some(primary)) = self.write_route()
            && let Some(Ok(body)) = self.call_one(&primary, &Read::ConfigVersion, VERSION_DEADLINE)
            && let Ok(v) = serde_json::from_slice::<u64>(&body)
        {
            return v;
        }
        self.local.config_version()
    }
    // REQ: API-002 (ADR-069), CLU-002 — the settings editors list the entries in force, and the
    // configuration is the primary's: a replica asks it (so every node shows the same rows, and
    // what the API changed on the primary). Without a reachable primary, or with one too old to
    // answer, this node's own view. (Before: the trait's default, an empty list, so every
    // editor said "None yet" on a cluster node; owner report 2026-10-09.)
    fn config_entries(&self, kind: Option<&str>) -> Vec<telltale_api::model::ConfigEntry> {
        if !self.cluster.is_primary()
            && let Some(primary) = self.cluster.reachable_primary()
            && let Some(Ok(body)) = self.call_one(
                &primary,
                &Read::ConfigEntries {
                    kind: kind.map(str::to_owned),
                },
                VERSION_DEADLINE,
            )
            && let Ok(v) = serde_json::from_slice::<Vec<telltale_api::model::ConfigEntry>>(&body)
        {
            return v;
        }
        self.local.config_entries(kind)
    }
    fn write_client(&self, w: ClientWrite) -> BoxFuture<Result<ClientChange, Problem>> {
        match self.write_route() {
            WriteRoute::Primary(primary) => Box::pin(crate::forward::client(
                Arc::clone(&self.cluster),
                primary,
                w,
            )),
            WriteRoute::Here => self.local.write_client(w),
            WriteRoute::NoLease => Box::pin(async { Err(no_lease()) }),
        }
    }
}

/// REQ: FLT-006, API-010 (ADR-183) — one device's identity across the nodes: the best guess of
/// any of them (`identify::merge`), with how the address is recognized taken from this node's
/// answer alone. Recognition is the entry node's own view (its table, its routers, its
/// `router_macs`): another node's differs, and merging them would give a MAC that this node
/// doesn't hold.
fn merge_identity(
    mut local: telltale_api::model::DeviceIdentity,
    others: Vec<telltale_api::model::DeviceIdentity>,
    key: &str,
) -> telltale_api::model::DeviceIdentity {
    let recognition = local.recognition.take();
    let mut all = vec![local];
    all.extend(others.into_iter().map(|mut i| {
        i.recognition = None;
        i
    }));
    let mut merged = crate::identify::merge(all)
        .into_iter()
        .next()
        .unwrap_or_else(|| crate::identify::unavailable(key, "not_seen"));
    merged.recognition = recognition;
    merged
}

#[cfg(test)]
mod identity_tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use telltale_api::Backend as _;
    use telltale_api::model::{DeviceIdentity, DeviceRecognition};

    use super::{Read, answer, merge_identity};

    // REQ: FLT-006, CLU-002, API-010 (ADR-183) — what a node answers a peer's identity read has no
    // `recognition`: the entry node never uses it (it keeps its own), so a node doesn't compute it
    // (the work of its routers' bindings, per read, per peer) or send it (its table's MACs, over the
    // cluster channel, to any member, ephemeral ones included). The entry node's own read still
    // has it, and the merge still shows the entry node's.
    #[test]
    fn clu_002_a_peers_identity_read_carries_no_recognition() {
        let dir = tempfile::tempdir().unwrap();
        let src = Arc::new(crate::http::tests::sources_in(dir.path()));
        src.pipeline.reload(
            Arc::new(telltale_upstream::Router::default()),
            crate::pipeline::Policy::from_config(
                &telltale_config::Config::default(),
                telltale_policy::LocalData::default(),
            ),
        );
        let lease = crate::devices::Lease {
            mac: "00:11:11:11:11:50".into(),
            ip: Ipv4Addr::new(10, 0, 0, 50),
            hostname: None,
            expires: 0,
            offline: false,
            unsure: false,
            stale: false,
        };
        src.pipeline
            .router_leases
            .store(Arc::new(HashMap::from([(lease.ip, lease)])));
        let backend = crate::api_backend::ApiBackend {
            src: Arc::clone(&src),
        };
        let mine = backend.identity("10.0.0.50").unwrap();
        assert_eq!(
            mine.recognition.as_ref().and_then(|r| r.mac.as_deref()),
            Some("00:11:11:11:11:50"),
            "the entry node's own read has it"
        );
        let bytes = answer(
            &backend,
            Read::Identity {
                client: "10.0.0.50".into(),
            },
        )
        .unwrap();
        let theirs: Option<DeviceIdentity> = serde_json::from_slice(&bytes).unwrap();
        let theirs = theirs.expect("an identity");
        assert!(theirs.recognition.is_none(), "{theirs:?}");
        assert_eq!(theirs.client, mine.client, "the rest is the same");
        let merged = merge_identity(mine.clone(), vec![theirs], "10.0.0.50");
        assert_eq!(merged.recognition, mine.recognition);
    }

    fn node(
        label: &str,
        product: Option<&str>,
        score: f32,
        recognition: Option<DeviceRecognition>,
    ) -> DeviceIdentity {
        DeviceIdentity {
            client: "192.168.1.20".into(),
            available: true,
            product: product.map(str::to_owned),
            class: "streaming".into(),
            level: "likely".into(),
            score,
            source: "inferred".into(),
            node: Some(label.into()),
            recognition,
            ..DeviceIdentity::default()
        }
    }

    fn seen_as(device: &str, mac: &str, from: &str) -> DeviceRecognition {
        DeviceRecognition {
            device: Some(device.into()),
            identified_by: "router_mac".into(),
            mac: Some(mac.into()),
            mac_from: Some(from.into()),
            ..DeviceRecognition::default()
        }
    }

    // REQ: FLT-006, API-010, CLU-002 (ADR-183) — how an address is recognized is the entry node's
    // own view: the merged identity takes the best guess of any node (here the other node's, with
    // the higher score), and the entry node's `recognition`, whatever the others say.
    #[test]
    fn clu_002_identity_recognition_is_the_entry_nodes() {
        let entry = node(
            "entry",
            Some("Roku player"),
            0.6,
            Some(seen_as("tv", "02:00:00:00:00:01", "router")),
        );
        let other = node(
            "pod",
            Some("Roku Ultra"),
            0.9,
            Some(seen_as("someone else", "02:00:00:00:00:99", "peer")),
        );
        let merged = merge_identity(entry, vec![other], "192.168.1.20");
        assert_eq!(
            merged.product.as_deref(),
            Some("Roku Ultra"),
            "the best guess wins"
        );
        let r = merged.recognition.expect("the entry node's recognition");
        assert_eq!(r.device.as_deref(), Some("tv"));
        assert_eq!(r.mac.as_deref(), Some("02:00:00:00:00:01"));
        assert_eq!(r.mac_from.as_deref(), Some("router"));
    }

    // REQ: FLT-006, API-010 (ADR-183) — an entry node that says nothing about recognition (privacy
    // level 2 and above) leaves none on the merged identity, though another node had one: that
    // node's MAC must not reach a caller this node hides it from.
    #[test]
    fn clu_002_identity_recognition_hidden_here_stays_hidden() {
        let entry = node("entry", Some("Roku player"), 0.6, None);
        let other = node(
            "pod",
            Some("Roku player"),
            0.6,
            Some(seen_as("tv", "02:00:00:00:00:01", "router")),
        );
        let merged = merge_identity(entry, vec![other], "192.168.1.20");
        assert!(merged.recognition.is_none(), "{merged:?}");
    }

    // REQ: CLU-010, API-010 (ADR-183) — a mixed cluster: a node on an earlier build writes no
    // `recognition` (it reads the same), and one on this build writes it where an earlier one
    // ignores the key.
    #[test]
    fn clu_010_identity_recognition_reads_both_ways() {
        let earlier = r#"{"client":"192.168.1.20","available":true,"class":"streaming","level":"likely","score":0.6,"source":"inferred"}"#;
        let read: DeviceIdentity = serde_json::from_str(earlier).unwrap();
        assert!(read.recognition.is_none());
        let newer = node(
            "pod",
            None,
            0.6,
            Some(seen_as("tv", "02:00:00:00:00:01", "peer")),
        );
        let mut json = serde_json::to_value(&newer).unwrap();
        assert_eq!(json["recognition"]["macFrom"], "peer");
        // An earlier build's struct has no such field and no `deny_unknown_fields`: the same read
        // with the key it doesn't know is what `from_value` does with an extra key here.
        json["futureField"] = serde_json::json!(1);
        assert!(serde_json::from_value::<DeviceIdentity>(json).is_ok());
    }
}

#[cfg(test)]
mod heatmap_read_tests {
    use std::sync::Arc;

    use telltale_api::Backend as _;
    use telltale_api::heatmap::{KeyPart, KeyQuery, MAX_SLOTS, NetworkQuery};
    use telltale_store::rollup::{Rollups, TopRow};
    use telltale_telemetry::agg::Counts;
    use telltale_telemetry::event::{Name, Record};

    use super::{Read, answer};

    /// 2020-09-14T00:00:00Z, a day boundary: every window below starts at or after it.
    const DAY0: u64 = 1_600_041_600;
    /// The node's current hour (one query in it), after every stored hour.
    const LIVE: u64 = DAY0 + 500 * 86_400;

    fn query(ts_s: u64) -> Record {
        Record::Query(
            telltale_telemetry::QueryEvent {
                ts_us: ts_s * 1_000_000,
                client_ip: std::net::Ipv4Addr::new(10, 0, 0, 1)
                    .to_ipv6_mapped()
                    .octets(),
                client_ref: 0,
                group: 0,
                qtype: 1,
                qclass: 1,
                rcode: Some(0),
                status: telltale_telemetry::Status::Forwarded,
                proto: telltale_telemetry::Proto::Udp,
                flags: 0x8180,
                rule: None,
                upstream: 0,
                attempts: 0,
                t_total_us: 100,
                t_upstream_us: 0,
                resp_size: 64,
                answers: 1,
            },
            Name::from_wire(b"\x07example\x03com\x00"),
        )
    }

    fn row(key: &str, count: u64) -> TopRow {
        TopRow {
            key: key.into(),
            count,
            error: 0,
        }
    }

    /// The hour `k` after `DAY0` has top lists when `k % 5 == 0`; `10.0.0.1` and `example.com`
    /// are on them with this count (at least 1), unless `k % 10 == 0` too (then the lists lack
    /// them: 0).
    fn listed(k: u64) -> Option<u64> {
        k.is_multiple_of(5)
            .then_some(if k.is_multiple_of(10) { 0 } else { k % 50 + 1 })
    }

    /// A node with two days of minutes, then a minute every three hours to day 401 (each with
    /// blocked queries), the hours' top lists of [`listed`], and one live query at `LIVE`.
    fn backend(dir: &std::path::Path) -> crate::api_backend::ApiBackend {
        let mut s = crate::http::tests::sources_in(dir);
        let db = Arc::new(Rollups::in_memory().unwrap());
        let minute = |t: u64| {
            let total = u32::try_from(t / 60 % 13 + 1).unwrap();
            let mut c = Counts {
                total,
                ..Counts::default()
            };
            c.status.fill(total / 2 + 1);
            (t, c)
        };
        let mut rows: Vec<(u64, Counts)> = (0..2 * 1440).map(|m| minute(DAY0 + m * 60)).collect();
        rows.extend((16..401 * 8).map(|i| minute(DAY0 + i * 3 * 3600 + 420)));
        db.put_minutes(&rows).unwrap();
        for (k, count) in (0..9_700u64).filter_map(|k| listed(k).map(|c| (k, c))) {
            let (clients, domains) = if count == 0 {
                (vec![row("10.0.0.2", 1)], vec![row("other.example", 1)])
            } else {
                (
                    vec![row("10.0.0.1", count), row("10.0.0.2", 1)],
                    vec![row("example.com", count), row("other.example", 1)],
                )
            };
            db.put_hour_extras(
                DAY0 + k * 3600,
                &[("clients", clients), ("domains", domains)],
                &[],
            )
            .unwrap();
        }
        s.rollups = Some(db);
        s.pipeline.telemetry.aggregates().record(&query(LIVE));
        crate::api_backend::ApiBackend { src: Arc::new(s) }
    }

    fn network(b: &crate::api_backend::ApiBackend, q: NetworkQuery) -> Vec<u64> {
        serde_json::from_slice(&answer(b, Read::HeatmapNetwork { q }).unwrap()).unwrap()
    }

    fn key_part(
        b: &crate::api_backend::ApiBackend,
        from_s: u64,
        to_s: u64,
        kind: &str,
        key: &str,
    ) -> KeyPart {
        let q = KeyQuery {
            from_s,
            to_s,
            kind: kind.into(),
            key: key.into(),
            blocked: false,
        };
        serde_json::from_slice(&answer(b, Read::HeatmapKey { q }).unwrap()).unwrap()
    }

    /// REQ: OBS-029 — whatever window and slot a peer's read names, the answering node's part
    /// has at most `MAX_SLOTS` slots: a window that doesn't end after it starts has none, a
    /// zero slot counts as a minute (the finest grain the API asks for), and a window longer
    /// than `MAX_SLOTS` slots is answered for its first `MAX_SLOTS`.
    #[test]
    fn obs_029_peer_heatmap_reads_use_bounded_windows() {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path());
        let net = |from_s, to_s, slot| {
            network(
                &b,
                NetworkQuery {
                    from_s,
                    to_s,
                    slot,
                    blocked: false,
                },
            )
        };
        for slot in [1, 0, 60, 3600] {
            assert_eq!(net(0, u64::MAX, slot).len(), MAX_SLOTS, "slot {slot}");
        }
        // No slot: minute slots, with the minutes' counts in them.
        let by_minute = net(DAY0, DAY0 + 7200, 60);
        assert_eq!(by_minute.len(), 120);
        assert!(by_minute.iter().all(|v| *v > 0), "{by_minute:?}");
        assert_eq!(net(DAY0, DAY0 + 7200, 0), by_minute);
        // A window that ends before it starts, or where it starts: no slots.
        assert_eq!(net(DAY0 + 7200, DAY0, 60), Vec::<u64>::new());
        assert_eq!(net(u64::MAX, 0, 0), Vec::<u64>::new());
        assert_eq!(net(DAY0, DAY0, 60), Vec::<u64>::new());
        // A slot longer than the window: one.
        assert_eq!(net(DAY0, DAY0 + 7200, u64::MAX).len(), 1);
        // A device's or a name's hours.
        for (kind, k) in [
            ("client", "10.0.0.1"),
            ("name", "example.com"),
            ("other", "x"),
        ] {
            for (from_s, to_s) in [(10, 0), (u64::MAX, 0), (DAY0, DAY0)] {
                let part = key_part(&b, from_s, to_s, kind, k);
                assert!(
                    part.values.is_empty() && part.covered.is_empty(),
                    "{kind} {from_s}..{to_s}"
                );
            }
            for (from_s, to_s) in [(0, u64::MAX), (DAY0, u64::MAX)] {
                let part = key_part(&b, from_s, to_s, kind, k);
                assert_eq!(
                    (part.values.len(), part.covered.len()),
                    (MAX_SLOTS, MAX_SLOTS),
                    "{kind} {from_s}..{to_s}"
                );
            }
        }
        // From DAY0 on, the first MAX_SLOTS hours are the stored ones.
        let part = key_part(&b, DAY0, u64::MAX, "client", "10.0.0.1");
        assert_eq!(Some(part.values[5]), listed(5));
        assert!(!part.covered[10]);
    }

    /// REQ: OBS-029 — for every window the API itself sends (its slot sizes, its windows of up
    /// to `MAX_SLOTS` slots, aligned starts, any end), the answering node's part is exactly
    /// what it was before parts were bounded: the slot count and the sums computed here the way
    /// the node computed them, without a bound.
    #[test]
    fn obs_029_peer_heatmap_reads_match_the_api_windows() {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path());
        let unbounded_count = |from_s: u64, to_s: u64, slot: u64| {
            usize::try_from(to_s.saturating_sub(from_s).div_ceil(slot.max(1))).unwrap_or(0)
        };
        let unbounded_slots = |points: &[(u64, u64)], from_s: u64, slot: u64, n: usize| {
            let mut v = vec![0u64; n];
            for &(start, value) in points {
                if start < from_s {
                    continue;
                }
                let i = usize::try_from((start - from_s) / slot).unwrap_or(usize::MAX);
                if let Some(x) = v.get_mut(i) {
                    *x += value;
                }
            }
            v
        };
        let counts = [
            1, 2, 3, 59, 60, 61, 96, 97, 168, 672, 673, 676, 1440, 9600, 9601, 10_079, 10_080,
        ];
        for (slot, max_days) in [(3600u64, 400u64), (900, 7), (60, 7)] {
            // The API's own limit for the grain (`stats_heatmap`).
            let api_max = ((max_days * 86_400 + 3600) / slot).min(MAX_SLOTS as u64);
            for n in counts
                .into_iter()
                .filter(|n| *n <= api_max)
                .chain([api_max])
            {
                // Aligned starts; ends anywhere in the last slot.
                for (start, rest, blocked) in [(0, slot, false), (3, 1, true), (7, slot - 1, false)]
                {
                    let from_s = DAY0 + start * slot;
                    let to_s = from_s + (n - 1) * slot + rest;
                    let q = NetworkQuery {
                        from_s,
                        to_s,
                        slot,
                        blocked,
                    };
                    let what =
                        format!("slot {slot}, {n} slots, {from_s}..{to_s}, blocked {blocked}");
                    let got = network(&b, q.clone());
                    let points: Vec<(u64, u64)> = b
                        .timeseries(q.step(), from_s, to_s)
                        .iter()
                        .map(|x| {
                            let v = if blocked {
                                x.by_status.get("blocked").copied().unwrap_or(0)
                            } else {
                                x.total
                            };
                            (x.start_unix_seconds, u64::from(v))
                        })
                        .collect();
                    let want =
                        unbounded_slots(&points, from_s, slot, unbounded_count(from_s, to_s, slot));
                    assert_eq!(got.len(), usize::try_from(n).unwrap(), "{what}");
                    assert!(got == want, "{what}");
                    assert_eq!(q.slot_count(), want.len(), "{what}");
                }
            }
        }
        // A device's or a name's hours (hour slots only, up to the API's 9,601).
        for n in [1u64, 2, 5, 24, 168, 1000, 9600, 9601] {
            for rest in [1, 3600] {
                let from_s = DAY0 + 3 * 3600;
                let to_s = from_s + (n - 1) * 3600 + rest;
                let hours = usize::try_from((to_s - from_s).div_ceil(3600)).unwrap();
                for (kind, k) in [("client", "10.0.0.1"), ("name", "example.com")] {
                    let what = format!("{kind}, {n} hours, {from_s}..{to_s}");
                    let part = key_part(&b, from_s, to_s, kind, k);
                    assert_eq!(part.values.len(), hours, "{what}");
                    assert_eq!(part.covered.len(), hours, "{what}");
                    for (i, (v, c)) in part.values.iter().zip(&part.covered).enumerate() {
                        let hour = (from_s - DAY0) / 3600 + i as u64;
                        // No list: covered, nothing; a list without the key: not covered.
                        let expected = match listed(hour) {
                            None => (0, true),
                            Some(0) => (0, false),
                            Some(count) => (count, true),
                        };
                        assert_eq!((*v, *c), expected, "{what}: hour {i}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod queries_read_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use telltale_api::Backend as _;
    use telltale_api::model::{QueryPage, QueryParams};
    use telltale_store::qlog::{Builder, Settings};

    use super::{Read, answer};

    /// The API's own page size (`GET /api/v1/queries` takes `limit` 1 to 1000).
    const API_PAGE: usize = telltale_api::MAX_QUERY_PAGE;
    /// Rows in the test log: more than one page.
    const ROWS: usize = 1_100;

    fn wire(name: &str) -> Vec<u8> {
        let mut w = Vec::new();
        for l in name.split('.') {
            w.push(u8::try_from(l.len()).unwrap());
            w.extend_from_slice(l.as_bytes());
        }
        w.push(0);
        w
    }

    /// A node whose query log holds `ROWS` queries (`n<i>.example.com`), one every 2 s from
    /// midnight UTC two days ago (the writer keeps 30 days by the real clock), from four
    /// devices, every fourth blocked. Returns the backend and the first row's time (µs).
    fn node(dir: &std::path::Path) -> (crate::api_backend::ApiBackend, u64) {
        let mut src = crate::http::tests::sources_in(dir);
        src.qlog = Some(Arc::new(telltale_store::qlog::Stats::default()));
        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let start = (now_s / 86_400 - 2) * 86_400;
        let mut w = Builder::spawn(Settings {
            dir: dir.join("qlog"),
            node: 1,
            privacy: 0,
            flush_interval: Duration::from_secs(3600),
            fsync: false,
            retention_days: 30,
            retention_bytes: u64::MAX,
            rotate_after: None,
        })
        .unwrap();
        for i in 0..u64::try_from(ROWS).unwrap() {
            let event = telltale_telemetry::QueryEvent {
                ts_us: (start + 2 * i) * 1_000_000,
                client_ip: std::net::Ipv4Addr::new(10, 0, 0, u8::try_from(1 + i % 4).unwrap())
                    .to_ipv6_mapped()
                    .octets(),
                client_ref: 0,
                group: 0,
                qtype: 1,
                qclass: 1,
                rcode: Some(0),
                status: if i.is_multiple_of(4) {
                    telltale_telemetry::Status::Blocked
                } else {
                    telltale_telemetry::Status::Forwarded
                },
                proto: telltale_telemetry::Proto::Udp,
                flags: 0x8180,
                rule: None,
                upstream: 0,
                attempts: 1,
                t_total_us: 100,
                t_upstream_us: 50,
                resp_size: 64,
                answers: 1,
            };
            w.push(&event, &wire(&format!("n{i}.example.com")));
        }
        drop(w);
        (
            crate::api_backend::ApiBackend { src: Arc::new(src) },
            start * 1_000_000,
        )
    }

    /// A peer's query-log read, as the asking node sends it (`QueriesNegated` for a negated
    /// filter), answered by `b`.
    fn ask(
        b: &crate::api_backend::ApiBackend,
        params: &QueryParams,
        from_us: u64,
        to_us: u64,
        limit: usize,
    ) -> Result<Vec<u8>, String> {
        let p = Box::new(params.clone());
        let read = if params.negates() {
            Read::QueriesNegated {
                params: p,
                from_us,
                to_us,
                limit,
            }
        } else {
            Read::Queries {
                params: p,
                from_us,
                to_us,
                limit,
            }
        };
        answer(b, read)
    }

    fn page(
        b: &crate::api_backend::ApiBackend,
        params: &QueryParams,
        from_us: u64,
        to_us: u64,
        limit: usize,
    ) -> QueryPage {
        serde_json::from_slice(&ask(b, params, from_us, to_us, limit).unwrap()).unwrap()
    }

    /// REQ: OBS-003 — a peer's query-log read is answered with at most the API's own page of rows,
    /// whatever `limit` it names, and its cursor goes on from there; `limit` 0, a window that
    /// ends before it starts or starts at the end of time give an empty page, a cursor that isn't
    /// one an error.
    #[test]
    fn obs_003_peer_queries_read_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let (b, start_us) = node(dir.path());
        let all = QueryParams::default();
        for limit in [usize::MAX, 1_000_000, API_PAGE + 1] {
            let p = page(&b, &all, 0, 0, limit);
            assert_eq!(p.items.len(), API_PAGE, "limit {limit}");
            assert!(p.next_cursor.is_some(), "limit {limit}: more to read");
        }
        // The rest, from the cursor: every row once.
        let first = page(&b, &all, 0, 0, usize::MAX);
        let next = QueryParams {
            cursor: first.next_cursor.clone(),
            ..all.clone()
        };
        let rest = page(&b, &next, 0, 0, usize::MAX);
        assert_eq!(rest.items.len(), ROWS - API_PAGE);
        let mut seen: Vec<u64> = first
            .items
            .iter()
            .chain(&rest.items)
            .map(|r| r.ts_unix_micros)
            .collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), ROWS, "every row once");
        // A negated filter (every row matches it) and an open end: the same bound.
        let negated = QueryParams {
            name: Some("nothing.example".into()),
            name_not: Some(true),
            ..all.clone()
        };
        assert_eq!(page(&b, &negated, 0, 0, usize::MAX).items.len(), API_PAGE);
        assert_eq!(
            page(&b, &all, 0, u64::MAX, usize::MAX).items.len(),
            API_PAGE
        );
        // Nothing to read.
        let none = |from_us, to_us, limit| page(&b, &all, from_us, to_us, limit).items.len();
        assert_eq!(none(0, 0, 0), 0, "limit 0");
        assert_eq!(
            none(start_us + 100_000_000, start_us, usize::MAX),
            0,
            "inverted"
        );
        assert_eq!(none(u64::MAX, 0, usize::MAX), 0, "from the end of time");
        let bad = QueryParams {
            cursor: Some("not a cursor".into()),
            ..all.clone()
        };
        assert!(
            ask(&b, &bad, 0, 0, usize::MAX).is_err(),
            "a cursor that isn't one"
        );
    }

    /// REQ: OBS-003 — for every page the API itself asks a peer for (it sends its own `limit`,
    /// 1 to 1000, and the window, with no cursor; the next page's window ends where each node
    /// stopped), the answer is exactly the backend's page for that `limit`, as a node always
    /// answered: the same bytes, for plain and negated filters, windows, and every page of a walk.
    #[test]
    fn obs_003_peer_queries_read_matches_the_api_pages() {
        let dir = tempfile::tempdir().unwrap();
        let (b, start_us) = node(dir.path());
        let filters = [
            QueryParams::default(),
            QueryParams {
                status: Some("blocked".into()),
                ..QueryParams::default()
            },
            QueryParams {
                client: Some("10.0.0.2".into()),
                ..QueryParams::default()
            },
            QueryParams {
                name: Some("n1".into()),
                ..QueryParams::default()
            },
            QueryParams {
                status: Some("blocked".into()),
                status_not: Some(true),
                ..QueryParams::default()
            },
        ];
        let windows = [
            (0, 0),
            (start_us + 300_000_000, start_us + 1_500_000_000),
            (start_us, u64::MAX),
        ];
        let mut compared = 0;
        for limit in [1, 2, 50, 100, 999, API_PAGE] {
            for params in &filters {
                for (from_us, to_us) in windows {
                    let want =
                        serde_json::to_vec(&b.queries(params, from_us, to_us, limit).unwrap())
                            .unwrap();
                    let got = ask(&b, params, from_us, to_us, limit).unwrap();
                    assert!(got == want, "limit {limit}, {params:?}, {from_us}..{to_us}");
                    compared += 1;
                }
            }
        }
        // A walk the way the asking node pages: each next read ends where the last row was.
        for limit in [50, 333, API_PAGE] {
            let all = QueryParams::default();
            let (mut to_us, mut rows) = (0, 0);
            loop {
                let want = b.queries(&all, 0, to_us, limit).unwrap();
                let got: QueryPage = page(&b, &all, 0, to_us, limit);
                assert_eq!(
                    serde_json::to_vec(&got).unwrap(),
                    serde_json::to_vec(&want).unwrap(),
                    "limit {limit}, to {to_us}"
                );
                rows += got.items.len();
                match got.items.last() {
                    Some(r) if got.items.len() == limit => to_us = r.ts_unix_micros,
                    _ => break,
                }
                compared += 1;
            }
            assert_eq!(rows, ROWS, "limit {limit}: the walk reads every row");
        }
        assert!(compared > 90, "{compared}");
    }
}

#[cfg(test)]
mod anomaly_tests {
    use super::*;

    fn finding(client: &str, observed: f64) -> AnomalyFinding {
        AnomalyFinding {
            id: telltale_api::model::anomaly_id("rate_spike", client, None, 1_790_000_000, 3600),
            kind: "rate_spike".into(),
            client: client.into(),
            client_name: None,
            domain: None,
            window_start: "2026-09-21T13:46:40.000Z".into(),
            window_seconds: 3600,
            observed,
            baseline: 100.0,
            spread: 10.0,
            threshold: 200.0,
            detail: format!("{observed} queries"),
            nodes: Vec::new(),
            acknowledged: None,
            informational: false,
            muted_by: None,
            rhythm: None,
        }
    }

    // REQ: OBS-014, CLU-002 — two pods behind one load balancer find the same device's spike:
    // one entry, both nodes listed, the larger observation shown.
    #[test]
    fn obs_014_the_same_finding_on_two_nodes_is_one_entry() {
        let merged = merge_findings(vec![
            (
                "pod-a".into(),
                vec![finding("10.0.0.5", 300.0), finding("10.0.0.6", 250.0)],
            ),
            ("pod-b".into(), vec![finding("10.0.0.5", 420.0)]),
        ]);
        assert_eq!(merged.len(), 2);
        let five = merged.iter().find(|f| f.client == "10.0.0.5").unwrap();
        assert_eq!(five.nodes, ["pod-a", "pod-b"]);
        assert!((five.observed - 420.0).abs() < f64::EPSILON);
        let six = merged.iter().find(|f| f.client == "10.0.0.6").unwrap();
        assert_eq!(six.nodes, ["pod-a"]);
    }

    // REQ: OBS-014 — a peer that doesn't know the anomaly read is skipped, not fatal: the
    // read is new, and its answer decodes as a list.
    #[test]
    fn obs_014_anomaly_and_health_reads_round_trip() {
        let r: Read =
            serde_json::from_slice(&serde_json::to_vec(&Read::Anomalies { since_s: 5 }).unwrap())
                .unwrap();
        assert!(matches!(r, Read::Anomalies { since_s: 5 }));
        // REQ: API-005 (ADR-158) — the last-hour read carries its group; peers send every
        // client so the merged counts stay exact.
        let r: Read = serde_json::from_slice(
            &serde_json::to_vec(&Read::TopClientsRolling {
                limit: 7,
                group: Some("kids".into()),
            })
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            r,
            Read::TopClientsRolling { limit: 7, group: Some(ref g) } if g == "kids"
        ));
        assert!(!changes_state(&r));
        assert!(!changes_state(&Read::Anomalies { since_s: 5 }));
        assert!(!changes_state(&Read::Health));
    }
}

#[cfg(test)]
mod ephemeral_tests {
    use super::*;

    /// REQ: CLU-009 (ADR-058) — the reads an ephemeral member may not send: the ones that
    /// change the answering node; plain reads and tails stay allowed.
    #[test]
    fn clu_009_ephemeral_members_cannot_change_other_nodes() {
        assert!(changes_state(&Read::BlockingPause {
            group: None,
            minutes: 5
        }));
        assert!(changes_state(&Read::BlockingResume { group: None }));
        assert!(changes_state(&Read::CacheFlush {
            name: None,
            subtree: false
        }));
        assert!(!changes_state(&Read::CacheStats));
        assert!(!changes_state(&Read::BlockingState));
        assert!(!changes_state(&Read::ConfigVersion));
        assert!(!changes_state(&Read::ConfigEntries { kind: None }));
        assert!(!changes_state(&Read::Timeseries {
            step: Step::Minute,
            from_s: 0,
            to_s: 1
        }));
    }

    /// A backend for the RPC tests below: the `update` call never reads it.
    struct NoBackend;

    impl Backend for NoBackend {
        fn system_info(&self) -> SystemInfo {
            unreachable!("not read here")
        }
        fn timeseries(&self, _: Step, _: u64, _: u64) -> Vec<TimeBucket> {
            Vec::new()
        }
        fn top(&self, _: TopKind, _: Hour, _: usize, _: Option<IpAddr>) -> Vec<TopItem> {
            Vec::new()
        }
        fn latency(&self, _: LatencyBy, _: Hour) -> Vec<LatencyRow> {
            Vec::new()
        }
        fn queries(&self, _: &QueryParams, _: u64, _: u64, _: usize) -> Result<QueryPage, Problem> {
            Err(Problem::unavailable("stub"))
        }
        fn explain(&self, _: &ExplainParams) -> Result<Explanation, Problem> {
            Err(Problem::unavailable("stub"))
        }
        fn lists(&self) -> Vec<ListInfo> {
            Vec::new()
        }
        fn groups(&self) -> Vec<GroupInfo> {
            Vec::new()
        }
        fn clients(&self) -> Vec<ClientInfo> {
            Vec::new()
        }
        fn upstreams(&self) -> Vec<UpstreamInfo> {
            Vec::new()
        }
        fn config_version(&self) -> u64 {
            0
        }
    }

    /// REQ: OPS-014, CLU-009 (ADR-182, ADR-058) — the `update` RPC: an ephemeral member (a
    /// resolver pod) and a peer the registry doesn't list get nothing from it, neither a request
    /// nor a read of the node's update state (which names who asked and the errors), as for
    /// maintenance. A member the registry lists gets the node's own answer.
    #[tokio::test]
    async fn ops_014_an_ephemeral_member_cannot_ask_for_an_update() {
        use telltale_cluster::node::{Identity, NodeRecord};
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::init(
            dir.path(),
            "home",
            vec!["https://127.0.0.1:1".into()],
            "k8s",
        )
        .unwrap();
        let member = |node_id: &str, ephemeral: bool| NodeRecord {
            node_id: node_id.into(),
            site: node_id.into(),
            eligible: false,
            advertise: Vec::new(),
            joined: 1,
            witness: false,
            ephemeral,
        };
        let mut registry = id.registry();
        registry.push(member("replica-1", false));
        registry.push(member("pod-1", true));
        id.save_registry(&registry).unwrap();
        let cluster = Cluster::new(id, "0.1.0");
        let data = tempfile::tempdir().unwrap();
        let src = Arc::new(crate::http::tests::sources_in(data.path()));
        let handler = rpc_handler(src, Arc::new(NoBackend), cluster);
        let now = crate::maintenance::now_ms();
        let body = |call: serde_json::Value| {
            serde_json::to_vec(&serde_json::json!({ "call": call, "sent_ms": now })).unwrap()
        };
        let request = serde_json::json!({"op": "request", "to": "99.0.0", "by": "mallory"});
        let status = serde_json::json!({"op": "status"});
        let written = || {
            data.path().join("update-request.json").exists()
                || data.path().join("update").join("request.json").exists()
        };
        for peer in ["pod-1", "a-stranger"] {
            let e = handler(
                peer.into(),
                crate::node_update::KIND.into(),
                body(request.clone()),
            )
            .await
            .expect_err("an ephemeral or unlisted peer can't ask for an update");
            assert!(e.contains("ephemeral member"), "{peer}: {e}");
            assert!(!written(), "{peer}: nothing is written");
            // Nor a read: it names admins and errors, and nothing legitimate asks through such a
            // peer (`ctl` and the API go through full members).
            let e = handler(
                peer.into(),
                crate::node_update::KIND.into(),
                body(status.clone()),
            )
            .await
            .expect_err("an ephemeral or unlisted peer can't read the update state");
            assert!(e.contains("ephemeral member"), "{peer}: {e}");
        }
        // A member the registry lists gets this node's answer (a test build is a local build, so
        // a problem that says so, not a refusal of the sender).
        let answer = handler(
            "replica-1".into(),
            crate::node_update::KIND.into(),
            body(request),
        )
        .await
        .expect("a listed member is answered");
        let decoded: Result<telltale_api::model::NodeUpdate, Problem> =
            crate::forward::decode_answer(&answer);
        assert!(
            decoded
                .as_ref()
                .is_err_and(|p| p.code != telltale_api::problem::Code::Forbidden),
            "{decoded:?}"
        );
    }

    /// REQ: OPS-010, OPS-014 — maintenance and updates find their node the same way (one helper):
    /// `local` and this node's own ID are here; a member of the registry not heard from is
    /// `node_unreachable` with the call's own hint; anything else `node_unknown`.
    #[test]
    fn ops_014_a_call_about_a_nodes_own_state_finds_its_node() {
        use telltale_api::problem::Code;
        use telltale_cluster::node::{Identity, NodeRecord};
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::init(
            dir.path(),
            "home",
            vec!["https://127.0.0.1:1".into()],
            "k8s",
        )
        .unwrap();
        let me = id.meta.node_id.clone();
        let mut registry = id.registry();
        registry.push(NodeRecord {
            node_id: "replica-1".into(),
            site: "pi".into(),
            eligible: false,
            advertise: Vec::new(),
            joined: 1,
            witness: false,
            ephemeral: false,
        });
        id.save_registry(&registry).unwrap();
        let fed = Federated::new(Arc::new(NoBackend), Cluster::new(id, "0.1.0"));
        assert_eq!(fed.own_state_node("local", "h").unwrap(), None);
        assert_eq!(fed.own_state_node(&me, "h").unwrap(), None);
        let p = fed.own_state_node("replica-1", "must be up").unwrap_err();
        assert_eq!(
            (p.code, p.hint.as_deref()),
            (Code::NodeUnreachable, Some("must be up"))
        );
        assert_eq!(
            fed.own_state_node("nope", "h").unwrap_err().code,
            Code::NodeUnknown
        );
    }

    /// The `fn` names of one `impl` block in a source file.
    fn methods(src: &str, marker: &str) -> std::collections::BTreeSet<String> {
        let start = src.find(marker).expect("the impl block");
        let end = start + src[start..].find("\n}\n").expect("its end");
        src[start..end]
            .lines()
            .filter_map(|l| l.strip_prefix("    fn "))
            .filter_map(|l| l.split('(').next())
            .map(str::to_owned)
            .collect()
    }

    /// REQ: CLU-002 (regression 2026-10-09) — every API read a node answers on its own, a
    /// cluster node answers too: `Federated` overrides each `Backend` method `ApiBackend`
    /// implements, so none silently falls back to the trait's empty default (as
    /// `config_entries` did: every settings editor said "None yet" on a cluster node). The
    /// exceptions are reads only peers make, answered by each node's own backend.
    #[test]
    fn clu_002_federated_covers_every_backend_read() {
        let api = methods(
            include_str!("api_backend.rs"),
            "impl Backend for ApiBackend",
        );
        let fed = methods(include_str!("federated.rs"), "impl Backend for Federated");
        let peer_only = ["latency_hists", "shipped_timeseries"];
        let missing: Vec<&String> = api
            .iter()
            .filter(|m| !fed.contains(*m) && !peer_only.contains(&m.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "Federated doesn't implement {missing:?}"
        );
        assert!(fed.contains("config_entries"));
    }
}

#[cfg(test)]
mod name_tests {
    use super::*;
    use telltale_api::model::QueryRow;

    fn row(client: &str, name: Option<&str>) -> QueryRow {
        QueryRow {
            time: String::new(),
            ts_unix_micros: 1,
            client: client.into(),
            client_name: name.map(str::to_owned),
            group: None,
            name: "example.com".into(),
            qtype: "A".into(),
            status: "forwarded".into(),
            rcode: None,
            proto: "udp".into(),
            list: None,
            rule: None,
            total_ms: 1.0,
            upstream_ms: 0.5,
            response_bytes: 40,
            answers: 1,
            node: None,
        }
    }

    // REQ: CLU-002 (ADR-125) — a resolver pod's unnamed rows take the name the entry node
    // knows; named rows and unknown devices stay as they came.
    #[test]
    fn clu_002_rows_without_a_name_are_named_here() {
        let mut rows = vec![
            row("192.168.5.2", Some("k8s")),
            row("192.168.5.2", None),
            row("192.168.5.7", Some("tablet")),
            row("192.168.5.9", None),
            row("192.168.5.x", None),
        ];
        let asked = std::cell::Cell::new(0);
        name_rows(&mut rows, |ip| {
            asked.set(asked.get() + 1);
            (ip == IpAddr::from([192, 168, 5, 2])).then(|| "k8s".to_owned())
        });
        let names: Vec<Option<&str>> = rows.iter().map(|r| r.client_name.as_deref()).collect();
        assert_eq!(
            names,
            [Some("k8s"), Some("k8s"), Some("tablet"), None, None]
        );
        assert_eq!(
            asked.get(),
            2,
            "each address is looked up once; text that isn't one, never"
        );
    }
}

/// REQ: CLU-002, CLU-004 (ADR-174, GitHub issue #7) — what a federated read costs when the runtime
/// can't help it: at most its deadline, never for ever. Two real nodes, joined over a real
/// stream, on one runtime with a single worker.
#[cfg(test)]
mod bridge_tests {
    use std::sync::mpsc;
    use std::time::Instant;

    use telltale_cluster::node::{Identity, JoinRequest, TokenGrants};
    use telltale_cluster::pki;

    use super::*;

    /// The replica's own node: nothing but a configuration version no peer has.
    struct Local;

    impl Backend for Local {
        fn system_info(&self) -> SystemInfo {
            unreachable!("not read here")
        }
        fn timeseries(&self, _: Step, _: u64, _: u64) -> Vec<TimeBucket> {
            Vec::new()
        }
        fn top(&self, _: TopKind, _: Hour, _: usize, _: Option<IpAddr>) -> Vec<TopItem> {
            Vec::new()
        }
        fn latency(&self, _: LatencyBy, _: Hour) -> Vec<LatencyRow> {
            Vec::new()
        }
        fn queries(&self, _: &QueryParams, _: u64, _: u64, _: usize) -> Result<QueryPage, Problem> {
            Err(Problem::unavailable("stub"))
        }
        fn explain(&self, _: &ExplainParams) -> Result<Explanation, Problem> {
            Err(Problem::unavailable("stub"))
        }
        fn lists(&self) -> Vec<ListInfo> {
            Vec::new()
        }
        fn groups(&self) -> Vec<GroupInfo> {
            Vec::new()
        }
        fn clients(&self) -> Vec<ClientInfo> {
            Vec::new()
        }
        fn upstreams(&self) -> Vec<UpstreamInfo> {
            Vec::new()
        }
        fn config_version(&self) -> u64 {
            7
        }
    }

    /// A replica's federated backend, and the primary it asks (which answers one read: its
    /// configuration version, 4242).
    struct Nodes {
        rt: tokio::runtime::Runtime,
        fed: Arc<Federated>,
        primary: String,
        _stop: tokio::sync::watch::Sender<bool>,
        _dirs: (tempfile::TempDir, tempfile::TempDir),
    }

    fn two_nodes() -> Nodes {
        let handler: RpcHandler = Arc::new(|_peer, _kind, body| {
            Box::pin(async move {
                match serde_json::from_slice::<Read>(&body) {
                    Ok(Read::ConfigVersion) => {
                        serde_json::to_vec(&4242_u64).map_err(|e| e.to_string())
                    }
                    _ => Err("a read these tests don't ask".to_owned()),
                }
            })
        });
        two_nodes_answering(handler)
    }

    /// As [`two_nodes`], with the primary answering with `handler`.
    fn two_nodes_answering(handler: RpcHandler) -> Nodes {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        assert_eq!(rt.metrics().num_workers(), 1, "the shape of the test");
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let primary_id =
            Identity::init(a.path(), "home", vec![format!("https://{addr}")], "k8s").unwrap();
        let token = primary_id
            .create_token_for(
                60,
                None,
                TokenGrants {
                    eligible: true,
                    witness: false,
                },
            )
            .unwrap();
        let key = pki::new_node_key().unwrap();
        let joined = primary_id
            .accept_join(
                &JoinRequest {
                    witness: false,
                    ephemeral: false,
                    secret: token.secret,
                    csr_pem: key.csr_pem,
                    advertise: vec![],
                    site: "pi".into(),
                    eligible: true,
                    version: "0.1.0".into(),
                },
                None,
            )
            .unwrap();
        let replica_id =
            Identity::save_joined(b.path(), &key.key_pem, &joined, "pi", true, vec![]).unwrap();
        let (primary, replica) = (
            Cluster::new(primary_id, "0.1.0"),
            Cluster::new(replica_id, "0.1.0"),
        );
        let primary_node = primary.identity.meta.node_id.clone();
        primary.set_rpc_handler(handler);
        // The nodes' tasks run until the runtime is dropped (the sender stays in `Nodes`).
        let (stop_tx, stop) = tokio::sync::watch::channel(false);
        drop(rt.spawn(telltale_cluster::net::serve(
            Arc::clone(&primary),
            addr,
            stop.clone(),
        )));
        drop(rt.spawn(telltale_cluster::net::dial(Arc::clone(&replica), stop)));
        let until = Instant::now() + Duration::from_secs(30);
        while replica.reachable_primary().as_deref() != Some(primary_node.as_str()) {
            assert!(
                Instant::now() < until,
                "the replica never reached the primary"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        Nodes {
            rt,
            fed: Arc::new(Federated::new(Arc::new(Local), replica)),
            primary: primary_node,
            _stop: stop_tx,
            _dirs: (a, b),
        }
    }

    /// Parks the runtime's only worker on a gate (a send on the returned sender opens it), and
    /// returns once it is parked: the production wedge.
    fn wedge(rt: &tokio::runtime::Runtime) -> mpsc::Sender<()> {
        let (gate, shut) = mpsc::channel::<()>();
        let (parked_tx, parked) = mpsc::channel::<()>();
        drop(rt.spawn(async move {
            let _ = parked_tx.send(());
            // Blocking on purpose; it gives up after a minute so a failed test leaves nothing.
            let _ = shut.recv_timeout(Duration::from_secs(60));
        }));
        parked.recv_timeout(Duration::from_secs(10)).unwrap();
        gate
    }

    /// What `f` returns when run on a plain thread in the runtime's context (as a blocking-pool
    /// thread is). The guard is a `std` timeout here, never a timer on the wedged runtime: a
    /// read that never returns fails the test after 10 s instead of hanging it.
    fn on_a_thread<T: Send + 'static>(
        n: Nodes,
        gate: &mpsc::Sender<()>,
        f: impl FnOnce(&Federated) -> T + Send + 'static,
    ) -> (T, Duration, Nodes) {
        let (fed, handle) = (Arc::clone(&n.fed), n.rt.handle().clone());
        let (tx, rx) = mpsc::channel();
        let started = Instant::now();
        drop(std::thread::spawn(move || {
            let _in = handle.enter();
            let _ = tx.send(f(&fed));
        }));
        let Ok(v) = rx.recv_timeout(Duration::from_secs(10)) else {
            // A runtime with a parked worker would hang the test run when dropped.
            let _ = gate.send(());
            n.rt.shutdown_background();
            panic!("the read never returned: it waits on a runtime that can't run");
        };
        (v, started.elapsed(), n)
    }

    // REQ: CLU-002, CLU-004 (ADR-174) — a read from a thread that waits for the runtime, while
    // every worker is parked, comes back at its deadline (and the grace) with "didn't answer",
    // and the peer isn't asked. Before: the wait had no bound, and nothing could time it out.
    #[test]
    fn clu_002_a_wedged_runtime_costs_a_federated_read_its_deadline() {
        let n = two_nodes();
        let gate = wedge(&n.rt);
        let peer = n.primary.clone();
        let (r, took, n) = on_a_thread(n, &gate, move |fed| {
            fed.call_one(&peer, &Read::ConfigVersion, Duration::from_millis(100))
        });
        let _ = gate.send(());
        // Only an upper bound, far above the deadline: no race.
        assert!(took < Duration::from_secs(5), "{took:?}");
        let e = r
            .expect("there is a runtime")
            .expect_err("nothing could have answered it");
        assert!(e.contains("didn't answer in time"), "{e}");
        drop(n);
    }

    // REQ: CLU-002, CLU-004 (ADR-174) — the same for a read to every peer: the peer is listed
    // as one that didn't answer, and the answer isn't held up.
    #[test]
    fn clu_002_a_wedged_runtime_costs_a_gathered_read_its_deadline() {
        let n = two_nodes();
        let gate = wedge(&n.rt);
        let peer = n.primary.clone();
        let ((answers, missing, label), took, n) = on_a_thread(n, &gate, move |fed| {
            let answers = fed.gather(vec![(peer.clone(), Read::ConfigVersion)]);
            (answers, fed.missing_nodes(), fed.label_of(&peer))
        });
        let _ = gate.send(());
        // `DEADLINE` and the grace are about 2.25 s; the bound only has to be finite.
        assert!(took < Duration::from_secs(8), "{took:?}");
        assert!(answers.is_empty(), "{answers:?}");
        assert_eq!(missing, [label]);
        drop(n);
    }

    // REQ: CLU-004 (ADR-174, GitHub issue #7) — a federated read that is made on the runtime's
    // only worker (a handler that was missed) gives up at its deadline, falls back to this
    // node's own answer, and gives the worker back: the runtime goes on. Before: the worker
    // waited for work only it could do, and the node stopped.
    #[test]
    fn clu_004_a_read_on_the_only_worker_gives_up_and_frees_it() {
        let n = two_nodes();
        let (tx, rx) = mpsc::channel();
        let fed = Arc::clone(&n.fed);
        drop(n.rt.spawn(async move {
            let _ = tx.send(fed.config_version());
        }));
        let Ok(version) = rx.recv_timeout(Duration::from_secs(10)) else {
            n.rt.shutdown_background();
            panic!("the read parked the runtime's only worker for good");
        };
        assert_eq!(
            version, 7,
            "this node's own version: the primary couldn't be asked"
        );
        // The worker is free again: a task runs, and a timer fires.
        let (tx, rx) = mpsc::channel();
        drop(n.rt.spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = tx.send(());
        }));
        assert!(
            rx.recv_timeout(Duration::from_secs(10)).is_ok(),
            "the runtime is stuck"
        );
    }

    // REQ: CLU-002 (ADR-174) — with a runtime that works, the answers are the peer's, whether
    // asked of one peer, of all (the way a config version, an entry list, or a list is), or
    // through `config_version`, and nobody is listed as missing.
    #[test]
    fn clu_002_a_healthy_runtime_answers_a_federated_read() {
        let n = two_nodes();
        let _in = n.rt.enter();
        let body = n
            .fed
            .call_one(&n.primary, &Read::ConfigVersion, Duration::from_secs(5))
            .expect("there is a runtime")
            .expect("the primary answers");
        assert_eq!(serde_json::from_slice::<u64>(&body).unwrap(), 4242);
        assert_eq!(
            n.fed.config_version(),
            4242,
            "the primary's, not this node's 7"
        );
        let answers = n.fed.gather(vec![(n.primary.clone(), Read::ConfigVersion)]);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].0, n.primary);
        assert_eq!(serde_json::from_slice::<u64>(&answers[0].1).unwrap(), 4242);
        assert!(n.fed.missing_nodes().is_empty(), "nobody is missing");
        // A peer that errors is listed, and its error isn't an answer.
        let none = n.fed.gather(vec![(n.primary.clone(), Read::CacheStats)]);
        assert!(none.is_empty(), "an error is no answer");
        assert_eq!(n.fed.missing_nodes(), [n.fed.label_of(&n.primary)]);
    }

    /// A primary that answers the time-bucket reads (with no buckets) and the configuration
    /// version, and keeps every read it was asked.
    fn recording_peer() -> (RpcHandler, Arc<Mutex<Vec<Read>>>) {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&asked);
        let handler: RpcHandler = Arc::new(move |_peer, _kind, body| {
            let log = Arc::clone(&log);
            Box::pin(async move {
                let r = serde_json::from_slice::<Read>(&body).map_err(|e| e.to_string())?;
                let answer = match &r {
                    Read::Timeseries { .. } => serde_json::to_vec(&Vec::<TimeBucket>::new()),
                    Read::ConfigVersion => serde_json::to_vec(&4242_u64),
                    _ => return Err("a read these tests don't ask".to_owned()),
                };
                log.lock().unwrap_or_else(PoisonError::into_inner).push(r);
                answer.map_err(|e| e.to_string())
            })
        });
        (handler, asked)
    }

    /// The time-bucket windows a peer was asked for, oldest first.
    fn windows_asked(asked: &Mutex<Vec<Read>>) -> Vec<(u64, u64)> {
        let mut w: Vec<(u64, u64)> = asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter_map(|r| match r {
                Read::Timeseries { from_s, to_s, .. } => Some((*from_s, *to_s)),
                _ => None,
            })
            .collect();
        w.sort_unstable();
        w
    }

    // REQ: CLU-004, CLU-002 (ADR-174, final review F1) — a time range of more windows than the
    // cap (256 a peer) is asked of no peer: the peers are listed as not answering and the answer
    // is this node's own, at once. Before: one read per window and peer, however long the range
    // (from the epoch at one second a bucket, 7.5 million a peer; to the year 9999, a thousand
    // million), all under one place of the cap on reads.
    #[test]
    fn clu_004_a_timeseries_over_the_window_cap_asks_no_peer() {
        let (handler, asked) = recording_peer();
        let n = two_nodes_answering(handler);
        let _in = n.rt.enter();
        let label = n.fed.label_of(&n.primary);
        // 300 windows of 240 seconds: a little over the cap, so the test is small if it fails.
        let from = 1_791_000_000;
        let started = Instant::now();
        let items = n.fed.timeseries(Step::Second, from, from + 300 * 240);
        assert!(started.elapsed() < Duration::from_secs(5), "{items:?}");
        assert!(
            items.is_empty(),
            "this node's own, which has none: {items:?}"
        );
        assert_eq!(windows_asked(&asked), [], "no peer was asked");
        assert_eq!(n.fed.missing_nodes(), std::slice::from_ref(&label));
        // The cases the report was about: from the epoch, and to the year 9999.
        for (from, to) in [(0, 1_791_072_000), (1_791_072_000, 253_402_300_799)] {
            let started = Instant::now();
            let _ = n.fed.timeseries(Step::Second, from, to);
            assert!(started.elapsed() < Duration::from_secs(5));
            assert_eq!(windows_asked(&asked), [], "no peer was asked");
            assert_eq!(n.fed.missing_nodes(), std::slice::from_ref(&label));
        }
    }

    // REQ: CLU-002 (ADR-174, final review F1) — what the cap must not touch: the longest range
    // each step documents is asked of a peer window by window, all of it, and nobody is listed
    // as missing. `step=second` covers 15 minutes (4 windows), `minute` 7 days (43), `hour` 400
    // days (41), `day` everything, here since 1970 (87).
    #[test]
    fn clu_002_the_documented_ranges_are_asked_of_a_peer_in_full() {
        let (handler, asked) = recording_peer();
        let n = two_nodes_answering(handler);
        let _in = n.rt.enter();
        let now = 1_791_072_000;
        let cases = [
            (Step::Second, now - 900, now + 1, 4),
            (Step::Minute, now - 7 * 86_400, now + 1, 43),
            (Step::Hour, now - 400 * 86_400, now + 1, 41),
            (Step::Day, 0, now + 1, 87),
        ];
        for (step, from, to, count) in cases {
            asked.lock().unwrap_or_else(PoisonError::into_inner).clear();
            let _ = n.fed.timeseries(step, from, to);
            let w = windows_asked(&asked);
            assert_eq!(w.len(), count, "{step:?}");
            assert_eq!(w.first().map(|x| x.0), Some(from), "{step:?}");
            assert_eq!(w.last().map(|x| x.1), Some(to), "{step:?}");
            assert!(w.windows(2).all(|p| p[0].1 == p[1].0), "{step:?}: {w:?}");
            assert_eq!(n.fed.missing_nodes(), Vec::<String>::new(), "{step:?}");
        }
    }

    // REQ: CLU-004 (ADR-174, final review F1) — the bridge's own bound covers any other caller: a
    // gathered read of over 4,096 calls asks nobody and lists the peer as not answering.
    #[test]
    fn clu_004_a_gathered_read_over_the_ceiling_asks_no_peer() {
        let (handler, asked) = recording_peer();
        let n = two_nodes_answering(handler);
        let _in = n.rt.enter();
        let reads: Vec<(String, Read)> = (0..=bridge::MAX_READ_CALLS)
            .map(|_| (n.primary.clone(), Read::ConfigVersion))
            .collect();
        let answers = n.fed.gather(reads);
        assert!(answers.is_empty(), "{} answers", answers.len());
        assert!(
            asked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty(),
            "no peer was asked"
        );
        assert_eq!(n.fed.missing_nodes(), [n.fed.label_of(&n.primary)]);
    }

    // REQ: CLU-004 (ADR-174) — a range that is refused lists the peers it did not ask in one step:
    // a thread that reads `missingNodes` while another refuses ranges never sees the list
    // half made (the nodes that are not connected, and not yet the peers that weren't asked).
    // Before: the list was written, then added to under a second lock, so a watcher sometimes
    // saw the list without the peer. The watcher can only pass by never seeing a half list; it
    // proves nothing by one pass on its own, so it also has to have seen the whole one.
    #[test]
    fn clu_004_a_refused_range_lists_the_peers_in_one_step() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        // Tells the watcher to stop when this test ends, a failed assertion included.
        struct StopOnDrop(Arc<AtomicBool>);
        impl Drop for StopOnDrop {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let n = two_nodes();
        let _in = n.rt.enter();
        let label = n.fed.label_of(&n.primary);
        let peers = n.fed.peers();
        assert_eq!(peers.len(), 1, "the shape of the test");
        // A range of 300 windows at one second a bucket: over the cap, so it is refused.
        let (from, to) = (1_791_000_000, 1_791_000_000 + 300 * 240);
        let refuse = |fed: &Federated| {
            let (parts, answered) = fed.peer_timeseries(peers.clone(), Step::Second, from, to);
            assert!(parts.is_empty() && answered.is_empty(), "nobody was asked");
        };
        refuse(&n.fed);
        assert_eq!(n.fed.missing_nodes(), std::slice::from_ref(&label));
        let watching = Arc::new(AtomicBool::new(true));
        let _stop = StopOnDrop(Arc::clone(&watching));
        let seen = Arc::new(AtomicU64::new(0));
        let watcher = {
            let (fed, watching, seen) =
                (Arc::clone(&n.fed), Arc::clone(&watching), Arc::clone(&seen));
            let label = label.clone();
            std::thread::spawn(move || {
                let mut torn = 0_u64;
                while watching.load(Ordering::SeqCst) {
                    if fed.missing_nodes() == [label.clone()] {
                        seen.fetch_add(1, Ordering::SeqCst);
                    } else {
                        torn += 1;
                    }
                }
                torn
            })
        };
        // The watcher is reading before the refusals start, and keeps reading while they run.
        let until = Instant::now() + Duration::from_secs(10);
        while seen.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < until, "the watcher never saw the list");
            std::thread::sleep(Duration::from_millis(1));
        }
        for _ in 0..20_000 {
            refuse(&n.fed);
        }
        watching.store(false, Ordering::SeqCst);
        let torn = watcher.join().unwrap();
        assert_eq!(
            torn, 0,
            "{torn} reads saw a list that was not the whole one"
        );
    }

    /// A primary that answers each time-bucket window with one bucket at the window's start, and
    /// the window that starts at `big_from` with a bucket of `groups` groups: a big answer.
    fn peer_with_one_big_window(big_from: u64, groups: usize) -> RpcHandler {
        Arc::new(move |_peer, _kind, body| {
            Box::pin(async move {
                let Ok(Read::Timeseries { from_s, .. }) = serde_json::from_slice::<Read>(&body)
                else {
                    return Err("a read these tests don't ask".to_owned());
                };
                let mut b = TimeBucket {
                    start_unix_seconds: from_s,
                    total: 1,
                    ..TimeBucket::default()
                };
                if from_s == big_from {
                    b.by_group = (0..groups).map(|g| (format!("group-{g:04}"), 1)).collect();
                }
                serde_json::to_vec(&vec![b]).map_err(|e| e.to_string())
            })
        })
    }

    /// A replica's federated backend over `n`'s cluster, with bounds of its own.
    fn with_limiter(n: &Nodes, limiter: &'static bridge::Limiter) -> Federated {
        Federated {
            limiter,
            ..Federated::new(Arc::new(Local), Arc::clone(&n.fed.cluster))
        }
    }

    // REQ: CLU-004, CLU-002 (ADR-174) — over the real cluster channel: a peer whose answer for one
    // window would take the read past its cap on bytes is listed in `missingNodes`, the same as a
    // peer that didn't answer, and the read keeps the peer's other windows. This test's read may
    // hold 4,096 bytes; the big window's answer is about 6 KB, the others under 200 bytes each.
    // Before: every answer was kept, however big, and nobody was listed.
    #[test]
    fn clu_004_a_peer_whose_answer_is_over_the_cap_on_bytes_is_listed_as_missing() {
        let from = 1_791_000_000;
        let n = two_nodes_answering(peer_with_one_big_window(from + 240, 400));
        let _in = n.rt.enter();
        let limiter: &'static bridge::Limiter = Box::leak(Box::new(bridge::Limiter::with_caps(
            8,
            1_000,
            64 * 1024,
            4 * 1024,
        )));
        let fed = with_limiter(&n, limiter);
        let label = fed.label_of(&n.primary);
        // Four windows of 240 seconds; the second is the big one.
        let items = fed.timeseries(Step::Second, from, from + 4 * 240);
        let starts: Vec<u64> = items.iter().map(|b| b.start_unix_seconds).collect();
        assert_eq!(
            starts,
            [from, from + 480, from + 720],
            "the peer's other windows are kept"
        );
        assert_eq!(
            fed.missing_nodes(),
            [label],
            "the peer is listed as one that didn't answer"
        );
    }

    // REQ: CLU-004 (ADR-174) — the refusals are a counter with a closed set of reasons, one
    // sample each from the start (0 until something is refused), and each refusal counts under
    // its own: a read over the ceiling (`ceiling`), one with no place left (`waits`), one the
    // budget of calls has no room for (`spent`), and one that lost an answer to a cap on bytes
    // (`bytes`). Peers' names and what a user asked are never labels.
    #[test]
    fn clu_004_refused_reads_are_a_metric_with_a_closed_set_of_reasons() {
        let render = |l: &bridge::Limiter| {
            let mut w = telltale_telemetry::prom::PromWriter::new();
            render_refusals(l, &mut w);
            w.finish()
        };
        let reasons = |text: &str| -> Vec<(String, u64)> {
            text.lines()
                .filter(|l| l.starts_with("telltale_federated_refused_total{"))
                .filter_map(|l| {
                    let (labels, n) = l.rsplit_once(' ')?;
                    let reason =
                        labels.strip_prefix("telltale_federated_refused_total{reason=\"")?;
                    Some((reason.strip_suffix("\"}")?.to_owned(), n.parse().ok()?))
                })
                .collect()
        };
        let n = two_nodes_answering(peer_with_one_big_window(1_791_000_240, 400));
        let _in = n.rt.enter();
        // One place, room for 4 calls, and 4,096 bytes a read.
        let limiter: &'static bridge::Limiter = Box::leak(Box::new(bridge::Limiter::with_caps(
            1,
            4,
            64 * 1024,
            4 * 1024,
        )));
        let text = render(limiter);
        assert!(text.contains("# TYPE telltale_federated_refused_total counter\n"));
        let zero: Vec<(String, u64)> = ["waits", "spent", "ceiling", "bytes"]
            .iter()
            .map(|r| ((*r).to_owned(), 0))
            .collect();
        assert_eq!(reasons(&text), zero, "every reason, from the start");
        let fed = with_limiter(&n, limiter);
        // Over the ceiling: a range of more windows than a read may have.
        let _ = fed.timeseries(Step::Second, 1_791_000_000, 1_791_000_000 + 300 * 240);
        // Over the budget of calls: five windows, with room for four.
        let _ = fed.timeseries(Step::Second, 1_791_000_000, 1_791_000_000 + 5 * 240);
        // Over a cap on bytes: four windows, the second one big.
        let _ = fed.timeseries(Step::Second, 1_791_000_000, 1_791_000_000 + 4 * 240);
        // No place left: a read waits on a call the runtime can't run, and the next is refused.
        // (The last read's place goes back as its last task ends, a moment after it answered.)
        let until = Instant::now() + Duration::from_secs(10);
        while limiter.in_flight() > 0 {
            assert!(
                Instant::now() < until,
                "the last read's place never came back"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let gate = wedge(&n.rt);
        let waiting = fed.start_calls(
            n.rt.handle(),
            vec![(n.primary.clone(), b"{}".to_vec())],
            Duration::from_secs(5),
        );
        let _ = fed.gather(vec![(n.primary.clone(), Read::ConfigVersion)]);
        // Its call isn't sent: nobody waits for it when the runtime runs it.
        drop(waiting);
        let _ = gate.send(());
        let got = reasons(&render(limiter));
        let want: Vec<(String, u64)> = ["waits", "spent", "ceiling", "bytes"]
            .iter()
            .map(|r| ((*r).to_owned(), 1))
            .collect();
        assert_eq!(got, want);
    }
}
