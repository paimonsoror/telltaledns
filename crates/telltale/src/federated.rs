//! Federated reads (REQ: CLU-002, OBS-012; T5.6): any node's dashboard and query log show the
//! whole cluster. Stats and query-log reads go to every reachable peer over the cluster
//! channel at once, with a deadline, and merge (`telltale_api::federation`); a node that
//! doesn't answer is listed in `missingNodes` instead of holding the read up. Everything else
//! — configuration, explain, the live tail — is this node's own (the tail stays node-local).
//!
//! Nothing here touches DNS answering: reads run on API worker threads only (CLU-004).

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
    Latency {
        by: LatencyBy,
        hour: Hour,
    },
    /// REQ: OBS-010 (T9.5) — devices first seen.
    NewDevices {
        since_s: u64,
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
    /// The configuration version (a replica's `If-Match` and `ETag` use the primary's; T5.7).
    ConfigVersion,
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
        Read::Latency { by, hour } => serde_json::to_vec(&b.latency(by, hour)),
        Read::LatencyHist { by, hour } => serde_json::to_vec(&b.latency_hists(by, hour)),
        Read::NewDevices { since_s } => serde_json::to_vec(&b.new_devices(since_s)),
        Read::TailOpen { params } => serde_json::to_vec(&tail_open(b, &params).map_err(text)?),
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
        } => serde_json::to_vec(&b.queries(&params, from_us, to_us, limit).map_err(text)?),
        Read::ConfigVersion => serde_json::to_vec(&b.config_version()),
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
    }
    .map_err(|e| e.to_string())
}

/// What answers peers: reads from this node's local backend (on a blocking thread), and
/// forwarded writes when this node is the primary (T5.7).
pub(crate) fn rpc_handler(
    src: Arc<crate::http::Sources>,
    local: Shared,
    cluster: Arc<Cluster>,
) -> RpcHandler {
    Arc::new(move |peer, kind, body| {
        let (src, local, cluster) = (Arc::clone(&src), Arc::clone(&local), Arc::clone(&cluster));
        Box::pin(async move {
            if kind == telltale_cluster::failover::KIND {
                // REQ: CLU-005 — a vote request (ADR-056); the ballot is written to disk first.
                return tokio::task::spawn_blocking(move || {
                    telltale_cluster::failover::answer(&cluster, &peer, &body)
                })
                .await
                .map_err(|e| format!("vote worker failed: {e}"))?;
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
            tokio::task::spawn_blocking(move || answer(local.as_ref(), read))
                .await
                .map_err(|e| format!("read worker failed: {e}"))?
        })
    })
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

    /// One RPC to one peer from synchronous code; `None` without a runtime.
    fn call_one(
        &self,
        peer: &str,
        read: &Read,
        timeout: Duration,
    ) -> Option<Result<Vec<u8>, String>> {
        let body = serde_json::to_vec(read).ok()?;
        let rt = tokio::runtime::Handle::try_current().ok()?;
        let cluster = Arc::clone(&self.cluster);
        std::thread::scope(|s| {
            s.spawn(|| rt.block_on(cluster.call(peer, KIND, body, timeout)))
                .join()
                .ok()
        })
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

    /// Sends `reads` (one per peer) concurrently and waits at most [`DEADLINE`]. Records
    /// which known nodes didn't answer.
    fn gather(&self, reads: Vec<(String, Read)>) -> Vec<(String, Vec<u8>)> {
        let mut missing: Vec<String> = self
            .cluster
            .members()
            .into_iter()
            .filter(|m| !m.connected && self.in_scope(&m.node_id))
            .map(|m| if m.site.is_empty() { m.node_id } else { m.site })
            .collect();
        let calls: Vec<(String, Vec<u8>)> = reads
            .into_iter()
            .filter_map(|(peer, r)| serde_json::to_vec(&r).ok().map(|b| (peer, b)))
            .collect();
        let answers = match tokio::runtime::Handle::try_current() {
            Ok(rt) if !calls.is_empty() => {
                let cluster = Arc::clone(&self.cluster);
                // A plain thread blocks on the runtime, so this works whether the caller is a
                // blocking worker or not.
                std::thread::scope(|s| {
                    s.spawn(|| {
                        rt.block_on(async {
                            let tasks: Vec<_> = calls
                                .into_iter()
                                .map(|(peer, body)| {
                                    let c = Arc::clone(&cluster);
                                    tokio::spawn(async move {
                                        let r = c.call(&peer, KIND, body, DEADLINE).await;
                                        (peer, r)
                                    })
                                })
                                .collect();
                            let mut out = Vec::new();
                            for t in tasks {
                                if let Ok(r) = t.await {
                                    out.push(r);
                                }
                            }
                            out
                        })
                    })
                    .join()
                    .unwrap_or_default()
                })
            }
            _ => Vec::new(),
        };
        let mut ok = Vec::new();
        for (peer, r) in answers {
            match r {
                Ok(body) => ok.push((peer, body)),
                Err(e) => {
                    tracing::debug!(peer, error = %e, "federated read failed");
                    missing.push(self.label_of(&peer));
                }
            }
        }
        missing.sort();
        missing.dedup();
        *self.missing.lock().unwrap_or_else(PoisonError::into_inner) = missing;
        ok
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

    // REQ: CLU-002 — counters sum across nodes.
    fn timeseries(&self, step: Step, from_s: u64, to_s: u64) -> Vec<TimeBucket> {
        let answers = self.gather(
            self.peers()
                .into_iter()
                .map(|p| (p, Read::Timeseries { step, from_s, to_s }))
                .collect(),
        );
        let mut live: Vec<String> = vec![self.cluster.identity.meta.node_id.clone()];
        let mut parts: Vec<Vec<TimeBucket>> = Vec::new();
        for (peer, body) in answers {
            if let Ok(v) = serde_json::from_slice(&body) {
                parts.push(v);
                live.push(peer);
            }
        }
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
                let read = Read::Queries {
                    params: Box::new(params.clone()),
                    from_us,
                    to_us: to,
                    limit,
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
        match local_error {
            // Only this node can say why its own log is unavailable; peers' rows still help.
            Some(e) if pages.is_empty() => Err(e),
            Some(_) => {
                self.missing
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(self.own_label());
                Ok(federation::merge_queries(pages, limit, &prev))
            }
            None => Ok(federation::merge_queries(pages, limit, &prev)),
        }
    }

    fn explain(&self, p: &ExplainParams) -> Result<Explanation, Problem> {
        self.local.explain(p)
    }
    fn lists(&self) -> Vec<ListInfo> {
        self.local.lists()
    }
    fn groups(&self) -> Vec<GroupInfo> {
        self.local.groups()
    }
    fn clients(&self) -> Vec<ClientInfo> {
        self.local.clients()
    }
    fn upstreams(&self) -> Vec<UpstreamInfo> {
        self.local.upstreams()
    }
    fn anomalies(&self, since_s: u64) -> Vec<AnomalyFinding> {
        self.local.anomalies(since_s)
    }
    // REQ: OBS-010 (T9.6) — alerts are evaluated here (the primary) or nowhere: this node's.
    fn alerts_status(&self) -> telltale_api::model::AlertsStatus {
        self.local.alerts_status()
    }
    fn alert_test(
        &self,
        name: &str,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::AlertTest, Problem>> {
        self.local.alert_test(name)
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
