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
    Queries {
        params: Box<QueryParams>,
        from_us: u64,
        to_us: u64,
        limit: usize,
    },
    /// The configuration version (a replica's `If-Match` and `ETag` use the primary's; T5.7).
    ConfigVersion,
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
        Read::Queries {
            params,
            from_us,
            to_us,
            limit,
        } => serde_json::to_vec(&b.queries(&params, from_us, to_us, limit).map_err(text)?),
        Read::ConfigVersion => serde_json::to_vec(&b.config_version()),
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

/// Where configuration writes go (T5.7).
enum WriteRoute {
    /// Applied on this node: it's the primary, or the cluster is configured from Git (which
    /// refuses API writes on every node).
    Here,
    /// Forwarded to the primary (`None`: it isn't reachable now).
    Primary(Option<String>),
}

/// The API backend of a clustered node: federated stats and query log over `local`.
pub(crate) struct Federated {
    local: Shared,
    cluster: Arc<Cluster>,
    /// Nodes the latest federated read couldn't reach (site labels).
    missing: Mutex<Vec<String>>,
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
        }
    }

    fn label_of(&self, node: &str) -> String {
        self.cluster
            .members()
            .into_iter()
            .find(|m| m.node_id == node)
            .map(|m| m.site)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| node.to_owned())
    }

    /// Where this node's configuration writes go.
    fn write_route(&self) -> WriteRoute {
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
            .filter(|m| !m.connected)
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

    /// Asks every reachable peer the same read; decoded answers.
    fn everyone<T: serde::de::DeserializeOwned>(&self, read: impl Fn() -> Read) -> Vec<T> {
        let reads = self
            .cluster
            .reachable_peers()
            .into_iter()
            .map(|p| (p, read()))
            .collect();
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
    fn cluster(&self) -> ClusterView {
        self.local.cluster()
    }

    // REQ: CLU-002 — counters sum across nodes.
    fn timeseries(&self, step: Step, from_s: u64, to_s: u64) -> Vec<TimeBucket> {
        let mut parts: Vec<Vec<TimeBucket>> =
            self.everyone(|| Read::Timeseries { step, from_s, to_s });
        parts.push(self.local.timeseries(step, from_s, to_s));
        federation::merge_timeseries(parts)
    }
    fn tail(&self, p: &TailParams) -> Result<tokio::sync::mpsc::Receiver<TailItem>, Problem> {
        self.local.tail(p)
    }
    // REQ: OBS-012 — Space-Saving lists merge by key.
    fn top(&self, kind: TopKind, hour: Hour, limit: usize, client: Option<IpAddr>) -> Vec<TopItem> {
        let mut parts: Vec<Vec<TopItem>> = self.everyone(|| Read::Top {
            kind,
            hour,
            limit,
            client,
        });
        parts.push(self.local.top(kind, hour, limit, client));
        federation::merge_top(parts, limit)
    }
    fn top_in_group(
        &self,
        kind: TopKind,
        hour: Hour,
        limit: usize,
        group: &str,
    ) -> Result<Vec<TopItem>, Problem> {
        let own = self.local.top_in_group(kind, hour, limit, group)?;
        let mut parts: Vec<Vec<TopItem>> = self.everyone(|| Read::TopInGroup {
            kind,
            hour,
            limit,
            group: group.to_owned(),
        });
        parts.push(own);
        Ok(federation::merge_top(parts, limit))
    }
    fn latency(&self, by: LatencyBy, hour: Hour) -> Vec<LatencyRow> {
        let mut parts: Vec<Vec<LatencyRow>> = self.everyone(|| Read::Latency { by, hour });
        parts.push(self.local.latency(by, hour));
        federation::merge_latency(parts)
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
            .cluster
            .reachable_peers()
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
        if let Some(to) = until(&me) {
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
    fn local_names(&self) -> Vec<LocalName> {
        self.local.local_names()
    }
    fn forwards(&self) -> Vec<ForwardInfo> {
        self.local.forwards()
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
        }
    }
}
