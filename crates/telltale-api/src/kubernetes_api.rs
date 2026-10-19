//! Kubernetes workloads as devices (REQ: FLT-017; T15.1, ADR-150): the workload list and the
//! watcher's status. The group rules (`/kubernetes/map/...`) are configuration writes, in
//! `config_api`.

use axum::Json;
use axum::extract::{Query, State};
use axum::routing::get;
use serde::Deserialize;
use utoipa::IntoParams;

use crate::Shared;
use crate::model::{KubernetesStatus, WorkloadPage};
use crate::problem::{Code, Problem};

/// Most workloads per page.
pub const PAGE: usize = 200;

pub(crate) fn routes(backend: Shared) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/kubernetes/workloads", get(workloads))
        .route("/api/v1/kubernetes/status", get(status))
        .with_state(backend)
}

/// `kubernetes_disabled`: the feature is off.
pub fn disabled() -> Problem {
    Problem::new(
        Code::KubernetesDisabled,
        "Kubernetes workloads are off: no node watches the Kubernetes API",
    )
    .hint("Set kubernetes.enabled: true in the Helm chart's values (with kubernetes.clusterDns), or [kubernetes] enabled = true, then point the cluster's DNS (or a workload's dnsConfig) at TelltaleDNS.")
}

/// `GET /api/v1/kubernetes/workloads` parameters.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct WorkloadParams {
    /// Only this namespace.
    #[param(example = "media")]
    pub namespace: Option<String>,
    /// Only workloads in this group (`none` for those without one).
    pub group: Option<String>,
    /// At most this many (default and maximum 200).
    pub limit: Option<usize>,
    /// From the previous page's `nextCursor`.
    pub cursor: Option<String>,
    /// `cluster` (default) or `node:local`: whose counts.
    pub scope: Option<String>,
}

/// The Kubernetes workloads TelltaleDNS names (FLT-017).
///
/// One row per workload (`namespace/kind/name`, from its pods' owners: a Deployment's replicas
/// are one device across rollouts), sorted by name: its group and where that came from (a pod
/// label, a namespace label, a `[[kubernetes.map]]` rule, or `default_group`), its pods and
/// their addresses, queries and blocked answers in the last 24 hours (summed over every node in
/// a cluster; `missingNodes` lists nodes whose counts are missing), and when it last asked.
/// Every node holds the watcher's table, so the list itself never depends on one node. Use the
/// name or `key` as `client` anywhere a device goes: the query log, the timeline, rhythm,
/// identity. `kubernetes_disabled` (409) when the feature is off. Example:
/// `GET /api/v1/kubernetes/workloads?namespace=media`.
#[utoipa::path(get, path = "/api/v1/kubernetes/workloads", tag = "config",
    params(WorkloadParams),
    responses(
        (status = 200, body = WorkloadPage, description = "The workloads, a page at a time."),
        (status = 400, body = Problem, description = "A bad cursor or scope."),
        (status = 409, body = Problem, description = "`kubernetes_disabled`: no node watches the Kubernetes API."),
    ))]
pub(crate) async fn workloads(
    State(b): State<Shared>,
    Query(p): Query<WorkloadParams>,
) -> Result<Json<WorkloadPage>, Problem> {
    let b = crate::pick(&b, p.scope.as_deref())?;
    let start = match p.cursor.as_deref() {
        None | Some("") => 0,
        Some(c) => c.parse::<usize>().map_err(|_| {
            Problem::invalid(format!("`cursor`: `{c}` isn't one of ours"))
                .hint("Pass the previous page's nextCursor as is.")
        })?,
    };
    let limit = p.limit.unwrap_or(PAGE).clamp(1, PAGE);
    let (all, missing_nodes) =
        tokio::task::spawn_blocking(move || (b.kubernetes_workloads(), b.missing_nodes()))
            .await
            .map_err(|e| Problem::internal(format!("request worker failed: {e}")))?;
    let mut all = all?;
    all.retain(|w| {
        p.namespace.as_deref().is_none_or(|n| w.namespace == n)
            && p.group.as_deref().is_none_or(|g| match &w.group {
                Some(x) => x == g,
                None => g == "none",
            })
    });
    all.sort_by(|a, b| a.name.cmp(&b.name));
    let total = all.len();
    let items: Vec<_> = all.into_iter().skip(start).take(limit).collect();
    let next = start + items.len();
    Ok(Json(WorkloadPage {
        items,
        total,
        next_cursor: (next < total).then(|| next.to_string()),
        missing_nodes,
    }))
}

/// Whether Kubernetes workloads are on, and how the table is doing (FLT-017).
///
/// `role`: `watching` (this node lists and watches pods and namespaces), `peer` (it takes the
/// watcher's table over the cluster channel), `fixture` (a test file), or `off`. With
/// `lastSyncSecondsAgo` (the API server last confirmed the table, or a peer last sent it), the
/// table's size, the namespaces watched, and the last error until the next success. The health
/// level turns `degraded` (`kubernetes_stale`) when a watcher's table is older than 15 minutes;
/// DNS answers regardless.
#[utoipa::path(get, path = "/api/v1/kubernetes/status", tag = "config",
    operation_id = "kubernetes_status",
    responses((status = 200, body = KubernetesStatus, description = "The status.")))]
pub(crate) async fn status(State(b): State<Shared>) -> Json<KubernetesStatus> {
    Json(
        tokio::task::spawn_blocking(move || b.kubernetes_status())
            .await
            .unwrap_or_default(),
    )
}
