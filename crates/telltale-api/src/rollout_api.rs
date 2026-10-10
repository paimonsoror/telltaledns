//! REQ: CLU-013 (ADR-116) — staged rollouts and pins: the rollout in progress and the kept
//! versions (viewers), and promoting, aborting, pinning, and unpinning (admins; agents
//! `cluster:admin`). The commands run on the primary's publisher: a replica sends them there
//! over the cluster channel. Audited as `rollout.promote`, `rollout.abort`, `cluster.pin`, and
//! `cluster.unpin`.

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};

use crate::auth::Auth;
use crate::auth::routes::{body, principal, reason, remote};
use crate::config_api::{DryRun, expected_version};
use crate::maintenance_api::check_reason;
use crate::model::{ClusterVersions, PinRequest, RolloutAction, RolloutStatus};
use crate::problem::{Code, Problem};
use crate::{RolloutWrite, Shared};

/// The reads (viewer).
pub(crate) fn read_routes(backend: Shared) -> Router {
    Router::new()
        .route("/api/v1/cluster/rollout", get(rollout_status))
        .route("/api/v1/cluster/versions", get(cluster_versions))
        .with_state(backend)
}

/// The commands (admin).
pub(crate) fn admin_routes(backend: Shared, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/cluster/rollout/promote", post(rollout_promote))
        .route("/api/v1/cluster/rollout/abort", post(rollout_abort))
        .route("/api/v1/cluster/versions/{version}/pin", post(pin_version))
        .route("/api/v1/cluster/pin", delete(unpin_cluster))
        .with_state((backend, auth))
}

/// `epoch.seq` → `(epoch, seq)`.
pub fn parse_version(v: &str) -> Result<(u64, u64), Problem> {
    v.split_once('.')
        .and_then(|(e, s)| Some((e.trim().parse().ok()?, s.trim().parse().ok()?)))
        .ok_or_else(|| {
            Problem::invalid(format!("`version`: `{v}` isn't `<epoch>.<seq>`"))
                .hint("Use a version from GET /api/v1/cluster/versions, e.g. 3.124.")
        })
}

/// The staged rollout in progress, the guard's readings, and the pin.
///
/// `stage` is `none`, `canary` (a version is baking on the canary nodes and the primary;
/// everyone else gets it after `bakeSecs` if the guard passes), `waiting` (canaries are set and
/// none is online), or `pinned` (every node serves an older version until someone unpins). On
/// the primary a pin carries the `diff` it holds back. A replica that can't reach the primary
/// answers from the version it applied (`fromPrimary: false`).
#[utoipa::path(get, path = "/api/v1/cluster/rollout", tag = "system",
    responses(
        (status = 200, body = RolloutStatus, description = "The stage, the version baking, the canaries, the guard's readings, and the pin."),
        (status = 503, body = Problem, description = "Not in a cluster (`unavailable`)."),
    ))]
async fn rollout_status(State(backend): State<Shared>) -> Response {
    match backend.rollout_status().await {
        Ok(s) => Json(s).into_response(),
        Err(e) => e.into_response(),
    }
}

/// The versions the primary keeps for pinning back to, newest first.
///
/// Each with when and what made it, its outcome (`stable`, `canary`, `canary_promoted`,
/// `canary_failed`, `superseded`, `aborted`, `pinned_to`), the guard's readings, and whether
/// its files are still kept (`pinnable`). `[cluster.rollout] history` says how many (20).
#[utoipa::path(get, path = "/api/v1/cluster/versions", tag = "system",
    responses(
        (status = 200, body = ClusterVersions, description = "The kept versions, newest first."),
        (status = 503, body = Problem, description = "Not in a cluster, or the primary is unreachable (`unavailable`)."),
    ))]
async fn cluster_versions(State(backend): State<Shared>) -> Response {
    match backend.cluster_versions().await {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Runs `w` on the primary and audits it as `action` on `target`.
async fn run(
    backend: &Shared,
    auth: &Auth,
    headers: &HeaderMap,
    ext: &axum::http::Extensions,
    action: &str,
    target: &str,
    w: RolloutWrite,
) -> Response {
    let p = match principal(ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let dry = w.dry_run();
    let actor = auth.actor(&p, remote(auth, ext, headers), reason(headers));
    let w = w.with_by(actor.name.clone());
    match backend.rollout_command(w).await {
        Ok(r) => {
            if !dry {
                auth.record(
                    &actor,
                    action,
                    target,
                    &serde_json::json!({ "done": r.done, "changes": r.changes }),
                );
            }
            Json(r).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Promote the version baking.
///
/// Every node gets it now, as a new version with the same content, without waiting for the
/// rest of the bake. Admin (agents: `cluster:admin`); audit-logged as `rollout.promote`.
#[utoipa::path(post, path = "/api/v1/cluster/rollout/promote", tag = "system",
    responses(
        (status = 200, body = RolloutAction, description = "What was done (or, with dryRun, what would be), and what changes on every node."),
        (status = 409, body = Problem, description = "No version is baking (`no_rollout`)."),
        (status = 503, body = Problem, description = "The primary is unreachable (`unavailable`)."),
    ))]
async fn rollout_promote(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let w = RolloutWrite::Promote { by: String::new() };
    run(
        &backend,
        &auth,
        &headers,
        &ext,
        "rollout.promote",
        "rollout",
        w,
    )
    .await
}

/// Abort the version baking.
///
/// The cluster is pinned to the stable version before it (the primary and the canaries ran the
/// change, so they're reverted too), until someone unpins. Admin (agents: `cluster:admin`);
/// audit-logged as `rollout.abort`.
#[utoipa::path(post, path = "/api/v1/cluster/rollout/abort", tag = "system",
    responses(
        (status = 200, body = RolloutAction, description = "What was done (or, with dryRun, what would be), and what changes on every node."),
        (status = 409, body = Problem, description = "No version is baking (`no_rollout`)."),
        (status = 503, body = Problem, description = "The primary is unreachable (`unavailable`)."),
    ))]
async fn rollout_abort(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let w = RolloutWrite::Abort { by: String::new() };
    run(
        &backend,
        &auth,
        &headers,
        &ext,
        "rollout.abort",
        "rollout",
        w,
    )
    .await
}

/// Pin the cluster to a kept version ("roll back").
///
/// The primary publishes a **new** version (versions never go backwards) whose configuration
/// and filter snapshot are `version`'s, and serves it itself; every node follows within
/// seconds. While pinned, configuration changes answer `409 cluster_pinned` with the diff they
/// would publish, the Git source keeps polling but publishes nothing, and health is
/// `degraded` (`cluster_pinned`). The configuration files, the UI's entries, and Git are not
/// rewritten: the diff says what to change there. `?dryRun=true` checks and shows the diff.
/// `If-Match` (a configuration version) refuses with 412 if the configuration changed since.
/// Admin (agents: `cluster:admin` with human approval); audit-logged as `cluster.pin`.
#[utoipa::path(post, path = "/api/v1/cluster/versions/{version}/pin", tag = "system",
    params(("version" = String, Path, description = "`<epoch>.<seq>` from GET /api/v1/cluster/versions."), DryRun),
    request_body = PinRequest,
    responses(
        (status = 200, body = RolloutAction, description = "What was done (or, with dryRun, what would be), and what changes on every node."),
        (status = 404, body = Problem, description = "No kept version by that number (`version_unknown`)."),
        (status = 409, body = Problem, description = "Its files are no longer kept (`version_blobs_missing`)."),
        (status = 412, body = Problem, description = "The configuration changed since `If-Match` (`version_conflict`)."),
        (status = 422, body = Problem, description = "No usable reason (`maintenance_invalid`)."),
        (status = 503, body = Problem, description = "The primary is unreachable (`unavailable`)."),
    ))]
async fn pin_version(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    Path(version): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<PinRequest>, JsonRejection>,
) -> Response {
    let checked = body(b)
        .and_then(|req| check_reason(req.reason.as_deref()))
        .and_then(|r| parse_version(&version).map(|v| (r, v)))
        .and_then(|(r, v)| expected_version(&headers).map(|e| (r, v, e)));
    let (why, to, expect) = match checked {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let w = RolloutWrite::Pin {
        epoch: to.0,
        seq: to.1,
        reason: why,
        dry_run: q.dry_run.unwrap_or(false),
        expect,
        by: String::new(),
    };
    run(&backend, &auth, &headers, &ext, "cluster.pin", &version, w).await
}

/// Unpin the cluster.
///
/// The primary publishes its current configuration again (through a staged rollout when
/// canaries are set) and serves it itself. `?dryRun=true` checks and shows the diff. The reason
/// (`X-Telltale-Reason`) goes into the audit log. Admin (agents: `cluster:admin` with human
/// approval); audit-logged as `cluster.unpin`.
#[utoipa::path(delete, path = "/api/v1/cluster/pin", tag = "system",
    params(DryRun),
    responses(
        (status = 200, body = RolloutAction, description = "What was done (or, with dryRun, what would be), and what changes on every node."),
        (status = 409, body = Problem, description = "The cluster isn't pinned (`conflict`)."),
        (status = 412, body = Problem, description = "The configuration changed since `If-Match` (`version_conflict`)."),
        (status = 503, body = Problem, description = "The primary is unreachable (`unavailable`)."),
    ))]
async fn unpin_cluster(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let expect = match expected_version(&headers) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let w = RolloutWrite::Unpin {
        dry_run: q.dry_run.unwrap_or(false),
        expect,
        by: String::new(),
    };
    run(
        &backend,
        &auth,
        &headers,
        &ext,
        "cluster.unpin",
        "cluster",
        w,
    )
    .await
}

/// The problem for a command that needs a cluster.
pub fn no_cluster() -> Problem {
    Problem::new(Code::Unavailable, "staged rollouts and pins need a cluster")
        .hint("Set up clustering (Cluster page) first; a single node applies changes at once.")
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: CLU-013 — versions are `<epoch>.<seq>`.
    #[test]
    fn clu_013_versions_parse() {
        assert_eq!(parse_version("3.124").unwrap(), (3, 124));
        for bad in ["3", "x.1", "3.", ".4", "3.4.5"] {
            assert_eq!(
                parse_version(bad).unwrap_err().code,
                Code::InvalidParameter,
                "{bad}"
            );
        }
    }
}
