//! REQ: CLU-014 (ADR-151) — failover drills: one node stops answering chosen devices (or a
//! group, or everyone) for 15 to 300 seconds while the rest of the cluster serves, then a
//! report says who followed to another node, how fast, and who was stuck. A drill is a
//! maintenance window with a drop: it's the node's own state, not configuration (allowed under
//! `GitOps`), sent to the node it's for, audited as `drill.start` / `drill.end`, and needs an
//! operator (agents: `ops:drill`, never in the default scopes). Reports and the affinity view
//! are reads (`analytics:read`).

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::auth::Auth;
use crate::auth::routes::{body, principal, reason, remote};
use crate::model::{
    ActiveDrill, AffinityPage, DrillPage, DrillReport, DrillRequest, DrillStart, DrillTargets,
};
use crate::problem::{Code, Problem};
use crate::{DrillWrite, Shared};

/// A drill's default, shortest, and longest lengths (seconds). The cap isn't configurable:
/// a drill that runs long is an outage (ADR-151).
pub const DEFAULT_SECS: u32 = 60;
pub const MIN_SECS: u32 = 15;
pub const MAX_SECS: u32 = 300;
/// The longest reason.
pub const MAX_REASON: usize = 200;
/// Most devices a `clients` target names.
pub const MAX_CLIENTS: usize = 256;

/// Drills aren't available (a backend without them).
pub fn no_drills() -> Problem {
    Problem::unavailable("failover drills aren't available on this node")
}

/// Start and end (operator; agents `ops:drill`).
pub(crate) fn write_routes(backend: Shared, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/nodes/{id}/drill", post(start).delete(end))
        .with_state((backend, auth))
}

/// The running drill, reports, and the affinity view (viewer; agents `analytics:read`).
pub(crate) fn read_routes(backend: Shared) -> Router {
    Router::new()
        .route("/api/v1/nodes/{id}/drill", get(active))
        .route("/api/v1/drills", get(list))
        .route("/api/v1/drills/{id}", get(report))
        .route("/api/v1/clients/affinity", get(affinity))
        .with_state(backend)
}

/// A drill's length: [`MIN_SECS`] to [`MAX_SECS`].
pub fn check_secs(secs: Option<u32>) -> Result<u32, Problem> {
    let s = secs.unwrap_or(DEFAULT_SECS);
    if !(MIN_SECS..=MAX_SECS).contains(&s) {
        return Err(Problem::new(
            Code::DrillTargets,
            format!("`forSecs`: {s} is outside {MIN_SECS} to {MAX_SECS} seconds"),
        )
        .hint("A drill runs at most 5 minutes: longer, it's an outage. Devices with a working second server switch within a few seconds."));
    }
    Ok(s)
}

/// A reason: present, one line, at most [`MAX_REASON`] characters.
pub fn check_reason(r: Option<&str>) -> Result<String, Problem> {
    let r = r.map(str::trim).unwrap_or_default();
    if r.is_empty() || r.chars().count() > MAX_REASON || r.chars().any(char::is_control) {
        return Err(Problem::new(
            Code::DrillTargets,
            format!("`reason`: 1 to {MAX_REASON} characters on one line, saying why"),
        )
        .hint("For example \"does the Pi's second server work?\": it shows with the report and in the audit log."));
    }
    Ok(r.to_owned())
}

/// Targets as given: at least one client, at most [`MAX_CLIENTS`], no empty names.
pub fn check_targets(t: &DrillTargets) -> Result<(), Problem> {
    match t {
        DrillTargets::Clients { clients }
            if clients.is_empty()
                || clients.len() > MAX_CLIENTS
                || clients.iter().any(|c| c.trim().is_empty()) =>
        {
            Err(Problem::new(
                Code::DrillTargets,
                format!(
                    "`targets.clients`: 1 to {MAX_CLIENTS} addresses, device names, or workloads"
                ),
            )
            .hint("Or `\"all\"`, or `{\"group\": \"iot\"}`."))
        }
        DrillTargets::Group { group } if group.trim().is_empty() => Err(Problem::new(
            Code::DrillTargets,
            "`targets.group`: a group's name",
        )),
        _ => Ok(()),
    }
}

/// `?dryRun=true`.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub(crate) struct DryRun {
    /// Only check the preconditions and resolve the targets; nothing is dropped.
    #[serde(default)]
    dry_run: bool,
}

/// Start a failover drill on a node.
///
/// For `forSecs` (15 to 300, default 60) the node stops answering its `targets` (`"all"`,
/// `{"clients": [...]}` with addresses, device names, or Kubernetes workloads, or
/// `{"group": "iot"}`): UDP queries get no answer and stream connections are closed, the
/// nearest thing to a dead node, counted as status `drilled`. It's a maintenance window too
/// (not ready, alerts muted, out of elections; on the primary, `handover` hands the role over
/// first). The node's infrastructure, cluster nodes, loopback, and excluded devices are always
/// answered. Every node records who asks it during the drill; 60 seconds after the end the
/// drilled node merges them into a report (`GET /api/v1/drills/{id}`). Refused (409
/// `drill_refused`, the reason in the detail) when no other node is ready and answering, the
/// node is in maintenance, a drill ran in the cluster in the last 10 minutes, a rollout is
/// pinned or baking, or health is `severe`; 409 `drill_active` while one runs; 422
/// `drill_targets` for an unknown group, no device seen in the last hour, or a bad length or
/// reason. A restart cancels a drill. `?dryRun=true` returns the checks, the baseline, and the
/// devices without dropping anything. Not a configuration change: a GitOps-managed cluster
/// takes it too. Needs the operator role (agents: the `ops:drill` scope, which no token gets by
/// default); audit-logged as `drill.start`.
#[utoipa::path(post, path = "/api/v1/nodes/{id}/drill", tag = "system", operation_id = "drill_start",
    params(("id" = String, Path, description = "`local`, or a node's ID, site, or pod name."), DryRun),
    request_body = DrillRequest,
    responses(
        (status = 201, body = DrillStart, description = "The drill started."),
        (status = 200, body = DrillStart, description = "A dry run: the checks, the baseline, and the devices."),
        (status = 404, body = Problem, description = "No such node (`node_unknown`)."),
        (status = 409, body = Problem, description = "A precondition refuses it (`drill_refused`), or one is running (`drill_active`)."),
        (status = 422, body = Problem, description = "Unusable targets, length, or reason (`drill_targets`)."),
        (status = 503, body = Problem, description = "The node isn't reachable over the cluster channel (`node_unreachable`)."),
    ))]
async fn start(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    Path(id): Path<String>,
    Query(params): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    payload: Result<Json<DrillRequest>, JsonRejection>,
) -> Response {
    let req = match body(payload) {
        Ok(req) => req,
        Err(problem) => return problem.into_response(),
    };
    let who = match principal(&ext) {
        Ok(who) => who,
        Err(problem) => return problem.into_response(),
    };
    let checked = check_reason(req.reason.as_deref()).and_then(|why| {
        check_targets(&req.targets)?;
        Ok((why, check_secs(req.for_secs)?))
    });
    let (why, for_secs) = match checked {
        Ok(v) => v,
        Err(problem) => return problem.into_response(),
    };
    let actor = auth.actor(&who, remote(&auth, &ext, &headers), reason(&headers));
    let write = DrillWrite::Start {
        for_secs,
        targets: req.targets.clone(),
        reason: why.clone(),
        handover: req.handover.unwrap_or(true),
        by: actor.name.clone(),
        dry_run: params.dry_run,
    };
    match backend.drill(&id, write).await {
        Ok(r) if r.dry_run => Json(r).into_response(),
        Ok(r) => {
            auth.record(
                &actor,
                "drill.start",
                &r.node,
                &serde_json::json!({
                    "id": r.id,
                    "until": r.until,
                    "targets": r.targets,
                    "reason": why,
                    "handover": r.handover,
                    "requested": id,
                }),
            );
            (axum::http::StatusCode::CREATED, Json(r)).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// End a node's drill early.
///
/// The node answers its targets again at once and leaves the maintenance window; the report
/// still runs 60 seconds later. 404 when no drill runs there. Needs the operator role (agents:
/// `ops:drill`); audit-logged as `drill.end`.
#[utoipa::path(delete, path = "/api/v1/nodes/{id}/drill", tag = "system", operation_id = "drill_end",
    params(("id" = String, Path, description = "`local`, or a node's ID, site, or pod name.")),
    responses(
        (status = 200, body = DrillStart, description = "The drill that ended (`until` is now)."),
        (status = 404, body = Problem, description = "No such node, or no drill running there."),
        (status = 503, body = Problem, description = "The node isn't reachable over the cluster channel (`node_unreachable`)."),
    ))]
async fn end(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    match backend
        .drill(
            &id,
            DrillWrite::End {
                by: actor.name.clone(),
            },
        )
        .await
    {
        Ok(r) => {
            auth.record(
                &actor,
                "drill.end",
                &r.node,
                &serde_json::json!({ "id": r.id, "requested": id, "early": true }),
            );
            Json(r).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// The drill running on a node.
///
/// Its targets, reason, time left, and how many queries (from how many devices) it hasn't
/// answered so far. 404 when none runs.
#[utoipa::path(get, path = "/api/v1/nodes/{id}/drill", tag = "system", operation_id = "drill_active",
    params(("id" = String, Path, description = "`local`, or a node's ID, site, or pod name.")),
    responses(
        (status = 200, body = ActiveDrill, description = "The running drill."),
        (status = 404, body = Problem, description = "No drill runs there (or no such node)."),
    ))]
async fn active(State(backend): State<Shared>, Path(id): Path<String>) -> Response {
    match backend.drill_active(&id).await {
        Ok(Some(d)) => Json(d).into_response(),
        Ok(None) => Problem::not_found(format!("no drill runs on `{id}`"))
            .hint(
                "Start one with POST /api/v1/nodes/{id}/drill; past drills are at /api/v1/drills.",
            )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /api/v1/drills`.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub(crate) struct ListParams {
    /// At most this many (1 to 50, default 20).
    #[serde(default)]
    limit: Option<usize>,
    /// From a previous page's `nextCursor`.
    #[serde(default)]
    cursor: Option<String>,
}

/// List failover drills.
///
/// Newest first, from every node (each keeps the reports of the drills it ran, the last 50):
/// when, which node, the targets, the status (`running`, `collecting`, `complete`,
/// `cancelled`), coverage (followed / (followed + stuck)), and counts per verdict.
/// `missingNodes` names nodes that didn't answer.
#[utoipa::path(get, path = "/api/v1/drills", tag = "system", operation_id = "drills",
    params(ListParams),
    responses(
        (status = 200, body = DrillPage, description = "Drills, newest first."),
        (status = 400, body = Problem, description = "A bad cursor or limit."),
    ))]
async fn list(State(backend): State<Shared>, Query(q): Query<ListParams>) -> Response {
    let limit = q.limit.unwrap_or(20);
    if !(1..=50).contains(&limit) {
        return Problem::invalid("`limit`: 1 to 50").into_response();
    }
    let offset = match q.cursor.as_deref().map(str::parse::<usize>).transpose() {
        Ok(o) => o.unwrap_or(0),
        Err(_) => {
            return Problem::invalid("`cursor`: use a page's `nextCursor`").into_response();
        }
    };
    match backend.drills(limit, offset).await {
        Ok(p) => Json(p).into_response(),
        Err(e) => e.into_response(),
    }
}

/// A drill's report.
///
/// Per device: the verdict (`followed`, `stuck`, `quiet`, `elsewhere`), how many queries the
/// drilled node didn't answer, how many other nodes did, the time to failover, and whether it
/// came back to the drilled node within 15 minutes (`returned`) or stayed on the other one.
/// Plus queries per node, coverage, and the median and p90 time to failover. A resolver pod
/// behind one balancer address measures the balancer (`viaBalancer`, `balancerSwitchMs`).
/// Read from the node that ran it; 404 with a hint naming that node when it's unreachable.
/// At privacy level 2 and above, counts only.
#[utoipa::path(get, path = "/api/v1/drills/{id}", tag = "system", operation_id = "drill_report",
    params(("id" = String, Path, description = "The drill's ID.")),
    responses(
        (status = 200, body = DrillReport, description = "The report."),
        (status = 404, body = Problem, description = "No such drill, or its node is unreachable."),
    ))]
async fn report(State(backend): State<Shared>, Path(id): Path<String>) -> Response {
    match backend.drill_report(&id).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /api/v1/clients/affinity`.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub(crate) struct AffinityParams {
    /// `1d` to `7d` (default `7d`).
    #[serde(default)]
    window: Option<String>,
}

/// Which servers each device uses.
///
/// Per device, its queries on each node over the window and the share on its most-used one
/// (`mostly pi`, `both`). A device that has only used one server may still have a second one
/// configured: most systems use their first server until it stops answering. Run a drill to
/// find out. No finding, no alert, no health reason. Federated over every node's seen table.
#[utoipa::path(get, path = "/api/v1/clients/affinity", tag = "stats", operation_id = "client_affinity",
    params(AffinityParams),
    responses(
        (status = 200, body = AffinityPage, description = "Devices and their nodes."),
        (status = 400, body = Problem, description = "A window outside 1d to 7d."),
    ))]
async fn affinity(State(backend): State<Shared>, Query(q): Query<AffinityParams>) -> Response {
    let days = match q.window.as_deref().unwrap_or("7d") {
        w if w.ends_with('d') => w[..w.len() - 1].parse::<u32>().ok(),
        _ => None,
    };
    let Some(days) = days.filter(|d| (1..=7).contains(d)) else {
        return Problem::invalid("`window`: 1d to 7d")
            .hint("For example `?window=7d`.")
            .into_response();
    };
    match backend.affinity(days).await {
        Ok(p) => Json(p).into_response(),
        Err(e) => e.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: CLU-014 (AC 2) — requests are checked: 15 to 300 seconds (301 refused with a
    // hint), a reason, targets that name something.
    #[test]
    fn clu_014_requests_are_checked() {
        assert_eq!(check_secs(None).unwrap(), DEFAULT_SECS);
        assert_eq!(check_secs(Some(300)).unwrap(), 300);
        for bad in [14, 301, 0] {
            let e = check_secs(Some(bad)).unwrap_err();
            assert_eq!((e.code, e.status), (Code::DrillTargets, 422), "{bad}");
        }
        assert!(check_reason(Some("second server?")).is_ok());
        assert!(check_reason(None).is_err() && check_reason(Some("a\nb")).is_err());
        assert!(check_targets(&DrillTargets::All(crate::model::DrillAll::All)).is_ok());
        assert!(check_targets(&DrillTargets::Clients { clients: vec![] }).is_err());
        assert!(check_targets(&DrillTargets::Group { group: " ".into() }).is_err());
        let t: DrillTargets = serde_json::from_str(r#""all""#).unwrap();
        assert_eq!(t, DrillTargets::All(crate::model::DrillAll::All));
        let t: DrillTargets = serde_json::from_str(r#"{"group":"iot"}"#).unwrap();
        assert_eq!(
            t,
            DrillTargets::Group {
                group: "iot".into()
            }
        );
        assert!(serde_json::from_str::<DrillTargets>(r#""some""#).is_err());
    }
}
