//! REQ: OPS-010, AGT-004 (ADR-118) — node maintenance mode: a node reports not ready for a
//! bounded time (balancers and Kubernetes stop sending it new queries), keeps answering
//! whatever still arrives, and is left out of alerts, the health level, and elections. It's
//! the node's own state, not configuration: allowed under `GitOps`, sent to the node it's for,
//! and audit-logged as `node.maintenance.start` / `node.maintenance.end`. Needs an operator
//! (agents: `ops:maintenance`, at most two hours).

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};

use crate::auth::Auth;
use crate::auth::routes::{body, principal, reason, remote};
use crate::model::{MaintenanceRequest, MaintenanceResult};
use crate::problem::{Code, Problem};
use crate::{MaintenanceWrite, Shared};

/// A window's default, shortest, and longest lengths (seconds); agents at most two hours
/// (`spec/13` §3.2; change it here if the owner wants another cap).
pub const DEFAULT_SECS: u32 = 3600;
pub const MIN_SECS: u32 = 60;
pub const MAX_SECS: u32 = 86_400;
pub const AGENT_MAX_SECS: u32 = 7200;
/// The longest reason.
pub const MAX_REASON: usize = 200;

/// Start and end (operator).
pub(crate) fn routes(backend: Shared, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/nodes/{id}/maintenance", post(start).delete(end))
        .with_state((backend, auth))
}

/// A reason: present, one line, at most [`MAX_REASON`] characters.
pub fn check_reason(r: Option<&str>) -> Result<String, Problem> {
    let r = r.map(str::trim).unwrap_or_default();
    if r.is_empty() || r.chars().count() > MAX_REASON || r.chars().any(char::is_control) {
        return Err(Problem::new(
            Code::MaintenanceInvalid,
            format!("`reason`: 1 to {MAX_REASON} characters on one line, saying why"),
        )
        .hint("For example \"SD card swap\" or \"kernel upgrade\": it shows on the Cluster page and in the audit log."));
    }
    Ok(r.to_owned())
}

/// A length in seconds, between [`MIN_SECS`] and `max`.
pub fn check_secs(secs: u32, max: u32) -> Result<u32, Problem> {
    if secs < MIN_SECS {
        return Err(Problem::new(
            Code::MaintenanceInvalid,
            format!("`forSecs`: at least {MIN_SECS} (a minute)"),
        ));
    }
    if secs > max {
        let hint = if max == AGENT_MAX_SECS {
            format!(
                "Agents may start maintenance for at most {} hours ({AGENT_MAX_SECS} seconds); a person can start a longer window.",
                AGENT_MAX_SECS / 3600
            )
        } else {
            format!("At most a day ({MAX_SECS} seconds); start it again later to extend it.")
        };
        return Err(Problem::new(
            Code::MaintenanceTooLong,
            format!("`forSecs`: {secs} is longer than the {max} seconds allowed"),
        )
        .hint(hint));
    }
    Ok(secs)
}

/// Start maintenance on a node.
///
/// For `forSecs` (60 to 86,400; agents at most 7,200; default the node's
/// `[node] maintenance_default_secs`, 3,600) the node answers `/readyz` with 503 so load
/// balancers and Kubernetes stop sending it new queries, while every DNS listener keeps
/// answering whatever still arrives. Its alerts and health conditions are left out, and it
/// doesn't stand in elections, until the window ends (by itself, or with DELETE). The window
/// survives a restart. Starting again replaces the window. `id` is `local` (the node answering)
/// or a cluster node's ID, site, or pod name: the request goes to that node over the cluster
/// channel. On the primary under automatic failover, `handover` (default true) hands the primary
/// role to another eligible node first (configuration changes pause for about 30 s); otherwise
/// the primary keeps the role and the answer's `note` says to promote another node first. It
/// changes no configuration, so a GitOps-managed cluster takes it too. Needs the operator role
/// (agents: the `ops:maintenance` scope); audit-logged as `node.maintenance.start`.
#[utoipa::path(post, path = "/api/v1/nodes/{id}/maintenance", tag = "system",
    params(("id" = String, Path, description = "`local`, or a node's ID, site, or pod name.")),
    request_body = MaintenanceRequest,
    responses(
        (status = 200, body = MaintenanceResult, description = "The node's window, and what happened to the primary role."),
        (status = 404, body = Problem, description = "No such node (`node_unknown`)."),
        (status = 422, body = Problem, description = "No reason, or a window too short or too long (`maintenance_invalid`, `maintenance_too_long`; agents at most 2 h)."),
        (status = 503, body = Problem, description = "The node isn't reachable over the cluster channel (`node_unreachable`)."),
    ))]
async fn start(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<MaintenanceRequest>, JsonRejection>,
) -> Response {
    let req = match body(b) {
        Ok(r) => r,
        Err(p) => return p.into_response(),
    };
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let max_secs = if p.agent.is_some() {
        AGENT_MAX_SECS
    } else {
        MAX_SECS
    };
    let checked = check_reason(req.reason.as_deref()).and_then(|r| {
        req.for_secs
            .map(|s| check_secs(s, max_secs))
            .transpose()
            .map(|s| (r, s))
    });
    let (why, for_secs) = match checked {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let w = MaintenanceWrite::Start {
        for_secs,
        max_secs,
        reason: why.clone(),
        handover: req.handover.unwrap_or(true),
        by: actor.name.clone(),
    };
    match backend.maintenance(&id, w).await {
        Ok(r) => {
            auth.record(
                &actor,
                "node.maintenance.start",
                &r.node,
                &serde_json::json!({
                    "until": r.window.as_ref().map(|w| w.until.clone()),
                    "reason": why,
                    "handover": r.handover,
                    "requested": id,
                }),
            );
            Json(r).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// End maintenance on a node.
///
/// The node is ready again at once (if it's otherwise ready), and alerts and the health level
/// cover it again: conditions that hold count from now, so an alert with `for_secs` waits its
/// usual time. Nothing happens if it wasn't in maintenance. `id` as for starting. Needs the
/// operator role (agents: `ops:maintenance`); audit-logged as `node.maintenance.end`.
#[utoipa::path(delete, path = "/api/v1/nodes/{id}/maintenance", tag = "system",
    params(("id" = String, Path, description = "`local`, or a node's ID, site, or pod name.")),
    responses(
        (status = 200, body = MaintenanceResult, description = "The node, no longer in maintenance."),
        (status = 404, body = Problem, description = "No such node (`node_unknown`)."),
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
    let w = MaintenanceWrite::End {
        by: actor.name.clone(),
    };
    match backend.maintenance(&id, w).await {
        Ok(r) => {
            auth.record(
                &actor,
                "node.maintenance.end",
                &r.node,
                &serde_json::json!({ "requested": id }),
            );
            Json(r).into_response()
        }
        Err(e) => e.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: OPS-010 — requests are checked: a reason is required (one line, at most 200
    // characters), windows run from a minute to a day, agents at most two hours, each with a
    // stable code and a hint that names the cap.
    #[test]
    fn ops_010_requests_are_checked() {
        assert!(check_reason(Some("SD card swap")).is_ok());
        for bad in [None, Some(""), Some("   "), Some("two\nlines")] {
            let e = check_reason(bad).unwrap_err();
            assert_eq!(e.code, Code::MaintenanceInvalid, "{bad:?}");
            assert_eq!(e.status, 422);
        }
        assert!(check_reason(Some(&"x".repeat(201))).is_err());
        assert_eq!(check_secs(3600, MAX_SECS).unwrap(), 3600);
        assert_eq!(
            check_secs(30, MAX_SECS).unwrap_err().code,
            Code::MaintenanceInvalid
        );
        let long = check_secs(86_401, MAX_SECS).unwrap_err();
        assert_eq!((long.code, long.status), (Code::MaintenanceTooLong, 422));
        let agent = check_secs(3 * 3600, AGENT_MAX_SECS).unwrap_err();
        assert_eq!(agent.code, Code::MaintenanceTooLong);
        assert!(
            agent.hint.as_deref().is_some_and(|h| h.contains("2 hours")),
            "{:?}",
            agent.hint
        );
        assert!(check_secs(2 * 3600, AGENT_MAX_SECS).is_ok());
    }
}
