//! REQ: FLT-009, AGT-004 (T7.1) — pausing and resuming blocking, for everyone or one group, on
//! every node (or one). Reading needs a viewer; pausing an operator (agents: `ops:pause`, at
//! most 60 minutes). Audit-logged as `blocking.pause` / `blocking.resume`.

use std::sync::Arc;

use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::auth::Auth;
use crate::auth::routes::{body, principal, reason, remote};
use crate::model::{BlockingNode, BlockingRequest, Items};
use crate::problem::Problem;
use crate::{Backend, Shared};

/// The longest pause: a day for people, an hour for agents (`spec/13` §3.2).
pub const MAX_MINUTES: u32 = 24 * 60;
pub const MAX_AGENT_MINUTES: u32 = 60;

/// Reads (viewer).
pub(crate) fn read_routes(backend: Shared) -> Router {
    Router::new()
        .route("/api/v1/blocking", get(state))
        .with_state(backend)
}

/// Pause and resume (operator).
pub(crate) fn write_routes(backend: Shared, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/blocking/pause", post(pause))
        .route("/api/v1/blocking/resume", post(resume))
        .with_state((backend, auth))
}

/// Whether blocking is paused, per node.
///
/// For each node: its active pauses (everyone, or one group) and when each ends. Nothing listed
/// means blocking is on.
#[utoipa::path(get, path = "/api/v1/blocking", tag = "config",
    responses((status = 200, body = Items<BlockingNode>, description = "One row per node.")))]
async fn state(State(b): State<Shared>) -> Response {
    match tokio::task::spawn_blocking(move || b.blocking_state()).await {
        Ok(items) => Json(Items {
            missing_nodes: Vec::new(),
            items,
        })
        .into_response(),
        Err(e) => Problem::internal(format!("blocking state: {e}")).into_response(),
    }
}

/// Pause blocking.
///
/// Turns blocking off for `minutes` (1 to 1,440; agents at most 60) for everyone, or only for
/// `group`'s devices, then it turns back on by itself. Every node pauses, unless `node` names
/// one. Quick rules that block stop too; local names, forwarding, and allow rules don't change.
/// Needs the operator role (agents: the `ops:pause` scope); audit-logged as `blocking.pause`.
#[utoipa::path(post, path = "/api/v1/blocking/pause", tag = "config",
    request_body = BlockingRequest,
    responses(
        (status = 200, body = Items<BlockingNode>, description = "Each node's pauses now."),
        (status = 400, body = Problem, description = "No or too many minutes, an unknown group, or an unknown node."),
    ))]
async fn pause(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<BlockingRequest>, JsonRejection>,
) -> Response {
    let req = match body(b) {
        Ok(r) => r,
        Err(p) => return p.into_response(),
    };
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let max = if p.agent.is_some() {
        MAX_AGENT_MINUTES
    } else {
        MAX_MINUTES
    };
    let Some(minutes) = req.minutes.filter(|m| (1..=max).contains(m)) else {
        return Problem::invalid(format!("`minutes`: 1 to {max}"))
            .hint(if p.agent.is_some() {
                "Agents may pause for at most an hour."
            } else {
                "Up to a day; resume earlier with POST /api/v1/blocking/resume."
            })
            .into_response();
    };
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let r = req.clone();
    let b2: Arc<dyn Backend> = Arc::clone(&backend);
    let result = tokio::task::spawn_blocking(move || {
        b2.blocking_pause(r.group.as_deref(), minutes, r.node.as_deref())
    })
    .await;
    match result {
        Ok(Ok(items)) => {
            auth.record(
                &actor,
                "blocking.pause",
                req.group.as_deref().unwrap_or("*"),
                &serde_json::json!({ "minutes": minutes, "node": req.node }),
            );
            Json(Items {
                missing_nodes: Vec::new(),
                items,
            })
            .into_response()
        }
        Ok(Err(e)) => e.into_response(),
        Err(e) => Problem::internal(format!("blocking pause: {e}")).into_response(),
    }
}

/// Resume blocking.
///
/// Ends the pause for `group`, or every pause (everyone's and every group's) without one, on
/// every node unless `node` names one. Needs the operator role (agents: `ops:pause`);
/// audit-logged as `blocking.resume`.
#[utoipa::path(post, path = "/api/v1/blocking/resume", tag = "config",
    request_body = BlockingRequest,
    responses(
        (status = 200, body = Items<BlockingNode>, description = "Each node's pauses now."),
        (status = 400, body = Problem, description = "An unknown group or node."),
    ))]
async fn resume(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<BlockingRequest>, JsonRejection>,
) -> Response {
    let req = match body(b) {
        Ok(r) => r,
        Err(p) => return p.into_response(),
    };
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let r = req.clone();
    let b2: Arc<dyn Backend> = Arc::clone(&backend);
    let result = tokio::task::spawn_blocking(move || {
        b2.blocking_resume(r.group.as_deref(), r.node.as_deref())
    })
    .await;
    match result {
        Ok(Ok(items)) => {
            auth.record(
                &actor,
                "blocking.resume",
                req.group.as_deref().unwrap_or("*"),
                &serde_json::json!({ "node": req.node }),
            );
            Json(Items {
                missing_nodes: Vec::new(),
                items,
            })
            .into_response()
        }
        Ok(Err(e)) => e.into_response(),
        Err(e) => Problem::internal(format!("blocking resume: {e}")).into_response(),
    }
}
