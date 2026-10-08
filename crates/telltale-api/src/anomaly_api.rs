//! REQ: OBS-014, AGT-004 (ADR-103) — acknowledging device anomalies: marking findings as seen,
//! so the badge and the default list stop counting them, on every node. Needs an operator
//! (agents: `ops:anomalies`); audit-logged as `anomaly.ack` / `anomaly.unack`. It isn't a
//! configuration change, so a GitOps-managed cluster takes it too.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};

use crate::auth::Auth;
use crate::auth::routes::{body, principal, reason, remote};
use crate::model::{AnomalyAckRequest, AnomalyAckResult, anomaly_id_window};
use crate::problem::Problem;
use crate::{AnomalyAckWrite, Shared};

/// The most findings one request may name.
pub const MAX_IDS: usize = 1000;
/// The longest note.
pub const MAX_NOTE: usize = 200;

/// Acknowledge and unacknowledge (operator).
pub(crate) fn routes(backend: Shared, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/analytics/anomalies/acknowledge", post(acknowledge))
        .route(
            "/api/v1/analytics/anomalies/unacknowledge",
            post(unacknowledge),
        )
        .with_state((backend, auth))
}

/// Checks a request: IDs present, well-formed, not too many; a short note.
fn validate(req: &AnomalyAckRequest, ack: bool) -> Result<Vec<String>, Problem> {
    if req.ids.is_empty() || req.ids.len() > MAX_IDS {
        return Err(
            Problem::invalid(format!("`ids`: 1 to {MAX_IDS} finding IDs"))
                .hint("Take them from `id` in GET /api/v1/analytics/anomalies."),
        );
    }
    if let Some(bad) = req.ids.iter().find(|id| anomaly_id_window(id).is_none()) {
        return Err(Problem::invalid(format!("`ids`: `{bad}` isn't a finding ID"))
            .hint("A finding ID is 16 lowercase hex digits, from `id` in GET /api/v1/analytics/anomalies."));
    }
    if let Some(n) = &req.note {
        if !ack {
            return Err(Problem::invalid("`note` goes with acknowledging only"));
        }
        if n.chars().count() > MAX_NOTE || n.chars().any(char::is_control) {
            return Err(Problem::invalid(format!(
                "`note`: at most {MAX_NOTE} characters, on one line"
            )));
        }
    }
    let mut seen = HashSet::new();
    Ok(req
        .ids
        .iter()
        .filter(|id| seen.insert(id.as_str()))
        .cloned()
        .collect())
}

async fn change(
    backend: Shared,
    auth: Arc<Auth>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<AnomalyAckRequest>, JsonRejection>,
    ack: bool,
) -> Response {
    let req = match body(b) {
        Ok(r) => r,
        Err(p) => return p.into_response(),
    };
    let ids = match validate(&req, ack) {
        Ok(ids) => ids,
        Err(p) => return p.into_response(),
    };
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    // The findings every reachable node has now, to say which IDs match none.
    let b2 = Arc::clone(&backend);
    let known: HashSet<String> =
        tokio::task::spawn_blocking(move || b2.anomalies(0).into_iter().map(|f| f.id).collect())
            .await
            .unwrap_or_default();
    let unknown: Vec<String> = ids
        .iter()
        .filter(|id| !known.contains(*id))
        .cloned()
        .collect();
    let w = AnomalyAckWrite {
        ids: ids.clone(),
        note: req.note.clone().filter(|n| !n.trim().is_empty()),
        ack,
        by: actor.name.clone(),
    };
    match backend.anomaly_ack(w).await {
        Ok(mut r) => {
            let action = if ack { "anomaly.ack" } else { "anomaly.unack" };
            let target = if ids.len() == 1 {
                ids[0].clone()
            } else {
                format!("{} findings", ids.len())
            };
            auth.record(
                &actor,
                action,
                &target,
                &serde_json::json!({ "ids": ids, "note": req.note, "changed": r.changed }),
            );
            r.unknown = unknown;
            Json(r).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Acknowledge device anomalies.
///
/// Marks findings as seen, by their `id` from `GET /analytics/anomalies`: the sidebar badge and
/// `acknowledged=false` stop counting them, and each shows who acknowledged it and when. In a
/// cluster the primary records it (any node forwards) and every node shows it within seconds,
/// including nodes that were down, when they reconnect. Acknowledging changes no configuration,
/// so it works in a GitOps-managed cluster too. Findings keep being reported as before.
/// Needs the operator role (agents: the `ops:anomalies` scope); audit-logged as `anomaly.ack`.
#[utoipa::path(post, path = "/api/v1/analytics/anomalies/acknowledge", tag = "stats",
    request_body = AnomalyAckRequest,
    responses(
        (status = 200, body = AnomalyAckResult, description = "How many were newly acknowledged."),
        (status = 400, body = Problem, description = "No IDs, too many, a malformed one, or a long note."),
        (status = 503, body = Problem, description = "A replica that can't reach the primary."),
    ))]
async fn acknowledge(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<AnomalyAckRequest>, JsonRejection>,
) -> Response {
    change(backend, auth, headers, ext, b, true).await
}

/// Take back acknowledgements of device anomalies.
///
/// The findings count in the badge again. Same rules as acknowledging; audit-logged as
/// `anomaly.unack`.
#[utoipa::path(post, path = "/api/v1/analytics/anomalies/unacknowledge", tag = "stats",
    request_body = AnomalyAckRequest,
    responses(
        (status = 200, body = AnomalyAckResult, description = "How many acknowledgements were taken back."),
        (status = 400, body = Problem, description = "No IDs, too many, or a malformed one."),
        (status = 503, body = Problem, description = "A replica that can't reach the primary."),
    ))]
async fn unacknowledge(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<AnomalyAckRequest>, JsonRejection>,
) -> Response {
    change(backend, auth, headers, ext, b, false).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::anomaly_id;

    // REQ: OBS-014 — the same finding gets the same ID everywhere; the ID carries its window.
    #[test]
    fn obs_014_finding_ids_are_stable_and_carry_the_window() {
        let a = anomaly_id("rate_spike", "192.168.1.20", None, 1_790_000_000, 3600);
        assert_eq!(
            a,
            anomaly_id("rate_spike", "192.168.1.20", None, 1_790_000_000, 3600)
        );
        assert_eq!(a.len(), 16);
        assert_eq!(anomaly_id_window(&a), Some(1_790_000_000));
        assert_ne!(
            a,
            anomaly_id("rate_spike", "192.168.1.21", None, 1_790_000_000, 3600)
        );
        assert_ne!(
            anomaly_id(
                "domain_volume",
                "192.168.1.20",
                Some("a.example"),
                1_790_000_000,
                3600
            ),
            anomaly_id(
                "domain_volume",
                "192.168.1.20",
                Some("b.example"),
                1_790_000_000,
                3600
            )
        );
        assert_eq!(anomaly_id_window("not-an-id"), None);
        assert_eq!(
            anomaly_id_window("6AB0F18000000000"),
            None,
            "lowercase only"
        );
    }

    #[test]
    fn obs_014_requests_are_checked() {
        let id = anomaly_id("beacon", "10.0.0.5", Some("x.example"), 1_790_000_000, 3600);
        let req = |ids: Vec<String>, note: Option<&str>| AnomalyAckRequest {
            ids,
            note: note.map(Into::into),
        };
        assert!(validate(&req(vec![], None), true).is_err());
        assert!(validate(&req(vec!["nope".into()], None), true).is_err());
        assert!(
            validate(&req(vec![id.clone()], Some("x")), false).is_err(),
            "no note on undo"
        );
        assert!(validate(&req(vec![id.clone()], Some(&"n".repeat(201))), true).is_err());
        assert_eq!(
            validate(&req(vec![id.clone(), id.clone()], Some("seen it")), true).unwrap(),
            vec![id],
            "duplicates collapse"
        );
    }
}
