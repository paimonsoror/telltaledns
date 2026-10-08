//! REQ: AGT-007 (T7.1, ADR-070) — plans: an agent's change, computed with the REST dry run and
//! kept for ten minutes. `apply_plan` (MCP) replays the write with `If-Match` on the version the
//! plan saw, so a configuration changed meanwhile makes the plan stale, and with the plan ID as
//! its idempotency key. With `[agents] require_approval`, an operator approves a plan first
//! (`POST /api/v1/plans/{id}/approve`, or "Agent changes" in the UI).
//!
//! Plans live in this node's memory: they're short-lived, and a restart only discards them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::routes::{principal, reason, remote};
use crate::auth::{Auth, Principal, Via};
use crate::model::Items;
use crate::problem::{Code, Problem};

/// How long a plan can be applied.
pub const TTL_SECS: u64 = 600;
/// How long a finished plan stays listed.
const KEEP_SECS: u64 = 24 * 3600;
/// Most plans kept; the oldest finished ones go first.
const MAX_PLANS: usize = 500;

/// A planned change (REQ: AGT-007).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    /// Pass it to `apply_plan` or `discard_plan`.
    pub id: String,
    /// The MCP tool that made it, e.g. `plan_block_domain`.
    pub tool: String,
    /// What it does, in one sentence.
    pub summary: String,
    /// The REST write it replays: `PUT` or `DELETE`.
    pub method: String,
    pub path: String,
    #[schema(value_type = Option<Object>)]
    pub body: Option<serde_json::Value>,
    /// The dry run's answer: before, after, impact, and warnings.
    #[schema(value_type = Object)]
    pub preview: serde_json::Value,
    /// The configuration version the plan was made against.
    pub config_version: u64,
    /// Why the agent wants it (goes into the audit log).
    pub reason: String,
    /// Who asked: `agent:<token> (owner: <user>) via <client>`.
    pub requested_by: String,
    #[serde(skip)]
    pub owner: String,
    pub created_unix_seconds: u64,
    pub expires_unix_seconds: u64,
    /// `pending` (waits for an operator), `ready`, `approved`, `rejected`, `applying`,
    /// `applied`, `stale` (the configuration changed), `failed`, `discarded`, or `expired`.
    pub state: String,
    /// Made while `[agents] require_approval` was on.
    pub needs_approval: bool,
    /// Who approved or rejected it.
    pub decided_by: Option<String>,
    /// The write's answer once applied (or why it failed).
    #[schema(value_type = Option<Object>)]
    pub result: Option<serde_json::Value>,
}

impl Plan {
    fn open(&self) -> bool {
        matches!(self.state.as_str(), "pending" | "ready" | "approved")
    }
}

/// The caller's identity for plans: a token, or a user.
pub fn owner_key(p: &Principal) -> String {
    match &p.via {
        Via::Token { id } => format!("token:{id}"),
        _ => format!("user:{}", p.user_id),
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The plans on this node.
#[derive(Debug, Default)]
pub struct Plans(Mutex<HashMap<String, Plan>>);

impl Plans {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Plan>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Marks open plans past their time as expired.
    fn expire(m: &mut HashMap<String, Plan>, now: u64) {
        for p in m.values_mut() {
            if p.open() && now > p.expires_unix_seconds {
                "expired".clone_into(&mut p.state);
            }
        }
    }

    pub fn add(&self, plan: Plan) -> Plan {
        let now = now();
        let mut m = self.lock();
        Self::expire(&mut m, now);
        m.retain(|_, p| p.open() || now.saturating_sub(p.expires_unix_seconds) < KEEP_SECS);
        while m.len() >= MAX_PLANS {
            let Some(oldest) = m
                .values()
                .min_by_key(|p| (p.open(), p.created_unix_seconds))
                .map(|p| p.id.clone())
            else {
                break;
            };
            m.remove(&oldest);
        }
        m.insert(plan.id.clone(), plan.clone());
        plan
    }

    pub fn get(&self, id: &str) -> Option<Plan> {
        let mut m = self.lock();
        Self::expire(&mut m, now());
        m.get(id).cloned()
    }

    /// Newest first; `owner` limits it to one caller's plans.
    pub fn list(&self, owner: Option<&str>) -> Vec<Plan> {
        let mut m = self.lock();
        Self::expire(&mut m, now());
        let mut v: Vec<Plan> = m
            .values()
            .filter(|p| owner.is_none_or(|o| p.owner == o))
            .cloned()
            .collect();
        v.sort_by_key(|p| std::cmp::Reverse(p.created_unix_seconds));
        v
    }

    /// Moves a plan in one of `from` to `to`. `owner`: only that caller's plan.
    pub fn transition(
        &self,
        id: &str,
        from: &[&str],
        to: &str,
        owner: Option<&str>,
        decided_by: Option<String>,
    ) -> Result<Plan, Problem> {
        let mut m = self.lock();
        Self::expire(&mut m, now());
        let Some(p) = m.get_mut(id).filter(|p| owner.is_none_or(|o| p.owner == o)) else {
            return Err(Problem::not_found(format!("no plan `{id}`"))
                .hint("Plans last ten minutes; list_plans shows yours."));
        };
        if !from.contains(&p.state.as_str()) {
            let hint = match p.state.as_str() {
                "pending" => "An operator has to approve it first (Agent changes in the web UI).",
                "expired" => "Plans last ten minutes: make the plan again.",
                "rejected" => "An operator rejected it.",
                _ => "Make a new plan.",
            };
            return Err(
                Problem::new(Code::Conflict, format!("plan `{id}` is {}", p.state)).hint(hint),
            );
        }
        to.clone_into(&mut p.state);
        if decided_by.is_some() {
            p.decided_by = decided_by;
        }
        Ok(p.clone())
    }

    /// Records how an apply ended.
    pub fn finish(&self, id: &str, state: &str, result: serde_json::Value) {
        if let Some(p) = self.lock().get_mut(id) {
            state.clone_into(&mut p.state);
            p.result = Some(result);
        }
    }
}

/// `GET /api/v1/plans` (viewer), approve and reject (operator; not agents).
pub(crate) fn read_routes(auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/plans", get(list))
        .with_state(auth)
}

pub(crate) fn decide_routes(auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/plans/{id}/approve", post(approve))
        .route("/api/v1/plans/{id}/reject", post(reject))
        .with_state(auth)
}

/// Agent change plans.
///
/// Changes AI agents planned through MCP (`plan_*` tools), newest first: what each does (the
/// dry run's before and after, impact, and warnings), why, who asked, and its state. With
/// `[agents] require_approval = true` a plan starts `pending` until an operator approves or
/// rejects it. An agent token, or a viewer, sees only its own plans; operators and admins,
/// who approve them, see all. Plans expire ten minutes after they're made and stay listed for
/// a day.
#[utoipa::path(get, path = "/api/v1/plans", tag = "agents",
    responses((status = 200, body = Items<Plan>, description = "The plans, newest first.")))]
pub(crate) async fn list(State(auth): State<Arc<Auth>>, ext: axum::http::Extensions) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let key = owner_key(&p);
    // REQ: AGT-007 (review 06-09) — a plan holds the write, its preview, and its reason: for
    // the people who decide on plans, not for viewers.
    let own = (p.agent.is_some() || p.role < crate::auth::Role::Operator).then_some(key.as_str());
    Json(Items {
        items: auth.plans().list(own),
        missing_nodes: Vec::new(),
    })
    .into_response()
}

/// Approve an agent's plan.
///
/// The agent can then apply it with `apply_plan` until it expires (ten minutes after it was
/// made). Only `pending` plans can be approved. Needs the operator role; agent tokens can't
/// approve. Audit-logged as `plan.approve`.
#[utoipa::path(post, path = "/api/v1/plans/{id}/approve", tag = "agents",
    params(("id" = String, Path, description = "The plan's ID.")),
    responses((status = 200, body = Plan, description = "The approved plan."),
        (status = 404, body = Problem, description = "No such plan."),
        (status = 409, body = Problem, description = "The plan isn't pending (applied, expired, rejected, ...).")))]
pub(crate) async fn approve(
    State(auth): State<Arc<Auth>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    decide(&auth, &id, &headers, &ext, "approved", "plan.approve")
}

/// Reject an agent's plan.
///
/// The plan can't be applied any more. Only `pending` plans can be rejected. Needs the operator
/// role; agent tokens can't reject. Audit-logged as `plan.reject`.
#[utoipa::path(post, path = "/api/v1/plans/{id}/reject", tag = "agents",
    params(("id" = String, Path, description = "The plan's ID.")),
    responses((status = 200, body = Plan, description = "The rejected plan."),
        (status = 404, body = Problem, description = "No such plan."),
        (status = 409, body = Problem, description = "The plan isn't pending.")))]
pub(crate) async fn reject(
    State(auth): State<Arc<Auth>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    decide(&auth, &id, &headers, &ext, "rejected", "plan.reject")
}

fn decide(
    auth: &Auth,
    id: &str,
    headers: &HeaderMap,
    ext: &axum::http::Extensions,
    to: &str,
    action: &str,
) -> Response {
    let p = match principal(ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if p.agent.is_some() {
        return Problem::new(Code::Forbidden, "agents can't approve or reject plans")
            .hint("A person with the operator role decides in the web UI (Agent changes).")
            .into_response();
    }
    let actor = auth.actor(&p, remote(auth, ext, headers), reason(headers));
    match auth
        .plans()
        .transition(id, &["pending"], to, None, Some(actor.name.clone()))
    {
        Ok(plan) => {
            auth.record(
                &actor,
                action,
                id,
                &serde_json::json!({ "summary": plan.summary, "requestedBy": plan.requested_by }),
            );
            Json(plan).into_response()
        }
        Err(e) => e.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(id: &str, owner: &str, state: &str, expires: u64) -> Plan {
        Plan {
            id: id.into(),
            tool: "plan_block_domain".into(),
            summary: "Block x.example".into(),
            method: "PUT".into(),
            path: "/api/v1/rules/x".into(),
            body: None,
            preview: serde_json::json!({}),
            config_version: 3,
            reason: "test".into(),
            requested_by: "agent:a (owner: admin)".into(),
            owner: owner.into(),
            created_unix_seconds: now(),
            expires_unix_seconds: expires,
            state: state.into(),
            needs_approval: state == "pending",
            decided_by: None,
            result: None,
        }
    }

    /// REQ: AGT-007 — pending plans wait for approval; expired ones can't be applied; owners
    /// see their own.
    #[test]
    fn agt_007_plan_states() {
        let plans = Plans::default();
        plans.add(plan("a", "token:1", "pending", now() + 600));
        plans.add(plan("b", "token:2", "ready", now() + 600));
        plans.add(plan("c", "token:1", "ready", now().saturating_sub(1)));
        assert!(
            plans
                .transition(
                    "a",
                    &["ready", "approved"],
                    "applying",
                    Some("token:1"),
                    None
                )
                .is_err()
        );
        assert_eq!(
            plans
                .transition("a", &["pending"], "approved", None, Some("op".into()))
                .unwrap()
                .decided_by
                .as_deref(),
            Some("op")
        );
        assert!(
            plans
                .transition(
                    "a",
                    &["ready", "approved"],
                    "applying",
                    Some("token:2"),
                    None
                )
                .is_err()
        );
        assert!(
            plans
                .transition(
                    "a",
                    &["ready", "approved"],
                    "applying",
                    Some("token:1"),
                    None
                )
                .is_ok()
        );
        assert_eq!(plans.get("c").unwrap().state, "expired");
        assert_eq!(plans.list(Some("token:2")).len(), 1);
        assert_eq!(plans.list(None).len(), 3);
    }
}
