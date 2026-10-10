//! Change simulation over the query log (REQ: OBS-024; T13.1, ADR-115): the whole-configuration
//! door. A dry run's `simulate` parameter covers single changes (`config_api`); this route takes
//! a candidate shared configuration, as a Git commit would make it, and answers what it would
//! have done to the logged queries.

use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::routing::post;
use axum::{Json, Router};

use crate::auth::routes::{body, principal};
use crate::model::{SimulateRequest, Simulation};
use crate::problem::{Code, Problem};
use crate::{Shared, SimulateOpts};

pub(crate) fn routes(backend: Shared) -> Router {
    Router::new()
        .route("/api/v1/simulate", post(simulate))
        .with_state(backend)
}

/// REQ: OBS-024 — what a caller must hold beyond the route's own check: agents need the query
/// log (`querylog:read`, checked by the route table) and, for a whole configuration, reading
/// the configuration; a token restricted to one group can't see the cluster's queries.
pub(crate) fn agent_may_simulate(
    p: &crate::auth::Principal,
    also: Option<&'static str>,
) -> Result<(), Problem> {
    let Some(g) = &p.agent else { return Ok(()) };
    if g.group.is_some() {
        return Err(Problem::new(
            Code::Forbidden,
            "a token restricted to one group can't simulate changes",
        )
        .hint("A simulation reads every device's queries: use a token without a group."));
    }
    for s in ["querylog:read"].into_iter().chain(also) {
        if !g.scopes.contains(s) {
            return Err(
                Problem::new(Code::Forbidden, format!("simulating needs the `{s}` scope"))
                    .hint("Create an agent token with it (POST /api/v1/tokens with kind = agent)."),
            );
        }
    }
    Ok(())
}

/// What a candidate configuration would have done (OBS-024).
///
/// The body's `config` is a shared configuration as JSON: the sections a cluster replicates,
/// as a Git commit's `telltale/shared.toml` becomes (`telltale config simulate` reads the TOML
/// and sends this). Node-local sections are ignored: this node's own apply. Each logged query
/// over `window` (default `[simulate] default_window`, at most 7 days; newest first, at most
/// `[simulate] max_rows` rows and `max_secs` seconds) is decided again under the configuration
/// in effect and under the candidate, and the differences are counted: newly blocked, newly
/// allowed, a changed route, a changed answer, by name, device, and group. In a cluster every
/// node replays its own log (and the logs shipped to it) and the counts are summed; nodes that
/// didn't answer are in `missingNodes`. Nothing changes and nothing is audited. Needs the
/// viewer role (agents: `config:read` and `querylog:read`).
#[utoipa::path(post, path = "/api/v1/simulate", tag = "config",
    request_body = SimulateRequest,
    responses(
        (status = 200, body = Simulation, description = "The differences (or `available: false` and why)."),
        (status = 409, body = Problem, description = "This node is already running a simulation (`simulation_busy`); retry after Retry-After seconds."),
        (status = 422, body = Problem, description = "The configuration isn't valid, or the window isn't a duration of at most 7 days (`simulation_window`)."),
    ))]
pub(crate) async fn simulate(
    State(backend): State<Shared>,
    ext: axum::http::Extensions,
    b: Result<Json<SimulateRequest>, JsonRejection>,
) -> Result<Json<Simulation>, Problem> {
    let p = principal(&ext)?;
    agent_may_simulate(&p, Some("config:read"))?;
    let req = body(b)?;
    let now = backend.now_unix_seconds();
    let until_s = req
        .until
        .as_deref()
        .map(|u| crate::time::parse_time(u, now))
        .transpose()
        .map_err(|e| Problem::invalid(format!("`until`: {e}")))?;
    let opts = SimulateOpts {
        window: req.window.clone(),
        auto: false,
        until_s,
    };
    let s = backend
        .simulate(req.config, opts)
        .await
        .map_err(|e| sanitize_problem(&p, e))?;
    Ok(Json(s))
}

/// REQ: OBS-024, AGT-009 — what an agent sees of a simulation that couldn't download a list:
/// that it couldn't, not why (the node would otherwise probe URLs on the agent's behalf).
pub(crate) fn sanitize_problem(p: &crate::auth::Principal, e: Problem) -> Problem {
    if p.agent.is_some() && e.detail.contains("to simulate it") {
        return Problem::new(
            e.code,
            "a list couldn't be downloaded to simulate the change (an operator can see why in the UI)",
        );
    }
    e
}
