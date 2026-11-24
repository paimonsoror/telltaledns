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
/// viewer role (agents: `config:read` and `querylog:read`). A caller who isn't an administrator
/// can name only the local files (a list's `path`, a zone's `file`, `[local] hosts_files`, an
/// upstream's TLS files) and plugin upstreams that the configuration in effect names: anything
/// else is refused before it's read (422, ADR-180).
#[utoipa::path(post, path = "/api/v1/simulate", tag = "config",
    request_body = SimulateRequest,
    responses(
        (status = 200, body = Simulation, description = "The differences (or `available: false` and why)."),
        (status = 409, body = Problem, description = "This node is already running a simulation (`simulation_busy`); retry after Retry-After seconds."),
        (status = 422, body = Problem, description = "The configuration isn't valid, the window isn't a duration of at most 7 days (`simulation_window`), or a caller below admin named a new local file, program or socket."),
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
    // REQ: OBS-024 (T13.1) — `now` is no end given: the backend's default takes in this second.
    let until_s = crate::time::parse_until(req.until.as_deref(), now)
        .map_err(|e| Problem::invalid(format!("`until`: {e}")))?;
    let opts = SimulateOpts {
        window: req.window.clone(),
        auto: false,
        until_s,
    };
    let s = backend
        .simulate(req.config, opts, crate::config_api::by_admin(&p))
        .await
        .map_err(|e| sanitize_problem(&p, e))?;
    Ok(Json(s))
}

/// REQ: OBS-024, AGT-009 — what an agent sees of a simulation that couldn't download a list:
/// that it couldn't, not why (the node would otherwise probe URLs on the agent's behalf).
pub(crate) fn sanitize_problem(p: &crate::auth::Principal, mut e: Problem) -> Problem {
    // REQ: FLT-005, AGT-004 (GitHub issue #73) — a hint that says which address a device name
    // belongs to is a lookup over every device, like reading the query log. The refusing node puts
    // the plain text in `hint` and the fuller one beside it, so a node that doesn't know the field
    // shows the plain one; this node (the one that answers the caller) upgrades it for everyone but
    // an agent that may not simulate (no `querylog:read`, or limited to a group).
    if let Some(fuller) = e.fuller_hint.take()
        && (p.agent.is_none() || agent_may_simulate(p, None).is_ok())
    {
        e.hint = Some(*fuller);
    }
    if p.agent.is_some() && e.detail.contains("to simulate it") {
        return Problem::new(
            e.code,
            "a list couldn't be downloaded to simulate the change (an operator can see why in the UI)",
        );
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AgentGrant, Principal, Role, Via};

    fn principal(agent: Option<AgentGrant>) -> Principal {
        Principal {
            user_id: 1,
            username: "olga".into(),
            role: Role::Operator,
            via: Via::Token { id: "t".into() },
            agent,
            display: None,
        }
    }

    /// An agent token with exactly `scopes`, perhaps limited to a group.
    fn bot(scopes: &[&str], group: Option<&str>) -> Principal {
        principal(Some(AgentGrant {
            token_name: "bot".into(),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            group: group.map(str::to_owned),
            rate_per_minute: None,
            client: None,
        }))
    }

    const PLAIN: &str = "Use the address, or name the device first.";
    const FULLER: &str =
        "`tv` is what your router calls 192.168.1.102. Use the address, or name the device first.";

    fn refusal() -> Problem {
        Problem::new(Code::InvalidConfig, "`tv` isn't a named device")
            .hint(PLAIN)
            .fuller_hint(FULLER)
    }

    /// REQ: FLT-005, AGT-004 (issue #73) — a refusal carries the plain hint in `hint` and the fuller
    /// one beside it. Whoever may read every device's queries (a person, or an agent token with
    /// `querylog:read` and no group) is given the fuller one; an agent token without that scope, or
    /// limited to a group, keeps the plain one. This is also what a node does with a refusal that
    /// came from the primary over the cluster channel (the problem is the same value there).
    #[test]
    fn agt_004_the_address_hint_goes_only_to_those_who_may_see_it() {
        for (who, p, sees) in [
            ("a person", principal(None), true),
            (
                "an agent with querylog:read",
                bot(&["config:write:rules", "querylog:read"], None),
                true,
            ),
            (
                "an agent without it",
                bot(&["config:write:rules", "config:read"], None),
                false,
            ),
            (
                "an agent limited to a group",
                bot(&["config:write:rules", "querylog:read"], Some("kids")),
                false,
            ),
        ] {
            let e = sanitize_problem(&p, refusal());
            assert_eq!(
                e.hint.as_deref(),
                Some(if sees { FULLER } else { PLAIN }),
                "{who}"
            );
            assert!(
                e.fuller_hint.is_none(),
                "{who}: the fuller text is never kept after this point"
            );
        }
    }

    /// REQ: FLT-005, AGT-004 (issue #73) — a refusal from a node that doesn't know the fuller hint
    /// (an older primary) has only the plain text in `hint`, and stays so for everyone.
    #[test]
    fn agt_004_a_refusal_without_a_fuller_hint_keeps_its_plain_one() {
        for p in [
            principal(None),
            bot(&["querylog:read"], None),
            bot(&[], None),
        ] {
            let e = sanitize_problem(&p, Problem::new(Code::InvalidConfig, "x").hint(PLAIN));
            assert_eq!(e.hint.as_deref(), Some(PLAIN));
        }
    }

    /// The public problem never carries the fuller text as a field of its own.
    #[test]
    fn agt_004_the_public_problem_has_no_extra_field() {
        let json = serde_json::to_value(refusal()).unwrap();
        assert!(
            json.get("fullerHint").is_none() && json.get("fuller_hint").is_none(),
            "{json}"
        );
        assert_eq!(json["hint"], PLAIN);
    }
}
