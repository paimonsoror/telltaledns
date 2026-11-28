//! Configuration changes through the API (REQ: API-002, API-010; AGT-002 dry-run, AGT-003
//! idempotency; ADR-040, ADR-042): devices (`/clients/{name}`), local names
//! (`/records/{name}`), and domains sent elsewhere (`/forwards/{domain}`). Every write takes
//! `?dryRun=true` (validate and report, change nothing), `If-Match: <configVersion>`
//! (412 when the config changed meanwhile), and `Idempotency-Key` (the first response is
//! replayed for 24 hours), and is recorded in the audit log.

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::Deserialize;
use telltale_store::state::Replay;
use utoipa::IntoParams;

use crate::auth::Auth;
use crate::auth::routes::{body, principal, reason, remote};
use crate::model::{ClientChange, ClientInput, ConfigChange, ForwardInput, RecordsInput};
use crate::problem::{Code, Problem};
use crate::{Backend, ClientWrite, ManagedKind, ManagedWrite, SimulateOpts, blocking};

type Ctx = (Arc<dyn Backend>, Arc<Auth>);

/// `?dryRun=true` validates and reports without changing anything (AGT-002).
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct DryRun {
    /// Validate and report the change without applying it.
    pub dry_run: Option<bool>,
    /// REQ: OBS-024 — with `dryRun=true`: replay the query log over this window (`24h`,
    /// `7d`; at most 7 days; `true` for `[simulate] default_window`) and report what the
    /// change would have done to those queries (`simulation`). `auto`: only when
    /// `[simulate] plans_by_default` is on.
    pub simulate: Option<String>,
    /// REQ: OBS-024 — where the simulated window ends: RFC 3339 or relative (`-24h`).
    /// Default now.
    pub simulate_until: Option<String>,
}

/// `?dryRun=true` alone, where nothing can be simulated (promotion).
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct PlainDryRun {
    /// Check and report without changing anything.
    pub dry_run: Option<bool>,
}

/// A dry run's options.
#[derive(Debug, Clone, Default)]
pub(crate) struct WriteOpts {
    pub(crate) dry_run: bool,
    pub(crate) simulate: Option<String>,
    pub(crate) simulate_until: Option<String>,
}

/// Header names.
pub const IF_MATCH: &str = "if-match";
pub const IDEMPOTENCY_KEY: &str = "idempotency-key";

/// `If-Match: "7"`, `7`, or `W/"7"` → 7. `*` or absent → no check.
pub(crate) fn expected_version(headers: &HeaderMap) -> Result<Option<u64>, Problem> {
    let Some(v) = headers.get(IF_MATCH) else {
        return Ok(None);
    };
    let s = v.to_str().unwrap_or("").trim();
    if s == "*" {
        return Ok(None);
    }
    s.trim_start_matches("W/")
        .trim_matches('"')
        .parse()
        .map(Some)
        .map_err(|_| {
            Problem::invalid(format!("`If-Match`: `{s}` is not a config version"))
                .hint("Send the configVersion from the last read or write, e.g. If-Match: \"7\".")
        })
}

pub(crate) fn routes(backend: Arc<dyn Backend>, auth: Arc<Auth>) -> Router {
    use axum::routing::put;
    Router::new()
        .route(
            "/api/v1/clients/{name}",
            put(put_client).delete(delete_client),
        )
        .route(
            "/api/v1/records/{name}",
            put(put_records).delete(delete_records),
        )
        .route(
            "/api/v1/forwards/{domain}",
            put(put_forward).delete(delete_forward),
        )
        .route("/api/v1/rules/{id}", put(put_rule).delete(delete_rule))
        // REQ: API-002 (T7.5, ADR-069)
        .route(
            "/api/v1/upstreams/{name}",
            put(put_upstream).delete(delete_upstream),
        )
        .route(
            "/api/v1/upstream-groups/{name}",
            put(put_upstream_group).delete(delete_upstream_group),
        )
        .route("/api/v1/lists/{name}", put(put_list).delete(delete_list))
        .route("/api/v1/groups/{name}", put(put_group).delete(delete_group))
        // REQ: OBS-010 (T9.6)
        .route(
            "/api/v1/alerts/destinations/{name}",
            put(put_alert_destination).delete(delete_alert_destination),
        )
        .route(
            "/api/v1/alerts/rules/{name}",
            put(put_alert_rule).delete(delete_alert_rule),
        )
        .route(
            "/api/v1/alerts/destinations/{name}/test",
            axum::routing::post(test_alert_destination),
        )
        // REQ: API-002 (T9.12)
        .route(
            "/api/v1/checks/upstream",
            axum::routing::post(check_upstream),
        )
        .route("/api/v1/checks/list", axum::routing::post(check_list))
        // REQ: FLT-010 (T9.7)
        .route(
            "/api/v1/schedules/{name}",
            put(put_schedule).delete(delete_schedule),
        )
        // REQ: OBS-038 (ADR-161)
        .route(
            "/api/v1/anomaly-mutes/{name}",
            put(put_anomaly_mute).delete(delete_anomaly_mute),
        )
        // REQ: FLT-017 — a workload's (or a namespace's) group.
        .route(
            "/api/v1/kubernetes/map/{*key}",
            put(put_kubernetes_map).delete(delete_kubernetes_map),
        )
        // REQ: DNS-014 (review 01 q1)
        .route(
            "/api/v1/ratelimit/default",
            put(put_ratelimit).delete(delete_ratelimit),
        )
        // REQ: OBS-022 (T12.1)
        .route(
            "/api/v1/exclusions/default",
            put(put_exclusions).delete(delete_exclusions),
        )
        // REQ: OBS-024 (T13.1)
        .route(
            "/api/v1/simulate-settings/default",
            put(put_simulate_settings).delete(delete_simulate_settings),
        )
        .with_state((backend, auth))
}

/// Add or change an upstream resolver (ADR-069).
///
/// The body has the same fields as `[[upstream]]` in `telltale.toml` (the name comes from the path),
/// e.g. `{"url": "tls://9.9.9.9", "tls_server_name": "dns.quad9.net"}`. A name the config files use is overridden: this definition replaces theirs
/// until it's deleted again (`GET /api/v1/config/overrides` lists such changes). The whole
/// configuration is checked before anything is stored. On a node whose configuration comes from
/// Git, the response's `toml` says what to add to the repository to keep the change. Plugin
/// upstreams (`exec://`, `unix://`, and `args`) are defined in the config file: such a body is
/// refused for everyone, an administrator included (422, ADR-180).
#[utoipa::path(put, path = "/api/v1/upstreams/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, the configuration wouldn't be valid, or the upstream is a plugin (`exec://`, `unix://`): problem+json says which."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_upstream(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /upstreams/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Upstream, Some(input)),
    )
    .await
}

/// Remove an upstream resolver (ADR-069).
///
/// An entry added through the API goes away; an override goes away and the config files'
/// entry is back; an entry only the files define is hidden (left out) until this override is
/// deleted in turn. The configuration is checked first (say, a group still using a list).
#[utoipa::path(delete, path = "/api/v1/upstreams/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No entry by that name."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "Something still uses it: problem+json says what."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_upstream(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /upstreams/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Upstream, None),
    )
    .await
}

/// Add or change an upstream group (ADR-069).
///
/// The body has the same fields as `[[upstream_group]]` in `telltale.toml` (the name comes from the path),
/// e.g. `{"members": ["quad9", "cloudflare"], "strategy": "fastest"}`. A name the config files use is overridden: this definition replaces theirs
/// until it's deleted again (`GET /api/v1/config/overrides` lists such changes). The whole
/// configuration is checked before anything is stored. On a node whose configuration comes from
/// Git, the response's `toml` says what to add to the repository to keep the change.
#[utoipa::path(put, path = "/api/v1/upstream-groups/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, or the configuration wouldn't be valid: problem+json says which."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_upstream_group(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /upstream-groups/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::UpstreamGroup, Some(input)),
    )
    .await
}

/// Remove an upstream group (ADR-069).
///
/// An entry added through the API goes away; an override goes away and the config files'
/// entry is back; an entry only the files define is hidden (left out) until this override is
/// deleted in turn. The configuration is checked first (say, a group still using a list).
#[utoipa::path(delete, path = "/api/v1/upstream-groups/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No entry by that name."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "Something still uses it: problem+json says what."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_upstream_group(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /upstream-groups/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::UpstreamGroup, None),
    )
    .await
}

/// Add or change a filter list (ADR-069).
///
/// The body has the same fields as `[[list]]` in `telltale.toml` (the name comes from the path),
/// e.g. `{"url": "https://example.com/hosts.txt"}`. A name the config files use is overridden: this definition replaces theirs
/// until it's deleted again (`GET /api/v1/config/overrides` lists such changes). The whole
/// configuration is checked before anything is stored. On a node whose configuration comes from
/// Git, the response's `toml` says what to add to the repository to keep the change. A list read
/// from a local file (`path`) is added, or pointed at another file, only by an administrator (an
/// admin's sign-in or API token; no agent token); the operator role covers URL lists, inline
/// rules, a file list's other settings, and deleting any list (ADR-180).
#[utoipa::path(put, path = "/api/v1/lists/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "The list names a local file (`path`) it didn't read before, and the caller isn't an administrator."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, or the configuration wouldn't be valid: problem+json says which."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_list(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /lists/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::List, Some(input)),
    )
    .await
}

/// Remove a filter list (ADR-069).
///
/// An entry added through the API goes away; an override goes away and the config files'
/// entry is back; an entry only the files define is hidden (left out) until this override is
/// deleted in turn. The configuration is checked first (say, a group still using a list).
#[utoipa::path(delete, path = "/api/v1/lists/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No entry by that name."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "Something still uses it: problem+json says what."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_list(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /lists/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::List, None),
    )
    .await
}

/// Add or change a client group (ADR-069).
///
/// The body has the same fields as `[[group]]` in `telltale.toml` (the name comes from the path),
/// e.g. `{"lists": ["stevenblack"], "block_mode": "null_ip"}`. A name the config files use is overridden: this definition replaces theirs
/// until it's deleted again (`GET /api/v1/config/overrides` lists such changes). The whole
/// configuration is checked before anything is stored. On a node whose configuration comes from
/// Git, the response's `toml` says what to add to the repository to keep the change.
#[utoipa::path(put, path = "/api/v1/groups/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, or the configuration wouldn't be valid: problem+json says which."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_group(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /groups/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Group, Some(input)),
    )
    .await
}

/// Remove a client group (ADR-069).
///
/// An entry added through the API goes away; an override goes away and the config files'
/// entry is back; an entry only the files define is hidden (left out) until this override is
/// deleted in turn. The configuration is checked first (say, a group still using a list).
#[utoipa::path(delete, path = "/api/v1/groups/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No entry by that name."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "Something still uses it: problem+json says what."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_group(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /groups/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Group, None),
    )
    .await
}

/// Admin-only cluster actions.
pub(crate) fn admin_routes(backend: Arc<dyn Backend>, auth: Arc<Auth>) -> Router {
    Router::new()
        .route(
            "/api/v1/cluster/promote",
            axum::routing::post(cluster_promote),
        )
        .route("/api/v1/backup", axum::routing::get(backup_download))
        .with_state((backend, auth))
}

/// Promote this node to primary.
///
/// Manual failover (ADR-051): use when the primary is gone. The node takes a new epoch,
/// publishes the cluster's configuration from the last version it applied, and every node
/// follows it. An old primary that comes back steps down, and anything it changed meanwhile
/// shows under `conflicts`.
///
/// Refused when:
/// - the current primary is up;
/// - the node isn't eligible or lacks the cluster key;
/// - without `emergency`, the cluster takes its configuration from Git and this node isn't
///   managed from Git.
///
/// With `?dryRun=true`, nothing changes: the checks run and the answer is a `PromotePlan`
/// (the epoch, whether it would be an emergency primary, and a sentence on what would happen).
///
/// Admin only; audited as `cluster.promote`. From a signed-in session it needs `password`
/// (and `totp` with two-factor sign-in on); API tokens don't.
#[utoipa::path(post, path = "/api/v1/cluster/promote", tag = "system",
    params(PlainDryRun),
    request_body = crate::model::PromoteRequest,
    responses(
        (status = 200, body = crate::model::ClusterView, description = "Promoted; the cluster as it is now. With `dryRun=true`: a `PromotePlan` instead, and nothing changed."),
        (status = 400, body = Problem, description = "A signed-in session didn't send `password`."),
        (status = 401, body = Problem, description = "Not signed in, or two-factor sign-in is on and `totp` is missing (`totp_required`)."),
        (status = 403, body = Problem, description = "The password or code is wrong, or not an admin."),
        (status = 409, body = Problem, description = "Not allowed now (the primary is up, or this node can't be primary)."),
        (status = 429, body = Problem, description = "Too many wrong passwords: wait for Retry-After seconds."),
    ))]
pub(crate) async fn cluster_promote(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<PlainDryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<crate::model::PromoteRequest>, JsonRejection>,
) -> Response {
    let req = match body(b) {
        Ok(r) => r,
        Err(p) => return p.into_response(),
    };
    if q.dry_run.unwrap_or(false) {
        let b2 = Arc::clone(&backend);
        return tokio::task::spawn_blocking(move || b2.promote_plan(&req))
            .await
            .unwrap_or_else(|e| Err(Problem::internal(format!("request worker failed: {e}"))))
            .map_or_else(IntoResponse::into_response, |plan| {
                Json(plan).into_response()
            });
    }
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    // REQ: CLU-005, API-003 (`spec/12` §5, review 05-09) — the password (and code) again.
    let (a2, p2) = (Arc::clone(&auth), p.clone());
    let (password, totp) = (req.password.clone(), req.totp.clone());
    let confirmed = tokio::task::spawn_blocking(move || {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        a2.confirm(&p2, password.as_deref(), totp.as_deref(), now)
    })
    .await
    .unwrap_or_else(|e| Err(Problem::internal(format!("request worker failed: {e}"))));
    if let Err(e) = confirmed {
        return e.into_response();
    }
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let emergency = req.emergency;
    let (b2, by) = (Arc::clone(&backend), actor.name.clone());
    let result = tokio::task::spawn_blocking(move || b2.promote(req, by))
        .await
        .unwrap_or_else(|e| Err(Problem::internal(format!("request worker failed: {e}"))));
    match result {
        Ok(view) => {
            auth.record(
                &actor,
                "cluster.promote",
                view.this_node.as_deref().unwrap_or(""),
                &serde_json::json!({ "emergency": emergency }),
            );
            Json(view).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Download a backup of this node.
///
/// One `.ttbk` file (ADR-063) with the configuration files, users and API tokens, devices and
/// names made through the API, the audit log, statistics history, and anomaly baselines.
/// Sign-in sessions, lists, and the cluster identity aren't included, and neither is the
/// query log (use `telltale backup create --include-qlog` for that). Restore it with
/// `telltale backup restore FILE` on the new machine.
///
/// The file holds password hashes: keep it private. Admin only; audited as `backup.create`.
#[utoipa::path(get, path = "/api/v1/backup", tag = "system",
    responses(
        (status = 200, content_type = "application/octet-stream", body = Vec<u8>,
            description = "The backup, as an attachment named `telltale-<node>-<time>.ttbk`."),
        (status = 503, body = Problem, description = "Backups aren't available on this node."),
    ))]
pub(crate) async fn backup_download(
    State((backend, auth)): State<Ctx>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let b2 = Arc::clone(&backend);
    let result = tokio::task::spawn_blocking(move || b2.backup())
        .await
        .unwrap_or_else(|e| Err(Problem::internal(format!("request worker failed: {e}"))));
    match result {
        Ok((name, bytes)) => {
            auth.record(
                &actor,
                "backup.create",
                &name,
                &serde_json::json!({ "bytes": bytes.len() }),
            );
            let mut resp = bytes.into_response();
            let h = resp.headers_mut();
            h.insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            h.insert(
                axum::http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            );
            // The name is ours (letters, digits, `-`, `.`), so it's safe in the header.
            if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
                h.insert(axum::http::header::CONTENT_DISPOSITION, v);
            }
            resp
        }
        Err(e) => e.into_response(),
    }
}

/// REQ: AGT-004 — an agent restricted to a group changes only that group's devices, and
/// only into that group (ADR-064).
async fn group_guard(
    p: &crate::auth::Principal,
    backend: &Arc<dyn Backend>,
    name: &str,
    op: &Op,
) -> Result<(), Problem> {
    let Some(g) = p.agent.as_ref().and_then(|a| a.group.as_deref()) else {
        return Ok(());
    };
    let refuse = |why: String| {
        Err(Problem::new(Code::Forbidden, why)
            .hint(format!("This token is restricted to group `{g}`.")))
    };
    // REQ: CLU-004 (ADR-174) — the device list is a federated read (every node is asked): off the
    // runtime's worker.
    let existing = {
        let (backend, name) = (Arc::clone(backend), name.to_owned());
        blocking(move || Ok(backend.clients().into_iter().find(|c| c.name == name))).await?
    };
    if let Some(c) = &existing
        && !c.groups.iter().any(|x| x == g)
    {
        return refuse(format!("`{name}` isn't in group `{g}`"));
    }
    match op {
        Op::Client(Some(input)) if input.groups != [g] => refuse(format!(
            "devices you change must be in group `{g}` (set \"groups\": [\"{g}\"])"
        )),
        Op::Client(None) if existing.is_none() => refuse(format!("`{name}` isn't in group `{g}`")),
        Op::Client(_) => Ok(()),
        Op::Managed(..) => refuse(
            "restricted tokens can't change local names, forwarded domains, quick rules, upstreams, lists, or groups".into(),
        ),
    }
}

/// Add or change an alert destination (OBS-010, T9.6).
///
/// The body has the same fields as `[[alerts.destination]]` (the name comes from the path):
/// `{"type": "ntfy", "url": "https://ntfy.sh/my-topic"}`, or for email
/// `{"type": "email", "url": "smtp://smtp.gmail.com:587", "from": "me@gmail.com", "to":
/// ["me@gmail.com"], "username": "me@gmail.com", "password_file": "/run/secrets/smtp"}`.
/// Secrets stay in files on the node (`token_file`, `password_file`): only the path is sent.
/// A destination that names either file, before or after the change, is added or changed only
/// by an administrator (an admin's sign-in or API token; agent tokens can't); without one, or to
/// delete one, the operator role is enough. The file is an absolute path under `/run/secrets/`,
/// `/etc/telltale-secrets/` or the data directory's `secrets/` folder (not
/// `/run/secrets/kubernetes.io/`), written without `.` or `..`; links are followed. It needn't
/// exist yet.
/// A destination the config files define is overridden until this one is deleted.
#[utoipa::path(put, path = "/api/v1/alerts/destinations/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "The destination names a credential file (`token_file`, `password_file`), before or after the change, and the caller isn't an administrator."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, or the configuration wouldn't be valid: problem+json says which."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_alert_destination(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /alerts/destinations/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::AlertDestination, Some(input)),
    )
    .await
}

/// Remove an alert destination (OBS-010, T9.6).
///
/// Rules that still send to it make the configuration invalid (422 says which).
#[utoipa::path(delete, path = "/api/v1/alerts/destinations/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No entry by that name."),
        (status = 422, body = Problem, description = "A rule still uses it."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_alert_destination(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /alerts/destinations/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::AlertDestination, None),
    )
    .await
}

/// Add or change an alert rule (OBS-010, T9.6).
///
/// The body has the same fields as `[[alerts.rule]]` (the name comes from the path):
/// `{"when": "upstream_down", "for_secs": 60, "to": ["phone"]}`. `when` is one of
/// `upstream_down`, `node_down`, `list_failing`, `anomaly`, `servfail_rate`,
/// `update_available`, `sync_lag`, `new_device`, `disk_full`, `plan_pending`.
#[utoipa::path(put, path = "/api/v1/alerts/rules/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, or the configuration wouldn't be valid: problem+json says which."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_alert_rule(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /alerts/rules/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::AlertRule, Some(input)),
    )
    .await
}

/// Remove an alert rule (OBS-010, T9.6).
///
/// An alert the rule has firing stops being tracked (no "Resolved" message is sent). A rule
/// the config files define is hidden until this override is deleted in turn.
#[utoipa::path(delete, path = "/api/v1/alerts/rules/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No entry by that name."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_alert_rule(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /alerts/rules/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::AlertRule, None),
    )
    .await
}

/// Send a test alert to one destination (OBS-010, T9.6).
///
/// Sends a message marked as a test, from this node, and answers with what happened: `ok`, or
/// the destination's error (a wrong password, an unreachable server). Nothing is stored, but
/// the test is audited. Needs the operator role. When the private CA file (`tls_ca`) can't be
/// used, only an administrator is told why; anyone else gets that it couldn't be (ADR-180).
#[utoipa::path(post, path = "/api/v1/alerts/destinations/{name}/test", tag = "config",
    params(("name" = String, Path, description = "The destination.")),
    responses(
        (status = 200, body = crate::model::AlertTest, description = "Sent, or why not."),
        (status = 404, body = Problem, description = "No destination by that name."),
    ))]
pub(crate) async fn test_alert_destination(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Result<Json<crate::model::AlertTest>, Problem> {
    let p = principal(&ext)?;
    let r = backend.alert_test(&name, by_admin(&p)).await?;
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    auth.record(
        &actor,
        "alert.test",
        &name,
        &serde_json::json!({ "ok": r.ok, "error": r.error }),
    );
    Ok(Json(r))
}

/// Check a draft upstream before saving it (API-002, T9.12).
///
/// The body has the same fields as `PUT /api/v1/upstreams/{name}` (`name` optional). This node
/// builds it and asks it for the root's NS records, as health checks do, and answers with what
/// happened: `ok` with the rcode, records, and time, or the error (a bad URL, a TLS name that
/// doesn't match, a timeout). Nothing is saved; the check is audited. Needs the operator role
/// (agents: `config:write:upstreams`). A plugin draft (`exec://`, `unix://`, `args`) is refused
/// before anything is built, for everyone: plugin upstreams are defined in the config file
/// (ADR-180). When a TLS file the draft names (`tls_ca`, `tls_client_cert`, `tls_client_key`)
/// can't be used, only an administrator is told why; anyone else gets that it couldn't be.
#[utoipa::path(post, path = "/api/v1/checks/upstream", tag = "config",
    request_body = Object,
    responses(
        (status = 200, body = crate::model::CheckResult, description = "Answered, or why not."),
        (status = 422, body = Problem, description = "The body isn't an upstream (an unknown or mistyped field), or it's a plugin (`exec://`, `unix://`)."),
    ))]
pub(crate) async fn check_upstream(
    State((backend, auth)): State<Ctx>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<crate::model::CheckResult>, Problem> {
    let p = principal(&ext)?;
    let input = body(b)?;
    let url = input.get("url").cloned().unwrap_or_default();
    let mut r = backend.check_upstream(input, by_admin(&p)).await?;
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    auth.record(
        &actor,
        "check.upstream",
        url.as_str().unwrap_or(""),
        &serde_json::json!({ "ok": r.ok, "error": r.error }),
    );
    // REQ: AGT-009 (review 06 q5) — why a probe failed (refused, timed out, reset) tells open
    // from closed ports: an agent learns only that it didn't answer. The audit log keeps it.
    if p.agent.is_some() && !r.ok && r.detail != "not built" {
        r.error = Some("unreachable (an operator can see why in the UI)".into());
        "no answer".clone_into(&mut r.detail);
    }
    Ok(Json(r))
}

/// Check a draft list before saving it (API-002, T9.12).
///
/// The body has the same fields as `PUT /api/v1/lists/{name}` (`name` optional): a `url` is
/// downloaded from this node (with `[filter]`'s size limit and timeout), or `rules` are taken
/// as they are, then parsed as the compiler would. Answers with the rules found, the lines it
/// couldn't use, and the time. Nothing is saved or compiled; the check is audited. `path`
/// lists are checked when saved. Needs the operator role (agents: `config:write:lists`).
#[utoipa::path(post, path = "/api/v1/checks/list", tag = "config",
    request_body = Object,
    responses(
        (status = 200, body = crate::model::CheckResult, description = "Parsed, or why not."),
        (status = 422, body = Problem, description = "The body isn't a list (an unknown or mistyped field), or it has no url or rules."),
    ))]
pub(crate) async fn check_list(
    State((backend, auth)): State<Ctx>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<crate::model::CheckResult>, Problem> {
    let p = principal(&ext)?;
    let input = body(b)?;
    let url = input.get("url").cloned().unwrap_or_default();
    let mut r = backend.check_list(input).await?;
    // REQ: AGT-009 — the sample lines are the fetched content: operators see them in the UI;
    // an agent gets how many and why (the node would otherwise read any URL it can reach on
    // the agent's behalf). The shape `line N: <text> (<reason>)` is `checks::list`'s.
    if p.agent.is_some() && !r.warnings.is_empty() {
        let reasons: std::collections::BTreeSet<&str> = r
            .warnings
            .iter()
            .filter_map(|w| w.rsplit_once(" ("))
            .map(|(_, reason)| reason.trim_end_matches(')'))
            .collect();
        r.warnings = vec![format!(
            "{} line(s) couldn't be used ({}); an operator can see them in the UI",
            r.warnings.len(),
            reasons.into_iter().collect::<Vec<_>>().join(", ")
        )];
    }
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    auth.record(
        &actor,
        "check.list",
        url.as_str().unwrap_or("(rules)"),
        &serde_json::json!({ "ok": r.ok, "rules": r.rules, "error": r.error }),
    );
    // REQ: AGT-009 (review 06 q5) — likewise for a download that failed.
    if p.agent.is_some() && r.detail == "not downloaded" {
        r.error = Some("unreachable (an operator can see why in the UI)".into());
    }
    Ok(Json(r))
}

/// Add or change a schedule (FLT-010, T9.7).
///
/// The body has the same fields as `[[schedule]]` (the name comes from the path), e.g. a
/// bedtime: `{"action": "block_all", "tz": "America/New_York", "window": [{"days":
/// ["weekdays"], "start": "21:00", "end": "07:00"}]}`. Groups use a schedule by naming it in
/// their `schedules`. A schedule the config files define is overridden until this one is
/// deleted.
#[utoipa::path(put, path = "/api/v1/schedules/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong (a window's time, an unknown list or service), or the configuration wouldn't be valid."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_schedule(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /schedules/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Schedule, Some(input)),
    )
    .await
}

/// Add or change a router integration (T8.2, API-002).
///
/// The body has the same fields as `[[router]]` (the name comes from the path), e.g. a UniFi
/// console: `{"type": "unifi", "url": "https://192.168.1.1", "api_key": "…",
/// "tls_insecure_skip_verify": true}`. The UniFi API key, the OPNsense key and secret, or a
/// UniFi or FRITZ!Box password are sent as `api_key`, `api_secret`, and `password`: TelltaleDNS writes
/// each to a new file only it can read under `<data_dir>/secrets/` on this node and stores that
/// file's path. The value itself is never stored, logged, or returned; with an `Idempotency-Key`,
/// the record kept for a retry holds only a keyed hash of it, for a day (ADR-181). A pasted key goes only
/// to an `https://` address (or a loopback one), and with `tls_insecure_skip_verify` only to an
/// address written as a number, not a host name. The body names no key file (`api_key_file`, …)
/// but the router's own, sent back unchanged at the same address: paste the key instead (a file
/// elsewhere, such as a Docker or Kubernetes secret, is named in the config file); with a pasted
/// value, the file named for it is replaced. Leave a credential out to keep the current one,
/// unless the type, address, site, or TLS settings change: then it must be entered again. Admins
/// only: an administrator's own sign-in or an admin API token; agent tokens can't. The routers
/// are read again within 5 seconds after the reads in progress end; a router the config files
/// define is overridden until this one is deleted. A key left out with none of its own is
/// refused (422) by the name to paste (`api_key`, `api_secret`, `password`). A FRITZ!Box
/// (`"type": "fritzbox"`, with `client_subnets`) signs in here: a `username` and its `password`;
/// one read without a sign-in is a `[[router]]` entry in the config file (422).
#[utoipa::path(put, path = "/api/v1/routers/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Not an administrator (agent tokens never are)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong (the URL, missing credentials, a key file named, a pasted key for an http:// address or, with an unchecked certificate, for a host name, the key not entered again for a new address, a node whose data_dir isn't a plain absolute path), or the configuration wouldn't be valid."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_router(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    // REQ: API-002, AGT-003, T8.2 (ADR-181) — security F5: the idempotency record (in state.db)
    // keeps the request, so a retry with the same key and body replays and another body is
    // refused. A pasted secret is kept there only as a hash keyed with this node's request key
    // (`Auth::request_digest`: a random key in a file only this user reads, outside state.db and
    // outside backups), so the record can't be used to test guesses of the secret.
    let mut shown = input.clone();
    if let Some(o) = shown.as_object_mut() {
        for (k, _) in crate::ROUTER_CREDENTIALS {
            if let Some(v) = o.get_mut(k)
                && let Some(s) = v.as_str()
            {
                *v = serde_json::Value::String(format!("keyed:{}", auth.request_digest(s)));
            }
        }
    }
    let request = format!("PUT /routers/{name} {}", json_of(&shown));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Router, Some(input)),
    )
    .await
}

/// Remove a router integration (T8.2, API-002).
///
/// Its devices lose the names it gave them after the next round of reads, which starts within 5
/// seconds after the reads in progress end. A router the config files define
/// is hidden until the files' entry is brought back (DELETE again, or Revert to the file).
/// Admins only, as for `PUT`.
#[utoipa::path(delete, path = "/api/v1/routers/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Not an administrator (agent tokens never are)."),
        (status = 404, body = Problem, description = "No entry by that name."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_router(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /routers/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Router, None),
    )
    .await
}

/// Mute kinds of device anomaly for some devices or groups (OBS-038).
///
/// The body has the same fields as `[[anomaly_mute]]` (the name comes from the path):
/// `devices` (device names, IPs or CIDRs) and/or `groups`, `kinds` (`rate_spike`,
/// `domain_volume`, `drift`, `beacon`, `nxdomain_storm`, `dga`, `chatty_loop`, `reverse_sweep`;
/// a mute of `nxdomain_storm` doesn't cover `reverse_sweep`), and optionally
/// `expires` (RFC 3339) and `note`, e.g. `{"devices": ["lg-tv-living"], "kinds":
/// ["reverse_sweep"], "expires": "2026-12-31T00:00:00Z", "note": "hourly PTR sweep"}`. A finding
/// a mute matches when it is created is still recorded and listed (`GET
/// /analytics/anomalies?muted=true`, with `mutedBy`), but isn't counted in
/// `telltale_anomalies_total`, the badge, the `anomaly` alert rule, or the health level
/// (`telltale_anomalies_muted_total` counts it). The same kind still counts for every other
/// device. The mute is shared: it applies on every node. There is no mute for everyone: name at
/// least one device or group.
#[utoipa::path(put, path = "/api/v1/anomaly-mutes/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong (no device or group, an unknown kind, a name that matches nothing, a MAC address), or the configuration wouldn't be valid."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_anomaly_mute(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /anomaly-mutes/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::AnomalyMute, Some(input)),
    )
    .await
}

/// Remove an anomaly mute (OBS-038).
///
/// Findings created from now on count again; ones recorded while the mute held stay muted.
#[utoipa::path(delete, path = "/api/v1/anomaly-mutes/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No entry by that name."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_anomaly_mute(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /anomaly-mutes/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::AnomalyMute, None),
    )
    .await
}

/// Put Kubernetes workloads in a group (FLT-017).
///
/// Writes a `[[kubernetes.map]]` rule: the key in the path is `namespace/kind/name` with `*` for
/// any (`media/deploy/jellyfin` for one workload, `media*/*/*` for every namespace starting with
/// `media`), the body names the group: `{"group": "iot"}`. Rules made here are checked before
/// the configuration files' (first match wins); a pod or namespace label
/// (`telltaledns.io/group`) still wins over any rule (the way to do the same from Git).
/// The workload's next query uses the group.
#[utoipa::path(put, path = "/api/v1/kubernetes/map/{key}", tag = "config",
    params(("key" = String, Path, description = "namespace/kind/name; `*` for any kind or name; the namespace may be a glob."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 400, body = Problem, description = "The key isn't namespace/kind/name, or the body has no `group`."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "No such group, or an unknown kind."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_kubernetes_map(
    State((backend, auth)): State<Ctx>,
    Path(key): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let key = key.trim_start_matches('/').to_owned();
    let request = format!("PUT /kubernetes/map/{key} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        key,
        Op::Managed(ManagedKind::KubernetesMap, Some(input)),
    )
    .await
}

/// Remove a Kubernetes workloads' group rule (FLT-017).
///
/// A rule made here goes; a rule of the configuration files is hidden until this one is put
/// back. The workloads it matched take the next rule, `default_group`, or their network's group.
#[utoipa::path(delete, path = "/api/v1/kubernetes/map/{key}", tag = "config",
    params(("key" = String, Path, description = "namespace/kind/name, as the rule was made."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No rule by that key."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_kubernetes_map(
    State((backend, auth)): State<Ctx>,
    Path(key): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let key = key.trim_start_matches('/').to_owned();
    let request = format!("DELETE /kubernetes/map/{key}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        key,
        Op::Managed(ManagedKind::KubernetesMap, None),
    )
    .await
}

/// Remove a schedule (FLT-010, T9.7).
///
/// A group that still names it makes the configuration invalid (422 says which): take it out
/// of the group's `schedules` first.
#[utoipa::path(delete, path = "/api/v1/schedules/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No entry by that name."),
        (status = 422, body = Problem, description = "A group still uses it."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_schedule(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /schedules/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Schedule, None),
    )
    .await
}

/// Set the per-client rate limit (DNS-014).
///
/// The body has the same fields as `[ratelimit]` in `telltale.toml`: `enabled`, `queries` (allowed
/// per window, per client; bursts up to this), `window_secs`, `action` (`refused` or `drop`),
/// `exempt` (CIDRs never limited), `ipv4_prefix`, and `ipv6_prefix` (how clients are grouped: 32
/// is one address, 64 groups a device's rotating IPv6 addresses). It replaces the whole section
/// (fields left out take the defaults, not the config file's values) until it's deleted again.
/// A router or proxy that forwards for a whole network shows up as one client: add it to
/// `exempt`, or raise `queries`. Applies on the next query, with no restart; every client's count
/// starts over.
#[utoipa::path(put, path = "/api/v1/ratelimit/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong (a prefix, a CIDR, zero queries while enabled), or the configuration wouldn't be valid."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_ratelimit(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /ratelimit/default {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        "default".to_owned(),
        Op::Managed(ManagedKind::RateLimit, Some(input)),
    )
    .await
}

/// Go back to the config file's rate limit (DNS-014).
///
/// Removes what the API or UI stored, so `[ratelimit]` in the config files (or the defaults)
/// applies again. 404 when nothing was stored.
#[utoipa::path(delete, path = "/api/v1/ratelimit/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's rate limit is in effect already."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_ratelimit(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        "DELETE /ratelimit/default".to_owned(),
        "default".to_owned(),
        Op::Managed(ManagedKind::RateLimit, None),
    )
    .await
}

/// Keep names and devices out of the query log and analytics (OBS-022).
///
/// The body has the same fields as `[exclusions]` in `telltale.toml`: `enabled` (turn them on or
/// off without losing the lists), `names` (each with its subdomains, e.g.
/// `connectivitycheck.gstatic.com`), and `clients` (addresses or networks). Their queries are
/// still answered and still counted in `/metrics`, but left out of the query log, the live view,
/// the dashboard and top lists, anomalies, and every export. It replaces the whole section until
/// it's deleted again; it applies to every node of a cluster from the next query on.
#[utoipa::path(put, path = "/api/v1/exclusions/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A name isn't a domain name, a client isn't an address or network, or the configuration wouldn't be valid."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_exclusions(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /exclusions/default {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        "default".to_owned(),
        Op::Managed(ManagedKind::Exclusions, Some(input)),
    )
    .await
}

/// Go back to the config file's exclusions (OBS-022).
///
/// Removes what the API or UI stored, so `[exclusions]` in the config files (or none) applies
/// again. 404 when nothing was stored.
#[utoipa::path(delete, path = "/api/v1/exclusions/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's exclusions are in effect already."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_exclusions(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        "DELETE /exclusions/default".to_owned(),
        "default".to_owned(),
        Op::Managed(ManagedKind::Exclusions, None),
    )
    .await
}

/// REQ: T8.2, API-002 (ADR-181) — routers, for admins (merged with `require_admin`): a
/// router holds credentials and is told where to send them.
pub(crate) fn router_routes(backend: Arc<dyn Backend>, auth: Arc<Auth>) -> Router {
    Router::new()
        .route(
            "/api/v1/routers/{name}",
            axum::routing::put(put_router).delete(delete_router),
        )
        .with_state((backend, auth))
}

/// REQ: CLU-013 — `[cluster.rollout]`, for admins (merged with `require_admin`).
pub(crate) fn rollout_settings_routes(backend: Arc<dyn Backend>, auth: Arc<Auth>) -> Router {
    Router::new()
        .route(
            "/api/v1/cluster/rollout-settings/default",
            axum::routing::put(put_rollout_settings).delete(delete_rollout_settings),
        )
        .with_state((backend, auth))
}

/// Staged rollouts' settings (CLU-013).
///
/// The body has the same fields as `[cluster.rollout]` in `telltale.toml`: `canaries` (node
/// IDs, `site:<name>`, or `ephemeral` for the resolver pods; empty = no rollouts), `bake_secs`
/// (at least 5), `servfail_pct`, `require_traffic`, `max_bake_secs`, `fail_on_disconnect`, and
/// `history` (versions kept for pinning). It replaces the whole section until deleted again,
/// on every node. A change to these settings is published at once, never staged itself.
/// Admins only (agents: `cluster:admin`).
#[utoipa::path(put, path = "/api/v1/cluster/rollout-settings/default", tag = "system",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A bound is out of range or a canary isn't a node ID, `site:<name>`, or `ephemeral`."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_rollout_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /cluster/rollout-settings/default {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        "default".to_owned(),
        Op::Managed(ManagedKind::Rollout, Some(input)),
    )
    .await
}

/// Go back to the config file's rollout settings (CLU-013).
///
/// Removes what the API or UI stored, so `[cluster.rollout]` in the config files (or the
/// default: no rollouts) applies again. 404 when nothing was stored.
#[utoipa::path(delete, path = "/api/v1/cluster/rollout-settings/default", tag = "system",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's settings are in effect already."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_rollout_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        "DELETE /cluster/rollout-settings/default".to_owned(),
        "default".to_owned(),
        Op::Managed(ManagedKind::Rollout, None),
    )
    .await
}

/// Change simulation's settings (OBS-024).
///
/// The body has the same fields as `[simulate]` in `telltale.toml`: `enabled` (simulations at
/// all), `plans_by_default` (agents' plans simulate even when they don't ask), `max_secs`
/// (1 to 300), `max_rows` (at least 1,000), and `default_window` (`24h`; at most `7d`). It
/// replaces the whole section until it's deleted again, on every node of a cluster.
#[utoipa::path(put, path = "/api/v1/simulate-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A bound is out of range, or the configuration wouldn't be valid."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_simulate_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /simulate-settings/default {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        "default".to_owned(),
        Op::Managed(ManagedKind::Simulate, Some(input)),
    )
    .await
}

/// Go back to the config file's simulation settings (OBS-024).
///
/// Removes what the API or UI stored, so `[simulate]` in the config files (or the defaults)
/// applies again. 404 when nothing was stored.
#[utoipa::path(delete, path = "/api/v1/simulate-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's settings are in effect already."),
        (status = 409, body = Problem, description = "The Idempotency-Key was used for another request, or its first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_simulate_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        "DELETE /simulate-settings/default".to_owned(),
        "default".to_owned(),
        Op::Managed(ManagedKind::Simulate, None),
    )
    .await
}

/// What a write changes.
enum Op {
    Client(Option<ClientInput>),
    Managed(ManagedKind, Option<serde_json::Value>),
}

impl Op {
    fn audit_kind(&self) -> &'static str {
        match self {
            Self::Client(_) => "client",
            Self::Managed(ManagedKind::Record, _) => "record",
            Self::Managed(ManagedKind::Forward, _) => "forward",
            Self::Managed(ManagedKind::Rule, _) => "rule",
            Self::Managed(ManagedKind::Upstream, _) => "upstream",
            Self::Managed(ManagedKind::UpstreamGroup, _) => "upstream_group",
            Self::Managed(ManagedKind::List, _) => "list",
            Self::Managed(ManagedKind::Group, _) => "group",
            Self::Managed(ManagedKind::AlertDestination, _) => "alert_destination",
            Self::Managed(ManagedKind::AlertRule, _) => "alert_rule",
            Self::Managed(ManagedKind::Schedule, _) => "schedule",
            Self::Managed(ManagedKind::AnomalyMute, _) => "anomaly_mute",
            Self::Managed(ManagedKind::RateLimit, _) => "ratelimit",
            Self::Managed(ManagedKind::Exclusions, _) => "exclusions",
            Self::Managed(ManagedKind::Simulate, _) => "simulate",
            Self::Managed(ManagedKind::Rollout, _) => "rollout_settings",
            Self::Managed(ManagedKind::KubernetesMap, _) => "kubernetes_map",
            Self::Managed(ManagedKind::Router, _) => "router",
        }
    }
    fn deleting(&self) -> bool {
        matches!(self, Self::Client(None) | Self::Managed(_, None))
    }
}

fn dry(q: &DryRun) -> WriteOpts {
    WriteOpts {
        dry_run: q.dry_run.unwrap_or(false),
        simulate: q.simulate.clone(),
        simulate_until: q.simulate_until.clone(),
    }
}

/// REQ: OBS-024 — `simulate`/`simulateUntil` as the backend takes them. Only with a dry run
/// (`auto` is ignored without one: it means "if the settings say so").
pub(crate) fn simulate_opts(d: &WriteOpts, now_s: u64) -> Result<Option<SimulateOpts>, Problem> {
    let Some(text) = d.simulate.as_deref().map(str::trim) else {
        if d.simulate_until.is_some() {
            return Err(Problem::invalid("`simulateUntil` needs `simulate`"));
        }
        return Ok(None);
    };
    let auto = text.eq_ignore_ascii_case("auto");
    if !d.dry_run {
        if auto {
            return Ok(None);
        }
        return Err(Problem::invalid("`simulate` needs `dryRun=true`")
            .hint("A simulation previews a change: add dryRun=true."));
    }
    // REQ: OBS-024 (T13.1) — `now` is no end given: the backend's default takes in this second.
    let until_s = crate::time::parse_until(d.simulate_until.as_deref(), now_s)
        .map_err(|e| Problem::invalid(format!("`simulateUntil`: {e}")))?;
    let window =
        (!auto && !text.is_empty() && !text.eq_ignore_ascii_case("true")).then(|| text.to_owned());
    Ok(Some(SimulateOpts {
        window,
        auto,
        until_s,
    }))
}

fn json_of<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

/// Create, rename, or change a device (API-010).
///
/// Names devices across every view: the query log, live tail, charts, and history (names
/// are resolved when read, so earlier queries are relabelled too). To rename, send the new
/// `name` in the body. Devices defined in the config files are read-only here (409). Needs
/// the operator role (or a `write` token).
#[utoipa::path(put, path = "/api/v1/clients/{name}", tag = "config",
    params(("name" = String, Path, description = "The device's current name (or the name for a new one)."), DryRun),
    request_body = ClientInput,
    responses(
        (status = 200, body = ClientChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 409, body = Problem, description = "Defined in the config files, or an Idempotency-Key reused for another request; or the Idempotency-Key's first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 412, body = Problem, description = "If-Match: the config changed since that version."),
        (status = 422, body = Problem, description = "The resulting configuration is invalid (e.g. an unknown group)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_client(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<ClientInput>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /clients/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Client(Some(input)),
    )
    .await
}

/// Delete a device named through the API.
///
/// Its queries, past and future, go back to showing the address, and it leaves its groups
/// (the `default` group applies). Devices from the config files can't be deleted here (409).
/// Needs the operator role (or a `write` token).
#[utoipa::path(delete, path = "/api/v1/clients/{name}", tag = "config",
    params(("name" = String, Path, description = "The device's name."), DryRun),
    responses(
        (status = 200, body = ClientChange, description = "The result."),
        (status = 404, body = Problem, description = "No device by that name was created through the API."),
        (status = 409, body = Problem, description = "Defined in the config files; or the Idempotency-Key's first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_client(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /clients/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Client(None),
    )
    .await
}

/// Set a local name's records (API-011, "Names on my network").
///
/// Replaces every record of `name` made through the API with `records` (A and AAAA addresses,
/// CNAME aliases, and in Advanced PTR, TXT, MX, SRV). TelltaleDNS then answers the name itself,
/// before the cache and upstreams; reverse lookups for addresses are added automatically
/// (`[local] auto_ptr`). Names defined in the config files are read-only here (409). Needs the
/// operator role (or a `write` token).
#[utoipa::path(put, path = "/api/v1/records/{name}", tag = "config",
    params(("name" = String, Path, description = "The full name, e.g. nas.home.arpa (a leading `*.` makes a wildcard)."), DryRun),
    request_body = RecordsInput,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 409, body = Problem, description = "Defined in the config files, or an Idempotency-Key reused; or the Idempotency-Key's first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A value doesn't fit its type (e.g. A with a name), or the result is invalid."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_records(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<RecordsInput>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /records/{name} {}", json_of(&input));
    let v = serde_json::to_value(&input).unwrap_or_default();
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Record, Some(v)),
    )
    .await
}

/// Remove a local name made through the API.
///
/// TelltaleDNS stops answering it itself; queries for it go to the upstreams (or a route) as
/// usual. Names from the config files can't be removed here (409).
#[utoipa::path(delete, path = "/api/v1/records/{name}", tag = "config",
    params(("name" = String, Path, description = "The full name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No name like that was created through the API."),
        (status = 409, body = Problem, description = "Conflicts with the current state: problem+json says what to change; or the Idempotency-Key's first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_records(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /records/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Record, None),
    )
    .await
}

/// Send a domain to other DNS servers (conditional forwarding; API-011).
///
/// Every name under `domain` is asked of `servers` (in order, failing over) instead of the
/// public upstreams: a work network's DNS over a VPN, a router that knows your devices, another
/// lab. A bare address means plain DNS; `tls://` and `https://` URLs work too. Local names still
/// answer first. Domains routed in the config files are read-only here (409). A server can't be a
/// plugin (`exec://`, `unix://`): those are defined in the config file (422, ADR-180).
#[utoipa::path(put, path = "/api/v1/forwards/{domain}", tag = "config",
    params(("domain" = String, Path, description = "The domain, e.g. corp.example (its whole subtree is sent)."), DryRun),
    request_body = ForwardInput,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 409, body = Problem, description = "Conflicts with the current state: problem+json says what to change; or the Idempotency-Key's first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A server isn't an address or a supported URL, or it's a plugin (`exec://`, `unix://`)."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_forward(
    State((backend, auth)): State<Ctx>,
    Path(domain): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<ForwardInput>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /forwards/{domain} {}", json_of(&input));
    let v = serde_json::to_value(&input).unwrap_or_default();
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        domain,
        Op::Managed(ManagedKind::Forward, Some(v)),
    )
    .await
}

/// Stop sending a domain to other servers.
///
/// Names under it go to the public upstreams again. Routes from the config files can't be
/// removed here (409).
#[utoipa::path(delete, path = "/api/v1/forwards/{domain}", tag = "config",
    params(("domain" = String, Path, description = "The domain."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "Not found."),
        (status = 409, body = Problem, description = "Conflicts with the current state: problem+json says what to change; or the Idempotency-Key's first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_forward(
    State((backend, auth)): State<Ctx>,
    Path(domain): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /forwards/{domain}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        domain,
        Op::Managed(ManagedKind::Forward, None),
    )
    .await
}

/// Create or replace a quick rule (T6.12, ADR-067).
///
/// Allows or blocks `domain` and its subdomains for `devices`, `groups`, or everyone (neither
/// given), before any list: a device rule beats a group rule beats an everyone rule; within one
/// scope the longer domain wins, then allow. With `expires` or `forMinutes` it stops applying
/// then (and is removed). It takes effect on the next query, without recompiling the lists.
/// `devices` takes the names of configured devices, IPs, or CIDRs; the name a router or mDNS gives
/// an address (a query's `clientName` for a device nobody named) is refused (422, with a hint):
/// use the address, or name the device first. A rule for an address stops matching when the
/// address changes (a Kubernetes pod's does with every restart: use `groups`, with the group an
/// operator placed the workload in).
/// Rules from the config files are read-only here (409). Needs the operator role (or the
/// `config:write:rules` agent scope, with a reason).
#[utoipa::path(put, path = "/api/v1/rules/{id}", tag = "config",
    params(("id" = String, Path, description = "The rule's ID: any short unique name (the UI makes one)."), DryRun),
    request_body = crate::model::RuleInput,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 409, body = Problem, description = "Defined in the config files, or an Idempotency-Key reused; or the Idempotency-Key's first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A device that isn't a configured device's name, an IP, or a CIDR (the hint says what to do; a name a router or mDNS gives an address is one), an unknown group, a bad domain, or an expiry in the past."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn put_rule(
    State((backend, auth)): State<Ctx>,
    Path(id): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<crate::model::RuleInput>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /rules/{id} {}", json_of(&input));
    let v = serde_json::to_value(&input).unwrap_or_default();
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        id,
        Op::Managed(ManagedKind::Rule, Some(v)),
    )
    .await
}

/// Remove a quick rule made through the API.
///
/// The lists decide for its domain again. Rules from the config files can't be removed here
/// (409).
#[utoipa::path(delete, path = "/api/v1/rules/{id}", tag = "config",
    params(("id" = String, Path, description = "The rule's ID."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No rule with that ID was created through the API."),
        (status = 409, body = Problem, description = "Defined in the config files; or the Idempotency-Key's first request is still running (`change_in_progress`, with `Retry-After`: retry shortly for its answer)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 503, body = Problem, description = "Too many configuration changes are running at once (`Retry-After`: retry shortly)."),
    ))]
pub(crate) async fn delete_rule(
    State((backend, auth)): State<Ctx>,
    Path(id): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /rules/{id}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        id,
        Op::Managed(ManagedKind::Rule, None),
    )
    .await
}

/// REQ: OBS-010, API-002, FLT-004, OBS-024 (ADR-179, ADR-180) — the caller is an administrator:
/// an admin's own sign-in (a session or HTTP Basic) or an admin-scoped API token. An agent token
/// never is, whoever owns it and whatever else it may do.
pub(crate) fn by_admin(p: &crate::auth::Principal) -> bool {
    p.role == crate::auth::Role::Admin && p.agent.is_none()
}

/// REQ: API-002, AGT-003, NFR-005 (ADR-181) — how many configuration changes run at once (each
/// in a task of its own, which a client that goes away doesn't cancel); one more gets 503.
pub(crate) const CHANGES_AT_ONCE: usize = 32;

/// REQ: API-002, AGT-003 (ADR-181) — review round 2 (security N2, N3): the configuration changes
/// running on this node: the Idempotency-Keys whose first request hasn't finished, and the places
/// for changes running at once. One per [`Auth`], so per API.
#[derive(Debug)]
pub(crate) struct WriteGate {
    running: std::sync::Mutex<std::collections::HashSet<String>>,
    places: Arc<tokio::sync::Semaphore>,
}

impl WriteGate {
    pub(crate) fn new() -> Self {
        Self {
            running: std::sync::Mutex::new(std::collections::HashSet::new()),
            places: Arc::new(tokio::sync::Semaphore::new(CHANGES_AT_ONCE)),
        }
    }

    /// Tests: every place, until the permit is dropped.
    #[cfg(test)]
    pub(crate) fn take_every_place(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.places)
            .try_acquire_many_owned(u32::try_from(CHANGES_AT_ONCE).ok()?)
            .ok()
    }

    /// Tests: `key` (`<user ID>:<Idempotency-Key>`) as if its first request were running, or no
    /// longer.
    #[cfg(test)]
    pub(crate) fn hold_key(&self, key: &str, held: bool) {
        let mut running = self
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if held {
            running.insert(key.to_owned());
        } else {
            running.remove(key);
        }
    }
}

/// An Idempotency-Key whose first request is running; let go when dropped: when the change's
/// task ends, or unwinds.
struct KeyHeld {
    gate: Arc<WriteGate>,
    key: String,
}

impl Drop for KeyHeld {
    fn drop(&mut self) {
        self.gate
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.key);
    }
}

/// REQ: AGT-003 (ADR-181) — security N2: a change with an Idempotency-Key, before it runs: the
/// stored answer is replayed, another request with the key is refused, and a retry while the
/// first request is still running gets 409 with `Retry-After` (it would otherwise be made a
/// second time: the answer is stored only once the first has finished). The lookup and the
/// claim are one step, under the gate's lock. `Ok` holds the key until dropped; `Err` is the
/// answer to send instead.
fn claim_key(auth: &Auth, key: &str, request: &str, now: u64) -> Result<KeyHeld, Box<Response>> {
    let gate = auth.write_gate();
    let mut running = gate
        .running
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match auth.state().idempotent(key, now) {
        Ok(Some(r)) if r.request == request.as_bytes() => return Err(Box::new(replay(&r))),
        Ok(Some(_)) => {
            return Err(Box::new(
                Problem::new(
                    Code::Conflict,
                    "this Idempotency-Key was used for a different request",
                )
                .hint("Use a new key for each distinct change.")
                .into_response(),
            ));
        }
        Ok(None) => {}
        Err(e) => return Err(Box::new(Problem::internal(e.to_string()).into_response())),
    }
    if !running.insert(key.to_owned()) {
        return Err(Box::new(
            Problem::new(
                Code::ChangeInProgress,
                "this Idempotency-Key's first request is still running",
            )
            .hint("Retry in a few seconds: once it has finished, the same request gets its answer.")
            .retry_after(2)
            .into_response(),
        ));
    }
    Ok(KeyHeld {
        gate: Arc::clone(gate),
        key: key.to_owned(),
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // one path for every write
async fn write(
    backend: Arc<dyn Backend>,
    auth: Arc<Auth>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    dry: WriteOpts,
    request: String,
    name: String,
    op: Op,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let dry_run = dry.dry_run;
    let simulate = match simulate_opts(&dry, backend.now_unix_seconds()) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    // REQ: OBS-024 — a simulation reads the query log: agents need that scope too.
    if simulate.as_ref().is_some_and(|s| !s.auto)
        && let Err(e) = crate::simulate_api::agent_may_simulate(&p, None)
    {
        return e.into_response();
    }
    // `simulate=auto` from a token that can't read the log: no simulation, not an error.
    let simulate = simulate.filter(|_| crate::simulate_api::agent_may_simulate(&p, None).is_ok());
    if let Err(e) = group_guard(&p, &backend, &name, &op).await {
        return e.into_response();
    }
    let expect = match expected_version(&headers) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    // REQ: AGT-003 — a retried request gets the first response; another request with the
    // same key is refused.
    let key = headers
        .get(IDEMPOTENCY_KEY)
        .and_then(|v| v.to_str().ok())
        .map(|k| format!("{}:{}", p.user_id, k.trim()))
        .filter(|k| !dry_run && k.len() > 2);
    let now = backend.now_unix_seconds();
    let held = match &key {
        Some(k) => match claim_key(&auth, k, &request, now) {
            Ok(h) => Some(h),
            Err(answer) => return *answer,
        },
        None => None,
    };
    // REQ: API-002, NFR-005 (ADR-181) — security N3: a place among the changes running at once
    // (dry runs aren't counted); given back when the change's task ends, or unwinds.
    let place = if dry_run {
        None
    } else {
        match Arc::clone(&auth.write_gate().places).try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => {
                return Problem::new(
                    Code::Unavailable,
                    format!("{CHANGES_AT_ONCE} configuration changes are running already"),
                )
                .hint("Retry in a few seconds.")
                .retry_after(2)
                .into_response();
            }
        }
    };
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let action = format!(
        "{}.{}",
        op.audit_kind(),
        if op.deleting() { "delete" } else { "put" }
    );
    let work = {
        let (backend, auth) = (Arc::clone(&backend), Arc::clone(&auth));
        async move {
            // Kept until the answer is stored for the key (below), then given back.
            let (_held, _place) = (held, place);
            let admin = by_admin(&p);
            let result: Result<serde_json::Value, Problem> = match op {
                Op::Client(input) => backend
                    .write_client(ClientWrite {
                        name: name.clone(),
                        input,
                        dry_run,
                        expect,
                        by: actor.name.clone(),
                        simulate: simulate.clone(),
                    })
                    .await
                    .map(|c| serde_json::to_value(c).unwrap_or_default()),
                Op::Managed(kind, body) => backend
                    .write_managed(ManagedWrite {
                        kind,
                        name: name.clone(),
                        body,
                        dry_run,
                        expect,
                        by: actor.name.clone(),
                        simulate,
                        // REQ: OBS-010, API-002 (ADR-179) — an agent token is never an
                        // administrator here, whoever owns it and whatever else it may do.
                        by_admin: admin,
                    })
                    .await
                    .map(|c| serde_json::to_value(c).unwrap_or_default()),
            };
            let result = result.map_err(|e| {
                let mut e = crate::simulate_api::sanitize_problem(&p, e);
                // REQ: API-002, T8.2 (ADR-181) — security F3: the diff of a `409 cluster_pinned`
                // shows a router's key files and username to an administrator only.
                if !admin
                    && let Some(d) = e
                        .diff
                        .as_deref_mut()
                        .and_then(serde_json::Value::as_array_mut)
                {
                    crate::mask_router_diff(d);
                }
                e
            });
            let (status, text) = match &result {
                Ok(c) => (StatusCode::OK, c.to_string()),
                Err(e) => (e.code_status(), json_of(e)),
            };
            if let Ok(c) = &result
                && c["applied"].as_bool() == Some(true)
            {
                auth.record(
                    &actor,
                    &action,
                    &name,
                    &serde_json::json!({ "before": c["before"], "after": c["after"], "configVersion": c["configVersion"] }),
                );
            }
            if let Some(k) = &key
                && status.is_success()
            {
                let r = Replay {
                    request: request.into_bytes(),
                    status: status.as_u16(),
                    response: text,
                };
                if let Err(e) = auth.state().remember_idempotent(k, &r, now) {
                    tracing::warn!("idempotency key not stored: {e}");
                }
            }
            result
        }
    };
    // REQ: API-002, API-006, AGT-003, T8.2 (ADR-181) — correctness F4: a configuration change
    // runs to its end in a task of its own, with its audit entry and its Idempotency-Key record,
    // whether or not the client waits for the answer (a client that went away before used to
    // leave a change made but not audited, and its retry made it again). For every change
    // through this write path: each is one bounded unit under `config_writes`, and only where it
    // stops changes, not what it does. A dry run changes nothing and stays tied to its request.
    let result = if dry_run {
        work.await
    } else {
        tokio::spawn(work).await.unwrap_or_else(|e| {
            // Correctness R6: the runtime's text (the task, a panic's message) stays in the log.
            tracing::error!(error = %e, "a configuration change's task failed");
            Err(Problem::internal(
                "the change didn't finish; the server log says why",
            ))
        })
    };
    match result {
        Ok(c) => {
            let mut r = Json(c).into_response();
            // REQ: CLU-004 (ADR-174) — a replica reads the version from the primary: off the
            // runtime's worker. The change is made either way, so a failed read is no ETag.
            let version = blocking(move || Ok(backend.config_version())).await;
            if let Ok(version) = version
                && let Ok(v) = HeaderValue::from_str(&format!("\"{version}\""))
            {
                r.headers_mut().insert(axum::http::header::ETAG, v);
            }
            r
        }
        Err(e) => e.into_response(),
    }
}

fn replay(r: &Replay) -> Response {
    let status = StatusCode::from_u16(r.status).unwrap_or(StatusCode::OK);
    let mut resp = (status, r.response.clone()).into_response();
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert("idempotency-replayed", HeaderValue::from_static("true"));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agt_001_if_match_forms() {
        let h = |v: &str| {
            let mut m = HeaderMap::new();
            m.insert(IF_MATCH, HeaderValue::from_str(v).unwrap());
            m
        };
        assert_eq!(expected_version(&HeaderMap::new()).unwrap(), None);
        assert_eq!(expected_version(&h("\"7\"")).unwrap(), Some(7));
        assert_eq!(expected_version(&h("W/\"7\"")).unwrap(), Some(7));
        assert_eq!(expected_version(&h("7")).unwrap(), Some(7));
        assert_eq!(expected_version(&h("*")).unwrap(), None);
        assert!(expected_version(&h("latest")).is_err());
    }
}
