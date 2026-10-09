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
use crate::{Backend, ClientWrite, ManagedKind, ManagedWrite};

type Ctx = (Arc<dyn Backend>, Arc<Auth>);

/// `?dryRun=true` validates and reports without changing anything (AGT-002).
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct DryRun {
    /// Validate and report the change without applying it.
    pub dry_run: Option<bool>,
}

/// Header names.
pub const IF_MATCH: &str = "if-match";
pub const IDEMPOTENCY_KEY: &str = "idempotency-key";

/// `If-Match: "7"`, `7`, or `W/"7"` → 7. `*` or absent → no check.
fn expected_version(headers: &HeaderMap) -> Result<Option<u64>, Problem> {
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
        .with_state((backend, auth))
}

/// Add or change an upstream resolver (ADR-069).
///
/// The body has the same fields as `[[upstream]]` in `telltale.toml` (the name comes from the path),
/// e.g. `{"url": "tls://9.9.9.9", "tls_server_name": "dns.quad9.net"}`. A name the config files use is overridden: this definition replaces theirs
/// until it's deleted again (`GET /api/v1/config/overrides` lists such changes). The whole
/// configuration is checked before anything is stored. On a node whose configuration comes from
/// Git, the response's `toml` says what to add to the repository to keep the change.
#[utoipa::path(put, path = "/api/v1/upstreams/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, or the configuration wouldn't be valid: problem+json says which."),
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
/// Git, the response's `toml` says what to add to the repository to keep the change.
#[utoipa::path(put, path = "/api/v1/lists/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, or the configuration wouldn't be valid: problem+json says which."),
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
    params(DryRun),
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
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<crate::model::PromoteRequest>, JsonRejection>,
) -> Response {
    let req = match body(b) {
        Ok(r) => r,
        Err(p) => return p.into_response(),
    };
    if dry(&q) {
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
fn group_guard(
    p: &crate::auth::Principal,
    backend: &dyn Backend,
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
    let existing = backend.clients().into_iter().find(|c| c.name == name);
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
/// A destination the config files define is overridden until this one is deleted.
#[utoipa::path(put, path = "/api/v1/alerts/destinations/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, or the configuration wouldn't be valid: problem+json says which."),
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
/// the test is audited. Needs the operator role.
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
    let r = backend.alert_test(&name).await?;
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
/// (agents: `config:write:upstreams`).
#[utoipa::path(post, path = "/api/v1/checks/upstream", tag = "config",
    request_body = Object,
    responses(
        (status = 200, body = crate::model::CheckResult, description = "Answered, or why not."),
        (status = 422, body = Problem, description = "The body isn't an upstream (an unknown or mistyped field)."),
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
    let mut r = backend.check_upstream(input).await?;
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
            Self::Managed(ManagedKind::RateLimit, _) => "ratelimit",
            Self::Managed(ManagedKind::Exclusions, _) => "exclusions",
        }
    }
    fn deleting(&self) -> bool {
        matches!(self, Self::Client(None) | Self::Managed(_, None))
    }
}

fn dry(q: &DryRun) -> bool {
    q.dry_run.unwrap_or(false)
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
        (status = 409, body = Problem, description = "Defined in the config files, or an Idempotency-Key reused for another request."),
        (status = 412, body = Problem, description = "If-Match: the config changed since that version."),
        (status = 422, body = Problem, description = "The resulting configuration is invalid (e.g. an unknown group)."),
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
        (status = 409, body = Problem, description = "Defined in the config files."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
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
        (status = 409, body = Problem, description = "Defined in the config files, or an Idempotency-Key reused."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A value doesn't fit its type (e.g. A with a name), or the result is invalid."),
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
        (status = 409, body = Problem, description = "Conflicts with the current state: problem+json says what to change."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
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
/// answer first. Domains routed in the config files are read-only here (409).
#[utoipa::path(put, path = "/api/v1/forwards/{domain}", tag = "config",
    params(("domain" = String, Path, description = "The domain, e.g. corp.example (its whole subtree is sent)."), DryRun),
    request_body = ForwardInput,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 409, body = Problem, description = "Conflicts with the current state: problem+json says what to change."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A server isn't an address or a supported URL."),
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
        (status = 409, body = Problem, description = "Conflicts with the current state: problem+json says what to change."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
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
/// Rules from the config files are read-only here (409). Needs the operator role (or the
/// `config:write:rules` agent scope, with a reason).
#[utoipa::path(put, path = "/api/v1/rules/{id}", tag = "config",
    params(("id" = String, Path, description = "The rule's ID: any short unique name (the UI makes one)."), DryRun),
    request_body = crate::model::RuleInput,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 409, body = Problem, description = "Defined in the config files, or an Idempotency-Key reused."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "An unknown device or group, a bad domain, or an expiry in the past."),
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
        (status = 409, body = Problem, description = "Defined in the config files."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
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

#[allow(clippy::too_many_arguments)]
async fn write(
    backend: Arc<dyn Backend>,
    auth: Arc<Auth>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    dry_run: bool,
    request: String,
    name: String,
    op: Op,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = group_guard(&p, backend.as_ref(), &name, &op) {
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
    if let Some(k) = &key {
        match auth.state().idempotent(k, now) {
            Ok(Some(r)) if r.request == request.as_bytes() => return replay(&r),
            Ok(Some(_)) => {
                return Problem::new(
                    Code::Conflict,
                    "this Idempotency-Key was used for a different request",
                )
                .hint("Use a new key for each distinct change.")
                .into_response();
            }
            Ok(None) => {}
            Err(e) => return Problem::internal(e.to_string()).into_response(),
        }
    }
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let action = format!(
        "{}.{}",
        op.audit_kind(),
        if op.deleting() { "delete" } else { "put" }
    );
    let result: Result<serde_json::Value, Problem> = match op {
        Op::Client(input) => backend
            .write_client(ClientWrite {
                name: name.clone(),
                input,
                dry_run,
                expect,
                by: actor.name.clone(),
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
            })
            .await
            .map(|c| serde_json::to_value(c).unwrap_or_default()),
    };
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
            response: text.clone(),
        };
        if let Err(e) = auth.state().remember_idempotent(k, &r, now) {
            tracing::warn!("idempotency key not stored: {e}");
        }
    }
    match result {
        Ok(c) => {
            let mut r = Json(c).into_response();
            if let Ok(v) = HeaderValue::from_str(&format!("\"{}\"", backend.config_version())) {
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
