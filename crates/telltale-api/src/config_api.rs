//! Configuration changes through the API (REQ: API-002, API-010; AGT-002 dry-run, AGT-003
//! idempotency; ADR-040). Today: devices (`/clients/{name}`). Every write takes
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
use crate::model::{ClientChange, ClientInput};
use crate::problem::{Code, Problem};
use crate::{Backend, ClientWrite};

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
        .with_state((backend, auth))
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
    Query(dry): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<ClientInput>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!(
        "PUT /clients/{name} {}",
        serde_json::to_string(&input).unwrap_or_default()
    );
    write(
        backend,
        auth,
        headers,
        ext,
        dry.dry_run.unwrap_or(false),
        request,
        name,
        Some(input),
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
        (status = 200, body = ClientChange),
        (status = 404, body = Problem, description = "No device by that name was created through the API."),
        (status = 409, body = Problem, description = "Defined in the config files."),
        (status = 412, body = Problem),
    ))]
pub(crate) async fn delete_client(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(dry): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /clients/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry.dry_run.unwrap_or(false),
        request,
        name,
        None,
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
    input: Option<ClientInput>,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
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
    let deleting = input.is_none();
    let w = ClientWrite {
        name: name.clone(),
        input,
        dry_run,
        expect,
        by: actor.name.clone(),
    };
    let result = backend.write_client(w).await;
    let (status, body) = match &result {
        Ok(c) => (StatusCode::OK, serde_json::to_string(c).unwrap_or_default()),
        Err(e) => (
            e.code_status(),
            serde_json::to_string(e).unwrap_or_default(),
        ),
    };
    if let Ok(c) = &result
        && c.applied
    {
        auth.record(
            &actor,
            if deleting { "client.delete" } else { "client.put" },
            &name,
            &serde_json::json!({ "before": c.before, "after": c.after, "configVersion": c.config_version }),
        );
    }
    if let Some(k) = &key
        && status.is_success()
    {
        let r = Replay {
            request: request.into_bytes(),
            status: status.as_u16(),
            response: body.clone(),
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
