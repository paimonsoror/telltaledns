//! REQ: OPS-011 (ADR-156) — the support package over HTTP: one archive a person makes, reviews, and
//! attaches to an issue. Admin only (no agent scope and no MCP tool: it reads logs and state);
//! audit-logged as `support.package` with the level and counts, never the content. The
//! pseudonym map, if asked for, is a second download that works once, for the package just made,
//! for ten minutes.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::Shared;
use crate::auth::Auth;
use crate::auth::routes::{principal, reason, remote};
use crate::model::SupportPackageRequest;
use crate::problem::Problem;

/// The longest `--reveal` list, and the longest name in it.
pub const MAX_REVEAL: usize = 50;
pub const MAX_REVEAL_LEN: usize = 100;
/// The most query-log rows a package may carry.
pub const MAX_QUERY_SAMPLE: u32 = 1_000;

/// The routes (admin).
pub(crate) fn admin_routes(backend: Shared, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/system/support-package", post(make))
        .route("/api/v1/system/support-package/{id}/map", get(map))
        .with_state((backend, auth))
}

/// Query parameters of the request.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct SupportQuery {
    /// Collect everything and answer with the manifest only: what the package would hold, how big
    /// each file is, and what was removed or replaced (counts, never values). Nothing is written.
    pub dry_run: Option<bool>,
}

/// Checks a request (the API and the command line both).
pub fn validate(req: &SupportPackageRequest) -> Result<(), Problem> {
    if let Some(l) = &req.level
        && !matches!(
            l.trim().to_ascii_lowercase().as_str(),
            "strict" | "standard" | "none"
        )
    {
        return Err(Problem::invalid(format!("`level`: `{l}` isn't strict, standard, or none"))
            .hint("`strict` is the default: addresses and names become pseudonyms, and only warnings and errors are in the log."));
    }
    if req.reveal.len() > MAX_REVEAL
        || req.reveal.iter().any(|n| {
            n.trim().is_empty()
                || n.chars().count() > MAX_REVEAL_LEN
                || n.chars().any(char::is_control)
        })
    {
        return Err(Problem::invalid(format!(
            "`reveal`: at most {MAX_REVEAL} names, each 1 to {MAX_REVEAL_LEN} characters on one line"
        )));
    }
    if req.query_sample > MAX_QUERY_SAMPLE {
        return Err(Problem::invalid(format!(
            "`querySample`: at most {MAX_QUERY_SAMPLE} rows"
        )));
    }
    let level = req
        .level
        .as_deref()
        .unwrap_or("strict")
        .trim()
        .to_ascii_lowercase();
    if req.query_sample > 0 && level == "strict" {
        return Err(Problem::invalid(
            "`querySample`: query names aren't included at the strict level",
        )
        .hint(
            "Use level `standard` (names are pseudonymized) or `none`, or leave the sample out.",
        ));
    }
    if req.cluster && req.keep_map {
        return Err(Problem::invalid("`keepMap`: not with `cluster`").hint(
            "A cluster package's names are replaced on the nodes they belong to and never leave them, so there is no map to keep. Make a package on one node for that.",
        ));
    }
    Ok(())
}

/// Make a support package.
///
/// One `.tar.gz` for an issue report: build and platform facts, the effective configuration
/// without secrets, the cluster view and timeline, health checks, upstream and listener state,
/// list names and counts (no domains), a metrics snapshot, aggregate statistics, and the node's
/// recent log lines, with a manifest that lists every file and counts what was removed or
/// replaced. Secrets (passwords and hashes, tokens, keys, credentials) are removed at every
/// level. Nothing is uploaded: the response is the archive.
///
/// **`level`** decides how much is obfuscated. `strict` (the default): addresses, MAC
/// addresses, host, device, group, node and pod names, e-mail addresses, URL hosts, and home
/// paths become pseudonyms that are stable inside the package and can't be reversed from it,
/// no query names, no free text, warnings and errors only in the log. `standard`: also INFO
/// log lines, top lists with pseudonymized names, and (with `querySample`) a query-log sample.
/// `none`: values as they are (secrets still removed). `reveal` keeps the named values readable.
///
/// With `keepMap`, the answer carries `X-Support-Package-Id`, and `GET
/// /system/support-package/{id}/map` returns the pseudonyms and the real values behind them once,
/// within ten minutes: it is not for attaching. `?dryRun=true` answers with the manifest only.
///
/// With **`cluster`**, the package covers every reachable node: each makes and redacts its own part
/// under one key made for this package (sent over the cluster channel, never stored), so a device
/// has the same pseudonym in every node's files and no real value crosses the network. The
/// manifest lists each node and whether it answered; the size cap is shared. Not with `keepMap`.
/// Free text is redacted by pattern, which is best effort: look the package over before you
/// attach it. Admin only; audit-logged as `support.package`. Not an MCP tool.
#[utoipa::path(post, path = "/api/v1/system/support-package", tag = "system",
    params(SupportQuery),
    request_body(content = SupportPackageRequest, description = "Optional: the defaults make a strict package."),
    responses(
        (status = 200, content_type = "application/gzip", body = Vec<u8>,
            description = "The package, as an attachment named `telltale-support-<node>-<time>.tar.gz`. With dryRun: the manifest as JSON."),
        (status = 409, body = Problem, description = "Another package is being made on this node (`conflict`)."),
        (status = 422, body = Problem, description = "A field is wrong: problem+json says which."),
    ))]
pub(crate) async fn make(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    Query(q): Query<SupportQuery>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    raw: Bytes,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let req: SupportPackageRequest = if raw.iter().all(u8::is_ascii_whitespace) {
        SupportPackageRequest::default()
    } else {
        match serde_json::from_slice(&raw) {
            Ok(r) => r,
            Err(e) => {
                return Problem::invalid(format!("the body isn't a support package request: {e}"))
                    .into_response();
            }
        }
    };
    if let Err(e) = validate(&req) {
        return e.into_response();
    }
    let dry_run = q.dry_run.unwrap_or(false);
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let (b2, r2) = (Arc::clone(&backend), req.clone());
    let made = tokio::task::spawn_blocking(move || b2.support_package(&r2, dry_run))
        .await
        .unwrap_or_else(|e| Err(Problem::internal(format!("request worker failed: {e}"))));
    let out = match made {
        Ok(o) => o,
        Err(e) => return e.into_response(),
    };
    if dry_run {
        return Json(out.manifest).into_response();
    }
    auth.record(
        &actor,
        "support.package",
        &out.file_name,
        &serde_json::json!({
            "level": req.level.as_deref().unwrap_or("strict"),
            "reveal": req.reveal.len(),
            "querySample": req.query_sample,
            "keepMap": req.keep_map,
            "bytes": out.archive.len(),
        }),
    );
    let mut resp = out.archive.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/gzip"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    // The name is ours (letters, digits, `-`, `.`), so it's safe in the header.
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{}\"", out.file_name)) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Some(id) = out.id
        && let Ok(v) = HeaderValue::from_str(&id)
    {
        h.insert("x-support-package-id", v);
    }
    resp
}

/// The pseudonym map of the package just made.
///
/// The pseudonyms and the real values behind them, one `pseudonym<TAB>original` line each, so you
/// can tell a maintainer what `device-3` was. It holds the real names and addresses: it isn't for
/// attaching to an issue. The node keeps it in memory only (never on disk), for the package that
/// asked for it (`keepMap`), and gives it out once, within ten minutes; a newer package replaces
/// it. Admin only; audit-logged as `support.package.map`.
#[utoipa::path(get, path = "/api/v1/system/support-package/{id}/map", tag = "system",
    params(("id" = String, Path, description = "`X-Support-Package-Id` of the package.")),
    responses(
        (status = 200, content_type = "text/plain", body = String, description = "The map, as an attachment."),
        (status = 404, body = Problem, description = "There is no map for that package: it was given out, expired, or was never asked for."),
    ))]
pub(crate) async fn map(
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
    let Some(text) = backend.support_map(id.trim()) else {
        return Problem::not_found("there is no pseudonym map for that package")
            .hint("A map is kept for the package that asked for it (`keepMap`), is given out once, and is gone after ten minutes or when a newer package is made.")
            .into_response();
    };
    auth.record(
        &actor,
        "support.package.map",
        id.trim(),
        &serde_json::json!({ "bytes": text.len() }),
    );
    let mut resp = text.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"telltale-support-map.txt\""),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(level: Option<&str>, sample: u32, reveal: &[&str]) -> SupportPackageRequest {
        SupportPackageRequest {
            level: level.map(str::to_owned),
            reveal: reveal.iter().map(|s| (*s).to_owned()).collect(),
            query_sample: sample,
            keep_map: false,
            cluster: false,
        }
    }

    // REQ: OPS-011 (ADR-172) — a cluster package has no pseudonym map to keep: the names are
    // replaced on the nodes they belong to.
    #[test]
    fn ops_011_a_cluster_package_has_no_map_to_keep() {
        let mut r = req(None, 0, &[]);
        r.cluster = true;
        assert!(validate(&r).is_ok());
        r.keep_map = true;
        let e = validate(&r).unwrap_err();
        assert!(e.detail.contains("keepMap"), "{}", e.detail);
        assert!(
            e.hint.unwrap_or_default().contains("never leave"),
            "it says why"
        );
    }

    // REQ: OPS-011 — a request is checked before anything is collected, with a hint.
    #[test]
    fn ops_011_a_request_is_checked() {
        assert!(validate(&req(None, 0, &[])).is_ok());
        assert!(validate(&req(Some("Standard"), 500, &["pi"])).is_ok());
        assert!(
            validate(&req(Some("loose"), 0, &[]))
                .unwrap_err()
                .detail
                .contains("strict, standard, or none")
        );
        assert!(validate(&req(Some("none"), 1001, &[])).is_err());
        let many: Vec<&str> = vec!["a"; MAX_REVEAL + 1];
        assert!(validate(&req(None, 0, &many)).is_err());
        assert!(validate(&req(None, 0, &[""])).is_err());
        assert!(validate(&req(None, 0, &["two\nlines"])).is_err());
    }

    // REQ: OPS-011 — the query-log sample is refused at strict (and by default).
    #[test]
    fn ops_011_no_query_names_at_strict() {
        let e = validate(&req(None, 10, &[])).unwrap_err();
        assert!(e.detail.contains("strict"), "{}", e.detail);
        assert!(e.hint.as_deref().is_some_and(|h| h.contains("standard")));
        assert!(validate(&req(Some("strict"), 10, &[])).is_err());
        assert!(validate(&req(Some("standard"), 10, &[])).is_ok());
    }
}
