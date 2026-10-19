//! REQ: OBS-033 (ADR-133) — change markers: `GET /api/v1/annotations` (every node's, newest
//! first) and notes, `POST /api/v1/annotations`. A note needs the operator role (agents:
//! `ops:annotate`), is audit-logged as `annotation.note`, and is written by the node that
//! received it: not configuration, so a GitOps-managed cluster takes it, and nothing is
//! replicated (the federated read shows it on every node). Markers are append-only: `PUT` and
//! `DELETE` answer 405; a wrong note gets a correcting note.

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::from_fn;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::auth::Auth;
use crate::auth::routes::{body, principal, reason, remote};
use crate::model::{Annotation, AnnotationFilter, AnnotationPage, AnnotationParams, NoteRequest};
use crate::problem::{Code, Problem};
use crate::{Shared, blocking, pick};

/// Every kind of marker.
pub const KINDS: &[&str] = &[
    "config.applied",
    "build.started",
    "node.restarted",
    "lists.refreshed",
    "rollout.stage",
    "maintenance.entered",
    "maintenance.left",
    "blocking.paused",
    "blocking.resumed",
    "cache.flushed",
    "upstream.breaker",
    "note",
    // REQ: CLU-014 — a failover drill started, and ended (with its report's summary).
    "drill.started",
    "drill.ended",
];

/// The longest note, in characters.
pub const MAX_TEXT: usize = 200;
/// How far back a note may be placed.
pub const MAX_BACK_MS: u64 = 7 * 86_400_000;
/// A note's time may be this far ahead of this node's clock (another machine's "now"); it's
/// written as now.
const SKEW_MS: u64 = 5_000;
/// The most markers one read returns.
pub const MAX_LIMIT: usize = 2_000;

/// The read (viewer) and the note (operator); `PUT`/`DELETE` are refused.
pub(crate) fn routes(backend: Shared, auth: Arc<Auth>) -> Router {
    use crate::auth::routes::{require_operator, require_viewer};
    Router::new()
        .route(
            "/api/v1/annotations",
            get(list_annotations)
                .put(append_only)
                .delete(append_only)
                .route_layer(from_fn(require_viewer))
                .merge(post(add_note).route_layer(from_fn(require_operator))),
        )
        .with_state((backend, auth))
}

/// Where a configuration change came from, by who made it: `agent`, `api` (a token), or
/// `ui` (a signed-in user).
pub fn source_of(actor: &str) -> &'static str {
    if actor.starts_with("agent:") {
        "agent"
    } else if actor.starts_with("token:") {
        "api"
    } else {
        "ui"
    }
}

/// Merges per-node pages: newest first (ties by node), at most `limit`.
pub fn merge(pages: Vec<Vec<Annotation>>, limit: usize) -> Vec<Annotation> {
    let mut all: Vec<Annotation> = pages.into_iter().flatten().collect();
    all.sort_by(|a, b| {
        b.t_unix_ms
            .cmp(&a.t_unix_ms)
            .then_with(|| a.node.cmp(&b.node))
            .then_with(|| a.kind.cmp(&b.kind))
    });
    all.truncate(limit);
    all
}

/// A marker of `kind` at `at_ms` saying `summary`.
pub fn marker(kind: &str, at_ms: u64, summary: impl Into<String>) -> Annotation {
    Annotation {
        t: crate::time::format_us(at_ms.saturating_mul(1000)),
        t_unix_ms: at_ms,
        kind: kind.to_owned(),
        summary: summary.into(),
        ..Annotation::default()
    }
}

/// Appends a marker on this node, best effort (an operation already done isn't undone
/// because its marker couldn't be written).
pub(crate) async fn mark(backend: &Shared, a: Annotation) {
    let b = Arc::clone(backend);
    let _ = tokio::task::spawn_blocking(move || b.annotate(a)).await;
}

/// `kinds=a,b`: known kinds only.
fn parse_kinds(text: Option<&str>) -> Result<Vec<String>, Problem> {
    let Some(t) = text.filter(|t| !t.trim().is_empty()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for k in t.split(',').map(str::trim).filter(|k| !k.is_empty()) {
        if !KINDS.contains(&k) {
            return Err(Problem::invalid(format!("`kinds`: unknown kind `{k}`"))
                .hint(format!("Kinds: {}.", KINDS.join(", "))));
        }
        out.push(k.to_owned());
    }
    Ok(out)
}

fn time_ms(text: Option<&str>, default_ms: u64, now_ms: u64, name: &str) -> Result<u64, Problem> {
    match text {
        None => Ok(default_ms),
        Some(t) => crate::time::parse_time_ms(t, now_ms).map_err(|e| {
            Problem::invalid(format!("`{name}`: {e}")).hint(
                "Use a relative offset such as -24h, or RFC 3339 such as 2026-10-03T00:00:00Z.",
            )
        }),
    }
}

/// The filter a request asks for, and the page size.
fn filter(p: &AnnotationParams, now_ms: u64) -> Result<(AnnotationFilter, usize), Problem> {
    let limit = p.limit.unwrap_or(500);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(Problem::invalid(format!(
            "`limit`: 1 to {MAX_LIMIT} markers"
        )));
    }
    let from_ms = time_ms(
        p.from.as_deref(),
        now_ms.saturating_sub(86_400_000),
        now_ms,
        "from",
    )?;
    let mut to_ms = time_ms(p.to.as_deref(), now_ms + 1, now_ms, "to")?;
    if let Some(b) = p.before.as_deref() {
        to_ms = to_ms.min(time_ms(Some(b), now_ms, now_ms, "before")?);
    }
    Ok((
        AnnotationFilter {
            from_ms,
            to_ms,
            kinds: parse_kinds(p.kinds.as_deref())?,
            // One more than asked: whether there are more.
            limit: limit + 1,
        },
        limit,
    ))
}

/// Change markers.
///
/// What was done to each node, or what it did to itself, newest first: configuration
/// versions applied (`seq`, `source`: `ui`, `api`, `agent`, `gitops`, `file`, or `cluster` on
/// a replica; `actor` when known), new builds, restarts, list refreshes that changed the rules,
/// rollout stages, maintenance, blocking paused or resumed, cache flushes, upstream circuit
/// breakers (at most one line per upstream per 5 minutes), and operators' and agents' notes.
/// Each node keeps its own (20,000 lines, 90 days); in a cluster every node is asked and each
/// marker carries its `node` (one change applied on four nodes is four markers with the same
/// `seq`). With `truncated`, ask again with `before = nextBefore` for older ones. Use it to
/// answer "what changed around then?". Example: `GET /api/v1/annotations?from=-6h&kinds=config.applied,note`.
#[utoipa::path(get, path = "/api/v1/annotations", tag = "stats", params(AnnotationParams),
    responses(
        (status = 200, body = AnnotationPage, description = "Markers, newest first."),
        (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it.")))]
async fn list_annotations(
    State((b, _)): State<(Shared, Arc<Auth>)>,
    Query(p): Query<AnnotationParams>,
) -> Result<Json<AnnotationPage>, Problem> {
    let b = pick(&b, p.scope.as_deref())?;
    let now_ms = b.now_unix_seconds() * 1000;
    let (f, limit) = filter(&p, now_ms)?;
    let bk = Arc::clone(&b);
    let mut items = blocking(move || Ok(bk.annotations(&f))).await?;
    let truncated = items.len() > limit;
    items.truncate(limit);
    Ok(Json(AnnotationPage {
        next_before: truncated
            .then(|| items.last().map(|a| a.t.clone()))
            .flatten(),
        items,
        truncated,
        missing_nodes: b.missing_nodes(),
    }))
}

/// The text, trimmed, or why it can't be a note.
pub fn check_text(text: &str) -> Result<String, Problem> {
    let t = text.trim();
    let n = t.chars().count();
    if n == 0 || n > MAX_TEXT || t.chars().any(char::is_control) {
        return Err(Problem::new(
            Code::AnnotationText,
            format!("`text`: 1 to {MAX_TEXT} characters on one line (got {n})"),
        )
        .hint("Say what happened in a sentence; a longer story belongs in the audit reason or your notes."));
    }
    Ok(t.to_owned())
}

/// When the note goes, in Unix milliseconds: now by default, up to 7 days back, never ahead.
pub fn check_time(time: Option<&str>, now_ms: u64) -> Result<u64, Problem> {
    let Some(text) = time.filter(|t| !t.trim().is_empty()) else {
        return Ok(now_ms);
    };
    let bad = |why: String| {
        Problem::new(Code::AnnotationTime, format!("`time`: {why}"))
            .hint("Leave `time` out for now, or give RFC 3339 within the last 7 days.")
    };
    let t = crate::time::parse_time_ms(text, now_ms).map_err(bad)?;
    if t > now_ms + SKEW_MS {
        return Err(bad(format!("`{text}` is in the future")));
    }
    if t + MAX_BACK_MS < now_ms {
        return Err(bad(format!("`{text}` is more than 7 days back")));
    }
    Ok(t.min(now_ms))
}

/// Leave a note on the time charts.
///
/// Marks a moment on every time chart of every node with a short text, for what the network
/// itself can't see: "moved the access point", "ISP outage", "migrated the NAS". `time`
/// defaults to now and may be up to 7 days back. The receiving node keeps it (the federated
/// read shows it everywhere); it's not configuration, so it's allowed in a GitOps-managed
/// cluster. Notes can't be changed or deleted: add a correcting note. Needs the operator role
/// (agents: the `ops:annotate` scope); audit-logged as `annotation.note`.
#[utoipa::path(post, path = "/api/v1/annotations", tag = "stats",
    request_body = NoteRequest,
    responses(
        (status = 201, body = Annotation, description = "The note as written."),
        (status = 403, body = Problem, description = "Needs the operator role (agents: ops:annotate)."),
        (status = 422, body = Problem, description = "`annotation_text`: empty, over 200 characters, or several lines; `annotation_time`: ahead of now, or more than 7 days back."),
    ))]
async fn add_note(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<NoteRequest>, JsonRejection>,
) -> Response {
    let req = match body(b) {
        Ok(r) => r,
        Err(p) => return p.into_response(),
    };
    let now_ms = backend.now_unix_seconds() * 1000;
    let (text, at) = match check_text(&req.text)
        .and_then(|t| Ok((t, check_time(req.time.as_deref(), now_ms)?)))
    {
        Ok(v) => v,
        Err(p) => return p.into_response(),
    };
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let a = Annotation {
        t: crate::time::format_us(at.saturating_mul(1000)),
        t_unix_ms: at,
        kind: "note".into(),
        summary: text.clone(),
        actor: Some(actor.name.clone()),
        text: Some(text.clone()),
        ..Annotation::default()
    };
    let b2 = Arc::clone(&backend);
    match blocking(move || b2.annotate(a)).await {
        Ok(written) => {
            auth.record(
                &actor,
                "annotation.note",
                &written.t,
                &serde_json::json!({ "text": text, "time": written.t }),
            );
            (StatusCode::CREATED, Json(written)).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Markers are append-only.
async fn append_only() -> Problem {
    Problem::new(
        Code::MethodNotAllowed,
        "change markers can't be changed or deleted",
    )
    .hint("Add a correcting note with POST /api/v1/annotations.")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(ms: u64, node: &str) -> Annotation {
        Annotation {
            t_unix_ms: ms,
            node: Some(node.into()),
            kind: "note".into(),
            ..Annotation::default()
        }
    }

    // REQ: OBS-033 — notes: one line of 1 to 200 characters, up to 7 days back, never ahead.
    #[test]
    fn obs_033_notes_are_checked() {
        assert_eq!(check_text("  moved the AP ").unwrap(), "moved the AP");
        assert_eq!(check_text(&"x".repeat(200)).unwrap().len(), 200);
        for bad in ["", "   ", "two\nlines"] {
            assert_eq!(
                check_text(bad).unwrap_err().code,
                Code::AnnotationText,
                "{bad:?}"
            );
        }
        assert_eq!(
            check_text(&"x".repeat(201)).unwrap_err().code,
            Code::AnnotationText
        );
        let now = 1_791_072_000_000; // 2026-10-04T00:00:00Z
        assert_eq!(check_time(None, now).unwrap(), now);
        assert_eq!(
            check_time(Some("2026-10-03T23:00:00Z"), now).unwrap(),
            now - 3_600_000
        );
        assert_eq!(check_time(Some("-6d"), now).unwrap(), now - 6 * 86_400_000);
        for bad in ["2026-10-04T01:00:00Z", "-8d", "yesterday"] {
            assert_eq!(
                check_time(Some(bad), now).unwrap_err().code,
                Code::AnnotationTime,
                "{bad}"
            );
        }
        assert_eq!(
            check_time(Some("2026-10-04T00:00:03Z"), now).unwrap(),
            now,
            "a few seconds of clock skew is now"
        );
    }

    // REQ: OBS-033 — kinds are known ones; the page asks one more than it returns.
    #[test]
    fn obs_033_read_parameters() {
        let now = 1_791_072_000_000;
        let p = AnnotationParams {
            kinds: Some("config.applied, note".into()),
            limit: Some(10),
            before: Some("2026-10-03T12:00:00.250Z".into()),
            ..AnnotationParams::default()
        };
        let (f, limit) = filter(&p, now).unwrap();
        assert_eq!(limit, 10);
        assert_eq!(f.limit, 11);
        assert_eq!(f.kinds, ["config.applied", "note"]);
        assert_eq!(f.from_ms, now - 86_400_000);
        assert_eq!(f.to_ms, now - 12 * 3_600_000 + 250);
        let bad = AnnotationParams {
            kinds: Some("config.applied,reboot".into()),
            ..AnnotationParams::default()
        };
        assert!(filter(&bad, now).is_err());
        let big = AnnotationParams {
            limit: Some(2001),
            ..AnnotationParams::default()
        };
        assert!(filter(&big, now).is_err());
    }

    // REQ: OBS-033 — two nodes merge newest first, cut at the limit.
    #[test]
    fn obs_033_pages_merge_newest_first() {
        let merged = merge(
            vec![
                vec![marker(30, "pi"), marker(10, "pi")],
                vec![marker(40, "k8s"), marker(20, "k8s"), marker(10, "k8s")],
            ],
            4,
        );
        let got: Vec<(u64, &str)> = merged
            .iter()
            .map(|a| (a.t_unix_ms, a.node.as_deref().unwrap_or("")))
            .collect();
        assert_eq!(got, [(40, "k8s"), (30, "pi"), (20, "k8s"), (10, "k8s")]);
    }

    #[test]
    fn obs_033_sources_from_the_actor() {
        assert_eq!(source_of("agent:ops-bot (owner: admin)"), "agent");
        assert_eq!(source_of("token:ci (owner: admin)"), "api");
        assert_eq!(source_of("admin"), "ui");
    }
}
