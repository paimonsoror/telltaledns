//! REST API, auth, OpenAPI, live tail, and embedded UI.
//!
//! Part of TelltaleDNS. See `spec/02-architecture.md` §2 and `spec/07`.
//!
//! This crate owns the HTTP surface: routes under `/api/v1`, request/response types,
//! problem+json errors, pagination, and the OpenAPI 3.1 document (REQ: API-001). It reaches
//! the server only through [`Backend`], which the `telltale` binary implements, so the API
//! never depends on pipeline internals.

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]

pub mod auth;
pub mod model;
pub mod problem;
pub mod time;
pub mod ui;

use std::net::IpAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use utoipa::OpenApi;

use crate::model::{
    ClientInfo, ExplainBlock, ExplainClient, ExplainFilter, ExplainLine, ExplainParams,
    ExplainRoute, ExplainRule, Explanation, GroupInfo, Hour, Items, LatencyBy, LatencyParams,
    LatencyRow, ListInfo, NameMatch, QueryPage, QueryParams, QueryRow, ScanStats, Step, Summary,
    SummaryParams, SystemInfo, TailDropped, TailItem, TailParams, TimeBucket, TimeseriesParams,
    TopItem, TopKind, TopParams, UpstreamInfo,
};
use crate::problem::Problem;

/// What the API needs from the server. Implemented by the `telltale` binary; calls may block
/// (query-log search reads files) and run on a blocking thread.
pub trait Backend: Send + Sync + 'static {
    /// Seconds since the Unix epoch (overridable for tests).
    fn now_unix_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
    fn system_info(&self) -> SystemInfo;
    /// Buckets with start in `[from_s, to_s)`, oldest first.
    fn timeseries(&self, step: Step, from_s: u64, to_s: u64) -> Vec<TimeBucket>;
    /// Live queries matching `p` as they happen (REQ: OBS-008). The stream ends when the
    /// receiver is dropped. `Err` when the tail is unavailable (privacy level 3, too many
    /// subscribers) or a filter is invalid.
    fn tail(&self, p: &TailParams) -> Result<tokio::sync::mpsc::Receiver<TailItem>, Problem> {
        let _ = p;
        Err(Problem::unavailable(
            "the live tail isn't available on this node",
        ))
    }
    /// Heaviest items, heaviest first; `client` narrows `domains` to one client.
    fn top(&self, kind: TopKind, hour: Hour, limit: usize, client: Option<IpAddr>) -> Vec<TopItem>;
    fn latency(&self, by: LatencyBy, hour: Hour) -> Vec<LatencyRow>;
    /// One page of the query log; `from_us`/`to_us` are already parsed.
    fn queries(
        &self,
        q: &QueryParams,
        from_us: u64,
        to_us: u64,
        limit: usize,
    ) -> Result<QueryPage, Problem>;
    fn explain(&self, p: &ExplainParams) -> Result<Explanation, Problem>;
    fn lists(&self) -> Vec<ListInfo>;
    fn groups(&self) -> Vec<GroupInfo>;
    fn clients(&self) -> Vec<ClientInfo>;
    fn upstreams(&self) -> Vec<UpstreamInfo>;
}

type Shared = Arc<dyn Backend>;

/// The `/api/v1` routes (REQ: API-001, API-003). Everything except sign-in, first-run setup,
/// and the OpenAPI document needs authentication; reads need `viewer`, user management
/// `admin`.
pub fn router(backend: Shared, auth: Arc<auth::Auth>) -> Router {
    use axum::middleware::{from_fn, from_fn_with_state};
    let data = Router::new()
        .route("/api/v1/system/info", get(system_info))
        .route("/api/v1/stats/summary", get(stats_summary))
        .route("/api/v1/stats/timeseries", get(stats_timeseries))
        .route("/api/v1/stats/top", get(stats_top))
        .route("/api/v1/stats/latency", get(stats_latency))
        .route("/api/v1/queries", get(queries))
        .route("/api/v1/queries/stream", get(queries_stream))
        .route("/api/v1/explain", get(explain))
        .route("/api/v1/lists", get(lists))
        .route("/api/v1/groups", get(groups))
        .route("/api/v1/clients", get(clients))
        .route("/api/v1/upstreams", get(upstreams))
        .with_state(backend)
        .route_layer(from_fn(auth::routes::require_viewer));
    let protected = data
        .merge(auth::routes::self_service(Arc::clone(&auth)))
        .merge(
            auth::routes::admin(Arc::clone(&auth))
                .route_layer(from_fn(auth::routes::require_admin)),
        )
        .layer(from_fn_with_state(
            Arc::clone(&auth),
            auth::routes::authenticate,
        ));
    Router::new()
        .route("/api/v1/openapi.json", get(openapi_json))
        .merge(auth::routes::public(auth))
        .merge(protected)
        .fallback(fallback)
}

/// `/api/*` misses are problem+json; everything else is the web UI (REQ: API-005).
async fn fallback(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Response {
    if uri.path() == "/api" || uri.path().starts_with("/api/") {
        not_found(&uri).into_response()
    } else {
        ui::serve(&method, &uri, &headers)
    }
}
/// The OpenAPI 3.1 document for every route above.
#[derive(Debug, OpenApi)]
#[openapi(
    info(
        title = "TelltaleDNS API",
        description = "Read and control a TelltaleDNS resolver. JSON is camelCase; field names \
            carry units (`totalMs`, `ttlSeconds`). Errors are RFC 9457 problem+json with a stable \
            `code` and a `hint`. Time parameters take RFC 3339 or a relative offset (`-24h`). \
            Collections page with `cursor`/`limit`. Analytics calls take `scope` (`cluster` or \
            `node:local`; both mean this node until clustering is available).",
        license(name = "Apache-2.0 OR MIT")
    ),
    paths(
        system_info, stats_summary, stats_timeseries, stats_top, stats_latency, queries,
        queries_stream,
        explain, lists, groups, clients, upstreams,
        auth::routes::status, auth::routes::setup, auth::routes::login, auth::routes::logout,
        auth::routes::get_me, auth::routes::change_password, auth::routes::totp_setup,
        auth::routes::totp_enable, auth::routes::totp_disable, auth::routes::list_tokens,
        auth::routes::create_token, auth::routes::delete_token, auth::routes::list_users,
        auth::routes::create_user, auth::routes::update_user, auth::routes::delete_user,
        auth::routes::audit_log, auth::routes::audit_verify
    ),
    components(schemas(
        Problem, problem::Code, SystemInfo, Summary, TimeBucket, TopItem, LatencyRow, QueryPage, QueryRow,
        TailDropped,
        ScanStats, Explanation, ExplainClient, ExplainBlock, ExplainFilter, ExplainRule,
        ExplainLine, ExplainRoute, ListInfo, GroupInfo, ClientInfo, UpstreamInfo, Step, TopKind,
        Hour, LatencyBy, NameMatch, auth::Role, auth::Scope, auth::routes::Me,
        auth::routes::AuthStatus, auth::routes::SetupRequest, auth::routes::LoginRequest,
        auth::routes::LoginResponse, auth::routes::PasswordChange, auth::routes::TotpSetup,
        auth::routes::TotpCode, auth::routes::PasswordConfirm, auth::routes::RecoveryCodes,
        auth::routes::TokenInfo, auth::routes::CreateToken, auth::routes::NewToken,
        auth::routes::UserInfo, auth::routes::CreateUser, auth::routes::UpdateUser,
        auth::routes::AuditInfo, auth::routes::AuditPage, auth::routes::AuditVerify
    )),
    modifiers(&Security),
    security(("session" = []), ("bearer" = []), ("basic" = [])),
    tags(
        (name = "system", description = "Node information."),
        (name = "stats", description = "Counters, top lists, and latency percentiles. Live \
            windows in memory (15 minutes per second, 48 hours per minute) plus rollups on disk \
            (7 days per minute, 400 days per hour, days forever)."),
        (name = "queries", description = "The query log and explanations of decisions."),
        (name = "config", description = "Lists, groups, clients, and upstreams as running."),
        (name = "auth", description = "Sign-in, two-factor, API tokens, and users. Everything \
            else needs one of: the session cookie from POST /auth/login (plus X-CSRF-Token on \
            changes), Authorization: Bearer <token>, or HTTP Basic for users who allow it.")
    )
)]
pub struct ApiDoc;

/// Declares the three ways to authenticate.
struct Security;

impl utoipa::Modify for Security {
    fn modify(&self, api: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{
            ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme,
        };
        let c = api.components.get_or_insert_with(Default::default);
        c.add_security_scheme(
            "session",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new(auth::routes::COOKIE))),
        );
        c.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("tt_<id>_<secret>")
                    .build(),
            ),
        );
        c.add_security_scheme(
            "basic",
            SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Basic).build()),
        );
    }
}

/// The document as pretty JSON (what `GET /api/v1/openapi.json` serves and what the
/// committed `docs/api/openapi.json` must equal).
pub fn openapi_document() -> String {
    ApiDoc::openapi().to_pretty_json().unwrap_or_default()
}

async fn openapi_json() -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        openapi_document(),
    )
        .into_response()
}

fn not_found(uri: &axum::http::Uri) -> Problem {
    Problem::not_found(format!("no API route `{}`", uri.path()))
        .hint("See /api/v1/openapi.json for every route.")
}

/// `scope` must be this node until clustering exists (`spec/12` §6).
fn check_scope(scope: Option<&str>) -> Result<(), Problem> {
    match scope {
        None | Some("" | "cluster" | "node:local") => Ok(()),
        Some(s) => Err(Problem::new(
            problem::Code::UnsupportedScope,
            format!("scope `{s}` needs clustering, which this node doesn't run"),
        )
        .hint("Use scope=cluster or omit it.")),
    }
}

fn time_param(text: Option<&str>, default_s: u64, now_s: u64, name: &str) -> Result<u64, Problem> {
    match text {
        None => Ok(default_s),
        Some(t) => time::parse_time(t, now_s).map_err(|e| {
            Problem::invalid(format!("`{name}`: {e}")).hint(
                "Use a relative offset such as -24h, or RFC 3339 such as 2026-10-03T00:00:00Z.",
            )
        }),
    }
}

/// Runs a blocking backend call off the async runtime.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Problem> + Send + 'static,
) -> Result<T, Problem> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|e| Err(Problem::internal(format!("request worker failed: {e}"))))
}

/// Node and build information.
///
/// Version, role, uptime, listeners, whether the query log is on, and the active filter
/// snapshot. Cheap; suitable for health dashboards.
#[utoipa::path(get, path = "/api/v1/system/info", tag = "system",
    responses((status = 200, body = SystemInfo)))]
async fn system_info(State(b): State<Shared>) -> Json<SystemInfo> {
    Json(b.system_info())
}

/// Totals over a time range.
///
/// Queries, blocked (count and percent), cache hits, forwarded, NXDOMAIN and SERVFAIL counts
/// over the range (per-minute data up to 48 hours back, hourly rollups beyond), plus this
/// hour's active clients and latency percentiles by answer path. Example:
/// `GET /api/v1/stats/summary?from=-24h` or `?from=-30d`.
#[utoipa::path(get, path = "/api/v1/stats/summary", tag = "stats", params(SummaryParams),
    responses((status = 200, body = Summary), (status = 400, body = Problem)))]
async fn stats_summary(
    State(b): State<Shared>,
    Query(p): Query<SummaryParams>,
) -> Result<Json<Summary>, Problem> {
    check_scope(p.scope.as_deref())?;
    let now = b.now_unix_seconds();
    let from = time_param(p.from.as_deref(), now.saturating_sub(86_400), now, "from")?;
    let to = time_param(p.to.as_deref(), now + 1, now, "to")?;
    let mut s = Summary {
        from_unix_seconds: from,
        to_unix_seconds: to,
        ..Summary::default()
    };
    let step = if now.saturating_sub(from) > 48 * 3600 {
        Step::Hour
    } else {
        Step::Minute
    };
    let bk = Arc::clone(&b);
    let buckets = blocking(move || Ok(bk.timeseries(step, from, to))).await?;
    for bucket in buckets {
        let st = |k: &str| u64::from(bucket.by_status.get(k).copied().unwrap_or(0));
        s.queries += u64::from(bucket.total);
        s.blocked += st("blocked");
        s.cached += st("cached") + st("stale");
        s.forwarded += st("forwarded");
        s.servfail += st("servfail");
        s.nxdomain += u64::from(bucket.by_rcode.get("NXDOMAIN").copied().unwrap_or(0));
    }
    #[allow(clippy::cast_precision_loss)]
    let pct = |a: u64, b: u64| {
        if b == 0 {
            0.0
        } else {
            (a as f64 * 1000.0 / b as f64).round() / 10.0
        }
    };
    s.blocked_percent = pct(s.blocked, s.queries);
    s.cache_hit_percent = pct(s.cached, s.cached + s.forwarded);
    s.active_clients = b.top(TopKind::Clients, Hour::Current, 1000, None).len() as u64;
    s.latency = b.latency(LatencyBy::Path, Hour::Current);
    Ok(Json(s))
}

/// Query counts over time.
///
/// Buckets by status, query type, and response code, plus upstream exchanges. `step=second`
/// covers the last 15 minutes, `step=minute` 7 days (48 hours live), `step=hour` 400 days,
/// `step=day` everything. Buckets without queries are omitted. Example:
/// `GET /api/v1/stats/timeseries?from=-30d&step=hour`.
#[utoipa::path(get, path = "/api/v1/stats/timeseries", tag = "stats", params(TimeseriesParams),
    responses((status = 200, body = Items<TimeBucket>), (status = 400, body = Problem)))]
async fn stats_timeseries(
    State(b): State<Shared>,
    Query(p): Query<TimeseriesParams>,
) -> Result<Json<Items<TimeBucket>>, Problem> {
    check_scope(p.scope.as_deref())?;
    let now = b.now_unix_seconds();
    let step = p.step.unwrap_or(Step::Minute);
    let default_from = now.saturating_sub(match step {
        Step::Second => 300,
        Step::Minute => 3600,
        Step::Hour => 7 * 86_400,
        Step::Day => 90 * 86_400,
    });
    let from = time_param(p.from.as_deref(), default_from, now, "from")?;
    let to = time_param(p.to.as_deref(), now + 1, now, "to")?;
    let items = blocking(move || Ok(b.timeseries(step, from, to))).await?;
    Ok(Json(Items { items }))
}

/// Live query stream.
///
/// Server-Sent Events, newest as they happen: `event: query` carries a `QueryRow` (same
/// fields as GET /queries), `event: dropped` a `TailDropped` when matching queries were
/// skipped (over `rate`, or this client fell behind), and a comment every 15 s keeps the
/// connection open. Filters are applied on the server. In a browser:
/// `new EventSource('/api/v1/queries/stream?status=blocked')` (the session cookie signs it
/// in). Honors the query-log privacy level; at most 16 streams per node.
#[utoipa::path(get, path = "/api/v1/queries/stream", tag = "queries", params(TailParams),
    responses(
        (status = 200, description = "`text/event-stream` of `query` (QueryRow) and `dropped` (TailDropped) events.",
            content_type = "text/event-stream", body = String),
        (status = 400, body = Problem),
        (status = 503, body = Problem)))]
async fn queries_stream(
    State(b): State<Shared>,
    Query(p): Query<TailParams>,
) -> Result<Response, Problem> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    check_scope(p.scope.as_deref())?;
    if p.rate.is_some_and(|r| !(1..=2000).contains(&r)) {
        return Err(Problem::invalid("`rate`: 1 to 2000 events per second"));
    }
    let rx = b.tail(&p)?;
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        let event = match rx.recv().await? {
            TailItem::Query(q) => Event::default()
                .event("query")
                .id(q.ts_unix_micros.to_string())
                .json_data(&q),
            TailItem::Dropped(d) => Event::default().event("dropped").json_data(&d),
        }
        .unwrap_or_else(|_| Event::default().comment("encode error"));
        Some((Ok::<_, std::convert::Infallible>(event), rx))
    });
    Ok(Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response())
}

/// Top domains, blocked domains, NXDOMAIN names, or clients.
///
/// Ranked by a Space-Saving sketch per hour: `count` is an upper bound and `errorBound` how
/// far it may be over. Example: `GET /api/v1/stats/top?kind=blocked&limit=10`. With
/// `kind=domains&client=192.168.1.20`, one client's top domains (recently active clients only).
#[utoipa::path(get, path = "/api/v1/stats/top", tag = "stats", params(TopParams),
    responses((status = 200, body = Items<TopItem>), (status = 400, body = Problem)))]
async fn stats_top(
    State(b): State<Shared>,
    Query(p): Query<TopParams>,
) -> Result<Json<Items<TopItem>>, Problem> {
    check_scope(p.scope.as_deref())?;
    let limit = p.limit.unwrap_or(10).clamp(1, 100);
    let client = match &p.client {
        None => None,
        Some(c) => Some(
            c.parse::<IpAddr>()
                .map_err(|_| Problem::invalid(format!("`client`: `{c}` is not an IP address")))?,
        ),
    };
    if client.is_some() && p.kind != TopKind::Domains {
        return Err(Problem::invalid("`client` only applies to kind=domains"));
    }
    Ok(Json(Items {
        items: b.top(p.kind, p.hour.unwrap_or_default(), limit, client),
    }))
}

/// Latency percentiles.
///
/// By answer path and transport, query type, upstream server, or the upstream stage, for the
/// current or previous hour, in milliseconds (HDR histograms, 2 significant digits).
#[utoipa::path(get, path = "/api/v1/stats/latency", tag = "stats", params(LatencyParams),
    responses((status = 200, body = Items<LatencyRow>), (status = 400, body = Problem)))]
async fn stats_latency(
    State(b): State<Shared>,
    Query(p): Query<LatencyParams>,
) -> Result<Json<Items<LatencyRow>>, Problem> {
    check_scope(p.scope.as_deref())?;
    Ok(Json(Items {
        items: b.latency(p.by, p.hour.unwrap_or_default()),
    }))
}

/// Search the query log.
///
/// Newest first. Filters combine with AND: name (substring by default; `match=exact|suffix|
/// glob|regex`), client, status, query type, response code, upstream, minimum latency, and
/// time range. Pass `nextCursor` back as `cursor` for older rows. Example:
/// `GET /api/v1/queries?name=doubleclick&status=blocked&from=-1h&limit=50`.
#[utoipa::path(get, path = "/api/v1/queries", tag = "queries", params(QueryParams),
    responses((status = 200, body = QueryPage), (status = 400, body = Problem),
        (status = 503, body = Problem, description = "The query log is off.")))]
async fn queries(
    State(b): State<Shared>,
    Query(p): Query<QueryParams>,
) -> Result<Json<QueryPage>, Problem> {
    check_scope(p.scope.as_deref())?;
    let now = b.now_unix_seconds();
    let from = time_param(p.from.as_deref(), 0, now, "from")?;
    let to = time_param(p.to.as_deref(), 0, now, "to")?;
    let limit = p.limit.unwrap_or(100).clamp(1, 1000);
    if p.name_match.is_some_and(|m| m != NameMatch::Substring) && p.name.is_none() {
        return Err(Problem::invalid("`match` needs `name`"));
    }
    let (from_us, to_us) = (from.saturating_mul(1_000_000), to.saturating_mul(1_000_000));
    blocking(move || b.queries(&p, from_us, to_us, limit))
        .await
        .map(Json)
}

/// Explain a decision.
///
/// Why `name` is or isn't blocked for a client: how the client is identified, its groups,
/// every matching rule in every list (with the list line), which rule decides, and where the
/// query would be forwarded. Example: `GET /api/v1/explain?name=ads.example.com&client=192.168.1.20`.
#[utoipa::path(get, path = "/api/v1/explain", tag = "queries", params(ExplainParams),
    responses((status = 200, body = Explanation), (status = 400, body = Problem)))]
async fn explain(
    State(b): State<Shared>,
    Query(p): Query<ExplainParams>,
) -> Result<Json<Explanation>, Problem> {
    blocking(move || b.explain(&p)).await.map(Json)
}

/// Filter lists and their download state.
///
/// Every configured list with its kind (block/allow), source, download state (`ok`, `failed`,
/// `pending`) and last error, size, and how many names it contributes to the active snapshot.
#[utoipa::path(get, path = "/api/v1/lists", tag = "config",
    responses((status = 200, body = Items<ListInfo>)))]
async fn lists(State(b): State<Shared>) -> Json<Items<ListInfo>> {
    Json(Items { items: b.lists() })
}

/// Client groups, their lists, block mode, and pause state.
///
/// Groups decide which lists apply to a device and how blocked queries are answered. `lists`
/// null means every enabled list; `pausedUntilUnixSeconds` is set while blocking is paused.
#[utoipa::path(get, path = "/api/v1/groups", tag = "config",
    responses((status = 200, body = Items<GroupInfo>)))]
async fn groups(State(b): State<Shared>) -> Json<Items<GroupInfo>> {
    Json(Items { items: b.groups() })
}

/// Configured clients (devices) and how they're recognized.
///
/// Each device's name, the IPs, CIDRs, MACs, or client IDs that identify it, and its groups in
/// priority order (the first group's settings apply). Unknown devices use the `default` group.
#[utoipa::path(get, path = "/api/v1/clients", tag = "config",
    responses((status = 200, body = Items<ClientInfo>)))]
async fn clients(State(b): State<Shared>) -> Json<Items<ClientInfo>> {
    Json(Items { items: b.clients() })
}

/// Upstream servers with health and latency.
///
/// Every upstream with its stable ID, endpoint, groups, circuit-breaker state (`closed` means
/// healthy), request and failure counts, and smoothed answer time in milliseconds.
#[utoipa::path(get, path = "/api/v1/upstreams", tag = "config",
    responses((status = 200, body = Items<UpstreamInfo>)))]
async fn upstreams(State(b): State<Shared>) -> Json<Items<UpstreamInfo>> {
    Json(Items {
        items: b.upstreams(),
    })
}

#[cfg(test)]
mod tests;
