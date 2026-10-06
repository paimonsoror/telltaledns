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
pub mod blocking_api;
pub mod cache_api;
pub mod config_api;
pub mod federation;
pub mod mcp;
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
    AnomalyFinding, AnomalyParams, ClientChange, ClientInfo, ClientInput, ClusterCheck,
    ClusterConflict, ClusterEvent, ClusterFailover, ClusterInfo, ClusterNode, ClusterPeer,
    ClusterSource, ClusterView, ConfigChange, ConfigEntry, EntriesQuery, ExplainBlock,
    ExplainClient, ExplainFilter, ExplainLine, ExplainParams, ExplainRoute, ExplainRule,
    Explanation, ForwardInfo, ForwardInput, GroupInfo, HostInfo, HostPoint, HostReport, Hour,
    Items, LatencyBy, LatencyParams, LatencyRow, ListInfo, LocalName, MaskedClients, NameMatch,
    PromoteRequest, QueryPage, QueryParams, QueryRow, RecordInput, RecordsInput, ScanStats, Step,
    Summary, SummaryParams, SystemInfo, TailDropped, TailItem, TailParams, TimeBucket,
    TimeseriesParams, TopItem, TopKind, TopParams, UpstreamInfo,
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
    /// This node's own data only, for `scope=node:local` (CLU-002); `None` when reads aren't
    /// federated (a standalone node).
    fn local(&self) -> Option<Shared> {
        None
    }
    /// Cluster nodes that couldn't be read just now (shown as `missingNodes`).
    fn missing_nodes(&self) -> Vec<String> {
        Vec::new()
    }
    /// Makes this node the cluster's primary (ADR-051).
    fn promote(&self, req: PromoteRequest, by: String) -> Result<ClusterView, Problem> {
        let _ = (req, by);
        Err(Problem::unavailable("this node isn't in a cluster"))
    }
    /// What [`Backend::promote`] would do, without doing it (AGT-002).
    fn promote_plan(&self, req: &PromoteRequest) -> Result<model::PromotePlan, Problem> {
        let _ = req;
        Err(Problem::unavailable("this node isn't in a cluster"))
    }
    /// A backup of this node (ADR-063) without the query log: a file name and the archive.
    /// May take a moment (it copies the databases); called on a blocking thread.
    fn backup(&self) -> Result<(String, Vec<u8>), Problem> {
        Err(Problem::unavailable(
            "backups aren't available on this node",
        ))
    }
    /// A Git push webhook (ADR-049): checks the signature, then the ref at once.
    fn git_hook(&self, signature: Option<String>, body: Vec<u8>) -> Result<(), Problem> {
        let _ = (signature, body);
        Err(Problem::not_found(
            "this node has no Git configuration source",
        ))
    }
    /// The cluster as this node sees it (CLU-008).
    fn cluster(&self) -> ClusterView {
        ClusterView {
            enabled: false,
            cluster_id: None,
            name: None,
            this_node: None,
            newest_config_seq: 0,
            healthy: true,
            checks: Vec::new(),
            nodes: Vec::new(),
            events: Vec::new(),
            authority: None,
            conflicts: Vec::new(),
            failover: None,
            source: None,
            host: None,
        }
    }
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
    /// Top items among one group's queries (ADR-050).
    fn top_in_group(
        &self,
        kind: TopKind,
        hour: Hour,
        limit: usize,
        group: &str,
    ) -> Result<Vec<TopItem>, Problem> {
        let _ = (kind, hour, limit, group);
        Err(Problem::unavailable(
            "per-group lists aren't available on this node",
        ))
    }
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
    /// The configuration version (bumped by every change made through the API; ADR-040).
    /// Device anomaly findings whose window started at or after `since_s`, newest first.
    fn anomalies(&self, since_s: u64) -> Vec<AnomalyFinding> {
        let _ = since_s;
        Vec::new()
    }
    /// Names TelltaleDNS answers itself (files and API), by name.
    fn local_names(&self) -> Vec<LocalName> {
        Vec::new()
    }
    /// Domains sent to other servers (files and API).
    fn forwards(&self) -> Vec<ForwardInfo> {
        Vec::new()
    }
    /// Quick rules (files and API), by ID (T6.12).
    fn rules(&self) -> Vec<crate::model::RuleInfo> {
        Vec::new()
    }
    /// Cache counters, one row per node (T6.13).
    fn cache_stats(&self) -> Vec<crate::model::CacheNodeStats> {
        Vec::new()
    }
    /// REQ: DNS-006, OBS-003 (T6.15) — each node's `limit` top entries by `sort` (`hits`,
    /// `bytes`, `expiring`) and what its cache holds by kind; `node` limits it to one node.
    fn cache_entries(
        &self,
        sort: &str,
        limit: usize,
        node: Option<&str>,
    ) -> Result<Vec<crate::model::CacheNodeEntries>, Problem> {
        let _ = (sort, limit, node);
        Ok(Vec::new())
    }
    /// REQ: API-002 (T7.5, ADR-069) — upstreams, upstream groups, lists, and groups: each
    /// definition in effect and its source (`kind` limits it to one kind).
    fn config_entries(&self, kind: Option<&str>) -> Vec<crate::model::ConfigEntry> {
        let _ = kind;
        Vec::new()
    }
    /// REQ: FLT-009 (T7.1) — each node's active pauses.
    fn blocking_state(&self) -> Vec<crate::model::BlockingNode> {
        Vec::new()
    }
    /// Pauses blocking for `minutes` (everyone, or `group`), on every node or `node`.
    fn blocking_pause(
        &self,
        group: Option<&str>,
        minutes: u32,
        node: Option<&str>,
    ) -> Result<Vec<crate::model::BlockingNode>, Problem> {
        let _ = (group, minutes, node);
        Err(Problem::unavailable("pausing isn't available here"))
    }
    /// Ends `group`'s pause, or every pause, on every node or `node`.
    fn blocking_resume(
        &self,
        group: Option<&str>,
        node: Option<&str>,
    ) -> Result<Vec<crate::model::BlockingNode>, Problem> {
        let _ = (group, node);
        Err(Problem::unavailable("pausing isn't available here"))
    }
    /// What the cache holds for `name`, on every node (T6.13).
    fn cache_lookup(&self, name: &str) -> Result<Vec<crate::model::CacheEntry>, Problem> {
        let _ = name;
        Ok(Vec::new())
    }
    /// Flushes `name` (with `subtree`, everything under it; `None`: everything) on every
    /// node, or on `node` only (T6.13).
    fn cache_flush(
        &self,
        name: Option<&str>,
        subtree: bool,
        node: Option<&str>,
    ) -> Result<Vec<crate::model::CacheFlushNode>, Problem> {
        let _ = (name, subtree, node);
        Ok(Vec::new())
    }
    /// Sets (`body` set) or removes (`body` None) a local name or a forwarded domain made
    /// through the API (ADR-042). Validates the resulting configuration and, unless `dry_run`,
    /// stores and applies it.
    fn write_managed(&self, w: ManagedWrite) -> BoxFuture<Result<ConfigChange, Problem>> {
        let _ = w;
        Box::pin(async {
            Err(Problem::unavailable(
                "configuration changes aren't available on this node",
            ))
        })
    }
    fn config_version(&self) -> u64 {
        0
    }
    /// REQ: OPS-004 (ADR-046) — checks the signed release index now instead of waiting for the
    /// daily check, and returns the new status. At most one check a minute: sooner, the
    /// current status comes back without a fetch.
    fn check_updates(&self) -> BoxFuture<Result<crate::model::UpdateStatus, Problem>> {
        Box::pin(async {
            Err(Problem::unavailable(
                "update checks aren't available on this node",
            ))
        })
    }
    /// Creates, renames, changes (`input` set), or deletes (`input` None) a device made
    /// through the API (API-010). Validates the resulting configuration and, unless
    /// `dry_run`, stores and applies it.
    fn write_client(&self, w: ClientWrite) -> BoxFuture<Result<ClientChange, Problem>> {
        let _ = w;
        Box::pin(async {
            Err(Problem::unavailable(
                "configuration changes aren't available on this node",
            ))
        })
    }
}

pub type Shared = Arc<dyn Backend>;

/// A boxed future returned by backend writes.
pub type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'static>>;

/// What kind of entry a [`ManagedWrite`] changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedKind {
    /// A local name and its records (`/records/{name}`).
    Record,
    /// A domain sent to other servers (`/forwards/{domain}`).
    Forward,
    /// A quick rule (`/rules/{id}`, T6.12).
    Rule,
    /// REQ: API-002 (T7.5, ADR-069) — an upstream (`/upstreams/{name}`): may override or hide
    /// the files' entry of the same name.
    Upstream,
    /// An upstream group (`/upstream-groups/{name}`).
    UpstreamGroup,
    /// A filter list (`/lists/{name}`).
    List,
    /// A client group (`/groups/{name}`).
    Group,
}

/// A write to a local name or a forwarded domain.
#[derive(Debug, Clone)]
pub struct ManagedWrite {
    pub kind: ManagedKind,
    /// The name or domain in the path.
    pub name: String,
    /// The new definition ([`model::RecordsInput`] or [`model::ForwardInput`] as JSON); `None`
    /// deletes.
    pub body: Option<serde_json::Value>,
    pub dry_run: bool,
    pub expect: Option<u64>,
    pub by: String,
}

/// A device write (`PUT`/`DELETE /api/v1/clients/{name}`).
#[derive(Debug, Clone)]
pub struct ClientWrite {
    /// The name in the path: the device's current name, or the new device's name.
    pub name: String,
    /// The new definition; `None` deletes.
    pub input: Option<ClientInput>,
    pub dry_run: bool,
    /// `If-Match`: refuse unless the config version is still this.
    pub expect: Option<u64>,
    /// Who made the change (stored with the entry).
    pub by: String,
}

/// The `/api/v1` routes (REQ: API-001, API-003). Everything except sign-in, first-run setup,
/// and the OpenAPI document needs authentication; reads need `viewer`, user management
/// `admin`.
#[allow(clippy::needless_pass_by_value)] // shared by every route
pub fn router(backend: Shared, auth: Arc<auth::Auth>) -> Router {
    // REQ: AGT-006 (ADR-065) — MCP at /mcp, calling the REST routes with the caller's
    // credentials.
    let api = rest_router(Arc::clone(&backend), Arc::clone(&auth));
    let mcp = mcp::Mcp {
        api: api.clone(),
        sessions: Arc::new(mcp::Sessions::default()),
    };
    let mcp_routes = Router::new()
        .route("/mcp", axum::routing::post(mcp::post).get(mcp::get))
        .with_state(mcp)
        .layer(axum::middleware::from_fn_with_state(
            auth,
            auth::routes::authenticate,
        ));
    api.merge(mcp_routes)
}

/// The `/api/v1` routes without MCP.
#[allow(clippy::needless_pass_by_value)] // shared by every route
fn rest_router(backend: Shared, auth: Arc<auth::Auth>) -> Router {
    use axum::middleware::{from_fn, from_fn_with_state};
    let data = Router::new()
        .route("/api/v1/system/info", get(system_info))
        .route("/api/v1/cluster", get(cluster))
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
        .route("/api/v1/analytics/anomalies", get(anomalies))
        .route("/api/v1/records", get(local_names))
        .route("/api/v1/forwards", get(forwards))
        .route("/api/v1/rules", get(rules))
        .route("/api/v1/config/entries", get(config_entries))
        .route("/api/v1/upstreams", get(upstreams))
        .with_state(Arc::clone(&backend))
        .merge(cache_api::read_routes(Arc::clone(&backend)))
        .merge(blocking_api::read_routes(Arc::clone(&backend)))
        .route_layer(from_fn(auth::routes::require_viewer));
    let protected = data
        .merge(auth::routes::self_service(Arc::clone(&auth)))
        // REQ: API-002, API-010 — configuration changes need operator (or a `write` token).
        .merge(
            config_api::routes(Arc::clone(&backend), Arc::clone(&auth))
                .route_layer(from_fn(auth::routes::require_operator)),
        )
        // REQ: DNS-006 (T6.13) — flushing the cache needs operator (agents: ops:cache).
        .merge(
            cache_api::flush_routes(Arc::clone(&backend), Arc::clone(&auth))
                .route_layer(from_fn(auth::routes::require_operator)),
        )
        // REQ: FLT-009 (T7.1) — pausing blocking needs operator (agents: ops:pause).
        .merge(
            blocking_api::write_routes(Arc::clone(&backend), Arc::clone(&auth))
                .route_layer(from_fn(auth::routes::require_operator)),
        )
        .merge(
            auth::routes::admin(Arc::clone(&auth))
                .route_layer(from_fn(auth::routes::require_admin)),
        )
        // REQ: OPS-004 — "Check now" for updates is an admin action.
        .merge(
            Router::new()
                .route(
                    "/api/v1/system/update-check",
                    axum::routing::post(update_check),
                )
                .with_state(Arc::clone(&backend))
                .route_layer(from_fn(auth::routes::require_admin)),
        )
        // REQ: CLU-005 — promotion is an admin action (ADR-051).
        .merge(
            config_api::admin_routes(Arc::clone(&backend), Arc::clone(&auth))
                .route_layer(from_fn(auth::routes::require_admin)),
        )
        .layer(from_fn_with_state(
            Arc::clone(&auth),
            auth::routes::authenticate,
        ));
    Router::new()
        .route("/api/v1/openapi.json", get(openapi_json))
        // REQ: CLU-003 (ADR-049) — authenticated by its HMAC signature, not a session.
        .route(
            "/api/v1/hooks/git",
            axum::routing::post(git_hook).with_state(Arc::clone(&backend)),
        )
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
        system_info, update_check, cluster, config_api::cluster_promote, config_api::backup_download, git_hook, stats_summary, stats_timeseries, stats_top, stats_latency, queries,
        queries_stream,
        explain, lists, groups, clients, upstreams,
        auth::routes::status, auth::routes::setup, auth::routes::login, auth::routes::logout,
        auth::routes::get_me, auth::routes::change_password, auth::routes::totp_setup,
        auth::routes::totp_enable, auth::routes::totp_disable, auth::routes::list_tokens,
        auth::routes::create_token, auth::routes::delete_token, auth::routes::list_users,
        auth::routes::create_user, auth::routes::update_user, auth::routes::delete_user,
        auth::routes::audit_log, auth::routes::audit_verify, auth::routes::oidc_start,
        auth::routes::oidc_callback, config_api::put_client, config_api::delete_client,
        local_names, forwards, rules, anomalies, cache_api::stats, cache_api::lookup, cache_api::entries, cache_api::flush, blocking_api::state, blocking_api::pause, blocking_api::resume, config_entries, config_api::put_upstream, config_api::delete_upstream, config_api::put_upstream_group, config_api::delete_upstream_group, config_api::put_list, config_api::delete_list, config_api::put_group, config_api::delete_group, config_api::put_records, config_api::delete_records, config_api::put_rule, config_api::delete_rule,
        config_api::put_forward, config_api::delete_forward
    ),
    components(schemas(
        Problem, problem::Code, SystemInfo, MaskedClients, ClusterInfo, ClusterPeer, ClusterView, ClusterNode, ClusterEvent, ClusterCheck, ClusterConflict, ClusterFailover, ClusterSource, HostReport, HostInfo, HostPoint, model::RuleInput, model::RuleInfo, model::CacheNodeStats, model::CacheEntry, model::CacheLookup, model::CacheFlushRequest, model::CacheFlushNode, model::CacheFlushResult, model::CacheSettings, model::CacheWarmStart, model::CachePoint, model::CacheMakeup, model::CacheTopEntry, model::CacheNodeEntries, model::BlockingRequest, model::BlockingNode, model::PauseInfo, model::ConfigEntry, PromoteRequest, model::PromotePlan, Summary, TimeBucket, TopItem, LatencyRow, QueryPage, QueryRow,
        TailDropped,
        ScanStats, Explanation, ExplainClient, ExplainBlock, ExplainFilter, ExplainRule,
        ExplainLine, ExplainRoute, ListInfo, GroupInfo, ClientInfo, ClientInput, ClientChange, LocalName, RecordInput, RecordsInput, ForwardInfo, ForwardInput, ConfigChange, AnomalyFinding, UpstreamInfo, Step, TopKind,
        Hour, LatencyBy, NameMatch, auth::Role, auth::Scope, auth::routes::Me,
        auth::routes::AuthStatus, auth::routes::SetupRequest, auth::routes::LoginRequest,
        auth::routes::LoginResponse, auth::routes::PasswordChange, auth::routes::TotpSetup,
        auth::routes::TotpCode, auth::routes::PasswordConfirm, auth::routes::RecoveryCodes,
        auth::routes::TokenInfo, auth::routes::TokenKind, auth::routes::CreateToken, auth::routes::NewToken,
        auth::routes::UserInfo, auth::routes::CreateUser, auth::routes::UpdateUser,
        auth::routes::AuditInfo, auth::routes::AuditPage, auth::routes::AuditVerify,
        auth::routes::OidcButton, auth::routes::LogoutResult
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

/// The backend a read's `scope` selects (`spec/12` §6, CLU-002): the whole cluster by default
/// (federated when this node is in one), or `node:local` for this node alone.
fn pick(b: &Shared, scope: Option<&str>) -> Result<Shared, Problem> {
    check_scope(scope)?;
    Ok(match (scope, b.local()) {
        (Some("node:local"), Some(local)) => local,
        _ => Arc::clone(b),
    })
}

/// `scope` is `cluster` (default) or `node:local`; reading one named peer isn't offered yet.
fn check_scope(scope: Option<&str>) -> Result<(), Problem> {
    match scope {
        None | Some("" | "cluster" | "node:local") => Ok(()),
        Some(s) => Err(Problem::new(
            problem::Code::UnsupportedScope,
            format!("scope `{s}` isn't supported"),
        )
        .hint("Use scope=cluster (or omit it) for every node, or scope=node:local for this one.")),
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
    responses((status = 200, body = SystemInfo, description = "The result.")))]
async fn system_info(State(b): State<Shared>) -> Json<SystemInfo> {
    Json(b.system_info())
}

/// Check for updates now.
///
/// Reads this node's channel's signed release index (`releases.json`) at once instead of at
/// the next daily check, and returns the update status (the same as `update` in
/// `GET /api/v1/system/info`). At most one check a minute: a sooner request returns the
/// current status without fetching. Nothing is installed. With `[updates] check = false` the
/// status stays `off` and nothing leaves the node. Needs the admin role.
#[utoipa::path(post, path = "/api/v1/system/update-check", tag = "system",
    responses((status = 200, body = crate::model::UpdateStatus, description = "The update status after the check."),
        (status = 403, body = Problem, description = "Needs the admin role.")))]
async fn update_check(
    State(b): State<Shared>,
) -> Result<Json<crate::model::UpdateStatus>, Problem> {
    b.check_updates().await.map(Json)
}

/// Git push webhook.
///
/// Point the repository's push webhook here (content type JSON, with the secret from
/// `[cluster.git] webhook_secret_file`): the primary checks the ref at once instead of at
/// the next poll. Authenticated by the `X-Hub-Signature-256` HMAC, not a session.
#[utoipa::path(post, path = "/api/v1/hooks/git", tag = "system",
    responses((status = 202, description = "The ref will be checked now."),
        (status = 401, body = Problem, description = "Not signed in, or the credentials are wrong."), (status = 404, body = Problem, description = "Not found.")))]
async fn git_hook(
    State(b): State<Shared>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<axum::http::StatusCode, Problem> {
    let sig = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    b.git_hook(sig, body.to_vec())?;
    Ok(axum::http::StatusCode::ACCEPTED)
}

/// The cluster's health.
///
/// Every node this node knows: role, link state and round-trip time, configuration version
/// and lag, and whether it's serving DNS (queries per second, SERVFAIL share, upstream p90).
/// Plus `checks` (each with a plain-language fix when failing) and recent `events`. On a
/// standalone node, `enabled` is false. Use it to answer "is the cluster healthy and serving?".
#[utoipa::path(get, path = "/api/v1/cluster", tag = "system",
    responses((status = 200, body = ClusterView, description = "The result.")))]
async fn cluster(State(b): State<Shared>) -> Result<Json<ClusterView>, Problem> {
    blocking(move || Ok(b.cluster())).await.map(Json)
}

/// Totals over a time range.
///
/// Queries, blocked (count and percent), cache hits, forwarded, NXDOMAIN and SERVFAIL counts
/// over the range (per-minute data up to 48 hours back, hourly rollups beyond), plus this
/// hour's active clients and latency percentiles by answer path. Example:
/// `GET /api/v1/stats/summary?from=-24h` or `?from=-30d`.
#[utoipa::path(get, path = "/api/v1/stats/summary", tag = "stats", params(SummaryParams),
    responses((status = 200, body = Summary, description = "The result."), (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it.")))]
async fn stats_summary(
    State(b): State<Shared>,
    Query(p): Query<SummaryParams>,
) -> Result<Json<Summary>, Problem> {
    let b = pick(&b, p.scope.as_deref())?;
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
    let bk = Arc::clone(&b);
    let (clients, latency) = blocking(move || {
        Ok((
            bk.top(TopKind::Clients, Hour::Current, 1000, None).len() as u64,
            bk.latency(LatencyBy::Path, Hour::Current),
        ))
    })
    .await?;
    s.active_clients = clients;
    s.latency = latency;
    s.missing_nodes = b.missing_nodes();
    Ok(Json(s))
}

/// Query counts over time.
///
/// Buckets by status, query type, and response code, plus upstream exchanges. `step=second`
/// covers the last 15 minutes, `step=minute` 7 days (48 hours live), `step=hour` 400 days,
/// `step=day` everything. Buckets without queries are omitted. Example:
/// `GET /api/v1/stats/timeseries?from=-30d&step=hour`.
#[utoipa::path(get, path = "/api/v1/stats/timeseries", tag = "stats", params(TimeseriesParams),
    responses((status = 200, body = Items<TimeBucket>, description = "The result."), (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it.")))]
async fn stats_timeseries(
    State(b): State<Shared>,
    Query(p): Query<TimeseriesParams>,
) -> Result<Json<Items<TimeBucket>>, Problem> {
    let b = pick(&b, p.scope.as_deref())?;
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
    let bk = Arc::clone(&b);
    let items = blocking(move || Ok(bk.timeseries(step, from, to))).await?;
    Ok(Json(Items {
        missing_nodes: b.missing_nodes(),
        items,
    }))
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
        (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it."),
        (status = 503, body = Problem, description = "Not available on this node right now.")))]
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
    responses((status = 200, body = Items<TopItem>, description = "The result."), (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it.")))]
async fn stats_top(
    State(b): State<Shared>,
    Query(p): Query<TopParams>,
) -> Result<Json<Items<TopItem>>, Problem> {
    let b = pick(&b, p.scope.as_deref())?;
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
    if p.group.is_some() {
        if client.is_some() {
            return Err(Problem::invalid("use either `client` or `group`"));
        }
        if p.kind == TopKind::Nxdomain {
            return Err(Problem::invalid(
                "`group` isn't available for kind=nxdomain",
            ));
        }
    }
    let bk = Arc::clone(&b);
    let (kind, hour, group) = (p.kind, p.hour.unwrap_or_default(), p.group);
    let items = blocking(move || match group {
        Some(g) => bk.top_in_group(kind, hour, limit, &g),
        None => Ok(bk.top(kind, hour, limit, client)),
    })
    .await?;
    Ok(Json(Items {
        missing_nodes: b.missing_nodes(),
        items,
    }))
}

/// Latency percentiles.
///
/// By answer path and transport, query type, upstream server, or the upstream stage, for the
/// current or previous hour, in milliseconds (HDR histograms, 2 significant digits).
#[utoipa::path(get, path = "/api/v1/stats/latency", tag = "stats", params(LatencyParams),
    responses((status = 200, body = Items<LatencyRow>, description = "The result."), (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it.")))]
async fn stats_latency(
    State(b): State<Shared>,
    Query(p): Query<LatencyParams>,
) -> Result<Json<Items<LatencyRow>>, Problem> {
    let b = pick(&b, p.scope.as_deref())?;
    let bk = Arc::clone(&b);
    let (by, hour) = (p.by, p.hour.unwrap_or_default());
    let items = blocking(move || Ok(bk.latency(by, hour))).await?;
    Ok(Json(Items {
        missing_nodes: b.missing_nodes(),
        items,
    }))
}

/// Search the query log.
///
/// Newest first. Filters combine with AND: name (substring by default; `match=exact|suffix|
/// glob|regex`), client, status, query type, response code, upstream, minimum latency, and
/// time range. Pass `nextCursor` back as `cursor` for older rows. Example:
/// `GET /api/v1/queries?name=doubleclick&status=blocked&from=-1h&limit=50`.
#[utoipa::path(get, path = "/api/v1/queries", tag = "queries", params(QueryParams),
    responses((status = 200, body = QueryPage, description = "The result."), (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it."),
        (status = 503, body = Problem, description = "The query log is off.")))]
async fn queries(
    State(b): State<Shared>,
    Query(p): Query<QueryParams>,
) -> Result<Json<QueryPage>, Problem> {
    let b = pick(&b, p.scope.as_deref())?;
    let now = b.now_unix_seconds();
    let from = time_param(p.from.as_deref(), 0, now, "from")?;
    let to = time_param(p.to.as_deref(), 0, now, "to")?;
    let limit = p.limit.unwrap_or(100).clamp(1, 1000);
    if p.name_match.is_some_and(|m| m != NameMatch::Substring) && p.name.is_none() {
        return Err(Problem::invalid("`match` needs `name`"));
    }
    let (from_us, to_us) = (from.saturating_mul(1_000_000), to.saturating_mul(1_000_000));
    let bk = Arc::clone(&b);
    let mut page = blocking(move || bk.queries(&p, from_us, to_us, limit)).await?;
    page.missing_nodes = b.missing_nodes();
    Ok(Json(page))
}

/// Explain a decision.
///
/// Why `name` is or isn't blocked for a client: how the client is identified, its groups,
/// every matching rule in every list (with the list line), which rule decides, and where the
/// query would be forwarded. Example: `GET /api/v1/explain?name=ads.example.com&client=192.168.1.20`.
#[utoipa::path(get, path = "/api/v1/explain", tag = "queries", params(ExplainParams),
    responses((status = 200, body = Explanation, description = "The result."), (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it.")))]
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
    responses((status = 200, body = Items<ListInfo>, description = "The result.")))]
async fn lists(State(b): State<Shared>) -> Json<Items<ListInfo>> {
    Json(Items {
        missing_nodes: Vec::new(),
        items: b.lists(),
    })
}

/// Client groups, their lists, block mode, and pause state.
///
/// Groups decide which lists apply to a device and how blocked queries are answered. `lists`
/// null means every enabled list; `pausedUntilUnixSeconds` is set while blocking is paused.
#[utoipa::path(get, path = "/api/v1/groups", tag = "config",
    responses((status = 200, body = Items<GroupInfo>, description = "The result.")))]
async fn groups(State(b): State<Shared>) -> Json<Items<GroupInfo>> {
    Json(Items {
        missing_nodes: Vec::new(),
        items: b.groups(),
    })
}

/// Configured clients (devices) and how they're recognized.
///
/// Each device's name, the IPs, CIDRs, MACs, or client IDs that identify it, and its groups in
/// priority order (the first group's settings apply). Unknown devices use the `default` group.
#[utoipa::path(get, path = "/api/v1/clients", tag = "config",
    responses((status = 200, body = Items<ClientInfo>, description = "The result.")))]
async fn clients(State(b): State<Shared>, ext: axum::http::Extensions) -> impl IntoResponse {
    // The config version for `If-Match` on writes (ADR-040).
    let etag = format!("\"{}\"", b.config_version());
    let mut items = b.clients();
    // REQ: AGT-004 — a group-restricted agent sees its group's devices only.
    if let Some(g) = ext
        .get::<auth::Principal>()
        .and_then(|p| p.agent.as_ref())
        .and_then(|a| a.group.as_deref())
    {
        items.retain(|c| {
            c.groups.iter().any(|x| x == g) || c.effective_groups.iter().any(|x| x == g)
        });
    }
    (
        [(axum::http::header::ETAG, etag)],
        Json(Items {
            missing_nodes: Vec::new(),
            items,
        }),
    )
}

/// Device anomalies: rate spikes, heavy volume to one domain, drift, beaconing (OBS-013).
///
/// Each finding compares a device with its own learned baseline (after a learning period,
/// 7 days by default) and carries the evidence: observed value, usual value ± spread, the
/// threshold, and the window. Findings are alert-only; TelltaleDNS never blocks on them.
/// Newest first.
#[utoipa::path(get, path = "/api/v1/analytics/anomalies", tag = "stats",
    params(AnomalyParams),
    responses((status = 200, body = Items<AnomalyFinding>, description = "The result."), (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it.")))]
async fn anomalies(
    State(b): State<Shared>,
    Query(p): Query<AnomalyParams>,
) -> Result<Json<Items<AnomalyFinding>>, Problem> {
    let now = b.now_unix_seconds();
    let since = time_param(
        p.since.as_deref(),
        now.saturating_sub(7 * 86_400),
        now,
        "since",
    )?;
    Ok(Json(Items {
        missing_nodes: Vec::new(),
        items: b.anomalies(since),
    }))
}

/// Names on my network: the names TelltaleDNS answers itself.
///
/// Every local name with its records and where it's defined (`file`: read-only here; `api`:
/// editable with `PUT /records/{name}`). The `ETag` is the config version for `If-Match`.
#[utoipa::path(get, path = "/api/v1/records", tag = "config",
    responses((status = 200, body = Items<LocalName>, description = "The result.")))]
async fn local_names(State(b): State<Shared>) -> impl IntoResponse {
    let etag = format!("\"{}\"", b.config_version());
    (
        [(axum::http::header::ETAG, etag)],
        Json(Items {
            missing_nodes: Vec::new(),
            items: b.local_names(),
        }),
    )
}

/// Domains sent to other DNS servers (conditional forwarding).
///
/// Each domain whose names are asked of specific servers instead of the public upstreams,
/// with where it's defined (`file` or `api`). The `ETag` is the config version for `If-Match`.
#[utoipa::path(get, path = "/api/v1/forwards", tag = "config",
    responses((status = 200, body = Items<ForwardInfo>, description = "The result.")))]
async fn forwards(State(b): State<Shared>) -> impl IntoResponse {
    let etag = format!("\"{}\"", b.config_version());
    (
        [(axum::http::header::ETAG, etag)],
        Json(Items {
            missing_nodes: Vec::new(),
            items: b.forwards(),
        }),
    )
}

/// The configuration's upstreams, upstream groups, lists, and groups, with their sources.
///
/// Each definition in effect, with the same fields as in `telltale.toml`, and where it comes
/// from (ADR-069): `file`, `added` (made through the UI or API), `override` (replaces the
/// config files' entry of the same name), or `hidden` (the files' entry is left out; listed so
/// it can be brought back). `DELETE` on an override's or a hidden entry's path brings the
/// files' version back. Secrets aren't part of these sections.
#[utoipa::path(get, path = "/api/v1/config/entries", tag = "config",
    params(EntriesQuery),
    responses((status = 200, body = Items<ConfigEntry>, description = "The entries, by kind and name.")))]
async fn config_entries(
    State(b): State<Shared>,
    Query(q): Query<EntriesQuery>,
) -> Json<Items<ConfigEntry>> {
    Json(Items {
        missing_nodes: Vec::new(),
        items: b.config_entries(q.kind.as_deref()),
    })
}

/// Quick rules: per-device and per-group allow and block (T6.12, ADR-067).
///
/// Every rule with whom it applies to, its expiry and how long it has left, its note, who made
/// it, and where it's defined (`file` or `api`). Quick rules decide before any list: a device
/// rule beats a group rule beats an everyone rule. The `ETag` is the config version for
/// `If-Match`.
#[utoipa::path(get, path = "/api/v1/rules", tag = "config",
    responses((status = 200, body = Items<crate::model::RuleInfo>, description = "The result.")))]
async fn rules(State(b): State<Shared>) -> impl IntoResponse {
    let etag = format!("\"{}\"", b.config_version());
    (
        [(axum::http::header::ETAG, etag)],
        Json(Items {
            missing_nodes: Vec::new(),
            items: b.rules(),
        }),
    )
}

/// Upstream servers with health and latency.
///
/// Every upstream with its stable ID, endpoint, groups, circuit-breaker state (`closed` means
/// healthy), request and failure counts, and smoothed answer time in milliseconds.
#[utoipa::path(get, path = "/api/v1/upstreams", tag = "config",
    responses((status = 200, body = Items<UpstreamInfo>, description = "The result.")))]
async fn upstreams(State(b): State<Shared>) -> Json<Items<UpstreamInfo>> {
    Json(Items {
        missing_nodes: Vec::new(),
        items: b.upstreams(),
    })
}

#[cfg(test)]
mod tests;
