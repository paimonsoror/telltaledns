//! Request and response types. JSON is camelCase; field names carry their units
//! (`totalMs`, `ttlSeconds`) so agents and dashboards never have to guess (AGT-001).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Node and build information.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SystemInfo {
    /// TelltaleDNS version.
    #[schema(example = "0.1.0")]
    pub version: String,
    /// Node name.
    pub node: String,
    /// Process role: `all`, `resolver`, or `controller`.
    pub role: String,
    pub uptime_seconds: u64,
    /// When the process started (RFC 3339).
    pub started_at: String,
    /// DNS listeners, as `proto://addr`.
    pub listeners: Vec<String>,
    /// Whether the per-query log is being written.
    pub query_log: bool,
    /// Version of the active filter snapshot, if one is loaded.
    pub filter_snapshot: Option<u64>,
    /// Blocked names in the active snapshot.
    pub filter_names: u64,
    /// Present when client IPs appear masked (OPS-003): most recent queries come from a few
    /// infrastructure addresses (a Kubernetes node, a Docker bridge, a forwarding router),
    /// so per-device statistics and rules see those instead of devices.
    pub client_ips_masked: Option<MaskedClients>,
}

/// Evidence that client IPs appear masked.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MaskedClients {
    /// Share of the window's queries sent by `sources`, in percent (> 90).
    #[schema(example = 97)]
    pub share_percent: u32,
    /// The infrastructure addresses that sent them, heaviest first (at most 3).
    #[schema(example = json!(["10.42.0.1"]))]
    pub sources: Vec<String>,
    /// Queries in the 10-minute window examined.
    pub queries: u64,
    /// Start of that window (RFC 3339).
    pub window_start: String,
}

/// Time-bucket size for [`TimeseriesParams`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Step {
    /// 1-second buckets (the last 15 minutes are kept).
    Second,
    /// 1-minute buckets: 48 hours in memory, 7 days in the rollup database.
    Minute,
    /// 1-hour buckets from the rollup database (400 days).
    Hour,
    /// 1-day buckets from the rollup database (kept forever).
    Day,
}

/// Which node's data an analytics call reads (`spec/07` §1, `spec/12` §6). Until clustering
/// lands, `cluster` and `node:local` both mean this node; other values are rejected.
#[derive(Debug, Clone, Default, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct ScopeParam {
    /// `cluster` (default) or `node:local`.
    #[param(example = "cluster")]
    pub scope: Option<String>,
}

/// Counts for one time bucket.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TimeBucket {
    /// Bucket start, Unix seconds.
    pub start_unix_seconds: u64,
    /// Queries in the bucket.
    pub total: u32,
    /// By status (`cached`, `forwarded`, `blocked`, ...).
    pub by_status: BTreeMap<String, u32>,
    /// By query type (`A`, `AAAA`, ..., `other`).
    pub by_qtype: BTreeMap<String, u32>,
    /// By response code (`NOERROR`, `NXDOMAIN`, ...).
    pub by_rcode: BTreeMap<String, u32>,
    /// Upstream exchanges, and how many failed.
    pub upstream_queries: u32,
    pub upstream_failures: u32,
}

/// Query parameters for `GET /stats/timeseries`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TimeseriesParams {
    /// Start: RFC 3339 or relative (`-1h`). Default: 5 minutes ago (second steps), 1 hour
    /// (minute), 7 days (hour), or 90 days (day).
    pub from: Option<String>,
    /// End: RFC 3339 or relative. Default: now.
    pub to: Option<String>,
    /// Bucket size. Default: `minute`.
    pub step: Option<Step>,
    /// `cluster` (default) or `node:local`.
    pub scope: Option<String>,
}

/// Totals over a time range.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub from_unix_seconds: u64,
    pub to_unix_seconds: u64,
    pub queries: u64,
    pub blocked: u64,
    /// Blocked share of all queries, 0–100.
    pub blocked_percent: f64,
    /// Answered from cache (fresh or stale).
    pub cached: u64,
    /// Cache share of answered queries that weren't blocked or local, 0–100.
    pub cache_hit_percent: f64,
    pub forwarded: u64,
    pub nxdomain: u64,
    pub servfail: u64,
    /// Distinct clients seen this hour.
    pub active_clients: u64,
    /// Latency percentiles this hour, by answer path (`cache`, `upstream`, ...).
    pub latency: Vec<LatencyRow>,
}

/// Query parameters for `GET /stats/summary`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SummaryParams {
    /// Start: RFC 3339 or relative (`-24h`, `-30d`). Default: 24 hours ago. Ranges over
    /// 48 hours are summed from hourly rollups.
    pub from: Option<String>,
    /// End. Default: now.
    pub to: Option<String>,
    /// `cluster` (default) or `node:local`.
    pub scope: Option<String>,
}

/// What a top-K list ranks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TopKind {
    /// Most queried names.
    Domains,
    /// Most blocked names.
    Blocked,
    /// Names most often answered NXDOMAIN.
    Nxdomain,
    /// Most active clients.
    Clients,
}

/// Which hour a top-K or latency call reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Hour {
    /// The hour in progress.
    #[default]
    Current,
    /// The last complete hour.
    Previous,
}

/// Query parameters for `GET /stats/top`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TopParams {
    pub kind: TopKind,
    /// Items to return (1–100, default 10).
    pub limit: Option<usize>,
    /// Default: `current`.
    pub hour: Option<Hour>,
    /// Only this client's domains (an IP address; `kind=domains` only).
    pub client: Option<String>,
    /// `cluster` (default) or `node:local`.
    pub scope: Option<String>,
}

/// One ranked item. Counts come from a Space-Saving sketch: the true count lies in
/// `[count - errorBound, count]`.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TopItem {
    /// Domain name or client address.
    pub key: String,
    /// The configured device name, for clients that have one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub count: u64,
    pub error_bound: u64,
}

/// What `GET /stats/latency` groups by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LatencyBy {
    /// Answer path (`cache`, `upstream`, `local`, `synthesized`) and transport.
    Path,
    /// Query type.
    Qtype,
    /// Upstream server (from upstream exchanges, including prefetches).
    Upstream,
    /// Time spent waiting for upstreams, per client query.
    Stage,
}

/// Query parameters for `GET /stats/latency`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LatencyParams {
    pub by: LatencyBy,
    /// Default: `current`.
    pub hour: Option<Hour>,
    /// `cluster` (default) or `node:local`.
    pub scope: Option<String>,
}

/// Latency percentiles for one key (HDR histogram, 2 significant digits).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LatencyRow {
    /// What the row is for (`cache/udp`, `AAAA`, `quad9-tls-1`, `upstream`).
    pub key: String,
    pub count: u64,
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p99_ms: f64,
    pub p999_ms: f64,
    pub max_ms: f64,
}

/// How `name` in [`QueryParams`] is matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum NameMatch {
    /// The name contains the text (default).
    #[default]
    Substring,
    /// Exactly this name.
    Exact,
    /// This name or any name below it.
    Suffix,
    /// `*` and `?` wildcards over the whole name.
    Glob,
    /// A regular expression over the whole name (no backreferences or lookaround).
    Regex,
}

/// Query parameters for `GET /queries`. Filters combine with AND.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct QueryParams {
    /// Name to look for; see `match`.
    pub name: Option<String>,
    /// How to match `name`. Default: `substring`.
    #[serde(rename = "match")]
    #[param(rename = "match")]
    pub name_match: Option<NameMatch>,
    /// Client IP address.
    pub client: Option<String>,
    /// Statuses, comma-separated (`blocked,forwarded`).
    pub status: Option<String>,
    /// Query types, comma-separated (`A,AAAA`).
    pub qtype: Option<String>,
    /// Response codes, comma-separated (`NXDOMAIN,SERVFAIL`).
    pub rcode: Option<String>,
    /// Upstream ID.
    pub upstream: Option<u16>,
    /// Only queries that took at least this long.
    pub min_latency_ms: Option<u32>,
    /// Start: RFC 3339 or relative (`-1h`). Default: no limit.
    pub from: Option<String>,
    /// End. Default: now.
    pub to: Option<String>,
    /// Rows per page (1–1000, default 100).
    pub limit: Option<usize>,
    /// Continue after a previous page (`nextCursor` from it).
    pub cursor: Option<String>,
    /// `cluster` (default) or `node:local`.
    pub scope: Option<String>,
}

/// One logged query.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct QueryRow {
    /// When the query arrived (RFC 3339, milliseconds).
    pub time: String,
    pub ts_unix_micros: u64,
    /// Client address.
    pub client: String,
    /// The configured device name, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// The client's primary group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    pub name: String,
    pub qtype: String,
    pub status: String,
    /// Response code, or null when nothing was sent.
    pub rcode: Option<String>,
    pub proto: String,
    /// The list whose rule blocked or allowed the query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list: Option<String>,
    /// `domain`, `modifier`, `regex`, `cname`, or `allow`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub total_ms: f64,
    pub upstream_ms: f64,
    pub response_bytes: u16,
    pub answers: u16,
}

/// A page of query-log rows, newest first.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct QueryPage {
    pub items: Vec<QueryRow>,
    /// Pass as `cursor` to get older rows; absent when there are none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// How much of the log this page looked at.
    pub scanned: ScanStats,
}

#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScanStats {
    pub segments: usize,
    pub blocks_read: usize,
    pub blocks_total: usize,
    pub rows_scanned: usize,
}

/// Query parameters for `GET /explain`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExplainParams {
    /// The name to explain.
    #[param(example = "ads.example.com")]
    pub name: String,
    /// The client's IP address. Default: 127.0.0.1.
    pub client: Option<String>,
    /// Query type. Default: `A`.
    pub qtype: Option<String>,
    /// The client's MAC address (default: from the neighbor table).
    pub mac: Option<String>,
}

/// Why a name is or isn't blocked for a client, and where it would go (FLT-013).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Explanation {
    pub name: String,
    pub qtype: String,
    pub client: ExplainClient,
    /// `refused`, `special`, `local`, `blocked`, `allowed`, or `resolved`.
    pub outcome: String,
    /// One sentence for people.
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<ExplainBlock>,
    /// Blocking is paused for this client until then (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paused_until_unix_seconds: Option<u64>,
    /// Every matching rule in precedence order; absent until a filter is loaded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<ExplainFilter>,
    /// Where a forwarded query goes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<ExplainRoute>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplainClient {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// The configured device it was recognized as.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// `client_id`, `edns_mac`, `neighbor_mac`, `ip`, `cidr`, or `default`.
    pub identified_by: String,
    /// Highest priority first.
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplainBlock {
    pub list: String,
    /// `null_ip`, `nxdomain`, `nodata`, `refused`, or `custom_ip`.
    pub mode: String,
    pub ttl_seconds: u32,
    pub ede_code: u16,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplainFilter {
    pub snapshot: Option<u64>,
    pub rules: Vec<ExplainRule>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplainRule {
    pub list: String,
    /// `important_allow`, `important_block`, `allow`, or `block`.
    pub tier: String,
    /// `domain`, `modifier`, or `regex`.
    pub kind: String,
    /// `subtree`, `exact`, or `subdomains`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The listed name that matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The client's groups use this list.
    pub enabled: bool,
    /// This rule decides the query.
    pub winner: bool,
    /// Where the rule is in the list.
    pub lines: Vec<ExplainLine>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplainLine {
    pub line: u32,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplainRoute {
    /// Upstream group.
    pub group: String,
    /// An explicit route matched (not just the default group).
    pub routed: bool,
}

/// A filter list and its download state.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListInfo {
    pub name: String,
    /// `block` or `allow`.
    pub kind: String,
    pub enabled: bool,
    /// URL, file path, or `inline`.
    pub source: String,
    /// `ok`, `failed`, or `pending` (not downloaded yet).
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub bytes: u64,
    pub lines: u64,
    /// Names this list contributes to the active snapshot.
    pub entries: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_checked_unix_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_changed_unix_seconds: Option<u64>,
}

/// A client group.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupInfo {
    pub name: String,
    pub priority: i32,
    /// Lists this group uses; null means every enabled list.
    pub lists: Option<Vec<String>>,
    /// `null_ip`, `nxdomain`, `nodata`, `refused`, or `custom_ip`.
    pub block_mode: String,
    pub block_ttl_seconds: u32,
    /// Blocking is paused for this group until then (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paused_until_unix_seconds: Option<u64>,
}

/// A configured client (device).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientInfo {
    pub name: String,
    /// IPs, CIDRs, MACs, or `id:<client-id>` this device is recognized by.
    #[serde(rename = "match")]
    pub matches: Vec<String>,
    /// Highest priority first.
    pub groups: Vec<String>,
}

/// An upstream server and its health.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamInfo {
    /// Stable ID (config order, from 1); query rows and latency rows refer to it.
    pub id: u16,
    pub name: String,
    /// `udp://…`, `tls://…`, `https://…`.
    pub endpoint: String,
    /// Groups it belongs to.
    pub groups: Vec<String>,
    /// Circuit breaker: `closed` (healthy), `open` (benched), or `half_open` (probing).
    pub breaker: String,
    pub requests: u64,
    pub failures: u64,
    /// Smoothed answer time.
    pub latency_ewma_ms: f64,
}

/// A list wrapper used by every collection endpoint.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Items<T> {
    pub items: Vec<T>,
}

/// Query parameters for `GET /queries/stream` (OBS-008). Filters combine with AND and are
/// applied on the server, before the rate cap.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct TailParams {
    /// Name to look for; see `match`.
    pub name: Option<String>,
    /// How to match `name`: `substring` (default), `exact`, `suffix`, or `glob` (`*`, `?`).
    #[serde(rename = "match")]
    #[param(rename = "match")]
    pub name_match: Option<NameMatch>,
    /// Client IP address.
    pub client: Option<String>,
    /// The client's group (its highest-priority group).
    pub group: Option<String>,
    /// Statuses, comma-separated (`blocked,forwarded`).
    pub status: Option<String>,
    /// Query types, comma-separated (`A,AAAA`).
    pub qtype: Option<String>,
    /// Upstream ID (from `GET /upstreams`).
    pub upstream: Option<u16>,
    /// Only queries that took at least this long.
    pub min_latency_ms: Option<u32>,
    /// Most events per second sent to this subscriber (1–2000, default 500). The rest are
    /// counted and reported in `dropped` events.
    pub rate: Option<u32>,
    /// `cluster` (default) or `node:local`.
    pub scope: Option<String>,
}

/// Sent as an SSE `dropped` event when matching queries weren't delivered.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TailDropped {
    /// How many matching queries were skipped since the last report.
    pub dropped: u64,
    /// `rate`: over this subscriber's `rate`; `lag`: the subscriber fell behind.
    pub reason: String,
}

/// What a live tail delivers.
#[derive(Debug, Clone)]
pub enum TailItem {
    Query(Box<QueryRow>),
    Dropped(TailDropped),
}
