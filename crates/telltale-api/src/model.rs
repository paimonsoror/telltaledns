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
    /// Present when this node belongs to a cluster (CLU-001).
    pub cluster: Option<ClusterInfo>,
    /// Exactly which build this is (ADR-046).
    pub build: BuildInfo,
    /// Whether a newer build exists on this build's channel (ADR-046).
    pub update: UpdateStatus,
}

/// The build identity (REQ: OPS-004, ADR-046): the same on every architecture of one commit.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BuildInfo {
    /// `0.1.0` (release), `0.1.0-edge.47` (main build), or `dev` (local build).
    pub version: String,
    /// Short commit SHA.
    pub commit: String,
    /// Build date (RFC 3339), or `unknown`.
    pub date: String,
    /// `stable`, `edge`, or `dev`.
    pub channel: String,
    /// Rust target, e.g. `aarch64-unknown-linux-musl`.
    pub target: String,
    /// `native`, `container`, or `helm`: decides how to update.
    pub install: String,
}

/// Update status from the signed release index (ADR-046).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatus {
    /// `up_to_date`, `available`, `newer` (this build is newer than the index, e.g. dev),
    /// `off` (`[updates] check = false`), or `unknown` (not checked yet, or failing).
    pub state: String,
    /// The newest version on this channel, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
    /// Its commit and date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_date: Option<String>,
    /// Release notes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes_url: Option<String>,
    /// When the index was last read successfully (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_unix_seconds: Option<u64>,
    /// Why the last check failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// How to update this install, step by step.
    pub how: String,
}

/// This node's cluster membership and the peers it holds a stream with.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterInfo {
    pub cluster_id: String,
    /// The name given at `telltale cluster init`.
    #[schema(example = "home")]
    pub name: String,
    /// This node's ID (from its key; stable across restarts).
    #[schema(example = "3f9c2a71d04b8e15")]
    pub node_id: String,
    #[schema(example = "home-pi")]
    pub site: String,
    /// Whether this node holds the cluster CA (the first node, until promotion arrives).
    pub primary: bool,
    /// When this node's cluster certificate expires (RFC 3339).
    pub cert_expires_at: String,
    /// The configuration version this node published (primary) or applied (replica), CLU-003.
    pub config_seq: u64,
    /// When that version was created on the primary (RFC 3339).
    pub config_created_at: Option<String>,
    /// When this node applied it (RFC 3339).
    pub config_applied_at: Option<String>,
    /// Blobs fetched for the last applied version (replicas).
    pub last_sync_fetched: u64,
    /// Fetch + apply time of the last sync, in milliseconds.
    pub last_sync_ms: u64,
    /// The last replication error, until the next success.
    pub sync_error: Option<String>,
    /// Peers this node has heard from since it started.
    pub peers: Vec<ClusterPeer>,
}

/// A peer node, as last heard over the cluster channel.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterPeer {
    pub node_id: String,
    pub site: String,
    pub version: String,
    /// Heard from within the last three heartbeats (15 s).
    pub up: bool,
    pub primary: bool,
    pub last_seen_seconds_ago: u64,
    /// `inbound` (it connected to us) or `outbound`.
    pub via: String,
    /// The configuration version the peer reports as applied (the primary: published).
    pub config_seq: u64,
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

/// Which nodes' data an analytics call reads (`spec/07` §1, `spec/12` §6, AGT-011). On a
/// standalone node, `cluster` and `node:local` both mean this node.
#[derive(Debug, Clone, Default, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct ScopeParam {
    /// `cluster` (default, every node), `site:<name>`, `node:<name or ID>`, or `node:local`
    /// (this node). Federated reads list nodes that didn't answer in `missingNodes`.
    #[param(example = "cluster")]
    pub scope: Option<String>,
}

/// Counts for one time bucket.
#[derive(Debug, Clone, Default, Serialize, ToSchema, Deserialize)]
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
    /// Queries by the client's group (ADR-050). Empty for buckets read from rollups.
    #[serde(default)]
    pub by_group: BTreeMap<String, u32>,
    /// Blocked queries by group.
    #[serde(default)]
    pub blocked_by_group: BTreeMap<String, u32>,
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
    /// `cluster` (default, every node), `site:<name>`, `node:<name or ID>`, or `node:local`
    /// (this node). Federated reads list nodes that didn't answer in `missingNodes`.
    pub scope: Option<String>,
}

/// Totals over a time range.
#[derive(Debug, Clone, Default, Serialize, ToSchema, Deserialize)]
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
    /// Cluster nodes that couldn't be read (CLU-002).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
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
    /// `cluster` (default, every node), `site:<name>`, `node:<name or ID>`, or `node:local`
    /// (this node). Federated reads list nodes that didn't answer in `missingNodes`.
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
    /// Which list: `domains`, `blocked`, `nxdomain`, or `clients`.
    pub kind: TopKind,
    /// Items to return (1–100, default 10).
    pub limit: Option<usize>,
    /// Default: `current`.
    pub hour: Option<Hour>,
    /// Only this client's domains (an IP address; `kind=domains` only).
    pub client: Option<String>,
    /// Only this group's queries (a group name; not with `client`, not for `nxdomain`).
    pub group: Option<String>,
    /// `cluster` (default, every node), `site:<name>`, `node:<name or ID>`, or `node:local`
    /// (this node). Federated reads list nodes that didn't answer in `missingNodes`.
    pub scope: Option<String>,
}

/// One ranked item. Counts come from a Space-Saving sketch: the true count lies in
/// `[count - errorBound, count]`.
#[derive(Debug, Clone, Serialize, ToSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopItem {
    /// Domain name or client address.
    pub key: String,
    /// The configured device name, for clients that have one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub count: u64,
    pub error_bound: u64,
    /// For clients: the groups whose settings apply to it, highest priority first (its
    /// device's groups, else its network's group, else the default; ADR-050).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
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
    /// What to break latency down by: `stage`, `upstream`, `client`, or `qtype`.
    pub by: LatencyBy,
    /// Default: `current`.
    pub hour: Option<Hour>,
    /// `cluster` (default, every node), `site:<name>`, `node:<name or ID>`, or `node:local`
    /// (this node). Federated reads list nodes that didn't answer in `missingNodes`.
    pub scope: Option<String>,
}

/// Latency percentiles for one key (HDR histogram, 2 significant digits).
#[derive(Debug, Clone, Serialize, ToSchema, Deserialize)]
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
#[derive(Debug, Clone, Default, Deserialize, IntoParams, Serialize)]
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
    /// Only queries from devices in this group (a group name, ADR-050).
    pub group: Option<String>,
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
    /// `cluster` (default, every node), `site:<name>`, `node:<name or ID>`, or `node:local`
    /// (this node). Federated reads list nodes that didn't answer in `missingNodes`.
    pub scope: Option<String>,
}

/// One logged query.
#[derive(Debug, Clone, Serialize, ToSchema, Deserialize)]
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
    /// The node that answered it (federated reads: its site).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
}

/// A page of query-log rows, newest first.
#[derive(Debug, Clone, Serialize, ToSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryPage {
    pub items: Vec<QueryRow>,
    /// Pass as `cursor` to get older rows; absent when there are none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// How much of the log this page looked at.
    pub scanned: ScanStats,
    /// Cluster nodes that couldn't be read (CLU-002: partial results, never a hang).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, ToSchema, Deserialize)]
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
    /// REQ: OBS-009 (T7.14) — names no other list has (what removing it would lose).
    pub unique: u64,
    /// Queries it blocked (or allowed, for an allow list) on this node since it started.
    pub hits: u64,
    /// Lists it shares names with, most shared first.
    pub overlap: Vec<ListShare>,
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
    /// Networks (CIDRs) whose devices belong to this group (ADR-050).
    pub networks: Vec<String>,
    /// `#rrggbb` for charts and chips (configured, or a stable pick).
    pub color: String,
    /// Queries from the group's devices over the last 24 hours.
    pub queries_24h: u64,
    /// Of those, blocked.
    pub blocked_24h: u64,
    /// Devices seen in the group this hour.
    pub devices_this_hour: u64,
    /// REQ: FLT-012 (T7.9) — services this group blocks (IDs from `GET /api/v1/services`).
    pub blocked_services: Vec<String>,
    /// REQ: FLT-010 (T7.10) — the group's schedules, and which of them are on now.
    pub schedules: Vec<String>,
    pub schedules_on: Vec<String>,
    /// REQ: FLT-011 (T7.11) — safe search, and YouTube's restriction: `strict`, `moderate`,
    /// or `off` (absent when safe search is off).
    pub safe_search: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub youtube_restrict: Option<String>,
    /// REQ: FLT-014 (T7.20) — private addresses in public answers are blocked (DNS
    /// rebinding protection), and the networks whose answers are filtered.
    pub rebinding_protection: bool,
    pub block_answer_ips: Vec<String>,
    /// REQ: FLT-015 (T7.20) — names answered with a fixed address or name.
    pub rewrites: Vec<RewriteInfo>,
    /// REQ: DNS-016 (T7.21) — AAAA answers synthesized for IPv4-only names (DNS64), and the
    /// prefix (`64:ff9b::/96` unless set).
    pub dns64: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns64_prefix: Option<String>,
}

/// A group's rewrite: `domain` (or `*.domain`) answered with `answer`.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RewriteInfo {
    #[schema(example = "nas.example.com")]
    pub domain: String,
    /// An address, or a name (answered as a CNAME).
    #[schema(example = "192.168.1.20")]
    pub answer: String,
}

/// REQ: DNS-018 (T7.22) — an authoritative zone from `[[zone]]`.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ZoneInfo {
    /// The apex.
    #[schema(example = "home.example.com")]
    pub name: String,
    /// Groups that see it (split horizon); empty: everyone.
    pub groups: Vec<String>,
    /// Records loaded (from the file and inline).
    pub records: u64,
    /// The zone file, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// TTL of its NXDOMAIN and no-data answers.
    pub negative_ttl_seconds: u32,
}

/// REQ: FLT-012 (T7.9) — a blockable service.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    /// For `blocked_services` in a group.
    #[schema(example = "tiktok")]
    pub id: String,
    #[schema(example = "TikTok")]
    pub name: String,
    /// `social`, `video`, `music`, `gaming`, `messaging`, `dating`, `ai`, ...
    pub category: String,
    /// The domains it blocks (with everything under them).
    pub domains: Vec<String>,
}

/// A configured client (device).
#[derive(Debug, Clone, Serialize, ToSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientInfo {
    pub name: String,
    /// IPs, CIDRs, MACs, or `id:<client-id>` this device is recognized by.
    #[serde(rename = "match")]
    pub matches: Vec<String>,
    /// Highest priority first.
    pub groups: Vec<String>,
    /// `file` (defined in the config files: read-only here) or `api` (named in the UI or
    /// through the API: editable with `PUT /clients/{name}`).
    #[schema(example = "api")]
    pub source: String,
    /// The groups that actually apply, highest priority first: `groups` when set, else the
    /// group of the network its addresses are in (ADR-050), else the default group. Empty
    /// when it depends on the address it's seen at (a device known only by MAC).
    #[serde(default)]
    pub effective_groups: Vec<String>,
    /// Where `effectiveGroups` comes from: `device`, `network`, or `default`.
    #[serde(default)]
    #[schema(example = "network")]
    pub groups_from: String,
}

/// A device to create, rename, or change (`PUT /api/v1/clients/{name}`, API-010).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientInput {
    /// The new name, to rename the device (default: the name in the path).
    #[schema(example = "Living room TV")]
    pub name: Option<String>,
    /// How to recognize it: IPs, CIDRs, MACs (`aa:bb:cc:dd:ee:ff`), or `id:<client-id>`.
    #[serde(rename = "match")]
    #[schema(example = json!(["192.168.1.42"]))]
    pub matches: Vec<String>,
    /// Groups, highest priority first (default `["default"]`).
    #[serde(default)]
    pub groups: Vec<String>,
}

/// What a device change did, or would do with `dryRun=true` (AGT-002).
#[derive(Debug, Clone, Serialize, ToSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientChange {
    /// False for a dry run.
    pub applied: bool,
    /// The configuration version after the change (send it as `If-Match` next time).
    pub config_version: u64,
    /// The device before the change (absent when it's new).
    pub before: Option<ClientInfo>,
    /// The device after the change (absent after a delete).
    pub after: Option<ClientInfo>,
    /// Queries in the current and previous hour from the addresses it matches: how much
    /// history gets the new label (names are resolved when read, so the past is relabelled).
    pub recent_queries: u64,
    /// What the change does, in one sentence, with the numbers (AGT-002 impact estimate).
    #[serde(default)]
    pub impact: String,
    /// Configuration warnings after the change.
    pub warnings: Vec<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Items<T> {
    pub items: Vec<T>,
    /// Cluster nodes that couldn't be read, for federated reads (CLU-002).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

/// Query parameters for `GET /queries/stream` (OBS-008). Filters combine with AND and are
/// applied on the server, before the rate cap.
#[derive(Debug, Clone, Default, Serialize, Deserialize, IntoParams)]
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
    /// `cluster` (default: every reachable node's queries, each row naming its node),
    /// `site:<name>`, `node:<id or site>`, or `node:local` (this node only).
    pub scope: Option<String>,
}

/// Sent as an SSE `dropped` event when matching queries weren't delivered.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TailDropped {
    /// How many matching queries were skipped since the last report.
    pub dropped: u64,
    /// `rate`: over this subscriber's `rate`; `lag`: the subscriber fell behind.
    pub reason: String,
}

/// What a live tail delivers (also sent between cluster nodes, T9.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "item", rename_all = "snake_case")]
pub enum TailItem {
    Query(Box<QueryRow>),
    Dropped(TailDropped),
}

/// REQ: OBS-010 (T9.5) — a device seen for the first time (internal: alerts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewDevice {
    pub client: String,
    pub client_name: Option<String>,
    pub first_seen_unix_seconds: u64,
}

/// REQ: CLU-002 (T9.2) — one latency histogram, as `(microseconds, count)` pairs: what
/// cluster nodes send each other so percentiles merge exactly. Internal (not an API route).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyHist {
    pub key: String,
    pub buckets: Vec<(u64, u64)>,
}

/// One record of a local name.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordInput {
    /// `A`, `AAAA`, `CNAME` (Simple); `PTR`, `TXT`, `MX`, `SRV` (Advanced).
    #[serde(rename = "type")]
    #[schema(example = "A")]
    pub rtype: String,
    /// An address for A/AAAA, a name for CNAME/PTR, text for TXT, `"10 mail.home.arpa"` for MX,
    /// `"0 5 5060 pbx.home.arpa"` for SRV.
    #[schema(example = "192.168.1.10")]
    pub value: String,
    /// TTL in seconds (default: `[local] default_ttl`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

/// A local name's records (`PUT /api/v1/records/{name}`).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordsInput {
    pub records: Vec<RecordInput>,
}

/// A name TelltaleDNS answers itself.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LocalName {
    #[schema(example = "nas.home.arpa")]
    pub name: String,
    pub records: Vec<RecordInput>,
    /// `file` (read-only here) or `api`.
    pub source: String,
}

/// The servers a domain is sent to (`PUT /api/v1/forwards/{domain}`).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForwardInput {
    /// Addresses (plain DNS) or `udp://`, `tcp://`, `tls://`, `https://` URLs, tried in order.
    #[schema(example = json!(["10.0.0.53"]))]
    pub servers: Vec<String>,
}

/// REQ: DNS-006 (T6.13) — one node's cache counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheNodeStats {
    /// The node (its site), or absent for a standalone node.
    pub node: Option<String>,
    pub entries: u64,
    pub bytes: u64,
    pub hits: u64,
    pub misses: u64,
    /// hits / (hits + misses), percent; absent before any lookup.
    pub hit_percent: Option<f64>,
    pub stale_served: u64,
    pub prefetches: u64,
    pub evictions: u64,
    pub inserts: u64,
    pub uncacheable: u64,
    /// REQ: DNS-006, OBS-003 (T6.15) — the `[cache]` settings in effect (absent from older
    /// nodes).
    #[serde(default)]
    pub settings: Option<CacheSettings>,
    /// Whether the cache was reloaded from its dump at the last start (DNS-009).
    #[serde(default)]
    pub warm_start: Option<CacheWarmStart>,
    /// The last hour, every 15 s, oldest first (empty from older nodes).
    #[serde(default)]
    pub history: Vec<CachePoint>,
}

/// REQ: DNS-006 (T6.15) — the `[cache]` settings a node runs with.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheSettings {
    /// Memory budget for cached answers.
    pub max_bytes: u64,
    /// Entry cap; absent: limited by memory only.
    pub max_entries: Option<u64>,
    pub min_ttl_seconds: u32,
    pub max_ttl_seconds: u32,
    /// Cap for negative answers (NXDOMAIN, no data), RFC 2308.
    pub negative_ttl_max_seconds: u32,
    /// How long SERVFAIL is cached, RFC 9520.
    pub servfail_ttl_seconds: u32,
    /// Serve expired answers when upstreams fail (RFC 8767).
    pub serve_stale: bool,
    /// How long expired answers are kept for that.
    pub stale_max_age_seconds: u32,
    /// Refresh popular answers before they expire.
    pub prefetch: bool,
    /// Prefetch below this share of the TTL left.
    pub prefetch_threshold_percent: u8,
    /// ...for answers asked at least this often.
    pub prefetch_min_hits: u32,
    /// Keep the cache across restarts.
    pub persist: bool,
}

/// REQ: DNS-009 (T6.15) — what happened to the cache dump at the last start.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheWarmStart {
    /// When (RFC 3339).
    pub at: String,
    /// Answers reloaded; absent when nothing was loaded.
    pub loaded: Option<u64>,
    /// Why nothing was loaded (no dump, a dump from other upstreams, ...).
    pub note: Option<String>,
}

/// REQ: OBS-003 (T6.15) — 15 s of one node's cache.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CachePoint {
    /// End of the interval (RFC 3339).
    pub at: String,
    /// Hits per lookup in the interval, percent; absent without lookups.
    pub hit_percent: Option<f64>,
    pub lookups: u64,
    pub stale_served: u64,
    pub prefetches: u64,
    pub evictions: u64,
    /// At the end of the interval.
    pub entries: u64,
    pub bytes: u64,
}

/// REQ: DNS-006, OBS-003 (T6.15) — what the cache holds by kind (entries).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheMakeup {
    /// Answers with records.
    pub positive: u64,
    /// The name doesn't exist.
    pub nxdomain: u64,
    /// The name exists, but not with that type.
    pub nodata: u64,
    pub servfail: u64,
    /// Expired, kept only to serve stale when upstreams fail.
    pub stale: u64,
    /// DNSSEC-validated.
    pub validated: u64,
}

/// One entry in a node's top list.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheTopEntry {
    #[schema(example = "www.example.com")]
    pub name: String,
    #[schema(example = "A")]
    pub qtype: String,
    #[schema(example = "NOERROR")]
    pub rcode: String,
    pub answers: u16,
    pub authentic: bool,
    pub dnssec_ok: bool,
    /// Seconds until it goes stale; negative: how long it has been stale.
    pub ttl_left_seconds: i64,
    pub age_seconds: u64,
    pub bytes: u64,
    pub hits: u32,
}

/// One node's top entries and makeup (`GET /api/v1/cache/entries`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheNodeEntries {
    /// The node (absent on a standalone node).
    pub node: Option<String>,
    pub makeup: CacheMakeup,
    pub entries: Vec<CacheTopEntry>,
    /// Set when the node couldn't be asked.
    pub error: Option<String>,
}

/// REQ: API-002 (T7.5, ADR-069) — one upstream, upstream group, list, or group: its definition
/// in effect and where it comes from.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigEntry {
    /// `upstream`, `upstream_group`, `list`, or `group`.
    pub kind: String,
    pub name: String,
    /// `file` (the config files), `added` (made through the UI or API), `override` (replaces
    /// the files' entry of that name), or `hidden` (the files' entry is left out).
    pub source: String,
    /// The definition in effect, with the same fields as in `telltale.toml` (absent when
    /// hidden).
    #[schema(value_type = Option<Object>)]
    pub definition: Option<serde_json::Value>,
}

/// `GET /api/v1/config/entries` parameters.
#[derive(Debug, Clone, Default, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EntriesQuery {
    /// One kind only: `upstream`, `upstream_group`, `list`, or `group`.
    pub kind: Option<String>,
}

/// REQ: FLT-009 (T7.1) — pause or resume blocking (`POST /api/v1/blocking/pause|resume`).
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlockingRequest {
    /// Pause only: for how long, 1 to 1,440 (agents: at most 60).
    #[schema(example = 15)]
    pub minutes: Option<u32>,
    /// One group's devices only; absent: everyone (resume: every pause).
    #[schema(example = "kids")]
    pub group: Option<String>,
    /// One node only (its site, pod, or ID); absent: every node.
    pub node: Option<String>,
}

/// One active pause.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PauseInfo {
    /// The group paused; absent: everyone.
    pub group: Option<String>,
    /// When blocking turns back on (RFC 3339).
    pub until: String,
    pub seconds_left: u64,
}

/// One node's pauses (`GET /api/v1/blocking`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BlockingNode {
    /// The node (absent on a standalone node).
    pub node: Option<String>,
    /// Active pauses; empty: blocking is on.
    pub pauses: Vec<PauseInfo>,
    /// Set when the node couldn't be reached.
    pub error: Option<String>,
}

/// One cached answer for a name.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheEntry {
    /// The node holding it (absent on a standalone node).
    pub node: Option<String>,
    #[schema(example = "A")]
    pub qtype: String,
    #[schema(example = "NOERROR")]
    pub rcode: String,
    pub answers: u16,
    /// DNSSEC-validated (the AD bit).
    pub authentic: bool,
    /// The variant for clients that set DO (they get DNSSEC records).
    pub dnssec_ok: bool,
    /// The variant for clients that set CD (checking disabled).
    pub checking_disabled: bool,
    /// Seconds until it goes stale; negative: how long it has been stale.
    pub ttl_left_seconds: i64,
    pub age_seconds: u64,
    pub bytes: u64,
    pub hits: u32,
}

/// What the cache holds for a name.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheLookup {
    pub name: String,
    pub entries: Vec<CacheEntry>,
}

/// What to flush (`POST /api/v1/cache/flush`).
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CacheFlushRequest {
    /// A name; absent: everything.
    #[schema(example = "www.example.com")]
    pub name: Option<String>,
    /// Also every name under `name`.
    pub subtree: Option<bool>,
    /// One node only (its site or ID); absent: every node.
    pub node: Option<String>,
}

/// What one node removed.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheFlushNode {
    pub node: Option<String>,
    /// Entries removed; absent when the node couldn't be reached.
    pub removed: Option<u64>,
    pub error: Option<String>,
}

/// The result of a flush.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheFlushResult {
    pub total_removed: u64,
    pub nodes: Vec<CacheFlushNode>,
}

/// REQ: FLT-005 (T6.12, ADR-067) — a quick rule to create or replace
/// (`PUT /api/v1/rules/{id}`).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleInput {
    /// `allow` or `block`.
    #[schema(example = "allow")]
    pub action: String,
    /// The domain; its subdomains are included.
    #[schema(example = "game.example.com")]
    pub domain: String,
    /// Device names, IPs, or CIDRs it applies to.
    #[serde(default)]
    pub devices: Vec<String>,
    /// Groups it applies to. With neither devices nor groups: everyone.
    #[serde(default)]
    pub groups: Vec<String>,
    /// When it stops applying (RFC 3339). Use this or `forMinutes`; neither means never.
    #[serde(default)]
    pub expires: Option<String>,
    /// Stop applying this many minutes from now.
    #[serde(default)]
    pub for_minutes: Option<u32>,
    /// Why it exists, shown with every decision it makes.
    #[serde(default)]
    pub note: Option<String>,
}

/// A quick rule (files and API), with how long it has left.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleInfo {
    pub id: String,
    /// `allow` or `block`.
    pub action: String,
    pub domain: String,
    pub devices: Vec<String>,
    pub groups: Vec<String>,
    /// RFC 3339, when it stops applying.
    pub expires: Option<String>,
    /// Seconds until it expires (0 once it has).
    pub expires_in_seconds: Option<u64>,
    pub note: Option<String>,
    pub created_by: Option<String>,
    pub created: Option<String>,
    /// `file` (read-only here) or `api`.
    pub source: String,
}

/// A domain sent to other servers (conditional forwarding).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ForwardInfo {
    #[schema(example = "corp.example")]
    pub domain: String,
    /// The servers (upstream URLs), in order.
    pub servers: Vec<String>,
    /// `file` (read-only here) or `api`.
    pub source: String,
}

/// What a change to local names or forwarded domains did (or would do, with `dryRun`).
#[derive(Debug, Clone, Serialize, ToSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigChange {
    /// False for a dry run.
    pub applied: bool,
    /// The configuration version after the change (send it as `If-Match` next time).
    pub config_version: u64,
    /// The entry before (absent when new).
    #[schema(value_type = Option<Object>)]
    pub before: Option<serde_json::Value>,
    /// The entry after (absent after a delete).
    #[schema(value_type = Option<Object>)]
    pub after: Option<serde_json::Value>,
    /// Queries in the current and previous hour for the name (or names under the domain)
    /// that the change affects. A lower bound: counted from the busiest names.
    #[serde(default)]
    pub recent_queries: u64,
    /// What the change does, in one sentence, with the numbers (AGT-002 impact estimate).
    #[serde(default)]
    pub impact: String,
    /// Configuration warnings after the change.
    pub warnings: Vec<String>,
    /// REQ: API-002 (T7.5, ADR-069) — on a node whose configuration comes from Git: the TOML
    /// to add to (or the block to remove from) the repository or the Helm values' `config:` to
    /// make this change permanent there. Changes made through the API live in this node's
    /// `state.db`, not in Git. Absent on other nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_in_git: Option<String>,
}

/// A DHCP lease (REQ: OPS-008).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DhcpLease {
    pub mac: String,
    pub ip: String,
    /// The name the device gave (option 12), or its reservation's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// The device's name in TelltaleDNS (a named client, else the host name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    pub expires_unix_seconds: u64,
    /// A reservation (`[[dhcp.reservation]]`).
    pub reserved: bool,
    /// `dhcp` (this node's DHCP server), `router` (read from a `[[router]]`), or `mdns` (the
    /// name the device announces, `[clients] mdns`; no MAC).
    pub source: String,
}

/// Names a list shares with another (OBS-009).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListShare {
    pub list: String,
    pub names: u64,
}

/// `GET /analytics/vqlog` parameters (REQ: AGT-012).
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct VqlogParams {
    /// The query, for example `from -24h | where status = blocked | top 10 name`.
    #[param(example = "from -24h | where status = blocked | top 10 name")]
    pub q: String,
    /// Only parse and estimate the cost; don't scan.
    #[serde(rename = "dryRun")]
    pub dry_run: Option<bool>,
}

/// What a `vqlog` query costs (REQ: AGT-012).
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VqlogCost {
    /// Before scanning, from block headers: how many logged queries could match at most.
    pub estimated_rows: u64,
    pub segments: usize,
    pub blocks: usize,
    /// What the scan did (0 for a dry run).
    pub rows_scanned: u64,
    pub rows_matched: u64,
    pub elapsed_ms: u64,
}

/// A `vqlog` result: a table (REQ: AGT-012).
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VqlogResult {
    /// The query as understood, with the defaults filled in.
    pub query: String,
    /// `time` (with `bucket`), the keys (a `client` key adds `clientName`), then the
    /// statistics. Latencies are in ms.
    pub columns: Vec<String>,
    /// One array per row, in column order.
    #[schema(value_type = Vec<Vec<Object>>)]
    pub rows: Vec<Vec<serde_json::Value>>,
    /// Groups found before `limit`.
    pub groups: u64,
    pub cost: VqlogCost,
    /// The scan stopped early (`truncatedReason` says why); the numbers cover what it read.
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_reason: Option<String>,
    /// Cluster nodes whose query log isn't here (not shipped to this node).
    pub missing_nodes: Vec<String>,
}

/// `GET /analytics/new-domains` parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct NewDomainParams {
    /// Only domains first seen after this (RFC 3339 or relative, default `-24h`).
    pub since: Option<String>,
    /// Only this device (its address).
    pub client: Option<String>,
    /// At most this many (default 200, at most 2000).
    pub limit: Option<usize>,
}

/// A registrable domain a device contacted for the first time (REQ: OBS-009).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NewDomain {
    /// When it was first seen (RFC 3339).
    pub time: String,
    pub client: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[schema(example = "vendor.example")]
    pub domain: String,
    /// How machine-generated its name looks, 0 to 1 (0.6 and up is suspicious; `06` §7).
    pub dga_score: f32,
}

/// `GET /analytics/anomalies` parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AnomalyParams {
    /// Only findings whose window started after this (RFC 3339 or relative, default `-7d`).
    pub since: Option<String>,
}

/// A device anomaly and its evidence (OBS-013). Alert-only: TelltaleDNS never acts on it.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyFinding {
    /// `rate_spike`, `domain_volume`, `drift`, `beacon`, `nxdomain_storm`, or `dga`.
    #[schema(example = "domain_volume")]
    pub kind: String,
    /// The device's address, and its name when known.
    pub client: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// The registrable domain, for domain findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "vendor.example")]
    pub domain: Option<String>,
    /// The window examined (RFC 3339 start, and length in seconds).
    pub window_start: String,
    pub window_seconds: u32,
    /// What was seen, the device's usual value (± spread), and the bar it crossed.
    pub observed: f64,
    pub baseline: f64,
    pub spread: f64,
    pub threshold: f64,
    /// The finding in words, with the numbers.
    #[schema(example = "4100 queries in an hour; usually 119 ± 30")]
    pub detail: String,
}

/// The cluster as this node sees it (REQ: CLU-008): every node with its health, sync, and
/// serving state, a timeline, and a pass/fail check list.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterView {
    /// False on a standalone node (everything else is then empty).
    pub enabled: bool,
    pub cluster_id: Option<String>,
    pub name: Option<String>,
    /// The node answering this request.
    pub this_node: Option<String>,
    /// The newest configuration version any node reports.
    pub newest_config_seq: u64,
    /// Every check passed.
    pub healthy: bool,
    pub checks: Vec<ClusterCheck>,
    /// This node first, then peers by site and ID.
    pub nodes: Vec<ClusterNode>,
    /// Recent events, newest first.
    pub events: Vec<ClusterEvent>,
    /// Where the cluster's configuration comes from: `api` or `gitops` (ADR-048).
    pub authority: Option<String>,
    /// Versions this node published that the cluster moved on without (ADR-051), newest first.
    pub conflicts: Vec<ClusterConflict>,
    /// How the cluster fails over (ADR-056).
    pub failover: Option<ClusterFailover>,
    /// The Git repository the configuration comes from, when it does (ADR-049).
    pub source: Option<ClusterSource>,
    /// A standalone node's own machine (T6.11); in a cluster, each node carries its own.
    pub host: Option<HostReport>,
}

/// REQ: CLU-008 (T6.11) — the machine a node runs on: its latest sample, what looks wrong,
/// and the last hour. Values the node couldn't read are absent (see `unavailable`).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HostReport {
    pub latest: HostInfo,
    /// Up to an hour of samples (every 15 s), oldest first.
    pub history: Vec<HostPoint>,
}

/// One host sample, with sizes in bytes and shares in percent.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HostInfo {
    /// When it was sampled (RFC 3339, the node's clock).
    pub sampled_at: String,
    pub os: Option<String>,
    pub kernel: Option<String>,
    pub arch: String,
    pub host_uptime_seconds: Option<u64>,
    pub cpus: Option<u32>,
    pub load1: Option<f64>,
    pub load5: Option<f64>,
    pub load15: Option<f64>,
    /// Host CPU busy over the last 15 s.
    pub cpu_percent: Option<f64>,
    pub mem_total_bytes: Option<u64>,
    pub mem_available_bytes: Option<u64>,
    /// `100 × (1 − available / total)`.
    pub mem_used_percent: Option<f64>,
    pub swap_total_bytes: Option<u64>,
    pub swap_used_bytes: Option<u64>,
    /// The container's (cgroup's) memory limit, when it has one.
    pub cgroup_mem_limit_bytes: Option<u64>,
    pub cgroup_mem_used_bytes: Option<u64>,
    pub cgroup_mem_used_percent: Option<f64>,
    /// Processes killed for lack of memory in this container, ever.
    pub oom_kills: Option<u64>,
    /// The container's CPU quota, in cores.
    pub cgroup_cpu_quota_cores: Option<f64>,
    /// Share of the last 15 s the container was throttled by its quota.
    pub throttled_percent: Option<f64>,
    /// The filesystem holding the data directory.
    pub disk_total_bytes: Option<u64>,
    pub disk_free_bytes: Option<u64>,
    pub disk_used_percent: Option<f64>,
    pub qlog_bytes: Option<u64>,
    pub snapshot_bytes: Option<u64>,
    /// What this process writes to storage (SD-card wear on a Pi).
    pub write_bytes_per_second: Option<u64>,
    pub process_rss_bytes: Option<u64>,
    pub open_fds: Option<u32>,
    pub max_fds: Option<u32>,
    pub threads: Option<u32>,
    /// The hottest thermal zone (on a Pi, the system-on-chip).
    pub temperature_c: Option<f64>,
    /// Its clock minus this node's, from heartbeats (peers only).
    pub clock_offset_ms: Option<i64>,
    /// Sources it couldn't read: `memory`, `load`, `cpu`, `process`, `cgroup`, `thermal`,
    /// `disk`, `os`.
    pub unavailable: Vec<String>,
    /// What looks wrong, in plain words (low disk, memory pressure, heat, clock drift).
    pub warnings: Vec<String>,
}

/// A point of the last hour, for trend lines.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HostPoint {
    /// Unix seconds.
    pub t: u64,
    pub cpu_percent: Option<f64>,
    pub mem_used_percent: Option<f64>,
    pub load1: Option<f64>,
    pub disk_used_percent: Option<f64>,
    pub temperature_c: Option<f64>,
}

/// The cluster's configuration from Git (ADR-049): the commit in use and the last check.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterSource {
    pub repo: String,
    pub git_ref: String,
    pub path: String,
    /// The commit every node should be serving.
    pub commit: Option<String>,
    pub author: Option<String>,
    /// Commit time (RFC 3339).
    pub committed_at: Option<String>,
    pub subject: Option<String>,
    /// The allowed signer who signed it (with `require_signed`).
    pub signed_by: Option<String>,
    /// When the primary last checked the ref (RFC 3339; on the primary only).
    pub checked_at: Option<String>,
    /// Why the last check failed, or why the newest commit was refused.
    pub error: Option<String>,
    /// The newest commit isn't acceptable (invalid, unsigned, rewound): the cluster stays on
    /// `commit`.
    pub refused: bool,
}

/// Automatic failover as this node sees it (ADR-056).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterFailover {
    /// `manual` (promote by hand) or `auto` (elected by vote).
    pub mode: String,
    /// Whether elections run: `auto`, with three or more voters, this node one of them.
    pub active: bool,
    /// Eligible nodes plus witnesses.
    pub voters: u32,
    /// Voters this node has a stream to (itself included).
    pub reachable_voters: u32,
    /// This node is the elected primary and its lease holds.
    pub lease_held: bool,
    /// How long its lease still runs, in seconds (primaries only).
    pub lease_seconds_left: Option<f64>,
    /// The epoch and node this node last voted for.
    pub voted_epoch: u64,
    pub voted_for: Option<String>,
}

/// A version an old primary published after a newer primary took over: never applied
/// anywhere; listed so the change can be re-made on the current primary.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterConflict {
    pub epoch: u64,
    pub seq: u64,
    /// When this node published it (RFC 3339).
    pub published_at: String,
    /// When the newer primary's version arrived (RFC 3339).
    pub detected_at: String,
    pub new_primary: String,
    /// Settings that differ from the current primary's version (dotted paths).
    pub changed: Vec<String>,
}

/// `POST /api/v1/cluster/promote`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PromoteRequest {
    /// Promote even though this node can't publish configuration under the cluster's
    /// authority (configuration from Git, and no Git-managed node reachable): it coordinates the
    /// cluster and keeps the last version, and publishes nothing new (ADR-048).
    #[serde(default)]
    pub emergency: bool,
}

/// What promoting this node would do (`POST /cluster/promote?dryRun=true`, AGT-002).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PromotePlan {
    /// Always false: nothing changed.
    pub applied: bool,
    /// The epoch this node would take.
    pub epoch: u64,
    /// It would coordinate without publishing new configuration (ADR-048).
    pub emergency: bool,
    /// What would happen, in one sentence.
    pub impact: String,
}

/// One node in [`ClusterView`].
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[allow(clippy::struct_excessive_bools)] // independent flags of one record
#[serde(rename_all = "camelCase")]
pub struct ClusterNode {
    pub node_id: String,
    pub site: String,
    /// A Kubernetes resolver pod (CLU-009): dropped when no longer heard from.
    pub ephemeral: bool,
    /// Votes in automatic failover only (ADR-056).
    pub witness: bool,
    /// The cluster protocol it speaks (CLU-010); nodes within one version work together.
    pub protocol: u32,
    /// The Git commit of the configuration it serves (ADR-049).
    pub source_commit: Option<String>,
    /// `primary` or `replica`.
    pub role: String,
    /// The node answering this request.
    pub this_node: bool,
    pub eligible: bool,
    pub version: String,
    /// Heard from within 15 s (always true for this node).
    pub up: bool,
    /// A stream to it is open (this node: n/a, true).
    pub connected: bool,
    /// `self`, `inbound` (it connected to this node), or `outbound`.
    pub link: String,
    pub last_seen_seconds_ago: u64,
    /// Round-trip time over the cluster link.
    pub rtt_ms: Option<u32>,
    pub config_seq: u64,
    /// Versions behind the newest.
    pub config_lag: u64,
    /// How long it has been behind (absent when in sync).
    pub behind_seconds: Option<u64>,
    /// Serving DNS (listeners bound, not shutting down).
    pub ready: bool,
    /// Queries per second over the last minute.
    pub qps: u64,
    /// SERVFAIL share over the last minute, percent.
    pub servfail_percent: f64,
    /// Upstream p90 this hour.
    pub upstream_p90_ms: f64,
    pub uptime_seconds: u64,
    /// This node only: when its cluster certificate expires (RFC 3339).
    pub cert_expires_at: Option<String>,
    /// How the node's own configuration is managed: `gitops` or `file` (ADR-048).
    pub config_source: Option<String>,
    /// The machine it runs on (T6.11); absent from older nodes and before the first sample.
    pub host: Option<HostReport>,
    /// REQ: CLU-008 (T6.14) — the Kubernetes node and pod it runs in (absent elsewhere and
    /// from older nodes).
    pub kube_node: Option<String>,
    pub pod: Option<String>,
    /// When its process started (RFC 3339); absent from older nodes.
    pub started_at: Option<String>,
    /// Restarts this node has seen since it started itself (0 for this node).
    pub restarts: u32,
    /// Its cache: entries, and the hit rate over the last minute (absent without lookups).
    pub cache_entries: Option<u64>,
    pub cache_hit_percent: Option<f64>,
    /// Its share of the queries the nodes that are up answered over the last minute, percent
    /// (absent when there were none).
    pub query_share_percent: Option<f64>,
}

/// A cluster event (joins, connections, published and applied versions, failures).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterEvent {
    /// RFC 3339.
    pub at: String,
    /// `joined`, `connected`, `disconnected`, `restarted`, `published`, `applied`,
    /// `sync_failed`, `rejected`.
    pub kind: String,
    pub node_id: String,
    pub detail: String,
}

/// One health check with a plain-language fix when it fails.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterCheck {
    /// Stable ID: `peers_up`, `primary_present`, `in_sync`, `sync_errors`, `serving`, `certificate`.
    pub id: String,
    pub ok: bool,
    pub summary: String,
    /// What to do about it (failing checks only).
    pub fix: Option<String>,
}
