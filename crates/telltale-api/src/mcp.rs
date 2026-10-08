//! The MCP server (REQ: AGT-006, AGT-009; T6.6, ADR-010, ADR-065): `POST /mcp` speaks the
//! Model Context Protocol (JSON-RPC 2.0 over Streamable HTTP) so AI agents can read the
//! resolver with the same rights as the REST API.
//!
//! Every tool is a thin wrapper over REST routes, called in-process with the caller's own
//! credentials: scopes, group restrictions, rate limits, privacy levels, and the agent kill
//! switch apply exactly as they do to REST calls. Read-only tools (`spec/13` §3.1) are GETs.
//! Write tools (§3.2, AGT-007) make a plan with the REST dry run; `apply_plan` replays the
//! write with `If-Match` on the plan's config version (see `crate::plans`). A few low-risk
//! operations (flush the cache, pause or resume blocking) act at once, still audited.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use tower::ServiceExt as _;

/// The protocol revision this server speaks.
pub const PROTOCOL_VERSION: &str = "2025-06-18";
/// Older revisions clients may ask for; the answer is then in their terms.
const SUPPORTED: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
/// Most rows a tool returns, and most bytes of text (AGT-009).
pub const MAX_ROWS: u64 = 200;
pub const MAX_BYTES: usize = 32 * 1024;
/// Most messages in one JSON-RPC batch: each runs in turn, with its REST calls (AGT-009).
pub const MAX_BATCH: usize = 16;

/// A tool's REST calls for its arguments: `(result key, GET path with query)`, or why the
/// arguments are wrong.
pub type Calls = fn(&Value) -> Result<Vec<(String, String)>, String>;

/// One read-only tool and the REST call(s) behind it.
#[derive(Debug)]
pub struct Tool {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: fn() -> Value,
    /// The REST GET paths (with query) for the arguments; an error is the caller's mistake.
    pub calls: Calls,
}

fn s(args: &Value, k: &str) -> Option<String> {
    match args.get(k)? {
        Value::String(v) if !v.trim().is_empty() => Some(v.trim().to_owned()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn enc(v: &str) -> String {
    let mut out = String::new();
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~:".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// `path?k=v&...` from the arguments present.
fn query(path: &str, args: &Value, keys: &[(&str, &str)]) -> String {
    let mut q: Vec<String> = Vec::new();
    for (arg, param) in keys {
        if let Some(v) = s(args, arg) {
            q.push(format!("{param}={}", enc(&v)));
        }
    }
    if q.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", q.join("&"))
    }
}

fn limit(args: &Value, default: u64) -> String {
    args.get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(default)
        .clamp(1, MAX_ROWS)
        .to_string()
}

/// REQ: AGT-011 (T7.3) — which nodes an analytics tool reads.
fn scope_schema() -> Value {
    json!({"type": "string", "description": "Which nodes: cluster (default, every node), site:<name>, node:<name or ID>, or node:local (the node you're connected to). Nodes that don't answer within 2 s are listed in missingNodes."})
}

/// `&scope=...` when the arguments name one.
fn scope_q(args: &Value) -> String {
    s(args, "scope").map_or_else(String::new, |v| format!("&scope={}", enc(&v)))
}

fn window_schema() -> Value {
    json!({"type": "string", "description": "Start of the window: a relative offset like -1h, -24h, -7d, or an RFC 3339 time. Default -24h."})
}

/// The catalog (`spec/13` §3.1). Names, descriptions, and schemas are part of the contract:
/// `docs/api/mcp-tools.json` is the committed snapshot.
#[allow(clippy::too_many_lines)] // one entry per tool: the catalog
pub fn tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "get_overview",
            description: "Read-only. Key numbers for a time window: queries, blocked %, cache hit %, NXDOMAIN, active clients, and latency percentiles (p50/p90/p99 in ms). Start here to see whether anything is off.",
            input_schema: || json!({"type": "object", "properties": {"window": window_schema(), "scope": scope_schema()}, "additionalProperties": false}),
            calls: |a| {
                let from = s(a, "window").unwrap_or_else(|| "-24h".into());
                Ok(vec![(
                    "overview".into(),
                    format!("/api/v1/stats/summary?from={}{}", enc(&from), scope_q(a)),
                )])
            },
        },
        Tool {
            name: "top_items",
            description: "Read-only. The heaviest items in the current or previous hour: most queried domains, most blocked domains, names answered NXDOMAIN, or most active clients. Optionally for one client (domains only) or one client group.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "kind": {"type": "string", "enum": ["domains", "blocked", "nxdomain", "clients"], "description": "Which list."},
                "hour": {"type": "string", "enum": ["current", "previous"], "description": "Which hour (default current)."},
                "client": {"type": "string", "description": "A client IP: its top domains (kind=domains only)."},
                "group": {"type": "string", "description": "A client group's top items."},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Items (default 10)."},
                "scope": scope_schema()
            }, "required": ["kind"], "additionalProperties": false})
            },
            calls: |a| {
                if s(a, "kind").is_none() {
                    return Err("`kind` is required: domains, blocked, nxdomain, or clients".into());
                }
                Ok(vec![(
                    "items".into(),
                    query(
                        "/api/v1/stats/top",
                        a,
                        &[
                            ("kind", "kind"),
                            ("hour", "hour"),
                            ("client", "client"),
                            ("group", "group"),
                            ("limit", "limit"),
                            ("scope", "scope"),
                        ],
                    ),
                )])
            },
        },
        Tool {
            name: "search_queries",
            description: "Read-only. Search the query log, newest first: who asked for what, the answer, and timings. Filter by client, group, name (substring), status (blocked, cached, forwarded, local, ...), qtype, rcode, minimum latency, and time. Pages with `cursor` (from the previous result's nextCursor). Needs the querylog:read scope; subject to the privacy level.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "name": {"type": "string", "description": "Part of the queried name."},
                "client": {"type": "string", "description": "Client IP or device name."},
                "group": {"type": "string", "description": "Client group."},
                "status": {"type": "string", "description": "blocked, cached, forwarded, local, refused, error, ..."},
                "qtype": {"type": "string", "description": "A, AAAA, HTTPS, ..."},
                "rcode": {"type": "string", "description": "NOERROR, NXDOMAIN, SERVFAIL, ..."},
                "minLatencyMs": {"type": "integer", "description": "Only queries slower than this."},
                "from": {"type": "string", "description": "Start (relative like -1h, or RFC 3339). Default: all retained."},
                "to": {"type": "string", "description": "End (default now)."},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "description": "Rows (default 50)."},
                "cursor": {"type": "string", "description": "From the previous page's nextCursor."},
                "scope": scope_schema()
            }, "additionalProperties": false})
            },
            calls: |a| {
                let mut q = query(
                    "/api/v1/queries",
                    a,
                    &[
                        ("name", "name"),
                        ("client", "client"),
                        ("group", "group"),
                        ("status", "status"),
                        ("qtype", "qtype"),
                        ("rcode", "rcode"),
                        ("minLatencyMs", "minLatencyMs"),
                        ("from", "from"),
                        ("to", "to"),
                        ("cursor", "cursor"),
                        ("scope", "scope"),
                    ],
                );
                q.push(if q.contains('?') { '&' } else { '?' });
                let _ = write!(q, "limit={}", limit(a, 50));
                Ok(vec![("queries".into(), q)])
            },
        },
        Tool {
            name: "explain_decision",
            description: "Read-only. Why a name is (or isn't) blocked or routed for a client: the client's identity and groups, the rules that match, which one wins, and the upstream route. Answers 'why was X blocked for Y?'.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "name": {"type": "string", "description": "The domain name."},
                "client": {"type": "string", "description": "Client IP (default: as if from the API caller)."},
                "qtype": {"type": "string", "description": "Query type (default A)."}
            }, "required": ["name"], "additionalProperties": false})
            },
            calls: |a| {
                if s(a, "name").is_none() {
                    return Err("`name` is required".into());
                }
                Ok(vec![(
                    "explanation".into(),
                    query(
                        "/api/v1/explain",
                        a,
                        &[("name", "name"), ("client", "client"), ("qtype", "qtype")],
                    ),
                )])
            },
        },
        Tool {
            name: "get_client_profile",
            description: "Read-only. A device's profile: its identity, groups, top domains this hour, and its most recent queries (with latency and status). Give a device name or IP. Recent queries need the querylog:read scope; without it that part is reported as not allowed.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "client": {"type": "string", "description": "Device name (as in the device list) or IP."},
                "window": window_schema(),
                "scope": scope_schema()
            }, "required": ["client"], "additionalProperties": false})
            },
            calls: |a| {
                s(a, "client").ok_or("`client` is required")?;
                // The device's queries follow in `call_tool`, by its IP.
                Ok(vec![("devices".into(), "/api/v1/clients".into())])
            },
        },
        Tool {
            name: "latency_breakdown",
            description: "Read-only. Latency percentiles (p50/p90/p99/p99.9/max in ms) broken down by pipeline stage, upstream, client, or query type, for the current or previous hour. Find where time goes.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "by": {"type": "string", "enum": ["stage", "upstream", "client", "qtype"], "description": "Break down by."},
                "hour": {"type": "string", "enum": ["current", "previous"], "description": "Which hour (default current)."},
                "scope": scope_schema()
            }, "required": ["by"], "additionalProperties": false})
            },
            calls: |a| {
                if s(a, "by").is_none() {
                    return Err("`by` is required: stage, upstream, client, or qtype".into());
                }
                Ok(vec![(
                    "latency".into(),
                    query(
                        "/api/v1/stats/latency",
                        a,
                        &[("by", "by"), ("hour", "hour"), ("scope", "scope")],
                    ),
                )])
            },
        },
        Tool {
            name: "upstream_health",
            description: "Read-only. Every upstream resolver: health, circuit-breaker state, error counts, and latency percentiles. Answers 'is the upstream the problem?'.",
            input_schema: || json!({"type": "object", "properties": {}, "additionalProperties": false}),
            calls: |_| Ok(vec![("upstreams".into(), "/api/v1/upstreams".into())]),
        },
        Tool {
            name: "list_effectiveness",
            description: "Read-only. Filter lists: size, last update, errors, hits since start, unique names (only that list has them), and which lists overlap. Find dead, failing, or redundant lists.",
            input_schema: || json!({"type": "object", "properties": {}, "additionalProperties": false}),
            calls: |_| Ok(vec![("lists".into(), "/api/v1/lists".into())]),
        },
        Tool {
            name: "find_anomalies",
            description: "Read-only. Device anomalies with their evidence: rate spikes, heavy volume to one domain, behavior drift, beaconing (regular call-home patterns), NXDOMAIN storms, and machine-generated-looking (DGA) new domains. Alert-only; nothing is blocked automatically.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "since": {"type": "string", "description": "Findings since (relative like -7d, or RFC 3339). Default -7d."}
            }, "additionalProperties": false})
            },
            calls: |a| {
                Ok(vec![(
                    "anomalies".into(),
                    query("/api/v1/analytics/anomalies", a, &[("since", "since")]),
                )])
            },
        },
        Tool {
            name: "new_domains",
            description: "Read-only. Domains devices contacted for the first time, newest first, each with a DGA score (0 to 1: how machine-generated the name looks; 0.6 and up is suspicious). Optionally for one device.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "since": {"type": "string", "description": "First seen since (relative like -24h, or RFC 3339). Default -24h."},
                "client": {"type": "string", "description": "Only this device's address."},
                "limit": {"type": "integer", "minimum": 1, "maximum": 2000, "description": "At most this many (default 200)."}
            }, "additionalProperties": false})
            },
            calls: |a| {
                let mut path = query(
                    "/api/v1/analytics/new-domains",
                    a,
                    &[("since", "since"), ("client", "client")],
                );
                if let Some(n) = a.get("limit").and_then(Value::as_u64) {
                    let sep = if path.contains('?') { '&' } else { '?' };
                    path = format!("{path}{sep}limit={n}");
                }
                Ok(vec![("newDomains".into(), path)])
            },
        },
        Tool {
            name: "vqlog",
            description: "Read-only. Analytics over the query log in one query (a small, safe pipe language; never SQL). Examples: `from -24h | where status = blocked and group = kids | top 10 name`; `from -7d | where client = 192.168.1.20 | bucket 1h | stats count, p95(latency)`; `where name under roku.com | by client | stats count, distinct(name)`. Stages: from TIME [to TIME] (-24h, -7d, RFC 3339; default -24h); where FIELD OP VALUE [and ...] (fields name, client, group, status, qtype, rcode, upstream, proto, latency, upstream_latency; ops =, !=, in (a, b), not in (a, b); names also ~ glob, has, under; latencies >, >=, <, <= in ms); bucket 5m|1h|1d; by KEY, ... (name, domain, client, group, status, qtype, rcode, upstream, proto; at most 3); stats count, distinct(KEY), avg|min|max|p50|p90|p95|p99(latency|upstream_latency|answers|bytes); top N KEY; sort COLUMN [asc|desc]; limit N (<= 200). Returns a table, the query as understood, and its cost. Set estimateOnly to check the cost first. Needs the querylog:read scope; subject to the privacy level.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "query": {"type": "string", "description": "The vqlog query."},
                "estimateOnly": {"type": "boolean", "description": "Only parse and estimate how much it would read."}
            }, "required": ["query"], "additionalProperties": false})
            },
            calls: |a| {
                let q = s(a, "query").ok_or("`query` is required")?;
                let dry = a
                    .get("estimateOnly")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                Ok(vec![(
                    "result".into(),
                    format!("/api/v1/analytics/vqlog?q={}&dryRun={dry}", enc(&q)),
                )])
            },
        },
        Tool {
            name: "cluster_status",
            description: "Read-only. The cluster as this node sees it: members, roles, epochs, sync lag, versions, health checks, each node's machine (memory, CPU, disk, temperature, with the last hour and warnings), and recent events. On a standalone node it says so and still shows its machine.",
            input_schema: || json!({"type": "object", "properties": {}, "additionalProperties": false}),
            calls: |_| Ok(vec![("cluster".into(), "/api/v1/cluster".into())]),
        },
        Tool {
            name: "get_config",
            description: "Read-only. One section of the running configuration, as the API shows it (no secrets): groups, lists, devices (clients), upstreams, local names (records), authoritative zones (zones), or forwarded domains (forwards). Also returns system information.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "section": {"type": "string", "enum": ["groups", "lists", "clients", "upstreams", "records", "zones", "forwards"], "description": "Which section."}
            }, "required": ["section"], "additionalProperties": false})
            },
            calls: |a| {
                let section = s(a, "section").ok_or("`section` is required")?;
                if ![
                    "groups",
                    "lists",
                    "clients",
                    "upstreams",
                    "records",
                    "zones",
                    "forwards",
                ]
                .contains(&section.as_str())
                {
                    return Err(format!("unknown section `{section}`"));
                }
                Ok(vec![
                    (section.clone(), format!("/api/v1/{section}")),
                    ("system".into(), "/api/v1/system/info".into()),
                ])
            },
        },
    ]
}

/// REQ: AGT-007 (T7.1) — what a write tool does: one REST write.
#[derive(Debug, Clone)]
pub struct Write {
    /// `PUT`, `DELETE`, or `POST`.
    pub method: &'static str,
    pub path: String,
    pub body: Option<Value>,
    /// One sentence for the plan and the approver.
    pub summary: String,
    /// Fill in the fields the agent left out from what's there now: a `config/entries` kind
    /// (`group`, `upstream`, `upstream_group`, `list`) or `client`, with the name.
    pub merge: Option<(&'static str, String)>,
}

/// How a write tool takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Stores a plan (dry run); `apply_plan` makes the change.
    Plan,
    /// Changes at once (low-risk operations, still audited).
    Immediate,
}

/// One write tool and the REST write behind it.
#[derive(Debug)]
pub struct WriteTool {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: fn() -> Value,
    pub effect: Effect,
    /// Whether applying it can take something away (MCP `destructiveHint`).
    pub destructive: bool,
    pub write: fn(&Value) -> Result<Write, String>,
}

fn reason_schema() -> Value {
    json!({"type": "string", "description": "Why (required): goes into the audit log and is shown to whoever approves the plan."})
}

fn need(args: &Value, k: &str) -> Result<String, String> {
    s(args, k).ok_or_else(|| format!("`{k}` is required"))
}

fn strings(args: &Value, k: &str) -> Vec<String> {
    args.get(k)
        .and_then(Value::as_array)
        .map(|v| {
            v.iter()
                .filter_map(Value::as_str)
                .map(|x| x.trim().to_owned())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// The fields of `args` named in `keys`, as a JSON object (absent ones left out).
fn pick(args: &Value, keys: &[(&str, &str)]) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    for (arg, field) in keys {
        if let Some(v) = args.get(*arg).filter(|v| !v.is_null()) {
            m.insert((*field).to_owned(), v.clone());
        }
    }
    m
}

/// A quick rule's ID for an agent's block or allow: one per action and domain.
fn rule_id(action: &str, domain: &str) -> String {
    let d: String = domain
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let mut id = format!("agent-{action}-{d}");
    id.truncate(64);
    id
}

fn rule(action: &'static str, a: &Value) -> Result<Write, String> {
    let domain = need(a, "domain")?;
    let mut body = pick(
        a,
        &[
            ("devices", "devices"),
            ("groups", "groups"),
            ("forMinutes", "forMinutes"),
        ],
    );
    body.insert("action".into(), action.into());
    body.insert("domain".into(), domain.clone().into());
    if let Some(r) = s(a, "reason") {
        body.insert("note".into(), r.into());
    }
    let who = match (strings(a, "devices"), strings(a, "groups")) {
        (d, g) if d.is_empty() && g.is_empty() => "everyone".to_owned(),
        (d, g) => [d, g].concat().join(", "),
    };
    let until = a
        .get("forMinutes")
        .and_then(Value::as_u64)
        .map_or_else(String::new, |m| format!(" for {m} minutes"));
    Ok(Write {
        method: "PUT",
        path: format!("/api/v1/rules/{}", enc(&rule_id(action, &domain))),
        body: Some(Value::Object(body)),
        summary: format!(
            "{} {domain} (and its subdomains) for {who}{until}",
            if action == "block" { "Block" } else { "Allow" }
        ),
        merge: None,
    })
}

fn rule_schema(what: &str) -> Value {
    json!({"type": "object", "properties": {
        "domain": {"type": "string", "description": format!("The domain to {what}; its subdomains are included.")},
        "devices": {"type": "array", "items": {"type": "string"}, "description": "Only for these devices (names, IPs, or CIDRs)."},
        "groups": {"type": "array", "items": {"type": "string"}, "description": "Only for these groups. With neither devices nor groups: everyone."},
        "forMinutes": {"type": "integer", "minimum": 1, "description": "Stop after this many minutes (default: until removed)."},
        "reason": reason_schema()
    }, "required": ["domain", "reason"], "additionalProperties": false})
}

/// The write catalog (`spec/13` §3.2). Plans first, then the immediate operations.
#[allow(clippy::too_many_lines)] // one entry per tool: the catalog
pub fn write_tools() -> Vec<WriteTool> {
    vec![
        WriteTool {
            name: "plan_block_domain",
            description: "Plans a change (nothing changes until apply_plan). A quick rule that blocks a domain and its subdomains, for everyone or for some devices or groups, optionally for a while. Returns a planId and a preview (what changes, how many recent queries it affects). Needs the config:write:rules scope.",
            input_schema: || rule_schema("block"),
            effect: Effect::Plan,
            destructive: false,
            write: |a| rule("block", a),
        },
        WriteTool {
            name: "plan_allow_domain",
            description: "Plans a change (nothing changes until apply_plan). A quick rule that allows a domain and its subdomains (it wins over every list), for everyone or for some devices or groups, optionally for a while. Returns a planId and a preview. Needs the config:write:rules scope.",
            input_schema: || rule_schema("allow"),
            effect: Effect::Plan,
            destructive: false,
            write: |a| rule("allow", a),
        },
        WriteTool {
            name: "plan_rename_client",
            description: "Plans a change (nothing changes until apply_plan). Renames a named device; its addresses and groups stay. Past queries show the new name too. Needs the config:write:clients scope.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "client": {"type": "string", "description": "The device's current name."},
                "newName": {"type": "string", "description": "The new name."},
                "reason": reason_schema()
            }, "required": ["client", "newName", "reason"], "additionalProperties": false})
            },
            effect: Effect::Plan,
            destructive: false,
            write: |a| {
                let client = need(a, "client")?;
                let new = need(a, "newName")?;
                Ok(Write {
                    method: "PUT",
                    path: format!("/api/v1/clients/{}", enc(&client)),
                    body: Some(json!({"name": new})),
                    summary: format!("Rename the device {client} to {new}"),
                    merge: Some(("client", client)),
                })
            },
        },
        WriteTool {
            name: "plan_assign_client",
            description: "Plans a change (nothing changes until apply_plan). Names a device and puts it in groups (highest priority first), or changes a named device's groups or addresses. For a new device give `match` (its IPs, CIDRs, MACs, or id:<client-id>); an IP as `client` is enough. Needs the config:write:clients scope.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "client": {"type": "string", "description": "The device's name (new or existing), or an IP."},
                "groups": {"type": "array", "items": {"type": "string"}, "description": "Its groups, highest priority first."},
                "match": {"type": "array", "items": {"type": "string"}, "description": "How to recognize it (default: what it has now, or the IP given as client)."},
                "reason": reason_schema()
            }, "required": ["client", "groups", "reason"], "additionalProperties": false})
            },
            effect: Effect::Plan,
            destructive: false,
            write: |a| {
                let client = need(a, "client")?;
                let groups = strings(a, "groups");
                if groups.is_empty() {
                    return Err("`groups` is required (at least one)".into());
                }
                let body = pick(a, &[("groups", "groups"), ("match", "match")]);
                Ok(Write {
                    method: "PUT",
                    path: format!("/api/v1/clients/{}", enc(&client)),
                    body: Some(Value::Object(body)),
                    summary: format!("Put the device {client} in {}", groups.join(", ")),
                    merge: Some(("client", client)),
                })
            },
        },
        WriteTool {
            name: "plan_set_local_name",
            description: "Plans a change (nothing changes until apply_plan). Answers a name on the local network with your own records (A, AAAA, CNAME, TXT, ...), e.g. nas.home.arpa → 192.168.1.10. Replaces that name's records. Needs the config:write:records scope.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "name": {"type": "string", "description": "The full name, e.g. nas.home.arpa."},
                "records": {"type": "array", "items": {"type": "object", "properties": {
                    "type": {"type": "string", "description": "A, AAAA, CNAME, TXT, MX, SRV, PTR."},
                    "value": {"type": "string", "description": "The answer, e.g. 192.168.1.10."},
                    "ttl": {"type": "integer", "description": "Seconds (optional)."}
                }, "required": ["type", "value"]}, "description": "The records."},
                "reason": reason_schema()
            }, "required": ["name", "records", "reason"], "additionalProperties": false})
            },
            effect: Effect::Plan,
            destructive: false,
            write: |a| {
                let name = need(a, "name")?;
                let records = a
                    .get("records")
                    .cloned()
                    .filter(Value::is_array)
                    .ok_or("`records` is required")?;
                let n = records.as_array().map_or(0, Vec::len);
                Ok(Write {
                    method: "PUT",
                    path: format!("/api/v1/records/{}", enc(&name)),
                    body: Some(json!({"records": records})),
                    summary: format!("Answer {name} with {n} record(s) of your own"),
                    merge: None,
                })
            },
        },
        WriteTool {
            name: "plan_remove_local_name",
            description: "Plans a change (nothing changes until apply_plan). Removes a local name made through the API or UI; the name is then resolved normally. Needs the config:write:records scope.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "name": {"type": "string", "description": "The full name."},
                "reason": reason_schema()
            }, "required": ["name", "reason"], "additionalProperties": false})
            },
            effect: Effect::Plan,
            destructive: true,
            write: |a| {
                let name = need(a, "name")?;
                Ok(Write {
                    method: "DELETE",
                    path: format!("/api/v1/records/{}", enc(&name)),
                    body: None,
                    summary: format!("Stop answering {name} locally"),
                    merge: None,
                })
            },
        },
        WriteTool {
            name: "plan_forward_domain",
            description: "Plans a change (nothing changes until apply_plan). Sends every question under a domain to other DNS servers (a work network, your router), e.g. corp.example → 10.0.0.53. Servers are IPs (plain DNS) or tls://, https:// addresses. Needs the config:write:forwards scope.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "domain": {"type": "string", "description": "The domain, e.g. corp.example."},
                "servers": {"type": "array", "items": {"type": "string"}, "description": "The servers, tried in order."},
                "reason": reason_schema()
            }, "required": ["domain", "servers", "reason"], "additionalProperties": false})
            },
            effect: Effect::Plan,
            destructive: false,
            write: |a| {
                let domain = need(a, "domain")?;
                let servers = strings(a, "servers");
                if servers.is_empty() {
                    return Err("`servers` is required (at least one)".into());
                }
                Ok(Write {
                    method: "PUT",
                    path: format!("/api/v1/forwards/{}", enc(&domain)),
                    body: Some(json!({"servers": servers})),
                    summary: format!("Send questions under {domain} to {}", servers.join(", ")),
                    merge: None,
                })
            },
        },
        WriteTool {
            name: "plan_add_list",
            description: "Plans a change (nothing changes until apply_plan). Adds (or replaces) a filter list: a URL to download (hosts, domains, or Adblock syntax) or inline rules; block or allow. Every group that uses all lists picks it up. Needs the config:write:lists scope.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "name": {"type": "string", "description": "An ID: lowercase letters, digits, - and _."},
                "url": {"type": "string", "description": "Where to download it (https)."},
                "rules": {"type": "array", "items": {"type": "string"}, "description": "Or inline rules, one per item."},
                "kind": {"type": "string", "enum": ["block", "allow"], "description": "Default block."},
                "enabled": {"type": "boolean", "description": "Default true."},
                "reason": reason_schema()
            }, "required": ["name", "reason"], "additionalProperties": false})
            },
            effect: Effect::Plan,
            destructive: false,
            write: |a| {
                let name = need(a, "name")?;
                let body = pick(
                    a,
                    &[
                        ("url", "url"),
                        ("rules", "rules"),
                        ("kind", "kind"),
                        ("enabled", "enabled"),
                    ],
                );
                if !body.contains_key("url") && !body.contains_key("rules") {
                    return Err("give `url` or `rules`".into());
                }
                let from = s(a, "url").unwrap_or_else(|| "inline rules".into());
                Ok(Write {
                    method: "PUT",
                    path: format!("/api/v1/lists/{}", enc(&name)),
                    body: Some(Value::Object(body)),
                    summary: format!(
                        "Add the {} list {name} ({from})",
                        s(a, "kind").unwrap_or_else(|| "block".into())
                    ),
                    merge: None,
                })
            },
        },
        // REQ: FLT-010, AGT-007 (T9.7) — schedules, as plans.
        WriteTool {
            name: "plan_set_schedule",
            description: "Plans a change (nothing changes until apply_plan). Makes or changes a weekly schedule: during its windows it blocks everything (block_all, a bedtime), applies extra lists (enable_lists), or blocks services (block_services). Groups follow a schedule once it's in their schedules (plan_update_group). Needs config:write:groups.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "name": {"type": "string", "description": "The schedule."},
                "action": {"type": "string", "enum": ["block_all", "enable_lists", "block_services"], "description": "What happens during the windows."},
                "windows": {"type": "array", "items": {"type": "object", "properties": {
                    "days": {"type": "array", "items": {"type": "string"}, "description": "mon..sun, or weekdays, weekends, daily."},
                    "start": {"type": "string", "description": "HH:MM, 24-hour, local time."},
                    "end": {"type": "string", "description": "HH:MM; at or before start runs past midnight."}
                }, "required": ["days", "start", "end"], "additionalProperties": false}, "description": "When it's on."},
                "lists": {"type": "array", "items": {"type": "string"}, "description": "enable_lists: the lists."},
                "services": {"type": "array", "items": {"type": "string"}, "description": "block_services: service IDs (GET /services)."},
                "tz": {"type": "string", "description": "IANA time zone, e.g. America/New_York (default: the node's)."},
                "reason": reason_schema()
            }, "required": ["name", "action", "windows", "reason"], "additionalProperties": false})
            },
            effect: Effect::Plan,
            destructive: false,
            write: |a| {
                let name = need(a, "name")?;
                let mut body = pick(
                    a,
                    &[
                        ("action", "action"),
                        ("lists", "lists"),
                        ("services", "services"),
                        ("tz", "tz"),
                        ("windows", "window"),
                    ],
                );
                let action = body
                    .get("action")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                if body
                    .get("window")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty)
                {
                    return Err("`windows`: at least one".into());
                }
                body.retain(|_, v| !v.is_null());
                Ok(Write {
                    method: "PUT",
                    path: format!("/api/v1/schedules/{}", enc(&name)),
                    summary: format!("Set the schedule {name} ({action})"),
                    body: Some(Value::Object(body)),
                    merge: Some(("schedule", name)),
                })
            },
        },
        // REQ: DNS-014, AGT-007 (review 01 q1) — the per-client rate limit, as a plan.
        WriteTool {
            name: "plan_set_ratelimit",
            description: "Plans a change (nothing changes until apply_plan). Changes the per-client rate limit: how many queries one client may send per window before it is refused (or dropped), the clients that are never limited, and how clients are grouped (IPv4 per address, IPv6 per /64 by default). A router or proxy that forwards for a whole network looks like one client: exempt it or raise `queries`. Fields left out keep their current values. Applies at once; every client's count starts over. Needs config:write:ratelimit (and config:read to read the current limit).",
            input_schema: || {
                json!({"type": "object", "properties": {
                "enabled": {"type": "boolean", "description": "Turn rate limiting on or off."},
                "queries": {"type": "integer", "minimum": 1, "description": "Queries allowed per client per window (bursts up to this)."},
                "windowSecs": {"type": "integer", "minimum": 1, "description": "The window, in seconds (default 60)."},
                "action": {"type": "string", "enum": ["refused", "drop"], "description": "What a limited query gets: REFUSED, or nothing."},
                "exempt": {"type": "array", "items": {"type": "string"}, "description": "CIDRs never limited (replaces the current list; include 127.0.0.0/8 and ::1/128 to keep loopback exempt)."},
                "ipv4Prefix": {"type": "integer", "minimum": 1, "maximum": 32, "description": "Count IPv4 clients per /N (32 = per address)."},
                "ipv6Prefix": {"type": "integer", "minimum": 1, "maximum": 128, "description": "Count IPv6 clients per /N (64 groups a device's rotating addresses)."},
                "reason": reason_schema()
            }, "required": ["reason"], "additionalProperties": false})
            },
            effect: Effect::Plan,
            destructive: false,
            write: |a| {
                let body = pick(
                    a,
                    &[
                        ("enabled", "enabled"),
                        ("queries", "queries"),
                        ("windowSecs", "window_secs"),
                        ("action", "action"),
                        ("exempt", "exempt"),
                        ("ipv4Prefix", "ipv4_prefix"),
                        ("ipv6Prefix", "ipv6_prefix"),
                    ],
                );
                if body.is_empty() {
                    return Err("give at least one setting to change".into());
                }
                let mut what: Vec<String> = Vec::new();
                for (k, label) in [
                    ("enabled", "enabled"),
                    ("queries", "queries"),
                    ("window_secs", "window"),
                ] {
                    if let Some(v) = body.get(k) {
                        what.push(format!("{label} {v}"));
                    }
                }
                let summary = if what.is_empty() {
                    "Change the rate limit".to_owned()
                } else {
                    format!("Set the rate limit ({})", what.join(", "))
                };
                Ok(Write {
                    method: "PUT",
                    path: "/api/v1/ratelimit/default".to_owned(),
                    summary,
                    body: Some(Value::Object(body)),
                    merge: Some(("ratelimit", "default".to_owned())),
                })
            },
        },
        WriteTool {
            name: "plan_update_group",
            description: "Plans a change (nothing changes until apply_plan). Changes a group (or makes a new one): its networks, which lists apply, how blocked names are answered, its priority. Fields left out keep their current values. Needs config:write:groups (and config:read to read the current group).",
            input_schema: || {
                json!({"type": "object", "properties": {
                "name": {"type": "string", "description": "The group."},
                "networks": {"type": "array", "items": {"type": "string"}, "description": "CIDRs whose devices belong to it."},
                "lists": {"type": "array", "items": {"type": "string"}, "description": "List names that apply (default: every enabled list)."},
                "blockMode": {"type": "string", "enum": ["null_ip", "nxdomain", "nodata", "refused", "custom_ip"], "description": "How blocked names are answered."},
                "priority": {"type": "integer", "description": "Higher wins when a device matches several groups."},
                "schedules": {"type": "array", "items": {"type": "string"}, "description": "Schedules (by name) the group follows (plan_set_schedule makes them)."},
                "reason": reason_schema()
            }, "required": ["name", "reason"], "additionalProperties": false})
            },
            effect: Effect::Plan,
            destructive: false,
            write: |a| {
                let name = need(a, "name")?;
                let body = pick(
                    a,
                    &[
                        ("networks", "networks"),
                        ("lists", "lists"),
                        ("blockMode", "block_mode"),
                        ("priority", "priority"),
                        ("schedules", "schedules"),
                    ],
                );
                let what: Vec<&str> = body.keys().map(String::as_str).collect();
                Ok(Write {
                    method: "PUT",
                    path: format!("/api/v1/groups/{}", enc(&name)),
                    summary: format!(
                        "Change the group {name} ({})",
                        if what.is_empty() {
                            "no fields".into()
                        } else {
                            what.join(", ")
                        }
                    ),
                    body: Some(Value::Object(body)),
                    merge: Some(("group", name)),
                })
            },
        },
        WriteTool {
            name: "plan_update_upstreams",
            description: "Plans a change (nothing changes until apply_plan). Changes (or adds) an upstream server (`url`) or an upstream group (`members`, `strategy`: failover, round_robin, weighted, fastest, parallel). Fields left out keep their current values. Needs config:write:upstreams (and config:read to read the current entry).",
            input_schema: || {
                json!({"type": "object", "properties": {
                "kind": {"type": "string", "enum": ["upstream", "upstream_group"], "description": "A server or a group."},
                "name": {"type": "string", "description": "Its name."},
                "url": {"type": "string", "description": "upstream: udp://, tcp://, tls://, https://, or quic:// address."},
                "members": {"type": "array", "items": {"type": "string"}, "description": "upstream_group: upstream names."},
                "strategy": {"type": "string", "enum": ["failover", "round_robin", "weighted", "fastest", "parallel"], "description": "upstream_group: how members are used."},
                "reason": reason_schema()
            }, "required": ["kind", "name", "reason"], "additionalProperties": false})
            },
            effect: Effect::Plan,
            destructive: false,
            write: |a| {
                let name = need(a, "name")?;
                let (kind, path, body) = match s(a, "kind").as_deref() {
                    Some("upstream") => ("upstream", "upstreams", pick(a, &[("url", "url")])),
                    Some("upstream_group") => (
                        "upstream_group",
                        "upstream-groups",
                        pick(a, &[("members", "members"), ("strategy", "strategy")]),
                    ),
                    _ => return Err("`kind` is upstream or upstream_group".into()),
                };
                let what: Vec<&str> = body.keys().map(String::as_str).collect();
                Ok(Write {
                    method: "PUT",
                    path: format!("/api/v1/{path}/{}", enc(&name)),
                    summary: format!(
                        "Change the {} {name} ({})",
                        kind.replace('_', " "),
                        what.join(", ")
                    ),
                    body: Some(Value::Object(body)),
                    merge: Some((kind, name)),
                })
            },
        },
        WriteTool {
            name: "flush_cache",
            description: "Changes at once (audited, no plan). Removes cached answers: one name (optionally everything under it), or the whole cache; on every node unless `node` names one. The next query is asked upstream again. Blocked answers are never cached. Needs the ops:cache scope.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "name": {"type": "string", "description": "One name (default: everything)."},
                "subtree": {"type": "boolean", "description": "Also every name under it."},
                "node": {"type": "string", "description": "Only this node."},
                "reason": reason_schema()
            }, "required": ["reason"], "additionalProperties": false})
            },
            effect: Effect::Immediate,
            destructive: true,
            write: |a| {
                let body = pick(
                    a,
                    &[("name", "name"), ("subtree", "subtree"), ("node", "node")],
                );
                Ok(Write {
                    method: "POST",
                    path: "/api/v1/cache/flush".into(),
                    summary: s(a, "name").map_or_else(
                        || "Empty the cache".into(),
                        |n| format!("Flush {n} from the cache"),
                    ),
                    body: Some(Value::Object(body)),
                    merge: None,
                })
            },
        },
        WriteTool {
            name: "pause_blocking",
            description: "Changes at once (audited, no plan). Turns blocking off for everyone (or one group) for 1 to 60 minutes, on every node; it comes back on by itself. Needs the ops:pause scope.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "minutes": {"type": "integer", "minimum": 1, "maximum": 60, "description": "How long."},
                "group": {"type": "string", "description": "Only this group."},
                "reason": reason_schema()
            }, "required": ["minutes", "reason"], "additionalProperties": false})
            },
            effect: Effect::Immediate,
            destructive: true,
            write: |a| {
                let minutes = a
                    .get("minutes")
                    .and_then(Value::as_u64)
                    .ok_or("`minutes` is required (1 to 60)")?;
                let body = pick(a, &[("minutes", "minutes"), ("group", "group")]);
                Ok(Write {
                    method: "POST",
                    path: "/api/v1/blocking/pause".into(),
                    summary: format!(
                        "Pause blocking{} for {minutes} minutes",
                        s(a, "group")
                            .map(|g| format!(" for {g}"))
                            .unwrap_or_default()
                    ),
                    body: Some(Value::Object(body)),
                    merge: None,
                })
            },
        },
        // REQ: API-002 (T9.12) — pre-save checks: nothing changes, but they reach out from the
        // node, so they need the scope that saves the entry and are audited.
        WriteTool {
            name: "check_upstream",
            description: "Changes nothing (audited). Checks an upstream before you save it: this node builds it from the fields you'd save (url, tls_server_name, bootstrap, proxy, ...) and asks it for the root's NS records. Returns ok, the answer or the error (bad URL, TLS name mismatch, timeout), and the time. Use it before plan_update_upstreams. Needs the config:write:upstreams scope.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "upstream": {"type": "object", "description": "The upstream's fields, as when saving it (url required, e.g. {\"url\": \"tls://9.9.9.9\", \"tls_server_name\": \"dns.quad9.net\"})."},
                "reason": reason_schema()
            }, "required": ["upstream", "reason"], "additionalProperties": false})
            },
            effect: Effect::Immediate,
            destructive: false,
            write: |a| {
                let u = a
                    .get("upstream")
                    .filter(|v| v.is_object())
                    .cloned()
                    .ok_or("`upstream` (an object with at least `url`) is required")?;
                let url = u
                    .get("url")
                    .and_then(Value::as_str)
                    .unwrap_or("?")
                    .to_owned();
                Ok(Write {
                    method: "POST",
                    path: "/api/v1/checks/upstream".into(),
                    summary: format!("Check the upstream {url}"),
                    body: Some(u),
                    merge: None,
                })
            },
        },
        WriteTool {
            name: "check_list",
            description: "Changes nothing (audited). Checks a filter list before you add it: this node downloads the URL (with the configured size limit and timeout), or takes inline rules, and parses it as the compiler would. Returns ok, how many rules it found, up to 10 lines it couldn't use and why, and the time. Use it before plan_add_list. Needs the config:write:lists scope.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "list": {"type": "object", "description": "The list's fields, as when saving it: url (or rules), and optionally kind (block|allow) and match."},
                "reason": reason_schema()
            }, "required": ["list", "reason"], "additionalProperties": false})
            },
            effect: Effect::Immediate,
            destructive: false,
            write: |a| {
                let l = a
                    .get("list")
                    .filter(|v| v.is_object())
                    .cloned()
                    .ok_or("`list` (an object with `url` or `rules`) is required")?;
                let what = l
                    .get("url")
                    .and_then(Value::as_str)
                    .map_or_else(|| "inline rules".to_owned(), ToOwned::to_owned);
                Ok(Write {
                    method: "POST",
                    path: "/api/v1/checks/list".into(),
                    summary: format!("Check the list {what}"),
                    body: Some(l),
                    merge: None,
                })
            },
        },
        WriteTool {
            name: "resume_blocking",
            description: "Changes at once (audited, no plan). Ends a pause of blocking: one group's, or every pause. Needs the ops:pause scope.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "group": {"type": "string", "description": "Only this group's pause."},
                "reason": reason_schema()
            }, "required": ["reason"], "additionalProperties": false})
            },
            effect: Effect::Immediate,
            destructive: false,
            write: |a| {
                Ok(Write {
                    method: "POST",
                    path: "/api/v1/blocking/resume".into(),
                    summary: "Resume blocking".into(),
                    body: Some(Value::Object(pick(a, &[("group", "group")]))),
                    merge: None,
                })
            },
        },
    ]
}

/// Plan management tools: `(name, description, schema, readOnly, destructive, idempotent)`.
fn plan_tools() -> Vec<(&'static str, &'static str, Value, bool, bool, bool)> {
    let id = || {
        json!({"type": "object", "properties": {
        "planId": {"type": "string", "description": "From a plan_* tool."}
    }, "required": ["planId"], "additionalProperties": false})
    };
    vec![
        (
            "apply_plan",
            "Changes the configuration: applies a plan made by a plan_* tool, on every node. Fails if the configuration changed since the plan was made (stale: plan again), if it expired (10 minutes), or if an operator must approve it first. Audited with your token, its owner, and the plan's reason.",
            id(),
            false,
            true,
            false,
        ),
        (
            "discard_plan",
            "Drops a plan you made; nothing in the configuration changes.",
            id(),
            false,
            false,
            true,
        ),
        (
            "list_plans",
            "Read-only. Your plans, newest first: what each does, its state (pending approval, ready, applied, stale, expired, ...), and when it expires.",
            json!({"type": "object", "properties": {}, "additionalProperties": false}),
            true,
            false,
            true,
        ),
    ]
}

/// REQ: AGT-010 (T7.2) — one MCP resource and the REST reads behind it.
#[derive(Debug)]
pub struct Resource {
    pub uri: &'static str,
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    /// `(key, GET path)`: each read becomes one key of the JSON document.
    pub reads: &'static [(&'static str, &'static str)],
}

/// The resources (`spec/13` AGT-010): read-only JSON documents built from REST reads, with the
/// caller's credentials (scopes apply; a read the token can't make shows as an error).
pub fn resources() -> Vec<Resource> {
    vec![
        Resource {
            uri: "telltale://cluster/status",
            name: "cluster-status",
            title: "Cluster status",
            description: "The cluster as this node sees it: members, roles, sync, versions, health checks, each node's machine, and recent events (or this node alone).",
            reads: &[
                ("cluster", "/api/v1/cluster"),
                ("system", "/api/v1/system/info"),
            ],
        },
        Resource {
            uri: "telltale://config",
            name: "config",
            title: "Configuration (redacted)",
            description: "The running configuration as the API shows it, without secrets: upstreams, upstream groups, lists, and groups (with where each comes from), devices, local names, forwarded domains, and quick rules.",
            reads: &[
                ("entries", "/api/v1/config/entries"),
                ("devices", "/api/v1/clients"),
                ("localNames", "/api/v1/records"),
                ("forwards", "/api/v1/forwards"),
                ("rules", "/api/v1/rules"),
                ("system", "/api/v1/system/info"),
            ],
        },
        Resource {
            uri: "telltale://reports/daily",
            name: "daily-summary",
            title: "Daily summary",
            description: "The last 24 hours: queries, blocked %, cache hits, latency, the top domains, blocked names, and clients, upstream health, and device anomalies.",
            reads: &[
                ("summary", "/api/v1/stats/summary?from=-24h"),
                ("topDomains", "/api/v1/stats/top?kind=domains&limit=10"),
                ("topBlocked", "/api/v1/stats/top?kind=blocked&limit=10"),
                ("topClients", "/api/v1/stats/top?kind=clients&limit=10"),
                ("upstreams", "/api/v1/upstreams"),
                ("anomalies", "/api/v1/analytics/anomalies?since=-1d"),
            ],
        },
    ]
}

/// REQ: AGT-010 (T7.2) — one MCP prompt: a playbook for a common question.
#[derive(Debug)]
pub struct Prompt {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    /// `(name, description, required)`.
    pub arguments: &'static [(&'static str, &'static str, bool)],
    /// The message, with `{argument}` placeholders.
    pub text: &'static str,
}

pub fn prompts() -> Vec<Prompt> {
    vec![
        Prompt {
            name: "investigate_device",
            title: "Investigate a device",
            description: "What a device has been doing, whether anything is off, and why.",
            arguments: &[
                ("client", "The device's name or IP address.", true),
                (
                    "window",
                    "How far back, like -6h or -7d (default -24h).",
                    false,
                ),
            ],
            text: "Investigate the device \"{client}\" on my network over {window}.\n\n1. get_client_profile (client \"{client}\", window \"{window}\"): who it is, its groups, top domains, recent and slow queries.\n2. find_anomalies: any findings for this device (rate spikes, beaconing, drift).\n3. For anything blocked or odd, explain_decision with the name and this client.\n4. If it's slow, latency_breakdown by upstream and upstream_health.\n\nReport in plain language: what the device is, what it talks to, anything unusual (with the evidence), and what you'd suggest. Don't change anything; if a change would help, say which plan_* tool would make it.",
        },
        Prompt {
            name: "weekly_network_report",
            title: "Weekly network report",
            description: "A short report on the last 7 days: traffic, blocking, devices, speed, and anything to look at.",
            arguments: &[],
            text: "Write a weekly report for my home network.\n\n1. get_overview with window -7d, and with -24h to compare with today.\n2. top_items: domains, blocked, nxdomain, and clients (current and previous hour), to see who and what dominates.\n3. find_anomalies since -7d.\n4. upstream_health and latency_breakdown by upstream.\n5. cluster_status: are all nodes healthy and in sync?\n\nKeep it short: the key numbers, the three things most worth attention (with evidence), and anything that needs no action said briefly. No changes.",
        },
        Prompt {
            name: "tune_blocklists",
            title: "Tune blocklists",
            description: "Which lists earn their place, which are dead weight, and what's blocked by mistake.",
            arguments: &[],
            text: "Help me tune my blocklists.\n\n1. list_effectiveness: each list's size, update state, errors, and how many names it adds.\n2. top_items kind blocked (current and previous hour): what's blocked most.\n3. For blocked names that look like they break something (CDNs, login, payment, app APIs), explain_decision to see which list and rule blocks them.\n4. get_config section lists and groups: which groups use which lists.\n\nSuggest: lists to drop (dead, failing, or adding nothing), possible false positives to allow (and for whom), and gaps. Propose changes as plan_allow_domain, plan_block_domain, or plan_add_list plans with a reason; don't apply them.",
        },
        Prompt {
            name: "upstream_health_review",
            title: "Upstream health review",
            description: "Whether the upstream DNS servers are healthy and fast, and what to change if not.",
            arguments: &[(
                "window",
                "How far back, like -1h or -24h (default -24h).",
                false,
            )],
            text: "Review my upstream DNS servers over {window}.\n\n1. upstream_health: each upstream's health, circuit breaker, failures, and latency.\n2. latency_breakdown by upstream and by stage, for the current and the previous hour.\n3. get_overview (window \"{window}\"): SERVFAIL and latency overall.\n4. get_config section upstreams: the groups and their strategies.\n\nSay which upstreams are healthy, which are slow or failing (with numbers), and whether the strategy fits. If a change would help, propose it with plan_update_upstreams (with a reason) and don't apply it.",
        },
    ]
}

/// A prompt's message with its arguments filled in (defaults for the optional ones).
fn render_prompt(p: &Prompt, args: &Value) -> Result<String, String> {
    let mut text = p.text.to_owned();
    for (name, _, required) in p.arguments {
        let v = args
            .get(*name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty());
        let v = match (v, required) {
            (Some(v), _) => v.chars().filter(|c| !c.is_control()).take(200).collect(),
            (None, true) => return Err(format!("`{name}` is required")),
            (None, false) => "-24h".to_owned(),
        };
        text = text.replace(&format!("{{{name}}}"), &v);
    }
    Ok(text)
}

/// The catalog as `tools/list` returns it. Annotations state each tool's side effects
/// (AGT-009): reads are read-only; plans change nothing until applied; `apply_plan` and the
/// immediate operations do.
pub fn catalog() -> Value {
    let ann = |read_only: bool, destructive: bool, idempotent: bool| json!({"readOnlyHint": read_only, "destructiveHint": destructive, "idempotentHint": idempotent, "openWorldHint": false});
    let mut out: Vec<Value> = tools()
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": (t.input_schema)(),
                "annotations": ann(true, false, true),
            })
        })
        .collect();
    out.extend(write_tools().iter().map(|t| {
        json!({
            "name": t.name,
            "description": t.description,
            "inputSchema": (t.input_schema)(),
            // A plan stores a plan, nothing else; the change is apply_plan's.
            "annotations": match t.effect {
                Effect::Plan => ann(false, false, false),
                Effect::Immediate => ann(false, t.destructive, false),
            },
        })
    }));
    out.extend(plan_tools().into_iter().map(|(name, description, schema, ro, de, idem)| {
        json!({"name": name, "description": description, "inputSchema": schema, "annotations": ann(ro, de, idem)})
    }));
    Value::Array(out)
}

/// MCP sessions: the client software named at `initialize` (AGT-005 attribution).
#[derive(Debug, Default)]
pub struct Sessions(Mutex<HashMap<String, String>>);

impl Sessions {
    fn start(&self, client: String) -> String {
        let id = crate::auth::crypto::random_id();
        let mut m = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if m.len() > 1000 {
            m.clear();
        }
        m.insert(id.clone(), client);
        id
    }
    fn client(&self, id: &str) -> Option<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned()
    }
}

#[derive(Debug, Clone)]
pub struct Mcp {
    /// The REST routes, called in-process with the caller's credentials.
    pub api: Router,
    pub sessions: Arc<Sessions>,
    /// Plans and the approval policy (AGT-007).
    pub auth: Arc<crate::auth::Auth>,
    /// REQ: AGT-005 — the client address of the request being served (`post` sets it), put
    /// on every in-process REST call so lockouts and the audit log see the agent's address.
    pub on_behalf_of: Option<std::net::IpAddr>,
    /// REQ: API-003 (review 06-05) — the request being served came over HTTPS by the rules of
    /// `is_https`; its in-process REST calls say so (and only then).
    pub forwarded_https: bool,
}

/// Who called: their plans key and how the audit log names them.
#[derive(Debug, Clone)]
pub struct Caller {
    pub owner: String,
    pub name: String,
}

fn tool_error(text: impl Into<String>) -> Value {
    json!({"isError": true, "content": [{"type": "text", "text": text.into()}]})
}

/// A tool result: the value as text and as structured content (when it fits).
fn tool_result(v: Value, is_error: bool) -> Value {
    let (text, truncated) = capped(&v);
    let mut result = json!({"content": [{"type": "text", "text": text}], "isError": is_error});
    if !truncated {
        result["structuredContent"] = v;
    }
    result
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn rpc_ok(id: &Value, result: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// REQ: AGT-009 (review 06-07) — takes `n − 1` more requests from an agent token's bucket
/// for a batch of `n` messages (the request took one), so a batch can't multiply its rate.
fn charge_batch(
    auth: &crate::auth::Auth,
    ext: &axum::http::Extensions,
    n: usize,
) -> Result<(), crate::problem::Problem> {
    let Ok(p) = crate::auth::routes::principal(ext) else {
        return Ok(());
    };
    let (Some(grant), crate::auth::Via::Token { id }) = (&p.agent, &p.via) else {
        return Ok(());
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    for _ in 1..n {
        if let Err(wait) = auth.agents().take(id, grant.rate_per_minute, now_ms) {
            return Err(crate::problem::Problem::new(
                crate::problem::Code::RateLimited,
                format!("this agent token is over its request rate; try again in {wait} s"),
            )
            .retry_after(wait));
        }
    }
    Ok(())
}

/// Caps a value at [`MAX_BYTES`] of JSON text (AGT-009).
fn capped(v: &Value) -> (String, bool) {
    let text = serde_json::to_string(v).unwrap_or_default();
    if text.len() <= MAX_BYTES {
        return (text, false);
    }
    let mut cut = MAX_BYTES;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    (text[..cut].to_owned(), true)
}

/// REQ: AGT-011 (T7.3) — `missingNodes` for a tool result: the nodes that didn't answer any of
/// its reads (empty when every node in scope did).
fn add_missing_nodes(out: &mut serde_json::Map<String, Value>) {
    let mut missing: Vec<String> = out
        .values()
        .filter_map(|v| v.get("missingNodes").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    missing.sort();
    missing.dedup();
    out.insert("missingNodes".into(), json!(missing));
}

/// `resources/list`.
fn resource_list() -> Value {
    json!({"resources": resources().iter().map(|r| json!({
        "uri": r.uri, "name": r.name, "title": r.title, "description": r.description, "mimeType": "application/json",
    })).collect::<Vec<_>>()})
}

/// `prompts/list`.
fn prompt_list() -> Value {
    json!({"prompts": prompts().iter().map(|p| json!({
        "name": p.name, "title": p.title, "description": p.description,
        "arguments": p.arguments.iter().map(|(n, d, r)| json!({"name": n, "description": d, "required": r})).collect::<Vec<_>>(),
    })).collect::<Vec<_>>()})
}

/// `prompts/get`: the prompt's message with its arguments filled in.
fn get_prompt(id: &Value, msg: &Value) -> Value {
    let p = msg.get("params").cloned().unwrap_or(Value::Null);
    let name = p.get("name").and_then(Value::as_str).unwrap_or_default();
    let args = p.get("arguments").cloned().unwrap_or_else(|| json!({}));
    let Some(pr) = prompts().into_iter().find(|x| x.name == name) else {
        return rpc_error(
            id,
            -32602,
            &format!("prompt `{name}` not found; see prompts/list"),
        );
    };
    match render_prompt(&pr, &args) {
        Err(e) => rpc_error(id, -32602, &format!("{name}: {e}")),
        Ok(text) => rpc_ok(
            id,
            &json!({
                "description": pr.description,
                "messages": [{"role": "user", "content": {"type": "text", "text": text}}],
            }),
        ),
    }
}

impl Mcp {
    /// One REST GET as the caller; the body (JSON or problem+json) and whether it succeeded.
    async fn get(&self, path: &str, auth: &HeaderMap, client: Option<&str>) -> (bool, Value) {
        let (status, body) = self.send("GET", path, None, auth, client, &[]).await;
        (status.is_success(), body)
    }

    /// One REST request as the caller, with `extra` headers; the status and the body.
    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        auth: &HeaderMap,
        client: Option<&str>,
        extra: &[(&str, String)],
    ) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(path);
        for h in ["authorization", "cookie", "x-csrf-token", "x-forwarded-for"] {
            if let Some(v) = auth.get(h) {
                req = req.header(h, v);
            }
        }
        if let Some(c) = client.and_then(|c| HeaderValue::from_str(c).ok()) {
            req = req.header("x-telltale-client", c);
        }
        for (k, v) in extra {
            if let Ok(v) = HeaderValue::from_str(v) {
                req = req.header(*k, v);
            }
        }
        // REQ: AGT-005 — the in-process request has no peer; it acts for the agent's.
        if self.forwarded_https {
            req = req.header("x-forwarded-proto", "https");
        }
        if let Some(ip) = self.on_behalf_of {
            req = req.extension(crate::auth::routes::OnBehalfOf(ip));
        }
        let req = match body {
            Some(b) => req
                .header("content-type", "application/json")
                .body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        };
        let Ok(req) = req else {
            return (
                StatusCode::BAD_REQUEST,
                json!({"detail": "bad request path"}),
            );
        };
        let resp = match self.api.clone().oneshot(req).await {
            Ok(r) => r,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"detail": e.to_string()}),
                );
            }
        };
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 8 << 20)
            .await
            .unwrap_or_default();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Fills in what a write left out from the entry as it is now (`Write::merge`).
    async fn merge(
        &self,
        w: &mut Write,
        auth: &HeaderMap,
        client: Option<&str>,
    ) -> Result<(), String> {
        let Some((kind, name)) = w.merge.clone() else {
            return Ok(());
        };
        let Some(Value::Object(body)) = w.body.as_mut() else {
            return Ok(());
        };
        if kind == "client" {
            let (ok, list) = self.get("/api/v1/clients", auth, client).await;
            if !ok {
                return Err(format!("reading the devices failed: {list}"));
            }
            let found = list
                .get("items")
                .and_then(Value::as_array)
                .and_then(|items| {
                    items.iter().find(|d| {
                        d.get("name")
                            .and_then(Value::as_str)
                            .is_some_and(|n| n.eq_ignore_ascii_case(&name))
                            && d.get("source").and_then(Value::as_str) != Some("seen")
                    })
                });
            match found {
                Some(d) => {
                    for k in ["match", "groups"] {
                        if !body.contains_key(k)
                            && let Some(v) = d.get(k)
                        {
                            body.insert(k.into(), v.clone());
                        }
                    }
                }
                None if body.contains_key("name") => {
                    return Err(format!(
                        "no named device `{name}` (plan_assign_client names a new one)"
                    ));
                }
                None if !body.contains_key("match") => {
                    if name.parse::<std::net::IpAddr>().is_ok() {
                        body.insert("match".into(), json!([name]));
                    } else {
                        return Err(format!(
                            "`{name}` is a new device: give `match` (its IPs, MACs, or id:<client-id>)"
                        ));
                    }
                }
                None => {}
            }
            return Ok(());
        }
        let (ok, list) = self
            .get(&format!("/api/v1/config/entries?kind={kind}"), auth, client)
            .await;
        if !ok {
            return Err(format!(
                "reading the current {kind} failed (needs config:read): {list}"
            ));
        }
        let current = list
            .get("items")
            .and_then(Value::as_array)
            .and_then(|items| {
                items
                    .iter()
                    .find(|e| e.get("name").and_then(Value::as_str) == Some(name.as_str()))
            });
        if let Some(Value::Object(def)) = current.and_then(|e| e.get("definition")) {
            for (k, v) in def {
                if k != "name" && !body.contains_key(k) {
                    body.insert(k.clone(), v.clone());
                }
            }
        }
        Ok(())
    }

    /// REQ: AGT-007 — a write tool: a plan (dry run, stored), or an immediate operation.
    async fn call_write(
        &self,
        tool: &WriteTool,
        args: &Value,
        auth: &HeaderMap,
        client: Option<&str>,
        caller: Option<&Caller>,
    ) -> Value {
        let Some(caller) = caller else {
            return tool_error("sign in to use write tools");
        };
        let Some(reason) = s(args, "reason") else {
            return tool_error(format!(
                "{}: `reason` is required: say why (it goes into the audit log)",
                tool.name
            ));
        };
        let mut w = match (tool.write)(args) {
            Ok(w) => w,
            Err(e) => return tool_error(format!("{}: {e}", tool.name)),
        };
        if let Err(e) = self.merge(&mut w, auth, client).await {
            return tool_error(format!("{}: {e}", tool.name));
        }
        let why = [("x-telltale-reason", reason.clone())];
        if tool.effect == Effect::Immediate {
            let (status, body) = self
                .send(w.method, &w.path, w.body.as_ref(), auth, client, &why)
                .await;
            return tool_result(
                json!({"done": w.summary, "result": body}),
                !status.is_success(),
            );
        }
        let dry = format!(
            "{}{}dryRun=true",
            w.path,
            if w.path.contains('?') { '&' } else { '?' }
        );
        let (status, preview) = self
            .send(w.method, &dry, w.body.as_ref(), auth, client, &why)
            .await;
        if !status.is_success() {
            return tool_result(json!({"error": preview, "planned": false}), true);
        }
        let Some(version) = preview.get("configVersion").and_then(Value::as_u64) else {
            return tool_error(format!(
                "{}: the dry run didn't report a config version",
                tool.name
            ));
        };
        let needs_approval = self.auth.agents().require_approval();
        let now = crate::plans::now();
        let plan = self.auth.plans().add(crate::plans::Plan {
            id: format!("plan_{}", crate::auth::crypto::random_id()),
            tool: tool.name.to_owned(),
            summary: w.summary,
            method: w.method.to_owned(),
            path: w.path,
            body: w.body,
            preview,
            config_version: version,
            reason,
            requested_by: caller.name.clone(),
            owner: caller.owner.clone(),
            created_unix_seconds: now,
            expires_unix_seconds: now + crate::plans::TTL_SECS,
            state: if needs_approval { "pending" } else { "ready" }.into(),
            needs_approval,
            decided_by: None,
            result: None,
        });
        let next = if needs_approval {
            "An operator has to approve this plan (Agent changes in the web UI) before apply_plan works. It expires in 10 minutes."
        } else {
            "Nothing has changed yet. Call apply_plan with the planId to make the change (within 10 minutes), or discard_plan."
        };
        tool_result(
            json!({"planId": plan.id, "state": plan.state, "summary": plan.summary, "preview": plan.preview, "expiresInSeconds": crate::plans::TTL_SECS, "next": next}),
            false,
        )
    }

    /// REQ: AGT-007 — `apply_plan`, `discard_plan`, `list_plans`.
    async fn call_plan_tool(
        &self,
        name: &str,
        args: &Value,
        auth: &HeaderMap,
        client: Option<&str>,
        caller: Option<&Caller>,
    ) -> Value {
        let Some(caller) = caller else {
            return tool_error("sign in to use plans");
        };
        if name == "list_plans" {
            let (ok, body) = self.get("/api/v1/plans", auth, client).await;
            return tool_result(body, !ok);
        }
        let Some(id) = s(args, "planId") else {
            return tool_error(format!("{name}: `planId` is required"));
        };
        let plans = self.auth.plans();
        if name == "discard_plan" {
            return match plans.transition(
                &id,
                &["pending", "ready", "approved"],
                "discarded",
                Some(&caller.owner),
                None,
            ) {
                Ok(p) => tool_result(json!({"planId": p.id, "state": p.state}), false),
                Err(e) => tool_result(serde_json::to_value(&e).unwrap_or_default(), true),
            };
        }
        let plan = match plans.transition(
            &id,
            &["ready", "approved"],
            "applying",
            Some(&caller.owner),
            None,
        ) {
            Ok(p) => p,
            Err(e) => return tool_result(serde_json::to_value(&e).unwrap_or_default(), true),
        };
        // The write as planned: refused (412) if the configuration changed since; the plan ID
        // makes a retry return the first answer.
        let extra = [
            ("x-telltale-reason", plan.reason.clone()),
            ("if-match", format!("\"{}\"", plan.config_version)),
            ("idempotency-key", plan.id.clone()),
        ];
        let (status, body) = self
            .send(
                &plan.method,
                &plan.path,
                plan.body.as_ref(),
                auth,
                client,
                &extra,
            )
            .await;
        let state = if status.is_success() {
            "applied"
        } else if status == StatusCode::PRECONDITION_FAILED {
            "stale"
        } else {
            "failed"
        };
        plans.finish(&id, state, body.clone());
        let hint = match state {
            "stale" => {
                Some("The configuration changed since this plan was made: make the plan again.")
            }
            _ => None,
        };
        tool_result(
            json!({"planId": id, "state": state, "summary": plan.summary, "result": body, "hint": hint}),
            state != "applied",
        )
    }

    async fn call_tool(
        &self,
        params: &Value,
        auth: &HeaderMap,
        client: Option<&str>,
        caller: Option<&Caller>,
    ) -> Value {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let args = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if let Some(w) = write_tools().into_iter().find(|t| t.name == name) {
            return self.call_write(&w, &args, auth, client, caller).await;
        }
        if plan_tools().iter().any(|t| t.0 == name) {
            return self.call_plan_tool(name, &args, auth, client, caller).await;
        }
        let Some(tool) = tools().into_iter().find(|t| t.name == name) else {
            return json!({"isError": true, "content": [{"type": "text", "text": format!("unknown tool `{name}`; see tools/list")}]});
        };
        let calls = match (tool.calls)(&args) {
            Ok(c) => c,
            Err(e) => {
                return json!({"isError": true, "content": [{"type": "text", "text": format!("{name}: {e}")}]});
            }
        };
        let mut out = serde_json::Map::new();
        let mut all_failed = true;
        for (key, path) in calls {
            let (ok, body) = self.get(&path, auth, client).await;
            if ok {
                all_failed = false;
                out.insert(key, body);
            } else {
                out.insert(key, json!({"error": body}));
            }
        }
        // The device profile picks the device out of the list.
        if name == "get_client_profile"
            && let Some(c) = s(&args, "client")
            && let Some(Value::Array(items)) =
                out.get("devices").and_then(|d| d.get("items")).cloned()
        {
            let found = items.into_iter().find(|d| {
                d.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|n| n.eq_ignore_ascii_case(&c))
                    || d.get("match")
                        .and_then(Value::as_array)
                        .is_some_and(|m| m.iter().any(|x| x.as_str() == Some(c.as_str())))
            });
            out.remove("devices");
            // The query log filters by address: the IP given, or the device's first one.
            let ip = if c.parse::<std::net::IpAddr>().is_ok() {
                Some(c.clone())
            } else {
                found
                    .as_ref()
                    .and_then(|d| d.get("match"))
                    .and_then(Value::as_array)
                    .and_then(|m| {
                        m.iter()
                            .filter_map(Value::as_str)
                            // An address, or a single-host network (`/32`, `/128`).
                            .map(|x| x.trim_end_matches("/32").trim_end_matches("/128"))
                            .find(|x| x.parse::<std::net::IpAddr>().is_ok())
                            .map(str::to_owned)
                    })
            };
            out.insert("device".into(), found.unwrap_or(Value::Null));
            if let Some(ip) = ip {
                let from = s(&args, "window").unwrap_or_else(|| "-24h".into());
                for (key, extra) in [
                    ("recentQueries", "&limit=50"),
                    ("slowQueries", "&minLatencyMs=200&limit=20"),
                ] {
                    let path = format!(
                        "/api/v1/queries?client={}&from={}{extra}{}",
                        enc(&ip),
                        enc(&from),
                        scope_q(&args)
                    );
                    let (ok, body) = self.get(&path, auth, client).await;
                    out.insert(key.into(), if ok { body } else { json!({"error": body}) });
                }
            } else {
                out.insert(
                    "recentQueries".into(),
                    json!({"error": "no IP address known for this device"}),
                );
            }
        }
        add_missing_nodes(&mut out);
        let structured = Value::Object(out);
        let (text, truncated) = capped(&structured);
        let mut content = vec![json!({"type": "text", "text": text})];
        if truncated {
            content.push(json!({"type": "text", "text": format!("(truncated at {} KiB: narrow the filters or page with `cursor`/`limit`)", MAX_BYTES / 1024)}));
        }
        let mut result = json!({"content": content, "isError": all_failed});
        if !truncated {
            result["structuredContent"] = structured;
        }
        result
    }

    /// `resources/read`: the resource's REST reads, as the caller, in one JSON document.
    async fn read_resource(
        &self,
        id: &Value,
        msg: &Value,
        headers: &HeaderMap,
        client: Option<&str>,
    ) -> Value {
        let uri = msg
            .get("params")
            .and_then(|p| p.get("uri"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let Some(r) = resources().into_iter().find(|r| r.uri == uri) else {
            return rpc_error(
                id,
                -32002,
                &format!("resource `{uri}` not found; see resources/list"),
            );
        };
        let mut doc = serde_json::Map::new();
        for (key, path) in r.reads {
            let (ok, body) = self.get(path, headers, client).await;
            doc.insert(
                (*key).to_owned(),
                if ok { body } else { json!({"error": body}) },
            );
        }
        let (text, truncated) = capped(&Value::Object(doc));
        let mut contents =
            vec![json!({"uri": r.uri, "mimeType": "application/json", "text": text})];
        // REQ: AGT-009 (review 06-07) — a cut document says so, as tool results do.
        if truncated {
            contents.push(json!({"uri": r.uri, "mimeType": "text/plain", "text": format!("(truncated at {} KiB: the JSON above is incomplete; use the tools for narrower reads)", MAX_BYTES / 1024)}));
        }
        rpc_ok(id, &json!({"contents": contents}))
    }

    /// One JSON-RPC message; `None` for notifications.
    pub async fn handle(
        &self,
        msg: &Value,
        headers: &HeaderMap,
        session: Option<&str>,
        caller: Option<&Caller>,
    ) -> (Option<Value>, Option<String>) {
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let method = msg
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let is_notification = msg.get("id").is_none();
        let client = session.and_then(|s| self.sessions.client(s));
        let reply = match method {
            "initialize" => {
                let p = msg.get("params").cloned().unwrap_or(Value::Null);
                let asked = p
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or(PROTOCOL_VERSION);
                let version = if SUPPORTED.contains(&asked) {
                    asked
                } else {
                    PROTOCOL_VERSION
                };
                let info = p.get("clientInfo").cloned().unwrap_or(Value::Null);
                let who = format!(
                    "{}/{}",
                    info.get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("mcp-client"),
                    info.get("version").and_then(Value::as_str).unwrap_or("?")
                )
                .chars()
                .filter(|c| !c.is_control())
                .take(100)
                .collect::<String>();
                let sid = self.sessions.start(who);
                let result = json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}, "resources": {"listChanged": false}, "prompts": {"listChanged": false}},
                    "serverInfo": {"name": "telltaledns", "title": "TelltaleDNS", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": "TelltaleDNS is a filtering DNS resolver. Start with get_overview, then narrow down with top_items, search_queries, get_client_profile, latency_breakdown, and upstream_health; explain_decision says why a name was blocked or routed. Times take relative offsets like -1h. To change something, a plan_* tool returns a planId and a preview without changing anything; apply_plan makes the change (an operator may have to approve it first). flush_cache, pause_blocking, and resume_blocking act at once. Every write needs a `reason`.",
                });
                return (Some(rpc_ok(&id, &result)), Some(sid));
            }
            "ping" => Some(rpc_ok(&id, &json!({}))),
            "tools/list" => Some(rpc_ok(&id, &json!({"tools": catalog()}))),
            // REQ: AGT-010 (T7.2) — resources and prompts.
            "resources/list" => Some(rpc_ok(&id, &resource_list())),
            "resources/templates/list" => Some(rpc_ok(&id, &json!({"resourceTemplates": []}))),
            "resources/read" => Some(
                self.read_resource(&id, msg, headers, client.as_deref())
                    .await,
            ),
            "prompts/list" => Some(rpc_ok(&id, &prompt_list())),
            "prompts/get" => Some(get_prompt(&id, msg)),
            "tools/call" => {
                let params = msg.get("params").cloned().unwrap_or(Value::Null);
                Some(rpc_ok(
                    &id,
                    &self
                        .call_tool(&params, headers, client.as_deref(), caller)
                        .await,
                ))
            }
            m if m.starts_with("notifications/") => None,
            _ if is_notification => None,
            other => Some(rpc_error(
                &id,
                -32601,
                &format!("method `{other}` not found"),
            )),
        };
        (reply, None)
    }
}

/// `POST /mcp`: one JSON-RPC message (or a batch) in, JSON out (Streamable HTTP, no SSE).
pub async fn post(
    State(mcp): State<Mcp>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    body: axum::body::Bytes,
) -> Response {
    // REQ: AGT-005 — every REST call made for this request carries its client address.
    let ip = crate::auth::routes::remote(&mcp.auth, &ext, &headers);
    let mcp = Mcp {
        on_behalf_of: Some(ip),
        forwarded_https: crate::auth::routes::is_https(&mcp.auth, &ext, &headers),
        ..mcp
    };
    // The caller, for plans (AGT-007): the session or token, and its audit name.
    let caller = crate::auth::routes::principal(&ext).ok().map(|p| Caller {
        owner: crate::plans::owner_key(&p),
        name: mcp.auth.actor(&p, ip, None).name,
    });
    let Ok(msg) = serde_json::from_slice::<Value>(&body) else {
        let e = rpc_error(&Value::Null, -32700, "parse error: the body isn't JSON");
        return (StatusCode::BAD_REQUEST, axum::Json(e)).into_response();
    };
    let session = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let mut new_session = None;
    let reply = if let Value::Array(batch) = &msg {
        // REQ: AGT-009 — one request can't queue up an unbounded amount of work.
        if batch.len() > MAX_BATCH {
            let e = rpc_error(
                &Value::Null,
                -32600,
                &format!("at most {MAX_BATCH} messages in a batch"),
            );
            return (StatusCode::BAD_REQUEST, axum::Json(e)).into_response();
        }
        // REQ: AGT-009 — each message counts against an agent's rate, as its own request
        // would (the request itself took one).
        if let Err(p) = charge_batch(&mcp.auth, &ext, batch.len()) {
            return p.into_response();
        }
        let mut out = Vec::new();
        for m in batch {
            let (r, sid) = mcp
                .handle(m, &headers, session.as_deref(), caller.as_ref())
                .await;
            new_session = new_session.or(sid);
            out.extend(r);
        }
        (!out.is_empty()).then_some(Value::Array(out))
    } else {
        let (r, sid) = mcp
            .handle(&msg, &headers, session.as_deref(), caller.as_ref())
            .await;
        new_session = sid;
        r
    };
    let mut resp = match reply {
        Some(v) => axum::Json(v).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    };
    if let Some(sid) = new_session.and_then(|s| HeaderValue::from_str(&s).ok()) {
        resp.headers_mut().insert("mcp-session-id", sid);
    }
    resp
}

/// `GET /mcp`: no server-initiated stream (every answer comes with its request).
pub async fn get() -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, [("allow", "POST")]).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: AGT-006 — the committed catalog is what the server lists (names, descriptions, and
    // schemas are a contract with agents).
    #[test]
    fn agt_006_committed_tool_catalog_matches() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/api/mcp-tools.json");
        let now = serde_json::to_string_pretty(&catalog()).unwrap() + "\n";
        if std::env::var_os("UPDATE_MCP").is_some() {
            std::fs::write(&path, &now).unwrap();
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            committed == now,
            "docs/api/mcp-tools.json is out of date: run UPDATE_MCP=1 cargo test -p telltale-api agt_006_committed"
        );
    }

    // AGT-009 — every tool states its side effects (description and annotations agree);
    // results are capped.
    #[test]
    fn agt_009_tools_state_side_effects_and_results_are_capped() {
        for t in catalog().as_array().unwrap() {
            let name = t["name"].as_str().unwrap();
            let d = t["description"].as_str().unwrap();
            let ro = t["annotations"]["readOnlyHint"].as_bool().unwrap();
            assert_eq!(d.starts_with("Read-only."), ro, "{name}");
            if name.starts_with("plan_") {
                assert!(
                    d.starts_with("Plans a change (nothing changes until apply_plan)."),
                    "{name}"
                );
                assert!(
                    t["inputSchema"]["required"]
                        .as_array()
                        .unwrap()
                        .contains(&json!("reason")),
                    "{name}"
                );
            }
            assert_eq!(t["inputSchema"]["type"], "object", "{name}");
        }
        let big = json!({"items": vec!["x".repeat(100); 1000]});
        let (text, cut) = capped(&big);
        assert!(cut && text.len() <= MAX_BYTES);
        assert!(!capped(&json!({"a": 1})).1);
    }

    #[test]
    fn agt_006_tool_arguments_become_rest_queries() {
        let t = tools();
        let find = |n: &str| t.iter().find(|x| x.name == n).unwrap();
        let q =
            (find("search_queries").calls)(&json!({"client": "tv room", "limit": 999})).unwrap();
        assert_eq!(q[0].1, "/api/v1/queries?client=tv%20room&limit=200");
        assert!((find("top_items").calls)(&json!({})).is_err());
        assert!((find("get_config").calls)(&json!({"section": "users"})).is_err());
        // AGT-011 — scope passes through to every analytics read.
        for (tool, args) in [
            ("get_overview", json!({"scope": "site:home pi"})),
            (
                "top_items",
                json!({"kind": "domains", "scope": "site:home pi"}),
            ),
            ("search_queries", json!({"scope": "site:home pi"})),
            (
                "latency_breakdown",
                json!({"by": "stage", "scope": "site:home pi"}),
            ),
        ] {
            let q = (find(tool).calls)(&args).unwrap();
            assert!(
                q[0].1.contains("scope=site:home%20pi"),
                "{tool}: {}",
                q[0].1
            );
            assert!(
                (find(tool).input_schema)()["properties"]["scope"].is_object(),
                "{tool}"
            );
        }
    }

    // AGT-010 — prompts name real tools, and fill in their arguments.
    #[test]
    fn agt_010_prompts_and_resources() {
        let names: Vec<String> = catalog()
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect();
        for p in prompts() {
            // Every word that looks like a tool name is one.
            for w in p
                .text
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            {
                if w.contains('_')
                    && w.chars().all(|c| c.is_ascii_lowercase() || c == '_')
                    && !w.starts_with('_')
                {
                    assert!(
                        names.contains(&w.to_owned()) || w == "plan_",
                        "{}: unknown tool {w}",
                        p.name
                    );
                }
            }
        }
        let inv = prompts()
            .into_iter()
            .find(|p| p.name == "investigate_device")
            .unwrap();
        let t = render_prompt(&inv, &json!({"client": "tv"})).unwrap();
        assert!(
            t.contains("\"tv\"") && t.contains("-24h") && !t.contains('{'),
            "{t}"
        );
        assert!(render_prompt(&inv, &json!({})).is_err());
        for r in resources() {
            assert!(r.uri.starts_with("telltale://"));
            for (_, path) in r.reads {
                assert!(path.starts_with("/api/v1/"), "{path}");
            }
        }
    }

    // AGT-007 — write tools become REST writes.
    #[test]
    fn agt_007_write_tools_become_rest_writes() {
        let t = write_tools();
        let find = |n: &str| t.iter().find(|x| x.name == n).unwrap();
        let w = (find("plan_block_domain").write)(
            &json!({"domain": "Ads.Example.", "groups": ["kids"], "forMinutes": 60, "reason": "r"}),
        )
        .unwrap();
        assert_eq!(
            (w.method, w.path.as_str()),
            ("PUT", "/api/v1/rules/agent-block-ads-example")
        );
        assert_eq!(w.body.as_ref().unwrap()["action"], "block");
        assert_eq!(w.body.as_ref().unwrap()["groups"], json!(["kids"]));
        assert!(
            w.summary.contains("for kids for 60 minutes"),
            "{}",
            w.summary
        );
        assert!((find("plan_add_list").write)(&json!({"name": "x"})).is_err());
        let g =
            (find("plan_update_group").write)(&json!({"name": "kids", "blockMode": "nxdomain"}))
                .unwrap();
        assert_eq!(g.body.unwrap()["block_mode"], "nxdomain");
        assert_eq!(g.merge, Some(("group", "kids".to_owned())));
        assert!((find("pause_blocking").write)(&json!({})).is_err());
    }
}
