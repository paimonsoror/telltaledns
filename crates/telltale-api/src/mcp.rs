//! The MCP server (REQ: AGT-006, AGT-009; T6.6, ADR-010, ADR-065): `POST /mcp` speaks the
//! Model Context Protocol (JSON-RPC 2.0 over Streamable HTTP) so AI agents can read the
//! resolver with the same rights as the REST API.
//!
//! Every tool is a thin wrapper over REST routes, called in-process with the caller's own
//! credentials: scopes, group restrictions, rate limits, privacy levels, and the agent kill
//! switch apply exactly as they do to REST calls. The tools are read-only (`spec/13` §3.1);
//! writes come with plan/apply (§3.2, P1).

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
            input_schema: || json!({"type": "object", "properties": {"window": window_schema()}, "additionalProperties": false}),
            calls: |a| {
                let from = s(a, "window").unwrap_or_else(|| "-24h".into());
                Ok(vec![(
                    "overview".into(),
                    format!("/api/v1/stats/summary?from={}", enc(&from)),
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
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Items (default 10)."}
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
                "cursor": {"type": "string", "description": "From the previous page's nextCursor."}
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
                "window": window_schema()
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
                "hour": {"type": "string", "enum": ["current", "previous"], "description": "Which hour (default current)."}
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
                        &[("by", "by"), ("hour", "hour")],
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
            description: "Read-only. Filter lists: size, last update, errors, and how many blocks each caused. Find dead or useless lists.",
            input_schema: || json!({"type": "object", "properties": {}, "additionalProperties": false}),
            calls: |_| Ok(vec![("lists".into(), "/api/v1/lists".into())]),
        },
        Tool {
            name: "find_anomalies",
            description: "Read-only. Device anomalies with their evidence: rate spikes, heavy volume to one domain, behavior drift, and beaconing (regular call-home patterns). Alert-only; nothing is blocked automatically.",
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
            name: "cluster_status",
            description: "Read-only. The cluster as this node sees it: members, roles, epochs, sync lag, versions, health checks, each node's machine (memory, CPU, disk, temperature, with the last hour and warnings), and recent events. On a standalone node it says so and still shows its machine.",
            input_schema: || json!({"type": "object", "properties": {}, "additionalProperties": false}),
            calls: |_| Ok(vec![("cluster".into(), "/api/v1/cluster".into())]),
        },
        Tool {
            name: "get_config",
            description: "Read-only. One section of the running configuration, as the API shows it (no secrets): groups, lists, devices (clients), upstreams, local names (records), or forwarded domains (forwards). Also returns system information.",
            input_schema: || {
                json!({"type": "object", "properties": {
                "section": {"type": "string", "enum": ["groups", "lists", "clients", "upstreams", "records", "forwards"], "description": "Which section."}
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

/// The catalog as `tools/list` returns it.
pub fn catalog() -> Value {
    Value::Array(
        tools()
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": (t.input_schema)(),
                    "annotations": {"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
                })
            })
            .collect(),
    )
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
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn rpc_ok(id: &Value, result: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
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

impl Mcp {
    /// One REST GET as the caller; the body (JSON or problem+json) and whether it succeeded.
    async fn get(&self, path: &str, auth: &HeaderMap, client: Option<&str>) -> (bool, Value) {
        let mut req = Request::get(path);
        for h in [
            "authorization",
            "cookie",
            "x-forwarded-for",
            "x-forwarded-proto",
        ] {
            if let Some(v) = auth.get(h) {
                req = req.header(h, v);
            }
        }
        if let Some(c) = client.and_then(|c| HeaderValue::from_str(c).ok()) {
            req = req.header("x-telltale-client", c);
        }
        let Ok(req) = req.body(Body::empty()) else {
            return (false, json!({"detail": "bad request path"}));
        };
        let resp = match self.api.clone().oneshot(req).await {
            Ok(r) => r,
            Err(e) => return (false, json!({"detail": e.to_string()})),
        };
        let ok = resp.status().is_success();
        let bytes = axum::body::to_bytes(resp.into_body(), 8 << 20)
            .await
            .unwrap_or_default();
        (ok, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn call_tool(&self, params: &Value, auth: &HeaderMap, client: Option<&str>) -> Value {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let args = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
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
                        "/api/v1/queries?client={}&from={}{extra}",
                        enc(&ip),
                        enc(&from)
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

    /// One JSON-RPC message; `None` for notifications.
    pub async fn handle(
        &self,
        msg: &Value,
        headers: &HeaderMap,
        session: Option<&str>,
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
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "telltaledns", "title": "TelltaleDNS", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": "TelltaleDNS is a filtering DNS resolver. These tools are read-only. Start with get_overview, then narrow down with top_items, search_queries, get_client_profile, latency_breakdown, and upstream_health; explain_decision says why a name was blocked or routed. Times take relative offsets like -1h.",
                });
                return (Some(rpc_ok(&id, &result)), Some(sid));
            }
            "ping" => Some(rpc_ok(&id, &json!({}))),
            "tools/list" => Some(rpc_ok(&id, &json!({"tools": catalog()}))),
            "tools/call" => {
                let params = msg.get("params").cloned().unwrap_or(Value::Null);
                Some(rpc_ok(
                    &id,
                    &self.call_tool(&params, headers, client.as_deref()).await,
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
pub async fn post(State(mcp): State<Mcp>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
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
        let mut out = Vec::new();
        for m in batch {
            let (r, sid) = mcp.handle(m, &headers, session.as_deref()).await;
            new_session = new_session.or(sid);
            out.extend(r);
        }
        (!out.is_empty()).then_some(Value::Array(out))
    } else {
        let (r, sid) = mcp.handle(&msg, &headers, session.as_deref()).await;
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

    // AGT-009 — every tool says it's read-only; results are capped.
    #[test]
    fn agt_009_tools_state_side_effects_and_results_are_capped() {
        for t in tools() {
            assert!(t.description.starts_with("Read-only."), "{}", t.name);
            assert_eq!((t.input_schema)()["type"], "object", "{}", t.name);
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
    }
}
