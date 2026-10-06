use std::collections::BTreeMap;
use std::sync::Mutex;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use super::*;

/// Records what it was asked for; returns fixed data.
#[derive(Default)]
struct Fake {
    seen: Mutex<Vec<String>>,
}

const NOW: u64 = 1_791_072_000;

impl Backend for Fake {
    fn now_unix_seconds(&self) -> u64 {
        NOW
    }
    fn system_info(&self) -> SystemInfo {
        SystemInfo {
            version: "0.1.0".into(),
            node: "test".into(),
            role: "all".into(),
            uptime_seconds: 5,
            started_at: "2026-10-04T00:00:00.000Z".into(),
            starts: 1,
            unclean_starts: 0,
            listeners: vec!["udp://0.0.0.0:53".into()],
            query_log: true,
            filter_snapshot: Some(3),
            filter_names: 42,
            client_ips_masked: None,
            cluster: None,
            build: crate::model::BuildInfo {
                version: "0.1.0-edge.60".into(),
                commit: "abc1234".into(),
                date: "2026-10-05T12:00:00Z".into(),
                channel: "edge".into(),
                target: "x86_64-unknown-linux-musl".into(),
                install: "native".into(),
            },
            update: crate::model::UpdateStatus {
                state: "up_to_date".into(),
                latest: Some("0.1.0-edge.60".into()),
                latest_commit: None,
                latest_date: None,
                notes_url: None,
                checked_unix_seconds: None,
                error: None,
                how: "Run: sudo telltale self-update --channel edge --restart.".into(),
            },
        }
    }
    fn timeseries(&self, step: Step, from_s: u64, to_s: u64) -> Vec<TimeBucket> {
        self.seen
            .lock()
            .unwrap()
            .push(format!("timeseries {step:?} {from_s} {to_s}"));
        let mut by_status = BTreeMap::new();
        by_status.insert("blocked".to_owned(), 25);
        by_status.insert("cached".to_owned(), 50);
        by_status.insert("forwarded".to_owned(), 25);
        let mut by_rcode = BTreeMap::new();
        by_rcode.insert("NXDOMAIN".to_owned(), 3);
        vec![
            TimeBucket {
                start_unix_seconds: from_s,
                total: 100,
                by_status: by_status.clone(),
                by_rcode: by_rcode.clone(),
                ..TimeBucket::default()
            };
            2
        ]
    }
    fn top(&self, kind: TopKind, hour: Hour, limit: usize, client: Option<IpAddr>) -> Vec<TopItem> {
        self.seen
            .lock()
            .unwrap()
            .push(format!("top {kind:?} {hour:?} {limit} {client:?}"));
        vec![TopItem {
            groups: Vec::new(),
            key: "a.example".into(),
            name: None,
            count: 7,
            error_bound: 0,
        }]
    }
    fn latency(&self, by: LatencyBy, _: Hour) -> Vec<LatencyRow> {
        vec![LatencyRow {
            key: format!("{by:?}"),
            count: 1,
            p50_ms: 0.03,
            p90_ms: 0.05,
            p99_ms: 0.1,
            p999_ms: 0.2,
            max_ms: 0.2,
        }]
    }
    fn queries(
        &self,
        q: &QueryParams,
        from_us: u64,
        to_us: u64,
        limit: usize,
    ) -> Result<QueryPage, Problem> {
        self.seen.lock().unwrap().push(format!(
            "queries {:?} {:?} {from_us} {to_us} {limit}",
            q.name, q.name_match
        ));
        Ok(QueryPage {
            items: Vec::new(),
            next_cursor: None,
            scanned: ScanStats::default(),
            missing_nodes: Vec::new(),
        })
    }
    fn tail(
        &self,
        p: &crate::model::TailParams,
    ) -> Result<tokio::sync::mpsc::Receiver<crate::model::TailItem>, Problem> {
        if p.status.as_deref() == Some("off") {
            return Err(Problem::unavailable("the live tail is off"));
        }
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tx.try_send(crate::model::TailItem::Query(Box::new(QueryRow {
            time: "2026-10-04T12:00:00.000Z".into(),
            ts_unix_micros: 1_791_072_000_000_000,
            client: "192.168.1.20".into(),
            client_name: Some("tablet".into()),
            group: Some("kids".into()),
            name: "ads.example.com".into(),
            qtype: "A".into(),
            status: "blocked".into(),
            rcode: Some("NOERROR".into()),
            proto: "udp".into(),
            list: Some("ads".into()),
            rule: Some("domain".into()),
            total_ms: 0.1,
            upstream_ms: 0.0,
            response_bytes: 60,
            answers: 1,
            node: None,
        })))
        .unwrap();
        tx.try_send(crate::model::TailItem::Dropped(crate::model::TailDropped {
            dropped: 7,
            reason: "rate".into(),
        }))
        .unwrap();
        Ok(rx) // the sender drops here, so the stream ends after these two
    }
    fn explain(&self, p: &ExplainParams) -> Result<Explanation, Problem> {
        if p.name.is_empty() {
            return Err(Problem::invalid("`name` is empty"));
        }
        Ok(Explanation {
            name: p.name.clone(),
            qtype: "A".into(),
            client: ExplainClient {
                ip: "127.0.0.1".into(),
                mac: None,
                device: None,
                identified_by: "default".into(),
                groups: vec!["default".into()],
            },
            outcome: "resolved".into(),
            summary: "no rule applies; resolved normally".into(),
            block: None,
            paused_until_unix_seconds: None,
            filter: None,
            route: None,
            notes: Vec::new(),
        })
    }
    fn lists(&self) -> Vec<ListInfo> {
        Vec::new()
    }
    fn groups(&self) -> Vec<GroupInfo> {
        Vec::new()
    }
    fn clients(&self) -> Vec<ClientInfo> {
        Vec::new()
    }
    fn upstreams(&self) -> Vec<UpstreamInfo> {
        Vec::new()
    }
    fn promote(&self, _: PromoteRequest, _: String) -> Result<ClusterView, Problem> {
        panic!("a dry run must not promote")
    }
    fn promote_plan(&self, req: &PromoteRequest) -> Result<crate::model::PromotePlan, Problem> {
        Ok(crate::model::PromotePlan {
            applied: false,
            epoch: 4,
            emergency: req.emergency,
            impact: "would promote".into(),
        })
    }
}

/// A router plus an admin token for authenticated requests.
struct TestApp {
    router: Router,
    bearer: String,
    auth: Arc<auth::Auth>,
}

async fn send(
    app: &TestApp,
    req: Request<Body>,
) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or_default(),
    )
}

/// GET with the admin token.
async fn get(app: &TestApp, uri: &str) -> (StatusCode, String, serde_json::Value) {
    let req = Request::get(uri)
        .header("authorization", format!("Bearer {}", app.bearer))
        .body(Body::empty())
        .unwrap();
    let (status, headers, v) = send(app, req).await;
    let ctype = headers
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    (status, ctype, v)
}

fn app() -> (TestApp, Arc<Fake>) {
    let fake = Arc::new(Fake::default());
    let state = Arc::new(telltale_store::state::State::in_memory().unwrap());
    let auth = Arc::new(auth::Auth::new(state, auth::Settings::default()));
    let admin = auth
        .create_user(
            "root",
            "correct horse battery",
            auth::Role::Admin,
            false,
            NOW,
        )
        .unwrap();
    let (id, secret) = (auth::crypto::random_id(), auth::crypto::random_secret());
    auth.state()
        .create_token(
            &id,
            admin.id,
            "tests",
            &auth::crypto::secret_hash(&secret),
            "admin",
            None,
            NOW,
        )
        .unwrap();
    let router = router(Arc::clone(&fake) as Shared, Arc::clone(&auth));
    (
        TestApp {
            router,
            bearer: format!("tt_{id}_{secret}"),
            auth,
        },
        fake,
    )
}
// REQ: AGT-004, AGT-005, AGT-009 — an agent token over HTTP: its scopes and nothing else,
// a reason on every change, the kill switch, and `agent:` attribution.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one story: create, use, refuse, attribute, switch off
async fn agt_004_agent_tokens_over_http() {
    let (app, _) = app();
    let call =
        |method: &str, uri: &str, bearer: &str, body: serde_json::Value, reason: Option<&str>| {
            let mut b = Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .header("x-telltale-client", "test-agent/1.0");
            if let Some(r) = reason {
                b = b.header("x-telltale-reason", r);
            }
            b.body(Body::from(body.to_string())).unwrap()
        };
    let (s, _, v) = send(
        &app,
        call(
            "POST",
            "/api/v1/tokens",
            &app.bearer,
            serde_json::json!({"name": "helper", "kind": "agent",
                "scopes": ["analytics:read", "config:write:clients"], "ratePerMinute": 600}),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["info"]["kind"], "agent");
    assert_eq!(
        v["info"]["scopes"],
        serde_json::json!(["analytics:read", "config:write:clients"])
    );
    let agent = v["token"].as_str().unwrap().to_owned();
    let null = serde_json::Value::Null;
    let status = |r: Request<Body>| async { send(&app, r).await.0 };

    assert_eq!(
        status(call(
            "GET",
            "/api/v1/stats/summary?from=-1h",
            &agent,
            null.clone(),
            None
        ))
        .await,
        StatusCode::OK
    );
    assert_eq!(
        status(call("GET", "/api/v1/queries", &agent, null.clone(), None)).await,
        StatusCode::FORBIDDEN,
        "no querylog:read"
    );
    assert_eq!(
        status(call("GET", "/api/v1/users", &agent, null.clone(), None)).await,
        StatusCode::FORBIDDEN,
        "people only"
    );
    assert_eq!(
        status(call("GET", "/api/v1/tokens", &agent, null.clone(), None)).await,
        StatusCode::FORBIDDEN
    );
    let put = serde_json::json!({"match": ["192.168.1.40"]});
    assert_eq!(
        status(call("PUT", "/api/v1/clients/tv", &agent, put.clone(), None)).await,
        StatusCode::BAD_REQUEST,
        "agents must give a reason"
    );
    let s = status(call(
        "PUT",
        "/api/v1/clients/tv",
        &agent,
        put,
        Some("name the TV"),
    ))
    .await;
    assert!(
        s != StatusCode::BAD_REQUEST && s != StatusCode::FORBIDDEN,
        "{s}"
    );

    // Attribution: the token, its owner, and the agent software.
    let p = app
        .auth
        .authenticate(
            &auth::Presented {
                bearer: Some(&agent),
                ..auth::Presented::default()
            },
            NOW,
        )
        .unwrap()
        .unwrap();
    let mut p2 = p.clone();
    if let Some(g) = p2.agent.as_mut() {
        g.client = Some("test-agent/1.0".into());
    }
    let actor = app
        .auth
        .actor(&p2, "127.0.0.1".parse().unwrap(), Some("why".into()));
    assert_eq!(actor.name, "agent:helper (owner: root) via test-agent/1.0");
    assert_eq!(actor.kind, "agent");

    // The kill switch refuses agents, not people.
    app.auth.agents().set(false, 120);
    assert_eq!(
        status(call(
            "GET",
            "/api/v1/stats/summary?from=-1h",
            &agent,
            null.clone(),
            None
        ))
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(call(
            "GET",
            "/api/v1/stats/summary?from=-1h",
            &app.bearer,
            null,
            None
        ))
        .await,
        StatusCode::OK
    );
}

// REQ: AGT-004 — a token restricted to a group: its group's devices only, other views
// refused.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one story: create, use, refuse
async fn agt_004_group_restricted_agent() {
    let (app, _) = app();
    let call = |method: &str, uri: &str, bearer: &str, body: serde_json::Value| {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .header("x-telltale-reason", "test")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let (s, _, v) = send(
        &app,
        call(
            "POST",
            "/api/v1/tokens",
            &app.bearer,
            serde_json::json!({"name": "kids-helper", "kind": "agent", "group": "kids",
                "scopes": ["querylog:read", "analytics:read", "config:read", "config:write:clients"]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["info"]["group"], "kids");
    let t = v["token"].as_str().unwrap().to_owned();
    let null = serde_json::Value::Null;
    let st = |r| async { send(&app, r).await.0 };
    assert_eq!(
        st(call("GET", "/api/v1/stats/summary", &t, null.clone())).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        st(call("GET", "/api/v1/clients", &t, null.clone())).await,
        StatusCode::OK
    );
    assert_eq!(
        st(call(
            "PUT",
            "/api/v1/clients/tv",
            &t,
            serde_json::json!({"match": ["192.168.1.9"], "groups": ["default"]})
        ))
        .await,
        StatusCode::FORBIDDEN,
        "only into its own group"
    );
    let s = st(call(
        "PUT",
        "/api/v1/clients/tablet",
        &t,
        serde_json::json!({"match": ["192.168.1.9"], "groups": ["kids"]}),
    ))
    .await;
    assert!(
        s != StatusCode::FORBIDDEN && s != StatusCode::BAD_REQUEST,
        "{s}"
    );
    assert_eq!(
        st(call(
            "DELETE",
            "/api/v1/clients/someone-else",
            &t,
            null.clone()
        ))
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        st(call("PUT", "/api/v1/records/x.lan", &t, null)).await,
        StatusCode::FORBIDDEN
    );
    // A viewer can't mint a token that writes.
    let viewer = app
        .auth
        .create_user(
            "kid",
            "another long password",
            auth::Role::Viewer,
            false,
            NOW,
        )
        .unwrap();
    let (id, secret) = (auth::crypto::random_id(), auth::crypto::random_secret());
    app.auth
        .state()
        .create_token(
            &id,
            viewer.id,
            "v",
            &auth::crypto::secret_hash(&secret),
            "read",
            None,
            NOW,
        )
        .unwrap();
    let vt = format!("tt_{id}_{secret}");
    let (s, _, _) = send(
        &app,
        call(
            "POST",
            "/api/v1/tokens",
            &vt,
            serde_json::json!({"name": "x", "kind": "agent", "scopes": ["config:write:*"]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

// REQ: AGT-002 — promotion has a dry run: the checks and what would happen, no change.
#[tokio::test]
async fn agt_002_promote_dry_run() {
    let (app, _) = app();
    let req = Request::post("/api/v1/cluster/promote?dryRun=true")
        .header("authorization", format!("Bearer {}", app.bearer))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"emergency": true}"#))
        .unwrap();
    let (s, _, v) = send(&app, req).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["applied"], false);
    assert_eq!(v["epoch"], 4);
    assert_eq!(v["emergency"], true);
}

// REQ: AGT-006 — MCP over HTTP: initialize, list tools, call one; a tool needing a scope the
// agent lacks reports an error, not data (the REST checks apply inside).
#[tokio::test]
#[allow(clippy::too_many_lines)] // one MCP session
async fn agt_006_mcp_over_http() {
    let (app, _) = app();
    let rpc = |bearer: &str, session: Option<&str>, body: serde_json::Value| {
        let mut b = Request::post("/mcp")
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream");
        if let Some(sid) = session {
            b = b.header("mcp-session-id", sid);
        }
        b.body(Body::from(body.to_string())).unwrap()
    };
    let (s, h, v) = send(
        &app,
        rpc(&app.bearer, None, serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test-agent", "version": "1.0"}}})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["result"]["serverInfo"]["name"], "telltaledns");
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
    let sid = h
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    let (s, _, _) = send(
        &app,
        rpc(
            &app.bearer,
            Some(&sid),
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let (_, _, v) = send(
        &app,
        rpc(
            &app.bearer,
            Some(&sid),
            serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        ),
    )
    .await;
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"get_overview") && names.contains(&"search_queries"),
        "{names:?}"
    );

    let (_, _, v) = send(
        &app,
        rpc(
            &app.bearer,
            Some(&sid),
            serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "get_overview", "arguments": {"window": "-1h"}}}),
        ),
    )
    .await;
    assert_eq!(v["result"]["isError"], false, "{v}");
    assert_eq!(v["result"]["structuredContent"]["overview"]["queries"], 200);

    // An agent without querylog:read gets an error from search_queries.
    let req = Request::post("/api/v1/tokens")
        .header("authorization", format!("Bearer {}", app.bearer))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name":"mcp-agent","kind":"agent","scopes":["analytics:read"]}"#,
        ))
        .unwrap();
    let (_, _, v) = send(&app, req).await;
    let agent = v["token"].as_str().unwrap().to_owned();
    let (s, _, v) = send(
        &app,
        rpc(
            &agent,
            None,
            serde_json::json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "search_queries", "arguments": {}}}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["result"]["isError"], true, "{v}");
    assert!(
        v["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("querylog:read"),
        "{v}"
    );
    let (_, _, v) = send(
        &app,
        rpc(
            &agent,
            None,
            serde_json::json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "get_overview", "arguments": {}}}),
        ),
    )
    .await;
    assert_eq!(v["result"]["isError"], false, "{v}");
    // Unknown methods are JSON-RPC errors; bad JSON is a parse error.
    let (_, _, v) = send(
        &app,
        rpc(
            &agent,
            None,
            serde_json::json!({"jsonrpc": "2.0", "id": 6, "method": "sampling/createMessage"}),
        ),
    )
    .await;
    assert_eq!(v["error"]["code"], -32601);
    // Without credentials, nothing.
    let req = Request::post("/mcp")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(send(&app, req).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_001_summary_is_derived_from_the_series() {
    let (app, fake) = app();
    let (status, _, v) = get(&app, "/api/v1/stats/summary?from=-1h").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["queries"], 200);
    assert_eq!(v["blocked"], 50);
    assert_eq!(v["blockedPercent"], 25.0);
    assert_eq!(v["cacheHitPercent"], 66.7);
    assert_eq!(v["nxdomain"], 6);
    assert_eq!(v["activeClients"], 1);
    assert_eq!(v["latency"][0]["p50Ms"], 0.03);
    assert!(fake.seen.lock().unwrap()[0].starts_with(&format!("timeseries Minute {}", NOW - 3600)));
}

#[tokio::test]
async fn api_001_errors_are_problem_json_with_codes_and_hints() {
    let (app, _) = app();
    let (status, ctype, v) = get(&app, "/api/v1/stats/summary?from=yesterday").await;
    assert_eq!(
        (status, ctype.as_str()),
        (StatusCode::BAD_REQUEST, "application/problem+json")
    );
    assert_eq!(v["code"], "invalid_parameter");
    assert!(v["hint"].as_str().unwrap().contains("-24h"));

    let (status, _, v) = get(&app, "/api/v1/stats/top?kind=domains&scope=node:pi").await;
    assert_eq!(
        (status, v["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("unsupported_scope"))
    );

    let (status, _, v) = get(&app, "/api/v1/stats/top?kind=clients&client=10.0.0.1").await;
    assert_eq!(
        (status, v["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_parameter"))
    );

    let (status, _, v) = get(&app, "/api/v1/nope").await;
    assert_eq!(
        (status, v["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );

    let (status, _, _) = get(&app, "/api/v1/stats/top?kind=sideways").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unknown enum values are rejected"
    );
}

#[tokio::test]
async fn api_001_parameters_reach_the_backend() {
    let (app, fake) = app();
    let (status, _, _) = get(
        &app,
        "/api/v1/stats/top?kind=domains&limit=500&client=192.168.1.5",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, v) = get(
        &app,
        "/api/v1/queries?name=ads&match=suffix&from=-15m&limit=5000",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["items"], serde_json::json!([]));
    let (status, _, _) = get(&app, "/api/v1/queries?match=regex").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "match without name");
    let (status, _, v) = get(&app, "/api/v1/explain?name=x.example").await;
    assert_eq!(
        (status, v["outcome"].as_str()),
        (StatusCode::OK, Some("resolved"))
    );
    let seen = fake.seen.lock().unwrap().clone();
    assert_eq!(
        seen[0], "top Domains Current 100 Some(192.168.1.5)",
        "limit clamped to 100"
    );
    assert_eq!(
        seen[1],
        format!(
            "queries Some(\"ads\") Some(Suffix) {} 0 1000",
            (NOW - 900) * 1_000_000
        )
    );
}

// REQ: CLU-008 — a standalone node says so (the binary fills in a cluster's view).
#[tokio::test]
async fn clu_008_cluster_view_on_a_standalone_node() {
    let (app, _) = app();
    let (status, _, v) = get(&app, "/api/v1/cluster").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["enabled"], false);
    assert_eq!(v["healthy"], true);
    assert_eq!(v["nodes"].as_array().unwrap().len(), 0);
    let anonymous = Request::get("/api/v1/cluster").body(Body::empty()).unwrap();
    assert_eq!(send(&app, anonymous).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_001_openapi_is_served_and_documents_every_route() {
    let (app, _) = app();
    let (status, _, v) = get(&app, "/api/v1/openapi.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["openapi"], "3.1.0");
    let paths = v["paths"].as_object().unwrap();
    assert_eq!(paths.len(), 69);
    for (path, ops) in paths {
        for (method, op) in ops.as_object().unwrap() {
            // AGT-001: every operation has a summary and a description for agents.
            assert!(
                op["summary"].as_str().is_some_and(|s| !s.is_empty()),
                "{method} {path} summary"
            );
            assert!(
                op["description"].as_str().is_some_and(|s| s.len() > 20),
                "{method} {path} description"
            );
        }
    }
}

/// `spec/07` §1: the committed OpenAPI document must match the code. Regenerate with
/// `UPDATE_OPENAPI=1 cargo test -p telltale-api api_001_committed_openapi`.
#[test]
fn api_001_committed_openapi_matches_the_code() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/api/openapi.json");
    let doc = openapi_document() + "\n";
    if std::env::var_os("UPDATE_OPENAPI").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &doc).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == doc,
        "docs/api/openapi.json is out of date: run UPDATE_OPENAPI=1 cargo test -p telltale-api api_001_committed_openapi"
    );
}

/// API-003 over HTTP: setup, sign-in with cookie + CSRF, tokens, roles, sign-out.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one end-to-end story: sign in, CSRF, tokens, roles, sign out
async fn api_003_http_sign_in_csrf_tokens_and_roles() {
    let (app, _) = app();
    let json = |method: &str, uri: &str, body: serde_json::Value| {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    // Unauthenticated: data is closed, status and the OpenAPI document are open.
    let (s, _, v) = send(
        &app,
        Request::get("/api/v1/stats/summary")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("unauthorized"))
    );
    let (s, _, v) = send(
        &app,
        Request::get("/api/v1/auth/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        (
            s,
            v["setupRequired"].as_bool(),
            v["authenticated"].as_bool()
        ),
        (StatusCode::OK, Some(false), Some(false))
    );
    let (s, _, _) = send(
        &app,
        Request::get("/api/v1/openapi.json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // A viewer signs in: cookie + CSRF token.
    app.auth
        .create_user(
            "ana",
            "another long password",
            auth::Role::Viewer,
            false,
            NOW,
        )
        .unwrap();
    let (s, h, v) = send(
        &app,
        json(
            "POST",
            "/api/v1/auth/login",
            serde_json::json!({"username": "ana", "password": "nope nope nope"}),
        ),
    )
    .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("unauthorized"))
    );
    assert!(h.get("set-cookie").is_none());
    let (s, h, v) = send(
        &app,
        json(
            "POST",
            "/api/v1/auth/login",
            serde_json::json!({"username": "ANA", "password": "another long password"}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let set = h.get("set-cookie").unwrap().to_str().unwrap().to_owned();
    assert!(
        set.contains("HttpOnly") && set.contains("SameSite=Strict") && !set.contains("Secure"),
        "{set}"
    );
    let cookie = set.split(';').next().unwrap().to_owned();
    let csrf = v["csrfToken"].as_str().unwrap().to_owned();
    assert_eq!(v["user"]["role"], "viewer");

    let with_cookie = |method: &str, uri: &str, csrf: Option<&str>, body: serde_json::Value| {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("cookie", &cookie)
            .header("content-type", "application/json");
        if let Some(c) = csrf {
            b = b.header("x-csrf-token", c);
        }
        b.body(Body::from(body.to_string())).unwrap()
    };
    let (s, _, v) = send(
        &app,
        with_cookie(
            "GET",
            "/api/v1/stats/summary",
            None,
            serde_json::json!(null),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, v) = send(
        &app,
        with_cookie("GET", "/api/v1/auth/status", None, serde_json::json!(null)),
    )
    .await;
    assert_eq!(
        (v["user"]["username"].as_str(), v["csrfToken"].as_str()),
        (Some("ana"), Some(csrf.as_str()))
    );
    assert_eq!(s, StatusCode::OK);

    // Changes with the cookie need the CSRF header.
    let body = serde_json::json!({"name": "grafana"});
    let (s, _, v) = send(
        &app,
        with_cookie("POST", "/api/v1/tokens", None, body.clone()),
    )
    .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("csrf_rejected"))
    );
    let (s, _, v) = send(
        &app,
        with_cookie("POST", "/api/v1/tokens", Some("wrong"), body.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, _, v) = send(
        &app,
        with_cookie("POST", "/api/v1/tokens", Some(&csrf), body),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let token = v["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("tt_"));
    assert_eq!(v["info"]["scope"], "read");
    // A viewer can't mint a write token, and can't manage users.
    let (s, _, _) = send(
        &app,
        with_cookie(
            "POST",
            "/api/v1/tokens",
            Some(&csrf),
            serde_json::json!({"name": "x", "scope": "write"}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, v) = send(
        &app,
        with_cookie("GET", "/api/v1/users", None, serde_json::json!(null)),
    )
    .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden"))
    );

    // The new token works without cookies or CSRF.
    let (s, _, v) = send(
        &app,
        Request::get("/api/v1/auth/me")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        (s, v["via"].as_str(), v["role"].as_str()),
        (StatusCode::OK, Some("token"), Some("viewer"))
    );

    // Admin user management; the last admin is protected.
    let admin = |method: &str, uri: &str, body: serde_json::Value| {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", app.bearer))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let (s, _, v) = send(&app, admin("GET", "/api/v1/users", serde_json::json!(null))).await;
    assert_eq!(
        (s, v["items"].as_array().map(Vec::len)),
        (StatusCode::OK, Some(2))
    );
    let (s, _, v) = send(
        &app,
        admin(
            "PATCH",
            "/api/v1/users/1",
            serde_json::json!({"role": "viewer"}),
        ),
    )
    .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("conflict"))
    );
    let (s, _, v) = send(&app, admin("POST", "/api/v1/users", serde_json::json!({"username": "ana", "password": "another long password", "role": "viewer"}))).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("conflict"))
    );
    let (s, _, v) = send(
        &app,
        admin(
            "POST",
            "/api/v1/users",
            serde_json::json!({"username": "bob"}),
        ),
    )
    .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_parameter")),
        "bad body is problem+json"
    );
    // Disabling ana ends her session.
    let (s, _, _) = send(
        &app,
        admin(
            "PATCH",
            "/api/v1/users/2",
            serde_json::json!({"disabled": true}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = send(
        &app,
        with_cookie(
            "GET",
            "/api/v1/stats/summary",
            None,
            serde_json::json!(null),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Sign-out clears the cookie (an admin session this time).
    let (_, h, v) = send(
        &app,
        json(
            "POST",
            "/api/v1/auth/login",
            serde_json::json!({"username": "root", "password": "correct horse battery"}),
        ),
    )
    .await;
    let cookie = h
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let csrf = v["csrfToken"].as_str().unwrap().to_owned();
    let out = Request::post("/api/v1/auth/logout")
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .body(Body::empty())
        .unwrap();
    let (s, h, _) = send(&app, out).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(
        h.get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let (s, _, _) = send(
        &app,
        Request::get("/api/v1/auth/me")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

/// API-005: the UI is served at `/` without sign-in, with a strict CSP; `/api` misses stay
/// problem+json. Passes with or without a built `ui/dist`.
#[tokio::test]
async fn api_005_ui_is_served_with_security_headers() {
    let (app, _) = app();
    let get = |uri: &str| {
        Request::get(uri)
            .header("accept-encoding", "gzip")
            .body(Body::empty())
            .unwrap()
    };
    let (s, h, _) = send(&app, get("/")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(h["content-type"].to_str().unwrap().starts_with("text/html"));
    let csp = h["content-security-policy"].to_str().unwrap();
    assert!(
        csp.contains("script-src 'self'") && !csp.contains("unsafe-inline"),
        "{csp}"
    );
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["cache-control"], "no-cache");
    let (s, h, v) = send(&app, get("/api/v1/nope")).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
    assert_eq!(h["content-type"], "application/problem+json");
    for bad in ["/assets/nope.js", "/assets/../Cargo.toml", "/index.html.gz"] {
        let (s, _, _) = send(&app, get(bad)).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{bad}");
    }
    let (s, _, _) = send(&app, Request::post("/").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
}

/// OBS-008: the live tail is Server-Sent Events with `query` and `dropped` events, signed in.
#[tokio::test]
async fn obs_008_live_tail_streams_server_sent_events() {
    let (app, _) = app();
    let (s, _, _) = send(
        &app,
        Request::get("/api/v1/queries/stream")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let req = Request::get("/api/v1/queries/stream?status=blocked")
        .header("authorization", format!("Bearer {}", app.bearer))
        .body(Body::empty())
        .unwrap();
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("event: query\n"), "{text}");
    assert!(text.contains("id: 1791072000000000\n"), "{text}");
    assert!(text.contains("\"name\":\"ads.example.com\""), "{text}");
    assert!(
        text.contains("event: dropped\ndata: {\"dropped\":7,\"reason\":\"rate\"}"),
        "{text}"
    );
    let (s, _, v) = get(&app, "/api/v1/queries/stream?rate=0").await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_parameter"))
    );
    let (s, _, v) = get(&app, "/api/v1/queries/stream?status=off").await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("unavailable"))
    );
}

/// API-006, AGT-005: changes are audited with who (token and owner), from where, why, and
/// what changed; the chain verifies; only admins read it.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one story: changes, reading, verifying, paging, access
async fn api_006_changes_are_audited_and_the_chain_verifies() {
    let (app, _) = app();
    let req = |method: &str, uri: &str, body: serde_json::Value, reason: Option<&str>| {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", app.bearer))
            .header("content-type", "application/json");
        if let Some(r) = reason {
            b = b.header("x-telltale-reason", r);
        }
        b.body(Body::from(body.to_string())).unwrap()
    };
    let (s, _, v) = send(&app, req("POST", "/api/v1/users", serde_json::json!({"username": "ana", "password": "another long password", "role": "viewer"}), Some("new family member"))).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let id = v["id"].as_i64().unwrap();
    let (s, _, _) = send(
        &app,
        req(
            "PATCH",
            &format!("/api/v1/users/{id}"),
            serde_json::json!({"role": "operator", "password": "a different password"}),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, v) = send(
        &app,
        req(
            "POST",
            "/api/v1/tokens",
            serde_json::json!({"name": "ci", "scope": "read"}),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let token_id = v["info"]["id"].as_str().unwrap().to_owned();
    let (s, _, _) = send(
        &app,
        req(
            "DELETE",
            &format!("/api/v1/tokens/{token_id}"),
            serde_json::json!(null),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    let (s, _, v) = get(&app, "/api/v1/audit").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let items = v["items"].as_array().unwrap();
    let actions: Vec<&str> = items
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(
        actions,
        ["token.revoke", "token.create", "user.update", "user.create"]
    );
    let create = &items[3];
    assert_eq!(create["actor"], "token:tests (owner: root)");
    assert_eq!(
        (create["actorKind"].as_str(), create["target"].as_str()),
        (Some("token"), Some("ana"))
    );
    assert_eq!(create["reason"], "new family member");
    assert_eq!(create["detail"]["role"], "viewer");
    let update = &items[2]["detail"];
    assert_eq!(
        update["role"],
        serde_json::json!({"from": "viewer", "to": "operator"})
    );
    assert_eq!(update["password"], "changed", "never the password itself");
    assert!(!v.to_string().contains("a different password"));
    assert_eq!(items[1]["detail"]["name"], "ci");

    let (s, _, v) = get(&app, "/api/v1/audit/verify").await;
    assert_eq!(
        (s, v["ok"].as_bool(), v["entries"].as_u64()),
        (StatusCode::OK, Some(true), Some(4))
    );
    assert_eq!(v["headHash"], items[0]["hash"]);

    let (_, _, v) = get(&app, "/api/v1/audit?action=user.&limit=1").await;
    assert_eq!(v["items"][0]["action"], "user.update");
    let cursor = v["nextCursor"].as_str().unwrap().to_owned();
    let (_, _, v) = get(
        &app,
        &format!("/api/v1/audit?action=user.&limit=1&cursor={cursor}"),
    )
    .await;
    assert_eq!(v["items"][0]["action"], "user.create");

    // A viewer can't read the audit log.
    app.auth
        .create_user("vic", "a viewer password", auth::Role::Viewer, false, NOW)
        .unwrap();
    let (_, h, v) = send(
        &app,
        Request::post("/api/v1/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"username": "vic", "password": "a viewer password"}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    let cookie = h["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert!(v["csrfToken"].is_string());
    let (s, _, _) = send(
        &app,
        Request::get("/api/v1/audit")
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // ... and the sign-in itself was recorded.
    let (_, _, v) = get(&app, "/api/v1/audit?action=auth.login").await;
    assert_eq!(v["items"][0]["actor"], "vic");
}

/// API-003: behind a trusted proxy, lockouts and audit entries use the forwarded client
/// address, so one client's failures don't lock everyone out through the proxy.
#[tokio::test]
async fn api_003_trusted_proxy_forwards_the_client_address() {
    let state = Arc::new(telltale_store::state::State::in_memory().unwrap());
    let settings = auth::Settings {
        // Test requests carry no peer address, which reads as 0.0.0.0: make that the proxy.
        trusted_proxies: vec![
            ("0.0.0.0".parse().unwrap(), 32),
            ("10.0.0.0".parse().unwrap(), 8),
        ],
        ..auth::Settings::default()
    };
    let a = Arc::new(auth::Auth::new(state, settings));
    a.create_user(
        "ana",
        "correct horse battery",
        auth::Role::Viewer,
        false,
        NOW,
    )
    .unwrap();
    let router = router(Arc::new(Fake::default()) as Shared, Arc::clone(&a));
    let login = |xff: &str, pw: &str| {
        Request::post("/api/v1/auth/login")
            .header("content-type", "application/json")
            .header("x-forwarded-for", xff)
            .body(Body::from(
                serde_json::json!({"username": "nobody", "password": pw}).to_string(),
            ))
            .unwrap()
    };
    // Six failures from 192.168.1.66 (forged left-hand entry ignored; 10.x is another proxy).
    for _ in 0..6 {
        let r = router
            .clone()
            .oneshot(login("6.6.6.6, 192.168.1.66, 10.1.2.3", "wrong password!"))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }
    let r = router
        .clone()
        .oneshot(login("192.168.1.66", "wrong password!"))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "that client is locked"
    );
    // Another client through the same proxy is not.
    let ok = Request::post("/api/v1/auth/login")
        .header("content-type", "application/json")
        .header("x-forwarded-for", "192.168.1.20")
        .body(Body::from(
            serde_json::json!({"username": "ana", "password": "correct horse battery"}).to_string(),
        ))
        .unwrap();
    assert_eq!(
        router.clone().oneshot(ok).await.unwrap().status(),
        StatusCode::OK
    );
    let lock = a
        .state()
        .audit_page(None, 10, Some("auth.lockout"), None)
        .unwrap();
    assert!(lock.iter().any(|e| e.target == "192.168.1.66"), "{lock:?}");
    let login = a
        .state()
        .audit_page(None, 10, Some("auth.login"), None)
        .unwrap();
    assert_eq!(login[0].remote.as_deref(), Some("192.168.1.20"));
}
