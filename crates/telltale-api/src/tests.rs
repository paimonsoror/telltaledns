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
            listeners: vec!["udp://0.0.0.0:53".into()],
            query_log: true,
            filter_snapshot: Some(3),
            filter_names: 42,
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
        })
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
}

async fn get(app: &Router, uri: &str) -> (StatusCode, String, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let ctype = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        ctype,
        serde_json::from_slice(&bytes).unwrap_or_default(),
    )
}

fn app() -> (Router, Arc<Fake>) {
    let fake = Arc::new(Fake::default());
    (router(Arc::clone(&fake) as Shared), fake)
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

#[tokio::test]
async fn api_001_openapi_is_served_and_documents_every_route() {
    let (app, _) = app();
    let (status, _, v) = get(&app, "/api/v1/openapi.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["openapi"], "3.1.0");
    let paths = v["paths"].as_object().unwrap();
    assert_eq!(paths.len(), 11);
    for (path, ops) in paths {
        let op = &ops["get"];
        // AGT-001: every operation has a summary and a description for agents.
        assert!(
            op["summary"].as_str().is_some_and(|s| !s.is_empty()),
            "{path} summary"
        );
        assert!(
            op["description"].as_str().is_some_and(|s| s.len() > 20),
            "{path} description"
        );
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
