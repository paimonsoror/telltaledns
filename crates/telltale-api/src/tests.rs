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
    /// REQ: OBS-014 — acknowledged finding IDs.
    acks: Mutex<Vec<String>>,
    /// REQ: OBS-033 — markers written.
    notes: Mutex<Vec<crate::model::Annotation>>,
    /// REQ: OPS-011 — the fake's one pseudonym map has been handed out.
    map_taken: std::sync::atomic::AtomicBool,
    /// REQ: OBS-010 (ADR-179) — each managed write's name and whether an admin made it.
    by_admin: Mutex<Vec<(String, bool)>>,
}

/// The one finding the fake reports.
fn fake_finding_id() -> String {
    crate::model::anomaly_id("rate_spike", "192.168.1.20", None, NOW - 3600, 3600)
}

const NOW: u64 = 1_791_072_000;

impl Backend for Fake {
    fn now_unix_seconds(&self) -> u64 {
        NOW
    }
    // REQ: FLT-017 — the map rule writes reach the backend as managed writes.
    fn write_managed(
        &self,
        w: crate::ManagedWrite,
    ) -> crate::BoxFuture<Result<crate::model::ConfigChange, Problem>> {
        self.by_admin
            .lock()
            .unwrap()
            .push((w.name.clone(), w.by_admin));
        self.seen.lock().unwrap().push(format!(
            "managed {:?} {} {}",
            w.kind,
            w.name,
            w.body.map(|b| b.to_string()).unwrap_or_default()
        ));
        Box::pin(async { Err(Problem::unavailable("recorded")) })
    }
    fn annotations(&self, f: &crate::model::AnnotationFilter) -> Vec<crate::model::Annotation> {
        let mut v: Vec<_> = self
            .notes
            .lock()
            .unwrap()
            .iter()
            .filter(|a| a.t_unix_ms >= f.from_ms && a.t_unix_ms < f.to_ms)
            .cloned()
            .collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.t_unix_ms));
        v.truncate(f.limit);
        v
    }
    fn annotate(&self, a: crate::model::Annotation) -> Result<crate::model::Annotation, Problem> {
        self.notes.lock().unwrap().push(a.clone());
        Ok(a)
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
            maintenance: None,
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
            by_status: None,
            key: "a.example".into(),
            name: None,
            count: 7,
            error_bound: 0,
        }]
    }
    fn top_clients_rolling(
        &self,
        limit: usize,
        group: Option<&str>,
    ) -> Result<Vec<TopItem>, Problem> {
        self.seen
            .lock()
            .unwrap()
            .push(format!("top_clients_rolling {limit} {group:?}"));
        Ok(vec![TopItem {
            groups: Vec::new(),
            key: "10.0.0.9".into(),
            name: None,
            count: 3,
            error_bound: 0,
            by_status: None,
        }])
    }
    fn top_range(&self, kind: TopKind, from_s: u64, to_s: u64, limit: usize) -> Vec<TopItem> {
        self.seen
            .lock()
            .unwrap()
            .push(format!("top_range {kind:?} {from_s} {to_s} {limit}"));
        vec![TopItem {
            groups: Vec::new(),
            key: "10.0.0.1".into(),
            name: None,
            count: 9,
            error_bound: 0,
            by_status: None,
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
        // OBS-017 — two queries logged in the microsecond a trace ID names.
        let row = |name: &str| QueryRow {
            time: "2026-10-04T12:00:00.000Z".into(),
            ts_unix_micros: from_us,
            client: "192.168.1.20".into(),
            client_name: None,
            group: None,
            name: name.into(),
            qtype: "A".into(),
            status: "forwarded".into(),
            rcode: Some("NOERROR".into()),
            proto: "udp".into(),
            list: None,
            rule: None,
            total_ms: 30.0,
            upstream_ms: 29.0,
            response_bytes: 60,
            answers: 1,
            node: None,
        };
        let items = if q.trace.is_some() {
            vec![row("ads.example.com"), row("cdn.example.com")]
        } else {
            Vec::new()
        };
        Ok(QueryPage {
            next_cursor: q.trace.is_some().then(|| "more".into()),
            items,
            scanned: ScanStats::default(),
            missing_nodes: Vec::new(),
            client_truncated: false,
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
                mac_from: None,
                device: None,
                identified_by: "default".into(),
                groups: vec!["default".into()],
                workload: None,
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
        // This node's own hits: 1 (the cluster's, from `list_hits`, are what the API shows).
        let list = |name: &str| ListInfo {
            name: name.into(),
            kind: "block".into(),
            enabled: true,
            mode: "enforce".into(),
            source: "inline".into(),
            local: false,
            state: "ok".into(),
            error: None,
            bytes: 0,
            lines: 1,
            entries: 1,
            unique: 1,
            regex_skipped: 0,
            hits: 1,
            overlap: Vec::new(),
            last_checked_unix_seconds: None,
            last_changed_unix_seconds: None,
            stale_days: None,
        };
        vec![list("ads"), list("quiet")]
    }
    fn list_hits(&self) -> BTreeMap<String, u64> {
        BTreeMap::from([("ads".to_owned(), 42)])
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
    fn support_package(
        &self,
        req: &crate::model::SupportPackageRequest,
        dry_run: bool,
    ) -> Result<crate::SupportPackageOutput, Problem> {
        Ok(crate::SupportPackageOutput {
            file_name: "telltale-support-node-1-20261016T000000Z.tar.gz".into(),
            id: (req.keep_map && !dry_run).then(|| "abc123".to_owned()),
            manifest: serde_json::json!({ "level": req.level.clone().unwrap_or_else(|| "strict".into()), "dryRun": dry_run }),
            archive: if dry_run {
                Vec::new()
            } else {
                vec![0x1f, 0x8b, 8, 0]
            },
        })
    }
    fn support_map(&self, id: &str) -> Option<String> {
        (id == "abc123"
            && !self
                .map_taken
                .swap(true, std::sync::atomic::Ordering::SeqCst))
        .then(|| "device-1\tlg-tv\n".to_owned())
    }
    fn anomalies(&self, _: u64) -> Vec<AnomalyFinding> {
        let mut v = vec![AnomalyFinding {
            id: fake_finding_id(),
            kind: "rate_spike".into(),
            client: "192.168.1.20".into(),
            client_name: Some("tablet".into()),
            domain: None,
            window_start: "2026-10-04T11:00:00.000Z".into(),
            window_seconds: 3600,
            observed: 4100.0,
            baseline: 119.0,
            spread: 30.0,
            threshold: 400.0,
            detail: "4100 queries in an hour; usually 119 ± 30".into(),
            nodes: Vec::new(),
            acknowledged: None,
            informational: false,
            muted_by: None,
            rhythm: None,
        }];
        // REQ: OBS-038 — one a mute matched: listed only with `muted=true`.
        v.push(AnomalyFinding {
            id: crate::model::anomaly_id("nxdomain_storm", "192.168.1.30", None, NOW - 7200, 60),
            kind: "nxdomain_storm".into(),
            client: "192.168.1.30".into(),
            client_name: Some("lg-tv".into()),
            domain: None,
            window_start: "2026-10-04T10:00:00.000Z".into(),
            window_seconds: 60,
            observed: 225.0,
            baseline: 260.0,
            spread: 0.0,
            threshold: 30.0,
            detail: "225 NXDOMAIN answers in a minute".into(),
            nodes: Vec::new(),
            acknowledged: None,
            informational: false,
            muted_by: Some("tv-sweep".into()),
            rhythm: None,
        });
        self.annotate_acks(&mut v);
        v
    }
    fn annotate_acks(&self, items: &mut [AnomalyFinding]) {
        let acks = self.acks.lock().unwrap();
        for f in items {
            f.acknowledged = acks.contains(&f.id).then(|| crate::model::AnomalyAckInfo {
                by: "root".into(),
                at: "2026-10-04T12:00:00.000Z".into(),
                note: None,
            });
        }
    }
    fn anomaly_ack(
        &self,
        w: AnomalyAckWrite,
    ) -> BoxFuture<Result<crate::model::AnomalyAckResult, Problem>> {
        let mut acks = self.acks.lock().unwrap();
        let mut changed = 0;
        for id in w.ids {
            let had = acks.contains(&id);
            if w.ack && !had {
                acks.push(id);
                changed += 1;
            } else if !w.ack && had {
                acks.retain(|a| *a != id);
                changed += 1;
            }
        }
        Box::pin(async move {
            Ok(crate::model::AnomalyAckResult {
                changed,
                unknown: Vec::new(),
            })
        })
    }
    fn promote(&self, _: PromoteRequest, _: String) -> Result<ClusterView, Problem> {
        panic!("a dry run must not promote")
    }
    // REQ: OPS-014 — `pod` is upgraded by its image; every other node takes a request.
    fn node_update(
        &self,
        node: &str,
        call: crate::NodeUpdateCall,
    ) -> BoxFuture<Result<crate::model::NodeUpdate, Problem>> {
        let state = match &call {
            crate::NodeUpdateCall::Request { to, by } => {
                self.seen
                    .lock()
                    .unwrap()
                    .push(format!("update {node} to={to} by={by}"));
                Some("requested".to_owned())
            }
            crate::NodeUpdateCall::Status => None,
            // REQ: OPS-014, AGT-002 — the node's checks, nothing written.
            crate::NodeUpdateCall::DryRun { to } => {
                self.seen
                    .lock()
                    .unwrap()
                    .push(format!("dry-run {node} to={to}"));
                Some("would_request".to_owned())
            }
        };
        let r = if node == "pod" && state.is_some() {
            Err(Problem::new(
                crate::problem::Code::UpdateUnsupported,
                "pod runs in a Kubernetes pod",
            ))
        } else {
            Ok(crate::model::NodeUpdate {
                node: node.to_owned(),
                version: "0.7.0".into(),
                install: "native".into(),
                channel: Some("stable".into()),
                enabled: true,
                held: None,
                state,
                pending: None,
                last: None,
            })
        };
        Box::pin(async move { r })
    }
    // REQ: CLU-001 (ADR-155) — `stale` can be removed, `up` only with force, `primary` never.
    fn remove_node(
        &self,
        w: crate::NodeRemoveWrite,
    ) -> BoxFuture<Result<crate::model::NodeRemoval, Problem>> {
        self.seen.lock().unwrap().push(format!(
            "remove {} force={} dry={} by={}",
            w.node, w.force, w.dry_run, w.by
        ));
        let r = match w.node.as_str() {
            "primary" => Err(Problem::new(
                crate::problem::Code::NodeIsPrimary,
                "it is the primary",
            )),
            "up" if !w.force => Err(Problem::new(crate::problem::Code::NodeIsUp, "it is up")),
            "stale" | "up" => Ok(crate::model::NodeRemoval {
                node_id: w.node.clone(),
                site: "pi".into(),
                up: w.node == "up",
                eligible: true,
                witness: false,
                ephemeral: false,
                held_cluster_key: true,
                voters_after: 2,
                automatic_failover_after: false,
                removed: !w.dry_run,
                notes: vec!["rotate the cluster CA".into()],
            }),
            other => Err(crate::cluster_nodes_api::unknown(other)),
        };
        Box::pin(async move { r })
    }
    fn promote_plan(&self, req: &PromoteRequest) -> Result<crate::model::PromotePlan, Problem> {
        Ok(crate::model::PromotePlan {
            applied: false,
            epoch: 4,
            emergency: req.emergency,
            impact: "would promote".into(),
        })
    }
    fn check_list(
        &self,
        _: serde_json::Value,
    ) -> BoxFuture<Result<crate::model::CheckResult, Problem>> {
        // What a page that isn't a list looks like to the parser.
        Box::pin(async {
            Ok(crate::model::CheckResult {
                ok: false,
                detail: "0 rules from 2 lines (2 invalid, 0 unsupported)".into(),
                rules: Some(0),
                warnings: vec![
                    "line 1: <title>internal dashboard</title> (not a rule)".into(),
                    "line 2: token=hunter2 (not a rule)".into(),
                ],
                ..crate::model::CheckResult::default()
            })
        })
    }
}

/// A router plus an admin token for authenticated requests, and the admin's signed-in
/// session for account changes (T10.7, ADR-142: tokens can't create or revoke tokens).
struct TestApp {
    router: Router,
    bearer: String,
    cookie: String,
    csrf: String,
    auth: Arc<auth::Auth>,
}

impl TestApp {
    /// A signed-in session for `user` (cookie header, CSRF token), on the real clock.
    fn session_for(&self, user: &telltale_store::state::User) -> (String, String) {
        let s = self
            .auth
            .start_session(user, "127.0.0.1".parse().unwrap(), auth_now())
            .unwrap();
        (format!("{}={}", auth::routes::COOKIE, s.cookie), s.csrf)
    }

    /// A request from the admin's signed-in session.
    fn signed_in(&self, method: &str, uri: &str, body: serde_json::Value) -> Request<Body> {
        with_session(&self.cookie, &self.csrf, method, uri, body)
    }
}

#[allow(clippy::needless_pass_by_value)] // called with `json!(..)` like the other helpers
fn with_session(
    cookie: &str,
    csrf: &str,
    method: &str,
    uri: &str,
    body: serde_json::Value,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("x-csrf-token", csrf)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Sessions are checked against the real clock, not [`NOW`].
fn auth_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(NOW, |d| d.as_secs())
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
    (app_over(Arc::clone(&fake) as Shared), fake)
}

/// [`app`] over another backend.
fn app_over(backend: Shared) -> TestApp {
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
    let sess = auth
        .start_session(&admin, "127.0.0.1".parse().unwrap(), auth_now())
        .unwrap();
    let router = router(backend, Arc::clone(&auth));
    TestApp {
        router,
        bearer: format!("tt_{id}_{secret}"),
        cookie: format!("{}={}", auth::routes::COOKIE, sess.cookie),
        csrf: sess.csrf,
        auth,
    }
}
// REQ: OBS-014, OBS-015 — acknowledging anomalies over HTTP: an operator's change, audited,
// reflected in the list and its filter; a viewer can't; health is a plain read.
/// REQ: OPS-011 (ADR-156) — a support package is an admin's: a viewer is refused; an admin gets the
/// archive as an attachment (and the map's ID), a dry run gets the manifest, the map comes once, a
/// wrong request is refused with a hint, and each is in the audit log without its content.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one flow: viewer, admin, dry run, map, errors, audit
async fn ops_011_a_support_package_is_an_admins() {
    let (app, _) = app();
    let vic = app
        .auth
        .create_user("vic", "a viewer password", auth::Role::Viewer, false, NOW)
        .unwrap();
    let (tid, secret) = (auth::crypto::random_id(), auth::crypto::random_secret());
    app.auth
        .state()
        .create_token(
            &tid,
            vic.id,
            "ro",
            &auth::crypto::secret_hash(&secret),
            "read",
            None,
            NOW,
        )
        .unwrap();
    let viewer = format!("tt_{tid}_{secret}");
    let make = |bearer: &str, uri: &str, body: serde_json::Value| {
        Request::post(uri)
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let url = "/api/v1/system/support-package";
    let (s, _, _) = send(&app, make(&viewer, url, serde_json::json!({}))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "a viewer can't");
    let req = Request::get("/api/v1/system/support-package/abc123/map")
        .header("authorization", format!("Bearer {viewer}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, req).await.0, StatusCode::FORBIDDEN);

    // An admin: the archive as an attachment, with the map's ID when asked.
    let (s, h, _) = send(
        &app,
        make(
            &app.bearer,
            url,
            serde_json::json!({"level": "standard", "keepMap": true}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h["content-type"], "application/gzip");
    assert!(
        h["content-disposition"]
            .to_str()
            .unwrap()
            .starts_with("attachment; filename=\"telltale-support-")
    );
    assert_eq!(h["x-support-package-id"], "abc123");
    assert_eq!(h["cache-control"], "no-store");
    // No body at all is a strict package.
    let empty = Request::post(url)
        .header("authorization", format!("Bearer {}", app.bearer))
        .body(Body::empty())
        .unwrap();
    let (s, h, _) = send(&app, empty).await;
    assert_eq!(s, StatusCode::OK);
    assert!(h.get("x-support-package-id").is_none());
    // A dry run answers with the manifest.
    let (s, _, v) = send(
        &app,
        make(
            &app.bearer,
            &format!("{url}?dryRun=true"),
            serde_json::json!({}),
        ),
    )
    .await;
    assert_eq!(
        (s, v["dryRun"].as_bool(), v["level"].as_str()),
        (StatusCode::OK, Some(true), Some("strict"))
    );
    // The map: once.
    let map = |bearer: &str| {
        Request::get("/api/v1/system/support-package/abc123/map")
            .header("authorization", format!("Bearer {bearer}"))
            .body(Body::empty())
            .unwrap()
    };
    let (s, h, _) = send(&app, map(&app.bearer)).await;
    assert_eq!(
        (s, h["content-type"].to_str().unwrap()),
        (StatusCode::OK, "text/plain; charset=utf-8")
    );
    assert_eq!(
        send(&app, map(&app.bearer)).await.0,
        StatusCode::NOT_FOUND,
        "once"
    );
    // A wrong request names the field and says what to do.
    let (s, _, v) = send(
        &app,
        make(&app.bearer, url, serde_json::json!({"level": "loose"})),
    )
    .await;
    assert!(s.is_client_error(), "{s}");
    assert!(v["detail"].as_str().unwrap().contains("level"), "{v}");
    let (s, _, _) = send(
        &app,
        make(&app.bearer, url, serde_json::json!({"querySample": 5})),
    )
    .await;
    assert!(s.is_client_error(), "no query names at strict");
    // The audit log has the package and the map, with counts and no content.
    let audit = app
        .auth
        .state()
        .audit_page(None, 20, Some("support.package"), None)
        .unwrap();
    assert_eq!(audit.len(), 3, "{audit:?}");
    let audit = app
        .auth
        .state()
        .audit_page(None, 20, Some("support.package.map"), None)
        .unwrap();
    assert_eq!(audit.len(), 1, "{audit:?}");
}

/// REQ: OBS-038 (ADR-161) — a finding a mute matched is left out of the list unless `muted=true`,
/// and then says which mute.
#[tokio::test]
async fn obs_038_muted_findings_are_listed_only_when_asked_for() {
    let (app, _) = app();
    let (_, _, v) = get(&app, "/api/v1/analytics/anomalies").await;
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{v}");
    assert!(items[0].get("mutedBy").is_none());
    let (_, _, v) = get(&app, "/api/v1/analytics/anomalies?muted=true").await;
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{v}");
    let muted: Vec<&serde_json::Value> = items
        .iter()
        .filter(|f| f.get("mutedBy").is_some())
        .collect();
    assert_eq!(muted.len(), 1);
    assert_eq!(muted[0]["mutedBy"], "tv-sweep");
    assert_eq!(muted[0]["kind"], "nxdomain_storm");
}

#[tokio::test]
async fn obs_014_acknowledging_anomalies_over_http() {
    let (app, fake) = app();
    let id = fake_finding_id();
    let post = |uri: &str, bearer: &str, body: serde_json::Value| {
        Request::post(uri)
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let other = crate::model::anomaly_id("beacon", "10.0.0.9", Some("x.example"), NOW, 3600);
    let (s, _, v) = send(
        &app,
        post(
            "/api/v1/analytics/anomalies/acknowledge",
            &app.bearer,
            serde_json::json!({"ids": [id, other], "note": "the tablet's update"}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["changed"], 2);
    assert_eq!(
        v["unknown"],
        serde_json::json!([other]),
        "not a current finding"
    );
    assert_eq!(fake.acks.lock().unwrap().len(), 2);

    let (_, _, v) = get(&app, "/api/v1/analytics/anomalies").await;
    assert_eq!(v["items"][0]["id"], id);
    assert_eq!(v["items"][0]["acknowledged"]["by"], "root");
    let (_, _, v) = get(&app, "/api/v1/analytics/anomalies?acknowledged=false").await;
    assert_eq!(v["items"].as_array().unwrap().len(), 0);

    let audit = app
        .auth
        .state()
        .audit_page(None, 10, Some("anomaly.ack"), None)
        .unwrap();
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].target, "2 findings");

    let (s, _, v) = send(
        &app,
        post(
            "/api/v1/analytics/anomalies/acknowledge",
            &app.bearer,
            serde_json::json!({"ids": ["not-an-id"]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");

    // A viewer reads, but can't acknowledge.
    let vic = app
        .auth
        .create_user("vic", "a viewer password", auth::Role::Viewer, false, NOW)
        .unwrap();
    let (tid, secret) = (auth::crypto::random_id(), auth::crypto::random_secret());
    app.auth
        .state()
        .create_token(
            &tid,
            vic.id,
            "ro",
            &auth::crypto::secret_hash(&secret),
            "read",
            None,
            NOW,
        )
        .unwrap();
    let viewer = format!("tt_{tid}_{secret}");
    let (s, _, _) = send(
        &app,
        post(
            "/api/v1/analytics/anomalies/unacknowledge",
            &viewer,
            serde_json::json!({"ids": [id]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    let (s, _, v) = send(
        &app,
        post(
            "/api/v1/analytics/anomalies/unacknowledge",
            &app.bearer,
            serde_json::json!({"ids": [id]}),
        ),
    )
    .await;
    assert_eq!((s, v["changed"].as_u64()), (StatusCode::OK, Some(1)));
    let (_, _, v) = get(&app, "/api/v1/analytics/anomalies?acknowledged=false").await;
    assert_eq!(v["items"][0]["id"], id, "counts again");

    let (s, _, v) = get(&app, "/api/v1/system/health").await;
    assert_eq!((s, v["level"].as_str()), (StatusCode::OK, Some("healthy")));
}

// REQ: OBS-009 (T7.14, regression 2026-11-15) — a list's hits are the cluster's (the backend's
// `list_hits`), not the API node's own: on a cluster whose replicas answer the queries, the
// primary serving the UI showed 0 for every list.
#[tokio::test]
async fn obs_009_list_hits_are_the_clusters() {
    let (app, _) = app();
    let (s, _, v) = get(&app, "/api/v1/lists").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["items"][0]["name"], "ads");
    assert_eq!(v["items"][0]["hits"], 42);
    assert_eq!(v["items"][1]["name"], "quiet");
    assert_eq!(v["items"][1]["hits"], 0, "no node used it");
}

// REQ: OBS-016 — the objectives over HTTP: worked out from the last 6 hours' minutes and the
// window's hours of the (federated) time buckets.
#[tokio::test]
async fn obs_016_slo_over_http() {
    let (app, fake) = app();
    let (s, _, v) = get(&app, "/api/v1/stats/slo").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["enabled"], true);
    assert_eq!(v["windowDays"], 30);
    let o = &v["objectives"];
    assert_eq!(o[0]["name"], "availability");
    assert_eq!(o[0]["targetPercent"], 99.9);
    assert_eq!(o[0]["sliPercent"], 100.0);
    assert_eq!(o[0]["budgetRemainingPercent"], 100.0);
    assert_eq!(o[1]["name"], "latency");
    assert_eq!(o[1]["latencyMs"], 250);
    assert_eq!(o[1]["burnRates"][2]["window"], "1h");
    let seen = fake.seen.lock().unwrap().clone();
    assert!(
        seen.contains(&format!("timeseries Minute {} {}", NOW - 6 * 3600, NOW + 1)),
        "{seen:?}"
    );
    assert!(
        seen.contains(&format!(
            "timeseries Hour {} {}",
            NOW - 30 * 86_400,
            NOW + 1
        )),
        "{seen:?}"
    );
    let (s, _, _) = get(&app, "/api/v1/stats/slo?scope=bogus").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
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
        app.signed_in(
            "POST",
            "/api/v1/tokens",
            serde_json::json!({"name": "helper", "kind": "agent",
                "scopes": ["analytics:read", "config:write:clients"], "ratePerMinute": 600}),
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
        app.signed_in(
            "POST",
            "/api/v1/tokens",
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
    let (cookie, csrf) = app.session_for(&viewer);
    let (s, _, v) = send(
        &app,
        with_session(
            &cookie,
            &csrf,
            "POST",
            "/api/v1/tokens",
            serde_json::json!({"name": "x", "kind": "agent", "scopes": ["config:write:*"]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(v["detail"].as_str().unwrap().contains("role"), "{v}");
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

// REQ: CLU-001 (ADR-155, GitHub issue #5) — removing a node: admin only, `force` and `dryRun`
// reach the backend with the actor, and the refusals carry stable codes.
#[tokio::test]
async fn clu_001_removing_a_node_over_the_api() {
    let (app, fake) = app();
    let del = |path: &str| {
        Request::delete(path)
            .header("authorization", format!("Bearer {}", app.bearer))
            .body(Body::empty())
            .unwrap()
    };
    let (s, _, v) = send(&app, del("/api/v1/cluster/nodes/stale")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["nodeId"], "stale");
    assert_eq!(v["removed"], true);
    assert_eq!(v["heldClusterKey"], true);
    assert_eq!(v["votersAfter"], 2);
    assert_eq!(v["automaticFailoverAfter"], false);
    let (s, _, v) = send(&app, del("/api/v1/cluster/nodes/stale?dryRun=true")).await;
    assert_eq!(
        (s, &v["removed"]),
        (StatusCode::OK, &serde_json::json!(false))
    );
    // Up needs force.
    let (s, _, v) = send(&app, del("/api/v1/cluster/nodes/up")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert!(v["type"].as_str().unwrap().ends_with("node_is_up"), "{v}");
    let (s, _, v) = send(&app, del("/api/v1/cluster/nodes/up?force=true")).await;
    assert_eq!((s, &v["up"]), (StatusCode::OK, &serde_json::json!(true)));
    // The primary, and a node nobody knows.
    let (s, _, v) = send(&app, del("/api/v1/cluster/nodes/primary")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert!(
        v["type"].as_str().unwrap().ends_with("node_is_primary"),
        "{v}"
    );
    let (s, _, v) = send(&app, del("/api/v1/cluster/nodes/nobody")).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    let seen = fake.seen.lock().unwrap().join("\n");
    assert!(
        seen.contains("remove stale force=false dry=false by="),
        "{seen}"
    );
    assert!(seen.contains("remove stale force=false dry=true"), "{seen}");
    assert!(seen.contains("remove up force=true dry=false"), "{seen}");
    // A viewer can't.
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
    let (cookie, csrf) = app.session_for(&viewer);
    let req = with_session(
        &cookie,
        &csrf,
        "DELETE",
        "/api/v1/cluster/nodes/stale",
        serde_json::Value::Null,
    );
    let (s, _, v) = send(&app, req).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
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
        .header("cookie", &app.cookie)
        .header("x-csrf-token", &app.csrf)
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

// REQ: API-005 (ADR-158) — `hour=rolling` reads the last 60 minutes, for clients only.
#[tokio::test]
async fn api_005_top_clients_over_the_rolling_hour() {
    let (app, fake) = app();
    let (status, _, v) = get(&app, "/api/v1/stats/top?kind=clients&hour=rolling&limit=50").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["items"][0]["key"], "10.0.0.9");
    assert_eq!(v["items"][0]["errorBound"], 0);
    assert!(
        fake.seen
            .lock()
            .unwrap()
            .iter()
            .any(|s| s == "top_clients_rolling 50 None")
    );
    // With a group (as AGT-004 forces for a group-restricted agent), narrowed to it.
    let (status, _, _) = get(
        &app,
        "/api/v1/stats/top?kind=clients&hour=rolling&group=kids",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        fake.seen
            .lock()
            .unwrap()
            .iter()
            .any(|s| s == "top_clients_rolling 10 Some(\"kids\")")
    );
    let (status, _, v) = get(&app, "/api/v1/stats/top?kind=domains&hour=rolling").await;
    assert_eq!(
        (status, v["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_parameter"))
    );
    // The clock hours still read the hourly lists.
    let (status, _, _) = get(&app, "/api/v1/stats/top?kind=clients&hour=previous").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        fake.seen
            .lock()
            .unwrap()
            .iter()
            .any(|s| s == "top Clients Previous 10 None")
    );
}

/// REQ: OBS-004 (ADR-160) — `from` (and `to`) read a top list over a window, and the summary's
/// active clients count the window's devices; `from` doesn't mix with one hour, one client, or
/// one group.
#[tokio::test]
async fn obs_004_top_lists_take_a_window() {
    let (app, fake) = app();
    let (status, _, v) = get(&app, "/api/v1/stats/top?kind=clients&from=-24h").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["items"][0]["count"], 9);
    let (status, _, _) = get(
        &app,
        "/api/v1/stats/top?kind=blocked&from=-7d&to=-1d&limit=5",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, v) = get(&app, "/api/v1/stats/summary?from=-48h&to=-24h").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["activeClients"], 1);
    let seen = fake.seen.lock().unwrap().clone();
    for want in [
        format!("top_range Clients {} {} 10", NOW - 86_400, NOW + 1),
        format!("top_range Blocked {} {} 5", NOW - 7 * 86_400, NOW - 86_400),
        format!(
            "top_range Clients {} {} 1000",
            NOW - 2 * 86_400,
            NOW - 86_400
        ),
    ] {
        assert!(seen.contains(&want), "{want} not in {seen:?}");
    }
    for bad in [
        "/api/v1/stats/top?kind=clients&to=-1h",
        "/api/v1/stats/top?kind=clients&from=-1h&hour=previous",
        "/api/v1/stats/top?kind=clients&from=-1h&group=iot",
        "/api/v1/stats/top?kind=domains&from=-1h&client=10.0.0.1",
        "/api/v1/stats/top?kind=clients&from=-1h&to=-2h",
        "/api/v1/stats/top?kind=clients&from=yesterday",
    ] {
        let (status, _, v) = get(&app, bad).await;
        assert_eq!(
            (status, v["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_parameter")),
            "{bad}"
        );
    }
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

// REQ: OBS-017 (ADR-110) — `trace` searches the microsecond its ID names (whatever `from`
// says) and keeps only the row whose fields give that ID; anything but 32 hex digits is
// refused.
#[tokio::test]
async fn obs_017_queries_by_trace_id() {
    let (app, fake) = app();
    let ts = 1_791_072_000_123_456;
    let id = telltale_telemetry::event::trace_id(ts, "192.168.1.20", "A", "ads.example.com");
    let hex = telltale_telemetry::event::trace_hex(&id);
    let (status, _, v) = get(&app, &format!("/api/v1/queries?trace={hex}&from=-15m")).await;
    assert_eq!(status, StatusCode::OK);
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{v}");
    assert_eq!(items[0]["name"], "ads.example.com");
    assert!(v.get("nextCursor").is_none(), "one query: no more pages");
    assert_eq!(
        fake.seen.lock().unwrap().last().unwrap(),
        &format!("queries None None {ts} {} 100", ts + 1)
    );
    for bad in ["xyz", "00", &"0".repeat(32)] {
        let (status, _, v) = get(&app, &format!("/api/v1/queries?trace={bad}")).await;
        assert_eq!(
            (status, v["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_parameter")),
            "{bad}"
        );
    }
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
    // 86 with OPS-010's /nodes/{id}/maintenance, OBS-024's /simulate and
    // /simulate-settings/default, and OBS-025's /clients/identities and /clients/{id}/identity;
    // 93 with CLU-013's /cluster/rollout-settings/default, /cluster/rollout, …/promote, …/abort,
    // /cluster/versions, /cluster/versions/{version}/pin, and /cluster/pin; 94 with OBS-033's
    // /annotations; 95 with OBS-027's /stats/slo/attribution; 96 with OBS-029's
    // /stats/heatmap; 98 with OBS-030's /stats/latency/heatmap and /exemplars; 99 with
    // OBS-032's /stats/flow.
    // 100 with OBS-028's /cluster/compare; 101 with OBS-031's /clients/{id}/rhythm; 102 with
    // OBS-034's /clients/{id}/timeline.
    // 105 with OBS-035's /auth/display, /displays and /displays/{id}.
    // 108 with FLT-017's /kubernetes/workloads, /kubernetes/status and /kubernetes/map/{key}.
    // 112 with CLU-014's /nodes/{id}/drill, /drills, /drills/{id} and /clients/affinity.
    // 113 with CLU-001's /cluster/nodes/{id}.
    // 114 with OBS-038's /anomaly-mutes/{name}; 116 with OPS-011's /system/support-package and
    // /system/support-package/{id}/map; 117 with T8.2's router routes; 118 with OPS-014's
    // /nodes/{id}/update.
    assert_eq!(paths.len(), 118);
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

/// REQ: FLT-006, CLU-002 (ADR-183) — a backend that doesn't override `identity_for_peer` answers a
/// peer's identity read with nothing (not with its own `identity`, which on a federating backend
/// asks every node): it cannot start a fan-out on a peer's behalf.
#[test]
fn clu_002_the_default_peer_identity_read_answers_nothing() {
    let fake = Fake::default();
    assert!(fake.identity_for_peer("192.168.1.20").is_err());
}

/// `spec/07` §1: the committed OpenAPI document must match the code. Regenerate with
/// `UPDATE_OPENAPI=1 cargo test -p telltale-api api_001_committed_openapi`.
#[test]
fn api_001_committed_openapi_matches_the_code() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/api/openapi.json");
    let doc = generated_openapi_document() + "\n";
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

/// REQ: API-001, NFR-001 (ADR-168) — `GET /api/v1/openapi.json` serves the committed file, byte
/// for byte (the document is compiled in from it, not generated while running).
#[test]
fn api_001_the_served_openapi_is_the_committed_file() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/api/openapi.json");
    let committed = std::fs::read_to_string(path).unwrap();
    assert_eq!(openapi_document().to_owned() + "\n", committed);
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
        app.signed_in(
            "POST",
            "/api/v1/tokens",
            serde_json::json!({"name": "ci", "scope": "read"}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let token_id = v["info"]["id"].as_str().unwrap().to_owned();
    let (s, _, _) = send(
        &app,
        app.signed_in(
            "DELETE",
            &format!("/api/v1/tokens/{token_id}"),
            serde_json::json!(null),
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

// REQ: AGT-009 — a pre-save list check shows the fetched sample lines to operators; an
// agent learns how many lines were unusable and why, not what they said.
#[tokio::test]
async fn agt_009_list_check_samples_are_for_operators() {
    let (app, _) = app();
    let call = |bearer: &str| {
        Request::post("/api/v1/checks/list")
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .header("x-telltale-reason", "checking a list")
            .body(Body::from(r#"{"url":"http://127.0.0.1:9/x"}"#))
            .unwrap()
    };
    let (s, _, v) = send(&app, call(&app.bearer)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        v["warnings"][1].as_str().unwrap().contains("hunter2"),
        "{v}"
    );
    let req = Request::post("/api/v1/tokens")
        .header("cookie", &app.cookie)
        .header("x-csrf-token", &app.csrf)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name":"lists","kind":"agent","scopes":["config:write:lists"]}"#,
        ))
        .unwrap();
    let (s, _, v) = send(&app, req).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let agent = v["token"].as_str().unwrap().to_owned();
    let (s, _, v) = send(&app, call(&agent)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let text = v["warnings"].to_string();
    assert!(
        !text.contains("hunter2") && text.contains("2 line(s)") && text.contains("not a rule"),
        "{v}"
    );
}

// REQ: OPS-010, AGT-004 — maintenance requests over HTTP: a day at most and a reason required
// (422 each), agents (`ops:maintenance`) at most two hours, with the cap in the hint.
#[tokio::test]
async fn ops_010_maintenance_requests_over_http() {
    let (app, _) = app();
    let post = |token: &str, body: &str| {
        Request::post("/api/v1/nodes/local/maintenance")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("x-telltale-reason", "SD card swap")
            .body(Body::from(body.to_owned()))
            .unwrap()
    };
    let (s, _, v) = send(&app, post(&app.bearer, r#"{"forSecs":86401,"reason":"x"}"#)).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("maintenance_too_long")
        ),
        "{v}"
    );
    let (s, _, v) = send(&app, post(&app.bearer, r#"{"forSecs":600}"#)).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("maintenance_invalid")
        ),
        "{v}"
    );
    let req = Request::post("/api/v1/tokens")
        .header("cookie", &app.cookie)
        .header("x-csrf-token", &app.csrf)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name":"maint","kind":"agent","scopes":["ops:maintenance"]}"#,
        ))
        .unwrap();
    let (s, _, v) = send(&app, req).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let agent = v["token"].as_str().unwrap().to_owned();
    let (s, _, v) = send(
        &app,
        post(&agent, r#"{"forSecs":10800,"reason":"kernel upgrade"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(v["hint"].as_str().unwrap().contains("2 hours"), "{v}");
    // Within the cap the request reaches the backend (this test backend has no maintenance).
    let (s, _, v) = send(
        &app,
        post(&agent, r#"{"forSecs":3600,"reason":"kernel upgrade"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{v}");
}

// REQ: OPS-014 (ADR-182) — a refused update request is audited too (`node.update.refused`, with
// the node's problem code and the node asked); a dry run isn't audited.
#[tokio::test]
async fn ops_014_a_refused_update_request_is_audited() {
    let (app, _) = app();
    let post = |path: &str| {
        Request::post(path)
            .header("authorization", format!("Bearer {}", app.bearer))
            .header("content-type", "application/json")
            .header("x-telltale-reason", "release day")
            .body(Body::from(r#"{"to":"0.8.0"}"#))
            .unwrap()
    };
    let (s, _, v) = send(&app, post("/api/v1/nodes/pod/update")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (s, _, _) = send(&app, post("/api/v1/nodes/dns-02/update?dryRun=true")).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, v) = get(&app, "/api/v1/audit").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let items = v["items"].as_array().unwrap();
    let refused: Vec<&serde_json::Value> = items
        .iter()
        .filter(|e| e["action"] == "node.update.refused")
        .collect();
    assert_eq!(refused.len(), 1, "{v}");
    assert!(
        refused[0].to_string().contains("update_unsupported"),
        "{}",
        refused[0]
    );
    assert!(
        !items.iter().any(|e| e["action"] == "node.update.request"),
        "a dry run isn't audited: {v}"
    );
}

// REQ: OPS-014, AGT-002 (ADR-182) — `?dryRun=true` asks the node to make its checks only: the
// call is a dry run, never a request.
#[tokio::test]
async fn ops_014_a_dry_run_reaches_the_node_as_one() {
    let (app, fake) = app();
    let (s, _, v) = send(
        &app,
        Request::post("/api/v1/nodes/dns-02/update?dryRun=true")
            .header("authorization", format!("Bearer {}", app.bearer))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"to":"0.8.0"}"#))
            .unwrap(),
    )
    .await;
    assert_eq!(
        (s, v["state"].as_str()),
        (StatusCode::OK, Some("would_request")),
        "{v}"
    );
    {
        let seen = fake.seen.lock().unwrap();
        assert!(
            seen.iter().any(|l| l == "dry-run dns-02 to=0.8.0")
                && !seen.iter().any(|l| l.starts_with("update ")),
            "a dry run reaches the node as one, never as a request: {seen:?}"
        );
    }
}

// REQ: OPS-014, AGT-004 — update requests over HTTP: the version is checked (422), the request
// reaches the node's backend with the actor, a pod says it's upgraded by its image (409), the
// read is for any agent with `analytics:read`, and the request only for `cluster:upgrade`.
#[tokio::test]
async fn ops_014_update_requests_over_http() {
    let (app, fake) = app();
    let post = |token: &str, node: &str, body: &str| {
        Request::post(format!("/api/v1/nodes/{node}/update"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("x-telltale-reason", "release day")
            .body(Body::from(body.to_owned()))
            .unwrap()
    };
    let get = |token: &str| {
        Request::get("/api/v1/nodes/dns-02/update")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    let (s, _, v) = send(&app, post(&app.bearer, "dns-02", r#"{"to":"0.8"}"#)).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("update_invalid")),
        "{v}"
    );
    let (s, _, v) = send(
        &app,
        post(&app.bearer, "dns-02", r#"{"to":"0.8.0","force":true}"#),
    )
    .await;
    assert!(s.is_client_error(), "unknown fields are refused: {s} {v}");
    let (s, _, v) = send(
        &app,
        post(&app.bearer, "dns-02", r#"{"to":"0.8.0-edge.393"}"#),
    )
    .await;
    assert_eq!(
        (s, v["state"].as_str()),
        (StatusCode::OK, Some("requested")),
        "{v}"
    );
    assert!(
        fake.seen
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.starts_with("update dns-02 to=0.8.0-edge.393 by=")),
        "{:?}",
        fake.seen.lock().unwrap()
    );
    let (s, _, v) = send(&app, post(&app.bearer, "pod", r#"{"to":"0.8.0"}"#)).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("update_unsupported")),
        "{v}"
    );
    let token = |scopes: &str| {
        Request::post("/api/v1/tokens")
            .header("cookie", &app.cookie)
            .header("x-csrf-token", &app.csrf)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"name":"up-{}","kind":"agent","scopes":[{scopes}]}}"#,
                scopes.len()
            )))
            .unwrap()
    };
    let (s, _, v) = send(&app, token(r#""analytics:read""#)).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let reader = v["token"].as_str().unwrap().to_owned();
    let (s, _, v) = send(&app, token(r#""analytics:read","cluster:upgrade""#)).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let upgrader = v["token"].as_str().unwrap().to_owned();
    let (s, _, v) = send(&app, get(&reader)).await;
    assert_eq!(
        (s, v["version"].as_str()),
        (StatusCode::OK, Some("0.7.0")),
        "{v}"
    );
    let (s, _, v) = send(&app, post(&reader, "dns-02", r#"{"to":"0.8.0"}"#)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, _, v) = send(&app, post(&upgrader, "dns-02", r#"{"to":"0.8.0"}"#)).await;
    assert_eq!(
        (s, v["state"].as_str()),
        (StatusCode::OK, Some("requested")),
        "{v}"
    );
}

// REQ: OBS-024, AGT-004 — simulations over HTTP: `simulate` needs a dry run; agents need
// `querylog:read` (and `config:read` for a whole configuration), never a group restriction;
// `POST /simulate` needs no reason header (it changes nothing).
#[tokio::test]
async fn obs_024_simulation_requests_over_http() {
    let (app, _) = app();
    let put = |token: &str, query: &str| {
        Request::put(format!("/api/v1/rules/r1{query}"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("x-telltale-reason", "trying it")
            .body(Body::from(r#"{"action":"block","domain":"x.example"}"#))
            .unwrap()
    };
    let sim = |token: &str| {
        Request::post("/api/v1/simulate")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"config":{},"window":"24h"}"#))
            .unwrap()
    };
    let code = |v: &serde_json::Value| v["code"].as_str().map(str::to_owned);
    let (s, _, v) = send(&app, put(&app.bearer, "?simulate=24h")).await;
    assert_eq!(
        (s, code(&v).as_deref()),
        (StatusCode::BAD_REQUEST, Some("invalid_parameter")),
        "{v}"
    );
    let (s, _, v) = send(&app, put(&app.bearer, "?dryRun=true&simulateUntil=-1h")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    // With a dry run the request reaches the backend (this one makes no changes: 503).
    let (s, _, v) = send(&app, put(&app.bearer, "?dryRun=true&simulate=24h")).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    let (s, _, v) = send(&app, sim(&app.bearer)).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{v}");

    let token = |scopes: &str, group: Option<&str>| {
        let body = serde_json::json!({"name": format!("t-{scopes}-{group:?}"), "kind": "agent",
            "scopes": scopes.split(',').collect::<Vec<_>>(), "group": group});
        Request::post("/api/v1/tokens")
            .header("cookie", &app.cookie)
            .header("x-csrf-token", &app.csrf)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let agent = |scopes: &'static str, group: Option<&'static str>| {
        let req = token(scopes, group);
        let app = &app;
        async move {
            let (s, _, v) = send(app, req).await;
            assert_eq!(s, StatusCode::CREATED, "{v}");
            v["token"].as_str().unwrap().to_owned()
        }
    };
    let writer = agent("config:write:rules", None).await;
    let (s, _, v) = send(&app, put(&writer, "?dryRun=true&simulate=24h")).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(
        v["detail"].as_str().unwrap().contains("querylog:read"),
        "{v}"
    );
    // `auto` (what plan tools send) is skipped for it, not refused.
    let (s, _, v) = send(&app, put(&writer, "?dryRun=true&simulate=auto")).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    let reader = agent("querylog:read", None).await;
    let (s, _, v) = send(&app, sim(&reader)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(v["detail"].as_str().unwrap().contains("config:read"), "{v}");
    let both = agent("querylog:read,config:read", None).await;
    let (s, _, v) = send(&app, sim(&both)).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "no reason needed: {v}");
}

// REQ: OBS-025 — the identity routes answer (this backend identifies nothing).
#[tokio::test]
async fn obs_025_identity_routes() {
    let (app, _) = app();
    let get = |path: &str| {
        Request::get(path)
            .header("authorization", format!("Bearer {}", app.bearer))
            .body(Body::empty())
            .unwrap()
    };
    let (s, _, v) = send(&app, get("/api/v1/clients/identities")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["items"], serde_json::json!([]));
    let (s, _, v) = send(&app, get("/api/v1/clients/192.168.1.20/identity")).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{v}");
}

// REQ: OBS-024 — `simulate` and `simulateUntil` as the backend takes them.
#[test]
fn obs_024_simulate_parameters() {
    use crate::config_api::{WriteOpts, simulate_opts};
    let opts = |dry_run: bool, simulate: Option<&str>, until: Option<&str>| WriteOpts {
        dry_run,
        simulate: simulate.map(str::to_owned),
        simulate_until: until.map(str::to_owned),
    };
    assert_eq!(simulate_opts(&opts(true, None, None), NOW).unwrap(), None);
    assert_eq!(
        simulate_opts(&opts(false, Some("auto"), None), NOW).unwrap(),
        None
    );
    assert!(simulate_opts(&opts(false, Some("24h"), None), NOW).is_err());
    let s = simulate_opts(&opts(true, Some("true"), None), NOW)
        .unwrap()
        .unwrap();
    assert_eq!((s.window, s.auto, s.until_s), (None, false, None));
    let s = simulate_opts(&opts(true, Some("auto"), None), NOW)
        .unwrap()
        .unwrap();
    assert!(s.auto);
    let s = simulate_opts(&opts(true, Some("7d"), Some("-1h")), NOW)
        .unwrap()
        .unwrap();
    assert_eq!(
        (s.window.as_deref(), s.until_s),
        (Some("7d"), Some(NOW - 3600))
    );
    assert!(simulate_opts(&opts(true, Some("24h"), Some("soon")), NOW).is_err());
}

// REQ: OBS-024 (T13.1) — issue #69: an end of `now` (or an empty one) is no end at all, so the
// backend's default applies: the end of the request's own second. Read as the whole second
// `now`, it ended at the start of that second and left out what had just been logged. Any other
// end stays exactly what it says.
#[test]
fn obs_024_until_now_is_the_default() {
    use crate::config_api::{WriteOpts, simulate_opts};
    let until_of = |until: Option<&str>| {
        simulate_opts(
            &WriteOpts {
                dry_run: true,
                simulate: Some("24h".to_owned()),
                simulate_until: until.map(str::to_owned),
            },
            NOW,
        )
        .unwrap()
        .unwrap()
        .until_s
    };
    for given in [None, Some("now"), Some(" now "), Some("")] {
        assert_eq!(until_of(given), None, "{given:?}");
    }
    assert_eq!(until_of(Some("-1h")), Some(NOW - 3600));
    let at = "2026-10-03T12:00:00Z";
    assert_eq!(
        until_of(Some(at)),
        Some(crate::time::parse_time(at, NOW).unwrap())
    );
}

// REQ: AGT-005 — a change made through MCP is audited with the agent's address: the REST
// call behind the tool runs in-process and has no peer address of its own.
#[tokio::test]
async fn agt_005_mcp_changes_keep_the_client_address() {
    let (app, _) = app();
    let mut req = Request::post("/mcp")
        .header("authorization", format!("Bearer {}", app.bearer))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "flush_cache", "arguments": {"reason": "stale answers"}}})
            .to_string(),
        ))
        .unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [192, 168, 1, 77],
            40_000,
        ))));
    let (s, _, v) = send(&app, req).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["result"]["isError"], false, "{v}");
    let flush = app
        .auth
        .state()
        .audit_page(None, 10, Some("cache.flush"), None)
        .unwrap();
    assert_eq!(flush.len(), 1, "{flush:?}");
    assert_eq!(flush[0].remote.as_deref(), Some("192.168.1.77"));
    assert_eq!(flush[0].reason.as_deref(), Some("stale answers"));
}

// REQ: AGT-009 (review 06-04) — an agent's rate limit counts tool calls: the REST read behind
// `get_overview` doesn't take a second request from the bucket.
#[tokio::test]
async fn agt_009_a_tool_call_costs_one_request() {
    let (app, _) = app();
    let (s, _, v) = send(
        &app,
        Request::post("/api/v1/tokens")
            .header("cookie", &app.cookie)
            .header("x-csrf-token", &app.csrf)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"name": "slow", "kind": "agent",
                    "scopes": ["analytics:read"], "ratePerMinute": 2})
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let agent = v["token"].as_str().unwrap().to_owned();
    let overview = || {
        Request::post("/mcp")
            .header("authorization", format!("Bearer {agent}"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "get_overview", "arguments": {}}})
                .to_string(),
            ))
            .unwrap()
    };
    for n in 1..=2 {
        let (s, _, v) = send(&app, overview()).await;
        assert_eq!(s, StatusCode::OK, "call {n}: {v}");
        assert_eq!(v["result"]["isError"], false, "call {n}: {v}");
    }
    let (s, _, v) = send(&app, overview()).await;
    assert_eq!(
        s,
        StatusCode::TOO_MANY_REQUESTS,
        "the third in a minute: {v}"
    );
}

// REQ: AGT-009 — a JSON-RPC batch is bounded: every message in it runs in turn.
#[tokio::test]
async fn agt_009_mcp_batches_are_bounded() {
    let (app, _) = app();
    let rpc = |n: usize| {
        let msgs: Vec<serde_json::Value> = (0..n)
            .map(|i| serde_json::json!({"jsonrpc": "2.0", "id": i, "method": "ping"}))
            .collect();
        Request::post("/mcp")
            .header("authorization", format!("Bearer {}", app.bearer))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::Value::Array(msgs).to_string()))
            .unwrap()
    };
    // 16 is `mcp::MAX_BATCH` (spelled out so the test also runs against older code).
    let (s, _, v) = send(&app, rpc(16)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v.as_array().map(Vec::len), Some(16));
    let (s, _, v) = send(&app, rpc(17)).await;
    assert_eq!(
        (s, v["error"]["code"].as_i64()),
        (StatusCode::BAD_REQUEST, Some(-32600)),
        "{v}"
    );
}

// REQ: AGT-009 (review 06-07) — every message in a batch counts against an agent's rate, so a
// batch can't multiply it.
#[tokio::test]
async fn agt_009_a_batch_counts_each_message() {
    let (app, _) = app();
    let token = |name: &str| {
        Request::post("/api/v1/tokens")
            .header("cookie", &app.cookie)
            .header("x-csrf-token", &app.csrf)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"name": name, "kind": "agent",
                    "scopes": ["analytics:read"], "ratePerMinute": 3})
                .to_string(),
            ))
            .unwrap()
    };
    let batch = |agent: &str, n: usize| {
        let msgs: Vec<serde_json::Value> = (0..n)
            .map(|i| serde_json::json!({"jsonrpc": "2.0", "id": i, "method": "ping"}))
            .collect();
        Request::post("/mcp")
            .header("authorization", format!("Bearer {agent}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::Value::Array(msgs).to_string()))
            .unwrap()
    };
    let (_, _, v) = send(&app, token("three")).await;
    let three = v["token"].as_str().unwrap().to_owned();
    let (s, _, v) = send(&app, batch(&three, 3)).await;
    assert_eq!(s, StatusCode::OK, "three messages fit a rate of 3: {v}");
    let (_, _, v) = send(&app, token("four")).await;
    let four = v["token"].as_str().unwrap().to_owned();
    let (s, _, v) = send(&app, batch(&four, 4)).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "four don't: {v}");
}

// REQ: AGT-007 (review 06-09) — a plan holds the write and its reason: the operators who decide
// on plans see every one, a viewer only their own.
#[tokio::test]
async fn agt_007_viewers_see_only_their_own_plans() {
    let (app, _) = app();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    app.auth.plans().add(crate::plans::Plan {
        id: "p1".into(),
        tool: "plan_block_domain".into(),
        summary: "block ads.example".into(),
        method: "PUT".into(),
        path: "/api/v1/rules/x".into(),
        body: None,
        preview: serde_json::json!({}),
        config_version: 1,
        reason: "too many ads".into(),
        requested_by: "agent:helper (owner: admin)".into(),
        owner: "token:someone-else".into(),
        created_unix_seconds: now,
        expires_unix_seconds: now + 600,
        state: "pending".into(),
        needs_approval: true,
        decided_by: None,
        result: None,
    });
    let (s, _, v) = get(&app, "/api/v1/plans").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["items"].as_array().map(Vec::len),
        Some(1),
        "an admin sees it"
    );
    app.auth
        .create_user("vic", "a viewer password", auth::Role::Viewer, false, NOW)
        .unwrap();
    let (_, h, _) = send(
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
    let (s, _, v) = send(
        &app,
        Request::get("/api/v1/plans")
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["items"].as_array().map(Vec::len),
        Some(0),
        "a viewer doesn't: {v}"
    );
}

// REQ: API-003 (ADR-029, review 06-05) — `X-Forwarded-Proto: https` counts only from a trusted
// proxy or loopback: a client on plain HTTP can't claim HTTPS to use HTTP Basic.
#[tokio::test]
async fn api_003_forwarded_proto_counts_only_from_trusted_peers() {
    let (app, _) = app();
    app.auth
        .create_user(
            "prom",
            "correct horse battery",
            auth::Role::Viewer,
            true,
            NOW,
        )
        .unwrap();
    let from = |peer: [u8; 4]| {
        let mut req = Request::get("/api/v1/stats/summary")
            .header(
                "authorization",
                "Basic cHJvbTpjb3JyZWN0IGhvcnNlIGJhdHRlcnk=",
            )
            .header("x-forwarded-proto", "https")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                peer, 40_000,
            ))));
        req
    };
    let (s, _, v) = send(&app, from([192, 168, 1, 50])).await;
    assert_ne!(
        s,
        StatusCode::OK,
        "a LAN client's own header doesn't count: {v}"
    );
    let (s, _, v) = send(&app, from([127, 0, 0, 1])).await;
    assert_eq!(s, StatusCode::OK, "a TLS terminator on this host: {v}");
    // REQ: API-003 (ADR-149) — the listener's own TLS counts from anywhere, with no header.
    let mut req = from([192, 168, 1, 50]);
    req.headers_mut().remove("x-forwarded-proto");
    req.extensions_mut().insert(auth::routes::TlsConnection);
    let (s, _, v) = send(&app, req).await;
    assert_eq!(s, StatusCode::OK, "over the API listener's TLS: {v}");
}

// REQ: API-003, API-006 (review 06-06) — an admin lists another user's API tokens and revokes
// one without touching the user; the revocation is audited with the owner.
#[tokio::test]
async fn api_003_admins_revoke_other_users_tokens() {
    let (app, _) = app();
    let ana = app
        .auth
        .create_user(
            "ana",
            "another long password",
            auth::Role::Operator,
            false,
            NOW,
        )
        .unwrap();
    app.auth
        .state()
        .create_token("tk1", ana.id, "laptop script", b"hash", "write", None, NOW)
        .unwrap();
    let (s, _, v) = get(&app, &format!("/api/v1/users/{}/tokens", ana.id)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["items"][0]["id"], "tk1", "{v}");
    let delete = |path: String| {
        Request::delete(path)
            .header("authorization", format!("Bearer {}", app.bearer))
            .body(Body::empty())
            .unwrap()
    };
    let path = format!("/api/v1/users/{}/tokens/tk1", ana.id);
    let (s, _, v) = send(&app, delete(path.clone())).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    let (_, _, v) = get(&app, &format!("/api/v1/users/{}/tokens", ana.id)).await;
    assert_eq!(v["items"].as_array().map(Vec::len), Some(0), "{v}");
    let (s, _, _) = send(&app, delete(path)).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "already gone");
    let revoked = app
        .auth
        .state()
        .audit_page(None, 10, Some("token.revoke"), None)
        .unwrap();
    assert_eq!(revoked.len(), 1, "{revoked:?}");
    assert!(
        revoked[0].detail.contains("\"owner\":\"ana\""),
        "{revoked:?}"
    );
    assert!(
        app.auth
            .state()
            .user(ana.id)
            .unwrap()
            .is_some_and(|u| !u.disabled)
    );
}

// REQ: OBS-033, AGT-004, AGT-005 — notes over HTTP: 201 with the line as written; 422
// `annotation_text` past 200 characters and `annotation_time` ahead of now; PUT and DELETE 405;
// an agent token needs `ops:annotate` (403 without), and its note and audit entry name its
// owner; a viewer reads but can't write; the read pages with `truncated` and `nextBefore`.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one flow: write, refuse, scope, audit, read
async fn obs_033_notes_over_http() {
    let (app, fake) = app();
    let post = |token: &str, body: serde_json::Value| {
        Request::post("/api/v1/annotations")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("x-telltale-reason", "recording why")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let code = |v: &serde_json::Value| v["code"].as_str().map(str::to_owned);
    let (s, _, v) = send(
        &app,
        post(&app.bearer, serde_json::json!({"text": " moved the AP "})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(
        (v["kind"].as_str(), v["text"].as_str(), v["actor"].as_str()),
        (
            Some("note"),
            Some("moved the AP"),
            Some("token:tests (owner: root)")
        )
    );
    assert_eq!(v["tUnixMs"], NOW * 1000);
    let (s, _, v) = send(
        &app,
        post(&app.bearer, serde_json::json!({"text": "x".repeat(201)})),
    )
    .await;
    assert_eq!(
        (s, code(&v).as_deref()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("annotation_text")),
        "{v}"
    );
    let (s, _, v) = send(
        &app,
        post(
            &app.bearer,
            serde_json::json!({"text": "later", "time": "2026-10-04T01:00:00Z"}),
        ),
    )
    .await;
    assert_eq!(
        (s, code(&v).as_deref()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("annotation_time")),
        "{v}"
    );
    for m in ["PUT", "DELETE"] {
        let req = Request::builder()
            .method(m)
            .uri("/api/v1/annotations")
            .header("authorization", format!("Bearer {}", app.bearer))
            .body(Body::empty())
            .unwrap();
        let (s, _, v) = send(&app, req).await;
        assert_eq!(
            (s, code(&v).as_deref()),
            (StatusCode::METHOD_NOT_ALLOWED, Some("method_not_allowed")),
            "{m}: {v}"
        );
    }
    // Agents: the scope, and their owner in the note and the audit log.
    let token = |name: &str, scopes: &[&str]| {
        Request::post("/api/v1/tokens")
            .header("cookie", &app.cookie)
            .header("x-csrf-token", &app.csrf)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"name": name, "kind": "agent", "scopes": scopes}).to_string(),
            ))
            .unwrap()
    };
    let (s, _, v) = send(&app, token("reader", &["analytics:read"])).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let reader = v["token"].as_str().unwrap().to_owned();
    let (s, _, v) = send(
        &app,
        post(&reader, serde_json::json!({"text": "not allowed"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, _, v) = send(&app, token("noter", &["ops:annotate"])).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let noter = v["token"].as_str().unwrap().to_owned();
    let (s, _, v) = send(
        &app,
        post(
            &noter,
            serde_json::json!({"text": "ISP outage", "time": "-2h"}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["actor"], "agent:noter (owner: root)");
    assert_eq!(v["tUnixMs"], (NOW - 7200) * 1000);
    let audit = app
        .auth
        .state()
        .audit_page(None, 10, Some("annotation.note"), None)
        .unwrap();
    assert_eq!(audit.len(), 2, "{audit:?}");
    assert!(
        audit.iter().any(|a| a.actor == "agent:noter (owner: root)"),
        "{audit:?}"
    );
    assert_eq!(
        fake.notes.lock().unwrap().len(),
        2,
        "refused notes never reach the backend"
    );
    // The read: newest first, one more than asked says there are more.
    let (s, _, v) = get(&app, "/api/v1/annotations?limit=1").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["items"][0]["text"], "moved the AP");
    assert_eq!(v["truncated"], true);
    let before = v["nextBefore"].as_str().unwrap().to_owned();
    let (_, _, v) = get(
        &app,
        &format!("/api/v1/annotations?limit=1&before={before}"),
    )
    .await;
    assert_eq!(v["items"][0]["text"], "ISP outage");
    assert_eq!(v["truncated"], false);
    let (s, _, v) = get(&app, "/api/v1/annotations?kinds=reboot").await;
    assert_eq!(
        (s, code(&v).as_deref()),
        (StatusCode::BAD_REQUEST, Some("invalid_parameter"))
    );
}

// REQ: API-003 (T10.7, ADR-142) — account changes need a signed-in session: an API token
// (even an admin's) can't create or revoke tokens, change the password, or touch two-factor
// sign-in. A wrong current password counts toward the sign-in lockout.
#[tokio::test]
async fn api_003_account_changes_need_a_signed_in_session() {
    let (app, _) = app();
    let bearer = |method: &str, uri: &str, body: serde_json::Value| {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", app.bearer))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let null = serde_json::Value::Null;
    for (method, uri, body) in [
        (
            "POST",
            "/api/v1/tokens",
            serde_json::json!({"name": "more"}),
        ),
        ("DELETE", "/api/v1/tokens/whatever", null.clone()),
        (
            "POST",
            "/api/v1/displays",
            serde_json::json!({"name": "hall"}),
        ),
        (
            "POST",
            "/api/v1/auth/password",
            serde_json::json!({"currentPassword": "correct horse battery",
                "newPassword": "a brand new password"}),
        ),
        ("POST", "/api/v1/auth/totp/setup", null.clone()),
        (
            "POST",
            "/api/v1/auth/totp/enable",
            serde_json::json!({"code": "123456"}),
        ),
        (
            "POST",
            "/api/v1/auth/totp/disable",
            serde_json::json!({"password": "correct horse battery"}),
        ),
    ] {
        let (s, _, v) = send(&app, bearer(method, uri, body)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{method} {uri}: {v}");
        assert!(
            v["detail"].as_str().unwrap().contains("signed-in session"),
            "{method} {uri}: {v}"
        );
    }
    // The signed-in session can.
    let (s, _, v) = send(
        &app,
        app.signed_in(
            "POST",
            "/api/v1/tokens",
            serde_json::json!({"name": "more"}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    // Guessing the current password through a session locks the account like sign-in does.
    let wrong = serde_json::json!({"currentPassword": "not the password",
        "newPassword": "a brand new password"});
    for n in 1..=5 {
        let (s, _, v) = send(
            &app,
            app.signed_in("POST", "/api/v1/auth/password", wrong.clone()),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "attempt {n}: {v}");
    }
    let (s, _, _) = send(&app, app.signed_in("POST", "/api/v1/auth/password", wrong)).await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "the sixth is counted and locks"
    );
    let right = serde_json::json!({"currentPassword": "correct horse battery",
        "newPassword": "a brand new password"});
    let (s, _, v) = send(&app, app.signed_in("POST", "/api/v1/auth/password", right)).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")),
        "locked, even with the right password: {v}"
    );
}

// REQ: FLT-017 — the workload routes: off by default (409 with a hint), the status, and a map
// rule's key with its slashes reaching the backend whole.
#[tokio::test]
async fn flt_017_kubernetes_routes() {
    let (app, fake) = app();
    let (s, ctype, v) = get(&app, "/api/v1/kubernetes/workloads").await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(ctype, "application/problem+json");
    assert_eq!(v["code"], "kubernetes_disabled");
    assert!(v["hint"].as_str().unwrap().contains("kubernetes.enabled"));
    let (s, _, v) = get(&app, "/api/v1/kubernetes/status").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["enabled"], false);
    let req = Request::put("/api/v1/kubernetes/map/media/deploy/jellyfin?dryRun=true")
        .header("authorization", format!("Bearer {}", app.bearer))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"group":"iot"}"#))
        .unwrap();
    let _ = send(&app, req).await;
    let seen = fake.seen.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|x| x == r#"managed KubernetesMap media/deploy/jellyfin {"group":"iot"}"#),
        "{seen:?}"
    );
}

// REQ: CLU-014, AGT-004 (AC 2) — drill requests over HTTP: 15 to 300 seconds (301 is 422
// `drill_targets`), a reason required, agents need `ops:drill` (403 without it, even with
// `ops:maintenance`); reads are routed; a window outside 1d to 7d is 400.
#[tokio::test]
async fn clu_014_drill_requests_over_http() {
    let (app, _) = app();
    let post = |token: &str, body: &str| {
        Request::post("/api/v1/nodes/local/drill")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("x-telltale-reason", "second server?")
            .body(Body::from(body.to_owned()))
            .unwrap()
    };
    let code = |v: &serde_json::Value| v["code"].as_str().map(str::to_owned);
    let (s, _, v) = send(
        &app,
        post(
            &app.bearer,
            r#"{"forSecs":301,"targets":"all","reason":"x"}"#,
        ),
    )
    .await;
    assert_eq!(
        (s, code(&v).as_deref()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("drill_targets")),
        "{v}"
    );
    assert!(v["hint"].as_str().unwrap().contains("5 minutes"), "{v}");
    let (s, _, v) = send(&app, post(&app.bearer, r#"{"targets":"all"}"#)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let (s, _, v) = send(
        &app,
        post(&app.bearer, r#"{"targets":{"clients":[]},"reason":"x"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let token = |scopes: &str| {
        Request::post("/api/v1/tokens")
            .header("cookie", &app.cookie)
            .header("x-csrf-token", &app.csrf)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"name":"drill-{}","kind":"agent","scopes":[{scopes}]}}"#,
                scopes.len()
            )))
            .unwrap()
    };
    let (s, _, v) = send(&app, token(r#""ops:maintenance""#)).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let maint = v["token"].as_str().unwrap().to_owned();
    let body = r#"{"forSecs":30,"targets":{"group":"iot"},"reason":"second server?"}"#;
    let (s, _, v) = send(&app, post(&maint, body)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, _, v) = send(&app, token(r#""ops:drill""#)).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let drill = v["token"].as_str().unwrap().to_owned();
    // With the scope the request reaches the backend (this test backend has no drills).
    let (s, _, v) = send(&app, post(&drill, body)).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    let get = |path: &str| {
        Request::get(path)
            .header("authorization", format!("Bearer {}", app.bearer))
            .body(Body::empty())
            .unwrap()
    };
    let (s, _, v) = send(&app, get("/api/v1/drills")).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    let (s, _, v) = send(&app, get("/api/v1/drills?limit=51")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, _, v) = send(&app, get("/api/v1/clients/affinity?window=9d")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, _, v) = send(&app, get("/api/v1/nodes/local/drill")).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{v}");
}

/// REQ: CLU-004, CLU-002 (ADR-174) — a backend whose federated reads wait on a gate, the way a
/// replica's read waits for the primary's answer (which needs the runtime, as the gate's opening
/// does here). Everything else is [`Fake`]'s.
struct ParkingBackend {
    inner: Fake,
    /// Federated reads that started.
    reads: std::sync::atomic::AtomicUsize,
    /// Told whenever a federated read starts: the handler is inside the backend.
    entered: Mutex<std::sync::mpsc::Sender<()>>,
    /// True once the test's probe task has run on the runtime.
    open: (Mutex<bool>, std::sync::Condvar),
}

impl ParkingBackend {
    fn new() -> (Arc<Self>, std::sync::mpsc::Receiver<()>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let me = Self {
            inner: Fake::default(),
            reads: std::sync::atomic::AtomicUsize::new(0),
            entered: Mutex::new(tx),
            open: (Mutex::new(false), std::sync::Condvar::new()),
        };
        (Arc::new(me), rx)
    }

    fn open_gate(&self) {
        *self.open.0.lock().unwrap() = true;
        self.open.1.notify_all();
    }

    /// One federated read: true when the gate opened. It gives up after 30 s, so a failing test
    /// doesn't leave a thread behind for long.
    fn federated_read(&self) -> bool {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _ = self.entered.lock().unwrap().send(());
        let guard = self.open.0.lock().unwrap();
        let (guard, _) = self
            .open
            .1
            .wait_timeout_while(guard, std::time::Duration::from_secs(30), |open| !*open)
            .unwrap();
        *guard
    }
}

impl Backend for ParkingBackend {
    fn now_unix_seconds(&self) -> u64 {
        NOW
    }
    fn system_info(&self) -> SystemInfo {
        self.inner.system_info()
    }
    fn timeseries(&self, step: Step, from_s: u64, to_s: u64) -> Vec<TimeBucket> {
        self.inner.timeseries(step, from_s, to_s)
    }
    fn top(&self, kind: TopKind, hour: Hour, limit: usize, client: Option<IpAddr>) -> Vec<TopItem> {
        self.inner.top(kind, hour, limit, client)
    }
    fn latency(&self, by: LatencyBy, hour: Hour) -> Vec<LatencyRow> {
        self.inner.latency(by, hour)
    }
    fn queries(
        &self,
        q: &QueryParams,
        from_us: u64,
        to_us: u64,
        limit: usize,
    ) -> Result<QueryPage, Problem> {
        self.inner.queries(q, from_us, to_us, limit)
    }
    fn explain(&self, p: &ExplainParams) -> Result<Explanation, Problem> {
        self.inner.explain(p)
    }
    fn lists(&self) -> Vec<ListInfo> {
        self.inner.lists()
    }
    fn groups(&self) -> Vec<GroupInfo> {
        self.inner.groups()
    }
    fn upstreams(&self) -> Vec<UpstreamInfo> {
        self.inner.upstreams()
    }
    // The reads a replica federates (or forwards to the primary): each waits for the gate.
    fn clients(&self) -> Vec<ClientInfo> {
        self.federated_read();
        Vec::new()
    }
    fn local_names(&self) -> Vec<LocalName> {
        self.federated_read();
        Vec::new()
    }
    fn forwards(&self) -> Vec<ForwardInfo> {
        self.federated_read();
        Vec::new()
    }
    fn rules(&self) -> Vec<crate::model::RuleInfo> {
        self.federated_read();
        Vec::new()
    }
    fn config_entries(&self, kind: Option<&str>) -> Vec<ConfigEntry> {
        let _ = kind;
        self.federated_read();
        vec![ConfigEntry {
            kind: "list".into(),
            name: "from-the-gate".into(),
            source: "added".into(),
            definition: None,
            credentials: None,
        }]
    }
    /// 4242 when the gate opened (the primary's version), 0 otherwise (a replica's own).
    fn config_version(&self) -> u64 {
        if self.federated_read() { 4242 } else { 0 }
    }
    fn write_client(
        &self,
        w: ClientWrite,
    ) -> BoxFuture<Result<crate::model::ClientChange, Problem>> {
        let _ = w;
        Box::pin(async {
            Ok(serde_json::from_value(serde_json::json!({
                "applied": true, "configVersion": 1, "before": null, "after": null,
                "recentQueries": 0, "impact": "", "warnings": []
            }))
            .unwrap())
        })
    }
    fn write_managed(
        &self,
        w: ManagedWrite,
    ) -> BoxFuture<Result<crate::model::ConfigChange, Problem>> {
        let _ = w;
        Box::pin(async {
            Ok(serde_json::from_value(serde_json::json!({
                "applied": true, "configVersion": 1, "before": null, "after": null,
                "warnings": []
            }))
            .unwrap())
        })
    }
}

/// One request of `clu_004_direct_handlers_never_park_a_runtime_worker`.
struct Route {
    name: &'static str,
    method: &'static str,
    uri: &'static str,
    body: &'static str,
    /// Made with a token restricted to the group `kids` (AGT-004), not the admin's.
    agent: bool,
    /// The federated reads the handler makes in all (the fake was reached the way a replica is).
    reads: usize,
    /// The answer carries the backend's version in the `ETag` (else: its one entry).
    etag: bool,
}

/// Sends `route` through the router on a runtime with one worker, from a thread that is not a
/// worker. The backend's reads wait for a gate that only a task on that runtime opens: a handler
/// that waits on its own worker never lets the task run (the production wedge: a replica's wait
/// for the primary needs a worker too). The guard is a `std` timeout on this thread; a timer on
/// the wedged runtime could never fire.
fn route_never_parks(route: &Route) -> Result<(), String> {
    const GUARD: std::time::Duration = std::time::Duration::from_secs(10);
    let fail = |what: &str| Err(format!("{}: {what}", route.name));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    assert_eq!(rt.metrics().num_workers(), 1, "the shape of the test");
    let (backend, entered) = ParkingBackend::new();
    let app = app_over(Arc::clone(&backend) as Shared);
    let bearer = if route.agent {
        let (s, _, v) = rt.block_on(send(
            &app,
            app.signed_in(
                "POST",
                "/api/v1/tokens",
                serde_json::json!({"name": "kids-helper", "kind": "agent", "group": "kids",
                    "scopes": ["querylog:read", "analytics:read", "config:read", "config:write:clients"]}),
            ),
        ));
        assert_eq!(s, StatusCode::CREATED, "{v}");
        v["token"].as_str().unwrap().to_owned()
    } else {
        app.bearer.clone()
    };
    let req = Request::builder()
        .method(route.method)
        .uri(route.uri)
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .header("x-telltale-reason", "test")
        .body(Body::from(route.body))
        .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let router = app.router.clone();
    drop(rt.spawn(async move {
        let resp = router.oneshot(req).await.unwrap();
        let (status, headers) = (resp.status(), resp.headers().clone());
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let _ = tx.send((status, headers, bytes));
    }));
    // Only once the handler is inside the backend does the probe run: a handler that had not
    // started yet could not tell the two cases apart.
    if entered.recv_timeout(GUARD).is_err() {
        backend.open_gate();
        rt.shutdown_background();
        return fail("never reached the backend");
    }
    let opener = Arc::clone(&backend);
    drop(rt.spawn(async move { opener.open_gate() }));
    let Ok((status, headers, bytes)) = rx.recv_timeout(GUARD) else {
        // Dropping a runtime whose worker is parked would hang the test run.
        backend.open_gate();
        rt.shutdown_background();
        return fail("the handler waited on the runtime's only worker (the probe task never ran)");
    };
    drop(rt);
    let reads = backend.reads.load(std::sync::atomic::Ordering::SeqCst);
    if reads != route.reads {
        return fail(&format!(
            "{reads} federated reads, expected {}",
            route.reads
        ));
    }
    if status != StatusCode::OK {
        return fail(&format!(
            "status {status}: {}",
            String::from_utf8_lossy(&bytes)
        ));
    }
    if route.etag {
        if headers.get("etag").and_then(|v| v.to_str().ok()) != Some("\"4242\"") {
            return fail(&format!(
                "ETag {:?}, not the backend's version",
                headers.get("etag")
            ));
        }
    } else {
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        if v["items"][0]["name"] != "from-the-gate" {
            return fail(&format!("the entries are {v}"));
        }
    }
    Ok(())
}

// REQ: CLU-004, CLU-002 (ADR-174, GitHub issue #7) — a handler whose backend call federates (a
// replica asks the primary, and the answer needs a runtime worker) must not run that call on a
// worker: with every worker parked nothing can answer it, nothing can time it out, and the API,
// the metrics and the cluster stream all stop. On a runtime of one worker a single request
// shows it. The rows are the direct handlers' routes (the ones that read the config version for
// the `ETag`, or federate their list), including a config write and a group-restricted agent's.
#[test]
fn clu_004_direct_handlers_never_park_a_runtime_worker() {
    let client = r#"{"match": ["192.168.1.9"], "groups": ["default"]}"#;
    let kids = r#"{"match": ["192.168.1.9"], "groups": ["kids"]}"#;
    let route = |name, method, uri, body, agent, reads, etag| Route {
        name,
        method,
        uri,
        body,
        agent,
        reads,
        etag,
    };
    let routes = [
        route("GET clients", "GET", "/api/v1/clients", "", false, 2, true),
        route(
            "GET clients (agent)",
            "GET",
            "/api/v1/clients",
            "",
            true,
            2,
            true,
        ),
        route("GET records", "GET", "/api/v1/records", "", false, 2, true),
        route(
            "GET forwards",
            "GET",
            "/api/v1/forwards",
            "",
            false,
            2,
            true,
        ),
        route("GET rules", "GET", "/api/v1/rules", "", false, 2, true),
        route(
            "GET config/entries",
            "GET",
            "/api/v1/config/entries?kind=list",
            "",
            false,
            1,
            false,
        ),
        route(
            "PUT clients",
            "PUT",
            "/api/v1/clients/tablet",
            client,
            false,
            1,
            true,
        ),
        route(
            "PUT clients (agent)",
            "PUT",
            "/api/v1/clients/tablet",
            kids,
            true,
            2,
            true,
        ),
        route(
            "DELETE records",
            "DELETE",
            "/api/v1/records/x.lan",
            "",
            false,
            1,
            true,
        ),
    ];
    let failed: Vec<String> = routes
        .iter()
        .filter_map(|r| route_never_parks(r).err())
        .collect();
    assert!(
        failed.is_empty(),
        "these requests did not complete on a runtime of one worker:\n{}",
        failed.join("\n")
    );
}

/// REQ: OBS-010, API-002 (ADR-179) — a configuration write tells the backend whether an
/// administrator made it: an admin's session or admin-scoped token is; an operator, an admin's
/// token capped below admin, and any agent token (an admin's, even with `cluster:admin`) aren't.
#[tokio::test]
async fn obs_010_a_write_says_whether_an_administrator_made_it() {
    let (app, fake) = app();
    let olga = app
        .auth
        .create_user(
            "olga",
            "an operator password",
            auth::Role::Operator,
            false,
            NOW,
        )
        .unwrap();
    let root = app.auth.state().user_by_name("root").unwrap().unwrap();
    let token = |user: i64, scope: &str, agent: Option<&str>| {
        let (id, secret) = (auth::crypto::random_id(), auth::crypto::random_secret());
        app.auth
            .state()
            .create_token(
                &id,
                user,
                "t",
                &auth::crypto::secret_hash(&secret),
                scope,
                None,
                NOW,
            )
            .unwrap();
        if let Some(s) = agent {
            app.auth
                .state()
                .set_token_agent(&id, s, None, None)
                .unwrap();
        }
        format!("tt_{id}_{secret}")
    };
    let body = serde_json::json!({ "type": "webhook", "url": "https://hooks.example.com/x" });
    let put = |bearer: String, name: &str| {
        Request::put(format!("/api/v1/alerts/destinations/{name}"))
            .header("authorization", format!("Bearer {bearer}"))
            .header("x-telltale-reason", "tests")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    for (name, req) in [
        ("admin-token", put(app.bearer.clone(), "admin-token")),
        (
            "admin-session",
            app.signed_in(
                "PUT",
                "/api/v1/alerts/destinations/admin-session",
                body.clone(),
            ),
        ),
        ("operator", put(token(olga.id, "write", None), "operator")),
        (
            "admin-write-scope",
            put(token(root.id, "write", None), "admin-write-scope"),
        ),
        (
            "admin-agent",
            put(
                token(root.id, "write", Some("config:write:alerts cluster:admin")),
                "admin-agent",
            ),
        ),
        (
            "operator-agent",
            put(
                token(olga.id, "write", Some("config:write:alerts")),
                "operator-agent",
            ),
        ),
    ] {
        let (s, _, v) = send(&app, req).await;
        assert_eq!(
            s,
            StatusCode::SERVICE_UNAVAILABLE,
            "{name}: reached the backend: {v}"
        );
    }
    let seen = fake.by_admin.lock().unwrap().clone();
    let admin: Vec<(&str, bool)> = seen.iter().map(|(n, a)| (n.as_str(), *a)).collect();
    assert_eq!(
        admin,
        [
            ("admin-token", true),
            ("admin-session", true),
            ("operator", false),
            ("admin-write-scope", false),
            ("admin-agent", false),
            ("operator-agent", false),
        ]
    );
}

/// REQ: API-002, T8.2 (ADR-181) — security F3: a pinned primary whose routers differ from the
/// pinned version. The rollout status and a write's `409 cluster_pinned` carry the diff the pin
/// holds back. Everything else is [`Fake`]'s.
struct PinnedBackend {
    inner: Fake,
}

/// A pin's diff that touches routers (key files, a username) and an upstream.
fn pin_ops() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({"op": "replace", "path": "/router/0/api_key_file",
            "value": "/data/secrets/router-udm.api_key.0123456789abcdef"}),
        serde_json::json!({"op": "add", "path": "/router/1", "value": {
            "name": "fw", "type": "opnsense", "url": "https://fw.example.test",
            "api_key_file": "/data/secrets/router-fw.api_key.fedcba9876543210",
            "api_secret_file": "/data/secrets/router-fw.api_secret.fedcba9876543210",
            "username": "reader-one"}}),
        serde_json::json!({"op": "add", "path": "/router", "value": [
            {"name": "ctl", "type": "unifi", "url": "https://ctl.example.test",
             "username": "reader-two", "password_file": "/data/secrets/router-ctl.password.0"}]}),
        serde_json::json!({"op": "replace", "path": "/router/2/username", "value": "reader-three"}),
        serde_json::json!({"op": "replace", "path": "/upstream/0/url", "value": "tls://9.9.9.9"}),
    ]
}

/// The required [`Backend`] methods, answered by the backend's `inner` [`Fake`].
macro_rules! fake_reads {
    () => {
        fn now_unix_seconds(&self) -> u64 {
            NOW
        }
        fn system_info(&self) -> SystemInfo {
            self.inner.system_info()
        }
        fn timeseries(&self, step: Step, from_s: u64, to_s: u64) -> Vec<TimeBucket> {
            self.inner.timeseries(step, from_s, to_s)
        }
        fn top(
            &self,
            kind: TopKind,
            hour: Hour,
            limit: usize,
            client: Option<IpAddr>,
        ) -> Vec<TopItem> {
            self.inner.top(kind, hour, limit, client)
        }
        fn latency(&self, by: LatencyBy, hour: Hour) -> Vec<LatencyRow> {
            self.inner.latency(by, hour)
        }
        fn queries(
            &self,
            q: &QueryParams,
            from_us: u64,
            to_us: u64,
            limit: usize,
        ) -> Result<QueryPage, Problem> {
            self.inner.queries(q, from_us, to_us, limit)
        }
        fn explain(&self, p: &ExplainParams) -> Result<Explanation, Problem> {
            self.inner.explain(p)
        }
        fn lists(&self) -> Vec<ListInfo> {
            self.inner.lists()
        }
        fn groups(&self) -> Vec<GroupInfo> {
            self.inner.groups()
        }
        fn clients(&self) -> Vec<ClientInfo> {
            self.inner.clients()
        }
        fn upstreams(&self) -> Vec<UpstreamInfo> {
            self.inner.upstreams()
        }
    };
}

impl Backend for PinnedBackend {
    fake_reads!();
    fn rollout_command(
        &self,
        w: crate::RolloutWrite,
    ) -> BoxFuture<Result<crate::model::RolloutAction, Problem>> {
        let dry_run = w.dry_run();
        Box::pin(async move {
            Ok(crate::model::RolloutAction {
                done: "would pin".into(),
                dry_run,
                diff: pin_ops(),
                changes: vec!["router: changed".into()],
                config_version: 7,
            })
        })
    }
    fn rollout_status(&self) -> BoxFuture<Result<crate::model::RolloutStatus, Problem>> {
        Box::pin(async {
            Ok(crate::model::RolloutStatus {
                stage: "pinned".into(),
                pinned: Some(crate::model::ClusterPin {
                    to: "3.124".into(),
                    diff: pin_ops(),
                    ..Default::default()
                }),
                ..Default::default()
            })
        })
    }
    fn write_managed(
        &self,
        w: ManagedWrite,
    ) -> BoxFuture<Result<crate::model::ConfigChange, Problem>> {
        let _ = w;
        Box::pin(async {
            Err(
                Problem::new(crate::problem::Code::ClusterPinned, "the cluster is pinned")
                    .diff(serde_json::Value::Array(pin_ops())),
            )
        })
    }
}

/// A bearer token for a new user of `role`.
fn bearer_for(app: &TestApp, name: &str, role: auth::Role, scope: &str) -> String {
    let user = app
        .auth
        .create_user(name, "a long enough password", role, false, NOW)
        .unwrap();
    let (id, secret) = (auth::crypto::random_id(), auth::crypto::random_secret());
    app.auth
        .state()
        .create_token(
            &id,
            user.id,
            "tests",
            &auth::crypto::secret_hash(&secret),
            scope,
            None,
            auth_now(),
        )
        .unwrap();
    format!("tt_{id}_{secret}")
}

/// REQ: API-002, T8.2 (ADR-181) — security F3: the diff a pin holds back names no router key
/// file or username to a caller below admin (the rollout status, which viewers read, and the
/// `409 cluster_pinned` an operator's write gets); the rest of the diff is as it was, and an
/// administrator sees all of it.
#[tokio::test]
async fn api_002_a_pin_diff_names_no_router_key_file() {
    let app = app_over(Arc::new(PinnedBackend {
        inner: Fake::default(),
    }));
    let viewer = bearer_for(&app, "vic", auth::Role::Viewer, "read");
    let operator = bearer_for(&app, "olga", auth::Role::Operator, "write");
    let hidden = [
        "router-udm.api_key",
        "router-fw.api_key",
        "router-fw.api_secret",
        "router-ctl.password",
        "reader-one",
        "reader-two",
        "reader-three",
    ];
    let call = |bearer: &str, method: &str, uri: &str| {
        let mut r = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {bearer}"));
        let body = if method == "PUT" {
            r = r.header("content-type", "application/json");
            Body::from(serde_json::json!({"url": "udp://9.9.9.9"}).to_string())
        } else {
            Body::empty()
        };
        r.body(body).unwrap()
    };
    for (who, bearer) in [("viewer", &viewer), ("operator", &operator)] {
        let (s, _, v) = send(&app, call(bearer, "GET", "/api/v1/cluster/rollout")).await;
        assert_eq!(s, StatusCode::OK, "{who}: {v}");
        let text = v.to_string();
        for h in hidden {
            assert!(!text.contains(h), "{who} sees {h}: {text}");
        }
        assert!(
            text.contains("tls://9.9.9.9"),
            "{who}: the rest stays: {text}"
        );
        assert!(text.contains("https://fw.example.test"), "{who}: {text}");
    }
    let (s, _, v) = send(&app, call(&operator, "PUT", "/api/v1/upstreams/up")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let text = v.to_string();
    for h in hidden {
        assert!(!text.contains(h), "the operator's 409 shows {h}: {text}");
    }
    assert!(text.contains("tls://9.9.9.9"), "{text}");
    // An administrator sees the whole diff.
    let (s, _, v) = send(&app, call(&app.bearer, "GET", "/api/v1/cluster/rollout")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let text = v.to_string();
    for h in hidden {
        assert!(text.contains(h), "the admin sees {h}: {text}");
    }
}

// ---- Review round 2.

/// A token of `kind` (`agent`, with `scopes`) made by the admin's session; its bearer.
async fn agent_token(app: &TestApp, name: &str, scopes: &[&str]) -> String {
    let body = serde_json::json!({"name": name, "kind": "agent", "scopes": scopes});
    let (s, _, v) = send(app, app.signed_in("POST", "/api/v1/tokens", body)).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    v["token"].as_str().unwrap().to_owned()
}

/// One MCP `tools/call` as `bearer`; the result.
async fn mcp_call(
    app: &TestApp,
    bearer: &str,
    tool: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    let req = Request::post("/mcp")
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(Body::from(
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": tool, "arguments": args}})
            .to_string(),
        ))
        .unwrap();
    send(app, req).await.2
}

/// REQ: API-002, T8.2, AGT-007 (ADR-181) — security N1: the diff a pin or an unpin command
/// answers with names no router key file or username below admin: an agent's dry run (an agent
/// is never an administrator), and so the MCP plans made from those dry runs, which every operator
/// reads through `GET /api/v1/plans` (a viewer sees only its own). An administrator's own dry run
/// shows them.
#[tokio::test]
async fn api_002_a_pin_command_diff_names_no_router_key_file_below_admin() {
    let app = app_over(Arc::new(PinnedBackend {
        inner: Fake::default(),
    }));
    app.auth.agents().set_require_approval(true);
    let agent = agent_token(&app, "pinner", &["cluster:admin"]).await;
    let hidden = [
        "router-udm.api_key",
        "router-fw.api_key",
        "router-ctl.password",
        "reader-one",
        "reader-two",
        "reader-three",
    ];
    let pin = |bearer: &str, uri: &str, method: &str| {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .header("x-telltale-reason", "a test of the pin preview")
            .body(Body::from(
                serde_json::json!({"reason": "a test of the pin preview"}).to_string(),
            ))
            .unwrap()
    };
    // The agent's own dry runs.
    for (method, uri) in [
        ("POST", "/api/v1/cluster/versions/3.124/pin?dryRun=true"),
        ("DELETE", "/api/v1/cluster/pin?dryRun=true"),
    ] {
        let (s, _, v) = send(&app, pin(&agent, uri, method)).await;
        assert_eq!(s, StatusCode::OK, "{method} {uri}: {v}");
        let text = v.to_string();
        for h in hidden {
            assert!(
                !text.contains(h),
                "the agent's {method} answer shows {h}: {text}"
            );
        }
        assert!(text.contains("tls://9.9.9.9"), "the rest stays: {text}");
    }
    // Plans made through MCP, read by an operator and a viewer.
    for (tool, args) in [
        (
            "plan_pin_version",
            serde_json::json!({"epoch": 3, "seq": 124, "reason": "a test of the pin preview"}),
        ),
        (
            "plan_unpin",
            serde_json::json!({"reason": "a test of the pin preview"}),
        ),
    ] {
        let v = mcp_call(&app, &agent, tool, args).await;
        assert_eq!(v["result"]["isError"], false, "{tool}: {v}");
    }
    let operator = bearer_for(&app, "olga", auth::Role::Operator, "write");
    let viewer = bearer_for(&app, "vic", auth::Role::Viewer, "read");
    for (who, bearer) in [("operator", &operator), ("viewer", &viewer)] {
        let req = Request::get("/api/v1/plans")
            .header("authorization", format!("Bearer {bearer}"))
            .body(Body::empty())
            .unwrap();
        let (s, _, v) = send(&app, req).await;
        assert_eq!(s, StatusCode::OK, "{who}: {v}");
        let text = v.to_string();
        // Operators see every plan (they approve them); a viewer sees only its own.
        let listed = text.contains("plan_pin_version") && text.contains("plan_unpin");
        assert_eq!(listed, who == "operator", "{who}: {text}");
        for h in hidden {
            assert!(!text.contains(h), "the {who} sees {h} in a plan: {text}");
        }
    }
    // An administrator's own dry run shows the whole diff.
    let (s, _, v) = send(
        &app,
        pin(
            &app.bearer,
            "/api/v1/cluster/versions/3.124/pin?dryRun=true",
            "POST",
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let text = v.to_string();
    for h in hidden {
        assert!(text.contains(h), "the admin sees {h}: {text}");
    }
}

/// A backend whose configuration writes wait for `gate` (a dry run, or a body with `"fail"`,
/// answers at once), or panic; it counts the writes waiting.
struct GatedBackend {
    inner: Fake,
    gate: Arc<tokio::sync::Semaphore>,
    waiting: Arc<std::sync::atomic::AtomicUsize>,
    panics: bool,
}

impl GatedBackend {
    fn new(panics: bool) -> Self {
        Self {
            inner: Fake::default(),
            gate: Arc::new(tokio::sync::Semaphore::new(0)),
            waiting: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            panics,
        }
    }
}

impl Backend for GatedBackend {
    fake_reads!();
    fn write_managed(
        &self,
        w: ManagedWrite,
    ) -> BoxFuture<Result<crate::model::ConfigChange, Problem>> {
        let (gate, waiting, panics) = (
            Arc::clone(&self.gate),
            Arc::clone(&self.waiting),
            self.panics,
        );
        Box::pin(async move {
            let change = crate::model::ConfigChange {
                applied: !w.dry_run,
                config_version: 2,
                before: None,
                after: w.body.clone(),
                recent_queries: 0,
                impact: String::new(),
                warnings: Vec::new(),
                keep_in_git: None,
                simulation: None,
            };
            if w.dry_run {
                return Ok(change);
            }
            assert!(
                !panics,
                "a test write that panics with an internal detail: /secret/path"
            );
            if w.body.as_ref().is_some_and(|b| b.get("fail").is_some()) {
                return Err(Problem::new(crate::problem::Code::InvalidConfig, "refused"));
            }
            waiting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Ok(p) = gate.acquire().await {
                p.forget();
            }
            waiting.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            Ok(change)
        })
    }
}

/// An admin's `PUT /api/v1/upstreams/{name}` with `body`, a dry run or not.
#[allow(clippy::needless_pass_by_value)] // called with `json!(..)` like the other helpers
fn put_upstream(app: &TestApp, name: &str, dry: bool, body: serde_json::Value) -> Request<Body> {
    let uri = format!(
        "/api/v1/upstreams/{name}{}",
        if dry { "?dryRun=true" } else { "" }
    );
    Request::put(uri)
        .header("authorization", format!("Bearer {}", app.bearer))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// REQ: API-002, NFR-005 (ADR-181) — security N3: at most 32 configuration changes run at once
/// (each in a task of its own, which a client that goes away no longer cancels); one more gets
/// 503 with `Retry-After`. Dry runs aren't counted. A change that fails, or finishes, gives its
/// place back.
#[tokio::test]
async fn api_002_configuration_changes_running_at_once_are_bounded() {
    let backend = Arc::new(GatedBackend::new(false));
    let app = app_over(Arc::clone(&backend) as Shared);
    let up = serde_json::json!({"url": "udp://192.0.2.53"});
    // Changes that fail give their place back: more of them than there are places, one by one.
    for i in 0..40 {
        let (s, _, v) = send(
            &app,
            put_upstream(
                &app,
                &format!("f{i}"),
                false,
                serde_json::json!({"fail": true}),
            ),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{i}: {v}");
    }
    // 32 changes waiting.
    let mut running = Vec::new();
    for i in 0..32 {
        let router = app.router.clone();
        let req = put_upstream(&app, &format!("u{i}"), false, up.clone());
        running.push(tokio::spawn(async move {
            router.oneshot(req).await.unwrap().status()
        }));
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while backend.waiting.load(std::sync::atomic::Ordering::SeqCst) < 32 {
        assert!(
            std::time::Instant::now() < deadline,
            "the 32 changes didn't start"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    // One more: refused, not queued.
    let (s, h, v) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        send(&app, put_upstream(&app, "one-more", false, up.clone())),
    )
    .await
    .expect("refused at once, not queued");
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    assert!(h.get("retry-after").is_some(), "{h:?}");
    // A dry run isn't counted.
    let (s, _, v) = send(&app, put_upstream(&app, "dry", true, up.clone())).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // They finish, and give their places back.
    backend.gate.add_permits(32);
    for r in running {
        assert_eq!(r.await.unwrap(), StatusCode::OK);
    }
    backend.gate.add_permits(1);
    let (s, _, v) = send(&app, put_upstream(&app, "after", false, up)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// REQ: API-002 (ADR-181) — correctness R6: a change whose task fails (a panic) answers a fixed
/// 500, never the runtime's text about the task or the panic's message.
#[tokio::test]
async fn api_002_a_change_whose_task_fails_answers_a_fixed_500() {
    let app = app_over(Arc::new(GatedBackend::new(true)));
    let (s, _, v) = send(
        &app,
        put_upstream(
            &app,
            "up",
            false,
            serde_json::json!({"url": "udp://192.0.2.53"}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    let text = v.to_string();
    for leak in ["panicked", "task", "/secret/path", "JoinError"] {
        assert!(!text.contains(leak), "{leak}: {text}");
    }
    assert!(
        v["detail"]
            .as_str()
            .is_some_and(|d| d.contains("server log")),
        "{v}"
    );
}

// ---- Review round 3.

/// REQ: AGT-007, AGT-003 (ADR-181) — review round 3 (F3): an MCP `apply_plan` that finds the node
/// busy (every place for a change taken: 503) or the plan's first apply still running (409
/// `change_in_progress`) doesn't spend the plan: it is `ready` again and the agent is told to
/// apply it again. Once the node is free, the plan is applied.
#[tokio::test]
async fn agt_007_a_busy_apply_leaves_the_plan_to_apply_again() {
    let backend = Arc::new(GatedBackend::new(false));
    let app = app_over(Arc::clone(&backend) as Shared);
    let agent = agent_token(&app, "planner", &["config:write:records"]).await;
    let made = mcp_call(
        &app,
        &agent,
        "plan_set_local_name",
        serde_json::json!({"name": "nas.home.arpa", "records": [{"type": "A", "value": "192.168.1.10"}],
            "reason": "a test of a busy apply"}),
    )
    .await;
    assert_eq!(made["result"]["isError"], false, "{made}");
    let id = made["result"]["structuredContent"]["planId"]
        .as_str()
        .unwrap()
        .to_owned();
    let apply = || {
        mcp_call(
            &app,
            &agent,
            "apply_plan",
            serde_json::json!({"planId": id}),
        )
    };
    let busy = |v: &serde_json::Value, why: &str| {
        assert_eq!(v["result"]["isError"], true, "{why}: {v}");
        assert_eq!(
            v["result"]["structuredContent"]["state"], "ready",
            "{why}: {v}"
        );
        assert!(
            v["result"]["structuredContent"]["hint"]
                .as_str()
                .is_some_and(|h| h.contains("again")),
            "{why}: {v}"
        );
    };
    // Every place taken.
    let all = app.auth.write_gate().take_every_place().unwrap();
    busy(&apply().await, "503");
    drop(all);
    // The plan's first apply still running (its Idempotency-Key is the plan's ID).
    let root = app.auth.state().user_by_name("root").unwrap().unwrap();
    let key = format!("{}:{id}", root.id);
    app.auth.write_gate().hold_key(&key, true);
    busy(&apply().await, "409");
    app.auth.write_gate().hold_key(&key, false);
    // Free: applied.
    backend.gate.add_permits(1);
    let v = apply().await;
    assert_eq!(v["result"]["isError"], false, "{v}");
    assert_eq!(v["result"]["structuredContent"]["state"], "applied", "{v}");
}
