use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use telltale_config::{Config, KubernetesConfig};
use telltale_policy::{GroupOrigin, Workloads};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

const PODS: &str = include_str!("fixtures/pods.json");

fn fixture() -> Vec<PodObject> {
    serde_json::from_str::<List<PodObject>>(PODS).unwrap().items
}

fn ns(name: &str, labels: &[(&str, &str)]) -> NamespaceObject {
    NamespaceObject {
        metadata: ObjectMeta {
            name: name.into(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            ..ObjectMeta::default()
        },
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

// REQ: FLT-017 (AC 1) — the fixture pods map to their workloads; the host-network pod and the
// terminating pod are left out; a pod with two addresses maps both.
#[test]
fn flt_017_parser_maps_fixture_pods() {
    let parsed: Vec<Parsed> = fixture().iter().map(parse_pod).collect();
    let texts: Vec<String> = parsed
        .iter()
        .filter_map(|p| match p {
            Parsed::Pod(i) => Some(i.text()),
            _ => None,
        })
        .collect();
    assert_eq!(
        texts,
        [
            "media/deploy/jellyfin",
            "db/sts/postgres",
            "kube-system/ds/cilium",
            "jobs/cronjob/backup",
            "tools/job/once",
            "tools/pod/debug",
        ]
    );
    assert_eq!(parsed[6], Parsed::Skip, "host network");
    assert_eq!(parsed[7], Parsed::Gone, "terminating");
    let Parsed::Pod(jellyfin) = &parsed[0] else {
        panic!("jellyfin")
    };
    assert_eq!(jellyfin.ips, [ip("10.42.0.15"), ip("fd00:42::f")]);
    assert_eq!(jellyfin.name, "jellyfin-7d9f4c8b6-x2k1q");
    assert!(jellyfin.created_s > 0);
    // A ReplicaSet without the template-hash label stays a ReplicaSet; an unknown owner is the
    // workload (ADR-150's gap).
    let mut m = ObjectMeta {
        name: "x-1".into(),
        owner_references: vec![OwnerRef {
            kind: "ReplicaSet".into(),
            name: "legacy-abc".into(),
            controller: Some(true),
        }],
        ..ObjectMeta::default()
    };
    assert_eq!(workload_of(&m), ("rs".into(), "legacy-abc".into()));
    m.owner_references[0].kind = "Cluster".into();
    m.owner_references[0].name = "pg-main".into();
    assert_eq!(workload_of(&m), ("cluster".into(), "pg-main".into()));
}

fn kcfg(toml: &str) -> Config {
    telltale_config::Loader::new()
        .toml_str("t.toml", toml)
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config
}

const GROUPS: &str = r#"
[[group]]
name = "media"
[[group]]
name = "servers"
[[group]]
name = "infra"
[[group]]
name = "lab"
[[group]]
name = "podnet"
networks = ["10.42.0.40/29"]

[kubernetes]
enabled = true
default_group = "lab"

[[kubernetes.map]]
namespace = "kube-*"
group = "infra"

[[kubernetes.map]]
namespace = "media*"
group = "servers"
"#;

fn built(cfg: &KubernetesConfig, groups: &[&str], namespaces: &[NamespaceObject]) -> Built {
    let mut m = Model::default();
    m.pod_list(None, &fixture(), 1_000);
    m.namespace_list(namespaces);
    let exists = |g: &str| groups.contains(&g) || g == "default";
    m.build(cfg, &exists, &mut HashSet::new(), 1_000)
}

fn group_of_text(b: &Built, text: &str) -> (Option<String>, GroupOrigin) {
    let w = b.table.by_text(text).unwrap();
    (w.group.as_deref().map(str::to_owned), w.origin)
}

// REQ: FLT-017 (AC 2) — pod label > namespace label > map rule > default_group; a label
// naming no group is treated as unset.
#[test]
fn flt_017_group_precedence() {
    let cfg = kcfg(GROUPS);
    let groups = ["media", "servers", "infra", "lab", "podnet"];
    let namespaces = [
        ns("media", &[("telltaledns.io/group", "media")]),
        ns("db", &[("telltaledns.io/group", "media")]),
        ns("tools", &[("telltaledns.io/group", "no-such-group")]),
    ];
    let b = built(&cfg.kubernetes, &groups, &namespaces);
    assert_eq!(b.workloads, 6);
    assert_eq!(
        b.pods, 6,
        "a pod first seen terminating is never added (no queries of its own to attribute)"
    );
    let g = |t| group_of_text(&b, t);
    assert_eq!(
        g("db/sts/postgres"),
        (Some("servers".into()), GroupOrigin::PodLabel)
    );
    assert_eq!(
        g("media/deploy/jellyfin"),
        (Some("media".into()), GroupOrigin::NamespaceLabel),
        "the namespace label beats the media* map rule"
    );
    assert_eq!(
        g("kube-system/ds/cilium"),
        (Some("infra".into()), GroupOrigin::Map)
    );
    assert_eq!(
        g("tools/pod/debug"),
        (Some("lab".into()), GroupOrigin::Default),
        "a label naming no group is unset"
    );
    // Without a default group, a workload no rule places has no group of its own.
    let mut k = cfg.kubernetes.clone();
    k.default_group = telltale_config::SafeString::default();
    let b = built(&k, &groups, &namespaces);
    assert_eq!(
        group_of_text(&b, "tools/pod/debug"),
        (None, GroupOrigin::None)
    );
    // Namespace scope and exclusions.
    k.exclude_namespaces = vec!["tools".into()];
    let b = built(&k, &groups, &namespaces);
    assert!(b.table.by_text("tools/pod/debug").is_none());
    assert!(b.table.by_text("db/sts/postgres").is_some());
    k.namespaces = vec!["db".into()];
    let b = built(&k, &groups, &namespaces);
    assert_eq!(b.workloads, 1);
}

// REQ: FLT-017 — a deleted pod keeps its address for the grace period, then leaves for the
// history; an address another workload takes later is named by whoever held it then.
#[test]
fn flt_017_grace_period_and_history() {
    let k = KubernetesConfig::default();
    let exists = |_: &str| true;
    let mut warned = HashSet::new();
    let mut m = Model::default();
    let pods = fixture();
    m.pod_list(None, &pods[..1], 1_000); // jellyfin
    let t = m.build(&k, &exists, &mut warned, 1_000).table;
    assert!(t.get(ip("10.42.0.15")).is_some());
    // Rolled out: the old pod is deleted, a new one (another workload) takes its address.
    m.pod_deleted(&pods[0], 2_000);
    let mut other = pods[1].clone(); // postgres-0
    other.status.pod_ips = vec![PodIp {
        ip: "10.42.0.15".into(),
    }];
    m.pod_event(&other, 2_000);
    let t = m.build(&k, &exists, &mut warned, 2_000).table;
    let hit = t.get(ip("10.42.0.15")).unwrap();
    assert_eq!(
        &*hit.workload.text, "db/sts/postgres",
        "the live pod wins the address"
    );
    assert!(
        t.get(ip("fd00:42::f")).is_some(),
        "the old pod's other address stays for the grace period"
    );
    m.sweep(2_000 + GRACE_S - 1);
    assert!(
        m.build(&k, &exists, &mut warned, 2_029)
            .table
            .get(ip("fd00:42::f"))
            .is_some()
    );
    m.sweep(2_000 + GRACE_S);
    let t = m.build(&k, &exists, &mut warned, 2_030).table;
    assert!(
        t.get(ip("fd00:42::f")).is_none(),
        "gone after the grace period"
    );
    assert_eq!(
        t.name_at(ip("10.42.0.15"), 1_500),
        Some("media/deploy/jellyfin")
    );
    assert_eq!(t.name_at(ip("10.42.0.15"), 2_500), Some("db/sts/postgres"));
    assert_eq!(
        t.name_at(ip("fd00:42::f"), 1_500),
        Some("media/deploy/jellyfin")
    );
    assert_eq!(
        t.key_name(&telltale_telemetry::workload::key("media/deploy/jellyfin")),
        Some("media/deploy/jellyfin"),
        "a gone workload's key is still named"
    );
    // The wire form (peers, workloads.json) round-trips.
    let w = to_wire(&t, 2_030, "ctrl");
    let back =
        from_wire(serde_json::from_slice(&serde_json::to_vec(&w).unwrap()).unwrap()).unwrap();
    assert_eq!(to_wire(&back, 2_030, "ctrl"), w);
    assert_eq!(
        back.name_at(ip("10.42.0.15"), 1_500),
        Some("media/deploy/jellyfin")
    );
}

// REQ: FLT-017 — a restart of TelltaleDNS itself: the saved history keys the replayed query
// log by the workload that held each address then, and each workload's 24-hour counts carry on.
#[test]
fn flt_017_a_restart_keeps_workload_analytics() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_str().unwrap();
    let k = KubernetesConfig::default();
    let exists = |_: &str| true;
    let mut warned = HashSet::new();
    let mut m = Model::default();
    let pods = fixture();
    m.pod_list(None, &pods[..1], 1_000); // jellyfin on 10.42.0.15
    m.build(&k, &exists, &mut warned, 1_000);
    m.pod_deleted(&pods[0], 2_000);
    let mut other = pods[1].clone(); // postgres-0 takes the address
    other.status.pod_ips = vec![PodIp {
        ip: "10.42.0.15".into(),
    }];
    m.pod_event(&other, 2_000);
    let t = m.build(&k, &exists, &mut warned, 2_000).table;
    save(data_dir, &to_wire(&t, 2_000, "ctrl"));
    let back = persisted(data_dir).expect("saved table");
    let addr = mapped(ip("10.42.0.15"));
    let jellyfin = telltale_telemetry::workload::key("media/deploy/jellyfin");
    let postgres = telltale_telemetry::workload::key("db/sts/postgres");
    assert_eq!(key_at(&back, addr, 1_500), Some(jellyfin));
    assert_eq!(key_at(&back, addr, 2_500), Some(postgres));
    assert_eq!(key_at(&back, mapped(ip("192.168.1.50")), 1_500), None);

    // Counts: saved from one hub, restored into the next one's (on top of what it saw since).
    let now = now_s();
    let name = telltale_telemetry::event::Name::from_wire(b"\x07example\x03com\x00");
    let keyed = |ts: u64, i: u64| {
        let mut e = event("10.42.0.15", ts, i);
        e.client_ip = jellyfin;
        telltale_telemetry::event::Record::Query(e, name)
    };
    let before = telltale_telemetry::Hub::new(1 << 16);
    for i in 0..30 {
        before.aggregates().record(&keyed(now - 7_200 + i, i));
    }
    save_counts(data_dir, &counts_of(&before));
    let after = telltale_telemetry::Hub::new(1 << 16);
    after.aggregates().record(&keyed(now, 1));
    assert_eq!(restore_counts(data_dir, &after), 1);
    let agg = after.aggregates();
    let c = &agg.workload_counts()[&jellyfin];
    assert_eq!(
        c.day(now),
        (31, 3),
        "30 saved (every tenth blocked) and 1 since"
    );
    assert_eq!(c.last_seen_s, now);
}

#[test]
fn flt_017_workload_refs() {
    let mut m = Model::default();
    m.pod_list(None, &fixture(), 1_000);
    let t = m
        .build(
            &KubernetesConfig::default(),
            &|_: &str| true,
            &mut HashSet::new(),
            1_000,
        )
        .table;
    assert_eq!(
        workload_ref("media/deploy/jellyfin", &t).as_deref(),
        Some("media/deploy/jellyfin")
    );
    let key = telltale_telemetry::workload::key("db/sts/postgres");
    let key_text = std::net::Ipv6Addr::from(key).to_string();
    assert_eq!(
        workload_ref(&key_text, &t).as_deref(),
        Some("db/sts/postgres")
    );
    assert_eq!(
        workload_ref("10.42.0.15", &t),
        None,
        "a pod address is an address"
    );
    assert_eq!(workload_ref("living-room-tv", &t), None);
    assert_eq!(workload_ref("a/b", &t), None);
}

// ---- A fake API server ----

#[derive(Default)]
struct FakeState {
    pods: Mutex<String>,
    /// Requests seen: (path, bearer token).
    hits: Mutex<Vec<(String, String)>>,
    /// The next lists that fail with 500.
    fail_lists: AtomicUsize,
}

/// Serves `/api/v1/pods` and `/api/v1/namespaces` (lists and watches) from `state`; a pods
/// watch streams the lines sent on `events` until a line `CLOSE`.
async fn fake_api(
    state: Arc<FakeState>,
    events: tokio::sync::mpsc::UnboundedReceiver<String>,
) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let events = Arc::new(tokio::sync::Mutex::new(events));
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let (state, events) = (Arc::clone(&state), Arc::clone(&events));
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut b = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&b[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let path = head.split(' ').nth(1).unwrap_or("").to_owned();
                let token = head
                    .lines()
                    .find_map(|l| l.strip_prefix("authorization: Bearer "))
                    .or_else(|| {
                        head.lines()
                            .find_map(|l| l.strip_prefix("Authorization: Bearer "))
                    })
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                state.hits.lock().unwrap().push((path.clone(), token));
                let watch = path.contains("watch=1");
                if path.starts_with("/api/v1/pods") && !watch {
                    if state.fail_lists.load(Ordering::SeqCst) > 0 {
                        state.fail_lists.fetch_sub(1, Ordering::SeqCst);
                        let _ = s
                            .write_all(b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                            .await;
                        return;
                    }
                    let body = state.pods.lock().unwrap().clone();
                    let _ = s
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                                body.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                } else if path.starts_with("/api/v1/pods") {
                    let _ = s
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n")
                        .await;
                    let mut rx = events.lock().await;
                    while let Some(line) = rx.recv().await {
                        if line == "CLOSE" {
                            break;
                        }
                        if s.write_all(format!("{line}\n").as_bytes()).await.is_err() {
                            return;
                        }
                    }
                } else if path.starts_with("/api/v1/namespaces") && !watch {
                    let body = r#"{"metadata":{"resourceVersion":"5"},"items":[{"metadata":{"name":"media","labels":{"telltaledns.io/group":"media"}}}]}"#;
                    let _ = s
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                                body.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                } else {
                    let _ = s
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n")
                        .await;
                    tokio::time::sleep(Duration::from_secs(120)).await;
                }
            });
        }
    });
    addr
}

fn pod_json(name: &str, ns: &str, rs: &str, hash: &str, ip: &str, rv: &str) -> String {
    format!(
        r#"{{"metadata":{{"name":"{name}","namespace":"{ns}","resourceVersion":"{rv}","labels":{{"pod-template-hash":"{hash}"}},"ownerReferences":[{{"kind":"ReplicaSet","name":"{rs}","controller":true}}]}},"spec":{{}},"status":{{"phase":"Running","podIPs":[{{"ip":"{ip}"}}]}}}}"#
    )
}

async fn until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

fn texts(m: &Mutex<Model>) -> Vec<String> {
    let mut m = m.lock().unwrap();
    m.build(
        &KubernetesConfig::default(),
        &|_: &str| true,
        &mut HashSet::new(),
        now_s(),
    )
    .table
    .workloads()
    .iter()
    .map(|w| w.text.to_string())
    .collect()
}

// REQ: FLT-017 (AC 5) — against a fake API server: the first list, an ADDED and a DELETED
// event, a 410 that makes it list again, a rotated token, and failed lists counted.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one scripted conversation with the fake server
async fn flt_017_watcher_against_a_fake_api_server() {
    let state = Arc::new(FakeState::default());
    *state.pods.lock().unwrap() = format!(
        r#"{{"metadata":{{"resourceVersion":"10"}},"items":[{}]}}"#,
        pod_json(
            "web-abc12-x1",
            "shop",
            "web-abc12",
            "abc12",
            "10.42.1.1",
            "9"
        )
    );
    state.fail_lists.store(2, Ordering::SeqCst);
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let addr = fake_api(Arc::clone(&state), rx).await;
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "first\n").unwrap();
    let client =
        telltale_filter::fetch::Client::new(Arc::new(telltale_filter::fetch::SystemResolver), &[])
            .unwrap();
    let api = Arc::new(Api::new(
        format!("http://{addr}"),
        token.clone(),
        Duration::ZERO,
        client,
    ));
    let model = Arc::new(Mutex::new(Model::default()));
    let kube = Arc::new(Kube::default());
    let changed = Arc::new(tokio::sync::Notify::new());
    let task = tokio::spawn(pods_loop(
        Arc::clone(&api),
        None,
        Arc::clone(&model),
        Arc::clone(&kube),
        Arc::clone(&changed),
    ));
    // Two failed lists are counted (and back off), then the list arrives.
    until("the first list", || texts(&model) == ["shop/deploy/web"]).await;
    assert!(kube.watch_errors.load(Ordering::Relaxed) >= 2);
    assert!(kube.sync_failed.load(Ordering::Relaxed) >= 2);
    assert!(kube.state().last_sync_s > 0);
    // The token rotates; the next request carries the new one.
    std::fs::write(&token, "second\n").unwrap();
    let added = pod_json(
        "api-def34-y2",
        "shop",
        "api-def34",
        "def34",
        "10.42.1.2",
        "11",
    );
    tx.send(format!(r#"{{"type":"ADDED","object":{added}}}"#))
        .unwrap();
    until("ADDED", || texts(&model).len() == 2).await;
    let deleted = pod_json(
        "web-abc12-x1",
        "shop",
        "web-abc12",
        "abc12",
        "10.42.1.1",
        "12",
    );
    tx.send(format!(r#"{{"type":"DELETED","object":{deleted}}}"#))
        .unwrap();
    until("DELETED (in its grace period)", || {
        model
            .lock()
            .unwrap()
            .pods
            .values()
            .any(|t| t.info.name == "web-abc12-x1" && t.deleted_s.is_some())
    })
    .await;
    // A bookmark only moves the resource version; a 410 makes it list again.
    tx.send(r#"{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"13"}}}"#.into())
        .unwrap();
    let lists_before = state
        .hits
        .lock()
        .unwrap()
        .iter()
        .filter(|(p, _)| !p.contains("watch=1"))
        .count();
    *state.pods.lock().unwrap() =
        format!(r#"{{"metadata":{{"resourceVersion":"20"}},"items":[{added}]}}"#);
    tx.send(r#"{"type":"ERROR","object":{"kind":"Status","code":410,"reason":"Expired"}}"#.into())
        .unwrap();
    until("a list after 410", || {
        state
            .hits
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| !p.contains("watch=1"))
            .count()
            > lists_before
    })
    .await;
    let hits = state.hits.lock().unwrap().clone();
    assert!(hits.iter().any(|(_, t)| t == "first"));
    assert!(
        hits.iter().any(|(_, t)| t == "second"),
        "the new token: {hits:?}"
    );
    assert!(
        hits.iter()
            .any(|(p, _)| p.contains("fieldSelector=status.phase%21%3DSucceeded")),
        "finished pods aren't listed: {hits:?}"
    );
    assert!(
        hits.iter().any(|(p, _)| p.contains("resourceVersion=10")),
        "watched from the list's version"
    );
    task.abort();
}

// REQ: FLT-017 (AC 5), CLU-004 — a watcher failing against an unreachable API server never
// touches answering: a query is answered while it fails, and the errors are counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flt_017_dns_answers_under_a_failing_watcher() {
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = dead.local_addr().unwrap();
    drop(dead); // nothing listens: every request fails at once
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "t").unwrap();
    let client =
        telltale_filter::fetch::Client::new(Arc::new(telltale_filter::fetch::SystemResolver), &[])
            .unwrap();
    let api = Arc::new(Api::new(
        format!("http://{addr}"),
        token,
        Duration::ZERO,
        client,
    ));
    let src = Arc::new(crate::http::tests::sources());
    let mut cfg = Config::default();
    cfg.kubernetes.enabled = true;
    src.config.store(Arc::new(cfg));
    let stop = Arc::new(AtomicBool::new(false));
    let h = spawn_watcher(
        Arc::clone(&src),
        Source::Api(api),
        HashMap::new(),
        Arc::clone(&stop),
    )
    .unwrap();
    let kube = Arc::clone(&src.pipeline.kube);
    until("failed lists", || {
        kube.watch_errors.load(Ordering::Relaxed) >= 2
    })
    .await;
    let answered = crate::pipeline::tests_support::answer(&src.pipeline, "localhost", "10.42.9.9");
    assert!(answered, "DNS answered while the watcher fails");
    assert!(kube.state().last_error.is_some());
    assert!(!src.pipeline.workloads.is_active(), "no table, no lookups");
    stop.store(true, Ordering::Relaxed);
    let _ = tokio::task::spawn_blocking(move || h.join()).await;
}

// REQ: FLT-017 (AC 2) — a pod address is recognized as its workload in the pipeline: the
// workload's group decides, explain says so, a `[[client]]` keyed by the pod's address loses,
// and `$client` rules match the workload by its text form.
#[test]
#[allow(clippy::many_single_char_names)]
fn flt_017_identification_in_the_pipeline() {
    let cfg = kcfg(&format!(
        "{GROUPS}
[[client]]
name = \"old-postgres-entry\"
match = [\"10.42.0.21\"]
groups = [\"media\"]
"
    ));
    let p = crate::pipeline::tests_support::pipeline_from(&cfg);
    let mut m = Model::default();
    m.pod_list(None, &fixture(), now_s());
    m.namespace_list(&[ns("media", &[("telltaledns.io/group", "media")])]);
    let groups: Vec<String> = cfg.group.iter().map(|g| g.name.to_string()).collect();
    let exists = |g: &str| groups.iter().any(|x| x == g) || g == "default";
    let t = m
        .build(&cfg.kubernetes, &exists, &mut HashSet::new(), now_s())
        .table;
    install(&p, t);
    let explain = |client: &str| {
        p.explain(
            &crate::explain::Request {
                name: "example.org",
                qtype: telltale_proto::rtype::A,
                client: client.parse().unwrap(),
                mac: None,
                client_id: None,
            },
            |_| None,
        )
        .unwrap()
    };
    let e = explain("10.42.0.15");
    assert_eq!(e.client.identified_by, "kubernetes");
    assert_eq!(e.client.device.as_deref(), Some("media/deploy/jellyfin"));
    assert_eq!(e.client.groups, ["media"]);
    let w = e.client.workload.as_ref().unwrap();
    assert_eq!(
        (w.pod.as_str(), w.group_from),
        ("jellyfin-7d9f4c8b6-x2k1q", "namespace_label")
    );
    assert!(
        e.notes.iter().any(|n| n
            == "recognized as Kubernetes workload media/deploy/jellyfin (pod jellyfin-7d9f4c8b6-x2k1q), group media from the namespace label"),
        "{:?}",
        e.notes
    );
    // The [[client]] keyed by postgres-0's address is stale: the workload wins.
    let e = explain("10.42.0.21");
    assert_eq!(e.client.identified_by, "kubernetes");
    assert_eq!(e.client.groups, ["servers"]);
    // The IPv6 address of the two-address pod too.
    assert_eq!(explain("fd00:42::f").client.groups, ["media"]);
    // No group of its own falls to the network group, like any device.
    let mut k = cfg.kubernetes.clone();
    k.default_group = telltale_config::SafeString::default();
    let t = m.build(&k, &exists, &mut HashSet::new(), now_s()).table;
    install(&p, t);
    let e = explain("10.42.0.43");
    assert_eq!(e.client.identified_by, "kubernetes");
    assert_eq!(e.client.groups, ["podnet"], "the pod's network group");
    // Not a pod: the usual chain.
    let e = explain("192.168.1.50");
    assert_eq!(e.client.identified_by, "default");
    // An empty table: the existing path, unchanged.
    install(&p, WorkloadTable::default());
    let e = explain("10.42.0.21");
    assert_eq!(e.client.identified_by, "ip");
    assert_eq!(e.client.device.as_deref(), Some("old-postgres-entry"));
    assert!(!Workloads::none().is_active());
}

fn replica(name: &str, rs: &str, hash: &str, ip: &str) -> PodObject {
    serde_json::from_str(&pod_json(name, "media", rs, hash, ip, "1")).unwrap()
}

fn event(ip: &str, ts_s: u64, i: u64) -> telltale_telemetry::QueryEvent {
    let ip: std::net::Ipv4Addr = ip.parse().unwrap();
    telltale_telemetry::QueryEvent {
        ts_us: ts_s * 1_000_000 + i,
        client_ip: ip.to_ipv6_mapped().octets(),
        client_ref: 0,
        group: 0,
        qtype: telltale_proto::rtype::A,
        qclass: 1,
        rcode: Some(0),
        status: if i.is_multiple_of(10) {
            telltale_telemetry::Status::Blocked
        } else {
            telltale_telemetry::Status::Forwarded
        },
        proto: telltale_telemetry::Proto::Udp,
        flags: 0x8180,
        rule: None,
        upstream: 1,
        attempts: 1,
        t_total_us: 900,
        t_upstream_us: 800,
        resp_size: 64,
        answers: 1,
    }
}

async fn counted(src: &crate::http::Sources, text: &str, n: u64) {
    let key = telltale_telemetry::workload::key(text);
    until("the events drained", || {
        src.pipeline
            .telemetry
            .aggregates()
            .workload_counts()
            .get(&key)
            .is_some_and(|c| c.day(now_s()).0 >= n)
    })
    .await;
}

// REQ: FLT-017 (AC 3) — 1,000 queries from a Deployment's three pods are one device: one in
// top clients, one anomaly baseline, one new device, one identity (`workload`, certain); the
// query log keeps the pods' addresses and names them by the workload at read time; after a
// rollout reuses the addresses for another workload, old rows keep the old name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn flt_017_a_deployment_is_one_device() {
    use telltale_api::Backend;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.node.data_dir = telltale_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
    cfg.telemetry.qlog.enabled = true;
    cfg.telemetry.anomaly.enabled = true;
    cfg.kubernetes.enabled = true;
    let mut src = crate::http::tests::sources();
    src.config.store(Arc::new(cfg.clone()));
    let (qlog, stats) = crate::server::query_log(&cfg);
    src.qlog = stats;
    let anomalies = crate::anomaly::Anomalies::start(&cfg).unwrap();
    src.anomalies = Some(Arc::clone(&anomalies));
    let src = Arc::new(src);
    let sink = crate::tail::combine(
        qlog,
        None,
        Some(Box::new(crate::tail::Fanout(vec![Box::new(
            anomalies.sink(),
        )]))),
    );
    let aggregator = src
        .pipeline
        .telemetry
        .spawn_aggregator(Duration::from_millis(25), sink)
        .unwrap();
    let now = now_s();
    let (t0, t1) = (now - 1_200, now - 600);
    let ips = ["10.42.0.11", "10.42.0.12", "10.42.0.13"];
    let v1: Vec<PodObject> = ips
        .iter()
        .enumerate()
        .map(|(i, ip)| {
            replica(
                &format!("jellyfin-7d9f4c8b6-{i}"),
                "jellyfin-7d9f4c8b6",
                "7d9f4c8b6",
                ip,
            )
        })
        .collect();
    let mut m = Model::default();
    let all = |_: &str| true;
    m.pod_list(None, &v1, t0);
    install(
        &src.pipeline,
        m.build(&cfg.kubernetes, &all, &mut HashSet::new(), t0)
            .table,
    );
    let name = b"\x07example\x03com\x00";
    // A laptop the engine has known for two days: devices are "new" only after its first day.
    src.pipeline
        .telemetry
        .emit_query(&event("192.168.1.50", t0 - 2 * 86_400, 1), name);
    // No workload holds its address, so the analytics see it only after the hold
    // (`WORKLOAD_HOLD`); let it seed the engine before the pods ask.
    let seeded = tokio::time::Instant::now() + Duration::from_secs(10);
    while anomalies.counters().1 < 1 {
        assert!(
            tokio::time::Instant::now() < seeded,
            "the laptop never reached the engine"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for i in 0..1_000u64 {
        let ts = t0 + 10 + i * 500 / 1_000;
        src.pipeline
            .telemetry
            .emit_query(&event(ips[usize::try_from(i % 3).unwrap()], ts, i), name);
    }
    counted(&src, "media/deploy/jellyfin", 1_000).await;
    let api = crate::api_backend::ApiBackend {
        src: Arc::clone(&src),
    };
    let key = telltale_telemetry::workload::key("media/deploy/jellyfin");
    let key_text = std::net::Ipv6Addr::from(key).to_string();
    // One device in top clients, named by the workload.
    let top: Vec<_> = [
        telltale_api::model::Hour::Current,
        telltale_api::model::Hour::Previous,
    ]
    .into_iter()
    .flat_map(|h| api.top(telltale_api::model::TopKind::Clients, h, 10, None))
    .collect();
    let keys: HashSet<&str> = top.iter().map(|t| t.key.as_str()).collect();
    assert_eq!(keys, HashSet::from([key_text.as_str()]), "{top:?}");
    assert!(
        top.iter()
            .all(|t| t.name.as_deref() == Some("media/deploy/jellyfin"))
    );
    // One anomaly baseline (beside the laptop's), one new device.
    assert_eq!(
        anomalies.counters().1,
        2,
        "the laptop and one for the three pods"
    );
    let new = api.new_devices(0);
    assert_eq!(new.len(), 1);
    assert_eq!(new[0].client_name.as_deref(), Some("media/deploy/jellyfin"));
    // One identity: a workload, certain.
    src.identify.pass(&src, now_s());
    let ids: Vec<_> = api
        .identities()
        .into_iter()
        .filter(|i| i.available)
        .collect();
    assert_eq!(ids.len(), 1, "{ids:?}");
    assert_eq!(
        (ids[0].class.as_str(), ids[0].level.as_str()),
        ("workload", "certain")
    );
    assert_eq!(ids[0].product.as_deref(), Some("Deployment in media"));
    let id = api.identity("media/deploy/jellyfin").unwrap();
    let ev = id.evidence.unwrap().kubernetes.unwrap();
    assert_eq!(ev.pods.len(), 3);
    // The workload list counts it.
    let w = api.kubernetes_workloads().unwrap();
    assert_eq!(w.len(), 1);
    assert_eq!((w[0].queries_24h, w[0].blocked_24h), (1_000, 100));
    // A rollout: another workload's pods take the same addresses.
    let v2: Vec<PodObject> = ips
        .iter()
        .enumerate()
        .map(|(i, ip)| {
            replica(
                &format!("sonarr-5f6d7c9b8-{i}"),
                "sonarr-5f6d7c9b8",
                "5f6d7c9b8",
                ip,
            )
        })
        .collect();
    m.pod_list(None, &v2, t1);
    install(
        &src.pipeline,
        m.build(&cfg.kubernetes, &all, &mut HashSet::new(), t1)
            .table,
    );
    for i in 0..300u64 {
        let ts = t1 + 10 + i;
        src.pipeline
            .telemetry
            .emit_query(&event(ips[usize::try_from(i % 3).unwrap()], ts, i), name);
    }
    counted(&src, "media/deploy/sonarr", 300).await;
    drop(aggregator); // the final drain, and the query log's segment is finished
    let page = |client: &str| {
        api.queries(
            &telltale_api::model::QueryParams {
                client: Some(client.into()),
                ..telltale_api::model::QueryParams::default()
            },
            t0 * 1_000_000,
            0,
            2_000,
        )
        .unwrap()
    };
    let rows = page("10.42.0.11").items;
    assert_eq!(rows.len(), 334 + 100);
    for r in &rows {
        let expect = if r.ts_unix_micros / 1_000_000 < t1 {
            "media/deploy/jellyfin"
        } else {
            "media/deploy/sonarr"
        };
        assert_eq!(
            r.client.as_str(),
            "10.42.0.11",
            "the log keeps the pod's address"
        );
        assert_eq!(r.client_name.as_deref(), Some(expect), "named at read time");
    }
    // `client` may name the workload: its addresses while it held them.
    let old = page("media/deploy/jellyfin").items;
    assert_eq!(old.len(), 1_000);
    assert!(old.iter().all(|r| r.ts_unix_micros / 1_000_000 < t1));
    let new = page(
        &std::net::Ipv6Addr::from(telltale_telemetry::workload::key("media/deploy/sonarr"))
            .to_string(),
    )
    .items;
    assert_eq!(new.len(), 300);
}
