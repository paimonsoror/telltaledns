// REQ: FLT-004, OBS-024, OBS-010, API-002 (ADR-180) — a local file named through the API: only an
// administrator points a list at one; what reading one went wrong with reaches a caller below
// admin only as a generic reason; and a simulation by such a caller reads no file the
// configuration in effect doesn't already name. Driven through the real routes, sign-in and
// backend (the harness of `local_access_tests`).

use std::sync::Arc;

use axum::http::StatusCode;
use telltale_api::auth;

use super::local_access_tests::{Creds, NO_PROGRAM, NO_SOCKET, Node, now};

fn marker() -> String {
    format!("marker{}", auth::crypto::random_id())
}

/// The running configuration and the files' are `cfg` (with this node's data directory).
fn configure(n: &Node, mut cfg: telltale_config::Config) {
    cfg.node.data_dir = telltale_config::SafeString::new(n.data()).unwrap();
    n.src.file_config.store(Arc::new(cfg.clone()));
    n.src.config.store(Arc::new(cfg));
}

fn file_list(path: &str) -> serde_json::Value {
    serde_json::json!({ "path": path, "kind": "allow" })
}

/// REQ: FLT-004, API-002 (ADR-180) — a list read from a local file is added, or pointed at another
/// file, only by an administrator (their session or an admin token, not an agent token): an
/// operator and agent tokens get 403 with a hint, dry run or not, and nothing is stored. An
/// operator keeps URL lists and inline rules, may change the administrator's file list without
/// choosing another file, and may delete it.
#[tokio::test]
async fn flt_004_only_an_admin_names_a_list_file() {
    let n = Node::new(telltale_config::Config::default());
    let path = "/etc/telltale/allow.txt";
    for (who, creds) in [
        ("operator", &n.operator),
        ("operator's agent", &n.operator_agent),
        ("admin's agent", &n.admin_agent),
    ] {
        for dry in [true, false] {
            let (s, v) = n
                .put("/api/v1/lists/family-allow", creds, dry, file_list(path))
                .await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{who}, dry={dry}: {v}");
            assert_eq!(v["code"], "forbidden", "{v}");
            assert!(
                v["detail"].as_str().unwrap_or("").contains("`path`"),
                "{who}: the field is named: {v}"
            );
            assert!(
                v["hint"]
                    .as_str()
                    .unwrap_or("")
                    .contains("needs an administrator"),
                "{who}: {v}"
            );
        }
    }
    assert!(
        crate::managed::entries(n.auth.state()).lists.is_empty(),
        "nothing was stored"
    );
    // An administrator may, with a token or a session (the documented place for such a file).
    for (who, creds) in [
        ("admin token", &n.admin),
        ("admin session", &n.admin_session),
    ] {
        let (s, v) = n
            .put("/api/v1/lists/family-allow", creds, true, file_list(path))
            .await;
        assert_eq!(s, StatusCode::OK, "{who}: {v}");
    }
    let (s, v) = n
        .put(
            "/api/v1/lists/family-allow",
            &n.admin_session,
            false,
            file_list(path),
        )
        .await;
    assert_eq!(
        (s, v["applied"].as_bool()),
        (StatusCode::OK, Some(true)),
        "{v}"
    );
    // An operator keeps every other kind of list.
    for (name, body, creds) in [
        (
            "ads",
            serde_json::json!({ "url": "https://lists.example.com/hosts.txt" }),
            &n.operator,
        ),
        (
            "manual",
            serde_json::json!({ "rules": ["||ads.example^"] }),
            &n.operator,
        ),
        (
            "agent-made",
            serde_json::json!({ "rules": ["||tracker.example^"] }),
            &n.operator_agent,
        ),
    ] {
        let (s, v) = n
            .put(&format!("/api/v1/lists/{name}"), creds, false, body)
            .await;
        assert_eq!(s, StatusCode::OK, "{name}: {v}");
    }
    // ...and may change the administrator's file list while it reads the same file.
    let mut off = file_list(path);
    off["enabled"] = false.into();
    let (s, v) = n
        .put("/api/v1/lists/family-allow", &n.operator, false, off)
        .await;
    assert_eq!(s, StatusCode::OK, "the same file: {v}");
    // Another file is the administrator's choice.
    let (s, v) = n
        .put(
            "/api/v1/lists/family-allow",
            &n.operator,
            true,
            file_list("/etc/telltale/other.txt"),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "another file: {v}");
    // Deleting only takes something away: an operator may.
    let (s, v) = n
        .send("DELETE", "/api/v1/lists/family-allow", &n.operator, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

fn error_of<'a>(v: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    v["items"]
        .as_array()?
        .iter()
        .find(|l| l["name"] == name)?
        .get("error")?
        .as_str()
}

/// REQ: FLT-004, API-002 (ADR-180) — what went wrong reading a list from a local file reaches a
/// caller below admin as a generic reason, never a line of the file; an administrator sees the
/// whole message (the node's log has it too). A URL list's error is shown to everyone as before.
#[tokio::test]
async fn flt_004_a_local_list_error_is_generic_below_admin() {
    use telltale_filter::fetch::{
        Client, FetchSettings, Fetcher, ListMeta, ListSpec, Outcome, Store, SystemResolver,
    };
    let n = Node::new(telltale_config::Config::default());
    let data = n.data();
    let mark = marker();
    let file = format!("{data}/hosts-copy.txt");
    std::fs::write(
        &file,
        format!("0.0.0.0 bad!{mark}\n0.0.0.0 also!{mark}\n0.0.0.0 more!{mark}\n"),
    )
    .unwrap();
    let cfg: telltale_config::Config = toml::from_str(&format!(
        r#"
        [[list]]
        name = "local"
        path = "{file}"
        [[list]]
        name = "web"
        url = "https://lists.example.com/hosts.txt"
        "#
    ))
    .unwrap();
    configure(&n, cfg.clone());
    let store = Store::open(&std::path::Path::new(&data).join("lists")).unwrap();
    store
        .save_meta(
            "web",
            &ListMeta {
                source: "https://lists.example.com/hosts.txt".into(),
                last_attempt: Some(5_000),
                last_error: Some("HTTP 404".into()),
                consecutive_failures: 2,
                ..ListMeta::default()
            },
        )
        .unwrap();
    let fetcher = Arc::new(Fetcher::new(
        store,
        Client::new(Arc::new(SystemResolver), &[]).unwrap(),
        FetchSettings::from_config(&cfg),
    ));
    let specs = ListSpec::from_config(&cfg);
    let _ = fetcher.due(&specs, now());
    let local = specs.iter().find(|s| s.name == "local").unwrap();
    let outcome = fetcher.refresh_one(local).await;
    assert!(
        matches!(&outcome, Outcome::Failed(e) if e.contains(&mark)),
        "the parser's reason quotes the line: {outcome:?}"
    );
    n.src.lists.store(Some(Arc::new(crate::lists::ListsShared {
        fetcher,
        compiled: std::sync::Mutex::new(None),
    })));
    for (who, creds) in [
        ("viewer", &n.viewer),
        ("operator", &n.operator),
        ("operator's agent", &n.operator_agent),
        ("admin's agent", &n.admin_agent),
    ] {
        let (s, v) = n.send("GET", "/api/v1/lists", creds, None).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert!(!v.to_string().contains(&mark), "{who}: {v}");
        let reason = error_of(&v, "local").unwrap_or_default();
        assert!(
            reason.contains("administrator"),
            "{who}: a generic reason: {v}"
        );
        assert_eq!(
            error_of(&v, "web"),
            Some("HTTP 404"),
            "{who}: a URL list's error is as it was"
        );
    }
    for (who, creds) in [
        ("admin token", &n.admin),
        ("admin session", &n.admin_session),
    ] {
        let (s, v) = n.send("GET", "/api/v1/lists", creds, None).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert!(
            error_of(&v, "local").unwrap_or_default().contains(&mark),
            "{who}: an administrator sees the whole message: {v}"
        );
    }
}

/// REQ: API-002 (ADR-180) — a pre-save check whose TLS file can't be used tells a caller below
/// admin only that, the same whether the file is there or not; an administrator sees why.
#[tokio::test]
async fn api_002_a_tls_file_error_in_a_check_is_generic_below_admin() {
    let n = Node::new(telltale_config::Config::default());
    let d = n.data();
    let bad = format!("{d}/ca-bad.pem");
    let missing = format!("{d}/ca-missing.pem");
    std::fs::write(&bad, format!("-----BEGIN {}\n", marker())).unwrap();
    let body = |ca: &str| serde_json::json!({ "url": "tls://192.0.2.53", "tls_server_name": "dns.example", "tls_ca": ca });
    for (who, creds) in [
        ("operator", &n.operator),
        ("operator's agent", &n.operator_agent),
        ("admin's agent", &n.admin_agent),
    ] {
        let (s1, v1) = n
            .send("POST", "/api/v1/checks/upstream", creds, Some(body(&bad)))
            .await;
        let (s2, v2) = n
            .send(
                "POST",
                "/api/v1/checks/upstream",
                creds,
                Some(body(&missing)),
            )
            .await;
        assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK), "{v1} {v2}");
        assert_eq!(v1["ok"], false, "{v1}");
        for v in [&v1, &v2] {
            let text = v.to_string();
            assert!(
                !text.contains("illegal section start")
                    && !text.contains("os error")
                    && !text.contains("No such file"),
                "{who}: {v}"
            );
            assert!(
                v["error"].as_str().unwrap_or("").contains("administrator"),
                "{who}: a generic reason: {v}"
            );
        }
        assert_eq!(v1, v2, "{who}: a file that is there and one that isn't");
    }
    for (who, creds) in [
        ("admin token", &n.admin),
        ("admin session", &n.admin_session),
    ] {
        let (_, v) = n
            .send("POST", "/api/v1/checks/upstream", creds, Some(body(&bad)))
            .await;
        assert!(
            v["error"]
                .as_str()
                .unwrap_or("")
                .contains("illegal section start"),
            "{who}: {v}"
        );
        let (_, v) = n
            .send(
                "POST",
                "/api/v1/checks/upstream",
                creds,
                Some(body(&missing)),
            )
            .await;
        assert!(
            v["error"].as_str().unwrap_or("").contains("os error"),
            "{who}: {v}"
        );
    }
}

/// REQ: OBS-010 (ADR-180) — a test send whose private CA file (`tls_ca`) can't be used tells a
/// caller below admin only that, the same whether the file is there or not; an administrator
/// sees why.
#[tokio::test]
async fn obs_010_a_tls_file_error_in_a_test_send_is_generic_below_admin() {
    let n = Node::new(telltale_config::Config::default());
    let d = n.data();
    let bad = format!("{d}/mail-ca-bad.pem");
    let missing = format!("{d}/mail-ca-missing.pem");
    std::fs::write(&bad, format!("-----BEGIN {}\n", marker())).unwrap();
    for (name, ca) in [("mail-bad", &bad), ("mail-missing", &missing)] {
        let (s, v) = n
            .put(
                &format!("/api/v1/alerts/destinations/{name}"),
                &n.operator,
                false,
                serde_json::json!({
                    "type": "email", "url": "smtp://127.0.0.1:9", "from": "dns@example.com",
                    "to": ["me@example.com"], "tls_ca": ca,
                }),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{name}: {v}");
    }
    let send_test = |name: &str| format!("/api/v1/alerts/destinations/{name}/test");
    for (who, creds) in [
        ("operator", &n.operator),
        ("operator's agent", &n.operator_agent),
    ] {
        let (s1, v1) = n.send("POST", &send_test("mail-bad"), creds, None).await;
        let (s2, v2) = n
            .send("POST", &send_test("mail-missing"), creds, None)
            .await;
        assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK), "{v1} {v2}");
        for v in [&v1, &v2] {
            assert_eq!(v["ok"], false, "{v}");
            let text = v.to_string();
            assert!(
                !text.contains("illegal section start")
                    && !text.contains("os error")
                    && !text.contains("No such file"),
                "{who}: {v}"
            );
            assert!(
                v["error"].as_str().unwrap_or("").contains("administrator"),
                "{who}: a generic reason: {v}"
            );
        }
        assert_eq!(v1, v2, "{who}: a file that is there and one that isn't");
    }
    for (who, creds) in [
        ("admin token", &n.admin),
        ("admin session", &n.admin_session),
    ] {
        let (_, v) = n.send("POST", &send_test("mail-bad"), creds, None).await;
        assert!(
            v["error"]
                .as_str()
                .unwrap_or("")
                .contains("illegal section start"),
            "{who}: {v}"
        );
        let (_, v) = n
            .send("POST", &send_test("mail-missing"), creds, None)
            .await;
        assert!(
            v["error"].as_str().unwrap_or("").contains("os error"),
            "{who}: {v}"
        );
    }
}

/// A request that may run a simulation, again while another simulation in this test binary holds
/// the node's one slot (409), within a bound.
async fn while_busy(
    n: &Node,
    method: &str,
    uri: &str,
    creds: &Creds,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    for _ in 0..400 {
        let r = n.send(method, uri, creds, Some(body.clone())).await;
        if r.0 != StatusCode::CONFLICT {
            return r;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("the simulation slot stayed busy");
}

/// `POST /api/v1/simulate` with `config` as the candidate.
async fn simulate(
    n: &Node,
    creds: &Creds,
    config: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    while_busy(
        n,
        "POST",
        "/api/v1/simulate",
        creds,
        &serde_json::json!({ "config": config }),
    )
    .await
}

/// REQ: OBS-024 (ADR-180) — a simulation run by a caller below admin names no local file,
/// program or socket that the configuration in effect doesn't already name: a candidate with a
/// new zone file, hosts file, list file, upstream TLS file or plugin upstream is refused before
/// anything is read (alike whether the file is there or not), and nothing from the file comes
/// back. A candidate that names only the configuration's own files isn't refused, and neither is
/// an administrator's: both go on to this node's own checks. (The query log is off here, so those
/// stop before anything is read or replayed, and the test never takes the node's one simulation
/// slot, which other tests in this binary use.)
#[tokio::test]
async fn obs_024_a_simulation_below_admin_names_no_new_local_file() {
    let n = Node::new(telltale_config::Config::default());
    let data = n.data();
    let mark = marker();
    let path = |f: &str| format!("{data}/{f}");
    std::fs::write(path("zone-new.db"), format!("www IN A {mark}\n")).unwrap();
    std::fs::write(path("zone-ok.db"), "www IN A 192.0.2.5\n").unwrap();
    std::fs::write(path("hosts-new"), format!("192.0.2.9 {mark}.example\n")).unwrap();
    std::fs::write(path("list-new.txt"), format!("{mark}.example\n")).unwrap();
    std::fs::write(path("ca-new.pem"), format!("-----BEGIN {mark}\n")).unwrap();
    let missing = path("not-there");
    // The configuration in effect reads one zone file of its own; no query log.
    let cfg: telltale_config::Config = toml::from_str(&format!(
        "[[zone]]\nname = \"corp.example\"\nfile = \"{}\"\n[telemetry.qlog]\nenabled = false\n",
        path("zone-ok.db")
    ))
    .unwrap();
    configure(&n, cfg);
    let own_zone = serde_json::json!([{ "name": "corp.example", "file": path("zone-ok.db") }]);
    let zone = |f: &str| serde_json::json!({ "zone": [{ "name": "corp.example", "file": f }] });
    let hosts = |f: &str| serde_json::json!({ "zone": own_zone, "local": { "hosts_files": [f] } });
    let list =
        |f: &str| serde_json::json!({ "zone": own_zone, "list": [{ "name": "new", "path": f }] });
    let tls = |f: &str| {
        serde_json::json!({
            "zone": own_zone,
            "upstream": [{ "name": "u", "url": "tls://192.0.2.53", "tls_server_name": "dns.example", "tls_ca": f }],
            "upstream_group": [{ "name": "default", "members": ["u"] }],
        })
    };
    let plugin = |url: String| {
        serde_json::json!({
            "zone": own_zone,
            "upstream": [{ "name": "p", "url": url }],
            "upstream_group": [{ "name": "default", "members": ["p"] }],
        })
    };
    let candidates = [
        ("a zone file", zone(&path("zone-new.db")), zone(&missing)),
        ("a hosts file", hosts(&path("hosts-new")), hosts(&missing)),
        ("a list file", list(&path("list-new.txt")), list(&missing)),
        ("a TLS file", tls(&path("ca-new.pem")), tls(&missing)),
        (
            "a program or a socket",
            plugin(format!("exec://{NO_PROGRAM}")),
            plugin(format!("unix://{NO_SOCKET}")),
        ),
    ];
    for (who, creds) in [
        ("viewer", &n.viewer),
        ("operator", &n.operator),
        ("operator's agent", &n.operator_agent),
        ("admin's agent", &n.admin_agent),
    ] {
        for (what, there, other) in &candidates {
            let (s1, v1) = simulate(&n, creds, there.clone()).await;
            let (s2, v2) = simulate(&n, creds, other.clone()).await;
            for (s, v) in [(s1, &v1), (s2, &v2)] {
                let text = v.to_string();
                assert!(
                    !text.contains(&mark) && !text.contains("illegal section start"),
                    "{who}, {what}: nothing from the file comes back: {v}"
                );
                assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{who}, {what}: {v}");
                assert!(
                    v["hint"].as_str().unwrap_or("").contains("administrator"),
                    "{who}, {what}: {v}"
                );
            }
            assert_eq!(v1, v2, "{who}, {what}: there or not, the same answer");
        }
    }
    // The configuration's own zone file, and a new inline list: not refused; nor is an
    // administrator's new zone file. Both reach this node's own checks (no query log here).
    for (who, creds, candidate) in [
        (
            "viewer, the configuration's own files",
            &n.viewer,
            serde_json::json!({ "zone": own_zone, "list": [{ "name": "new", "rules": ["||x.example^"] }] }),
        ),
        (
            "admin, a new zone file",
            &n.admin,
            zone(&path("zone-new.db")),
        ),
    ] {
        let (s, v) = simulate(&n, creds, candidate).await;
        assert_eq!(
            (s, v["reason"].as_str()),
            (StatusCode::OK, Some("no_query_log")),
            "{who}: {v}"
        );
    }
}

/// REQ: OBS-024 (ADR-180) — a dry run's simulation is the same door: an operator's change that
/// names a new TLS file is planned as before, and its simulation says it wasn't run, without
/// reading the file; an administrator's goes on to this node's own checks (the query log is off
/// here, so nothing is read and the node's one simulation slot isn't taken).
#[tokio::test]
async fn obs_024_a_dry_run_simulation_below_admin_reads_no_new_local_file() {
    let n = Node::new(toml::from_str("[telemetry.qlog]\nenabled = false\n").unwrap());
    let d = n.data();
    let ca = format!("{d}/ca-new.pem");
    std::fs::write(&ca, format!("-----BEGIN {}\n", marker())).unwrap();
    let body = serde_json::json!({ "url": "tls://192.0.2.53", "tls_server_name": "dns.example", "tls_ca": ca });
    let uri = "/api/v1/upstreams/private?dryRun=true&simulate=true";
    let (s, v) = while_busy(&n, "PUT", uri, &n.operator, &body).await;
    assert!(!v.to_string().contains("illegal section start"), "{v}");
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["applied"], false, "{v}");
    assert_eq!(v["simulation"]["available"], false, "{v}");
    assert_eq!(v["simulation"]["reason"], "local_file", "{v}");
    let (s, v) = while_busy(&n, "PUT", uri, &n.admin, &body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["simulation"]["reason"], "no_query_log", "{v}");
}

/// A plain HTTP server on loopback that answers every request with `body`.
fn serve(body: Vec<u8>) -> String {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut c) = conn else { continue };
            let _ = c.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let mut head = Vec::new();
            let mut chunk = [0u8; 1024];
            while let Ok(k) = c.read(&mut chunk) {
                if k == 0 {
                    break;
                }
                head.extend_from_slice(&chunk[..k]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = c.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = c.write_all(&body);
        }
    });
    url
}

/// REQ: OBS-024 (ADR-180) — a simulation downloads a candidate's lists under this node's rules:
/// the candidate's `[filter]` settings (link-local addresses allowed, the byte cap, the timeout)
/// take effect only after a restart, and a list's own `max_bytes` can't go past what this node
/// allows. For every caller, an administrator included. (It takes the node's one simulation slot
/// while it fetches.)
#[test]
fn obs_024_a_simulation_keeps_this_nodes_download_rules() {
    holding_the_slot(keeps_this_nodes_download_rules());
}

async fn keeps_this_nodes_download_rules() {
    let n = Node::new(telltale_config::Config::default());
    // This node: at most 1 KiB per list.
    configure(
        &n,
        toml::from_str("[filter]\nmax_list_bytes = \"1KiB\"\n").unwrap(),
    );
    let url = serve("a.example\n".repeat(400).into_bytes());
    let loose = serde_json::json!({
        "allow_link_local_urls": true, "max_list_bytes": "64MiB", "fetch_timeout_secs": 5,
    });
    for (who, creds) in [("viewer", &n.viewer), ("admin", &n.admin)] {
        for (what, candidate, refusal) in [
            (
                "a link-local address",
                // An IPv6 link-local address without a zone: refused before any connection, and
                // nothing could be reached there anyway.
                serde_json::json!({ "filter": loose, "list": [{ "name": "remote", "url": "http://[fe80::1]:9/list.txt" }] }),
                "link-local",
            ),
            (
                "this node's byte cap",
                serde_json::json!({ "filter": loose, "list": [{ "name": "big", "url": format!("{url}/big.txt") }] }),
                "-byte limit",
            ),
            (
                "a list's own cap",
                serde_json::json!({ "list": [{ "name": "big2", "url": format!("{url}/big2.txt"), "max_bytes": "64MiB" }] }),
                "-byte limit",
            ),
        ] {
            let (s, v) = simulate(&n, creds, candidate).await;
            assert!(
                v["detail"].as_str().unwrap_or("").contains(refusal),
                "{who}, {what}: {s} {v}"
            );
        }
    }
}

/// REQ: API-002 (ADR-180) — what a caller below admin can still tell from a check that names a
/// valid TLS file: that it parses as certificates (the upstream is then built and asked), never
/// what it holds. Here nothing listens where it's asked (loopback), so no network is used.
#[tokio::test]
async fn api_002_a_valid_tls_file_in_a_check_shows_only_that_it_builds() {
    let n = Node::new(telltale_config::Config::default());
    let pem = rcgen::generate_simple_self_signed(vec!["ca.example".to_owned()])
        .unwrap()
        .cert
        .pem();
    let ca = format!("{}/ca-valid.pem", n.data());
    std::fs::write(&ca, &pem).unwrap();
    let body = serde_json::json!({ "url": "tls://127.0.0.1:9", "tls_server_name": "dns.example", "tls_ca": ca });
    let (s, v) = n
        .send("POST", "/api/v1/checks/upstream", &n.operator, Some(body))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["ok"], false, "{v}");
    assert_ne!(v["detail"], "not built", "it builds: {v}");
    let text = v.to_string();
    for line in pem
        .lines()
        .filter(|l| l.len() > 16 && !l.starts_with("-----"))
    {
        assert!(!text.contains(line), "{v}");
    }
}

/// A plain HTTP server on loopback that records the path of every request and answers it with
/// `body` once the gate is open.
struct Catcher {
    url: String,
    seen: Arc<std::sync::Mutex<Vec<String>>>,
    gate: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

impl Catcher {
    fn new(body: Vec<u8>, open: bool) -> Self {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let gate = Arc::new((std::sync::Mutex::new(open), std::sync::Condvar::new()));
        let (s, g) = (Arc::clone(&seen), Arc::clone(&gate));
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut c) = conn else { continue };
                let (s, g, body) = (Arc::clone(&s), Arc::clone(&g), body.clone());
                std::thread::spawn(move || {
                    let _ = c.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                    let mut head = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while let Ok(k) = c.read(&mut chunk) {
                        if k == 0 {
                            break;
                        }
                        head.extend_from_slice(&chunk[..k]);
                        if head.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let path = String::from_utf8_lossy(&head)
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("")
                        .to_owned();
                    s.lock().unwrap().push(path);
                    let (lock, cv) = &*g;
                    drop(
                        cv.wait_timeout_while(
                            lock.lock().unwrap(),
                            std::time::Duration::from_secs(20),
                            |open| !*open,
                        )
                        .unwrap(),
                    );
                    let _ = c.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    );
                    let _ = c.write_all(&body);
                });
            }
        });
        Self { url, seen, gate }
    }

    fn saw(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    fn open(&self) {
        let (lock, cv) = &*self.gate;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
}

/// REQ: OBS-024 (ADR-180) — what one simulation fetches is bounded by this node, for every caller:
/// at most 4 lists by URL or from a file, whose byte caps add up to no more than 4 times this
/// node's `max_list_bytes`, else refused before any request is made; within that it runs as before;
/// and the side snapshot is compiled under this node's `compile_memory` and `max_regexes`.
#[test]
fn obs_024_a_simulation_fetches_within_this_nodes_budget() {
    holding_the_slot(async {
        let n = Node::new(telltale_config::Config::default());
        let own = format!("{}/own.txt", n.data());
        std::fs::write(&own, "a.example\n").unwrap();
        // This node: 1 KiB per list (so 4 KiB for one simulation), a list of its own allowed
        // 2 KiB, and a list file of its own.
        configure(
            &n,
            toml::from_str(&format!(
                "[filter]\nmax_list_bytes = \"1KiB\"\ncompile_memory = \"64MiB\"\nmax_regexes = 3\n\
                 [[list]]\nname = \"big\"\nurl = \"https://lists.example.com/big.txt\"\nmax_bytes = \"2KiB\"\n\
                 [[list]]\nname = \"own\"\npath = \"{own}\"\nkind = \"allow\"\n"
            ))
            .unwrap(),
        );
        let server = Catcher::new("a.example\n".repeat(10).into_bytes(), true);
        let list = |name: &str| serde_json::json!({ "name": name, "url": format!("{}/{name}.txt", server.url) });
        let mut big = list("big");
        big["max_bytes"] = "64MiB".into();
        let own_file =
            |name: &str| serde_json::json!({ "name": name, "path": own, "kind": "allow" });
        let by_url: Vec<serde_json::Value> = (1..=5).map(|i| list(&format!("l{i}"))).collect();
        let over = [
            (
                "five lists by URL",
                serde_json::json!({ "list": by_url }),
                "at most 4 lists",
            ),
            (
                "three by URL and this node's list file twice",
                serde_json::json!({ "list": [list("l1"), list("l2"), list("l3"), own_file("f1"), own_file("f2")] }),
                "at most 4 lists",
            ),
            (
                "this node's 2 KiB list at a new address, and three more",
                serde_json::json!({ "list": [big, list("l1"), list("l2"), list("l3")] }),
                "4KiB",
            ),
        ];
        for (who, creds) in [("viewer", &n.viewer), ("admin", &n.admin)] {
            for (what, candidate, limit) in &over {
                let (s, v) = simulate(&n, creds, candidate.clone()).await;
                assert_eq!(server.saw(), Vec::<String>::new(), "{who}, {what}: {v}");
                assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{who}, {what}: {v}");
                assert!(
                    v["detail"].as_str().unwrap_or("").contains(limit),
                    "{who}, {what}: the limit is named: {v}"
                );
            }
        }
        // Within it, as before: two lists, then the 2 KiB list and two more (4 KiB).
        for (what, candidate, fetched) in [
            (
                "two lists",
                serde_json::json!({ "list": [list("l1"), list("l2")] }),
                2,
            ),
            (
                "4 KiB",
                serde_json::json!({ "list": [big, list("l1"), list("l2")] }),
                5,
            ),
        ] {
            let (s, v) = simulate(&n, &n.viewer, candidate).await;
            assert_eq!(s, StatusCode::OK, "{what}: {v}");
            assert_eq!(server.saw().len(), fetched, "{what}: {:?}", server.saw());
        }
        // The side snapshot is compiled under this node's limits, whatever the candidate says.
        let running = n.src.config.load_full();
        let candidate: telltale_config::Config =
            toml::from_str("[filter]\ncompile_memory = \"1GiB\"\nmax_regexes = 0\n").unwrap();
        let c = crate::simulate::with_this_nodes_downloads(&running, &candidate);
        assert_eq!(
            (c.filter.compile_memory, c.filter.max_regexes),
            (running.filter.compile_memory, running.filter.max_regexes)
        );
    });
}

/// REQ: OBS-024 (ADR-180) — a dry run's simulation past what one simulation fetches on this node
/// isn't run (`download_limit`), before anything is fetched; the dry run itself answers as before.
/// Here a list of this node's own allowed 8 KiB, 8 times its 1 KiB cap.
#[test]
fn obs_024_a_dry_run_simulation_past_the_fetch_limit_isnt_run() {
    holding_the_slot(async {
        let n = Node::new(telltale_config::Config::default());
        configure(
            &n,
            toml::from_str(
                "[filter]\nmax_list_bytes = \"1KiB\"\n\
                 [[list]]\nname = \"big\"\nurl = \"https://lists.example.com/big.txt\"\nmax_bytes = \"8KiB\"\n",
            )
            .unwrap(),
        );
        let server = Catcher::new(b"a.example\n".to_vec(), true);
        let body =
            serde_json::json!({ "url": format!("{}/big.txt", server.url), "max_bytes": "8KiB" });
        let uri = "/api/v1/lists/big?dryRun=true&simulate=true";
        let (s, v) = while_busy(&n, "PUT", uri, &n.operator, &body).await;
        assert_eq!(server.saw(), Vec::<String>::new(), "{v}");
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["applied"], false, "{v}");
        assert_eq!(v["simulation"]["available"], false, "{v}");
        assert_eq!(v["simulation"]["reason"], "download_limit", "{v}");
    });
}

/// Runs `test` on a runtime of its own while no other test that may take the node's one simulation
/// slot runs (the slot is a static, and `simulate::tests` need it free).
fn holding_the_slot(test: impl std::future::Future<Output = ()>) {
    let _one = crate::simulate::slot_tests();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(test);
}

/// REQ: OBS-024 (ADR-180) — the node's one simulation at a time covers its downloads too: while
/// one simulation is fetching a list, another is refused as busy before it fetches anything.
#[test]
fn obs_024_one_simulation_at_a_time_includes_its_downloads() {
    holding_the_slot(one_at_a_time_includes_downloads());
}

async fn one_at_a_time_includes_downloads() {
    let n = Node::new(telltale_config::Config::default());
    let server = Catcher::new(b"a.example\n".to_vec(), false);
    let candidate = |name: &str| serde_json::json!({ "config": { "list": [{ "name": name, "url": format!("{}/{name}.txt", server.url) }] } });
    let first = n.send(
        "POST",
        "/api/v1/simulate",
        &n.viewer,
        Some(candidate("first")),
    );
    let second = async {
        // The first is fetching its list (held at the server).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !server.saw().iter().any(|p| p == "/first.txt") {
            assert!(
                std::time::Instant::now() < deadline,
                "the first simulation never fetched"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            n.send(
                "POST",
                "/api/v1/simulate",
                &n.viewer,
                Some(candidate("second")),
            ),
        )
        .await;
        let saw = server.saw();
        server.open();
        (r, saw)
    };
    let ((s1, v1), (r2, saw)) = tokio::join!(first, second);
    assert!(
        !saw.iter().any(|p| p == "/second.txt"),
        "the second simulation fetched while the first ran: {saw:?}"
    );
    let (s2, v2) = r2.expect("the second simulation answered at once");
    assert_eq!(s2, StatusCode::CONFLICT, "{v2}");
    assert_eq!(v2["code"], "simulation_busy", "{v2}");
    assert_eq!(s1, StatusCode::OK, "{v1}");
}

/// REQ: FLT-004 (ADR-180) — a list is a local file because it has a `path`, whatever that path
/// looks like: one written `inline` or like a URL still gets the generic reason below admin.
#[tokio::test]
async fn flt_004_a_list_file_named_like_a_url_is_still_a_local_file() {
    use telltale_filter::fetch::{
        Client, FetchSettings, Fetcher, ListSpec, Outcome, Store, SystemResolver,
    };
    let n = Node::new(telltale_config::Config::default());
    // Relative paths that exist nowhere: reading them fails, and the error names them.
    let cfg: telltale_config::Config = toml::from_str(
        "[[list]]\nname = \"plain\"\npath = \"inline\"\n\
         [[list]]\nname = \"urlish\"\npath = \"https://lists.example.com/not-a-download.txt\"\n",
    )
    .unwrap();
    configure(&n, cfg.clone());
    let fetcher = Arc::new(Fetcher::new(
        Store::open(&std::path::Path::new(&n.data()).join("lists")).unwrap(),
        Client::new(Arc::new(SystemResolver), &[]).unwrap(),
        FetchSettings::from_config(&cfg),
    ));
    for spec in ListSpec::from_config(&cfg) {
        assert!(matches!(
            fetcher.refresh_one(&spec).await,
            Outcome::Failed(_)
        ));
    }
    n.src.lists.store(Some(Arc::new(crate::lists::ListsShared {
        fetcher,
        compiled: std::sync::Mutex::new(None),
    })));
    let (_, v) = n.send("GET", "/api/v1/lists", &n.viewer, None).await;
    for name in ["plain", "urlish"] {
        let e = error_of(&v, name).unwrap_or_default();
        assert!(
            e.contains("administrator") && !e.contains("os error"),
            "{name}: {v}"
        );
    }
    let (_, v) = n.send("GET", "/api/v1/lists", &n.admin, None).await;
    assert!(
        error_of(&v, "urlish")
            .unwrap_or_default()
            .contains("os error"),
        "{v}"
    );
}
