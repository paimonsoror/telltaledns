// REQ: OBS-010, API-002 (ADR-179) — credential files (`token_file`, `password_file`) on alert
// destinations made through the API, driven through the real routes, sign-in and backend: only an
// administrator sets or changes a destination that names one, the file must be in a place meant
// for secrets, and a destination stored otherwise isn't used.

use std::io::{Read as _, Write as _};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use telltale_api::auth::{self, Auth, Role};
use tower::ServiceExt as _;

use super::*;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// One node with a state database, an admin, an operator, and agent tokens.
struct Node {
    src: Arc<Sources>,
    app: axum::Router,
    auth: Arc<Auth>,
    /// Bearer tokens.
    admin: String,
    operator: String,
    /// Agent tokens with `config:write:alerts`: an operator's, and an admin's.
    agent: String,
    admin_agent: String,
    dir: tempfile::TempDir,
}

fn token(auth: &Auth, user: i64, scope: &str, agent_scopes: Option<&str>) -> String {
    let (id, secret) = (auth::crypto::random_id(), auth::crypto::random_secret());
    auth.state()
        .create_token(
            &id,
            user,
            "tests",
            &auth::crypto::secret_hash(&secret),
            scope,
            None,
            now(),
        )
        .unwrap();
    if let Some(s) = agent_scopes {
        auth.state().set_token_agent(&id, s, None, None).unwrap();
    }
    format!("tt_{id}_{secret}")
}

/// A node whose data directory is a fresh temporary directory. Applying a change rebuilds the
/// running configuration from the files and `state.db`, as the main loop does.
fn node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let mut s = crate::http::tests::sources_in(dir.path());
    let mut file = telltale_config::Config::default();
    file.node.data_dir = telltale_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
    s.file_config = arc_swap::ArcSwap::from_pointee(file.clone());
    s.config = arc_swap::ArcSwap::from_pointee(file);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<bool>>(4);
    s.reload = tx;
    let state = Arc::new(telltale_store::state::State::open(&dir.path().join("state.db")).unwrap());
    let auth = Arc::new(Auth::new(state, auth::Settings::default()));
    let src = Arc::new(s);
    let _ = src.auth.set(Arc::clone(&auth));
    let applier = Arc::clone(&src);
    tokio::spawn(async move {
        while let Some(done) = rx.recv().await {
            apply(&applier);
            let _ = done.send(true);
        }
    });
    let root = auth
        .create_user("root", "correct horse battery", Role::Admin, false, now())
        .unwrap();
    let olga = auth
        .create_user("olga", "an operator password", Role::Operator, false, now())
        .unwrap();
    let admin = token(&auth, root.id, "admin", None);
    let operator = token(&auth, olga.id, "write", None);
    let agent = token(&auth, olga.id, "write", Some("config:write:alerts"));
    let admin_agent = token(&auth, root.id, "write", Some("config:write:alerts"));
    let app = telltale_api::router(
        Arc::new(ApiBackend {
            src: Arc::clone(&src),
        }),
        Arc::clone(&auth),
    );
    Node {
        src,
        app,
        auth,
        admin,
        operator,
        agent,
        admin_agent,
        dir,
    }
}

/// The running configuration from the files and `state.db`.
fn apply(src: &Sources) {
    let file = src.file_config.load_full();
    if let Some(a) = src.auth.get()
        && let Ok(c) = crate::managed::merge(&file, &crate::managed::entries(a.state()))
    {
        src.config.store(Arc::new(c));
    }
}

impl Node {
    fn data(&self) -> String {
        self.dir.path().to_str().unwrap().to_owned()
    }

    async fn send(
        &self,
        method: &str,
        uri: &str,
        bearer: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {bearer}"))
            // Agents say why (AGT-005); people may.
            .header("x-telltale-reason", "credential file tests");
        let body = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let resp = self
            .app
            .clone()
            .oneshot(req.body(body).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    async fn put(
        &self,
        name: &str,
        bearer: &str,
        dry: bool,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let uri = format!(
            "/api/v1/alerts/destinations/{name}{}",
            if dry { "?dryRun=true" } else { "" }
        );
        self.send("PUT", &uri, bearer, Some(body)).await
    }

    fn audit_text(&self) -> String {
        self.auth
            .state()
            .audit_page(None, 1000, None, None)
            .unwrap()
            .iter()
            .map(|e| [e.action.as_str(), e.target.as_str(), e.detail.as_str()].join(" "))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn ntfy(token_file: &str) -> serde_json::Value {
    serde_json::json!({ "type": "ntfy", "url": "https://ntfy.sh/home-dns", "token_file": token_file })
}

fn email(password_file: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "email", "url": "smtp://smtp.example.com:587", "from": "dns@example.com",
        "to": ["me@example.com"], "username": "dns@example.com", "password_file": password_file,
    })
}

/// REQ: OBS-010, API-002 (ADR-179) — a destination that names a credential file is set by an
/// administrator: an operator, an operator's agent token, and an admin's agent token are refused
/// (dry runs too), with a hint; an admin's own sign-in or token is not. A destination without one
/// is anyone's with the operator role.
#[tokio::test]
async fn obs_010_only_an_admin_sets_a_credential_file() {
    let n = node();
    for (who, bearer) in [
        ("operator", &n.operator),
        ("operator's agent", &n.agent),
        ("admin's agent", &n.admin_agent),
    ] {
        for (field, body) in [
            ("token_file", ntfy("/run/secrets/ntfy-token")),
            ("password_file", email("/run/secrets/smtp-password")),
        ] {
            for dry in [false, true] {
                let (s, v) = n.put("phone", bearer, dry, body.clone()).await;
                assert_eq!(s, StatusCode::FORBIDDEN, "{who} {field} dry={dry}: {v}");
                assert_eq!(v["code"], "forbidden", "{v}");
                assert!(
                    v["detail"].as_str().unwrap_or("").contains(field),
                    "{who}: the refusal names the field: {v}"
                );
                assert!(
                    v["hint"]
                        .as_str()
                        .unwrap_or("")
                        .contains("needs an administrator"),
                    "{v}"
                );
            }
        }
    }
    assert!(
        crate::managed::entries(n.auth.state())
            .alert_destinations
            .is_empty(),
        "nothing was stored"
    );
    // Without a credential file, an operator and an operator's agent may.
    let plain = serde_json::json!({ "type": "webhook", "url": "https://hooks.example.com/dns" });
    for bearer in [&n.operator, &n.agent] {
        let (s, v) = n.put("hook", bearer, true, plain.clone()).await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    let (s, v) = n.put("hook", &n.operator, false, plain).await;
    assert_eq!(
        (s, v["applied"].as_bool()),
        (StatusCode::OK, Some(true)),
        "{v}"
    );
    // An admin may, dry run or not.
    let (s, v) = n
        .put("phone", &n.admin, true, ntfy("/run/secrets/ntfy-token"))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = n
        .put("phone", &n.admin, false, ntfy("/run/secrets/ntfy-token"))
        .await;
    assert_eq!(
        (s, v["applied"].as_bool()),
        (StatusCode::OK, Some(true)),
        "{v}"
    );
    let (s, v) = n
        .put(
            "inbox",
            &n.admin,
            false,
            email("/run/secrets/smtp-password"),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// REQ: OBS-010, API-002 (ADR-179) — a destination that already names a credential file is an
/// administrator's to change, whatever the change (its address, its account, or leaving the file
/// out); an operator may still delete it, and keeps every destination without one.
#[tokio::test]
async fn obs_010_only_an_admin_changes_a_destination_with_a_credential_file() {
    let n = node();
    for (name, body) in [
        ("phone", ntfy("/run/secrets/ntfy-token")),
        ("inbox", email("/run/secrets/smtp-password")),
    ] {
        let (s, v) = n.put(name, &n.admin, false, body).await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    let (s, _) = n
        .put(
            "hook",
            &n.admin,
            false,
            serde_json::json!({ "type": "webhook", "url": "https://hooks.example.com/a" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let mut moved = ntfy("/run/secrets/ntfy-token");
    moved["url"] = "https://ntfy.example.net/elsewhere".into();
    let mut no_file = ntfy("/run/secrets/ntfy-token");
    no_file.as_object_mut().unwrap().remove("token_file");
    no_file["url"] = "https://ntfy.example.net/elsewhere".into();
    let mut account = email("/run/secrets/smtp-password");
    account["username"] = "someone@example.com".into();
    for (bearer, who) in [(&n.operator, "operator"), (&n.agent, "agent")] {
        for (name, body, what) in [
            ("phone", moved.clone(), "a new address"),
            ("phone", no_file.clone(), "the file left out"),
            ("inbox", account.clone(), "a new account"),
        ] {
            for dry in [true, false] {
                let (s, v) = n.put(name, bearer, dry, body.clone()).await;
                assert_eq!(s, StatusCode::FORBIDDEN, "{who}, {what}, dry={dry}: {v}");
                assert!(
                    v["hint"]
                        .as_str()
                        .unwrap_or("")
                        .contains("needs an administrator"),
                    "{v}"
                );
            }
        }
    }
    // Nothing moved.
    let stored = crate::managed::entries(n.auth.state()).alert_destinations;
    let phone = stored
        .iter()
        .find_map(|(k, o)| match o {
            crate::managed::Ovr::Set(d) if k == "phone" => Some(d.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(phone.url.as_str(), "https://ntfy.sh/home-dns");
    // A destination without a credential file is an operator's to change.
    let (s, v) = n
        .put(
            "hook",
            &n.operator,
            false,
            serde_json::json!({ "type": "webhook", "url": "https://hooks.example.com/b" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // Deleting only takes something away: an operator may.
    for name in ["phone", "inbox"] {
        let (s, v) = n
            .send(
                "DELETE",
                &format!("/api/v1/alerts/destinations/{name}"),
                &n.operator,
                None,
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{name}: {v}");
    }
    // The admin changes a destination with a credential file as before.
    let (s, v) = n
        .put("phone", &n.admin, false, ntfy("/run/secrets/ntfy-token"))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = n.put("phone", &n.admin, false, moved).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// REQ: OBS-010, API-002 (ADR-179) — an API-set credential file is an absolute path under
/// `/run/secrets/`, `/etc/telltale-secrets/` or `<data_dir>/secrets/`, compared by path
/// components after normalisation, and not the Kubernetes service-account mount. Anything else is
/// a 422 that names the field and the places; a file that doesn't exist yet is fine.
#[tokio::test]
async fn obs_010_credential_files_must_be_in_a_place_for_secrets() {
    let n = node();
    let d = n.data();
    std::fs::write(format!("{d}/outside"), "not a secret").unwrap();
    let refused = [
        "/etc/shadow".to_owned(),
        "/proc/self/environ".to_owned(),
        format!("{d}/state.db"),
        format!("{d}/outside"),
        format!("{d}/secrets/../state.db"),
        format!("{d}/secrets/./x/../../state.db"),
        format!("{d}/secrets"),
        format!("{d}/secretsx/token"),
        "/run/secrets/../etc/passwd".to_owned(),
        "/run/secrets-evil/x".to_owned(),
        "/run/secretsx".to_owned(),
        "/run/secrets".to_owned(),
        "/run/secrets/".to_owned(),
        "/run/secrets/kubernetes.io/serviceaccount/token".to_owned(),
        "/var/run/secrets/kubernetes.io/serviceaccount/token".to_owned(),
        "/etc/telltale-secrets".to_owned(),
        "relative/token".to_owned(),
        "secrets/token".to_owned(),
        String::new(),
        "/run/secrets/a\u{0}b".to_owned(),
    ];
    for p in &refused {
        for (field, body) in [("token_file", ntfy(p)), ("password_file", email(p))] {
            let (s, v) = n.put("phone", &n.admin, true, body).await;
            assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{field} = {p:?}: {v}");
            // A control character is refused by the schema already, before this rule.
            if !p.contains('\u{0}') {
                let detail = v["detail"].as_str().unwrap_or("");
                assert!(detail.contains(field), "{p:?}: {v}");
                assert!(
                    detail.contains("/run/secrets/") && detail.contains("/etc/telltale-secrets/"),
                    "{p:?}: the places are named: {v}"
                );
            }
        }
    }
    for p in [
        "/run/secrets/ntfy-token".to_owned(),
        "/run/secrets/telltale/ntfy".to_owned(),
        "/etc/telltale-secrets/ntfy/token".to_owned(),
        format!("{d}/secrets/ntfy-token"),
    ] {
        for body in [ntfy(&p), email(&p)] {
            let (s, v) = n.put("phone", &n.admin, true, body).await;
            assert_eq!(s, StatusCode::OK, "{p}: {v}");
        }
    }
    // Saved for real, and refused for real: nothing is stored.
    let (s, _) = n.put("phone", &n.admin, false, ntfy("/etc/shadow")).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        crate::managed::entries(n.auth.state())
            .alert_destinations
            .is_empty(),
        "a refused write stores nothing"
    );
    let (s, v) = n
        .put(
            "phone",
            &n.admin,
            false,
            ntfy(&format!("{d}/secrets/ntfy-token")),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// REQ: OBS-010 (ADR-179) — the place is checked on the file itself: a link inside a secrets
/// folder that leads out of it (to a file, or through a linked folder, even to a file that isn't
/// there yet) is refused; the links a Kubernetes Secret mount is made of, which stay inside, are
/// not.
#[cfg(unix)]
#[tokio::test]
async fn obs_010_a_link_that_leaves_a_secrets_folder_is_refused() {
    use std::os::unix::fs::symlink;
    let n = node();
    let d = n.data();
    let secrets = format!("{d}/secrets");
    // A Secret mount: `<key> -> ..data/<key>`, `..data -> ..<timestamp>`.
    std::fs::create_dir_all(format!("{secrets}/..2026_11_19_00_00_00.1")).unwrap();
    std::fs::write(
        format!("{secrets}/..2026_11_19_00_00_00.1/ntfy-token"),
        "tk",
    )
    .unwrap();
    symlink("..2026_11_19_00_00_00.1", format!("{secrets}/..data")).unwrap();
    symlink("..data/ntfy-token", format!("{secrets}/ntfy-token")).unwrap();
    std::fs::create_dir_all(format!("{d}/elsewhere")).unwrap();
    std::fs::write(format!("{d}/elsewhere/file"), "x").unwrap();
    symlink(format!("{d}/state.db"), format!("{secrets}/state")).unwrap();
    symlink(format!("{d}/elsewhere"), format!("{secrets}/folder")).unwrap();
    symlink(format!("{d}/nothing-here"), format!("{secrets}/dangling")).unwrap();
    for ok in [
        format!("{secrets}/ntfy-token"),
        format!("{secrets}/..data/ntfy-token"),
    ] {
        let (s, v) = n.put("phone", &n.admin, true, ntfy(&ok)).await;
        assert_eq!(s, StatusCode::OK, "{ok}: {v}");
    }
    for bad in [
        format!("{secrets}/state"),
        format!("{secrets}/folder/file"),
        format!("{secrets}/folder/not-yet"),
        format!("{secrets}/dangling"),
    ] {
        let (s, v) = n.put("phone", &n.admin, true, ntfy(&bad)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {v}");
    }
}

/// A plain HTTP server that answers 200 and keeps every request it got (head and body).
struct Catcher {
    url: String,
    got: Arc<Mutex<Vec<String>>>,
}

fn catcher() -> Catcher {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let got = Arc::new(Mutex::new(Vec::new()));
    let keep = Arc::clone(&got);
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut c) = conn else { continue };
            let _ = c.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            // The head, then as much body as `content-length` says.
            while let Ok(k) = c.read(&mut chunk) {
                if k == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..k]);
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some(end) = text.find("\r\n\r\n") {
                    let len = text[..end]
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse::<usize>().ok())?
                        })
                        .unwrap_or(0);
                    if buf.len() >= end + 4 + len {
                        break;
                    }
                }
            }
            keep.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf).to_string());
            let _ =
                c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        }
    });
    Catcher { url, got }
}

/// REQ: OBS-010 (ADR-179) — at use time: a destination made through the API whose credential
/// file isn't in a place for secrets (stored by an older version, replicated, or restored) isn't
/// used. Its test send reads nothing, sends nothing, and says why. A destination from the config
/// files with the same file still sends.
#[tokio::test]
async fn obs_010_a_stored_destination_outside_the_secrets_folders_is_not_used() {
    let n = node();
    let d = n.data();
    let server = catcher();
    let marker = format!("marker-{}", auth::crypto::random_id());
    std::fs::create_dir_all(format!("{d}/outside/folder")).unwrap();
    std::fs::write(format!("{d}/outside/token"), &marker).unwrap();
    // The files' destination.
    let mut file = (*n.src.file_config.load_full()).clone();
    file.alerts.destination.push(
        serde_json::from_value(serde_json::json!({
            "name": "from-file", "type": "ntfy", "url": format!("{}/file-topic", server.url),
            "token_file": format!("{d}/outside/token"),
        }))
        .unwrap(),
    );
    n.src.file_config.store(Arc::new(file));
    // Destinations stored as an older version would have stored them.
    for (name, token_file) in [
        ("from-api", format!("{d}/outside/token")),
        ("from-api-folder", format!("{d}/outside/folder")),
    ] {
        let body = serde_json::json!({
            "name": name, "type": "ntfy", "url": format!("{}/api-topic", server.url),
            "token_file": token_file,
        });
        n.auth
            .state()
            .put_managed(
                crate::managed::ALERT_DESTINATION,
                name,
                &body.to_string(),
                None,
                None,
                now(),
                "an older version",
            )
            .unwrap();
    }
    apply(&n.src);
    let names: Vec<String> = n
        .src
        .config
        .load()
        .alerts
        .destination
        .iter()
        .map(|d| d.name.to_string())
        .collect();
    assert_eq!(names.len(), 3, "{names:?}");
    for name in ["from-api", "from-api-folder"] {
        let (s, v) = n
            .send(
                "POST",
                &format!("/api/v1/alerts/destinations/{name}/test"),
                &n.admin,
                None,
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["ok"], false, "{name}: {v}");
        let why = v["error"].as_str().unwrap_or("");
        assert!(
            why.contains("token_file") && why.contains("/run/secrets/"),
            "{name}: says why, not what reading the file did: {v}"
        );
        assert!(!why.contains(&marker), "{v}");
    }
    assert!(
        server
            .got
            .lock()
            .unwrap()
            .iter()
            .all(|r| !r.contains("/api-topic")),
        "nothing went to the API destinations' address"
    );
    let (s, v) = n
        .send(
            "POST",
            "/api/v1/alerts/destinations/from-file/test",
            &n.admin,
            None,
        )
        .await;
    assert_eq!((s, v["ok"].as_bool()), (StatusCode::OK, Some(true)), "{v}");
    let got = server.got.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "{got:?}");
    assert!(got[0].contains("/file-topic"), "{got:?}");
    assert!(
        got[0].contains(&format!("Bearer {marker}")),
        "the files' destination reads its file: {got:?}"
    );
}

/// REQ: OBS-010 (ADR-179) — refusals say what the rule is and never what is in the file: the 403,
/// the 422 (the same for a file that is there and one that isn't), and the audit log after saves
/// and test sends hold no byte of it.
#[tokio::test]
async fn obs_010_refusals_and_the_audit_log_hold_no_file_content() {
    let n = node();
    let d = n.data();
    let server = catcher();
    let marker = format!("marker-{}", auth::crypto::random_id());
    std::fs::create_dir_all(format!("{d}/secrets")).unwrap();
    std::fs::write(format!("{d}/outside-token"), &marker).unwrap();
    std::fs::write(format!("{d}/secrets/ntfy-token"), &marker).unwrap();
    let (s, v) = n
        .put(
            "phone",
            &n.operator,
            false,
            ntfy(&format!("{d}/outside-token")),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(!v.to_string().contains(&marker), "{v}");
    let there = format!("{d}/outside-token");
    let missing = format!("{d}/outside-missing");
    let (s1, v1) = n.put("phone", &n.admin, false, ntfy(&there)).await;
    let (s2, v2) = n.put("phone", &n.admin, true, ntfy(&missing)).await;
    assert_eq!(
        (s1, s2),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            StatusCode::UNPROCESSABLE_ENTITY
        )
    );
    assert!(!v1.to_string().contains(&marker), "{v1}");
    assert_eq!(
        v1.to_string().replace(&there, "P"),
        v2.to_string().replace(&missing, "P"),
        "a file that is there and one that isn't are refused alike"
    );
    // Saved where it belongs, then sent: the audit log has the path, never the content.
    let mut body = ntfy(&format!("{d}/secrets/ntfy-token"));
    body["url"] = format!("{}/topic", server.url).into();
    let (s, v) = n.put("phone", &n.admin, false, body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = n
        .send(
            "POST",
            "/api/v1/alerts/destinations/phone/test",
            &n.admin,
            None,
        )
        .await;
    assert_eq!((s, v["ok"].as_bool()), (StatusCode::OK, Some(true)), "{v}");
    assert!(
        server.got.lock().unwrap()[0].contains(&format!("Bearer {marker}")),
        "it was sent"
    );
    let audit = n.audit_text();
    assert!(audit.contains("alert_destination.put"), "{audit}");
    assert!(audit.contains("alert.test"), "{audit}");
    assert!(!audit.contains(&marker), "{audit}");
}

// ---- Review round 1: where a destination comes from, as a node that follows another sees it.

/// An ntfy destination whose token is `token_file`, sent to `url`.
fn ntfy_dest(name: &str, url: &str, token_file: &str) -> telltale_config::AlertDestination {
    serde_json::from_value(serde_json::json!({
        "name": name, "type": "ntfy", "url": url, "token_file": token_file,
    }))
    .unwrap()
}

/// The configuration a node runs when its shared sections come from another node (a replica,
/// or a primary promoted from one or pinned to a version): its own files plus `primary`'s
/// shared part, as replication merges them.
fn following(n: &Node, primary: &telltale_config::Config) {
    let file = n.src.file_config.load_full();
    let shared = telltale_config::shared::shared_part(primary);
    let c = telltale_config::shared::with_shared(&file, &shared).unwrap();
    n.src.config.store(Arc::new(c));
}

impl Node {
    async fn test_send(&self, name: &str) -> serde_json::Value {
        let (s, v) = self
            .send(
                "POST",
                &format!("/api/v1/alerts/destinations/{name}/test"),
                &self.admin,
                None,
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{name}: {v}");
        v
    }
}

/// REQ: OBS-010 (ADR-179) — a node whose shared sections come from another node holds every
/// destination with a credential file to the folder rule unless its own config files define it
/// the same way: one an older primary stored through the API is neither read nor sent to from
/// here, and neither is a primary's file destination that this node's files don't have (the
/// cost). One its own files define the same way (one `ConfigMap` for every pod) still sends,
/// whatever its path.
#[tokio::test]
async fn obs_010_a_replica_does_not_send_an_unchecked_destination() {
    let n = node();
    let d = n.data();
    let server = catcher();
    let marker = format!("marker-{}", auth::crypto::random_id());
    std::fs::create_dir_all(format!("{d}/outside")).unwrap();
    std::fs::write(format!("{d}/outside/token"), &marker).unwrap();
    let token = format!("{d}/outside/token");
    let at = |topic: &str| format!("{}/{topic}", server.url);
    let mut file = (*n.src.file_config.load_full()).clone();
    file.alerts
        .destination
        .push(ntfy_dest("same", &at("same"), &token));
    n.src.file_config.store(Arc::new(file.clone()));
    let mut primary = file;
    primary.alerts.destination = vec![
        ntfy_dest("same", &at("same"), &token),
        ntfy_dest("legacy", &at("legacy"), &token),
        ntfy_dest("theirs", &at("theirs"), &token),
    ];
    following(&n, &primary);
    for name in ["legacy", "theirs"] {
        let v = n.test_send(name).await;
        assert_eq!(v["ok"], false, "{name}: {v}");
        assert!(
            v["error"].as_str().unwrap_or("").contains("token_file"),
            "{name}: {v}"
        );
    }
    let v = n.test_send("same").await;
    assert_eq!(v["ok"], true, "{v}");
    let got = server.got.lock().unwrap().clone();
    assert_eq!(
        got.len(),
        1,
        "only the node's own destination was sent to: {got:?}"
    );
    assert!(
        got[0].contains("/same") && got[0].contains(&format!("Bearer {marker}")),
        "{got:?}"
    );
}

/// REQ: OBS-010 (ADR-179) — the alert task of a primary whose configuration came from another
/// node (promoted after a failover, or pinned to a version) doesn't send to a destination with
/// a credential file outside the folders that its own files don't define; the Alerts page says
/// why, and a destination without one goes out as usual. Driven through `alerts::run`.
#[tokio::test]
async fn obs_010_a_promoted_primary_does_not_send_an_unchecked_destination() {
    let n = node();
    let d = n.data();
    let server = catcher();
    std::fs::create_dir_all(format!("{d}/outside")).unwrap();
    std::fs::write(format!("{d}/outside/token"), "tk").unwrap();
    let mut primary = (*n.src.file_config.load_full()).clone();
    primary.alerts.destination = vec![
        ntfy_dest(
            "legacy",
            &format!("{}/legacy", server.url),
            &format!("{d}/outside/token"),
        ),
        serde_json::from_value(serde_json::json!({
            "name": "plain", "type": "webhook", "url": format!("{}/plain", server.url),
        }))
        .unwrap(),
    ];
    primary.alerts.rule = vec![
        serde_json::from_value(serde_json::json!({
            "name": "Update", "when": "update_available", "for_secs": 0, "to": ["legacy", "plain"],
        }))
        .unwrap(),
    ];
    following(&n, &primary);
    {
        let mut u = n.src.update.lock().unwrap();
        u.state = "available".into();
        u.latest = Some("99.0.0".into());
    }
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(crate::alerts::run(Arc::clone(&n.src), stopped));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let deliveries = loop {
        let got = n.src.alerts.lock().unwrap().deliveries.clone();
        if ["legacy", "plain"]
            .iter()
            .all(|w| got.iter().any(|x| x.destination == *w))
        {
            break got;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no deliveries: {got:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    let _ = stop.send(true);
    let _ = task.await;
    let of = |w: &str| deliveries.iter().find(|x| x.destination == w).unwrap();
    assert!(!of("legacy").ok, "{deliveries:?}");
    assert!(
        of("legacy")
            .error
            .as_deref()
            .unwrap_or("")
            .contains("token_file"),
        "{deliveries:?}"
    );
    assert!(of("plain").ok, "{deliveries:?}");
    let got = server.got.lock().unwrap().clone();
    assert!(got.iter().all(|r| !r.contains("/legacy")), "{got:?}");
    assert!(got.iter().any(|r| r.contains("/plain")), "{got:?}");
}

/// REQ: OBS-010 (ADR-179) — a destination made through the API that overrides a config-file
/// destination of the same name isn't the files': it is held to the folder rule.
#[tokio::test]
async fn obs_010_an_api_override_of_a_file_destination_is_held() {
    let n = node();
    let d = n.data();
    let server = catcher();
    std::fs::create_dir_all(format!("{d}/outside")).unwrap();
    std::fs::write(format!("{d}/outside/token"), "tk").unwrap();
    let token = format!("{d}/outside/token");
    let mut file = (*n.src.file_config.load_full()).clone();
    file.alerts.destination.push(ntfy_dest(
        "phone",
        &format!("{}/file-topic", server.url),
        &token,
    ));
    n.src.file_config.store(Arc::new(file));
    let over = ntfy_dest("phone", &format!("{}/api-topic", server.url), &token);
    n.auth
        .state()
        .put_managed(
            crate::managed::ALERT_DESTINATION,
            "phone",
            &serde_json::to_string(&over).unwrap(),
            None,
            None,
            now(),
            "an older version",
        )
        .unwrap();
    apply(&n.src);
    let v = n.test_send("phone").await;
    assert_eq!(v["ok"], false, "{v}");
    assert!(server.got.lock().unwrap().is_empty(), "nothing was sent");
}

/// REQ: OBS-010 (ADR-179) — on a node that takes the cluster's configuration from Git, the commit
/// in use is the node's own too: a destination it defines sends, whatever its path.
#[tokio::test]
async fn obs_010_a_git_commits_destination_counts_as_the_nodes_own() {
    let n = node();
    let d = n.data();
    let server = catcher();
    std::fs::create_dir_all(format!("{d}/outside")).unwrap();
    std::fs::write(format!("{d}/outside/token"), "tk").unwrap();
    let mut file = (*n.src.file_config.load_full()).clone();
    file.cluster.git = Some(
        serde_json::from_value(serde_json::json!({
            "repo": "https://git.example.test/homelab", "path": "telltale/shared.toml",
        }))
        .unwrap(),
    );
    n.src.file_config.store(Arc::new(file));
    let dir = telltale_cluster::node::dir_of(n.dir.path());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("git-shared.toml"),
        format!(
            "[[alerts.destination]]\nname = \"phone\"\ntype = \"ntfy\"\nurl = \"{}/git\"\ntoken_file = \"{d}/outside/token\"\n",
            server.url
        ),
    )
    .unwrap();
    let file = n.src.file_config.load_full();
    let shared = crate::gitsource::shared(&file).unwrap();
    n.src.config.store(Arc::new(
        telltale_config::shared::with_shared(&file, &shared).unwrap(),
    ));
    let v = n.test_send("phone").await;
    assert_eq!(v["ok"], true, "{v}");
    assert!(server.got.lock().unwrap()[0].contains("/git"));
}

/// REQ: OBS-010, API-002 (ADR-179) — an operator can't override a config-file destination that
/// names a credential file (whatever the new body says), but may hide it; an admin may override
/// it with a file in a folder.
#[tokio::test]
async fn obs_010_an_operator_cannot_override_a_file_destination_with_a_credential_file() {
    let n = node();
    let mut file = (*n.src.file_config.load_full()).clone();
    file.alerts.destination.push(ntfy_dest(
        "phone",
        "https://ntfy.sh/home-dns",
        "/run/secrets/ntfy-token",
    ));
    n.src.file_config.store(Arc::new(file));
    apply(&n.src);
    let mut moved = ntfy("/run/secrets/ntfy-token");
    moved["url"] = "https://ntfy.example.net/elsewhere".into();
    let mut bare = moved.clone();
    bare.as_object_mut().unwrap().remove("token_file");
    for body in [moved.clone(), bare] {
        for bearer in [&n.operator, &n.agent] {
            let (s, v) = n.put("phone", bearer, true, body.clone()).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{body}: {v}");
        }
    }
    let (s, v) = n.put("phone", &n.admin, true, moved).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = n
        .send(
            "DELETE",
            "/api/v1/alerts/destinations/phone?dryRun=true",
            &n.operator,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "hiding it takes something away: {v}");
}

/// REQ: OBS-010, API-002 (ADR-179) — a write forwarded from another node is planned on this
/// node (the primary) with the same rule: without the entry node's word that an administrator
/// made it, a destination with a credential file is refused and nothing is stored; with it, the
/// write is planned like a local administrator's.
#[tokio::test]
async fn obs_010_a_forwarded_write_from_a_non_admin_is_refused() {
    let n = node();
    let local: telltale_api::Shared = Arc::new(ApiBackend {
        src: Arc::clone(&n.src),
    });
    let write = |by_admin: bool, dry_run: bool| crate::forward::Write::Managed {
        kind: ManagedKind::AlertDestination,
        name: "phone".into(),
        body: Some(ntfy("/run/secrets/ntfy-token")),
        dry_run,
        expect: None,
        by: "olga".into(),
        simulate: None,
        by_admin,
    };
    for dry_run in [false, true] {
        let a =
            crate::forward::apply(&n.src, &local, "node-b", "site-b", write(false, dry_run)).await;
        let a = serde_json::to_value(a).unwrap();
        assert_eq!(a["err"]["code"], "forbidden", "dry_run={dry_run}: {a}");
    }
    assert!(
        crate::managed::entries(n.auth.state())
            .alert_destinations
            .is_empty(),
        "nothing was stored"
    );
    assert!(
        !n.audit_text().contains("alert_destination.put"),
        "a refused write isn't audited as a change"
    );
    let a = crate::forward::apply(&n.src, &local, "node-b", "site-b", write(true, true)).await;
    let a = serde_json::to_value(a).unwrap();
    assert_eq!(a["ok"]["applied"], false, "planned as a dry run: {a}");
}

/// REQ: OBS-010 — a webhook or Slack destination never uses a token, so it doesn't read
/// `token_file`: one whose file isn't there still sends.
#[tokio::test]
async fn obs_010_a_webhook_does_not_read_a_token_file() {
    let n = node();
    let d = n.data();
    let server = catcher();
    let mut file = (*n.src.file_config.load_full()).clone();
    for (name, kind) in [("hook", "webhook"), ("chat", "slack")] {
        file.alerts.destination.push(
            serde_json::from_value(serde_json::json!({
                "name": name, "type": kind, "url": format!("{}/{name}", server.url),
                "token_file": format!("{d}/not-there"),
            }))
            .unwrap(),
        );
    }
    n.src.file_config.store(Arc::new(file));
    apply(&n.src);
    for name in ["hook", "chat"] {
        let v = n.test_send(name).await;
        assert_eq!(v["ok"], true, "{name}: {v}");
    }
    assert_eq!(server.got.lock().unwrap().len(), 2);
}

/// REQ: OBS-010 (ADR-179) — if a node can't read its config files at start-up, it runs on the
/// configuration it has, which then stands in for its files. That configuration holds entries
/// made through the API too, so nothing in it counts as the node's own: every destination with a
/// credential file is held to the folder rule until a reload reads the files.
#[tokio::test]
async fn obs_010_without_its_files_a_node_holds_every_credential_file() {
    let n = node();
    let d = n.data();
    let server = catcher();
    std::fs::create_dir_all(format!("{d}/outside")).unwrap();
    std::fs::write(format!("{d}/outside/token"), "tk").unwrap();
    let api = ntfy_dest(
        "api",
        &format!("{}/api", server.url),
        &format!("{d}/outside/token"),
    );
    n.auth
        .state()
        .put_managed(
            crate::managed::ALERT_DESTINATION,
            "api",
            &serde_json::to_string(&api).unwrap(),
            None,
            None,
            now(),
            "an older version",
        )
        .unwrap();
    apply(&n.src);
    // Start-up, with the files unreadable since the configuration was made from them.
    let broken = n.dir.path().join("broken.toml");
    std::fs::write(&broken, "[node\n").unwrap();
    let (files, unread) = crate::server::files_at_start(&[broken], &n.src.config.load());
    assert!(unread);
    assert_eq!(
        files,
        **n.src.config.load(),
        "the running configuration stands in"
    );
    n.src.file_config.store(Arc::new(files));
    n.src
        .files_unread
        .store(unread, std::sync::atomic::Ordering::Release);
    let v = n.test_send("api").await;
    assert_eq!(v["ok"], false, "{v}");
    assert!(server.got.lock().unwrap().is_empty(), "nothing was sent");
}
