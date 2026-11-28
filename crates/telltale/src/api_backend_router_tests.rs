// REQ: T8.2, API-002 (ADR-181) — routers made through the API and the UI, with keys pasted and
// saved as files on the node that took the write, driven through the real routes, sign-in and
// backend. The router consoles here are loopback fakes; nothing leaves the machine.

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

/// How a caller signs in: the headers it sends.
type Creds = Vec<(&'static str, String)>;

fn bearer(t: &str) -> Creds {
    vec![("authorization", format!("Bearer {t}"))]
}

fn token(auth: &Auth, user: i64, scope: &str, agent_scopes: Option<&str>) -> Creds {
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
        // Stored as given: a token an earlier build made may hold a scope this one doesn't offer.
        auth.state().set_token_agent(&id, s, None, None).unwrap();
    }
    bearer(&format!("tt_{id}_{secret}"))
}

/// The running configuration from the files and `state.db`, as a reload builds it.
fn apply(src: &Sources) {
    let file = src.file_config.load_full();
    if let Some(a) = src.auth.get()
        && let Ok(c) = crate::managed::merge(&file, &crate::managed::entries(a.state()))
    {
        src.config.store(Arc::new(c));
    }
}

/// What the test's reload does when a write asks for one.
enum Reload {
    /// Applies the change (the files plus `state.db`), as the main loop does.
    Applies,
    /// Answers that it couldn't apply it.
    Fails,
    /// Says on `asked` that a reload was asked for, then waits for `go` before applying.
    Gated {
        asked: tokio::sync::mpsc::UnboundedSender<()>,
        go: Arc<tokio::sync::Notify>,
    },
}

/// One node with a state database and callers of every kind.
struct Node {
    src: Arc<Sources>,
    app: axum::Router,
    auth: Arc<Auth>,
    /// An admin's API token, and the same admin's signed-in session.
    admin: Creds,
    admin_session: Creds,
    operator: Creds,
    viewer: Creds,
    /// Agent tokens: an operator's with every write area, and an admin's with the scope an
    /// earlier build gave routers (and `cluster:admin`).
    operator_agent: Creds,
    admin_agent: Creds,
    /// A viewer's agent token with the default scopes.
    viewer_agent: Creds,
    dir: tempfile::TempDir,
}

impl Node {
    fn new(reload: Reload) -> Self {
        Self::with(reload, |_, _| {})
    }

    /// [`Node::new`], with `f` changing the sources first (given the data directory).
    fn with(reload: Reload, f: impl FnOnce(&Path, &mut Sources)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut s = crate::http::tests::sources_in(dir.path());
        let mut file = telltale_config::Config::default();
        file.node.data_dir =
            telltale_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
        s.file_config = arc_swap::ArcSwap::from_pointee(file.clone());
        s.config = arc_swap::ArcSwap::from_pointee(file);
        // The folders a platform fills with secrets (`/run/secrets/`, `/etc/telltale-secrets/`)
        // have a stand-in in test builds: `<data_dir>/mount` (`secret_path::mount_roots_for`).
        f(dir.path(), &mut s);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<bool>>(4);
        s.reload = tx;
        let state =
            Arc::new(telltale_store::state::State::open(&dir.path().join("state.db")).unwrap());
        let auth = Arc::new(Auth::new(state, auth::Settings::default()));
        let src = Arc::new(s);
        let _ = src.auth.set(Arc::clone(&auth));
        let applier = Arc::clone(&src);
        tokio::spawn(async move {
            while let Some(done) = rx.recv().await {
                match &reload {
                    Reload::Applies => {
                        apply(&applier);
                        let _ = done.send(true);
                    }
                    Reload::Fails => {
                        let _ = done.send(false);
                    }
                    Reload::Gated { asked, go } => {
                        let _ = asked.send(());
                        go.notified().await;
                        apply(&applier);
                        let _ = done.send(true);
                    }
                }
            }
        });
        let root = auth
            .create_user("root", "correct horse battery", Role::Admin, false, now())
            .unwrap();
        let olga = auth
            .create_user("olga", "an operator password", Role::Operator, false, now())
            .unwrap();
        let vic = auth
            .create_user("vic", "a viewer's password", Role::Viewer, false, now())
            .unwrap();
        let session = auth
            .start_session(&root, "127.0.0.1".parse().unwrap(), now())
            .unwrap();
        let admin_session = vec![
            (
                "cookie",
                format!("{}={}", telltale_api::auth::routes::COOKIE, session.cookie),
            ),
            ("x-csrf-token", session.csrf),
        ];
        let app = telltale_api::router(
            Arc::new(ApiBackend {
                src: Arc::clone(&src),
            }),
            Arc::clone(&auth),
        );
        let every_write = "config:write:clients config:write:records config:write:forwards config:write:rules config:write:upstreams config:write:lists config:write:alerts config:write:groups config:read";
        Self {
            admin: token(&auth, root.id, "admin", None),
            operator: token(&auth, olga.id, "write", None),
            viewer: token(&auth, vic.id, "read", None),
            operator_agent: token(&auth, olga.id, "write", Some(every_write)),
            admin_agent: token(
                &auth,
                root.id,
                "write",
                Some("config:write:routers cluster:admin config:read"),
            ),
            viewer_agent: token(&auth, vic.id, "read", Some("analytics:read config:read")),
            admin_session,
            src,
            app,
            auth,
            dir,
        }
    }

    fn request(
        method: &str,
        uri: &str,
        creds: &Creds,
        body: Option<&serde_json::Value>,
    ) -> Request<Body> {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            // Agents say why (AGT-005); people may.
            .header("x-telltale-reason", "router tests");
        for (k, v) in creds {
            req = req.header(*k, v.as_str());
        }
        let body = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        req.body(body).unwrap()
    }

    async fn send(
        &self,
        method: &str,
        uri: &str,
        creds: &Creds,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let resp = self
            .app
            .clone()
            .oneshot(Self::request(method, uri, creds, body.as_ref()))
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
        creds: &Creds,
        dry: bool,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let uri = format!(
            "/api/v1/routers/{name}{}",
            if dry { "?dryRun=true" } else { "" }
        );
        self.send("PUT", &uri, creds, Some(body)).await
    }

    /// The stored API entry for `name`.
    fn stored(&self, name: &str) -> Option<telltale_config::RouterConfig> {
        crate::managed::entries(self.auth.state())
            .routers
            .into_iter()
            .find_map(|(n, o)| match o {
                crate::managed::Ovr::Set(r) if n == name => Some(r),
                _ => None,
            })
    }

    /// Stores a router as an earlier build, a backup or a hand edit would have.
    fn store(&self, name: &str, body: &serde_json::Value) {
        self.auth
            .state()
            .put_managed(
                crate::managed::ROUTER,
                name,
                &body.to_string(),
                None,
                None,
                now(),
                "an older version",
            )
            .unwrap();
    }

    /// The routers in `GET /api/v1/config/entries?kind=router`, as `creds` sees them.
    async fn routers(&self, creds: &Creds) -> Vec<serde_json::Value> {
        let (s, v) = self
            .send("GET", "/api/v1/config/entries?kind=router", creds, None)
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v["items"].as_array().cloned().unwrap_or_default()
    }

    /// The key file the stored entry for `name` names.
    fn key_file(&self, name: &str) -> Option<String> {
        self.stored(name)
            .and_then(|r| r.api_key_file.map(|f| f.to_string()))
    }

    fn data(&self) -> String {
        self.dir.path().to_str().unwrap().to_owned()
    }

    /// Every file under `<data_dir>/secrets/` but the API's own list.
    fn secret_files(&self) -> Vec<String> {
        let dir = self.dir.path().join("secrets");
        let mut v: Vec<String> = std::fs::read_dir(&dir)
            .map(|d| {
                d.filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| !n.starts_with(".written"))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }
}

/// A UniFi router with a pasted API key at `url`.
fn unifi(url: &str, key: &str) -> serde_json::Value {
    serde_json::json!({ "type": "unifi", "url": url, "api_key": key, "offline_days": 0 })
}

fn marker(tag: &str) -> String {
    format!("{tag}-{}", auth::crypto::random_id())
}

/// Loopback addresses nothing listens on, for tests that don't poll a router.
const HERE: &str = "http://127.0.0.1:1";
const ELSEWHERE: &str = "http://127.0.0.2:1";

/// Waits (at most `secs`) until `f` holds.
async fn wait_until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ---- T1: who may write a router.

/// REQ: T8.2, API-002 (ADR-189) — a FRITZ!Box router is the config file's: the API refuses it,
/// dry run or not, and stores nothing.
#[tokio::test]
async fn api_002_the_api_refuses_a_fritzbox_router() {
    let n = Node::new(Reload::Applies);
    let body = serde_json::json!({
        "type": "fritzbox",
        "url": "http://192.0.2.1:49000",
        "client_subnets": ["192.168.40.0/24"]
    });
    for dry in [true, false] {
        let (s, v) = n.put("box", &n.admin, dry, body.clone()).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "dry={dry}: {v}");
        assert!(v.to_string().contains("config file"), "{v}");
    }
    assert!(n.stored("box").is_none(), "nothing was stored");
}

/// REQ: API-002, T8.2 (ADR-181, as ADR-179) — a router is added, changed or removed only by an
/// administrator's own sign-in or an admin API token: an operator, a viewer, an operator's agent
/// token with every write area, and an admin's agent token holding the scope an earlier build
/// gave routers are all refused, dry run or not, PUT or DELETE, and nothing is stored or written.
#[tokio::test]
async fn api_002_only_an_admin_writes_a_router() {
    let n = Node::new(Reload::Applies);
    let body = unifi("https://192.0.2.1", "a-key");
    for (who, creds) in [
        ("operator", &n.operator),
        ("viewer", &n.viewer),
        ("operator's agent", &n.operator_agent),
        ("admin's agent", &n.admin_agent),
    ] {
        for dry in [true, false] {
            let (s, v) = n.put("udm", creds, dry, body.clone()).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{who} dry={dry}: {v}");
        }
        let (s, v) = n.send("DELETE", "/api/v1/routers/udm", creds, None).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{who} DELETE: {v}");
    }
    assert!(n.stored("udm").is_none(), "nothing was stored");
    assert!(n.secret_files().is_empty(), "{:?}", n.secret_files());
    // An administrator's session and token may.
    let (s, v) = n.put("udm", &n.admin_session, true, body.clone()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = n.put("udm", &n.admin, false, body).await;
    assert_eq!(
        (s, v["applied"].as_bool()),
        (StatusCode::OK, Some(true)),
        "{v}"
    );
    // An admin's agent token can't change one that is there, even without a key in the body,
    // nor remove it.
    let (s, v) = n
        .put(
            "udm",
            &n.admin_agent,
            false,
            serde_json::json!({"type": "unifi", "url": "https://192.0.2.1", "offline_days": 0, "interval_secs": 60}),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, v) = n
        .send("DELETE", "/api/v1/routers/udm", &n.admin_agent, None)
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(n.stored("udm").is_some());
    let (s, v) = n
        .send("DELETE", "/api/v1/routers/udm", &n.admin_session, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// REQ: API-002, T8.2 (ADR-181, as ADR-179) — a router write forwarded from another node is
/// planned on this node (the primary) with the same rule: without the entry node's word that an
/// administrator made it (a write from a node that doesn't say is not one), it is refused, dry run
/// or not, PUT or DELETE, and nothing is stored or written; with it, it is planned and applied.
#[tokio::test]
async fn api_002_a_forwarded_router_write_needs_an_admin() {
    let n = Node::new(Reload::Applies);
    let local: telltale_api::Shared = Arc::new(ApiBackend {
        src: Arc::clone(&n.src),
    });
    let write = |by_admin: bool, dry_run: bool, body: Option<serde_json::Value>| {
        crate::forward::Write::Managed {
            kind: ManagedKind::Router,
            name: "udm".into(),
            body,
            dry_run,
            expect: None,
            by: "olga".into(),
            simulate: None,
            by_admin,
        }
    };
    for dry_run in [false, true] {
        for body in [Some(unifi("https://192.0.2.1", "a-key")), None] {
            let a = crate::forward::apply(
                &n.src,
                &local,
                "node-b",
                "site-b",
                write(false, dry_run, body),
            )
            .await;
            let a = serde_json::to_value(a).unwrap();
            assert_eq!(a["err"]["code"], "forbidden", "dry_run={dry_run}: {a}");
        }
    }
    assert!(n.stored("udm").is_none(), "nothing was stored");
    assert!(n.secret_files().is_empty(), "{:?}", n.secret_files());
    let a = crate::forward::apply(
        &n.src,
        &local,
        "node-b",
        "site-b",
        write(true, true, Some(unifi("https://192.0.2.1", "a-key"))),
    )
    .await;
    let a = serde_json::to_value(a).unwrap();
    assert_eq!(a["ok"]["applied"], false, "planned as a dry run: {a}");
    let a = crate::forward::apply(
        &n.src,
        &local,
        "node-b",
        "site-b",
        write(true, false, Some(unifi("https://192.0.2.1", "a-key"))),
    )
    .await;
    let a = serde_json::to_value(a).unwrap();
    assert_eq!(a["ok"]["applied"], true, "{a}");
}

// ---- T2: a body carries a key, never a path.

/// REQ: API-002, T8.2 (ADR-181) — F2: a router can't name another router's key file (here with
/// another address) and so have the node send that key there. Refused with 422 and a hint to
/// paste the key, dry run or not; nothing is stored.
#[tokio::test]
async fn api_002_router_cannot_name_another_routers_key() {
    let n = Node::new(Reload::Applies);
    let (s, v) = n
        .put("udm", &n.admin, false, unifi(HERE, &marker("udm-key")))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let udm_file = n.key_file("udm").unwrap();
    for dry in [true, false] {
        let (s, v) = n
            .put(
                "evil",
                &n.admin,
                dry,
                serde_json::json!({"type": "unifi", "url": ELSEWHERE, "api_key_file": udm_file, "offline_days": 0}),
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "dry={dry}: {v}");
        assert!(
            v["hint"].as_str().unwrap_or("").contains("Paste the key"),
            "{v}"
        );
    }
    assert!(n.stored("evil").is_none(), "nothing was stored");
}

/// REQ: API-002, T8.2 (ADR-181) — every key-file field in an API body is refused unless it is the
/// file the router already has and its endpoint is unchanged: `..`, a path outside the data
/// directory, a relative path, a link inside `secrets/`, a file someone put in `secrets/`, and
/// another router's file, for each of `api_key_file`, `api_secret_file` and `password_file`; and
/// the router's own file with a new address. Keeping the router's own file at the same address,
/// or leaving it out, is fine.
#[tokio::test]
async fn api_002_router_credential_paths_are_refused() {
    let n = Node::new(Reload::Applies);
    let d = n.data();
    let (s, v) = n
        .put("udm", &n.admin, false, unifi(HERE, &marker("udm-key")))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = n
        .put("nas", &n.admin, false, unifi(HERE, &marker("nas-key")))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let udm_file = n.key_file("udm").unwrap();
    let other_routers_file = n.key_file("nas").unwrap();
    std::fs::write(format!("{d}/secrets/mine"), "someone's file").unwrap();
    let mut paths = vec![
        format!("{d}/secrets/../state.db"),
        "/etc/passwd".to_owned(),
        "secrets/mine".to_owned(),
        format!("{d}/secrets/mine"),
        other_routers_file.clone(),
    ];
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&other_routers_file, format!("{d}/secrets/link")).unwrap();
        paths.push(format!("{d}/secrets/link"));
    }
    let bodies = |p: &str| {
        [
            serde_json::json!({"type": "unifi", "url": HERE, "api_key_file": p, "offline_days": 0}),
            serde_json::json!({"type": "opnsense", "url": HERE, "api_key": "k", "api_secret_file": p}),
            serde_json::json!({"type": "unifi", "url": HERE, "username": "telltale", "password_file": p, "offline_days": 0}),
        ]
    };
    for p in &paths {
        for b in bodies(p) {
            for name in ["udm", "fresh"] {
                let (s, v) = n.put(name, &n.admin, true, b.clone()).await;
                assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{name} {b}: {v}");
                assert!(
                    v["hint"].as_str().unwrap_or("").contains("Paste the key"),
                    "{name} {b}: {v}"
                );
            }
        }
    }
    // The router's own file, at a new address.
    let (s, v) = n
        .put(
            "udm",
            &n.admin,
            true,
            serde_json::json!({"type": "unifi", "url": ELSEWHERE, "api_key_file": udm_file, "offline_days": 0}),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    // Its own file at the same address, or none named: kept.
    for b in [
        serde_json::json!({"type": "unifi", "url": HERE, "api_key_file": udm_file, "offline_days": 0, "interval_secs": 60}),
        serde_json::json!({"type": "unifi", "url": HERE, "offline_days": 0, "interval_secs": 90}),
    ] {
        let (s, v) = n.put("udm", &n.admin, false, b.clone()).await;
        assert_eq!(s, StatusCode::OK, "{b}: {v}");
        assert_eq!(n.key_file("udm").as_deref(), Some(udm_file.as_str()));
    }
    assert!(n.stored("fresh").is_none());
}

// ---- T7 (a): a pasted key goes over https.

/// REQ: API-002, T8.2 (ADR-181) — a key pasted through the API goes to a router reached over
/// `https://` or a loopback address; `http://` to anything else (`localhost` included: a name can
/// be made to resolve elsewhere) is refused with 422 and a hint. Dry runs only: nothing is polled.
#[tokio::test]
async fn api_002_a_pasted_key_goes_only_over_https() {
    let n = Node::new(Reload::Applies);
    for url in [
        "http://192.168.1.1",
        "http://unifi.example.test:8443",
        "http://localhost:8080",
    ] {
        let (s, v) = n.put("udm", &n.admin, true, unifi(url, "k")).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{url}: {v}");
        assert!(
            v["detail"].as_str().unwrap_or("").contains("https://"),
            "{url}: {v}"
        );
    }
    for url in [
        "https://192.0.2.1",
        "https://unifi.example.test:8443",
        "http://127.0.0.1:1",
        "http://127.0.0.2:1",
        "http://[::1]:1",
    ] {
        let (s, v) = n.put("udm", &n.admin, true, unifi(url, "k")).await;
        assert_eq!(s, StatusCode::OK, "{url}: {v}");
    }
}

// ---- T4: a saved key is kept.

/// REQ: API-002, T8.2 (ADR-181) — F3: once the entry naming a new key file is stored, the file is
/// kept even when the reload then fails: the stored entry never names a file that was removed.
#[tokio::test]
async fn api_002_router_key_kept_when_saved_but_not_applied() {
    let n = Node::new(Reload::Fails);
    let (s, v) = n.put("udm", &n.admin, false, unifi(HERE, "the-key")).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    assert!(
        v["detail"]
            .as_str()
            .unwrap_or("")
            .contains("saved but couldn't be applied"),
        "{v}"
    );
    let f = n.key_file("udm").expect("the entry is stored");
    assert_eq!(
        std::fs::read_to_string(&f).ok().as_deref().map(str::trim),
        Some("the-key"),
        "the file the stored entry names is there: {f}"
    );
}

/// REQ: API-002, API-006, T8.2 (ADR-181) — F3: a client that goes away after the change is
/// stored doesn't undo it half way: the key file stays, the change is still applied, audited, and
/// kept for the Idempotency-Key, so the client's retry gets the first answer rather than a
/// second change.
#[tokio::test]
async fn api_002_router_key_kept_when_the_client_goes_away() {
    let (asked, mut reload_asked) = tokio::sync::mpsc::unbounded_channel();
    let go = Arc::new(tokio::sync::Notify::new());
    let n = Node::new(Reload::Gated {
        asked,
        go: Arc::clone(&go),
    });
    let mut creds = n.admin.clone();
    creds.push(("idempotency-key", marker("retry")));
    let req = Node::request(
        "PUT",
        "/api/v1/routers/udm",
        &creds,
        Some(&unifi(HERE, "the-key")),
    );
    let app = n.app.clone();
    let client = tokio::spawn(async move { app.oneshot(req).await });
    // The change is stored and its reload asked for: the client goes away.
    reload_asked.recv().await.unwrap();
    client.abort();
    let _ = client.await;
    let f = n.key_file("udm").expect("the entry is stored");
    assert!(Path::new(&f).exists(), "the key stays: {f}");
    go.notify_one();
    wait_until("the change applied", 10, || {
        n.src
            .config
            .load()
            .router
            .iter()
            .any(|r| r.name.as_str() == "udm")
    })
    .await;
    assert_eq!(
        std::fs::read_to_string(&f).ok().as_deref().map(str::trim),
        Some("the-key")
    );
    // Audited, though nobody waited for the answer.
    wait_until("the change audited", 10, || {
        n.auth
            .state()
            .audit_page(None, 100, None, None)
            .unwrap()
            .iter()
            .any(|e| e.action == "router.put" && e.target == "udm")
    })
    .await;
    // The retry with the same Idempotency-Key replays the first answer: no second file.
    go.notify_one();
    let (s, v) = n
        .send(
            "PUT",
            "/api/v1/routers/udm",
            &creds,
            Some(unifi(HERE, "the-key")),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(n.key_file("udm").as_deref(), Some(f.as_str()), "replayed");
}

/// REQ: API-002, API-006, AGT-003 (ADR-181) — the same for a change of another kind (an
/// upstream): every change that isn't a dry run runs to its end with its audit entry and its
/// Idempotency-Key record, whether or not the client waits.
#[tokio::test]
async fn api_002_any_change_is_audited_when_the_client_goes_away() {
    let (asked, mut reload_asked) = tokio::sync::mpsc::unbounded_channel();
    let go = Arc::new(tokio::sync::Notify::new());
    let n = Node::new(Reload::Gated {
        asked,
        go: Arc::clone(&go),
    });
    let mut creds = n.admin.clone();
    creds.push(("idempotency-key", marker("retry")));
    let body = serde_json::json!({"url": "udp://192.0.2.53"});
    let req = Node::request("PUT", "/api/v1/upstreams/up", &creds, Some(&body));
    let app = n.app.clone();
    let client = tokio::spawn(async move { app.oneshot(req).await });
    reload_asked.recv().await.unwrap();
    client.abort();
    let _ = client.await;
    go.notify_one();
    wait_until("the upstream change audited", 10, || {
        n.auth
            .state()
            .audit_page(None, 100, None, None)
            .unwrap()
            .iter()
            .any(|e| e.action == "upstream.put" && e.target == "up")
    })
    .await;
    // The retry replays the first answer: no second change (a second one would wait for a reload
    // nobody lets go).
    let (s, v) = tokio::time::timeout(
        Duration::from_secs(10),
        n.send("PUT", "/api/v1/upstreams/up", &creds, Some(body)),
    )
    .await
    .expect("replayed, not made again");
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        reload_asked.try_recv().is_err(),
        "no second reload asked for"
    );
}

/// A UniFi console on loopback. It answers `stat/sta` for any site with one device, and keeps,
/// for every request, the site and the API key it came with.
struct Console {
    url: String,
    asked: Arc<Mutex<Vec<(String, String)>>>,
}

impl Console {
    fn sites(&self) -> Vec<String> {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .map(|(s, _)| s.clone())
            .collect()
    }

    fn key_for(&self, site: &str) -> Option<String> {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .find(|(s, _)| s == site)
            .map(|(_, k)| k.clone())
    }
}

fn console() -> Console {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let asked = Arc::new(Mutex::new(Vec::new()));
    let keep = Arc::clone(&asked);
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut c) = conn else { continue };
            let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            while !String::from_utf8_lossy(&buf).contains("\r\n\r\n") {
                match c.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(k) => buf.extend_from_slice(&chunk[..k]),
                }
            }
            let head = String::from_utf8_lossy(&buf).to_string();
            let path = head.split_whitespace().nth(1).unwrap_or("").to_owned();
            let key = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.trim()
                        .eq_ignore_ascii_case("x-api-key")
                        .then(|| v.trim().to_owned())
                })
                .unwrap_or_default();
            let site = path
                .strip_prefix("/proxy/network/api/s/")
                .and_then(|r| r.strip_suffix("/stat/sta"))
                .unwrap_or("")
                .to_owned();
            keep.lock().unwrap().push((site.clone(), key));
            let body = serde_json::json!({"meta": {"rc": "ok"}, "data": [
                {"mac": "02:00:00:00:07:01", "ip": "192.168.7.20", "name": format!("{site} device")}
            ]})
            .to_string();
            let _ = write!(
                c,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    Console { url, asked }
}

/// The router task, polling the routers in effect until the returned sender says stop.
fn poll(
    n: &Node,
) -> (
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let view = Arc::new(arc_swap::ArcSwap::from_pointee(
        crate::devices::Leases::new(),
    ));
    let task = tokio::spawn(crate::routers::run(
        Arc::clone(&n.src),
        view,
        stopped,
        false,
    ));
    (stop, task)
}

// ---- T3: what a node polls with.

/// REQ: API-002, T8.2 (ADR-181) — at use time, a router in effect that names a key file is polled
/// only if this node's own config files define it with that file for the same endpoint, or the
/// file is one this node wrote for that router (`.written`) under its `secrets/`. A stored entry
/// that names another router's key (with another site), or a file outside `secrets/`, isn't
/// polled; the files' router, a stored override of it that keeps its file and endpoint, and a
/// router with its own pasted key are.
#[tokio::test]
async fn api_002_a_stored_router_naming_another_routers_key_is_not_polled() {
    let n = Node::new(Reload::Applies);
    let d = n.data();
    let fake = console();
    let udm_key = marker("udm-key");
    let (s, v) = n
        .put("udm", &n.admin, false, unifi(&fake.url, &udm_key))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let udm_file = n.key_file("udm").unwrap();
    std::fs::create_dir_all(format!("{d}/outside")).unwrap();
    for (f, k) in [
        ("key", "outside-key"),
        ("key2", "file-key"),
        ("key3", "override-key"),
    ] {
        std::fs::write(format!("{d}/outside/{f}"), k).unwrap();
    }
    // The files' routers.
    let mut file = (*n.src.file_config.load_full()).clone();
    for (name, site, key) in [
        ("c-file", "file", "key2"),
        ("d-override", "override", "key3"),
    ] {
        file.router.push(
            serde_json::from_value(serde_json::json!({
                "name": name, "type": "unifi", "url": fake.url, "site": site,
                "api_key_file": format!("{d}/outside/{key}"), "offline_days": 0,
            }))
            .unwrap(),
        );
    }
    n.src.file_config.store(Arc::new(file));
    // An override of a files' router that keeps its file and endpoint, and entries stored as an
    // earlier build, a backup or a hand edit could have.
    n.store(
        "d-override",
        &serde_json::json!({"name": "d-override", "type": "unifi", "url": fake.url, "site": "override",
            "api_key_file": format!("{d}/outside/key3"), "offline_days": 0, "interval_secs": 60}),
    );
    n.store(
        "a-evil",
        &serde_json::json!({"name": "a-evil", "type": "unifi", "url": fake.url, "site": "evil",
            "api_key_file": udm_file, "offline_days": 0}),
    );
    n.store(
        "b-outside",
        &serde_json::json!({"name": "b-outside", "type": "unifi", "url": fake.url, "site": "outside",
            "api_key_file": format!("{d}/outside/key"), "offline_days": 0}),
    );
    apply(&n.src);
    let order: Vec<String> = n
        .src
        .config
        .load()
        .router
        .iter()
        .map(|r| r.name.to_string())
        .collect();
    // Review round 4 (final review M2): the stored entry naming a key file outside secrets/ that
    // the files don't vouch for is left out where the entries are merged (it was held at use
    // time before); the other held one comes before the last one polled.
    assert_eq!(
        order,
        ["c-file", "a-evil", "d-override", "udm"],
        "b-outside left out; the held one comes before the last one polled"
    );
    let (stop, task) = poll(&n);
    wait_until("udm, the files' router and the override polled", 20, || {
        let s = fake.sites();
        ["default", "file", "override"]
            .iter()
            .all(|w| s.iter().any(|x| x == w))
    })
    .await;
    let _ = stop.send(true);
    let _ = task.await;
    let sites = fake.sites();
    assert!(
        !sites.iter().any(|s| s == "evil" || s == "outside"),
        "the held routers weren't polled: {:?}",
        fake.asked.lock().unwrap()
    );
    assert_eq!(fake.key_for("default").as_deref(), Some(udm_key.as_str()));
    assert_eq!(fake.key_for("file").as_deref(), Some("file-key"));
    assert_eq!(fake.key_for("override").as_deref(), Some("override-key"));
    // Through the API too: an administrator's override of the files' router that keeps its file
    // (outside secrets/) and its endpoint is accepted, since it is what the node uses already.
    let (s, v) = n
        .put(
            "c-file",
            &n.admin,
            true,
            serde_json::json!({"type": "unifi", "url": fake.url, "site": "file",
                "api_key_file": format!("{d}/outside/key2"), "offline_days": 0, "interval_secs": 60}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

// ---- Decision 1: the status needs no secret to read.

/// REQ: API-002, T8.2 (ADR-181) — a router's credentials have a status anyone who may read the
/// configuration sees, read without the secret: `saved`, `missing` once the file is gone (after a
/// restore elsewhere, or a failover: enter it again), and `not_used` for a stored entry naming a
/// file this node won't send for it. Entering the key again makes it `saved`.
#[tokio::test]
async fn api_002_a_router_whose_key_file_is_gone_says_key_missing() {
    let n = Node::new(Reload::Applies);
    let (s, v) = n.put("udm", &n.admin, false, unifi(HERE, "k1")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let status = |items: &[serde_json::Value], name: &str| {
        items
            .iter()
            .find(|e| e["name"] == name)
            .map(|e| e["credentials"]["api_key"].clone())
            .unwrap_or_default()
    };
    for creds in [&n.admin, &n.viewer] {
        assert_eq!(status(&n.routers(creds).await, "udm"), "saved");
    }
    let f = n.key_file("udm").unwrap();
    std::fs::remove_file(&f).unwrap();
    for creds in [&n.admin, &n.viewer] {
        assert_eq!(status(&n.routers(creds).await, "udm"), "missing");
    }
    let (s, v) = n.put("udm", &n.admin, false, unifi(HERE, "k2")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    n.store(
        "a-evil",
        &serde_json::json!({"name": "a-evil", "type": "unifi", "url": HERE, "site": "evil",
            "api_key_file": n.key_file("udm").unwrap(), "offline_days": 0}),
    );
    apply(&n.src);
    let items = n.routers(&n.viewer).await;
    assert_eq!(status(&items, "udm"), "saved");
    assert_eq!(status(&items, "a-evil"), "not_used");
}

// ---- T5: the sweep.

/// REQ: API-002, T8.2 (ADR-181) — F5: each node removes the key files it wrote that nothing names
/// any more: at start (an entry gone without the API: a crash before the prune, a restored
/// `state.db`), and after a change (a replica whose primary now names another file). Never a file
/// the API didn't write, and never one outside `<data_dir>/secrets/`.
#[tokio::test]
async fn api_002_orphaned_router_key_files_removed() {
    let n = Node::new(Reload::Applies);
    let d = n.data();
    let fake = console();
    for (name, key) in [("udm", "k1"), ("tmp", "k2")] {
        let (s, v) = n.put(name, &n.admin, false, unifi(&fake.url, key)).await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    let (udm_file, tmp_file) = (n.key_file("udm").unwrap(), n.key_file("tmp").unwrap());
    // `tmp` goes without the API: its key file is an orphan.
    n.auth
        .state()
        .delete_managed(crate::managed::ROUTER, "tmp", None)
        .unwrap();
    apply(&n.src);
    // A file the API didn't write, and a record (as this version keeps them) for a file outside
    // secrets/.
    std::fs::write(format!("{d}/secrets/mine"), "keep").unwrap();
    std::fs::write(format!("{d}/outside-file"), "keep").unwrap();
    let mut written = std::fs::OpenOptions::new()
        .append(true)
        .open(format!("{d}/secrets/.written"))
        .unwrap();
    writeln!(
        written,
        "{}",
        serde_json::json!({"router": "tmp", "field": "api_key", "file": format!("{d}/outside-file")})
    )
    .unwrap();
    drop(written);
    let (stop, task) = poll(&n);
    wait_until("the orphan removed at start", 20, || {
        !Path::new(&tmp_file).exists()
    })
    .await;
    assert!(Path::new(&udm_file).exists(), "udm's key is named");
    let _ = stop.send(true);
    let _ = task.await;
    // The routers in effect stop naming udm's file (a replica, after the key was entered again on
    // the primary), and this node's own stored entry doesn't name it either: the sweep the task
    // runs after such a change, called here directly.
    let mut cfg = (*n.src.config.load_full()).clone();
    if let Some(r) = cfg.router.iter_mut().find(|r| r.name.as_str() == "udm") {
        r.api_key_file =
            Some(telltale_config::SafeString::new(format!("{d}/secrets/elsewhere")).unwrap());
    }
    n.auth
        .state()
        .delete_managed(crate::managed::ROUTER, "udm", None)
        .unwrap();
    n.src.config.store(Arc::new(cfg));
    let gone = crate::router_secrets::sweep_now(&n.src).unwrap();
    assert_eq!(gone.len(), 1, "{gone:?}");
    assert!(!Path::new(&udm_file).exists());
    assert!(Path::new(&format!("{d}/secrets/mine")).exists());
    assert!(Path::new(&format!("{d}/outside-file")).exists());
}

/// REQ: API-002, T8.2 (ADR-181) — the sweep keeps a file the API wrote while this node's own stored
/// entry still names it, though the configuration in effect doesn't (a reload that fell back to
/// the config files, a pinned version, a primary that was demoted and may be promoted again).
#[tokio::test]
async fn api_002_a_key_its_own_stored_entry_names_is_kept() {
    let n = Node::new(Reload::Applies);
    let fake = console();
    for (name, key) in [("udm", "k1"), ("tmp", "k2")] {
        let (s, v) = n.put(name, &n.admin, false, unifi(&fake.url, key)).await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    let (udm_file, tmp_file) = (n.key_file("udm").unwrap(), n.key_file("tmp").unwrap());
    // The configuration in effect is the files' alone; `tmp` is gone from state.db.
    n.auth
        .state()
        .delete_managed(crate::managed::ROUTER, "tmp", None)
        .unwrap();
    n.src.config.store(n.src.file_config.load_full());
    let (stop, task) = poll(&n);
    wait_until("the orphan removed", 20, || !Path::new(&tmp_file).exists()).await;
    let _ = stop.send(true);
    let _ = task.await;
    assert!(Path::new(&udm_file).exists(), "named by the stored entry");
}

// ---- T6: what a caller below admin sees.

/// REQ: API-002, T8.2 (ADR-181) — F7: only an administrator (own sign-in or admin API token) sees
/// a router's key-file paths and `username`; a viewer, an operator, an agent token with the
/// default scopes, an operator's and an admin's agent tokens see the definition without them, with
/// the credentials' status. Routers from the files and from the API alike, by kind or not, and
/// through an MCP resource read (which calls the same route with the caller's credentials).
#[tokio::test]
async fn api_002_router_definitions_redacted_for_viewers() {
    let n = Node::new(Reload::Applies);
    let d = n.data();
    let (s, v) = n.put("udm", &n.admin, false, unifi(HERE, "k1")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let mut file = (*n.src.file_config.load_full()).clone();
    file.router.push(
        serde_json::from_value(serde_json::json!({
            "name": "fw", "type": "opnsense", "url": "https://opnsense.example.test",
            "api_key_file": format!("{d}/fw.key"), "api_secret_file": format!("{d}/fw.secret"),
        }))
        .unwrap(),
    );
    file.router.push(
        serde_json::from_value(serde_json::json!({
            "name": "ctl", "type": "unifi", "url": "https://unifi.example.test",
            "username": "telltale-reader", "password_file": format!("{d}/ctl.pass"),
        }))
        .unwrap(),
    );
    n.src.file_config.store(Arc::new(file));
    apply(&n.src);
    let hidden = [
        "api_key_file",
        "api_secret_file",
        "password_file",
        "username",
    ];
    for (who, creds) in [
        ("viewer", &n.viewer),
        ("operator", &n.operator),
        ("default agent", &n.viewer_agent),
        ("operator's agent", &n.operator_agent),
        ("admin's agent", &n.admin_agent),
    ] {
        for uri in [
            "/api/v1/config/entries?kind=router",
            "/api/v1/config/entries",
        ] {
            let (s, v) = n.send("GET", uri, creds, None).await;
            assert_eq!(s, StatusCode::OK, "{who} {uri}: {v}");
            let routers: Vec<&serde_json::Value> = v["items"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|e| e["kind"] == "router")
                .collect();
            assert_eq!(routers.len(), 3, "{who} {uri}: {v}");
            for e in routers {
                for f in hidden {
                    assert!(
                        e["definition"].get(f).is_none(),
                        "{who} {uri} sees {f}: {e}"
                    );
                }
                assert!(e["definition"]["url"].is_string(), "{e}");
                assert!(
                    e["credentials"].is_object(),
                    "{who}: the status is there: {e}"
                );
            }
            assert!(!v.to_string().contains("telltale-reader"), "{who}: {v}");
            assert!(!v.to_string().contains("/secrets/router-"), "{who}: {v}");
        }
    }
    // An MCP resource read, as an agent.
    for creds in [&n.viewer_agent, &n.admin_agent] {
        let (s, v) = n
            .send(
                "POST",
                "/mcp",
                creds,
                Some(
                    serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "resources/read",
                    "params": {"uri": "telltale://config"}}),
                ),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let text = v["result"]["contents"][0]["text"].as_str().unwrap_or("");
        assert!(
            text.contains("opnsense.example.test"),
            "the routers are there: {v}"
        );
        assert!(
            !text.contains("telltale-reader")
                && !text.contains("/secrets/router-")
                && !text.contains("fw.secret"),
            "{text}"
        );
    }
    for creds in [&n.admin, &n.admin_session] {
        let items = n.routers(creds).await;
        let of = |name: &str| items.iter().find(|e| e["name"] == name).unwrap().clone();
        assert!(of("udm")["definition"]["api_key_file"].is_string());
        assert!(of("fw")["definition"]["api_secret_file"].is_string());
        assert_eq!(of("ctl")["definition"]["username"], "telltale-reader");
    }
}

// ---- Review round 1.

/// The `credentials` status of `name`'s `api_key` in `items`.
fn key_status(items: &[serde_json::Value], name: &str) -> serde_json::Value {
    items
        .iter()
        .find(|e| e["name"] == name)
        .map(|e| e["credentials"]["api_key"].clone())
        .unwrap_or_default()
}

/// REQ: API-002, T8.2 (ADR-181, ADR-120) — a router the node gets only from the cluster's shared
/// configuration (a native replica, a primary promoted after a failover), with its key file in a
/// folder a platform fills with secrets (`/etc/telltale-secrets/`, `/run/secrets/`; here the test's
/// own), is polled on this node, as before the use-time rule. With its key elsewhere, or through a
/// link that leaves the folder, it is held, logged once with what to do, and its status says so.
#[tokio::test]
async fn api_002_a_shared_router_with_its_key_in_a_secrets_folder_is_polled_on_any_node() {
    use telltale_cluster::node::Role as NodeRole;
    let items = shared_router_on(None).await;
    assert_eq!(key_status(&items, "d-mounted"), "saved");
    assert_eq!(key_status(&items, "b-etc"), "not_used");
    // A native replica, and a node promoted to primary (a newer epoch): the same rule, and the
    // held router is a warning on both (review round 2, R1: a replica's page shows the primary's
    // status, so its log is where it says what it does).
    for (role, epoch, level) in [
        (NodeRole::Replica, 1, tracing::Level::WARN),
        (NodeRole::Primary, 2, tracing::Level::WARN),
    ] {
        let items = shared_router_on(Some((role, epoch, level))).await;
        assert_eq!(key_status(&items, "d-mounted"), "saved", "{role:?}");
        assert_eq!(key_status(&items, "b-etc"), "not_used", "{role:?}");
    }
}

/// [`api_002_a_shared_router_with_its_key_in_a_secrets_folder_is_polled_on_any_node`] on one
/// node: standalone, or a cluster member in `role` at `epoch` whose held routers are logged at
/// `level`. Returns each router's credential status (`name`, `credentials`).
async fn shared_router_on(
    member: Option<(telltale_cluster::node::Role, u64, tracing::Level)>,
) -> Vec<serde_json::Value> {
    let n = Node::with(Reload::Applies, |dir, s| {
        if let Some((role, epoch, _)) = member {
            let id = telltale_cluster::node::Identity::init_with(
                dir,
                "home",
                vec!["https://node.example.test:8443".into()],
                "home",
                "api",
            )
            .unwrap();
            let c = telltale_cluster::net::Cluster::new(id, "0.1.0");
            if role == telltale_cluster::node::Role::Primary {
                // Promoted: a replica first, then primary at a newer epoch.
                c.set_role(telltale_cluster::node::Role::Replica, epoch - 1)
                    .unwrap();
            }
            c.set_role(role, epoch).unwrap();
            s.cluster = Some(c);
        }
    });
    let d = n.data();
    let fake = console();
    std::fs::create_dir_all(format!("{d}/mount/unifi")).unwrap();
    std::fs::create_dir_all(format!("{d}/etc-telltale")).unwrap();
    std::fs::write(format!("{d}/mount/unifi/key"), "mounted-key").unwrap();
    std::fs::write(format!("{d}/etc-telltale/key"), "etc-key").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(format!("{d}/etc-telltale/key"), format!("{d}/mount/link")).unwrap();
    // The node's own files define no router: the routers in effect come from the cluster.
    let mut cfg = (*n.src.config.load_full()).clone();
    for (name, site, file) in [
        ("b-etc", "etc", format!("{d}/etc-telltale/key")),
        ("c-link", "link", format!("{d}/mount/link")),
        ("d-mounted", "mounted", format!("{d}/mount/unifi/key")),
    ] {
        cfg.router.push(
            serde_json::from_value(serde_json::json!({
                "name": name, "type": "unifi", "url": fake.url, "site": site,
                "api_key_file": file, "offline_days": 0,
            }))
            .unwrap(),
        );
    }
    n.src.config.store(Arc::new(cfg));
    let seen = super::local_access_tests::Seen::default();
    let _log = tracing::subscriber::set_default(seen.subscriber());
    let (stop, task) = poll(&n);
    wait_until("the router with its key in the folder polled", 20, || {
        fake.sites().iter().any(|s| s == "mounted")
    })
    .await;
    let _ = stop.send(true);
    let _ = task.await;
    assert_eq!(fake.key_for("mounted").as_deref(), Some("mounted-key"));
    assert!(
        !fake.sites().iter().any(|s| s == "etc" || s == "link"),
        "held: {:?}",
        fake.sites()
    );
    let held = seen.lines(|l| l.contains("not read on this node") && l.contains("b-etc"));
    assert_eq!(held.len(), 1, "logged once: {held:?}");
    assert!(
        held[0].contains("this node's config file") && held[0].contains("/etc/telltale-secrets/"),
        "says what to do: {held:?}"
    );
    assert_eq!(
        seen.lines(|l| l.contains("not read on this node") && l.contains("c-link"))
            .len(),
        1,
        "a link out of the folder is held"
    );
    if let Some((_, _, level)) = member {
        let at: Vec<_> = seen
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, l)| l.contains("not read on this node") && l.contains("b-etc"))
            .map(|(lv, _)| *lv)
            .collect();
        assert_eq!(at, vec![level]);
        // The status as the API reports it, read here (a member's API would ask its primary).
        let check = crate::router_secrets::UseCheck::load(&n.src);
        return n
            .src
            .config
            .load()
            .router
            .iter()
            .map(|r| serde_json::json!({"name": r.name.as_str(), "credentials": check.status(r)}))
            .collect();
    }
    n.routers(&n.viewer).await
}

/// REQ: API-002, T8.2 (ADR-181) — after a failover the router in effect comes from the last
/// version the cluster published, which is in neither this node's files nor its stored entries.
/// The UI sends the definition back with the key pasted again: the pasted key replaces whatever
/// file the body names for it (that path is never read), and goes to a new file here.
#[tokio::test]
async fn api_002_a_pasted_key_replaces_a_file_the_planned_router_lacks() {
    let n = Node::new(Reload::Applies);
    let d = n.data();
    let old = format!("{d}/old-primary/secrets/router-udm.api_key.0123456789abcdef");
    let mut cfg = (*n.src.config.load_full()).clone();
    cfg.router.push(
        serde_json::from_value(serde_json::json!({
            "name": "udm", "type": "unifi", "url": HERE, "api_key_file": old, "offline_days": 0,
        }))
        .unwrap(),
    );
    n.src.config.store(Arc::new(cfg));
    let (status, answer) = n
        .put(
            "udm",
            &n.admin,
            false,
            serde_json::json!({"type": "unifi", "url": HERE, "api_key_file": old,
                "api_key": "re-entered", "offline_days": 0}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let saved = n.key_file("udm").unwrap();
    assert!(
        saved.starts_with(&format!("{d}/secrets/router-udm.api_key.")),
        "{saved}"
    );
    assert_eq!(
        std::fs::read_to_string(&saved)
            .ok()
            .as_deref()
            .map(str::trim),
        Some("re-entered")
    );
}

/// REQ: API-002, T8.2 (ADR-181) — F3: the router task starts before the state database is open
/// (`start_http` opens it). The sweep at start then can't see the stored entries; it doesn't count
/// as done, and runs once the database is open, so a key file a crash left behind is removed.
#[tokio::test]
async fn api_002_the_start_sweep_waits_for_the_state_database() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap().to_owned();
    let mut s = crate::http::tests::sources_in(dir.path());
    let mut file = telltale_config::Config::default();
    file.node.data_dir = telltale_config::SafeString::new(&d).unwrap();
    s.file_config = arc_swap::ArcSwap::from_pointee(file.clone());
    s.config = arc_swap::ArcSwap::from_pointee(file);
    let src = Arc::new(s);
    std::fs::create_dir_all(format!("{d}/secrets")).unwrap();
    let orphan = format!("{d}/secrets/router-gone.api_key.0123456789abcdef");
    std::fs::write(&orphan, "k").unwrap();
    std::fs::write(
        format!("{d}/secrets/.written"),
        format!(
            "{}\n",
            serde_json::json!({"router": "gone", "field": "api_key", "file": orphan})
        ),
    )
    .unwrap();
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let view = Arc::new(arc_swap::ArcSwap::from_pointee(
        crate::devices::Leases::new(),
    ));
    let first = view.load_full();
    let task = tokio::spawn(crate::routers::run(
        Arc::clone(&src),
        Arc::clone(&view),
        stopped,
        false,
    ));
    wait_until("the task's first round", 10, || {
        !Arc::ptr_eq(&first, &view.load_full())
    })
    .await;
    assert!(Path::new(&orphan).exists(), "nothing removed unchecked");
    let state = Arc::new(telltale_store::state::State::open(&dir.path().join("state.db")).unwrap());
    let _ = src
        .auth
        .set(Arc::new(Auth::new(state, auth::Settings::default())));
    wait_until("the orphan removed once the database is open", 20, || {
        !Path::new(&orphan).exists()
    })
    .await;
    let _ = stop.send(true);
    let _ = task.await;
}

/// REQ: API-002, T8.2 (ADR-181) — security F1: a pasted key with an unchecked certificate goes
/// only to an address, not a host name (a local name, forward or upstream, which operators may
/// add, could change where a name resolves on a node whose resolver is TelltaleDNS). Dry runs.
#[tokio::test]
async fn api_002_an_unchecked_certificate_needs_an_address_for_a_pasted_key() {
    let n = Node::new(Reload::Applies);
    let insecure = |url: &str| {
        serde_json::json!({"type": "unifi", "url": url, "api_key": "k",
            "tls_insecure_skip_verify": true, "offline_days": 0})
    };
    for url in ["https://unifi.example.test", "https://unifi.lan:8443/"] {
        let (s, v) = n.put("udm", &n.admin, true, insecure(url)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{url}: {v}");
        assert!(
            v["hint"].as_str().unwrap_or("").contains("tls_ca"),
            "{url}: {v}"
        );
    }
    for url in [
        "https://192.0.2.1",
        "https://[2001:db8::1]:8443",
        "http://127.0.0.1:1",
    ] {
        let (s, v) = n.put("udm", &n.admin, true, insecure(url)).await;
        assert_eq!(s, StatusCode::OK, "{url}: {v}");
    }
    let (s, v) = n
        .put(
            "udm",
            &n.admin,
            true,
            unifi("https://unifi.example.test", "k"),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "a checked certificate with a name: {v}");
}

/// Every byte of this node's state database (with its write-ahead log).
fn state_bytes(n: &Node) -> Vec<u8> {
    let mut b = Vec::new();
    for f in ["state.db", "state.db-wal"] {
        if let Ok(x) = std::fs::read(n.dir.path().join(f)) {
            b.extend(x);
        }
    }
    b
}

/// REQ: API-002, AGT-003, T8.2 (ADR-181) — security F5: the request kept for an Idempotency-Key
/// holds a pasted key only as a keyed hash (with a key of this node's), not a plain one anyone
/// with `state.db` could test guesses against.
#[tokio::test]
async fn api_002_a_pasted_key_is_kept_for_a_retry_only_as_a_keyed_hash() {
    let n = Node::new(Reload::Applies);
    let key = marker("pasted");
    let mut creds = n.admin.clone();
    creds.push(("idempotency-key", marker("k")));
    let (s, v) = n
        .send(
            "PUT",
            "/api/v1/routers/udm",
            &creds,
            Some(unifi(HERE, &key)),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let plain = blake3::hash(key.as_bytes()).to_hex().to_string();
    let db = state_bytes(&n);
    assert_ne!(db.len(), 0, "state.db read");
    // Review round 2, R5(c): the record is there, with the keyed hash.
    let keyed = format!("keyed:{}", n.auth.request_digest(&key));
    assert!(
        db.windows(keyed.len()).any(|w| w == keyed.as_bytes()),
        "no idempotency record with the keyed hash"
    );
    assert!(
        !db.windows(plain.len()).any(|w| w == plain.as_bytes()),
        "a plain hash of the key is in state.db"
    );
    assert!(!db.windows(key.len()).any(|w| w == key.as_bytes()));
}

/// REQ: API-002, AGT-003, T8.2 (ADR-181) — an Idempotency-Key replays a router write: the same
/// key and body get the first answer and no second file; the same key with another pasted key
/// is another request (409).
#[tokio::test]
async fn api_002_a_router_write_replays_for_its_idempotency_key() {
    let n = Node::new(Reload::Applies);
    let mut creds = n.admin.clone();
    creds.push(("idempotency-key", marker("k")));
    let (s, first) = n
        .send(
            "PUT",
            "/api/v1/routers/udm",
            &creds,
            Some(unifi(HERE, "k1")),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{first}");
    let f = n.key_file("udm").unwrap();
    let (s, again) = n
        .send(
            "PUT",
            "/api/v1/routers/udm",
            &creds,
            Some(unifi(HERE, "k1")),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!(again, first, "the first answer");
    assert_eq!(n.key_file("udm").as_deref(), Some(f.as_str()));
    assert_eq!(n.secret_files().len(), 1, "{:?}", n.secret_files());
    let (s, other) = n
        .send(
            "PUT",
            "/api/v1/routers/udm",
            &creds,
            Some(unifi(HERE, "k2")),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{other}");
    assert_eq!(n.key_file("udm").as_deref(), Some(f.as_str()));
}

/// REQ: API-002, T8.2 (ADR-181) — security F6: a router's `site` stays in the path of the request
/// (percent-encoded), never in the host; a body whose `url` holds `{` or `}` is refused.
#[tokio::test]
async fn api_002_a_routers_site_stays_in_the_path() {
    let n = Node::new(Reload::Applies);
    let d = n.data();
    let fake = console();
    std::fs::write(format!("{d}/file-key"), "file-key").unwrap();
    let mut file = (*n.src.file_config.load_full()).clone();
    file.router.push(
        serde_json::from_value(serde_json::json!({
            "name": "site", "type": "unifi", "url": fake.url, "site": "a/b@c",
            "api_key_file": format!("{d}/file-key"), "offline_days": 0,
        }))
        .unwrap(),
    );
    n.src.file_config.store(Arc::new(file));
    apply(&n.src);
    let (stop, task) = poll(&n);
    wait_until("the router polled", 20, || !fake.sites().is_empty()).await;
    let _ = stop.send(true);
    let _ = task.await;
    assert_eq!(fake.sites()[0], "a%2Fb%40c", "{:?}", fake.sites());
    for url in ["https://{site}.example.test", "https://192.0.2.1/}"] {
        let (s, v) = n.put("x", &n.admin, true, unifi(url, "k")).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{url}: {v}");
    }
}

/// REQ: API-002, T8.2 (ADR-181) — the sweep keeps a record whose file is a link inside
/// `secrets/` that leads out, and touches neither the link nor what it leads to.
#[cfg(unix)]
#[tokio::test]
async fn api_002_the_sweep_never_follows_a_link_out() {
    let n = Node::new(Reload::Applies);
    let d = n.data();
    std::fs::create_dir_all(format!("{d}/secrets")).unwrap();
    std::fs::write(format!("{d}/precious"), "not a key").unwrap();
    std::os::unix::fs::symlink(format!("{d}/precious"), format!("{d}/secrets/link")).unwrap();
    std::fs::write(
        format!("{d}/secrets/.written"),
        format!(
            "{}\n",
            serde_json::json!({"router": "gone", "field": "api_key", "file": format!("{d}/secrets/link")})
        ),
    )
    .unwrap();
    let gone = crate::router_secrets::sweep_now(&n.src).unwrap();
    assert!(gone.is_empty(), "{gone:?}");
    assert!(Path::new(&format!("{d}/secrets/link")).exists());
    assert!(Path::new(&format!("{d}/precious")).exists());
}

/// REQ: API-002, T8.2 (ADR-181, ADR-179) — if the config files couldn't be read at start-up,
/// nothing counts as this node's own: a router whose key is outside the folders is held, while
/// one with its key in a folder for secrets is still used. A Git commit in use counts as the
/// node's own.
#[tokio::test]
async fn api_002_the_use_rule_without_files_and_with_a_git_commit() {
    let n = Node::new(Reload::Applies);
    let d = n.data();
    std::fs::create_dir_all(format!("{d}/mount")).unwrap();
    let outside = |name: &str| -> telltale_config::RouterConfig {
        serde_json::from_value(serde_json::json!({
            "name": name, "type": "unifi", "url": HERE, "api_key_file": format!("{d}/outside/key"),
        }))
        .unwrap()
    };
    let mounted: telltale_config::RouterConfig = serde_json::from_value(serde_json::json!({
        "name": "mounted", "type": "unifi", "url": HERE, "api_key_file": format!("{d}/mount/key"),
    }))
    .unwrap();
    let mut file = (*n.src.file_config.load_full()).clone();
    file.router.push(outside("own"));
    n.src.file_config.store(Arc::new(file.clone()));
    let check = || crate::router_secrets::UseCheck::load(&n.src);
    assert!(check().refused(&outside("own")).is_none());
    n.src
        .files_unread
        .store(true, std::sync::atomic::Ordering::Release);
    assert!(check().refused(&outside("own")).is_some(), "files unread");
    assert!(check().refused(&mounted).is_none(), "a folder for secrets");
    n.src
        .files_unread
        .store(false, std::sync::atomic::Ordering::Release);
    // The commit in use, on a node that takes the cluster's configuration from Git.
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
            "[[router]]\nname = \"git\"\ntype = \"unifi\"\nurl = \"{HERE}\"\napi_key_file = \"{d}/outside/key\"\n"
        ),
    )
    .unwrap();
    assert!(check().refused(&outside("git")).is_none(), "the Git commit");
    assert!(check().refused(&outside("other")).is_some());
}

// ---- Review round 2.

/// REQ: API-002, AGT-003 (ADR-181) — security N2: a retry with the same Idempotency-Key while the
/// first change still runs isn't made a second time: it gets 409 with `Retry-After`, and once the
/// first has finished, the first answer. One reload, one audit row.
#[tokio::test]
async fn api_002_a_retry_while_the_first_change_runs_is_not_made_twice() {
    let (asked, mut reload_asked) = tokio::sync::mpsc::unbounded_channel();
    let go = Arc::new(tokio::sync::Notify::new());
    let n = Node::new(Reload::Gated {
        asked,
        go: Arc::clone(&go),
    });
    let mut creds = n.admin.clone();
    creds.push(("idempotency-key", marker("retry")));
    let body = serde_json::json!({"url": "udp://192.0.2.53"});
    let req = || Node::request("PUT", "/api/v1/upstreams/up", &creds, Some(&body));
    let app = n.app.clone();
    let first_req = req();
    let first = tokio::spawn(async move { app.oneshot(first_req).await.unwrap() });
    reload_asked.recv().await.unwrap();
    // The retry, while the first waits for its reload.
    let retry = tokio::time::timeout(Duration::from_secs(5), n.app.clone().oneshot(req()))
        .await
        .expect("answered at once, not queued behind the first")
        .unwrap();
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert!(
        retry.headers().get("retry-after").is_some(),
        "{:?}",
        retry.headers()
    );
    go.notify_one();
    let first = first.await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first = axum::body::to_bytes(first.into_body(), 1 << 20)
        .await
        .unwrap();
    // Afterwards: the first answer.
    let again = tokio::time::timeout(Duration::from_secs(5), n.app.clone().oneshot(req()))
        .await
        .expect("replayed, not made again")
        .unwrap();
    assert_eq!(again.status(), StatusCode::OK);
    assert!(again.headers().get("idempotency-replayed").is_some());
    let again = axum::body::to_bytes(again.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(again, first, "the first answer");
    assert!(reload_asked.try_recv().is_err(), "one reload");
    let rows = n
        .auth
        .state()
        .audit_page(None, 100, None, None)
        .unwrap()
        .iter()
        .filter(|e| e.action == "upstream.put" && e.target == "up")
        .count();
    assert_eq!(rows, 1, "one audit row");
}

/// REQ: API-002, T8.2 (ADR-181) — correctness R5(a), review round 3 (F1): a write that reaches
/// the backend without the API's handler (a write a replica forwarded, on the primary) runs to its
/// end in the backend's own task: another change holds the configuration lock, the write waits
/// for it, and its caller goes away meanwhile. Once the lock is free the write is planned,
/// stored and applied (without that task, nothing would be).
#[tokio::test]
async fn api_002_a_backend_write_whose_caller_goes_away_runs_to_its_end() {
    let n = Node::new(Reload::Applies);
    let backend = ApiBackend {
        src: Arc::clone(&n.src),
    };
    let w = telltale_api::ManagedWrite {
        kind: ManagedKind::Router,
        name: "udm".into(),
        body: Some(unifi(HERE, "the-key")),
        dry_run: false,
        expect: None,
        by: "root".into(),
        simulate: None,
        by_admin: true,
    };
    let held = n.src.config_writes.lock().await;
    let caller = tokio::spawn(backend.write_managed(w));
    // The write starts and waits for the lock.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        n.key_file("udm").is_none(),
        "nothing stored while the lock is held"
    );
    caller.abort();
    let _ = caller.await;
    drop(held);
    wait_until("the change stored and applied", 10, || {
        n.src
            .config
            .load()
            .router
            .iter()
            .any(|r| r.name.as_str() == "udm")
    })
    .await;
    let f = n.key_file("udm").expect("the entry is stored");
    assert_eq!(
        std::fs::read_to_string(&f).ok().as_deref().map(str::trim),
        Some("the-key")
    );
}

/// REQ: API-002, T8.2 (ADR-181) — correctness R5(b): the router task sweeps after a change of the
/// routers in effect, within one 5-second check: a key file this node saved for a router that is
/// gone (here its stored entry removed by hand, so no write prunes it) is removed.
#[tokio::test]
async fn api_002_the_router_task_sweeps_after_the_routers_change() {
    let n = Node::new(Reload::Applies);
    let (s, v) = n.put("udm", &n.admin, false, unifi(HERE, "the-key")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let f = n.key_file("udm").unwrap();
    let (stop, task) = poll(&n);
    // The task's first round has seen the router (its key named, so kept).
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(Path::new(&f).exists());
    n.auth
        .state()
        .delete_managed("router", "udm", None)
        .unwrap();
    apply(&n.src);
    wait_until("the key file of the router that's gone removed", 20, || {
        !Path::new(&f).exists()
    })
    .await;
    let _ = stop.send(true);
    let _ = task.await;
}

/// A UniFi router `name` at `url` whose key is the file `key`.
fn mounted_router(name: &str, url: &str, key: &str) -> telltale_config::RouterConfig {
    serde_json::from_value(serde_json::json!({
        "name": name, "type": "unifi", "url": url, "site": "default",
        "api_key_file": key, "offline_days": 0,
    }))
    .unwrap()
}

/// The routers a replica would get from this node's configuration in effect (its shared part).
fn shared_routers(n: &Node) -> Vec<serde_json::Value> {
    telltale_config::shared::shared_part(&n.src.config.load())["router"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// An administrator's override of router `name` at `url` that keeps the mounted `key` (allowed:
/// the files' router's own file at the same endpoint) and reads every minute.
async fn override_keeping(n: &Node, name: &str, url: &str, key: &str) {
    let (s, v) = n
        .put(
            name,
            &n.admin,
            false,
            serde_json::json!({"type": "unifi", "url": url, "site": "default",
                "api_key_file": key, "interval_secs": 60, "offline_days": 0}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// REQ: API-002, T8.2 (ADR-181) — review round 3 (security S1, correctness R9): an override made
/// through the API that names a mounted key is in the configuration in effect, and in what the
/// node publishes, only while the files' router of that name names the same file at the same
/// address. Once the files move the router, the merge leaves the override out (the files' router
/// is in effect, and the shared part a replica takes has only it); once they remove it, neither
/// is there. Each left-out entry is a warning, once.
#[tokio::test]
async fn api_002_a_stale_override_with_a_mounted_key_is_left_out_of_the_shared_configuration() {
    let n = Node::new(Reload::Applies);
    let d = n.data();
    std::fs::create_dir_all(format!("{d}/mount/udm")).unwrap();
    let key = format!("{d}/mount/udm/key");
    std::fs::write(&key, "mounted-key").unwrap();
    let mut file = (*n.src.file_config.load_full()).clone();
    file.router = vec![mounted_router("udm", HERE, &key)];
    n.src.file_config.store(Arc::new(file.clone()));
    apply(&n.src);
    override_keeping(&n, "udm", HERE, &key).await;
    let in_effect = || -> Vec<(String, u32)> {
        n.src
            .config
            .load()
            .router
            .iter()
            .map(|r| (r.url.to_string(), r.interval_secs))
            .collect()
    };
    // The override matches the files: kept, and published.
    assert_eq!(in_effect(), vec![(HERE.to_owned(), 60)]);
    assert_eq!(shared_routers(&n)[0]["interval_secs"], 60);
    // The files move the router.
    file.router = vec![mounted_router("udm", ELSEWHERE, &key)];
    n.src.file_config.store(Arc::new(file.clone()));
    apply(&n.src);
    assert_eq!(
        in_effect(),
        vec![(ELSEWHERE.to_owned(), 300)],
        "the files' router"
    );
    let shared = shared_routers(&n);
    assert_eq!(shared.len(), 1, "{shared:?}");
    assert_eq!(shared[0]["url"], ELSEWHERE, "{shared:?}");
    // A replica built from it has only the files' router.
    let replica = telltale_config::shared::with_shared(
        &telltale_config::Config::default(),
        &telltale_config::shared::shared_part(&n.src.config.load()),
    )
    .unwrap();
    assert!(
        replica.router.iter().all(|r| r.url.as_str() == ELSEWHERE),
        "{:?}",
        replica.router
    );
    // The node that applies the stored entries says why, once.
    let seen = super::local_access_tests::Seen::default();
    {
        let _log = tracing::subscriber::set_default(seen.subscriber());
        let _ = crate::managed::effective(&file);
        let _ = crate::managed::effective(&file);
    }
    let said = seen.lines(|l| l.contains("router `udm` made through the API isn't used"));
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(said[0].contains("DELETE /api/v1/routers/udm"), "{said:?}");
    // The files remove the router: the override isn't there either.
    file.router.clear();
    n.src.file_config.store(Arc::new(file));
    apply(&n.src);
    assert_eq!(in_effect(), Vec::<(String, u32)>::new());
    assert_eq!(shared_routers(&n), Vec::<serde_json::Value>::new());
}

/// REQ: API-002, T8.2 (ADR-181) — review round 3 (security S1, correctness R9): an override that
/// kept the files' mounted key and address is read while they match; once the files remove the
/// router, the override is left out and its console is never asked again, on this node or (from
/// the shared part) any other.
#[tokio::test]
async fn api_002_an_override_of_a_removed_files_router_is_held() {
    let n = Node::new(Reload::Applies);
    let d = n.data();
    let fake = console();
    std::fs::create_dir_all(format!("{d}/mount/udm")).unwrap();
    let key = format!("{d}/mount/udm/key");
    std::fs::write(&key, "mounted-key").unwrap();
    let mut file = (*n.src.file_config.load_full()).clone();
    file.router = vec![mounted_router("udm", &fake.url, &key)];
    n.src.file_config.store(Arc::new(file.clone()));
    apply(&n.src);
    override_keeping(&n, "udm", &fake.url, &key).await;
    let (stop, task) = poll(&n);
    wait_until("the override read while the files match", 20, || {
        !fake.sites().is_empty()
    })
    .await;
    let _ = stop.send(true);
    let _ = task.await;
    assert_eq!(fake.key_for("default").as_deref(), Some("mounted-key"));
    // The files remove the router; the stored override stays.
    file.router.clear();
    n.src.file_config.store(Arc::new(file));
    apply(&n.src);
    assert!(n.key_file("udm").is_some(), "the entry is still stored");
    assert!(n.src.config.load().router.is_empty(), "left out");
    fake.asked.lock().unwrap().clear();
    let (stop, task) = poll(&n);
    // A round reads every router in effect at once: two seconds is plenty.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _ = stop.send(true);
    let _ = task.await;
    assert!(fake.sites().is_empty(), "asked: {:?}", fake.sites());
}

/// REQ: API-002, T8.2 (ADR-181, CLU-006) — review round 3 (correctness R9): a native replica
/// whose own config file still holds an older copy of the primary's `[[router]]` (CLU-006: the
/// section is ignored) polls the router the primary shares, with its key in a folder for
/// secrets, as before round 2. A pinned controller whose files changed since the pin is the same
/// case.
#[tokio::test]
async fn api_002_a_replica_with_a_stale_own_copy_still_polls_a_folder_key() {
    let n = Node::with(Reload::Applies, |dir, s| {
        let id = telltale_cluster::node::Identity::init_with(
            dir,
            "home",
            vec!["https://node.example.test:8443".into()],
            "home",
            "api",
        )
        .unwrap();
        let c = telltale_cluster::net::Cluster::new(id, "0.1.0");
        c.set_role(telltale_cluster::node::Role::Replica, 1)
            .unwrap();
        s.cluster = Some(c);
    });
    let d = n.data();
    let fake = console();
    std::fs::create_dir_all(format!("{d}/mount/udm")).unwrap();
    let key = format!("{d}/mount/udm/key");
    std::fs::write(&key, "mounted-key").unwrap();
    // Its own file: the copy from before the primary moved the router.
    let mut own = (*n.src.file_config.load_full()).clone();
    own.router = vec![mounted_router("udm", ELSEWHERE, &key)];
    n.src.file_config.store(Arc::new(own));
    // In effect: the primary's router, from the shared configuration.
    let mut cfg = (*n.src.config.load_full()).clone();
    cfg.router = vec![mounted_router("udm", &fake.url, &key)];
    n.src.config.store(Arc::new(cfg));
    let (stop, task) = poll(&n);
    wait_until("the shared router polled", 20, || !fake.sites().is_empty()).await;
    let _ = stop.send(true);
    let _ = task.await;
    assert_eq!(fake.key_for("default").as_deref(), Some("mounted-key"));
}

/// REQ: API-002, T8.2 (ADR-181) — correctness R4: a router write that leaves its key out (nothing
/// pasted, no key file of its own) is refused with what to paste, by the names the editor uses,
/// not by the configuration's key-file fields.
#[tokio::test]
async fn api_002_a_router_without_its_key_asks_for_the_key_to_be_pasted() {
    let n = Node::new(Reload::Applies);
    for (body, wants) in [
        (
            serde_json::json!({"type": "unifi", "url": HERE, "offline_days": 0}),
            "paste the API key",
        ),
        (
            serde_json::json!({"type": "opnsense", "url": HERE, "api_key": "k"}),
            "paste the API key and the API secret",
        ),
    ] {
        let (s, v) = n.put("r", &n.admin, true, body.clone()).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{body}: {v}");
        let detail = v["detail"].as_str().unwrap_or("");
        assert!(detail.contains(wants), "{body}: {v}");
        assert!(!detail.contains("_file"), "{body}: {v}");
    }
}

/// REQ: API-002, T8.2 (ADR-181) — correctness R7: a key file that isn't there reads `file_missing`
/// ("put the key file there") when it isn't one this node saves (a platform's folder for secrets,
/// a path the config file names), and `missing` ("enter it again") when it is.
#[tokio::test]
async fn api_002_a_missing_mounted_key_says_put_the_file_there() {
    let n = Node::new(Reload::Applies);
    let d = n.data();
    let mut file = (*n.src.file_config.load_full()).clone();
    file.router.push(
        serde_json::from_value(serde_json::json!({
            "name": "mounted", "type": "unifi", "url": HERE,
            "api_key_file": format!("{d}/mount/gone/key"), "offline_days": 0,
        }))
        .unwrap(),
    );
    n.src.file_config.store(Arc::new(file));
    apply(&n.src);
    let (s, v) = n.put("pasted", &n.admin, false, unifi(HERE, "k")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    std::fs::remove_file(n.key_file("pasted").unwrap()).unwrap();
    let items = n.routers(&n.viewer).await;
    assert_eq!(key_status(&items, "mounted"), "file_missing", "{items:?}");
    assert_eq!(key_status(&items, "pasted"), "missing", "{items:?}");
}

/// REQ: API-002, AGT-003, T8.2 (ADR-181) — review round 3 (S7, F5): the sweep also removes the
/// `.request-key.<16 hex>.tmp` files a crash during the first start left behind, once old, and
/// never the request key itself nor a fresh one.
#[cfg(unix)]
#[tokio::test]
async fn api_002_the_sweep_removes_old_temporary_request_key_files() {
    let n = Node::new(Reload::Applies);
    let d = n.data();
    let dir = format!("{d}/secrets");
    std::fs::create_dir_all(&dir).unwrap();
    let old = std::time::SystemTime::now() - Duration::from_secs(3600);
    for (name, aged) in [
        (".request-key.0123456789abcdef.tmp", true),
        (".request-key.fedcba9876543210.tmp", false),
        (".request-key", true),
        (".request-key.0123456789ABCDEF.tmp", true),
    ] {
        let f = std::fs::File::create(format!("{dir}/{name}")).unwrap();
        if aged {
            f.set_modified(old).unwrap();
        }
    }
    crate::router_secrets::sweep_now(&n.src).unwrap();
    let left = |name: &str| Path::new(&format!("{dir}/{name}")).exists();
    assert!(
        !left(".request-key.0123456789abcdef.tmp"),
        "an old one is removed"
    );
    for kept in [
        ".request-key.fedcba9876543210.tmp",
        ".request-key",
        ".request-key.0123456789ABCDEF.tmp",
    ] {
        assert!(left(kept), "{kept} kept");
    }
}

/// REQ: API-002, T8.2 (ADR-181) — security N7: the sweep removes `.written.<16 hex>.tmp` files a
/// crash left behind once they are a few minutes old, and nothing else: not a fresh one, not
/// another name, not a link (nor what it leads to).
#[cfg(unix)]
#[tokio::test]
async fn api_002_the_sweep_removes_old_temporary_record_files() {
    let n = Node::new(Reload::Applies);
    let d = n.data();
    let dir = format!("{d}/secrets");
    std::fs::create_dir_all(&dir).unwrap();
    let old = std::time::SystemTime::now() - Duration::from_secs(3600);
    let make = |name: &str, aged: bool| {
        let f = std::fs::File::create(format!("{dir}/{name}")).unwrap();
        if aged {
            f.set_modified(old).unwrap();
        }
    };
    make(".written.0123456789abcdef.tmp", true);
    make(".written.fedcba9876543210.tmp", false);
    make(".written.tmp", true);
    make(".written.0123456789abcdeg.tmp", true);
    make("router-x.api_key.0123456789abcdef", true);
    std::fs::write(format!("{d}/precious"), "not a record").unwrap();
    std::fs::File::open(format!("{d}/precious"))
        .unwrap()
        .set_modified(old)
        .unwrap();
    std::os::unix::fs::symlink(
        format!("{d}/precious"),
        format!("{dir}/.written.aaaaaaaaaaaaaaaa.tmp"),
    )
    .unwrap();
    crate::router_secrets::sweep_now(&n.src).unwrap();
    let left = |name: &str| {
        Path::new(&format!("{dir}/{name}")).exists()
            || std::fs::symlink_metadata(format!("{dir}/{name}")).is_ok()
    };
    assert!(
        !left(".written.0123456789abcdef.tmp"),
        "an old one is removed"
    );
    for kept in [
        ".written.fedcba9876543210.tmp",
        ".written.tmp",
        ".written.0123456789abcdeg.tmp",
        "router-x.api_key.0123456789abcdef",
        ".written.aaaaaaaaaaaaaaaa.tmp",
    ] {
        assert!(left(kept), "{kept} kept");
    }
    assert!(Path::new(&format!("{d}/precious")).exists());
}

// ---- Review round 4 (the final review's M2 and M3).

/// REQ: API-002, T8.2 (ADR-181) — final review M2: the merge decides by the key file's path as
/// written, so it can't fail open. An override that kept the files' mounted key, which on this
/// node is a link out of the folder (the use-time rule doesn't take it here, so a check that
/// looked at the filesystem would miss it), and an override that kept a key file outside every
/// folder, are both left out once the files move their routers: the files' routers are in effect
/// and published, at their new addresses.
#[cfg(unix)]
#[tokio::test]
async fn api_002_a_stale_override_is_left_out_when_the_primary_cannot_resolve_the_key() {
    let n = Node::new(Reload::Applies);
    let d = n.data();
    for dir in ["mount/udm", "elsewhere", "etc-telltale"] {
        std::fs::create_dir_all(format!("{d}/{dir}")).unwrap();
    }
    std::fs::write(format!("{d}/elsewhere/udm-key"), "linked-key").unwrap();
    let linked = format!("{d}/mount/udm/key");
    std::os::unix::fs::symlink(format!("{d}/elsewhere/udm-key"), &linked).unwrap();
    let outside = format!("{d}/etc-telltale/fw-key");
    std::fs::write(&outside, "fw-key").unwrap();
    let third = "http://127.0.0.3:1";
    let mut file = (*n.src.file_config.load_full()).clone();
    file.router = vec![
        mounted_router("udm", HERE, &linked),
        mounted_router("fw", ELSEWHERE, &outside),
    ];
    n.src.file_config.store(Arc::new(file.clone()));
    apply(&n.src);
    override_keeping(&n, "udm", HERE, &linked).await;
    override_keeping(&n, "fw", ELSEWHERE, &outside).await;
    let in_effect = || -> Vec<(String, String, u32)> {
        let mut v: Vec<_> = n
            .src
            .config
            .load()
            .router
            .iter()
            .map(|r| (r.name.to_string(), r.url.to_string(), r.interval_secs))
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        in_effect(),
        vec![
            ("fw".to_owned(), ELSEWHERE.to_owned(), 60),
            ("udm".to_owned(), HERE.to_owned(), 60)
        ],
        "the overrides match the files: kept"
    );
    // The files move both routers.
    file.router = vec![
        mounted_router("udm", ELSEWHERE, &linked),
        mounted_router("fw", third, &outside),
    ];
    n.src.file_config.store(Arc::new(file));
    apply(&n.src);
    assert_eq!(
        in_effect(),
        vec![
            ("fw".to_owned(), third.to_owned(), 300),
            ("udm".to_owned(), ELSEWHERE.to_owned(), 300)
        ],
        "the files' routers"
    );
    let shared = shared_routers(&n);
    assert!(
        shared
            .iter()
            .all(|r| r["interval_secs"] == 300 && r["url"] != HERE),
        "{shared:?}"
    );
}

/// REQ: API-002, T8.2 (ADR-181) — final review M3: the sweep removes only what the API makes: a
/// direct child of `secrets/` named `router-<slug>.<credential>.<16 hex>`, a regular file. Forged
/// records for `secrets/mine`, `secrets/.request-key` and `secrets/sub/router-x.api_key.<hex>`
/// keep their files (and their records); a genuine orphan goes. A stored row that isn't a
/// router's object means it can't tell what is named: no sweep at all.
#[tokio::test]
async fn api_002_the_sweep_removes_only_names_it_makes() {
    let n = Node::new(Reload::Applies);
    let d = n.data();
    let dir = format!("{d}/secrets");
    std::fs::create_dir_all(format!("{dir}/sub")).unwrap();
    let forged = [
        format!("{dir}/mine"),
        format!("{dir}/.request-key"),
        format!("{dir}/sub/router-x.api_key.0123456789abcdef"),
    ];
    let orphan = format!("{dir}/router-gone.api_key.0123456789abcdef");
    let mut lines = String::new();
    for f in forged.iter().chain([&orphan]) {
        std::fs::write(f, "x").unwrap();
        lines.push_str(
            &serde_json::json!({"router": "gone", "field": "api_key", "file": f}).to_string(),
        );
        lines.push('\n');
    }
    std::fs::write(format!("{dir}/.written"), lines).unwrap();
    let gone = crate::router_secrets::sweep_now(&n.src).unwrap();
    assert_eq!(gone.len(), 1, "{gone:?}");
    assert!(!Path::new(&orphan).exists(), "the orphan is removed");
    for f in &forged {
        assert!(Path::new(f).exists(), "{f} kept");
    }
    let written = std::fs::read_to_string(format!("{dir}/.written")).unwrap();
    assert_eq!(written.lines().count(), 3, "their records kept: {written}");
    // A stored row the sweep can't read: nothing is removed.
    n.store("broken", &serde_json::json!("not a router"));
    let orphan2 = format!("{dir}/router-gone.api_key.fedcba9876543210");
    std::fs::write(&orphan2, "x").unwrap();
    std::fs::write(
        format!("{dir}/.written"),
        format!(
            "{}\n",
            serde_json::json!({"router": "gone", "field": "api_key", "file": orphan2})
        ),
    )
    .unwrap();
    assert!(
        crate::router_secrets::sweep_now(&n.src).is_err(),
        "no sweep"
    );
    assert!(Path::new(&orphan2).exists(), "nothing removed");
}
