// REQ: UPS-011, API-002 (ADR-180) — what a setting made through the API can make the server start
// or connect to: plugin upstreams (`exec://`, `unix://`) are defined in the config file, so every
// API write, dry run and pre-save check refuses them, and entries stored before are left out of
// the merge. Driven through the real routes, sign-in and backend, with a harness like
// `cred_file_tests`' (copied here so that file stays as it is). No test here starts a program:
// every plugin path names a file that doesn't exist.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use telltale_api::auth::{self, Auth, Role};
use tower::ServiceExt as _;

use super::*;

pub(super) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A program and a socket that don't exist: nothing can start, or answer, there.
pub(super) const NO_PROGRAM: &str = "/nonexistent/telltale-test-plugin";
pub(super) const NO_SOCKET: &str = "/nonexistent/telltale-test-plugin.sock";

/// The scopes the agent tokens get: every write these tests make.
const AGENT_SCOPES: &str = "config:write:upstreams config:write:forwards config:write:lists config:write:alerts querylog:read config:read";

/// How a caller signs in: the headers it sends.
pub(super) type Creds = Vec<(&'static str, String)>;

/// One node with a state database and callers of every kind.
pub(super) struct Node {
    pub(super) src: Arc<Sources>,
    pub(super) app: axum::Router,
    pub(super) auth: Arc<Auth>,
    /// An admin's API token, and the same admin's signed-in session.
    pub(super) admin: Creds,
    pub(super) admin_session: Creds,
    pub(super) operator: Creds,
    pub(super) viewer: Creds,
    /// Agent tokens: an operator's, and an admin's.
    pub(super) operator_agent: Creds,
    pub(super) admin_agent: Creds,
    pub(super) dir: tempfile::TempDir,
}

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
        auth.state().set_token_agent(&id, s, None, None).unwrap();
    }
    bearer(&format!("tt_{id}_{secret}"))
}

/// The running configuration from the files and `state.db`, as a reload builds it.
pub(super) fn apply(src: &Sources) {
    let file = src.file_config.load_full();
    if let Some(a) = src.auth.get()
        && let Ok(c) = crate::managed::merge(&file, &crate::managed::entries(a.state()))
    {
        src.config.store(Arc::new(c));
    }
}

impl Node {
    /// A node whose config files are `file`, with a fresh temporary data directory.
    pub(super) fn new(mut file: telltale_config::Config) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut s = crate::http::tests::sources_in(dir.path());
        file.node.data_dir =
            telltale_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
        s.file_config = arc_swap::ArcSwap::from_pointee(file.clone());
        s.config = arc_swap::ArcSwap::from_pointee(file);
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
        Self {
            admin: token(&auth, root.id, "admin", None),
            operator: token(&auth, olga.id, "write", None),
            viewer: token(&auth, vic.id, "read", None),
            operator_agent: token(&auth, olga.id, "write", Some(AGENT_SCOPES)),
            admin_agent: token(&auth, root.id, "write", Some(AGENT_SCOPES)),
            admin_session,
            src,
            app,
            auth,
            dir,
        }
    }

    pub(super) fn data(&self) -> String {
        self.dir.path().to_str().unwrap().to_owned()
    }

    /// An agent token (a viewer's) holding exactly `scopes` (space separated), optionally
    /// restricted to one client group.
    pub(super) fn agent(&self, scopes: &str, group: Option<&str>) -> Creds {
        let name = format!("agent{}", auth::crypto::random_id());
        let owner = self
            .auth
            .create_user(
                &name,
                "an agent owner's password",
                Role::Viewer,
                false,
                now(),
            )
            .unwrap();
        let (id, secret) = (auth::crypto::random_id(), auth::crypto::random_secret());
        self.auth
            .state()
            .create_token(
                &id,
                owner.id,
                "tests",
                &auth::crypto::secret_hash(&secret),
                "read",
                None,
                now(),
            )
            .unwrap();
        self.auth
            .state()
            .set_token_agent(&id, scopes, group, None)
            .unwrap();
        bearer(&format!("tt_{id}_{secret}"))
    }

    /// Everyone who may write the configuration: an operator, an admin (token and session), and
    /// agent tokens (an operator's and an admin's).
    pub(super) fn writers(&self) -> Vec<(&'static str, &Creds)> {
        vec![
            ("operator", &self.operator),
            ("admin token", &self.admin),
            ("admin session", &self.admin_session),
            ("admin's agent", &self.admin_agent),
            ("operator's agent", &self.operator_agent),
        ]
    }

    pub(super) async fn send(
        &self,
        method: &str,
        uri: &str,
        creds: &Creds,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            // Agents say why (AGT-005); people may.
            .header("x-telltale-reason", "local access tests");
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

    pub(super) async fn put(
        &self,
        path: &str,
        creds: &Creds,
        dry: bool,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let uri = format!("{path}{}", if dry { "?dryRun=true" } else { "" });
        self.send("PUT", &uri, creds, Some(body)).await
    }

    /// Stores an entry as an older version, a backup, or a hand edit would have.
    pub(super) fn store(&self, kind: &str, name: &str, body: &serde_json::Value) {
        self.auth
            .state()
            .put_managed(
                kind,
                name,
                &body.to_string(),
                None,
                None,
                now(),
                "an older version",
            )
            .unwrap();
    }
}

/// Every log event a test subscriber saw: level and message.
#[derive(Clone, Default)]
pub(super) struct Seen(pub(super) Arc<Mutex<Vec<(tracing::Level, String)>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Seen {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Message(String);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write as _;
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                } else {
                    let _ = write!(self.0, " {}={value:?}", field.name());
                }
            }
        }
        let mut m = Message(String::new());
        event.record(&mut m);
        if let Ok(mut v) = self.0.lock() {
            v.push((*event.metadata().level(), m.0));
        }
    }
}

impl Seen {
    pub(super) fn lines(&self, f: impl Fn(&str) -> bool) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, l)| f(l))
            .map(|(_, l)| l.clone())
            .collect()
    }

    pub(super) fn warnings(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(l, _)| *l == tracing::Level::WARN)
            .map(|(_, m)| m.clone())
            .collect()
    }

    pub(super) fn subscriber(
        &self,
    ) -> tracing_subscriber::layer::Layered<Self, tracing_subscriber::Registry> {
        use tracing_subscriber::layer::SubscriberExt as _;
        tracing_subscriber::registry().with(self.clone())
    }
}

/// What the supervisor logs when it tries to start a plugin, or did.
fn plugin_start(l: &str) -> bool {
    l.contains("plugin can't start") || l.contains("plugin started")
}

/// REQ: UPS-011, API-002 (ADR-180) — an upstream that names a program (`exec://`, with or without
/// `args`) or a local socket (`unix://`) is refused through the API for every caller, an
/// administrator's session and token included, dry run or not, with a 422 that names the field
/// and says where such upstreams are defined; nothing is stored. Other upstreams still save.
#[tokio::test]
async fn ups_011_plugin_upstreams_cant_be_set_through_the_api() {
    let n = Node::new(telltale_config::Config::default());
    let bodies = [
        (
            "a program with arguments",
            serde_json::json!({ "url": format!("exec://{NO_PROGRAM}"), "args": ["--zone", "home"] }),
            "url",
        ),
        (
            "a program",
            serde_json::json!({ "url": format!("exec://{NO_PROGRAM}") }),
            "url",
        ),
        (
            "a socket",
            serde_json::json!({ "url": format!("unix://{NO_SOCKET}") }),
            "url",
        ),
        (
            "arguments",
            serde_json::json!({ "url": "udp://192.0.2.53", "args": ["--zone", "home"] }),
            "args",
        ),
    ];
    for (who, creds) in n.writers() {
        for (what, body, field) in &bodies {
            for dry in [true, false] {
                let (s, v) = n
                    .put("/api/v1/upstreams/plug", creds, dry, body.clone())
                    .await;
                assert_eq!(
                    s,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "{who}, {what}, dry={dry}: {v}"
                );
                assert_eq!(v["code"], "invalid_config", "{v}");
                assert!(
                    v["detail"]
                        .as_str()
                        .unwrap_or("")
                        .contains(&format!("`{field}`")),
                    "{who}, {what}: the field is named: {v}"
                );
                assert!(
                    v["hint"].as_str().unwrap_or("").contains("config file"),
                    "{who}, {what}: {v}"
                );
            }
        }
    }
    // A viewer can't write upstreams at all.
    let (s, v) = n
        .put(
            "/api/v1/upstreams/plug",
            &n.viewer,
            true,
            bodies[0].1.clone(),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(
        crate::managed::entries(n.auth.state()).upstreams.is_empty(),
        "nothing was stored"
    );
    // Upstreams that don't name a program or a socket still save, for everyone.
    for (i, (who, creds)) in n.writers().into_iter().enumerate() {
        for url in [
            "udp://192.0.2.53",
            "tls://192.0.2.53",
            "https://192.0.2.53/dns-query",
        ] {
            let name = format!("up-{i}-{}", url.split(':').next().unwrap_or(""));
            let (s, v) = n
                .put(
                    &format!("/api/v1/upstreams/{name}"),
                    creds,
                    false,
                    serde_json::json!({ "url": url }),
                )
                .await;
            assert_eq!(
                (s, v["applied"].as_bool()),
                (StatusCode::OK, Some(true)),
                "{who}, {url}: {v}"
            );
        }
    }
}

/// REQ: UPS-011, API-002 (ADR-180) — a forwarded domain's servers become upstreams: one with a
/// plugin scheme is refused (dry run or not, an administrator included), and nothing is stored;
/// plain, encrypted and HTTPS servers still save.
#[tokio::test]
async fn ups_011_a_forward_to_a_plugin_is_refused() {
    let n = Node::new(telltale_config::Config::default());
    let lists = [
        vec![format!("exec://{NO_PROGRAM}")],
        vec![format!("unix://{NO_SOCKET}")],
        vec!["192.0.2.53".to_owned(), format!("unix://{NO_SOCKET}")],
    ];
    for (who, creds) in [
        ("operator", &n.operator),
        ("admin token", &n.admin),
        ("admin session", &n.admin_session),
        ("operator's agent", &n.operator_agent),
    ] {
        for servers in &lists {
            for dry in [true, false] {
                let (s, v) = n
                    .put(
                        "/api/v1/forwards/corp.example",
                        creds,
                        dry,
                        serde_json::json!({ "servers": servers }),
                    )
                    .await;
                assert_eq!(
                    s,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "{who}, {servers:?}, dry={dry}: {v}"
                );
                assert!(
                    v["detail"].as_str().unwrap_or("").contains("`servers"),
                    "{who}: the field is named: {v}"
                );
                assert!(
                    v["hint"].as_str().unwrap_or("").contains("config file"),
                    "{v}"
                );
            }
        }
    }
    assert!(
        crate::managed::entries(n.auth.state()).forwards.is_empty(),
        "nothing was stored"
    );
    let (s, v) = n
        .put(
            "/api/v1/forwards/corp.example",
            &n.operator,
            false,
            serde_json::json!({ "servers": ["192.0.2.53", "tls://192.0.2.54", "https://192.0.2.55/dns-query"] }),
        )
        .await;
    assert_eq!(
        (s, v["applied"].as_bool()),
        (StatusCode::OK, Some(true)),
        "{v}"
    );
}

/// REQ: UPS-011, API-002 (ADR-180) — a pre-save check of a draft that names a program or a
/// socket is refused before anything is built: no start is even attempted (the supervisor would
/// log one; the same capture sees it when the config files name such a program).
#[tokio::test]
async fn ups_011_a_check_never_starts_a_plugin() {
    let n = Node::new(telltale_config::Config::default());
    let seen = Seen::default();
    let _guard = tracing::subscriber::set_default(seen.subscriber());
    for (who, creds) in [
        ("admin token", &n.admin),
        ("admin session", &n.admin_session),
        ("operator", &n.operator),
        ("operator's agent", &n.operator_agent),
    ] {
        // With bootstrap servers given, so a build doesn't depend on this machine's resolv.conf.
        for body in [
            serde_json::json!({
                "url": format!("exec://{NO_PROGRAM}"), "args": ["--zone", "home"],
                "bootstrap": ["192.0.2.1"],
            }),
            serde_json::json!({ "url": format!("unix://{NO_SOCKET}"), "bootstrap": ["192.0.2.1"] }),
        ] {
            let (s, v) = n
                .send("POST", "/api/v1/checks/upstream", creds, Some(body))
                .await;
            // A supervisor, had one been made, gets every chance to run.
            for _ in 0..50 {
                tokio::task::yield_now().await;
            }
            let started = seen.lines(plugin_start);
            assert!(
                started.is_empty(),
                "{who}: a plugin start was attempted: {started:?} ({s} {v})"
            );
            assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{who}: {v}");
            assert!(
                v["hint"].as_str().unwrap_or("").contains("config file"),
                "{who}: {v}"
            );
        }
    }
    // The capture sees the supervisor: the config files may name a program, which is then
    // started (here it doesn't exist, so it can't be). Its socket would be in the data directory.
    let mut c = (*n.src.config.load_full()).clone();
    assert_eq!(c.node.data_dir.as_str(), n.data());
    c.upstream = vec![
        serde_json::from_value(serde_json::json!({
            "name": "from-file", "url": format!("exec://{NO_PROGRAM}"), "args": ["--zone", "home"],
            "bootstrap": ["192.0.2.1"],
        }))
        .unwrap(),
    ];
    c.upstream_group = vec![
        serde_json::from_value(serde_json::json!({ "name": "default", "members": ["from-file"] }))
            .unwrap(),
    ];
    let router = telltale_upstream::Router::from_config(&c).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while seen.lines(|l| l.contains("plugin can't start")).is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "the supervisor never tried the config file's program"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    drop(router);
}

/// A node whose config files define two plain upstreams and a plugin one, with entries in
/// `state.db` as an older version would have stored them: a plugin override of the files'
/// `consul`, an added plugin `magic`, a plain override of `quad9`, the `default` group naming all
/// three, a forward to a program, and a plain forward.
fn node_with_stored_plugins() -> Node {
    let file: telltale_config::Config = toml::from_str(
        r#"
        [[upstream]]
        name = "quad9"
        url = "udp://9.9.9.9"
        [[upstream]]
        name = "consul"
        url = "udp://127.0.0.1:5353"
        [[upstream]]
        name = "file-plugin"
        url = "exec:///nonexistent/telltale-test-plugin"
        args = ["--from", "the config file"]
        [[upstream_group]]
        name = "default"
        members = ["quad9", "consul"]
        "#,
    )
    .unwrap();
    let n = Node::new(file);
    let up = |name: &str, extra: serde_json::Value| {
        let mut v = serde_json::json!({ "name": name });
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    };
    n.store(
        crate::managed::UPSTREAM,
        "consul",
        &up(
            "consul",
            serde_json::json!({ "url": format!("exec://{NO_PROGRAM}"), "args": ["--dc", "home"] }),
        ),
    );
    n.store(
        crate::managed::UPSTREAM,
        "magic",
        &up(
            "magic",
            serde_json::json!({ "url": format!("unix://{NO_SOCKET}") }),
        ),
    );
    n.store(
        crate::managed::UPSTREAM,
        "quad9",
        &up(
            "quad9",
            serde_json::json!({ "url": "tls://9.9.9.9", "tls_server_name": "dns.quad9.net" }),
        ),
    );
    n.store(
        crate::managed::UPSTREAM_GROUP,
        "default",
        &serde_json::json!({ "name": "default", "members": ["quad9", "magic", "consul"] }),
    );
    n.store(
        crate::managed::FORWARD,
        "corp.example",
        &serde_json::json!({ "servers": [format!("exec://{NO_PROGRAM}")] }),
    );
    n.store(
        crate::managed::FORWARD,
        "lab.example",
        &serde_json::json!({ "servers": ["192.0.2.53"] }),
    );
    n
}

/// The members of upstream group `name` in `groups`.
fn members_of(groups: &[telltale_config::UpstreamGroup], name: &str) -> Vec<String> {
    groups
        .iter()
        .find(|g| g.name.as_str() == name)
        .map(|g| g.members.iter().map(ToString::to_string).collect())
        .unwrap_or_default()
}

/// REQ: UPS-011 (ADR-180) — entries made through the API that name a program or a socket and are
/// already in `state.db` (from an older version, a backup, or a hand edit) are left out of the
/// running configuration: an added one is gone (and out of the upstream groups that named it),
/// an override leaves the files' entry of that name in effect, a forward to one is dropped. Each
/// is logged once, with a warning naming it, and not again while nothing changes. Other entries
/// apply as before, and a plugin upstream of the config files is untouched.
#[tokio::test]
async fn ups_011_stored_plugin_entries_are_left_out_of_the_merge() {
    let n = node_with_stored_plugins();
    let file = n.src.file_config.load_full();
    let seen = Seen::default();
    let cfg =
        tracing::subscriber::with_default(seen.subscriber(), || crate::managed::effective(&file));
    let url = |name: &str| {
        cfg.upstream
            .iter()
            .find(|u| u.name.as_str() == name)
            .map(|u| u.url.to_string())
    };
    assert_eq!(
        url("consul").as_deref(),
        Some("udp://127.0.0.1:5353"),
        "the files' entry stays in effect"
    );
    assert_eq!(url("magic"), None, "an added plugin upstream isn't used");
    assert_eq!(
        url("quad9").as_deref(),
        Some("tls://9.9.9.9"),
        "a normal override still applies"
    );
    assert_eq!(
        url("file-plugin"),
        Some(format!("exec://{NO_PROGRAM}")),
        "the config files' plugin upstream is untouched"
    );
    assert!(
        cfg.upstream
            .iter()
            .filter(|u| u.name.as_str() != "file-plugin")
            .all(|u| {
                let s = u.url.as_str();
                !s.starts_with("exec://") && !s.starts_with("unix://")
            }),
        "{:?}",
        cfg.upstream
    );
    assert_eq!(
        members_of(&cfg.upstream_group, "default"),
        ["quad9", "consul"],
        "the group lost what was left out"
    );
    let routed = |d: &str| {
        cfg.route
            .iter()
            .any(|r| r.match_suffix.iter().any(|s| s.as_str() == d))
    };
    assert!(
        !routed("corp.example"),
        "the forward to a program is dropped"
    );
    assert!(routed("lab.example"), "a normal forward still applies");
    let warned = seen.warnings();
    for name in ["consul", "magic", "corp.example"] {
        let about: Vec<&String> = warned.iter().filter(|w| w.contains(name)).collect();
        assert_eq!(about.len(), 1, "one warning naming {name}: {warned:?}");
    }
    assert!(
        warned.iter().all(|w| !w.contains("quad9")
            && !w.contains("lab.example")
            && !w.contains("file-plugin")),
        "{warned:?}"
    );
    // Built again with nothing changed: no new warning.
    let again = Seen::default();
    let _ =
        tracing::subscriber::with_default(again.subscriber(), || crate::managed::effective(&file));
    assert!(
        again.warnings().is_empty(),
        "logged once per change, not at every rebuild: {:?}",
        again.warnings()
    );
}

/// REQ: UPS-011, API-002 (ADR-180) — a plugin upstream left out of the merge can still be removed
/// through the API, and the upstream group made through the API that still names it loses it.
#[tokio::test]
async fn ups_011_a_stored_plugin_upstream_can_still_be_removed() {
    let n = node_with_stored_plugins();
    apply(&n.src);
    let (s, v) = n
        .send("DELETE", "/api/v1/upstreams/magic", &n.admin, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let stored = crate::managed::entries(n.auth.state());
    assert!(stored.upstreams.iter().all(|(k, _)| k != "magic"));
    let groups: Vec<telltale_config::UpstreamGroup> = stored
        .upstream_groups
        .iter()
        .filter_map(|(_, o)| match o {
            crate::managed::Ovr::Set(g) => Some(g.clone()),
            crate::managed::Ovr::Hidden => None,
        })
        .collect();
    assert_eq!(members_of(&groups, "default"), ["quad9", "consul"]);
}

/// A node whose config files define `quad9` and `cloudflare`, the `default` group, and a client
/// group `iot` that sends to `default`, with a device, a list and a quick rule made the ordinary
/// way through the API.
async fn node_with_api_entries() -> Node {
    let file: telltale_config::Config = toml::from_str(
        r#"
        [[upstream]]
        name = "quad9"
        url = "udp://9.9.9.9"
        [[upstream]]
        name = "cloudflare"
        url = "udp://1.1.1.1"
        [[upstream_group]]
        name = "default"
        members = ["quad9"]
        [[group]]
        name = "iot"
        upstreams = "default"
        "#,
    )
    .unwrap();
    let n = Node::new(file);
    for (path, body) in [
        (
            "/api/v1/clients/tv",
            serde_json::json!({ "match": ["192.168.1.20"] }),
        ),
        (
            "/api/v1/lists/manual",
            serde_json::json!({ "rules": ["||ads.example^"] }),
        ),
        (
            "/api/v1/rules/r-1",
            serde_json::json!({ "action": "block", "domain": "tracker.example" }),
        ),
    ] {
        let (s, v) = n.put(path, &n.admin, false, body).await;
        assert_eq!(s, StatusCode::OK, "{path}: {v}");
    }
    n.store(
        crate::managed::UPSTREAM,
        "magic",
        &serde_json::json!({ "name": "magic", "url": format!("unix://{NO_SOCKET}") }),
    );
    n
}

/// The running configuration `effective` builds for `n`, with the warnings and errors it logged.
fn effective_of(n: &Node) -> (telltale_config::Config, Seen) {
    let file = n.src.file_config.load_full();
    let seen = Seen::default();
    let cfg =
        tracing::subscriber::with_default(seen.subscriber(), || crate::managed::effective(&file));
    (cfg, seen)
}

/// The API's device, list and quick rule are in effect, and nothing made the node fall back to
/// the config files alone.
fn assert_api_entries_kept(cfg: &telltale_config::Config, seen: &Seen) {
    assert!(
        cfg.client.iter().any(|c| c.name.as_str() == "tv"),
        "the device: {:?}",
        seen.lines(|_| true)
    );
    assert!(cfg.list.iter().any(|l| l.name.as_str() == "manual"));
    assert!(
        cfg.rule
            .iter()
            .any(|r| r.domain.as_str() == "tracker.example")
    );
    let fell_back = seen.lines(|l| l.contains("using the config files only"));
    assert!(fell_back.is_empty(), "{fell_back:?}");
}

/// REQ: UPS-011, API-002 (ADR-180) — an upstream group made through the API whose only members
/// are left out is left out too (an override of the files' group gives the files' back), so the
/// merged configuration stays valid and every other entry made through the API stays in effect;
/// each is named in a warning.
#[tokio::test]
async fn ups_011_a_group_emptied_by_a_left_out_plugin_keeps_the_other_api_entries() {
    let n = node_with_api_entries().await;
    n.store(
        crate::managed::UPSTREAM_GROUP,
        "plugins",
        &serde_json::json!({ "name": "plugins", "members": ["magic"] }),
    );
    n.store(
        crate::managed::UPSTREAM_GROUP,
        "default",
        &serde_json::json!({ "name": "default", "members": ["magic"] }),
    );
    let (cfg, seen) = effective_of(&n);
    assert_api_entries_kept(&cfg, &seen);
    assert!(
        cfg.upstream_group
            .iter()
            .all(|g| g.name.as_str() != "plugins"),
        "{:?}",
        cfg.upstream_group
    );
    assert_eq!(
        members_of(&cfg.upstream_group, "default"),
        ["quad9"],
        "the files' group is back"
    );
    let warned = seen.warnings();
    for name in ["`plugins`", "`default`", "`magic`"] {
        assert_eq!(
            warned.iter().filter(|w| w.contains(name)).count(),
            1,
            "one warning naming {name}: {warned:?}"
        );
    }
}

/// REQ: UPS-011, API-002 (ADR-180) — a `parallel` upstream group made through the API that loses
/// a left-out member asks as many at once as it still has, or, with one left, uses `failover`;
/// the merge stays valid.
#[tokio::test]
async fn ups_011_a_parallel_group_keeps_working_without_a_left_out_member() {
    let n = node_with_api_entries().await;
    for (name, members, fanout) in [
        ("race2", vec!["quad9", "magic"], 2),
        ("race3", vec!["quad9", "cloudflare", "magic"], 3),
    ] {
        n.store(
            crate::managed::UPSTREAM_GROUP,
            name,
            &serde_json::json!({
                "name": name, "members": members, "strategy": "parallel", "parallel_fanout": fanout,
            }),
        );
    }
    let (cfg, seen) = effective_of(&n);
    assert_api_entries_kept(&cfg, &seen);
    let group = |name: &str| {
        cfg.upstream_group
            .iter()
            .find(|g| g.name.as_str() == name)
            .cloned()
            .unwrap()
    };
    let race2 = group("race2");
    assert_eq!(members_of(&cfg.upstream_group, "race2"), ["quad9"]);
    assert_eq!(race2.strategy, telltale_config::Strategy::Failover);
    let race3 = group("race3");
    assert_eq!(
        members_of(&cfg.upstream_group, "race3"),
        ["quad9", "cloudflare"]
    );
    assert_eq!(
        (race3.strategy, race3.parallel_fanout),
        (telltale_config::Strategy::Parallel, 2)
    );
    let warned = seen.warnings();
    for name in ["`race2`", "`race3`"] {
        assert_eq!(
            warned.iter().filter(|w| w.contains(name)).count(),
            1,
            "{name}: {warned:?}"
        );
    }
}

/// REQ: UPS-011, API-002 (ADR-180) — a client group made through the API that sends its queries to
/// an upstream group that is left out (one emptied by a left-out plugin, or a forward left out as a
/// whole) goes back to the default (an override of a config-file group, to the files' choice); its
/// other settings stay, and the merge stays valid.
#[tokio::test]
async fn ups_011_a_client_group_naming_a_left_out_group_keeps_working() {
    let n = node_with_api_entries().await;
    n.store(
        crate::managed::UPSTREAM_GROUP,
        "plugins",
        &serde_json::json!({ "name": "plugins", "members": ["magic"] }),
    );
    n.store(
        crate::managed::FORWARD,
        "corp.example",
        &serde_json::json!({ "servers": [format!("exec://{NO_PROGRAM}")] }),
    );
    for (name, upstreams) in [
        ("kids", "plugins"),
        ("iot", "plugins"),
        ("office", "forward:corp.example"),
    ] {
        n.store(
            crate::managed::GROUP,
            name,
            &serde_json::json!({ "name": name, "upstreams": upstreams, "block_ttl": 60 }),
        );
    }
    let (cfg, seen) = effective_of(&n);
    assert_api_entries_kept(&cfg, &seen);
    let group = |name: &str| {
        cfg.group
            .iter()
            .find(|g| g.name.as_str() == name)
            .cloned()
            .unwrap()
    };
    assert_eq!(group("kids").upstreams, None);
    assert_eq!(group("office").upstreams, None);
    let iot = group("iot");
    assert_eq!(
        iot.upstreams.as_deref(),
        Some("default"),
        "the files' choice"
    );
    assert_eq!(iot.block_ttl, 60, "its other settings stay the API's");
    let warned = seen.warnings();
    for name in ["`kids`", "`iot`", "`office`"] {
        assert_eq!(
            warned.iter().filter(|w| w.contains(name)).count(),
            1,
            "{name}: {warned:?}"
        );
    }
}

/// REQ: UPS-011 (ADR-180) — a forwarded domain made through the API keeps the servers that aren't
/// plugins (only those are left out); one with none left is left out, and its warning says where
/// its names go instead.
#[tokio::test]
async fn ups_011_a_forward_keeps_its_servers_that_arent_plugins() {
    let n = node_with_api_entries().await;
    n.store(
        crate::managed::FORWARD,
        "corp.example",
        &serde_json::json!({ "servers": ["192.0.2.53", format!("exec://{NO_PROGRAM}"), "tls://192.0.2.54"] }),
    );
    n.store(
        crate::managed::FORWARD,
        "lab.example",
        &serde_json::json!({ "servers": [format!("unix://{NO_SOCKET}")] }),
    );
    let (cfg, seen) = effective_of(&n);
    assert_api_entries_kept(&cfg, &seen);
    let route = |d: &str| {
        cfg.route
            .iter()
            .find(|r| r.match_suffix.iter().any(|s| s.as_str() == d))
            .cloned()
    };
    let corp = route("corp.example").expect("the forward stays");
    let urls: Vec<String> = cfg
        .upstream_group
        .iter()
        .find(|g| g.name == corp.upstream_group)
        .unwrap()
        .members
        .iter()
        .filter_map(|m| cfg.upstream.iter().find(|u| u.name == *m))
        .map(|u| u.url.to_string())
        .collect();
    assert_eq!(urls, ["udp://192.0.2.53", "tls://192.0.2.54"]);
    assert!(route("lab.example").is_none(), "no server left");
    let warned = seen.warnings();
    let corp: Vec<&String> = warned
        .iter()
        .filter(|w| w.contains("`corp.example`"))
        .collect();
    assert_eq!(corp.len(), 1, "{warned:?}");
    assert!(corp[0].contains("keeps"), "{corp:?}");
    let lab: Vec<&String> = warned
        .iter()
        .filter(|w| w.contains("`lab.example`"))
        .collect();
    assert_eq!(lab.len(), 1, "{warned:?}");
    assert!(
        lab[0].contains("`default`"),
        "says where its names go: {lab:?}"
    );
}

/// The URLs of upstream group `name`'s members in `cfg`.
fn member_urls(cfg: &telltale_config::Config, name: &str) -> Vec<String> {
    members_of(&cfg.upstream_group, name)
        .iter()
        .filter_map(|m| cfg.upstream.iter().find(|u| u.name.as_str() == m))
        .map(|u| u.url.to_string())
        .collect()
}

/// REQ: UPS-011, API-002 (ADR-180) — a forwarded domain's servers keep their upstream names
/// (`forward:<domain>#<n>`, by place) when a plugin server among them is left out, so an upstream
/// group made through the API that names one still means the same server; the names the left-out
/// servers had are taken out of such groups, as any left-out upstream is. The merge stays valid.
#[tokio::test]
async fn ups_011_a_forwards_servers_keep_their_names_when_a_plugin_is_left_out() {
    let n = node_with_api_entries().await;
    n.store(
        crate::managed::FORWARD,
        "corp.example",
        &serde_json::json!({ "servers": [format!("exec://{NO_PROGRAM}"), "192.0.2.53", "tls://192.0.2.54"] }),
    );
    n.store(
        crate::managed::FORWARD,
        "lab.example",
        &serde_json::json!({ "servers": [format!("unix://{NO_SOCKET}")] }),
    );
    for (name, members) in [
        (
            "corp",
            vec!["forward:corp.example#2", "forward:corp.example#1", "quad9"],
        ),
        ("corp-tls", vec!["forward:corp.example#3"]),
        ("lab", vec!["forward:lab.example#1", "cloudflare"]),
    ] {
        n.store(
            crate::managed::UPSTREAM_GROUP,
            name,
            &serde_json::json!({ "name": name, "members": members }),
        );
    }
    let (cfg, seen) = effective_of(&n);
    assert_api_entries_kept(&cfg, &seen);
    assert_eq!(
        member_urls(&cfg, "forward:corp.example"),
        ["udp://192.0.2.53", "tls://192.0.2.54"]
    );
    assert_eq!(
        members_of(&cfg.upstream_group, "corp"),
        ["forward:corp.example#2", "quad9"],
        "the plugin server's name is taken out"
    );
    assert_eq!(
        member_urls(&cfg, "corp"),
        ["udp://192.0.2.53", "udp://9.9.9.9"]
    );
    assert_eq!(member_urls(&cfg, "corp-tls"), ["tls://192.0.2.54"]);
    assert_eq!(member_urls(&cfg, "lab"), ["udp://1.1.1.1"]);
}

/// REQ: UPS-011, API-002 (ADR-180) — a write that names what the merge leaves out (an upstream
/// that names a program or a socket, a forward's plugin server, or an upstream group left out with
/// them) is refused with a 422 that names it and says where plugin upstreams are defined, dry run
/// or not, instead of being stored and adjusted. A write that names what is in effect is not.
#[tokio::test]
async fn ups_011_a_write_naming_a_left_out_entry_is_refused() {
    let n = node_with_api_entries().await;
    n.store(
        crate::managed::UPSTREAM_GROUP,
        "plugins",
        &serde_json::json!({ "name": "plugins", "members": ["magic"] }),
    );
    n.store(
        crate::managed::FORWARD,
        "corp.example",
        &serde_json::json!({ "servers": [format!("exec://{NO_PROGRAM}"), "192.0.2.53"] }),
    );
    n.store(
        crate::managed::FORWARD,
        "lab.example",
        &serde_json::json!({ "servers": [format!("unix://{NO_SOCKET}")] }),
    );
    let refused = [
        (
            "/api/v1/upstream-groups/g",
            serde_json::json!({ "members": ["magic"] }),
            "magic",
        ),
        (
            "/api/v1/upstream-groups/g",
            serde_json::json!({ "members": ["quad9", "forward:corp.example#1"] }),
            "forward:corp.example#1",
        ),
        (
            "/api/v1/groups/kids",
            serde_json::json!({ "upstreams": "plugins" }),
            "plugins",
        ),
        (
            "/api/v1/groups/iot",
            serde_json::json!({ "upstreams": "forward:lab.example" }),
            "forward:lab.example",
        ),
    ];
    for (who, creds) in [("operator", &n.operator), ("admin", &n.admin)] {
        for (path, body, name) in &refused {
            for dry in [true, false] {
                let (s, v) = n.put(path, creds, dry, body.clone()).await;
                assert_eq!(
                    s,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "{who}, {path}, dry={dry}: {v}"
                );
                assert!(
                    v["detail"]
                        .as_str()
                        .unwrap_or("")
                        .contains(&format!("`{name}`")),
                    "{who}, {path}: names it: {v}"
                );
                assert!(
                    v["hint"].as_str().unwrap_or("").contains("config file"),
                    "{who}, {path}: {v}"
                );
            }
        }
    }
    let stored = crate::managed::entries(n.auth.state());
    assert!(stored.upstream_groups.iter().all(|(k, _)| k != "g"));
    assert!(stored.groups.iter().all(|(k, _)| k != "kids"));
    for (path, body) in [
        (
            "/api/v1/upstream-groups/g",
            serde_json::json!({ "members": ["quad9", "forward:corp.example#2"] }),
        ),
        (
            "/api/v1/groups/kids",
            serde_json::json!({ "upstreams": "forward:corp.example" }),
        ),
    ] {
        let (s, v) = n.put(path, &n.operator, false, body).await;
        assert_eq!(s, StatusCode::OK, "{path}: {v}");
        assert!(!v["after"].is_null(), "{path}: in effect: {v}");
    }
}
