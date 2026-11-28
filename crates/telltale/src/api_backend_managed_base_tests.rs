// REQ: API-002, API-010, CLU-003 (ADR-040, ADR-051; GitHub issue #113) — a configuration change
// made through the API is checked against the configuration the node applies: every stored entry
// with the change, merged onto what a reload merges them onto (this node's config files, or, on a
// primary promoted from replica, the files plus the cluster version it last applied as a replica).
// A change the reload would set aside, or leave out, is refused before anything is stored; a change
// it applies is accepted as before. The node here runs the real backend, and each reload runs the
// real `replication::effective`; whether a reload sets the stored entries aside is worked out with
// the reload's own merge onto a base the test builds from what it wrote, not with the code under
// test. Nothing here leaves the machine.

use std::path::Path;
use std::sync::Arc;

use serde_json::json;
use telltale_api::Backend as _;
use telltale_api::auth::{self, Auth};
use telltale_api::model::{ClientChange, ClientInput, ConfigChange};
use telltale_api::problem::Problem;
use telltale_api::{ClientWrite, ManagedKind, ManagedWrite};
use telltale_config::Config;
use telltale_store::state::State;

use super::{ApiBackend, Sources};

/// What a person is shown of a refusal: its detail and its hint, the fuller one included (the
/// node that answers a person gives that one in `hint`, `sanitize_problem`).
fn said(p: &Problem) -> String {
    format!(
        "{} | {} | {}",
        p.detail,
        p.hint.as_deref().unwrap_or(""),
        p.fuller_hint.as_deref().map_or("", |h| h.as_str())
    )
}

/// A configuration from TOML, as the loader reads the files.
fn config(toml: &str) -> Config {
    telltale_config::Loader::new()
        .toml_str("t.toml", toml)
        .env(Vec::<(String, String)>::new())
        .load()
        .map_err(|e| format!("{e:?}"))
        .unwrap()
        .config
}

/// What a reload keeps of the config files it read (`server::reload`).
fn store_files(src: &Sources, file: Config) {
    src.store_files(file);
}

/// A reload as the main loop runs one (`server::reload`), without listeners and lists: the files
/// (here, the ones kept), and the configuration in effect for this node's role
/// (`replication::effective`).
fn reload(src: &Sources) {
    let file = (*src.file_config.load_full()).clone();
    let new = crate::replication::effective(&file);
    store_files(src, file);
    src.config.store(Arc::new(new));
}

/// Makes `dir` a primary promoted from replica: a cluster member that was a replica in epoch 1 and
/// is primary in epoch 2, and that last applied, as a replica, a version whose shared sections are
/// `inherited`'s (`cluster/applied.json`, its configuration in the blob store). Returns that
/// version's shared configuration.
fn promote(dir: &Path, inherited: &Config) -> serde_json::Value {
    use telltale_cluster::node::{Identity, Role};
    use telltale_cluster::sync::{BlobStore, ClusterManifest, SCHEMA, blob_ref};
    let mut id = Identity::init(
        dir,
        "home",
        vec!["https://node.example.test:8443".into()],
        "home",
    )
    .unwrap();
    id.save_role(Role::Replica, 1).unwrap();
    id.save_role(Role::Primary, 2).unwrap();
    let shared = telltale_config::shared::shared_part(inherited);
    let bytes = serde_json::to_vec(&shared).unwrap();
    let blob = blob_ref("config.json", &bytes);
    BlobStore::open(dir).unwrap().put(&blob, &bytes).unwrap();
    let applied = ClusterManifest {
        cluster_id: id.meta.cluster_id.clone(),
        epoch: 1,
        seq: 26,
        primary: "the-other-primary".into(),
        config: blob,
        authority: "api".into(),
        schema: SCHEMA,
        ..ClusterManifest::default()
    };
    std::fs::write(
        telltale_cluster::node::dir_of(dir).join("applied.json"),
        serde_json::to_vec_pretty(&applied).unwrap(),
    )
    .unwrap();
    shared
}

/// One node with a state database, the real backend, and a reload that runs the real
/// `replication::effective`.
struct Node {
    src: Arc<Sources>,
    api: ApiBackend,
    auth: Arc<Auth>,
    /// What a reload merges the stored entries onto, built here from what the test wrote: the
    /// files, or the files with the inherited version's shared sections in place of theirs.
    base: Config,
    _dir: tempfile::TempDir,
}

impl Node {
    /// A node outside any cluster, with config files `own`.
    fn standalone(own: Config) -> Self {
        Self::new(own, None, false)
    }

    /// A cluster's first primary, never a replica: it builds on its own files.
    fn first_primary(own: Config) -> Self {
        Self::new(own, None, true)
    }

    /// A primary promoted from replica: config files `own`, and the version it last applied as a
    /// replica has `inherited`'s shared sections.
    fn promoted(own: Config, inherited: &Config) -> Self {
        Self::new(own, Some(inherited), true)
    }

    fn new(mut own: Config, inherited: Option<&Config>, member: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        own.node.data_dir = telltale_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
        let base = if let Some(inherited) = inherited {
            let shared = promote(dir.path(), inherited);
            telltale_config::shared::with_shared(&own, &shared).unwrap()
        } else {
            if member {
                telltale_cluster::node::Identity::init(
                    dir.path(),
                    "home",
                    vec!["https://node.example.test:8443".into()],
                    "home",
                )
                .unwrap();
            }
            own.clone()
        };
        let mut s = crate::http::tests::sources_in(dir.path());
        let (tx, mut rx) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<bool>>(4);
        s.reload = tx;
        let state = Arc::new(State::open(&dir.path().join("state.db")).unwrap());
        let auth = Arc::new(Auth::new(state, auth::Settings::default()));
        let src = Arc::new(s);
        let _ = src.auth.set(Arc::clone(&auth));
        store_files(&src, own);
        reload(&src);
        let applier = Arc::clone(&src);
        tokio::spawn(async move {
            while let Some(done) = rx.recv().await {
                reload(&applier);
                let _ = done.send(true);
            }
        });
        Self {
            api: ApiBackend {
                src: Arc::clone(&src),
            },
            src,
            auth,
            base,
            _dir: dir,
        }
    }

    /// Stores an entry as the UI did earlier (or a backup, or an older version), and reloads.
    fn store(&self, kind: &str, name: &str, body: &serde_json::Value) {
        self.auth
            .state()
            .put_managed(kind, name, &body.to_string(), None, None, 0, "earlier")
            .unwrap();
        reload(&self.src);
    }

    /// Removes a stored entry as a hand edit would, and reloads.
    fn unstore(&self, kind: &str, name: &str) {
        self.auth.state().delete_managed(kind, name, None).unwrap();
        reload(&self.src);
    }

    fn version(&self) -> u64 {
        self.auth.state().config_version().unwrap()
    }

    /// The names stored for `kind`.
    fn stored(&self, kind: &str) -> Vec<String> {
        self.auth
            .state()
            .managed(kind)
            .unwrap()
            .into_iter()
            .map(|m| m.name)
            .collect()
    }

    /// Whether a reload sets the stored entries aside now: the reload's merge, over everything
    /// `state.db` holds, onto [`Node::base`].
    fn falls_back(&self) -> bool {
        crate::managed::merge(&self.base, &crate::managed::entries(self.auth.state())).is_err()
    }

    /// The configuration in effect, as the last reload made it.
    fn running(&self) -> Arc<Config> {
        self.src.config.load_full()
    }

    fn has_device(&self, name: &str) -> bool {
        self.running()
            .client
            .iter()
            .any(|c| c.name.as_str() == name)
    }

    /// Whether storing `body` as `kind`/`name` (as the API would have) would leave it out of what
    /// the reload applies: the reload would set the stored entries aside, or `in_effect` doesn't
    /// find it in what it makes. What was stored under that name is put back.
    fn left_out_if_stored(
        &self,
        kind: &str,
        name: &str,
        body: &serde_json::Value,
        in_effect: fn(&Config) -> bool,
    ) -> bool {
        let state = self.auth.state();
        let had = state
            .managed(kind)
            .unwrap()
            .into_iter()
            .find(|m| m.name == name);
        state
            .put_managed(kind, name, &body.to_string(), None, None, 0, "oracle")
            .unwrap();
        let out = match crate::managed::merge(&self.base, &crate::managed::entries(state)) {
            Err(_) => true,
            Ok(c) => !in_effect(&c),
        };
        match had {
            Some(m) => {
                state
                    .put_managed(kind, name, &m.body, None, None, 0, "oracle")
                    .unwrap();
            }
            None => {
                state.delete_managed(kind, name, None).unwrap();
            }
        }
        out
    }

    async fn device(
        &self,
        name: &str,
        input: Option<ClientInput>,
        dry_run: bool,
    ) -> Result<ClientChange, Problem> {
        self.api
            .write_client(ClientWrite {
                name: name.to_owned(),
                input,
                dry_run,
                expect: None,
                by: "tests".to_owned(),
                simulate: None,
            })
            .await
    }

    async fn write(
        &self,
        kind: ManagedKind,
        name: &str,
        body: Option<serde_json::Value>,
    ) -> Result<ConfigChange, Problem> {
        self.api
            .write_managed(ManagedWrite {
                kind,
                name: name.to_owned(),
                body,
                dry_run: false,
                expect: None,
                by: "tests".to_owned(),
                simulate: None,
                by_admin: true,
            })
            .await
    }
}

/// A device's body: its new name (to rename), its match keys, the default group.
fn input(name: Option<&str>, matches: &[&str]) -> ClientInput {
    ClientInput {
        name: name.map(str::to_owned),
        matches: matches.iter().map(|m| (*m).to_owned()).collect(),
        groups: Vec::new(),
        kind: None,
    }
}

/// A stored device's body, as the API stores one.
fn device_row(name: &str, matches: &[&str]) -> serde_json::Value {
    json!({ "name": name, "match": matches, "groups": ["default"] })
}

/// The config file of the node in issue #113 (its shared sections are replaced by the cluster's
/// once it follows a primary, and stay so when it is promoted).
const OWN: &str = r#"
[[client]]
name = "homeassistant"
match = ["192.168.0.5"]
"#;

/// The version the other primary published, which this node last applied as a replica: `Newt`
/// came from this node, made in the UI while it was primary before.
const INHERITED: &str = r#"
[[upstream]]
name = "cloudflare"
url = "udp://192.0.2.53:53"

[[upstream_group]]
name = "default"
members = ["cloudflare"]

[[group]]
name = "kids"

[[client]]
name = "homeassistant"
match = ["192.168.0.5"]

[[client]]
name = "Newt"
match = ["192.168.0.55"]
groups = ["default"]

[[client]]
name = "tv"
match = ["192.168.0.70"]
groups = ["kids"]

[[record]]
name = "printer.lan"
type = "A"
value = "192.168.0.7"

[[route]]
match_suffix = ["corp.example"]
upstream_group = "default"
"#;

/// The primary of issue #113: promoted from replica, it builds on [`INHERITED`]. `Newt` is still
/// stored (it was made in the UI here, before), and `tablet`, a DoH client ID, was made in the UI
/// since the promotion, so it is stored only.
fn newt_primary() -> Node {
    let n = Node::promoted(config(OWN), &config(INHERITED));
    n.store(
        crate::managed::CLIENT,
        "Newt",
        &device_row("Newt", &["192.168.0.55"]),
    );
    n.store(
        crate::managed::CLIENT,
        "tablet",
        &device_row("tablet", &["id:tablet"]),
    );
    assert!(!n.falls_back(), "the stored devices apply");
    assert!(n.has_device("tablet") && n.has_device("Newt"));
    n
}

/// What a refused or accepted write says, for a failure message.
fn outcome<T>(r: &Result<T, Problem>, n: &Node) -> String {
    match r {
        Ok(_) => format!(
            "accepted; a reload now {}",
            if n.falls_back() {
                "sets every stored entry aside"
            } else {
                "applies the stored entries"
            }
        ),
        Err(p) => format!("refused: {} {}", p.status, p.detail),
    }
}

/// REQ: API-010, CLU-003 (ADR-040, ADR-051; issue #113) — on a primary promoted from replica,
/// `Newt` is in the version it builds on, and also stored (it was made in the UI here, while this
/// node was primary before). Renaming it with the same address would leave the address on two
/// devices in the merge the reload applies, which then sets every stored device aside (`tablet`'s
/// client ID would stop working on every node). The rename is refused, saved or dry run, and so is
/// a new device on `Newt`'s address; what a person is shown names `Newt` and where it comes from,
/// not only places in a list (an agent that may not read every device is shown less:
/// `agt_004_a_group_agent_is_not_told_which_device_holds_a_key`). Nothing is stored, the
/// configuration version doesn't move, and the devices made in the UI stay in effect.
#[tokio::test]
async fn api_010_rename_onto_an_address_the_base_still_holds_is_refused() {
    let n = newt_primary();
    let version = n.version();
    for (what, name, body) in [
        (
            "the rename",
            "Newt",
            input(Some("Newt-pve1"), &["192.168.0.55"]),
        ),
        (
            "a new device on its address",
            "Newt-pve1",
            input(None, &["192.168.0.55"]),
        ),
    ] {
        for dry_run in [false, true] {
            let r = n.device(name, Some(body.clone()), dry_run).await;
            match &r {
                Err(p) => {
                    assert!(
                        (400..500).contains(&p.status),
                        "{what}, dry run {dry_run}: {p:?}"
                    );
                    assert!(
                        said(p).contains("`Newt`")
                            && said(p).contains("the cluster version this node builds on"),
                        "{what}: names the device that holds the address, and where it is: {p:?}"
                    );
                }
                Ok(_) => panic!("{what}, dry run {dry_run}: {}", outcome(&r, &n)),
            }
        }
    }
    assert_eq!(
        n.stored(crate::managed::CLIENT),
        ["Newt", "tablet"],
        "nothing was stored"
    );
    assert_eq!(
        n.version(),
        version,
        "the configuration version didn't move"
    );
    assert!(!n.falls_back());
    assert!(n.has_device("tablet"), "the devices made in the UI apply");
}

/// REQ: API-010 (ADR-040; issue #113) — the same on a standalone node, with the files: `nas` is
/// stored (made in the UI before the config file gained a `[[client]]` of that name), and the
/// files' `nas` is the one in effect. Renaming the stored copy with the files' address, changing
/// the files' device in place, and giving a stored device the files' name are all refused, saved
/// or dry run, and what a person is shown names `nas`; nothing is stored and the stored devices
/// stay in effect. (A rename of the stored copy to a free name and address is accepted, as it was:
/// `api_010_renaming_a_hidden_stored_device_to_a_free_name_applies_as_before`.)
#[tokio::test]
async fn api_010_rename_shadowed_by_a_file_device_is_refused() {
    let n = Node::standalone(config(
        r#"
[[client]]
name = "nas"
match = ["192.168.1.10"]
"#,
    ));
    n.store(
        crate::managed::CLIENT,
        "nas",
        &device_row("nas", &["192.168.1.10"]),
    );
    n.store(
        crate::managed::CLIENT,
        "tv",
        &device_row("tv", &["192.168.1.20"]),
    );
    assert!(!n.falls_back() && n.has_device("tv"));
    let version = n.version();
    for (what, name, body) in [
        (
            "renaming the stored copy, same address",
            "nas",
            input(Some("nas-2"), &["192.168.1.10"]),
        ),
        (
            "changing the files' device in place",
            "nas",
            input(None, &["192.168.1.11"]),
        ),
        (
            "giving a stored device the files' name",
            "tv",
            input(Some("nas"), &["192.168.1.20"]),
        ),
    ] {
        for dry_run in [false, true] {
            let r = n.device(name, Some(body.clone()), dry_run).await;
            match &r {
                Err(p) => {
                    assert!((400..500).contains(&p.status), "{what}: {p:?}");
                    assert!(said(p).contains("`nas`"), "{what}: {p:?}");
                }
                Ok(_) => panic!("{what} (dry run {dry_run}): {}", outcome(&r, &n)),
            }
        }
    }
    assert_eq!(n.stored(crate::managed::CLIENT), ["nas", "tv"]);
    assert_eq!(n.version(), version);
    assert!(!n.falls_back() && n.has_device("tv"));
}

/// A write of one API-written kind, and where its result shows in the configuration in effect.
struct Case {
    what: &'static str,
    write: Write,
    in_effect: fn(&Config) -> bool,
}

enum Write {
    Device(&'static str, ClientInput),
    Managed(ManagedKind, &'static str, serde_json::Value),
}

impl Node {
    async fn send(&self, w: &Write) -> Result<(), Problem> {
        match w {
            Write::Device(name, body) => self
                .device(name, Some(body.clone()), false)
                .await
                .map(|_| ()),
            Write::Managed(kind, name, body) => self
                .write(*kind, name, Some(body.clone()))
                .await
                .map(|_| ()),
        }
    }
}

/// One write per kind written through the API, in an order that lets each name what an earlier
/// one made.
#[allow(clippy::too_many_lines)] // one case per kind
fn every_kind() -> Vec<Case> {
    fn has<T>(items: &[T], name: impl Fn(&T) -> &str, want: &str) -> bool {
        items.iter().any(|i| name(i) == want)
    }
    vec![
        Case {
            what: "device",
            write: Write::Device("speaker", input(None, &["192.168.0.80"])),
            in_effect: |c| has(&c.client, |x| x.name.as_str(), "speaker"),
        },
        Case {
            what: "local name",
            write: Write::Managed(
                ManagedKind::Record,
                "nas2.lan",
                json!({ "records": [{ "type": "A", "value": "192.168.0.60" }] }),
            ),
            in_effect: |c| has(&c.record, |x| x.name.as_str(), "nas2.lan"),
        },
        Case {
            what: "forwarded domain",
            write: Write::Managed(
                ManagedKind::Forward,
                "lab.example",
                json!({ "servers": ["192.0.2.1"] }),
            ),
            in_effect: |c| {
                c.route
                    .iter()
                    .any(|r| r.match_suffix.iter().any(|s| s.as_str() == "lab.example"))
            },
        },
        Case {
            what: "quick rule",
            write: Write::Managed(
                ManagedKind::Rule,
                "r-ads",
                json!({ "action": "block", "domain": "ads.example.com" }),
            ),
            in_effect: |c| has(&c.rule, |x| x.id.as_str(), "r-ads"),
        },
        Case {
            what: "upstream",
            write: Write::Managed(
                ManagedKind::Upstream,
                "quad9",
                json!({ "url": "udp://192.0.2.9:53" }),
            ),
            in_effect: |c| has(&c.upstream, |x| x.name.as_str(), "quad9"),
        },
        Case {
            what: "upstream group",
            write: Write::Managed(
                ManagedKind::UpstreamGroup,
                "fast",
                json!({ "members": ["quad9"] }),
            ),
            in_effect: |c| has(&c.upstream_group, |x| x.name.as_str(), "fast"),
        },
        Case {
            what: "list",
            write: Write::Managed(
                ManagedKind::List,
                "extra",
                json!({ "rules": ["tracker.example.com"] }),
            ),
            in_effect: |c| has(&c.list, |x| x.name.as_str(), "extra"),
        },
        Case {
            what: "group",
            write: Write::Managed(ManagedKind::Group, "media", json!({})),
            in_effect: |c| has(&c.group, |x| x.name.as_str(), "media"),
        },
        Case {
            what: "alert destination",
            write: Write::Managed(
                ManagedKind::AlertDestination,
                "hook",
                json!({ "type": "webhook", "url": "https://hooks.example.test/x" }),
            ),
            in_effect: |c| has(&c.alerts.destination, |x| x.name.as_str(), "hook"),
        },
        Case {
            what: "alert rule",
            write: Write::Managed(
                ManagedKind::AlertRule,
                "nodes",
                json!({ "when": "node_down", "to": ["hook"] }),
            ),
            in_effect: |c| has(&c.alerts.rule, |x| x.name.as_str(), "nodes"),
        },
        Case {
            what: "schedule",
            write: Write::Managed(
                ManagedKind::Schedule,
                "bedtime",
                json!({ "action": "block_all",
                    "window": [{ "days": ["daily"], "start": "21:00", "end": "07:00" }] }),
            ),
            in_effect: |c| has(&c.schedule, |x| x.name.as_str(), "bedtime"),
        },
        Case {
            what: "anomaly mute",
            write: Write::Managed(
                ManagedKind::AnomalyMute,
                "quiet",
                json!({ "devices": ["192.168.0.80"], "kinds": ["beacon"] }),
            ),
            in_effect: |c| has(&c.anomaly_mute, |x| x.name.as_str(), "quiet"),
        },
        Case {
            what: "kubernetes map rule",
            write: Write::Managed(
                ManagedKind::KubernetesMap,
                "media/*/*",
                json!({ "group": "media" }),
            ),
            in_effect: |c| c.kubernetes.map.iter().any(|r| r.key() == "media/*/*"),
        },
        Case {
            what: "router",
            write: Write::Managed(
                ManagedKind::Router,
                "udm",
                json!({ "type": "unifi", "url": "http://127.0.0.1:1", "api_key": "pasted",
                    "offline_days": 0 }),
            ),
            in_effect: |c| has(&c.router, |x| x.name.as_str(), "udm"),
        },
        Case {
            what: "rate limit",
            write: Write::Managed(ManagedKind::RateLimit, "default", json!({ "queries": 500 })),
            in_effect: |c| c.ratelimit.queries == 500,
        },
        Case {
            what: "exclusions",
            write: Write::Managed(
                ManagedKind::Exclusions,
                "default",
                json!({ "names": ["ntp.org"] }),
            ),
            in_effect: |c| c.exclusions.names.iter().any(|n| n.as_str() == "ntp.org"),
        },
        Case {
            what: "simulation settings",
            write: Write::Managed(ManagedKind::Simulate, "default", json!({ "max_secs": 30 })),
            in_effect: |c| c.simulate.max_secs == 30,
        },
        Case {
            what: "rollout settings",
            write: Write::Managed(ManagedKind::Rollout, "default", json!({ "bake_secs": 120 })),
            in_effect: |c| c.cluster.rollout.bake_secs == 120,
        },
    ]
}

/// Every case of [`every_kind`] on `n`, which applies its stored entries: each is accepted and in
/// effect after its reload, and no reload sets the stored entries aside. Returns what went wrong.
async fn all_accepted(n: &Node, node: &str) -> Vec<String> {
    let mut wrong = Vec::new();
    for c in every_kind() {
        let r = n.send(&c.write).await;
        if r.is_err() || n.falls_back() || !(c.in_effect)(&n.running()) {
            wrong.push(format!(
                "{node}, {}: {} (in effect: {})",
                c.what,
                outcome(&r, n),
                (c.in_effect)(&n.running())
            ));
        }
    }
    wrong
}

/// REQ: API-002, API-010, CLU-003 (ADR-040; issue #113) — a write is accepted only if the reload
/// that follows applies it, for every kind the API writes. While the stored devices of a promoted
/// primary don't apply on the version it builds on (`Newt-pve1`, stored by the rename of the
/// issue, has `Newt`'s address), every reload sets the stored entries aside, so every write is
/// refused and nothing is stored (each write leaves `Newt-pve1` in place, so with it stored too
/// the reload would still set everything aside). Once that row is gone, the same writes are all
/// accepted and in effect, and none makes the reload set anything aside; and so on a standalone
/// node and on a primary that was never a replica (they check writes as before).
#[tokio::test]
async fn api_002_an_accepted_plan_never_falls_back() {
    let n = newt_primary();
    // The state the rename of the issue left: the row moved to `Newt-pve1`, same address.
    n.unstore(crate::managed::CLIENT, "Newt");
    n.store(
        crate::managed::CLIENT,
        "Newt-pve1",
        &device_row("Newt-pve1", &["192.168.0.55"]),
    );
    assert!(n.falls_back(), "the stored devices don't apply");
    let mut wrong = Vec::new();
    for c in every_kind() {
        let kinds = [
            crate::managed::CLIENT,
            crate::managed::RECORD,
            crate::managed::FORWARD,
            crate::managed::RULE,
            crate::managed::UPSTREAM,
            crate::managed::UPSTREAM_GROUP,
            crate::managed::LIST,
            crate::managed::GROUP,
            crate::managed::ALERT_DESTINATION,
            crate::managed::ALERT_RULE,
            crate::managed::SCHEDULE,
            crate::managed::ANOMALY_MUTE,
            crate::managed::KUBERNETES_MAP,
            crate::managed::ROUTER,
            crate::managed::RATELIMIT,
            crate::managed::EXCLUSIONS,
            crate::managed::SIMULATE,
            crate::managed::ROLLOUT,
        ];
        let before: Vec<Vec<String>> = kinds.iter().map(|k| n.stored(k)).collect();
        let version = n.version();
        let r = n.send(&c.write).await;
        let after: Vec<Vec<String>> = kinds.iter().map(|k| n.stored(k)).collect();
        if r.is_ok() || after != before || n.version() != version {
            wrong.push(format!(
                "promoted, stored devices not applying, {}: {}",
                c.what,
                outcome(&r, &n)
            ));
        }
        if let Err(p) = &r
            && !(400..500).contains(&p.status)
        {
            wrong.push(format!("{}: not a 4xx: {p:?}", c.what));
        }
    }
    // The row the rename stored, removed by hand: the stored devices apply again.
    n.unstore(crate::managed::CLIENT, "Newt-pve1");
    assert!(!n.falls_back() && n.has_device("tablet"));
    wrong.extend(all_accepted(&n, "promoted").await);
    wrong.extend(all_accepted(&Node::standalone(config(OWN)), "standalone").await);
    wrong.extend(all_accepted(&Node::first_primary(config(OWN)), "first primary").await);
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The config file of a node whose own shared sections differ from the cluster's: on a promoted
/// primary they are replaced by those of the version it builds on (CLU-006), so what only they
/// define isn't in effect there.
const OWN_DIFFERENT: &str = r#"
[[upstream]]
name = "own-up"
url = "udp://192.0.2.99:53"

[[upstream_group]]
name = "default"
members = ["own-up"]

[[client]]
name = "own-dev"
match = ["192.168.0.90"]

[[record]]
name = "nas.lan"
type = "A"
value = "192.168.0.10"
"#;

/// One write to a promoted primary, what the reload makes of it, and what the API would have
/// stored (for [`Node::left_out_if_stored`]).
struct Inherited {
    what: &'static str,
    kind: ManagedKind,
    name: &'static str,
    body: Option<serde_json::Value>,
    row: (&'static str, serde_json::Value),
    in_effect: fn(&Config) -> bool,
    accepted: bool,
}

/// REQ: CLU-003, API-002 (ADR-051, ADR-040; issue #113) — a primary promoted from replica builds
/// on the version it last applied, in place of its own files' shared sections, and checks a write
/// against that: a rule may name a device, and an upstream group an upstream, that only that
/// version has, and a local name its own file defines is free here; a rule naming a device, or a
/// group naming an upstream, that only its own file has is refused (the reload would set every
/// stored entry aside), and so are a local name and a forwarded domain the version already has
/// (the reload would leave them out), and hiding a group a device of that version is in. What is
/// accepted is in effect after its reload; what is refused stores nothing, and, stored anyway,
/// would be left out.
#[allow(clippy::too_many_lines)] // one case per kind of check
#[tokio::test]
async fn clu_003_promoted_primary_checks_writes_on_its_inherited_base() {
    let n = Node::promoted(config(OWN_DIFFERENT), &config(INHERITED));
    assert!(!n.falls_back());
    let rule = |id: &str, device: &str| {
        let body = json!({ "action": "block", "domain": "games.example.com", "devices": [device] });
        let row = super::rule_of(&body, id, "tests", None).unwrap();
        (body, serde_json::to_value(row).unwrap())
    };
    let (tv_rule, tv_row) = rule("r-tv", "tv");
    let (own_rule, own_row) = rule("r-own", "own-dev");
    let cases = [
        Inherited {
            what: "a rule naming a device of the version this node builds on",
            kind: ManagedKind::Rule,
            name: "r-tv",
            body: Some(tv_rule),
            row: (crate::managed::RULE, tv_row),
            in_effect: |c| c.rule.iter().any(|r| r.id.as_str() == "r-tv"),
            accepted: true,
        },
        Inherited {
            what: "a rule naming a device only this node's file has",
            kind: ManagedKind::Rule,
            name: "r-own",
            body: Some(own_rule),
            row: (crate::managed::RULE, own_row),
            in_effect: |c| c.rule.iter().any(|r| r.id.as_str() == "r-own"),
            accepted: false,
        },
        Inherited {
            what: "an upstream group of an upstream of that version",
            kind: ManagedKind::UpstreamGroup,
            name: "fast",
            body: Some(json!({ "members": ["cloudflare"] })),
            row: (
                crate::managed::UPSTREAM_GROUP,
                json!({ "name": "fast", "members": ["cloudflare"] }),
            ),
            in_effect: |c| c.upstream_group.iter().any(|g| g.name.as_str() == "fast"),
            accepted: true,
        },
        Inherited {
            what: "an upstream group of an upstream only this node's file has",
            kind: ManagedKind::UpstreamGroup,
            name: "slow",
            body: Some(json!({ "members": ["own-up"] })),
            row: (
                crate::managed::UPSTREAM_GROUP,
                json!({ "name": "slow", "members": ["own-up"] }),
            ),
            in_effect: |c| c.upstream_group.iter().any(|g| g.name.as_str() == "slow"),
            accepted: false,
        },
        Inherited {
            what: "a local name only this node's file defines",
            kind: ManagedKind::Record,
            name: "nas.lan",
            body: Some(json!({ "records": [{ "type": "A", "value": "192.168.0.11" }] })),
            row: (
                crate::managed::RECORD,
                json!([{ "type": "A", "value": "192.168.0.11" }]),
            ),
            in_effect: |c| {
                c.record
                    .iter()
                    .any(|r| r.name.as_str() == "nas.lan" && r.value.as_str() == "192.168.0.11")
            },
            accepted: true,
        },
        Inherited {
            what: "a local name the version already has",
            kind: ManagedKind::Record,
            name: "printer.lan",
            body: Some(json!({ "records": [{ "type": "A", "value": "192.168.0.8" }] })),
            row: (
                crate::managed::RECORD,
                json!([{ "type": "A", "value": "192.168.0.8" }]),
            ),
            in_effect: |c| {
                c.record
                    .iter()
                    .any(|r| r.name.as_str() == "printer.lan" && r.value.as_str() == "192.168.0.8")
            },
            accepted: false,
        },
        Inherited {
            what: "a forwarded domain the version already routes",
            kind: ManagedKind::Forward,
            name: "corp.example",
            body: Some(json!({ "servers": ["192.0.2.1"] })),
            row: (crate::managed::FORWARD, json!({ "servers": ["192.0.2.1"] })),
            in_effect: |c| {
                c.upstream_group
                    .iter()
                    .any(|g| g.name.as_str() == "forward:corp.example")
            },
            accepted: false,
        },
        Inherited {
            what: "hiding a group a device of that version is in",
            kind: ManagedKind::Group,
            name: "kids",
            body: None,
            row: (crate::managed::GROUP, json!({ "hidden": true })),
            in_effect: |c| !c.group.iter().any(|g| g.name.as_str() == "kids"),
            accepted: false,
        },
    ];
    let mut wrong = Vec::new();
    for c in cases {
        let (kind, row) = &c.row;
        let stored = n.stored(kind);
        let version = n.version();
        let r = n.write(c.kind, c.name, c.body.clone()).await;
        if c.accepted {
            if r.is_err() || n.falls_back() || !(c.in_effect)(&n.running()) {
                wrong.push(format!("{}: {}", c.what, outcome(&r, &n)));
            }
            continue;
        }
        if r.is_ok() || n.stored(kind) != stored || n.version() != version {
            wrong.push(format!("{}: {}", c.what, outcome(&r, &n)));
            continue;
        }
        // Refused: stored anyway, the reload wouldn't apply it.
        if !n.left_out_if_stored(kind, c.name, row, c.in_effect) {
            wrong.push(format!(
                "{}: refused, but the reload would apply it: {}",
                c.what,
                outcome(&r, &n)
            ));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The configuration a device write was checked against before this change, rebuilt here: the
/// running configuration without the device (by its old and new name), with the new one at the
/// end, validated alone. Clients are compared by name, since their order doesn't matter.
fn plan_as_before(
    running: &Config,
    w: &ClientWrite,
    after: Option<&telltale_config::ClientConfig>,
) -> Result<(Config, Vec<String>), u16> {
    let mut c = running.clone();
    let new_name = after.map(|a| a.name.to_string());
    c.client
        .retain(|x| x.name.as_str() != w.name && Some(x.name.as_str()) != new_name.as_deref());
    if let Some(a) = after {
        c.client.push(a.clone());
    }
    match telltale_config::validate_config(&c) {
        Ok(warnings) => Ok((by_name(c), warnings)),
        Err(_) => Err(422),
    }
}

/// `c` with its clients in name order.
fn by_name(mut c: Config) -> Config {
    c.client
        .sort_by(|a, b| a.name.as_str().cmp(b.name.as_str()));
    c
}

/// REQ: API-010, API-002 (ADR-040; issue #113) — on a standalone node and on a primary that was
/// never a replica, a device write is planned as before: an accepted write gets the same
/// configuration to simulate (its devices in any order) and the same warnings (here: no upstream
/// is configured), and a write refused for an invalid configuration still is.
#[tokio::test]
async fn api_010_a_device_write_on_a_node_without_an_inherited_version_is_planned_as_before() {
    let files = r#"
[[group]]
name = "kids"

[[client]]
name = "nas"
match = ["192.168.1.10"]
"#;
    for (node, n) in [
        ("standalone", Node::standalone(config(files))),
        ("first primary", Node::first_primary(config(files))),
    ] {
        n.store(
            crate::managed::CLIENT,
            "phone",
            &device_row("phone", &["192.168.1.30"]),
        );
        n.store(
            crate::managed::CLIENT,
            "tv",
            &device_row("tv", &["192.168.1.20"]),
        );
        let kids = |name: Option<&str>, m: &[&str]| ClientInput {
            groups: vec!["kids".to_owned()],
            ..input(name, m)
        };
        let writes = [
            (
                "a new device",
                "speaker",
                Some(input(None, &["192.168.1.40"])),
            ),
            (
                "a change of groups",
                "tv",
                Some(kids(None, &["192.168.1.20"])),
            ),
            (
                "a rename",
                "tv",
                Some(input(Some("tv-2"), &["192.168.1.21"])),
            ),
            ("a delete", "phone", None),
            (
                "an address another device has",
                "speaker",
                Some(input(None, &["192.168.1.10"])),
            ),
            (
                "an unknown group",
                "speaker",
                Some(ClientInput {
                    groups: vec!["nope".to_owned()],
                    ..input(None, &["192.168.1.41"])
                }),
            ),
        ];
        for (what, name, body) in writes {
            let w = ClientWrite {
                name: name.to_owned(),
                input: body,
                dry_run: true,
                expect: None,
                by: "tests".to_owned(),
                simulate: None,
            };
            let plan = super::plan_client(&n.src, n.auth.state(), &w);
            let after = w.input.as_ref().map(|i| {
                let name = i.name.clone().unwrap_or_else(|| w.name.clone());
                let groups = if i.groups.is_empty() {
                    vec!["default".to_owned()]
                } else {
                    i.groups.clone()
                };
                serde_json::from_value::<telltale_config::ClientConfig>(
                    json!({ "name": name, "match": i.matches, "groups": groups }),
                )
                .unwrap()
            });
            match (plan, plan_as_before(&n.running(), &w, after.as_ref())) {
                (Ok(p), Ok((candidate, warnings))) => {
                    assert_eq!(by_name((*p.candidate).clone()), candidate, "{node}, {what}");
                    assert!(!warnings.is_empty(), "{node}, {what}: a warning to compare");
                    assert_eq!(p.warnings, warnings, "{node}, {what}");
                }
                (Err(p), Err(status)) => assert_eq!(p.status, status, "{node}, {what}: {p:?}"),
                (p, before) => panic!(
                    "{node}, {what}: now {:?}, before {:?}",
                    p.map(|p| p.impact),
                    before.map(|_| ())
                ),
            }
        }
    }
}

/// REQ: API-010, CLU-003 (ADR-040; issue #113) — the way back through the API: a stored device
/// the configuration in effect doesn't use can be deleted. After the rename of the issue
/// (`Newt-pve1` stored with `Newt`'s address), the stored devices don't apply, and `Newt-pve1` is
/// in effect nowhere. Deleting it (a dry run first, which stores nothing) says what it was and that
/// it isn't in effect, removes the row, and the stored devices apply again. A stored copy of a
/// device the base has can be deleted too, and the base's device stays; so on a standalone node
/// with the files' device. With two rows that keep the stored devices from applying, each delete
/// is accepted: after the first they still don't apply, and its warnings say why; after the
/// second they do. A name with no stored row and no device is still not found.
#[tokio::test]
async fn api_010_delete_removes_a_stored_device_not_in_effect() {
    let client = crate::managed::CLIENT;
    let n = newt_primary();
    n.unstore(client, "Newt");
    n.store(
        client,
        "Newt-pve1",
        &device_row("Newt-pve1", &["192.168.0.55"]),
    );
    assert!(n.falls_back() && !n.has_device("tablet") && !n.has_device("Newt-pve1"));
    let version = n.version();
    let dry = n.device("Newt-pve1", None, true).await;
    let dry = dry.unwrap_or_else(|p| panic!("the dry run of the delete: {p:?}"));
    assert!(!dry.applied, "{dry:?}");
    assert_eq!(
        n.stored(client),
        ["Newt-pve1", "tablet"],
        "a dry run stores nothing"
    );
    assert_eq!(n.version(), version);
    assert_eq!(
        dry.before.as_ref().map(|b| b.name.as_str()),
        Some("Newt-pve1"),
        "{dry:?}"
    );
    assert!(dry.impact.contains("isn't in effect"), "{dry:?}");
    let done = n.device("Newt-pve1", None, false).await;
    let done = done.unwrap_or_else(|p| panic!("the delete: {p:?}"));
    assert!(done.applied && done.config_version > version, "{done:?}");
    assert_eq!(n.stored(client), ["tablet"]);
    assert!(
        !n.falls_back() && n.has_device("tablet") && n.has_device("Newt"),
        "the stored devices apply again"
    );

    // A stored copy of a device of the version this node builds on.
    n.store(client, "Newt", &device_row("Newt", &["192.168.0.55"]));
    let copy = n.device("Newt", None, false).await;
    let copy = copy.unwrap_or_else(|p| panic!("deleting the stored copy: {p:?}"));
    assert!(copy.impact.contains("isn't in effect"), "{copy:?}");
    assert_eq!(n.stored(client), ["tablet"]);
    assert!(n.has_device("Newt") && n.has_device("tablet") && !n.falls_back());

    // Two rows that keep the stored devices from applying (`Newt`'s and `homeassistant`'s addresses).
    n.store(client, "a", &device_row("a", &["192.168.0.55"]));
    n.store(client, "b", &device_row("b", &["192.168.0.5"]));
    assert!(n.falls_back());
    let first = n.device("a", None, false).await;
    let first = first.unwrap_or_else(|p| panic!("the first delete: {p:?}"));
    assert!(
        first.warnings.iter().any(|w| w.contains("`192.168.0.5`")),
        "says what still keeps them from applying: {first:?}"
    );
    assert!(n.falls_back() && n.stored(client) == ["b", "tablet"]);
    if let Err(p) = n.device("b", None, false).await {
        panic!("the second delete: {p:?}");
    }
    assert_eq!(n.stored(client), ["tablet"]);
    assert!(!n.falls_back() && n.has_device("tablet"));

    let missing = n.device("nobody", None, false).await;
    assert_eq!(missing.map(|_| ()).unwrap_err().status, 404);

    // A standalone node: the files' `nas` hides the stored one.
    let s = Node::standalone(config(
        r#"
[[client]]
name = "nas"
match = ["192.168.1.10"]
"#,
    ));
    s.store(client, "nas", &device_row("nas", &["192.168.1.10"]));
    let r = s.device("nas", None, false).await;
    let r = r.unwrap_or_else(|p| panic!("deleting the stored nas: {p:?}"));
    assert!(r.impact.contains("isn't in effect"), "{r:?}");
    assert!(s.stored(client).is_empty() && s.has_device("nas") && !s.falls_back());
}

/// REQ: API-010, CLU-003 (ADR-040; issue #113) — a stored device that a device of the base hides
/// (the files', or one of the version a promoted primary builds on) can be renamed to a free name
/// with an address no other device has, as it could before: the write is accepted, the stored row
/// takes the new name, and after the reload both devices are in effect, the base's one unchanged.
#[tokio::test]
async fn api_010_renaming_a_hidden_stored_device_to_a_free_name_applies_as_before() {
    let client = crate::managed::CLIENT;
    let standalone = Node::standalone(config(
        r#"
[[client]]
name = "nas"
match = ["192.168.1.10"]
"#,
    ));
    standalone.store(client, "nas", &device_row("nas", &["192.168.1.12"]));
    let promoted = newt_primary();
    promoted.store(client, "Newt", &device_row("Newt", &["192.168.0.56"]));
    for (node, n, from, to, address, kept, kept_address) in [
        (
            "standalone",
            &standalone,
            "nas",
            "nas-old",
            "192.168.1.12",
            "nas",
            "192.168.1.10",
        ),
        (
            "promoted",
            &promoted,
            "Newt",
            "Newt-old",
            "192.168.0.56",
            "Newt",
            "192.168.0.55",
        ),
    ] {
        assert!(!n.falls_back(), "{node}");
        let version = n.version();
        let r = n
            .device(from, Some(input(Some(to), &[address])), false)
            .await;
        let done = r.unwrap_or_else(|p| panic!("{node}: the rename was refused: {p:?}"));
        assert!(
            done.applied && done.config_version > version,
            "{node}: {done:?}"
        );
        assert!(n.stored(client).iter().any(|s| s == to), "{node}");
        assert!(!n.stored(client).iter().any(|s| s == from), "{node}");
        assert!(!n.falls_back(), "{node}: the stored devices apply");
        let running = n.running();
        let has = |name: &str, key: &str| {
            running
                .client
                .iter()
                .any(|c| c.name.as_str() == name && c.match_keys.iter().any(|k| k.as_str() == key))
        };
        assert!(
            has(to, address) && has(kept, kept_address),
            "{node}: both in effect: {:?}",
            running.client
        );
    }
}

/// An API token for `user`, with `scope`, and, for an agent, its scopes and group.
fn token(auth: &Auth, user: i64, scope: &str, agent: Option<(&str, Option<&str>)>) -> String {
    let (id, secret) = (auth::crypto::random_id(), auth::crypto::random_secret());
    let now = super::local_access_tests::now();
    auth.state()
        .create_token(
            &id,
            user,
            "tests",
            &auth::crypto::secret_hash(&secret),
            scope,
            None,
            now,
        )
        .unwrap();
    if let Some((scopes, group)) = agent {
        auth.state()
            .set_token_agent(&id, scopes, group, None)
            .unwrap();
    }
    format!("Bearer tt_{id}_{secret}")
}

/// REQ: AGT-004, API-010 (ADR-064, ADR-191; issue #113) — an agent token limited to a group may add
/// a device in its group, and a dry run stores nothing; a refusal for a match key that a device
/// outside its view holds doesn't name that device to it (its detail doesn't give the merge's
/// reasons, which can name devices it can't read, and its hint stays plain), even with
/// `querylog:read`. A person (here an operator) gets the reasons, and is told which device holds
/// the key, and where it is defined.
#[tokio::test]
async fn agt_004_a_group_agent_is_not_told_which_device_holds_a_key() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;
    let n = Node::standalone(config(
        r#"
[[group]]
name = "kids"

[[client]]
name = "nas"
match = ["192.168.1.10"]
"#,
    ));
    let app = telltale_api::router(
        Arc::new(ApiBackend {
            src: Arc::clone(&n.src),
        }),
        Arc::clone(&n.auth),
    );
    let olga = n
        .auth
        .create_user(
            "olga",
            "an operator password",
            auth::Role::Operator,
            false,
            super::local_access_tests::now(),
        )
        .unwrap();
    let operator = token(&n.auth, olga.id, "write", None);
    let group_agent = token(
        &n.auth,
        olga.id,
        "write",
        Some(("config:write:clients querylog:read", Some("kids"))),
    );
    for (who, creds, told) in [
        ("operator", &operator, true),
        ("agent limited to kids", &group_agent, false),
    ] {
        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/clients/probe?dryRun=true")
            .header("authorization", creds.as_str())
            .header("x-telltale-reason", "managed base tests")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "match": ["192.168.1.10"], "groups": ["kids"] }).to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        assert_eq!(status.as_u16(), 422, "{who}: {v}");
        assert_eq!(
            v["detail"]
                .as_str()
                .is_some_and(|d| d.contains("`192.168.1.10`")),
            told,
            "{who}: the reason: {v}"
        );
        assert_eq!(v.to_string().contains("`nas`"), told, "{who}: {v}");
        if told {
            assert!(
                v["hint"]
                    .as_str()
                    .is_some_and(|h| h.contains("in the config files")),
                "{who}: {v}"
            );
        }
    }
    assert_eq!(
        n.stored(crate::managed::CLIENT),
        Vec::<String>::new(),
        "a dry run stores nothing"
    );
}

/// REQ: CLU-003, FLT-005 (ADR-051, ADR-067; issue #113) — on a primary promoted from replica, the
/// quick rules of the version it builds on are that version's, not this node's API's: listed with
/// `source` `file`, so the UI doesn't offer them for editing and the expiry sweep (which removes
/// expired rules whose `source` is `api`) leaves an expired one alone, instead of trying again
/// every 5 s. Changing one is refused with words that say where it comes from. A rule made here
/// since the promotion is `api`, and swept once it has expired.
#[tokio::test]
async fn clu_003_an_inherited_quick_rule_is_not_offered_as_api_and_is_not_swept() {
    let inherited = config(&format!(
        r#"{INHERITED}
[[rule]]
id = "r-old"
action = "block"
domain = "old.example.com"
expires = "2026-01-01T00:00:00Z"

[[rule]]
id = "r-inh"
action = "block"
domain = "games.example.com"
"#
    ));
    let n = Node::promoted(config(OWN), &inherited);
    n.store(
        crate::managed::RULE,
        "r-mine",
        &json!({ "id": "r-mine", "action": "block", "domain": "mine.example.com",
            "expires": "2026-01-01T00:00:00Z" }),
    );
    assert!(!n.falls_back());
    let rules = n.api.rules();
    let source = |id: &str| {
        rules
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.source.clone())
            .unwrap_or_default()
    };
    assert_eq!(
        (source("r-old"), source("r-inh"), source("r-mine")),
        ("file".to_owned(), "file".to_owned(), "api".to_owned()),
        "{rules:?}"
    );
    // The sweep's choice (`spawn_rule_sweep`): expired, and made through the API.
    let swept: Vec<&str> = rules
        .iter()
        .filter(|r| r.source == "api" && r.expires_in_seconds == Some(0))
        .map(|r| r.id.as_str())
        .collect();
    assert_eq!(swept, ["r-mine"]);
    let p = n
        .write(
            ManagedKind::Rule,
            "r-inh",
            Some(json!({ "action": "allow", "domain": "games.example.com" })),
        )
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(p.status, 409, "{p:?}");
    assert!(
        p.detail.contains("the cluster version this node builds on"),
        "says where the rule comes from: {p:?}"
    );
}

/// Runs `test` on a runtime of its own while no other test that may take the node's one simulation
/// slot runs (the slot is a static, one per test binary, and `simulate::tests` need it free).
fn holding_the_slot(test: impl std::future::Future<Output = ()>) {
    let _one = crate::simulate::slot_tests();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(test);
}

/// REQ: OBS-024, API-002 (ADR-115; issue #113) — a dry run's simulation compares the change with
/// what the stored entries make on the base now (the base alone while they don't apply), for a
/// device change as for any other kind. A device change's comparison includes a device stored but
/// not yet in the running configuration (its reload hadn't run); a quick rule's delete that makes
/// the stored entries apply again is simulated, not answered with an error.
#[test]
fn api_002_a_dry_run_compares_with_what_the_stored_entries_make_now() {
    holding_the_slot(a_dry_run_compares_with_what_the_stored_entries_make_now());
}

async fn a_dry_run_compares_with_what_the_stored_entries_make_now() {
    let n = newt_primary();
    n.auth
        .state()
        .put_managed(
            crate::managed::CLIENT,
            "quiet",
            &device_row("quiet", &["192.168.0.81"]).to_string(),
            None,
            None,
            0,
            "a write whose reload hasn't run",
        )
        .unwrap();
    assert!(
        !n.has_device("quiet"),
        "not in the running configuration yet"
    );
    let w = ClientWrite {
        name: "speaker".to_owned(),
        input: Some(input(None, &["192.168.0.80"])),
        dry_run: true,
        expect: None,
        by: "tests".to_owned(),
        simulate: Some(telltale_api::SimulateOpts::default()),
    };
    let plan = super::plan_client(&n.src, n.auth.state(), &w)
        .unwrap_or_else(|p| panic!("the plan: {p:?}"));
    let names = |c: &Config| {
        let mut v: Vec<String> = c.client.iter().map(|c| c.name.to_string()).collect();
        v.sort();
        v
    };
    let mut expected = names(&plan.candidate);
    expected.retain(|x| x != "speaker");
    assert_eq!(
        names(&plan.baseline),
        expected,
        "the comparison is the candidate without the change"
    );

    // A stored rule that names a device the base doesn't have: the stored entries don't apply.
    let m = newt_primary();
    m.store(
        crate::managed::RULE,
        "r-gone",
        &json!({ "id": "r-gone", "action": "block", "domain": "x.example.com", "devices": ["gone"] }),
    );
    assert!(m.falls_back());
    let r = m
        .api
        .write_managed(ManagedWrite {
            kind: ManagedKind::Rule,
            name: "r-gone".to_owned(),
            body: None,
            dry_run: true,
            expect: None,
            by: "tests".to_owned(),
            simulate: Some(telltale_api::SimulateOpts::default()),
            by_admin: true,
        })
        .await;
    let r = r.unwrap_or_else(|p| panic!("the dry run of the repair: {p:?}"));
    assert!(!r.applied && r.simulation.is_some(), "{r:?}");
}

/// The data folder of `n`.
fn data_dir(n: &Node) -> std::path::PathBuf {
    std::path::PathBuf::from(n.src.file_config.load().node.data_dir.as_str())
}

/// Saves this node's role and epoch on disk, as a promotion or a step-down does; no reload runs.
fn save_role(n: &Node, role: telltale_cluster::node::Role, epoch: u64) {
    let mut id = telltale_cluster::node::Identity::load(&data_dir(n))
        .unwrap()
        .unwrap();
    id.save_role(role, epoch).unwrap();
}

/// REQ: API-010 (ADR-040, ADR-191; issue #113) — deleting a stored device that a device of the
/// base hides (the files' `nas`, or `Newt` of the version a promoted primary builds on) removes the
/// stored row, and the answer's `before`, which the audit entry records, is that row (its address,
/// `source` `api`), not the base's device, which stays. So for a dry run and a saved delete, and
/// through the API the audit entry has the row's address.
#[tokio::test]
async fn api_010_delete_of_a_hidden_stored_device_reports_the_row() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;
    let client = crate::managed::CLIENT;
    let nas = r#"
[[client]]
name = "nas"
match = ["192.168.1.10"]
"#;
    let standalone = Node::standalone(config(nas));
    standalone.store(client, "nas", &device_row("nas", &["192.168.1.12"]));
    let promoted = newt_primary();
    promoted.store(client, "Newt", &device_row("Newt", &["192.168.0.56"]));
    for (node, n, name, row, kept) in [
        (
            "standalone",
            &standalone,
            "nas",
            "192.168.1.12",
            "192.168.1.10",
        ),
        (
            "promoted",
            &promoted,
            "Newt",
            "192.168.0.56",
            "192.168.0.55",
        ),
    ] {
        assert!(!n.falls_back(), "{node}");
        for dry_run in [true, false] {
            let r = n.device(name, None, dry_run).await;
            let r = r.unwrap_or_else(|p| panic!("{node}, dry run {dry_run}: {p:?}"));
            assert_eq!(
                r.before
                    .as_ref()
                    .map(|b| (b.name.as_str(), b.matches.clone(), b.source.as_str())),
                Some((name, vec![row.to_owned()], "api")),
                "{node}, dry run {dry_run}: `before` is the stored row"
            );
        }
        assert!(!n.stored(client).iter().any(|s| s == name), "{node}");
        let running = n.running();
        assert!(
            running
                .client
                .iter()
                .any(|c| c.name.as_str() == name && c.match_keys.iter().any(|k| k.as_str() == kept)),
            "{node}: the base's device stays: {:?}",
            running.client
        );
    }

    // Through the API: the audit entry of the delete records the row as `before`.
    standalone.store(client, "nas", &device_row("nas", &["192.168.1.12"]));
    let app = telltale_api::router(
        Arc::new(ApiBackend {
            src: Arc::clone(&standalone.src),
        }),
        Arc::clone(&standalone.auth),
    );
    let olga = standalone
        .auth
        .create_user(
            "olga",
            "an operator password",
            auth::Role::Operator,
            false,
            super::local_access_tests::now(),
        )
        .unwrap();
    let operator = token(&standalone.auth, olga.id, "write", None);
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/clients/nas")
        .header("authorization", operator.as_str())
        .header("x-telltale-reason", "managed base tests")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let entries = standalone
        .auth
        .state()
        .audit_page(None, 10, Some("client.delete"), None)
        .unwrap();
    let detail: serde_json::Value = entries
        .first()
        .map(|e| serde_json::from_str(&e.detail).unwrap())
        .unwrap_or_default();
    assert_eq!(
        detail["before"]["match"],
        json!(["192.168.1.12"]),
        "the audit entry: {entries:?}"
    );
}

/// A primary promoted from replica a moment ago, before the reload that follows its promotion: it
/// was a replica that last applied [`INHERITED`] (a replica's reloads keep no base to merge the
/// stored entries onto), `Newt` and `tablet` are stored (made in the UI here, earlier), and its role
/// on disk is now primary.
fn just_promoted() -> Node {
    just_promoted_on(&config(INHERITED))
}

/// [`just_promoted`], with the version it last applied made from `inherited`.
fn just_promoted_on(inherited: &Config) -> Node {
    use telltale_cluster::node::Role;
    let n = Node::promoted(config(OWN), inherited);
    save_role(&n, Role::Replica, 1);
    reload(&n.src);
    n.store(
        crate::managed::CLIENT,
        "Newt",
        &device_row("Newt", &["192.168.0.55"]),
    );
    n.store(
        crate::managed::CLIENT,
        "tablet",
        &device_row("tablet", &["id:tablet"]),
    );
    assert!(
        n.src.managed_base.load().is_none(),
        "a replica keeps no base"
    );
    save_role(&n, Role::Primary, 2);
    n
}

/// REQ: CLU-003, API-010, API-002 (ADR-051, ADR-191; issue #113) — a write in the moment after a
/// promotion, before the reload that follows it has run, is checked on the version the node now
/// builds on, as that reload merges it: the node's role and that version are read when the write
/// is planned, not taken from what the last reload (as a replica) kept. The rename of the issue
/// (`Newt` to `Newt-pve1`, same address) is refused and names `Newt` and where it is; a local name
/// that version has is refused (409) with words that say where it comes from. Nothing is stored,
/// the configuration version doesn't move, and after the reload the stored devices apply. So for
/// every planner: an upstream group of an upstream only that version has is accepted and in
/// effect after its reload, and a change of the rate limit starts from that version's.
#[allow(clippy::too_many_lines)] // one case per planner
#[tokio::test]
async fn clu_003_a_write_right_after_promotion_is_checked_on_the_inherited_base() {
    let client = crate::managed::CLIENT;
    let mut wrong = Vec::new();

    let n = just_promoted();
    let version = n.version();
    let r = n
        .device(
            "Newt",
            Some(input(Some("Newt-pve1"), &["192.168.0.55"])),
            false,
        )
        .await;
    match &r {
        Err(p)
            if (400..500).contains(&p.status)
                && said(p).contains("`Newt`")
                && said(p).contains("the cluster version this node builds on") => {}
        _ => wrong.push(format!("the rename of the issue: {}", outcome(&r, &n))),
    }
    if n.stored(client) != ["Newt", "tablet"] || n.version() != version {
        wrong.push(format!(
            "after the rename: stored {:?}, version {} (was {version})",
            n.stored(client),
            n.version()
        ));
    }
    reload(&n.src);
    if n.falls_back() || !n.has_device("tablet") {
        wrong.push("after the reload, the stored devices don't apply".to_owned());
    }

    let n = just_promoted();
    let version = n.version();
    let r = n
        .write(
            ManagedKind::Record,
            "printer.lan",
            Some(json!({ "records": [{ "type": "A", "value": "192.168.0.8" }] })),
        )
        .await;
    match &r {
        Err(p)
            if p.status == 409 && p.detail.contains("the cluster version this node builds on") => {}
        _ => wrong.push(format!("a local name the version has: {}", outcome(&r, &n))),
    }
    if !n.stored(crate::managed::RECORD).is_empty() || n.version() != version {
        wrong.push(format!(
            "after the local name: stored {:?}, version {} (was {version})",
            n.stored(crate::managed::RECORD),
            n.version()
        ));
    }

    // `plan_override`: `cloudflare` is that version's upstream, not this node's files'.
    let n = just_promoted();
    let r = n
        .write(
            ManagedKind::UpstreamGroup,
            "fast",
            Some(json!({ "members": ["cloudflare"] })),
        )
        .await;
    let fast = |c: &Config| c.upstream_group.iter().any(|g| g.name.as_str() == "fast");
    if r.is_err() || n.falls_back() || !fast(&n.running()) {
        wrong.push(format!(
            "an upstream group of that version's upstream: {}",
            outcome(&r, &n)
        ));
    }

    // `plan_singleton`: the rate limit before the change is that version's.
    let n = just_promoted_on(&config(&format!(
        "{INHERITED}\n[ratelimit]\nqueries = 300\n"
    )));
    let r = n
        .write(
            ManagedKind::RateLimit,
            "default",
            Some(json!({ "queries": 500 })),
        )
        .await;
    match &r {
        Ok(c) if c.before.as_ref().and_then(|b| b["queries"].as_u64()) == Some(300) => {}
        Ok(c) => wrong.push(format!("the rate limit before the change: {:?}", c.before)),
        Err(p) => wrong.push(format!("the rate limit: refused: {p:?}")),
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// REQ: CLU-003, API-010, API-002 (ADR-051, ADR-191; issue #113) — the base a write is checked on
/// (`replication::managed_base`) is what `replication::unpinned` merges the stored entries onto,
/// role by role. On a node that applies them, the configuration in effect is the stored entries
/// merged onto that base, or onto the files when there is none; on one that doesn't (a replica, a
/// primary with a `[cluster.git]` source) there is no base, and no stored entry is in effect. A
/// promoted primary and an emergency primary under a Git authority build on the version they last
/// applied; a standalone node, a first primary, a Git-managed primary under a Git authority, and a
/// promoted primary whose applied version can't be read (no `applied.json`, a damaged one, a missing
/// blob) build on their files.
#[allow(clippy::too_many_lines)] // one case per role
#[tokio::test]
async fn clu_003_the_write_base_is_what_unpinned_merges_onto_for_every_role() {
    use telltale_cluster::node::{Identity, Role};
    use telltale_cluster::sync::{ClusterManifest, blob_ref};
    let with_tablet = |n: Node| {
        n.store(
            crate::managed::CLIENT,
            "tablet",
            &device_row("tablet", &["id:tablet"]),
        );
        n
    };
    let promoted = || with_tablet(Node::promoted(config(OWN), &config(INHERITED)));
    let files = |n: &Node| (*n.src.file_config.load_full()).clone();
    let applied = |n: &Node| telltale_cluster::node::dir_of(&data_dir(n)).join("applied.json");
    let authority = |n: &Node| {
        Identity::load(&data_dir(n))
            .unwrap()
            .unwrap()
            .save_authority("gitops")
            .unwrap();
    };
    // (role, its config files, the node, whether it has a base, whether it applies stored entries)
    let mut cases: Vec<(&str, Config, Node, bool, bool)> = Vec::new();
    let n = with_tablet(Node::standalone(config(OWN)));
    cases.push(("standalone", files(&n), n, false, true));
    let n = with_tablet(Node::first_primary(config(OWN)));
    cases.push(("first primary, never a replica", files(&n), n, false, true));
    let n = promoted();
    cases.push(("promoted from replica", files(&n), n, true, true));
    let n = promoted();
    authority(&n);
    cases.push((
        "emergency primary under a Git authority",
        files(&n),
        n,
        true,
        true,
    ));
    let n = promoted();
    authority(&n);
    let mut f = files(&n);
    f.cluster.config_source = telltale_config::SafeString::from("gitops");
    cases.push((
        "Git-managed primary under a Git authority",
        f,
        n,
        false,
        true,
    ));
    let n = promoted();
    let mut f = files(&n);
    f.cluster.git = Some(
        serde_json::from_value(
            json!({ "repo": "https://git.example.test/homelab", "path": "telltale/shared.toml" }),
        )
        .unwrap(),
    );
    cases.push(("primary with a [cluster.git] source", f, n, false, false));
    let n = promoted();
    save_role(&n, Role::Replica, 1);
    cases.push(("replica", files(&n), n, false, false));
    let n = promoted();
    std::fs::remove_file(applied(&n)).unwrap();
    cases.push(("promoted, no applied.json", files(&n), n, false, true));
    let n = promoted();
    std::fs::write(applied(&n), b"{").unwrap();
    cases.push((
        "promoted, a damaged applied.json",
        files(&n),
        n,
        false,
        true,
    ));
    let n = promoted();
    let mut m: ClusterManifest =
        serde_json::from_slice(&std::fs::read(applied(&n)).unwrap()).unwrap();
    m.config = blob_ref("config.json", b"never stored");
    std::fs::write(applied(&n), serde_json::to_vec(&m).unwrap()).unwrap();
    cases.push((
        "promoted, its version's blob missing",
        files(&n),
        n,
        false,
        true,
    ));

    let mut wrong = Vec::new();
    // Each node stays in `cases`, so its data folder (what these read) is there throughout.
    for (role, file, _node, has_base, applies) in &cases {
        let base = crate::replication::managed_base(file);
        let unpinned = crate::replication::unpinned(file);
        let in_effect = unpinned.client.iter().any(|c| c.name.as_str() == "tablet");
        if base.is_some() != *has_base || in_effect != *applies {
            wrong.push(format!(
                "{role}: a base {}, the stored device in effect {in_effect}",
                base.is_some()
            ));
            continue;
        }
        if *applies {
            let onto = base.as_ref().unwrap_or(file);
            if unpinned != crate::managed::effective(onto) {
                wrong.push(format!(
                    "{role}: the configuration in effect isn't the stored entries merged onto the base"
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// REQ: API-010, CLU-003 (ADR-040, ADR-191; issue #113) — while the stored devices don't apply, the
/// way back names itself. The fallback's log line names the stored device the reasons point at
/// (`Newt-pve1`, the row to delete) by its name, not only by its place in a list, with the request
/// that removes it, and not the stored device that has nothing to do with it (`tablet`). A device
/// change refused meanwhile says, to whoever may read every device, which stored device that is;
/// its plain hint names none, says the stored entries don't apply now, and doesn't point at the
/// groups. A delete refused because something else stored names the device says so, not where the
/// groups are.
#[tokio::test]
async fn api_010_a_fallback_names_the_stored_rows_to_delete() {
    let client = crate::managed::CLIENT;
    let mut wrong = Vec::new();
    let n = newt_primary();
    n.unstore(client, "Newt");
    n.store(
        client,
        "Newt-pve1",
        &device_row("Newt-pve1", &["192.168.0.55"]),
    );
    assert!(n.falls_back());
    // The line the fallback logs (`managed::effective` logs `managed::fallback_line`), for the merge
    // the reload runs: the stored entries onto the version this node builds on. Read from the
    // function itself, as a test subscriber scoped to this thread doesn't see every event while
    // other tests log in parallel.
    let base = crate::replication::managed_base(&n.src.file_config.load()).unwrap();
    let entries = crate::managed::entries(n.auth.state());
    let Err(errs) = crate::managed::merge(&base, &entries) else {
        panic!("the stored entries apply");
    };
    let line = crate::managed::fallback_line(&base, &entries, &errs);
    if !line.contains("`Newt-pve1`")
        || !line.contains("DELETE /api/v1/clients/")
        || line.contains("tablet")
    {
        wrong.push(format!(
            "the fallback's log line: {line} (the reasons: {errs:?})"
        ));
    }
    let r = n
        .device("speaker", Some(input(None, &["192.168.0.80"])), false)
        .await;
    match &r {
        Err(p) => {
            let plain = p.hint.as_deref().unwrap_or("");
            if !said(p).contains("`Newt-pve1`")
                || plain.contains("Newt-pve1")
                || !plain.contains("don't apply")
                || plain.contains("GET /api/v1/groups")
            {
                wrong.push(format!("a device change meanwhile: {p:?}"));
            }
        }
        Ok(_) => wrong.push(format!("a device change meanwhile: {}", outcome(&r, &n))),
    }

    // A delete of a device that a stored quick rule names.
    let s = Node::standalone(config(OWN));
    s.store(client, "tv", &device_row("tv", &["192.168.1.20"]));
    let body = json!({ "action": "block", "domain": "games.example.com", "devices": ["tv"] });
    let row = super::rule_of(&body, "r-tv", "tests", None).unwrap();
    s.store(
        crate::managed::RULE,
        "r-tv",
        &serde_json::to_value(row).unwrap(),
    );
    assert!(!s.falls_back() && s.has_device("tv"));
    let r = s.device("tv", None, false).await;
    match &r {
        Err(p) => {
            let plain = p.hint.as_deref().unwrap_or("");
            if plain.contains("GET /api/v1/groups") || !plain.contains("names this device") {
                wrong.push(format!("the delete of a device a rule names: {p:?}"));
            }
        }
        Ok(_) => wrong.push(format!(
            "the delete of a device a rule names: {}",
            outcome(&r, &s)
        )),
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// Records `count` queries from `ip` in `n`'s telemetry, all in one hour (what `recentQueries`
/// counts).
fn queries_from(n: &Node, ip: [u8; 4], count: u64) {
    use telltale_telemetry::event::{Name, Record};
    let mut agg = n.src.pipeline.telemetry.aggregates();
    for i in 0..count {
        agg.record(&Record::Query(
            telltale_telemetry::QueryEvent {
                ts_us: (1_700_000_000 + i) * 1_000_000,
                client_ip: std::net::Ipv4Addr::from(ip).to_ipv6_mapped().octets(),
                client_ref: 0,
                group: 0,
                qtype: 1,
                qclass: 1,
                rcode: Some(0),
                status: telltale_telemetry::Status::Forwarded,
                proto: telltale_telemetry::Proto::Udp,
                flags: 0x8180,
                rule: None,
                upstream: 0,
                attempts: 0,
                t_total_us: 100,
                t_upstream_us: 0,
                resp_size: 64,
                answers: 1,
            },
            Name::from_wire(b"\x07example\x03com\x00"),
        ));
    }
}

/// REQ: AGT-002, API-010 (ADR-191; issue #113) — deleting a stored device that a device of the
/// base hides changes nothing in effect, so its answer counts no recent queries: not the traffic of
/// the row's address, nor that of the base device, whose label stays. A delete of a device in
/// effect still counts the queries of its address.
#[tokio::test]
async fn api_010_a_hidden_row_delete_counts_no_recent_queries() {
    let client = crate::managed::CLIENT;
    let n = Node::standalone(config(
        r#"
[[client]]
name = "nas"
match = ["192.168.1.10"]
"#,
    ));
    n.store(client, "nas", &device_row("nas", &["192.168.1.12"]));
    n.store(client, "tv", &device_row("tv", &["192.168.1.20"]));
    queries_from(&n, [192, 168, 1, 12], 5);
    queries_from(&n, [192, 168, 1, 10], 3);
    queries_from(&n, [192, 168, 1, 20], 4);
    let hidden = n.device("nas", None, true).await;
    let hidden = hidden.unwrap_or_else(|p| panic!("the hidden row's delete: {p:?}"));
    let tv = n.device("tv", None, true).await;
    let tv = tv.unwrap_or_else(|p| panic!("the delete of a device in effect: {p:?}"));
    assert_eq!(
        (hidden.recent_queries, tv.recent_queries),
        (0, 4),
        "the hidden row's delete: {hidden:?}; a device in effect: {tv:?}"
    );
}

/// A standalone node whose config file names `nas` (in group `kids`), and a stored `nas` that the
/// file's device hides, with match keys (an address and a MAC) and a group of its own that no list
/// shows; 5 recent queries came from the row's address. The API on it, and an operator who owns
/// the tokens.
fn hidden_nas() -> (Node, axum::Router, i64) {
    let n = Node::standalone(config(
        r#"
[[group]]
name = "kids"

[[client]]
name = "nas"
match = ["192.168.1.10"]
groups = ["kids"]
"#,
    ));
    n.store(
        crate::managed::CLIENT,
        "nas",
        &json!({ "name": "nas", "match": ["192.168.1.12", "02:00:00:00:00:12"], "groups": ["guests"] }),
    );
    assert!(!n.falls_back() && n.has_device("nas"));
    queries_from(&n, [192, 168, 1, 12], 5);
    let app = telltale_api::router(
        Arc::new(ApiBackend {
            src: Arc::clone(&n.src),
        }),
        Arc::clone(&n.auth),
    );
    let olga = n
        .auth
        .create_user(
            "olga",
            "an operator password",
            auth::Role::Operator,
            false,
            super::local_access_tests::now(),
        )
        .unwrap();
    (n, app, olga.id)
}

/// `DELETE /api/v1/clients/{name}` as `creds` (with a reason): the status, and the answer as
/// JSON and as text.
async fn api_delete(
    app: &axum::Router,
    creds: &str,
    name: &str,
    dry_run: bool,
) -> (u16, serde_json::Value, String) {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;
    let uri = format!(
        "/api/v1/clients/{name}{}",
        if dry_run { "?dryRun=true" } else { "" }
    );
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("authorization", creds)
        .header("x-telltale-reason", "managed base tests")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    (
        status,
        serde_json::from_str(&text).unwrap_or_default(),
        text,
    )
}

/// The detail of the newest `client.delete` audit entry.
fn last_delete_audit(n: &Node) -> serde_json::Value {
    n.auth
        .state()
        .audit_page(None, 10, Some("client.delete"), None)
        .unwrap()
        .first()
        .map(|e| serde_json::from_str(&e.detail).unwrap())
        .unwrap_or_default()
}

/// REQ: AGT-004, API-010 (ADR-064, ADR-191; issue #113) — deleting a stored device that a device
/// of the config files hides answers, as `before`, the stored row it removes, which no list shows.
/// An agent token limited to a group may delete it (the device in effect of that name is in its
/// group), and is shown that row by its name and `source` only: no match keys, no groups, no
/// recent queries, for a dry run and a saved delete alike. The audit entry of the saved delete
/// keeps the whole row.
#[tokio::test]
async fn agt_004_a_group_agent_is_shown_a_hidden_stored_row_by_its_name_only() {
    let (n, app, owner) = hidden_nas();
    let agent = token(
        &n.auth,
        owner,
        "write",
        Some(("config:write:clients querylog:read", Some("kids"))),
    );
    let mut wrong = Vec::new();
    for dry_run in [true, false] {
        let (status, v, text) = api_delete(&app, &agent, "nas", dry_run).await;
        let hidden = ["192.168.1.12", "02:00:00:00:00:12", "guests"];
        if status != 200
            || hidden.iter().any(|h| text.contains(h))
            || v["before"]["name"] != "nas"
            || v["before"]["source"] != "api"
            || v["recentQueries"] != 0
        {
            wrong.push(format!("dry run {dry_run}: {status} {text}"));
        }
    }
    let audit = last_delete_audit(&n);
    if audit["before"]["match"] != json!(["192.168.1.12", "02:00:00:00:00:12"])
        || audit["before"]["groups"] != json!(["guests"])
    {
        wrong.push(format!("the audit entry: {audit}"));
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    assert!(n.stored(crate::managed::CLIENT).is_empty() && n.has_device("nas"));
}

/// REQ: AGT-004, API-010 (ADR-191; issue #113) — whoever may read every device (a person, here an
/// operator; an agent token without a group that may read the query log) is shown that row whole
/// as `before`, and the audit entry of the saved delete has it.
#[tokio::test]
async fn agt_004_a_caller_that_may_read_every_device_is_shown_the_hidden_row() {
    let (n, app, owner) = hidden_nas();
    let operator = token(&n.auth, owner, "write", None);
    let unrestricted = token(
        &n.auth,
        owner,
        "write",
        Some(("config:write:clients querylog:read", None)),
    );
    let row = json!(["192.168.1.12", "02:00:00:00:00:12"]);
    let mut wrong = Vec::new();
    for (who, creds, dry_run) in [
        ("an agent without a group", &unrestricted, true),
        ("an operator", &operator, true),
        ("an operator", &operator, false),
    ] {
        let (status, v, text) = api_delete(&app, creds, "nas", dry_run).await;
        if status != 200
            || v["before"]["match"] != row
            || v["before"]["groups"] != json!(["guests"])
        {
            wrong.push(format!("{who}, dry run {dry_run}: {status} {text}"));
        }
    }
    let audit = last_delete_audit(&n);
    if audit["before"]["match"] != row || audit["before"]["groups"] != json!(["guests"]) {
        wrong.push(format!("the audit entry: {audit}"));
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// REQ: AGT-004, AGT-002, API-010 (ADR-064, ADR-191; issue #113) — a group agent deleting a device
/// in effect in its group (a stored device that nothing hides) is shown it whole as `before`, with
/// the recent queries of its address, for a dry run and a saved delete through the API alike: the
/// device in effect is looked up before the write, so the reload of a saved delete doesn't make it
/// look like a row that isn't in effect.
#[tokio::test]
async fn agt_004_a_group_agent_deleting_a_device_in_effect_is_shown_it_whole() {
    let (n, app, owner) = hidden_nas();
    n.store(
        crate::managed::CLIENT,
        "tv",
        &json!({ "name": "tv", "match": ["192.168.1.20"], "groups": ["kids"] }),
    );
    assert!(!n.falls_back() && n.has_device("tv"));
    queries_from(&n, [192, 168, 1, 20], 4);
    let agent = token(
        &n.auth,
        owner,
        "write",
        Some(("config:write:clients querylog:read", Some("kids"))),
    );
    let mut wrong = Vec::new();
    for dry_run in [true, false] {
        let (status, v, text) = api_delete(&app, &agent, "tv", dry_run).await;
        if status != 200
            || v["before"]["match"] != json!(["192.168.1.20"])
            || v["before"]["groups"] != json!(["kids"])
            || v["recentQueries"] != 4
        {
            wrong.push(format!("dry run {dry_run}: {status} {text}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    assert!(!n.has_device("tv"), "the saved delete removed it");
}

/// REQ: AGT-004, API-010 (ADR-191; issue #113) — an agent token without `querylog:read` (and with
/// no group) may not read every device either: it is shown the hidden stored row by its name and
/// `source` only, dry run and saved, and the audit entry keeps the whole row.
#[tokio::test]
async fn agt_004_an_agent_without_querylog_read_is_shown_a_hidden_row_by_its_name_only() {
    let (n, app, owner) = hidden_nas();
    let agent = token(
        &n.auth,
        owner,
        "write",
        Some(("config:write:clients", None)),
    );
    let mut wrong = Vec::new();
    for dry_run in [true, false] {
        let (status, v, text) = api_delete(&app, &agent, "nas", dry_run).await;
        let hidden = ["192.168.1.12", "02:00:00:00:00:12", "guests"];
        if status != 200
            || hidden.iter().any(|h| text.contains(h))
            || v["before"]["name"] != "nas"
            || v["before"]["source"] != "api"
            || v["recentQueries"] != 0
        {
            wrong.push(format!("dry run {dry_run}: {status} {text}"));
        }
    }
    let audit = last_delete_audit(&n);
    if audit["before"]["match"] != json!(["192.168.1.12", "02:00:00:00:00:12"]) {
        wrong.push(format!("the audit entry: {audit}"));
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A saved `DELETE /api/v1/clients/{name}` as `creds` (with a reason), with an Idempotency-Key:
/// the status and the answer as text.
async fn api_delete_keyed(app: &axum::Router, creds: &str, name: &str, key: &str) -> (u16, String) {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/clients/{name}"))
        .header("authorization", creds)
        .header("x-telltale-reason", "managed base tests")
        .header("idempotency-key", key)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// REQ: AGT-003, AGT-004 (ADR-181, ADR-191) — an agent token's Idempotency-Keys are its own: with
/// the key its owner used for the same request, it gets an answer of its own, and the owner's retry
/// gets the owner's first answer.
#[tokio::test]
async fn agt_003_an_agent_token_gets_its_own_stored_answer() {
    let (n, app, owner) = hidden_nas();
    let operator = token(&n.auth, owner, "write", None);
    let agent = token(
        &n.auth,
        owner,
        "write",
        Some(("config:write:clients querylog:read", Some("kids"))),
    );
    let (status, first) = api_delete_keyed(&app, &operator, "nas", "k-113").await;
    assert!(
        status == 200 && first.contains("192.168.1.12"),
        "{status} {first}"
    );
    let mut wrong = Vec::new();
    let (status, again) = api_delete_keyed(&app, &operator, "nas", "k-113").await;
    if status != 200 || again != first {
        wrong.push(format!("the owner's retry: {status} {again}"));
    }
    let (status, agents) = api_delete_keyed(&app, &agent, "nas", "k-113").await;
    if agents == first || agents.contains("192.168.1.12") {
        wrong.push(format!("the agent with its owner's key: {status} {agents}"));
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A dry-run `PUT /api/v1/clients/{name}` of `body` as `creds` (with a reason): the status and the
/// answer as text.
async fn api_put_dry(
    app: &axum::Router,
    creds: &str,
    name: &str,
    body: &serde_json::Value,
) -> (u16, String) {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/clients/{name}?dryRun=true"))
        .header("authorization", creds)
        .header("x-telltale-reason", "managed base tests")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// REQ: AGT-004, API-010 (ADR-191; issue #113) — while the stored entries don't apply (a stored quick
/// rule names `secret-laptop`, which no device is), their reasons can name devices that a caller
/// that may not read every device can't read. Such a caller's refused device change gets a
/// `detail` without them, and a delete it may make gets the warning without them. An operator gets
/// the reasons in both, as before.
#[tokio::test]
async fn agt_004_a_restricted_caller_is_not_given_the_reasons_of_rows_it_cant_read() {
    let (n, app, owner) = hidden_nas();
    let body =
        json!({ "action": "block", "domain": "games.example.com", "devices": ["secret-laptop"] });
    let row = super::rule_of(&body, "r-x", "tests", None).unwrap();
    n.store(
        crate::managed::RULE,
        "r-x",
        &serde_json::to_value(row).unwrap(),
    );
    assert!(n.falls_back(), "the stored entries don't apply");
    let operator = token(&n.auth, owner, "write", None);
    let agent = token(
        &n.auth,
        owner,
        "write",
        Some(("config:write:clients querylog:read", Some("kids"))),
    );
    let mut wrong = Vec::new();
    for (who, creds, told) in [
        ("an operator", &operator, true),
        ("a group agent", &agent, false),
    ] {
        let speaker = json!({ "match": ["192.168.1.80"], "groups": ["kids"] });
        let (status, text) = api_put_dry(&app, creds, "speaker", &speaker).await;
        if status != 422 || text.contains("secret-laptop") != told {
            wrong.push(format!("{who}, a device change: {status} {text}"));
        }
        let (status, _, text) = api_delete(&app, creds, "nas", true).await;
        if status != 200
            || text.contains("secret-laptop") != told
            || !text.contains("still don't apply")
        {
            wrong.push(format!(
                "{who}, the delete of the hidden row: {status} {text}"
            ));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A `GET` of `uri` as `creds`: the status and the answer as text.
async fn api_get(app: &axum::Router, creds: &str, uri: &str) -> (u16, String) {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", creds)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// REQ: AGT-004, API-010 (ADR-191; issue #113) — in place of reasons that can name devices it can't
/// read, a restricted agent is told what is true. For a match key a device of the config files
/// holds (nothing is wrong now): that the change conflicts with another device, which the answer
/// doesn't name, and the hint says what to do; that is true also for these agents, which may list
/// that device (`config:read`; the group agent's own group). While the stored entries don't apply:
/// that they don't apply now and that an operator sees why when making the change in the UI, with a
/// hint that doesn't point at the reasons; and a delete then accepted says they still don't apply
/// without pointing at warnings it doesn't get. An operator gets the reasons, the hint and the
/// impact as they are.
#[tokio::test]
async fn agt_004_a_restricted_agent_is_told_what_is_true_in_place_of_the_reasons() {
    let conflict = "this change conflicts with another device, which this answer doesn't name; the hint says what to do";
    let key_hint =
        "A match key identifies one device: give this one a key the other device doesn't use.";
    let dont_apply = "the devices and settings made through the API don't apply now, before this change; an operator sees why when making the change in the UI";
    let withheld_hint = "The devices and settings made through the API don't apply now, before this change: that has to be fixed first. A device made through the API that isn't in effect can be deleted (DELETE /api/v1/clients/{name}).";
    let dont_apply_hint = telltale_api::config_api::STORED_ENTRIES_DONT_APPLY_HINT;
    let (n, app, owner) = hidden_nas();
    let operator = token(&n.auth, owner, "write", None);
    let group_agent = token(
        &n.auth,
        owner,
        "write",
        Some((
            "config:read config:write:clients querylog:read",
            Some("kids"),
        )),
    );
    let no_log_agent = token(
        &n.auth,
        owner,
        "write",
        Some(("config:read config:write:clients", None)),
    );
    let parse = |text: &str| serde_json::from_str::<serde_json::Value>(text).unwrap_or_default();
    let mut wrong = Vec::new();

    // The files' `nas` (in `kids`) holds the match key; both agents may list it.
    let probe = json!({ "match": ["192.168.1.10"], "groups": ["kids"] });
    for (who, creds) in [
        ("a group agent", &group_agent),
        ("an agent without querylog:read", &no_log_agent),
    ] {
        let (status, listed) = api_get(&app, creds, "/api/v1/clients").await;
        if status != 200 || !listed.contains("\"nas\"") {
            wrong.push(format!("{who} lists the devices: {status} {listed}"));
        }
        let (status, text) = api_put_dry(&app, creds, "probe", &probe).await;
        let v = parse(&text);
        if status != 422 || v["detail"] != conflict || v["hint"] != key_hint {
            wrong.push(format!("{who}, the conflict: {status} {text}"));
        }
    }

    // The stored entries don't apply (a stored rule names a device no one is); `tv` is stored, and so
    // not in effect either.
    let body =
        json!({ "action": "block", "domain": "games.example.com", "devices": ["secret-laptop"] });
    let row = super::rule_of(&body, "r-x", "tests", None).unwrap();
    n.store(
        crate::managed::RULE,
        "r-x",
        &serde_json::to_value(row).unwrap(),
    );
    n.store(
        crate::managed::CLIENT,
        "tv",
        &device_row("tv", &["192.168.1.20"]),
    );
    assert!(n.falls_back(), "the stored entries don't apply");
    let speaker = json!({ "match": ["192.168.1.80"], "groups": ["kids"] });
    for (who, creds, told) in [
        ("an operator", &operator, true),
        ("a group agent", &group_agent, false),
        ("an agent without querylog:read", &no_log_agent, false),
    ] {
        let (status, text) = api_put_dry(&app, creds, "speaker", &speaker).await;
        let v = parse(&text);
        let right = if told {
            v["detail"]
                .as_str()
                .is_some_and(|d| d.contains("secret-laptop"))
                && v["hint"] == dont_apply_hint
        } else {
            v["detail"] == dont_apply && v["hint"] == withheld_hint
        };
        if status != 422 || !right {
            wrong.push(format!("{who}, a device change: {status} {text}"));
        }
    }
    for (who, creds, told) in [
        ("an operator", &operator, true),
        ("an agent without querylog:read", &no_log_agent, false),
    ] {
        let (status, v, text) = api_delete(&app, creds, "tv", true).await;
        let impact = v["impact"].as_str().unwrap_or_default();
        if status != 200
            || impact.contains("(the warnings say why)") != told
            || !impact.contains("still don't apply after it")
        {
            wrong.push(format!("{who}, the delete of `tv`: {status} {text}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// REQ: AGT-004, API-010 (ADR-191) — a refusal whose reasons are about the caller's own input (here
/// a group that doesn't exist) keeps them in `detail`, for a caller that may not read every device
/// too.
#[tokio::test]
async fn agt_004_a_refusal_about_the_callers_own_input_keeps_its_reasons() {
    let (n, app, owner) = hidden_nas();
    let agent = token(
        &n.auth,
        owner,
        "write",
        Some(("config:write:clients", None)),
    );
    let body = json!({ "match": ["192.168.1.80"], "groups": ["nope"] });
    let (status, text) = api_put_dry(&app, &agent, "speaker", &body).await;
    assert!(
        status == 422 && text.contains("unknown group `nope`"),
        "{status} {text}"
    );
}

/// REQ: AGT-004, AGT-002, API-010 (ADR-191; issue #113) — an agent token without `querylog:read` (and
/// with no group) deleting a device in effect is shown it whole as `before`, with the recent queries
/// of its address, for a dry run and a saved delete alike, as a group agent is.
#[tokio::test]
async fn agt_004_an_agent_without_querylog_read_deleting_a_device_in_effect_is_shown_it_whole() {
    let (n, app, owner) = hidden_nas();
    n.store(
        crate::managed::CLIENT,
        "tv",
        &json!({ "name": "tv", "match": ["192.168.1.20"], "groups": ["kids"] }),
    );
    assert!(!n.falls_back() && n.has_device("tv"));
    queries_from(&n, [192, 168, 1, 20], 4);
    let agent = token(
        &n.auth,
        owner,
        "write",
        Some(("config:write:clients", None)),
    );
    let mut wrong = Vec::new();
    for dry_run in [true, false] {
        let (status, v, text) = api_delete(&app, &agent, "tv", dry_run).await;
        if status != 200
            || v["before"]["match"] != json!(["192.168.1.20"])
            || v["before"]["groups"] != json!(["kids"])
            || v["recentQueries"] != 4
        {
            wrong.push(format!("dry run {dry_run}: {status} {text}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    assert!(!n.has_device("tv"), "the saved delete removed it");
}

/// REQ: AGT-003 (ADR-181, ADR-191) — an agent token's retry with its own key gets its own first
/// answer again; another agent token of the same owner sending that key gets an answer of its own.
#[tokio::test]
async fn agt_003_an_agent_tokens_retry_replays_its_own_answer_only() {
    let (n, app, owner) = hidden_nas();
    let one = token(
        &n.auth,
        owner,
        "write",
        Some(("config:write:clients querylog:read", Some("kids"))),
    );
    let two = token(
        &n.auth,
        owner,
        "write",
        Some(("config:write:clients querylog:read", Some("kids"))),
    );
    let (status, first) = api_delete_keyed(&app, &one, "nas", "k-a").await;
    assert_eq!(status, 200, "{first}");
    let mut wrong = Vec::new();
    let (status, again) = api_delete_keyed(&app, &one, "nas", "k-a").await;
    if status != 200 || again != first {
        wrong.push(format!("the token's own retry: {status} {again}"));
    }
    let (status, other) = api_delete_keyed(&app, &two, "nas", "k-a").await;
    if other == first {
        wrong.push(format!("the other token with that key: {status} {other}"));
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// REQ: API-010, AGT-004 (ADR-191; issue #113) — a device change whose match key another stored device
/// (`tv`) holds says what to do: give the device a name and match keys no other device uses. A
/// person gets that in the fuller hint, which also names `tv` and the request that removes it; a
/// caller that may not read every device gets the sentence alone.
#[tokio::test]
async fn api_010_a_conflict_with_another_stored_device_says_to_use_free_keys() {
    let sentence = "This change conflicts with another device made through the API: give this one a name and match keys no other device uses.";
    let (n, app, owner) = hidden_nas();
    n.store(
        crate::managed::CLIENT,
        "tv",
        &json!({ "name": "tv", "match": ["192.168.1.20"], "groups": ["kids"] }),
    );
    assert!(!n.falls_back() && n.has_device("tv"));
    let operator = token(&n.auth, owner, "write", None);
    let agent = token(
        &n.auth,
        owner,
        "write",
        Some(("config:write:clients querylog:read", Some("kids"))),
    );
    let speaker = json!({ "match": ["192.168.1.20"], "groups": ["kids"] });
    let parse = |text: &str| serde_json::from_str::<serde_json::Value>(text).unwrap_or_default();
    let mut wrong = Vec::new();
    let (status, text) = api_put_dry(&app, &operator, "speaker", &speaker).await;
    let hint = parse(&text)["hint"].as_str().unwrap_or_default().to_owned();
    if status != 422 || !hint.starts_with(sentence) || !hint.contains("`tv`") {
        wrong.push(format!("an operator: {status} {text}"));
    }
    let (status, text) = api_put_dry(&app, &agent, "speaker", &speaker).await;
    if status != 422 || parse(&text)["hint"] != sentence {
        wrong.push(format!("a group agent: {status} {text}"));
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}
