// REQ: FLT-005 (GitHub issue #73) — a quick rule names a device by a `[[client]]` name (any case),
// an IP, or a CIDR, and by nothing else: a name a router, mDNS, or another node gives an address is
// refused. The refusal says what a rule can name and what to do, and when the string is such a
// name, says which address has it. The hint reads this node's tables, but the answer (accept or
// refuse) comes from the configuration alone, so every node gives the same one. Driven through the
// real routes, sign-in and backend (the harness of `local_access_tests`). No test reaches a host:
// the leases are made in memory.

use std::net::Ipv4Addr;
use std::sync::Arc;

use axum::http::StatusCode;

use super::local_access_tests::Node;

fn lease(ip: [u8; 4], name: &str) -> crate::devices::Lease {
    crate::devices::Lease {
        mac: String::new(),
        ip: Ipv4Addr::from(ip),
        hostname: Some(name.into()),
        expires: 0,
        offline: false,
        unsure: false,
        stale: false,
    }
}

fn table(leases: &[crate::devices::Lease]) -> Arc<crate::devices::Leases> {
    Arc::new(leases.iter().map(|l| (l.ip, l.clone())).collect())
}

/// A node whose router calls 192.168.1.102 "`LGwebOSTV`".
fn node_with_router_tv() -> Node {
    let n = Node::new(telltale_config::Config::default());
    n.src
        .pipeline
        .router_leases
        .store(table(&[lease([192, 168, 1, 102], "LGwebOSTV")]));
    n
}

fn rule(devices: &[&str]) -> serde_json::Value {
    serde_json::json!({ "action": "block", "domain": "scan.example.com", "devices": devices })
}

/// The sentence every plain refusal's hint ends with. It promises only what is true today: naming a
/// device recognizes it by the address it has now, so it says to use the new name, not that rules
/// then follow the device.
const WHAT_TO_DO: &str = "Use the address, or name the device first (Clients → its address → Name this device…) and use that name.";

fn text<'a>(v: &'a serde_json::Value, field: &str) -> &'a str {
    v[field].as_str().unwrap_or("")
}

/// REQ: FLT-005 (issue #73) — the form's old pre-fill: the name a router gives an address is
/// refused (it is no device named in TelltaleDNS), with words that say so, and a hint that says
/// which address the router means and what to do. Nothing is stored, in any case of the name.
#[tokio::test]
async fn flt_005_rule_router_name_refused_with_hint() {
    let n = node_with_router_tv();
    for name in ["LGwebOSTV", "lgwebostv"] {
        let (s, v) = n
            .put("/api/v1/rules/x", &n.admin, false, rule(&[name]))
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{name}: {v}");
        assert_eq!(v["code"], "invalid_config", "{v}");
        assert!(
            text(&v, "detail").contains(&format!(
                "`{name}` isn't a named device (`[[client]]`), an IP, or a CIDR"
            )),
            "the refusal says what a rule can name: {v}"
        );
        assert_eq!(
            text(&v, "hint"),
            format!("`{name}` is what your router calls 192.168.1.102. {WHAT_TO_DO}"),
            "{v}"
        );
    }
    assert!(
        crate::managed::entries(n.auth.state()).rules.is_empty(),
        "nothing was stored"
    );
}

/// REQ: FLT-005 (issue #73) — a string no table knows still gets the clear text and the hint
/// without an address; a rule refused for another reason (an unknown group) gets no device hint;
/// and with one good device and one bad, only the bad one is named.
#[tokio::test]
async fn flt_005_rule_unknown_device_refused_with_the_plain_hint() {
    let n = node_with_router_tv();
    let (s, v) = n
        .put("/api/v1/rules/x", &n.admin, false, rule(&["fridge"]))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(
        text(&v, "detail")
            .contains("`fridge` isn't a named device (`[[client]]`), an IP, or a CIDR"),
        "{v}"
    );
    assert_eq!(text(&v, "hint"), WHAT_TO_DO, "no address to name: {v}");

    let (s, v) = n
        .put(
            "/api/v1/rules/x",
            &n.admin,
            false,
            rule(&["192.168.1.20", "fridge"]),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(
        text(&v, "detail").contains("devices[1]"),
        "the bad one: {v}"
    );
    assert!(!text(&v, "detail").contains("devices[0]"), "{v}");

    let (s, v) = n
        .put(
            "/api/v1/rules/x",
            &n.admin,
            false,
            serde_json::json!({ "action": "block", "domain": "scan.example.com", "groups": ["nope"] }),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(text(&v, "detail").contains("unknown group `nope`"), "{v}");
    assert!(
        v.get("hint").is_none_or(serde_json::Value::is_null),
        "a group mistake has no device hint: {v}"
    );
}

/// REQ: FLT-005 (issue #73) — the hint also reads mDNS and the names other nodes know (in the order
/// the query log uses: this node's router, then mDNS, then the peers'), says an announced name
/// belongs to the device itself, and, when several addresses have the name, lists them rather than
/// choosing one.
#[tokio::test]
async fn flt_005_rule_hint_reads_mdns_peers_and_several_matches() {
    let n = Node::new(telltale_config::Config::default());
    n.src
        .pipeline
        .mdns_names
        .store(table(&[lease([192, 168, 1, 30], "printer")]));
    let mut peers = crate::devices::Names::default();
    peers.routers.insert(
        Ipv4Addr::new(192, 168, 1, 40),
        lease([192, 168, 1, 40], "nas"),
    );
    peers.mdns.insert(
        Ipv4Addr::new(192, 168, 1, 50),
        lease([192, 168, 1, 50], "speaker"),
    );
    n.src.pipeline.peer_names.store(Arc::new(peers));
    for (name, says) in [
        ("printer", "`printer` is what 192.168.1.30 calls itself."),
        ("nas", "`nas` is what your router calls 192.168.1.40."),
        ("speaker", "`speaker` is what 192.168.1.50 calls itself."),
    ] {
        let (s, v) = n
            .put("/api/v1/rules/x", &n.admin, true, rule(&[name]))
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{name}: {v}");
        assert_eq!(text(&v, "hint"), format!("{says} {WHAT_TO_DO}"), "{v}");
    }

    // Two televisions with one name (and the router and mDNS agreeing about one of them).
    n.src.pipeline.router_leases.store(table(&[
        lease([192, 168, 1, 102], "LGwebOSTV"),
        lease([192, 168, 1, 140], "LGwebOSTV"),
    ]));
    n.src
        .pipeline
        .mdns_names
        .store(table(&[lease([192, 168, 1, 102], "LGwebOSTV")]));
    let (s, v) = n
        .put("/api/v1/rules/x", &n.admin, true, rule(&["LGwebOSTV"]))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(
        text(&v, "hint"),
        format!(
            "`LGwebOSTV` is the name of more than one device here (192.168.1.102, 192.168.1.140), so pick the address of the one you mean. {WHAT_TO_DO}"
        ),
        "{v}"
    );
}

/// REQ: FLT-005 (issue #73) — "What would this have done?" and the pre-save check are dry runs:
/// they refuse a string with the same words and the same hint as the save, and store nothing.
#[tokio::test]
async fn flt_005_rule_dry_run_refuses_with_the_same_message() {
    let n = node_with_router_tv();
    let (s_dry, dry) = n
        .put("/api/v1/rules/x", &n.admin, true, rule(&["LGwebOSTV"]))
        .await;
    let (s, saved) = n
        .put("/api/v1/rules/x", &n.admin, false, rule(&["LGwebOSTV"]))
        .await;
    assert_eq!(s_dry, StatusCode::UNPROCESSABLE_ENTITY, "{dry}");
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{saved}");
    assert_eq!(dry["detail"], saved["detail"]);
    assert_eq!(dry["hint"], saved["hint"]);
    assert!(text(&dry, "hint").contains("192.168.1.102"), "{dry}");
    // The words are the backend's, whoever asks.
    let (s, v) = n
        .put("/api/v1/rules/x", &n.operator, true, rule(&["LGwebOSTV"]))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["hint"], dry["hint"]);
}

/// REQ: FLT-005 (issue #73) — what a rule accepts doesn't change: the name of a configured device
/// in any case, an IP, a CIDR. A router's name is refused until the device is named that, and
/// then it is the device's name like any other.
#[tokio::test]
async fn flt_005_rule_named_device_any_case_accepted() {
    let n = node_with_router_tv();
    let (s, v) = n
        .put(
            "/api/v1/clients/Living%20Room%20TV",
            &n.admin,
            false,
            serde_json::json!({ "match": ["192.168.1.20"] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    for device in [
        "Living Room TV",
        "living room tv",
        "LIVING ROOM TV",
        "192.168.1.20",
        "192.168.1.0/24",
        "fd00::1",
    ] {
        let (s, v) = n
            .put("/api/v1/rules/ok", &n.admin, false, rule(&[device]))
            .await;
        assert_eq!(s, StatusCode::OK, "{device}: {v}");
    }
    let (s, v) = n
        .put("/api/v1/rules/ok", &n.admin, false, rule(&["LGwebOSTV"]))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "not named yet: {v}");
    // Naming the device (what the hint says to do) makes its name a target, in any case.
    let (s, v) = n
        .put(
            "/api/v1/clients/LGwebOSTV",
            &n.admin,
            false,
            serde_json::json!({ "match": ["192.168.1.102"] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    for device in ["LGwebOSTV", "lgwebostv"] {
        let (s, v) = n
            .put("/api/v1/rules/ok", &n.admin, false, rule(&[device]))
            .await;
        assert_eq!(s, StatusCode::OK, "{device}: {v}");
    }
}

/// A router lease with a MAC address.
fn lease_mac(ip: [u8; 4], name: &str, mac: &str) -> crate::devices::Lease {
    crate::devices::Lease {
        mac: mac.into(),
        ..lease(ip, name)
    }
}

/// REQ: FLT-005 (issue #73, review F6) — when the refused name belongs to an address that IS a
/// configured device (by its IP, or by the MAC its router lease reports), the hint says so and says
/// to use the device's name, instead of telling the person to name a device that is already named.
/// A device recognized by a network (a CIDR) is not "the device": the hint stays the plain one.
#[tokio::test]
async fn flt_005_rule_hint_names_the_configured_device_behind_a_discovered_name() {
    let n = Node::new(telltale_config::Config::default());
    n.src.pipeline.router_leases.store(table(&[
        lease_mac([192, 168, 1, 20], "Pixel-7", "aa:bb:cc:dd:ee:20"),
        lease_mac([192, 168, 1, 21], "Galaxy", "aa:bb:cc:dd:ee:21"),
        lease_mac([10, 0, 5, 30], "printer", "aa:bb:cc:dd:ee:30"),
        lease_mac([192, 168, 1, 22], "Tab", "aa:bb:cc:dd:ee:22"),
    ]));
    for (path, body) in [
        // One address written as a network of one.
        (
            "/api/v1/clients/Kid%20tablet",
            serde_json::json!({ "match": ["192.168.1.22/32"] }),
        ),
        (
            "/api/v1/clients/Mom%20phone",
            serde_json::json!({ "match": ["AA:BB:CC:DD:EE:20"] }),
        ),
        (
            "/api/v1/clients/Dad%20phone",
            serde_json::json!({ "match": ["192.168.1.21"] }),
        ),
        (
            "/api/v1/clients/Office",
            serde_json::json!({ "match": ["10.0.5.0/24"] }),
        ),
    ] {
        let (s, v) = n.put(path, &n.admin, false, body).await;
        assert_eq!(s, StatusCode::OK, "{path}: {v}");
    }
    let cases: [(&str, String); 4] = [
        (
            "Tab",
            "`Tab` is what your router calls 192.168.1.22, which is the device “Kid tablet”: use its name.".to_owned(),
        ),
        (
            "Pixel-7",
            "`Pixel-7` is what your router calls 192.168.1.20, which is the device “Mom phone”: use its name.".to_owned(),
        ),
        (
            "Galaxy",
            "`Galaxy` is what your router calls 192.168.1.21, which is the device “Dad phone”: use its name.".to_owned(),
        ),
        // The network "Office" holds the printer, but a rule for it would be for the whole network.
        (
            "printer",
            format!("`printer` is what your router calls 10.0.5.30. {WHAT_TO_DO}"),
        ),
    ];
    for (name, says) in cases {
        let (s, v) = n
            .put("/api/v1/rules/x", &n.admin, true, rule(&[name]))
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{name}: {v}");
        assert_eq!(text(&v, "hint"), says, "{v}");
    }
}

/// REQ: FLT-005 (issue #73, review F6) — a MAC address typed as the device gets words about MACs
/// (as the mute form's validator has), pointing at naming the device with that MAC in its match
/// list; it names no address and reads no table, so every caller sees it.
#[tokio::test]
async fn flt_005_rule_mac_typed_into_device_gets_mac_wording() {
    let n = node_with_router_tv();
    for mac in ["aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF"] {
        let (s, v) = n.put("/api/v1/rules/x", &n.admin, true, rule(&[mac])).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{mac}: {v}");
        assert_eq!(
            text(&v, "hint"),
            format!(
                "`{mac}` is a MAC address, and a rule can't name one. Name the device with that MAC in its match list (a `[[client]]` in the config file, or `PUT /api/v1/clients/{{name}}`), then use that name. MAC addresses are recognized only where TelltaleDNS can see them."
            ),
            "{v}"
        );
    }
}

/// REQ: FLT-017, FLT-005 (issue #73, review F7) — a pod's `namespace/kind/name` (what the log and
/// `search_queries` show for it) typed as the device is not advised an address: its address changes
/// with every restart, so the hint says to use the group an operator placed the workload in.
#[tokio::test]
async fn flt_017_rule_hint_for_a_workload_name_points_at_its_group() {
    let n = node_with_router_tv();
    let (s, v) = n
        .put(
            "/api/v1/rules/x",
            &n.admin,
            true,
            rule(&["media/deploy/jellyfin"]),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let hint = text(&v, "hint");
    assert!(
        hint.starts_with("`media/deploy/jellyfin` looks like a Kubernetes workload's name, and a pod's address changes with every restart."),
        "{hint}"
    );
    assert!(hint.contains("Add to group…"), "{hint}");
    assert!(
        !hint.contains("Use the address"),
        "no advice to use an address: {hint}"
    );
}

/// REQ: FLT-005 (issue #73, review F7) — the hint looks each refused device up once: the same name
/// twice (in any case) is one sentence, and only the first few devices are looked up at all.
#[tokio::test]
async fn flt_005_rule_hint_checks_each_refused_device_once() {
    let n = node_with_router_tv();
    let (s, v) = n
        .put(
            "/api/v1/rules/x",
            &n.admin,
            true,
            rule(&[
                "LGwebOSTV",
                "lgwebostv",
                "LGwebOSTV",
                "a1",
                "a2",
                "a3",
                "a4",
                "a5",
                "a6",
            ]),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let hint = text(&v, "hint");
    assert_eq!(hint.matches("calls 192.168.1.102").count(), 1, "{hint}");
    assert_eq!(hint.matches(WHAT_TO_DO).count(), 1, "{hint}");
    assert!(
        hint.starts_with("`LGwebOSTV` is what your router"),
        "{hint}"
    );
}

/// An agent token on the operator's account with exactly `scopes`.
fn agent(n: &Node, scopes: &str) -> super::local_access_tests::Creds {
    let olga = n.auth.state().user_by_name("olga").unwrap().unwrap();
    let (id, secret) = (
        telltale_api::auth::crypto::random_id(),
        telltale_api::auth::crypto::random_secret(),
    );
    n.auth
        .state()
        .create_token(
            &id,
            olga.id,
            "tests",
            &telltale_api::auth::crypto::secret_hash(&secret),
            "write",
            None,
            super::local_access_tests::now(),
        )
        .unwrap();
    n.auth
        .state()
        .set_token_agent(&id, scopes, None, None)
        .unwrap();
    vec![("authorization", format!("Bearer tt_{id}_{secret}"))]
}

/// REQ: FLT-005, AGT-004 (issue #73, review F5) — what the hint says about this node's devices
/// (which address a name belongs to, which configured device that is) is a lookup over every
/// device's name and address, like reading the query log: an agent token without `querylog:read`
/// gets the plain hint (and the MAC wording, which names nothing of the node's). People and agents
/// with the scope get the address. Tested through the REST route and through the MCP plan preview,
/// which makes the same REST call in process for the agent.
#[tokio::test]
async fn agt_004_rule_hint_without_querylog_names_no_address() {
    let n = node_with_router_tv();
    let blind = agent(&n, "config:write:rules config:read");
    let reader = agent(&n, "config:write:rules querylog:read");
    for (who, creds, sees) in [
        ("agent without querylog:read", &blind, false),
        ("agent with querylog:read", &reader, true),
        ("operator", &n.operator, true),
        ("admin", &n.admin, true),
    ] {
        let (s, v) = n
            .put("/api/v1/rules/x", creds, true, rule(&["LGwebOSTV"]))
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{who}: {v}");
        assert!(
            text(&v, "detail").contains("`LGwebOSTV` isn't a named device"),
            "{who}: {v}"
        );
        if sees {
            assert!(text(&v, "hint").contains("192.168.1.102"), "{who}: {v}");
        } else {
            assert_eq!(text(&v, "hint"), WHAT_TO_DO, "{who}: {v}");
        }
        assert!(
            !v.to_string().contains("calls 192.168.1.102") || sees,
            "{who}: {v}"
        );
    }
    // A MAC names nothing of the node's: the agent without the scope sees the same wording.
    let (s, v) = n
        .put(
            "/api/v1/rules/x",
            &blind,
            true,
            rule(&["aa:bb:cc:dd:ee:ff"]),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(text(&v, "hint").contains("is a MAC address"), "{v}");

    // The MCP plan preview: the same refusal, inside the tool's error.
    for (who, creds, sees) in [("blind agent", &blind, false), ("reader", &reader, true)] {
        let (s, v) = n
            .send(
                "POST",
                "/mcp",
                creds,
                Some(serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": { "name": "plan_block_domain", "arguments": {
                        "domain": "scan.example.com", "devices": ["LGwebOSTV"],
                        "reason": "stop a scan"
                    }}
                })),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{who}: {v}");
        let all = v.to_string();
        assert!(
            all.contains("isn't a named device") && all.contains("Name this device"),
            "{who}: the plan preview carries the refusal: {all}"
        );
        assert_eq!(all.contains("192.168.1.102"), sees, "{who}: {all}");
    }
}

/// REQ: FLT-005, AGT-004 (issue #73, round-2 S2) — the plain hint fails CLOSED across versions. The
/// refusal the primary sends over the cluster channel has the plain text in the `hint` an older
/// replica reads (it ignores fields it doesn't know), and the address text only in an extra field;
/// so an older node, which can't tell an agent without `querylog:read` from anyone else, never has
/// the address to show. (The node that answers the caller gives the fuller text to whoever may see
/// it: `simulate_api`'s `agt_004_the_address_hint_goes_only_to_those_who_may_see_it`.)
#[tokio::test]
async fn flt_005_an_older_node_reading_the_primarys_refusal_sees_only_the_plain_hint() {
    use super::{ApiBackend, ManagedKind, ManagedWrite};
    use telltale_api::Backend as _;

    // What an older node's own `WireProblem` has: the code, the detail, the hint, the diff.
    #[derive(serde::Deserialize)]
    struct Older {
        detail: String,
        hint: Option<String>,
    }

    let n = node_with_router_tv();
    let backend = ApiBackend {
        src: Arc::clone(&n.src),
    };
    let write = |device: &str| ManagedWrite {
        kind: ManagedKind::Rule,
        name: "x".into(),
        body: Some(rule(&[device])),
        dry_run: true,
        expect: None,
        by: "tests".into(),
        simulate: None,
        by_admin: false,
    };
    let primary_answers = |p: telltale_api::problem::Problem| {
        serde_json::to_value(crate::forward::WireProblem::from(p)).unwrap()
    };

    let p = backend.write_managed(write("LGwebOSTV")).await.unwrap_err();
    let wire = primary_answers(p);
    let older: Older = serde_json::from_value(wire.clone()).unwrap();
    assert!(
        older.detail.contains("`LGwebOSTV` isn't a named device"),
        "{wire}"
    );
    assert_eq!(older.hint.as_deref(), Some(WHAT_TO_DO), "{wire}");
    assert!(
        !serde_json::to_string(&older.hint)
            .unwrap()
            .contains("192.168.1.102"),
        "an older node has no address to show: {wire}"
    );
    // The fuller text is there for a node that knows the field, beside it.
    assert!(
        wire["fuller_hint"].as_str().is_some_and(|f| f
            .contains("what your router calls 192.168.1.102")
            && f.ends_with(WHAT_TO_DO)),
        "{wire}"
    );
    // A refusal that says nothing of this node's tables sends no extra field at all.
    let p = backend.write_managed(write("fridge")).await.unwrap_err();
    let wire = primary_answers(p);
    assert!(wire.get("fuller_hint").is_none(), "{wire}");
    assert_eq!(wire["hint"], WHAT_TO_DO);
}
