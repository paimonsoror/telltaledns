// REQ: FLT-006, API-010, AGT-004 (ADR-183) — `GET /api/v1/clients/{address}/identity` says how the
// address is recognized on the node that answers (`recognition`) and the MAC a device there could
// be named by, with where it comes from: the kernel's neighbor table, this node's router, or
// another full member's. The router's MACs are offered before any device matches by MAC (the
// moment the MAC is wanted), from the same function that builds the MAC table. A MAC at two or
// more addresses is given as shared, and a binding the node withholds is given as none. Driven
// through the real routes, sign-in and backend (the harness of `local_access_tests`); no host is
// contacted, and every address and MAC here is made up.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use axum::http::StatusCode;

use super::local_access_tests::{Creds, Node};
use crate::devices::{Lease, PeerMacs};

/// `tablet` is named by this MAC, `guest` by an address. The MAC is universally administered.
const TABLET: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const BASE: &str = r#"
[[group]]
name = "default"
lists = []

[[group]]
name = "kids"
lists = []

[[client]]
name = "tablet"
match = ["00:11:22:33:44:55"]
groups = ["kids"]

[[client]]
name = "guest"
match = ["10.0.0.9"]
groups = ["default"]
"#;
/// Only an address names a device: no device is named by its MAC.
const NO_MACS: &str = r#"
[[group]]
name = "default"
lists = []

[[client]]
name = "guest"
match = ["10.0.0.9"]
groups = ["default"]
"#;

/// A node over `toml`, whose policy has its devices.
fn node(toml: &str) -> Node {
    let cfg: telltale_config::Config = telltale_config::Loader::new()
        .toml_str("t.toml", toml)
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    let n = Node::new(cfg.clone());
    n.src.pipeline.reload(
        std::sync::Arc::new(telltale_upstream::Router::default()),
        crate::pipeline::Policy {
            allowed: crate::pipeline::Policy::open().allowed,
            ..crate::pipeline::Policy::from_config(&cfg, telltale_policy::LocalData::default())
        },
    );
    n
}

fn ip(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, last)
}

fn lease(last: u8, mac: &str) -> Lease {
    Lease {
        mac: mac.into(),
        ip: ip(last),
        hostname: None,
        expires: 0,
        offline: false,
        unsure: false,
        stale: false,
    }
}

/// What this node's routers say, and what the other full members' routers say.
fn routers(n: &Node, own: &[Lease], peers: &[(u8, [u8; 6])], peer_tombstones: &[u8]) {
    let leases: HashMap<Ipv4Addr, Lease> = own.iter().map(|l| (l.ip, l.clone())).collect();
    n.src
        .pipeline
        .router_leases
        .store(std::sync::Arc::new(leases));
    n.src
        .pipeline
        .peer_router_macs
        .store(std::sync::Arc::new(PeerMacs {
            macs: peers.iter().map(|(l, m)| (ip(*l), *m)).collect(),
            tombstones: peer_tombstones.iter().map(|l| ip(*l)).collect(),
            ..PeerMacs::default()
        }));
}

async fn identity(n: &Node, who: &Creds, address: &str) -> serde_json::Value {
    let (s, v) = n
        .send(
            "GET",
            &format!("/api/v1/clients/{address}/identity"),
            who,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{address}: {v}");
    v
}

// REQ: API-010 (ADR-183) — an address's identity says how it is recognized now: the device and
// how (`identifiedBy`), the MAC a device there could be named by and where it comes from, and
// whether that MAC is locally administered. A named device's identity (by name) has no recognition:
// it isn't an address.
#[tokio::test]
async fn api_010_identity_says_how_an_address_is_recognized() {
    let n = node(BASE);
    n.src.pipeline.neighbors.replace([
        (ip(77).into(), TABLET),
        (ip(78).into(), [0x02, 0, 0, 0, 0, 0x01]),
    ]);
    let r = &identity(&n, &n.admin, "10.0.0.77").await["recognition"];
    assert_eq!(r["device"], "tablet", "{r}");
    assert_eq!(r["identifiedBy"], "neighbor_mac", "{r}");
    assert_eq!(r["mac"], "00:11:22:33:44:55", "{r}");
    assert_eq!(r["macFrom"], "neighbor", "{r}");
    assert!(
        r.get("macShared").is_none() && r.get("macRandomized").is_none(),
        "false flags are left out: {r}"
    );

    // No device matches it, and the MAC is a made-up (locally administered) one.
    let r = &identity(&n, &n.admin, "10.0.0.78").await["recognition"];
    assert!(r.get("device").is_none(), "{r}");
    assert_eq!(r["identifiedBy"], "default", "{r}");
    assert_eq!(r["mac"], "02:00:00:00:00:01", "{r}");
    assert_eq!(r["macRandomized"], true, "{r}");

    // Named by its address: recognized, with no MAC to offer.
    let r = &identity(&n, &n.admin, "10.0.0.9").await["recognition"];
    assert_eq!(r["device"], "guest", "{r}");
    assert_eq!(r["identifiedBy"], "ip", "{r}");
    assert!(r.get("mac").is_none() && r.get("macFrom").is_none(), "{r}");

    // An address nobody knows.
    let r = &identity(&n, &n.admin, "10.0.0.99").await["recognition"];
    assert_eq!(r["identifiedBy"], "default", "{r}");
    assert!(r.get("device").is_none() && r.get("mac").is_none(), "{r}");

    // By name there is no address: nothing to say.
    let (s, v) = n
        .send("GET", "/api/v1/clients/tablet/identity", &n.admin, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v.get("recognition").is_none(), "{v}");
}

// REQ: FLT-006, API-010 (ADR-183) — while no device is named by its MAC the table holds no
// router entries, and the identity offers the router's MAC all the same: it is the MAC the
// dialog is about to name a device by. This node's router (`router`), then another member's
// (`peer`); the kernel's entry wins over both.
#[tokio::test]
async fn api_010_recognition_offers_a_router_mac_before_any_device_matches_by_mac() {
    let n = node(NO_MACS);
    assert!(!n.src.pipeline.current().policy.clients.uses_macs());
    n.src
        .pipeline
        .neighbors
        .replace([(ip(52).into(), [0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0x52])]);
    routers(
        &n,
        &[
            lease(50, "02:00:00:00:00:50"),
            lease(52, "00:bb:bb:bb:bb:52"),
        ],
        &[(51, [0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0x51])],
        &[],
    );
    assert_eq!(n.src.pipeline.neighbors.router_len(), 0, "no entries yet");

    let r = &identity(&n, &n.admin, "10.0.0.50").await["recognition"];
    assert_eq!(r["identifiedBy"], "default", "{r}");
    assert_eq!(r["mac"], "02:00:00:00:00:50", "{r}");
    assert_eq!(r["macFrom"], "router", "{r}");
    assert_eq!(r["macRandomized"], true, "{r}");

    let r = &identity(&n, &n.admin, "10.0.0.51").await["recognition"];
    assert_eq!(r["mac"], "00:cc:cc:cc:cc:51", "{r}");
    assert_eq!(r["macFrom"], "peer", "{r}");
    assert!(r.get("macRandomized").is_none(), "{r}");

    let r = &identity(&n, &n.admin, "10.0.0.52").await["recognition"];
    assert_eq!(
        r["mac"], "00:aa:aa:aa:aa:52",
        "the kernel's entry wins: {r}"
    );
    assert_eq!(r["macFrom"], "neighbor", "{r}");
}

// REQ: FLT-006, API-010 (ADR-183) — a MAC the routers report at two or more addresses (a range
// extender or bridge) is given as shared, and a device named by it is recognized at none of them;
// a binding this node withholds (an `unsure` lease, a junk MAC, a member's tombstone, an offline
// client) has no MAC to offer.
#[tokio::test]
async fn api_010_recognition_withholds_a_shared_or_tombstoned_mac() {
    let n = node(NO_MACS);
    let mut unsure = lease(62, "00:dd:dd:dd:dd:62");
    unsure.unsure = true;
    let mut offline = lease(65, "00:ee:ee:ee:ee:65");
    offline.offline = true;
    routers(
        &n,
        &[
            lease(60, "00:11:11:11:11:99"),
            lease(61, "00:11:11:11:11:99"),
            unsure,
            lease(63, "01:00:5e:00:00:63"),
            lease(64, "not a mac"),
            offline,
        ],
        &[(66, [0x00, 0xff, 0xff, 0xff, 0xff, 0x66])],
        &[66],
    );
    for last in [60, 61] {
        let r = &identity(&n, &n.admin, &format!("10.0.0.{last}")).await["recognition"];
        assert_eq!(r["mac"], "00:11:11:11:11:99", "{last}: {r}");
        assert_eq!(r["macShared"], true, "{last}: {r}");
        assert_eq!(r["macFrom"], "router", "{last}: {r}");
    }
    for (last, why) in [
        (62, "an unsure lease"),
        (63, "a multicast MAC"),
        (64, "an unparsable MAC"),
        (65, "an offline client"),
        (66, "a member's tombstone, though it also has a binding"),
    ] {
        let r = &identity(&n, &n.admin, &format!("10.0.0.{last}")).await["recognition"];
        assert!(
            r.get("mac").is_none() && r.get("macFrom").is_none() && r.get("macShared").is_none(),
            "{why}: {r}"
        );
        assert_eq!(r["identifiedBy"], "default", "{why}: {r}");
    }
}

// REQ: FLT-006, CLU-010 (ADR-183) — with `[clients] router_macs = false` no router's or member's
// MAC is offered (a device named by it wouldn't be recognized by it); the kernel's still is.
#[tokio::test]
async fn api_010_recognition_offers_no_router_mac_when_router_macs_is_off() {
    let n = node(&format!("[clients]\nrouter_macs = false\n{NO_MACS}"));
    n.src
        .pipeline
        .neighbors
        .replace([(ip(52).into(), [0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0x52])]);
    routers(
        &n,
        &[lease(50, "00:11:11:11:11:50")],
        &[(51, [0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0x51])],
        &[],
    );
    for last in [50, 51] {
        let r = &identity(&n, &n.admin, &format!("10.0.0.{last}")).await["recognition"];
        assert!(r.get("mac").is_none(), "{last}: {r}");
        assert_eq!(r["identifiedBy"], "default", "{last}: {r}");
    }
    let r = &identity(&n, &n.admin, "10.0.0.52").await["recognition"];
    assert_eq!(r["mac"], "00:aa:aa:aa:aa:52", "{r}");
    assert_eq!(r["macFrom"], "neighbor", "{r}");
}

// REQ: API-010 (ADR-183) — at query-log privacy level 2 and above (clients hidden) the identity
// says nothing about how an address is recognized; at level 1 it still does.
#[tokio::test]
async fn api_010_recognition_is_hidden_at_privacy_level_2() {
    for (level, shown) in [(0, true), (1, true), (2, false), (3, false)] {
        let n = node(&format!(
            "[telemetry.qlog]\nprivacy_level = {level}\n{NO_MACS}"
        ));
        routers(&n, &[lease(50, "00:11:11:11:11:50")], &[], &[]);
        let v = identity(&n, &n.admin, "10.0.0.50").await;
        assert_eq!(v.get("recognition").is_some(), shown, "level {level}: {v}");
        assert!(
            !v.to_string().contains("00:11:11:11:11:50") || shown,
            "level {level}: {v}"
        );
    }
}

// REQ: AGT-004, FLT-006 (ADR-183) — the MAC an identity offers is what `/api/v1/clients` shows in
// a device's keys, so it goes only to a caller who may read the devices: a person or API token of
// any role, an agent with `config:read` that isn't restricted to a group; an agent with only
// `analytics:read` (what `identify_device` needs) gets the recognition without the MAC. Explain
// follows the same rule.
#[tokio::test]
async fn agt_004_recognition_mac_needs_config_read() {
    let n = node(NO_MACS);
    routers(
        &n,
        &[lease(50, "00:11:11:11:11:50")],
        &[(51, [0, 0x22, 0x22, 0x22, 0x22, 0x51])],
        &[],
    );
    let analytics_only = n.agent("analytics:read", None);
    let with_devices = n.agent("analytics:read config:read", None);
    let for_a_group = n.agent("analytics:read config:read", Some("kids"));
    for (who, creds, sees) in [
        ("admin token", &n.admin, true),
        ("admin session", &n.admin_session, true),
        ("operator token", &n.operator, true),
        ("viewer token", &n.viewer, true),
        ("agent with config:read", &with_devices, true),
        ("agent with analytics:read only", &analytics_only, false),
    ] {
        for (last, mac, from) in [
            (50, "00:11:11:11:11:50", "router"),
            (51, "00:22:22:22:22:51", "peer"),
        ] {
            let (s, v) = n
                .send(
                    "GET",
                    &format!("/api/v1/clients/10.0.0.{last}/identity"),
                    creds,
                    None,
                )
                .await;
            assert_eq!(s, StatusCode::OK, "{who}: {v}");
            let r = &v["recognition"];
            assert_eq!(
                r["identifiedBy"], "default",
                "{who}: the rest is shown: {v}"
            );
            assert_eq!(r["mac"].as_str(), sees.then_some(mac), "{who} {last}: {v}");
            assert_eq!(
                r["macFrom"].as_str(),
                sees.then_some(from),
                "{who} {last}: {v}"
            );
            assert!(
                !v.to_string().contains(&mac[..8]) || sees,
                "{who}: nothing else carries it: {v}"
            );
        }
    }
    // Shared: whether a MAC is shared is told with the MAC, not without it.
    routers(
        &n,
        &[
            lease(60, "00:33:33:33:33:33"),
            lease(61, "00:33:33:33:33:33"),
        ],
        &[],
        &[],
    );
    for (who, creds, sees) in [
        ("devices", &with_devices, true),
        ("analytics only", &analytics_only, false),
    ] {
        let (_, v) = n
            .send("GET", "/api/v1/clients/10.0.0.60/identity", creds, None)
            .await;
        assert_eq!(
            v["recognition"]["macShared"].as_bool().unwrap_or(false),
            sees,
            "{who}: {v}"
        );
        assert_eq!(v["recognition"]["mac"].is_string(), sees, "{who}: {v}");
    }
    // A token restricted to a group may not read the devices: no MAC.
    let (s, v) = n
        .send(
            "GET",
            "/api/v1/clients/10.0.0.50/identity",
            &for_a_group,
            None,
        )
        .await;
    assert!(
        s == StatusCode::FORBIDDEN
            || (s == StatusCode::OK && v["recognition"].get("mac").is_none()),
        "{s}: {v}"
    );
}

// REQ: AGT-004, FLT-013 (ADR-183) — explain's MAC and where it comes from (`macFrom`) follow the same
// rule as the identity's: a MAC the caller gave in the request is theirs.
#[tokio::test]
async fn agt_004_explain_mac_from_follows_the_mac() {
    let n = node(NO_MACS);
    let analytics_only = n.agent("analytics:read", None);
    let with_devices = n.agent("analytics:read config:read", None);
    n.src
        .pipeline
        .neighbors
        .replace([(ip(70).into(), [0x00, 0x44, 0x44, 0x44, 0x44, 0x70])]);
    let explain = "/api/v1/explain?name=example.com&client=10.0.0.70";
    for (who, creds, sees) in [
        ("admin", &n.admin, true),
        ("devices", &with_devices, true),
        ("analytics only", &analytics_only, false),
    ] {
        let (s, v) = n.send("GET", explain, creds, None).await;
        assert_eq!(s, StatusCode::OK, "{who}: {v}");
        assert_eq!(
            v["client"]["mac"].as_str(),
            sees.then_some("00:44:44:44:44:70"),
            "{who}: {v}"
        );
        assert_eq!(
            v["client"]["macFrom"].as_str(),
            sees.then_some("neighbor"),
            "{who}: {v}"
        );
    }
    let (_, v) = n
        .send(
            "GET",
            &format!("{explain}&mac=00:55:55:55:55:55"),
            &analytics_only,
            None,
        )
        .await;
    assert_eq!(v["client"]["mac"], "00:55:55:55:55:55", "{v}");
    assert_eq!(v["client"]["macFrom"], "given", "{v}");
}

// REQ: FLT-006, API-010 (ADR-183) — the kernel's neighbor table has no shared-MAC rule (a device is
// recognized by an entry it holds, as it always was), so behind a MAC-translating extender the
// kernel holds one MAC at every address behind it. The identity says so (`macShared`), so the
// dialog doesn't offer that MAC as if it named one device: it is withheld from the default, with
// the reason. Counted in the request, over this node's table, never on the query path.
#[tokio::test]
async fn api_010_recognition_flags_a_kernel_mac_at_two_addresses() {
    let n = node(NO_MACS);
    n.src.pipeline.neighbors.replace([
        (ip(80).into(), [0x00, 0xee, 0xee, 0xee, 0xee, 0x01]),
        (ip(81).into(), [0x00, 0xee, 0xee, 0xee, 0xee, 0x01]),
        (ip(82).into(), [0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0x82]),
    ]);
    for last in [80, 81] {
        let r = &identity(&n, &n.admin, &format!("10.0.0.{last}")).await["recognition"];
        assert_eq!(r["mac"], "00:ee:ee:ee:ee:01", "{last}: {r}");
        assert_eq!(r["macFrom"], "neighbor", "{last}: {r}");
        assert_eq!(r["macShared"], true, "{last}: {r}");
    }
    let r = &identity(&n, &n.admin, "10.0.0.82").await["recognition"];
    assert_eq!(r["mac"], "00:aa:aa:aa:aa:82", "{r}");
    assert!(r.get("macShared").is_none(), "alone at its address: {r}");
}

// REQ: AGT-004, FLT-013 (ADR-183) — explain's MAC and `macFrom` are hidden at query-log privacy
// level 2 and above, as the identity's recognition is (every node reads its neighbor table now,
// so the MAC of a neighbor is there to be read); a MAC the caller gave is theirs and comes back.
#[tokio::test]
async fn agt_004_explain_mac_is_hidden_at_privacy_level_2() {
    for (level, shown) in [(0, true), (1, true), (2, false), (3, false)] {
        let n = node(&format!(
            "[telemetry.qlog]\nprivacy_level = {level}\n{NO_MACS}"
        ));
        n.src
            .pipeline
            .neighbors
            .replace([(ip(70).into(), [0x00, 0x44, 0x44, 0x44, 0x44, 0x70])]);
        let explain = "/api/v1/explain?name=example.com&client=10.0.0.70";
        let (s, v) = n.send("GET", explain, &n.admin, None).await;
        assert_eq!(s, StatusCode::OK, "level {level}: {v}");
        assert_eq!(
            v["client"]["mac"].as_str(),
            shown.then_some("00:44:44:44:44:70"),
            "level {level}: {v}"
        );
        assert_eq!(
            v["client"]["macFrom"].as_str(),
            shown.then_some("neighbor"),
            "level {level}: {v}"
        );
        let given = format!("{explain}&mac=00:55:55:55:55:55");
        let (_, v) = n.send("GET", &given, &n.admin, None).await;
        assert_eq!(
            v["client"]["mac"], "00:55:55:55:55:55",
            "level {level}: {v}"
        );
        assert_eq!(v["client"]["macFrom"], "given", "level {level}: {v}");
    }
}

// REQ: FLT-013 (ADR-183) — explain looks the client's MAC up under its canonical address, as
// identification does: a client given as an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) has the
// MAC of the IPv4 address.
#[tokio::test]
async fn flt_013_explain_finds_the_mac_of_a_mapped_address() {
    let n = node(NO_MACS);
    n.src
        .pipeline
        .neighbors
        .replace([(ip(70).into(), [0x00, 0x44, 0x44, 0x44, 0x44, 0x70])]);
    let (s, v) = n
        .send(
            "GET",
            "/api/v1/explain?name=example.com&client=::ffff:10.0.0.70",
            &n.admin,
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["client"]["mac"], "00:44:44:44:44:70", "{v}");
    assert_eq!(v["client"]["macFrom"], "neighbor", "{v}");
}

// REQ: FLT-006, API-010 (ADR-183) — "a MAC at several addresses" means several IPv4 addresses (the
// routers' bindings are IPv4 only): the kernel's table holds a dual-stack device's MAC at its IPv4
// address and at its link-local and global IPv6 ones, and that is one device, not an extender, so
// no IPv6 entry makes a MAC shared. A MAC at two IPv4 addresses still is.
#[tokio::test]
async fn api_010_a_dual_stack_device_is_not_shared() {
    let n = node(NO_MACS);
    let dual: [u8; 6] = [0x00, 0xd1, 0xa1, 0x00, 0x00, 0x90];
    let extender: [u8; 6] = [0x00, 0xee, 0xee, 0xee, 0xee, 0x02];
    let v6 = |text: &str| -> std::net::IpAddr { text.parse().unwrap() };
    n.src.pipeline.neighbors.replace([
        (ip(90).into(), dual),
        (v6("fe80::2d1:a1ff:fe00:90"), dual),
        (v6("2001:db8::90"), dual),
        (ip(91).into(), extender),
        (ip(92).into(), extender),
    ]);
    let r = &identity(&n, &n.admin, "10.0.0.90").await["recognition"];
    assert_eq!(r["mac"], "00:d1:a1:00:00:90", "{r}");
    assert!(
        r.get("macShared").is_none(),
        "one IPv4 address and two IPv6 ones: {r}"
    );
    // The device's IPv6 address is the same device.
    let r = &identity(&n, &n.admin, "2001:db8::90").await["recognition"];
    assert_eq!(r["mac"], "00:d1:a1:00:00:90", "{r}");
    assert!(r.get("macShared").is_none(), "{r}");
    // Two IPv4 addresses with one MAC are still shared.
    for last in [91, 92] {
        let r = &identity(&n, &n.admin, &format!("10.0.0.{last}")).await["recognition"];
        assert_eq!(r["macShared"], true, "{last}: {r}");
    }
}

// REQ: AGT-004, FLT-006 (ADR-183) — `identify_device` through `/mcp` follows the same rule as the
// REST route it calls (the tool re-enters the router with the caller's own credentials): an agent
// with `analytics:read` alone (all `identify_device` needs) gets the recognition without the MAC,
// one that may also read the devices (`config:read`, not restricted to a group) gets it. A guard,
// not a fix: it passes on the code before this round.
#[tokio::test]
async fn agt_004_identify_device_through_mcp_gives_the_mac_only_to_who_may_read_devices() {
    let n = node(NO_MACS);
    routers(&n, &[lease(50, "00:11:11:11:11:50")], &[], &[]);
    let analytics_only = n.agent("analytics:read", None);
    let with_devices = n.agent("analytics:read config:read", None);
    let call = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "identify_device", "arguments": {"client": "10.0.0.50"}}
    });
    for (who, creds, sees) in [
        ("analytics only", &analytics_only, false),
        ("with config:read", &with_devices, true),
    ] {
        let (s, v) = n.send("POST", "/mcp", creds, Some(call.clone())).await;
        assert_eq!(s, StatusCode::OK, "{who}: {v}");
        let text = v.to_string();
        assert!(
            text.contains("identifiedBy"),
            "{who}: the recognition is there: {text}"
        );
        assert_eq!(text.contains("00:11:11:11:11:50"), sees, "{who}: {text}");
    }
}
