// REQ: AGT-004, FLT-013 (ADR-183) — `GET /api/v1/explain` names the client's MAC. Since the
// kernel's neighbor table is read whenever `[clients] neighbor_table` is on (the default), every
// node holds the MAC of every neighbor, whether or not a device is named by its MAC, and explain
// needs only `analytics:read`: so the MAC is shown only to a caller who may read the devices
// (`/api/v1/clients`: `config:read` for an agent token, not restricted to a group), as the MACs
// in `[[client]]` keys are. A MAC the caller gave is theirs and is echoed. Driven through the real
// routes, sign-in and backend (the harness of `local_access_tests`); no host is contacted.

use axum::http::StatusCode;

use super::local_access_tests::Node;

const NEIGHBOR: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
const EXPLAIN: &str = "/api/v1/explain?name=example.com&client=192.168.1.20";

/// A node with no device named by its MAC, whose kernel table holds a neighbor.
fn node() -> Node {
    let n = Node::new(telltale_config::Config::default());
    assert!(!n.src.pipeline.current().policy.clients.uses_macs());
    n.src
        .pipeline
        .neighbors
        .replace([("192.168.1.20".parse().unwrap(), NEIGHBOR)]);
    n
}

fn mac_in(v: &serde_json::Value) -> Option<&str> {
    v["client"]["mac"].as_str()
}

/// REQ: AGT-004, FLT-013 — who sees the neighbor's MAC in an explanation, on a node where no
/// device is named by its MAC (the case the base never showed a MAC on).
#[tokio::test]
async fn agt_004_explain_mac_needs_config_read() {
    let n = node();
    let analytics_only = n.agent("analytics:read", None);
    let with_devices = n.agent("analytics:read config:read", None);
    let for_a_group = n.agent("analytics:read config:read", Some("kids"));
    for (who, creds, sees) in [
        ("admin token", &n.admin, true),
        ("admin session", &n.admin_session, true),
        ("operator token", &n.operator, true),
        ("viewer token", &n.viewer, true),
        (
            "agent with analytics:read and config:read",
            &with_devices,
            true,
        ),
        ("agent with analytics:read only", &analytics_only, false),
    ] {
        let (s, v) = n.send("GET", EXPLAIN, creds, None).await;
        assert_eq!(s, StatusCode::OK, "{who}: {v}");
        assert_eq!(
            mac_in(&v),
            sees.then_some("02:00:00:00:00:01"),
            "{who}: {v}"
        );
        assert_eq!(
            v["client"]["ip"], "192.168.1.20",
            "{who}: the rest is shown: {v}"
        );
    }
    // A token restricted to a group never sees a MAC (it may not read the devices either), and is
    // refused explain where the route is not for it.
    let (s, v) = n.send("GET", EXPLAIN, &for_a_group, None).await;
    assert!(
        s == StatusCode::FORBIDDEN || (s == StatusCode::OK && mac_in(&v).is_none()),
        "{s}: {v}"
    );
    // The MAC a caller gives is theirs: it comes back to them, whoever they are.
    let given = format!("{EXPLAIN}&mac=aa:bb:cc:dd:ee:02");
    for (who, creds) in [
        ("analytics only", &analytics_only),
        ("with devices", &with_devices),
    ] {
        let (s, v) = n.send("GET", &given, creds, None).await;
        assert_eq!(s, StatusCode::OK, "{who}: {v}");
        assert_eq!(mac_in(&v), Some("aa:bb:cc:dd:ee:02"), "{who}: {v}");
    }
}
