use super::*;
use crate::clients::Neighbors;

fn cfg(toml: &str) -> Config {
    telltale_config::Loader::new()
        .toml_str("t.toml", toml)
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config
}

/// `game.example.com` → wire format.
fn q(name: &str) -> Vec<u8> {
    wire(name).unwrap().into_vec()
}

const BASE: &str = r#"
[[group]]
name = "kids"
[[client]]
name = "Mom phone"
match = ["192.168.1.20"]
[[client]]
name = "Kid tablet"
match = ["192.168.1.30"]
groups = ["kids"]
"#;

struct Setup {
    table: ClientTable,
    rules: QuickRules,
    neighbors: Neighbors,
}

fn setup(rules: &str) -> Setup {
    let c = cfg(&format!("{BASE}{rules}"));
    let table = ClientTable::from_config(&c);
    let rules = QuickRules::from_config(&c, &table);
    Setup {
        table,
        rules,
        neighbors: Neighbors::default(),
    }
}

impl Setup {
    /// The decision for `name` asked from `ip` at `now`: Some(allow) or None (lists decide).
    fn ask(&self, ip: &str, name: &str, now: i64) -> Option<bool> {
        let peer: IpAddr = ip.parse().unwrap();
        let who = self.table.identify(peer, None, None, &self.neighbors);
        let groups = self.table.group_ids(who);
        self.rules
            .decide(&q(name), who, peer, groups, now)
            .map(|m| m.allow)
    }
}

const MOM: &str = "192.168.1.20";
const KID: &str = "192.168.1.30";
const GUEST: &str = "192.168.1.99";

#[test]
fn flt_005_device_rules_apply_to_that_device_only_with_subdomains_and_any_case() {
    let s = setup(
        r#"
[[rule]]
id = "mom-game"
action = "allow"
domain = "game.example.com"
devices = ["Mom phone"]
"#,
    );
    assert_eq!(s.ask(MOM, "game.example.com", 0), Some(true));
    assert_eq!(
        s.ask(MOM, "API.Game.Example.COM", 0),
        Some(true),
        "subdomains, any case"
    );
    assert_eq!(
        s.ask(KID, "game.example.com", 0),
        None,
        "other devices: the lists decide"
    );
    assert_eq!(s.ask(MOM, "example.com", 0), None, "a parent isn't covered");
    assert_eq!(s.ask(MOM, "notgame.example.com", 0), None);
}

#[test]
fn flt_005_device_beats_group_beats_everyone() {
    let s = setup(
        r#"
[[rule]]
id = "everyone-block"
action = "block"
domain = "videos.example"
[[rule]]
id = "kids-allow"
action = "allow"
domain = "videos.example"
groups = ["kids"]
[[rule]]
id = "tablet-block"
action = "block"
domain = "videos.example"
devices = ["Kid tablet"]
"#,
    );
    assert_eq!(s.ask(GUEST, "videos.example", 0), Some(false), "everyone");
    assert_eq!(
        s.ask(KID, "videos.example", 0),
        Some(false),
        "the device rule beats its group's allow"
    );
    // Without the device rule, the group's allow beats the everyone block.
    let s = setup(
        r#"
[[rule]]
id = "everyone-block"
action = "block"
domain = "videos.example"
[[rule]]
id = "kids-allow"
action = "allow"
domain = "videos.example"
groups = ["kids"]
"#,
    );
    assert_eq!(s.ask(KID, "videos.example", 0), Some(true));
}

#[test]
fn flt_005_within_a_scope_the_longer_domain_wins_then_allow() {
    let s = setup(
        r#"
[[rule]]
id = "block-all"
action = "block"
domain = "example.org"
devices = ["Mom phone"]
[[rule]]
id = "allow-docs"
action = "allow"
domain = "docs.example.org"
devices = ["Mom phone"]
[[rule]]
id = "both-block"
action = "block"
domain = "same.example.net"
devices = ["Mom phone"]
[[rule]]
id = "both-allow"
action = "allow"
domain = "same.example.net"
devices = ["Mom phone"]
"#,
    );
    assert_eq!(s.ask(MOM, "www.example.org", 0), Some(false));
    assert_eq!(
        s.ask(MOM, "docs.example.org", 0),
        Some(true),
        "more specific"
    );
    assert_eq!(
        s.ask(MOM, "same.example.net", 0),
        Some(true),
        "a tie: allow"
    );
}

#[test]
fn flt_005_expired_rules_stop_applying() {
    let s = setup(
        r#"
[[rule]]
id = "two-hours"
action = "allow"
domain = "game.example.com"
devices = ["Mom phone"]
expires = "2026-10-05T21:30:00Z"
"#,
    );
    let expiry = 1_791_235_800;
    assert_eq!(s.ask(MOM, "game.example.com", expiry - 1), Some(true));
    assert_eq!(s.ask(MOM, "game.example.com", expiry), None);
    assert_eq!(s.rules.expired(expiry - 1), Vec::<Box<str>>::new());
    assert_eq!(s.rules.expired(expiry), vec![Box::<str>::from("two-hours")]);
}

#[test]
fn flt_005_devices_by_address_and_no_rules_cost_nothing() {
    let s = setup(
        r#"
[[rule]]
id = "lan-block"
action = "block"
domain = "ads.example.net"
devices = ["192.168.1.0/28"]
"#,
    );
    assert_eq!(s.ask("192.168.1.5", "ads.example.net", 0), Some(false));
    assert_eq!(s.ask(MOM, "ads.example.net", 0), None, ".20 is outside /28");
    let none = setup("");
    assert!(none.rules.is_empty());
    assert_eq!(none.ask(MOM, "anything.example", 0), None);
}
