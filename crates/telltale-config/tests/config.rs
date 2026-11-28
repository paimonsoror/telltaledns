//! OPS-005 acceptance tests: unknown keys error with path; env overrides apply.

use std::fmt::Write as _;

use telltale_config::{ByteSize, Config, ConfigError, Loader, Role, Strategy, TelemetryMode};

const EXAMPLE: &str = include_str!("../../../docs/examples/telltale.toml");

fn load_str(toml: &str) -> Result<telltale_config::Loaded, Vec<ConfigError>> {
    Loader::new()
        .toml_str("test.toml", toml)
        .env(Vec::<(String, String)>::new())
        .load()
}

fn paths(errs: &[ConfigError]) -> Vec<&str> {
    errs.iter().map(|e| e.path.as_str()).collect()
}

#[test]
fn ops_005_defaults_are_valid() {
    let loaded = load_str("").unwrap();
    assert_eq!(loaded.config, Config::default());
    assert_eq!(loaded.config.listen.len(), 4);
    assert_eq!(loaded.config.node.data_dir.as_str(), "/var/lib/telltale");
}

#[test]
fn ops_005_example_config_is_valid() {
    let loaded = load_str(EXAMPLE).unwrap();
    let c = &loaded.config;
    assert_eq!(c.upstream.len(), 3);
    assert_eq!(c.upstream_group[0].strategy, Strategy::Fastest);
    assert_eq!(c.cache.max_bytes, ByteSize::mib(32));
    assert_eq!(c.cluster.site.as_str(), "home-pi");
    assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
}

#[test]
fn ops_005_unknown_key_errors_with_path() {
    let errs = load_str("[cache]\nmax_ttl = 600\nbogus = 1\n").unwrap_err();
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].path, "cache.bogus");
    assert!(
        errs[0].message.contains("unknown field `bogus`"),
        "{}",
        errs[0]
    );
}

#[test]
fn ops_005_unknown_key_in_array_element_errors_with_path() {
    let errs = load_str(
        "[[upstream]]\nname = \"a\"\nurl = \"udp://9.9.9.9\"\n\n\
         [[upstream]]\nname = \"b\"\nurl = \"udp://1.1.1.1\"\ntimeout = 5\n",
    )
    .unwrap_err();
    assert_eq!(errs[0].path, "upstream[1].timeout");
}

#[test]
fn ops_005_unknown_top_level_key_errors_with_path() {
    let errs = load_str("cache_size = 5\n").unwrap_err();
    assert_eq!(errs[0].path, "cache_size");
}

#[test]
fn ops_005_type_error_has_path() {
    let errs = load_str("[telemetry.qlog]\nretention_days = \"thirty\"\n").unwrap_err();
    assert_eq!(errs[0].path, "telemetry.qlog.retention_days");
}

#[test]
fn ops_005_syntax_error_names_the_file() {
    let errs = load_str("[cache\n").unwrap_err();
    assert_eq!(errs[0].path, "test.toml");
}

#[test]
fn ops_005_control_characters_rejected() {
    let errs = load_str("[node]\nname = \"pi\\nevil\"\n").unwrap_err();
    assert_eq!(errs[0].path, "node.name");
    assert!(errs[0].message.contains("control character"));
}

#[test]
fn ops_005_env_override_applies() {
    let loaded = Loader::new()
        .toml_str("test.toml", "[cache]\nmax_ttl = 600\n")
        .env([
            ("TELLTALE_CACHE_MAX_TTL", "1200"),
            ("TELLTALE_ROLE", "resolver"),
            ("TELLTALE_CLUSTER_SITE", "home-pi"),
            ("TELLTALE_CLUSTER_ELIGIBLE", "false"),
            ("TELLTALE_TELEMETRY_MODE", "ship"),
            ("TELLTALE_TELEMETRY_QLOG_RETENTION_DAYS", "7"),
            ("TELLTALE_CACHE_MAX_BYTES", "64MiB"),
            ("UNRELATED", "x"),
        ])
        .load()
        .unwrap();
    let c = loaded.config;
    assert_eq!(c.cache.max_ttl, 1200, "env must beat the file");
    assert_eq!(c.node.role, Role::Resolver);
    assert_eq!(c.cluster.site.as_str(), "home-pi");
    assert!(!c.cluster.eligible);
    assert_eq!(c.telemetry.mode, TelemetryMode::Ship);
    assert_eq!(c.telemetry.qlog.retention_days, 7);
    assert_eq!(c.cache.max_bytes, ByteSize::mib(64));
}

#[test]
fn ops_005_env_override_bad_value_names_variable() {
    let errs = Loader::new()
        .env([("TELLTALE_CACHE_MAX_TTL", "soon")])
        .load()
        .unwrap_err();
    assert_eq!(errs[0].path, "cache.max_ttl (from TELLTALE_CACHE_MAX_TTL)");
}

#[test]
fn ops_005_env_override_invalid_enum_is_reported() {
    let errs = Loader::new()
        .env([("TELLTALE_ROLE", "boss")])
        .load()
        .unwrap_err();
    assert_eq!(errs[0].path, "node.role");
}

#[test]
fn ops_005_unknown_env_vars_warn_not_fail() {
    // Kubernetes service links for a Service named "telltale".
    let loaded = Loader::new()
        .env([
            ("TELLTALE_SERVICE_HOST", "10.0.0.1"),
            ("TELLTALE_PORT", "udp://10.0.0.1:53"),
            ("TELLTALE_CONFIG", "/etc/telltale/telltale.toml"),
            // T6.14 — the Helm charts' downward-API variables are the binary's own.
            ("TELLTALE_KUBE_NODE", "k3s-1"),
            ("TELLTALE_POD", "telltale-resolver-7d9f"),
            ("TELLTALE_NODE_IPS", "192.168.5.2"),
        ])
        .load()
        .unwrap();
    assert_eq!(loaded.config.node, Config::default().node);
    let unknown: Vec<_> = loaded
        .warnings
        .iter()
        .filter(|w| w.contains("unknown environment variable"))
        .collect();
    assert_eq!(
        unknown.len(),
        2,
        "TELLTALE_CONFIG, _KUBE_NODE, _POD, _NODE_IPS are reserved: {unknown:?}"
    );
}

#[test]
fn ops_005_layers_merge_tables_and_replace_arrays() {
    let loaded = Loader::new()
        .toml_str("base.toml", EXAMPLE)
        .toml_str(
            "node.toml",
            "[cache]\nmax_bytes = \"16MiB\"\n\n[[listen]]\nproto = \"udp\"\naddr = \"127.0.0.1:5353\"\n",
        )
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap();
    let c = loaded.config;
    assert_eq!(c.cache.max_bytes, ByteSize::mib(16));
    assert_eq!(c.cache.max_ttl, 86_400, "sibling keys survive the merge");
    assert_eq!(c.listen.len(), 1, "arrays replace");
    assert_eq!(c.upstream.len(), 3);
}

#[test]
fn ops_005_semantic_errors_are_all_reported() {
    let errs = load_str(
        r#"
[[listen]]
proto = "dot"
addr = "0.0.0.0:853"

[[upstream]]
name = "a"
url = "ftp://example.com"

[[upstream_group]]
name = "default"
members = ["a", "ghost"]

[[route]]
match_suffix = ["lan"]
upstream_group = "nope"

[cache]
min_ttl = 100
max_ttl = 10
"#,
    )
    .unwrap_err();
    let p = paths(&errs);
    for want in [
        "listen[0].tls",
        "upstream[0].url",
        "upstream_group[0].members[1]",
        "route[0].upstream_group",
        "cache.min_ttl",
    ] {
        assert!(p.contains(&want), "missing {want} in {p:?}");
    }
}

#[test]
fn ops_005_json_schema_rejects_unknown_fields() {
    let schema = serde_json::to_value(telltale_config::json_schema()).unwrap();
    assert_eq!(
        schema["additionalProperties"],
        serde_json::Value::Bool(false)
    );
    assert!(schema["properties"]["cache"].is_object());
}

#[test]
fn flt_004_lists_parse_with_defaults() {
    let loaded = load_str(
        r#"
[[list]]
name = "hagezi-pro"
url = "https://example.com/pro.txt"

[[list]]
name = "my_allow"
kind = "allow"
match = "exact"
rules = ["good.example.com"]

[[list]]
name = "local-file"
path = "/etc/telltale/block.txt"
enabled = false
refresh_secs = 3600
max_bytes = "1MiB"

[filter]
fetch_concurrency = 2
"#,
    )
    .unwrap();
    let c = &loaded.config;
    assert_eq!(c.list.len(), 3);
    assert_eq!(c.list[0].kind, telltale_config::ListKind::Block);
    assert_eq!(c.list[0].match_mode, telltale_config::ListMatch::Subtree);
    assert!(c.list[0].enabled);
    assert_eq!(c.list[1].kind, telltale_config::ListKind::Allow);
    assert_eq!(c.list[1].match_mode, telltale_config::ListMatch::Exact);
    assert!(!c.list[2].enabled);
    assert_eq!(c.list[2].max_bytes, Some(ByteSize::mib(1)));
    assert_eq!(c.filter.fetch_concurrency, 2);
    assert_eq!(c.filter.refresh_secs, 86_400);
    assert_eq!(c.filter.max_list_bytes, ByteSize::mib(64));
    assert!(
        !loaded.warnings.iter().any(|w| w.contains("list")),
        "{:?}",
        loaded.warnings
    );
}

#[test]
fn flt_004_list_validation_errors_have_paths() {
    let errs = load_str(
        r#"
[[list]]
name = "Bad Name"
url = "https://example.com/a.txt"

[[list]]
name = "two-sources"
url = "https://example.com/b.txt"
path = "/tmp/b.txt"

[[list]]
name = "no-source"

[[list]]
name = "ftp"
url = "ftp://example.com/c.txt"

[[list]]
name = "ftp"
url = "https://example.com/d.txt"
refresh_secs = 60

[filter]
fetch_concurrency = 0
max_list_bytes = "10B"
"#,
    )
    .unwrap_err();
    let p = paths(&errs);
    for want in [
        "list[0].name",
        "list[1]",
        "list[2]",
        "list[3].url",
        "list[4].name",
        "list[4].refresh_secs",
        "filter.fetch_concurrency",
        "filter.max_list_bytes",
    ] {
        assert!(p.contains(&want), "missing {want} in {p:?}");
    }
}

#[test]
fn flt_004_plain_http_list_warns() {
    let loaded = load_str("[[list]]\nname = \"a\"\nurl = \"http://example.com/a.txt\"\n").unwrap();
    let list_warnings: Vec<_> = loaded
        .warnings
        .iter()
        .filter(|w| w.contains("list["))
        .collect();
    assert_eq!(list_warnings.len(), 1, "{:?}", loaded.warnings);
    assert!(list_warnings[0].contains("list[0].url"));
}

#[test]
fn flt_005_groups_and_clients() {
    let loaded = load_str(
        r#"
[[list]]
name = "ads"
rules = ["||ads.example.com^"]

[[list]]
name = "adult"
rules = ["||adult.example.com^"]

[[group]]
name = "kids"
lists = ["ads", "adult"]
priority = 10

[[client]]
name = "Kids Tablet"
match = ["192.168.1.50", "AA-BB-CC-DD-EE-FF", "id:kids-tablet"]
groups = ["kids"]

[[client]]
name = "office"
match = ["10.0.5.0/24"]

[clients]
trust_edns_mac_from = ["192.168.1.1/32"]
"#,
    )
    .unwrap();
    let c = &loaded.config;
    assert_eq!(c.group[0].priority, 10);
    // No groups of its own: it takes its network's group, else `default` (ADR-050).
    assert_eq!(
        c.client[1].groups,
        Vec::<telltale_config::SafeString>::new()
    );
    assert_eq!(
        telltale_config::MatchKey::parse("AA-BB-CC-DD-EE-FF").unwrap(),
        telltale_config::MatchKey::Mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    );
    assert!(c.clients.neighbor_table);
}

// REQ: FLT-005 (ADR-050) — a network can belong to one group; colors are #rrggbb.
#[test]
fn flt_005_group_networks_validation() {
    let errs = load_str(
        r##"
[[group]]
name = "iot"
networks = ["192.168.2.0/24"]
color = "#22c55e"

[[group]]
name = "cameras"
networks = ["192.168.2.0/24", "192.168.7.0/24"]
color = "green"
"##,
    )
    .unwrap_err();
    let text: Vec<String> = errs.iter().map(ToString::to_string).collect();
    assert!(
        text.iter()
            .any(|e| e.contains("group[1].networks[0]") && e.contains("`iot`")),
        "{text:?}"
    );
    assert!(
        text.iter().any(|e| e.contains("group[1].color")),
        "{text:?}"
    );
    assert_eq!(text.len(), 2, "{text:?}");
}

#[test]
fn flt_006_client_validation_errors() {
    let errs = load_str(
        r#"
[[group]]
name = "kids"
lists = ["nope"]

[[client]]
name = "a"
match = ["192.168.1.50", "zz:zz:zz:zz:zz:zz", "id:Bad_ID", "hello"]
groups = ["ghosts"]

[[client]]
name = "A"
match = ["192.168.1.50"]
"#,
    )
    .unwrap_err();
    let p = paths(&errs);
    for want in [
        "group[0].lists[0]",
        "client[0].match[1]",
        "client[0].match[2]",
        "client[0].match[3]",
        "client[0].groups[0]",
        "client[1].name",
        "client[1].match[0]",
    ] {
        assert!(p.contains(&want), "missing {want} in {p:?}");
    }
}

#[test]
fn flt_008_block_modes() {
    let loaded = load_str(
        r#"
[[group]]
name = "kids"
block_mode = "custom_ip"
block_ips = ["192.168.1.2", "fd00::2"]
block_ttl = 300
ede = "filtered"
ede_text = false

[[group]]
name = "default"
block_mode = "nxdomain"
"#,
    )
    .unwrap();
    let g = &loaded.config.group;
    assert_eq!(g[0].block_mode, telltale_config::BlockMode::CustomIp);
    assert_eq!(g[0].block_ips.len(), 2);
    assert_eq!(g[0].ede, telltale_config::EdeKind::Filtered);
    assert!(!g[0].ede_text);
    assert_eq!(g[1].block_mode, telltale_config::BlockMode::Nxdomain);
    assert_eq!(g[1].block_ttl, 60);
    assert!(g[1].ede_text);

    let errs = load_str("[[group]]\nname = \"x\"\nblock_mode = \"custom_ip\"\n").unwrap_err();
    assert_eq!(paths(&errs), vec!["group[0].block_ips"]);
    let errs = load_str("[[group]]\nname = \"x\"\nblock_mode = \"sinkhole\"\n").unwrap_err();
    assert_eq!(errs[0].path, "group[0].block_mode");
}

/// REQ: DOC-002/003 (T4.6) — the site's configuration reference is rendered from
/// docs/config-schema.json; this keeps it identical to `telltale config schema`.
/// Regenerate with `UPDATE_SCHEMA=1 cargo test -p telltale-config doc_002_committed_schema`.
#[test]
fn doc_002_committed_schema_matches_the_code() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/config-schema.json");
    let doc = serde_json::to_string_pretty(&telltale_config::json_schema()).unwrap() + "\n";
    if std::env::var_os("UPDATE_SCHEMA").is_some() {
        std::fs::write(&path, &doc).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == doc,
        "docs/config-schema.json is out of date: run UPDATE_SCHEMA=1 cargo test -p telltale-config doc_002_committed_schema"
    );
}

/// REQ: FLT-005 (T6.12, ADR-067) — quick rules: a valid one loads; each kind of mistake is
/// reported at its path.
#[test]
fn flt_005_quick_rules_validate() {
    let ok = load_str(
        r#"
[[group]]
name = "kids"
[[client]]
name = "Mom phone"
match = ["192.168.1.20"]
[[rule]]
id = "r1"
action = "allow"
domain = "game.example.com"
devices = ["Mom phone"]
expires = "2026-10-05T21:30:00Z"
note = "Mom's game"
[[rule]]
id = "r2"
action = "block"
domain = "videos.example.com"
groups = ["kids"]
[[rule]]
id = "r3"
action = "block"
domain = "ads.example.net"
devices = ["192.168.1.0/24"]
"#,
    )
    .unwrap();
    assert_eq!(ok.config.rule.len(), 3);
    assert_eq!(ok.config.rule[0].action, telltale_config::RuleAction::Allow);

    let errs = load_str(
        r#"
[[rule]]
id = "a"
action = "block"
domain = "*.bad"
[[rule]]
id = "a"
action = "allow"
domain = "ok.example"
groups = ["nope"]
devices = ["Nobody"]
expires = "tomorrow"
"#,
    )
    .unwrap_err();
    let p = paths(&errs);
    for want in [
        "rule[0].domain",
        "rule[1].id",
        "rule[1].groups[0]",
        "rule[1].devices[0]",
        "rule[1].expires",
    ] {
        assert!(p.contains(&want), "{want} missing from {p:?}");
    }
}

/// REQ: FLT-005 (GitHub issue #73) — a rule's device is a configured device's name (any case), an
/// IP, or a CIDR; the refusal says exactly that, in words that tell a named device (`[[client]]`)
/// from a name a router gives an address.
#[test]
fn flt_005_rule_device_refusal_says_what_a_rule_can_name() {
    let base = r#"
[[client]]
name = "Mom phone"
match = ["192.168.1.20"]
[[rule]]
id = "r1"
action = "block"
domain = "scan.example.com"
"#;
    for ok in [
        "Mom phone",
        "mom PHONE",
        "192.168.1.20",
        "192.168.1.0/24",
        "fd00::1",
    ] {
        let cfg = format!("{base}devices = [\"{ok}\"]\n");
        assert!(load_str(&cfg).is_ok(), "{ok} is a rule target");
    }
    let errs = load_str(&format!("{base}devices = [\"LGwebOSTV\"]\n")).unwrap_err();
    let e = errs
        .iter()
        .find(|e| e.path == "rule[0].devices[0]")
        .unwrap_or_else(|| panic!("the device is refused at its path: {errs:?}"));
    assert_eq!(
        e.message,
        "`LGwebOSTV` isn't a named device (`[[client]]`), an IP, or a CIDR"
    );
}

/// REQ: OPS-012 (ADR-163) — the watchdog is on by default (60 s, restart, six an hour), and its
/// limits are checked at their paths.
#[test]
fn ops_012_watchdog_settings_and_limits() {
    let d = load_str("").unwrap().config.watchdog;
    assert!(d.enabled);
    assert_eq!(d.stall_secs, 60);
    assert_eq!(d.action, telltale_config::WatchdogAction::Restart);
    assert_eq!(d.max_restarts_per_hour, 6);

    let set = load_str(
        "[watchdog]\nenabled = false\nstall_secs = 120\naction = \"dump\"\nmax_restarts_per_hour = 0\n",
    )
    .unwrap()
    .config
    .watchdog;
    assert!(!set.enabled);
    assert_eq!(set.stall_secs, 120);
    assert_eq!(set.action, telltale_config::WatchdogAction::Dump);
    assert_eq!(set.max_restarts_per_hour, 0);

    for (toml, path) in [
        ("[watchdog]\nstall_secs = 19\n", "watchdog.stall_secs"),
        ("[watchdog]\nstall_secs = 601\n", "watchdog.stall_secs"),
        (
            "[watchdog]\nmax_restarts_per_hour = 61\n",
            "watchdog.max_restarts_per_hour",
        ),
    ] {
        let errs = load_str(toml).unwrap_err();
        assert!(paths(&errs).contains(&path), "{toml}: {:?}", paths(&errs));
    }
    assert!(load_str("[watchdog]\naction = \"explode\"\n").is_err());
    // Node-local: a replica keeps its own, and the cluster's shared settings don't carry it.
    assert!(telltale_config::shared::NODE_LOCAL.contains(&"watchdog"));
}

/// REQ: FLT-012 (T7.9) — a group can only block services that exist, and `svc-` list names
/// are kept for them.
#[test]
fn flt_012_blocked_services_are_validated() {
    let load = |toml: &str| {
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    assert!(
        load("[[group]]\nname = \"kids\"\nblocked_services = [\"tiktok\", \"roblox\"]\n").is_ok()
    );
    let err = format!(
        "{:?}",
        load("[[group]]\nname = \"kids\"\nblocked_services = [\"myspace\"]\n").unwrap_err()
    );
    assert!(err.contains("no service `myspace`"), "{err}");
    let err = format!(
        "{:?}",
        load("[[list]]\nname = \"svc-mine\"\nrules = [\"||x.example^\"]\n").unwrap_err()
    );
    assert!(err.contains("kept for blocked services"), "{err}");
}

/// REQ: FLT-010 (T7.10) — schedules: known schedules, lists, and services; readable windows
/// and time zones.
#[test]
fn flt_010_schedules_are_validated() {
    let load = |toml: &str| {
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let ok = r#"
[[group]]
name = "kids"
schedules = ["bedtime"]
[[schedule]]
name = "bedtime"
action = "block_all"
tz = "UTC"
window = [{ days = ["weekdays"], start = "21:00", end = "07:00" }]
"#;
    assert!(load(ok).is_ok());
    for (bad, why) in [
        (
            ok.replace("schedules = [\"bedtime\"]", "schedules = [\"nap\"]"),
            "no schedule `nap`",
        ),
        (ok.replace("\"weekdays\"", "\"someday\""), "day `someday`"),
        (ok.replace("\"21:00\"", "\"9pm\""), "use HH:MM"),
        (
            ok.replace("\"UTC\"", "\"Mars/Base\""),
            "time zone `Mars/Base`",
        ),
        (
            ok.replace("\"block_all\"", "\"enable_lists\""),
            "needs at least one list",
        ),
    ] {
        let err = format!("{:?}", load(&bad).unwrap_err());
        assert!(err.contains(why), "{why}: {err}");
    }
}

/// REQ: OBS-010 (T7.12) — alerts: rules name destinations that exist; http(s) URLs; a sane
/// interval and threshold.
#[test]
fn obs_010_alerts_are_validated() {
    let load = |toml: &str| {
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let ok = r#"
[alerts]
interval_secs = 30
[[alerts.destination]]
name = "phone"
type = "ntfy"
url = "https://ntfy.sh/my-dns"
[[alerts.rule]]
name = "upstreams"
when = "upstream_down"
for_secs = 60
to = ["phone"]
[[alerts.rule]]
name = "servfail"
when = "servfail_rate"
threshold = 10
to = ["phone"]
"#;
    assert!(load(ok).is_ok(), "{:?}", load(ok).err());
    for (bad, why) in [
        (
            ok.replace("to = [\"phone\"]\n[[", "to = [\"pager\"]\n[["),
            "no destination `pager`",
        ),
        (
            ok.replace("https://ntfy.sh", "ftp://ntfy.sh"),
            "http:// or https://",
        ),
        (
            ok.replace("interval_secs = 30", "interval_secs = 1"),
            "at least 5 seconds",
        ),
        (
            ok.replace("threshold = 10", "threshold = 150"),
            "from 0 to 100",
        ),
        (
            ok.replace("name = \"servfail\"", "name = \"upstreams\""),
            "must be unique",
        ),
        (
            ok.replace("\"upstream_down\"", "\"moon_phase\""),
            "moon_phase",
        ),
    ] {
        let err = format!("{:?}", load(&bad).unwrap_err());
        assert!(err.contains(why), "{why}: {err}");
    }
}

/// REQ: OBS-016 (T11.1) — objectives below 100%, a threshold that is a histogram bucket bound,
/// a window the rollups hold; `slo_burn` is an alert condition.
#[test]
fn obs_016_slo_is_validated() {
    let load = |toml: &str| {
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let ok = r#"
[slo]
availability_target = 99.95
latency_target = 99.0
latency_ms = 100
window_days = 28
[[alerts.destination]]
name = "phone"
type = "ntfy"
url = "https://ntfy.sh/my-dns"
[[alerts.rule]]
name = "budget"
when = "slo_burn"
to = ["phone"]
"#;
    let cfg = load(ok).unwrap().config;
    assert_eq!((cfg.slo.latency_ms, cfg.slo.window_days), (100, 28));
    assert!(cfg.slo.enabled, "on by default");
    let d = telltale_config::Config::default().slo;
    assert_eq!(
        (
            d.availability_target,
            d.latency_target,
            d.latency_ms,
            d.window_days
        ),
        (99.9, 99.0, 250, 30)
    );
    for (bad, why) in [
        (
            ok.replace("availability_target = 99.95", "availability_target = 100"),
            "up to (not including) 100",
        ),
        (
            ok.replace("latency_target = 99.0", "latency_target = 20"),
            "from 50",
        ),
        (
            ok.replace("latency_ms = 100", "latency_ms = 120"),
            "bucket bounds",
        ),
        (
            ok.replace("window_days = 28", "window_days = 365"),
            "from 1 to 90 days",
        ),
    ] {
        let err = format!("{:?}", load(&bad).unwrap_err());
        assert!(err.contains(why), "{why}: {err}");
    }
}

/// REQ: OBS-018 (T11.5) — `mode = "shadow"` for block lists only; enforce by default.
#[test]
fn obs_018_shadow_mode_is_validated() {
    let load = |toml: &str| {
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let ok = "[[list]]\nname = \"candidate\"\nrules = [\"||shop.example^\"]\nmode = \"shadow\"\n";
    let cfg = load(ok).unwrap().config;
    assert_eq!(cfg.list[0].mode, telltale_config::ListMode::Shadow);
    let plain = load("[[list]]\nname = \"x\"\nrules = [\"||a.example^\"]\n")
        .unwrap()
        .config;
    assert_eq!(plain.list[0].mode, telltale_config::ListMode::Enforce);
    let err = format!(
        "{:?}",
        load(&format!("{ok}kind = \"allow\"\n")).unwrap_err()
    );
    assert!(err.contains("shadow is for block lists"), "{err}");
}

/// REQ: OBS-022 (T12.1) — exclusions: on by default but empty; names must be domain names
/// (`*.` and a trailing dot allowed), clients addresses or networks; off keeps the lists.
#[test]
fn obs_022_exclusions_are_validated() {
    let load = |toml: &str| {
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let cfg = load("").unwrap().config;
    assert!(cfg.exclusions.enabled && !cfg.exclusions.active());
    let cfg = load(
        "[exclusions]\nnames = [\"*.ntp.org\", \"connectivitycheck.gstatic.com.\"]\nclients = [\"192.168.1.10\", \"fd00::/64\"]\n",
    )
    .unwrap()
    .config;
    assert!(cfg.exclusions.active());
    let off = load("[exclusions]\nenabled = false\nnames = [\"ntp.org\"]\n")
        .unwrap()
        .config;
    assert!(
        !off.exclusions.active(),
        "off keeps the list, excludes nothing"
    );
    for bad in [
        "[exclusions]\nnames = [\"not a name\"]\n",
        "[exclusions]\nnames = [\"\"]\n",
        "[exclusions]\nclients = [\"300.1.1.1\"]\n",
    ] {
        assert!(load(bad).is_err(), "{bad}");
    }
}

/// REQ: OPS-010 (T13.4) — maintenance lasts an hour unless a request says otherwise; the
/// default is a minute to a day; `maintenance` is an alert condition.
#[test]
fn ops_010_maintenance_default_and_alert_rule() {
    let load = |toml: &str| {
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    assert_eq!(load("").unwrap().config.node.maintenance_default_secs, 3600);
    let cfg = load(
        "[node]\nmaintenance_default_secs = 7200\n[[alerts.destination]]\nname = \"phone\"\ntype = \"ntfy\"\nurl = \"https://ntfy.sh/my-dns\"\n[[alerts.rule]]\nname = \"maint\"\nwhen = \"maintenance\"\nfor_secs = 0\nto = [\"phone\"]\n",
    )
    .unwrap()
    .config;
    assert_eq!(cfg.node.maintenance_default_secs, 7200);
    assert_eq!(
        cfg.alerts.rule[0].when,
        telltale_config::AlertWhen::Maintenance
    );
    for bad in [30, 86_401] {
        let e = load(&format!("[node]\nmaintenance_default_secs = {bad}\n"))
            .err()
            .map(|e| format!("{e:?}"))
            .unwrap_or_default();
        assert!(e.contains("maintenance_default_secs"), "{bad}: {e}");
    }
}

/// REQ: OBS-023 (T12.3) — lists go stale after 30 days unchanged by default; per list too.
#[test]
fn obs_023_stale_after_days() {
    let cfg = telltale_config::Loader::new()
        .toml_str(
            "t.toml",
            "[[list]]\nname = \"slow\"\nurl = \"https://lists.example/slow.txt\"\nstale_after_days = 0\n",
        )
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    assert_eq!(cfg.filter.stale_after_days, 30);
    assert_eq!(cfg.list[0].stale_after_days, Some(0));
}

/// REQ: OBS-017 (T11.6) — exemplars on by default, traces off; traces need the collector.
#[test]
fn obs_017_traces_need_an_endpoint() {
    let load = |toml: &str| {
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let cfg = load("").unwrap().config;
    assert!(cfg.telemetry.metrics.exemplars);
    assert_eq!(
        (
            cfg.telemetry.otlp.traces_sample_every,
            cfg.telemetry.otlp.traces_slow_ms
        ),
        (0, 0)
    );
    let err = format!(
        "{:?}",
        load("[telemetry.otlp]\ntraces_slow_ms = 500\n").unwrap_err()
    );
    assert!(err.contains("telemetry.otlp.traces_slow_ms"), "{err}");
    let cfg = load(
        "[telemetry.otlp]\nendpoint = \"http://otel:4318\"\ntraces_slow_ms = 500\ntraces_sample_every = 1000\n",
    )
    .unwrap()
    .config;
    assert_eq!(cfg.telemetry.otlp.traces_sample_every, 1000);
}

/// REQ: OBS-019 (T11.4) — second opinions: off by default; a reference group that exists; a
/// warning when the sample adds noticeable traffic.
#[test]
fn obs_019_upstream_check_is_validated() {
    let load = |toml: &str| {
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    assert_eq!(
        telltale_config::Config::default()
            .upstream_check
            .sample_every,
        0
    );
    let ok = r#"
[[upstream]]
name = "quad9"
url = "udp://9.9.9.9"
[[upstream_group]]
name = "reference"
members = ["quad9"]
[upstream_check]
sample_every = 1000
reference = "reference"
keep = 50
"#;
    let loaded = load(ok).unwrap();
    assert_eq!(loaded.config.upstream_check.keep, 50);
    assert!(
        loaded
            .warnings
            .iter()
            .all(|w| !w.contains("upstream_check"))
    );
    let busy = load(&ok.replace("sample_every = 1000", "sample_every = 10")).unwrap();
    assert!(
        busy.warnings.iter().any(|w| w.contains("asked twice")),
        "{:?}",
        busy.warnings
    );
    for (bad, why) in [
        (
            ok.replace("reference = \"reference\"", "reference = \"nope\""),
            "no upstream group `nope`",
        ),
        (ok.replace("keep = 50", "keep = 0"), "from 1 to 1000"),
    ] {
        let err = format!("{:?}", load(&bad).unwrap_err());
        assert!(err.contains(why), "{why}: {err}");
    }
}

/// REQ: OBS-020 (T11.3) — probes: targets by IP with a scheme probes speak; a sane schedule;
/// `cert_expiring` thresholds in days.
#[test]
fn obs_020_probes_are_validated() {
    let load = |toml: &str| {
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let ok = r#"
[probe]
interval_secs = 60
timeout_ms = 1500
targets = ["udp://192.168.5.112:53", "https://[fd00::53]:443/dns-query"]
cert_warn_days = 21
[[alerts.destination]]
name = "phone"
type = "ntfy"
url = "https://ntfy.sh/my-dns"
[[alerts.rule]]
name = "certs"
when = "cert_expiring"
threshold = 30
to = ["phone"]
"#;
    let cfg = load(ok).unwrap().config;
    assert_eq!(cfg.probe.targets.len(), 2);
    assert!(
        telltale_config::Config::default().probe.enabled,
        "on by default"
    );
    for (bad, why) in [
        (
            ok.replace("udp://192.168.5.112:53", "udp://dns.example:53"),
            "an IP address and port",
        ),
        (
            ok.replace("udp://192.168.5.112:53", "ftp://192.168.5.112:53"),
            "the scheme is",
        ),
        (
            ok.replace("udp://192.168.5.112:53", "udp://192.168.5.112:53/x"),
            "take a path",
        ),
        (
            ok.replace("interval_secs = 60", "interval_secs = 1"),
            "at least 5 seconds",
        ),
        (
            ok.replace("timeout_ms = 1500", "timeout_ms = 60000"),
            "from 100 to 10000",
        ),
        (
            ok.replace("threshold = 30", "threshold = 900"),
            "days from 1 to 365",
        ),
    ] {
        let err = format!("{:?}", load(&bad).unwrap_err());
        assert!(err.contains(why), "{why}: {err}");
    }
}

/// REQ: OBS-010 (T7.13) — event sinks: each kind's required settings; known statuses.
#[test]
fn obs_010_sinks_are_validated() {
    let load = |toml: &str| {
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let ok = r#"
[[telemetry.sink]]
name = "file"
type = "file"
path = "/var/log/q.jsonl"
[[telemetry.sink]]
name = "siem"
type = "syslog"
address = "udp://10.0.0.2:514"
statuses = ["blocked"]
[[telemetry.sink]]
name = "hook"
type = "webhook"
url = "https://logs.example.net/in"
"#;
    assert!(load(ok).is_ok(), "{:?}", load(ok).err());
    for (bad, why) in [
        (
            ok.replace("path = \"/var/log/q.jsonl\"\n", ""),
            "needs `path`",
        ),
        (
            ok.replace("udp://10.0.0.2:514", "10.0.0.2"),
            "udp://host:port",
        ),
        (
            ok.replace("https://logs", "ftp://logs"),
            "http:// or https://",
        ),
        (
            ok.replace("\"blocked\"", "\"naughty\""),
            "unknown status `naughty`",
        ),
        (
            ok.replace("name = \"hook\"", "name = \"file\""),
            "must be unique",
        ),
    ] {
        let err = format!("{:?}", load(&bad).unwrap_err());
        assert!(err.contains(why), "{why}: {err}");
    }
}

/// REQ: DNS-001 (review 01 q2) — a listener's connection caps parse, `0` per address means no
/// limit, and neither applies to a udp listener (or `max_connections = 0`).
#[test]
fn dns_001_listener_connection_caps() {
    let c = load_str(
        "[[listen]]\nproto = \"tcp\"\naddr = \"0.0.0.0:53\"\nmax_connections = 256\nmax_connections_per_address = 0\n",
    )
    .unwrap()
    .config;
    assert_eq!(c.listen[0].max_connections, Some(256));
    assert_eq!(c.listen[0].max_connections_per_address, Some(0));
    let plain = load_str("[[listen]]\nproto = \"tcp\"\naddr = \"0.0.0.0:53\"\n")
        .unwrap()
        .config;
    assert_eq!(
        plain.listen[0].max_connections_per_address, None,
        "unset = the default"
    );

    let errs = load_str(
        "[[listen]]\nproto = \"udp\"\naddr = \"0.0.0.0:53\"\nmax_connections = 5\nmax_connections_per_address = 5\n\n[[listen]]\nproto = \"tcp\"\naddr = \"0.0.0.0:53\"\nmax_connections = 0\n",
    )
    .unwrap_err();
    let p = paths(&errs);
    assert!(p.contains(&"listen[0].max_connections"), "{p:?}");
    assert!(
        p.contains(&"listen[0].max_connections_per_address"),
        "{p:?}"
    );
    assert!(p.contains(&"listen[1].max_connections"), "{p:?}");
}

/// REQ: FLT-003 (review 02-08) — `[filter] max_regexes` defaults to 1,000, 0 means no limit,
/// and an absurd value is refused.
#[test]
fn flt_003_max_regexes_setting() {
    assert_eq!(Config::default().filter.max_regexes, 1000);
    let c = load_str("[filter]\nmax_regexes = 0\n").unwrap().config;
    assert_eq!(c.filter.max_regexes, 0);
    let errs = load_str("[filter]\nmax_regexes = 100001\n").unwrap_err();
    assert!(paths(&errs).contains(&"filter.max_regexes"));
}

/// REQ: T8.2 — `[[router]]`: the credentials each kind needs, and `tls_server_name` (a host
/// name, only for https, and not with verification off).
#[test]
fn t8_2_routers_are_validated() {
    const UNIFI: &str = "[[router]]\nname = \"udm\"\ntype = \"unifi\"\nurl = \"https://192.168.1.1\"\napi_key_file = \"/k\"\n";
    let ok = load_str(&format!(
        "{UNIFI}tls_ca = \"/ca.pem\"\ntls_server_name = \"unifi.local\"\n"
    ))
    .unwrap();
    assert_eq!(
        ok.config.router[0]
            .tls_server_name
            .as_ref()
            .map(telltale_config::SafeString::as_str),
        Some("unifi.local")
    );
    assert!(
        !ok.warnings.iter().any(|w| w.contains("router")),
        "{:?}",
        ok.warnings
    );

    let errs =
        load_str("[[router]]\nname = \"udm\"\ntype = \"unifi\"\nurl = \"https://192.168.1.1\"\n")
            .unwrap_err();
    assert_eq!(paths(&errs), ["router[0]"]);
    let errs = load_str(&format!("{UNIFI}tls_server_name = \"not a name\"\n")).unwrap_err();
    assert_eq!(paths(&errs), ["router[0].tls_server_name"]);
    let errs = load_str(&format!(
        "{UNIFI}tls_insecure_skip_verify = true\ntls_server_name = \"unifi.local\"\n"
    ))
    .unwrap_err();
    assert_eq!(paths(&errs), ["router[0].tls_server_name"]);
    let http = UNIFI.replace("https://", "http://");
    let errs = load_str(&format!("{http}tls_server_name = \"unifi.local\"\n")).unwrap_err();
    assert_eq!(paths(&errs), ["router[0].tls_server_name"]);
    // Verification off still loads, with a warning that points at the alternative.
    let off = load_str(&format!("{UNIFI}tls_insecure_skip_verify = true\n")).unwrap();
    assert!(
        off.warnings.iter().any(|w| w.contains("tls_server_name")),
        "{:?}",
        off.warnings
    );
}

// REQ: FLT-017 (T15.1) — `[kubernetes]`: map rules name known groups and kinds; the section is
// shared but left out of the shared part while at its defaults (older replicas).
#[test]
fn flt_017_kubernetes_section() {
    let ok = load_str(
        r#"
[[group]]
name = "media"

[kubernetes]
enabled = true
namespaces = ["media", "home"]
default_group = "media"

[[kubernetes.map]]
namespace = "media*"
group = "media"

[[kubernetes.map]]
namespace = "jobs"
kind = "cronjob"
name = "backup"
group = "default"
"#,
    )
    .unwrap();
    let k = &ok.config.kubernetes;
    assert!(k.enabled);
    assert_eq!(k.label.as_str(), "telltaledns.io/group");
    assert_eq!(k.map[0].key(), "media*/*/*");
    assert_eq!(k.map[1].key(), "jobs/cronjob/backup");
    let errs = load_str(
        "[kubernetes]\ndefault_group = \"nope\"\n[[kubernetes.map]]\nnamespace = \"a b\"\nkind = \"vm\"\ngroup = \"kids\"\n",
    )
    .unwrap_err();
    assert_eq!(
        paths(&errs),
        [
            "kubernetes.default_group",
            "kubernetes.map[0].namespace",
            "kubernetes.map[0].kind",
            "kubernetes.map[0].group"
        ]
    );
    let errs = load_str(
        "[[kubernetes.map]]\nnamespace = \"a\"\ngroup = \"default\"\n[[kubernetes.map]]\nnamespace = \"a\"\ngroup = \"default\"\n",
    )
    .unwrap_err();
    assert_eq!(paths(&errs), ["kubernetes.map[1]"]);
    let shared = telltale_config::shared::shared_part(&Config::default());
    assert!(shared.get("kubernetes").is_none(), "defaults aren't sent");
    let shared = telltale_config::shared::shared_part(&ok.config);
    assert!(shared.get("kubernetes").is_some());
}

// REQ: CLU-014 (owner 2026-10-19) — `[drill]`: a monthly schedule names its nodes, 15 to 300 s,
// an hour of the day, a known zone and group, not a group and devices both; the defaults
// (schedule off) aren't sent to the cluster.
#[test]
fn clu_014_drill_section() {
    let ok = load_str(
        "[[group]]\nname = \"iot\"\n[drill]\nschedule = \"monthly\"\nnodes = [\"home-pi\"]\ngroup = \"iot\"\nfor_secs = 45\nhour = 4\ntz = \"UTC\"\nmode = \"refused\"\n",
    )
    .unwrap();
    let d = &ok.config.drill;
    assert_eq!(d.schedule, telltale_config::DrillSchedule::Monthly);
    assert_eq!((d.for_secs, d.hour), (45, 4));
    assert_eq!(d.mode, telltale_config::DrillMode::Refused);
    let errs = load_str(
        "[drill]\nschedule = \"monthly\"\nfor_secs = 400\nhour = 24\ntz = \"Mars/Base\"\ngroup = \"nope\"\nclients = [\"tv\"]\n",
    )
    .unwrap_err();
    assert_eq!(
        paths(&errs),
        [
            "drill.for_secs",
            "drill.hour",
            "drill.tz",
            "drill.group",
            "drill.clients",
            "drill.nodes"
        ]
    );
    let shared = telltale_config::shared::shared_part(&Config::default());
    assert!(shared.get("drill").is_none(), "defaults aren't sent");
}

/// REQ: DNS-022 — a stub zone on a `recursive://` upstream needs its name and its servers,
/// and isn't valid on another kind of upstream.
#[test]
fn dns_022_stub_zone_validates() {
    let ok = load_str(
        r#"
[[upstream]]
name = "corp"
url = "recursive://"
[upstream.recursive]
stub_zone = "corp.example"
stub_servers = ["10.0.0.53", "10.0.0.54"]
"#,
    )
    .unwrap();
    let r = &ok.config.upstream[0].recursive;
    assert_eq!(r.stub_zone.as_deref(), Some("corp.example"));
    assert_eq!(r.stub_servers.len(), 2);

    let errs = load_str(
        r#"
[[upstream]]
name = "no-servers"
url = "recursive://"
[upstream.recursive]
stub_zone = "corp.example"
[[upstream]]
name = "no-zone"
url = "recursive://"
[upstream.recursive]
stub_servers = ["10.0.0.53"]
[[upstream]]
name = "not-recursive"
url = "udp://10.0.0.53"
[upstream.recursive]
stub_zone = "corp.example"
stub_servers = ["10.0.0.53"]
"#,
    )
    .unwrap_err();
    let p = paths(&errs);
    for want in [
        "upstream[0].recursive.stub_servers",
        "upstream[1].recursive.stub_zone",
        "upstream[2].recursive",
    ] {
        assert!(p.contains(&want), "{want} missing from {p:?}");
    }
}

/// The listeners of the `loop_tag` tests: an IPv4 and an IPv6 address of this node.
const LOOP_TAG_LISTENERS: &str = "[[listen]]
proto = \"udp\"
addr = \"192.168.1.5:53\"
[[listen]]
proto = \"tcp\"
addr = \"[fd00::5]:5300\"
";

/// REQ: UPS-009 (ADR-192) — `loop_tag = false` is refused toward this node, as far as the
/// configuration can tell: a loopback or unspecified address (IPv4, IPv6, or IPv4-mapped), the
/// name `localhost`, or an address a `[[listen]]` entry uses (on any port), in the URL or among
/// the `bootstrap` servers. Accepted: a public address, a LAN address no listener uses, a host
/// name with public bootstrap servers, and loopback with the switch left on.
#[test]
fn ups_009_loop_tag_off_is_refused_toward_this_node() {
    let refused = [
        ("udp://127.0.0.1", ""),
        ("udp://127.0.0.53:5353", ""),
        ("tcp://[::1]:53", ""),
        ("udp://0.0.0.0", ""),
        ("udp://[::]:53", ""),
        ("udp://[::ffff:127.0.0.1]", ""),
        ("udp://localhost:5300", ""),
        ("https://LocalHost./dns-query", ""),
        ("tls://resolver.localhost", ""),
        ("udp://192.168.1.5:5353", ""),
        ("tcp://[fd00::5]", ""),
        ("tls://dns.example", "bootstrap = [\"127.0.0.1\"]\n"),
        (
            "tls://dns.example",
            "bootstrap = [\"9.9.9.9\", \"192.168.1.5\"]\n",
        ),
        ("https://dns.example/dns-query", "bootstrap = [\"::\"]\n"),
    ];
    let mut upstreams = String::new();
    for (i, (url, extra)) in refused.iter().enumerate() {
        write!(
            upstreams,
            "[[upstream]]\nname = \"u{i}\"\nurl = \"{url}\"\nloop_tag = false\n{extra}"
        )
        .unwrap();
    }
    let errs = load_str(&format!("{LOOP_TAG_LISTENERS}{upstreams}"))
        .err()
        .unwrap_or_default();
    for (i, (url, extra)) in refused.iter().enumerate() {
        let want = format!("upstream[{i}].loop_tag");
        let e = errs.iter().find(|e| e.path == want);
        assert!(
            e.is_some_and(|e| e.message.contains("this node")),
            "{url} {extra}: {want} not refused; errors: {errs:?}"
        );
    }
    assert_eq!(errs.len(), refused.len(), "nothing else: {errs:?}");

    let accepted = load_str(&format!(
        "{LOOP_TAG_LISTENERS}[[upstream]]
name = \"public\"
url = \"udp://198.51.100.53\"
loop_tag = false
[[upstream]]
name = \"lan\"
url = \"udp://192.168.1.9\"
loop_tag = false
[[upstream]]
name = \"named\"
url = \"tls://dns.example\"
bootstrap = [\"9.9.9.9\"]
loop_tag = false
[[upstream]]
name = \"system-bootstrap\"
url = \"https://dns.example/dns-query\"
loop_tag = false
[[upstream]]
name = \"loopback-tagged\"
url = \"udp://127.0.0.1:5335\"
"
    ));
    assert!(accepted.is_ok(), "{:?}", accepted.err());
}

/// REQ: UPS-009 (ADR-192) — `loop_tag = false` only where it changes what is sent: refused on a
/// `recursive://` upstream, stub zones included, which asks authoritative servers without the
/// option either way; accepted on the kinds that send the query's bytes on (DNS stamps and
/// plugins).
#[test]
fn ups_009_loop_tag_off_is_refused_where_it_does_nothing() {
    let errs = load_str(
        r#"
[[upstream]]
name = "root"
url = "recursive://"
loop_tag = false
[[upstream]]
name = "stub"
url = "recursive://"
loop_tag = false
[upstream.recursive]
stub_zone = "corp.example"
stub_servers = ["10.0.0.53"]
"#,
    )
    .err()
    .unwrap_or_default();
    for want in ["upstream[0].loop_tag", "upstream[1].loop_tag"] {
        assert!(
            errs.iter()
                .any(|e| e.path == want && e.message.contains("recursive://")),
            "{want} not refused; errors: {errs:?}"
        );
    }
    assert_eq!(errs.len(), 2, "nothing else: {errs:?}");

    let accepted = load_str(
        r#"
[[upstream]]
name = "stamp"
url = "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
loop_tag = false
[[upstream]]
name = "socket"
url = "unix:///run/magicdns.sock"
loop_tag = false
[[upstream]]
name = "program"
url = "exec:///usr/local/bin/consul-dns-plugin"
loop_tag = false
[[upstream]]
name = "root"
url = "recursive://"
"#,
    );
    assert!(accepted.is_ok(), "{:?}", accepted.err());
}

/// REQ: OBS-038 (ADR-161) — anomaly mutes: a device or group and a kind each, names that exist
/// and have addresses, no mute for everyone, no MAC address, a readable end time; devices and
/// groups resolve to the networks the engine matches.
#[test]
fn obs_038_anomaly_mutes_are_validated_and_resolved() {
    let load = |toml: &str| {
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let ok = r#"
[[client]]
name = "lg-tv"
match = ["192.168.1.20", "aa:bb:cc:dd:ee:ff"]
[[client]]
name = "mac-only"
match = ["aa:bb:cc:dd:ee:01"]
[[group]]
name = "iot"
networks = ["192.168.9.0/24"]
[[anomaly_mute]]
name = "tv-sweep"
devices = ["lg-tv", "10.0.0.7"]
groups = ["iot"]
kinds = ["nxdomain_storm", "chatty_loop"]
expires = "2026-12-31T00:00:00Z"
note = "hourly reverse-DNS sweep"
"#;
    let loaded = load(ok).unwrap();
    let r = telltale_config::mute::resolve(&loaded.config);
    assert_eq!(r.len(), 1);
    let nets: Vec<String> = r[0]
        .nets
        .iter()
        .map(|c| format!("{}/{}", c.addr, c.prefix))
        .collect();
    assert_eq!(nets, ["10.0.0.7/32", "192.168.1.20/32", "192.168.9.0/24"]);
    assert_eq!(r[0].expires_unix, Some(1_798_675_200));
    for (bad, why) in [
        (
            ok.replace(
                "devices = [\"lg-tv\", \"10.0.0.7\"]\ngroups = [\"iot\"]",
                "",
            ),
            "switching the anomaly engine off",
        ),
        (
            ok.replace(
                "kinds = [\"nxdomain_storm\", \"chatty_loop\"]",
                "kinds = []",
            ),
            "at least one kind",
        ),
        (ok.replace("\"nxdomain_storm\"", "\"bogus\""), "bogus"),
        (
            ok.replace("devices = [\"lg-tv\"", "devices = [\"fridge\""),
            "neither a device name nor an IP",
        ),
        (
            ok.replace("devices = [\"lg-tv\"", "devices = [\"aa:bb:cc:dd:ee:ff\""),
            "is a MAC address",
        ),
        (
            ok.replace("devices = [\"lg-tv\"", "devices = [\"mac-only\""),
            "has no IP or network",
        ),
        (
            ok.replace("groups = [\"iot\"]", "groups = [\"default\"]"),
            "no addresses to mute",
        ),
        (
            ok.replace("groups = [\"iot\"]", "groups = [\"ghost\"]"),
            "unknown group `ghost`",
        ),
        (
            ok.replace("2026-12-31T00:00:00Z", "next week"),
            "isn't an RFC 3339 time",
        ),
        (
            format!(
                "{ok}\n[[anomaly_mute]]\nname = \"tv-sweep\"\ndevices = [\"10.0.0.8\"]\nkinds = [\"dga\"]\n"
            ),
            "used twice",
        ),
    ] {
        let err = format!("{:?}", load(&bad).unwrap_err());
        assert!(err.contains(why), "{why}: {err}");
    }
}

/// REQ: OBS-038 (ADR-186) — a mute may name `reverse_sweep` (a sweep of private reverse names is
/// its own kind), and it resolves like any kind: listed after `nxdomain_storm`, whose order is
/// unchanged.
#[test]
fn obs_038_a_mute_may_name_reverse_sweep() {
    let load = |kinds: &str| {
        telltale_config::Loader::new()
            .toml_str(
                "t.toml",
                format!(
                    "[[anomaly_mute]]\nname = \"lg-tv-reverse-sweep\"\ndevices = [\"192.168.1.30\"]\nkinds = {kinds}\nnote = \"hourly reverse-DNS sweep\"\n"
                ),
            )
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap_or_else(|e| panic!("{kinds}: {e:?}"))
    };
    for (kinds, want) in [
        ("[\"reverse_sweep\"]", vec!["reverse_sweep"]),
        (
            "[\"reverse_sweep\", \"nxdomain_storm\"]",
            vec!["nxdomain_storm", "reverse_sweep"],
        ),
    ] {
        let loaded = load(kinds);
        let r = telltale_config::mute::resolve(&loaded.config);
        assert_eq!(r.len(), 1, "{kinds}");
        let labels: Vec<&str> = r[0].kinds.iter().map(|k| k.label()).collect();
        assert_eq!(labels, want);
    }
}

/// REQ: T8.2, CLU-003 (ADR-166) — `offline_days`: 30 unless set, 0 turns offline names off,
/// more than a year is refused, and the default is not written back, so a node on an older
/// build (the section refuses fields it doesn't know) still reads the shared configuration.
#[test]
fn t8_2_router_offline_days() {
    const UNIFI: &str = "[[router]]\nname = \"udm\"\ntype = \"unifi\"\nurl = \"https://192.168.1.1\"\napi_key_file = \"/k\"\n";
    let default = load_str(UNIFI).unwrap();
    assert_eq!(default.config.router[0].offline_days, 30);
    let written = serde_json::to_value(&default.config.router[0]).unwrap();
    assert!(written.get("offline_days").is_none(), "{written}");

    let off = load_str(&format!("{UNIFI}offline_days = 0\n")).unwrap();
    assert_eq!(off.config.router[0].offline_days, 0);
    let written = serde_json::to_value(&off.config.router[0]).unwrap();
    assert_eq!(written["offline_days"], 0);

    let year = load_str(&format!("{UNIFI}offline_days = 365\n")).unwrap();
    assert_eq!(year.config.router[0].offline_days, 365);
    let errs = load_str(&format!("{UNIFI}offline_days = 366\n")).unwrap_err();
    assert_eq!(paths(&errs), ["router[0].offline_days"]);
}

/// REQ: API-004 (issue #63) — `telltale config check` warns when `disable_local_login` is on and
/// `allowed_admin_networks` is empty: no address may then use a password, so with the provider
/// down nobody can sign in. A list that names networks, the default list, and the flag off are
/// all quiet.
#[test]
fn api_004_config_check_warns_on_an_empty_break_glass_list() {
    let toml = |oidc_keys: &str| {
        format!(
            "[auth.oidc]\npublic_url = \"https://dns.example.com\"\n{oidc_keys}\n\
             [[auth.oidc.provider]]\nid = \"kc\"\nissuer = \"https://auth.example.com/realms/home\"\nclient_id = \"telltale\"\n"
        )
    };
    let warns = |oidc_keys: &str| -> Vec<String> {
        load_str(&toml(oidc_keys))
            .unwrap()
            .warnings
            .into_iter()
            .filter(|w| w.contains("allowed_admin_networks"))
            .collect()
    };
    let w = warns("disable_local_login = true\nallowed_admin_networks = []");
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(
        w[0].starts_with("auth.oidc.allowed_admin_networks:"),
        "names the setting first, like the other warnings: {}",
        w[0]
    );
    assert!(
        w[0].contains("nobody can sign in with a password"),
        "{}",
        w[0]
    );
    assert!(
        warns("disable_local_login = true").is_empty(),
        "the default list"
    );
    assert!(
        warns("disable_local_login = true\nallowed_admin_networks = [\"127.0.0.0/8\"]").is_empty(),
        "a list that names a network"
    );
    assert!(
        warns("allowed_admin_networks = []").is_empty(),
        "with the flag off the list is not used"
    );
}

/// REQ: FLT-006, CLU-010 (ADR-183) — `[clients] router_macs`: on unless set, `false` is read and
/// written, and the default is not written back, so a node on an older build (the section
/// refuses fields it doesn't know) still reads the shared configuration.
#[test]
fn flt_006_router_macs_default_on_and_not_written() {
    let clients = |toml: &str| load_str(toml).unwrap().config.clients;
    let written = |c: &telltale_config::ClientsConfig| serde_json::to_value(c).unwrap();

    let default = clients("");
    assert!(default.router_macs);
    assert!(
        written(&default).get("router_macs").is_none(),
        "{default:?}"
    );
    assert!(
        serde_json::to_value(Config::default()).unwrap()["clients"]
            .get("router_macs")
            .is_none()
    );

    // Other `[clients]` settings leave it on, and still don't write it.
    let other = clients("[clients]\nmdns = true\n");
    assert!(other.router_macs);
    assert!(written(&other).get("router_macs").is_none());
    let on = clients("[clients]\nrouter_macs = true\n");
    assert!(on.router_macs);
    assert!(
        written(&on).get("router_macs").is_none(),
        "on is the default"
    );

    // Off is written, and reads back as off.
    let off = clients("[clients]\nrouter_macs = false\n");
    assert!(!off.router_macs);
    let text = written(&off);
    assert_eq!(text["router_macs"], false);
    let back: telltale_config::ClientsConfig = serde_json::from_value(text).unwrap();
    assert!(!back.router_macs);

    // A typo is still an error with its path.
    let errs = load_str("[clients]\nrouter_mac = false\n").unwrap_err();
    assert_eq!(errs.len(), 1, "{errs:?}");
}

/// REQ: DNS-019, CLU-010 (ADR-187) — `[special] resolver_arpa`: on unless set, `false` is read and
/// written, and the default is not written back, so a node on an older build (the section refuses
/// fields it doesn't know) still reads the shared configuration.
#[test]
fn dns_019_resolver_arpa_default_on_and_not_written() {
    let special = |toml: &str| load_str(toml).unwrap().config.special;
    let written = |s: &telltale_config::SpecialConfig| serde_json::to_value(s).unwrap();

    let default = special("");
    assert!(default.resolver_arpa);
    assert!(
        written(&default).get("resolver_arpa").is_none(),
        "{default:?}"
    );
    assert!(
        serde_json::to_value(Config::default()).unwrap()["special"]
            .get("resolver_arpa")
            .is_none()
    );

    // Other `[special]` settings leave it on, and still don't write it.
    let other = special("[special]\nrefuse_chaos = false\n");
    assert!(other.resolver_arpa);
    assert!(written(&other).get("resolver_arpa").is_none());
    let on = special("[special]\nresolver_arpa = true\n");
    assert!(on.resolver_arpa);
    assert!(
        written(&on).get("resolver_arpa").is_none(),
        "on is the default"
    );

    // Off is written, and reads back as off.
    let off = special("[special]\nresolver_arpa = false\n");
    assert!(!off.resolver_arpa);
    let text = written(&off);
    assert_eq!(text["resolver_arpa"], false);
    let back: telltale_config::SpecialConfig = serde_json::from_value(text).unwrap();
    assert!(!back.resolver_arpa);

    // A typo or a wrong type is still an error.
    let errs = load_str("[special]\nresolver_arpas = false\n").unwrap_err();
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert!(load_str("[special]\nresolver_arpa = \"no\"\n").is_err());
}

#[test]
fn t8_2_fritzbox_requires_distinct_ipv4_client_networks() {
    let source = |name: &str, subnets: &str| {
        format!(
            "[[router]]\nname = \"{name}\"\ntype = \"fritzbox\"\nurl = \"http://{name}:49000\"\nclient_subnets = {subnets}\n"
        )
    };
    let first = source("site-a", r#"["192.168.40.0/24"]"#);
    let valid = first.clone() + &source("site-b", r#"["192.168.50.0/24"]"#);
    let loaded = load_str(&valid).unwrap();
    assert_eq!(loaded.config.router.len(), 2);
    assert!(
        loaded
            .warnings
            .iter()
            .any(|w| w.starts_with("router[1].url: plain http://")),
        "{:?}",
        loaded.warnings
    );
    for subnets in ["[]", r#"["192.168.40.128/25"]"#, r#"["fd00::/64"]"#] {
        let config = first.clone() + &source("site-b", subnets);
        assert!(paths(&load_str(&config).unwrap_err()).contains(&"router[1].client_subnets"));
    }
}

#[test]
fn t8_2_fritzbox_url_is_an_origin_and_subnets_are_fritzbox_only() {
    let source = |url: &str| {
        format!(
            "[[router]]\nname = \"box\"\ntype = \"fritzbox\"\nurl = \"{url}\"\nclient_subnets = [\"192.168.40.0/24\"]\n"
        )
    };
    for url in ["http://192.168.40.1:49000", "http://[fd00::1]:49000/"] {
        assert!(load_str(&source(url)).is_ok(), "{url}");
    }
    for url in [
        "http://192.168.40.1:49000/tr064",
        "http://admin:pw@192.168.40.1:49000",
        "http://192.168.40.1:49000?a=1",
        "http://",
    ] {
        let errs = load_str(&source(url)).unwrap_err();
        assert!(paths(&errs).contains(&"router[0].url"), "{url}: {errs:?}");
    }
    let unifi = "[[router]]\nname = \"udm\"\ntype = \"unifi\"\nurl = \"https://192.168.1.1\"\napi_key_file = \"/run/secrets/k\"\nclient_subnets = [\"192.168.40.0/24\"]\n";
    assert!(paths(&load_str(unifi).unwrap_err()).contains(&"router[0].client_subnets"));
}

/// REQ: T8.2 (ADR-190) — a FRITZ!Box signs in with a user and its password, or not at all.
#[test]
fn t8_2_fritzbox_signs_in_with_a_user_and_its_password_or_not_at_all() {
    let source = |extra: &str| {
        format!(
            "[[router]]\nname = \"box\"\ntype = \"fritzbox\"\nurl = \"https://192.168.40.1:49443\"\nclient_subnets = [\"192.168.40.0/24\"]\n{extra}"
        )
    };
    for ok in [
        "",
        "username = \"telltale\"\npassword_file = \"/etc/telltale-secrets/box/password\"\n",
    ] {
        assert!(load_str(&source(ok)).is_ok(), "{ok}");
    }
    for bad in [
        "username = \"telltale\"\n",
        "password_file = \"/etc/telltale-secrets/box/password\"\n",
        "api_key_file = \"/etc/telltale-secrets/box/key\"\n",
        "api_secret_file = \"/etc/telltale-secrets/box/secret\"\n",
    ] {
        let errs = load_str(&source(bad)).unwrap_err();
        assert!(paths(&errs).contains(&"router[0]"), "{bad}: {errs:?}");
    }
}

/// A TLS `doh` listener on all addresses, for the ADR-194 tests to add keys to.
const DOH_TLS: &str = "[[listen]]\nproto = \"doh\"\naddr = \"0.0.0.0:443\"\ntls = { cert = \"/etc/telltale/tls.crt\", key = \"/etc/telltale/tls.key\" }\n";

/// The errors at `path`, as text.
fn errors_at(errs: &[ConfigError], path: &str) -> Vec<String> {
    errs.iter()
        .filter(|e| e.path == path)
        .map(|e| e.message.clone())
        .collect()
}

/// The warnings about listeners (a configuration without upstreams also warns about those).
fn listen_warnings(l: &telltale_config::Loaded) -> Vec<&str> {
    l.warnings
        .iter()
        .map(String::as_str)
        .filter(|w| w.starts_with("listen["))
        .collect()
}

/// REQ: DNS-003 (ADR-194) — `x_forwarded_for` is for `doh` listeners only, and needs the list
/// of the proxies it believes; with them it loads and is read back.
#[test]
fn dns_003_x_forwarded_for_needs_trusted_proxies() {
    let ok = load_str(&format!(
        "{DOH_TLS}x_forwarded_for = true\ntrusted_proxies = [\"10.0.5.20/32\", \"10.0.5.21\"]\nmax_connections_per_address = 0\n"
    ))
    .unwrap();
    assert!(listen_warnings(&ok).is_empty(), "{:?}", ok.warnings);
    let written = serde_json::to_value(&ok.config.listen[0]).unwrap();
    assert_eq!(written["x_forwarded_for"], true);
    assert_eq!(
        written["trusted_proxies"],
        serde_json::json!(["10.0.5.20/32", "10.0.5.21/32"])
    );

    let errs = load_str(&format!("{DOH_TLS}x_forwarded_for = true\n")).unwrap_err();
    assert_eq!(paths(&errs), ["listen[0].trusted_proxies"], "{errs:?}");
    assert!(
        errs[0]
            .message
            .contains("required with `x_forwarded_for`: list your proxies' addresses"),
        "{errs:?}"
    );

    for (proto, tls) in [
        ("tcp", ""),
        ("udp", ""),
        ("dot", "tls = { cert = \"/c\", key = \"/k\" }\n"),
        ("doh3", "tls = { cert = \"/c\", key = \"/k\" }\n"),
        ("doq", "tls = { cert = \"/c\", key = \"/k\" }\n"),
    ] {
        let errs = load_str(&format!(
            "[[listen]]\nproto = \"{proto}\"\naddr = \"0.0.0.0:853\"\n{tls}x_forwarded_for = true\ntrusted_proxies = [\"10.0.5.20/32\"]\n"
        ))
        .unwrap_err();
        assert_eq!(
            errors_at(&errs, "listen[0].x_forwarded_for"),
            ["only valid for doh listeners"],
            "{proto}: {errs:?}"
        );
    }
}

/// REQ: DNS-003, DNS-020 (ADR-194) — one source of client addresses per listener.
#[test]
fn dns_003_proxy_protocol_and_x_forwarded_for_are_exclusive() {
    let errs = load_str(&format!(
        "{DOH_TLS}proxy_protocol = true\nx_forwarded_for = true\ntrusted_proxies = [\"10.0.5.20/32\"]\n"
    ))
    .unwrap_err();
    assert_eq!(
        errors_at(&errs, "listen[0].x_forwarded_for"),
        ["set `proxy_protocol` or `x_forwarded_for`, not both"],
        "{errs:?}"
    );
    assert_eq!(errs.len(), 1, "{errs:?}");
}

/// REQ: DNS-003, DNS-020 (ADR-194) — `trusted_proxies` is for a `doh` listener that takes the
/// client's address from them (PROXY protocol or `X-Forwarded-For`).
#[test]
fn dns_003_trusted_proxies_only_with_a_forwarded_source() {
    let why = "only valid on a doh listener with `proxy_protocol` or `x_forwarded_for`";
    for toml in [
        format!("{DOH_TLS}trusted_proxies = [\"10.0.5.20/32\"]\n"),
        "[[listen]]\nproto = \"tcp\"\naddr = \"0.0.0.0:53\"\nproxy_protocol = true\ntrusted_proxies = [\"10.0.5.20/32\"]\n".to_owned(),
        "[[listen]]\nproto = \"dot\"\naddr = \"0.0.0.0:853\"\ntls = { cert = \"/c\", key = \"/k\" }\nproxy_protocol = true\ntrusted_proxies = [\"10.0.5.20/32\"]\n".to_owned(),
    ] {
        let errs = load_str(&toml).unwrap_err();
        assert_eq!(
            errors_at(&errs, "listen[0].trusted_proxies"),
            [why],
            "{toml}: {errs:?}"
        );
    }
    let ok = load_str(&format!(
        "{DOH_TLS}proxy_protocol = true\ntrusted_proxies = [\"10.0.5.20/32\"]\n"
    ))
    .unwrap();
    assert!(listen_warnings(&ok).is_empty(), "{:?}", ok.warnings);
    assert!(ok.config.listen[0].proxy_protocol);
}

/// REQ: DNS-003 (ADR-194) — a prefix of 0 trusts everyone and is refused; a network wider than
/// one host, a proxy a loopback listener can never see, and the per-address limit left at its
/// default behind `X-Forwarded-For` are warnings.
#[test]
fn dns_003_trusted_proxies_refuses_everyone_and_warns_on_networks() {
    let errs = load_str(&format!(
        "{DOH_TLS}proxy_protocol = true\ntrusted_proxies = [\"0.0.0.0/0\", \"10.0.5.20/32\", \"::/0\"]\n"
    ))
    .unwrap_err();
    assert_eq!(
        errors_at(&errs, "listen[0].trusted_proxies[0]"),
        ["`0.0.0.0/0` trusts every address: list only your proxies"],
        "{errs:?}"
    );
    assert_eq!(
        errors_at(&errs, "listen[0].trusted_proxies[2]"),
        ["`::/0` trusts every address: list only your proxies"],
        "{errs:?}"
    );
    assert_eq!(errs.len(), 2, "{errs:?}");

    let wide = load_str(&format!(
        "{DOH_TLS}proxy_protocol = true\ntrusted_proxies = [\"10.0.0.0/24\", \"10.0.5.20/32\", \"2001:db8::/64\", \"2001:db8::5\"]\n"
    ))
    .unwrap();
    assert_eq!(
        listen_warnings(&wide),
        [
            "listen[0].trusted_proxies[0]: `10.0.0.0/24` is a network, not one proxy: every machine in it can name any client; list only your proxies",
            "listen[0].trusted_proxies[2]: `2001:db8::/64` is a network, not one proxy: every machine in it can name any client; list only your proxies",
        ],
    );

    let local = load_str(
        "[[listen]]\nproto = \"doh\"\naddr = \"127.0.0.1:9443\"\ntls = { cert = \"/c\", key = \"/k\" }\nproxy_protocol = true\ntrusted_proxies = [\"10.0.5.20/32\", \"127.0.0.1/32\", \"127.0.0.2\"]\n",
    )
    .unwrap();
    assert_eq!(
        listen_warnings(&local),
        [
            "listen[0].trusted_proxies[0]: a loopback listener only sees this host; `10.0.5.20/32` never connects"
        ],
    );

    let limit = load_str(&format!(
        "{DOH_TLS}x_forwarded_for = true\ntrusted_proxies = [\"10.0.5.20/32\"]\n"
    ))
    .unwrap();
    assert_eq!(
        listen_warnings(&limit),
        [
            "listen[0].max_connections_per_address: with `x_forwarded_for` every connection is the proxy's; the default 32 may refuse it: raise it or set 0"
        ],
    );
    let raised = load_str(&format!(
        "{DOH_TLS}x_forwarded_for = true\ntrusted_proxies = [\"10.0.5.20/32\"]\nmax_connections_per_address = 256\n"
    ))
    .unwrap();
    assert!(listen_warnings(&raised).is_empty(), "{:?}", raised.warnings);
}

/// REQ: DNS-003 (ADR-194) — neither key lifts the certificate a `doh` listener needs: without
/// `tls` it is refused with the same message as before.
#[test]
fn dns_003_forwarding_keys_keep_the_tls_requirement() {
    let errs = load_str(
        "[[listen]]\nproto = \"doh\"\naddr = \"127.0.0.1:8053\"\nx_forwarded_for = true\ntrusted_proxies = [\"127.0.0.1/32\"]\nmax_connections_per_address = 0\n",
    )
    .unwrap_err();
    assert_eq!(
        errors_at(&errs, "listen[0].tls"),
        ["required for dot, doh, doh3, and doq listeners"],
        "{errs:?}"
    );
    assert_eq!(errs.len(), 1, "{errs:?}");
}

/// REQ: DNS-003 (ADR-194) — a loopback listener's peers are this host in the listener's own
/// family: an IPv4 one never sees `::1`, an IPv6 one never sees `127.0.0.1`, and an entry it can
/// never see is a warning.
#[test]
fn dns_003_a_loopback_listener_warns_about_the_other_family() {
    let warns = |addr: &str, list: &str| -> Vec<String> {
        let loaded = load_str(&format!(
            "[[listen]]\nproto = \"doh\"\naddr = \"{addr}\"\ntls = {{ cert = \"/c\", key = \"/k\" }}\nproxy_protocol = true\ntrusted_proxies = [{list}]\n"
        ))
        .unwrap();
        listen_warnings(&loaded)
            .iter()
            .map(|w| (*w).to_owned())
            .collect()
    };
    assert_eq!(
        warns("127.0.0.1:9443", "\"::1/128\""),
        [
            "listen[0].trusted_proxies[0]: a loopback listener only sees this host; `::1/128` never connects"
        ]
    );
    assert_eq!(
        warns("[::1]:9443", "\"127.0.0.1/32\""),
        [
            "listen[0].trusted_proxies[0]: a loopback listener only sees this host; `127.0.0.1/32` never connects"
        ]
    );
    for (addr, list) in [
        ("127.0.0.1:9443", "\"127.0.0.2\""),
        ("[::1]:9443", "\"::1\""),
    ] {
        assert_eq!(warns(addr, list), Vec::<String>::new(), "{addr} {list}");
    }
}

/// REQ: DNS-003 (ADR-194) — `trusted_proxies` takes networks or addresses only: a host name is
/// refused with the network type's own message.
#[test]
fn dns_003_trusted_proxies_entries_are_networks() {
    let errs = load_str(&format!(
        "{DOH_TLS}proxy_protocol = true\ntrusted_proxies = [\"proxy.example\"]\n"
    ))
    .unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.path.starts_with("listen[0].trusted_proxies")
                && e.message.contains("`proxy.example` is not an IP network")),
        "{errs:?}"
    );
}

/// REQ: DNS-003, CLU-010 (ADR-194, ADR-187) — the new keys are written only when set: every
/// listener without them serializes as before (the defaults, and a `doh` listener that sets
/// them to their defaults), and set ones read back.
#[test]
fn dns_003_new_listener_keys_not_written_at_default() {
    // Sorted, whatever order the map keeps.
    let keys = |v: &serde_json::Value| -> Vec<String> {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    for l in serde_json::to_value(Config::default()).unwrap()["listen"]
        .as_array()
        .unwrap()
    {
        assert_eq!(keys(l), ["addr", "proto", "proxy_protocol"], "{l}");
    }
    let plain = load_str(DOH_TLS).unwrap().config;
    let written = serde_json::to_value(&plain.listen[0]).unwrap();
    assert_eq!(
        keys(&written),
        ["addr", "proto", "proxy_protocol", "tls"],
        "{written}"
    );
    let defaults = load_str(&format!(
        "{DOH_TLS}x_forwarded_for = false\ntrusted_proxies = []\n"
    ))
    .unwrap()
    .config;
    assert_eq!(serde_json::to_value(&defaults.listen[0]).unwrap(), written);
    assert_eq!(defaults, plain);

    let set = load_str(&format!(
        "{DOH_TLS}x_forwarded_for = true\ntrusted_proxies = [\"10.0.5.20/32\"]\nmax_connections_per_address = 0\n"
    ))
    .unwrap()
    .config;
    let text = serde_json::to_value(&set.listen[0]).unwrap();
    assert_eq!(
        keys(&text),
        [
            "addr",
            "max_connections_per_address",
            "proto",
            "proxy_protocol",
            "tls",
            "trusted_proxies",
            "x_forwarded_for"
        ]
    );
    let back: telltale_config::Listener = serde_json::from_value(text).unwrap();
    assert_eq!(back, set.listen[0]);
}

/// REQ: CLU-003, CLU-006 (ADR-194) — listener settings never leave a node: the shared part of a
/// configuration with the new keys is the same bytes as without them.
#[test]
fn clu_003_listener_keys_never_shared() {
    let with = load_str(&format!(
        "{DOH_TLS}x_forwarded_for = true\ntrusted_proxies = [\"10.0.5.20/32\"]\nmax_connections_per_address = 0\n"
    ))
    .unwrap()
    .config;
    let without = load_str(DOH_TLS).unwrap().config;
    let shared = telltale_config::shared::shared_part(&with);
    assert!(shared.get("listen").is_none(), "{shared}");
    let text = serde_json::to_string(&shared).unwrap();
    assert!(
        !text.contains("x_forwarded_for") && !text.contains("trusted_proxies"),
        "{text}"
    );
    assert_eq!(
        text,
        serde_json::to_string(&telltale_config::shared::shared_part(&without)).unwrap()
    );
}
