//! OPS-005 acceptance tests: unknown keys error with path; env overrides apply.

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
