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
        ])
        .load()
        .unwrap();
    assert_eq!(loaded.config.node, Config::default().node);
    let unknown: Vec<_> = loaded
        .warnings
        .iter()
        .filter(|w| w.contains("unknown environment variable"))
        .collect();
    assert_eq!(unknown.len(), 2, "TELLTALE_CONFIG is reserved: {unknown:?}");
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
