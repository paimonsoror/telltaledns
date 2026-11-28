// REQ: OPS-011 (ADR-156) — configuration classification: every string field of the generated
// schema has a class (a new field can't ship without one), unknown fields fail closed, and a
// config with secrets planted in it comes out without them at every level.

use super::*;
use crate::Level;
use crate::pseudo::Pseudonyms;
use serde_json::json;

fn red(level: Level) -> Redactor {
    Redactor::new(level, Pseudonyms::new([3; 32]))
}

#[test]
fn ops_011_every_string_field_of_the_schema_has_a_class() {
    let info = schema_info();
    let missing: Vec<&String> = info
        .needs_class
        .iter()
        .filter(|p| class_of(p).is_none())
        .collect();
    assert!(
        missing.is_empty(),
        "these configuration fields have no class in telltale-support's classify.rs TABLE (a field with no class is dropped from every package): {missing:#?}"
    );
}

#[test]
fn ops_011_every_table_entry_names_a_real_field() {
    let info = schema_info();
    let stale: Vec<&str> = table_paths()
        .into_iter()
        .filter(|p| !info.needs_class.contains(*p))
        .collect();
    assert!(
        stale.is_empty(),
        "table entries that match no string, size, or map field (mistyped or removed): {stale:#?}"
    );
}

#[test]
fn ops_011_the_schema_walk_finds_the_fields_it_should() {
    let info = schema_info();
    assert!(info.paths.len() > 250, "{}", info.paths.len());
    assert!(info.needs_class.contains("node.name") && info.needs_class.contains("upstream[].url"));
    assert!(
        info.needs_class.contains("upstream[].headers"),
        "a free-form map is one leaf"
    );
    assert!(
        info.plain.contains("cache.max_ttl"),
        "a number is plain by type"
    );
    assert!(
        info.plain.contains("node.role"),
        "a fixed word is plain by type"
    );
    assert!(!info.plain.contains("node.name"));
}

#[test]
fn ops_011_the_default_configuration_has_nothing_unclassified() {
    let cfg = serde_json::to_value(telltale_config::Config::default()).unwrap();
    for level in [Level::Strict, Level::Standard, Level::Off] {
        let view = config_view(&cfg, &mut red(level));
        assert!(
            view.unclassified.is_empty(),
            "{level:?}: {:?}",
            view.unclassified
        );
    }
}

fn planted() -> Value {
    json!({
        "node": { "name": "home-pi", "data_dir": "/home/alice/telltale", "role": "All" },
        "client": [{
            "name": "Living-TV",
            "match": ["192.168.1.20", "aa:bb:cc:dd:ee:ff", "id:kids-tablet"],
            "groups": ["kids"]
        }],
        "group": [{ "name": "kids", "networks": ["192.168.1.0/24"], "rewrite": [{ "domain": "ads.acme-dns.net", "answer": "0.0.0.0" }] }],
        "upstream": [
            { "name": "doh", "url": "https://dns.acme-dns.net/dns-query/abc123secretprofile",
              "headers": { "Authorization": "Bearer hunter2hunter2" } },
            { "name": "quad9", "url": "tls://9.9.9.9", "tls_server_name": "dns.quad9.net" }
        ],
        "auth": { "oidc": {
            "public_url": "https://dns.home.acme-dns.org",
            "provider": [{ "id": "idp", "name": "IdP", "issuer": "https://idp.acme-dns.org/realms/me",
                           "client_id": "telltale-client-id", "client_secret": "oidc-secret-value-123",
                           "client_secret_file": "/home/alice/.secrets/oidc" }]
        } },
        "telemetry": { "otlp": { "endpoint": "https://otel.acme-dns.net:4318/v1/traces", "headers": { "x-key": "otlp-header-secret-9" } } },
        "cache": { "max_ttl": 600, "max_bytes": "64MiB" },
        "cluster": { "name": "telltale", "site": "home", "bootstrap_secret_file": "/run/secrets/boot" },
        "rule": [{ "id": "r-1", "action": "block", "domain": "game.acme-dns.com", "note": "Mom's game", "devices": ["Living-TV"] }]
    })
}

#[test]
fn ops_011_secrets_and_names_do_not_survive_at_strict() {
    let mut r = red(Level::Strict);
    let view = config_view(&planted(), &mut r);
    let text = serde_json::to_string(&view.value).unwrap();
    for gone in [
        "hunter2hunter2",
        "oidc-secret-value-123",
        "otlp-header-secret-9",
        "telltale-client-id",
        "abc123secretprofile",
        "alice",
        "Living-TV",
        "kids-tablet",
        "192.168.1.20",
        "aa:bb:cc",
        "home-pi",
        "dns.acme-dns.net",
        "dns.quad9.net",
        "game.acme-dns.com",
        "Mom's game",
        "ads.acme-dns.net",
        "otel.acme-dns.net",
        "idp.acme-dns.org",
        "dns.home.acme-dns.org",
    ] {
        assert!(!text.contains(gone), "{gone} survived: {text}");
    }
    // What triage needs stays.
    for kept in [
        "\"max_ttl\":600",
        "64MiB",
        "\"All\"",
        "9.9.9.9",
        "\"name\":\"doh\"",
        "\"name\":\"quad9\"",
        "IdP",
    ] {
        assert!(text.contains(kept), "{kept} missing: {text}");
    }
    assert!(
        view.dropped.contains(&"upstream[].headers".to_owned()),
        "{:?}",
        view.dropped
    );
    assert!(
        view.dropped
            .contains(&"auth.oidc.provider[].client_secret".to_owned()),
        "{:?}",
        view.dropped
    );
    assert!(view.dropped.contains(&"telemetry.otlp.headers".to_owned()));
    assert!(view.unclassified.is_empty(), "{:?}", view.unclassified);
    // The same device is one pseudonym wherever it appears.
    assert!(text.matches("device-").count() >= 2, "{text}");
}

#[test]
fn ops_011_none_keeps_names_and_still_drops_secrets() {
    let mut r = red(Level::Off);
    let view = config_view(&planted(), &mut r);
    let text = serde_json::to_string(&view.value).unwrap();
    for gone in [
        "hunter2hunter2",
        "oidc-secret-value-123",
        "otlp-header-secret-9",
        "telltale-client-id",
    ] {
        assert!(!text.contains(gone), "{gone} survived at none: {text}");
    }
    for kept in [
        "home-pi",
        "Living-TV",
        "192.168.1.20",
        "kids-tablet",
        "game.acme-dns.com",
        "dns.quad9.net",
    ] {
        assert!(text.contains(kept), "{kept} missing at none: {text}");
    }
}

#[test]
fn ops_011_an_unknown_string_field_is_dropped_and_listed() {
    let mut r = red(Level::Standard);
    let view = config_view(
        &json!({ "node": { "name": "x", "mystery_field": "value", "api_token": "tok-123456789" } }),
        &mut r,
    );
    let text = serde_json::to_string(&view.value).unwrap();
    assert!(
        !text.contains("value") && !text.contains("tok-123456789"),
        "{text}"
    );
    assert!(
        view.unclassified.iter().any(|p| p.ends_with("{}")),
        "{:?}",
        view.unclassified
    );
    assert!(
        view.dropped.iter().any(|p| p.ends_with("{}")),
        "the credential-looking key is dropped: {:?}",
        view.dropped
    );
}

#[test]
fn ops_011_known_names_and_inline_secrets_come_from_the_config() {
    let known = known_from_config(&planted());
    let mut r = red(Level::Strict);
    r.set_known(&known).unwrap();
    // A log line naming the device, the node, or holding the secret.
    let out = r
        .text("Living-TV asked home-pi; auth failed with oidc-secret-value-123 and hunter2hunter2");
    for gone in [
        "Living-TV",
        "home-pi",
        "oidc-secret-value-123",
        "hunter2hunter2",
    ] {
        assert!(!out.contains(gone), "{gone}: {out}");
    }
    assert!(
        out.contains("device-") && out.contains("node-") && out.contains("<secret>"),
        "{out}"
    );
    // The configuration and the log agree on the pseudonyms.
    let view = config_view(&planted(), &mut r);
    let cfg_text = serde_json::to_string(&view.value).unwrap();
    let dev = out.split_whitespace().next().unwrap();
    assert!(cfg_text.contains(dev), "{dev} not in {cfg_text}");
}

// REQ: OPS-011, DNS-003 (ADR-194) — a `doh` listener's proxies are addresses: kept at `none`,
// replaced by a network of the same size at `strict`, and never dropped as unclassified.
#[test]
fn ops_011_support_package_classifies_the_new_listener_fields() {
    assert_eq!(class_of("listen[].trusted_proxies[]"), Some(Class::Scan));
    let cfg = json!({ "listen": [{
        "proto": "doh", "addr": "0.0.0.0:443",
        "tls": { "cert": "/etc/telltale/tls.crt", "key": "/etc/telltale/tls.key" },
        "proxy_protocol": false, "x_forwarded_for": true,
        "trusted_proxies": ["10.0.5.20/32"]
    }] });
    let off = config_view(&cfg, &mut red(Level::Off));
    assert!(off.unclassified.is_empty(), "{:?}", off.unclassified);
    assert_eq!(
        off.value["listen"][0]["trusted_proxies"],
        json!(["10.0.5.20/32"])
    );
    assert_eq!(off.value["listen"][0]["x_forwarded_for"], true);
    let strict = config_view(&cfg, &mut red(Level::Strict));
    assert!(strict.unclassified.is_empty(), "{:?}", strict.unclassified);
    let kept = strict.value["listen"][0]["trusted_proxies"][0]
        .as_str()
        .unwrap();
    assert!(
        !kept.contains("10.0.5.20") && kept.ends_with("/32"),
        "{kept}"
    );
}
