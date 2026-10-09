//! The cluster's shared configuration (REQ: CLU-003, CLU-006; ADR-047): what the primary
//! replicates, and how a replica combines it with its own node-local sections.
//!
//! Node-local sections stay with each node: where it listens, its identity and data
//! directory, its cluster port, the API listener and sign-in (ADR-045 replicates identities
//! separately), telemetry/query-log retention, and the cache size. Everything else (upstreams,
//! routes, records, lists, groups, clients, access, rate limits, special names) is the
//! primary's.

use serde_json::{Map, Value};

use crate::{Config, ConfigError, validate_config};

/// Top-level sections that never leave a node.
pub const NODE_LOCAL: &[&str] = &[
    "config_version",
    "node",
    "cluster",
    "listen",
    "api",
    "auth",
    "telemetry",
    "cache",
];

/// The shared part of `cfg` as a JSON object. Serializing the same struct always gives the
/// same key order, so equal configs give equal bytes and equal hashes.
pub fn shared_part(cfg: &Config) -> Value {
    let mut v = serde_json::to_value(cfg).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut v {
        for k in NODE_LOCAL {
            m.remove(*k);
        }
        // Node-only records stay on their node (CLU-006).
        if let Some(Value::Array(records)) = m.get_mut("record") {
            records.retain(|r| r.get("node_only") != Some(&Value::Bool(true)));
        }
        // REQ: CLU-010 — sections left at their defaults aren't sent: a replica one version
        // behind would refuse a section it doesn't know even when nobody uses it. Replicas
        // read a missing section as the default (`with_shared`).
        if let Ok(Value::Object(d)) = serde_json::to_value(Config::default()) {
            m.retain(|k, v| d.get(k) != Some(v));
        }
    }
    v
}

/// Shared sections a replica's own configuration sets, which the primary's replace
/// (CLU-006): they're ignored, and the node says so. Node-only records don't count.
pub fn ignored_on_replica(own: &Config) -> Vec<String> {
    let (Value::Object(mine), Value::Object(defaults)) =
        (shared_part(own), shared_part(&Config::default()))
    else {
        return Vec::new();
    };
    mine.iter()
        .filter(|(k, v)| defaults.get(*k) != Some(v))
        .map(|(k, _)| k.clone())
        .collect()
}

/// `local` with every shared section replaced by the primary's `shared`, validated as a
/// whole. Unknown sections in `shared` (a newer primary) are an error, so a replica never
/// silently drops settings it doesn't understand.
pub fn with_shared(local: &Config, shared: &Value) -> Result<Config, Vec<ConfigError>> {
    let Value::Object(shared) = shared else {
        return Err(vec![ConfigError::new(
            "cluster",
            "the shared configuration isn't an object",
        )]);
    };
    let mut merged: Map<String, Value> = match serde_json::to_value(local) {
        Ok(Value::Object(m)) => m,
        _ => {
            return Err(vec![ConfigError::new(
                "cluster",
                "cannot serialize the local configuration",
            )]);
        }
    };
    // This node's node-only records survive the merge (CLU-006).
    let own_records: Vec<Value> = match merged.get("record") {
        Some(Value::Array(r)) => r
            .iter()
            .filter(|r| r.get("node_only") == Some(&Value::Bool(true)))
            .cloned()
            .collect(),
        _ => Vec::new(),
    };
    // A shared section the primary didn't send is at its default (see `shared_part`).
    if let Ok(Value::Object(d)) = serde_json::to_value(Config::default()) {
        for (k, v) in d {
            if !NODE_LOCAL.contains(&k.as_str()) && !shared.contains_key(&k) {
                merged.insert(k, v);
            }
        }
    }
    for (k, v) in shared {
        if NODE_LOCAL.contains(&k.as_str()) {
            continue;
        }
        if !merged.contains_key(k) {
            return Err(vec![ConfigError::new(
                k.clone(),
                "the primary sent a setting this version doesn't know; upgrade this node",
            )]);
        }
        merged.insert(k.clone(), v.clone());
    }
    if !own_records.is_empty() {
        if let Some(Value::Array(r)) = merged.get_mut("record") {
            r.extend(own_records);
        } else {
            merged.insert("record".into(), Value::Array(own_records));
        }
    }
    let cfg: Config = serde_json::from_value(Value::Object(merged)).map_err(|e| {
        vec![ConfigError::new(
            "cluster",
            format!("shared configuration: {e}"),
        )]
    })?;
    validate_config(&cfg)?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Loader;

    // REQ: CLU-010 — a section at its defaults isn't sent (an older replica doesn't know new
    // sections), and a replica reads a missing section as the default, not as its own.
    #[test]
    fn clu_010_default_sections_stay_out_of_the_shared_part() {
        let primary = load("[[record]]\nname = \"a.test\"\ntype = \"A\"\nvalue = \"10.0.0.1\"\n");
        let shared = shared_part(&primary);
        let keys: Vec<&String> = shared.as_object().unwrap().keys().collect();
        assert!(keys.iter().any(|k| *k == "record"), "{keys:?}");
        assert!(
            !keys.iter().any(|k| *k == "dnssec"),
            "an unused section isn't sent: {keys:?}"
        );
        // The replica's own (ignored) DNSSEC setting gives way to the primary's default.
        let replica = load("[dnssec]\nmode = \"validate\"\n");
        let merged = with_shared(&replica, &shared).unwrap();
        assert_eq!(merged.dnssec.mode, crate::DnssecMode::Off);
        assert_eq!(merged.record.len(), 1);
        // A used setting is sent.
        let p2 = load("[dnssec]\nmode = \"validate\"\n");
        assert!(shared_part(&p2).as_object().unwrap().contains_key("dnssec"));
    }

    fn load(toml: &str) -> Config {
        Loader::new().toml_str("t", toml).load().unwrap().config
    }

    // REQ: OBS-022, DNS-021, CLU-003 (regression 2026-10-09) — a replica whose own files leave
    // the M12 sections at their defaults takes the primary's: `[exclusions]` was skipped when
    // default, so the replica's merge didn't know the key and refused the whole version.
    #[test]
    fn clu_003_replica_takes_new_sections_it_leaves_at_defaults() {
        let primary = load(
            "[dns]\nnsid = true\n[exclusions]\nnames = [\"technitium1.dnscluster\"]\n[filter]\nstale_after_days = 7\n[[group]]\nname = \"guest\"\nnetworks = [\"10.9.0.0/24\"]\nfilter_aaaa = true\n",
        );
        let shared = shared_part(&primary);
        let replica = load("[node]\nname = \"pi\"\n");
        let merged = with_shared(&replica, &shared).unwrap();
        assert!(merged.dns.nsid);
        assert_eq!(merged.exclusions.names.len(), 1);
        assert_eq!(merged.filter.stale_after_days, 7);
        assert!(merged.group.iter().any(|g| g.filter_aaaa));
        // And back: the primary turning them off again reaches the replica too.
        let off = with_shared(&merged, &shared_part(&load(""))).unwrap();
        assert!(!off.dns.nsid && off.exclusions.names.is_empty());
    }

    #[test]
    fn clu_006_local_sections_stay_and_shared_ones_come_from_the_primary() {
        let primary = load(
            r#"
[node]
name = "pi"
[[listen]]
proto = "udp"
addr = "0.0.0.0:53"
[[upstream]]
name = "q9"
url = "udp://9.9.9.9"
[[upstream_group]]
name = "default"
members = ["q9"]
[[record]]
name = "nas.home.arpa"
type = "A"
value = "192.168.1.10"
"#,
        );
        let replica = load(
            r#"
[node]
name = "k8s"
[[listen]]
proto = "udp"
addr = "0.0.0.0:5300"
[[upstream]]
name = "cf"
url = "udp://1.1.1.1"
[[upstream_group]]
name = "default"
members = ["cf"]
[cache]
max_bytes = "128 MiB"
"#,
        );
        let shared = shared_part(&primary);
        assert!(shared.get("node").is_none() && shared.get("listen").is_none());
        let merged = with_shared(&replica, &shared).unwrap();
        // Local: name, listeners, cache. Shared: upstreams, records.
        assert_eq!(merged.node.name.as_str(), "k8s");
        assert_eq!(merged.listen, replica.listen);
        assert_eq!(merged.cache, replica.cache);
        assert_eq!(merged.upstream, primary.upstream);
        assert_eq!(merged.record, primary.record);
        // Same config, same bytes.
        assert_eq!(
            serde_json::to_vec(&shared_part(&primary)).unwrap(),
            serde_json::to_vec(&shared).unwrap()
        );
    }

    // REQ: CLU-006 — node-only records stay put; a replica's own shared settings are listed.
    #[test]
    fn clu_006_node_only_records_and_ignored_settings() {
        let primary = load(
            r#"
[[record]]
name = "nas.home.arpa"
type = "A"
value = "192.168.1.10"

[[record]]
name = "primary-only.home.arpa"
type = "A"
value = "10.0.0.1"
node_only = true
"#,
        );
        let replica = load(
            r#"
[[record]]
name = "pi.home.arpa"
type = "A"
value = "192.168.3.2"
node_only = true

[[record]]
name = "old.home.arpa"
type = "A"
value = "192.168.1.99"

[[list]]
name = "mine"
rules = ["||x.test^"]
"#,
        );
        let shared = shared_part(&primary);
        let names = |c: &Config| {
            c.record
                .iter()
                .map(|r| r.name.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            shared["record"].as_array().unwrap().len(),
            1,
            "node-only records aren't shared"
        );
        let merged = with_shared(&replica, &shared).unwrap();
        assert_eq!(names(&merged), ["nas.home.arpa", "pi.home.arpa"]);
        assert_eq!(ignored_on_replica(&replica), ["list", "record"]);
        assert_eq!(
            ignored_on_replica(&load(
                "[[record]]\nname = \"pi.home.arpa\"\ntype = \"A\"\nvalue = \"192.168.3.2\"\nnode_only = true\n"
            )),
            Vec::<String>::new()
        );
    }

    #[test]
    fn clu_003_an_unknown_or_invalid_shared_setting_is_refused() {
        let local = Config::default();
        let mut shared = shared_part(&local);
        shared["from_the_future"] = Value::Bool(true);
        assert!(with_shared(&local, &shared).is_err());
        // A route to a group that doesn't exist fails validation as a whole.
        let mut shared = shared_part(&local);
        shared["route"] =
            serde_json::json!([{ "match_suffix": ["x.test"], "upstream_group": "nope" }]);
        assert!(with_shared(&local, &shared).is_err());
    }
}
