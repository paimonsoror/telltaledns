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

/// Shared lists whose entries can say `node_only = true` (CLU-006): such an entry stays on
/// its node. FLT-017: the chart's route to `CoreDNS`, which only pods in that cluster can reach.
const NODE_ONLY_LISTS: &[&str] = &["record", "upstream", "upstream_group", "route"];

fn node_only(v: &Value) -> bool {
    v.get("node_only") == Some(&Value::Bool(true))
}

/// The shared part of `cfg` as a JSON object. Serializing the same struct always gives the
/// same key order, so equal configs give equal bytes and equal hashes.
pub fn shared_part(cfg: &Config) -> Value {
    let mut v = serde_json::to_value(cfg).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut v {
        for k in NODE_LOCAL {
            m.remove(*k);
        }
        // Node-only entries stay on their node (CLU-006).
        for k in NODE_ONLY_LISTS {
            if let Some(Value::Array(list)) = m.get_mut(*k) {
                list.retain(|v| !node_only(v));
            }
        }
        // REQ: CLU-013 — `[cluster.rollout]` is the one part of `[cluster]` the cluster shares
        // (who the canaries are, for every node to show). Older replicas skip `cluster`.
        if cfg.cluster.rollout != crate::RolloutConfig::default()
            && let Ok(r) = serde_json::to_value(&cfg.cluster.rollout)
        {
            let mut c = Map::new();
            c.insert("rollout".into(), r);
            m.insert("cluster".into(), Value::Object(c));
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
    // This node's node-only entries survive the merge (CLU-006).
    let own: Vec<(&str, Vec<Value>)> = NODE_ONLY_LISTS
        .iter()
        .map(|k| match merged.get(*k) {
            Some(Value::Array(l)) => (*k, l.iter().filter(|v| node_only(v)).cloned().collect()),
            _ => (*k, Vec::new()),
        })
        .collect();
    // A shared section the primary didn't send is at its default (see `shared_part`).
    if let Ok(Value::Object(d)) = serde_json::to_value(Config::default()) {
        for (k, v) in d {
            if !NODE_LOCAL.contains(&k.as_str()) && !shared.contains_key(&k) {
                merged.insert(k, v);
            }
        }
    }
    // REQ: CLU-013 — the primary's `[cluster.rollout]` (the default when it didn't send one);
    // the rest of `[cluster]` stays this node's.
    let rollout = shared
        .get("cluster")
        .and_then(|c| c.get("rollout"))
        .cloned()
        .or_else(|| serde_json::to_value(crate::RolloutConfig::default()).ok());
    if let (Some(r), Some(Value::Object(c))) = (rollout, merged.get_mut("cluster")) {
        c.insert("rollout".into(), r);
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
    for (k, mine) in own.into_iter().filter(|(_, l)| !l.is_empty()) {
        if let Some(Value::Array(l)) = merged.get_mut(k) {
            // A named entry of this node's own takes the place of the cluster's of that name
            // (an older primary that still shares it, mid-rollout).
            if matches!(k, "upstream" | "upstream_group") {
                l.retain(|v| !mine.iter().any(|m| m.get("name") == v.get("name")));
            }
            l.extend(mine);
        } else {
            merged.insert(k.into(), Value::Array(mine));
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

    // REQ: CLU-013 — `[cluster.rollout]` travels with the shared part (the rest of `[cluster]`
    // doesn't); a replica takes the primary's, and the default when the primary sends none.
    #[test]
    fn clu_013_rollout_settings_are_shared() {
        let primary = load(
            "[cluster]\nsite = \"k8s\"\nlisten = \"0.0.0.0:9443\"\n[cluster.rollout]\ncanaries = [\"ephemeral\"]\nbake_secs = 60\n",
        );
        let shared = shared_part(&primary);
        let c = shared["cluster"].as_object().unwrap();
        assert_eq!(
            c.keys().collect::<Vec<_>>(),
            vec!["rollout"],
            "only the rollout"
        );
        let replica = load("[cluster]\nsite = \"pi\"\n");
        let merged = with_shared(&replica, &shared).unwrap();
        assert_eq!(merged.cluster.rollout.canaries.len(), 1);
        assert_eq!(merged.cluster.rollout.bake_secs, 60);
        assert_eq!(
            merged.cluster.site.as_str(),
            "pi",
            "the rest stays the node's"
        );
        assert_eq!(merged.cluster.listen.as_str(), "0.0.0.0:8443");
        // Off at the primary: off everywhere; the default isn't sent at all.
        let none = shared_part(&load(""));
        assert!(none.get("cluster").is_none());
        let off = with_shared(&merged, &none).unwrap();
        assert_eq!(off.cluster.rollout, crate::RolloutConfig::default());
        // Validation: bounds and canary names.
        assert!(
            Loader::new()
                .toml_str("t", "[cluster.rollout]\nbake_secs = 1\n")
                .load()
                .is_err()
        );
        assert!(
            Loader::new()
                .toml_str("t", "[cluster.rollout]\ncanaries = [\"site:\"]\n")
                .load()
                .is_err()
        );
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

    // REQ: FLT-017, CLU-006 (regression 2026-10-19) — the chart's route to CoreDNS is
    // node-only: a Pi in the same cluster can't reach 10.43.0.10, and got the upstream, timed
    // out on it, and reported its group as down. Pods in the cluster keep it.
    #[test]
    fn flt_017_kubernetes_route_stays_on_the_nodes_in_the_cluster() {
        let chart = r#"
[[upstream]]
name = "q9"
url = "udp://9.9.9.9"
[[upstream_group]]
name = "default"
members = ["q9"]
[[upstream]]
name = "kubernetes-dns"
url = "udp://10.43.0.10"
node_only = true
[[upstream_group]]
name = "kubernetes"
members = ["kubernetes-dns"]
node_only = true
[[route]]
match_suffix = ["cluster.local"]
upstream_group = "kubernetes"
node_only = true
"#;
        let primary = load(chart);
        let shared = shared_part(&primary);
        let names = |v: &Value, k: &str| -> Vec<String> {
            v[k].as_array()
                .map(|l| {
                    l.iter()
                        .filter_map(|x| x["name"].as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        assert_eq!(names(&shared, "upstream"), ["q9"]);
        assert_eq!(names(&shared, "upstream_group"), ["default"]);
        assert!(shared.get("route").is_none(), "{shared}");
        // The Pi: the cluster's default group, no route to CoreDNS.
        let pi = with_shared(&load("[node]\nname = \"pi\"\n"), &shared).unwrap();
        assert_eq!(pi.upstream.len(), 1);
        assert!(pi.route.is_empty() && pi.upstream_group.len() == 1);
        // A resolver pod loads the same chart file: it keeps its own route.
        let pod = with_shared(&primary, &shared).unwrap();
        assert_eq!(pod.upstream, primary.upstream);
        assert_eq!(pod.upstream_group, primary.upstream_group);
        assert_eq!(pod.route, primary.route);
        assert_eq!(
            ignored_on_replica(&load(chart)),
            ["upstream", "upstream_group"]
        );
        // Mid-rollout, an older primary still shares the chart's upstream and group (no
        // node_only); the pod's own copies take their place instead of clashing.
        let mut old = shared.clone();
        for (k, x) in [
            ("upstream", serde_json::to_value(&primary.upstream)),
            (
                "upstream_group",
                serde_json::to_value(&primary.upstream_group),
            ),
        ] {
            old[k] = x.unwrap();
            for v in old[k].as_array_mut().unwrap() {
                v.as_object_mut().unwrap().remove("node_only");
            }
        }
        let pod = with_shared(&primary, &old).unwrap();
        assert_eq!(pod.upstream.len(), 2);
        assert!(
            pod.upstream
                .iter()
                .all(|u| u.name.as_str() == "q9" || u.node_only)
        );
        // Nothing shared may lean on a node-only entry: other nodes wouldn't have it.
        for bad in [
            "[[upstream]]\nname = \"k\"\nurl = \"udp://10.43.0.10\"\nnode_only = true\n[[upstream_group]]\nname = \"default\"\nmembers = [\"k\"]\n",
            "[[upstream]]\nname = \"k\"\nurl = \"udp://10.43.0.10\"\n[[upstream_group]]\nname = \"g\"\nmembers = [\"k\"]\nnode_only = true\n[[route]]\nmatch_suffix = [\"cluster.local\"]\nupstream_group = \"g\"\n",
        ] {
            let e = Loader::new()
                .toml_str("t", bad)
                .load()
                .unwrap_err()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            assert!(e.contains("node_only"), "{e}");
        }
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
