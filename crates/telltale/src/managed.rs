//! Config made through the API and UI, merged with the config files (REQ: API-002, API-010,
//! API-011; ADR-040, ADR-042).
//!
//! Entries live in `state.db` by kind and name: devices (`client`), local names (`record`: an
//! owner name and its records), and domains sent to other servers (`forward`: a domain and its
//! servers, expanded into upstreams, an upstream group, and a route). The files stay
//! authoritative: an entry the files define is read-only through the API, and the API can't
//! create a name the files use. If the merged config doesn't validate (say a group named by an
//! API client was removed from the file), the files alone are used and the reason is logged:
//! DNS never waits on, or breaks because of, the API layer.

use std::path::Path;

use serde::{Deserialize, Serialize};
use telltale_config::{
    ClientConfig, Config, LocalRecord, Route, SafeString, Upstream, UpstreamGroup,
};
use telltale_store::state::State;
use tracing::{error, warn};

/// The kind names in `state.db`.
pub(crate) const CLIENT: &str = "client";
pub(crate) const RECORD: &str = "record";
pub(crate) const FORWARD: &str = "forward";
/// Quick rules (T6.12, ADR-067), stored by ID.
pub(crate) const RULE: &str = "rule";

/// One record of a local name (a name's records are stored together).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordValue {
    #[serde(rename = "type")]
    pub(crate) rtype: String,
    pub(crate) value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ttl: Option<u32>,
}

/// The servers a domain is sent to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Forward {
    pub(crate) servers: Vec<String>,
}

/// Everything stored through the API.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Entries {
    pub(crate) clients: Vec<ClientConfig>,
    pub(crate) records: Vec<(String, Vec<RecordValue>)>,
    pub(crate) forwards: Vec<(String, Forward)>,
    pub(crate) rules: Vec<telltale_config::RuleConfig>,
}

/// Where the state database lives.
pub(crate) fn state_path(cfg: &Config) -> std::path::PathBuf {
    Path::new(cfg.node.data_dir.as_str()).join("state.db")
}

fn decode<T: for<'de> Deserialize<'de>>(state: &State, kind: &str) -> Vec<(String, T)> {
    let rows = match state.managed(kind) {
        Ok(r) => r,
        Err(e) => {
            warn!("config made in the UI ({kind}) is unavailable: {e}");
            return Vec::new();
        }
    };
    rows.into_iter()
        .filter_map(|m| match serde_json::from_str::<T>(&m.body) {
            Ok(v) => Some((m.name, v)),
            Err(e) => {
                warn!(kind, name = %m.name, "skipping a stored entry: {e}");
                None
            }
        })
        .collect()
}

/// Everything stored through the API, decoded (bad rows are skipped with a warning).
pub(crate) fn entries(state: &State) -> Entries {
    Entries {
        clients: decode::<ClientConfig>(state, CLIENT)
            .into_iter()
            .map(|(_, c)| c)
            .collect(),
        records: decode(state, RECORD),
        forwards: decode(state, FORWARD),
        rules: decode::<telltale_config::RuleConfig>(state, RULE)
            .into_iter()
            .map(|(_, r)| r)
            .collect(),
    }
}

/// The upstream group a forwarded domain uses.
pub(crate) fn forward_group(domain: &str) -> String {
    format!("forward:{domain}")
}

/// A server as an upstream URL: a bare address means plain DNS (`udp://`).
pub(crate) fn server_url(s: &str) -> String {
    if s.contains("://") {
        s.to_owned()
    } else {
        format!("udp://{s}")
    }
}

fn safe(s: &str) -> Result<SafeString, String> {
    SafeString::new(s)
}

/// `file` plus the entries (names the files already use are skipped), if the result validates
/// (including record values); otherwise `Err` with the reasons.
pub(crate) fn merge(file: &Config, e: &Entries) -> Result<Config, Vec<String>> {
    let mut cfg = file.clone();
    for c in &e.clients {
        if !cfg.client.iter().any(|f| f.name == c.name) {
            cfg.client.push(c.clone());
        }
    }
    // A rule ID the files use wins (ADR-067).
    for r in &e.rules {
        if !cfg.rule.iter().any(|f| f.id == r.id) {
            cfg.rule.push(r.clone());
        }
    }
    let mut errs = Vec::new();
    for (name, recs) in &e.records {
        if file
            .record
            .iter()
            .any(|r| r.name.eq_ignore_ascii_case(name))
        {
            continue;
        }
        for r in recs {
            match (safe(name), safe(&r.rtype), safe(&r.value)) {
                (Ok(n), Ok(t), Ok(v)) => cfg.record.push(LocalRecord {
                    name: n,
                    rtype: t,
                    value: v,
                    ttl: r.ttl,
                    node_only: false,
                }),
                _ => errs.push(format!("record `{name}`: invalid characters")),
            }
        }
    }
    for (domain, f) in &e.forwards {
        let taken = file.route.iter().any(|r| {
            r.match_suffix
                .iter()
                .any(|s| s.eq_ignore_ascii_case(domain))
        });
        if taken {
            continue;
        }
        let group = forward_group(domain);
        let mut members = Vec::new();
        for (i, s) in f.servers.iter().enumerate() {
            let name = format!("{group}#{}", i + 1);
            match (safe(&name), safe(&server_url(s))) {
                (Ok(n), Ok(url)) => match new_upstream(n.clone(), url) {
                    Some(u) => {
                        members.push(n);
                        cfg.upstream.push(u);
                    }
                    None => errs.push(format!("forward `{domain}`: invalid server `{s}`")),
                },
                _ => errs.push(format!("forward `{domain}`: invalid server `{s}`")),
            }
        }
        match (safe(&group), safe(domain)) {
            (Ok(g), Ok(d)) => {
                cfg.upstream_group.push(UpstreamGroup {
                    name: g.clone(),
                    members,
                    strategy: telltale_config::Strategy::Failover,
                    parallel_fanout: 2,
                });
                cfg.route.push(Route {
                    match_suffix: vec![d],
                    match_group: Vec::new(),
                    match_qtype: Vec::new(),
                    upstream_group: g,
                    dnssec_nta: true,
                });
            }
            _ => errs.push(format!("forward `{domain}`: invalid name")),
        }
    }
    if let Err(v) = telltale_config::validate_config(&cfg) {
        errs.extend(v.iter().map(ToString::to_string));
    }
    let (_, report) = telltale_policy::LocalData::from_config(&cfg);
    errs.extend(report.errors);
    if errs.is_empty() { Ok(cfg) } else { Err(errs) }
}

/// An upstream with every optional field at its default.
fn new_upstream(name: SafeString, url: SafeString) -> Option<Upstream> {
    let mut u: Upstream = toml::from_str(
        "name = \"x\"
url = \"udp://127.0.0.1\"",
    )
    .ok()?;
    u.name = name;
    u.url = url;
    Some(u)
}

/// Tests that only add devices.
#[cfg(test)]
pub(crate) fn merge_clients(
    file: &Config,
    extra: Vec<ClientConfig>,
) -> Result<Config, Vec<String>> {
    merge(
        file,
        &Entries {
            clients: extra,
            ..Entries::default()
        },
    )
}

/// The effective config: `file` plus what the API stored. Opens `state.db` briefly; any
/// problem falls back to `file`.
pub(crate) fn effective(file: &Config) -> Config {
    let path = state_path(file);
    if !path.exists() {
        return file.clone();
    }
    let state = match State::open(&path) {
        Ok(s) => s,
        Err(e) => {
            warn!("config made in the UI is unavailable ({e}); using the config files only");
            return file.clone();
        }
    };
    match merge(file, &entries(&state)) {
        Ok(c) => c,
        Err(errs) => {
            for e in &errs {
                error!("config made in the UI/API: {e}");
            }
            error!(
                "ignoring config made in the UI until this is fixed; using the config files only"
            );
            file.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_config::SafeString;

    fn client(name: &str, ip: &str, groups: &[&str]) -> ClientConfig {
        ClientConfig {
            name: SafeString::new(name).unwrap(),
            match_keys: vec![SafeString::new(ip).unwrap()],
            groups: groups
                .iter()
                .map(|g| SafeString::new(*g).unwrap())
                .collect(),
        }
    }

    #[test]
    fn api_010_files_win_and_bad_entries_fall_back() {
        let mut file = Config::default();
        file.client
            .push(client("nas", "192.168.1.10", &["default"]));
        let merged = merge_clients(
            &file,
            vec![
                client("tv", "192.168.1.20", &["default"]),
                client("nas", "192.168.1.99", &["default"]), // the file's name: ignored
            ],
        )
        .unwrap();
        let names: Vec<&str> = merged.client.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["nas", "tv"]);
        assert_eq!(merged.client[0].match_keys[0].as_str(), "192.168.1.10");
        // A group that doesn't exist: the merge is refused with the reason.
        let err =
            merge_clients(&file, vec![client("phone", "192.168.1.30", &["kids"])]).unwrap_err();
        assert!(err.iter().any(|e| e.contains("kids")), "{err:?}");
    }

    #[test]
    fn api_010_effective_reads_state_db() {
        let dir = tempfile::tempdir().unwrap();
        let mut file = Config::default();
        file.node.data_dir = SafeString::new(dir.path().to_str().unwrap()).unwrap();
        assert_eq!(effective(&file), file, "no state.db yet");
        let state = State::open(&state_path(&file)).unwrap();
        let body = serde_json::to_string(&client("tv", "192.168.1.20", &["default"])).unwrap();
        state
            .put_managed(CLIENT, "tv", &body, None, None, 1, "admin")
            .unwrap();
        state
            .put_managed(CLIENT, "junk", "not json", None, None, 2, "admin")
            .unwrap();
        let eff = effective(&file);
        assert_eq!(eff.client.len(), 1);
        assert_eq!(eff.client[0].name.as_str(), "tv");
    }

    fn rv(t: &str, v: &str) -> RecordValue {
        RecordValue {
            rtype: t.into(),
            value: v.into(),
            ttl: None,
        }
    }

    fn base() -> Config {
        telltale_config::Loader::new()
            .toml_str(
                "t",
                "[[upstream]]\nname = \"up\"\nurl = \"udp://9.9.9.9\"\n[[upstream_group]]\nname = \"default\"\nmembers = [\"up\"]\n[[record]]\nname = \"router.home.arpa\"\ntype = \"A\"\nvalue = \"192.168.1.1\"\n",
            )
            .load()
            .unwrap()
            .config
    }

    #[test]
    fn api_011_records_and_forwards_merge() {
        let e = Entries {
            records: vec![
                (
                    "nas.home.arpa".into(),
                    vec![rv("A", "192.168.1.10"), rv("AAAA", "fd00::10")],
                ),
                ("router.home.arpa".into(), vec![rv("A", "10.9.9.9")]), // the file's: ignored
            ],
            forwards: vec![(
                "corp.example".into(),
                Forward {
                    servers: vec!["10.0.0.53".into(), "tls://10.0.0.54".into()],
                },
            )],
            ..Entries::default()
        };
        let cfg = merge(&base(), &e).unwrap();
        let names: Vec<(&str, &str)> = cfg
            .record
            .iter()
            .map(|r| (r.name.as_str(), r.value.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                ("router.home.arpa", "192.168.1.1"),
                ("nas.home.arpa", "192.168.1.10"),
                ("nas.home.arpa", "fd00::10")
            ]
        );
        let route = cfg.route.last().unwrap();
        assert_eq!(route.match_suffix[0].as_str(), "corp.example");
        assert_eq!(route.upstream_group.as_str(), "forward:corp.example");
        let urls: Vec<&str> = cfg
            .upstream
            .iter()
            .skip(1)
            .map(|u| u.url.as_str())
            .collect();
        assert_eq!(urls, ["udp://10.0.0.53", "tls://10.0.0.54"]);
    }

    #[test]
    fn api_011_bad_values_are_refused_with_reasons() {
        let bad_record = Entries {
            records: vec![("nas.home.arpa".into(), vec![rv("A", "not-an-address")])],
            ..Entries::default()
        };
        let errs = merge(&base(), &bad_record).unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("not-an-address")),
            "{errs:?}"
        );
        let bad_server = Entries {
            forwards: vec![(
                "corp.example".into(),
                Forward {
                    servers: vec!["ftp://x".into()],
                },
            )],
            ..Entries::default()
        };
        assert!(merge(&base(), &bad_server).is_err());
    }
}
