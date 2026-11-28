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
    ClientConfig, Config, FilterList, GroupConfig, LocalRecord, Route, SafeString, Upstream,
    UpstreamGroup,
};
use telltale_store::state::State;
use tracing::{error, warn};

/// The kind names in `state.db`.
pub(crate) const CLIENT: &str = "client";
pub(crate) const RECORD: &str = "record";
pub(crate) const FORWARD: &str = "forward";
/// Quick rules (T6.12, ADR-067), stored by ID.
pub(crate) const RULE: &str = "rule";
/// T7.5 (ADR-069): these may override or hide the files' entry of the same name.
pub(crate) const UPSTREAM: &str = "upstream";
pub(crate) const UPSTREAM_GROUP: &str = "upstream_group";
pub(crate) const LIST: &str = "list";
pub(crate) const GROUP: &str = "group";
/// REQ: OBS-010 (T9.6) — alert destinations and rules (they override the files' too).
pub(crate) const ALERT_DESTINATION: &str = "alert_destination";
pub(crate) const ALERT_RULE: &str = "alert_rule";
/// REQ: FLT-010 (T9.7) — schedules.
pub(crate) const SCHEDULE: &str = "schedule";
/// REQ: OBS-038 (ADR-161) — anomaly mutes.
pub(crate) const ANOMALY_MUTE: &str = "anomaly_mute";
/// REQ: DNS-014 (review 01 q1) — the rate limit: one entry, `default`, replacing `[ratelimit]`.
pub(crate) const RATELIMIT: &str = "ratelimit";
/// REQ: OBS-022 (T12.1) — the exclusions: one entry, `default`, replacing `[exclusions]`.
pub(crate) const EXCLUSIONS: &str = "exclusions";
/// REQ: OBS-024 (T13.1) — change simulation's settings: one entry, `default`, replacing
/// `[simulate]`.
pub(crate) const SIMULATE: &str = "simulate";
/// REQ: CLU-013 (T13.2) — staged rollouts' settings: one entry, `default`, replacing
/// `[cluster.rollout]`.
pub(crate) const ROLLOUT: &str = "rollout";
/// REQ: FLT-017 (T15.1) — `[[kubernetes.map]]` rules, by key (`namespace/kind/name`).
pub(crate) const KUBERNETES_MAP: &str = "kubernetes_map";
/// REQ: T8.2, API-002 (ADR-181) — router integrations (they override the files' too).
pub(crate) const ROUTER: &str = "router";

/// An API entry for a kind that can override the files (ADR-069): a definition, or the
/// files' entry of that name left out.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Ovr<T> {
    Set(T),
    Hidden,
}

/// The stored body of a hidden entry.
pub(crate) const HIDDEN: &str = r#"{"hidden":true}"#;

/// The config entries a kind holds, by name.
pub(crate) trait Named {
    fn name(&self) -> &str;
}
impl Named for Upstream {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
impl Named for UpstreamGroup {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
impl Named for FilterList {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
impl Named for GroupConfig {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
impl Named for telltale_config::AlertDestination {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
impl Named for telltale_config::ScheduleConfig {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
impl Named for telltale_config::RouterConfig {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
impl Named for telltale_config::AnomalyMuteConfig {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
impl Named for telltale_config::AlertRule {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

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
    /// REQ: DNS-022 — a stub zone: the servers are the zone's own (authoritative only), asked
    /// iteratively, and the delegations they give are followed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) stub: bool,
}

/// Everything stored through the API.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Entries {
    pub(crate) clients: Vec<ClientConfig>,
    pub(crate) records: Vec<(String, Vec<RecordValue>)>,
    pub(crate) forwards: Vec<(String, Forward)>,
    pub(crate) rules: Vec<telltale_config::RuleConfig>,
    pub(crate) upstreams: Vec<(String, Ovr<Upstream>)>,
    pub(crate) upstream_groups: Vec<(String, Ovr<UpstreamGroup>)>,
    pub(crate) lists: Vec<(String, Ovr<FilterList>)>,
    pub(crate) groups: Vec<(String, Ovr<GroupConfig>)>,
    pub(crate) alert_destinations: Vec<(String, Ovr<telltale_config::AlertDestination>)>,
    pub(crate) alert_rules: Vec<(String, Ovr<telltale_config::AlertRule>)>,
    pub(crate) schedules: Vec<(String, Ovr<telltale_config::ScheduleConfig>)>,
    /// REQ: OBS-038 — anomaly mutes.
    pub(crate) anomaly_mutes: Vec<(String, Ovr<telltale_config::AnomalyMuteConfig>)>,
    /// The `[ratelimit]` the API or UI set, replacing the files' section as a whole.
    pub(crate) ratelimit: Option<telltale_config::RateLimitConfig>,
    /// The `[exclusions]` the API or UI set, likewise.
    pub(crate) exclusions: Option<telltale_config::ExclusionsConfig>,
    /// REQ: OBS-024 — the `[simulate]` the API or UI set, likewise.
    pub(crate) simulate: Option<telltale_config::SimulateConfig>,
    /// REQ: CLU-013 — the `[cluster.rollout]` the API or UI set, likewise.
    pub(crate) rollout: Option<telltale_config::RolloutConfig>,
    /// REQ: FLT-017 — `[[kubernetes.map]]` rules by key; they come before the files' rules.
    pub(crate) kubernetes_map: Vec<(String, Ovr<telltale_config::KubernetesMapRule>)>,
    /// REQ: T8.2 (ADR-181) — router integrations.
    pub(crate) routers: Vec<(String, Ovr<telltale_config::RouterConfig>)>,
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

/// Entries of a kind that can override the files: a definition, or `{"hidden":true}`.
fn decode_ovr<T: for<'de> Deserialize<'de>>(state: &State, kind: &str) -> Vec<(String, Ovr<T>)> {
    decode::<serde_json::Value>(state, kind)
        .into_iter()
        .filter_map(|(name, v)| {
            if v.get("hidden").and_then(serde_json::Value::as_bool) == Some(true) {
                return Some((name, Ovr::Hidden));
            }
            match serde_json::from_value::<T>(v) {
                Ok(t) => Some((name, Ovr::Set(t))),
                Err(e) => {
                    warn!(kind, %name, "skipping a stored entry: {e}");
                    None
                }
            }
        })
        .collect()
}

/// Applies `over` to `items` by name: an override replaces the files' entry, a new name is
/// added, a hidden name is removed.
pub(crate) fn apply_ovr<T: Named + Clone>(items: &mut Vec<T>, over: &[(String, Ovr<T>)]) {
    for (name, o) in over {
        items.retain(|i| i.name() != name);
        if let Ovr::Set(t) = o {
            items.push(t.clone());
        }
    }
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
        upstreams: decode_ovr(state, UPSTREAM),
        upstream_groups: decode_ovr(state, UPSTREAM_GROUP),
        lists: decode_ovr(state, LIST),
        groups: decode_ovr(state, GROUP),
        alert_destinations: decode_ovr(state, ALERT_DESTINATION),
        alert_rules: decode_ovr(state, ALERT_RULE),
        schedules: decode_ovr(state, SCHEDULE),
        anomaly_mutes: decode_ovr(state, ANOMALY_MUTE),
        ratelimit: decode::<telltale_config::RateLimitConfig>(state, RATELIMIT)
            .into_iter()
            .next()
            .map(|(_, r)| r),
        exclusions: decode::<telltale_config::ExclusionsConfig>(state, EXCLUSIONS)
            .into_iter()
            .next()
            .map(|(_, x)| x),
        simulate: decode::<telltale_config::SimulateConfig>(state, SIMULATE)
            .into_iter()
            .next()
            .map(|(_, x)| x),
        rollout: decode::<telltale_config::RolloutConfig>(state, ROLLOUT)
            .into_iter()
            .next()
            .map(|(_, x)| x),
        kubernetes_map: decode_ovr(state, KUBERNETES_MAP),
        routers: decode_ovr(state, ROUTER),
    }
}

/// REQ: FLT-017 — the API's `[[kubernetes.map]]` rules: each replaces (or hides) the files'
/// rule with the same key, and comes first, so a rule made for one workload wins over a
/// namespace glob in the files.
fn apply_kubernetes_map(
    cfg: &mut Config,
    over: &[(String, Ovr<telltale_config::KubernetesMapRule>)],
) {
    let mut front = Vec::new();
    for (key, o) in over {
        cfg.kubernetes.map.retain(|r| r.key() != *key);
        if let Ovr::Set(r) = o {
            front.push(r.clone());
        }
    }
    front.append(&mut cfg.kubernetes.map);
    cfg.kubernetes.map = front;
}

/// The upstream group a forwarded domain uses.
pub(crate) fn forward_group(domain: &str) -> String {
    format!("forward:{domain}")
}

/// REQ: DNS-022 — the one upstream a stub zone's servers become.
pub(crate) fn stub_upstream_name(group: &str) -> String {
    format!("{group}#stub")
}

/// REQ: DNS-022 — a stub zone's server: an IP address (port 53), written bare or as
/// `udp://` plus the address, as the forwarding form writes servers.
pub(crate) fn stub_addr(s: &str) -> Option<std::net::IpAddr> {
    s.trim()
        .strip_prefix("udp://")
        .unwrap_or(s.trim())
        .parse()
        .ok()
}

/// REQ: DNS-022 — a stub zone as an upstream: `recursive://`, starting at `servers` for
/// `domain` instead of the root.
fn stub_upstream(domain: &str, group: &str, servers: &[String]) -> Result<Upstream, String> {
    let mut addrs = Vec::new();
    for s in servers {
        addrs.push(stub_addr(s).ok_or_else(|| {
            format!("invalid server `{s}` (a stub zone's servers are IP addresses)")
        })?);
    }
    let mut u = new_upstream(safe(&stub_upstream_name(group))?, safe("recursive://")?)
        .ok_or("invalid upstream")?;
    u.recursive.stub_zone = Some(safe(domain)?);
    u.recursive.stub_servers = addrs;
    Ok(u)
}

/// A server as an upstream URL: a bare address means plain DNS (`udp://`).
pub(crate) fn server_url(s: &str) -> String {
    if s.contains("://") {
        s.to_owned()
    } else {
        format!("udp://{s}")
    }
}

/// REQ: UPS-011 (ADR-180) — an upstream URL that names a program the server starts (`exec://`)
/// or a local socket it connects to (`unix://`): a plugin upstream.
pub(crate) fn is_plugin_url(url: &str) -> bool {
    url.trim_start()
        .split_once("://")
        .is_some_and(|(s, _)| s.eq_ignore_ascii_case("exec") || s.eq_ignore_ascii_case("unix"))
}

/// REQ: UPS-011, API-002 (ADR-180) — the field that makes an upstream a plugin one: its `url`, or
/// `args` (a program's arguments). Plugin upstreams are defined in the config file, so a write
/// through the API, or a pre-save check, that has one is refused.
pub(crate) fn plugin_field(url: &str, has_args: bool) -> Option<&'static str> {
    if is_plugin_url(url) {
        Some("url")
    } else if has_args {
        Some("args")
    } else {
        None
    }
}

/// REQ: UPS-011 (ADR-180) — something the merge changed in the entries made through the API
/// because some of them name a program or a local socket: such an upstream, or such a server of a
/// forwarded domain, is left out (plugin upstreams are defined in the config file; it was stored
/// by an older version, restored from a backup, or written into `state.db` by hand, and isn't
/// deleted), and what named it is adjusted so the merged configuration stays valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LeftOut {
    /// The entry's name.
    pub(crate) name: String,
    /// What happened to it, as the warning says it.
    pub(crate) what: String,
}

/// How an upstream group is chosen when the merge leaves out the one an entry named.
fn default_route(file: &Config) -> &'static str {
    if file
        .upstream_group
        .iter()
        .any(|g| g.name.as_str() == "default")
    {
        "the `default` upstream group"
    } else {
        "the `default` upstream group, if there is one"
    }
}

/// REQ: UPS-011, API-002 (ADR-180) — the names of what the merge leaves out of the entries made
/// through the API because they name a program or a local socket: upstreams (a forward's server is
/// the upstream `forward:<domain>#<n>`) and upstream groups. A write that names one is refused.
#[derive(Debug, Default)]
pub(crate) struct LeftOutNames {
    pub(crate) upstreams: Vec<String>,
    pub(crate) groups: Vec<String>,
}

/// REQ: UPS-011, API-002 (ADR-180) — what [`merge`] leaves out of `e`, by name.
pub(crate) fn left_out_names(file: &Config, e: &Entries) -> LeftOutNames {
    without_plugins(file, e)
        .map(|k| k.names)
        .unwrap_or_default()
}

/// What [`without_plugins`] keeps, what it changed, and the names it left out.
struct Kept {
    entries: Entries,
    notes: Vec<LeftOut>,
    names: LeftOutNames,
}

/// The upstream a forwarded domain's server becomes: numbered by its place among the domain's
/// servers, so a server keeps its name when another one is left out.
fn forward_server_name(group: &str, i: usize) -> String {
    format!("{group}#{}", i + 1)
}

/// `e` without what names a program or a local socket, and what that changed (`None`: nothing
/// does). Only these references to an upstream or an upstream group exist (`validate.rs`): a
/// group's members, a client group's `upstreams`, and a route's group, and routes made through the
/// API are the forwards' own. So, made through the API:
/// - a plugin upstream is left out, and taken out of the upstream groups that name it, unless the
///   files define an upstream of that name (theirs is then the one in effect);
/// - a forwarded domain keeps its other servers, under the names they had; the upstreams its
///   plugin servers were are taken out of the upstream groups that name them; with none left it is
///   left out, and its names go where they would without it;
/// - an upstream group left with no member is left out (an override of the files' group gives
///   theirs back); a `parallel` one left with fewer members than it races races them all, or with
///   one uses `failover`;
/// - a client group that sent its queries to a group left out uses the files' choice when it
///   overrides a files' group, else the default.
///
/// The merged configuration then validates whenever it did with the plugin entries in it.
fn without_plugins(file: &Config, e: &Entries) -> Option<Kept> {
    let plugin_server = |s: &String| is_plugin_url(&server_url(s));
    let any = e
        .upstreams
        .iter()
        .any(|(_, o)| matches!(o, Ovr::Set(u) if is_plugin_url(u.url.as_str())))
        || e.forwards
            .iter()
            .any(|(_, f)| f.servers.iter().any(plugin_server));
    if !any {
        return None;
    }
    let mut e = e.clone();
    let mut notes = Vec::new();
    let mut gone = Vec::new();
    e.upstreams.retain(|(n, o)| {
        let left = matches!(o, Ovr::Set(u) if is_plugin_url(u.url.as_str()));
        if left {
            notes.push(LeftOut {
                name: n.clone(),
                what: format!(
                    "upstream `{n}` made through the API isn't used: it names a program or a local socket (`exec://`, `unix://`), and plugin upstreams are defined in the config file; define it there, or remove this one (DELETE /api/v1/upstreams/{n})"
                ),
            });
            if !file.upstream.iter().any(|u| u.name.as_str() == n) {
                gone.push(n.clone());
            }
        }
        !left
    });
    let mut removed = forwards_without_plugins(file, &mut e, &mut gone, &mut notes);
    upstream_groups_without(file, &mut e, &gone, &mut removed, &mut notes);
    for (n, o) in &mut e.groups {
        let Ovr::Set(g) = o else { continue };
        let Some(u) = g
            .upstreams
            .clone()
            .filter(|u| removed.contains(&u.to_string()))
        else {
            continue;
        };
        g.upstreams = file
            .group
            .iter()
            .find(|f| f.name.as_str() == n)
            .and_then(|f| f.upstreams.clone());
        let now = g.upstreams.as_ref().map_or_else(
            || default_route(file).to_owned(),
            |f| format!("the config files' choice, `{f}`"),
        );
        notes.push(LeftOut {
            name: n.clone(),
            what: format!(
                "client group `{n}` made through the API sent its queries to upstream group `{u}`, which isn't used (it named only upstreams that are left out); it uses {now} instead"
            ),
        });
    }
    Some(Kept {
        entries: e,
        notes,
        names: LeftOutNames {
            upstreams: gone,
            groups: removed,
        },
    })
}

/// The forwards' plugin servers left out: the upstreams they were go to `gone` (unless the files
/// define one of that name); the other servers keep their names ([`forward_upstreams`] skips
/// plugin servers). Returns the upstream groups of forwards left out whole.
fn forwards_without_plugins(
    file: &Config,
    e: &mut Entries,
    gone: &mut Vec<String>,
    notes: &mut Vec<LeftOut>,
) -> Vec<String> {
    let mut removed = Vec::new();
    e.forwards.retain_mut(|(d, f)| {
        let group = forward_group(d);
        let plugins: Vec<usize> = f
            .servers
            .iter()
            .enumerate()
            .filter(|(_, s)| is_plugin_url(&server_url(s)))
            .map(|(i, _)| i)
            .collect();
        let left = plugins.len();
        if left == 0 {
            return true;
        }
        let kept = f.servers.len() - left;
        // A stub zone's servers are one upstream together: it goes when none is left.
        let names = if f.stub && kept == 0 {
            vec![stub_upstream_name(&group)]
        } else if f.stub {
            f.servers.retain(|s| !is_plugin_url(&server_url(s)));
            Vec::new()
        } else {
            plugins
                .iter()
                .map(|&i| forward_server_name(&group, i))
                .collect()
        };
        gone.extend(
            names
                .into_iter()
                .filter(|n| !file.upstream.iter().any(|u| u.name.as_str() == n)),
        );
        if kept == 0 {
            notes.push(LeftOut {
                name: d.clone(),
                what: format!(
                    "forwarded domain `{d}` made through the API isn't used: its servers name a program or a local socket (`exec://`, `unix://`), and plugin upstreams are defined in the config file; names under it go to {} or a route that matches them; define it in the config file, or remove this one (DELETE /api/v1/forwards/{d})",
                    default_route(file)
                ),
            });
            removed.push(group);
            false
        } else {
            notes.push(LeftOut {
                name: d.clone(),
                what: format!(
                    "forwarded domain `{d}` made through the API: {left} of its servers name a program or a local socket and aren't used (plugin upstreams are defined in the config file); it keeps the other {kept}"
                ),
            });
            true
        }
    });
    removed
}

/// The upstream groups made through the API without the upstreams in `gone`; the ones left empty
/// are left out (their names go to `removed` unless the files define a group of that name).
fn upstream_groups_without(
    file: &Config,
    e: &mut Entries,
    gone: &[String],
    removed: &mut Vec<String>,
    notes: &mut Vec<LeftOut>,
) {
    e.upstream_groups.retain_mut(|(n, o)| {
        let Ovr::Set(g) = o else { return true };
        let had = g.members.len();
        g.members.retain(|m| !gone.iter().any(|x| x == m.as_str()));
        let left = g.members.len();
        if left == had {
            return true;
        }
        if left == 0 {
            let instead = if file.upstream_group.iter().any(|f| f.name.as_str() == n) {
                format!("the config files' `{n}` is the one in effect")
            } else {
                removed.push(n.clone());
                "what sent queries to it uses another group".to_owned()
            };
            notes.push(LeftOut {
                name: n.clone(),
                what: format!(
                    "upstream group `{n}` made through the API isn't used: every member names a program or a local socket and is left out; {instead}"
                ),
            });
            return false;
        }
        if g.strategy == telltale_config::Strategy::Parallel && usize::from(g.parallel_fanout) > left
        {
            let now = if left >= 2 {
                g.parallel_fanout = u8::try_from(left).unwrap_or(u8::MAX);
                format!("asks its {left} members at once")
            } else {
                g.strategy = telltale_config::Strategy::Failover;
                "uses `failover` with its one member".to_owned()
            };
            notes.push(LeftOut {
                name: n.clone(),
                what: format!(
                    "upstream group `{n}` made through the API lost members that are left out (they name a program or a local socket); it now {now}"
                ),
            });
        }
        true
    });
}

/// REQ: API-002, T8.2 (ADR-181) — review round 3 (security S1, correctness R9) and round 4
/// (final review M2): `e` without the routers made through the API that name a key file outside
/// this node's `<data_dir>/secrets/` (by the path as written, so it fails closed) which the
/// files' router of that name doesn't name for that credential at the same endpoint (a router
/// the files don't define counts as not matching), and why (`None`: there is none). Such an entry
/// is an override kept from before the files moved or removed the router, or one restored or
/// edited in `state.db`; a mounted key is used on any node (the use-time rule's folder rule), so
/// it is left out here, on the node that applies the API's entries, and the configuration it
/// publishes never carries it. The files' router, if any, is the one in effect. Routers are named
/// by nothing else in the configuration, so the merge stays valid. A key pasted in the UI (in
/// `<data_dir>/secrets/`) is unaffected: its `.written` record vouches for it.
fn without_unvouched_router_keys(file: &Config, e: &Entries) -> Option<(Entries, Vec<LeftOut>)> {
    let data_dir = file.node.data_dir.as_str();
    let unvouched = |o: &Ovr<telltale_config::RouterConfig>| match o {
        Ovr::Set(r) => crate::router_secrets::unvouched_key_file(&file.router, r, data_dir),
        Ovr::Hidden => None,
    };
    if !e.routers.iter().any(|(_, o)| unvouched(o).is_some()) {
        return None;
    }
    let mut e = e.clone();
    let mut notes = Vec::new();
    e.routers.retain(|(n, o)| {
        let Some(field) = unvouched(o) else {
            return true;
        };
        let instead = if file.router.iter().any(|f| f.name.as_str() == n) {
            "the config files' router of that name is the one in effect"
        } else {
            "the config files don't define it any more, so it isn't read"
        };
        notes.push(LeftOut {
            name: n.clone(),
            what: format!(
                "router `{n}` made through the API isn't used: its `{field}` is a key file outside this node's secrets/ folder that the config files don't give this router at this address (they moved or removed it since, or the entry was restored or edited); {instead}. Edit the router in the UI to save it again for the files' address (or paste its key), or remove this entry (DELETE /api/v1/routers/{n})"
            ),
        });
        false
    });
    Some((e, notes))
}

/// REQ: UPS-011 (ADR-180) — one warning per change the merge makes for plugin entries, when it
/// starts: a configuration that is built again with the same ones logs nothing (per data
/// directory, so each node in a test process keeps its own).
fn warn_left_out(file: &Config, left: &[LeftOut]) {
    static LAST: std::sync::Mutex<std::collections::BTreeMap<String, Vec<LeftOut>>> =
        std::sync::Mutex::new(std::collections::BTreeMap::new());
    let mut last = LAST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let key = file.node.data_dir.to_string();
    let before = last.get(&key).cloned().unwrap_or_default();
    for l in left.iter().filter(|l| !before.contains(l)) {
        warn!("{}", l.what);
    }
    if left.is_empty() {
        last.remove(&key);
    } else {
        last.insert(key, left.to_vec());
    }
}

fn safe(s: &str) -> Result<SafeString, String> {
    SafeString::new(s)
}

/// The one-of sections the API or UI set, each replacing the files' section as a whole.
fn apply_one_of(cfg: &mut Config, e: &Entries) {
    if let Some(r) = &e.ratelimit {
        cfg.ratelimit = r.clone();
    }
    if let Some(x) = &e.exclusions {
        cfg.exclusions = x.clone();
    }
    if let Some(x) = &e.simulate {
        cfg.simulate = x.clone();
    }
    if let Some(x) = &e.rollout {
        cfg.cluster.rollout = x.clone();
    }
}

/// `file` plus the entries (names the files already use are skipped), if the result validates
/// (including record values); otherwise `Err` with the reasons. Entries that name a program or a
/// local socket are left out (REQ: UPS-011, ADR-180; [`without_plugins`]).
pub(crate) fn merge(file: &Config, e: &Entries) -> Result<Config, Vec<String>> {
    let kept = without_plugins(file, e);
    let e = kept.as_ref().map_or(e, |k| &k.entries);
    // REQ: API-002, T8.2 (ADR-181) — and the routers whose mounted key the files don't vouch for.
    let routers = without_unvouched_router_keys(file, e);
    let e = routers.as_ref().map_or(e, |(r, _)| r);
    let mut cfg = file.clone();
    // ADR-069 — upstreams, upstream groups, lists, and groups made through the API override
    // or hide the files' entries of the same name (before forwards add their own).
    apply_ovr(&mut cfg.upstream, &e.upstreams);
    apply_ovr(&mut cfg.upstream_group, &e.upstream_groups);
    apply_ovr(&mut cfg.list, &e.lists);
    apply_ovr(&mut cfg.group, &e.groups);
    apply_ovr(&mut cfg.alerts.destination, &e.alert_destinations);
    apply_ovr(&mut cfg.alerts.rule, &e.alert_rules);
    apply_ovr(&mut cfg.schedule, &e.schedules);
    apply_ovr(&mut cfg.anomaly_mute, &e.anomaly_mutes);
    apply_ovr(&mut cfg.router, &e.routers);
    apply_kubernetes_map(&mut cfg, &e.kubernetes_map);
    apply_one_of(&mut cfg, e);
    for c in added_clients(file, e) {
        cfg.client.push(c.clone());
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
        let members = forward_upstreams(&mut cfg, domain, &group, f, &mut errs);
        match (safe(&group), safe(domain)) {
            (Ok(g), Ok(d)) => {
                cfg.upstream_group.push(UpstreamGroup {
                    name: g.clone(),
                    members,
                    strategy: telltale_config::Strategy::Failover,
                    parallel_fanout: 2,
                    node_only: false,
                });
                cfg.route.push(Route {
                    match_suffix: vec![d],
                    match_group: Vec::new(),
                    match_qtype: Vec::new(),
                    upstream_group: g,
                    dnssec_nta: true,
                    node_only: false,
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

/// The devices made through the API that [`merge`] adds after `file`'s own, in the store's order:
/// each one whose name no device before it has (a device of the files with that name wins).
fn added_clients<'e>(file: &Config, e: &'e Entries) -> Vec<&'e ClientConfig> {
    let mut taken: Vec<&str> = file.client.iter().map(|c| c.name.as_str()).collect();
    let mut added = Vec::new();
    for c in &e.clients {
        if !taken.contains(&c.name.as_str()) {
            taken.push(c.name.as_str());
            added.push(c);
        }
    }
    added
}

/// REQ: API-010, CLU-003 (ADR-191; GitHub issue #113) — the devices made through the API that
/// `errs`, the reasons a [`merge`] of `e` onto `file` gave, name by their place in its list of
/// devices (`client[3]`): the stored rows to change or delete, which the API's lists don't show
/// while they aren't in effect. The merge lists `file`'s devices first, so a place after them is a
/// stored device ([`added_clients`]). In the order the reasons name them, each once.
pub(crate) fn stored_devices_named(file: &Config, e: &Entries, errs: &[String]) -> Vec<String> {
    let added = added_clients(file, e);
    let mut named: Vec<String> = Vec::new();
    for at in errs.iter().flat_map(|r| client_places(r)) {
        if let Some(c) = at.checked_sub(file.client.len()).and_then(|i| added.get(i))
            && !named.iter().any(|n| n == c.name.as_str())
        {
            named.push(c.name.to_string());
        }
    }
    named
}

/// The places `client[N]` a reason names (as `validate_config` writes them).
fn client_places(reason: &str) -> Vec<usize> {
    const AT: &str = "client[";
    reason
        .match_indices(AT)
        .filter(|(i, _)| {
            !reason[..*i]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        })
        .filter_map(|(i, _)| {
            let tail = &reason[i + AT.len()..];
            let digits = tail.find(|c: char| !c.is_ascii_digit())?;
            if digits == 0 || !tail[digits..].starts_with(']') {
                return None;
            }
            tail[..digits].parse().ok()
        })
        .collect()
}

/// `` `a`, `b` ``, for a message.
pub(crate) fn quoted(names: &[String]) -> String {
    names
        .iter()
        .map(|n| format!("`{n}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Adds the upstreams a forwarded domain becomes to `cfg` and returns their names: one per
/// server, or (REQ: DNS-022) one `recursive://` upstream for a stub zone.
fn forward_upstreams(
    cfg: &mut Config,
    domain: &str,
    group: &str,
    f: &Forward,
    errs: &mut Vec<String>,
) -> Vec<SafeString> {
    let mut members = Vec::new();
    if f.stub {
        match stub_upstream(domain, group, &f.servers) {
            Ok(u) => {
                members.push(u.name.clone());
                cfg.upstream.push(u);
            }
            Err(e) => errs.push(format!("forward `{domain}`: {e}")),
        }
        return members;
    }
    for (i, s) in f.servers.iter().enumerate() {
        // REQ: UPS-011 (ADR-180) — a server that names a program or a local socket is left out
        // ([`without_plugins`]); the others keep the names their places give them.
        if is_plugin_url(&server_url(s)) {
            continue;
        }
        let name = forward_server_name(group, i);
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
    members
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
    let stored = entries(&state);
    // REQ: UPS-011 (ADR-180), API-002 (ADR-181) — what the merge leaves out, logged once.
    let mut left = without_plugins(file, &stored)
        .map(|k| k.notes)
        .unwrap_or_default();
    left.extend(
        without_unvouched_router_keys(file, &stored)
            .map(|(_, n)| n)
            .unwrap_or_default(),
    );
    warn_left_out(file, &left);
    match merge(file, &stored) {
        Ok(c) => c,
        Err(errs) => {
            for e in &errs {
                error!("config made in the UI/API: {e}");
            }
            error!("{}", fallback_line(file, &stored, &errs));
            file.clone()
        }
    }
}

/// REQ: API-010, CLU-003 (ADR-191; GitHub issue #113) — the line [`effective`] logs when the
/// merge of `e` onto `file` fails with `errs` and the node uses `file` alone. It names the stored
/// devices the reasons give only by their place in a list, by their names, with the request that
/// removes one: the way back names itself.
pub(crate) fn fallback_line(file: &Config, e: &Entries, errs: &[String]) -> String {
    const LINE: &str =
        "ignoring config made in the UI until this is fixed; using the config files only";
    let named = stored_devices_named(file, e, errs);
    if named.is_empty() {
        return LINE.to_owned();
    }
    format!(
        "{LINE} (the devices made in the UI that the reasons name: {}; DELETE /api/v1/clients/{{name}} removes one)",
        quoted(&named)
    )
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
            kind: None,
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

    // REQ: FLT-017 — map rules made through the API come before the files' (first match
    // wins), replace a file rule with the same key, or hide it.
    #[test]
    fn flt_017_api_map_rules_come_first() {
        let file: Config = toml::from_str(
            r#"
            [[group]]
            name = "iot"
            [[group]]
            name = "media"
            [[kubernetes.map]]
            namespace = "media*"
            group = "iot"
            [[kubernetes.map]]
            namespace = "tools"
            group = "iot"
            "#,
        )
        .unwrap();
        let rule =
            |ns: &str, kind: &str, name: &str, group: &str| telltale_config::KubernetesMapRule {
                namespace: SafeString::new(ns).unwrap(),
                kind: SafeString::new(kind).unwrap(),
                name: SafeString::new(name).unwrap(),
                group: SafeString::new(group).unwrap(),
            };
        let e = Entries {
            kubernetes_map: vec![
                (
                    "media/deploy/jellyfin".into(),
                    Ovr::Set(rule("media", "deploy", "jellyfin", "media")),
                ),
                ("tools/*/*".into(), Ovr::Hidden),
            ],
            ..Entries::default()
        };
        let c = merge(&file, &e).unwrap();
        let keys: Vec<String> = c
            .kubernetes
            .map
            .iter()
            .map(telltale_config::KubernetesMapRule::key)
            .collect();
        assert_eq!(keys, ["media/deploy/jellyfin", "media*/*/*"]);
        // A rule naming a group that doesn't exist is refused with the reason.
        let bad = Entries {
            kubernetes_map: vec![("x/*/*".into(), Ovr::Set(rule("x", "", "", "nope")))],
            ..Entries::default()
        };
        assert!(
            merge(&file, &bad)
                .unwrap_err()
                .iter()
                .any(|e| e.contains("nope"))
        );
    }

    /// REQ: UPS-011 (ADR-180) — a plugin upstream is known by its URL's scheme, whatever its
    /// case or leading blanks; `args` count only beside another URL.
    #[test]
    fn ups_011_plugin_upstreams_are_known_by_their_scheme() {
        for url in [
            "exec:///usr/local/bin/x",
            "EXEC:///x",
            " unix:///run/x.sock",
            "Unix:///x",
        ] {
            assert!(is_plugin_url(url), "{url}");
            assert_eq!(plugin_field(url, false), Some("url"));
        }
        for url in [
            "udp://192.0.2.1",
            "tls://dns.example",
            "https://dns.example/dns-query",
            "recursive://",
            "sdns://AgcAAAAAAAAA",
            "executable://x",
            "192.0.2.1",
        ] {
            assert!(!is_plugin_url(url), "{url}");
            assert_eq!(plugin_field(url, false), None, "{url}");
        }
        assert_eq!(plugin_field("udp://192.0.2.1", true), Some("args"));
        assert!(is_plugin_url(&server_url("exec:///x")));
        assert!(!is_plugin_url(&server_url("192.0.2.1")));
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
                    stub: false,
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
                    stub: false,
                },
            )],
            ..Entries::default()
        };
        assert!(merge(&base(), &bad_server).is_err());
    }

    /// REQ: DNS-022 — a stub forward becomes one `recursive://` upstream that starts at the
    /// zone's servers; a server that isn't an address is refused.
    #[test]
    fn dns_022_stub_forward_merges() {
        let e = Entries {
            forwards: vec![(
                "corp.example".into(),
                Forward {
                    servers: vec!["10.0.0.53".into(), "udp://10.0.0.54".into()],
                    stub: true,
                },
            )],
            ..Entries::default()
        };
        let cfg = merge(&base(), &e).unwrap();
        let u = cfg.upstream.last().unwrap();
        assert_eq!(u.name.as_str(), "forward:corp.example#stub");
        assert_eq!(u.url.as_str(), "recursive://");
        assert_eq!(u.recursive.stub_zone.as_deref(), Some("corp.example"));
        assert_eq!(
            u.recursive.stub_servers,
            [
                "10.0.0.53".parse::<std::net::IpAddr>().unwrap(),
                "10.0.0.54".parse().unwrap()
            ]
        );
        let g = cfg.upstream_group.last().unwrap();
        assert_eq!(g.members, std::slice::from_ref(&u.name));
        assert_eq!(cfg.route.last().unwrap().upstream_group, g.name);
        let bad = Entries {
            forwards: vec![(
                "corp.example".into(),
                Forward {
                    servers: vec!["tls://10.0.0.53".into()],
                    stub: true,
                },
            )],
            ..Entries::default()
        };
        let errs = merge(&base(), &bad).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("IP addresses")), "{errs:?}");
    }

    /// REQ: API-002 (T7.5, ADR-069) — API upstreams, groups, and lists add, override, or hide
    /// the files' entries by name, and the merged configuration must still be valid.
    #[test]
    fn api_002_overrides_add_replace_and_hide_file_entries() {
        let file: Config = toml::from_str(
            r#"
            [[upstream]]
            name = "quad9"
            url = "udp://9.9.9.9"
            [[upstream]]
            name = "cloudflare"
            url = "udp://1.1.1.1"
            [[upstream_group]]
            name = "default"
            members = ["quad9"]
            [[list]]
            name = "ads"
            rules = ["||ads.example^"]
            "#,
        )
        .unwrap();
        let up = |name: &str, url: &str| {
            new_upstream(
                SafeString::new(name).unwrap(),
                SafeString::new(url).unwrap(),
            )
            .unwrap()
        };
        let mut group: UpstreamGroup = file.upstream_group[0].clone();
        group.members = vec![SafeString::from("cloudflare"), SafeString::from("mullvad")];
        let e = Entries {
            upstreams: vec![
                ("quad9".into(), Ovr::Set(up("quad9", "tls://9.9.9.9"))),
                (
                    "mullvad".into(),
                    Ovr::Set(up("mullvad", "udp://194.242.2.2")),
                ),
            ],
            upstream_groups: vec![("default".into(), Ovr::Set(group))],
            lists: vec![("ads".into(), Ovr::Hidden)],
            ..Entries::default()
        };
        let c = merge(&file, &e).unwrap();
        let names: Vec<&str> = c.upstream.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, ["cloudflare", "quad9", "mullvad"]);
        assert_eq!(
            c.upstream
                .iter()
                .find(|u| u.name.as_str() == "quad9")
                .unwrap()
                .url
                .as_str(),
            "tls://9.9.9.9"
        );
        assert_eq!(c.upstream_group[0].members.len(), 2);
        assert!(c.list.is_empty(), "the files' list is hidden");
        // Hiding an upstream the default group still uses is refused (the merge doesn't validate).
        let broken = Entries {
            upstreams: vec![("quad9".into(), Ovr::Hidden)],
            ..Entries::default()
        };
        assert!(merge(&file, &broken).is_err());
    }
}
