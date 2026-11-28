//! The `telltale_api::Backend` implementation: the API's view of this server (REQ: API-001,
//! API-002). Reads only shared state that already exists for `/metrics` and the pipeline;
//! nothing here sits on the query path.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use serde::Serialize;
use telltale_api::model::{
    ClientChange, ClientInfo, ConfigChange, DeviceRecognition, ExplainBlock, ExplainClient,
    ExplainFilter, ExplainLine, ExplainParams, ExplainRoute, ExplainRule, Explanation,
    FailureKinds, ForwardInfo, GroupInfo, Hour, LatencyBy, LatencyRow, ListInfo, LocalName,
    NameMatch, QueryPage, QueryParams, QueryRow, RecordInput, ScanStats, Step, SystemInfo,
    TimeBucket, TopItem, TopKind, UpstreamInfo,
};
use telltale_api::problem::{Code, Problem};
use telltale_api::time::format_us;
use telltale_api::{Backend, BoxFuture, ClientWrite, ManagedKind, ManagedWrite};
use telltale_store::qlog;
use telltale_store::rollup::{Level, merge};
use telltale_store::state::ManagedError;
use telltale_telemetry::agg::{Counts, HourSel, LatencyKey, Percentiles, Resolution};
use telltale_telemetry::{N_RCODE, Path as AnswerPath, Proto, QTYPES, Status};
use telltale_upstream::health::Breaker;

use crate::http::Sources;

/// REQ: FLT-017, API-010 — the name of the device at `ip` (v4-mapped) when a query-log row from
/// `ts_s` was made: a reused pod address is named by the workload that held it then. Every
/// other address (and a pod address the history doesn't cover) is named as [`device_name`].
pub(crate) fn device_name_at(src: &Sources, ip: [u8; 16], ts_s: u64) -> Option<String> {
    let t = src.pipeline.workloads.load();
    if t.has_any() {
        let v6 = std::net::Ipv6Addr::from(ip);
        let addr = v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4);
        if let Some(name) = t.name_at(addr, ts_s) {
            return Some(name.to_owned());
        }
    }
    drop(t);
    device_name(src, ip)
}

/// REQ: FLT-017 — a workload that has no pods now, from its text form: no group, no pods.
pub(crate) fn past_workload(
    text: &str,
    key: &[u8; 16],
) -> Option<telltale_api::model::WorkloadInfo> {
    let mut parts = text.splitn(3, '/');
    let (ns, kind, name) = (parts.next()?, parts.next()?, parts.next()?);
    Some(telltale_api::model::WorkloadInfo {
        name: text.to_owned(),
        namespace: ns.to_owned(),
        kind: kind.to_owned(),
        workload_name: name.to_owned(),
        key: std::net::Ipv6Addr::from(*key).to_string(),
        group: None,
        group_from: "none".to_owned(),
        ..telltale_api::model::WorkloadInfo::default()
    })
}

/// REQ: FLT-017 — the stretches a workload (its text form or analytics key) held each pod
/// address, v4-mapped; `None` when `client` isn't a workload.
pub(crate) fn workload_spans(src: &Sources, client: &str) -> Option<Vec<([u8; 16], u64, u64)>> {
    let t = src.pipeline.workloads.load();
    let text = crate::kubernetes::workload_ref(client, &t)?;
    Some(
        t.spans_of(&text)
            .into_iter()
            .map(|(ip, f, to)| (mapped(ip), f, to))
            .collect(),
    )
}

/// The current name of the device at `ip` (v4-mapped), by today's client table.
/// REQ: CLU-014 — `node` names this node (`local`, its ID, or its label), else `node_unknown`.
fn local_node(src: &Sources, node: &str) -> Result<(), Problem> {
    if crate::maintenance::is_local(src, node) {
        return Ok(());
    }
    Err(Problem::new(
        telltale_api::problem::Code::NodeUnknown,
        format!("no node `{node}`: this node isn't in a cluster"),
    )
    .hint("Use `local` for this node."))
}

pub(crate) fn device_name(src: &Sources, ip: [u8; 16]) -> Option<String> {
    // REQ: FLT-017 — a workload's analytics key, or a pod address, is named by the workload.
    if telltale_telemetry::workload::is_key(&ip) {
        return src
            .pipeline
            .workloads
            .load()
            .key_name(&ip)
            .map(str::to_owned);
    }
    let v6 = std::net::Ipv6Addr::from(ip);
    let ip = v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4);
    let state = src.pipeline.current();
    let clients = &state.policy.clients;
    let id = clients.identify(
        ip,
        None,
        None,
        &src.pipeline.neighbors,
        &src.pipeline.workloads,
    );
    if id.source == telltale_policy::IdSource::Workload {
        return src
            .pipeline
            .workloads
            .load()
            .get(ip)
            .map(|h| h.workload.text.to_string());
    }
    clients.client(id).map(|c| c.name.to_string()).or_else(|| {
        // REQ: T8.2 — an unnamed device is called by the name its router's DHCP knows.
        let IpAddr::V4(v4) = ip else { return None };
        src.pipeline
            .router_leases
            .load()
            .get(&v4)
            .and_then(|l| l.hostname.clone())
            // REQ: T8.3 — then what the device announces over mDNS.
            .or_else(|| {
                src.pipeline
                    .mdns_names
                    .load()
                    .get(&v4)
                    .and_then(|l| l.hostname.clone())
            })
            // REQ: CLU-002 (ADR-125) — then what the other nodes' routers and mDNS know.
            .or_else(|| {
                let peers = src.pipeline.peer_names.load();
                [&peers.routers, &peers.mdns]
                    .into_iter()
                    .find_map(|t| t.get(&v4).and_then(|l| l.hostname.clone()))
            })
    })
}

/// REQ: FLT-006, API-010 (ADR-183) — how the address `ip` is recognized on this node now, and the
/// MAC a device there could be named by. The device is a configured `[[client]]` only, never a
/// Kubernetes workload's text. The MAC is the kernel's entry for the address, else (while
/// `router_macs` is on) what [`crate::devices::router_bindings`], the function the MAC table is
/// built with, says: this node's router's sure binding, else a member's; a MAC at two or more
/// addresses is given with `mac_shared`, and an address this node withholds has none. No kernel
/// read happens here: the table is the task's.
pub(crate) fn recognize(src: &Sources, ip: IpAddr) -> DeviceRecognition {
    let ip = ip.to_canonical();
    let state = src.pipeline.current();
    let clients = &state.policy.clients;
    let id = clients.identify(
        ip,
        None,
        None,
        &src.pipeline.neighbors,
        &src.pipeline.workloads,
    );
    let mut r = DeviceRecognition {
        device: clients.client(id).map(|c| c.name.to_string()),
        identified_by: crate::explain::source_name(id.source).to_owned(),
        ..DeviceRecognition::default()
    };
    // The kernel's entry first, as in the table; else, while `router_macs` is on, the routers'. A
    // kernel MAC at two or more addresses (a MAC-translating extender) is shared: the kernel table
    // has no such rule for identification, and the dialog must not offer it as one device's.
    let table = src.pipeline.neighbors.table();
    let (mac, from, shared) = match table.get(ip) {
        Some(e) if e.from == telltale_policy::MacFrom::Kernel => (
            Some(e.mac),
            "neighbor",
            table.kernel_addresses_of(e.mac) >= 2,
        ),
        _ => match router_mac_of(src, &state.policy.clients, ip) {
            Some((mac, from, shared)) => (Some(mac), from, shared),
            None => (None, "", false),
        },
    };
    if let Some(mac) = mac {
        r.mac = Some(crate::explain::mac_text(mac));
        r.mac_from = Some(from.to_owned());
        r.mac_shared = shared;
        r.mac_randomized = mac[0] & 0x02 != 0;
    }
    r
}

/// REQ: FLT-006 (ADR-183) — what this node's routers, then other full members', say about `ip`, as
/// the MAC table is built from it (`devices::router_bindings`), whether or not a device is named by
/// its MAC yet: the MAC, whose router it is (`router`, `peer`), and whether it is shared (a MAC at
/// two or more addresses: given, because the dialog says why it isn't the default). An address
/// this node withholds (an `unsure` lease, a MAC that can't identify, a member's tombstone) and
/// every address with `router_macs` off or an IPv6 one have none.
fn router_mac_of(
    src: &Sources,
    clients: &telltale_policy::ClientTable,
    ip: IpAddr,
) -> Option<([u8; 6], &'static str, bool)> {
    let IpAddr::V4(v4) = ip else { return None };
    if !clients.router_macs() {
        return None;
    }
    let own = src.pipeline.router_leases.load();
    let peers = src.pipeline.peer_router_macs.load();
    let b = crate::devices::router_bindings(&own, &peers);
    if let Some(mac) = b.own.get(&v4) {
        return Some((*mac, "router", false));
    }
    if let Some(mac) = b.peer.get(&v4) {
        return Some((*mac, "peer", false));
    }
    let mac = *b.shared.get(&v4)?;
    // Whose router says it: this node's own lease for the address, if it is a sure one with this MAC.
    let own_says = own
        .get(&v4)
        .and_then(crate::devices::eligible)
        .is_some_and(|m| m == mac);
    Some((mac, if own_says { "router" } else { "peer" }, true))
}

/// The API backend over the server's shared state.
#[derive(Debug)]
pub(crate) struct ApiBackend {
    pub(crate) src: Arc<Sources>,
}

/// A serde enum's wire name (`BlockMode::NullIp` → `null_ip`), so API strings never drift
/// from config and explain output.
fn label<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_owned))
        .unwrap_or_default()
}

const RCODES: [&str; 16] = [
    "NOERROR",
    "FORMERR",
    "SERVFAIL",
    "NXDOMAIN",
    "NOTIMP",
    "REFUSED",
    "YXDOMAIN",
    "YXRRSET",
    "NXRRSET",
    "NOTAUTH",
    "NOTZONE",
    "DSOTYPENI",
    "RCODE12",
    "RCODE13",
    "RCODE14",
    "RCODE15",
];

pub(crate) fn rcode_name(rc: u8) -> String {
    RCODES
        .get(usize::from(rc))
        .map_or_else(|| format!("RCODE{rc}"), |s| (*s).to_owned())
}

pub(crate) fn rcode_value(name: &str) -> Option<u8> {
    let up = name.trim().to_ascii_uppercase();
    RCODES
        .iter()
        .position(|r| *r == up)
        .and_then(|i| u8::try_from(i).ok())
        .or_else(|| up.strip_prefix("RCODE").and_then(|n| n.parse().ok()))
}

pub(crate) fn qtype_name(t: u16) -> String {
    QTYPES
        .iter()
        .find(|(v, _)| *v == t)
        .map_or_else(|| format!("TYPE{t}"), |(_, n)| (*n).to_owned())
}

#[allow(clippy::cast_precision_loss)]
pub(crate) fn ms(us: u64) -> f64 {
    (us as f64 / 10.0).round() / 100.0
}

fn mapped(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn hour(h: Hour) -> HourSel {
    match h {
        Hour::Current => HourSel::Current,
        Hour::Previous => HourSel::Previous,
    }
}

pub(crate) fn latency_row(key: String, p: Percentiles) -> LatencyRow {
    LatencyRow {
        key,
        count: p.count,
        p50_ms: ms(p.p50),
        p90_ms: ms(p.p90),
        p99_ms: ms(p.p99),
        p999_ms: ms(p.p999),
        max_ms: ms(p.max),
    }
}

/// Comma-separated values, trimmed, empty ones dropped.
fn csv(v: Option<&String>) -> Vec<String> {
    v.map(|s| {
        s.split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(str::to_owned)
            .collect()
    })
    .unwrap_or_default()
}

impl ApiBackend {
    /// The latency keys `by` breaks down into, with their names.
    fn latency_keys(&self, by: LatencyBy) -> Vec<(String, LatencyKey)> {
        match by {
            LatencyBy::Path => AnswerPath::ALL
                .into_iter()
                .flat_map(|p| {
                    Proto::ALL.into_iter().map(move |proto| {
                        (
                            format!("{}/{}", p.label(), proto.label()),
                            LatencyKey::Total(p, proto),
                        )
                    })
                })
                .collect(),
            LatencyBy::Qtype => (0..=QTYPES.len())
                .map(|i| {
                    let key = QTYPES.get(i).map_or("other", |(_, n)| n);
                    (key.to_owned(), LatencyKey::Qtype(i))
                })
                .collect(),
            LatencyBy::Stage => vec![("upstream".to_owned(), LatencyKey::StageUpstream)],
            LatencyBy::Upstream => {
                let router = Arc::clone(&self.src.pipeline.current().router);
                router
                    .upstreams()
                    .iter()
                    .map(|u| (u.name.clone(), LatencyKey::Upstream(u.id)))
                    .collect()
            }
        }
    }

    /// Count buckets at `step`: seconds from memory; minutes from the rollup database
    /// overlaid with memory (memory is fresher); hours and days from the rollup database,
    /// or summed from memory minutes when it isn't available.
    fn counts(&self, step: Step, from_s: u64, to_s: u64) -> Vec<(u64, Counts)> {
        let mem = |res| {
            self.src
                .pipeline
                .telemetry
                .aggregates()
                .series(res, from_s, to_s)
        };
        let db = self.src.rollups.as_ref();
        let stored = |level| {
            db.map(|d| {
                d.range(level, from_s, to_s).unwrap_or_else(|e| {
                    tracing::warn!("rollups: {e}");
                    Vec::new()
                })
            })
        };
        match step {
            Step::Second => mem(Resolution::Second),
            Step::Minute => {
                let live = mem(Resolution::Minute);
                let Some(old) = stored(Level::Minute) else {
                    return live;
                };
                let mut by: std::collections::BTreeMap<u64, Counts> = old.into_iter().collect();
                by.extend(live);
                by.into_iter().collect()
            }
            Step::Hour | Step::Day => {
                let level = if step == Step::Hour {
                    Level::Hour
                } else {
                    Level::Day
                };
                stored(level).unwrap_or_else(|| {
                    let width = level.width_s();
                    let mut by = std::collections::BTreeMap::<u64, Counts>::new();
                    for (start, c) in mem(Resolution::Minute) {
                        merge(by.entry(start - start % width).or_default(), &c);
                    }
                    by.into_iter().collect()
                })
            }
        }
    }

    /// REQ: OBS-027 — the window's bad-answer clients and names: stored hours from the rollups,
    /// the current hour (and the previous one until it's stored) from memory, summed per key;
    /// and how many hours that covers. No client list at privacy level 2 and above.
    fn bad_lists(
        &self,
        q: &telltale_api::attribution::PartQuery,
        privacy: u8,
    ) -> (Vec<TopItem>, Vec<TopItem>, u64) {
        use telltale_telemetry::agg::BadTop;
        let (client_list, name_list) = if q.latency {
            (BadTop::SlowClient, BadTop::SlowName)
        } else {
            (BadTop::ServfailClient, BadTop::ServfailName)
        };
        let db = self.src.rollups.as_ref();
        let (current, previous) = {
            let agg = self.src.pipeline.telemetry.aggregates();
            (agg.current_hour_start(), agg.previous_hour_start())
        };
        let prev_live =
            previous.filter(|h| db.is_none_or(|d| !d.has_hour_tops(*h).unwrap_or(false)));
        let in_window = |h: u64| h >= q.from_s - q.from_s % 3600 && h < q.to_s;
        let stored_to = q.to_s.min(prev_live.unwrap_or(current));
        // Space-Saving's lists are kept per hour: read more than asked, so the summed heaviest
        // are among them.
        let n = (q.limit * 2).max(20);
        let mut out = [
            std::collections::BTreeMap::<String, (u64, u64)>::new(),
            std::collections::BTreeMap::new(),
        ];
        let mut hours = 0;
        for (i, which) in [client_list, name_list].into_iter().enumerate() {
            if i == 0 && privacy >= 2 {
                continue;
            }
            if let Some(d) = db {
                match d.top_range(q.from_s, stored_to, which.kind(), n) {
                    Ok((rows, h)) => {
                        hours = hours.max(h);
                        for r in rows {
                            let e = out[i].entry(r.key).or_default();
                            e.0 += r.count;
                            e.1 += r.error;
                        }
                    }
                    Err(e) => tracing::warn!("rollups: {e}"),
                }
            }
            let agg = self.src.pipeline.telemetry.aggregates();
            let mut live = Vec::new();
            if in_window(current) {
                live.push(telltale_telemetry::agg::HourSel::Current);
            }
            if prev_live.is_some_and(in_window) {
                live.push(telltale_telemetry::agg::HourSel::Previous);
            }
            for sel in live {
                for t in agg.bad_top(which, sel, n) {
                    let e = out[i].entry(t.key).or_default();
                    e.0 += t.count;
                    e.1 += t.error;
                }
            }
        }
        hours += u64::from(in_window(current)) + u64::from(prev_live.is_some_and(in_window));
        let [clients, names] = out;
        let items = |m: std::collections::BTreeMap<String, (u64, u64)>, named: bool| {
            let mut v: Vec<TopItem> = m
                .into_iter()
                .map(|(key, (count, error_bound))| TopItem {
                    name: if named {
                        key.parse::<IpAddr>()
                            .ok()
                            .and_then(|ip| self.client_name(ip))
                    } else {
                        None
                    },
                    key,
                    count,
                    error_bound,
                    groups: Vec::new(),
                    by_status: None,
                })
                .collect();
            v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
            v.truncate(q.limit);
            v
        };
        (items(clients, true), items(names, false), hours)
    }

    /// List names of the active snapshot, by list ID.
    fn list_names(&self) -> Vec<String> {
        self.src
            .pipeline
            .filter
            .load()
            .as_ref()
            .and_then(|f| f.matcher.snapshot().cloned())
            .map(|s| s.manifest.lists.iter().map(|l| l.name.clone()).collect())
            .unwrap_or_default()
    }
}

/// REQ: FLT-010 (T7.10) — the group's schedules that are on at `now`.
fn schedules_on(cfg: &telltale_config::Config, group: &str, now: i64) -> Vec<String> {
    let Some(g) = cfg.group.iter().find(|x| x.name.as_str() == group) else {
        return Vec::new();
    };
    telltale_config::schedule::compile(cfg)
        .into_iter()
        .filter(|s| g.schedules.iter().any(|n| n.as_str() == s.name) && s.is_on(now))
        .map(|s| s.name)
        .collect()
}

/// REQ: FLT-013 (ADR-067) — a decision's list and kind for query-log rows. A quick rule is
/// named by its note (else its domain) and whom it applies to; one that no longer exists says so.
pub(crate) fn rule_labels(
    rule: Option<telltale_telemetry::event::Rule>,
    lists: &[String],
    quick: &telltale_policy::QuickRules,
    schedules: &[(u16, String)],
) -> (Option<String>, Option<String>) {
    use telltale_telemetry::event::RuleKind;
    let Some(x) = rule else { return (None, None) };
    // REQ: FLT-015 (T7.20) — an answer address refused.
    if x.kind == RuleKind::AnswerIp {
        return (
            Some("answer address (rebinding protection or a blocked range)".to_owned()),
            Some("answer_ip".to_owned()),
        );
    }
    // REQ: FLT-010 (T7.10) — a block-everything schedule.
    if x.kind == RuleKind::Schedule {
        let name = schedules.iter().find(|(r, _)| *r == x.list).map_or_else(
            || "a schedule (since removed)".to_owned(),
            |(_, n)| format!("schedule {n}"),
        );
        return (Some(name), Some("schedule".to_owned()));
    }
    if x.kind == RuleKind::Quick {
        let list = quick.by_ref(x.list).map_or_else(
            || "a quick rule (since removed)".to_owned(),
            |q| {
                let what = q.note.as_deref().unwrap_or(&q.domain);
                if q.targets.is_empty() {
                    format!("quick rule: {what}")
                } else {
                    format!("quick rule: {what} ({})", q.targets.join(", "))
                }
            },
        );
        let kind = if x.allow {
            "quick allow"
        } else {
            "quick block"
        };
        return (Some(list), Some(kind.to_owned()));
    }
    let list = lists
        .get(usize::from(x.list))
        .cloned()
        .unwrap_or_else(|| format!("#{}", x.list));
    let kind = if x.allow { "allow" } else { x.kind.label() };
    (Some(list), Some(kind.to_owned()))
}

/// REQ: OBS-023 (T12.3, ADR-112) — days since an enabled URL list's content last changed, when
/// longer than its limit (the list's `stale_after_days`, else `[filter]`'s; 0 = never). Files
/// and inline rules change when you change them: never stale.
fn stale_days(
    filter: &telltale_config::FilterConfig,
    l: &telltale_config::FilterList,
    last_changed: Option<u64>,
) -> Option<u64> {
    let limit = u64::from(l.stale_after_days.unwrap_or(filter.stale_after_days));
    if !l.enabled || l.url.is_none() || limit == 0 {
        return None;
    }
    let days = crate::pipeline::unix_now().saturating_sub(last_changed?) / 86_400;
    (days >= limit).then_some(days)
}

/// REQ: FLT-017 — most pod addresses one workload's query-log search covers.
const MAX_WORKLOAD_ADDRESSES: usize = 64;

fn qlog_filter(q: &QueryParams, from_us: u64, to_us: u64) -> Result<qlog::Filter, Problem> {
    let name = q
        .name
        .clone()
        .map(|n| match q.name_match.unwrap_or_default() {
            NameMatch::Substring => qlog::NameMatch::Substring(n),
            NameMatch::Exact => qlog::NameMatch::Exact(n),
            NameMatch::Suffix => qlog::NameMatch::Suffix(n),
            NameMatch::Glob => qlog::NameMatch::Glob(n),
            NameMatch::Regex => qlog::NameMatch::Regex(n),
        });
    let client_ip = match &q.client {
        None => None,
        Some(c) => Some(mapped(c.parse::<IpAddr>().map_err(|_| {
            Problem::invalid(format!(
                "`client`: `{c}` is not an IP address or a Kubernetes workload"
            ))
            .hint("Give an address, or a workload as namespace/kind/name (GET /api/v1/kubernetes/workloads).")
        })?)),
    };
    let status = csv(q.status.as_ref())
        .iter()
        .map(|s| {
            Status::ALL
                .into_iter()
                .find(|x| x.label() == s)
                .ok_or_else(|| {
                    let all: Vec<&str> = Status::ALL.iter().map(|x| x.label()).collect();
                    Problem::invalid(format!("`status`: unknown `{s}`"))
                        .hint(format!("One or more of: {}.", all.join(", ")))
                })
        })
        .collect::<Result<_, _>>()?;
    let qtype = csv(q.qtype.as_ref())
        .iter()
        .map(|t| {
            telltale_proto::rtype::from_name(t)
                .ok_or_else(|| Problem::invalid(format!("`qtype`: unknown type `{t}`")))
        })
        .collect::<Result<_, _>>()?;
    let rcode = csv(q.rcode.as_ref())
        .iter()
        .map(|r| {
            rcode_value(r).ok_or_else(|| {
                Problem::invalid(format!("`rcode`: unknown `{r}`"))
                    .hint("Use names such as NOERROR, NXDOMAIN, SERVFAIL, REFUSED.")
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(qlog::Filter {
        from_us,
        to_us,
        name,
        client_ip,
        status,
        qtype,
        rcode,
        upstream: q.upstream,
        min_total_us: q.min_latency_ms.map(|v| v.saturating_mul(1000)),
        not: qlog::Not {
            name: q.name_not.unwrap_or(false),
            client: q.client_not.unwrap_or(false),
            status: q.status_not.unwrap_or(false),
            qtype: q.qtype_not.unwrap_or(false),
            rcode: q.rcode_not.unwrap_or(false),
        },
        ..qlog::Filter::default()
    })
}

impl ApiBackend {
    /// One device's identity (by address, or a named device's name), with the evidence, and, for an
    /// address and when `with_recognition`, how it is recognized here (REQ: FLT-006, API-010,
    /// ADR-183): the entry node's own read has it, what a node answers a peer doesn't.
    fn identity_of(
        &self,
        client: &str,
        with_recognition: bool,
    ) -> Result<telltale_api::model::DeviceIdentity, Problem> {
        // REQ: FLT-017 — a workload's identity is under its analytics key.
        if let Some((_, key)) = self.workload(client) {
            return Ok(self.src.identify.get(&key));
        }
        if let Ok(ip) = client.parse::<IpAddr>() {
            let mut id = self.src.identify.get(client);
            // REQ: FLT-006, API-010 (ADR-183) — how this address is recognized, and the MAC a
            // device here could be named by: not at query-log privacy level 2 and above.
            if with_recognition && self.src.config.load().telemetry.qlog.privacy_level < 2 {
                id.recognition = Some(recognize(&self.src, ip));
            }
            return Ok(id);
        }
        let cfg = self.src.config.load();
        let c = cfg
            .client
            .iter()
            .find(|c| c.name.as_str().eq_ignore_ascii_case(client))
            .ok_or_else(|| {
                Problem::not_found(format!(
                    "`{client}` is neither an address nor a named device"
                ))
                .hint("Give a device's IP address, or the name it has on the Clients page.")
            })?;
        let snap = self.src.identify.snapshot();
        let addrs = device_addresses(c);
        let addr = addrs
            .iter()
            .find(|a| snap.by_client.contains_key(*a))
            .or(addrs.first())
            .cloned()
            .unwrap_or_else(|| client.to_owned());
        Ok(self.src.identify.get(&addr))
    }

    /// One query-log directory, as an API page. `node` labels its rows (shipped logs).
    fn search_dir(
        &self,
        dir: &Path,
        filter: &qlog::Filter,
        limit: usize,
        cursor: Option<qlog::Cursor>,
        node: Option<&str>,
    ) -> Result<QueryPage, Problem> {
        let opts = qlog::Options {
            threads: std::thread::available_parallelism().map_or(1, |n| n.get().min(4)),
            on_thread_start: Some(telltale_net::background_thread),
        };
        let page = qlog::search_with(dir, filter, limit, cursor, &opts)
            .map_err(|e| Problem::internal(format!("query log: {e}")))?;
        let lists = self.list_names();
        let policy = &self.src.pipeline.current().policy;
        let groups = policy.clients.groups();
        let quick = Arc::clone(&policy.quick);
        let schedules = self.src.pipeline.schedules.load().names.clone();
        let items = page
            .rows
            .iter()
            .map(|r| {
                let (list, rule) = rule_labels(r.rule, &lists, &quick, &schedules);
                QueryRow {
                    time: format_us(r.ts_us),
                    ts_unix_micros: r.ts_us,
                    client: telltale_telemetry::agg::client_text(r.client_ip),
                    // REQ: API-010 — names are resolved now, from the address, so naming or
                    // renaming a device relabels its history without rewriting the log.
                    client_name: device_name_at(&self.src, r.client_ip, r.ts_us / 1_000_000),
                    node: node.map(str::to_owned),
                    group: groups.get(usize::from(r.group)).map(|g| g.name.to_string()),
                    name: r.name.clone(),
                    qtype: qtype_name(r.qtype),
                    status: r.status.label().to_owned(),
                    rcode: r.rcode.map(rcode_name),
                    proto: r.proto.label().to_owned(),
                    list,
                    rule,
                    total_ms: ms(u64::from(r.t_total_us)),
                    upstream_ms: ms(u64::from(r.t_upstream_us)),
                    response_bytes: r.resp_size,
                    answers: r.answers,
                }
            })
            .collect();
        Ok(QueryPage {
            items,
            next_cursor: page.next.map(|c| c.encode()),
            scanned: ScanStats {
                segments: page.stats.segments,
                blocks_read: page.stats.blocks_read,
                blocks_total: page.stats.blocks_total,
                rows_scanned: page.stats.rows_scanned,
            },
            missing_nodes: Vec::new(),
            client_truncated: false,
        })
    }

    /// This node's query log plus the logs shipped to it, newest first, paged with a
    /// federated cursor (one position per source; CLU-007).
    fn search_with_shipped(
        &self,
        filter: &qlog::Filter,
        limit: usize,
        cursor: Option<&str>,
        own: std::path::PathBuf,
        shipped: Vec<(String, std::path::PathBuf)>,
    ) -> Result<QueryPage, Problem> {
        use telltale_api::federation::{self, Bounds, NodePage};
        let prev: Bounds = match cursor {
            None => Bounds::new(),
            Some(c) => federation::decode_cursor(Some(c)).ok_or_else(bad_cursor)?,
        };
        let mut sources = vec![("self".to_owned(), own, None)];
        for (id, dir) in shipped {
            let label = self.site_of(&id);
            sources.push((format!("shipped:{id}"), dir, Some(label)));
        }
        let mut pages = Vec::new();
        for (key, dir, label) in sources {
            let Some(to) = federation::until(&prev, &key, filter.to_us) else {
                continue;
            };
            let mut f = filter.clone();
            f.to_us = to;
            let page = self.search_dir(&dir, &f, limit, None, label.as_deref())?;
            pages.push(NodePage {
                node: key,
                label: self.own_site(),
                page,
                asked: limit,
            });
        }
        Ok(federation::merge_queries(pages, limit, &prev))
    }

    /// A cluster node's site (else its ID), for labelling shipped rows.
    fn site_of(&self, id: &str) -> String {
        let Some(c) = &self.src.cluster else {
            return id.to_owned();
        };
        c.members()
            .into_iter()
            .find(|m| m.node_id == id)
            .map(|m| m.site)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                c.identity
                    .registry()
                    .into_iter()
                    .find(|n| n.node_id == id)
                    .map(|n| n.site)
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| id.to_owned())
    }

    /// This node's own site (else its ID; empty outside a cluster).
    fn own_site(&self) -> String {
        self.src.cluster.as_ref().map_or_else(String::new, |c| {
            let m = &c.identity.meta;
            if m.site.is_empty() {
                m.node_id.clone()
            } else {
                m.site.clone()
            }
        })
    }
}

fn bad_cursor() -> Problem {
    Problem::invalid("`cursor`: not a cursor from this API")
        .hint("Pass the nextCursor value from the previous page unchanged.")
}

impl Backend for ApiBackend {
    fn system_info(&self) -> SystemInfo {
        let cfg = self.src.config.load();
        let snap = self
            .src
            .pipeline
            .filter
            .load()
            .as_ref()
            .and_then(|f| f.matcher.snapshot().cloned());
        let node = crate::http::node_name(&cfg);
        let started_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_micros())
            .saturating_sub(self.src.started.elapsed().as_micros());
        SystemInfo {
            version: crate::build_info::VERSION.to_owned(),
            build: crate::build_info::api(),
            update: self
                .src
                .update
                .lock()
                .map_or_else(|e| e.into_inner().clone(), |u| u.clone()),
            node,
            role: label(&cfg.node.role),
            uptime_seconds: self.src.started.elapsed().as_secs(),
            started_at: format_us(u64::try_from(started_us).unwrap_or(0)),
            starts: crate::datadir::runs().starts,
            unclean_starts: crate::datadir::runs().unclean,
            listeners: cfg
                .listen
                .iter()
                .map(|l| format!("{}://{}", label(&l.proto), l.addr))
                .collect(),
            query_log: self.src.qlog.is_some(),
            filter_snapshot: snap.as_ref().map(|s| s.manifest.version),
            filter_names: snap.as_ref().map_or(0, |s| {
                let st = &s.manifest.stats;
                st.subtree_names + st.exact_names + st.subdomains_names
            }),
            client_ips_masked: self.src.masked_clients().map(|m| {
                telltale_api::model::MaskedClients {
                    share_percent: m.share_percent,
                    sources: m.sources,
                    queries: m.queries,
                    window_start: format_us(m.window_start_s.saturating_mul(1_000_000)),
                }
            }),
            cluster: self.src.cluster.as_deref().map(crate::cluster::info),
            // REQ: OPS-010 — the web UI's banner when this node is in maintenance.
            maintenance: {
                let now = crate::maintenance::now_ms();
                self.src
                    .maintenance
                    .current(now)
                    .map(|w| crate::maintenance::api_window(&w.cluster_window(), now, None))
            },
        }
    }

    // REQ: CLU-008
    fn cluster(&self) -> telltale_api::model::ClusterView {
        match &self.src.cluster {
            Some(c) => {
                let mut v = crate::cluster::view(c, &self.src.host);
                // REQ: CLU-013 — the rollout and the pin, in brief.
                v.rollout = crate::rollout::surface::summary(&self.src);
                // ADR-049 — where the configuration comes from, when it's Git.
                v.source = crate::gitsource::view(&self.src.config.load(), c.is_primary());
                let cfg = self.src.config.load_full();
                // REQ: CLU-006 — settings in this node's file that the primary's replace.
                if crate::replication::follows_primary(&cfg) {
                    let ignored =
                        telltale_config::shared::ignored_on_replica(&self.src.file_config.load());
                    v.checks.push(telltale_api::model::ClusterCheck {
                        id: "node_settings".into(),
                        ok: ignored.is_empty(),
                        summary: if ignored.is_empty() {
                            "This node's file holds only node-local settings".into()
                        } else {
                            format!("Ignored in this node's file (the primary's apply): {}", ignored.join(", "))
                        },
                        fix: (!ignored.is_empty()).then(|| {
                            "Remove them from this node's file, or mark records that should stay on this node with node_only = true.".to_owned()
                        }),
                    });
                    v.healthy = v.checks.iter().all(|c| c.ok);
                }
                v.conflicts = crate::replication::conflicts(&cfg)
                    .into_iter()
                    .map(|k| telltale_api::model::ClusterConflict {
                        epoch: k.epoch,
                        seq: k.seq,
                        published_at: format_us(k.created_ms.saturating_mul(1000)),
                        detected_at: format_us(k.detected_ms.saturating_mul(1000)),
                        new_primary: k.new_primary,
                        changed: k.changed,
                    })
                    .collect();
                v
            }
            None => telltale_api::model::ClusterView {
                enabled: false,
                cluster_id: None,
                name: None,
                this_node: None,
                newest_config_seq: 0,
                healthy: true,
                checks: Vec::new(),
                nodes: Vec::new(),
                events: Vec::new(),
                authority: None,
                conflicts: Vec::new(),
                failover: None,
                source: None,
                rollout: None,
                // T6.11 — a standalone node still shows its machine.
                host: crate::host::report(self.src.host.latest(), &self.src.host.history(), None),
            },
        }
    }

    // REQ: API-007 (T6.7, ADR-063)
    fn backup(&self) -> Result<(String, Vec<u8>), Problem> {
        let cfg = self.src.config.load_full();
        let name = crate::backup::default_name(cfg.node.name.as_str());
        let tmp = std::path::Path::new(cfg.node.data_dir.as_str()).join(format!(
            ".backup-api-{}-{}.ttbk",
            std::process::id(),
            self.now_unix_seconds()
        ));
        let made = crate::backup::create(&self.src.config_files, &cfg, false, &tmp);
        let bytes = made.and_then(|_| std::fs::read(&tmp).map_err(|e| e.to_string()));
        let _ = std::fs::remove_file(&tmp);
        let bytes = bytes.map_err(|e| Problem::internal(format!("backup failed: {e}")))?;
        tracing::info!(bytes = bytes.len(), "backup downloaded through the API");
        Ok((name.display().to_string(), bytes))
    }

    // REQ: OPS-011 (ADR-156) — a support package, and its map for one download.
    fn support_package(
        &self,
        req: &telltale_api::model::SupportPackageRequest,
        dry_run: bool,
    ) -> Result<telltale_api::SupportPackageOutput, Problem> {
        if req.cluster {
            return Err(
                Problem::invalid("`cluster`: this node isn't part of a cluster")
                    .hint("Leave `cluster` out to make this node's own package."),
            );
        }
        crate::support::build(self, req, dry_run)
    }

    // REQ: OPS-011 (ADR-172) — this node's part of a cluster package, for the node that asked.
    fn support_part(
        &self,
        req: &telltale_api::model::SupportCollectRequest,
    ) -> Result<Vec<u8>, Problem> {
        crate::support::part(self, req)
    }

    fn support_map(&self, id: &str) -> Option<String> {
        crate::support::take_map(id)
    }

    // REQ: AGT-002 — the promotion checks without promoting.
    fn promote_plan(
        &self,
        req: &telltale_api::model::PromoteRequest,
    ) -> Result<telltale_api::model::PromotePlan, Problem> {
        let c = self
            .src
            .cluster
            .as_ref()
            .ok_or_else(|| Problem::unavailable("this node isn't in a cluster"))?;
        let cfg = self.src.config.load_full();
        let gitops_source = crate::replication::gitops_capable(&cfg);
        let (epoch, emergency) = crate::cluster::promote_plan(c, gitops_source, req.emergency)
            .map_err(|e| Problem::new(telltale_api::problem::Code::Conflict, e))?;
        let impact = if emergency {
            format!(
                "This node would become an emergency primary at epoch {epoch}: every node follows it, and the configuration stays at its last version until a Git-managed node takes over."
            )
        } else {
            format!(
                "This node would become the primary at epoch {epoch}: it publishes the configuration from the last version it applied, every node follows it, and an old primary that comes back steps down."
            )
        };
        Ok(telltale_api::model::PromotePlan {
            applied: false,
            epoch,
            emergency,
            impact,
        })
    }

    // REQ: CLU-005 (ADR-051)
    fn promote(
        &self,
        req: telltale_api::model::PromoteRequest,
        by: String,
    ) -> Result<telltale_api::model::ClusterView, Problem> {
        let c = self
            .src
            .cluster
            .as_ref()
            .ok_or_else(|| Problem::unavailable("this node isn't in a cluster"))?;
        let cfg = self.src.config.load_full();
        let gitops_source = crate::replication::gitops_capable(&cfg);
        crate::cluster::promote(c, gitops_source, req.emergency)
            .map_err(|e| Problem::new(telltale_api::problem::Code::Conflict, e))?;
        tracing::info!(by = %by, "promoted to cluster primary through the API");
        Ok(self.cluster())
    }

    // REQ: OBS-004, `spec/06` §3 — live windows from memory, longer ranges from rollups.
    // REQ: CLU-007 (T9.3) — shipped minutes, in the requested step (minutes are kept 7 days).
    fn shipped_timeseries(
        &self,
        step: Step,
        from_s: u64,
        to_s: u64,
        live: &[String],
    ) -> Vec<TimeBucket> {
        let width = match step {
            Step::Second => return Vec::new(),
            Step::Minute => 60,
            Step::Hour => 3600,
            Step::Day => 86_400,
        };
        let Some(db) = self.src.rollups.as_ref() else {
            return Vec::new();
        };
        let rows = db.shipped_range(from_s, to_s, live).unwrap_or_else(|e| {
            tracing::warn!("rollups: {e}");
            Vec::new()
        });
        let mut by = std::collections::BTreeMap::<u64, Counts>::new();
        for (start, c) in rows {
            merge(by.entry(start - start % width).or_default(), &c);
        }
        time_buckets(&self.src, by.into_iter().collect())
    }

    fn timeseries(&self, step: Step, from_s: u64, to_s: u64) -> Vec<TimeBucket> {
        time_buckets(&self.src, self.counts(step, from_s, to_s))
    }

    // REQ: OBS-030 (ADR-130) — this node's exemplar ring, newest first, with upstream names.
    fn exemplars(
        &self,
        from_us: u64,
        to_us: u64,
        path: Option<&str>,
    ) -> Vec<telltale_api::latency_heatmap::LatencyExemplar> {
        let paths = telltale_telemetry::Path::ALL;
        let want = path.and_then(|p| paths.iter().position(|x| x.label() == p));
        if path.is_some() && want.is_none() {
            return Vec::new();
        }
        let ups = crate::rollups::upstream_names(&self.src.pipeline);
        self.src
            .traces
            .recent(from_us, to_us, want)
            .into_iter()
            .map(|x| {
                let mut trace = String::with_capacity(32);
                for b in x.trace {
                    use std::fmt::Write as _;
                    let _ = write!(trace, "{b:02x}");
                }
                telltale_api::latency_heatmap::LatencyExemplar {
                    trace_id: trace,
                    time: telltale_api::time::format_us(x.ts_us),
                    ts_unix_micros: x.ts_us,
                    latency_us: x.value_us,
                    path: paths.get(x.path).map_or("other", |p| p.label()).to_owned(),
                    upstream: (x.upstream > 0)
                        .then(|| ups.get(usize::from(x.upstream)).cloned())
                        .flatten()
                        .filter(|n| !n.is_empty()),
                    node: None,
                }
            })
            .collect()
    }

    // REQ: OBS-029 (ADR-129) — a device's or a name's hours on this node, from the stored top
    // lists and, for the current hour (and the previous one until it's stored), memory's.
    // REQ: OBS-034 — how far back the query log reaches.
    fn qlog_retention_days(&self) -> u32 {
        self.src.config.load().telemetry.qlog.retention_days
    }
    fn qlog_privacy_level(&self) -> u8 {
        self.src.config.load().telemetry.qlog.privacy_level
    }

    fn heatmap_key(
        &self,
        q: &telltale_api::heatmap::KeyQuery,
    ) -> Result<telltale_api::heatmap::KeyPart, Problem> {
        use telltale_telemetry::agg::HourSel;
        let privacy = self.src.config.load().telemetry.qlog.privacy_level;
        let hidden = (q.kind == "name" && privacy >= 1) || (q.kind == "client" && privacy >= 2);
        if hidden {
            return Err(Problem::new(
                telltale_api::problem::Code::PrivacyLevel,
                format!(
                    "the query log's privacy level ({privacy}) hides {}s",
                    q.kind
                ),
            )
            .hint("The network heatmap works at every level."));
        }
        let (stored_kind, mem_kind) = match (q.kind.as_str(), q.blocked) {
            ("client", _) => ("clients", telltale_telemetry::agg::TopKind::Clients),
            (_, true) => ("blocked", telltale_telemetry::agg::TopKind::Blocked),
            _ => ("domains", telltale_telemetry::agg::TopKind::Domains),
        };
        // REQ: OBS-029 — hours of the window, at most `MAX_SLOTS`; none when it doesn't end after
        // it starts (a peer's read names its own window).
        let n = telltale_api::heatmap::window_slots(q.from_s, q.to_s, 3600);
        let mut part = telltale_api::heatmap::KeyPart {
            values: vec![0; n],
            covered: vec![true; n],
        };
        let slot = |start: u64| -> Option<usize> {
            (start >= q.from_s)
                .then(|| usize::try_from((start - q.from_s) / 3600).ok())
                .flatten()
                .filter(|i| *i < n)
        };
        let same = |k: &str| -> bool {
            if q.kind == "client" {
                k.parse::<IpAddr>().ok() == q.key.parse::<IpAddr>().ok()
            } else {
                k.trim_end_matches('.').eq_ignore_ascii_case(&q.key)
            }
        };
        let (current, previous) = {
            let agg = self.src.pipeline.telemetry.aggregates();
            (agg.current_hour_start(), agg.previous_hour_start())
        };
        let db = self.src.rollups.as_ref();
        let prev_live =
            previous.filter(|h| db.is_none_or(|d| !d.has_hour_tops(*h).unwrap_or(false)));
        let stored_to = q.to_s.min(prev_live.unwrap_or(current));
        if let Some(d) = db {
            let key = if q.kind == "client" {
                q.key
                    .parse::<IpAddr>()
                    .map_or_else(|_| q.key.clone(), |ip| ip.to_string())
            } else {
                q.key.clone()
            };
            let (found, hours) = d
                .top_key_hours(q.from_s, stored_to, stored_kind, &key)
                .map_err(|e| Problem::internal(e.to_string()))?;
            for h in hours {
                if let Some(i) = slot(h) {
                    part.covered[i] = false;
                }
            }
            for (h, c) in found {
                if let Some(i) = slot(h) {
                    part.values[i] += c;
                    part.covered[i] = true;
                }
            }
        }
        let agg = self.src.pipeline.telemetry.aggregates();
        let live = [
            (HourSel::Current, Some(current)),
            (HourSel::Previous, prev_live),
        ];
        for (sel, start) in live {
            let Some(i) = start.and_then(slot) else {
                continue;
            };
            let top = agg.top_names(mem_kind, sel, telltale_telemetry::agg::TOP_REPORTED);
            match top.iter().find(|t| same(&t.key)) {
                Some(t) => {
                    part.values[i] += t.count;
                    part.covered[i] = true;
                }
                None => part.covered[i] = top.is_empty(),
            }
        }
        Ok(part)
    }

    // REQ: OBS-027 (ADR-127) — this node's hours and bad-answer lists; with `q.live` set (the
    // whole cluster's read), also the pods that shipped minutes here and aren't answering.
    fn slo_parts(
        &self,
        q: &telltale_api::attribution::PartQuery,
    ) -> Vec<telltale_api::attribution::Part> {
        let privacy = self.src.config.load().telemetry.qlog.privacy_level;
        let (clients, names, top_hours) = self.bad_lists(q, privacy);
        let mut parts = vec![telltale_api::attribution::Part {
            node: None,
            hours: self.timeseries(Step::Hour, q.from_s, q.to_s),
            clients,
            names,
            top_hours,
            partial: false,
            privacy,
        }];
        if !q.live.is_empty()
            && let Some(db) = self.src.rollups.as_ref()
        {
            let shipped = db
                .shipped_hours_by_node(q.from_s, q.to_s, &q.live)
                .unwrap_or_else(|e| {
                    tracing::warn!("rollups: {e}");
                    Vec::new()
                });
            for (node, rows) in shipped {
                parts.push(telltale_api::attribution::Part {
                    node: Some(node),
                    hours: time_buckets(&self.src, rows),
                    partial: true,
                    privacy,
                    ..telltale_api::attribution::Part::default()
                });
            }
        }
        parts
    }

    // REQ: FLT-005 (ADR-050)
    fn top_in_group(
        &self,
        kind: TopKind,
        h: Hour,
        limit: usize,
        group: &str,
    ) -> Result<Vec<TopItem>, Problem> {
        let gi = self.group_index(group)?;
        let k = match kind {
            TopKind::Domains => telltale_telemetry::agg::TopKind::Domains,
            TopKind::Blocked => telltale_telemetry::agg::TopKind::Blocked,
            TopKind::Nxdomain => telltale_telemetry::agg::TopKind::Nxdomain,
            TopKind::Clients => telltale_telemetry::agg::TopKind::Clients,
            TopKind::Internal => telltale_telemetry::agg::TopKind::Internal,
        };
        let agg = self.src.pipeline.telemetry.aggregates();
        let tops = if kind == TopKind::Clients {
            agg.top_clients(hour(h), Some(gi), limit)
                .into_iter()
                .map(|(t, s)| (t, Some(s)))
                .collect()
        } else {
            agg.top_names_in_group(k, hour(h), gi, limit)
                .into_iter()
                .map(|t| (t, None))
                .collect::<Vec<_>>()
        };
        drop(agg);
        Ok(self.top_items(kind, tops))
    }

    // REQ: OBS-004 (ADR-160) — a top list over a window: the stored hours (`hour_top`) plus
    // the current hour (and the previous one until it's stored) from memory, summed per key.
    // Hour granularity: every hour the window overlaps counts whole.
    fn top_range(&self, kind: TopKind, from_s: u64, to_s: u64, limit: usize) -> Vec<TopItem> {
        use telltale_telemetry::agg::{HourSel, TopKind as Mem};
        let (stored_kind, mem_kind) = match kind {
            TopKind::Domains => ("domains", Mem::Domains),
            TopKind::Blocked => ("blocked", Mem::Blocked),
            TopKind::Nxdomain => ("nxdomain", Mem::Nxdomain),
            TopKind::Clients => ("clients", Mem::Clients),
            TopKind::Internal => ("internal", Mem::Internal),
        };
        let db = self.src.rollups.as_ref();
        let (current, previous) = {
            let agg = self.src.pipeline.telemetry.aggregates();
            (agg.current_hour_start(), agg.previous_hour_start())
        };
        let prev_live =
            previous.filter(|h| db.is_none_or(|d| !d.has_hour_tops(*h).unwrap_or(false)));
        let first = from_s - from_s % 3600;
        let in_window = |h: u64| h >= first && h < to_s;
        let stored_to = to_s.min(prev_live.unwrap_or(current));
        // Space-Saving's lists are kept per hour: read more than asked, so the summed
        // heaviest are among them.
        let n = (limit * 2).max(20);
        let mut by = std::collections::HashMap::<String, (u64, u64)>::new();
        // REQ: OBS-004 (ADR-159, ADR-160) — a client's queries by status over the same hours: the
        // stored `clients_*` lists (hours closed since the split was kept) plus the hours in memory.
        // An hour stored before that has no split, and its queries stay in `count` only.
        let mut split = std::collections::HashMap::<String, [u64; 3]>::new();
        if let Some(d) = db {
            match d.top_range(first, stored_to, stored_kind, n) {
                Ok((rows, _)) => {
                    for r in rows {
                        let e = by.entry(r.key).or_default();
                        e.0 += r.count;
                        e.1 += r.error;
                    }
                }
                Err(e) => tracing::warn!("rollups: {e}"),
            }
            if kind == TopKind::Clients {
                for (i, list) in ["clients_blocked", "clients_cached", "clients_forwarded"]
                    .into_iter()
                    .enumerate()
                {
                    // Each stored list holds a hour's busiest 100: ask for every key it kept.
                    match d.top_range(first, stored_to, list, 1000) {
                        Ok((rows, _)) => {
                            for r in rows {
                                split.entry(r.key).or_default()[i] += r.count;
                            }
                        }
                        Err(e) => tracing::warn!("rollups: {e}"),
                    }
                }
            }
        }
        let agg = self.src.pipeline.telemetry.aggregates();
        for (sel, start) in [
            (HourSel::Current, Some(current)),
            (HourSel::Previous, prev_live),
        ] {
            if !start.is_some_and(in_window) {
                continue;
            }
            if kind == TopKind::Clients {
                for (t, s) in agg.top_clients(sel, None, n) {
                    let x = split.entry(t.key.clone()).or_default();
                    x[0] += s.blocked;
                    x[1] += s.cached;
                    x[2] += s.forwarded;
                    let e = by.entry(t.key).or_default();
                    e.0 += t.count;
                    e.1 += t.error;
                }
                continue;
            }
            for t in agg.top_names(mem_kind, sel, n) {
                let e = by.entry(t.key).or_default();
                e.0 += t.count;
                e.1 += t.error;
            }
        }
        drop(agg);
        let mut v: Vec<(String, (u64, u64))> = by.into_iter().collect();
        v.sort_by(|a, b| b.1.0.cmp(&a.1.0).then_with(|| a.0.cmp(&b.0)));
        v.truncate(limit);
        v.into_iter()
            .map(|(key, (count, error_bound))| {
                let (name, groups) = self.client_labels(kind, &key);
                let by_status = split
                    .get(&key)
                    .map(|s| telltale_api::model::ClientStatusCounts {
                        blocked: s[0],
                        cached: s[1],
                        forwarded: s[2],
                    });
                TopItem {
                    key,
                    name,
                    groups,
                    count,
                    error_bound,
                    by_status,
                }
            })
            .collect()
    }

    fn top(&self, kind: TopKind, h: Hour, limit: usize, client: Option<IpAddr>) -> Vec<TopItem> {
        let agg = self.src.pipeline.telemetry.aggregates();
        let plain = |v: Vec<telltale_telemetry::topk::Top<String>>| {
            v.into_iter().map(|t| (t, None)).collect::<Vec<_>>()
        };
        let tops = match (kind, client) {
            (TopKind::Domains, Some(ip)) => plain(agg.top_client_domains(mapped(ip), limit)),
            (TopKind::Clients, _) => agg
                .top_clients(hour(h), None, limit)
                .into_iter()
                .map(|(t, s)| (t, Some(s)))
                .collect(),
            (k, _) => {
                let k = match k {
                    TopKind::Domains => telltale_telemetry::agg::TopKind::Domains,
                    TopKind::Blocked => telltale_telemetry::agg::TopKind::Blocked,
                    TopKind::Nxdomain => telltale_telemetry::agg::TopKind::Nxdomain,
                    TopKind::Clients => telltale_telemetry::agg::TopKind::Clients,
                    TopKind::Internal => telltale_telemetry::agg::TopKind::Internal,
                };
                plain(agg.top_names(k, hour(h), limit))
            }
        };
        drop(agg);
        self.top_items(kind, tops)
    }

    // REQ: API-005 (ADR-158) — the clients of the last hour, labelled like `top`. The counts
    // are read under the aggregator's lock; ranking and labels come after it's released.
    fn top_clients_rolling(
        &self,
        limit: usize,
        group: Option<&str>,
    ) -> Result<Vec<TopItem>, Problem> {
        if let Some(g) = group {
            self.group_index(g)?;
        }
        let now = self.now_unix_seconds();
        let counts = self
            .src
            .pipeline
            .telemetry
            .aggregates()
            .last_hour_counts(now);
        let item = |(ip, count): ([u8; 16], u64)| {
            let key = telltale_telemetry::agg::client_text(ip);
            let (name, groups) = self.client_labels(TopKind::Clients, &key);
            TopItem {
                key,
                name,
                groups,
                count,
                error_bound: 0,
                // The rolling hour keeps one count per client, no split by status.
                by_status: None,
            }
        };
        Ok(match group {
            // Ranked first, so only the kept ones are labelled.
            None => telltale_telemetry::last_hour::rank(counts, limit)
                .into_iter()
                .map(item)
                .collect(),
            // A client's group needs its labels, so every client is labelled, then ranked.
            Some(g) => {
                let mut v: Vec<TopItem> = counts
                    .into_iter()
                    .map(item)
                    .filter(|t| t.groups.first().is_some_and(|f| f == g))
                    .collect();
                v.sort_unstable_by(|a, b| b.count.cmp(&a.count).then(a.key.cmp(&b.key)));
                v.truncate(limit);
                v
            }
        })
    }

    fn latency(&self, by: LatencyBy, h: Hour) -> Vec<LatencyRow> {
        let sel = hour(h);
        let agg = self.src.pipeline.telemetry.aggregates();
        self.latency_keys(by)
            .into_iter()
            .filter_map(|(name, key)| agg.latency(key, sel).map(|v| latency_row(name, v)))
            .collect()
    }

    // REQ: CLU-002 (T9.2) — the same keys' histograms, for an exact cluster merge.
    fn latency_hists(&self, by: LatencyBy, h: Hour) -> Vec<telltale_api::model::LatencyHist> {
        let sel = hour(h);
        let agg = self.src.pipeline.telemetry.aggregates();
        self.latency_keys(by)
            .into_iter()
            .filter_map(|(name, key)| {
                agg.latency_buckets(key, sel)
                    .map(|buckets| telltale_api::model::LatencyHist { key: name, buckets })
            })
            .collect()
    }

    // REQ: OBS-008 — live tail: filter, rate-cap, and format on a per-subscriber task.
    fn tail(
        &self,
        p: &telltale_api::model::TailParams,
    ) -> Result<tokio::sync::mpsc::Receiver<telltale_api::model::TailItem>, Problem> {
        let tail = self.src.tail.as_ref().ok_or_else(|| {
            Problem::unavailable("the live tail is off: the query-log privacy level is 3")
                .hint("Lower [telemetry.qlog] privacy_level to see live queries.")
        })?;
        let policy = &self.src.pipeline.current().policy;
        let groups: Vec<String> = policy
            .clients
            .groups()
            .iter()
            .map(|g| g.name.to_string())
            .collect();
        let src = Arc::clone(&self.src);
        let filter = crate::tail::Filter::parse(p, &groups, &self.src.pipeline.workloads)?;
        let (events, slot) = tail.subscribe().ok_or_else(|| {
            Problem::unavailable(format!(
                "too many live tails on this node (at most {})",
                crate::tail::MAX_SUBSCRIBERS
            ))
            .hint("Close another live view, or use GET /queries.")
        })?;
        let lists = self.list_names();
        Ok(crate::tail::spawn_subscriber(
            events,
            slot,
            filter,
            move |t| {
                let e = &t.ev;
                let (list, rule) = rule_labels(
                    e.rule,
                    &lists,
                    &src.pipeline.current().policy.quick,
                    &src.pipeline.schedules.load().names,
                );
                QueryRow {
                    time: format_us(e.ts_us),
                    ts_unix_micros: e.ts_us,
                    client: telltale_telemetry::agg::client_text(e.client_ip),
                    client_name: device_name(&src, e.client_ip),
                    group: groups.get(usize::from(e.group)).cloned(),
                    name: telltale_telemetry::event::dotted(&t.name),
                    qtype: qtype_name(e.qtype),
                    status: e.status.label().to_owned(),
                    rcode: e.rcode.map(rcode_name),
                    proto: e.proto.label().to_owned(),
                    list,
                    rule,
                    total_ms: ms(u64::from(e.t_total_us)),
                    upstream_ms: ms(u64::from(e.t_upstream_us)),
                    response_bytes: e.resp_size,
                    answers: e.answers,
                    node: None,
                }
            },
        ))
    }

    fn queries(
        &self,
        q: &QueryParams,
        from_us: u64,
        to_us: u64,
        limit: usize,
    ) -> Result<QueryPage, Problem> {
        if self.src.qlog.is_none() {
            return Err(
                Problem::unavailable("the query log is off on this node").hint(
                    "Enable it with [telemetry.qlog] enabled = true (and privacy_level below 3).",
                ),
            );
        }
        // REQ: FLT-017 — `client` may name a Kubernetes workload (its text form or analytics
        // key): the search covers the addresses it held in the window.
        let workload = q
            .client
            .as_deref()
            .and_then(|c| crate::kubernetes::workload_ref(c, &self.src.pipeline.workloads.load()));
        let mut filter = match &workload {
            Some(_) => {
                let mut plain = q.clone();
                plain.client = None;
                qlog_filter(&plain, from_us, to_us)?
            }
            None => qlog_filter(q, from_us, to_us)?,
        };
        let mut client_truncated = false;
        if let Some(text) = &workload {
            let until_s = if to_us == 0 {
                u64::MAX
            } else {
                to_us / 1_000_000 + 1
            };
            let mut ips =
                self.src
                    .pipeline
                    .workloads
                    .load()
                    .addresses_of(text, from_us / 1_000_000, until_s);
            client_truncated = ips.len() > MAX_WORKLOAD_ADDRESSES;
            ips.truncate(MAX_WORKLOAD_ADDRESSES);
            filter.client_any = ips.into_iter().map(mapped).collect();
            if filter.client_any.is_empty() {
                // Nothing held by it in the window: match no row (no address is a key).
                filter.client_ip = Some(telltale_telemetry::workload::key(text));
            }
        }
        if let Some(g) = &q.group {
            filter.group = Some(self.group_index(g)?);
        }
        let data_dir = self.src.config.load().node.data_dir.to_string();
        let dir = Path::new(&data_dir).join("qlog");
        // REQ: CLU-007 — query logs other nodes shipped here are searched too (ADR-055).
        let shipped = crate::ship::shipped_dirs(&data_dir);
        let mut page = if shipped.is_empty() {
            let cursor = match &q.cursor {
                None => None,
                Some(c) => Some(qlog::Cursor::decode(c).ok_or_else(bad_cursor)?),
            };
            self.search_dir(&dir, &filter, limit, cursor, None)?
        } else {
            self.search_with_shipped(&filter, limit, q.cursor.as_deref(), dir, shipped)?
        };
        page.client_truncated = client_truncated;
        // REQ: FLT-017 — an address another workload held at the row's time isn't this one's.
        if let Some(text) = &workload
            && let Some(spans) = workload_spans(&self.src, text)
        {
            page.items.retain(|r| {
                let Ok(ip) = r.client.parse::<IpAddr>() else {
                    return false;
                };
                let (ip, ts) = (mapped(ip), r.ts_unix_micros / 1_000_000);
                spans
                    .iter()
                    .any(|(a, f, t)| *a == ip && *f <= ts && ts < *t)
            });
        }
        Ok(page)
    }

    #[allow(clippy::too_many_lines)] // the explanation's fields, one by one
    fn explain(&self, p: &ExplainParams) -> Result<Explanation, Problem> {
        let qtype_text = p.qtype.clone().unwrap_or_else(|| "A".to_owned());
        let qtype = telltale_proto::rtype::from_name(&qtype_text)
            .ok_or_else(|| Problem::invalid(format!("`qtype`: unknown type `{qtype_text}`")))?;
        let given = p.client.as_deref().unwrap_or("127.0.0.1");
        // REQ: FLT-017 — a Kubernetes workload: as if from one of its pods.
        let pod_ip = {
            let t = self.src.pipeline.workloads.load();
            crate::kubernetes::workload_ref(given, &t).and_then(|text| {
                t.by_text(&text).and_then(|w| {
                    w.pods
                        .iter()
                        .filter(|p| p.deleted_s.is_none())
                        .find_map(|p| p.ips.first().copied())
                })
            })
        };
        let client: IpAddr = match pod_ip {
            Some(ip) => ip,
            None => given.parse().map_err(|_| {
                Problem::invalid("`client` is not an IP address")
                    .hint("Give an address, or a Kubernetes workload with a running pod (namespace/kind/name).")
            })?,
        };
        let mac = match p.mac.as_deref().map(telltale_config::MatchKey::parse) {
            None => None,
            Some(Ok(telltale_config::MatchKey::Mac(m))) => Some(m),
            Some(_) => {
                return Err(Problem::invalid("`mac` is not a MAC address")
                    .hint("Use the form aa:bb:cc:dd:ee:ff."));
            }
        };
        let req = crate::explain::Request {
            name: &p.name,
            qtype,
            client,
            mac,
            client_id: None,
        };
        let cfg = self.src.config.load();
        let e = self
            .src
            .pipeline
            .explain(&req, crate::lists::source_reader(&cfg))
            .map_err(|e| Problem::invalid(e).hint("Pass a domain name such as ads.example.com."))?;
        // REQ: FLT-013, AGT-004 (ADR-183) — at query-log privacy level 2 and above (clients hidden)
        // the node's own knowledge of the client's MAC isn't shown, as the identity's `recognition`
        // isn't; a MAC the caller gave is theirs and comes back.
        let hide_mac = mac.is_none() && cfg.telemetry.qlog.privacy_level >= 2;
        Ok(Explanation {
            name: e.name,
            qtype: qtype_name(e.qtype),
            client: ExplainClient {
                ip: e.client.ip.to_string(),
                mac: e.client.mac.filter(|_| !hide_mac),
                mac_from: e.client.mac_from.filter(|_| !hide_mac).map(str::to_owned),
                device: e.client.device,
                identified_by: e.client.identified_by.to_owned(),
                groups: e.client.groups,
                workload: e
                    .client
                    .workload
                    .map(|w| telltale_api::model::ExplainWorkload {
                        name: w.name,
                        pod: w.pod,
                        group_from: w.group_from.to_owned(),
                    }),
            },
            outcome: label(&e.outcome),
            summary: e.summary,
            block: e.block.map(|b| ExplainBlock {
                list: b.list,
                mode: label(&b.mode),
                ttl_seconds: b.ttl,
                ede_code: b.ede_code,
            }),
            paused_until_unix_seconds: e.paused_until,
            filter: e.filter.map(|f| ExplainFilter {
                snapshot: f.snapshot,
                rules: f
                    .rules
                    .into_iter()
                    .map(|r| ExplainRule {
                        // REQ: OBS-018 (T11.5)
                        shadow: cfg.list.iter().any(|l| {
                            l.name.as_str() == r.list && l.mode == telltale_config::ListMode::Shadow
                        }),
                        list: r.list,
                        tier: label(&r.tier),
                        kind: label(&r.kind),
                        scope: r.scope.map(|s| label(&s)),
                        name: r.name,
                        enabled: r.enabled,
                        winner: r.winner,
                        lines: r
                            .lines
                            .into_iter()
                            .map(|l| ExplainLine {
                                line: l.line,
                                text: l.text,
                            })
                            .collect(),
                    })
                    .collect(),
                notes: f.notes,
            }),
            route: e.route.map(|r| ExplainRoute {
                group: r.group,
                routed: r.routed,
            }),
            notes: e.notes,
        })
    }

    fn lists(&self) -> Vec<ListInfo> {
        let cfg = self.src.config.load();
        let shared = self.src.lists.load_full();
        let status = shared
            .as_ref()
            .map(|l| l.fetcher.status())
            .unwrap_or_default();
        let compiled = shared.as_ref().and_then(|l| {
            l.compiled
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .map(|c| c.manifest.clone())
        });
        // REQ: OBS-009 — this node's own hits by list name. `GET /api/v1/lists` replaces them with
        // the cluster's (`list_hits`); a caller that reads this directly, like the support
        // package, still gets this node's.
        let decided = self.src.shadow.decided();
        cfg.list
            .iter()
            .map(|l| {
                let meta = status.iter().find(|(n, _)| *n == *l.name).map(|(_, m)| m);
                let id = compiled
                    .as_ref()
                    .and_then(|m| m.lists.iter().position(|x| x.name == *l.name));
                let per = compiled
                    .as_ref()
                    .zip(id)
                    .and_then(|(m, i)| m.stats.per_list.get(i));
                let entries = per.map_or(0, |s| s.entries);
                let unique = per.map_or(0, |s| s.unique);
                let regex_skipped = per.map_or(0, |s| s.regex_skipped);
                let mut overlap: Vec<telltale_api::model::ListShare> = match (&compiled, id) {
                    (Some(m), Some(i)) => {
                        let i = u16::try_from(i).unwrap_or(u16::MAX);
                        m.stats
                            .overlap
                            .iter()
                            .filter_map(|o| {
                                let other = if o.a == i {
                                    o.b
                                } else if o.b == i {
                                    o.a
                                } else {
                                    return None;
                                };
                                m.lists.get(usize::from(other)).map(|x| {
                                    telltale_api::model::ListShare {
                                        list: x.name.clone(),
                                        names: o.names,
                                    }
                                })
                            })
                            .collect()
                    }
                    _ => Vec::new(),
                };
                overlap.sort_by(|a, b| b.names.cmp(&a.names).then(a.list.cmp(&b.list)));
                let source = l
                    .url
                    .as_ref()
                    .or(l.path.as_ref())
                    .map_or_else(|| "inline".to_owned(), ToString::to_string);
                let state = match meta {
                    Some(m) if m.last_error.is_some() && !m.has_content() => "failed",
                    Some(m) if m.has_content() => "ok",
                    _ => "pending",
                };
                ListInfo {
                    name: l.name.to_string(),
                    kind: label(&l.kind),
                    enabled: l.enabled,
                    mode: label(&l.mode),
                    source,
                    local: l.url.is_none() && l.path.is_some(),
                    state: state.to_owned(),
                    error: meta.and_then(|m| m.last_error.clone()),
                    bytes: meta.map_or(0, |m| m.bytes),
                    lines: meta.map_or(0, |m| m.lines),
                    entries,
                    unique,
                    regex_skipped,
                    hits: decided.get(&*l.name).copied().unwrap_or(0),
                    overlap,
                    last_checked_unix_seconds: meta.and_then(|m| m.last_attempt),
                    last_changed_unix_seconds: meta.and_then(|m| m.last_changed),
                    stale_days: stale_days(&cfg.filter, l, meta.and_then(|m| m.last_changed)),
                }
            })
            .collect()
    }

    // REQ: OBS-009 (T7.14) — this node's blocks and allows by list name, counted on the
    // telemetry thread (`shadow::ShadowSink`): a replica that only receives the snapshot
    // counts too, and the counts survive lists being renumbered.
    fn list_hits(&self) -> std::collections::BTreeMap<String, u64> {
        self.src.shadow.decided()
    }

    fn groups(&self) -> Vec<GroupInfo> {
        let cfg = self.src.config.load();
        let now_s = i64::try_from(crate::pipeline::unix_now()).unwrap_or(i64::MAX);
        let now = crate::pipeline::unix_now();
        let pauses = self.src.pipeline.pause.active(now);
        let global = pauses.iter().find(|(g, _)| g.is_none()).map(|(_, u)| *u);
        let policy = &self.src.pipeline.current().policy;
        // Last 24 hours from the minute series, per group: (queries, blocked).
        let agg = self.src.pipeline.telemetry.aggregates();
        let mut day = (Vec::<u64>::new(), Vec::<u64>::new());
        for (_, c) in agg.series(
            telltale_telemetry::agg::Resolution::Minute,
            now.saturating_sub(86_400),
            now + 60,
        ) {
            for (i, n) in c.groups.iter().enumerate() {
                if day.0.len() <= i {
                    day.0.resize(i + 1, 0);
                }
                day.0[i] += u64::from(*n);
            }
            for (i, n) in c.group_blocked.iter().enumerate() {
                if day.1.len() <= i {
                    day.1.resize(i + 1, 0);
                }
                day.1[i] += u64::from(*n);
            }
        }
        policy
            .clients
            .groups()
            .iter()
            .enumerate()
            .map(|(i, g)| GroupInfo {
                networks: g.networks.iter().map(ToString::to_string).collect(),
                color: g
                    .color
                    .as_deref()
                    .map_or_else(|| palette(i, &g.name), str::to_owned),
                queries_24h: day.0.get(i).copied().unwrap_or(0),
                blocked_24h: day.1.get(i).copied().unwrap_or(0),
                devices_this_hour: u64::try_from(agg.group_devices(
                    telltale_telemetry::agg::HourSel::Current,
                    u16::try_from(i).unwrap_or(u16::MAX),
                ))
                .unwrap_or(0),
                name: g.name.to_string(),
                blocked_services: g.services.iter().map(ToString::to_string).collect(),
                schedules: cfg
                    .group
                    .iter()
                    .find(|x| x.name.as_str() == &*g.name)
                    .map(|x| x.schedules.iter().map(ToString::to_string).collect())
                    .unwrap_or_default(),
                schedules_on: schedules_on(&cfg, &g.name, now_s),
                safe_search: g.safe_search.is_some(),
                youtube_restrict: g.safe_search.map(|y| {
                    match y {
                        telltale_config::YoutubeRestrict::Strict => "strict",
                        telltale_config::YoutubeRestrict::Moderate => "moderate",
                        telltale_config::YoutubeRestrict::Off => "off",
                    }
                    .to_owned()
                }),
                priority: g.priority,
                lists: g
                    .lists
                    .as_ref()
                    .map(|l| l.iter().map(ToString::to_string).collect()),
                block_mode: label(&g.block.mode),
                block_ttl_seconds: g.block.ttl,
                paused_until_unix_seconds: pauses
                    .iter()
                    .find(|(n, _)| n.as_deref() == Some(&*g.name))
                    .map(|(_, u)| *u)
                    .max(global),
                rebinding_protection: false,
                block_answer_ips: Vec::new(),
                rewrites: Vec::new(),
                dns64: false,
                dns64_prefix: None,
                filter_aaaa: false,
                upstreams: None,
            })
            .map(|info| with_group_config(info, &cfg))
            .collect()
    }

    fn clients(&self) -> Vec<ClientInfo> {
        let managed = managed_names(&self.src);
        let state = self.src.pipeline.current();
        let clients = &state.policy.clients;
        // REQ: OBS-025 — what each named device looks like (its first address seen).
        let identities: std::collections::HashMap<String, telltale_api::model::DeviceIdentity> =
            self.src
                .identify
                .list()
                .into_iter()
                .map(|i| (i.client.clone(), i))
                .collect();
        self.src
            .config
            .load()
            .client
            .iter()
            .map(|c| {
                let mut info = client_info(c, &managed);
                // ADR-050 — a device without its own groups takes its network's.
                let (effective, from) = effective_groups(clients, c);
                info.effective_groups = effective;
                from.clone_into(&mut info.groups_from);
                info.identity = device_addresses(c)
                    .into_iter()
                    .find_map(|a| identities.get(&a).cloned());
                info
            })
            .collect()
    }

    // REQ: OBS-025 (T13.3)
    fn identities(&self) -> Vec<telltale_api::model::DeviceIdentity> {
        self.src.identify.list()
    }

    // REQ: OBS-031 — this node's view of a device's rhythm.
    fn client_rhythm(
        &self,
        client: &str,
    ) -> Result<telltale_api::rhythm_api::ClientRhythm, Problem> {
        let addr = if let Some(ip) = self
            .workload(client)
            .and_then(|(_, key)| key.parse::<IpAddr>().ok())
        {
            // REQ: FLT-017 — a workload's rhythm is under its analytics key.
            ip
        } else if let Ok(ip) = client.parse::<IpAddr>() {
            ip
        } else {
            let cfg = self.src.config.load();
            let c = cfg
                .client
                .iter()
                .find(|c| c.name.as_str().eq_ignore_ascii_case(client))
                .ok_or_else(|| {
                    Problem::not_found(format!(
                        "`{client}` is neither an address nor a named device"
                    ))
                    .hint("Give a device's IP address, or the name it has on the Clients page.")
                })?;
            device_addresses(c)
                .iter()
                .find_map(|a| a.parse::<IpAddr>().ok())
                .ok_or_else(|| {
                    Problem::not_found(format!("`{client}` has no single address"))
                        .hint("Give one of the device's IP addresses.")
                })?
        };
        let text = addr.to_string();
        let Some(a) = &self.src.anomalies else {
            return Ok(telltale_api::rhythm_api::ClientRhythm {
                client: text,
                reason: Some("disabled".into()),
                ..telltale_api::rhythm_api::ClientRhythm::default()
            });
        };
        let key = match addr {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        };
        let domains = a
            .rhythm(key)
            .into_iter()
            .map(|r| telltale_api::rhythm_api::RhythmDomain {
                domain: r.domain,
                hour: r.hour.iter().map(|&n| u32::from(n)).collect(),
                recent: r.recent.iter().map(|&n| u32::from(n)).collect(),
                typical_gap_s: r.typical_gap_s,
                regular_hours: r.regular_hours,
                known_periodic: r.known_periodic,
                since_unix_seconds: Some(r.since_s),
                mean_per_hour: f64::from(r.mean_per_hour),
                ..telltale_api::rhythm_api::RhythmDomain::default()
            })
            .collect();
        Ok(telltale_api::rhythm_api::ClientRhythm {
            client: text,
            available: true,
            domains,
            ..telltale_api::rhythm_api::ClientRhythm::default()
        })
    }

    // REQ: FLT-017 — a Kubernetes workload by its name or analytics key.
    fn workload(&self, client: &str) -> Option<(String, String)> {
        let t = self.src.pipeline.workloads.load();
        let text = crate::kubernetes::workload_ref(client, &t)?;
        let key = telltale_telemetry::workload::key(&text);
        Some((text, std::net::Ipv6Addr::from(key).to_string()))
    }

    fn kubernetes_workloads(&self) -> Result<Vec<telltale_api::model::WorkloadInfo>, Problem> {
        let kube = &self.src.pipeline.kube;
        let t = self.src.pipeline.workloads.snapshot();
        if kube.state().role == crate::kubernetes::Role::Off && t.workloads().is_empty() {
            return Err(telltale_api::kubernetes_api::disabled());
        }
        let now = crate::kubernetes::now_s();
        let agg = self.src.pipeline.telemetry.aggregates();
        let counts = agg.workload_counts();
        let items = t
            .workloads()
            .iter()
            .map(|w| {
                let (q, blocked, last) = counts.get(&w.key).map_or((0, 0, 0), |c| {
                    let (q, b) = c.day(now);
                    (q, b, c.last_seen_s)
                });
                telltale_api::model::WorkloadInfo {
                    name: w.text.to_string(),
                    namespace: w.namespace.to_string(),
                    kind: w.kind.to_string(),
                    workload_name: w.name.to_string(),
                    key: std::net::Ipv6Addr::from(w.key).to_string(),
                    group: w.group.as_deref().map(str::to_owned),
                    group_from: w.origin.label().to_owned(),
                    pods: w
                        .pods
                        .iter()
                        .map(|p| telltale_api::model::WorkloadPod {
                            name: p.name.to_string(),
                            addresses: p.ips.iter().map(ToString::to_string).collect(),
                            terminating: p.deleted_s.is_some(),
                        })
                        .collect(),
                    queries_24h: q,
                    blocked_24h: blocked,
                    last_seen: (last > 0).then(|| format_us(last.saturating_mul(1_000_000))),
                    labels: w
                        .labels
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                }
            })
            .collect::<Vec<_>>();
        let mut items = items;
        // Workloads without pods now that asked in the last day (a CronJob between runs), named
        // from the history.
        for (key, c) in counts {
            let (q, blocked) = c.day(now);
            if q == 0 || t.by_key(key).is_some() {
                continue;
            }
            if let Some(info) = t.key_name(key).and_then(|text| past_workload(text, key)) {
                items.push(telltale_api::model::WorkloadInfo {
                    queries_24h: q,
                    blocked_24h: blocked,
                    last_seen: Some(format_us(c.last_seen_s.saturating_mul(1_000_000))),
                    ..info
                });
            }
        }
        Ok(items)
    }

    fn workload_counts(&self) -> Vec<telltale_api::model::WorkloadCount> {
        let now = crate::kubernetes::now_s();
        self.src
            .pipeline
            .telemetry
            .aggregates()
            .workload_counts()
            .iter()
            .map(|(k, c)| {
                let (q, b) = c.day(now);
                telltale_api::model::WorkloadCount {
                    key: std::net::Ipv6Addr::from(*k).to_string(),
                    queries_24h: q,
                    blocked_24h: b,
                    last_seen_unix_seconds: c.last_seen_s,
                }
            })
            .collect()
    }

    fn kubernetes_status(&self) -> telltale_api::model::KubernetesStatus {
        use crate::kubernetes::Role;
        let kube = &self.src.pipeline.kube;
        let st = kube.state();
        let now = crate::kubernetes::now_s();
        telltale_api::model::KubernetesStatus {
            enabled: self.src.config.load().kubernetes.enabled || st.role == Role::Fixture,
            role: match st.role {
                Role::Off => "off",
                Role::Peer => "peer",
                Role::Watching => "watching",
                Role::Fixture => "fixture",
            }
            .to_owned(),
            watching: st.role.watches(),
            last_sync_seconds_ago: kube.age_s(now),
            pods: st.pods as u64,
            workloads: st.workloads as u64,
            namespaces_watched: st.namespaces,
            last_error: st.last_error,
            source: st.source,
            addresses_dropped: kube.dropped.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    fn identity(&self, client: &str) -> Result<telltale_api::model::DeviceIdentity, Problem> {
        self.identity_of(client, true)
    }

    // REQ: FLT-006, CLU-002, API-010 (ADR-183) — what a node answers another node's identity read:
    // the identity without `recognition`, which only the entry node's own view uses, so it is not
    // computed here, nor are this node's MACs sent over the cluster channel.
    fn identity_for_peer(
        &self,
        client: &str,
    ) -> Result<telltale_api::model::DeviceIdentity, Problem> {
        self.identity_of(client, false)
    }

    // REQ: OBS-033 — this node's change markers.
    fn annotations(
        &self,
        f: &telltale_api::model::AnnotationFilter,
    ) -> Vec<telltale_api::model::Annotation> {
        crate::annotations::get().map_or_else(Vec::new, |a| a.read(f))
    }

    fn annotate(
        &self,
        a: telltale_api::model::Annotation,
    ) -> Result<telltale_api::model::Annotation, Problem> {
        let Some(store) = crate::annotations::get() else {
            return Err(Problem::unavailable(
                "change markers aren't open on this node yet",
            ));
        };
        store.append(a).map_err(|e| {
            Problem::unavailable(format!("the marker couldn't be written: {e}"))
                .hint("The node's data directory may be full or read-only; DNS is unaffected.")
        })
    }

    fn config_version(&self) -> u64 {
        self.src
            .auth
            .get()
            .and_then(|a| a.state().config_version().ok())
            .unwrap_or(0)
    }

    // REQ: OBS-013 — device anomalies with evidence.
    fn anomalies(&self, since_s: u64) -> Vec<telltale_api::model::AnomalyFinding> {
        let Some(a) = &self.src.anomalies else {
            return Vec::new();
        };
        // REQ: OBS-025 — findings say what the device looks like, when that's known.
        let snap = self.src.identify.snapshot();
        let mut items: Vec<telltale_api::model::AnomalyFinding> = a
            .findings_with_rhythm()
            .into_iter()
            .filter(|(f, _)| f.window_start_s >= since_s)
            .map(|(f, rhythm)| {
                let client = telltale_telemetry::agg::client_text(f.client);
                let kind = f.kind.label();
                let detail = match snap
                    .by_client
                    .get(&client)
                    .and_then(crate::identify::looks_like)
                {
                    Some(l) => format!("{} The device {l}.", f.detail),
                    None => f.detail,
                };
                telltale_api::model::AnomalyFinding {
                    // REQ: OBS-014 — the same ID on every node that finds it.
                    id: telltale_api::model::anomaly_id(
                        kind,
                        &client,
                        f.domain.as_deref(),
                        f.window_start_s,
                        f.window_s,
                    ),
                    kind: kind.to_owned(),
                    client,
                    client_name: device_name(&self.src, f.client),
                    domain: f.domain,
                    window_start: format_us(f.window_start_s.saturating_mul(1_000_000)),
                    window_seconds: f.window_s,
                    observed: f.observed,
                    baseline: f.baseline,
                    spread: f.spread,
                    threshold: f.threshold,
                    detail,
                    nodes: Vec::new(),
                    acknowledged: None,
                    // REQ: OBS-031 — a beacon's strip at report time.
                    rhythm: rhythm.map(|b| b.iter().map(|&n| u32::from(n)).collect()),
                    informational: f.kind.informational(),
                    muted_by: f.muted_by,
                    // REQ: OBS-038 (ADR-186) — a storm-only mute a counted sweep names.
                    storm_mute: f.storm_mute,
                }
            })
            .collect();
        self.annotate_acks(&mut items);
        items
    }

    // REQ: OBS-014 — this node's acknowledgements (the primary's, on a replica).
    fn annotate_acks(&self, items: &mut [telltale_api::model::AnomalyFinding]) {
        let Some(auth) = self.src.auth.get() else {
            return;
        };
        let Ok(acks) = auth.state().anomaly_acks() else {
            return;
        };
        let by_id: std::collections::HashMap<&str, &telltale_store::state::AnomalyAck> =
            acks.iter().map(|a| (a.id.as_str(), a)).collect();
        for f in items {
            f.acknowledged =
                by_id
                    .get(f.id.as_str())
                    .map(|a| telltale_api::model::AnomalyAckInfo {
                        by: a.by.clone(),
                        at: format_us(a.at.saturating_mul(1_000_000)),
                        note: a.note.clone(),
                    });
        }
    }

    // REQ: OBS-014 (ADR-103) — recorded here; a primary publishes the set with its next version.
    fn anomaly_ack(
        &self,
        w: telltale_api::AnomalyAckWrite,
    ) -> BoxFuture<Result<telltale_api::model::AnomalyAckResult, Problem>> {
        let auth = self.src.auth.get().cloned();
        Box::pin(async move {
            let Some(auth) = auth else {
                return Err(Problem::unavailable(
                    "this node's state database isn't open yet",
                ));
            };
            tokio::task::spawn_blocking(move || {
                let state = auth.state();
                let now = crate::pipeline::unix_now();
                let changed = if w.ack {
                    let acks: Vec<telltale_store::state::AnomalyAck> = w
                        .ids
                        .iter()
                        .filter_map(|id| {
                            Some(telltale_store::state::AnomalyAck {
                                id: id.clone(),
                                by: w.by.clone(),
                                at: now,
                                note: w.note.clone(),
                                window_start: telltale_api::model::anomaly_id_window(id)?,
                            })
                        })
                        .collect();
                    state.ack_anomalies(&acks, now)
                } else {
                    state.unack_anomalies(&w.ids)
                };
                changed
                    .map(|changed| telltale_api::model::AnomalyAckResult {
                        changed,
                        unknown: Vec::new(),
                    })
                    .map_err(|e| Problem::internal(format!("acknowledgements not saved: {e}")))
            })
            .await
            .map_err(|e| Problem::internal(format!("acknowledge worker failed: {e}")))?
        })
    }

    // REQ: OBS-015 (ADR-104) — this node's own conditions.
    // REQ: OBS-020 (ADR-107)
    fn probes(&self) -> Vec<telltale_api::model::ProbeResult> {
        self.src.probes.results()
    }

    // REQ: OBS-018 (ADR-109)
    fn shadow_lists(&self) -> Vec<telltale_api::model::ShadowListStats> {
        self.src
            .shadow
            .lists_view(&self.src.pipeline.current().policy.shadow_lists)
    }
    fn overblocking(&self, limit: usize) -> Vec<telltale_api::model::OverblockSuspect> {
        self.src.shadow.suspects_view(limit)
    }

    // REQ: OBS-019 (ADR-108)
    fn upstream_checks(&self) -> Vec<telltale_api::model::UpstreamChecks> {
        let names: Vec<(u16, String)> = self
            .src
            .pipeline
            .current()
            .router
            .upstreams()
            .iter()
            .map(|u| (u.id, u.name.clone()))
            .collect();
        vec![
            self.src
                .pipeline
                .quality
                .view(&self.src.config.load().upstream_check, &names),
        ]
    }

    // REQ: OBS-016 (ADR-105)
    fn slo_settings(&self) -> telltale_api::slo::Settings {
        crate::health::slo_settings(&self.src.config.load())
    }

    fn health(&self) -> telltale_api::model::Health {
        let now = crate::pipeline::unix_now();
        let recent = self.timeseries(Step::Minute, now.saturating_sub(300), now);
        let upstreams = self.upstreams();
        let lists = self.src.lists.load().is_some().then(|| self.lists());
        let disk_used_percent =
            self.src
                .host
                .latest()
                .and_then(|s| match (s.disk_total, s.disk_free) {
                    #[allow(clippy::cast_precision_loss)] // byte counts as a share
                    (Some(t), Some(f)) if t > 0 => {
                        Some(t.saturating_sub(f) as f64 * 100.0 / t as f64)
                    }
                    _ => None,
                });
        let probes = self.src.probes.results();
        let mut reasons = crate::health::local_reasons(&crate::health::Local {
            // REQ: OPS-010 — a node in maintenance still serves.
            serving: self.src.readiness.serving(),
            upstreams: &upstreams,
            recent: &recent,
            lists: lists.as_deref(),
            disk_used_percent,
            probes: &probes,
            cert_warn_days: self.src.config.load().probe.cert_warn_days,
            kubernetes_stale_s: {
                let now = crate::kubernetes::now_s();
                let k = &self.src.pipeline.kube;
                k.stale(now).then(|| k.age_s(now).unwrap_or(0))
            },
        });
        // REQ: OPS-010 — a standalone node in maintenance leaves its own conditions out (in a
        // cluster, the federated health does it from every node's heartbeats).
        let mut maintenance = Vec::new();
        if self.src.cluster.is_none()
            && let Some(w) = self.src.maintenance.current(crate::maintenance::now_ms())
        {
            reasons.clear();
            maintenance.push(crate::maintenance::api_window(
                &w.cluster_window(),
                crate::maintenance::now_ms(),
                Some(crate::maintenance::label(&self.src)),
            ));
        }
        // REQ: OBS-016 (ADR-105) — in a cluster the objectives cover every node, so the
        // federated health adds them once; a standalone node adds its own.
        if self.src.cluster.is_none() {
            reasons.extend(crate::health::slo_reasons(self, now));
        }
        let mut h = crate::health::summarize(
            reasons,
            Vec::new(),
            format_us(now.saturating_mul(1_000_000)),
        );
        h.maintenance = maintenance;
        h
    }

    // REQ: OPS-010 (ADR-118) — this node's own maintenance (in a cluster, the federated
    // backend sends requests for other nodes to them).
    fn maintenance(
        &self,
        node: &str,
        w: telltale_api::MaintenanceWrite,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::MaintenanceResult, Problem>> {
        crate::maintenance::local_backend_call(Arc::clone(&self.src), node, w)
    }

    // REQ: OPS-014 (ADR-182) — this node's own update state and requests (in a cluster, the
    // federated backend sends calls for other nodes to them).
    fn node_update(
        &self,
        node: &str,
        call: telltale_api::NodeUpdateCall,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::NodeUpdate, Problem>> {
        crate::node_update::local_backend_call(Arc::clone(&self.src), node, call)
    }

    // REQ: CLU-014 (ADR-151) — failover drills on this node (a cluster routes them first).
    fn drill(
        &self,
        node: &str,
        w: telltale_api::DrillWrite,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::DrillStart, Problem>> {
        let src = Arc::clone(&self.src);
        if let Err(p) = local_node(&src, node) {
            return Box::pin(async move { Err(p) });
        }
        Box::pin(async move { crate::drill::apply(src, w, None).await })
    }

    fn drill_active(
        &self,
        node: &str,
    ) -> telltale_api::BoxFuture<Result<Option<telltale_api::model::ActiveDrill>, Problem>> {
        let r = local_node(&self.src, node).map(|()| crate::drill::active(&self.src));
        Box::pin(async move { r })
    }

    fn drills(
        &self,
        limit: usize,
        offset: usize,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::DrillPage, Problem>> {
        let p = crate::drill::page(crate::drill::list(&self.src), limit, offset, Vec::new());
        Box::pin(async move { Ok(p) })
    }

    fn drill_report(
        &self,
        id: &str,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::DrillReport, Problem>> {
        let r = crate::drill::report(&self.src, id).ok_or_else(|| {
            Problem::not_found(format!("no drill `{id}`"))
                .hint("List them with GET /api/v1/drills.")
        });
        Box::pin(async move { r })
    }

    fn affinity(
        &self,
        days: u32,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::AffinityPage, Problem>> {
        let own = vec![(
            crate::maintenance::label(&self.src),
            crate::drill::seen_rows(&self.src, days),
        )];
        let p = crate::drill::affinity_page(days, own, Vec::new());
        Box::pin(async move { Ok(p) })
    }

    // REQ: CLU-013 (T13.2) — rollouts and pins: this node's publisher (the primary), or what
    // the version it applied says.
    fn rollout_status(
        &self,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::RolloutStatus, Problem>> {
        let r = crate::rollout::surface::status(&self.src);
        Box::pin(async move { r })
    }

    fn cluster_versions(
        &self,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::ClusterVersions, Problem>> {
        let r = crate::rollout::surface::versions(&self.src);
        Box::pin(async move { r })
    }

    fn rollout_command(
        &self,
        w: telltale_api::RolloutWrite,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::RolloutAction, Problem>> {
        let src = Arc::clone(&self.src);
        let version = self.config_version();
        Box::pin(async move { crate::rollout::surface::command(&src, version, w).await })
    }

    // REQ: OPS-008 (T7.19) — this node's DHCP leases.
    fn dhcp_leases(&self) -> Vec<telltale_api::model::DhcpLease> {
        // REQ: T8.2 — the routers' DHCP clients.
        let mut v: Vec<telltale_api::model::DhcpLease> = self
            .src
            .pipeline
            .router_leases
            .load()
            .values()
            .map(|l| telltale_api::model::DhcpLease {
                mac: l.mac.clone(),
                ip: l.ip.to_string(),
                hostname: l.hostname.clone(),
                client_name: device_name(&self.src, l.ip.to_ipv6_mapped().octets()),
                expires_unix_seconds: l.expires,
                source: "router".to_owned(),
            })
            .collect();
        // REQ: T8.3, T8.6 — and the names devices announce over mDNS (routers win).
        let known: std::collections::HashSet<String> = v.iter().map(|l| l.ip.clone()).collect();
        for l in self.src.pipeline.mdns_names.load().values() {
            if known.contains(&l.ip.to_string()) {
                continue;
            }
            v.push(telltale_api::model::DhcpLease {
                mac: String::new(),
                ip: l.ip.to_string(),
                hostname: l.hostname.clone(),
                client_name: device_name(&self.src, l.ip.to_ipv6_mapped().octets()),
                expires_unix_seconds: 0,
                source: "mdns".to_owned(),
            });
        }
        v.sort_by_key(|l| l.ip.parse::<std::net::Ipv4Addr>().map_or(0, u32::from));
        v
    }

    // REQ: OBS-010 (T9.6) — what the alert task last saw and sent.
    fn alerts_status(&self) -> telltale_api::model::AlertsStatus {
        self.src
            .alerts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    // REQ: OBS-010 (T9.6) — a test message to one destination, sent from this node.
    fn alert_test(
        &self,
        name: &str,
        by_admin: bool,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::AlertTest, Problem>> {
        let cfg = self.src.config.load_full();
        let d = cfg
            .alerts
            .destination
            .iter()
            .find(|d| d.name.as_str() == name)
            .cloned();
        let node = crate::http::node_name(&cfg);
        let name = name.to_owned();
        let src = Arc::clone(&self.src);
        Box::pin(async move {
            let d =
                d.ok_or_else(|| Problem::not_found(format!("no alert destination `{name}`")))?;
            // REQ: OBS-010 (ADR-179) — a destination made through the API whose credential file
            // isn't in a folder meant for secrets isn't read or sent to; the answer says why.
            let refused = tokio::task::spawn_blocking(move || {
                crate::alerts::refused(&cfg, &crate::alerts::own_destinations(&src))
            })
            .await
            .map_err(|e| Problem::internal(format!("request worker failed: {e}")))?;
            let r = match refused.get(d.name.as_str()) {
                Some(why) => Err(why.clone()),
                None => crate::alerts::send_test(&d, &node).await,
            };
            // REQ: OBS-010 (ADR-180) — what went wrong reading the private CA file (a line of it,
            // whether it is there) is an administrator's to see; the node's log has it.
            let r = r.map_err(|e| match &d.tls_ca {
                Some(ca) if !by_admin && e.contains(ca.as_str()) => {
                    tracing::info!(destination = %d.name, error = %e, "test send: the private CA file couldn't be used");
                    "the private CA file (`tls_ca`) couldn't be used; an administrator sees why, and the node's log says".to_owned()
                }
                _ => e,
            });
            Ok(telltale_api::model::AlertTest {
                ok: r.is_ok(),
                error: r.err(),
            })
        })
    }

    // REQ: API-002 (T9.12) — a draft upstream asked the root's NS records, as health checks do.
    fn check_upstream(
        &self,
        body: serde_json::Value,
        by_admin: bool,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::CheckResult, Problem>> {
        let cfg = self.src.config.load_full();
        Box::pin(async move { crate::checks::upstream(&cfg, body, by_admin).await })
    }

    // REQ: API-002 (T9.12) — a draft list downloaded (or its rules taken) and parsed.
    fn check_list(
        &self,
        body: serde_json::Value,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::CheckResult, Problem>> {
        let cfg = self.src.config.load_full();
        Box::pin(async move { crate::checks::list(&cfg, body).await })
    }

    // REQ: OBS-024 (T13.1) — a candidate shared configuration against the one in effect, over
    // the cluster's logs (this node fans out itself: `simulate::simulate`).
    fn simulate(
        &self,
        config: serde_json::Value,
        opts: telltale_api::SimulateOpts,
        by_admin: bool,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::Simulation, Problem>> {
        let src = Arc::clone(&self.src);
        let mut config = config;
        if let Some(o) = config.as_object_mut() {
            for k in telltale_config::shared::NODE_LOCAL {
                o.remove(*k);
            }
        }
        Box::pin(async move {
            let current = src.config.load_full();
            let candidate = telltale_config::shared::with_shared(&src.file_config.load(), &config)
                .map_err(|errs| {
                    Problem::new(
                        Code::InvalidConfig,
                        errs.iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join("; "),
                    )
                    .hint(
                        "Send the shared sections as JSON, as a Git commit's shared TOML becomes.",
                    )
                })?;
            // REQ: OBS-024 (ADR-180) — below admin, refused before anything is read.
            if !by_admin && let Some(field) = crate::simulate::new_local_name(&current, &candidate)
            {
                return Err(crate::simulate::local_name_refused(&field));
            }
            crate::simulate::simulate(&src, current, Arc::new(candidate), &opts)
                .await
                .map(Option::unwrap_or_default)
        })
    }

    // REQ: CLU-002 (ADR-125)
    fn client_name(&self, ip: IpAddr) -> Option<String> {
        let v6 = match ip {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        };
        device_name(&self.src, v6.octets())
    }

    // REQ: OBS-010 (T9.5) — devices this node's anomaly engine met for the first time.
    fn new_devices(&self, since_s: u64) -> Vec<telltale_api::model::NewDevice> {
        let Some(a) = &self.src.anomalies else {
            return Vec::new();
        };
        a.new_clients(since_s)
            .into_iter()
            .map(|(ip, first)| telltale_api::model::NewDevice {
                client: telltale_telemetry::agg::client_text(ip),
                client_name: device_name(&self.src, ip),
                first_seen_unix_seconds: first,
            })
            .collect()
    }

    // REQ: AGT-012 (T8.4) — vqlog over this node's query log and the logs shipped to it.
    fn vqlog(
        &self,
        q: &telltale_api::vqlog::Query,
        from_us: u64,
        to_us: u64,
        dry_run: bool,
    ) -> Result<telltale_api::model::VqlogResult, Problem> {
        // REQ: AGT-012 (T9.12) — past what the query log keeps (or with it off), counts by
        // one breakdown come from the rollups.
        let cfg = self.src.config.load();
        let kept_from_us = self
            .now_unix_seconds()
            .saturating_sub(u64::from(cfg.telemetry.qlog.retention_days) * 86_400)
            .saturating_mul(1_000_000);
        let beyond = from_us < kept_from_us || self.src.qlog.is_none();
        let dim = crate::vqlog::rollup_dim(q);
        if beyond
            && self.src.rollups.is_some()
            && let Some(dim) = dim
        {
            let step = if q.bucket_secs.is_some_and(|b| b.is_multiple_of(86_400)) {
                Step::Day
            } else {
                Step::Hour
            };
            let buckets = if dry_run {
                Vec::new()
            } else {
                self.counts(step, from_us / 1_000_000, to_us.div_ceil(1_000_000))
            };
            let no_names = |_: [u8; 16]| None;
            let ctx = crate::vqlog::Ctx {
                groups: self
                    .src
                    .pipeline
                    .current()
                    .policy
                    .clients
                    .groups()
                    .iter()
                    .map(|g| g.name.to_string())
                    .collect(),
                upstreams: std::collections::HashMap::new(),
                client_name: &no_names,
                // Rollups keep no clients.
                workload_spans: &|_| None,
                qtype_name,
                rcode_name,
                rcode_value,
            };
            return crate::vqlog::run_rollups(q, dim, &buckets, &ctx);
        }
        drop(cfg);
        if self.src.qlog.is_none() {
            return Err(
                Problem::unavailable("the query log is off on this node").hint(
                    "Enable it with [telemetry.qlog] enabled = true (and privacy_level below 3).",
                ),
            );
        }
        let data_dir = self.src.config.load().node.data_dir.to_string();
        let mut dirs = vec![Path::new(&data_dir).join("qlog")];
        dirs.extend(
            crate::ship::shipped_dirs(&data_dir)
                .into_iter()
                .map(|(_, d)| d),
        );
        let groups = self
            .src
            .pipeline
            .current()
            .policy
            .clients
            .groups()
            .iter()
            .map(|g| g.name.to_string())
            .collect();
        let upstreams = self
            .upstreams()
            .into_iter()
            .map(|u| (u.id, u.name))
            .collect();
        let name = |ip: [u8; 16]| device_name(&self.src, ip);
        let ctx = crate::vqlog::Ctx {
            groups,
            upstreams,
            client_name: &name,
            workload_spans: &|c| workload_spans(&self.src, c),
            qtype_name,
            rcode_name,
            rcode_value,
        };
        let opts = qlog::Options {
            threads: std::thread::available_parallelism().map_or(1, |n| n.get().min(4)),
            on_thread_start: Some(telltale_net::background_thread),
        };
        let mut r = crate::vqlog::run(q, from_us, to_us, &dirs, &ctx, dry_run, &opts)?;
        if beyond {
            r.note = Some(format!(
                "The query log keeps {} days: this covers those. Counts by one of status, qtype, rcode, proto, or group (with buckets of 1h or more) reach further, from the rollups.",
                self.src.config.load().telemetry.qlog.retention_days
            ));
        }
        Ok(r)
    }

    // REQ: OBS-009 (T7.14) — first-seen domains with their DGA scores.
    fn new_domains(
        &self,
        since_s: u64,
        client: Option<&str>,
        limit: usize,
    ) -> Vec<telltale_api::model::NewDomain> {
        let Some(a) = &self.src.anomalies else {
            return Vec::new();
        };
        let want = client.map(str::trim).filter(|c| !c.is_empty());
        a.new_domains(since_s, usize::MAX)
            .into_iter()
            .map(|d| (telltale_telemetry::agg::client_text(d.client), d))
            .filter(|(c, _)| want.is_none_or(|w| w == c))
            .take(limit)
            .map(|(c, d)| telltale_api::model::NewDomain {
                time: format_us(d.ts_s.saturating_mul(1_000_000)),
                client: c,
                client_name: device_name(&self.src, d.client),
                domain: d.domain,
                dga_score: (d.dga_score * 100.0).round() / 100.0,
            })
            .collect()
    }

    // REQ: API-011 — names on my network and domains sent elsewhere (ADR-042).
    fn local_names(&self) -> Vec<LocalName> {
        self.list_local_names()
    }

    // REQ: DNS-018 (T8.6) — the zones as loaded.
    fn zones(&self) -> Vec<telltale_api::model::ZoneInfo> {
        let cfg = self.src.config.load();
        let mut v: Vec<telltale_api::model::ZoneInfo> = self
            .src
            .pipeline
            .current()
            .policy
            .zones
            .iter()
            .map(|z| {
                let name = z
                    .apex
                    .display()
                    .to_string()
                    .trim_end_matches('.')
                    .to_owned();
                let file = cfg
                    .zone
                    .iter()
                    .find(|c| {
                        c.name
                            .as_str()
                            .trim_end_matches('.')
                            .eq_ignore_ascii_case(&name)
                    })
                    .and_then(|c| c.file.as_ref().map(ToString::to_string));
                telltale_api::model::ZoneInfo {
                    groups: z.groups.iter().map(ToString::to_string).collect(),
                    records: z.data.len() as u64,
                    file,
                    negative_ttl_seconds: z.negative_ttl,
                    name,
                }
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    fn forwards(&self) -> Vec<ForwardInfo> {
        self.list_forwards()
    }

    // REQ: DNS-006 (T6.13) — this node's cache.
    fn cache_stats(&self) -> Vec<telltale_api::model::CacheNodeStats> {
        let s = self.src.cache.stats();
        // REQ: OBS-021 (T11.2) — whether the cache is the right size.
        let sizing = crate::cache_sizing::advise(&s, self.src.cache.policy().max_bytes as u64);
        let looked = s.hits + s.misses;
        #[allow(clippy::cast_precision_loss)] // a percentage for display
        let hit_percent =
            (looked > 0).then(|| (s.hits as f64 / looked as f64 * 1000.0).round() / 10.0);
        // REQ: DNS-007 — an expired entry answered (refreshed or stale) counts as a miss in the
        // cache's own counters; answered from the cache all the same.
        #[allow(clippy::cast_precision_loss)]
        let answered_percent = (looked > 0).then(|| {
            ((s.hits + s.stale_served).min(looked) as f64 / looked as f64 * 1000.0).round() / 10.0
        });
        vec![telltale_api::model::CacheNodeStats {
            node: None,
            entries: s.entries as u64,
            bytes: s.bytes as u64,
            hits: s.hits,
            misses: s.misses,
            hit_percent,
            answered_percent,
            stale_served: s.stale_served,
            prefetches: s.prefetches,
            evictions: s.evictions,
            inserts: s.inserts,
            uncacheable: s.uncacheable,
            settings: Some(cache_settings(&self.src.config.load().cache)),
            warm_start: self.src.cache_history.warm_start(),
            history: self.src.cache_history.points(),
            sizing: Some(sizing),
        }]
    }

    // REQ: API-002 (T7.5, ADR-069) — upstreams, upstream groups, lists, and groups in effect,
    // with their sources (hidden files' entries included, so they can be brought back).
    // T9.6/T9.7: alert destinations and rules, and schedules too.
    #[allow(clippy::too_many_lines)] // one branch per kind of entry
    fn config_entries(&self, kind: Option<&str>) -> Vec<telltale_api::model::ConfigEntry> {
        use crate::managed::{Named, Ovr};
        fn rows<T: Named + Serialize>(
            kind: &str,
            effective: &[T],
            file: &[T],
            stored: &[(String, Ovr<T>)],
            out: &mut Vec<telltale_api::model::ConfigEntry>,
        ) {
            let in_file = |n: &str| file.iter().any(|f| f.name() == n);
            for e in effective {
                let n = e.name();
                let api = stored.iter().any(|(s, _)| s == n);
                out.push(telltale_api::model::ConfigEntry {
                    kind: kind.to_owned(),
                    name: n.to_owned(),
                    source: match (api, in_file(n)) {
                        (true, true) => "override",
                        (true, false) => "added",
                        _ => "file",
                    }
                    .to_owned(),
                    definition: serde_json::to_value(e).ok(),
                    credentials: None,
                });
            }
            for (n, o) in stored {
                if matches!(o, Ovr::Hidden) {
                    out.push(telltale_api::model::ConfigEntry {
                        kind: kind.to_owned(),
                        name: n.clone(),
                        source: "hidden".to_owned(),
                        definition: None,
                        credentials: None,
                    });
                }
            }
        }
        let cfg = self.src.config.load();
        let file = self.src.file_config.load();
        let e = self
            .src
            .auth
            .get()
            .map(|a| crate::managed::entries(a.state()))
            .unwrap_or_default();
        let want = |k: &str| kind.is_none_or(|w| w == k);
        let mut out = Vec::new();
        if want("upstream") {
            // Upstreams a forwarded domain made are part of that domain, not listed here.
            let up: Vec<_> = cfg
                .upstream
                .iter()
                .filter(|u| !u.name.as_str().starts_with("forward:"))
                .cloned()
                .collect();
            rows("upstream", &up, &file.upstream, &e.upstreams, &mut out);
        }
        if want("upstream_group") {
            let g: Vec<_> = cfg
                .upstream_group
                .iter()
                .filter(|u| !u.name.as_str().starts_with("forward:"))
                .cloned()
                .collect();
            rows(
                "upstream_group",
                &g,
                &file.upstream_group,
                &e.upstream_groups,
                &mut out,
            );
        }
        if want("list") {
            rows("list", &cfg.list, &file.list, &e.lists, &mut out);
        }
        if want("group") {
            rows("group", &cfg.group, &file.group, &e.groups, &mut out);
        }
        // REQ: OBS-010 (T9.6)
        if want("alert_destination") {
            rows(
                "alert_destination",
                &cfg.alerts.destination,
                &file.alerts.destination,
                &e.alert_destinations,
                &mut out,
            );
        }
        // REQ: DNS-014 (review 01 q1) — the one rate limit in effect, and whether the API or UI
        // replaced the files'.
        if want("ratelimit") {
            out.push(telltale_api::model::ConfigEntry {
                kind: "ratelimit".to_owned(),
                name: "default".to_owned(),
                source: if e.ratelimit.is_some() {
                    "override"
                } else {
                    "file"
                }
                .to_owned(),
                definition: serde_json::to_value(&cfg.ratelimit).ok(),
                credentials: None,
            });
        }
        // REQ: OBS-022 (T12.1) — likewise, the exclusions.
        if want("exclusions") {
            out.push(telltale_api::model::ConfigEntry {
                kind: "exclusions".to_owned(),
                name: "default".to_owned(),
                source: if e.exclusions.is_some() {
                    "override"
                } else {
                    "file"
                }
                .to_owned(),
                definition: serde_json::to_value(&cfg.exclusions).ok(),
                credentials: None,
            });
        }
        // REQ: CLU-013 (T13.2) — likewise, the rollout settings.
        if want("rollout") {
            out.push(telltale_api::model::ConfigEntry {
                kind: "rollout".to_owned(),
                name: "default".to_owned(),
                source: if e.rollout.is_some() {
                    "override"
                } else {
                    "file"
                }
                .to_owned(),
                definition: serde_json::to_value(&cfg.cluster.rollout).ok(),
                credentials: None,
            });
        }
        // REQ: OBS-024 (T13.1) — likewise, the simulation settings.
        if want("simulate") {
            out.push(telltale_api::model::ConfigEntry {
                kind: "simulate".to_owned(),
                name: "default".to_owned(),
                source: if e.simulate.is_some() {
                    "override"
                } else {
                    "file"
                }
                .to_owned(),
                definition: serde_json::to_value(&cfg.simulate).ok(),
                credentials: None,
            });
        }
        // REQ: FLT-010 (T9.7)
        if want("schedule") {
            rows(
                "schedule",
                &cfg.schedule,
                &file.schedule,
                &e.schedules,
                &mut out,
            );
        }
        // REQ: T8.2 (ADR-181) — the definitions name files, never the secrets themselves. REQ:
        // API-002, T8.2 (ADR-181) — each router's credentials have a status that takes no secret
        // to read: saved, missing (enter it again), or not used on this node.
        if want("router") {
            let start = out.len();
            rows("router", &cfg.router, &file.router, &e.routers, &mut out);
            let check = crate::router_secrets::UseCheck::load(&self.src);
            for entry in &mut out[start..] {
                entry.credentials = entry
                    .definition
                    .as_ref()
                    .and_then(|d| {
                        serde_json::from_value::<telltale_config::RouterConfig>(d.clone()).ok()
                    })
                    .map(|r| check.status(&r));
            }
        }
        // REQ: OBS-038
        if want("anomaly_mute") {
            rows(
                "anomaly_mute",
                &cfg.anomaly_mute,
                &file.anomaly_mute,
                &e.anomaly_mutes,
                &mut out,
            );
        }
        if want("alert_rule") {
            rows(
                "alert_rule",
                &cfg.alerts.rule,
                &file.alerts.rule,
                &e.alert_rules,
                &mut out,
            );
        }
        out
    }

    // REQ: OPS-004 (ADR-046) — "Check now" in Settings.
    fn check_updates(
        &self,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::UpdateStatus, Problem>> {
        let cfg = self.src.config.load();
        let fut = crate::updates::check_now(
            Arc::clone(&self.src.update),
            cfg.updates.check,
            cfg.updates.index_url.as_ref().map(ToString::to_string),
        );
        Box::pin(async move { Ok(fut.await) })
    }

    // REQ: FLT-012 (T7.9) — the blockable services catalog.
    fn services(&self) -> Vec<telltale_api::model::ServiceInfo> {
        telltale_config::services::catalog()
            .iter()
            .map(|s| telltale_api::model::ServiceInfo {
                id: s.id.clone(),
                name: s.name.clone(),
                category: s.category.clone(),
                domains: s
                    .rules
                    .iter()
                    .map(|r| r.trim_start_matches("||").trim_end_matches('^').to_owned())
                    .collect(),
            })
            .collect()
    }

    // REQ: FLT-009 (T7.1) — this node's pauses.
    fn blocking_state(&self) -> Vec<telltale_api::model::BlockingNode> {
        let now = crate::pipeline::unix_now();
        let mut pauses: Vec<telltale_api::model::PauseInfo> = self
            .src
            .pipeline
            .pause
            .active(now)
            .into_iter()
            .map(|(group, until)| telltale_api::model::PauseInfo {
                group: group.map(|g| g.to_string()),
                until: telltale_api::time::format_us(until.saturating_mul(1_000_000)),
                seconds_left: until.saturating_sub(now),
            })
            .collect();
        pauses.sort_by(|a, b| a.group.cmp(&b.group));
        vec![telltale_api::model::BlockingNode {
            node: None,
            pauses,
            error: None,
        }]
    }

    fn blocking_pause(
        &self,
        group: Option<&str>,
        minutes: u32,
        _node: Option<&str>,
    ) -> Result<Vec<telltale_api::model::BlockingNode>, Problem> {
        let until = crate::pipeline::unix_now() + u64::from(minutes) * 60;
        match group {
            Some(g) => {
                self.known_group(g)?;
                self.src.pipeline.pause.pause_group(g, until);
            }
            None => self.src.pipeline.pause.pause_all(until),
        }
        Ok(self.blocking_state())
    }

    fn blocking_resume(
        &self,
        group: Option<&str>,
        _node: Option<&str>,
    ) -> Result<Vec<telltale_api::model::BlockingNode>, Problem> {
        let pause = &self.src.pipeline.pause;
        if let Some(g) = group {
            self.known_group(g)?;
            pause.pause_group(g, 0);
        } else {
            // Every pause: everyone's and each group's.
            pause.pause_all(0);
            let groups = pause.active(crate::pipeline::unix_now());
            for g in groups.into_iter().filter_map(|(g, _)| g) {
                pause.pause_group(&g, 0);
            }
        }
        Ok(self.blocking_state())
    }

    // REQ: DNS-006, OBS-003 (T6.15) — this node's top entries and makeup.
    fn cache_entries(
        &self,
        sort: &str,
        limit: usize,
        _node: Option<&str>,
    ) -> Result<Vec<telltale_api::model::CacheNodeEntries>, Problem> {
        use telltale_cache::TopBy;
        let by = match sort {
            "bytes" => TopBy::Bytes,
            "expiring" => TopBy::Expiring,
            "hits" => TopBy::Hits,
            other => return Err(Problem::invalid(format!("`sort`: `{other}`"))),
        };
        let (top, m) = self.src.cache.top(by, limit, std::time::Instant::now());
        Ok(vec![telltale_api::model::CacheNodeEntries {
            node: None,
            makeup: telltale_api::model::CacheMakeup {
                positive: m.positive,
                nxdomain: m.nxdomain,
                nodata: m.nodata,
                servfail: m.servfail,
                stale: m.stale,
                validated: m.validated,
            },
            entries: top
                .into_iter()
                .map(|t| {
                    let mut name = telltale_proto::NameBuf::default();
                    let shown = telltale_proto::read_name_uncompressed(&t.name, 0, &mut name)
                        .map_or_else(|_| "?".to_owned(), |_| name.display().to_string());
                    let e = t.info;
                    telltale_api::model::CacheTopEntry {
                        name: shown,
                        qtype: qtype_name(e.qtype),
                        rcode: rcode_name(e.rcode),
                        answers: e.answers,
                        authentic: e.authentic,
                        dnssec_ok: e.dnssec_ok,
                        ttl_left_seconds: i64::from(e.ttl) - i64::from(e.age_secs),
                        age_seconds: u64::from(e.age_secs),
                        bytes: e.bytes as u64,
                        hits: e.hits,
                    }
                })
                .collect(),
            error: None,
        }])
    }

    fn cache_lookup(&self, name: &str) -> Result<Vec<telltale_api::model::CacheEntry>, Problem> {
        let n = telltale_proto::NameBuf::from_presentation(name.trim())
            .map_err(|e| Problem::invalid(format!("`name`: {e}")))?;
        let now = std::time::Instant::now();
        Ok(self
            .src
            .cache
            .inspect(&n, now)
            .into_iter()
            .map(|e| telltale_api::model::CacheEntry {
                node: None,
                qtype: qtype_name(e.qtype),
                rcode: rcode_name(e.rcode),
                answers: e.answers,
                authentic: e.authentic,
                dnssec_ok: e.dnssec_ok,
                checking_disabled: e.checking_disabled,
                ttl_left_seconds: i64::from(e.ttl) - i64::from(e.age_secs),
                age_seconds: u64::from(e.age_secs),
                bytes: e.bytes as u64,
                hits: e.hits,
            })
            .collect())
    }

    fn cache_flush(
        &self,
        name: Option<&str>,
        subtree: bool,
        _node: Option<&str>,
    ) -> Result<Vec<telltale_api::model::CacheFlushNode>, Problem> {
        let removed = match name {
            Some(n) => {
                let n = telltale_proto::NameBuf::from_presentation(n.trim())
                    .map_err(|e| Problem::invalid(format!("`name`: {e}")))?;
                self.src.cache.flush_name(&n, subtree)
            }
            None => self.src.cache.flush_all_counted(),
        };
        Ok(vec![telltale_api::model::CacheFlushNode {
            node: None,
            removed: Some(removed as u64),
            error: None,
        }])
    }

    // REQ: FLT-005 (T6.12) — quick rules in effect, with how long each has left.
    fn rules(&self) -> Vec<telltale_api::model::RuleInfo> {
        let cfg = self.src.config.load();
        let file = self.src.file_config.load();
        let now = unix_now_secs();
        let mut out: Vec<telltale_api::model::RuleInfo> = cfg
            .rule
            .iter()
            .map(|r| {
                let at = r
                    .expires
                    .as_deref()
                    .and_then(telltale_config::parse_rfc3339);
                telltale_api::model::RuleInfo {
                    id: r.id.to_string(),
                    action: if r.action == telltale_config::RuleAction::Allow {
                        "allow"
                    } else {
                        "block"
                    }
                    .to_owned(),
                    domain: r.domain.to_string(),
                    devices: r.devices.iter().map(ToString::to_string).collect(),
                    groups: r.groups.iter().map(ToString::to_string).collect(),
                    expires: r.expires.as_ref().map(ToString::to_string),
                    expires_in_seconds: at.map(|a| u64::try_from(a - now).unwrap_or(0)),
                    note: r.note.as_ref().map(ToString::to_string),
                    created_by: r.created_by.as_ref().map(ToString::to_string),
                    created: r.created.as_ref().map(ToString::to_string),
                    source: if file.rule.iter().any(|f| f.id == r.id) {
                        "file"
                    } else {
                        "api"
                    }
                    .to_owned(),
                }
            })
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    // REQ: CLU-003 (ADR-049) — a push webhook checks the Git source at once.
    fn git_hook(&self, signature: Option<String>, body: Vec<u8>) -> Result<(), Problem> {
        let cfg = self.src.config.load();
        if cfg.cluster.git.is_none() {
            return Err(Problem::not_found(
                "this node has no Git configuration source",
            ));
        }
        crate::gitsource::webhook_ok(&cfg, signature.as_deref(), &body).map_err(|e| {
            Problem::new(Code::Unauthorized, e).hint(
                "Set the webhook's secret to the contents of [cluster.git] webhook_secret_file.",
            )
        })?;
        self.src.git_poke.notify_one();
        Ok(())
    }

    fn write_managed(&self, w: ManagedWrite) -> BoxFuture<Result<ConfigChange, Problem>> {
        if let Some(p) = self.replica_read_only() {
            return Box::pin(async move { Err(p) });
        }
        // REQ: CLU-013 — a pinned cluster publishes nothing new: changes wait for the unpin (a
        // dry run still shows what one would do).
        if !w.dry_run
            && let Some(p) = crate::rollout::surface::pinned_problem(&self.src)
        {
            return Box::pin(async move { Err(p) });
        }
        self.do_write_managed(w)
    }

    // REQ: API-002, API-010 — devices named through the API (ADR-040).
    fn write_client(&self, w: ClientWrite) -> BoxFuture<Result<ClientChange, Problem>> {
        if let Some(p) = self.replica_read_only() {
            return Box::pin(async move { Err(p) });
        }
        // REQ: CLU-013 — as for the other configuration changes.
        if !w.dry_run
            && let Some(p) = crate::rollout::surface::pinned_problem(&self.src)
        {
            return Box::pin(async move { Err(p) });
        }
        let src = Arc::clone(&self.src);
        Box::pin(async move {
            // REQ: API-002, API-010 (ADR-040) — one change at a time: the plan below is
            // checked against what the store then changes, and the result is applied before
            // the next write looks (two writes planned on the same snapshot could each be
            // valid and together not: the reload would then fall back to the files alone).
            let one_at_a_time = src.config_writes.lock().await;
            let state = src
                .auth
                .get()
                .map(|a| Arc::clone(a.state()))
                .ok_or_else(|| Problem::unavailable("the state database isn't open yet"))?;
            let (plan, current) = {
                let (src, state, w) = (Arc::clone(&src), Arc::clone(&state), w.clone());
                tokio::task::spawn_blocking(move || {
                    let current = state
                        .config_version()
                        .map_err(|e| Problem::internal(e.to_string()))?;
                    plan_client(&src, &state, &w).map(|p| (p, current))
                })
                .await
                .map_err(|e| Problem::internal(format!("request worker failed: {e}")))??
            };
            let change = |applied, version| ClientChange {
                applied,
                config_version: version,
                before: plan.before.clone(),
                after: plan
                    .after
                    .as_ref()
                    .map(|c| client_info(c, &[c.name.to_string()])),
                recent_queries: plan.recent_queries,
                impact: plan.impact.clone(),
                warnings: plan.warnings.clone(),
                simulation: None,
            };
            if w.dry_run {
                if let Some(v) = w.expect
                    && v != current
                {
                    return Err(version_conflict(current));
                }
                let mut out = change(false, current);
                // REQ: OBS-024 — `simulate`: what the device change would have done. Other
                // writes needn't wait for the replay.
                drop(one_at_a_time);
                if let Some(opts) = &w.simulate {
                    out.simulation = crate::simulate::simulate(
                        &src,
                        Arc::clone(&plan.baseline),
                        Arc::clone(&plan.candidate),
                        opts,
                    )
                    .await?;
                }
                return Ok(out);
            }
            let stored = {
                let (state, w, after) = (Arc::clone(&state), w.clone(), plan.after.clone());
                tokio::task::spawn_blocking(move || {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs());
                    match &after {
                        Some(c) => {
                            let body = serde_json::to_string(c).unwrap_or_default();
                            let from = (c.name.as_str() != w.name).then_some(w.name.as_str());
                            state.put_managed(
                                crate::managed::CLIENT,
                                c.name.as_str(),
                                &body,
                                from,
                                w.expect,
                                now,
                                &w.by,
                            )
                        }
                        None => state.delete_managed(crate::managed::CLIENT, &w.name, w.expect),
                    }
                })
                .await
                .map_err(|e| Problem::internal(format!("request worker failed: {e}")))?
            };
            let version = stored.map_err(|e| match e {
                ManagedError::VersionConflict { current } => version_conflict(current),
                ManagedError::NotFound { .. } => Problem::not_found(e.to_string()),
                ManagedError::State(e) => Problem::internal(e.to_string()),
            })?;
            // Apply: the main loop re-reads the files and state.db, validates, and swaps.
            provenance(&w.by, version);
            let (tx, rx) = tokio::sync::oneshot::channel();
            let applied = src.reload.send(tx).await.is_ok() && rx.await.unwrap_or(false);
            if !applied {
                return Err(Problem::internal(
                    "the change was saved but couldn't be applied; the server log says why",
                ));
            }
            Ok(change(true, version))
        })
    }

    fn upstreams(&self) -> Vec<UpstreamInfo> {
        let cfg = self.src.config.load();
        let router = Arc::clone(&self.src.pipeline.current().router);
        router
            .upstreams()
            .iter()
            .map(|u| {
                let h = u.health.snapshot();
                UpstreamInfo {
                    id: u.id,
                    name: u.name.clone(),
                    endpoint: u.endpoint.to_string(),
                    groups: cfg
                        .upstream_group
                        .iter()
                        .filter(|g| g.members.iter().any(|m| **m == *u.name))
                        .map(|g| g.name.to_string())
                        .collect(),
                    breaker: match h.breaker {
                        Breaker::Closed => "closed",
                        Breaker::HalfOpen => "half_open",
                        Breaker::Open => "open",
                    }
                    .to_owned(),
                    requests: h.requests,
                    failures: h.failures,
                    failures_by_kind: failure_kinds(h.failures_by_kind),
                    latency_ewma_ms: h.ewma.map_or(0.0, |d| {
                        ms(u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
                    }),
                }
            })
            .collect()
    }
}

/// REQ: UPS-006, OBS-011 — the health tracker's per-kind counts (in `Outcome::FAILURES` order)
/// as the API's named fields.
fn failure_kinds(counts: [u64; telltale_upstream::health::FAILURE_KINDS]) -> FailureKinds {
    use telltale_upstream::health::Outcome;
    let mut k = FailureKinds::default();
    for (kind, n) in Outcome::FAILURES.iter().zip(counts) {
        match kind {
            Outcome::Timeout => k.timeout = n,
            Outcome::Network => k.network = n,
            Outcome::BadResponse => k.bad_response = n,
            Outcome::Unresolved => k.unresolved = n,
            Outcome::ServFail => k.servfail = n,
            Outcome::Refused => k.refused = n,
            Outcome::OtherRcode => k.other_rcode = n,
            Outcome::Ok => {}
        }
    }
    k
}

/// Names of the devices stored through the API.
fn managed_names(src: &Sources) -> Vec<String> {
    src.auth
        .get()
        .and_then(|a| a.state().managed(crate::managed::CLIENT).ok())
        .map(|m| m.into_iter().map(|e| e.name).collect())
        .unwrap_or_default()
}

fn client_info(c: &telltale_config::ClientConfig, managed: &[String]) -> ClientInfo {
    ClientInfo {
        name: c.name.to_string(),
        matches: c.match_keys.iter().map(ToString::to_string).collect(),
        groups: c.groups.iter().map(ToString::to_string).collect(),
        source: if managed.iter().any(|m| m == c.name.as_str()) {
            "api".to_owned()
        } else {
            "file".to_owned()
        },
        effective_groups: c.groups.iter().map(ToString::to_string).collect(),
        groups_from: "device".to_owned(),
        kind: c.kind.map(|k| k.as_str().to_owned()),
        identity: None,
    }
}

/// REQ: OBS-025 — the single addresses a named device is matched by, as the query log shows
/// them (`192.168.1.20`, `10.0.0.5/32`; not networks, MACs, or client IDs).
fn device_addresses(c: &telltale_config::ClientConfig) -> Vec<String> {
    c.match_keys
        .iter()
        .filter_map(|k| {
            let k = k.as_str().trim();
            let k = k
                .strip_suffix("/32")
                .or_else(|| k.strip_suffix("/128"))
                .unwrap_or(k);
            k.parse::<IpAddr>().ok()
        })
        .map(|ip| {
            let o = match ip {
                IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
                IpAddr::V6(v6) => v6.octets(),
            };
            telltale_telemetry::agg::client_text(o)
        })
        .collect()
}

/// The groups that apply to a configured device and where they come from (ADR-050): its
/// own, else the network group of the first address or subnet it's matched by, else the
/// default. A device known only by MAC or client ID gets its group from wherever it's seen.
fn effective_groups(
    clients: &telltale_policy::ClientTable,
    c: &telltale_config::ClientConfig,
) -> (Vec<String>, &'static str) {
    if !c.groups.is_empty() {
        return (c.groups.iter().map(ToString::to_string).collect(), "device");
    }
    let names = |g: u16| {
        clients
            .groups()
            .get(usize::from(g))
            .map(|g| vec![g.name.to_string()])
            .unwrap_or_default()
    };
    let mut addressed = false;
    for key in &c.match_keys {
        let ip = key.split('/').next().and_then(|a| a.parse::<IpAddr>().ok());
        if let Some(ip) = ip {
            addressed = true;
            if let Some(g) = clients.network_group(ip) {
                return (names(g), "network");
            }
        }
    }
    if addressed || clients.groups().iter().all(|g| g.networks.is_empty()) {
        let default = clients
            .groups()
            .iter()
            .find(|g| g.name.as_ref() == "default")
            .map(|g| vec![g.name.to_string()])
            .unwrap_or_default();
        return (default, "default");
    }
    (Vec::new(), "network")
}

fn version_conflict(current: u64) -> Problem {
    Problem::new(
        Code::VersionConflict,
        format!("the configuration is now at version {current}"),
    )
    .hint("Re-read the clients (GET /api/v1/clients returns the version as ETag) and retry with If-Match.")
}

/// A validated device change.
struct ClientPlan {
    before: Option<ClientInfo>,
    /// `None` deletes.
    after: Option<telltale_config::ClientConfig>,
    recent_queries: u64,
    impact: String,
    warnings: Vec<String>,
    /// REQ: OBS-024 — the configuration with the change, and the one it's compared with
    /// (for `simulate`).
    candidate: Arc<telltale_config::Config>,
    baseline: Arc<telltale_config::Config>,
}

/// AGT-002 impact of a device change: recent queries from the addresses it matches (they
/// get the new label), and a sentence.
fn client_impact(
    src: &Sources,
    name: &str,
    before: Option<&ClientInfo>,
    after: Option<&telltale_config::ClientConfig>,
) -> (u64, String) {
    let keys: Vec<String> = after
        .map(|c| c.match_keys.iter().map(ToString::to_string).collect())
        .or_else(|| before.map(|b| b.matches.clone()))
        .unwrap_or_default();
    let nets: Vec<telltale_config::Cidr> = keys
        .iter()
        .filter_map(|k| telltale_config::Cidr::parse(k).ok())
        .collect();
    let agg = src.pipeline.telemetry.aggregates();
    let recent_queries = [HourSel::Current, HourSel::Previous]
        .into_iter()
        .flat_map(|h| agg.top_names(telltale_telemetry::agg::TopKind::Clients, h, 1000))
        .filter(|t| {
            t.key
                .parse::<IpAddr>()
                .is_ok_and(|ip| nets.iter().any(|n| n.contains(ip)))
        })
        .map(|t| t.count)
        .sum();
    drop(agg);
    let impact = match after {
        None => format!(
            "Deletes `{name}`: its queries ({recent_queries} in the last two hours) show the address again, and it falls back to its network's group or `default`."
        ),
        Some(a) => {
            let groups: Vec<String> = a.groups.iter().map(ToString::to_string).collect();
            let groups = if groups.is_empty() {
                "its network's group (or `default`)".to_owned()
            } else {
                groups.join(", ")
            };
            format!(
                "{} `{}` ({} address(es)); its {recent_queries} queries in the last two hours, and all history, show that name, and it gets {groups}.",
                if before.is_some() { "Changes" } else { "Names" },
                a.name,
                a.match_keys.len()
            )
        }
    };
    (recent_queries, impact)
}

/// Checks a device write against the running configuration (ADR-040): files win, names are
/// unique, and the resulting configuration must validate.
fn plan_client(
    src: &Sources,
    state: &telltale_store::state::State,
    w: &ClientWrite,
) -> Result<ClientPlan, Problem> {
    let managed: Vec<String> = state
        .managed(crate::managed::CLIENT)
        .map_err(|e| Problem::internal(e.to_string()))?
        .into_iter()
        .map(|m| m.name)
        .collect();
    let cfg = src.config.load_full();
    let is_managed = |n: &str| managed.iter().any(|m| m == n);
    let in_files = |n: &str| cfg.client.iter().any(|c| c.name.as_str() == n) && !is_managed(n);
    if in_files(&w.name) {
        return Err(Problem::new(
            Code::Conflict,
            format!("`{}` is defined in the config files", w.name),
        )
        .hint("Change it in the config file, or name the device differently."));
    }
    let before = cfg
        .client
        .iter()
        .find(|c| c.name.as_str() == w.name)
        .map(|c| client_info(c, &managed));
    let after = match &w.input {
        None => {
            if before.is_none() {
                return Err(Problem::not_found(format!(
                    "no device named `{}` was created through the API",
                    w.name
                )));
            }
            None
        }
        Some(input) => {
            let name = input.name.as_deref().unwrap_or(&w.name).trim().to_owned();
            if name != w.name && (in_files(&name) || is_managed(&name)) {
                return Err(Problem::new(
                    Code::Conflict,
                    format!("there is already a device named `{name}`"),
                ));
            }
            let groups = if input.groups.is_empty() {
                vec!["default".to_owned()]
            } else {
                input.groups.clone()
            };
            // REQ: OBS-025 — `kind` overrides identification (a class name, or `unknown`).
            let json = serde_json::json!({ "name": name, "match": input.matches, "groups": groups, "kind": input.kind });
            let c: telltale_config::ClientConfig = serde_json::from_value(json)
                .map_err(|e| Problem::new(Code::InvalidConfig, format!("device: {e}")))?;
            Some(c)
        }
    };
    let mut candidate = (*cfg).clone();
    let new_name = after.as_ref().map(|c| c.name.to_string());
    candidate
        .client
        .retain(|c| c.name.as_str() != w.name && Some(c.name.as_str()) != new_name.as_deref());
    if let Some(c) = &after {
        candidate.client.push(c.clone());
    }
    let warnings = telltale_config::validate_config(&candidate).map_err(|errs| {
        Problem::new(
            Code::InvalidConfig,
            errs.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; "),
        )
        .hint("GET /api/v1/groups lists the groups a device can join.")
    })?;
    let (recent_queries, impact) = client_impact(src, &w.name, before.as_ref(), after.as_ref());
    Ok(ClientPlan {
        before,
        after,
        recent_queries,
        impact,
        warnings,
        candidate: Arc::new(candidate),
        baseline: cfg,
    })
}

/// The `state.db` kind for an API kind.
fn kind_name(k: ManagedKind) -> &'static str {
    match k {
        ManagedKind::Record => crate::managed::RECORD,
        ManagedKind::Forward => crate::managed::FORWARD,
        ManagedKind::Rule => crate::managed::RULE,
        ManagedKind::Upstream => crate::managed::UPSTREAM,
        ManagedKind::UpstreamGroup => crate::managed::UPSTREAM_GROUP,
        ManagedKind::List => crate::managed::LIST,
        ManagedKind::Group => crate::managed::GROUP,
        ManagedKind::AlertDestination => crate::managed::ALERT_DESTINATION,
        ManagedKind::AlertRule => crate::managed::ALERT_RULE,
        ManagedKind::Schedule => crate::managed::SCHEDULE,
        ManagedKind::AnomalyMute => crate::managed::ANOMALY_MUTE,
        ManagedKind::RateLimit => crate::managed::RATELIMIT,
        ManagedKind::Exclusions => crate::managed::EXCLUSIONS,
        ManagedKind::Simulate => crate::managed::SIMULATE,
        ManagedKind::Rollout => crate::managed::ROLLOUT,
        ManagedKind::KubernetesMap => crate::managed::KUBERNETES_MAP,
        ManagedKind::Router => crate::managed::ROUTER,
    }
}

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// REQ: FLT-005 (T6.12, ADR-067) — every 5 s, deletes quick rules made through the API whose
/// expiry has passed, and audit-logs each as `rule.expire`. Only a standalone node or the
/// primary does this (replicas receive the deletion with the next version, and stop applying
/// an expired rule on their own anyway). Rules from the config files are left alone: they
/// simply stop applying.
pub(crate) fn spawn_rule_sweep(
    src: Arc<Sources>,
    auth: Arc<telltale_api::auth::Auth>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let backend = ApiBackend {
            src: Arc::clone(&src),
        };
        loop {
            tokio::select! {
                _ = stop.changed() => return,
                () = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
            }
            if src.cluster.as_ref().is_some_and(|c| !c.is_primary()) {
                continue;
            }
            let expired = backend
                .rules()
                .into_iter()
                .filter(|r| r.source == "api" && r.expires_in_seconds == Some(0));
            for r in expired {
                let w = ManagedWrite {
                    kind: ManagedKind::Rule,
                    name: r.id.clone(),
                    body: None,
                    dry_run: false,
                    expect: None,
                    by: "rule expiry".into(),
                    simulate: None,
                    by_admin: false,
                };
                match backend.write_managed(w).await {
                    Ok(c) if c.applied => auth.record(
                        &telltale_api::auth::Actor::system("rule expiry"),
                        "rule.expire",
                        &r.id,
                        &serde_json::json!({ "before": c.before, "configVersion": c.config_version }),
                    ),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(rule = %r.id, "an expired quick rule wasn't removed: {}", e.detail),
                }
            }
        }
    });
}

/// REQ: FLT-005 (T6.12, ADR-067) — a rule body as stored: validated shape, the expiry as an
/// absolute time (from `expires` or `forMinutes`), and who made it and when. REQ: FLT-005
/// (T20.1, ADR-162) — a rule that replaces one with the same ID (an edit) keeps who made it and
/// when (`before`); the editor is in the audit entry, which holds the rule before and after.
fn rule_of(
    v: &serde_json::Value,
    id: &str,
    by: &str,
    before: Option<&telltale_config::RuleConfig>,
) -> Result<telltale_config::RuleConfig, Problem> {
    use telltale_config::{RuleAction, RuleConfig, SafeString};
    let input: telltale_api::model::RuleInput =
        serde_json::from_value(v.clone()).map_err(|e| Problem::invalid(format!("body: {e}")))?;
    let safe = |what: &str, s: &str| {
        SafeString::new(s.trim()).map_err(|e| Problem::invalid(format!("`{what}`: {e}")))
    };
    let action = match input.action.trim() {
        "allow" => RuleAction::Allow,
        "block" => RuleAction::Block,
        other => {
            return Err(Problem::invalid(format!(
                "`action`: `{other}` (use `allow` or `block`)"
            )));
        }
    };
    let now = unix_now_secs();
    let expires = match (input.expires.as_deref(), input.for_minutes) {
        (Some(_), Some(_)) => {
            return Err(Problem::invalid("give `expires` or `forMinutes`, not both"));
        }
        (Some(e), None) => {
            let at = telltale_config::parse_rfc3339(e).ok_or_else(|| {
                Problem::invalid(format!("`expires`: `{e}` isn't an RFC 3339 time"))
                    .hint("For example 2026-10-05T21:30:00Z, or use forMinutes.")
            })?;
            if at <= now {
                return Err(Problem::new(
                    Code::InvalidConfig,
                    "`expires` is in the past",
                ));
            }
            Some(safe("expires", e)?)
        }
        (None, Some(0)) => return Err(Problem::invalid("`forMinutes` must be at least 1")),
        (None, Some(m)) => {
            let at = u64::try_from(now).unwrap_or(0) + u64::from(m) * 60;
            Some(safe("expires", &format_us(at * 1_000_000))?)
        }
        (None, None) => None,
    };
    Ok(RuleConfig {
        id: safe("id", id)?,
        action,
        domain: safe("domain", &norm(&input.domain))?,
        devices: input
            .devices
            .iter()
            .map(|d| safe("devices", d))
            .collect::<Result<_, _>>()?,
        groups: input
            .groups
            .iter()
            .map(|g| safe("groups", g))
            .collect::<Result<_, _>>()?,
        expires,
        note: input
            .note
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(|n| safe("note", n))
            .transpose()?,
        created_by: match before.and_then(|b| b.created_by.clone()) {
            Some(kept) => Some(kept),
            None => Some(safe("createdBy", by)?),
        },
        created: match before.and_then(|b| b.created.clone()) {
            Some(kept) => Some(kept),
            None => Some(safe(
                "created",
                &format_us(u64::try_from(now).unwrap_or(0) * 1_000_000),
            )?),
        },
    })
}

/// What a plain quick-rule device refusal's hint says (GitHub issue #73). It promises only what
/// holds today: naming a device recognizes it by the address it has now, so a rule for the name
/// stops matching when that address changes too (until the device's `match` list is changed, or it
/// is recognized by its MAC address). It says to use the new name, not that rules then follow the
/// device. Phase 1 (MAC addresses from the router) can say more.
const RULE_DEVICE_HINT: &str = "Use the address, or name the device first (Clients → its address → Name this device…) and use that name.";

/// How many refused devices of one rule a hint looks up (the others are refused all the same).
const HINTED_DEVICES: usize = 4;

/// What a hint says about one refused device.
enum DeviceHint {
    /// Words that need nothing of this node's tables and end the matter: a MAC address (how to
    /// name the device by it), a Kubernetes workload's name (its pods' addresses change).
    Plain(String),
    /// The discovered name of an address that is a configured device. Learned from this node's
    /// tables.
    Configured(String),
    /// A discovered name: which address(es). Learned from this node's tables; the plain sentence
    /// still follows.
    Discovered(String),
    /// Nothing known about it: the plain sentence.
    Unknown,
}

/// REQ: FLT-005 (GitHub issue #73) — what to do about a device a quick rule can't name. When the
/// string is a name this node's router, mDNS, or the other nodes' tables give an address (what the
/// query log shows for a device nobody named), the hint says which address, and which configured
/// device that is if it is one; a MAC address gets words about MACs. Words only: whether a device
/// is accepted is the validator's answer, from the configuration alone, so every node gives the
/// same one; this reads node-local tables, off the DNS path, and only once a rule was refused, for
/// the first few devices, each once. `hint` is the text without what the tables told it, and the
/// text with it travels beside it (`fuller_hint`): the node that answers the caller gives the
/// fuller one only to a caller who may read every device's queries, and a node that doesn't know
/// the field shows the plain one.
fn rule_device_hint(
    src: &Sources,
    file: &telltale_config::Config,
    entries: &crate::managed::Entries,
    rule: &serde_json::Value,
    refusal: Problem,
) -> Problem {
    let clients: Vec<&telltale_config::ClientConfig> =
        file.client.iter().chain(&entries.clients).collect();
    let known: std::collections::HashSet<String> = clients
        .iter()
        .map(|c| c.name.as_str().to_ascii_lowercase())
        .collect();
    let mut once = std::collections::HashSet::new();
    let refused: Vec<&str> = rule["devices"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .filter(|d| !telltale_config::rule_device_known(&known, d))
        .filter(|d| once.insert(d.to_ascii_lowercase()))
        .take(HINTED_DEVICES)
        .collect();
    if refused.is_empty() {
        return refusal; // refused for another reason
    }
    let (mut full, mut plain) = (Vec::new(), Vec::new());
    let (mut full_ends_plain, mut plain_ends_plain) = (false, false);
    for device in refused {
        match device_hint(src, &clients, device) {
            DeviceHint::Plain(says) => {
                full.push(says.clone());
                plain.push(says);
            }
            DeviceHint::Configured(says) => {
                full.push(says);
                plain_ends_plain = true;
            }
            DeviceHint::Discovered(says) => {
                full.push(says);
                (full_ends_plain, plain_ends_plain) = (true, true);
            }
            DeviceHint::Unknown => (full_ends_plain, plain_ends_plain) = (true, true),
        }
    }
    if full_ends_plain {
        full.push(RULE_DEVICE_HINT.to_owned());
    }
    if plain_ends_plain {
        plain.push(RULE_DEVICE_HINT.to_owned());
    }
    let (full, plain) = (full.join(" "), plain.join(" "));
    if plain == full {
        refusal.hint(full)
    } else {
        refusal.hint(plain).fuller_hint(full)
    }
}

/// What the hint says about one refused `device`.
fn device_hint(
    src: &Sources,
    clients: &[&telltale_config::ClientConfig],
    device: &str,
) -> DeviceHint {
    if matches!(
        telltale_config::MatchKey::parse(device),
        Ok(telltale_config::MatchKey::Mac(_))
    ) {
        return DeviceHint::Plain(format!(
            "`{device}` is a MAC address, and a rule can't name one. Name the device with that MAC in its match list (a `[[client]]` in the config file, or `PUT /api/v1/clients/{{name}}`), then use that name. MAC addresses are recognized only where TelltaleDNS can see them."
        ));
    }
    // What the query log calls a pod: `namespace/kind/name`. Its address is not a good thing to
    // name: it changes with every restart.
    let mut parts = device.split('/');
    if let (Some(ns), Some(kind), Some(name), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
        && !ns.is_empty()
        && !kind.is_empty()
        && !name.is_empty()
    {
        return DeviceHint::Plain(format!(
            "`{device}` looks like a Kubernetes workload's name, and a pod's address changes with every restart. A rule can be for the group an operator placed it in (click its name in the query log, then Add to group…), or, for a short time, for one pod's address."
        ));
    }
    let found = discovered_addresses(src, device);
    match found.len() {
        0 => DeviceHint::Unknown,
        1 => {
            let Some((&ip, by)) = found.iter().next() else {
                return DeviceHint::Unknown;
            };
            if let Some(named) = configured_device_at(clients, ip, &by.mac) {
                let who = if by.router {
                    format!("your router calls {ip}")
                } else {
                    format!("{ip} calls itself")
                };
                DeviceHint::Configured(format!(
                    "`{device}` is what {who}, which is the device “{named}”: use its name."
                ))
            } else if by.router {
                DeviceHint::Discovered(format!("`{device}` is what your router calls {ip}."))
            } else {
                DeviceHint::Discovered(format!("`{device}` is what {ip} calls itself."))
            }
        }
        n => {
            /// How many addresses a sentence lists before "and N more".
            const SHOWN: usize = 4;
            let mut list: Vec<String> = found.keys().take(SHOWN).map(ToString::to_string).collect();
            if n > SHOWN {
                list.push(format!("and {} more", n - SHOWN));
            }
            DeviceHint::Discovered(format!(
                "`{device}` is the name of more than one device here ({}), so pick the address of the one you mean.",
                list.join(", ")
            ))
        }
    }
}

/// Who gave an address a name: a router (not the device itself over mDNS), and its MAC if known.
#[derive(Debug, Clone)]
struct NamedBy {
    router: bool,
    mac: String,
}

/// The addresses `name` is the discovered name of (any case): this node's router, then its mDNS,
/// then the other nodes' routers and mDNS, as the query log reads them (the first table to know an
/// address names it).
fn discovered_addresses(
    src: &Sources,
    name: &str,
) -> std::collections::BTreeMap<std::net::Ipv4Addr, NamedBy> {
    let routers = src.pipeline.router_leases.load();
    let mdns = src.pipeline.mdns_names.load();
    let peers = src.pipeline.peer_names.load();
    let mut found = std::collections::BTreeMap::<std::net::Ipv4Addr, NamedBy>::new();
    for (table, router) in [
        (&**routers, true),
        (&**mdns, false),
        (&peers.routers, true),
        (&peers.mdns, false),
    ] {
        for (ip, lease) in table {
            if lease
                .hostname
                .as_deref()
                .is_some_and(|h| h.eq_ignore_ascii_case(name))
            {
                let by = found.entry(*ip).or_insert_with(|| NamedBy {
                    router,
                    mac: String::new(),
                });
                if by.mac.is_empty() {
                    by.mac.clone_from(&lease.mac);
                }
            }
        }
    }
    found
}

/// The configured device that is exactly this address: it names the address, or the MAC the lease
/// reports, in its `match` list. (A device that is a network, a CIDR, isn't "the device".)
fn configured_device_at(
    clients: &[&telltale_config::ClientConfig],
    ip: std::net::Ipv4Addr,
    mac: &str,
) -> Option<String> {
    use telltale_config::MatchKey;
    let mac = MatchKey::parse(mac)
        .ok()
        .filter(|k| matches!(k, MatchKey::Mac(_)));
    clients
        .iter()
        .find(|c| {
            c.match_keys
                .iter()
                .any(|k| match MatchKey::parse(k.as_str()) {
                    Ok(MatchKey::Ip(a)) => a == std::net::IpAddr::V4(ip),
                    // `192.168.1.20/32` is one address too.
                    Ok(MatchKey::Cidr(c)) => c.prefix == 32 && c.addr == std::net::IpAddr::V4(ip),
                    Ok(m @ MatchKey::Mac(_)) => mac.as_ref() == Some(&m),
                    _ => false,
                })
        })
        .map(|c| c.name.to_string())
}

/// AGT-002 impact of a quick rule: recent queries for its domain (or names under it) and a
/// sentence saying for whom it changes.
fn rule_impact(src: &Sources, rule: &telltale_config::RuleConfig, setting: bool) -> (u64, String) {
    let domain = rule.domain.as_str();
    let under = format!(".{domain}");
    let agg = src.pipeline.telemetry.aggregates();
    let recent_queries: u64 = [HourSel::Current, HourSel::Previous]
        .into_iter()
        .flat_map(|h| agg.top_names(telltale_telemetry::agg::TopKind::Domains, h, 1000))
        .filter(|t| t.key == domain || t.key.ends_with(&under))
        .map(|t| t.count)
        .sum();
    drop(agg);
    let whom = if !rule.devices.is_empty() {
        format!(
            "for {}",
            rule.devices
                .iter()
                .map(telltale_config::SafeString::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else if !rule.groups.is_empty() {
        format!(
            "for the group(s) {}",
            rule.groups
                .iter()
                .map(telltale_config::SafeString::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        "for everyone".to_owned()
    };
    let action = if rule.action == telltale_config::RuleAction::Allow {
        "allowed"
    } else {
        "blocked"
    };
    let until = rule
        .expires
        .as_deref()
        .map_or(String::new(), |e| format!(" until {e}"));
    let impact = if setting {
        format!(
            "`{domain}` and its subdomains are {action} {whom}{until}, before any list; {recent_queries} queries for them in the last two hours (at least)."
        )
    } else {
        format!(
            "`{domain}` goes back to the lists {whom}; {recent_queries} queries for it in the last two hours (at least)."
        )
    };
    (recent_queries, impact)
}

/// A local name or domain as stored: lowercase, no trailing dot.
fn norm(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// A validated change to a local name or forwarded domain.
struct ManagedPlan {
    name: String,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
    /// What to store (`None` deletes).
    body: Option<String>,
    recent_queries: u64,
    impact: String,
    warnings: Vec<String>,
    /// REQ: API-002 (T9.22) — entries the change also needs, stored first: removing an
    /// upstream takes it out of the upstream groups that use it. (kind, name, body).
    also: AlsoStored,
    /// REQ: OBS-024 — the merged configuration with the change (for `simulate`).
    candidate: telltale_config::Config,
}

/// Parses a records body into stored form.
fn record_values(
    v: &serde_json::Value,
    name: &str,
) -> Result<Vec<crate::managed::RecordValue>, Problem> {
    let input: telltale_api::model::RecordsInput =
        serde_json::from_value(v.clone()).map_err(|e| Problem::invalid(format!("body: {e}")))?;
    if input.records.is_empty() {
        return Err(Problem::new(
            Code::InvalidConfig,
            format!("`{name}`: give at least one record (or DELETE the name)"),
        ));
    }
    Ok(input
        .records
        .into_iter()
        .map(|r| crate::managed::RecordValue {
            rtype: r.rtype.trim().to_ascii_uppercase(),
            value: r.value.trim().to_owned(),
            ttl: r.ttl,
        })
        .collect())
}

/// A forward as a change shows it: the domain, its servers, and (REQ: DNS-022) `stub` when set.
fn forward_json(name: &str, f: &crate::managed::Forward) -> serde_json::Value {
    let mut v = serde_json::json!({ "domain": name, "servers": f.servers });
    if f.stub {
        v["stub"] = true.into();
    }
    v
}

/// Parses a forward body into stored form.
fn forward_of(v: &serde_json::Value, name: &str) -> Result<crate::managed::Forward, Problem> {
    let input: telltale_api::model::ForwardInput =
        serde_json::from_value(v.clone()).map_err(|e| Problem::invalid(format!("body: {e}")))?;
    let servers: Vec<String> = input
        .servers
        .iter()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    if servers.is_empty() {
        return Err(Problem::new(
            Code::InvalidConfig,
            format!("`{name}`: give at least one server"),
        ));
    }
    // REQ: UPS-011, API-002 (ADR-180) — a server becomes an upstream: not a program or a socket.
    if let Some(i) = servers
        .iter()
        .position(|s| crate::managed::is_plugin_url(&crate::managed::server_url(s)))
    {
        return Err(plugin_refused(&format!("servers[{i}]")));
    }
    // REQ: DNS-022 — a stub zone's servers are asked directly, by address.
    if input.stub
        && let Some(bad) = servers
            .iter()
            .find(|s| crate::managed::stub_addr(s).is_none())
    {
        return Err(Problem::new(
            Code::InvalidConfig,
            format!("`{name}`: `{bad}` isn't an IP address"),
        )
        .hint("A stub zone's servers are the zone's own, by IP address (port 53), e.g. [\"10.0.0.53\"]."));
    }
    Ok(crate::managed::Forward {
        servers,
        stub: input.stub,
    })
}

/// AGT-002 impact of a local-name or forward change: recent queries for the name (or names
/// under the domain), and a sentence.
fn managed_impact(src: &Sources, kind: ManagedKind, name: &str, setting: bool) -> (u64, String) {
    let agg = src.pipeline.telemetry.aggregates();
    let under = format!(".{name}");
    let recent_queries: u64 = [HourSel::Current, HourSel::Previous]
        .into_iter()
        .flat_map(|h| agg.top_names(telltale_telemetry::agg::TopKind::Domains, h, 1000))
        .filter(|t| match kind {
            ManagedKind::Record => t.key == name,
            ManagedKind::Forward | ManagedKind::Rule => t.key == name || t.key.ends_with(&under),
            _ => false,
        })
        .map(|t| t.count)
        .sum();
    drop(agg);
    let impact = match (kind, setting) {
        (ManagedKind::Record, true) => format!(
            "TelltaleDNS answers `{name}` itself from now on; {recent_queries} queries for it in the last two hours (at least) went elsewhere."
        ),
        (ManagedKind::Record, false) => format!(
            "`{name}` goes back to the upstreams; {recent_queries} queries for it in the last two hours (at least)."
        ),
        (ManagedKind::Forward, true) => format!(
            "Names under `{name}` go to the servers given; {recent_queries} queries for them in the last two hours (at least)."
        ),
        (ManagedKind::Forward, false) => format!(
            "Names under `{name}` go back to the default upstreams; {recent_queries} queries for them in the last two hours (at least)."
        ),
        (ManagedKind::Rule, _) => String::new(), // rule_impact says it better
        (ManagedKind::Upstream | ManagedKind::UpstreamGroup, _) => {
            "Applies on the next query; answers already cached stay until they expire.".into()
        }
        (ManagedKind::List, true) => {
            "The list is downloaded and compiled in the background; blocking changes when that's done.".into()
        }
        (ManagedKind::List, false) => "Its blocks stop when the lists are compiled again (seconds).".into(),
        (ManagedKind::Group, _) => "Applies to the group's devices on their next query.".into(),
        (ManagedKind::Schedule, _) => {
            "Applies within 15 seconds to the groups that use it.".into()
        }
        // REQ: T8.2 (ADR-181) — review round 2, correctness R3: what the router task does.
        (ManagedKind::Router, true) => {
            "The router is read within 5 seconds after the reads in progress end; its devices are named once it answers (the log says if it doesn't).".into()
        }
        (ManagedKind::Router, false) => {
            "Its devices lose the names it gave them after the next round of reads, which starts within 5 seconds after the reads in progress end.".into()
        }
        // REQ: OBS-038 — decided when a finding is created, so nothing already recorded changes.
        (ManagedKind::AnomalyMute, true) => {
            "Applies to findings created from now on, on every node: they are still recorded and listed (with Show muted), but not counted in the badge, the alerts or /metrics (telltale_anomalies_muted_total counts them). Findings already recorded stay as they are.".into()
        }
        (ManagedKind::AnomalyMute, false) => {
            "Findings created from now on count again; ones already muted stay muted.".into()
        }
        (ManagedKind::AlertDestination | ManagedKind::AlertRule, _) => {
            "Applies at the next alert check; firing alerts of a changed rule start over.".into()
        }
        (ManagedKind::RateLimit, true) => {
            "Applies on the next query, with no restart; every client's count starts over.".into()
        }
        (ManagedKind::RateLimit, false) => {
            "The config file's rate limit (or the default) applies again from the next query; every client's count starts over.".into()
        }
        (ManagedKind::Exclusions, true) => {
            "From the next query on, on every node: matching queries are still answered and counted in /metrics, but left out of the query log, live view, dashboard, anomalies, and exports. Queries already logged stay.".into()
        }
        (ManagedKind::Exclusions, false) => {
            "The config file's exclusions (or none) apply again from the next query.".into()
        }
        (ManagedKind::Simulate, true) => {
            "Applies to the next simulation, on every node. DNS answers don't change.".into()
        }
        (ManagedKind::Simulate, false) => {
            "The config file's simulation settings (or the defaults) apply again to the next simulation.".into()
        }
        (ManagedKind::Rollout, true) => {
            "Applies to the next change, on every node; this change itself is published at once, not staged.".into()
        }
        (ManagedKind::Rollout, false) => {
            "The config file's rollout settings (or none: every change reaches every node at once) apply again.".into()
        }
        (ManagedKind::KubernetesMap, true) => {
            "The workloads it matches use the group from their next query, and on the other nodes within a few seconds (a pod or namespace label still wins).".into()
        }
        (ManagedKind::KubernetesMap, false) => {
            "The workloads it matched take the next rule, the default group, or their network's group from their next query, and on the other nodes within a few seconds.".into()
        }
    };
    (recent_queries, impact)
}

/// Checks a local-name, forward, or quick-rule write (ADR-042): files win, and the files plus
/// every API entry with this change must validate, record values included.
#[allow(clippy::too_many_lines)] // one branch per kind of entry
fn plan_managed(
    src: &Sources,
    state: &telltale_store::state::State,
    w: &ManagedWrite,
) -> Result<ManagedPlan, Problem> {
    if matches!(
        w.kind,
        ManagedKind::RateLimit
            | ManagedKind::Exclusions
            | ManagedKind::Simulate
            | ManagedKind::Rollout
    ) {
        return plan_singleton(src, state, w);
    }
    if matches!(
        w.kind,
        ManagedKind::Upstream
            | ManagedKind::UpstreamGroup
            | ManagedKind::List
            | ManagedKind::Group
            | ManagedKind::AlertDestination
            | ManagedKind::AlertRule
            | ManagedKind::Schedule
            | ManagedKind::AnomalyMute
            | ManagedKind::KubernetesMap
            | ManagedKind::Router
    ) {
        return plan_override(src, state, w);
    }
    let name = norm(&w.name);
    if name.is_empty() {
        return Err(Problem::invalid("the name is empty"));
    }
    let file = src.file_config.load_full();
    let in_files = match w.kind {
        ManagedKind::Record => file
            .record
            .iter()
            .any(|r| r.name.eq_ignore_ascii_case(&name)),
        ManagedKind::Forward => file
            .route
            .iter()
            .any(|r| r.match_suffix.iter().any(|s| s.eq_ignore_ascii_case(&name))),
        ManagedKind::Rule => file.rule.iter().any(|r| r.id.eq_ignore_ascii_case(&name)),
        _ => false,
    };
    if in_files {
        return Err(Problem::new(
            Code::Conflict,
            format!("`{name}` is defined in the config files"),
        )
        .hint("Change it in the config file."));
    }
    let mut entries = crate::managed::entries(state);
    let (before, after) = match w.kind {
        ManagedKind::Record => {
            let before = entries
                .records
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, r)| r.clone());
            entries.records.retain(|(n, _)| *n != name);
            let after = match &w.body {
                None => None,
                Some(v) => {
                    let recs = record_values(v, &name)?;
                    entries.records.push((name.clone(), recs.clone()));
                    Some(recs)
                }
            };
            (
                before.map(|b| serde_json::json!({ "name": name, "records": b })),
                after.map(|a| serde_json::json!({ "name": name, "records": a })),
            )
        }
        ManagedKind::Forward => {
            let before = entries
                .forwards
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, f)| f.clone());
            entries.forwards.retain(|(n, _)| *n != name);
            let after = match &w.body {
                None => None,
                Some(v) => {
                    let f = forward_of(v, &name)?;
                    entries.forwards.push((name.clone(), f.clone()));
                    Some(f)
                }
            };
            (
                before.map(|b| forward_json(&name, &b)),
                after.map(|a| forward_json(&name, &a)),
            )
        }
        ManagedKind::Rule => {
            let before = entries
                .rules
                .iter()
                .find(|r| r.id.as_str() == name)
                .cloned();
            entries.rules.retain(|r| r.id.as_str() != name);
            let after = match &w.body {
                None => None,
                Some(v) => {
                    let r = rule_of(v, &name, &w.by, before.as_ref())?;
                    entries.rules.push(r.clone());
                    Some(r)
                }
            };
            (
                before.map(|b| serde_json::to_value(b).unwrap_or_default()),
                after.map(|a| serde_json::to_value(a).unwrap_or_default()),
            )
        }
        _ => return Err(Problem::internal("handled by plan_override")),
    };
    if w.body.is_none() && before.is_none() {
        return Err(Problem::not_found(format!(
            "`{name}` wasn't created through the API"
        )));
    }
    let merged = crate::managed::merge(&file, &entries).map_err(|errs| {
        let refusal = Problem::new(Code::InvalidConfig, errs.join("; "));
        match (w.kind, after.as_ref()) {
            // REQ: FLT-005 (GitHub issue #73) — a device a rule can't name says what to do.
            (ManagedKind::Rule, Some(rule)) => {
                rule_device_hint(src, &file, &entries, rule, refusal)
            }
            _ => refusal,
        }
    })?;
    let warnings = telltale_config::validate_config(&merged).unwrap_or_default();
    let body = match (w.kind, &after) {
        (_, None) => None,
        (ManagedKind::Record, Some(a)) => Some(a["records"].to_string()),
        (ManagedKind::Forward, Some(a)) => {
            let mut b = serde_json::json!({ "servers": a["servers"] });
            // REQ: DNS-022 — the stored entry keeps its stub flag.
            if a["stub"] == true {
                b["stub"] = true.into();
            }
            Some(b.to_string())
        }
        (_, Some(a)) => Some(a.to_string()),
    };
    let (recent_queries, impact) = if w.kind == ManagedKind::Rule {
        let rule = after
            .as_ref()
            .or(before.as_ref())
            .and_then(|v| serde_json::from_value::<telltale_config::RuleConfig>(v.clone()).ok());
        rule.map_or((0, String::new()), |r| rule_impact(src, &r, body.is_some()))
    } else {
        managed_impact(src, w.kind, &name, body.is_some())
    };
    Ok(ManagedPlan {
        name,
        before,
        after,
        body,
        recent_queries,
        impact,
        warnings,
        also: Vec::new(),
        candidate: merged,
    })
}

/// What a write to a one-of section does: the section before and after, what to store (`None`
/// deletes), and the merged configuration.
#[derive(Debug)]
struct SingletonChange {
    before: serde_json::Value,
    after: serde_json::Value,
    body: Option<String>,
    merged: telltale_config::Config,
}

/// The section a one-of kind replaces, as JSON.
fn singleton_section(kind: ManagedKind, cfg: &telltale_config::Config) -> serde_json::Value {
    match kind {
        ManagedKind::Exclusions => serde_json::to_value(&cfg.exclusions),
        ManagedKind::Simulate => serde_json::to_value(&cfg.simulate),
        ManagedKind::Rollout => serde_json::to_value(&cfg.cluster.rollout),
        _ => serde_json::to_value(&cfg.ratelimit),
    }
    .unwrap_or_default()
}

/// What a one-of kind is called in messages.
fn singleton_noun(kind: ManagedKind) -> &'static str {
    match kind {
        ManagedKind::Exclusions => "exclusions",
        ManagedKind::Simulate => "simulation settings",
        ManagedKind::Rollout => "rollout settings",
        _ => "rate limit",
    }
}

/// Parses and stores `v` as the kind's section; returns it as stored.
fn singleton_store(
    kind: ManagedKind,
    entries: &mut crate::managed::Entries,
    v: &serde_json::Value,
) -> Result<String, Problem> {
    let bad = |e: serde_json::Error| Problem::new(Code::InvalidConfig, format!("{e}"));
    Ok(if kind == ManagedKind::Exclusions {
        let x: telltale_config::ExclusionsConfig =
            serde_json::from_value(v.clone()).map_err(bad)?;
        let text = serde_json::to_string(&x).unwrap_or_default();
        entries.exclusions = Some(x);
        text
    } else if kind == ManagedKind::Simulate {
        let x: telltale_config::SimulateConfig = serde_json::from_value(v.clone()).map_err(bad)?;
        let text = serde_json::to_string(&x).unwrap_or_default();
        entries.simulate = Some(x);
        text
    } else if kind == ManagedKind::Rollout {
        let x: telltale_config::RolloutConfig = serde_json::from_value(v.clone()).map_err(bad)?;
        let text = serde_json::to_string(&x).unwrap_or_default();
        entries.rollout = Some(x);
        text
    } else {
        let r: telltale_config::RateLimitConfig = serde_json::from_value(v.clone()).map_err(bad)?;
        let text = serde_json::to_string(&r).unwrap_or_default();
        entries.ratelimit = Some(r);
        text
    })
}

/// REQ: DNS-014 (review 01 q1), OBS-022 (T12.1) — a change to a one-of section (the rate limit,
/// the exclusions): `PUT` (`body` set) stores a whole section (fields left out take the
/// defaults), `DELETE` removes it so the files' applies again. The merged configuration must
/// validate.
fn singleton_change(
    kind: ManagedKind,
    file: &telltale_config::Config,
    entries: &mut crate::managed::Entries,
    body: Option<&serde_json::Value>,
) -> Result<SingletonChange, Problem> {
    let before_cfg = crate::managed::merge(file, entries).unwrap_or_else(|_| file.clone());
    let before = singleton_section(kind, &before_cfg);
    let stored = if let Some(v) = body {
        Some(singleton_store(kind, entries, v)?)
    } else {
        let had = match kind {
            ManagedKind::Exclusions => entries.exclusions.take().is_some(),
            ManagedKind::Simulate => entries.simulate.take().is_some(),
            ManagedKind::Rollout => entries.rollout.take().is_some(),
            _ => entries.ratelimit.take().is_some(),
        };
        if !had {
            return Err(Problem::not_found(match kind {
                ManagedKind::Exclusions => {
                    "the exclusions weren't changed through the API or UI: the config file's are in effect"
                }
                ManagedKind::Simulate => {
                    "the simulation settings weren't changed through the API or UI: the config file's are in effect"
                }
                ManagedKind::Rollout => {
                    "the rollout settings weren't changed through the API or UI: the config file's are in effect"
                }
                _ => {
                    "the rate limit wasn't changed through the API or UI: the config file's is in effect"
                }
            }));
        }
        None
    };
    let merged = crate::managed::merge(file, entries)
        .map_err(|errs| Problem::new(Code::InvalidConfig, errs.join("; ")))?;
    let after = singleton_section(kind, &merged);
    Ok(SingletonChange {
        before,
        after,
        body: stored,
        merged,
    })
}

/// REQ: DNS-014, OBS-022 — plans a write to a one-of section (see [`singleton_change`]).
fn plan_singleton(
    src: &Sources,
    state: &telltale_store::state::State,
    w: &ManagedWrite,
) -> Result<ManagedPlan, Problem> {
    if w.name.trim() != "default" {
        return Err(Problem::not_found(format!(
            "there is one {}, named `default`",
            singleton_noun(w.kind)
        )));
    }
    let file = src.file_config.load_full();
    let mut entries = crate::managed::entries(state);
    let change = singleton_change(w.kind, &file, &mut entries, w.body.as_ref())?;
    let warnings = telltale_config::validate_config(&change.merged).unwrap_or_default();
    let (recent_queries, impact) = managed_impact(src, w.kind, "default", change.body.is_some());
    Ok(ManagedPlan {
        name: "default".to_owned(),
        before: Some(change.before),
        after: Some(change.after),
        body: change.body,
        recent_queries,
        impact,
        warnings,
        also: Vec::new(),
        candidate: change.merged,
    })
}

/// ADR-069 — one kind's change: returns (the entry before, the body to store).
fn override_step<T>(
    name: &str,
    body: Option<&serde_json::Value>,
    in_files: bool,
    current: Option<&T>,
    stored: &mut Vec<(String, crate::managed::Ovr<T>)>,
) -> Result<(Option<serde_json::Value>, Option<String>), Problem>
where
    T: crate::managed::Named + Clone + Serialize + serde::de::DeserializeOwned,
{
    let before = current.map(|c| serde_json::to_value(c).unwrap_or_default());
    let had = stored.iter().any(|(n, _)| n == name);
    stored.retain(|(n, _)| n != name);
    let body = match body {
        Some(v) => {
            let mut v = v.clone();
            if let Some(o) = v.as_object_mut() {
                o.insert("name".into(), serde_json::Value::String(name.to_owned()));
            } else {
                return Err(Problem::invalid("the body must be an object"));
            }
            let t: T = serde_json::from_value(v)
                .map_err(|e| Problem::new(Code::InvalidConfig, format!("{e}")))?;
            let s = serde_json::to_string(&t).unwrap_or_default();
            stored.push((name.to_owned(), crate::managed::Ovr::Set(t)));
            Some(s)
        }
        // DELETE: what the API stored goes (the files' entry is back), else hide the files'.
        None if had => None,
        None if in_files => {
            stored.push((name.to_owned(), crate::managed::Ovr::Hidden));
            Some(crate::managed::HIDDEN.to_owned())
        }
        None => return Err(Problem::not_found(format!("no `{name}`"))),
    };
    Ok((before, body))
}

/// REQ: FLT-017 — a `[[kubernetes.map]]` rule by key (`namespace/kind/name`, `*` for any): the
/// body names the group. Like [`override_step`], with the key parsed into the rule.
fn kubernetes_map_step(
    key: &str,
    body: Option<&serde_json::Value>,
    file: &telltale_config::Config,
    before_cfg: &telltale_config::Config,
    entries: &mut crate::managed::Entries,
) -> Result<(Option<serde_json::Value>, Option<String>), Problem> {
    let mut parts = key.split('/');
    let (Some(ns), Some(kind), Some(name), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(
            Problem::invalid(format!("`{key}`: a rule's key is namespace/kind/name"))
                .hint("For one workload: media/deploy/jellyfin. For a whole namespace: media/*/*."),
        );
    };
    let any = |s: &str| {
        if s == "*" {
            String::new()
        } else {
            s.to_owned()
        }
    };
    let safe = |s: String| {
        telltale_config::SafeString::new(s).map_err(|e| Problem::invalid(format!("`{key}`: {e}")))
    };
    let before = before_cfg
        .kubernetes
        .map
        .iter()
        .find(|r| r.key() == key)
        .map(|r| serde_json::to_value(r).unwrap_or_default());
    let stored = &mut entries.kubernetes_map;
    let had = stored.iter().any(|(n, _)| n == key);
    stored.retain(|(n, _)| n != key);
    let body = match body {
        Some(v) => {
            let group = v
                .get("group")
                .and_then(serde_json::Value::as_str)
                .filter(|g| !g.trim().is_empty())
                .ok_or_else(|| {
                    Problem::invalid("`group` is required")
                        .hint("Send {\"group\": \"<a group's name>\"}.")
                })?;
            let rule = telltale_config::KubernetesMapRule {
                namespace: safe(ns.to_owned())?,
                kind: safe(any(kind))?,
                name: safe(any(name))?,
                group: safe(group.trim().to_owned())?,
            };
            if rule.key() != key {
                return Err(Problem::invalid(format!(
                    "`{key}`: use `*` for any kind or name"
                )));
            }
            let s = serde_json::to_string(&rule).unwrap_or_default();
            stored.push((key.to_owned(), crate::managed::Ovr::Set(rule)));
            Some(s)
        }
        None if had => None,
        None if file.kubernetes.map.iter().any(|r| r.key() == key) => {
            stored.push((key.to_owned(), crate::managed::Ovr::Hidden));
            Some(crate::managed::HIDDEN.to_owned())
        }
        None => {
            return Err(Problem::not_found(format!(
                "no [[kubernetes.map]] rule `{key}`"
            )));
        }
    };
    Ok((before, body))
}

/// REQ: API-002 (T9.22) — the impact sentence, plus the upstream groups a removal changes.
fn with_cascade(impact: String, groups: &[String]) -> String {
    if groups.is_empty() {
        return impact;
    }
    let list = groups
        .iter()
        .map(|g| format!("`{g}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let (s, verb) = if groups.len() == 1 {
        ("", "keeps")
    } else {
        ("s", "keep")
    };
    format!(
        "{impact} It's also taken out of upstream group{s} {list}, which {verb} its other upstreams."
    )
}

/// What a change stores besides its own entry: (kind, name, body).
type AlsoStored = Vec<(&'static str, String, Option<String>)>;

/// REQ: API-002 (T9.22) — removing upstream `name`: each upstream group that lists it, without
/// it (stored before the upstream is hidden, so a stop halfway leaves a valid configuration),
/// and the groups' names. A group it's the only member of has to change first.
fn upstream_cascade(
    name: &str,
    file: &telltale_config::Config,
    entries: &mut crate::managed::Entries,
) -> Result<(AlsoStored, Vec<String>), Problem> {
    use crate::managed::Named;
    let mut also = Vec::new();
    let mut groups = Vec::new();
    // The groups as the files and the API define them: one made through the API may still name
    // an upstream that the merge leaves out (REQ: UPS-011, ADR-180), and loses it here too.
    let mut defined = file.upstream_group.clone();
    crate::managed::apply_ovr(&mut defined, &entries.upstream_groups);
    for g in defined
        .iter()
        .filter(|g| g.members.iter().any(|m| m.as_str() == name))
    {
        let members: Vec<_> = g
            .members
            .iter()
            .filter(|m| m.as_str() != name)
            .cloned()
            .collect();
        if members.is_empty() {
            return Err(Problem::new(
                Code::InvalidConfig,
                format!(
                    "`{name}` is the only upstream in upstream group `{}`",
                    g.name.as_str()
                ),
            )
            .hint(format!(
                "Add another upstream to `{}` first (Upstream groups → Edit), or remove the group.",
                g.name.as_str()
            )));
        }
        let mut trimmed = g.clone();
        trimmed.members = members;
        let mut body = serde_json::to_value(&trimmed).unwrap_or_default();
        if let Some(o) = body.as_object_mut() {
            o.remove("name");
        }
        let gname = g.name.to_string();
        let (_, stored) = override_step(
            &gname,
            Some(&body),
            file.upstream_group.iter().any(|x| x.name() == gname),
            Some(g),
            &mut entries.upstream_groups,
        )?;
        also.push(("upstream_group", gname.clone(), stored));
        groups.push(gname);
    }
    Ok((also, groups))
}

/// REQ: UPS-007 (T9.25) — an upstream group a client group or a route still sends questions to
/// can't be removed (sending them to `default` instead could quietly drop, say, a family
/// resolver). Reverting an override of the files' entry keeps the group, so that's fine.
fn upstream_group_in_use(
    name: &str,
    file: &telltale_config::Config,
    entries: &crate::managed::Entries,
    before_cfg: &telltale_config::Config,
) -> Result<(), Problem> {
    use crate::managed::Named;
    if entries.upstream_groups.iter().any(|(n, _)| *n == name)
        && file.upstream_group.iter().any(|g| g.name() == name)
    {
        return Ok(());
    }
    let groups: Vec<_> = before_cfg
        .group
        .iter()
        .filter(|g| g.upstreams.as_deref() == Some(name))
        .map(|g| format!("`{}`", g.name.as_str()))
        .collect();
    let routes = before_cfg
        .route
        .iter()
        .filter(|r| r.upstream_group.as_str() == name)
        .count();
    if groups.is_empty() && routes == 0 {
        return Ok(());
    }
    let mut users = Vec::new();
    if !groups.is_empty() {
        users.push(format!(
            "group{} {}",
            if groups.len() == 1 { "" } else { "s" },
            groups.join(", ")
        ));
    }
    if routes > 0 {
        users.push(format!(
            "{routes} route{}",
            if routes == 1 { "" } else { "s" }
        ));
    }
    Err(Problem::new(
        Code::InvalidConfig,
        format!("upstream group `{name}` is in use by {}", users.join(" and ")),
    )
    .hint("Pick other upstream servers for those groups first (Groups → Edit), or remove their `[[route]]` entries."))
}

/// REQ: T8.6 — answer filtering, rewrites, DNS64 (from the group's config); UPS-007 (T9.25) —
/// its upstream group.
fn with_group_config(mut info: GroupInfo, cfg: &telltale_config::Config) -> GroupInfo {
    if let Some(c) = cfg.group.iter().find(|x| x.name.as_str() == info.name) {
        info.rebinding_protection = c.rebinding_protection;
        info.block_answer_ips = c.block_answer_ips.iter().map(ToString::to_string).collect();
        info.rewrites = c
            .rewrite
            .iter()
            .map(|r| telltale_api::model::RewriteInfo {
                domain: r.domain.to_string(),
                answer: r.answer.to_string(),
            })
            .collect();
        info.dns64 = c.dns64;
        info.dns64_prefix = c.dns64_prefix.as_ref().map(ToString::to_string);
        info.filter_aaaa = c.filter_aaaa;
        info.upstreams = c.upstreams.as_ref().map(ToString::to_string);
    }
    info
}

/// The entry named `name`, as JSON.
fn named_json<T: crate::managed::Named + Serialize>(
    items: &[T],
    name: &str,
) -> Option<serde_json::Value> {
    items
        .iter()
        .find(|i| i.name() == name)
        .map(|x| serde_json::to_value(x).unwrap_or_default())
}

/// REQ: UPS-011, API-002 (ADR-180) — an upstream that names a program the server would start
/// (`exec://`, its `args`) or a local socket it would connect to (`unix://`) is a configuration
/// file matter: a write through the API, a dry run, a forward's servers, and a pre-save check are
/// refused for every caller, an administrator included. `field` is the one that says so.
pub(crate) fn plugin_refused(field: &str) -> Problem {
    Problem::new(
        Code::InvalidConfig,
        format!(
            "`{field}`: an upstream that names a program or a local socket isn't set through the API"
        ),
    )
    .hint("Plugin upstreams (`exec://`, `unix://`) are defined in the config file.")
}

/// REQ: UPS-011, API-002 (ADR-180) — the plugin field of an upstream's body (JSON), if any.
fn plugin_field_of(body: &serde_json::Value) -> Option<&'static str> {
    crate::managed::plugin_field(
        body.get("url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
        body.get("args")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|a| !a.is_empty()),
    )
}

/// REQ: FLT-004, API-002 (ADR-180) — a list made through the API that reads a local file
/// (`path`) is pointed at that file only by an administrator: the server reads it on every
/// refresh, so which file is read is for someone trusted with the node. `current` is the file
/// the list in effect reads, if any: a write that keeps it (another setting changed) needs only
/// the operator role, as do URL lists, inline rules, and deletes. Dry runs and writes forwarded
/// from another node are checked the same way.
fn local_file_guard(w: &ManagedWrite, current: Option<&str>) -> Result<(), Problem> {
    if w.by_admin {
        return Ok(());
    }
    let Some(after) = w
        .body
        .as_ref()
        .and_then(|b| b.get("path"))
        .filter(|p| !p.is_null())
    else {
        return Ok(());
    };
    if after.as_str().is_some_and(|p| Some(p) == current) {
        return Ok(());
    }
    Err(Problem::new(
        Code::Forbidden,
        "a list's `path` (a local file) is set or changed only by an administrator",
    )
    .hint("Setting or changing a list's local file needs an administrator. A URL list, inline rules, a change that keeps the list's file, or deleting it, need only the operator role."))
}

/// REQ: OBS-010, API-002 (ADR-179) — the credential-file fields an alert destination (as JSON)
/// names.
fn credential_fields(d: &serde_json::Value) -> Vec<&'static str> {
    ["token_file", "password_file"]
        .into_iter()
        .filter(|f| d.get(*f).is_some_and(|v| !v.is_null()))
        .collect()
}

/// REQ: OBS-010, API-002 (ADR-179) — only an administrator adds or changes an alert destination
/// that names a credential file (`token_file`, `password_file`) before or after the change. The
/// server reads that file when it sends and puts what it holds in the request to the
/// destination's address (or the mail server's login), so choosing the file, or where its content
/// goes, is for someone trusted with the node's secrets. A delete only takes away: the operator
/// role is enough. Dry runs and writes forwarded from another node are checked the same way.
fn credential_guard(w: &ManagedWrite, current: Option<&serde_json::Value>) -> Result<(), Problem> {
    let Some(after) = w.body.as_ref().filter(|_| !w.by_admin) else {
        return Ok(());
    };
    let mut fields = credential_fields(after);
    for f in current.map(credential_fields).unwrap_or_default() {
        if !fields.contains(&f) {
            fields.push(f);
        }
    }
    if fields.is_empty() {
        return Ok(());
    }
    Err(Problem::new(
        Code::Forbidden,
        format!(
            "an alert destination with `{}` is added or changed only by an administrator",
            fields.join("` or `")
        ),
    )
    .hint("Setting or changing a credential file needs an administrator. A destination without one, or deleting this one, needs only the operator role."))
}

/// REQ: API-002, T8.2 (ADR-181, as ADR-179) — a router is added, changed or removed only by an
/// administrator: an admin's own sign-in or admin API token (`by_admin`), never an agent token. A
/// router holds credentials and says where they're sent, so every write is one, a delete and a
/// change that keeps the key included. Checked first, before anything in the body is looked at,
/// for dry runs and for writes forwarded from another node alike.
fn router_guard(w: &ManagedWrite) -> Result<(), Problem> {
    if w.kind != ManagedKind::Router || w.by_admin {
        return Ok(());
    }
    Err(Problem::new(
        Code::Forbidden,
        "a router is added, changed or removed only by an administrator",
    )
    .hint("Routers hold credentials and say where they're sent: use an administrator's own sign-in or an admin API token (agent tokens can't)."))
}

/// REQ: OBS-010, API-002 (ADR-179) — a credential file an alert destination made through the API
/// names is in a folder meant for secrets ([`crate::secret_path`]): otherwise a 422 that names the
/// field and the folders. The message is the same whatever is, or isn't, at that path. Blocking
/// (the check may look at the filesystem; writes are planned on a blocking thread).
fn credential_place(d: &telltale_config::AlertDestination, data_dir: &str) -> Result<(), Problem> {
    for (field, path) in [
        ("token_file", &d.token_file),
        ("password_file", &d.password_file),
    ] {
        if let Some(p) = path
            && !crate::secret_path::allowed(p.as_str(), data_dir)
        {
            return Err(Problem::new(
                Code::InvalidConfig,
                format!("`{field}`: use {}", crate::secret_path::places()),
            )
            .hint("Keep the file in a Docker or Compose secret (/run/secrets/), a Kubernetes Secret (the Helm chart's secretMounts, /etc/telltale-secrets/), or the data directory's secrets/ folder, and name that path."));
        }
    }
    Ok(())
}

/// REQ: UPS-011, API-002 (ADR-180) — an upstream group or a client group written through the API
/// (`entries`, with the write in them) that names what the merge leaves out because it names a
/// program or a local socket (a plugin upstream, a forward's plugin server, an upstream group left
/// out with them) is refused, rather than stored and adjusted.
fn left_out_guard(
    kind: ManagedKind,
    name: &str,
    file: &telltale_config::Config,
    entries: &crate::managed::Entries,
) -> Result<(), Problem> {
    fn set<'a, T>(stored: &'a [(String, crate::managed::Ovr<T>)], name: &str) -> Option<&'a T> {
        match stored.iter().find(|(n, _)| n == name) {
            Some((_, crate::managed::Ovr::Set(v))) => Some(v),
            _ => None,
        }
    }
    let named: Option<Vec<String>> = match kind {
        ManagedKind::UpstreamGroup => set(&entries.upstream_groups, name)
            .map(|g| g.members.iter().map(ToString::to_string).collect()),
        ManagedKind::Group => set(&entries.groups, name)
            .and_then(|g| g.upstreams.as_ref())
            .map(|u| vec![u.to_string()]),
        _ => None,
    };
    let Some(named) = named else {
        return Ok(());
    };
    let out = crate::managed::left_out_names(file, entries);
    let (field, list, what) = if kind == ManagedKind::UpstreamGroup {
        ("members", &out.upstreams, "upstream")
    } else {
        ("upstreams", &out.groups, "upstream group")
    };
    if let Some(n) = named.iter().find(|n| list.contains(*n)) {
        return Err(Problem::new(
            Code::InvalidConfig,
            format!(
                "`{field}`: {what} `{n}` isn't used: it names a program or a local socket, or has only upstreams that do"
            ),
        )
        .hint("Plugin upstreams (`exec://`, `unix://`) are defined in the config file."));
    }
    Ok(())
}

/// REQ: API-002 (T7.5, ADR-069) — a change to an upstream, upstream group, list, or group: it
/// may override or hide the files' entry of the same name. `PUT` stores a definition; `DELETE`
/// removes what the API stored (so the files' entry, if any, is back), or else hides the
/// files' entry. The merged configuration must validate.
#[allow(clippy::too_many_lines)] // one branch per kind of entry
fn plan_override(
    src: &Sources,
    state: &telltale_store::state::State,
    w: &ManagedWrite,
) -> Result<ManagedPlan, Problem> {
    use crate::managed::Named;
    let name = w.name.trim().to_owned();
    if name.is_empty() {
        return Err(Problem::invalid("the name is empty"));
    }
    let file = src.file_config.load_full();
    let mut entries = crate::managed::entries(state);
    let before_cfg = crate::managed::merge(&file, &entries).unwrap_or_else(|_| (*file).clone());
    // REQ: API-002, T8.2 (ADR-181) — routers are an administrator's (checked again here, where
    // every write is planned; `do_write_managed` checks before a body's keys are looked at).
    router_guard(w)?;
    // REQ: T8.2, API-002 (ADR-190) — a FRITZ!Box from the UI or the API signs in, so its
    // password is pasted, sent only over https:// and kept like any router key; one read
    // without a sign-in (a box's open TR-064) stays the configuration file's (ADR-189).
    if w.kind == ManagedKind::Router
        && let Some(body) = w.body.as_ref()
        && body.get("type").and_then(serde_json::Value::as_str) == Some("fritzbox")
        && body
            .get("username")
            .and_then(serde_json::Value::as_str)
            .is_none_or(|u| u.trim().is_empty())
    {
        return Err(Problem::new(
            Code::InvalidConfig,
            "`username`: a FRITZ!Box router set through the UI or the API signs in with a username and its password",
        )
        .hint("Give a FRITZ!Box user and paste its password, over the box's https:// address (port 49443). A box read without a sign-in is a `[[router]]` entry in the configuration file."));
    }
    // REQ: OBS-010, API-002 (ADR-179) — before anything else about the body is checked, so
    // whoever is refused learns nothing more.
    if w.kind == ManagedKind::AlertDestination {
        let current = before_cfg
            .alerts
            .destination
            .iter()
            .find(|u| u.name() == name)
            .map(|d| serde_json::to_value(d).unwrap_or_default());
        credential_guard(w, current.as_ref())?;
    }
    // REQ: UPS-011, API-002 (ADR-180) — likewise first: plugin upstreams are the config file's.
    if w.kind == ManagedKind::Upstream
        && let Some(field) = w.body.as_ref().and_then(plugin_field_of)
    {
        return Err(plugin_refused(field));
    }
    // REQ: FLT-004, API-002 (ADR-180) — likewise first: a list's local file is an
    // administrator's to choose.
    if w.kind == ManagedKind::List {
        let current = before_cfg
            .list
            .iter()
            .find(|l| l.name() == name)
            .and_then(|l| l.path.as_ref())
            .map(ToString::to_string);
        local_file_guard(w, current.as_deref())?;
    }
    // REQ: API-002 (T9.22) — removing an upstream also takes it out of its upstream groups.
    // A DELETE that reverts an override of the files' entry (or un-hides it) brings the
    // upstream back: nothing to cascade.
    let reverting = entries.upstreams.iter().any(|(n, _)| *n == name)
        && file.upstream.iter().any(|u| u.name() == name);
    let (also, also_groups) = if w.kind == ManagedKind::Upstream && w.body.is_none() && !reverting {
        upstream_cascade(&name, &file, &mut entries)?
    } else {
        (Vec::new(), Vec::new())
    };
    if w.kind == ManagedKind::UpstreamGroup && w.body.is_none() {
        upstream_group_in_use(&name, &file, &entries, &before_cfg)?;
    }

    let (before, body) = match w.kind {
        ManagedKind::Upstream => override_step(
            &name,
            w.body.as_ref(),
            file.upstream.iter().any(|u| u.name() == name),
            before_cfg.upstream.iter().find(|u| u.name() == name),
            &mut entries.upstreams,
        )?,
        ManagedKind::UpstreamGroup => override_step(
            &name,
            w.body.as_ref(),
            file.upstream_group.iter().any(|u| u.name() == name),
            before_cfg.upstream_group.iter().find(|u| u.name() == name),
            &mut entries.upstream_groups,
        )?,
        ManagedKind::List => override_step(
            &name,
            w.body.as_ref(),
            file.list.iter().any(|u| u.name() == name),
            before_cfg.list.iter().find(|u| u.name() == name),
            &mut entries.lists,
        )?,
        ManagedKind::AlertDestination => override_step(
            &name,
            w.body.as_ref(),
            file.alerts.destination.iter().any(|u| u.name() == name),
            before_cfg
                .alerts
                .destination
                .iter()
                .find(|u| u.name() == name),
            &mut entries.alert_destinations,
        )?,
        ManagedKind::AlertRule => override_step(
            &name,
            w.body.as_ref(),
            file.alerts.rule.iter().any(|u| u.name() == name),
            before_cfg.alerts.rule.iter().find(|u| u.name() == name),
            &mut entries.alert_rules,
        )?,
        ManagedKind::Schedule => override_step(
            &name,
            w.body.as_ref(),
            file.schedule.iter().any(|u| u.name() == name),
            before_cfg.schedule.iter().find(|u| u.name() == name),
            &mut entries.schedules,
        )?,
        // REQ: T8.2 (ADR-181) — the secrets were swapped for their files' paths already.
        ManagedKind::Router => override_step(
            &name,
            w.body.as_ref(),
            file.router.iter().any(|u| u.name() == name),
            before_cfg.router.iter().find(|u| u.name() == name),
            &mut entries.routers,
        )?,
        ManagedKind::AnomalyMute => override_step(
            &name,
            w.body.as_ref(),
            file.anomaly_mute.iter().any(|u| u.name() == name),
            before_cfg.anomaly_mute.iter().find(|u| u.name() == name),
            &mut entries.anomaly_mutes,
        )?,
        ManagedKind::KubernetesMap => {
            kubernetes_map_step(&name, w.body.as_ref(), &file, &before_cfg, &mut entries)?
        }
        _ => override_step(
            &name,
            w.body.as_ref(),
            file.group.iter().any(|u| u.name() == name),
            before_cfg.group.iter().find(|u| u.name() == name),
            &mut entries.groups,
        )?,
    };
    // REQ: OBS-010, API-002 (ADR-179) — a credential file named here is in a folder meant for
    // secrets, whoever writes it.
    if w.kind == ManagedKind::AlertDestination
        && let Some((_, crate::managed::Ovr::Set(d))) =
            entries.alert_destinations.iter().find(|(n, _)| *n == name)
    {
        credential_place(d, file.node.data_dir.as_str())?;
    }
    left_out_guard(w.kind, &name, &file, &entries)?;
    let merged = crate::managed::merge(&file, &entries).map_err(|errs| {
        // REQ: API-002, T8.2 (ADR-181) — correctness R4: a router written here names no key
        // file; a missing key is said as what to paste.
        let errs = if w.kind == ManagedKind::Router {
            crate::router_secrets::paste_wording(errs)
        } else {
            errs
        };
        Problem::new(Code::InvalidConfig, errs.join("; "))
    })?;
    let after = match w.kind {
        ManagedKind::Upstream => named_json(&merged.upstream, &name),
        ManagedKind::UpstreamGroup => named_json(&merged.upstream_group, &name),
        ManagedKind::List => named_json(&merged.list, &name),
        ManagedKind::AlertDestination => named_json(&merged.alerts.destination, &name),
        ManagedKind::AlertRule => named_json(&merged.alerts.rule, &name),
        ManagedKind::Schedule => named_json(&merged.schedule, &name),
        ManagedKind::Router => named_json(&merged.router, &name),
        ManagedKind::AnomalyMute => named_json(&merged.anomaly_mute, &name),
        ManagedKind::KubernetesMap => merged
            .kubernetes
            .map
            .iter()
            .find(|r| r.key() == name)
            .map(|r| serde_json::to_value(r).unwrap_or_default()),
        _ => named_json(&merged.group, &name),
    };
    let warnings = telltale_config::validate_config(&merged).unwrap_or_default();
    let (recent_queries, impact) = managed_impact(src, w.kind, &name, w.body.is_some());
    let impact = with_cascade(impact, &also_groups);
    Ok(ManagedPlan {
        name,
        before,
        after,
        body,
        recent_queries,
        impact,
        warnings,
        also,
        candidate: merged,
    })
}

impl ApiBackend {
    /// Top-list entries for the API: client names and groups (`client_labels`), and the
    /// clients' split by status (REQ: OBS-004).
    fn top_items(
        &self,
        kind: TopKind,
        tops: Vec<(
            telltale_telemetry::topk::Top<String>,
            Option<telltale_telemetry::agg::ClientStatus>,
        )>,
    ) -> Vec<TopItem> {
        tops.into_iter()
            .map(|(t, s)| {
                let (name, groups) = self.client_labels(kind, &t.key);
                TopItem {
                    key: t.key,
                    name,
                    groups,
                    count: t.count,
                    error_bound: t.error,
                    by_status: s.map(|s| telltale_api::model::ClientStatusCounts {
                        blocked: s.blocked,
                        cached: s.cached,
                        forwarded: s.forwarded,
                    }),
                }
            })
            .collect()
    }

    /// For a client row of a top list: its device name and the groups that apply to it now.
    fn client_labels(&self, kind: TopKind, key: &str) -> (Option<String>, Vec<String>) {
        let Some(ip) = (kind == TopKind::Clients)
            .then(|| key.parse::<IpAddr>().ok())
            .flatten()
        else {
            return (None, Vec::new());
        };
        let state = self.src.pipeline.current();
        let clients = &state.policy.clients;
        // REQ: FLT-017 — a workload's key: its name, and its group (else the default's).
        if telltale_telemetry::workload::is_key(&mapped(ip)) {
            let t = self.src.pipeline.workloads.load();
            let name = t.key_name(&mapped(ip)).map(str::to_owned);
            let group = t
                .by_key(&mapped(ip))
                .and_then(|w| w.group.as_deref().map(str::to_owned))
                .unwrap_or_else(|| "default".to_owned());
            return (name, vec![group]);
        }
        let id = clients.identify(
            ip,
            None,
            None,
            &self.src.pipeline.neighbors,
            &self.src.pipeline.workloads,
        );
        (
            // REQ: CLU-002 (T8.2, T8.3) — an unnamed device by the name its router, mDNS, or a
            // peer knows, as the query log names it (`device_name` checks the configured name
            // first).
            clients
                .client(id)
                .map(|c| c.name.to_string())
                .or_else(|| device_name(&self.src, mapped(ip))),
            clients
                .group_names(id)
                .iter()
                .map(ToString::to_string)
                .collect(),
        )
    }

    /// A group's index by name, or a 400 naming the groups that exist.
    fn group_index(&self, name: &str) -> Result<u16, Problem> {
        let policy = &self.src.pipeline.current().policy;
        let groups = policy.clients.groups();
        groups
            .iter()
            .position(|g| &*g.name == name)
            .and_then(|i| u16::try_from(i).ok())
            .ok_or_else(|| {
                Problem::invalid(format!("`group`: no group named `{name}`")).hint(format!(
                    "Groups: {}.",
                    groups
                        .iter()
                        .map(|g| g.name.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })
    }

    /// REQ: CLU-003 — a replica that follows the primary takes configuration only from it;
    /// writes go to the primary (forwarded automatically once T5.7 lands).
    fn replica_read_only(&self) -> Option<Problem> {
        let cfg = self.src.config.load_full();
        // ADR-048 — under a GitOps authority, configuration changes go to Git on every node.
        if let Some(c) = &self.src.cluster
            && c.identity.reload().meta.config_authority == "gitops"
        {
            return Some(
                Problem::new(
                    telltale_api::problem::Code::GitopsManaged,
                    "this cluster's configuration comes from Git",
                )
                .hint("change it in the Git repository; every node follows within seconds of the primary applying it"),
            );
        }
        let m = crate::replication::applied(&cfg)?;
        let at = self
            .src
            .cluster
            .as_ref()
            .and_then(|c| c.connected_primary())
            .unwrap_or_else(|| format!("node {}", m.primary));
        Some(
            Problem::new(
                telltale_api::problem::Code::Conflict,
                "this node is a cluster replica: its configuration comes from the primary",
            )
            .hint(format!(
                "make this change on the primary ({at}); it reaches every node within seconds"
            )),
        )
    }

    fn managed_names_of(&self, kind: &str) -> Vec<String> {
        self.src
            .auth
            .get()
            .and_then(|a| a.state().managed(kind).ok())
            .map(|m| m.into_iter().map(|e| e.name).collect())
            .unwrap_or_default()
    }

    pub(crate) fn list_local_names(&self) -> Vec<LocalName> {
        let api = self.managed_names_of(crate::managed::RECORD);
        let cfg = self.src.config.load();
        let mut out: Vec<LocalName> = Vec::new();
        for r in &cfg.record {
            let rec = RecordInput {
                rtype: r.rtype.to_ascii_uppercase(),
                value: r.value.to_string(),
                ttl: r.ttl,
            };
            match out
                .iter_mut()
                .find(|n| n.name.eq_ignore_ascii_case(&r.name))
            {
                Some(n) => n.records.push(rec),
                None => out.push(LocalName {
                    name: r.name.to_ascii_lowercase(),
                    records: vec![rec],
                    source: if api.iter().any(|a| a.eq_ignore_ascii_case(&r.name)) {
                        "api".into()
                    } else {
                        "file".into()
                    },
                }),
            }
        }
        out
    }

    pub(crate) fn list_forwards(&self) -> Vec<ForwardInfo> {
        let api = self.managed_names_of(crate::managed::FORWARD);
        let cfg = self.src.config.load();
        // A member's servers: its URL, or (REQ: DNS-022) a stub zone's addresses.
        let servers_of = |name: &str| {
            cfg.upstream
                .iter()
                .find(|u| u.name.as_str() == name)
                .map(|u| {
                    if u.recursive.stub_zone.is_some() {
                        let a = &u.recursive.stub_servers;
                        (a.iter().map(ToString::to_string).collect(), true)
                    } else {
                        (vec![u.url.to_string()], false)
                    }
                })
        };
        let mut out = Vec::new();
        for r in &cfg.route {
            if !r.match_group.is_empty() || !r.match_qtype.is_empty() {
                continue; // per-group or per-type routes aren't "send this domain" routes
            }
            let members: Vec<(Vec<String>, bool)> = cfg
                .upstream_group
                .iter()
                .find(|g| g.name == r.upstream_group)
                .map(|g| g.members.iter().filter_map(|m| servers_of(m)).collect())
                .unwrap_or_default();
            let stub = !members.is_empty() && members.iter().all(|(_, s)| *s);
            let servers: Vec<String> = members.into_iter().flat_map(|(v, _)| v).collect();
            for d in &r.match_suffix {
                out.push(ForwardInfo {
                    domain: d.to_ascii_lowercase(),
                    servers: servers.clone(),
                    stub,
                    source: if api.iter().any(|a| a.eq_ignore_ascii_case(d)) {
                        "api".into()
                    } else {
                        "file".into()
                    },
                });
            }
        }
        out
    }

    /// A write to an entry made through the API (ADR-069): planned, stored and applied. REQ:
    /// API-002, T8.2 (ADR-181) — F3: a write that stores something runs to its end in a task of
    /// its own, so a client that goes away can't stop it between writing a router's new key file
    /// and storing the entry that names it, or between storing and applying. A dry run stores
    /// nothing: it stays tied to its request (a simulation stops when its client goes). The API's
    /// handler runs a change in a task of its own too; this one covers the writes that come
    /// another way (a write a replica forwarded, on the primary: review round 2, R5).
    pub(crate) fn do_write_managed(
        &self,
        w: ManagedWrite,
    ) -> BoxFuture<Result<ConfigChange, Problem>> {
        let src = Arc::clone(&self.src);
        if w.dry_run {
            return Box::pin(run_managed_write(src, w));
        }
        Box::pin(async move {
            tokio::spawn(run_managed_write(src, w)).await.map_err(|e| {
                // Review round 2, R6: the runtime's text stays in the log.
                tracing::error!(error = %e, "a configuration change's task failed");
                Problem::internal("the change didn't finish; the server log says why")
            })?
        })
    }
}

/// [`ApiBackend::do_write_managed`]'s work.
#[allow(clippy::too_many_lines)] // one write, from its plan to its reload
async fn run_managed_write(
    src: Arc<Sources>,
    mut w: ManagedWrite,
) -> Result<ConfigChange, Problem> {
    // REQ: API-002, API-010 (ADR-040) — one change at a time: the plan below is
    // checked against what the store then changes, and the result is applied before
    // the next write looks (two writes planned on the same snapshot could each be
    // valid and together not: the reload would then fall back to the files alone).
    let one_at_a_time = src.config_writes.lock().await;
    // REQ: API-002, T8.2 (ADR-181) — routers are an administrator's: refused before the
    // body's keys are looked at.
    router_guard(&w)?;
    let state = src
        .auth
        .get()
        .map(|a| Arc::clone(a.state()))
        .ok_or_else(|| Problem::unavailable("the state database isn't open yet"))?;
    let (plan, current, secrets, w) = {
        let (src, state) = (Arc::clone(&src), Arc::clone(&state));
        tokio::task::spawn_blocking(move || {
            // REQ: T8.2, API-002 (ADR-181) — a router's pasted secrets, swapped for new
            // files' paths; a key file the body names is refused unless it's the
            // router's own (against what the write is planned on, below).
            let secrets = crate::router_secrets::prepare(&src, &state, &mut w)?;
            let current = state
                .config_version()
                .map_err(|e| Problem::internal(e.to_string()))?;
            plan_managed(&src, &state, &w).map(|p| (p, current, secrets, w))
        })
        .await
        .map_err(|e| Problem::internal(format!("request worker failed: {e}")))??
    };
    // T7.5 — on a Git-managed node, what to add to Git to keep the change.
    let keep_in_git = (src.config.load().cluster.config_source.as_str() == "gitops")
        .then(|| keep_in_git(w.kind, &plan.name, w.body.as_ref(), plan.after.as_ref()));
    let change = |applied, version| ConfigChange {
        applied,
        config_version: version,
        before: plan.before.clone(),
        after: plan.after.clone(),
        recent_queries: plan.recent_queries,
        impact: plan.impact.clone(),
        warnings: plan.warnings.clone(),
        keep_in_git: keep_in_git.clone(),
        simulation: None,
    };
    if w.dry_run {
        if let Some(v) = w.expect
            && v != current
        {
            return Err(version_conflict(current));
        }
        let mut out = change(false, current);
        // REQ: OBS-024 — `simulate`: what the change would have done to the logged
        // queries (after the version check: a stale plan isn't worth replaying).
        // Other writes needn't wait for the replay.
        drop(one_at_a_time);
        if let Some(opts) = &w.simulate {
            out.simulation =
                dry_run_simulation(&src, &state, &plan.candidate, opts, w.by_admin).await?;
        }
        return Ok(out);
    }
    // REQ: T8.2, API-002 (ADR-181) — new key files, recorded for the router as planned (its
    // name, credential and endpoint), removed again unless the entry naming them is stored.
    let secrets = Arc::new(secrets);
    let written = {
        let (secrets, planned) = (
            Arc::clone(&secrets),
            (w.kind == ManagedKind::Router)
                .then(|| {
                    plan.after.as_ref().and_then(|a| {
                        serde_json::from_value::<telltale_config::RouterConfig>(a.clone()).ok()
                    })
                })
                .flatten(),
        );
        tokio::task::spawn_blocking(move || secrets.write(planned.as_ref()))
            .await
            .map_err(|e| Problem::internal(format!("request worker failed: {e}")))??
    };
    let stored = {
        let (state, w, name, body, also) = (
            Arc::clone(&state),
            w.clone(),
            plan.name.clone(),
            plan.body.clone(),
            plan.also.clone(),
        );
        tokio::task::spawn_blocking(move || {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let kind = kind_name(w.kind);
            // REQ: API-002 (T9.22) — what the change also needs, first; the version
            // check applies to the first write.
            let mut expect = w.expect;
            for (k, n, b) in &also {
                let r = match b {
                    Some(b) => state.put_managed(k, n, b, None, expect, now, &w.by),
                    None => state.delete_managed(k, n, expect),
                };
                r?;
                expect = None;
            }
            let r = match &body {
                Some(b) => state.put_managed(kind, &name, b, None, expect, now, &w.by),
                None => state.delete_managed(kind, &name, expect),
            };
            // REQ: API-002, T8.2 (ADR-181) — F3, security F4: the entry naming the new key
            // files is stored, so they stay, kept here as the store returns (a runtime shutdown
            // after this can't remove them), whatever the reload says next. A store that failed
            // removes them, on this blocking thread.
            if r.is_ok() {
                written.keep();
            } else {
                drop(written);
            }
            r
        })
        .await
        .map_err(|e| Problem::internal(format!("request worker failed: {e}")))?
    };
    let version = stored.map_err(|e| match e {
        ManagedError::VersionConflict { current } => version_conflict(current),
        ManagedError::NotFound { .. } => Problem::not_found(e.to_string()),
        ManagedError::State(e) => Problem::internal(e.to_string()),
    })?;
    provenance(&w.by, version);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let applied = src.reload.send(tx).await.is_ok() && rx.await.unwrap_or(false);
    if !applied {
        return Err(Problem::internal(
            "the change was saved but couldn't be applied; the server log says why",
        ));
    }
    // Only once the change is in effect: the router's old files that nothing names now.
    if w.kind == ManagedKind::Router {
        let src = Arc::clone(&src);
        let _ = tokio::task::spawn_blocking(move || secrets.prune(&src)).await;
    }
    Ok(change(true, version))
}

/// REQ: OBS-024 — a dry run's `simulate`: what `candidate` (the planned configuration) would have
/// done to the logged queries, against the configuration the API's entries make now.
async fn dry_run_simulation(
    src: &Arc<Sources>,
    state: &telltale_store::state::State,
    candidate: &telltale_config::Config,
    opts: &telltale_api::SimulateOpts,
    by_admin: bool,
) -> Result<Option<telltale_api::model::Simulation>, Problem> {
    let baseline = Arc::new(
        crate::managed::merge(
            &src.file_config.load_full(),
            &crate::managed::entries(state),
        )
        .map_err(|errs| Problem::internal(errs.join("; ")))?,
    );
    let candidate = Arc::new(candidate.clone());
    // REQ: OBS-024 (ADR-180) — the rule of `POST /api/v1/simulate`, before anything is read:
    // here the plan still answers, and its simulation says it wasn't run.
    let running = src.config.load_full();
    let asked = !opts.auto || running.simulate.plans_by_default;
    if asked && !by_admin && crate::simulate::new_local_name(&baseline, &candidate).is_some() {
        return Ok(Some(crate::simulate::local_name_unavailable()));
    }
    // REQ: OBS-024 (ADR-180) — likewise for a change that would fetch more lists than one
    // simulation may on this node.
    if asked && crate::simulate::over_fetch_limit(&running, &baseline, &candidate).is_some() {
        return Ok(Some(crate::simulate::fetch_limit_unavailable()));
    }
    crate::simulate::simulate(src, baseline, candidate, opts).await
}

/// REQ: OBS-033 — the change about to be applied came from `by` and is configuration
/// version `version`: for its `config.applied` marker.
fn provenance(by: &str, version: u64) {
    if let Some(a) = crate::annotations::get() {
        a.set_provenance(crate::annotations::Provenance {
            source: telltale_api::annotations_api::source_of(by).to_owned(),
            actor: Some(by.to_owned()),
            seq: Some(version),
            filter_version: None,
        });
    }
}

/// A stable color for a group without one (ADR-050): `default` is neutral; others cycle a
/// palette by position, so colors don't shift when a group's stats change.
fn palette(i: usize, name: &str) -> String {
    const COLORS: [&str; 10] = [
        "#3b82f6", "#22c55e", "#f59e0b", "#ef4444", "#8b5cf6", "#06b6d4", "#ec4899", "#84cc16",
        "#f97316", "#14b8a6",
    ];
    if name == "default" {
        "#94a3b8".into()
    } else {
        COLORS[i % COLORS.len()].into()
    }
}

impl ApiBackend {
    /// `Ok` when `name` is a configured group (pauses are kept by name, so a typo would pause
    /// nobody without saying so).
    fn known_group(&self, name: &str) -> Result<(), Problem> {
        let policy = &self.src.pipeline.current().policy;
        if policy.clients.groups().iter().any(|g| &*g.name == name) {
            Ok(())
        } else {
            Err(Problem::invalid(format!("`group`: no group `{name}`"))
                .hint("GET /api/v1/groups lists them."))
        }
    }
}

/// REQ: API-002 (T7.5, ADR-069) — the configuration TOML that makes an API change permanent in
/// Git: the section(s) to add (from what the request set), or which block to remove.
/// REQ: DNS-014, OBS-022 — `[ratelimit]` and `[exclusions]` are one table each, not arrays, and
/// there is nothing to remove: a revert just makes the configuration's own apply again.
fn singleton_in_git(
    head: &str,
    section: &str,
    set: bool,
    after: Option<&serde_json::Value>,
) -> String {
    match after {
        Some(a) if set => {
            let mut root = toml::Table::new();
            if let Ok(toml::Value::Table(t)) = toml::Value::try_from(a) {
                root.insert(section.to_owned(), toml::Value::Table(t));
            }
            format!("{head}{}", toml::to_string(&root).unwrap_or_default())
        }
        _ => format!(
            "# Nothing to change in Git: the configuration's own [{section}] applies again.\n"
        ),
    }
}

#[allow(clippy::too_many_lines)] // one branch per kind of entry
fn keep_in_git(
    kind: ManagedKind,
    name: &str,
    body: Option<&serde_json::Value>,
    after: Option<&serde_json::Value>,
) -> String {
    let section = match kind {
        ManagedKind::Record => "record",
        ManagedKind::Forward => "route",
        ManagedKind::Rule => "rule",
        ManagedKind::Upstream => "upstream",
        ManagedKind::UpstreamGroup => "upstream_group",
        ManagedKind::List => "list",
        ManagedKind::Group => "group",
        ManagedKind::AlertDestination => "alerts.destination",
        ManagedKind::AlertRule => "alerts.rule",
        ManagedKind::Schedule => "schedule",
        ManagedKind::AnomalyMute => "anomaly_mute",
        ManagedKind::RateLimit => "ratelimit",
        ManagedKind::Exclusions => "exclusions",
        ManagedKind::Simulate => "simulate",
        ManagedKind::Rollout => "cluster.rollout",
        ManagedKind::KubernetesMap => "kubernetes.map",
        ManagedKind::Router => "router",
    };
    let head = "# Add to the configuration in Git (with the Helm chart: under `config:`).\n";
    // REQ: FLT-017 — a map rule: `[[kubernetes.map]]`, or a label on the namespace or pod.
    if kind == ManagedKind::KubernetesMap {
        let Some(a) = after.filter(|_| body.is_some()) else {
            return format!(
                "# Remove the [[kubernetes.map]] rule `{name}` from the configuration in Git.\n"
            );
        };
        let mut out = String::from(head);
        if let Ok(toml::Value::Table(rule)) = toml::Value::try_from(a) {
            let mut kube = toml::Table::new();
            kube.insert(
                "map".into(),
                toml::Value::Array(vec![toml::Value::Table(rule)]),
            );
            let mut root = toml::Table::new();
            root.insert("kubernetes".into(), toml::Value::Table(kube));
            if let Ok(s) = toml::to_string(&root) {
                out.push_str(&s);
            }
        }
        out.push_str("# Or label the namespace: kubectl label namespace <namespace> telltaledns.io/group=<group>\n");
        return out;
    }
    if matches!(
        kind,
        ManagedKind::RateLimit
            | ManagedKind::Exclusions
            | ManagedKind::Simulate
            | ManagedKind::Rollout
    ) {
        return singleton_in_git(head, section, body.is_some(), after);
    }
    let Some(body) = body else {
        return if after.is_some() {
            format!(
                "# Nothing to change in Git: the configuration's own [[{section}]] `{name}` applies again.\n"
            )
        } else {
            format!("# Remove the [[{section}]] `{name}` from the configuration in Git.\n")
        };
    };
    // Tables to render under `section`: one per record, the request's fields otherwise.
    let tables: Vec<(&str, serde_json::Value)> = match kind {
        ManagedKind::Record => body
            .get("records")
            .and_then(serde_json::Value::as_array)
            .map(|rs| {
                rs.iter()
                    .map(|r| {
                        let mut t = r.clone();
                        if let Some(o) = t.as_object_mut() {
                            o.insert("name".into(), name.into());
                        }
                        ("record", t)
                    })
                    .collect()
            })
            .unwrap_or_default(),
        ManagedKind::Forward => {
            let group = crate::managed::forward_group(name);
            let servers: Vec<String> = body
                .get("servers")
                .and_then(serde_json::Value::as_array)
                .map(|v| {
                    v.iter()
                        .filter_map(|s| s.as_str().map(crate::managed::server_url))
                        .collect()
                })
                .unwrap_or_default();
            let stub = body
                .get("stub")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let (mut t, members): (Vec<(&str, serde_json::Value)>, Vec<String>) = if stub {
                // REQ: DNS-022 — one recursive upstream that starts at the zone's servers.
                let up = crate::managed::stub_upstream_name(&group);
                let addrs: Vec<String> = servers
                    .iter()
                    .filter_map(|s| crate::managed::stub_addr(s).map(|a| a.to_string()))
                    .collect();
                (
                    vec![(
                        "upstream",
                        serde_json::json!({ "name": up, "url": "recursive://",
                            "recursive": { "stub_zone": name, "stub_servers": addrs } }),
                    )],
                    vec![up],
                )
            } else {
                (
                    servers
                        .iter()
                        .enumerate()
                        .map(|(i, url)| {
                            (
                                "upstream",
                                serde_json::json!({ "name": format!("{group}#{}", i + 1), "url": url }),
                            )
                        })
                        .collect(),
                    (1..=servers.len()).map(|i| format!("{group}#{i}")).collect(),
                )
            };
            t.push((
                "upstream_group",
                serde_json::json!({ "name": group, "members": members, "strategy": "failover" }),
            ));
            t.push(("route", serde_json::json!({ "match_suffix": [name], "upstream_group": group, "dnssec_nta": true })));
            t
        }
        ManagedKind::Rule => after.map(|a| vec![("rule", a.clone())]).unwrap_or_default(),
        // REQ: API-002, T8.2 (ADR-181) — F8: in Git a router's key is a Secret every pod can
        // mount (the chart's `secretMounts`), not the file one node saved in its data directory.
        ManagedKind::Router => {
            let mut t = serde_json::Map::new();
            t.insert("name".into(), name.into());
            for (k, v) in body.as_object().into_iter().flatten() {
                if k == "name" {
                    continue;
                }
                let secret = telltale_api::ROUTER_CREDENTIALS
                    .iter()
                    .find(|(_, file_field)| *file_field == k.as_str());
                // Security F8: one safe folder name, whatever the router's name holds.
                let v = match secret {
                    Some((field, _)) => serde_json::Value::String(format!(
                        "/etc/telltale-secrets/{}/{field}",
                        crate::router_secrets::slug(name)
                    )),
                    None => v.clone(),
                };
                t.insert(k.clone(), v);
            }
            vec![(section, serde_json::Value::Object(t))]
        }
        _ => {
            let mut t = body.clone();
            if let Some(o) = t.as_object_mut() {
                // `name` first, as people write it.
                let mut ordered = serde_json::Map::new();
                ordered.insert("name".into(), name.into());
                for (k, v) in o.iter().filter(|(k, _)| *k != "name") {
                    ordered.insert(k.clone(), v.clone());
                }
                *o = ordered;
            }
            vec![(section, t)]
        }
    };
    let mut out = String::from(head);
    if kind == ManagedKind::Router {
        out.push_str("# Its keys: put each in a Kubernetes Secret mounted with the chart's `secretMounts` (name: the router's), or in a Docker secret under /run/secrets/ (then name that file), and paste nothing in the UI. The files this node saved stay on this node.\n");
    }
    for (sec, t) in tables {
        let mut root = toml::Table::new();
        let Ok(toml::Value::Table(table)) = toml::Value::try_from(&t) else {
            continue;
        };
        root.insert(
            sec.to_owned(),
            toml::Value::Array(vec![toml::Value::Table(table)]),
        );
        if let Ok(s) = toml::to_string(&root) {
            out.push_str(&s);
        }
    }
    out
}

/// REQ: DNS-006 (T6.15) — `[cache]` as the API shows it.
fn cache_settings(c: &telltale_config::CacheConfig) -> telltale_api::model::CacheSettings {
    telltale_api::model::CacheSettings {
        max_bytes: c.max_bytes.bytes(),
        max_entries: (c.max_entries > 0).then_some(u64::from(c.max_entries)),
        min_ttl_seconds: c.min_ttl,
        max_ttl_seconds: c.max_ttl,
        negative_ttl_max_seconds: c.negative_ttl_max,
        servfail_ttl_seconds: c.servfail_ttl,
        serve_stale: c.serve_stale,
        stale_max_age_seconds: c.stale_max_age,
        stale_answer_wait_ms: Some(c.stale_answer_client_timeout_ms),
        prefetch: c.prefetch,
        prefetch_threshold_percent: c.prefetch_threshold_pct,
        prefetch_min_hits: c.prefetch_min_hits,
        persist: c.persist,
    }
}

/// Count buckets as API time buckets (groups by their current names).
fn time_buckets(src: &Sources, series: Vec<(u64, Counts)>) -> Vec<TimeBucket> {
    let groups: Vec<String> = src
        .pipeline
        .current()
        .policy
        .clients
        .groups()
        .iter()
        .map(|g| g.name.to_string())
        .collect();
    let ups = crate::rollups::upstream_names(&src.pipeline);
    series
        .into_iter()
        .map(|(start, c)| {
            let mut b = TimeBucket {
                start_unix_seconds: start,
                total: c.total,
                upstream_queries: c.upstreams.iter().sum(),
                upstream_failures: c.upstream_failures,
                slow: c.slow,
                ..TimeBucket::default()
            };
            for (i, s) in Status::ALL.iter().enumerate() {
                if c.status[i] > 0 {
                    b.by_status.insert(s.label().to_owned(), c.status[i]);
                }
            }
            for (i, n) in c.qtype.iter().enumerate() {
                if *n > 0 {
                    let key = QTYPES.get(i).map_or("other", |(_, name)| name);
                    b.by_qtype.insert(key.to_owned(), *n);
                }
            }
            for (i, n) in c.rcode.iter().enumerate() {
                if *n > 0 {
                    let key = if i == N_RCODE - 1 {
                        "other".to_owned()
                    } else {
                        rcode_name(u8::try_from(i).unwrap_or(u8::MAX))
                    };
                    b.by_rcode.insert(key, *n);
                }
            }
            // ADR-050 — by group (index → name; indexes past the table are "other").
            for (i, n) in c.groups.iter().enumerate() {
                if *n > 0 {
                    let key = groups.get(i).cloned().unwrap_or_else(|| "other".into());
                    *b.by_group.entry(key).or_default() += n;
                }
            }
            for (i, n) in c.group_blocked.iter().enumerate() {
                if *n > 0 {
                    let key = groups.get(i).cloned().unwrap_or_else(|| "other".into());
                    *b.blocked_by_group.entry(key).or_default() += n;
                }
            }
            // T6.16 — stored buckets carry groups by name.
            for g in &c.named_groups {
                if g.total > 0 {
                    *b.by_group.entry(g.name.to_string()).or_default() += g.total;
                }
                if g.blocked > 0 {
                    *b.blocked_by_group.entry(g.name.to_string()).or_default() += g.blocked;
                }
            }
            if let Some(bad) = c.bad.as_deref() {
                bad_maps(&mut b, bad, &ups);
            }
            if let Some(lat) = c.lat.as_deref() {
                lat_rows(&mut b, lat, &ups);
            }
            if let Some(flow) = c.flow.as_deref() {
                flow_map(&mut b, flow, &groups, &ups);
            }
            b
        })
        .collect()
}

/// REQ: OBS-030 — a bucket's latency rows: by path label, and `upstream:<name>` (live buckets by
/// ID through `ups`, stored ones by name).
fn lat_rows(b: &mut TimeBucket, lat: &telltale_telemetry::agg::Lat, ups: &[String]) {
    for (p, row) in telltale_telemetry::Path::ALL.iter().zip(&lat.by_path) {
        if row.iter().any(|n| *n > 0) {
            b.latency_hist.insert(p.label().to_owned(), row.to_vec());
        }
    }
    let mut add = |key: String, row: &[u32]| {
        let into = b
            .latency_hist
            .entry(key)
            .or_insert_with(|| vec![0; row.len()]);
        for (x, y) in into.iter_mut().zip(row) {
            *x += y;
        }
    };
    for (i, row) in lat.by_upstream.iter().enumerate() {
        if i > 0 && row.iter().any(|n| *n > 0) {
            let name = ups
                .get(i)
                .filter(|n| !n.is_empty())
                .cloned()
                .unwrap_or_else(|| "other".into());
            add(format!("upstream:{name}"), row);
        }
    }
    for (k, row) in &lat.named_upstream {
        add(format!("upstream:{k}"), row);
    }
}

/// The name of a bucket's response-code column (the last holds every higher code).
fn rcode_column(i: usize) -> String {
    if i >= N_RCODE - 1 {
        "other".to_owned()
    } else {
        rcode_name(u8::try_from(i).unwrap_or(u8::MAX))
    }
}

/// REQ: OBS-032 — a bucket's flow joints as `gs:<group>/<status>`, `sr:<status>/<rcode>`,
/// `su:<status>/<upstream>`, `ur:<upstream>/<rcode>` (live buckets through this node's group and
/// upstream tables; stored ones carry names and rcode numbers).
fn flow_map(
    b: &mut TimeBucket,
    flow: &telltale_telemetry::agg::Flow,
    groups: &[String],
    ups: &[String],
) {
    use telltale_telemetry::agg::{Joint, flow_unkey};
    let status = |i: usize| Status::ALL.get(i).map_or("other", |s| s.label());
    let named = |v: &[String], i: usize| {
        v.get(i)
            .filter(|n| !n.is_empty())
            .cloned()
            .unwrap_or_else(|| "other".into())
    };
    for (k, n) in &flow.live {
        let key = match flow_unkey(*k) {
            (Joint::GroupStatus, g, s) => format!("gs:{}/{}", named(groups, g), status(s)),
            (Joint::StatusRcode, s, r) => format!("sr:{}/{}", status(s), rcode_column(r)),
            (Joint::StatusUpstream, s, u) => format!("su:{}/{}", status(s), named(ups, u)),
            (Joint::UpstreamRcode, u, r) => format!("ur:{}/{}", named(ups, u), rcode_column(r)),
        };
        *b.flow.entry(key).or_default() += n;
    }
    for (k, n) in &flow.named {
        let key = match (k.split_at_checked(3), k.rsplit_once('/')) {
            (Some(("sr:" | "ur:", _)), Some((head, code))) => match code.parse::<usize>() {
                Ok(r) => format!("{head}/{}", rcode_column(r)),
                Err(_) => continue,
            },
            _ => k.to_string(),
        };
        *b.flow.entry(key).or_default() += n;
    }
}

/// REQ: OBS-027 — a bucket's bad answers as the API's maps: statuses by label, upstreams by name
/// (live buckets by ID through this node's upstream table, `ups`; stored ones carry names), and
/// slow answers' response codes by name.
fn bad_maps(b: &mut TimeBucket, bad: &telltale_telemetry::agg::Bad, ups: &[String]) {
    for (i, s) in Status::ALL.iter().enumerate() {
        if bad.servfail_status[i] > 0 {
            b.servfail_by_status
                .insert(s.label().to_owned(), bad.servfail_status[i]);
        }
        if bad.slow_status[i] > 0 {
            b.slow_by_status
                .insert(s.label().to_owned(), bad.slow_status[i]);
        }
    }
    for (i, n) in bad.slow_rcode.iter().enumerate() {
        if *n > 0 {
            let key = if i == N_RCODE - 1 {
                "other".to_owned()
            } else {
                rcode_name(u8::try_from(i).unwrap_or(u8::MAX))
            };
            *b.slow_by_rcode.entry(key).or_default() += n;
        }
    }
    let name = |i: usize| -> String {
        if i == 0 {
            "none".to_owned()
        } else {
            ups.get(i)
                .filter(|n| !n.is_empty())
                .cloned()
                .unwrap_or_else(|| "other".into())
        }
    };
    for (i, n) in bad.servfail_upstream.iter().enumerate() {
        if *n > 0 {
            *b.servfail_by_upstream.entry(name(i)).or_default() += n;
        }
    }
    for (i, n) in bad.slow_upstream.iter().enumerate() {
        if *n > 0 {
            *b.slow_by_upstream.entry(name(i)).or_default() += n;
        }
    }
    for (k, n) in &bad.named_servfail_upstream {
        *b.servfail_by_upstream.entry(k.to_string()).or_default() += n;
    }
    for (k, n) in &bad.named_slow_upstream {
        *b.slow_by_upstream.entry(k.to_string()).or_default() += n;
    }
}

#[cfg(test)]
mod keep_in_git_tests {
    use super::*;

    /// REQ: API-002, T8.2 (ADR-181) — F8: "Keep it in Git" for a router names each key as a file
    /// of a Kubernetes Secret mounted with the chart's `secretMounts`
    /// (`/etc/telltale-secrets/<router>/<credential>`), not the file one node saved under its
    /// data directory; it says so, and the rest of the router is as written.
    #[test]
    fn api_002_keep_in_git_names_a_secret_mount_for_a_router_key() {
        let toml_text = keep_in_git(
            ManagedKind::Router,
            "fw",
            Some(&serde_json::json!({
                "type": "opnsense", "url": "https://opnsense.lan",
                "api_key_file": "/var/lib/telltale/secrets/router-fw.api_key.0123456789abcdef",
                "api_secret_file": "/var/lib/telltale/secrets/router-fw.api_secret.fedcba9876543210",
            })),
            None,
        );
        assert!(!toml_text.contains("/var/lib/telltale"), "{toml_text}");
        assert!(toml_text.contains("secretMounts"), "{toml_text}");
        let parsed: toml::Table = toml::from_str(&toml_text).unwrap();
        let r = &parsed["router"][0];
        assert_eq!(r["name"].as_str(), Some("fw"));
        assert_eq!(r["url"].as_str(), Some("https://opnsense.lan"));
        assert_eq!(
            r["api_key_file"].as_str(),
            Some("/etc/telltale-secrets/fw/api_key")
        );
        assert_eq!(
            r["api_secret_file"].as_str(),
            Some("/etc/telltale-secrets/fw/api_secret")
        );
        assert!(r.get("password_file").is_none());
    }

    /// REQ: API-002, T8.2 (ADR-181) — security F8: the Secret folder Keep it in Git names for a
    /// router is one safe folder name, whatever the router's name holds (`/`, `..`).
    #[test]
    fn api_002_keep_in_git_uses_a_safe_folder_name() {
        let toml_text = keep_in_git(
            ManagedKind::Router,
            "a/../b",
            Some(&serde_json::json!({
                "type": "unifi", "url": "https://192.168.1.1",
                "api_key_file": "/var/lib/telltale/secrets/router-a_.._b-0123abcd.api_key.0123456789abcdef",
            })),
            None,
        );
        let parsed: toml::Table = toml::from_str(&toml_text).unwrap();
        let f = parsed["router"][0]["api_key_file"]
            .as_str()
            .unwrap()
            .to_owned();
        let rest = f.strip_prefix("/etc/telltale-secrets/").unwrap_or_default();
        let parts: Vec<&str> = rest.split('/').collect();
        assert_eq!(parts.len(), 2, "{f}");
        assert!(
            parts[0]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{f}"
        );
        assert_eq!(parts[1], "api_key", "{f}");
    }

    /// REQ: API-002 (T7.5) — the TOML that keeps an API change in Git.
    #[test]
    fn api_002_keep_in_git_toml() {
        let up = keep_in_git(
            ManagedKind::Upstream,
            "quad9",
            Some(
                &serde_json::json!({ "url": "tls://9.9.9.9", "tls_server_name": "dns.quad9.net" }),
            ),
            None,
        );
        assert!(up.contains("[[upstream]]\nname = \"quad9\"\n"), "{up}");
        assert!(up.contains("url = \"tls://9.9.9.9\""), "{up}");
        let parsed: toml::Table = toml::from_str(&up).unwrap();
        assert_eq!(
            parsed["upstream"][0]["tls_server_name"].as_str(),
            Some("dns.quad9.net")
        );
        let rec = keep_in_git(
            ManagedKind::Record,
            "nas.home",
            Some(&serde_json::json!({ "records": [{ "type": "A", "value": "192.168.1.10" }] })),
            None,
        );
        let parsed: toml::Table = toml::from_str(&rec).unwrap();
        assert_eq!(parsed["record"][0]["name"].as_str(), Some("nas.home"));
        let fwd = keep_in_git(
            ManagedKind::Forward,
            "corp.example",
            Some(&serde_json::json!({ "servers": ["10.0.0.53"] })),
            None,
        );
        let parsed: toml::Table = toml::from_str(&fwd).unwrap();
        assert_eq!(
            parsed["route"][0]["upstream_group"].as_str(),
            Some("forward:corp.example")
        );
        assert_eq!(
            parsed["upstream"][0]["url"].as_str(),
            Some("udp://10.0.0.53")
        );
        // REQ: DNS-022 — a stub forward is one recursive upstream with the stub fields.
        let stub = keep_in_git(
            ManagedKind::Forward,
            "corp.example",
            Some(&serde_json::json!({ "servers": ["10.0.0.53"], "stub": true })),
            None,
        );
        let parsed: toml::Table = toml::from_str(&stub).unwrap();
        let up = &parsed["upstream"][0];
        assert_eq!(up["url"].as_str(), Some("recursive://"));
        assert_eq!(up["recursive"]["stub_zone"].as_str(), Some("corp.example"));
        assert_eq!(
            parsed["upstream_group"][0]["members"][0].as_str(),
            Some("forward:corp.example#stub")
        );
        // ...and the stored entry and the change it shows keep the flag.
        let f = forward_of(
            &serde_json::json!({ "servers": ["10.0.0.53"], "stub": true }),
            "corp.example",
        )
        .unwrap();
        assert!(f.stub);
        assert_eq!(forward_json("corp.example", &f)["stub"], true);
        let plain = forward_of(
            &serde_json::json!({ "servers": ["10.0.0.53"] }),
            "corp.example",
        )
        .unwrap();
        assert!(forward_json("corp.example", &plain).get("stub").is_none());
        assert!(
            forward_of(
                &serde_json::json!({ "servers": ["tls://10.0.0.53"], "stub": true }),
                "corp.example"
            )
            .is_err()
        );
        let gone = keep_in_git(ManagedKind::List, "ads", None, None);
        assert!(gone.starts_with("# Remove the [[list]] `ads`"), "{gone}");
        let back = keep_in_git(ManagedKind::List, "ads", None, Some(&serde_json::json!({})));
        assert!(back.contains("Nothing to change in Git"), "{back}");
    }
}

#[cfg(test)]
mod upstream_group_tests {
    use super::*;

    fn cfg(toml: &str) -> telltale_config::Config {
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
            .map_err(|e| format!("{e:?}"))
            .unwrap()
            .config
    }

    /// REQ: UPS-007 (T9.25) — an upstream group in use by a client group or a route can't be
    /// removed; one nothing uses can, and so can reverting an override of the files' entry.
    #[test]
    fn ups_007_upstream_group_in_use() {
        let c = cfg(r#"[[upstream]]
name = "a"
url = "udp://127.0.0.1:9"
[[upstream_group]]
name = "default"
members = ["a"]
[[upstream_group]]
name = "family"
members = ["a"]
[[upstream_group]]
name = "spare"
members = ["a"]
[[route]]
match_suffix = ["home.arpa"]
upstream_group = "family"
[[group]]
name = "kids"
upstreams = "family"
"#);
        let none = crate::managed::Entries::default();
        let err = upstream_group_in_use("family", &c, &none, &c).unwrap_err();
        let text = format!("{err:?}");
        assert!(
            text.contains("in use by group `kids` and 1 route"),
            "{text}"
        );
        assert!(upstream_group_in_use("spare", &c, &none, &c).is_ok());
        let mut overridden = crate::managed::Entries::default();
        let g = c
            .upstream_group
            .iter()
            .find(|g| g.name.as_str() == "family")
            .unwrap();
        overridden
            .upstream_groups
            .push(("family".into(), crate::managed::Ovr::Set(g.clone())));
        assert!(upstream_group_in_use("family", &c, &overridden, &c).is_ok());
    }
}

#[cfg(test)]
mod stale_tests {
    use super::*;

    /// REQ: OBS-023 (T12.3) — an enabled URL list unchanged for its limit (the list's, else
    /// `[filter]`'s) is stale by whole days; 0 turns it off; files, inline rules, disabled
    /// lists, and lists never downloaded aren't.
    #[test]
    fn obs_023_stale_days() {
        let now = crate::pipeline::unix_now();
        let filter = telltale_config::FilterConfig::default();
        let list = |url: bool, own: Option<u32>| telltale_config::FilterList {
            name: telltale_config::SafeString::new("x".to_owned()).unwrap(),
            url: url.then(|| {
                telltale_config::SafeString::new("https://l.example/x".to_owned()).unwrap()
            }),
            path: None,
            rules: Vec::new(),
            kind: telltale_config::ListKind::Block,
            match_mode: telltale_config::ListMatch::Subtree,
            enabled: true,
            mode: telltale_config::ListMode::Enforce,
            refresh_secs: None,
            max_bytes: None,
            stale_after_days: own,
        };
        let days = |d: u64| Some(now - d * 86_400 - 60);
        assert_eq!(stale_days(&filter, &list(true, None), days(31)), Some(31));
        assert_eq!(stale_days(&filter, &list(true, None), days(29)), None);
        assert_eq!(stale_days(&filter, &list(true, Some(7)), days(8)), Some(8));
        assert_eq!(stale_days(&filter, &list(true, Some(0)), days(400)), None);
        assert_eq!(
            stale_days(&filter, &list(false, None), days(400)),
            None,
            "not a URL list"
        );
        assert_eq!(
            stale_days(&filter, &list(true, None), None),
            None,
            "never downloaded"
        );
        let mut off = list(true, None);
        off.enabled = false;
        assert_eq!(stale_days(&filter, &off, days(400)), None);
    }
}

#[cfg(test)]
mod ratelimit_tests {
    use super::*;

    fn file(extra: &str) -> telltale_config::Config {
        telltale_config::Loader::new()
            .toml_str("t.toml", extra)
            .env(Vec::<(String, String)>::new())
            .load()
            .map_err(|e| format!("{e:?}"))
            .unwrap()
            .config
    }

    /// REQ: DNS-014 (review 01 q1) — a write replaces the files' `[ratelimit]` as a whole (fields
    /// left out take the defaults), reports before and after, and a DELETE brings the files'
    /// back; there is nothing to delete until something was stored.
    #[test]
    fn dns_014_rate_limit_override_and_revert() {
        let f = file("[ratelimit]\nqueries = 100\nwindow_secs = 30\n");
        let mut entries = crate::managed::Entries::default();

        let err = singleton_change(ManagedKind::RateLimit, &f, &mut entries, None).unwrap_err();
        assert_eq!(err.status, 404, "nothing stored yet");

        let put = singleton_change(
            ManagedKind::RateLimit,
            &f,
            &mut entries,
            Some(&serde_json::json!({ "queries": 5000, "action": "drop" })),
        )
        .unwrap();
        assert_eq!(put.before["queries"], 100, "the file's value");
        assert_eq!(put.after["queries"], 5000);
        assert_eq!(
            put.after["window_secs"], 60,
            "left out: the default, not the file's 30"
        );
        assert_eq!(put.merged.ratelimit.queries, 5000);
        let stored: telltale_config::RateLimitConfig =
            serde_json::from_str(&put.body.unwrap()).unwrap();
        assert_eq!(stored.queries, 5000);
        assert!(entries.ratelimit.is_some());

        let back = singleton_change(ManagedKind::RateLimit, &f, &mut entries, None).unwrap();
        assert!(back.body.is_none(), "deleting stores nothing");
        assert_eq!(back.before["queries"], 5000);
        assert_eq!(
            back.after["queries"], 100,
            "the file's section applies again"
        );
        assert!(entries.ratelimit.is_none());
    }

    /// REQ: DNS-014 — a section that wouldn't be valid is refused with the reason, and so is a
    /// field that doesn't exist.
    #[test]
    fn dns_014_rate_limit_is_validated() {
        let f = file("");
        let mut entries = crate::managed::Entries::default();
        let bad = singleton_change(
            ManagedKind::RateLimit,
            &f,
            &mut entries,
            Some(&serde_json::json!({ "ipv4_prefix": 33 })),
        )
        .unwrap_err();
        assert!(bad.detail.contains("ipv4_prefix"), "{}", bad.detail);
        let zero = singleton_change(
            ManagedKind::RateLimit,
            &f,
            &mut entries,
            Some(&serde_json::json!({ "enabled": true, "queries": 0 })),
        )
        .unwrap_err();
        assert!(zero.detail.contains("queries"), "{}", zero.detail);
        let typo = singleton_change(
            ManagedKind::RateLimit,
            &f,
            &mut entries,
            Some(&serde_json::json!({ "querys": 5 })),
        )
        .unwrap_err();
        assert!(typo.detail.contains("querys"), "{}", typo.detail);
    }

    /// REQ: DNS-014 — what to keep in Git is one `[ratelimit]` table.
    #[test]
    fn dns_014_rate_limit_keep_in_git() {
        let after = serde_json::json!({ "enabled": true, "queries": 5000, "window_secs": 60 });
        let toml = keep_in_git(
            ManagedKind::RateLimit,
            "default",
            Some(&serde_json::json!({ "queries": 5000 })),
            Some(&after),
        );
        let parsed: toml::Table = toml::from_str(&toml).unwrap();
        assert_eq!(parsed["ratelimit"]["queries"].as_integer(), Some(5000));
        let gone = keep_in_git(ManagedKind::RateLimit, "default", None, Some(&after));
        assert!(gone.contains("Nothing to change in Git"), "{gone}");
    }

    /// REQ: OBS-022 (T12.1) — the exclusions are set and reverted like the rate limit: the
    /// toggle and both lists, validated (a bad name or client is refused), and kept in Git as
    /// one `[exclusions]` table; the exclusions the aggregator gets follow the toggle.
    #[test]
    fn obs_022_exclusions_override_toggle_and_revert() {
        let f = file("[exclusions]\nnames = [\"ntp.org\"]\n");
        let mut entries = crate::managed::Entries::default();
        assert_eq!(
            singleton_change(ManagedKind::Exclusions, &f, &mut entries, None)
                .unwrap_err()
                .status,
            404
        );
        let put = singleton_change(
            ManagedKind::Exclusions,
            &f,
            &mut entries,
            Some(&serde_json::json!({
                "names": ["connectivitycheck.gstatic.com", "*.ntp.org"],
                "clients": ["192.168.1.10", "10.20.0.0/24"]
            })),
        )
        .unwrap();
        assert_eq!(put.before["names"], serde_json::json!(["ntp.org"]));
        assert_eq!(put.merged.exclusions.clients.len(), 2);
        assert!(crate::server::exclusions(&put.merged).is_some());
        let off = singleton_change(
            ManagedKind::Exclusions,
            &f,
            &mut entries,
            Some(&serde_json::json!({ "enabled": false, "names": ["ntp.org"] })),
        )
        .unwrap();
        assert!(!off.merged.exclusions.enabled);
        assert!(
            crate::server::exclusions(&off.merged).is_none(),
            "off: nothing excluded, lists kept"
        );
        for bad in [
            serde_json::json!({ "names": ["not a name"] }),
            serde_json::json!({ "clients": ["300.1.1.1"] }),
        ] {
            assert!(
                singleton_change(ManagedKind::Exclusions, &f, &mut entries, Some(&bad)).is_err(),
                "{bad}"
            );
        }
        let back = singleton_change(ManagedKind::Exclusions, &f, &mut entries, None).unwrap();
        assert_eq!(back.after["names"], serde_json::json!(["ntp.org"]));
        let after = serde_json::json!({ "enabled": true, "names": ["ntp.org"], "clients": [] });
        let toml = keep_in_git(
            ManagedKind::Exclusions,
            "default",
            Some(&after),
            Some(&after),
        );
        let parsed: toml::Table = toml::from_str(&toml).unwrap();
        assert_eq!(
            parsed["exclusions"]["names"].as_array().map(Vec::len),
            Some(1)
        );
    }
}

#[cfg(test)]
mod top_client_name_tests {
    use super::*;

    fn lease(ip: [u8; 4], name: &str) -> crate::devices::Lease {
        crate::devices::Lease {
            mac: String::new(),
            ip: std::net::Ipv4Addr::from(ip),
            hostname: Some(name.into()),
            expires: 0,
            offline: false,
            unsure: false,
            stale: false,
        }
    }

    /// REQ: CLU-002 (T8.2) — Top clients names an unnamed device the way the query log does:
    /// by this node's router leases, then the names the peers know; an address nobody knows
    /// stays unnamed, and other top lists carry no client names.
    #[test]
    fn clu_002_top_clients_name_unnamed_devices() {
        let src = Arc::new(crate::http::tests::sources());
        let nas = lease([192, 168, 1, 20], "nas");
        src.pipeline
            .router_leases
            .store(Arc::new([(nas.ip, nas)].into_iter().collect()));
        let printer = lease([192, 168, 1, 30], "printer");
        let mut peers = crate::devices::Names::default();
        peers.routers.insert(printer.ip, printer);
        src.pipeline.peer_names.store(Arc::new(peers));
        let api = ApiBackend { src };
        let name = |kind, key| api.client_labels(kind, key).0;
        assert_eq!(
            name(TopKind::Clients, "192.168.1.20").as_deref(),
            Some("nas")
        );
        assert_eq!(
            name(TopKind::Clients, "192.168.1.30").as_deref(),
            Some("printer")
        );
        assert_eq!(name(TopKind::Clients, "192.168.1.40"), None);
        assert_eq!(name(TopKind::Domains, "example.com"), None);
    }
}

#[cfg(test)]
mod top_range_tests {
    use super::*;
    use telltale_store::rollup::{Rollups, TopRow};
    use telltale_telemetry::event::{Name, Record};

    fn query(ts_s: u64, ip: [u8; 4]) -> Record {
        Record::Query(
            telltale_telemetry::QueryEvent {
                ts_us: ts_s * 1_000_000,
                client_ip: std::net::Ipv4Addr::from(ip).to_ipv6_mapped().octets(),
                client_ref: 0,
                group: 0,
                qtype: 1,
                qclass: 1,
                rcode: Some(0),
                status: telltale_telemetry::Status::Forwarded,
                proto: telltale_telemetry::Proto::Udp,
                flags: 0x8180,
                rule: None,
                upstream: 0,
                attempts: 0,
                t_total_us: 100,
                t_upstream_us: 0,
                resp_size: 64,
                answers: 1,
            },
            Name::from_wire(b"\x07example\x03com\x00"),
        )
    }

    fn row(key: &str, count: u64) -> TopRow {
        TopRow {
            key: key.into(),
            count,
            error: 0,
        }
    }

    /// REQ: OBS-004 (ADR-160) — a top list over a window sums the stored hours it overlaps and
    /// the current hour from memory, per key; an hour the window only touches counts whole,
    /// and a window that ends before this hour leaves memory out. Active clients (the
    /// summary's) is the same list's length.
    #[test]
    fn obs_004_top_lists_over_a_window_sum_stored_and_live_hours() {
        let mut s = crate::http::tests::sources();
        let db = Arc::new(Rollups::in_memory().unwrap());
        s.rollups = Some(Arc::clone(&db));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cur = now - now % 3600;
        let (h0, h1) = (cur - 7200, cur - 3600);
        db.put_hour_extras(
            h0,
            &[("clients", vec![row("10.0.0.1", 5), row("10.0.0.3", 4)])],
            &[],
        )
        .unwrap();
        db.put_hour_extras(h1, &[("clients", vec![row("10.0.0.3", 2)])], &[])
            .unwrap();
        {
            let mut agg = s.pipeline.telemetry.aggregates();
            for ip in [[10, 0, 0, 1], [10, 0, 0, 1], [10, 0, 0, 1], [10, 0, 0, 2]] {
                agg.record(&query(cur + 1, ip));
            }
        }
        let api = ApiBackend { src: Arc::new(s) };
        let list = |from, to| -> Vec<(String, u64)> {
            api.top_range(TopKind::Clients, from, to, 10)
                .into_iter()
                .map(|t| (t.key, t.count))
                .collect()
        };
        let pairs = |v: &[(&str, u64)]| -> Vec<(String, u64)> {
            v.iter().map(|(k, c)| ((*k).to_owned(), *c)).collect()
        };
        assert_eq!(
            list(h0 + 600, now + 1),
            pairs(&[("10.0.0.1", 8), ("10.0.0.3", 6), ("10.0.0.2", 1)])
        );
        assert_eq!(
            list(h1 + 5, now + 1),
            pairs(&[("10.0.0.1", 3), ("10.0.0.3", 2), ("10.0.0.2", 1)])
        );
        assert_eq!(list(h0, h1), pairs(&[("10.0.0.1", 5), ("10.0.0.3", 4)]));
        assert_eq!(api.top_range(TopKind::Clients, h0, now + 1, 2).len(), 2);
    }
}

#[cfg(test)]
mod rule_edit_tests {
    use super::*;

    fn maker(r: &telltale_config::RuleConfig) -> Option<&str> {
        r.created_by
            .as_ref()
            .map(telltale_config::SafeString::as_str)
    }

    /// REQ: FLT-005 (T20.1, ADR-162) — an edit replaces the rule but keeps who made it and when;
    /// a new rule is made by the writer, now.
    #[test]
    fn flt_005_editing_a_rule_keeps_its_maker_and_creation_time() {
        let made = rule_of(
            &serde_json::json!({ "action": "allow", "domain": "Game.Example.com", "devices": ["phone"] }),
            "r-1",
            "alice",
            None,
        )
        .unwrap();
        assert_eq!(maker(&made), Some("alice"));
        assert_eq!(made.domain.as_str(), "game.example.com");
        let first_created = made.created.clone();
        assert!(first_created.is_some());

        let mut earlier = made.clone();
        earlier.created = Some(telltale_config::SafeString::new("2026-10-05T10:00:00Z").unwrap());
        let edited = rule_of(
            &serde_json::json!({
                "action": "block", "domain": "game.example.com", "groups": ["kids"], "note": "later"
            }),
            "r-1",
            "bob",
            Some(&earlier),
        )
        .unwrap();
        assert_eq!(maker(&edited), Some("alice"), "the editor isn't the maker");
        assert_eq!(
            edited
                .created
                .as_ref()
                .map(telltale_config::SafeString::as_str),
            Some("2026-10-05T10:00:00Z"),
            "and the rule keeps its creation time"
        );
        assert_eq!(edited.action, telltale_config::RuleAction::Block);
        assert!(edited.devices.is_empty(), "the body is the whole rule");
        assert_eq!(edited.groups.len(), 1);

        // A stored rule with no maker (older data) takes the writer and now.
        let mut anonymous = made;
        anonymous.created_by = None;
        anonymous.created = None;
        let taken = rule_of(
            &serde_json::json!({ "action": "allow", "domain": "game.example.com" }),
            "r-1",
            "bob",
            Some(&anonymous),
        )
        .unwrap();
        assert_eq!(maker(&taken), Some("bob"));
        assert!(taken.created.is_some());
    }
}

// REQ: OBS-010, API-002 (ADR-179) — credential files on alert destinations made through the API.
#[cfg(test)]
#[path = "api_backend_cred_tests.rs"]
mod cred_file_tests;

// REQ: UPS-011, API-002 (ADR-180) — plugin upstreams and the API.
#[cfg(test)]
#[path = "api_backend_local_access_tests.rs"]
mod local_access_tests;

// REQ: FLT-004, OBS-024, OBS-010, API-002 (ADR-180) — local files named through the API.
#[cfg(test)]
#[path = "api_backend_local_file_tests.rs"]
mod local_file_tests;

// REQ: API-002, T8.2 (ADR-181) — routers made through the API, and their pasted keys.
#[cfg(test)]
#[path = "api_backend_router_tests.rs"]
mod router_tests;

// REQ: FLT-005 (issue #73) — a quick rule's device: what a rule can name, and the refusal's hint.
#[cfg(test)]
#[path = "api_backend_rule_device_tests.rs"]
mod rule_device_tests;

// REQ: AGT-004, FLT-013 (ADR-183) — explain's MAC is for those who may read the devices.
#[cfg(test)]
#[path = "api_backend_explain_mac_tests.rs"]
mod explain_mac_tests;

// REQ: FLT-006, API-010, AGT-004 (ADR-183) — an identity says how its address is recognized, and
// by which MAC, to who may see MACs.
#[cfg(test)]
#[path = "api_backend_recognition_tests.rs"]
mod recognition_tests;
