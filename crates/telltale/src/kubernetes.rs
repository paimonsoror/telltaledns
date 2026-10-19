//! Kubernetes workloads as devices (REQ: FLT-017; T15.1, ADR-150).
//!
//! The process holding a service-account token (the Helm chart's controller, or the pod in
//! `allInOne`) lists and watches pods and namespaces, read-only, maps each pod address to its
//! workload (`media/deploy/jellyfin`, from `ownerReferences` alone), and builds the table the
//! query path reads ([`telltale_policy::Workloads`]). It pushes the table to every peer on
//! change (`workloads.table`), and peers also pull it every minute. Nothing here depends on a
//! Kubernetes client crate: the API is a handful of JSON GETs over the rustls client the list
//! fetcher uses.
//!
//! DNS never waits on any of it (CLU-004): the watcher runs on its own background thread with
//! its own runtime, a failing API server leaves the last good table in place (counted in
//! `telltale_kubernetes_watch_errors_total`, logged once an hour), and a peer that can't be
//! reached keeps the table it has.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use telltale_config::KubernetesConfig;
use telltale_policy::workloads::glob;
use telltale_policy::{GroupOrigin, Interval, Pod, Workload, WorkloadTable};
use tracing::{info, warn};

#[cfg(test)]
mod tests;

/// The cluster call that carries the table: an empty body asks for it, a body delivers it.
pub(crate) const KIND: &str = "workloads.table";
/// The in-cluster service-account files.
const TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const CA_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
/// A test hook (AC 4): a JSON file of pods (and namespaces) loaded instead of an API server,
/// re-read when it changes.
const FIXTURE_ENV: &str = "TELLTALE_KUBERNETES_FIXTURE";
/// A deleted pod keeps its addresses this long, so queries in flight are still attributed.
pub(crate) const GRACE_S: u64 = 30;
/// History kept per address.
const HISTORY_S: u64 = 30 * 86_400;
/// Most pod addresses in the table (ADR-150); past this the metric says so.
pub(crate) const MAX_ADDRESSES: usize = 20_000;
/// Bound tokens rotate: re-read this often.
const TOKEN_EVERY: Duration = Duration::from_secs(300);
/// A watch ends after this, and the next pass lists everything again (drift guard).
const WATCH_SECS: u64 = 600;
/// Changes are folded into one rebuild this long: short, because a new pod (a Job's above
/// all) asks DNS within a second of getting its address, and a rebuild costs well under a
/// millisecond for hundreds of pods (ADR-150 amendment: the design said 500 ms).
const DEBOUNCE: Duration = Duration::from_millis(50);
/// Pushes to peers are folded this long.
const PUSH_DEBOUNCE: Duration = Duration::from_secs(2);
/// Peers pull this often (a resolver pod that started after the last push).
const PULL_EVERY: Duration = Duration::from_secs(60);
/// How long a peer has to answer a push or a pull.
const DEADLINE: Duration = Duration::from_secs(5);
/// The table is persisted this often (and at shutdown).
const PERSIST_EVERY: Duration = Duration::from_secs(3600);
/// Largest list answer read (a 1,000-pod list is about 2 MB).
const MAX_LIST: u64 = 64 << 20;
/// Longest watch line kept (one pod object).
const MAX_LINE: usize = 4 << 20;
/// The health level turns `degraded` when the watcher's table is older than this.
pub(crate) const STALE_S: u64 = 900;
/// Errors are logged at most this often.
const LOG_EVERY: Duration = Duration::from_secs(3600);

// ---- What the API server sends (only the fields used) ----

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct ObjectMeta {
    pub(crate) name: String,
    pub(crate) namespace: String,
    pub(crate) labels: BTreeMap<String, String>,
    pub(crate) owner_references: Vec<OwnerRef>,
    pub(crate) deletion_timestamp: Option<String>,
    pub(crate) creation_timestamp: Option<String>,
    pub(crate) resource_version: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub(crate) struct OwnerRef {
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) controller: Option<bool>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct PodSpec {
    pub(crate) host_network: bool,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub(crate) struct PodStatus {
    pub(crate) phase: String,
    #[serde(rename = "podIP")]
    pub(crate) pod_ip: Option<String>,
    #[serde(rename = "podIPs")]
    pub(crate) pod_ips: Vec<PodIp>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub(crate) struct PodIp {
    pub(crate) ip: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub(crate) struct PodObject {
    pub(crate) metadata: ObjectMeta,
    pub(crate) spec: PodSpec,
    pub(crate) status: PodStatus,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub(crate) struct NamespaceObject {
    pub(crate) metadata: ObjectMeta,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct List<T> {
    pub(crate) metadata: ListMeta,
    pub(crate) items: Vec<T>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct ListMeta {
    pub(crate) resource_version: String,
    #[serde(rename = "continue")]
    pub(crate) cont: String,
}

#[derive(Debug, Deserialize)]
struct WatchEvent {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    object: Value,
}

// ---- One pod ----

/// A pod as the table needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PodInfo {
    pub(crate) namespace: String,
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) workload: String,
    /// Canonical addresses.
    pub(crate) ips: Vec<IpAddr>,
    pub(crate) labels: BTreeMap<String, String>,
    pub(crate) created_s: u64,
}

impl PodInfo {
    pub(crate) fn text(&self) -> String {
        Workload::text_of(&self.namespace, &self.kind, &self.workload)
    }
}

/// What a pod object means for the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Parsed {
    Pod(PodInfo),
    /// Terminating or finished: it leaves (after the grace period).
    Gone,
    /// Not a device of its own: host network (the node's address), or no address yet.
    Skip,
}

/// `backup-28456789` → `backup`: the Job of a `CronJob` (its run's suffix is the schedule time
/// in minutes). ADR-150: the Job's own owner isn't read.
fn cron_base(job: &str) -> Option<&str> {
    let (base, suffix) = job.rsplit_once('-')?;
    (!base.is_empty() && !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
        .then_some(base)
}

/// REQ: FLT-017 (ADR-150) — a pod's workload (kind, name) from its owner references alone.
pub(crate) fn workload_of(m: &ObjectMeta) -> (String, String) {
    let owner = m
        .owner_references
        .iter()
        .find(|o| o.controller == Some(true))
        .or_else(|| m.owner_references.first());
    let Some(o) = owner else {
        return ("pod".into(), m.name.clone());
    };
    match o.kind.as_str() {
        "ReplicaSet" => match m.labels.get("pod-template-hash") {
            Some(h) => match o
                .name
                .strip_suffix(h.as_str())
                .and_then(|n| n.strip_suffix('-'))
            {
                Some(d) if !d.is_empty() => ("deploy".into(), d.to_owned()),
                _ => ("rs".into(), o.name.clone()),
            },
            None => ("rs".into(), o.name.clone()),
        },
        "StatefulSet" => ("sts".into(), o.name.clone()),
        "DaemonSet" => ("ds".into(), o.name.clone()),
        "Job" => match cron_base(&o.name) {
            Some(b) => ("cronjob".into(), b.to_owned()),
            None => ("job".into(), o.name.clone()),
        },
        // ADR-150 (gap): another controller (an operator's custom resource) owns the pod: it
        // is the workload, so its pods stay one device across restarts.
        other => (other.to_ascii_lowercase(), o.name.clone()),
    }
}

fn parse_ip(s: &str) -> Option<IpAddr> {
    s.trim().parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

/// Unix seconds of an RFC 3339 time.
fn unix_s(t: Option<&str>) -> Option<u64> {
    telltale_config::parse_rfc3339(t?).map(|v| u64::try_from(v).unwrap_or(0))
}

/// REQ: FLT-017 — what a pod object means: its workload and addresses, or why it isn't one.
pub(crate) fn parse_pod(p: &PodObject) -> Parsed {
    if p.spec.host_network {
        return Parsed::Skip;
    }
    if p.metadata.deletion_timestamp.is_some()
        || matches!(p.status.phase.as_str(), "Succeeded" | "Failed")
    {
        return Parsed::Gone;
    }
    let mut ips: Vec<IpAddr> = p
        .status
        .pod_ips
        .iter()
        .filter_map(|i| parse_ip(&i.ip))
        .collect();
    if ips.is_empty()
        && let Some(ip) = p.status.pod_ip.as_deref().and_then(parse_ip)
    {
        ips.push(ip);
    }
    ips.dedup();
    if ips.is_empty() {
        return Parsed::Skip;
    }
    let (kind, workload) = workload_of(&p.metadata);
    Parsed::Pod(PodInfo {
        namespace: p.metadata.namespace.clone(),
        name: p.metadata.name.clone(),
        kind,
        workload,
        ips,
        labels: p.metadata.labels.clone(),
        created_s: unix_s(p.metadata.creation_timestamp.as_deref()).unwrap_or(0),
    })
}

// ---- The cluster as the watcher knows it ----

#[derive(Debug, Clone)]
struct Tracked {
    info: PodInfo,
    deleted_s: Option<u64>,
}

/// The pods and namespaces seen, and who held each address when.
#[derive(Debug, Default)]
pub(crate) struct Model {
    pods: BTreeMap<(String, String), Tracked>,
    namespaces: BTreeMap<String, BTreeMap<String, String>>,
    history: HashMap<IpAddr, Vec<Interval>>,
    /// Bumped on every change.
    pub(crate) changes: u64,
}

/// What a build made.
#[derive(Debug)]
pub(crate) struct Built {
    pub(crate) table: WorkloadTable,
    pub(crate) pods: usize,
    pub(crate) workloads: usize,
    /// Addresses left out past [`MAX_ADDRESSES`].
    pub(crate) dropped: usize,
}

impl Model {
    /// Starts from a persisted history (a restart keeps naming old rows).
    pub(crate) fn with_history(history: HashMap<IpAddr, Vec<Interval>>) -> Self {
        Self {
            history,
            ..Self::default()
        }
    }

    fn key(p: &PodObject) -> (String, String) {
        (p.metadata.namespace.clone(), p.metadata.name.clone())
    }

    /// An ADDED or MODIFIED pod.
    pub(crate) fn pod_event(&mut self, p: &PodObject, now: u64) {
        let key = Self::key(p);
        match parse_pod(p) {
            Parsed::Pod(info) => {
                let same = self
                    .pods
                    .get(&key)
                    .is_some_and(|t| t.info == info && t.deleted_s.is_none());
                if !same {
                    self.pods.insert(
                        key,
                        Tracked {
                            info,
                            deleted_s: None,
                        },
                    );
                    self.changes += 1;
                }
            }
            Parsed::Gone | Parsed::Skip => self.mark_deleted(&key, now),
        }
    }

    /// A DELETED pod.
    pub(crate) fn pod_deleted(&mut self, p: &PodObject, now: u64) {
        self.mark_deleted(&Self::key(p), now);
    }

    fn mark_deleted(&mut self, key: &(String, String), now: u64) {
        if let Some(t) = self.pods.get_mut(key)
            && t.deleted_s.is_none()
        {
            t.deleted_s = Some(now);
            self.changes += 1;
        }
    }

    /// A full list of the pods in `scope` (`None`: every namespace): the ones it doesn't
    /// have are gone.
    pub(crate) fn pod_list(&mut self, scope: Option<&str>, items: &[PodObject], now: u64) {
        let mut seen = HashSet::new();
        for p in items {
            seen.insert(Self::key(p));
            self.pod_event(p, now);
        }
        let gone: Vec<(String, String)> = self
            .pods
            .keys()
            .filter(|k| scope.is_none_or(|s| k.0 == s) && !seen.contains(*k))
            .cloned()
            .collect();
        for k in gone {
            self.mark_deleted(&k, now);
        }
    }

    pub(crate) fn namespace_event(&mut self, n: &NamespaceObject, deleted: bool) {
        let name = n.metadata.name.clone();
        let changed = if deleted {
            self.namespaces.remove(&name).is_some()
        } else {
            self.namespaces.insert(name, n.metadata.labels.clone())
                != Some(n.metadata.labels.clone())
        };
        if changed {
            self.changes += 1;
        }
    }

    pub(crate) fn namespace_list(&mut self, items: &[NamespaceObject]) {
        let next: BTreeMap<String, BTreeMap<String, String>> = items
            .iter()
            .map(|n| (n.metadata.name.clone(), n.metadata.labels.clone()))
            .collect();
        if next != self.namespaces {
            self.namespaces = next;
            self.changes += 1;
        }
    }

    /// Drops pods deleted more than [`GRACE_S`] ago.
    pub(crate) fn sweep(&mut self, now: u64) {
        let before = self.pods.len();
        self.pods
            .retain(|_, t| t.deleted_s.is_none_or(|d| d + GRACE_S > now));
        if self.pods.len() != before {
            self.changes += 1;
        }
    }

    /// Opens an interval for every address a pod holds, closes the ones no pod holds, and
    /// trims to [`telltale_policy::workloads::MAX_INTERVALS`] per address and 30 days.
    fn update_history(&mut self, now: u64) {
        // Pods in their grace period first, so a live pod that took an address wins it.
        let mut live: HashMap<IpAddr, (String, u64)> = HashMap::new();
        let (going, staying): (Vec<&Tracked>, Vec<&Tracked>) =
            self.pods.values().partition(|t| t.deleted_s.is_some());
        for t in going.into_iter().chain(staying) {
            for ip in &t.info.ips {
                live.insert(*ip, (t.info.text(), t.info.created_s));
            }
        }
        for (ip, (text, created)) in &live {
            let v = self.history.entry(*ip).or_default();
            let open_same = v
                .last()
                .is_some_and(|l| l.to_s.is_none() && *l.text == **text);
            if open_same {
                continue;
            }
            if let Some(last) = v.last_mut()
                && last.to_s.is_none()
            {
                last.to_s = Some(now);
            }
            let from_s = match v.last() {
                None if *created > 0 => (*created).min(now),
                None => now,
                Some(l) => l.to_s.unwrap_or(now).max(l.from_s).min(now),
            };
            v.push(Interval {
                text: text.as_str().into(),
                key: telltale_telemetry::workload::key(text),
                from_s,
                to_s: None,
            });
        }
        for (ip, v) in &mut self.history {
            if !live.contains_key(ip)
                && let Some(last) = v.last_mut()
                && last.to_s.is_none()
            {
                last.to_s = Some(now);
            }
        }
        let max = telltale_policy::workloads::MAX_INTERVALS;
        self.history.retain(|_, v| {
            v.retain(|i| i.to_s.is_none_or(|t| t + HISTORY_S >= now));
            if v.len() > max {
                v.drain(..v.len() - max);
            }
            !v.is_empty()
        });
    }

    /// REQ: FLT-017 (ADR-150) — the table: one workload per `ns/kind/name`, its pods (deleted
    /// ones within the grace period too), its group by the precedence pod label > namespace
    /// label > map rule > `default_group`. `group_exists` says which group names exist; a
    /// label naming another is logged once per value (`warned`) and treated as unset.
    pub(crate) fn build(
        &mut self,
        cfg: &KubernetesConfig,
        group_exists: &dyn Fn(&str) -> bool,
        warned: &mut HashSet<String>,
        now: u64,
    ) -> Built {
        self.update_history(now);
        let included = |ns: &str| {
            (cfg.namespaces.is_empty() || cfg.namespaces.iter().any(|n| n.as_str() == ns))
                && !cfg.exclude_namespaces.iter().any(|n| n.as_str() == ns)
        };
        let mut by_text: BTreeMap<String, Workload> = BTreeMap::new();
        // The labels of each workload's first live pod (or first pod) choose its group.
        let mut labels_of: HashMap<String, (bool, BTreeMap<String, String>)> = HashMap::new();
        let (mut addresses, mut dropped, mut pods) = (0usize, 0usize, 0usize);
        for t in self.pods.values() {
            let i = &t.info;
            if !included(&i.namespace) {
                continue;
            }
            if addresses + i.ips.len() > MAX_ADDRESSES {
                dropped += i.ips.len();
                continue;
            }
            addresses += i.ips.len();
            pods += 1;
            let text = i.text();
            let live = t.deleted_s.is_none();
            let slot = labels_of
                .entry(text.clone())
                .or_insert((live, i.labels.clone()));
            if live && !slot.0 {
                *slot = (true, i.labels.clone());
            }
            let w = by_text.entry(text.clone()).or_insert_with(|| Workload {
                namespace: i.namespace.as_str().into(),
                kind: i.kind.as_str().into(),
                name: i.workload.as_str().into(),
                key: telltale_telemetry::workload::key(&text),
                text: text.as_str().into(),
                group: None,
                origin: GroupOrigin::None,
                pods: Vec::new(),
                labels: Vec::new(),
            });
            w.pods.push(Pod {
                name: i.name.as_str().into(),
                ips: i.ips.clone(),
                deleted_s: t.deleted_s,
            });
        }
        for (text, w) in &mut by_text {
            let labels = labels_of.get(text).map(|(_, l)| l);
            let ns_labels = self.namespaces.get(&*w.namespace);
            let (group, origin) = group_of(cfg, labels, ns_labels, w, group_exists, warned);
            w.group = group.map(Into::into);
            w.origin = origin;
            if let Some(l) = labels {
                w.labels = ["app.kubernetes.io/name", "app.kubernetes.io/part-of"]
                    .iter()
                    .filter_map(|k| l.get(*k).map(|v| ((*k).into(), v.as_str().into())))
                    .collect();
            }
        }
        let workloads = by_text.len();
        Built {
            table: WorkloadTable::new(by_text.into_values().collect())
                .with_history(self.history.clone()),
            pods,
            workloads,
            dropped,
        }
    }
}

/// REQ: FLT-017 — a workload's group and where it came from.
fn group_of(
    cfg: &KubernetesConfig,
    pod_labels: Option<&BTreeMap<String, String>>,
    ns_labels: Option<&BTreeMap<String, String>>,
    w: &Workload,
    exists: &dyn Fn(&str) -> bool,
    warned: &mut HashSet<String>,
) -> (Option<String>, GroupOrigin) {
    let label = cfg.label.as_str();
    let mut check = |v: &str, whose: &str| -> Option<String> {
        if exists(v) {
            return Some(v.to_owned());
        }
        if warned.insert(v.to_owned()) {
            warn!(
                "kubernetes: {whose} label {label}={v} names no group; treated as unset (add the group, or fix the label)"
            );
        }
        None
    };
    if let Some(g) = pod_labels
        .and_then(|l| l.get(label))
        .and_then(|v| check(v, "a pod"))
    {
        return (Some(g), GroupOrigin::PodLabel);
    }
    if let Some(g) = ns_labels
        .and_then(|l| l.get(label))
        .and_then(|v| check(v, "a namespace"))
    {
        return (Some(g), GroupOrigin::NamespaceLabel);
    }
    if let Some(m) = cfg.map.iter().find(|m| {
        glob(&m.namespace, &w.namespace)
            && (m.kind.is_empty() || m.kind.as_str() == &*w.kind)
            && (m.name.is_empty() || m.name.as_str() == &*w.name)
    }) && exists(&m.group)
    {
        return (Some(m.group.to_string()), GroupOrigin::Map);
    }
    if !cfg.default_group.is_empty() && exists(&cfg.default_group) {
        return (Some(cfg.default_group.to_string()), GroupOrigin::Default);
    }
    (None, GroupOrigin::None)
}

// ---- The table on the wire and on disk ----

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Wire {
    /// When the watcher built it (Unix seconds).
    pub(crate) built_s: u64,
    /// The node that built it.
    #[serde(default)]
    pub(crate) source: String,
    pub(crate) workloads: Vec<WireWorkload>,
    #[serde(default)]
    pub(crate) history: Vec<WireHistory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WireWorkload {
    pub(crate) namespace: String,
    pub(crate) kind: String,
    pub(crate) name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) group: Option<String>,
    pub(crate) origin: String,
    pub(crate) pods: Vec<WirePod>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WirePod {
    pub(crate) name: String,
    pub(crate) ips: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) deleted_s: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WireHistory {
    pub(crate) ip: IpAddr,
    pub(crate) intervals: Vec<WireInterval>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WireInterval {
    pub(crate) workload: String,
    pub(crate) from_s: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) to_s: Option<u64>,
}

pub(crate) fn to_wire(t: &WorkloadTable, built_s: u64, source: &str) -> Wire {
    let mut history: Vec<WireHistory> = t
        .history()
        .map(|(ip, v)| WireHistory {
            ip: *ip,
            intervals: v
                .iter()
                .map(|i| WireInterval {
                    workload: i.text.to_string(),
                    from_s: i.from_s,
                    to_s: i.to_s,
                })
                .collect(),
        })
        .collect();
    history.sort_by_key(|h| h.ip);
    Wire {
        built_s,
        source: source.to_owned(),
        workloads: t
            .workloads()
            .iter()
            .map(|w| WireWorkload {
                namespace: w.namespace.to_string(),
                kind: w.kind.to_string(),
                name: w.name.to_string(),
                group: w.group.as_deref().map(str::to_owned),
                origin: w.origin.label().to_owned(),
                pods: w
                    .pods
                    .iter()
                    .map(|p| WirePod {
                        name: p.name.to_string(),
                        ips: p.ips.clone(),
                        deleted_s: p.deleted_s,
                    })
                    .collect(),
                labels: w
                    .labels
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            })
            .collect(),
        history,
    }
}

/// The table a wire form describes; refused when it's past the caps (a peer's mistake mustn't
/// grow this node without bound).
pub(crate) fn from_wire(w: Wire) -> Result<WorkloadTable, String> {
    let addresses: usize = w
        .workloads
        .iter()
        .flat_map(|x| &x.pods)
        .map(|p| p.ips.len())
        .sum();
    if addresses > MAX_ADDRESSES || w.history.len() > MAX_ADDRESSES * 2 {
        return Err(format!("too large ({addresses} addresses)"));
    }
    let workloads = w
        .workloads
        .into_iter()
        .map(|x| {
            let text = Workload::text_of(&x.namespace, &x.kind, &x.name);
            Workload {
                key: telltale_telemetry::workload::key(&text),
                text: text.into(),
                namespace: x.namespace.into(),
                kind: x.kind.into(),
                name: x.name.into(),
                group: x.group.map(Into::into),
                origin: GroupOrigin::from_label(&x.origin),
                pods: x
                    .pods
                    .into_iter()
                    .map(|p| Pod {
                        name: p.name.into(),
                        ips: p.ips.iter().map(IpAddr::to_canonical).collect(),
                        deleted_s: p.deleted_s,
                    })
                    .collect(),
                labels: x
                    .labels
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
            }
        })
        .collect();
    let history = w
        .history
        .into_iter()
        .map(|h| {
            (
                h.ip.to_canonical(),
                h.intervals
                    .into_iter()
                    .take(telltale_policy::workloads::MAX_INTERVALS)
                    .map(|i| Interval {
                        key: telltale_telemetry::workload::key(&i.workload),
                        text: i.workload.into(),
                        from_s: i.from_s,
                        to_s: i.to_s,
                    })
                    .collect(),
            )
        })
        .collect();
    Ok(WorkloadTable::new(workloads).with_history(history))
}

/// The history in a persisted or received table.
fn history_of(t: &WorkloadTable) -> HashMap<IpAddr, Vec<Interval>> {
    t.history().map(|(ip, v)| (*ip, v.to_vec())).collect()
}

/// REQ: FLT-017 — what `client` names when it's a workload: its text form
/// (`media/deploy/jellyfin`) or its analytics key (`100::…`). `None` for anything else.
pub(crate) fn workload_ref(client: &str, t: &WorkloadTable) -> Option<String> {
    let c = client.trim();
    if let Ok(ip) = c.parse::<IpAddr>() {
        let v6 = match ip {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        };
        let o = v6.octets();
        return telltale_telemetry::workload::is_key(&o)
            .then(|| t.key_name(&o).map(str::to_owned))
            .flatten();
    }
    let mut parts = c.split('/');
    let (Some(ns), Some(_kind), Some(name), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    (!ns.is_empty() && !name.is_empty()).then(|| c.to_owned())
}

// ---- Shared state (status, metrics) ----

/// What this node does about Kubernetes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// `[kubernetes] enabled = false`.
    #[default]
    Off,
    /// Enabled, but not in a pod with a token: it takes the table from its peers.
    Peer,
    /// Watching the API server.
    Watching,
    /// The test hook's file.
    Fixture,
}

impl Role {
    pub(crate) fn watches(self) -> bool {
        matches!(self, Self::Watching | Self::Fixture)
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct State {
    pub(crate) role: Role,
    pub(crate) namespaces: Vec<String>,
    pub(crate) last_error: Option<String>,
    /// Unix seconds of the last successful list, event, or bookmark (watcher), or the last
    /// table received (peer).
    pub(crate) last_sync_s: u64,
    /// The node the table came from (a peer's).
    pub(crate) source: Option<String>,
    pub(crate) pods: usize,
    pub(crate) workloads: usize,
}

/// REQ: FLT-017 — the watcher's and the peer side's state, for the API, `/metrics`, and health.
#[derive(Debug, Default)]
pub(crate) struct Kube {
    state: Mutex<State>,
    pub(crate) watch_errors: AtomicU64,
    pub(crate) sync_ok: AtomicU64,
    pub(crate) sync_failed: AtomicU64,
    pub(crate) dropped: AtomicU64,
    /// Unix seconds the table in use was built (0: none).
    pub(crate) table_s: AtomicU64,
    /// A new table was built here (the pusher sends it).
    pub(crate) built: tokio::sync::Notify,
    /// The configuration was reloaded: the watcher rebuilds at once if `[kubernetes]` or the
    /// group names changed, so a new map rule applies to the very next query.
    pub(crate) reconfigured: tokio::sync::Notify,
    last_log: Mutex<Option<Instant>>,
}

impl Kube {
    pub(crate) fn state(&self) -> State {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn update(&self, f: impl FnOnce(&mut State)) {
        f(&mut self.state.lock().unwrap_or_else(PoisonError::into_inner));
    }

    /// An API error: counted, kept for the status, logged at most once an hour.
    fn error(&self, what: &str, e: &str) {
        self.watch_errors.fetch_add(1, Ordering::Relaxed);
        let msg = format!("{what}: {e}");
        let mut last = self.last_log.lock().unwrap_or_else(PoisonError::into_inner);
        if last.is_none_or(|t| t.elapsed() >= LOG_EVERY) {
            *last = Some(Instant::now());
            warn!(
                "kubernetes: {msg} (DNS keeps answering; pods keep their last names; logged once an hour)"
            );
        }
        drop(last);
        self.update(|s| s.last_error = Some(msg));
    }

    fn synced(&self, now: u64) {
        self.update(|s| {
            s.last_sync_s = now;
            s.last_error = None;
        });
    }

    /// Seconds since the table was last confirmed (watcher) or received (peer); `None` with
    /// no table.
    pub(crate) fn age_s(&self, now: u64) -> Option<u64> {
        let s = self.state().last_sync_s;
        (s > 0).then(|| now.saturating_sub(s))
    }

    /// REQ: FLT-017, OBS-015 — whether this node's watcher table is stale (health `degraded`).
    pub(crate) fn stale(&self, now: u64) -> bool {
        let st = self.state();
        st.role == Role::Watching && now.saturating_sub(st.last_sync_s) > STALE_S
    }

    /// `/metrics`.
    pub(crate) fn render(&self, w: &mut telltale_telemetry::prom::PromWriter, now: u64) {
        let st = self.state();
        if st.role == Role::Off {
            return;
        }
        w.family(
            "telltale_kubernetes_watching",
            "gauge",
            "1 when this node watches the Kubernetes API (the others take its table).",
        )
        .sample(
            "telltale_kubernetes_watching",
            &[],
            u8::from(st.role == Role::Watching),
        );
        w.family(
            "telltale_kubernetes_pods",
            "gauge",
            "Kubernetes pods in the workload table (FLT-017).",
        )
        .sample("telltale_kubernetes_pods", &[], st.pods);
        w.family(
            "telltale_kubernetes_workloads",
            "gauge",
            "Kubernetes workloads in the table.",
        )
        .sample("telltale_kubernetes_workloads", &[], st.workloads);
        w.family(
            "telltale_kubernetes_table_age_seconds",
            "gauge",
            "Seconds since the workload table was last confirmed by the API server (watcher) or received (peer).",
        )
        .sample(
            "telltale_kubernetes_table_age_seconds",
            &[],
            self.age_s(now).unwrap_or(0),
        );
        w.family(
            "telltale_kubernetes_watch_errors_total",
            "counter",
            "Failed lists and watches of the Kubernetes API since start.",
        )
        .sample(
            "telltale_kubernetes_watch_errors_total",
            &[],
            self.watch_errors.load(Ordering::Relaxed),
        );
        w.family(
            "telltale_kubernetes_sync_total",
            "counter",
            "Workload table syncs (a full list, or a table from a peer), by result.",
        )
        .sample(
            "telltale_kubernetes_sync_total",
            &[("result", "ok")],
            self.sync_ok.load(Ordering::Relaxed),
        )
        .sample(
            "telltale_kubernetes_sync_total",
            &[("result", "error")],
            self.sync_failed.load(Ordering::Relaxed),
        );
        w.family(
            "telltale_kubernetes_addresses_dropped",
            "gauge",
            "Pod addresses left out of the table past its cap of 20,000.",
        )
        .sample(
            "telltale_kubernetes_addresses_dropped",
            &[],
            self.dropped.load(Ordering::Relaxed),
        );
    }
}

/// Unix seconds now.
pub(crate) fn now_s() -> u64 {
    crate::pipeline::unix_now()
}

/// REQ: FLT-017 — puts `t` in use: the query path's table and the aggregator's keys.
pub(crate) fn install(p: &crate::pipeline::Pipeline, t: WorkloadTable) {
    let keys: telltale_telemetry::workload::Keys = t
        .keys()
        .into_iter()
        .map(|(ip, k)| (mapped(ip), k))
        .collect();
    p.telemetry.set_workload_keys(Some(keys));
    p.workloads.replace(t);
}

fn mapped(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

// ---- Persistence ----

fn state_file(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("workloads.json")
}

fn load(data_dir: &str) -> Option<Wire> {
    let bytes = std::fs::read(state_file(data_dir)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// REQ: FLT-017 (ADR-150) — whether this node keeps workload analytics: the analytics then
/// hold unknown addresses from the start, before the first table arrives (see
/// [`telltale_telemetry::ring::WORKLOAD_HOLD`]).
pub(crate) fn wanted(cfg: &telltale_config::Config) -> bool {
    decide(cfg) != Role::Off
}

/// REQ: FLT-017 (ADR-150) — the persisted table and its address history, for keying the
/// startup replay of the query log (`None` when Kubernetes is off or nothing was saved).
pub(crate) fn persisted(data_dir: &str) -> Option<WorkloadTable> {
    load(data_dir).and_then(|w| from_wire(w).ok())
}

/// REQ: FLT-017 — the workload key of a logged query: the workload that held `client` at
/// `ts_s`, by the table's history.
pub(crate) fn key_at(t: &WorkloadTable, client: [u8; 16], ts_s: u64) -> Option<[u8; 16]> {
    let ip = IpAddr::V6(std::net::Ipv6Addr::from(client)).to_canonical();
    t.name_at(ip, ts_s).map(telltale_telemetry::workload::key)
}

/// REQ: FLT-017 — one workload's per-hour counts on this node, kept across restarts in their
/// own file (`workload-counts.json`): node-local, so never part of the table sent to peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SavedCounts {
    /// The workload's analytics key.
    pub(crate) key: std::net::Ipv6Addr,
    pub(crate) last_seen_s: u64,
    /// (hour index, queries, blocked).
    pub(crate) hours: Vec<(u64, u32, u32)>,
}

fn counts_file(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("workload-counts.json")
}

fn save_counts(data_dir: &str, counts: &[SavedCounts]) {
    write_atomic(&counts_file(data_dir), counts, "workload counts");
}

/// REQ: FLT-017 — folds the saved counts back into the analytics (at start, off the DNS path).
pub(crate) fn restore_counts(data_dir: &str, hub: &telltale_telemetry::Hub) -> usize {
    let Some(saved) = std::fs::read(counts_file(data_dir))
        .ok()
        .and_then(|b| serde_json::from_slice::<Vec<SavedCounts>>(&b).ok())
    else {
        return 0;
    };
    let mut agg = hub.aggregates();
    for c in &saved {
        agg.restore_workload_counts(c.key.octets(), c.last_seen_s, c.hours.iter().copied());
    }
    saved.len()
}

fn counts_of(hub: &telltale_telemetry::Hub) -> Vec<SavedCounts> {
    let agg = hub.aggregates();
    let mut v: Vec<SavedCounts> = agg
        .workload_counts()
        .iter()
        .map(|(k, c)| SavedCounts {
            key: std::net::Ipv6Addr::from(*k),
            last_seen_s: c.last_seen_s,
            hours: c.slots().collect(),
        })
        .filter(|c| !c.hours.is_empty())
        .collect();
    drop(agg);
    v.sort_by_key(|c| c.key);
    v
}

fn write_atomic<T: Serialize + ?Sized>(path: &Path, v: &T, what: &str) {
    let tmp = path.with_extension("json.tmp");
    let r = serde_json::to_vec(v)
        .map_err(std::io::Error::other)
        .and_then(|b| std::fs::write(&tmp, b))
        .and_then(|()| std::fs::rename(&tmp, path));
    if let Err(e) = r {
        warn!("kubernetes: {what} not saved to {}: {e}", path.display());
    }
}

fn save(data_dir: &str, w: &Wire) {
    write_atomic(&state_file(data_dir), w, "workload table");
}

// ---- The API server ----

/// Why a request failed.
#[derive(Debug)]
pub(crate) enum ApiError {
    /// 410: the resource version is too old; list again.
    Gone,
    /// 401/403: the token (re-read at once next time) or the RBAC.
    Denied(String),
    Other(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gone => f.write_str("410 Gone (resource version too old)"),
            Self::Denied(e) | Self::Other(e) => f.write_str(e),
        }
    }
}

/// The API server and the service account's token.
pub(crate) struct Api {
    base: String,
    token_path: PathBuf,
    token_every: Duration,
    token: Mutex<Option<(String, Instant)>>,
    client: telltale_filter::fetch::Client,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// In a pod: `KUBERNETES_SERVICE_HOST`/`_PORT`, the mounted token and CA. `Err` with why
    /// not (every node outside Kubernetes, and pods without a token: ADR-120).
    pub(crate) fn in_cluster() -> Result<Self, String> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST")
            .map_err(|_| "not running in a Kubernetes pod (no KUBERNETES_SERVICE_HOST)")?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
        std::fs::metadata(TOKEN_PATH).map_err(|_| {
            "no service-account token is mounted (the chart mounts one on the controller when kubernetes.enabled is true)".to_owned()
        })?;
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        let client = telltale_filter::fetch::Client::with_ca_file(
            Arc::new(telltale_filter::fetch::SystemResolver),
            CA_PATH,
        )?;
        Ok(Self::new(
            format!("https://{host}:{port}"),
            PathBuf::from(TOKEN_PATH),
            TOKEN_EVERY,
            client,
        ))
    }

    pub(crate) fn new(
        base: String,
        token_path: PathBuf,
        token_every: Duration,
        client: telltale_filter::fetch::Client,
    ) -> Self {
        Self {
            base,
            token_path,
            token_every,
            token: Mutex::new(None),
            client,
        }
    }

    fn token(&self) -> Result<String, ApiError> {
        let mut t = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((tok, at)) = &*t
            && at.elapsed() < self.token_every
        {
            return Ok(tok.clone());
        }
        let tok = std::fs::read_to_string(&self.token_path)
            .map_err(|e| ApiError::Denied(format!("{}: {e}", self.token_path.display())))?
            .trim()
            .to_owned();
        *t = Some((tok.clone(), Instant::now()));
        Ok(tok)
    }

    fn forget_token(&self) {
        *self.token.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    fn request(&self, path: &str) -> Result<http::Request<Vec<u8>>, ApiError> {
        let tok = self.token()?;
        http::Request::get(format!("{}{path}", self.base))
            .header(http::header::AUTHORIZATION, format!("Bearer {tok}"))
            .header(http::header::ACCEPT, "application/json")
            .body(Vec::new())
            .map_err(|e| ApiError::Other(format!("bad request {path}: {e}")))
    }

    fn status_error(&self, status: http::StatusCode, path: &str) -> ApiError {
        match status.as_u16() {
            410 => ApiError::Gone,
            401 | 403 => {
                self.forget_token();
                ApiError::Denied(format!(
                    "{path}: HTTP {status} (the service account needs get/list/watch on pods and namespaces)"
                ))
            }
            _ => ApiError::Other(format!("{path}: HTTP {status}")),
        }
    }

    /// Every page of a list (`limit=500`, `continue`).
    pub(crate) async fn list<T: for<'de> Deserialize<'de> + Default>(
        &self,
        path: &str,
        selector: &str,
    ) -> Result<(Vec<T>, String), ApiError> {
        let mut items = Vec::new();
        let mut cont = String::new();
        loop {
            let mut p = format!("{path}?limit=500{selector}");
            if !cont.is_empty() {
                p.push_str("&continue=");
                p.push_str(&encode(&cont));
            }
            let req = self.request(&p)?;
            let resp =
                tokio::time::timeout(Duration::from_secs(60), self.client.request(req, MAX_LIST))
                    .await
                    .map_err(|_| ApiError::Other(format!("{path}: timed out")))?
                    .map_err(|e| ApiError::Other(format!("{path}: {}", e.message)))?;
            if !resp.status().is_success() {
                return Err(self.status_error(resp.status(), path));
            }
            let page: List<T> = serde_json::from_slice(resp.body())
                .map_err(|e| ApiError::Other(format!("{path}: {e}")))?;
            items.extend(page.items);
            if page.metadata.cont.is_empty() {
                return Ok((items, page.metadata.resource_version));
            }
            cont = page.metadata.cont;
        }
    }

    /// One watch from `rv`: every line to `on_line` until the server ends it (after
    /// [`WATCH_SECS`]); returns the newest resource version seen.
    pub(crate) async fn watch(
        &self,
        path: &str,
        selector: &str,
        rv: &str,
        mut on_line: impl FnMut(&[u8]) -> Result<Option<String>, ApiError>,
    ) -> Result<String, ApiError> {
        let p = format!(
            "{path}?watch=1&allowWatchBookmarks=true&timeoutSeconds={WATCH_SECS}&resourceVersion={}{selector}",
            encode(rv)
        );
        let req = self.request(&p)?;
        let (head, mut body) =
            tokio::time::timeout(Duration::from_secs(30), self.client.request_stream(req))
                .await
                .map_err(|_| ApiError::Other(format!("{path}: timed out")))?
                .map_err(|e| ApiError::Other(format!("{path}: {}", e.message)))?;
        if !head.status.is_success() {
            return Err(self.status_error(head.status, path));
        }
        let mut rv = rv.to_owned();
        let mut buf: Vec<u8> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(WATCH_SECS + 30);
        loop {
            let chunk = match tokio::time::timeout_at(deadline, body.next_chunk()).await {
                Err(_) => return Ok(rv),
                Ok(None) => break,
                Ok(Some(Err(e))) => return Err(ApiError::Other(format!("{path}: {}", e.message))),
                Ok(Some(Ok(c))) => c,
            };
            buf.extend_from_slice(&chunk);
            while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = buf.drain(..=pos).collect();
                if let Some(v) = on_line(&line[..line.len() - 1])? {
                    rv = v;
                }
            }
            if buf.len() > MAX_LINE {
                return Err(ApiError::Other(format!(
                    "{path}: a watch line over {MAX_LINE} bytes"
                )));
            }
        }
        if !buf.is_empty()
            && let Some(v) = on_line(&buf)?
        {
            rv = v;
        }
        Ok(rv)
    }
}

/// Percent-encodes a query value.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Pods that will never ask again aren't listed.
fn pod_selector() -> String {
    format!(
        "&fieldSelector={}",
        encode("status.phase!=Succeeded,status.phase!=Failed")
    )
}

/// One watch event line for pods: applied to the model; the resource version it carries.
fn pod_line(model: &Mutex<Model>, line: &[u8], now: u64) -> Result<Option<String>, ApiError> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let ev: WatchEvent =
        serde_json::from_slice(line).map_err(|e| ApiError::Other(format!("watch event: {e}")))?;
    if ev.kind == "ERROR" {
        let code = ev.object.get("code").and_then(Value::as_u64);
        return Err(if code == Some(410) {
            ApiError::Gone
        } else {
            ApiError::Other(format!("watch error: {}", ev.object))
        });
    }
    let p: PodObject = serde_json::from_value(ev.object)
        .map_err(|e| ApiError::Other(format!("watch object: {e}")))?;
    let rv = (!p.metadata.resource_version.is_empty()).then(|| p.metadata.resource_version.clone());
    let mut m = model.lock().unwrap_or_else(PoisonError::into_inner);
    match ev.kind.as_str() {
        "ADDED" | "MODIFIED" => m.pod_event(&p, now),
        "DELETED" => m.pod_deleted(&p, now),
        _ => {} // BOOKMARK: only the resource version
    }
    Ok(rv)
}

fn namespace_line(model: &Mutex<Model>, line: &[u8]) -> Result<Option<String>, ApiError> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let ev: WatchEvent =
        serde_json::from_slice(line).map_err(|e| ApiError::Other(format!("watch event: {e}")))?;
    if ev.kind == "ERROR" {
        let code = ev.object.get("code").and_then(Value::as_u64);
        return Err(if code == Some(410) {
            ApiError::Gone
        } else {
            ApiError::Other(format!("watch error: {}", ev.object))
        });
    }
    let n: NamespaceObject = serde_json::from_value(ev.object)
        .map_err(|e| ApiError::Other(format!("watch object: {e}")))?;
    let rv = (!n.metadata.resource_version.is_empty()).then(|| n.metadata.resource_version.clone());
    let mut m = model.lock().unwrap_or_else(PoisonError::into_inner);
    match ev.kind.as_str() {
        "ADDED" | "MODIFIED" => m.namespace_event(&n, false),
        "DELETED" => m.namespace_event(&n, true),
        _ => {}
    }
    Ok(rv)
}

/// A jittered backoff from 1 s to 60 s.
struct Backoff(u64);

impl Backoff {
    fn reset(&mut self) {
        self.0 = 0;
    }
    async fn wait(&mut self) {
        self.0 = (self.0 * 2).clamp(1_000, 60_000);
        let jitter = u64::from(rand::random::<u16>()) % (self.0 / 2 + 1);
        tokio::time::sleep(Duration::from_millis(self.0 / 2 + jitter)).await;
    }
}

/// List, then watch until the watch ends, forever: pods in `scope` (`None`: all namespaces).
async fn pods_loop(
    api: Arc<Api>,
    scope: Option<String>,
    model: Arc<Mutex<Model>>,
    kube: Arc<Kube>,
    changed: Arc<tokio::sync::Notify>,
) {
    let path = match &scope {
        Some(ns) => format!("/api/v1/namespaces/{}/pods", encode(ns)),
        None => "/api/v1/pods".to_owned(),
    };
    let sel = pod_selector();
    let mut backoff = Backoff(0);
    loop {
        let (items, mut rv) = match api.list::<PodObject>(&path, &sel).await {
            Ok(x) => x,
            Err(e) => {
                kube.sync_failed.fetch_add(1, Ordering::Relaxed);
                kube.error("listing pods", &e.to_string());
                backoff.wait().await;
                continue;
            }
        };
        let now = now_s();
        model
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pod_list(scope.as_deref(), &items, now);
        drop(items);
        kube.sync_ok.fetch_add(1, Ordering::Relaxed);
        kube.synced(now);
        changed.notify_one();
        backoff.reset();
        let m = Arc::clone(&model);
        let (k, c) = (Arc::clone(&kube), Arc::clone(&changed));
        let started = Instant::now();
        let watched = api
            .watch(&path, &sel, &rv, |line| {
                let r = pod_line(&m, line, now_s());
                if r.is_ok() {
                    k.synced(now_s());
                    c.notify_one();
                }
                r
            })
            .await;
        match watched {
            Ok(v) => {
                rv = v;
                // A server that ends watches at once mustn't make this loop spin.
                if started.elapsed() < Duration::from_secs(5) {
                    backoff.wait().await;
                }
            }
            Err(ApiError::Gone) => {}
            Err(e) => {
                kube.error("watching pods", &e.to_string());
                backoff.wait().await;
            }
        }
        let _ = rv; // the next pass lists again (the drift guard), from scratch
    }
}

async fn namespaces_loop(
    api: Arc<Api>,
    model: Arc<Mutex<Model>>,
    kube: Arc<Kube>,
    changed: Arc<tokio::sync::Notify>,
) {
    let path = "/api/v1/namespaces";
    let mut backoff = Backoff(0);
    loop {
        let (items, rv) = match api.list::<NamespaceObject>(path, "").await {
            Ok(x) => x,
            Err(e) => {
                kube.error("listing namespaces", &e.to_string());
                backoff.wait().await;
                continue;
            }
        };
        model
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .namespace_list(&items);
        changed.notify_one();
        backoff.reset();
        let m = Arc::clone(&model);
        let c = Arc::clone(&changed);
        let started = Instant::now();
        match api
            .watch(path, "", &rv, |line| {
                let r = namespace_line(&m, line);
                if r.is_ok() {
                    c.notify_one();
                }
                r
            })
            .await
        {
            Ok(_) if started.elapsed() < Duration::from_secs(5) => backoff.wait().await,
            Ok(_) | Err(ApiError::Gone) => {}
            Err(e) => {
                kube.error("watching namespaces", &e.to_string());
                backoff.wait().await;
            }
        }
    }
}

/// The test hook's file: a pod list, or `{"pods": <list>, "namespaces": <list>}`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Fixture {
    pods: List<PodObject>,
    namespaces: List<NamespaceObject>,
    items: Vec<PodObject>,
}

fn read_fixture(path: &Path) -> Result<Fixture, String> {
    let b = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut f: Fixture =
        serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))?;
    if f.pods.items.is_empty() {
        f.pods.items = std::mem::take(&mut f.items);
    }
    Ok(f)
}

/// What the watcher thread reads: an API server or the test hook's file.
pub(crate) enum Source {
    Api(Arc<Api>),
    Fixture(PathBuf),
}

/// REQ: FLT-017 — the watcher: lists and watches on a background thread with its own
/// runtime (`SCHED_IDLE`, like the list compiler), rebuilds the table on change (debounced),
/// installs it, and wakes the pusher. Runs until `stop`.
pub(crate) fn spawn_watcher(
    src: Arc<crate::http::Sources>,
    source: Source,
    history: HashMap<IpAddr, Vec<Interval>>,
    stop: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("telltale-k8s".into())
        .spawn(move || {
            telltale_net::background_thread();
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    warn!("kubernetes: watcher runtime: {e}");
                    return;
                }
            };
            rt.block_on(watch_main(src, source, history, stop));
        })
}

#[allow(clippy::too_many_lines)] // one loop: sources, rebuilds, installs
async fn watch_main(
    src: Arc<crate::http::Sources>,
    source: Source,
    history: HashMap<IpAddr, Vec<Interval>>,
    stop: Arc<AtomicBool>,
) {
    let kube = Arc::clone(&src.pipeline.kube);
    let model = Arc::new(Mutex::new(Model::with_history(history)));
    let changed = Arc::new(tokio::sync::Notify::new());
    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let mut scopes: Option<Vec<String>> = None;
    let mut fixture_mtime = None;
    let mut warned = HashSet::new();
    let mut last_built: Option<(u64, KubernetesConfig, Vec<String>)> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            _ = tick.tick() => {}
            () = changed.notified() => tokio::time::sleep(DEBOUNCE).await,
            () = kube.reconfigured.notified() => {}
        }
        let cfg = src.config.load_full();
        let k = &cfg.kubernetes;
        match &source {
            Source::Api(api) => {
                let want: Vec<String> = k.namespaces.iter().map(ToString::to_string).collect();
                if scopes.as_ref() != Some(&want) {
                    for t in tasks.drain(..) {
                        t.abort();
                    }
                    let list: Vec<Option<String>> = if want.is_empty() {
                        vec![None]
                    } else {
                        want.iter().cloned().map(Some).collect()
                    };
                    for s in list {
                        tasks.push(tokio::spawn(pods_loop(
                            Arc::clone(api),
                            s,
                            Arc::clone(&model),
                            Arc::clone(&kube),
                            Arc::clone(&changed),
                        )));
                    }
                    tasks.push(tokio::spawn(namespaces_loop(
                        Arc::clone(api),
                        Arc::clone(&model),
                        Arc::clone(&kube),
                        Arc::clone(&changed),
                    )));
                    kube.update(|s| {
                        s.namespaces = if want.is_empty() {
                            vec!["*".into()]
                        } else {
                            want.clone()
                        };
                    });
                    scopes = Some(want);
                }
            }
            Source::Fixture(path) => {
                let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
                if mtime != fixture_mtime {
                    fixture_mtime = mtime;
                    match read_fixture(path) {
                        Ok(f) => {
                            let now = now_s();
                            let mut m = model.lock().unwrap_or_else(PoisonError::into_inner);
                            m.pod_list(None, &f.pods.items, now);
                            m.namespace_list(&f.namespaces.items);
                            drop(m);
                            kube.sync_ok.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            kube.sync_failed.fetch_add(1, Ordering::Relaxed);
                            kube.error("reading the fixture", &e);
                        }
                    }
                    kube.update(|s| s.namespaces = vec!["*".into()]);
                }
                // The file stands for an API server that's always reachable.
                kube.synced(now_s());
            }
        }
        let now = now_s();
        let groups: Vec<String> = cfg
            .group
            .iter()
            .map(|g| g.name.to_string())
            .chain(["default".to_owned()])
            .collect();
        let mut m = model.lock().unwrap_or_else(PoisonError::into_inner);
        m.sweep(now);
        let stamp = (m.changes, k.clone(), groups.clone());
        if last_built.as_ref() == Some(&stamp) {
            continue;
        }
        let exists = |g: &str| groups.iter().any(|x| x == g);
        let built = m.build(k, &exists, &mut warned, now);
        drop(m);
        last_built = Some(stamp);
        kube.dropped.store(built.dropped as u64, Ordering::Relaxed);
        if built.dropped > 0 {
            kube.error(
                "table",
                &format!(
                    "{} pod addresses past the cap of {MAX_ADDRESSES} left out",
                    built.dropped
                ),
            );
        }
        kube.update(|s| {
            s.pods = built.pods;
            s.workloads = built.workloads;
        });
        kube.table_s.store(now, Ordering::Relaxed);
        install(&src.pipeline, built.table);
        kube.built.notify_one();
    }
    for t in tasks {
        t.abort();
    }
}

/// The node's name in the cluster (for `source`).
fn node_id(src: &crate::http::Sources) -> String {
    src.cluster
        .as_ref()
        .map_or_else(|| "local".to_owned(), |c| c.identity.meta.node_id.clone())
}

/// REQ: FLT-017 — answers a peer's `workloads.table`: an empty body asks for this node's table
/// (only a node that watches has one to give); a body delivers the watcher's table, which a
/// node that doesn't watch puts in use. `from_member` is false for a peer the registry
/// doesn't list as a full member (resolver pods never watch).
pub(crate) fn handle(
    src: &crate::http::Sources,
    body: &[u8],
    from_member: bool,
) -> Result<Vec<u8>, String> {
    let kube = &src.pipeline.kube;
    let role = kube.state().role;
    if body.is_empty() {
        if !role.watches() {
            return Err("this node doesn't watch Kubernetes".into());
        }
        let t = src.pipeline.workloads.snapshot();
        let w = to_wire(&t, kube.table_s.load(Ordering::Relaxed), &node_id(src));
        return serde_json::to_vec(&w).map_err(|e| e.to_string());
    }
    if !from_member {
        return Err("only a full cluster member sends the workload table".into());
    }
    if role.watches() {
        return Ok(b"ignored: this node watches Kubernetes itself".to_vec());
    }
    if role == Role::Off {
        return Ok(b"ignored: [kubernetes] enabled is false here".to_vec());
    }
    receive(src, body)
}

fn receive(src: &crate::http::Sources, body: &[u8]) -> Result<Vec<u8>, String> {
    let kube = &src.pipeline.kube;
    let w: Wire = serde_json::from_slice(body).map_err(|e| format!("bad table: {e}"))?;
    if w.built_s < kube.table_s.load(Ordering::Relaxed) {
        return Ok(b"older than the table in use".to_vec());
    }
    let (built_s, source) = (w.built_s, w.source.clone());
    let pods = w.workloads.iter().map(|x| x.pods.len()).sum();
    let workloads = w.workloads.len();
    let t = from_wire(w)?;
    install(&src.pipeline, t);
    kube.table_s.store(built_s, Ordering::Relaxed);
    kube.sync_ok.fetch_add(1, Ordering::Relaxed);
    kube.update(|s| {
        s.pods = pods;
        s.workloads = workloads;
        s.last_sync_s = now_s();
        s.source = Some(source);
        s.last_error = None;
    });
    Ok(b"ok".to_vec())
}

/// Pushes this node's table to every peer (a node that doesn't watch skips it).
async fn push(src: &Arc<crate::http::Sources>) {
    let Some(cluster) = src.cluster.clone() else {
        return;
    };
    let kube = &src.pipeline.kube;
    let t = src.pipeline.workloads.snapshot();
    let w = to_wire(&t, kube.table_s.load(Ordering::Relaxed), &node_id(src));
    let Ok(body) = serde_json::to_vec(&w) else {
        return;
    };
    for (peer, r) in cluster.call_all(KIND, &body, DEADLINE).await {
        // A peer on an older build answers "unknown call": skipped (it names pods by address).
        if let Err(e) = r
            && !e.contains("unknown call")
        {
            tracing::debug!("kubernetes: pushing the table to {peer}: {e}");
        }
    }
}

/// Asks the peers for their table; the newest one a watcher gave is put in use.
async fn pull(src: &Arc<crate::http::Sources>) {
    let Some(cluster) = src.cluster.clone() else {
        return;
    };
    let mut best: Option<Vec<u8>> = None;
    let mut best_s = 0;
    for (_, r) in cluster.call_all(KIND, &[], DEADLINE).await {
        let Ok(body) = r else { continue };
        let built: u64 = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| v.get("built_s").and_then(Value::as_u64))
            .unwrap_or(0);
        if built >= best_s {
            best_s = built;
            best = Some(body);
        }
    }
    if let Some(body) = best {
        let s = Arc::clone(src);
        let r = tokio::task::spawn_blocking(move || receive(&s, &body)).await;
        if let Ok(Err(e)) = r {
            src.pipeline
                .kube
                .sync_failed
                .fetch_add(1, Ordering::Relaxed);
            src.pipeline.kube.error("the table from a peer", &e);
        }
    }
}

/// What this node should be for `cfg` (checked every second: no client is built here).
fn decide(cfg: &telltale_config::Config) -> Role {
    if std::env::var_os(FIXTURE_ENV).is_some() {
        return Role::Fixture;
    }
    if !cfg.kubernetes.enabled {
        return Role::Off;
    }
    let in_pod = std::env::var_os("KUBERNETES_SERVICE_HOST").is_some()
        && std::fs::metadata(TOKEN_PATH).is_ok();
    if in_pod { Role::Watching } else { Role::Peer }
}

/// The watcher's source for `role`, or why there's none (a node that can't watch takes the
/// table from its peers).
fn source_for(role: Role) -> Result<Source, String> {
    match role {
        Role::Fixture => std::env::var(FIXTURE_ENV)
            .map(|p| Source::Fixture(PathBuf::from(p)))
            .map_err(|e| e.to_string()),
        _ => Api::in_cluster().map(|api| Source::Api(Arc::new(api))),
    }
}

/// REQ: FLT-017 — the node's Kubernetes task: loads the persisted table, starts the watcher
/// when this node can watch, pushes new tables to peers (debounced) or pulls them every
/// minute, follows `[kubernetes] enabled` across reloads, and persists the table hourly and
/// at shutdown. Off the DNS path entirely.
#[allow(clippy::too_many_lines)] // one select loop: watcher, push, pull, reload, persist
pub(crate) async fn run(
    src: Arc<crate::http::Sources>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let data_dir = src.config.load().node.data_dir.to_string();
    let kube = Arc::clone(&src.pipeline.kube);
    let saved = load(&data_dir);
    let mut role = Role::Off;
    let mut watcher: Option<(Arc<AtomicBool>, std::thread::JoinHandle<()>)> = None;
    let mut last_pull: Option<Instant> = None;
    let mut last_persist = Instant::now();
    let mut push_at: Option<tokio::time::Instant> = None;
    let mut saved = saved;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = tick.tick() => {}
            () = kube.built.notified() => {
                push_at.get_or_insert_with(|| tokio::time::Instant::now() + PUSH_DEBOUNCE);
            }
        }
        let cfg = src.config.load_full();
        let mut want = decide(&cfg);
        let mut why = None;
        let mut source = None;
        if want != role && want.watches() {
            match source_for(want) {
                Ok(s) => source = Some(s),
                Err(e) => {
                    // In a pod, but its token or CA can't be used: take the peers' table.
                    why = Some(e);
                    want = Role::Peer;
                }
            }
        } else if want == Role::Peer && role != Role::Peer {
            why = Some(
                "not in a Kubernetes pod with a service-account token (the chart mounts one on the controller when kubernetes.enabled is true)"
                    .to_owned(),
            );
        }
        if want != role {
            if let Some((flag, h)) = watcher.take() {
                flag.store(true, Ordering::Relaxed);
                let _ = tokio::task::spawn_blocking(move || h.join()).await;
            }
            // Turned on by a reload: the analytics wait for pod addresses from now on.
            if role == Role::Off
                && want != Role::Off
                && src.pipeline.telemetry.workload_keys().is_none()
            {
                src.pipeline
                    .telemetry
                    .set_workload_keys(Some(telltale_telemetry::workload::Keys::new()));
            }
            match want {
                Role::Off => {
                    src.pipeline.workloads.replace(WorkloadTable::default());
                    src.pipeline.telemetry.set_workload_keys(None);
                    kube.update(|s| *s = State::default());
                }
                Role::Peer => {
                    info!(
                        "kubernetes: [kubernetes] is on, but this node can't watch the API server ({}); it takes the workload table from the cluster",
                        why.unwrap_or_default()
                    );
                    kube.update(|s| s.role = Role::Peer);
                    if let Some(w) = saved.take()
                        && let Ok(t) = from_wire(w.clone())
                    {
                        install(&src.pipeline, t);
                        kube.table_s.store(w.built_s, Ordering::Relaxed);
                    }
                    last_pull = None;
                }
                Role::Watching | Role::Fixture => {
                    info!(
                        "kubernetes: watching pods to name them by their workload ({})",
                        if want == Role::Fixture {
                            "test fixture"
                        } else {
                            "in-cluster API server"
                        }
                    );
                    kube.update(|s| s.role = want);
                    let history = saved
                        .take()
                        .and_then(|w| from_wire(w).ok())
                        .map(|t| history_of(&t))
                        .unwrap_or_default();
                    if let Some(source) = source {
                        let flag = Arc::new(AtomicBool::new(false));
                        match spawn_watcher(Arc::clone(&src), source, history, Arc::clone(&flag)) {
                            Ok(h) => watcher = Some((flag, h)),
                            Err(e) => kube.error("starting the watcher", &e.to_string()),
                        }
                    }
                }
            }
            role = want;
        }
        if role == Role::Peer && last_pull.is_none_or(|t| t.elapsed() >= PULL_EVERY) {
            last_pull = Some(Instant::now());
            pull(&src).await;
        }
        if push_at.is_some_and(|t| tokio::time::Instant::now() >= t) {
            push_at = None;
            if role.watches() {
                push(&src).await;
            }
        }
        if role != Role::Off && last_persist.elapsed() >= PERSIST_EVERY {
            last_persist = Instant::now();
            persist(&src, &data_dir).await;
        }
    }
    if let Some((flag, h)) = watcher.take() {
        flag.store(true, Ordering::Relaxed);
        let _ = tokio::task::spawn_blocking(move || h.join()).await;
    }
    if role != Role::Off {
        persist(&src, &data_dir).await;
    }
}

async fn persist(src: &Arc<crate::http::Sources>, data_dir: &str) {
    let counts = counts_of(&src.pipeline.telemetry);
    if !counts.is_empty() {
        let dir = data_dir.to_owned();
        let _ = tokio::task::spawn_blocking(move || save_counts(&dir, &counts)).await;
    }
    let t = src.pipeline.workloads.snapshot();
    if !t.has_any() {
        return;
    }
    let w = to_wire(
        &t,
        src.pipeline.kube.table_s.load(Ordering::Relaxed),
        &node_id(src),
    );
    let dir = data_dir.to_owned();
    let _ = tokio::task::spawn_blocking(move || save(&dir, &w)).await;
}
