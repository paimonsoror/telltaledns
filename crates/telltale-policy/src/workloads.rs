//! Kubernetes workloads as devices (REQ: FLT-017; T15.1, ADR-150).
//!
//! The controller watches pods and maps each pod address to its workload (`ns/kind/name`);
//! every node gets the table over the cluster channel. This module is the table the query
//! path reads: an `ArcSwap` behind a flag, so a node with no Kubernetes workloads (every
//! install that doesn't turn the feature on) pays one relaxed load and a branch, and a node
//! with them one `ArcSwap` load and one hash lookup. Node-local operational state, like the
//! neighbor table: never part of the configuration or its replication.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::{ArcSwap, Guard};

/// Where a workload's group came from (shown in explain and the Workloads tab).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupOrigin {
    /// The pod's `telltaledns.io/group` label (`[kubernetes] label`).
    PodLabel,
    /// The namespace's label.
    NamespaceLabel,
    /// A `[[kubernetes.map]]` rule.
    Map,
    /// `[kubernetes] default_group`.
    Default,
    /// None of them: the pod falls to its network's group or `default`, like any device.
    None,
}

impl GroupOrigin {
    pub const fn label(self) -> &'static str {
        match self {
            Self::PodLabel => "pod_label",
            Self::NamespaceLabel => "namespace_label",
            Self::Map => "map",
            Self::Default => "default_group",
            Self::None => "none",
        }
    }

    /// Words for explain.
    pub const fn words(self) -> &'static str {
        match self {
            Self::PodLabel => "from the pod label",
            Self::NamespaceLabel => "from the namespace label",
            Self::Map => "from a [[kubernetes.map]] rule",
            Self::Default => "from [kubernetes] default_group",
            Self::None => "no group of its own",
        }
    }

    pub fn from_label(s: &str) -> Self {
        match s {
            "pod_label" => Self::PodLabel,
            "namespace_label" => Self::NamespaceLabel,
            "map" => Self::Map,
            "default_group" => Self::Default,
            _ => Self::None,
        }
    }
}

/// One pod of a workload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pod {
    pub name: Box<str>,
    /// Canonical addresses (IPv4 as IPv4).
    pub ips: Vec<IpAddr>,
    /// Unix seconds the pod was deleted; it keeps its addresses for a grace period so queries
    /// in flight are still attributed (ADR-150: 30 s), then leaves the table for the history.
    pub deleted_s: Option<u64>,
}

/// A workload: what a pod address is named by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workload {
    pub namespace: Box<str>,
    /// `deploy`, `sts`, `ds`, `job`, `cronjob`, `rs`, or `pod`.
    pub kind: Box<str>,
    pub name: Box<str>,
    /// `ns/kind/name`: the device name everywhere (shared with the history's intervals).
    pub text: Arc<str>,
    /// The synthetic analytics address (`telltale_telemetry::workload::key`).
    pub key: [u8; 16],
    /// The group's name; resolved against the client table on every lookup, so a
    /// configuration reload can't leave a stale index behind.
    pub group: Option<Box<str>>,
    pub origin: GroupOrigin,
    pub pods: Vec<Pod>,
    /// `app.kubernetes.io/name` and `app.kubernetes.io/part-of`, when a pod has them.
    pub labels: Vec<(Box<str>, Box<str>)>,
}

impl Workload {
    /// The text form of a workload.
    pub fn text_of(namespace: &str, kind: &str, name: &str) -> String {
        format!("{namespace}/{kind}/{name}")
    }
}

/// A recognized pod address: its workload and pod.
#[derive(Debug, Clone, Copy)]
pub struct Hit<'a> {
    pub workload: &'a Workload,
    pub pod: &'a Pod,
}

/// REQ: FLT-017 — one stretch of time a workload held an address (names at read time: pod
/// addresses are reused).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interval {
    /// One allocation per workload, however many addresses it held.
    pub text: Arc<str>,
    pub key: [u8; 16],
    pub from_s: u64,
    /// `None` while it still holds the address.
    pub to_s: Option<u64>,
}

/// Intervals kept per address, newest last.
pub const MAX_INTERVALS: usize = 8;

/// The workloads by pod address, by synthetic key, and by text form.
#[derive(Debug, Clone, Default)]
pub struct WorkloadTable {
    workloads: Vec<Workload>,
    by_ip: HashMap<IpAddr, (u32, u32)>,
    by_key: HashMap<[u8; 16], u32>,
    by_text: HashMap<Arc<str>, u32>,
    /// Who held each address when, sorted by address, each list sized exactly (never read on
    /// the query path: a binary search is enough, at half the memory of a hash map).
    history: Vec<(IpAddr, Box<[Interval]>)>,
    /// Names of keys whose workload is gone (from the history).
    past_keys: HashMap<[u8; 16], Arc<str>>,
}

impl WorkloadTable {
    /// Indexes `workloads`. An address two pods claim (a race between a delete and a reuse)
    /// goes to the live pod.
    pub fn new(workloads: Vec<Workload>) -> Self {
        let mut t = Self {
            by_ip: HashMap::new(),
            by_key: HashMap::with_capacity(workloads.len()),
            by_text: HashMap::with_capacity(workloads.len()),
            history: Vec::new(),
            past_keys: HashMap::new(),
            workloads,
        };
        for (wi, w) in t.workloads.iter().enumerate() {
            let Ok(wi) = u32::try_from(wi) else { break };
            t.by_key.insert(w.key, wi);
            t.by_text.insert(w.text.clone(), wi);
            for (pi, p) in w.pods.iter().enumerate() {
                let Ok(pi) = u32::try_from(pi) else { break };
                for ip in &p.ips {
                    let ip = ip.to_canonical();
                    let keep_old = t.by_ip.get(&ip).is_some_and(|&(ow, op)| {
                        p.deleted_s.is_some()
                            && t.workloads[ow as usize].pods[op as usize]
                                .deleted_s
                                .is_none()
                    });
                    if !keep_old {
                        t.by_ip.insert(ip, (wi, pi));
                    }
                }
            }
        }
        t
    }

    /// The table with the address history (`ip` canonical).
    #[must_use]
    pub fn with_history(mut self, history: HashMap<IpAddr, Vec<Interval>>) -> Self {
        // One string per workload name, shared by the live workload and every interval.
        let mut names: std::collections::HashSet<Arc<str>> =
            self.workloads.iter().map(|w| Arc::clone(&w.text)).collect();
        let mut v: Vec<(IpAddr, Box<[Interval]>)> = history
            .into_iter()
            .map(|(ip, mut list)| {
                for i in &mut list {
                    match names.get(&*i.text) {
                        Some(shared) => i.text = Arc::clone(shared),
                        None => {
                            names.insert(Arc::clone(&i.text));
                        }
                    }
                }
                (ip, list.into_boxed_slice())
            })
            .collect();
        self.past_keys = v
            .iter()
            .flat_map(|(_, l)| l.iter())
            .filter(|i| !self.by_key.contains_key(&i.key))
            .map(|i| (i.key, Arc::clone(&i.text)))
            .collect();
        v.sort_unstable_by_key(|(ip, _)| *ip);
        self.history = v;
        self
    }

    /// Every address's intervals, by address.
    pub fn history(&self) -> impl Iterator<Item = (&IpAddr, &[Interval])> {
        self.history.iter().map(|(ip, v)| (ip, &**v))
    }

    fn history_at(&self, ip: &IpAddr) -> Option<&[Interval]> {
        self.history
            .binary_search_by_key(ip, |(a, _)| *a)
            .ok()
            .map(|i| &*self.history[i].1)
    }

    /// Whether there's anything to name: live pods or history.
    pub fn has_any(&self) -> bool {
        !self.by_ip.is_empty() || !self.history.is_empty()
    }

    /// REQ: FLT-017 (API-010, ADR-125) — the workload that held `ip` at `ts_s`; the current one
    /// when the history doesn't say.
    pub fn name_at(&self, ip: IpAddr, ts_s: u64) -> Option<&str> {
        let ip = ip.to_canonical();
        self.history_at(&ip)
            .and_then(|v| {
                v.iter()
                    .rev()
                    .find(|i| i.from_s <= ts_s && i.to_s.is_none_or(|t| ts_s < t))
            })
            .map(|i| &*i.text)
            .or_else(|| self.get(ip).map(|h| &*h.workload.text))
    }

    /// The name of a workload key, live or from the history.
    pub fn key_name(&self, key: &[u8; 16]) -> Option<&str> {
        self.by_key(key)
            .map(|w| &*w.text)
            .or_else(|| self.past_keys.get(key).map(|t| &**t))
    }

    /// The addresses `text` held in `[from_s, to_s)`, from the history and the live pods.
    pub fn addresses_of(&self, text: &str, from_s: u64, to_s: u64) -> Vec<IpAddr> {
        let mut out: Vec<IpAddr> = self
            .spans_of(text)
            .into_iter()
            .filter(|(_, f, t)| *f < to_s && *t > from_s)
            .map(|(ip, _, _)| ip)
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Every stretch `text` held an address: `(address, from_s, to_s)` (`u64::MAX` while it
    /// still does). A live pod the history doesn't cover holds its address from the start.
    pub fn spans_of(&self, text: &str) -> Vec<(IpAddr, u64, u64)> {
        let mut out: Vec<(IpAddr, u64, u64)> = self
            .history
            .iter()
            .flat_map(|(ip, v)| {
                v.iter()
                    .filter(|i| &*i.text == text)
                    .map(|i| (*ip, i.from_s, i.to_s.unwrap_or(u64::MAX)))
            })
            .collect();
        if let Some(w) = self.by_text(text) {
            for p in w.pods.iter().filter(|p| p.deleted_s.is_none()) {
                for ip in &p.ips {
                    let ip = ip.to_canonical();
                    if self.history_at(&ip).is_none() {
                        out.push((ip, 0, u64::MAX));
                    }
                }
            }
        }
        out.sort();
        out
    }

    pub fn workloads(&self) -> &[Workload] {
        &self.workloads
    }

    /// Pod addresses in the table.
    pub fn addresses(&self) -> usize {
        self.by_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ip.is_empty()
    }

    /// The workload and pod at `ip`. REQ: FLT-017 — query path: one hash lookup.
    pub fn get(&self, ip: IpAddr) -> Option<Hit<'_>> {
        let &(w, p) = self.by_ip.get(&ip.to_canonical())?;
        let workload = self.workloads.get(w as usize)?;
        Some(Hit {
            workload,
            pod: workload.pods.get(p as usize)?,
        })
    }

    /// The workload with this synthetic key.
    pub fn by_key(&self, key: &[u8; 16]) -> Option<&Workload> {
        self.workloads.get(*self.by_key.get(key)? as usize)
    }

    /// The workload with this text form (`media/deploy/jellyfin`).
    pub fn by_text(&self, text: &str) -> Option<&Workload> {
        self.workloads.get(*self.by_text.get(text)? as usize)
    }

    /// Pod address → synthetic key, for the aggregator's substitution.
    pub fn keys(&self) -> HashMap<IpAddr, [u8; 16]> {
        self.by_ip
            .iter()
            .map(|(ip, &(w, _))| (*ip, self.workloads[w as usize].key))
            .collect()
    }
}

/// The table the query path reads, swapped whole on every change.
#[derive(Debug, Default)]
pub struct Workloads {
    table: ArcSwap<WorkloadTable>,
    /// Set while the table has any address: the query path's first (and, for every install
    /// without Kubernetes workloads, only) check.
    active: AtomicBool,
}

impl Workloads {
    /// An empty table for callers outside the pipeline (simulation, tests).
    pub fn none() -> &'static Self {
        static NONE: std::sync::OnceLock<Workloads> = std::sync::OnceLock::new();
        NONE.get_or_init(Self::default)
    }

    pub fn replace(&self, t: WorkloadTable) {
        let active = !t.is_empty();
        self.table.store(Arc::new(t));
        self.active.store(active, Ordering::Release);
    }

    /// Whether any pod address is known (one relaxed load).
    #[inline]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    pub fn load(&self) -> Guard<Arc<WorkloadTable>> {
        self.table.load()
    }

    /// The whole table, for the API and distribution.
    pub fn snapshot(&self) -> Arc<WorkloadTable> {
        self.table.load_full()
    }
}

/// REQ: FLT-017 — a `[[kubernetes.map]]` namespace glob: `*` matches any run of characters.
pub fn glob(pattern: &str, s: &str) -> bool {
    let (p, s) = (pattern.as_bytes(), s.as_bytes());
    let (mut pi, mut si) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while si < s.len() {
        if pi < p.len() && p[pi] != b'*' && p[pi] == s[si] {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flt_017_namespace_globs() {
        assert!(glob("media*", "media"));
        assert!(glob("media*", "media-dev"));
        assert!(!glob("media*", "xmedia"));
        assert!(glob("*", "anything"));
        assert!(glob("*-prod", "shop-prod"));
        assert!(glob("a*b*c", "a1b2c"));
        assert!(!glob("a*b*c", "a1b2"));
        assert!(glob("home", "home"));
        assert!(!glob("home", "homes"));
    }

    fn pod(name: &str, ips: &[&str], deleted: Option<u64>) -> Pod {
        Pod {
            name: name.into(),
            ips: ips.iter().map(|i| i.parse().unwrap()).collect(),
            deleted_s: deleted,
        }
    }

    fn workload(text: &str, key: u8, pods: Vec<Pod>) -> Workload {
        let mut parts = text.splitn(3, '/');
        Workload {
            namespace: parts.next().unwrap().into(),
            kind: parts.next().unwrap().into(),
            name: parts.next().unwrap().into(),
            text: text.into(),
            key: [key; 16],
            group: None,
            origin: GroupOrigin::None,
            pods,
            labels: Vec::new(),
        }
    }

    #[test]
    fn flt_017_table_lookups() {
        let w = Workloads::default();
        assert!(!w.is_active());
        w.replace(WorkloadTable::new(vec![
            workload(
                "media/deploy/jellyfin",
                1,
                vec![
                    pod("jellyfin-a", &["10.42.0.5", "fd00::5"], None),
                    pod("jellyfin-old", &["10.42.0.9"], Some(100)),
                ],
            ),
            // A new pod took the old one's address before the grace period ended.
            workload(
                "db/sts/postgres",
                2,
                vec![pod("postgres-0", &["10.42.0.9"], None)],
            ),
        ]));
        assert!(w.is_active());
        let t = w.load();
        let hit = t.get("10.42.0.5".parse().unwrap()).unwrap();
        assert_eq!(&*hit.workload.text, "media/deploy/jellyfin");
        assert_eq!(&*hit.pod.name, "jellyfin-a");
        assert!(
            t.get("::ffff:10.42.0.5".parse().unwrap()).is_some(),
            "v4-mapped"
        );
        assert!(t.get("fd00::5".parse().unwrap()).is_some());
        let reused = t.get("10.42.0.9".parse().unwrap()).unwrap();
        assert_eq!(
            &*reused.workload.text, "db/sts/postgres",
            "the live pod wins"
        );
        assert_eq!(
            t.by_key(&[2; 16]).map(|w| &*w.text),
            Some("db/sts/postgres")
        );
        assert_eq!(
            t.by_text("media/deploy/jellyfin").map(|w| w.key),
            Some([1; 16])
        );
        assert_eq!(t.addresses(), 3);
        assert_eq!(t.keys().len(), 3);
        drop(t);
        w.replace(WorkloadTable::default());
        assert!(!w.is_active());
    }

    // REQ: FLT-017 (API-010) — a reused address is named by whoever held it at the row's time.
    #[test]
    fn flt_017_names_at_read_time() {
        let ip: IpAddr = "10.42.0.9".parse().unwrap();
        let iv = |text: &str, key: u8, from_s, to_s| Interval {
            text: text.into(),
            key: [key; 16],
            from_s,
            to_s,
        };
        let t = WorkloadTable::new(vec![workload(
            "db/sts/postgres",
            2,
            vec![pod("postgres-0", &["10.42.0.9"], None)],
        )])
        .with_history(HashMap::from([(
            ip,
            vec![
                iv("media/deploy/jellyfin", 1, 100, Some(200)),
                iv("db/sts/postgres", 2, 200, None),
            ],
        )]));
        assert_eq!(t.name_at(ip, 150), Some("media/deploy/jellyfin"));
        assert_eq!(t.name_at(ip, 250), Some("db/sts/postgres"));
        assert_eq!(
            t.name_at(ip, 50),
            Some("db/sts/postgres"),
            "before: the current one"
        );
        assert_eq!(
            t.key_name(&[1; 16]),
            Some("media/deploy/jellyfin"),
            "gone, from history"
        );
        assert_eq!(t.key_name(&[2; 16]), Some("db/sts/postgres"));
        assert_eq!(t.addresses_of("media/deploy/jellyfin", 0, 1000), [ip]);
        assert_eq!(
            t.addresses_of("media/deploy/jellyfin", 300, 1000),
            Vec::<IpAddr>::new()
        );
        assert!(t.has_any());
    }
}
