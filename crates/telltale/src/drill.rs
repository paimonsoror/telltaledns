//! Failover drills (REQ: CLU-014; ADR-151, `docs/design/failover-drills.md`).
//!
//! A drill makes this node stop answering chosen devices for 15 to 300 seconds while the
//! other nodes keep serving, then reports who followed to another node. It is a maintenance
//! window with a drop:
//!
//! - **The drop** ([`Gate`]): one relaxed load on the query path when no drill runs; during
//!   one, a set lookup after client identification. A target's UDP query gets no answer and
//!   its stream connection is closed; counted as status `drilled`. Loopback, the node's
//!   infrastructure (masking's list: gateways, `TELLTALE_NODE_IPS`, `[clients]
//!   infrastructure`), cluster nodes, and excluded devices are always answered.
//! - **The window:** [`crate::maintenance`] with `drill` set: not ready, alerts muted, out of
//!   elections, handover on the primary; a restart cancels it instead of resuming it.
//! - **Coverage:** every node records a window per client while any node drills (the
//!   aggregates' [`telltale_telemetry::seen::Window`], started by a direct call from the drilled
//!   node and by the heartbeat's drill mark), frozen 60 s after the end into
//!   `drills/<id>.part.json`. The drilled node then asks every peer for its part (retried for
//!   5 minutes), computes the verdicts, saves `drills/<id>.json` (the last 50 kept), and leaves
//!   the `drill.ended` marker. 15 minutes later it checks who came back.
//!
//! Nothing here but [`Gate::active`] is on the query path; DNS never waits on a peer or a file.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use arc_swap::{ArcSwap, Guard};
use serde::{Deserialize, Serialize};
use telltale_api::DrillWrite;
use telltale_api::model::{
    ActiveDrill, DrillCheck, DrillDevice, DrillMode, DrillNodeCount, DrillReport, DrillStart,
    DrillSummary, DrillTargetDevice, DrillTargets,
};
use telltale_api::problem::{Code, Problem};
use telltale_cluster::net::{Cluster, DrillMark};
use telltale_config::Cidr;
use telltale_telemetry::seen::Window;
use tracing::{info, warn};

use crate::http::Sources;
use crate::maintenance::{label, now_ms};

/// The peer call (one kind; the operation inside).
pub(crate) const KIND: &str = "drill";
/// Reports and parts, under the data directory.
const DIR: &str = "drills";
/// The nodes keep recording this long after the end (who asked where once it was over).
pub(crate) const GRACE_MS: u64 = 60_000;
/// A query to another node counts as following a dropped one until this long after the end (a
/// stub resolver's retry timer); later, the drilled node answers again, so it proves nothing.
const FOLLOW_GRACE_MS: u64 = 5_000;
/// How long the drilled node keeps asking for missing parts: 5 minutes (test hook
/// `TELLTALE_DRILL_RETRY_SECS`).
fn part_retry_ms() -> u64 {
    hook_secs("TELLTALE_DRILL_RETRY_SECS").unwrap_or(300) * 1000
}
/// Reports kept per node.
const KEEP: usize = 50;
/// A device with this many unanswered queries and nothing elsewhere is `stuck`.
const STUCK_MIN: u32 = 3;
/// The baseline: devices seen on the node in the hour before.
const BASELINE_S: u64 = 3600;
/// Deadlines for peer calls: the start notice, and reads.
const NOTICE_DEADLINE: Duration = Duration::from_secs(1);
const READ_DEADLINE: Duration = Duration::from_secs(2);
const WRITE_DEADLINE: Duration = Duration::from_secs(5);
/// A forwarded start or end older than this is dropped (as for maintenance).
const STALE_MS: u64 = 30_000;
/// Devices listed on a dry run.
const DRY_RUN_DEVICES: usize = 200;

/// Waits between drills in the cluster, and before the "came back" check: 10 and 15 minutes,
/// shortened by test hooks (`TELLTALE_DRILL_GAP_SECS`, `TELLTALE_DRILL_RETURN_SECS`).
fn gap_ms() -> u64 {
    hook_secs("TELLTALE_DRILL_GAP_SECS").unwrap_or(600) * 1000
}
fn return_ms() -> u64 {
    hook_secs("TELLTALE_DRILL_RETURN_SECS").unwrap_or(900) * 1000
}
fn hook_secs(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
}

// ---- The query path ----

/// REQ: CLU-014 — who this node doesn't answer during a drill.
#[derive(Debug, Default)]
pub(crate) struct Targets {
    pub(crate) all: bool,
    pub(crate) ips: HashSet<IpAddr>,
    /// `[[client]]` names.
    pub(crate) names: HashSet<Box<str>>,
    /// Kubernetes workloads (`ns/kind/name`, FLT-017).
    pub(crate) workloads: HashSet<Box<str>>,
    pub(crate) group: Option<Box<str>>,
    /// Never dropped: infrastructure, this node, the cluster's nodes.
    pub(crate) spared_nets: Vec<Cidr>,
    pub(crate) spared_ips: HashSet<IpAddr>,
    /// Excluded devices (OBS-022) are never dropped either.
    pub(crate) excluded: Option<Arc<telltale_telemetry::exclude::Exclusions>>,
    /// REQ: CLU-014 (owner 2026-10-19) — answer REFUSED instead of nothing.
    pub(crate) refused: bool,
}

impl Targets {
    /// Whether a query from `peer` (named `name`, a pod of `workload`, in `groups`) goes
    /// unanswered.
    pub(crate) fn drops(
        &self,
        peer: IpAddr,
        name: Option<&str>,
        workload: Option<&str>,
        groups: &[Box<str>],
    ) -> bool {
        let peer = peer.to_canonical();
        let hit = self.all
            || self.ips.contains(&peer)
            || name.is_some_and(|n| self.names.contains(n))
            || workload.is_some_and(|w| self.workloads.contains(w))
            || self
                .group
                .as_deref()
                .is_some_and(|g| groups.iter().any(|x| &**x == g));
        hit && !self.spared(peer)
    }

    /// Never dropped: the node itself (`127.0.0.1`, `::1`: its probes and local programs), its
    /// infrastructure, the cluster's nodes, excluded devices. Other loopback addresses are
    /// ordinary clients (test stubs bind them).
    fn spared(&self, peer: IpAddr) -> bool {
        peer == IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            || peer == IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            || self.spared_ips.contains(&peer)
            || self.spared_nets.iter().any(|n| n.contains(peer))
            || self
                .excluded
                .as_ref()
                .is_some_and(|x| x.client(&mapped(peer)))
    }
}

/// REQ: CLU-014 (ADR-151) — the drill's targets on the query path: the end (Unix ms, 0 when
/// none) and the set, like `Pause`.
#[derive(Debug, Default)]
pub(crate) struct Gate {
    until_ms: AtomicU64,
    targets: ArcSwap<Targets>,
    /// Queries left unanswered for drills, ever (during a drill only: one relaxed add).
    dropped: AtomicU64,
}

impl Gate {
    /// The targets while a drill runs: one relaxed load when none does.
    #[inline]
    pub(crate) fn active(&self) -> Option<Guard<Arc<Targets>>> {
        let until = self.until_ms.load(Ordering::Relaxed);
        if until == 0 || now_ms() >= until {
            return None;
        }
        Some(self.targets.load())
    }

    /// Counts one query left unanswered.
    #[inline]
    pub(crate) fn count(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn set(&self, t: Targets, until_ms: u64) {
        self.targets.store(Arc::new(t));
        self.until_ms.store(until_ms, Ordering::Release);
    }

    fn clear(&self) {
        self.until_ms.store(0, Ordering::Release);
        self.targets.store(Arc::default());
    }
}

fn mapped(ip: IpAddr) -> [u8; 16] {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// A client key (address, or a workload's analytics key) as text.
pub(crate) fn key_text(k: &[u8; 16]) -> String {
    let v6 = std::net::Ipv6Addr::from(*k);
    v6.to_ipv4_mapped()
        .map_or_else(|| v6.to_string(), |v4| v4.to_string())
}

fn key_ip(k: &[u8; 16]) -> IpAddr {
    let v6 = std::net::Ipv6Addr::from(*k);
    v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
}

// ---- Stored reports ----

/// A drill as this node keeps it (`drills/<id>.json`): the report and what computing it needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Stored {
    pub(crate) report: DrillReport,
    pub(crate) since_ms: u64,
    pub(crate) until_ms: u64,
    #[serde(default)]
    pub(crate) ended_ms: Option<u64>,
    /// Devices seen here in the hour before, and which of them were targets.
    #[serde(default)]
    pub(crate) baseline: Vec<[u8; 16]>,
    #[serde(default)]
    pub(crate) targets: Vec<[u8; 16]>,
    /// When the drilled node first asked for parts, and the nodes still missing.
    #[serde(default)]
    pub(crate) first_try_ms: Option<u64>,
    #[serde(default)]
    pub(crate) waiting: Vec<String>,
}

fn dir(src: &Sources) -> PathBuf {
    Path::new(src.config.load().node.data_dir.as_str()).join(DIR)
}

fn write_json<T: Serialize>(path: &Path, v: &T) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(v).map_err(std::io::Error::other)?)?;
    std::fs::rename(&tmp, path)
}

fn save(src: &Sources, s: &Stored) {
    let path = dir(src).join(format!("{}.json", s.report.summary.id));
    if let Err(e) = write_json(&path, s) {
        warn!("drill: report not saved to {}: {e}", path.display());
    }
}

/// This node's stored drills, newest first.
fn stored(src: &Sources) -> Vec<Stored> {
    let Ok(rd) = std::fs::read_dir(dir(src)) else {
        return Vec::new();
    };
    let mut v: Vec<Stored> = rd
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|x| x == "json")
                && !p.to_string_lossy().ends_with(".part.json")
        })
        .filter_map(|p| std::fs::read(p).ok())
        .filter_map(|b| serde_json::from_slice::<Stored>(&b).ok())
        .collect();
    v.sort_by_key(|s| std::cmp::Reverse(s.since_ms));
    v
}

fn load(src: &Sources, id: &str) -> Option<Stored> {
    if !valid_id(id) {
        return None;
    }
    std::fs::read(dir(src).join(format!("{id}.json")))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// Drill IDs are ours: `d` + digits + `-` + hex.
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 40 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Keeps the newest [`KEEP`] reports (and drops parts older than a day).
fn prune(src: &Sources) {
    let d = dir(src);
    for s in stored(src).into_iter().skip(KEEP) {
        let _ = std::fs::remove_file(d.join(format!("{}.json", s.report.summary.id)));
    }
    let day_ago = now_ms().saturating_sub(86_400_000);
    if let Ok(rd) = std::fs::read_dir(&d) {
        for p in rd.filter_map(Result::ok).map(|e| e.path()) {
            if p.to_string_lossy().ends_with(".part.json")
                && std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .is_some_and(|t| u64::try_from(t.as_millis()).unwrap_or(0) < day_ago)
            {
                let _ = std::fs::remove_file(p);
            }
        }
    }
}

// ---- State ----

/// REQ: CLU-014 — this node's drills: the one it runs, the window it records, and counters.
#[derive(Debug, Default)]
pub(crate) struct Drills {
    /// The drill this node runs.
    running: Mutex<Option<Stored>>,
    /// The window this node records: `(id, until, ended)`.
    recording: Mutex<Option<(String, u64, Option<u64>)>>,
    /// The last drill anywhere in the cluster ended (Unix ms).
    last_any_ms: AtomicU64,
    completed: AtomicU64,
    cancelled: AtomicU64,
    /// The last report's numbers, for `/metrics`.
    last: Mutex<Option<DrillSummary>>,
    /// REQ: CLU-014 — the last try to start a scheduled drill (Unix ms): once a minute at most.
    scheduled_try_ms: AtomicU64,
    changed: tokio::sync::Notify,
}

impl Drills {
    /// The drill this node runs.
    pub(crate) fn running(&self) -> Option<Stored> {
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// REQ: CLU-014 — `/metrics`.
pub(crate) fn render(src: &Sources, w: &mut telltale_telemetry::prom::PromWriter) {
    let d = &src.drills;
    let active = u8::from(d.running().is_some_and(|s| s.until_ms > now_ms()));
    w.family(
        "telltale_drill_active",
        "gauge",
        "Whether this node runs a failover drill now.",
    )
    .sample("telltale_drill_active", &[], active);
    w.family(
        "telltale_drill_dropped_total",
        "counter",
        "Queries this node left unanswered for failover drills.",
    )
    .sample(
        "telltale_drill_dropped_total",
        &[],
        src.pipeline.drill.dropped.load(Ordering::Relaxed),
    );
    w.family(
        "telltale_drills_total",
        "counter",
        "Failover drills this node ran since it started, by result.",
    )
    .sample(
        "telltale_drills_total",
        &[("result", "completed")],
        d.completed.load(Ordering::Relaxed),
    )
    .sample(
        "telltale_drills_total",
        &[("result", "cancelled")],
        d.cancelled.load(Ordering::Relaxed),
    );
    let last = d
        .last
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    if let Some(s) = last {
        if let Some(c) = s.coverage_percent {
            w.family(
                "telltale_drill_last_coverage_percent",
                "gauge",
                "Followed / (followed + stuck) in this node's last drill, in percent.",
            )
            .sample("telltale_drill_last_coverage_percent", &[], c);
        }
        w.family(
            "telltale_drill_last_stuck",
            "gauge",
            "Devices stuck on this node in its last drill.",
        )
        .sample("telltale_drill_last_stuck", &[], s.stuck);
        w.family(
            "telltale_drill_last_failover_ms",
            "gauge",
            "Time to failover in this node's last drill (milliseconds).",
        );
        for (q, v) in [("0.5", s.median_failover_ms), ("0.9", s.p90_failover_ms)] {
            if let Some(v) = v {
                w.sample("telltale_drill_last_failover_ms", &[("quantile", q)], v);
            }
        }
    }
}

// ---- Starting and ending ----

/// A target spec in words.
fn targets_text(t: &DrillTargets) -> String {
    match t {
        DrillTargets::All(_) => "everyone".into(),
        DrillTargets::Group { group } => format!("group {group}"),
        DrillTargets::Clients { clients } if clients.len() <= 3 => clients.join(", "),
        DrillTargets::Clients { clients } => format!("{} devices", clients.len()),
    }
}

/// The set the gate checks, from the spec (names become addresses, workloads, or `[[client]]`
/// names; an unknown group is refused).
fn build_targets(src: &Sources, spec: &DrillTargets) -> Result<Targets, Problem> {
    let cfg = src.config.load();
    let mut t = Targets {
        // Loopback is left to `spared` (the node's own address only).
        spared_nets: crate::masking::infrastructure(&cfg.clients.infrastructure)
            .into_iter()
            .filter(|c| !c.addr.is_loopback())
            .collect(),
        excluded: crate::server::exclusions(&cfg).map(Arc::new),
        ..Targets::default()
    };
    if let Some(c) = &src.cluster {
        for n in c.identity.registry() {
            for a in &n.advertise {
                if let Some(ip) = host_ip(a) {
                    t.spared_ips.insert(ip);
                }
            }
        }
    }
    match spec {
        DrillTargets::All(_) => t.all = true,
        DrillTargets::Group { group } => {
            let known = group == "default" || cfg.group.iter().any(|g| g.name.as_str() == group);
            if !known {
                return Err(Problem::new(
                    Code::DrillTargets,
                    format!("`targets.group`: no group `{group}`"),
                )
                .hint("Use a group's name from the Groups page."));
            }
            t.group = Some(group.as_str().into());
        }
        DrillTargets::Clients { clients } => {
            let workloads = src.pipeline.workloads.snapshot();
            for c in clients {
                let c = c.trim();
                if let Ok(ip) = c.parse::<IpAddr>() {
                    t.ips.insert(ip.to_canonical());
                } else if workloads.by_text(c).is_some() {
                    t.workloads.insert(c.into());
                } else if cfg.client.iter().any(|x| x.name.as_str() == c) {
                    t.names.insert(c.into());
                } else {
                    return Err(Problem::new(
                        Code::DrillTargets,
                        format!("`targets.clients`: `{c}` is no address, device name, or workload"),
                    )
                    .hint(
                        "Use an address, a named device, or a Kubernetes workload (ns/kind/name).",
                    ));
                }
            }
        }
    }
    Ok(t)
}

/// The host of an advertised URL (`https://192.168.3.2:8443`).
fn host_ip(url: &str) -> Option<IpAddr> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let host = rest.split('/').next()?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.split(']').next())
        .unwrap_or_else(|| host.rsplit_once(':').map_or(host, |(h, _)| h));
    host.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

/// The baseline (devices seen here in the hour before `now`), and which of them `t` targets.
fn baseline(src: &Sources, t: &Targets, at_ms: u64) -> (Vec<[u8; 16]>, Vec<[u8; 16]>) {
    let now_s = at_ms / 1000;
    let base: Vec<[u8; 16]> = src
        .pipeline
        .telemetry
        .aggregates()
        .seen()
        .between(now_s.saturating_sub(BASELINE_S), now_s)
        .map(|(k, _)| *k)
        .collect();
    let workloads = src.pipeline.workloads.snapshot();
    let targets = base
        .iter()
        .filter(|k| {
            if telltale_telemetry::workload::is_key(k) {
                let text = workloads.key_name(k);
                return t.all
                    || text.is_some_and(|w| t.workloads.contains(w))
                    || (t.group.is_some()
                        && workloads
                            .by_key(k)
                            .and_then(|w| w.group.as_deref())
                            .is_some_and(|g| t.group.as_deref() == Some(g)));
            }
            let ip = key_ip(k);
            let (name, groups) = crate::pipeline::name_and_groups(&src.pipeline, ip);
            t.drops(ip, name.as_deref(), None, &groups)
        })
        .copied()
        .collect();
    (base, targets)
}

/// The preconditions, each with whether it holds.
fn checks(src: &Arc<Sources>, now: u64) -> Vec<DrillCheck> {
    let mut v = Vec::new();
    let mut check = |name: &str, ok: bool, detail: String| {
        v.push(DrillCheck {
            name: name.into(),
            ok,
            detail,
        });
    };
    // Another node ready and answering.
    let others: Vec<String> = src
        .cluster
        .as_ref()
        .map(|c| {
            c.members()
                .into_iter()
                .filter(|m| {
                    m.up(now)
                        && m.ready
                        && m.in_maintenance(now).is_none()
                        && m.queries_last_minute > 0
                })
                .map(|m| member_label(&m))
                .collect()
        })
        .unwrap_or_default();
    check(
        "other_node",
        !others.is_empty(),
        if others.is_empty() {
            "No other node is ready and answering queries: a drill would be an outage. Add a second node first, and hand its address out as the second DNS server.".into()
        } else {
            format!("{} can answer meanwhile.", others.join(", "))
        },
    );
    let maint = src.maintenance.current(now);
    check(
        "maintenance",
        maint.is_none(),
        maint.map_or_else(
            || "Not in maintenance.".into(),
            |w| format!("The node is in maintenance ({}): end it first.", w.reason),
        ),
    );
    let last = src.drills.last_any_ms.load(Ordering::Relaxed);
    let running_elsewhere = src.cluster.as_ref().and_then(|c| {
        c.members()
            .into_iter()
            .find(|m| m.drill.as_ref().is_some_and(|d| d.until_ms > now))
            .map(|m| member_label(&m))
    });
    let recent = last > 0 && now < last + gap_ms();
    check(
        "recent_drill",
        !recent && running_elsewhere.is_none() && src.drills.running().is_none(),
        if let Some(n) = running_elsewhere {
            format!("{n} is running a drill: one at a time.")
        } else if recent {
            format!(
                "A drill ended {} s ago: let devices settle for 10 minutes between drills.",
                now.saturating_sub(last) / 1000
            )
        } else {
            "No drill in the last 10 minutes.".into()
        },
    );
    let rollout = crate::rollout::surface::summary(src)
        .filter(|r| r.stage == "pinned" || r.stage == "canary");
    check(
        "rollout",
        rollout.is_none(),
        rollout.map_or_else(
            || "No rollout is baking and the cluster isn't pinned.".into(),
            |r| {
                format!(
                    "The cluster's rollout is {}: wait until it's done.",
                    r.stage
                )
            },
        ),
    );
    let level = telltale_api::Backend::health(&crate::api_backend::ApiBackend {
        src: Arc::clone(src),
    })
    .level;
    // Test hook: the cluster e2e's nodes have no working upstream, so their health is severe.
    let ignore = std::env::var_os("TELLTALE_DRILL_IGNORE_HEALTH").is_some();
    check(
        "health",
        level != "severe" || ignore,
        if level == "severe" && ignore {
            "Health is severe (ignored: the TELLTALE_DRILL_IGNORE_HEALTH test hook).".into()
        } else if level == "severe" {
            "Health is severe: fix that first; a drill would make it worse.".into()
        } else {
            format!("Health is {level}.")
        },
    );
    v
}

/// A cluster member as people know it: its pod, site, or ID.
fn member_label(m: &telltale_cluster::net::Member) -> String {
    if !m.pod.is_empty() {
        m.pod.clone()
    } else if !m.site.is_empty() {
        m.site.clone()
    } else {
        m.node_id.clone()
    }
}

/// What a drill will do, in plain words.
fn preview(secs: u32, resolved: usize, all: bool, mode: DrillMode) -> String {
    let who = if all {
        "every device that asks it".to_owned()
    } else if resolved == 1 {
        "1 device".to_owned()
    } else {
        format!("{resolved} devices")
    };
    match mode {
        DrillMode::Drop => format!(
            "For {secs} seconds this node will not answer {who}. Devices with a second DNS server switch to it within a few seconds; devices without one lose DNS until the drill ends."
        ),
        DrillMode::Refused => format!(
            "For {secs} seconds this node will answer {who} with REFUSED. Devices that try their next server on REFUSED switch at once; the others fail their lookups until the drill ends, even with a second server."
        ),
    }
}

/// A new drill's ID: the start time and some randomness.
fn new_id(now: u64) -> String {
    let r: u32 = rand::random();
    format!("d{now}-{r:08x}")
}

/// REQ: CLU-014 — a drill to start (or dry-run) on this node, as the API checked it.
#[derive(Debug, Clone)]
pub(crate) struct Request {
    pub(crate) for_secs: u32,
    pub(crate) spec: DrillTargets,
    pub(crate) reason: String,
    pub(crate) handover: bool,
    pub(crate) by: String,
    pub(crate) dry_run: bool,
    /// REQ: CLU-014 (owner 2026-10-19) — REFUSED instead of no answer.
    pub(crate) mode: DrillMode,
}

/// REQ: CLU-014 — starts (or dry-runs) a drill on this node; the API checked the request.
#[allow(clippy::too_many_lines)] // checks, resolve, notify, start: one sequence
pub(crate) async fn start_here(src: Arc<Sources>, req: Request) -> Result<DrillStart, Problem> {
    let Request {
        for_secs,
        spec,
        reason,
        handover,
        by,
        dry_run,
        mode,
    } = req;
    let now = now_ms();
    let this = label(&src);
    if src.drills.running().is_some_and(|s| s.until_ms > now) {
        return Err(Problem::new(
            Code::DrillActive,
            format!("{this} is already running a drill"),
        )
        .hint("End it with DELETE /api/v1/nodes/{id}/drill, or wait for it to finish."));
    }
    let checks = {
        let src = Arc::clone(&src);
        tokio::task::spawn_blocking(move || checks(&src, now))
            .await
            .map_err(|e| Problem::internal(format!("drill: {e}")))?
    };
    let targets = build_targets(&src, &spec)?;
    let all = targets.all;
    let (base, hit) = baseline(&src, &targets, now);
    let text = targets_text(&spec);
    let until = now + u64::from(for_secs) * 1000;
    let mut out = DrillStart {
        id: String::new(),
        node: this.clone(),
        dry_run,
        since: telltale_api::time::format_us(now.saturating_mul(1000)),
        until: telltale_api::time::format_us(until.saturating_mul(1000)),
        targets: text.clone(),
        targets_resolved: u32::try_from(hit.len()).unwrap_or(u32::MAX),
        baseline: u32::try_from(base.len()).unwrap_or(u32::MAX),
        checks: checks.clone(),
        devices: Vec::new(),
        handover: "not_needed".into(),
        preview: preview(for_secs, hit.len(), all, mode),
        note: None,
    };
    let no_device = !all && hit.is_empty();
    if dry_run {
        out.devices = hit
            .iter()
            .take(DRY_RUN_DEVICES)
            .map(|k| DrillTargetDevice {
                client: key_text(k),
                name: crate::api_backend::device_name(&src, *k),
            })
            .collect();
        out.checks.push(DrillCheck {
            name: "targets".into(),
            ok: !no_device,
            detail: if no_device {
                "No device seen on this node in the last hour matches the targets.".into()
            } else {
                format!(
                    "{} of the {} devices seen here in the last hour.",
                    hit.len(),
                    base.len()
                )
            },
        });
        return Ok(out);
    }
    if let Some(failed) = checks.iter().find(|c| !c.ok) {
        return Err(
            Problem::new(Code::DrillRefused, failed.detail.clone()).hint(format!(
                "Precondition `{}`. A dry run (?dryRun=true) lists them all.",
                failed.name
            )),
        );
    }
    if no_device {
        return Err(Problem::new(
            Code::DrillTargets,
            format!("no device seen on {this} in the last hour matches {text}"),
        )
        .hint("Check the targets (a typo?), or drill `\"all\"`."));
    }
    let id = new_id(now);
    // The other nodes start recording before anything is dropped (the heartbeat's mark is the
    // fallback for a node that misses this).
    notify_peers(&src, &id, now, until).await;
    src.pipeline.telemetry.aggregates().start_window(&id, now);
    *src.drills
        .recording
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some((id.clone(), until, None));
    let (outcome, note, step_down) = match &src.cluster {
        Some(c) => crate::maintenance::handover_plan(c, handover, now),
        None => ("not_needed", None, false),
    };
    src.maintenance
        .start(crate::maintenance::Window {
            until_ms: until,
            since_ms: now,
            reason: format!("failover drill: {reason}"),
            by: by.clone(),
            handover: step_down,
            drill: Some(id.clone()),
        })
        .map_err(|e| Problem::internal(format!("can't write the drill's window: {e}")))?;
    src.pipeline.drill.set(
        Targets {
            refused: mode == DrillMode::Refused,
            ..targets
        },
        until,
    );
    if let Some(c) = &src.cluster {
        c.set_local(|l| {
            l.drill = Some(DrillMark {
                id: id.clone(),
                since_ms: now,
                until_ms: until,
            });
        });
    }
    let via_balancer = src.cluster.as_ref().is_some_and(|c| c.is_ephemeral());
    let s = Stored {
        report: DrillReport {
            summary: DrillSummary {
                id: id.clone(),
                node: this.clone(),
                since: out.since.clone(),
                until: out.until.clone(),
                targets: text.clone(),
                reason: reason.clone(),
                by: by.clone(),
                mode,
                status: "running".into(),
                via_balancer,
                ..DrillSummary::default()
            },
            baseline: out.baseline,
            ..DrillReport::default()
        },
        since_ms: now,
        until_ms: until,
        ended_ms: None,
        baseline: base,
        targets: hit,
        first_try_ms: None,
        waiting: Vec::new(),
    };
    save(&src, &s);
    *src.drills
        .running
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(s);
    src.drills.changed.notify_one();
    info!(%id, until_ms = until, targets = %text, "failover drill started ({reason})");
    // REQ: OBS-033 — a change marker.
    crate::annotations::record(telltale_api::model::Annotation {
        actor: Some(by),
        until: Some(out.until.clone()),
        reason: Some(reason),
        href: Some("#/cluster".into()),
        ..crate::annotations::marker(
            "drill.started",
            now,
            format!("failover drill on {this} for {for_secs} s: {text}"),
        )
    });
    out.id = id;
    out.handover = if outcome == "unavailable" {
        "none".into()
    } else {
        outcome.into()
    };
    out.note = note;
    Ok(out)
}

/// Tells every peer to start recording (best effort, at most [`NOTICE_DEADLINE`]).
async fn notify_peers(src: &Sources, id: &str, since_ms: u64, until_ms: u64) {
    let Some(c) = &src.cluster else { return };
    let now = now_ms();
    let Ok(body) = serde_json::to_vec(&Op::Window {
        id: id.to_owned(),
        since_ms,
        until_ms,
    }) else {
        return;
    };
    let mut calls = tokio::task::JoinSet::new();
    for m in c.members().into_iter().filter(|m| m.up(now)) {
        let (c, body) = (Arc::clone(c), body.clone());
        calls.spawn(async move { c.call(&m.node_id, KIND, body, NOTICE_DEADLINE).await });
    }
    while calls.join_next().await.is_some() {}
}

/// REQ: CLU-014 — ends this node's drill (early, or at its end); the report follows after the
/// grace. Returns it, or `None` when none ran.
pub(crate) fn end_here(src: &Sources, why: &str) -> Option<Stored> {
    let mut s = src
        .drills
        .running
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()?;
    let now = now_ms();
    src.pipeline.drill.clear();
    if let Some(c) = &src.cluster {
        c.set_local(|l| l.drill = None);
    }
    if src
        .maintenance
        .current(now)
        .is_some_and(|w| w.drill.as_deref() == Some(s.report.summary.id.as_str()))
        && let Err(e) = src.maintenance.end()
    {
        warn!("drill: can't remove the window file: {e}");
    }
    let ended = now.min(s.until_ms);
    s.ended_ms = Some(ended);
    s.report.summary.ended = Some(telltale_api::time::format_us(ended.saturating_mul(1000)));
    s.report.summary.status = "collecting".into();
    if let Some((_, _, e)) = src
        .drills
        .recording
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_mut()
    {
        *e = Some(ended);
    }
    src.drills.last_any_ms.fetch_max(ended, Ordering::Relaxed);
    save(src, &s);
    info!(id = %s.report.summary.id, "failover drill ended ({why}); the report follows in about a minute");
    src.drills.changed.notify_one();
    Some(s)
}

/// REQ: CLU-014 — a drill cancelled by a restart: recorded, never resumed.
pub(crate) fn cancelled_at_start(src: &Sources) {
    let Some(w) = src.maintenance.take_cancelled_drill() else {
        return;
    };
    let Some(id) = w.drill else { return };
    src.drills.cancelled.fetch_add(1, Ordering::Relaxed);
    src.drills
        .last_any_ms
        .fetch_max(now_ms(), Ordering::Relaxed);
    if let Some(mut s) = load(src, &id) {
        s.report.summary.status = "cancelled".into();
        s.ended_ms = Some(now_ms().min(s.until_ms));
        s.report.summary.ended = s
            .ended_ms
            .map(|e| telltale_api::time::format_us(e.saturating_mul(1000)));
        save(src, &s);
    }
    crate::annotations::record(telltale_api::model::Annotation {
        href: Some("#/cluster".into()),
        ..crate::annotations::marker(
            "drill.ended",
            now_ms(),
            "failover drill cancelled: the node restarted during it".to_owned(),
        )
    });
}

// ---- The peer call ----

/// One request on [`KIND`].
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum Op {
    /// Start or end a drill on the node called (a user acted elsewhere).
    Write { write: DrillWrite, sent_ms: u64 },
    /// A drill started on the caller: record a window.
    Window {
        id: String,
        since_ms: u64,
        until_ms: u64,
    },
    /// This node's part of a drill's window.
    Part { id: String },
    /// This node's drills.
    List,
    /// One of this node's drills, in full.
    Report { id: String },
    /// The drill this node runs.
    Active,
    /// This node's seen table over `days` (the affinity view).
    Seen { days: u32 },
}

/// A part: the window, or why there's none yet.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum PartAnswer {
    Ready { window: Window },
    Recording,
    Unknown,
}

/// One device in a node's affinity answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SeenRow {
    pub(crate) key: [u8; 16],
    pub(crate) queries: u64,
    /// The device's name as the answering node knows it.
    #[serde(default)]
    pub(crate) name: Option<String>,
}

fn json<T: Serialize>(v: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(v).map_err(|e| e.to_string())
}

/// REQ: CLU-014 — a peer's drill call.
pub(crate) async fn handle(
    src: Arc<Sources>,
    cluster: Arc<Cluster>,
    peer: String,
    body: Vec<u8>,
    ephemeral: bool,
) -> Result<Vec<u8>, String> {
    let op: Op = serde_json::from_slice(&body).map_err(|e| format!("bad drill call: {e}"))?;
    match op {
        Op::Write { write, sent_ms } => {
            if ephemeral {
                return Err("an ephemeral member can't change this node's state".into());
            }
            if now_ms() > sent_ms.saturating_add(STALE_MS) {
                return Err("the request is too old; the node that sent it gave up on it".into());
            }
            let via = cluster
                .members()
                .into_iter()
                .find(|m| m.node_id == peer)
                .map_or_else(|| peer.clone(), |m| member_label(&m));
            let r = apply(Arc::clone(&src), write, Some(&via)).await;
            if let (Ok(res), Some(auth)) = (&r, src.auth.get())
                && !res.dry_run
            {
                let actor = telltale_api::auth::Actor {
                    name: format!("via {via}"),
                    kind: "cluster",
                    remote: Some(format!("node {peer}")),
                    reason: None,
                };
                auth.record(
                    &actor,
                    if res.id.is_empty() { "drill.end" } else { "drill.start" },
                    &res.node,
                    &serde_json::json!({ "id": res.id, "until": res.until, "targets": res.targets }),
                );
            }
            crate::forward::encode_answer(r)
        }
        Op::Window {
            id,
            since_ms,
            until_ms,
        } => {
            record_window(&src, &id, since_ms, until_ms);
            json(&true)
        }
        Op::Part { id } => json(&part(&src, &id)),
        Op::List => json(
            &stored(&src)
                .into_iter()
                .map(|s| s.report.summary)
                .collect::<Vec<_>>(),
        ),
        Op::Report { id } => json(&load(&src, &id).map(|s| privacy(&src, s.report))),
        Op::Active => json(&active(&src)),
        Op::Seen { days } => json(&seen_rows(&src, days)),
    }
}

/// REQ: CLU-014 — a start or end for this node (from the API, or a peer: `via`).
pub(crate) async fn apply(
    src: Arc<Sources>,
    w: DrillWrite,
    via: Option<&str>,
) -> Result<DrillStart, Problem> {
    match w {
        DrillWrite::Start {
            for_secs,
            targets,
            reason,
            handover,
            by,
            dry_run,
            mode,
        } => {
            let for_secs = telltale_api::drill_api::check_secs(Some(for_secs))?;
            let by = via.map_or(by.clone(), |v| format!("{by} via {v}"));
            start_here(
                src,
                Request {
                    for_secs,
                    spec: targets,
                    reason,
                    handover,
                    by,
                    dry_run,
                    mode,
                },
            )
            .await
        }
        DrillWrite::End { .. } => {
            let this = label(&src);
            let s = tokio::task::spawn_blocking({
                let src = Arc::clone(&src);
                move || end_here(&src, "ended early")
            })
            .await
            .map_err(|e| Problem::internal(format!("drill: {e}")))?
            .ok_or_else(|| {
                Problem::not_found(format!("no drill runs on {this}"))
                    .hint("Past drills are at /api/v1/drills.")
            })?;
            Ok(DrillStart {
                id: s.report.summary.id.clone(),
                node: this,
                since: s.report.summary.since.clone(),
                until: s.report.summary.ended.clone().unwrap_or_default(),
                targets: s.report.summary.targets.clone(),
                handover: "not_needed".into(),
                preview: "Ended early: the node answers everyone again. The report follows in about a minute.".into(),
                ..DrillStart::default()
            })
        }
    }
}

/// REQ: CLU-014 — a request for a peer, over its cluster stream.
pub(crate) async fn send(
    cluster: Arc<Cluster>,
    peer: String,
    label: String,
    w: DrillWrite,
) -> Result<DrillStart, Problem> {
    let body = serde_json::to_vec(&Op::Write {
        write: w,
        sent_ms: now_ms(),
    })
    .map_err(|e| Problem::internal(e.to_string()))?;
    let reply = cluster
        .call(&peer, KIND, body, WRITE_DEADLINE)
        .await
        .map_err(|e| {
            let older = e.contains("unknown call");
            Problem::new(
                Code::NodeUnreachable,
                if older {
                    format!("{label} runs a version without failover drills")
                } else {
                    format!("{label} isn't reachable over the cluster channel: {e}")
                },
            )
            .hint(if older {
                "Upgrade it first."
            } else {
                "A drill is the node's own state, so the node must be up to take it. Check the Cluster page."
            })
        })?;
    crate::forward::decode_answer(&reply)
}

/// Asks every member for `op`: the answers by label, and who didn't answer (unreachable, or
/// too old to know drills).
pub(crate) async fn ask_all(
    cluster: &Arc<Cluster>,
    op: &Op,
) -> (Vec<(String, Vec<u8>)>, Vec<String>) {
    let Ok(body) = serde_json::to_vec(op) else {
        return (Vec::new(), Vec::new());
    };
    let mut calls = tokio::task::JoinSet::new();
    for m in cluster.members() {
        let (c, body) = (Arc::clone(cluster), body.clone());
        calls.spawn(async move {
            let label = member_label(&m);
            (label, c.call(&m.node_id, KIND, body, READ_DEADLINE).await)
        });
    }
    let mut ok = Vec::new();
    let mut missing = Vec::new();
    while let Some(r) = calls.join_next().await {
        match r {
            Ok((label, Ok(b))) => ok.push((label, b)),
            Ok((label, Err(_))) => missing.push(label),
            Err(_) => {}
        }
    }
    ok.sort_by(|a, b| a.0.cmp(&b.0));
    missing.sort();
    (ok, missing)
}

/// The drill this node runs, for the API.
pub(crate) fn active(src: &Sources) -> Option<ActiveDrill> {
    let s = src.drills.running()?;
    let now = now_ms();
    if s.until_ms <= now {
        return None;
    }
    let w = src
        .pipeline
        .telemetry
        .aggregates()
        .window()
        .filter(|w| w.id == s.report.summary.id)
        .map(|w| {
            let dropped: u64 = w.clients.values().map(|e| u64::from(e.drilled)).sum();
            let devices = w.clients.values().filter(|e| e.drilled > 0).count();
            (dropped, u32::try_from(devices).unwrap_or(u32::MAX))
        })
        .unwrap_or_default();
    Some(ActiveDrill {
        id: s.report.summary.id.clone(),
        node: s.report.summary.node.clone(),
        since: s.report.summary.since.clone(),
        until: s.report.summary.until.clone(),
        seconds_left: s.until_ms.saturating_sub(now).div_ceil(1000),
        targets: s.report.summary.targets.clone(),
        reason: s.report.summary.reason.clone(),
        by: s.report.summary.by.clone(),
        dropped: w.0,
        devices_dropped: w.1,
    })
}

/// This node's drills, newest first.
pub(crate) fn list(src: &Sources) -> Vec<DrillSummary> {
    stored(src).into_iter().map(|s| s.report.summary).collect()
}

/// One of this node's reports, as the privacy level allows.
pub(crate) fn report(src: &Sources, id: &str) -> Option<DrillReport> {
    load(src, id).map(|s| privacy(src, s.report))
}

/// Privacy level 2 and above: counts only.
fn privacy(src: &Sources, mut r: DrillReport) -> DrillReport {
    if src.config.load().telemetry.qlog.privacy_level >= 2 {
        r.devices.clear();
    }
    r
}

/// This node's seen table over the last `days`.
pub(crate) fn seen_rows(src: &Sources, days: u32) -> Vec<SeenRow> {
    let now_s = now_ms() / 1000;
    let n = usize::try_from(days).unwrap_or(7);
    let rows: Vec<SeenRow> = src
        .pipeline
        .telemetry
        .aggregates()
        .seen()
        .clients
        .iter()
        .map(|(k, e)| SeenRow {
            key: *k,
            queries: e.recent(now_s, n),
            name: None,
        })
        .filter(|r| r.queries > 0)
        .collect();
    rows.into_iter()
        .map(|mut r| {
            r.name = crate::api_backend::device_name(src, r.key);
            r
        })
        .collect()
}

/// REQ: CLU-014 — the rows behind an affinity page (one node's), to merge with peers'.
pub(crate) fn rows_of(page: &telltale_api::model::AffinityPage) -> Vec<SeenRow> {
    page.items
        .iter()
        .filter_map(|r| {
            let key = mapped(r.client.parse::<IpAddr>().ok()?);
            Some(SeenRow {
                key,
                queries: r.queries,
                name: r.name.clone(),
            })
        })
        .collect()
}

/// REQ: CLU-014 — a page of drills (every node's, newest first).
pub(crate) fn page(
    mut items: Vec<DrillSummary>,
    limit: usize,
    offset: usize,
    missing: Vec<String>,
) -> telltale_api::model::DrillPage {
    items.sort_by(|a, b| b.since.cmp(&a.since).then(a.id.cmp(&b.id)));
    items.dedup_by(|a, b| a.id == b.id);
    let next = (items.len() > offset + limit).then(|| (offset + limit).to_string());
    telltale_api::model::DrillPage {
        items: items.into_iter().skip(offset).take(limit).collect(),
        next_cursor: next,
        missing_nodes: missing,
    }
}

/// What the affinity view can't tell (`spec/06` §8.5).
pub(crate) const AFFINITY_CAVEAT: &str = "A device that has only used one server may still have a second one configured; most systems use their first server until it stops answering. Run a drill to find out.";

/// REQ: CLU-014 — the affinity view from every node's seen rows.
pub(crate) fn affinity_page(
    days: u32,
    per_node: Vec<(String, Vec<SeenRow>)>,
    missing: Vec<String>,
) -> telltale_api::model::AffinityPage {
    use telltale_api::model::{AffinityNode, AffinityRow};
    let mut by: BTreeMap<[u8; 16], Vec<(String, u64)>> = BTreeMap::new();
    let mut names: HashMap<[u8; 16], String> = HashMap::new();
    for (node, rows) in per_node {
        for r in rows {
            by.entry(r.key).or_default().push((node.clone(), r.queries));
            if let Some(n) = r.name {
                names.entry(r.key).or_insert(n);
            }
        }
    }
    let mut items: Vec<AffinityRow> = by
        .into_iter()
        .map(|(k, mut nodes)| {
            nodes.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            let total: u64 = nodes.iter().map(|(_, q)| q).sum();
            let (top, top_q) = nodes.first().cloned().unwrap_or_default();
            #[allow(clippy::cast_precision_loss)] // shares of query counts
            let share = if total == 0 {
                0.0
            } else {
                ((top_q as f64) * 1000.0 / (total as f64)).round() / 10.0
            };
            let label = if share >= 90.0 {
                format!("mostly {top}")
            } else if nodes.len() == 2 {
                "both".to_owned()
            } else {
                "several".to_owned()
            };
            AffinityRow {
                client: key_text(&k),
                name: names.get(&k).cloned(),
                queries: total,
                nodes: nodes
                    .into_iter()
                    .map(|(node, queries)| AffinityNode { node, queries })
                    .collect(),
                top_node: top,
                top_share_percent: share,
                label,
            }
        })
        .collect();
    items.sort_by(|a, b| b.queries.cmp(&a.queries).then(a.client.cmp(&b.client)));
    telltale_api::model::AffinityPage {
        window_days: days,
        items,
        missing_nodes: missing,
        caveat: AFFINITY_CAVEAT.into(),
    }
}

// ---- Windows and parts (every node) ----

/// Starts recording a drill's window here (from the drilled node's notice or its heartbeat).
fn record_window(src: &Sources, id: &str, since_ms: u64, until_ms: u64) {
    if !valid_id(id) {
        return;
    }
    let mut rec = src
        .drills
        .recording
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if rec.as_ref().is_some_and(|(r, _, _)| r == id) {
        return;
    }
    if rec.is_some() {
        // One at a time: an unfinished window is frozen as it stands.
        drop(rec);
        freeze(src);
        rec = src
            .drills
            .recording
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
    }
    src.pipeline
        .telemetry
        .aggregates()
        .start_window(id, since_ms);
    *rec = Some((id.to_owned(), until_ms, None));
    info!(%id, "recording a failover drill's window");
}

/// Stops recording and saves this node's part.
fn freeze(src: &Sources) {
    let taken = src
        .drills
        .recording
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    let Some((id, _, _)) = taken else { return };
    let w = src.pipeline.telemetry.aggregates().take_window();
    if let Some(w) = w.filter(|w| w.id == id) {
        let path = dir(src).join(format!("{id}.part.json"));
        if let Err(e) = write_json(&path, &w) {
            warn!("drill: part not saved to {}: {e}", path.display());
        }
    }
}

/// This node's part of drill `id`.
fn part(src: &Sources, id: &str) -> PartAnswer {
    if !valid_id(id) {
        return PartAnswer::Unknown;
    }
    if src
        .drills
        .recording
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .is_some_and(|(r, _, _)| r == id)
    {
        return PartAnswer::Recording;
    }
    std::fs::read(dir(src).join(format!("{id}.part.json")))
        .ok()
        .and_then(|b| serde_json::from_slice::<Window>(&b).ok())
        .map_or(PartAnswer::Unknown, |window| PartAnswer::Ready { window })
}

/// One pass of the background task: expiry, windows, reports, the "came back" check.
async fn tick(src: &Arc<Sources>) {
    let now = now_ms();
    // This node's drill ran out.
    if src.drills.running().is_some_and(|s| s.until_ms <= now) {
        let src2 = Arc::clone(src);
        let _ = tokio::task::spawn_blocking(move || end_here(&src2, "time is up")).await;
    }
    // Drills elsewhere, from heartbeats (the fallback for a missed notice), and the gap.
    if let Some(c) = &src.cluster {
        for m in c.members() {
            if let Some(d) = &m.drill {
                if d.until_ms > now {
                    record_window(src, &d.id, d.since_ms, d.until_ms);
                }
                src.drills
                    .last_any_ms
                    .fetch_max(d.until_ms.min(now), Ordering::Relaxed);
            }
        }
        // A recorded drill that vanished from heartbeats ended early.
        let marks: HashSet<String> = c
            .members()
            .into_iter()
            .filter_map(|m| m.drill.map(|d| d.id))
            .chain(src.drills.running().map(|s| s.report.summary.id))
            .collect();
        let mut rec = src
            .drills
            .recording
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((id, until, ended)) = rec.as_mut()
            && ended.is_none()
            && (!marks.contains(id.as_str()) || *until <= now)
        {
            *ended = Some(now.min(*until));
        }
    } else if let Some((_, until, ended)) = src
        .drills
        .recording
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_mut()
        && ended.is_none()
        && *until <= now
    {
        *ended = Some(*until);
    }
    let due = src
        .drills
        .recording
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .and_then(|(_, _, e)| *e)
        .is_some_and(|e| now >= e + GRACE_MS);
    if due {
        freeze(src);
    }
    // Reports this node collects.
    for s in stored(src) {
        match s.report.summary.status.as_str() {
            "collecting" if s.ended_ms.is_some_and(|e| now >= e + GRACE_MS + 2_000) => {
                collect(src, s).await;
            }
            "complete"
                if !s.report.returned_checked
                    && s.ended_ms.is_some_and(|e| now >= e + return_ms()) =>
            {
                check_returned(src, s);
            }
            _ => {}
        }
    }
    scheduled(src).await;
}

/// The names `[drill] nodes` may use for this node: its label, site, pod, and ID.
fn own_names(src: &Sources) -> Vec<String> {
    let mut v = vec![label(src)];
    if let Some(c) = &src.cluster {
        let m = &c.identity.meta;
        v.push(m.node_id.clone());
        v.push(m.site.clone());
        v.push(c.local_state().pod);
    }
    v.retain(|n| !n.is_empty());
    v
}

/// REQ: CLU-014 (owner 2026-10-19) — `[drill] schedule = "monthly"`: on the nodes `[drill]
/// nodes` names, in the drill's hour on its day, start it (tried once a minute through the hour:
/// a precondition that fails all hour skips the month), never within 7 days of another drill on
/// this node. The report goes out as the `drill_report` alert.
async fn scheduled(src: &Arc<Sources>) {
    let cfg = src.config.load_full();
    let d = &cfg.drill;
    if d.schedule == telltale_config::DrillSchedule::Off {
        return;
    }
    let names = own_names(src);
    if !d
        .nodes
        .iter()
        .any(|n| names.iter().any(|x| x == n.as_str()))
    {
        return;
    }
    let now = now_ms();
    let Some((year, month)) = telltale_config::schedule::drill_slot(
        d,
        &label(src),
        i64::try_from(now / 1000).unwrap_or(i64::MAX),
    ) else {
        return;
    };
    if now < src.drills.scheduled_try_ms.load(Ordering::Relaxed) + 60_000
        || src.drills.running().is_some()
    {
        return;
    }
    src.drills.scheduled_try_ms.store(now, Ordering::Relaxed);
    if stored(src)
        .iter()
        .any(|s| s.since_ms + 7 * 86_400_000 > now)
    {
        return;
    }
    let spec = match (&d.group, d.clients.is_empty()) {
        (Some(g), _) => DrillTargets::Group {
            group: g.to_string(),
        },
        (None, false) => DrillTargets::Clients {
            clients: d.clients.iter().map(ToString::to_string).collect(),
        },
        (None, true) => DrillTargets::All(telltale_api::model::DrillAll::All),
    };
    let req = Request {
        for_secs: d.for_secs.clamp(15, 300),
        spec,
        reason: format!("scheduled monthly drill ({year}-{month:02})"),
        handover: true,
        by: "schedule".into(),
        dry_run: false,
        mode: match d.mode {
            telltale_config::DrillMode::Drop => DrillMode::Drop,
            telltale_config::DrillMode::Refused => DrillMode::Refused,
        },
    };
    match start_here(Arc::clone(src), req).await {
        Ok(r) => {
            info!(id = %r.id, "scheduled failover drill started");
            if let Some(auth) = src.auth.get() {
                auth.record(
                    &telltale_api::auth::Actor::system("schedule"),
                    "drill.start",
                    &r.node,
                    &serde_json::json!({ "id": r.id, "until": r.until, "targets": r.targets, "scheduled": true }),
                );
            }
        }
        Err(p) => info!(
            "scheduled failover drill not started ({}); tried again in a minute, until the hour ends",
            p.detail
        ),
    }
}

/// Merges every node's part into the report (or waits for missing ones, up to 5 minutes).
#[allow(clippy::too_many_lines)] // gather, wait or finalize, name, compute, save, mark
async fn collect(src: &Arc<Sources>, mut s: Stored) {
    let now = now_ms();
    let id = s.report.summary.id.clone();
    let own_label = label(src);
    let mut parts: Vec<(String, Window)> = Vec::new();
    if let PartAnswer::Ready { window } = part(src, &id) {
        parts.push((own_label.clone(), window));
    }
    let mut missing = Vec::new();
    let mut pending = Vec::new();
    if let Some(c) = &src.cluster {
        let (answers, unreachable) = ask_all(c, &Op::Part { id: id.clone() }).await;
        missing.extend(unreachable);
        let drills_ok: HashMap<String, bool> = c
            .members()
            .into_iter()
            .map(|m| (member_label(&m), m.drills))
            .collect();
        for (label, body) in answers {
            match serde_json::from_slice::<PartAnswer>(&body) {
                Ok(PartAnswer::Ready { window }) => parts.push((label, window)),
                Ok(PartAnswer::Recording) => pending.push(label),
                // It never recorded this drill: too old, or it missed both the notice and
                // the heartbeat (a partition).
                Ok(PartAnswer::Unknown) | Err(_) => missing.push(label),
            }
        }
        // An N-1 peer answers "unknown call": missing, never an error.
        missing.retain(|l| !parts.iter().any(|(p, _)| p == l));
        let _ = drills_ok;
    }
    let first = *s.first_try_ms.get_or_insert(now);
    let waiting: Vec<String> = missing.iter().chain(&pending).cloned().collect();
    if !waiting.is_empty() && now < first + part_retry_ms() {
        s.waiting = waiting;
        save(src, &s);
        return;
    }
    missing.extend(pending);
    missing.sort();
    missing.dedup();
    let names = {
        let src = Arc::clone(src);
        let keys: Vec<[u8; 16]> = parts
            .iter()
            .flat_map(|(_, w)| w.clients.keys().copied())
            .chain(s.targets.iter().copied())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        tokio::task::spawn_blocking(move || {
            keys.into_iter()
                .map(|k| {
                    (
                        k,
                        (
                            crate::api_backend::device_name(&src, k),
                            crate::pipeline::group_of(&src.pipeline, key_ip(&k)),
                        ),
                    )
                })
                .collect::<HashMap<_, _>>()
        })
        .await
        .unwrap_or_default()
    };
    let computed = compute(&Input {
        drilled: &own_label,
        parts: &parts,
        targets: &s.targets.iter().copied().collect(),
        since_ms: s.since_ms,
        ended_ms: s.ended_ms.unwrap_or(s.until_ms),
        names: &names,
    });
    let sum = &mut s.report.summary;
    sum.status = "complete".into();
    sum.followed = computed.followed;
    sum.stuck = computed.stuck;
    sum.quiet = computed.quiet;
    sum.elsewhere = computed.elsewhere;
    sum.coverage_percent = computed.coverage_percent;
    sum.median_failover_ms = computed.median_ms;
    sum.p90_failover_ms = computed.p90_ms;
    sum.missing_nodes = missing;
    s.report.devices = computed.devices;
    s.report.nodes = computed.nodes;
    s.report.overflow = computed.overflow;
    s.report.balancer_switch_ms = s
        .report
        .summary
        .via_balancer
        .then_some(
            computed
                .last_dropped_ms
                .map(|l| l.saturating_sub(s.since_ms)),
        )
        .flatten();
    s.waiting.clear();
    save(src, &s);
    prune(src);
    src.drills.completed.fetch_add(1, Ordering::Relaxed);
    *src.drills
        .last
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(s.report.summary.clone());
    let sum = &s.report.summary;
    let coverage = sum.coverage_percent.map_or_else(
        || "no coverage figure".to_owned(),
        |c| format!("{c:.0} % coverage"),
    );
    info!(%id, followed = sum.followed, stuck = sum.stuck, "failover drill report ready ({coverage})");
    // REQ: OBS-033 — the marker, with the summary.
    crate::annotations::record(telltale_api::model::Annotation {
        reason: Some(sum.reason.clone()),
        href: Some(format!("#/cluster?drill={id}")),
        ..crate::annotations::marker(
            "drill.ended",
            s.ended_ms.unwrap_or(now),
            format!(
                "failover drill on {}: {} followed, {} stuck, {} quiet ({coverage})",
                sum.node, sum.followed, sum.stuck, sum.quiet
            ),
        )
    });
    if let Some(auth) = src.auth.get() {
        auth.record(
            &telltale_api::auth::Actor::system("drill"),
            "drill.end",
            &sum.node,
            &serde_json::json!({
                "id": id, "followed": sum.followed, "stuck": sum.stuck, "quiet": sum.quiet,
                "coveragePercent": sum.coverage_percent, "missingNodes": sum.missing_nodes,
            }),
        );
    }
}

/// 15 minutes after the drill: did each device that followed come back to this node?
fn check_returned(src: &Sources, mut s: Stored) {
    let ended_s = s.ended_ms.unwrap_or(s.until_ms) / 1000;
    let agg = src.pipeline.telemetry.aggregates();
    let seen = agg.seen();
    for d in s
        .report
        .devices
        .iter_mut()
        .filter(|d| d.verdict == "followed")
    {
        let key = d
            .client
            .parse::<IpAddr>()
            .map(mapped)
            .ok()
            .or_else(|| s.targets.iter().copied().find(|k| key_text(k) == d.client));
        d.returned = Some(
            key.and_then(|k| seen.clients.get(&k))
                .is_some_and(|e| e.last_s > ended_s),
        );
    }
    drop(agg);
    s.report.returned_checked = true;
    save(src, &s);
}

/// The seen table's file in the data directory.
const SEEN_FILE: &str = "clients-seen.json";
/// How often it's saved (and at shutdown).
const SEEN_EVERY: Duration = Duration::from_secs(3600);

/// REQ: CLU-014 (AC 6) — folds the saved seen table into the aggregates (at start).
pub(crate) fn load_seen(src: &Sources) {
    let path = Path::new(src.config.load().node.data_dir.as_str()).join(SEEN_FILE);
    let Some(saved) = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<telltale_telemetry::seen::Seen>(&b).ok())
    else {
        return;
    };
    let mut agg = src.pipeline.telemetry.aggregates();
    let seen = agg.seen_mut();
    seen.merge(saved);
    seen.expire(now_ms() / 1000);
}

/// REQ: CLU-014 — saves the seen table (expired entries dropped first).
pub(crate) fn save_seen(src: &Sources) {
    let path = Path::new(src.config.load().node.data_dir.as_str()).join(SEEN_FILE);
    let seen = {
        let mut agg = src.pipeline.telemetry.aggregates();
        agg.seen_mut().expire(now_ms() / 1000);
        agg.seen().clone()
    };
    if let Err(e) = write_json(&path, &seen) {
        warn!("drill: seen table not saved to {}: {e}", path.display());
    }
}

/// REQ: CLU-014 — the background task: once a second, until `stop` (then the seen table is
/// saved).
pub(crate) fn spawn(src: Arc<Sources>, mut stop: tokio::sync::watch::Receiver<bool>) {
    cancelled_at_start(&src);
    load_seen(&src);
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(1));
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut saved = tokio::time::Instant::now();
        loop {
            tokio::select! {
                _ = t.tick() => {}
                () = src.drills.changed.notified() => {}
                _ = stop.wait_for(|s| *s) => break,
            }
            tick(&src).await;
            if saved.elapsed() >= SEEN_EVERY {
                saved = tokio::time::Instant::now();
                let src = Arc::clone(&src);
                let _ = tokio::task::spawn_blocking(move || save_seen(&src)).await;
            }
        }
        let src2 = Arc::clone(&src);
        let _ = tokio::task::spawn_blocking(move || save_seen(&src2)).await;
    });
}

// ---- The report ----

/// What [`compute`] needs.
pub(crate) struct Input<'a> {
    /// The drilled node's label (its part has the dropped queries).
    pub(crate) drilled: &'a str,
    pub(crate) parts: &'a [(String, Window)],
    /// The baseline's devices the drill targeted.
    pub(crate) targets: &'a HashSet<[u8; 16]>,
    pub(crate) since_ms: u64,
    /// When the drill ended (its end time, or earlier when stopped).
    pub(crate) ended_ms: u64,
    /// Name and group per device.
    pub(crate) names: &'a HashMap<[u8; 16], (Option<String>, Option<String>)>,
}

/// The verdicts and the summary numbers.
#[derive(Debug, Default)]
pub(crate) struct Computed {
    pub(crate) devices: Vec<DrillDevice>,
    pub(crate) nodes: Vec<DrillNodeCount>,
    pub(crate) followed: u32,
    pub(crate) stuck: u32,
    pub(crate) quiet: u32,
    pub(crate) elsewhere: u32,
    pub(crate) coverage_percent: Option<f64>,
    pub(crate) median_ms: Option<u64>,
    pub(crate) p90_ms: Option<u64>,
    pub(crate) overflow: u64,
    pub(crate) last_dropped_ms: Option<u64>,
}

/// REQ: CLU-014 (ADR-151) — the verdicts. Per device among the targets, anyone the drilled node
/// dropped, and anyone another node answered: `followed` when another node answered it after
/// its first dropped query and by [`FOLLOW_GRACE_MS`] after the end, `stuck` with [`STUCK_MIN`]
/// or more dropped and no such answer, `quiet` otherwise for a target (nothing dropped, or too
/// few to tell), and `elsewhere` for a device that wasn't targeted.
#[allow(clippy::too_many_lines)] // one pass per device; the summary after
pub(crate) fn compute(i: &Input<'_>) -> Computed {
    let mut out = Computed::default();
    let drilled = i.parts.iter().find(|(l, _)| l == i.drilled).map(|(_, w)| w);
    let mut devices: std::collections::BTreeSet<[u8; 16]> = i.targets.iter().copied().collect();
    for (_, w) in i.parts {
        out.overflow += w.overflow;
        for (k, e) in &w.clients {
            let is_drilled_node = drilled.is_some_and(|d| std::ptr::eq(d, w));
            if !is_drilled_node || e.drilled > 0 {
                devices.insert(*k);
            }
        }
    }
    for (label, w) in i.parts {
        let queries: u64 = w.clients.values().map(|e| u64::from(e.queries)).sum();
        out.nodes.push(DrillNodeCount {
            node: label.clone(),
            queries,
            devices: u32::try_from(w.clients.len()).unwrap_or(u32::MAX),
        });
    }
    let mut times = Vec::new();
    let cutoff = i.ended_ms.saturating_add(FOLLOW_GRACE_MS);
    for k in &devices {
        let here = drilled.and_then(|w| w.clients.get(k));
        let dropped = here.map_or(0, |e| e.drilled);
        let first_drop = here.map(|e| e.first_drilled_ms).filter(|t| *t > 0);
        if let Some(e) = here.filter(|e| e.drilled > 0) {
            out.last_dropped_ms = out.last_dropped_ms.max(Some(e.last_drilled_ms));
        }
        let mut elsewhere_q = 0u32;
        let mut first_after: Option<u64> = None;
        // Asking another node before and after the first drop: it followed, time unknown.
        let mut already_there = false;
        let mut nodes = Vec::new();
        for (label, w) in i.parts.iter().filter(|(l, _)| l != i.drilled) {
            if let Some(e) = w.clients.get(k) {
                elsewhere_q = elsewhere_q.saturating_add(e.queries);
                nodes.push(label.clone());
                match first_drop {
                    Some(fd) if e.first_ms >= fd && e.first_ms <= cutoff => {
                        first_after = Some(first_after.map_or(e.first_ms, |f| f.min(e.first_ms)));
                    }
                    Some(fd) if e.first_ms < fd && e.last_ms >= fd => already_there = true,
                    _ => {}
                }
            }
        }
        let target = i.targets.contains(k) || dropped > 0;
        let verdict = if !target {
            "elsewhere"
        } else if first_after.is_some() || already_there {
            "followed"
        } else if dropped >= STUCK_MIN {
            "stuck"
        } else {
            "quiet"
        };
        let ttf = (verdict == "followed")
            .then(|| first_drop.zip(first_after).map(|(d, a)| a - d))
            .flatten();
        match verdict {
            "followed" => out.followed += 1,
            "stuck" => out.stuck += 1,
            "quiet" => out.quiet += 1,
            _ => out.elsewhere += 1,
        }
        if let Some(t) = ttf {
            times.push(t);
        }
        let (name, group) = i.names.get(k).cloned().unwrap_or_default();
        out.devices.push(DrillDevice {
            client: key_text(k),
            name,
            group,
            verdict: verdict.into(),
            dropped,
            queries_elsewhere: elsewhere_q,
            time_to_failover_ms: ttf,
            returned: None,
            nodes,
        });
    }
    let _ = i.since_ms;
    if out.followed + out.stuck > 0 {
        let pct = f64::from(out.followed) * 100.0 / f64::from(out.followed + out.stuck);
        out.coverage_percent = Some((pct * 10.0).round() / 10.0);
    }
    times.sort_unstable();
    let q = |p: usize| (!times.is_empty()).then(|| times[(times.len() - 1) * p / 100]);
    out.median_ms = q(50);
    out.p90_ms = q(90);
    // Stuck first, then followed by time, then the rest.
    let rank = |v: &str| match v {
        "stuck" => 0,
        "followed" => 1,
        "quiet" => 2,
        _ => 3,
    };
    out.devices.sort_by(|a, b| {
        rank(&a.verdict)
            .cmp(&rank(&b.verdict))
            .then(b.dropped.cmp(&a.dropped))
            .then(a.client.cmp(&b.client))
    });
    out
}

#[cfg(test)]
mod tests;
