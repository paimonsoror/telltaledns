//! Change simulation (REQ: OBS-024; ADR-115, `docs/design/change-simulation.md`): what a
//! configuration change would have done to the queries already in the query log.
//!
//! Each logged query (over a window, newest first, bounded in rows and time) is decided twice,
//! off the query path: under the configuration in effect and under the candidate, with the
//! pipeline's own decision steps (access, special names, local data, quick rules, schedules,
//! list rewrites, the filter, AAAA filtering, group rewrites and safe search, the route). Only
//! the differences count: newly blocked, newly allowed, a changed route, a changed answer.
//! Deciding the current configuration again, rather than comparing with what was recorded,
//! keeps out everything the change doesn't cause (pauses, CNAME-target blocks, lists updated
//! since), so a change that affects nothing reports zeros (ADR-115, amended).
//!
//! The filter isn't recompiled for a preview: the serving snapshot is reused with masks built
//! for the candidate's groups, and only lists the change adds or edits are compiled, into a
//! side snapshot. The two snapshots' matches merge by the filter's own precedence
//! ([`telltale_filter::matcher::Ranked`]), so the result equals a compile of everything.
//!
//! Nothing here touches the pipeline: the candidate state is built beside it, and the work
//! runs on a blocking thread at background priority, one simulation per node at a time.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use telltale_api::model::{
    SimulatedClass, SimulatedDevice, SimulatedGroup, SimulatedName, Simulation,
};
use telltale_api::problem::{Code, Problem};
use telltale_config::{Config, FilterList};
use telltale_filter::matcher::{ClientCtx, Decision, ListMask, Lookup, Matcher, Ranked, Scratch};
use telltale_policy::{ClientTable, IdSource, Identity, Neighbors, Pause, RewriteTarget, Special};
use telltale_proto::{NameBuf, build_query, class, parse_query, rtype};
use telltale_store::qlog;
use telltale_telemetry::Status;
use telltale_upstream::{Question, Router};

use crate::pipeline::{FilterState, Pipeline, Policy, ScheduleNow};

/// Names reported per kind of difference, and devices.
const TOP_NAMES: usize = 20;
const TOP_DEVICES: usize = 50;
/// Bounds on what one node keeps while counting (beyond them, counts go on, names don't).
const MAX_NAMES: usize = 50_000;
const MAX_DEVICES: usize = 4096;
const MAX_DEVICES_PER_NAME: usize = 64;
/// Decisions remembered (the same device asks the same names over and over).
const MEMO: usize = 200_000;
/// Logged queries read per page, and how often the clock is looked at.
const PAGE: usize = 2048;
/// The longest window.
pub(crate) const MAX_WINDOW_SECS: u64 = 7 * 86_400;

/// Simulations run since start, by outcome, and their time and rows (`/metrics`).
#[derive(Debug, Default)]
pub(crate) struct Stats {
    pub(crate) ok: AtomicU64,
    pub(crate) partial: AtomicU64,
    pub(crate) busy: AtomicU64,
    pub(crate) unavailable: AtomicU64,
    pub(crate) error: AtomicU64,
    pub(crate) rows: AtomicU64,
    pub(crate) micros: AtomicU64,
    /// Durations in the histogram's buckets (`BUCKETS`), cumulative at render time.
    pub(crate) buckets: [AtomicU64; BUCKETS.len()],
}

/// `telltale_simulation_duration_seconds` bucket bounds.
pub(crate) const BUCKETS: [f64; 8] = [0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 60.0];

pub(crate) fn stats() -> &'static Stats {
    static S: std::sync::OnceLock<Stats> = std::sync::OnceLock::new();
    S.get_or_init(Stats::default)
}

/// REQ: OBS-024 — `telltale_simulations_total{outcome}`, the duration histogram, and the rows
/// read, since start.
pub(crate) fn render(w: &mut telltale_telemetry::prom::PromWriter) {
    let s = stats();
    let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
    w.family(
        "telltale_simulations_total",
        "counter",
        "Change simulations this node ran or refused, by outcome (ok, partial: bounds reached, busy: one was running, unavailable: off or not allowed, error).",
    );
    for (outcome, v) in [
        ("ok", &s.ok),
        ("partial", &s.partial),
        ("busy", &s.busy),
        ("unavailable", &s.unavailable),
        ("error", &s.error),
    ] {
        w.sample("telltale_simulations_total", &[("outcome", outcome)], n(v));
    }
    w.family(
        "telltale_simulation_duration_seconds",
        "histogram",
        "How long this node's part of a simulation took (replaying its logs at background priority).",
    );
    let mut cumulative = 0;
    for (b, c) in BUCKETS.iter().zip(&s.buckets) {
        cumulative += n(c);
        w.sample(
            "telltale_simulation_duration_seconds_bucket",
            &[("le", &b.to_string())],
            cumulative,
        );
    }
    let count = n(&s.ok) + n(&s.partial) + n(&s.error);
    w.sample(
        "telltale_simulation_duration_seconds_bucket",
        &[("le", "+Inf")],
        count,
    );
    #[allow(clippy::cast_precision_loss)] // seconds for a dashboard
    let sum = n(&s.micros) as f64 / 1e6;
    w.sample("telltale_simulation_duration_seconds_sum", &[], sum);
    w.sample("telltale_simulation_duration_seconds_count", &[], count);
    w.family(
        "telltale_simulation_rows_total",
        "counter",
        "Logged queries this node read for simulations.",
    )
    .sample("telltale_simulation_rows_total", &[], n(&s.rows));
}

/// One simulation per node at a time.
static BUSY: AtomicBool = AtomicBool::new(false);

struct BusyGuard;

impl BusyGuard {
    fn take() -> Option<Self> {
        BUSY.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then_some(Self)
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::Release);
    }
}

/// The 409 for a node already simulating.
pub(crate) fn busy() -> Problem {
    Problem::new(
        Code::SimulationBusy,
        "this node is already running a simulation",
    )
    .hint("Retry in a few seconds: simulations run one at a time per node.")
    .retry_after(5)
}

/// What to replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Window {
    /// `[from_us, to_us)`.
    pub(crate) from_us: u64,
    pub(crate) to_us: u64,
    pub(crate) max_rows: u64,
    pub(crate) max_secs: u32,
}

/// A window from `[simulate]` and a request: `window` (`24h`), ending at `until` (Unix
/// seconds, default now). 422 past 7 days.
pub(crate) fn window(
    cfg: &telltale_config::SimulateConfig,
    window: Option<&str>,
    until_s: Option<u64>,
    now_s: u64,
) -> Result<Window, Problem> {
    let text = window.unwrap_or(&cfg.default_window);
    let secs = telltale_config::window_secs(text).ok_or_else(|| {
        Problem::new(
            Code::SimulationWindow,
            format!("`simulate`: `{text}` isn't a window"),
        )
        .hint("A number and m, h, or d: 30m, 24h, 7d.")
    })?;
    if secs > MAX_WINDOW_SECS {
        return Err(Problem::new(
            Code::SimulationWindow,
            format!("`simulate`: `{text}` is longer than 7 days"),
        )
        .hint("Simulations replay at most the last 7 days."));
    }
    let to_s = until_s.unwrap_or(now_s);
    Ok(Window {
        from_us: to_s.saturating_sub(secs).saturating_mul(1_000_000),
        to_us: to_s.saturating_mul(1_000_000),
        max_rows: cfg.max_rows,
        max_secs: cfg.max_secs,
    })
}

/// What one node found, mergeable across nodes (the `sim.run` RPC's answer).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Tally {
    pub(crate) rows: u64,
    pub(crate) partial: bool,
    pub(crate) unchanged: u64,
    pub(crate) undetermined: u64,
    /// Newly blocked, newly allowed, changed route, changed answer.
    pub(crate) classes: [ClassTally; 4],
    /// Per device: the four counts and its name.
    pub(crate) devices: BTreeMap<String, DeviceTally>,
    pub(crate) groups: BTreeMap<String, [u64; 4]>,
    pub(crate) notes: BTreeSet<String>,
    /// This node holds no query log of its own to read (ship mode, or the log is off).
    pub(crate) no_log: bool,
    /// Lists compiled into the side snapshot (for tests and the report).
    pub(crate) side_lists: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ClassTally {
    pub(crate) queries: u64,
    pub(crate) devices: BTreeSet<String>,
    pub(crate) names: BTreeMap<String, NameTally>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NameTally {
    pub(crate) queries: u64,
    pub(crate) list: Option<String>,
    pub(crate) devices: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DeviceTally {
    pub(crate) name: Option<String>,
    pub(crate) counts: [u64; 4],
}

impl Tally {
    /// Adds another node's counts.
    pub(crate) fn merge(&mut self, o: Self) {
        self.rows += o.rows;
        self.partial |= o.partial;
        self.unchanged += o.unchanged;
        self.undetermined += o.undetermined;
        for (mine, theirs) in self.classes.iter_mut().zip(o.classes) {
            mine.queries += theirs.queries;
            for d in theirs.devices {
                if mine.devices.len() < MAX_DEVICES {
                    mine.devices.insert(d);
                }
            }
            for (name, n) in theirs.names {
                if !mine.names.contains_key(&name) && mine.names.len() >= MAX_NAMES {
                    continue;
                }
                let e = mine.names.entry(name).or_default();
                e.queries += n.queries;
                if e.list.is_none() {
                    e.list = n.list;
                }
                for d in n.devices {
                    if e.devices.len() < MAX_DEVICES_PER_NAME {
                        e.devices.insert(d);
                    }
                }
            }
        }
        for (k, d) in o.devices {
            let e = self.devices.entry(k).or_default();
            if e.name.is_none() {
                e.name = d.name;
            }
            for (a, b) in e.counts.iter_mut().zip(d.counts) {
                *a += b;
            }
        }
        for (k, g) in o.groups {
            let e = self.groups.entry(k).or_default();
            for (a, b) in e.iter_mut().zip(g) {
                *a += b;
            }
        }
        self.notes.extend(o.notes);
        for l in o.side_lists {
            if !self.side_lists.contains(&l) {
                self.side_lists.push(l);
            }
        }
    }

    fn count(
        &mut self,
        class: usize,
        name: &str,
        list: Option<&str>,
        device: &str,
        label: Option<&str>,
        group: &str,
    ) {
        let c = &mut self.classes[class];
        c.queries += 1;
        if c.devices.len() < MAX_DEVICES {
            c.devices.insert(device.to_owned());
        }
        if c.names.contains_key(name) || c.names.len() < MAX_NAMES {
            let n = c.names.entry(name.to_owned()).or_default();
            n.queries += 1;
            if n.list.is_none() {
                n.list = list.map(str::to_owned);
            }
            if n.devices.len() < MAX_DEVICES_PER_NAME {
                n.devices.insert(device.to_owned());
            }
        } else {
            self.notes.insert("names_capped".to_owned());
        }
        let key = if self.devices.contains_key(device) || self.devices.len() < MAX_DEVICES {
            device.to_owned()
        } else {
            "other".to_owned()
        };
        let d = self.devices.entry(key).or_default();
        if d.name.is_none() {
            d.name = label.map(str::to_owned);
        }
        d.counts[class] += 1;
        self.groups.entry(group.to_owned()).or_default()[class] += 1;
    }

    /// The API's answer: the top names and devices, in a fixed order (count, then name), so
    /// the same log gives the same bytes.
    pub(crate) fn finish(self, w: Option<&Window>) -> Simulation {
        let class = |c: &ClassTally| SimulatedClass {
            queries: c.queries,
            devices: c.devices.len() as u64,
            top_names: {
                let mut v: Vec<(&String, &NameTally)> = c.names.iter().collect();
                v.sort_by(|a, b| b.1.queries.cmp(&a.1.queries).then_with(|| a.0.cmp(b.0)));
                v.into_iter()
                    .take(TOP_NAMES)
                    .map(|(name, n)| SimulatedName {
                        name: name.clone(),
                        queries: n.queries,
                        devices: n.devices.len() as u64,
                        list: n.list.clone(),
                    })
                    .collect()
            },
        };
        let mut devices: Vec<(&String, &DeviceTally)> = self
            .devices
            .iter()
            .filter(|(_, d)| d.counts.iter().any(|c| *c > 0))
            .collect();
        devices.sort_by(|a, b| {
            let sa: u64 = a.1.counts.iter().sum();
            let sb: u64 = b.1.counts.iter().sum();
            sb.cmp(&sa).then_with(|| a.0.cmp(b.0))
        });
        let mut groups: Vec<(&String, &[u64; 4])> = self.groups.iter().collect();
        groups.sort_by(|a, b| {
            let sa: u64 = a.1.iter().sum();
            let sb: u64 = b.1.iter().sum();
            sb.cmp(&sa).then_with(|| a.0.cmp(b.0))
        });
        Simulation {
            available: true,
            applicable: true,
            reason: None,
            from: w.map(|w| telltale_api::time::format_us(w.from_us)),
            to: w.map(|w| telltale_api::time::format_us(w.to_us)),
            rows: self.rows,
            partial: self.partial,
            newly_blocked: class(&self.classes[0]),
            newly_allowed: class(&self.classes[1]),
            changed_route: class(&self.classes[2]),
            changed_answer: class(&self.classes[3]),
            unchanged: self.unchanged,
            undetermined: self.undetermined,
            by_device: devices
                .into_iter()
                .take(TOP_DEVICES)
                .map(|(client, d)| SimulatedDevice {
                    client: client.clone(),
                    name: d.name.clone(),
                    newly_blocked: d.counts[0],
                    newly_allowed: d.counts[1],
                    changed_route: d.counts[2],
                    changed_answer: d.counts[3],
                })
                .collect(),
            by_group: groups
                .into_iter()
                .map(|(group, c)| SimulatedGroup {
                    group: group.clone(),
                    newly_blocked: c[0],
                    newly_allowed: c[1],
                    changed_route: c[2],
                    changed_answer: c[3],
                })
                .collect(),
            notes: self.notes.into_iter().collect(),
            missing_nodes: Vec::new(),
        }
    }
}

/// An answer that says why nothing could be simulated.
pub(crate) fn unavailable(reason: &str) -> Simulation {
    Simulation {
        available: false,
        applicable: true,
        reason: Some(reason.to_owned()),
        ..Simulation::default()
    }
}

/// An answer for a change that can't affect a decision.
pub(crate) fn not_applicable() -> Simulation {
    Simulation {
        available: true,
        applicable: false,
        ..Simulation::default()
    }
}

/// How a query would be decided: the part a change can move.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Verdict {
    /// Blocked; by what (a list, a quick rule, a schedule).
    Blocked(Arc<str>),
    /// Resolved normally (an allow rule may have decided), sent to this upstream group (none:
    /// refused for lack of one).
    Resolved {
        allowed_by: Option<Arc<str>>,
        route: Option<Arc<str>>,
    },
    /// Answered without forwarding and without a block: what.
    Answered(Arc<str>),
}

impl Verdict {
    fn blocked(&self) -> Option<&str> {
        match self {
            Self::Blocked(by) => Some(by),
            _ => None,
        }
    }
}

/// One snapshot the decision reads: its matcher, its list IDs in the combined order, and the
/// lists of it that must not take part (changed or removed by the candidate).
struct Side {
    matcher: Arc<Matcher>,
    to_combined: Vec<Option<u16>>,
    excluded: ListMask,
    lists: usize,
}

/// One configuration's decisions (the current one, or the candidate).
struct Decider {
    cfg: Arc<Config>,
    policy: Policy,
    router: Arc<Router>,
    schedules: Vec<telltale_config::schedule::Compiled>,
    sides: Vec<Side>,
    shadow: Vec<Box<str>>,
    /// List names in the combined ID space.
    names: Vec<Arc<str>>,
    /// Per schedule state, one filter state per side.
    states: Vec<(ScheduleNow, Vec<FilterState>)>,
    /// Minute → index into `states`.
    minutes: HashMap<i64, usize>,
}

/// The configuration's enabled lists (blocked services included), in ID order.
fn enabled_lists(cfg: &Config) -> Vec<FilterList> {
    telltale_config::services::expand(cfg)
        .list
        .into_iter()
        .filter(|l| l.enabled)
        .collect()
}

/// Whether a list compiles to something else than `old` did (source or options).
fn compiles_differently(new: &FilterList, old: &FilterList) -> bool {
    new.url != old.url
        || new.path != old.path
        || new.rules != old.rules
        || new.kind != old.kind
        || new.match_mode != old.match_mode
}

/// The candidate's lists that the serving snapshot can't stand for: new, or compiled
/// differently than the current configuration's list of the same name.
pub(crate) fn changed_lists(current: &Config, candidate: &Config) -> Vec<FilterList> {
    let now = enabled_lists(current);
    enabled_lists(candidate)
        .into_iter()
        .filter(|l| {
            now.iter()
                .find(|o| o.name == l.name)
                .is_none_or(|o| compiles_differently(l, o))
        })
        .collect()
}

impl Decider {
    /// `snapshots`: the serving matcher (if any), then a side matcher (if any). `changed`:
    /// list names whose serving version must not take part.
    fn new(
        cfg: Arc<Config>,
        snapshots: &[Arc<Matcher>],
        changed: &BTreeSet<String>,
    ) -> Result<Self, String> {
        let (router, policy) = crate::server::build_candidate(&cfg).map_err(|e| e.join("; "))?;
        let names: Vec<Arc<str>> = enabled_lists(&cfg)
            .iter()
            .map(|l| Arc::from(l.name.as_str()))
            .collect();
        let index: HashMap<&str, u16> = names
            .iter()
            .enumerate()
            .filter_map(|(i, n)| Some((&**n, u16::try_from(i).ok()?)))
            .collect();
        let mut sides = Vec::new();
        for (si, m) in snapshots.iter().enumerate() {
            let list_names: Vec<String> = m
                .snapshot()
                .map(|s| s.manifest.lists.iter().map(|l| l.name.clone()).collect())
                .unwrap_or_default();
            let mut excluded = ListMask::default();
            let to_combined = list_names
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    let id = index.get(n.as_str()).copied();
                    // The serving snapshot's version of a changed list gives way to the side
                    // snapshot's; a list the configuration doesn't enable doesn't take part.
                    let stale = si == 0 && snapshots.len() > 1 && changed.contains(n);
                    if (id.is_none() || stale)
                        && let Ok(local) = u16::try_from(i)
                    {
                        excluded.set(local);
                    }
                    id
                })
                .collect();
            sides.push(Side {
                matcher: Arc::clone(m),
                to_combined,
                excluded,
                lists: list_names.len(),
            });
        }
        let shadow = policy.shadow_lists.clone();
        Ok(Self {
            schedules: telltale_config::schedule::compile(&cfg),
            cfg,
            policy,
            router,
            sides,
            shadow,
            names,
            states: Vec::new(),
            minutes: HashMap::new(),
        })
    }

    /// The schedule state at `ts` (whole minutes) and its filter states.
    fn state(&mut self, ts: i64) -> usize {
        let minute = ts.div_euclid(60);
        if let Some(&i) = self.minutes.get(&minute) {
            return i;
        }
        let now = ScheduleNow::compute(
            &self.cfg,
            &self.schedules,
            self.policy.clients.groups(),
            minute * 60,
        );
        let i = if let Some(i) = self.states.iter().position(|(s, _)| *s == now) {
            i
        } else {
            let filters = self
                .sides
                .iter()
                .map(|side| {
                    let mut f = FilterState::new(
                        Arc::clone(&side.matcher),
                        Arc::clone(&self.policy.clients),
                        &now,
                        &self.shadow,
                    );
                    strip(&mut f, &side.excluded, side.lists);
                    f
                })
                .collect();
            self.states.push((now, filters));
            self.states.len() - 1
        };
        self.minutes.insert(minute, i);
        i
    }

    /// How `row` would be decided.
    #[allow(clippy::too_many_lines)] // the pipeline's steps, in order
    fn decide(
        &mut self,
        row: &RowIn<'_>,
        scratch: &mut Scratch,
        notes: &mut BTreeSet<String>,
    ) -> Verdict {
        let answered = |s: &str| Verdict::Answered(Arc::from(s));
        let Ok(name) = NameBuf::from_presentation(row.name) else {
            return answered("unparseable name");
        };
        let mut buf = [0u8; 512];
        let Ok(len) = build_query(&mut buf, 0, &name, row.qtype, class::IN, true, None) else {
            return answered("unparseable name");
        };
        let Ok(q) = parse_query(&buf[..len]) else {
            return answered("unparseable name");
        };
        let state = self.state(row.ts_s);
        let clients: &ClientTable = &self.policy.clients;
        let mut ident = clients.identify(row.ip, None, None, empty_neighbors());
        // A device identified by MAC or client ID when it asked can't be identified again by
        // its address alone: it keeps the group the query was logged with.
        if ident.source == IdSource::Default
            && ident.net.is_none()
            && let Some(g) = row.group.filter(|g| *g != "default")
            && let Some(i) = clients.groups().iter().position(|x| &*x.name == g)
        {
            ident = Identity {
                net: u16::try_from(i).ok(),
                ..ident
            };
            notes.insert("identity_from_event".to_owned());
        }
        let special = match crate::explain::answered_early(
            &self.policy,
            &q,
            row.ip,
            clients.group_names(ident),
        ) {
            Ok(s) => s,
            Err((outcome, _)) => {
                return answered(match outcome {
                    crate::explain::Outcome::Refused => "refused",
                    crate::explain::Outcome::Local => "local data",
                    _ => "special answer",
                });
            }
        };
        let group = clients.primary_group(ident);
        let device = clients.client(ident).map(|c| &*c.name);
        let wire = q.qname.as_wire();
        // Quick rules, at the query's time.
        if let Some(m) =
            self.policy
                .quick
                .decide(wire, ident, row.ip, clients.group_ids(ident), row.ts_s)
        {
            let r = self.policy.quick.rules().get(m.rule as usize);
            let desc = r.map_or("?", |r| r.note.as_deref().unwrap_or(&r.domain));
            if !m.allow {
                return Verdict::Blocked(Arc::from(format!("quick rule: {desc}")));
            }
            return self.after_filter(
                &q,
                ident,
                group,
                Some(Arc::from(format!("quick rule: {desc}"))),
                special,
            );
        }
        let (sched, filters) = &self.states[state];
        if let Some(&g) = clients.group_ids(ident).first()
            && let Some(Some((reason, _))) = sched.block_all.get(usize::from(g))
        {
            return Verdict::Blocked(Arc::from(reason.as_str()));
        }
        let ctx = ClientCtx {
            ip: row.ip,
            name: device,
            client_id: None,
        };
        // A list's `$dnsrewrite` decides before blocking (the pipeline's own function; a
        // replay never sees a pause).
        for f in filters {
            if let Some((_, list)) = f.list_rewrite(&q, |_| ident, row.ip, None, never_paused()) {
                let n = f
                    .list_names
                    .get(usize::from(list))
                    .map_or("?", String::as_str);
                return answered(&format!("rewritten by list {n}"));
            }
        }
        // The filter: every snapshot's matches in the combined ID space, merged.
        let mut merged = Ranked::default();
        for (f, side) in filters.iter().zip(&self.sides) {
            let mut r = f
                .matcher
                .decide_ranked(wire, q.qtype, &ctx, f.mask(ident), scratch);
            r.remap(|id| side.to_combined.get(usize::from(id)).copied().flatten());
            merged.merge(&r);
        }
        let list_name = |id: u16| {
            self.names
                .get(usize::from(id))
                .cloned()
                .unwrap_or_else(|| Arc::from("?"))
        };
        let allowed_by = match merged.decision() {
            Decision::Block(a) => return Verdict::Blocked(list_name(a.list)),
            Decision::Allow(a) => Some(list_name(a.list)),
            Decision::None => None,
        };
        self.after_filter(&q, ident, group, allowed_by, special)
    }

    /// After the filter let it through: AAAA filtering, the group's rewrites and safe search,
    /// then where it's forwarded.
    fn after_filter(
        &self,
        q: &telltale_proto::Query<'_>,
        ident: Identity,
        group: &telltale_policy::Group,
        allowed_by: Option<Arc<str>>,
        special: Option<Special>,
    ) -> Verdict {
        if q.qtype == rtype::AAAA && group.filter_aaaa {
            return Verdict::Answered(Arc::from("no IPv6 addresses (filter_aaaa)"));
        }
        match group.rewrite_for(&q.qname) {
            Some(RewriteTarget::Addr(ip)) => {
                return Verdict::Answered(Arc::from(format!("rewritten to {ip}")));
            }
            Some(RewriteTarget::Name(t)) => {
                return Verdict::Answered(Arc::from(format!("rewritten to {}", t.display())));
            }
            None => {}
        }
        if let Some(t) = Pipeline::safe_search_target(q, group) {
            return Verdict::Answered(Arc::from(format!("safe search: {}", t.display())));
        }
        let names = self.policy.clients.group_names(ident);
        let selection = self.router.select(&Question::from_query(q), names);
        if special == Some(Special::PrivatePtr) && !selection.as_ref().is_some_and(|s| s.routed) {
            return Verdict::Answered(Arc::from("private reverse lookup: NXDOMAIN"));
        }
        Verdict::Resolved {
            allowed_by,
            route: selection.map(|s| Arc::from(s.group.name.as_str())),
        }
    }
}

/// Takes `excluded` lists out of every mask of `f`.
fn strip(f: &mut FilterState, excluded: &ListMask, lists: usize) {
    fn keep(m: &ListMask, ids: &[u16], excluded: &ListMask) -> ListMask {
        let mut out = ListMask::default();
        for &id in ids {
            if m.contains(id) && !excluded.contains(id) {
                out.set(id);
            }
        }
        out
    }
    let ids: Vec<u16> = (0..lists).filter_map(|i| u16::try_from(i).ok()).collect();
    if !ids.iter().any(|id| excluded.contains(*id)) {
        return;
    }
    f.default_mask = keep(&f.default_mask, &ids, excluded);
    for m in f.client_masks.iter_mut().chain(f.group_masks.iter_mut()) {
        *m = keep(m, &ids, excluded);
    }
}

fn empty_neighbors() -> &'static Neighbors {
    static N: std::sync::OnceLock<Neighbors> = std::sync::OnceLock::new();
    N.get_or_init(Neighbors::default)
}

fn never_paused() -> &'static Pause {
    static P: std::sync::OnceLock<Pause> = std::sync::OnceLock::new();
    P.get_or_init(Pause::default)
}

/// One logged query, as the decision needs it.
struct RowIn<'a> {
    ts_s: i64,
    ip: IpAddr,
    name: &'a str,
    qtype: u16,
    /// The group it was logged with.
    group: Option<&'a str>,
}

/// Logged outcomes that went through the decision: rate-limited, malformed, and dropped
/// queries never reached it. Refused ones are replayed: a query refused for want of an
/// upstream went through the filter first, and one refused by `allowed_networks` is decided
/// again by the same step.
fn replayed(s: Status) -> bool {
    !matches!(s, Status::RateLimited | Status::Malformed | Status::Dropped)
}

/// A list's text for the side snapshot: inline rules, a local file, the stored download (when
/// only its options changed), or a fresh download.
pub(crate) struct SideSource {
    pub(crate) list: FilterList,
    pub(crate) data: Vec<u8>,
}

/// Fetches the texts of the lists the side snapshot needs (async: downloads).
pub(crate) async fn side_sources(
    current: &Config,
    candidate: &Config,
    store: Option<&telltale_filter::fetch::Store>,
) -> Result<Vec<SideSource>, Problem> {
    let mut out = Vec::new();
    let now = enabled_lists(current);
    for l in changed_lists(current, candidate) {
        let data = if !l.rules.is_empty() {
            l.rules
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
                .into_bytes()
        } else if let Some(p) = &l.path {
            tokio::fs::read(p.as_str()).await.map_err(|e| {
                Problem::new(
                    Code::InvalidConfig,
                    format!("list {}: {}: {e}", l.name.as_str(), p.as_str()),
                )
            })?
        } else if let Some(url) = &l.url {
            // Only the options changed: the stored download is the same text.
            let same_source = now.iter().any(|o| o.name == l.name && o.url == l.url);
            let stored = store
                .filter(|_| same_source)
                .and_then(|s| s.read_source(l.name.as_str()).ok());
            match stored {
                Some(d) => d,
                None => download(candidate, &l, url.as_str()).await?,
            }
        } else {
            continue;
        };
        out.push(SideSource { list: l, data });
    }
    Ok(out)
}

async fn download(cfg: &Config, l: &FilterList, url: &str) -> Result<Vec<u8>, Problem> {
    let client =
        telltale_filter::fetch::Client::new(Arc::new(telltale_filter::fetch::SystemResolver), &[])
            .map_err(|e| Problem::internal(format!("the download client: {e}")))?
            .allow_link_local(cfg.filter.allow_link_local_urls);
    let max = l.max_bytes.unwrap_or(cfg.filter.max_list_bytes).bytes();
    let timeout = Duration::from_secs(u64::from(cfg.filter.fetch_timeout_secs.max(1)));
    match tokio::time::timeout(
        timeout,
        client.get(url, &telltale_filter::fetch::Conditional::default(), max),
    )
    .await
    {
        Ok(Ok(telltale_filter::fetch::Response::Body { data, .. })) => Ok(data),
        Ok(Ok(telltale_filter::fetch::Response::NotModified)) => Ok(Vec::new()),
        Ok(Err(e)) => Err(Problem::new(
            Code::Unavailable,
            format!(
                "list {} couldn't be downloaded to simulate it: {}",
                l.name.as_str(),
                e.message
            ),
        )),
        Err(_) => Err(Problem::new(
            Code::Unavailable,
            format!(
                "list {} didn't download within {} s",
                l.name.as_str(),
                timeout.as_secs()
            ),
        )),
    }
}

/// Compiles the side snapshot (only the changed lists) into a temporary directory under
/// `<data_dir>/snapshots/`, removed when the returned guard drops.
fn compile_side(
    cfg: &Config,
    sources: Vec<SideSource>,
) -> Result<Option<(Arc<Matcher>, SideDir)>, String> {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    if sources.is_empty() {
        return Ok(None);
    }
    let dir = Path::new(cfg.node.data_dir.as_str())
        .join("snapshots")
        .join(format!(
            "sim-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    let guard = SideDir(dir.clone());
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    let inputs: Vec<telltale_filter::compile::ListInput> = sources
        .into_iter()
        .map(|s| telltale_filter::compile::ListInput {
            name: s.list.name.to_string(),
            options: telltale_filter::parse::ListOptions {
                kind: s.list.kind,
                match_mode: s.list.match_mode,
            },
            source_hash: telltale_filter::fetch::content_hash(&s.data),
            size: s.data.len() as u64,
            data: telltale_filter::compile::ListData::Bytes(s.data),
        })
        .collect();
    telltale_filter::compile::compile(
        inputs,
        &dir,
        &telltale_filter::compile::CompileOptions {
            threads: 1,
            memory_budget: usize::try_from(cfg.filter.compile_memory.bytes()).unwrap_or(usize::MAX),
            version: 0,
            sync: false,
            max_regexes: usize::try_from(cfg.filter.max_regexes).unwrap_or(usize::MAX),
        },
    )
    .map_err(|e| format!("compiling the changed lists: {e}"))?;
    let snap = telltale_filter::snapshot::Snapshot::open(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let m = Matcher::with_lookup(Some(Arc::new(snap)), Lookup::Walk)?;
    Ok(Some((Arc::new(m), guard)))
}

/// A side snapshot's directory, removed on drop.
pub(crate) struct SideDir(PathBuf);

impl Drop for SideDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Where this node's rows are: its own query log (unless it ships it) and the logs shipped to
/// it (CLU-007).
pub(crate) fn log_dirs(cfg: &Config) -> Vec<PathBuf> {
    let data = cfg.node.data_dir.as_str();
    let mut dirs = Vec::new();
    // A shipping node's own log is a buffer of rows its receiver also holds: counting both
    // would count them twice.
    if cfg.telemetry.qlog.enabled && cfg.telemetry.mode != telltale_config::TelemetryMode::Ship {
        dirs.push(Path::new(data).join("qlog"));
    }
    dirs.extend(crate::ship::shipped_dirs(data).into_iter().map(|(_, d)| d));
    dirs
}

/// Everything one node needs to run a simulation.
pub(crate) struct Inputs {
    pub(crate) current: Arc<Config>,
    pub(crate) candidate: Arc<Config>,
    /// The serving filter (none before the first snapshot).
    pub(crate) serving: Option<Arc<Matcher>>,
    pub(crate) sources: Vec<SideSource>,
    pub(crate) dirs: Vec<PathBuf>,
    pub(crate) window: Window,
    /// The device names to show, by address (the API's labels).
    pub(crate) label: Box<dyn Fn(IpAddr) -> Option<String> + Send>,
}

/// Runs a simulation on this node (blocking: call from a background thread). Takes the
/// node's one-at-a-time slot; `Err(busy)` when it's taken.
pub(crate) fn run(inputs: Inputs) -> Result<Tally, Problem> {
    metered(|started| run_inner(inputs, started))
}

/// REQ: OBS-024 — privacy level 1 and a change to devices only: each logged query of a device
/// whose groups change is unchanged when the new groups decide alike (same settings apart
/// from their names and networks), else undetermined (the names, hashed, can't be decided
/// again).
pub(crate) fn run_devices_only(inputs: &Inputs) -> Result<Tally, Problem> {
    metered(|started| devices_only_inner(inputs, started))
}

/// Takes the slot, runs `f`, and counts the outcome for `/metrics`.
fn metered(f: impl FnOnce(Instant) -> Result<Tally, Problem>) -> Result<Tally, Problem> {
    let Some(_slot) = BusyGuard::take() else {
        stats().busy.fetch_add(1, Ordering::Relaxed);
        return Err(busy());
    };
    let started = Instant::now();
    let r = f(started);
    let s = stats();
    match &r {
        Ok(t) => {
            if t.partial {
                s.partial.fetch_add(1, Ordering::Relaxed);
            } else {
                s.ok.fetch_add(1, Ordering::Relaxed);
            }
            s.rows.fetch_add(t.rows, Ordering::Relaxed);
        }
        Err(_) => {
            s.error.fetch_add(1, Ordering::Relaxed);
        }
    }
    let secs = started.elapsed().as_secs_f64();
    s.micros.fetch_add(
        u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    if let Some(i) = BUCKETS.iter().position(|b| secs <= *b) {
        s.buckets[i].fetch_add(1, Ordering::Relaxed);
    }
    r
}

fn run_inner(inputs: Inputs, started: Instant) -> Result<Tally, Problem> {
    let mut tally = Tally::default();
    if inputs.dirs.is_empty() {
        tally.no_log = true;
        return Ok(tally);
    }
    let changed: BTreeSet<String> = inputs
        .sources
        .iter()
        .map(|s| s.list.name.to_string())
        .collect();
    tally.side_lists = changed.iter().cloned().collect();
    if inputs
        .sources
        .iter()
        .any(|s| String::from_utf8_lossy(&s.data).contains("$badfilter"))
    {
        tally.notes.insert("badfilter_cross_snapshot".to_owned());
    }
    let side = compile_side(&inputs.candidate, inputs.sources).map_err(Problem::internal)?;
    let mut serving: Vec<Arc<Matcher>> = inputs.serving.iter().cloned().collect();
    let base = Decider::new(Arc::clone(&inputs.current), &serving, &BTreeSet::new())
        .map_err(Problem::internal)?;
    if let Some((m, _)) = &side {
        serving.push(Arc::clone(m));
    }
    let cand = Decider::new(Arc::clone(&inputs.candidate), &serving, &changed).map_err(|e| {
        Problem::new(
            Code::InvalidConfig,
            format!("the candidate configuration: {e}"),
        )
    })?;
    // The groups the log names, by index (as the configuration in effect orders them).
    let groups: Vec<String> = base
        .policy
        .clients
        .groups()
        .iter()
        .map(|g| g.name.to_string())
        .collect();
    let mut replay = Replay {
        base,
        cand,
        groups,
        memo: HashMap::new(),
        scratch: Scratch::default(),
        labels: HashMap::new(),
        label: &*inputs.label,
    };
    scan(&inputs.dirs, &inputs.window, started, &mut tally, |r, t| {
        replay.row(r, t);
    })?;
    drop(side);
    Ok(tally)
}

/// Reads the logs in `dirs` over the window, newest first, handing each row to `each` (which
/// counts it), until the rows or the time run out (`partial`).
fn scan(
    dirs: &[PathBuf],
    w: &Window,
    started: Instant,
    tally: &mut Tally,
    mut each: impl FnMut(&qlog::Row, &mut Tally),
) -> Result<(), Problem> {
    let filter = qlog::Filter {
        from_us: w.from_us,
        to_us: w.to_us,
        ..qlog::Filter::default()
    };
    let opts = qlog::Options {
        threads: 1,
        on_thread_start: Some(telltale_net::background_thread),
    };
    let deadline = Duration::from_secs(u64::from(w.max_secs.max(1)));
    for dir in dirs {
        let mut cursor = None;
        loop {
            let page = qlog::search_with(dir, &filter, PAGE, cursor, &opts)
                .map_err(|e| Problem::internal(format!("query log: {e}")))?;
            for r in &page.rows {
                if tally.rows >= w.max_rows
                    || (tally.rows.is_multiple_of(64) && started.elapsed() >= deadline)
                {
                    tally.partial = true;
                    return Ok(());
                }
                tally.rows += 1;
                each(r, tally);
            }
            match page.next {
                Some(c) if started.elapsed() < deadline => cursor = Some(c),
                Some(_) => {
                    tally.partial = true;
                    return Ok(());
                }
                None => break,
            }
        }
    }
    Ok(())
}

/// A remembered pair of decisions: name, type, address, logged group, and both schedule
/// states.
type MemoKey = (String, u16, IpAddr, u16, usize, usize);

/// Both configurations' decisions over the replayed rows.
struct Replay<'a> {
    base: Decider,
    cand: Decider,
    groups: Vec<String>,
    memo: HashMap<MemoKey, (Verdict, Verdict)>,
    scratch: Scratch,
    labels: HashMap<IpAddr, Option<String>>,
    label: &'a (dyn Fn(IpAddr) -> Option<String> + Send),
}

impl Replay<'_> {
    fn row(&mut self, r: &qlog::Row, tally: &mut Tally) {
        if !replayed(r.status) {
            tally.unchanged += 1;
            return;
        }
        let ip = Ipv6Addr::from(r.client_ip).to_canonical();
        let group = self.groups.get(usize::from(r.group)).map(String::as_str);
        let row = RowIn {
            ts_s: i64::try_from(r.ts_us / 1_000_000).unwrap_or(i64::MAX),
            ip,
            name: &r.name,
            qtype: r.qtype,
            group,
        };
        let key = (
            r.name.clone(),
            r.qtype,
            ip,
            r.group,
            self.base.state(row.ts_s),
            self.cand.state(row.ts_s),
        );
        let (b, c) = if let Some(v) = self.memo.get(&key) {
            v.clone()
        } else {
            let b = self.base.decide(&row, &mut self.scratch, &mut tally.notes);
            let c = self.cand.decide(&row, &mut self.scratch, &mut tally.notes);
            if self.memo.len() >= MEMO {
                self.memo.clear();
            }
            self.memo.insert(key, (b.clone(), c.clone()));
            (b, c)
        };
        let Some((class, list)) = classify(&b, &c) else {
            tally.unchanged += 1;
            return;
        };
        let device = telltale_telemetry::agg::client_text(r.client_ip);
        let label = self.labels.entry(ip).or_insert_with(|| (self.label)(ip));
        let gname = cand_group(&self.cand, ip, group);
        tally.count(
            class,
            &r.name,
            list.as_deref(),
            &device,
            label.as_deref(),
            &gname,
        );
    }
}

/// The group a device belongs to under the candidate (for `byGroup`).
fn cand_group(d: &Decider, ip: IpAddr, logged: Option<&str>) -> String {
    let clients = &d.policy.clients;
    let ident = clients.identify(ip, None, None, empty_neighbors());
    if ident.source == IdSource::Default
        && ident.net.is_none()
        && let Some(g) = logged
    {
        return g.to_owned();
    }
    clients.primary_group(ident).name.to_string()
}

/// The kind of difference between the current decision `b` and the candidate's `c`, with what
/// to show for it; `None` when they agree.
fn classify(b: &Verdict, c: &Verdict) -> Option<(usize, Option<String>)> {
    match (b.blocked(), c.blocked()) {
        (None, Some(by)) => Some((0, Some(by.to_owned()))),
        // Newly allowed: shown with what had blocked it.
        (Some(by), None) => Some((1, Some(by.to_owned()))),
        (Some(_), Some(_)) => None,
        (None, None) => match (b, c) {
            (Verdict::Resolved { route: rb, .. }, Verdict::Resolved { route: rc, .. }) => {
                (rb != rc).then(|| {
                    let show = |r: &Option<Arc<str>>| r.as_deref().unwrap_or("none").to_owned();
                    (2, Some(format!("{} → {}", show(rb), show(rc))))
                })
            }
            (x, y) if x == y => None,
            (_, Verdict::Answered(what)) => Some((3, Some(what.to_string()))),
            (Verdict::Answered(was), _) => Some((3, Some(format!("forwarded (was: {was})")))),
            _ => None,
        },
    }
}

/// How a simulation of a change can run on this configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Every logged query decided again.
    Full,
    /// Privacy level 1 and a change to devices only ([`run_devices_only`]).
    DevicesOnly,
    /// The change can't move a decision: nothing to replay.
    NotApplicable,
    /// It can't run: `disabled`, `no_query_log`, `privacy_level`.
    Unavailable(&'static str),
}

/// REQ: OBS-024 — the mode for simulating `candidate` against `current` (the configuration
/// in effect decides the settings: a change can't switch its own simulation on).
pub(crate) fn mode(current: &Config, candidate: &Config) -> Mode {
    if !current.simulate.enabled {
        return Mode::Unavailable("disabled");
    }
    if !could_change_decisions(current, candidate) {
        return Mode::NotApplicable;
    }
    if !current.telemetry.qlog.enabled {
        return Mode::Unavailable("no_query_log");
    }
    match current.telemetry.qlog.privacy_level {
        0 => Mode::Full,
        1 if clients_only(current, candidate) => Mode::DevicesOnly,
        _ => Mode::Unavailable("privacy_level"),
    }
}

/// REQ: OBS-024 — whether two configurations differ only in `[[client]]`: the change a
/// privacy level 1 log (names hashed) can still be replayed for.
pub(crate) fn clients_only(a: &Config, b: &Config) -> bool {
    let (mut x, mut y) = (a.clone(), b.clone());
    x.client.clear();
    y.client.clear();
    x == y
}

/// Whether two configurations could decide any query differently: false for alert, user,
/// exclusion, and other changes that never reach a decision.
pub(crate) fn could_change_decisions(a: &Config, b: &Config) -> bool {
    // The sections the decision steps read (`Decider::decide`); everything else (alerts,
    // users, telemetry, the cache, exclusions, ...) never moves a query.
    a.upstream != b.upstream
        || a.upstream_group != b.upstream_group
        || a.route != b.route
        || a.record != b.record
        || a.zone != b.zone
        || a.local != b.local
        || a.list != b.list
        || a.group != b.group
        || a.schedule != b.schedule
        || a.client != b.client
        || a.rule != b.rule
        || a.clients != b.clients
        || a.access != b.access
        || a.special != b.special
}

fn devices_only_inner(inputs: &Inputs, started: Instant) -> Result<Tally, Problem> {
    let mut tally = Tally::default();
    if inputs.dirs.is_empty() {
        tally.no_log = true;
        return Ok(tally);
    }
    let base = ClientTable::from_config(&inputs.current);
    let cand = ClientTable::from_config(&inputs.candidate);
    let settings = |cfg: &Config, name: &str| {
        cfg.group.iter().find(|g| g.name.as_str() == name).map(|g| {
            let mut v = serde_json::to_value(g).unwrap_or_default();
            if let Some(o) = v.as_object_mut() {
                for k in ["name", "networks", "priority", "description", "color"] {
                    o.remove(k);
                }
            }
            v
        })
    };
    let mut alike: HashMap<IpAddr, bool> = HashMap::new();
    scan(&inputs.dirs, &inputs.window, started, &mut tally, |r, t| {
        let ip = Ipv6Addr::from(r.client_ip).to_canonical();
        let same = *alike.entry(ip).or_insert_with(|| {
            let b = base.group_names(base.identify(ip, None, None, empty_neighbors()));
            let c = cand.group_names(cand.identify(ip, None, None, empty_neighbors()));
            b == c
                || (b.len() == c.len()
                    && b.iter().zip(c).all(|(x, y)| {
                        settings(&inputs.current, x) == settings(&inputs.candidate, y)
                    }))
        });
        if same {
            t.unchanged += 1;
        } else {
            t.undetermined += 1;
        }
    })?;
    tally
        .notes
        .insert("privacy_level_1_devices_only".to_owned());
    Ok(tally)
}

/// RPC: run a simulation over this node's rows; the body is a [`Remote`], the answer a
/// [`Tally`] (`forward::encode_answer`). A node without it (an older version) answers an
/// error and is listed in `missingNodes`.
pub(crate) const KIND: &str = "sim.run";
/// Extra time peers get over `max_secs`: downloading and compiling changed lists.
const PEER_SLACK: Duration = Duration::from_secs(30);
/// A request older than this when a peer reads it was given up on.
const STALE_MS: u64 = 120_000;

/// A simulation request to a peer: both configurations' shared parts (each node runs them
/// with its own node-local settings) and the window.
#[derive(Debug, Serialize, Deserialize)]
struct Remote {
    current: serde_json::Value,
    candidate: serde_json::Value,
    window: Window,
    devices_only: bool,
    sent_ms: u64,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Runs `f` on a thread of its own at background priority (never a runtime worker: a
/// simulation takes seconds of CPU, and a pooled blocking thread would keep the priority).
async fn on_background_thread<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Problem> + Send + 'static,
) -> Result<T, Problem> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("telltale-sim".into())
        .spawn(move || {
            telltale_net::background_thread();
            let _ = tx.send(f());
        })
        .map_err(|e| Problem::internal(format!("simulation thread: {e}")))?;
    rx.await
        .map_err(|_| Problem::internal("the simulation thread stopped"))?
}

/// This node's part: the changed lists' texts, the serving filter, its logs, its device
/// names.
async fn local_part(
    src: &Arc<crate::http::Sources>,
    current: Arc<Config>,
    candidate: Arc<Config>,
    window: Window,
    devices_only: bool,
) -> Result<Tally, Problem> {
    let sources = if devices_only {
        Vec::new()
    } else {
        let lists = src.lists.load_full();
        let store = lists.as_ref().map(|l| l.fetcher.store());
        side_sources(&current, &candidate, store).await?
    };
    let serving = src
        .pipeline
        .filter
        .load_full()
        .map(|f| Arc::clone(&f.matcher));
    let dirs = log_dirs(&src.config.load());
    let names = Arc::clone(src);
    let inputs = Inputs {
        current,
        candidate,
        serving,
        sources,
        dirs,
        window,
        label: Box::new(move |ip| {
            let v6 = match ip {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            crate::api_backend::device_name(&names, v6.octets())
        }),
    };
    on_background_thread(move || {
        if devices_only {
            run_devices_only(&inputs)
        } else {
            run(inputs)
        }
    })
    .await
}

/// REQ: OBS-024 — what `candidate` would have done to the logged queries of the whole
/// cluster, compared with `current`: this node's rows plus every reachable peer's (each
/// replays its own log and the logs shipped to it), merged; unreachable nodes in
/// `missingNodes`. `Ok(None)` for `simulate=auto` while `[simulate] plans_by_default` is
/// off. The settings that apply are the running configuration's.
pub(crate) async fn simulate(
    src: &Arc<crate::http::Sources>,
    current: Arc<Config>,
    candidate: Arc<Config>,
    opts: &telltale_api::SimulateOpts,
) -> Result<Option<Simulation>, Problem> {
    let running = src.config.load_full();
    if opts.auto && !running.simulate.plans_by_default {
        return Ok(None);
    }
    let unavailable_counted = |reason: &str| {
        stats().unavailable.fetch_add(1, Ordering::Relaxed);
        Ok(Some(unavailable(reason)))
    };
    let devices_only = match mode(&current, &candidate) {
        Mode::NotApplicable => return Ok(Some(not_applicable())),
        Mode::Unavailable(r) => return unavailable_counted(r),
        Mode::Full => false,
        Mode::DevicesOnly => true,
    };
    let now_s = now_ms() / 1000;
    let w = window(
        &running.simulate,
        opts.window.as_deref(),
        opts.until_s,
        now_s,
    )?;
    // Peers run while this node does.
    let peers = src.cluster.as_ref().map(|cluster| {
        let req = Remote {
            current: telltale_config::shared::shared_part(&current),
            candidate: telltale_config::shared::shared_part(&candidate),
            window: w,
            devices_only,
            sent_ms: now_ms(),
        };
        let body = serde_json::to_vec(&req).unwrap_or_default();
        let deadline = Duration::from_secs(u64::from(w.max_secs)) + PEER_SLACK;
        let calls: Vec<_> = cluster
            .reachable_peers()
            .into_iter()
            .map(|peer| {
                let (c, body) = (Arc::clone(cluster), body.clone());
                tokio::spawn(async move {
                    let r = c.call(&peer, KIND, body, deadline).await;
                    (peer, r)
                })
            })
            .collect();
        (Arc::clone(cluster), calls)
    });
    let local = local_part(src, current, candidate, w, devices_only).await;
    let mut tally = match local {
        Ok(t) => t,
        Err(p) if p.code == Code::SimulationBusy && opts.auto => {
            return unavailable_counted("busy");
        }
        Err(p) => return Err(p),
    };
    let mut missing = Vec::new();
    if let Some((cluster, calls)) = peers {
        let label = |id: &str| {
            cluster
                .members()
                .into_iter()
                .find(|m| m.node_id == id)
                .map(|m| if m.pod.is_empty() { m.site } else { m.pod })
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| id.to_owned())
        };
        for m in cluster.members() {
            if !m.connected {
                missing.push(label(&m.node_id));
            }
        }
        for call in calls {
            let Ok((peer, r)) = call.await else { continue };
            let answer = r
                .map_err(Problem::unavailable)
                .and_then(|body| crate::forward::decode_answer::<Tally>(&body));
            match answer {
                Ok(t) => tally.merge(t),
                Err(e) => {
                    tracing::debug!(peer, error = %e.detail, "simulation: a peer didn't answer");
                    missing.push(label(&peer));
                }
            }
        }
    }
    missing.sort();
    missing.dedup();
    let mut s = tally.finish(Some(&w));
    s.missing_nodes = missing;
    Ok(Some(s))
}

/// REQ: OBS-024 — a peer's `sim.run`: this node's rows under both configurations (with its
/// own node-local settings), as a [`Tally`].
pub(crate) async fn handle(
    src: Arc<crate::http::Sources>,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let r = async {
        let req: Remote = serde_json::from_slice(&body)
            .map_err(|e| Problem::invalid(format!("bad simulation request: {e}")))?;
        if now_ms().saturating_sub(req.sent_ms) > STALE_MS {
            return Err(Problem::unavailable("the simulation request is stale"));
        }
        let file = src.file_config.load_full();
        let merge = |shared: &serde_json::Value| {
            telltale_config::shared::with_shared(&file, shared).map_err(|errs| {
                Problem::new(
                    Code::InvalidConfig,
                    errs.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; "),
                )
            })
        };
        let current = Arc::new(merge(&req.current)?);
        let candidate = Arc::new(merge(&req.candidate)?);
        // This node's own privacy level and settings decide what it may replay.
        match mode(&src.config.load(), &candidate) {
            Mode::Unavailable(r) => {
                return Err(Problem::unavailable(format!("not on this node: {r}")));
            }
            Mode::DevicesOnly if !req.devices_only => {
                return Err(Problem::unavailable("not on this node: privacy_level"));
            }
            _ => {}
        }
        local_part(&src, current, candidate, req.window, req.devices_only).await
    }
    .await;
    crate::forward::encode_answer(r)
}

#[cfg(test)]
mod tests;
