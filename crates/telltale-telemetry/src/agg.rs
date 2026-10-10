//! The aggregator's state (`spec/06` §2 steps 2–4): live windows, Space-Saving top-K, and
//! HDR latency histograms. Updated only by the aggregator thread; read by the API under a
//! short lock. Memory is bounded by construction (fixed windows, capped keys).

use std::collections::HashMap;

use hdrhistogram::Histogram;

use crate::event::{Name, QueryEvent, Record, UpstreamEvent};
use crate::export::Exported;
use crate::recent::{ClientWindow, RecentClients};
use crate::topk::{SpaceSaving, Top};
use crate::{N_PROTO, N_QTYPE, N_RCODE, N_STATUS, Path, Proto, Status, qtype_index};

/// Per-second buckets kept (15 minutes) and per-minute buckets (48 hours).
pub const SECONDS: usize = 15 * 60;
pub const MINUTES: usize = 48 * 60;
/// Space-Saving capacity per tracker, and how many are reported (`spec/06` §2).
pub const TOP_CAPACITY: usize = 1000;
pub const TOP_REPORTED: usize = 100;
/// Clients with their own domain top-K (least recently seen evicted), and its capacity.
const PER_CLIENT: usize = 64;
const PER_CLIENT_CAPACITY: usize = 100;
/// Clients with their own latency histogram; the rest share "other".
pub const CLIENT_HISTOGRAMS: usize = 256;
/// Group and upstream columns kept per bucket; higher IDs share the last column.
const MAX_IDS: usize = 64;
/// Histogram range: 1 µs to 60 s, 2 significant digits (ADR-026).
const HIST_MAX_US: u64 = 60_000_000;
const HIST_DIGITS: u8 = 2;

/// Counts for one time bucket.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counts {
    pub total: u32,
    pub status: [u32; N_STATUS],
    pub qtype: [u32; N_QTYPE],
    pub rcode: [u32; N_RCODE],
    pub proto: [u32; N_PROTO],
    /// By primary group index (the last column also holds every higher index).
    pub groups: Vec<u32>,
    /// Blocked queries by primary group index (ADR-050), like `groups`.
    pub group_blocked: Vec<u32>,
    /// Upstream exchanges by upstream index, and how many failed.
    pub upstreams: Vec<u32>,
    pub upstream_failures: u32,
    /// REQ: OBS-004 (T6.16) — by group name, in buckets read back from the rollups (the
    /// indexes above only mean something within one process's group table). Empty in live
    /// buckets.
    pub named_groups: Vec<NamedGroup>,
    /// REQ: OBS-016 (T11.1) — answered queries slower than the latency objective's
    /// threshold ([`Aggregates::slo_latency_us`] when they were counted).
    pub slow: u32,
}

/// One group's queries and blocked queries in a stored bucket (T6.16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedGroup {
    pub name: Box<str>,
    pub total: u32,
    pub blocked: u32,
}

impl Counts {
    /// REQ: OBS-004 (T6.16) — the per-index group columns as names (from `names`, this
    /// process's group table; indexes past it are "other"), for storing. Merges equal names.
    pub fn name_groups(&mut self, names: &[&str]) {
        let len = self.groups.len().max(self.group_blocked.len());
        for i in 0..len {
            let total = self.groups.get(i).copied().unwrap_or(0);
            let blocked = self.group_blocked.get(i).copied().unwrap_or(0);
            if total == 0 && blocked == 0 {
                continue;
            }
            let name = names.get(i).copied().unwrap_or("other");
            add_named(&mut self.named_groups, name, total, blocked);
        }
    }
}

/// Adds to `name`'s entry in `v` (kept sorted by name).
pub fn add_named(v: &mut Vec<NamedGroup>, name: &str, total: u32, blocked: u32) {
    match v.binary_search_by(|g| (*g.name).cmp(name)) {
        Ok(i) => {
            v[i].total = v[i].total.saturating_add(total);
            v[i].blocked = v[i].blocked.saturating_add(blocked);
        }
        Err(i) => v.insert(
            i,
            NamedGroup {
                name: name.into(),
                total,
                blocked,
            },
        ),
    }
}

fn bump(v: &mut Vec<u32>, id: usize) {
    let i = id.min(MAX_IDS - 1);
    if v.len() <= i {
        v.resize(i + 1, 0);
    }
    v[i] = v[i].saturating_add(1);
}

impl Counts {
    fn add_query(&mut self, e: &QueryEvent, slow_us: u64) {
        self.total = self.total.saturating_add(1);
        // REQ: OBS-016 — the latency objective's bad events (dropped queries got no answer).
        if e.status != Status::Dropped && u64::from(e.t_total_us) > slow_us {
            self.slow = self.slow.saturating_add(1);
        }
        let s = &mut self.status[e.status as usize];
        *s = s.saturating_add(1);
        let q = &mut self.qtype[qtype_index(e.qtype)];
        *q = q.saturating_add(1);
        if let Some(rc) = e.rcode {
            let r = &mut self.rcode[usize::from(rc).min(N_RCODE - 1)];
            *r = r.saturating_add(1);
        }
        let p = &mut self.proto[e.proto as usize];
        *p = p.saturating_add(1);
        bump(&mut self.groups, usize::from(e.group));
        if e.status == Status::Blocked {
            bump(&mut self.group_blocked, usize::from(e.group));
        }
    }

    fn add_upstream(&mut self, e: &UpstreamEvent) {
        bump(&mut self.upstreams, usize::from(e.upstream));
        if !e.ok {
            self.upstream_failures = self.upstream_failures.saturating_add(1);
        }
    }
}

/// Fixed ring of time buckets.
#[derive(Debug, Clone)]
struct Series {
    width_s: u64,
    /// `(bucket start, counts)`; a slot whose start is stale is reused.
    slots: Vec<(u64, Counts)>,
}

impl Series {
    fn new(width_s: u64, n: usize) -> Self {
        Self {
            width_s,
            slots: vec![(u64::MAX, Counts::default()); n],
        }
    }

    /// The bucket for `ts_s`, or `None` if it's older than what this series keeps.
    fn at(&mut self, ts_s: u64) -> Option<&mut Counts> {
        let start = ts_s - ts_s % self.width_s;
        let n = self.slots.len() as u64;
        let i = usize::try_from((start / self.width_s) % n).unwrap_or(0);
        let slot = &mut self.slots[i];
        if slot.0 != start {
            if slot.0 != u64::MAX && slot.0 > start {
                return None; // a newer bucket lives here: the event is too old
            }
            *slot = (start, Counts::default());
        }
        Some(&mut slot.1)
    }

    /// Buckets with start in `[from_s, to_s)`, oldest first.
    fn range(&self, from_s: u64, to_s: u64) -> Vec<(u64, Counts)> {
        let mut v: Vec<(u64, Counts)> = self
            .slots
            .iter()
            .filter(|(s, _)| *s != u64::MAX && *s >= from_s && *s < to_s)
            .cloned()
            .collect();
        v.sort_by_key(|(s, _)| *s);
        v
    }
}

/// Resolution of [`Aggregates::series`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    Second,
    Minute,
}

/// What a top-K list counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopKind {
    Domains,
    Blocked,
    Nxdomain,
    Clients,
}

/// Latency histogram selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatencyKey {
    /// Receive → send, by answer path and transport.
    Total(Path, Proto),
    /// By query type (the `QTYPES` index; the last is "other").
    Qtype(usize),
    /// By client address (v4-mapped); unknown or over the cap → "other".
    Client([u8; 16]),
    /// Time waiting for upstreams, per client query.
    StageUpstream,
    /// Per upstream (its config-order ID), from upstream events.
    Upstream(u16),
}

/// Percentiles of one histogram, in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Percentiles {
    pub count: u64,
    pub p50: u64,
    pub p90: u64,
    pub p99: u64,
    pub p999: u64,
    pub max: u64,
}

/// Client → (last seen, its heaviest domains).
type ClientDomains = HashMap<[u8; 16], (u64, SpaceSaving<Box<[u8]>>)>;

/// One hour's top-K trackers and histograms (`spec/06` §3 stores both per hour).
#[derive(Debug, Clone)]
struct Hour {
    /// Hours since the Unix epoch.
    index: u64,
    domains: SpaceSaving<Box<[u8]>>,
    blocked: SpaceSaving<Box<[u8]>>,
    nxdomain: SpaceSaving<Box<[u8]>>,
    clients: SpaceSaving<[u8; 16]>,
    /// Client → (last seen, its domains).
    per_client: ClientDomains,
    total: Vec<Hist>,
    qtype: Vec<Hist>,
    clients_hist: HashMap<[u8; 16], Hist>,
    other_clients: Hist,
    stage_upstream: Hist,
    upstreams: Vec<Hist>,
    /// Per primary group (ADR-050), allocated when a group first shows up.
    per_group: Vec<Option<Box<GroupTops>>>,
}

/// One group's top lists for an hour.
#[derive(Debug, Clone)]
struct GroupTops {
    domains: SpaceSaving<Box<[u8]>>,
    blocked: SpaceSaving<Box<[u8]>>,
    clients: SpaceSaving<[u8; 16]>,
}

/// Entries per group top list (smaller than the overall lists: there are several groups).
const GROUP_TOP_CAPACITY: usize = 256;

/// A histogram that allocates on first use (most keys never see a value).
#[derive(Debug, Clone, Default)]
struct Hist(Option<Histogram<u32>>);

impl Hist {
    fn record(&mut self, us: u64) {
        if self.0.is_none() {
            self.0 = Histogram::new_with_bounds(1, HIST_MAX_US, HIST_DIGITS).ok();
        }
        if let Some(h) = &mut self.0 {
            h.saturating_record(us.clamp(1, HIST_MAX_US));
        }
    }

    fn percentiles(&self) -> Option<Percentiles> {
        let h = self.0.as_ref()?;
        (!h.is_empty()).then(|| Percentiles {
            count: h.len(),
            p50: h.value_at_quantile(0.50),
            p90: h.value_at_quantile(0.90),
            p99: h.value_at_quantile(0.99),
            p999: h.value_at_quantile(0.999),
            max: h.max(),
        })
    }

    /// REQ: CLU-002 (T9.2) — the recorded `(value, count)` pairs, to merge across nodes.
    fn buckets(&self) -> Option<Vec<(u64, u64)>> {
        let h = self.0.as_ref().filter(|h| !h.is_empty())?;
        Some(
            h.iter_recorded()
                .map(|v| (v.value_iterated_to(), v.count_at_value().into()))
                .collect(),
        )
    }
}

/// REQ: CLU-002 (T9.2) — percentiles of several nodes' histograms together (exact to the
/// histograms' precision, unlike averaging their percentiles).
pub fn merged_percentiles(parts: &[&[(u64, u64)]]) -> Option<Percentiles> {
    let mut h = Histogram::<u64>::new_with_bounds(1, HIST_MAX_US, HIST_DIGITS).ok()?;
    for part in parts {
        for &(v, n) in *part {
            h.saturating_record_n(v.clamp(1, HIST_MAX_US), n);
        }
    }
    (!h.is_empty()).then(|| Percentiles {
        count: h.len(),
        p50: h.value_at_quantile(0.50),
        p90: h.value_at_quantile(0.90),
        p99: h.value_at_quantile(0.99),
        p999: h.value_at_quantile(0.999),
        max: h.max(),
    })
}

impl Hour {
    fn new(index: u64) -> Self {
        Self {
            index,
            domains: SpaceSaving::new(TOP_CAPACITY),
            blocked: SpaceSaving::new(TOP_CAPACITY),
            nxdomain: SpaceSaving::new(TOP_CAPACITY),
            clients: SpaceSaving::new(TOP_CAPACITY),
            per_client: HashMap::new(),
            total: vec![Hist::default(); Path::ALL.len() * Proto::ALL.len()],
            qtype: vec![Hist::default(); N_QTYPE],
            clients_hist: HashMap::new(),
            other_clients: Hist::default(),
            stage_upstream: Hist::default(),
            upstreams: Vec::new(),
            per_group: Vec::new(),
        }
    }

    fn add_query(&mut self, e: &QueryEvent, name: &Name, seq: u64) {
        let wire = name.as_wire();
        if !wire.is_empty() {
            self.domains.offer(wire, boxed);
            if e.status == Status::Blocked {
                self.blocked.offer(wire, boxed);
            }
            if e.rcode == Some(3) {
                self.nxdomain.offer(wire, boxed);
            }
            self.per_client_domain(e.client_ip, wire, seq);
        }
        self.clients.offer(&e.client_ip, |ip| *ip);
        self.group_add(e, wire);
        if e.status != Status::Dropped {
            let us = u64::from(e.t_total_us);
            self.total[e.status.path() as usize * Proto::ALL.len() + e.proto as usize].record(us);
            self.qtype[qtype_index(e.qtype)].record(us);
            if let Some(h) = self.clients_hist.get_mut(&e.client_ip) {
                h.record(us);
            } else if self.clients_hist.len() < CLIENT_HISTOGRAMS {
                self.clients_hist.entry(e.client_ip).or_default().record(us);
            } else {
                self.other_clients.record(us);
            }
            if e.t_upstream_us > 0 {
                self.stage_upstream.record(u64::from(e.t_upstream_us));
            }
        }
    }

    fn group_add(&mut self, e: &QueryEvent, wire: &[u8]) {
        let g = usize::from(e.group).min(MAX_IDS - 1);
        if self.per_group.len() <= g {
            self.per_group.resize(g + 1, None);
        }
        let t = self.per_group[g].get_or_insert_with(|| {
            Box::new(GroupTops {
                domains: SpaceSaving::new(GROUP_TOP_CAPACITY),
                blocked: SpaceSaving::new(GROUP_TOP_CAPACITY),
                clients: SpaceSaving::new(GROUP_TOP_CAPACITY),
            })
        });
        if !wire.is_empty() {
            t.domains.offer(wire, boxed);
            if e.status == Status::Blocked {
                t.blocked.offer(wire, boxed);
            }
        }
        t.clients.offer(&e.client_ip, |ip| *ip);
    }

    fn per_client_domain(&mut self, client: [u8; 16], wire: &[u8], seq: u64) {
        if !self.per_client.contains_key(&client) && self.per_client.len() >= PER_CLIENT {
            // Least recently seen client makes room.
            if let Some(oldest) = self
                .per_client
                .iter()
                .min_by_key(|(_, (seen, _))| *seen)
                .map(|(k, _)| *k)
            {
                self.per_client.remove(&oldest);
            }
        }
        let (seen, top) = self
            .per_client
            .entry(client)
            .or_insert_with(|| (seq, SpaceSaving::new(PER_CLIENT_CAPACITY)));
        *seen = seq;
        top.offer(wire, boxed);
    }

    fn add_upstream(&mut self, e: &UpstreamEvent) {
        let i = usize::from(e.upstream).min(MAX_IDS - 1);
        if self.upstreams.len() <= i {
            self.upstreams.resize(i + 1, Hist::default());
        }
        self.upstreams[i].record(u64::from(e.latency_us));
    }
}

/// Everything the aggregator maintains.
#[derive(Debug, Clone)]
pub struct Aggregates {
    seconds: Series,
    minutes: Series,
    current: Hour,
    previous: Option<Hour>,
    /// Events seen (orders "recently seen" for the per-client LRU).
    seq: u64,
    /// Newest event timestamp (seconds).
    pub latest_s: u64,
    /// Cumulative series for Prometheus (OBS-005).
    pub exported: Exported,
    /// Per-client counts in 10-minute windows (OPS-003).
    recent: RecentClients,
    /// REQ: OBS-016 (T11.1) — answers slower than this (µs) count as `slow` in the time
    /// buckets: the latency objective's threshold (`[slo] latency_ms`).
    pub slo_latency_us: u64,
}

/// The latency objective's default threshold (`[slo] latency_ms = 250`).
pub const DEFAULT_SLO_LATENCY_US: u64 = 250_000;

impl Default for Aggregates {
    fn default() -> Self {
        Self::new()
    }
}

/// Which hour a top-K or latency query reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HourSel {
    Current,
    Previous,
}

impl Aggregates {
    pub fn new() -> Self {
        Self {
            seconds: Series::new(1, SECONDS),
            minutes: Series::new(60, MINUTES),
            current: Hour::new(0),
            previous: None,
            seq: 0,
            latest_s: 0,
            exported: Exported::default(),
            recent: RecentClients::default(),
            slo_latency_us: DEFAULT_SLO_LATENCY_US,
        }
    }

    /// Folds one record in.
    pub fn record(&mut self, r: &Record) {
        self.seq += 1;
        let ts_s = match r {
            Record::Query(e, _) => e.ts_us / 1_000_000,
            Record::Upstream(e) => e.ts_us / 1_000_000,
        };
        self.latest_s = self.latest_s.max(ts_s);
        let hour = ts_s / 3600;
        if hour > self.current.index {
            let done = std::mem::replace(&mut self.current, Hour::new(hour));
            self.previous = (done.index + 1 == hour).then_some(done);
        }
        // Late events from an earlier hour still count in the windows, not the hour stats.
        let in_hour = hour == self.current.index;
        match r {
            Record::Query(e, name) => {
                self.exported.add_query(e);
                self.recent.add(e.client_ip, ts_s);
                let slow_us = self.slo_latency_us;
                for series in [&mut self.seconds, &mut self.minutes] {
                    if let Some(c) = series.at(ts_s) {
                        c.add_query(e, slow_us);
                    }
                }
                if in_hour {
                    self.current.add_query(e, name, self.seq);
                }
            }
            Record::Upstream(e) => {
                self.exported.add_upstream(e);
                for series in [&mut self.seconds, &mut self.minutes] {
                    if let Some(c) = series.at(ts_s) {
                        c.add_upstream(e);
                    }
                }
                if in_hour {
                    self.current.add_upstream(e);
                }
            }
        }
    }

    /// REQ: OBS-004 (T6.16) — folds one query from before this process started (replayed from
    /// the query log) into the current or previous hour's top lists and latency histograms, by
    /// its own timestamp, in any order. The time windows aren't touched (the rollups hold those
    /// minutes), nor are the Prometheus counters or the masked-client windows (they count this
    /// process). Queries older than the previous hour are ignored.
    pub fn replay_hours(&mut self, now_s: u64, e: &QueryEvent, name: &Name) {
        let now_hour = now_s / 3600;
        if now_hour > self.current.index {
            let done = std::mem::replace(&mut self.current, Hour::new(now_hour));
            self.previous = (done.index + 1 == now_hour).then_some(done);
        }
        let hour = e.ts_us / 1_000_000 / 3600;
        self.seq += 1;
        if hour == self.current.index {
            self.current.add_query(e, name, self.seq);
        } else if hour + 1 == self.current.index {
            self.previous
                .get_or_insert_with(|| Hour::new(hour))
                .add_query(e, name, self.seq);
        }
    }

    /// Buckets in `[from_s, to_s)` at `res`, oldest first.
    pub fn series(&self, res: Resolution, from_s: u64, to_s: u64) -> Vec<(u64, Counts)> {
        match res {
            Resolution::Second => self.seconds.range(from_s, to_s),
            Resolution::Minute => self.minutes.range(from_s, to_s),
        }
    }

    fn hour(&self, sel: HourSel) -> Option<&Hour> {
        match sel {
            HourSel::Current => Some(&self.current),
            HourSel::Previous => self.previous.as_ref(),
        }
    }

    /// The heaviest names (presentation form) for `kind`, heaviest first.
    pub fn top_names(&self, kind: TopKind, sel: HourSel, n: usize) -> Vec<Top<String>> {
        let Some(h) = self.hour(sel) else {
            return Vec::new();
        };
        let names = |t: &SpaceSaving<Box<[u8]>>| {
            t.top(n)
                .into_iter()
                .map(|x| Top {
                    key: crate::event::dotted(&x.key),
                    count: x.count,
                    error: x.error,
                })
                .collect()
        };
        match kind {
            TopKind::Domains => names(&h.domains),
            TopKind::Blocked => names(&h.blocked),
            TopKind::Nxdomain => names(&h.nxdomain),
            TopKind::Clients => h
                .clients
                .top(n)
                .into_iter()
                .map(|x| Top {
                    key: client_text(x.key),
                    count: x.count,
                    error: x.error,
                })
                .collect(),
        }
    }

    /// The heaviest names (or clients) for `kind` among one group's queries (ADR-050).
    /// `Nxdomain` isn't tracked per group (empty).
    pub fn top_names_in_group(
        &self,
        kind: TopKind,
        sel: HourSel,
        group: u16,
        n: usize,
    ) -> Vec<Top<String>> {
        let Some(t) = self
            .hour(sel)
            .and_then(|h| h.per_group.get(usize::from(group)))
            .and_then(|t| t.as_deref())
        else {
            return Vec::new();
        };
        let names = |t: &SpaceSaving<Box<[u8]>>| {
            t.top(n)
                .into_iter()
                .map(|x| Top {
                    key: crate::event::dotted(&x.key),
                    count: x.count,
                    error: x.error,
                })
                .collect()
        };
        match kind {
            TopKind::Domains => names(&t.domains),
            TopKind::Blocked => names(&t.blocked),
            TopKind::Nxdomain => Vec::new(),
            TopKind::Clients => t
                .clients
                .top(n)
                .into_iter()
                .map(|x| Top {
                    key: client_text(x.key),
                    count: x.count,
                    error: x.error,
                })
                .collect(),
        }
    }

    /// Devices seen in a group this hour (up to the tracked capacity).
    pub fn group_devices(&self, sel: HourSel, group: u16) -> usize {
        self.hour(sel)
            .and_then(|h| h.per_group.get(usize::from(group)))
            .and_then(|t| t.as_deref())
            .map_or(0, |t| t.clients.len())
    }

    /// A client's heaviest domains this hour (if it's among the recently seen clients).
    pub fn top_client_domains(&self, client: [u8; 16], n: usize) -> Vec<Top<String>> {
        self.top_client_domains_in(HourSel::Current, client, n)
    }

    /// REQ: OBS-025 — the clients whose heaviest domains the selected hour keeps.
    pub fn clients_with_domains(&self, sel: HourSel) -> Vec<[u8; 16]> {
        let mut v: Vec<[u8; 16]> = self
            .hour(sel)
            .map(|h| h.per_client.keys().copied().collect())
            .unwrap_or_default();
        v.sort_unstable();
        v
    }

    /// REQ: OBS-025 — a client's heaviest domains in the selected hour.
    pub fn top_client_domains_in(
        &self,
        sel: HourSel,
        client: [u8; 16],
        n: usize,
    ) -> Vec<Top<String>> {
        self.hour(sel)
            .and_then(|h| h.per_client.get(&client))
            .map(|(_, t)| {
                t.top(n)
                    .into_iter()
                    .map(|x| Top {
                        key: crate::event::dotted(&x.key),
                        count: x.count,
                        error: x.error,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Who sent the queries in the latest 10-minute window (REQ: OPS-003).
    pub fn recent_clients(&self, now_s: u64) -> Option<ClientWindow> {
        self.recent.latest(now_s)
    }

    /// Start (Unix seconds) of the last complete hour kept in memory, if any.
    pub fn previous_hour_start(&self) -> Option<u64> {
        self.previous.as_ref().map(|h| h.index * 3600)
    }

    /// Latency percentiles for `key` in the selected hour.
    pub fn latency(&self, key: LatencyKey, sel: HourSel) -> Option<Percentiles> {
        self.hist(key, sel)?.percentiles()
    }

    /// REQ: CLU-002 (T9.2) — the histogram behind [`Self::latency`], as `(value, count)`
    /// pairs for [`merged_percentiles`].
    pub fn latency_buckets(&self, key: LatencyKey, sel: HourSel) -> Option<Vec<(u64, u64)>> {
        self.hist(key, sel)?.buckets()
    }

    fn hist(&self, key: LatencyKey, sel: HourSel) -> Option<&Hist> {
        let h = self.hour(sel)?;
        match key {
            LatencyKey::Total(p, proto) => {
                h.total.get(p as usize * Proto::ALL.len() + proto as usize)
            }
            LatencyKey::Qtype(i) => h.qtype.get(i),
            LatencyKey::Client(ip) => Some(h.clients_hist.get(&ip).unwrap_or(&h.other_clients)),
            LatencyKey::StageUpstream => Some(&h.stage_upstream),
            LatencyKey::Upstream(u) => h.upstreams.get(usize::from(u)),
        }
    }
}

fn boxed(wire: &[u8]) -> Box<[u8]> {
    Box::from(wire)
}

/// Presentation form of a v4-mapped client address.
pub fn client_text(ip: [u8; 16]) -> String {
    let v6 = std::net::Ipv6Addr::from(ip);
    v6.to_ipv4_mapped()
        .map_or_else(|| v6.to_string(), |v4| v4.to_string())
}

#[cfg(test)]
mod merge_tests {
    use super::*;

    /// REQ: CLU-002 (T9.2) — merging nodes' histograms gives the percentiles of all their
    /// values together, which averaging each node's percentiles doesn't.
    #[test]
    fn clu_002_latency_histograms_merge_exactly() {
        let (mut fast, mut slow, mut all) = (Hist::default(), Hist::default(), Hist::default());
        for us in 1..=9_000u64 {
            fast.record(100 + us % 50);
            all.record(100 + us % 50);
        }
        for us in 1..=1_000u64 {
            slow.record(40_000 + us);
            all.record(40_000 + us);
        }
        let (f, s) = (fast.buckets().unwrap(), slow.buckets().unwrap());
        let merged = merged_percentiles(&[&f, &s]).unwrap();
        assert_eq!(merged, all.percentiles().unwrap());
        assert_eq!(merged.count, 10_000);
        // The top 1% are all from the slow node.
        assert!(merged.p99 > 40_000, "{merged:?}");
        assert!(merged_percentiles(&[]).is_none());
    }
}
