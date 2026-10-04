//! The aggregator's state (`spec/06` §2 steps 2–4): live windows, Space-Saving top-K, and
//! HDR latency histograms. Updated only by the aggregator thread; read by the API under a
//! short lock. Memory is bounded by construction (fixed windows, capped keys).

use std::collections::HashMap;

use hdrhistogram::Histogram;

use crate::event::{Name, QueryEvent, Record, UpstreamEvent};
use crate::export::Exported;
use crate::topk::{SpaceSaving, Top};
use crate::{N_QTYPE, N_RCODE, N_STATUS, Path, Proto, Status, qtype_index};

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
    pub proto: [u32; 2],
    /// By primary group index (the last column also holds every higher index).
    pub groups: Vec<u32>,
    /// Upstream exchanges by upstream index, and how many failed.
    pub upstreams: Vec<u32>,
    pub upstream_failures: u32,
}

fn bump(v: &mut Vec<u32>, id: usize) {
    let i = id.min(MAX_IDS - 1);
    if v.len() <= i {
        v.resize(i + 1, 0);
    }
    v[i] = v[i].saturating_add(1);
}

impl Counts {
    fn add_query(&mut self, e: &QueryEvent) {
        self.total = self.total.saturating_add(1);
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
}

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
}

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
                for series in [&mut self.seconds, &mut self.minutes] {
                    if let Some(c) = series.at(ts_s) {
                        c.add_query(e);
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

    /// A client's heaviest domains this hour (if it's among the recently seen clients).
    pub fn top_client_domains(&self, client: [u8; 16], n: usize) -> Vec<Top<String>> {
        self.current
            .per_client
            .get(&client)
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

    /// Start (Unix seconds) of the last complete hour kept in memory, if any.
    pub fn previous_hour_start(&self) -> Option<u64> {
        self.previous.as_ref().map(|h| h.index * 3600)
    }

    /// Latency percentiles for `key` in the selected hour.
    pub fn latency(&self, key: LatencyKey, sel: HourSel) -> Option<Percentiles> {
        let h = self.hour(sel)?;
        match key {
            LatencyKey::Total(p, proto) => {
                h.total[p as usize * Proto::ALL.len() + proto as usize].percentiles()
            }
            LatencyKey::Qtype(i) => h.qtype.get(i)?.percentiles(),
            LatencyKey::Client(ip) => h
                .clients_hist
                .get(&ip)
                .unwrap_or(&h.other_clients)
                .percentiles(),
            LatencyKey::StageUpstream => h.stage_upstream.percentiles(),
            LatencyKey::Upstream(u) => h.upstreams.get(usize::from(u))?.percentiles(),
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
