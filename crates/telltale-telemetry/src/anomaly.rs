//! Device anomaly engine v1 (REQ: OBS-013, OBS-009; `spec/06` §7.1, ADR-019, ADR-043).
//!
//! Runs on the aggregator thread over query events, never on the query path. Four detectors,
//! all fixed-math streaming statistics (no trained models):
//! - **Rate spike:** a device's hourly query count against an exponentially weighted mean and
//!   mean absolute deviation for that hour of the day.
//! - **Domain volume:** hourly queries from one device to one registrable domain (eTLD+1)
//!   against that pair's own baseline (up to [`TRACKED`] domains per device).
//! - **Drift:** new registrable domains per day against the device's learned set and its own
//!   daily-new baseline.
//! - **Beaconing:** a tracked domain queried at a regular interval (low jitter) for at least
//!   [`BEACON_HOURS`] consecutive hours, when it wasn't periodic while the device was learning.
//!
//! **Deterministic:** time comes only from event timestamps (windows close when an event from a
//! later window arrives), state is ordered (`BTreeMap`), hashing is FNV-1a, and the math is
//! basic IEEE-754 arithmetic (no `exp`/`ln`), so replaying the same events yields byte-identical
//! findings on every architecture. **Explainable:** each finding carries the observed value,
//! the baseline (center ± spread), the threshold, and the window. **Learn first:** a device
//! alerts only after `learning_days`. **Bounded:** fixed-size per-device state, at most
//! `max_clients` devices (the least recently seen are evicted, and counted). **Alert-only.**

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Registrable domains tracked per device (volume and beaconing).
pub const TRACKED: usize = 16;
/// Learned registrable domains per device (drift), as 32-bit fingerprints.
pub const LEARNED: usize = 128;
/// Consecutive regular hours before a beacon is reported.
pub const BEACON_HOURS: u32 = 4;
/// Inter-arrival samples kept per tracked domain.
const INTERVALS: usize = 16;
/// New-domain names kept per device per day (evidence for drift).
const SAMPLES: usize = 5;
/// Longest registrable-domain text kept.
const MAX_DOMAIN: usize = 64;
/// Findings kept in memory (oldest dropped first).
const MAX_FINDINGS: usize = 1000;

/// Detector sensitivity: the spread multiplier for "observed > center + k × spread".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    Low,
    #[default]
    Normal,
    High,
}

impl Sensitivity {
    fn mult(self) -> f32 {
        match self {
            Self::Low => 8.0,
            Self::Normal => 6.0,
            Self::High => 4.0,
        }
    }
}

/// Engine settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// Days a device is watched before it can alert.
    pub learning_days: u32,
    pub sensitivity: Sensitivity,
    /// Devices with state (least recently seen evicted first).
    pub max_clients: usize,
    /// Registrable domains never reported (OS connectivity checks, NTP, ...).
    pub ignore_domains: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            learning_days: 7,
            sensitivity: Sensitivity::Normal,
            max_clients: 1024,
            ignore_domains: Vec::new(),
        }
    }
}

/// What a finding is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    RateSpike,
    DomainVolume,
    Drift,
    Beacon,
}

impl Kind {
    pub const ALL: [Self; 4] = [
        Self::RateSpike,
        Self::DomainVolume,
        Self::Drift,
        Self::Beacon,
    ];
    pub const fn label(self) -> &'static str {
        match self {
            Self::RateSpike => "rate_spike",
            Self::DomainVolume => "domain_volume",
            Self::Drift => "drift",
            Self::Beacon => "beacon",
        }
    }
}

/// One anomaly, with its evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: Kind,
    /// The device's address (v4-mapped).
    pub client: [u8; 16],
    /// The registrable domain, for domain findings.
    pub domain: Option<String>,
    /// Start of the window (Unix seconds) and its length.
    pub window_start_s: u64,
    pub window_s: u32,
    /// Observed value and the baseline it was compared with (center ± spread).
    pub observed: f64,
    pub baseline: f64,
    pub spread: f64,
    /// The value it had to exceed.
    pub threshold: f64,
    /// More evidence in words (beacon period, sample new domains, ...).
    pub detail: String,
}

/// Exponentially weighted mean and mean absolute deviation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
struct Ewm {
    mean: f32,
    dev: f32,
    n: u32,
}

impl Ewm {
    fn update(&mut self, x: f32, alpha: f32) {
        if self.n == 0 {
            self.mean = x;
            self.dev = 0.0;
        } else {
            let d = (x - self.mean).abs();
            self.mean += alpha * (x - self.mean);
            self.dev += alpha * (d - self.dev);
        }
        self.n = self.n.saturating_add(1);
    }

    /// `(spread, threshold)` with an absolute floor `min_spread` and a relative floor `rel`.
    fn bound(&self, mult: f32, min_spread: f32, rel: f32) -> (f32, f32) {
        let spread = self.dev.max(min_spread).max(rel * self.mean);
        (spread, self.mean + mult * spread)
    }
}

/// A count as `f32` (counts here stay far below 2^24).
fn count(n: u32) -> f32 {
    f32::from(u16::try_from(n).unwrap_or(u16::MAX))
}

/// A tracked (device, registrable domain) pair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Tracked {
    fp: u64,
    domain: String,
    since_s: u64,
    hour: u32,
    volume: Ewm,
    last_s: u64,
    intervals: [u16; INTERVALS],
    n_intervals: u8,
    regular_hours: u32,
    /// Periodic during learning: its baseline, not an anomaly.
    known_periodic: bool,
    reported_beacon: bool,
}

impl Tracked {
    fn new(fp: u64, domain: String, ts_s: u64) -> Self {
        Self {
            fp,
            domain,
            since_s: ts_s,
            hour: 0,
            volume: Ewm::default(),
            last_s: 0,
            intervals: [0; INTERVALS],
            n_intervals: 0,
            regular_hours: 0,
            known_periodic: false,
            reported_beacon: false,
        }
    }

    fn gaps(&self) -> &[u16] {
        &self.intervals[..usize::from(self.n_intervals)]
    }

    fn push_gap(&mut self, gap: u16) {
        let n = usize::from(self.n_intervals);
        if n >= INTERVALS {
            self.intervals.copy_within(1.., 0);
            self.intervals[INTERVALS - 1] = gap;
        } else {
            self.intervals[n] = gap;
            self.n_intervals += 1;
        }
    }
}

/// Per-device state (fixed size: see [`Engine::client_bytes`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Client {
    first_s: u64,
    last_s: u64,
    /// Queries this hour, and the baseline per hour of day.
    hour_count: u32,
    rate: Vec<Ewm>,
    tracked: Vec<Tracked>,
    /// Learned domain fingerprints and the day each was last seen.
    learned: Vec<(u32, u32)>,
    new_today: u32,
    new_samples: Vec<String>,
    daily_new: Ewm,
}

impl Client {
    fn new(ts: u64) -> Self {
        Self {
            first_s: ts,
            last_s: ts,
            hour_count: 0,
            rate: vec![Ewm::default(); 24],
            tracked: Vec::with_capacity(TRACKED),
            learned: Vec::with_capacity(LEARNED),
            new_today: 0,
            new_samples: Vec::new(),
            daily_new: Ewm::default(),
        }
    }

    /// Drift: remembers the domain; counts it if it's new for the device.
    fn learn(&mut self, fp: u64, span: &[u8], day: u32) {
        let fp32 = u32::try_from((fp >> 32) ^ (fp & 0xffff_ffff)).unwrap_or(0);
        if let Some(e) = self.learned.iter_mut().find(|(f, _)| *f == fp32) {
            e.1 = day;
            return;
        }
        if self.learned.len() >= LEARNED
            && let Some(i) = self
                .learned
                .iter()
                .enumerate()
                .min_by_key(|(_, (f, d))| (*d, *f))
                .map(|(i, _)| i)
        {
            self.learned.swap_remove(i);
        }
        self.learned.push((fp32, day));
        self.new_today += 1;
        if self.new_samples.len() < SAMPLES {
            self.new_samples.push(span_text(span));
        }
    }

    /// Volume and beaconing: counts a query to a tracked pair (tracking it if there's room or
    /// an idle pair to replace).
    fn track(&mut self, fp: u64, span: &[u8], ts_s: u64) {
        let idx = match self.tracked.iter().position(|t| t.fp == fp) {
            Some(i) => Some(i),
            None if self.tracked.len() < TRACKED => {
                self.tracked.push(Tracked::new(fp, span_text(span), ts_s));
                Some(self.tracked.len() - 1)
            }
            None => {
                // Replace an idle pair (nothing this hour, baseline under 1 query an hour).
                let idle = self
                    .tracked
                    .iter()
                    .enumerate()
                    .filter(|(_, t)| t.hour == 0 && t.volume.mean < 1.0)
                    .min_by(|(_, a), (_, b)| {
                        a.volume
                            .mean
                            .total_cmp(&b.volume.mean)
                            .then(a.fp.cmp(&b.fp))
                    })
                    .map(|(i, _)| i);
                if let Some(i) = idle {
                    self.tracked[i] = Tracked::new(fp, span_text(span), ts_s);
                }
                idle
            }
        };
        let Some(i) = idx else { return };
        let t = &mut self.tracked[i];
        t.hour = t.hour.saturating_add(1);
        if t.last_s > 0 {
            let gap = ts_s.saturating_sub(t.last_s);
            if (1..3600).contains(&gap) {
                t.push_gap(u16::try_from(gap).unwrap_or(u16::MAX));
            }
        }
        t.last_s = ts_s;
    }
}

/// `BTreeMap<[u8; 16], Client>` as a list of pairs (JSON object keys must be strings).
mod as_pairs {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(
        m: &BTreeMap<[u8; 16], super::Client>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        m.iter().collect::<Vec<_>>().serialize(s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<[u8; 16], super::Client>, D::Error> {
        Ok(Vec::<([u8; 16], super::Client)>::deserialize(d)?
            .into_iter()
            .collect())
    }
}

/// The engine: feed it query events in timestamp order; read findings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Engine {
    settings: Settings,
    #[serde(with = "as_pairs")]
    clients: BTreeMap<[u8; 16], Client>,
    hour: u64,
    day: u64,
    findings: Vec<Finding>,
    pub evicted: u64,
    pub total: BTreeMap<Kind, u64>,
    /// Fingerprints of `settings.ignore_domains` (rebuilt from the settings).
    #[serde(skip)]
    ignore_fps: Vec<u64>,
}

/// Second-level labels under which registrations sit one level deeper (`co.uk`, `com.au`).
const SECOND_LEVEL: [&[u8]; 9] = [
    b"co", b"com", b"net", b"org", b"gov", b"ac", b"edu", b"ne", b"or",
];

/// The wire-format span of a name's registrable domain (eTLD+1): the last two labels, or three
/// under common second-level public suffixes. An approximation of the Public Suffix List that
/// needs no data file. `None` for the root, single labels, and reverse-lookup names. No
/// allocation: this runs for every query.
fn registrable_span(wire: &[u8]) -> Option<&[u8]> {
    let mut starts = [0usize; 128];
    let (mut n, mut i) = (0usize, 0usize);
    while i < wire.len() && n < starts.len() {
        let len = usize::from(wire[i]);
        if len == 0 || i + 1 + len > wire.len() {
            break;
        }
        starts[n] = i;
        n += 1;
        i += 1 + len;
    }
    if n < 2 {
        return None;
    }
    let label = |k: usize| {
        let at = starts[k];
        &wire[at + 1..at + 1 + usize::from(wire[at])]
    };
    if label(n - 1).eq_ignore_ascii_case(b"arpa") {
        return None;
    }
    let take = if label(n - 1).len() == 2
        && n >= 3
        && SECOND_LEVEL
            .iter()
            .any(|s| label(n - 2).eq_ignore_ascii_case(s))
    {
        3
    } else {
        2
    };
    Some(&wire[starts[n - take]..i])
}

/// FNV-1a over the span, lowercased.
fn span_fp(span: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for x in span {
        h ^= u64::from(x.to_ascii_lowercase());
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// The span as dotted, lowercased text (at most [`MAX_DOMAIN`] characters).
fn span_text(span: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < span.len() {
        let len = usize::from(span[i]);
        if i + 1 + len > span.len() {
            break;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(&span[i + 1..i + 1 + len]).to_ascii_lowercase());
        i += 1 + len;
    }
    out.chars().take(MAX_DOMAIN).collect()
}

/// The fingerprint of a dotted domain (for `ignore_domains`), as [`span_fp`] computes it.
fn text_fp(domain: &str) -> u64 {
    let mut wire = Vec::new();
    for l in domain.trim_end_matches('.').split('.') {
        wire.push(u8::try_from(l.len()).unwrap_or(u8::MAX));
        wire.extend_from_slice(l.as_bytes());
    }
    span_fp(&wire)
}

/// The registrable domain (eTLD+1) of a wire-format name, lowercased (see
/// [`registrable_span`]).
pub fn registrable(wire: &[u8]) -> Option<String> {
    registrable_span(wire).map(span_text)
}

/// Mean and standard deviation of the gaps (at most [`INTERVALS`] of them).
fn mean_std(xs: &[u16]) -> (f64, f64) {
    let n = f64::from(u16::try_from(xs.len()).unwrap_or(u16::MAX).max(1));
    let mean = xs.iter().map(|x| f64::from(*x)).sum::<f64>() / n;
    let var = xs
        .iter()
        .map(|x| (f64::from(*x) - mean) * (f64::from(*x) - mean))
        .sum::<f64>()
        / n;
    (mean, var.sqrt())
}

impl Engine {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            clients: BTreeMap::new(),
            hour: 0,
            day: 0,
            findings: Vec::new(),
            evicted: 0,
            total: BTreeMap::new(),
            ignore_fps: Vec::new(),
        }
        .with_ignores()
    }

    fn with_ignores(mut self) -> Self {
        self.ignore_fps = self
            .settings
            .ignore_domains
            .iter()
            .map(|d| text_fp(d))
            .collect();
        self
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Replaces the settings (state is kept).
    pub fn set_settings(&mut self, s: Settings) {
        self.ignore_fps = s.ignore_domains.iter().map(|d| text_fp(d)).collect();
        self.settings = s;
    }

    /// Findings so far, oldest first.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Devices with state.
    pub fn clients(&self) -> usize {
        self.clients.len()
    }

    /// Approximate memory of one device's state, in bytes (the T3.13 budget is 4 KiB).
    pub fn client_bytes(&self, ip: [u8; 16]) -> Option<usize> {
        let c = self.clients.get(&ip)?;
        Some(
            std::mem::size_of::<Client>()
                + c.rate.capacity() * std::mem::size_of::<Ewm>()
                + c.tracked.capacity() * std::mem::size_of::<Tracked>()
                + c.tracked.iter().map(|t| t.domain.capacity()).sum::<usize>()
                + c.learned.capacity() * std::mem::size_of::<(u32, u32)>()
                + c.new_samples.iter().map(String::capacity).sum::<usize>()
                + c.new_samples.capacity() * std::mem::size_of::<String>(),
        )
    }

    fn is_learned(&self, c: &Client, now_s: u64) -> bool {
        now_s.saturating_sub(c.first_s) >= u64::from(self.settings.learning_days) * 86_400
    }

    /// Folds in one query from `client` for `wire` at `ts_s` (event time, non-decreasing).
    pub fn observe(&mut self, ts_s: u64, client: [u8; 16], wire: &[u8]) {
        let hour = ts_s / 3600;
        if self.hour == 0 {
            self.hour = hour;
            self.day = ts_s / 86_400;
        }
        while hour > self.hour {
            self.close_hour();
        }
        if hour < self.hour {
            return; // late event from a closed window
        }
        if !self.clients.contains_key(&client) && self.clients.len() >= self.settings.max_clients {
            // The least recently seen device makes room (ties: lowest address).
            if let Some(k) = self
                .clients
                .iter()
                .min_by_key(|(k, c)| (c.last_s, **k))
                .map(|(k, _)| *k)
            {
                self.clients.remove(&k);
                self.evicted += 1;
            }
        }
        let day = u32::try_from(ts_s / 86_400).unwrap_or(u32::MAX);
        let c = self
            .clients
            .entry(client)
            .or_insert_with(|| Client::new(ts_s));
        c.last_s = ts_s;
        c.hour_count = c.hour_count.saturating_add(1);
        let Some(span) = registrable_span(wire) else {
            return;
        };
        let fp = span_fp(span);
        if self.ignore_fps.contains(&fp) {
            return;
        }
        c.learn(fp, span, day);
        c.track(fp, span, ts_s);
    }

    fn push(&mut self, f: Finding) {
        *self.total.entry(f.kind).or_insert(0) += 1;
        if self.findings.len() >= MAX_FINDINGS {
            self.findings.remove(0);
        }
        self.findings.push(f);
    }

    /// Closes the current hour (and the day, at midnight UTC): evaluates and updates baselines.
    fn close_hour(&mut self) {
        let start = self.hour * 3600;
        let end = start + 3600;
        let hod = usize::try_from(self.hour % 24).unwrap_or(0);
        let mult = self.settings.sensitivity.mult();
        let mut out = Vec::new();
        let keys: Vec<[u8; 16]> = self.clients.keys().copied().collect();
        for key in keys {
            let learned = self
                .clients
                .get(&key)
                .is_some_and(|c| self.is_learned(c, end));
            let Some(client) = self.clients.get_mut(&key) else {
                continue;
            };
            // Domain volume first, so a rate spike one domain explains is reported once.
            let explained = Self::close_pairs(client, key, start, end, learned, mult, &mut out);
            if let Some(f) = Self::close_rate(client, key, start, hod, learned, mult, explained) {
                out.push(f);
            }
        }
        for f in out {
            self.push(f);
        }
        self.hour += 1;
        if self.hour * 3600 / 86_400 > self.day {
            self.close_day();
        }
    }

    /// Domain volume and beaconing for one device's tracked pairs. Returns how much of the
    /// hour's excess the reported volume findings explain.
    fn close_pairs(
        client: &mut Client,
        key: [u8; 16],
        start: u64,
        end: u64,
        learned: bool,
        mult: f32,
        out: &mut Vec<Finding>,
    ) -> f32 {
        let mut explained = 0.0;
        for t in &mut client.tracked {
            let x = count(t.hour);
            let (spread, thr) = t.volume.bound(mult, 5.0, 0.25);
            let mature = end.saturating_sub(t.since_s) >= 86_400 && t.volume.n >= 24;
            if learned && mature && x >= 200.0 && x > thr && x >= 3.0 * t.volume.mean {
                explained += x - t.volume.mean;
                out.push(Finding {
                    kind: Kind::DomainVolume,
                    client: key,
                    domain: Some(t.domain.clone()),
                    window_start_s: start,
                    window_s: 3600,
                    observed: f64::from(x),
                    baseline: f64::from(t.volume.mean),
                    spread: f64::from(spread),
                    threshold: f64::from(thr),
                    detail: format!(
                        "{x:.0} queries in an hour; usually {:.0} ± {spread:.0}",
                        t.volume.mean
                    ),
                });
                // An alerted spike doesn't become the new normal.
            } else {
                t.volume.update(x, 1.0 / 48.0);
            }
            // Beaconing: regular gaps this hour.
            let regular = t.n_intervals >= 10 && {
                let (m, s) = mean_std(t.gaps());
                (30.0..=3600.0).contains(&m) && s <= (0.05 * m).max(2.0)
            };
            if regular && t.hour >= 1 {
                t.regular_hours += 1;
            } else if t.hour > 0 || end.saturating_sub(t.last_s) > 3600 {
                t.regular_hours = 0;
            }
            if t.regular_hours >= BEACON_HOURS {
                if !learned {
                    t.known_periodic = true;
                } else if !t.known_periodic && !t.reported_beacon {
                    t.reported_beacon = true;
                    let (m, s) = mean_std(t.gaps());
                    out.push(Finding {
                        kind: Kind::Beacon,
                        client: key,
                        domain: Some(t.domain.clone()),
                        window_start_s: end - u64::from(t.regular_hours) * 3600,
                        window_s: t.regular_hours * 3600,
                        observed: m,
                        baseline: 0.0,
                        spread: s,
                        threshold: (0.05 * m).max(2.0),
                        detail: format!(
                            "every {m:.0} s ± {s:.1} s for {} hours; it wasn't periodic before",
                            t.regular_hours
                        ),
                    });
                }
            }
            t.hour = 0;
        }
        explained
    }

    /// The rate-spike check for one device, unless domain findings explain most of it.
    fn close_rate(
        client: &mut Client,
        key: [u8; 16],
        start: u64,
        hod: usize,
        learned: bool,
        mult: f32,
        explained: f32,
    ) -> Option<Finding> {
        let x = count(client.hour_count);
        client.hour_count = 0;
        let r = &mut client.rate[hod];
        let (spread, thr) = r.bound(mult, 10.0, 0.25);
        if learned && r.n >= 3 && x >= 300.0 && x > thr && x >= 2.0 * r.mean {
            (explained < 0.5 * (x - r.mean)).then(|| Finding {
                kind: Kind::RateSpike,
                client: key,
                domain: None,
                window_start_s: start,
                window_s: 3600,
                observed: f64::from(x),
                baseline: f64::from(r.mean),
                spread: f64::from(spread),
                threshold: f64::from(thr),
                detail: format!(
                    "{x:.0} queries in an hour; usually {:.0} ± {spread:.0} at this hour",
                    r.mean
                ),
            })
        } else {
            r.update(x, 1.0 / 7.0);
            None
        }
    }

    fn close_day(&mut self) {
        let start = self.day * 86_400;
        let end = start + 86_400;
        let mult = self.settings.sensitivity.mult();
        let mut out = Vec::new();
        let keys: Vec<[u8; 16]> = self.clients.keys().copied().collect();
        for key in keys {
            let learned = self
                .clients
                .get(&key)
                .is_some_and(|c| self.is_learned(c, end));
            let Some(client) = self.clients.get_mut(&key) else {
                continue;
            };
            let x = count(client.new_today);
            let (spread, thr) = client.daily_new.bound(mult, 2.0, 0.25);
            // Day one teaches the whole set, so its count isn't part of the baseline.
            let first_day = client.first_s >= start;
            if learned && client.daily_new.n >= 3 && x >= 20.0 && x > thr {
                out.push(Finding {
                    kind: Kind::Drift,
                    client: key,
                    domain: None,
                    window_start_s: start,
                    window_s: 86_400,
                    observed: f64::from(x),
                    baseline: f64::from(client.daily_new.mean),
                    spread: f64::from(spread),
                    threshold: f64::from(thr),
                    detail: format!(
                        "{x:.0} new domains today (usually {:.0} ± {spread:.0}), e.g. {}",
                        client.daily_new.mean,
                        client.new_samples.join(", ")
                    ),
                });
            } else if !first_day {
                client.daily_new.update(x, 1.0 / 7.0);
            }
            client.new_today = 0;
            client.new_samples.clear();
        }
        for f in out {
            self.push(f);
        }
        self.day += 1;
    }
}

#[cfg(test)]
#[path = "anomaly_tests.rs"]
mod tests;
