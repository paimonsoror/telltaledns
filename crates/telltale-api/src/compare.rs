//! REQ: OBS-028 (ADR-128) — the node odd-one-out comparison: every node's answered count,
//! SERVFAIL, slow, from-cache, and upstream-failure shares, p50 and p99, and q/s over the same
//! window, with the node that deviates from the others named, the bucket it started deviating
//! in, and honest notes for small denominators. Robust statistics only: leave-one-out median and
//! MAD for three or more nodes, Wilson 95 % intervals for two.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::latency_heatmap::BOUNDS_US;
use crate::model::{Step, TimeBucket};
use crate::problem::Problem;
use crate::{Shared, blocking, pick, time_param};

/// At most this many points per sparkline series (buckets are summed into wider spans).
pub const SERIES_POINTS: usize = 240;
/// A node needs this many answers before its latency percentiles are compared.
pub const MIN_LATENCY_ANSWERS: u64 = 100;
/// The robust z (or its two-node equivalent) at which a node is odd.
const Z_ODD: f64 = 3.0;
/// MAD to standard deviation for a normal distribution.
const MAD_SCALE: f64 = 1.4826;
/// The floor under a ratio's spread (a fraction: 0.05 percentage points).
const RATIO_FLOOR: f64 = 0.0005;
/// The floor under a latency's spread, as a share of the others' value.
const LATENCY_FLOOR: f64 = 0.10;
/// The normal quantile for a 95 % interval.
const Z95: f64 = 1.96;

/// `GET /api/v1/cluster/compare` parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CompareParams {
    /// Start: RFC 3339 or relative (default 24 hours ago).
    #[param(example = "-24h")]
    pub from: Option<String>,
    /// End (default now).
    pub to: Option<String>,
    /// `minute` (up to 48 hours) or `hour` (up to 400 days). Default: minute up to 48 hours,
    /// hour beyond.
    pub step: Option<String>,
}

/// One node's ratios over time, for the sparklines (at most 240 points: buckets summed into
/// spans). A span without a base (no answers, no upstream exchanges) is null.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeSeries {
    /// Each span's start, Unix seconds.
    pub start: Vec<u64>,
    pub servfail_pct: Vec<Option<f64>>,
    pub slow_pct: Vec<Option<f64>>,
    pub from_cache_pct: Vec<Option<f64>>,
    pub upstream_fail_pct: Vec<Option<f64>>,
    pub qps: Vec<f64>,
    pub p99_us: Vec<Option<u64>>,
}

/// One node's numbers over the window.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeNumbers {
    pub node_id: String,
    /// Its pod name, else its site, else its ID.
    pub label: String,
    /// The node answering this request.
    pub this_node: bool,
    /// Answers (queries less the dropped ones).
    pub answered: u64,
    pub servfail: u64,
    pub slow: u64,
    /// Answered from the cache (fresh, refreshed, or stale).
    pub from_cache: u64,
    pub upstream_queries: u64,
    pub upstream_failures: u64,
    /// Queries per second over the window.
    pub qps: f64,
    /// Percentages, 0–100.
    pub servfail_pct: f64,
    pub slow_pct: f64,
    pub from_cache_pct: f64,
    pub upstream_fail_pct: f64,
    /// Wilson 95 % intervals of the percentages, `[low, high]`, by metric name.
    pub intervals: BTreeMap<String, [f64; 2]>,
    /// From the latency histograms (absent without any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p50_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p99_us: Option<u64>,
    pub series: NodeSeries,
}

/// A node that stands out on one metric, or a note on why it only looks like it does.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeFinding {
    /// `servfailPct`, `slowPct`, `fromCachePct`, `upstreamFailPct`, `p50Us`, or `p99Us`.
    pub metric: String,
    pub node_id: String,
    pub label: String,
    /// `odd` (it deviates from the others) or `note` (it looks worse only because its base is
    /// smaller). Never an error: this is a lens, not a condition.
    pub level: String,
    /// The node's value (percent, or µs).
    pub observed: f64,
    /// The others' value: their median, or the other node's.
    pub others: f64,
    /// The spread the deviation is measured against (1.4826 × MAD, floored).
    pub spread: f64,
    /// When the deviation started (RFC 3339): the change point of the node's excess over the
    /// others. Absent when it covers the whole window, or for latency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub odd_since: Option<String>,
    pub detail: String,
}

/// REQ: OBS-028 — every node side by side over one window.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeCompare {
    pub from: String,
    pub to: String,
    /// `minute` or `hour`.
    pub step: String,
    /// This node first, then the others in the cluster view's order. Witnesses don't answer
    /// DNS and aren't listed.
    pub nodes: Vec<NodeNumbers>,
    /// `odd` findings first, then notes.
    pub findings: Vec<NodeFinding>,
    /// Some node had answers without latency counts (an older build's): its percentiles are
    /// missing.
    pub partial: bool,
    /// Nodes that didn't answer; the findings cover the rest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

/// One node's buckets, as read.
#[derive(Debug, Clone, Default)]
pub struct NodeInput {
    pub node_id: String,
    pub label: String,
    pub this_node: bool,
    pub buckets: Vec<TimeBucket>,
}

/// The counts behind every metric, for one bucket or a sum of them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Counts {
    total: u64,
    answered: u64,
    servfail: u64,
    slow: u64,
    cached: u64,
    upq: u64,
    upf: u64,
    hist: [u64; BOUNDS_US.len() + 1],
}

impl Counts {
    fn of(b: &TimeBucket) -> Self {
        let st = |k: &str| u64::from(b.by_status.get(k).copied().unwrap_or(0));
        let mut hist = [0u64; BOUNDS_US.len() + 1];
        // Per path only: the `upstream:<name>` rows count the same answers again.
        for row in b
            .latency_hist
            .iter()
            .filter(|(k, _)| !k.starts_with("upstream:"))
            .map(|(_, r)| r)
        {
            for (h, n) in hist.iter_mut().zip(row) {
                *h += u64::from(*n);
            }
        }
        Self {
            total: u64::from(b.total),
            answered: u64::from(b.total).saturating_sub(st("dropped")),
            servfail: u64::from(b.by_rcode.get("SERVFAIL").copied().unwrap_or(0)),
            slow: u64::from(b.slow),
            cached: st("cached") + st("stale") + st("refreshed"),
            upq: u64::from(b.upstream_queries),
            upf: u64::from(b.upstream_failures),
            hist,
        }
    }

    fn add(&mut self, o: &Self) {
        self.total += o.total;
        self.answered += o.answered;
        self.servfail += o.servfail;
        self.slow += o.slow;
        self.cached += o.cached;
        self.upq += o.upq;
        self.upf += o.upf;
        for (h, n) in self.hist.iter_mut().zip(o.hist) {
            *h += n;
        }
    }

    fn hist_total(&self) -> u64 {
        self.hist.iter().sum()
    }
}

/// The metrics compared, in the order findings list them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Metric {
    Servfail,
    Slow,
    FromCache,
    UpstreamFail,
    P50,
    P99,
}

impl Metric {
    const ALL: [Self; 6] = [
        Self::Servfail,
        Self::Slow,
        Self::FromCache,
        Self::UpstreamFail,
        Self::P50,
        Self::P99,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Servfail => "servfailPct",
            Self::Slow => "slowPct",
            Self::FromCache => "fromCachePct",
            Self::UpstreamFail => "upstreamFailPct",
            Self::P50 => "p50Us",
            Self::P99 => "p99Us",
        }
    }

    fn words(self) -> &'static str {
        match self {
            Self::Servfail => "SERVFAIL share",
            Self::Slow => "slow share",
            Self::FromCache => "from-cache share",
            Self::UpstreamFail => "upstream failure share",
            Self::P50 => "p50",
            Self::P99 => "p99",
        }
    }

    /// `(bad, base)` for a ratio metric.
    fn ratio(self, c: &Counts) -> Option<(u64, u64)> {
        match self {
            Self::Servfail => Some((c.servfail, c.answered)),
            Self::Slow => Some((c.slow, c.answered)),
            Self::FromCache => Some((c.cached, c.answered)),
            Self::UpstreamFail => Some((c.upf, c.upq)),
            Self::P50 | Self::P99 => None,
        }
    }

    /// The "same bad count, smaller base" note fits counts of bad things, not the cache share.
    fn counts_bad(self) -> bool {
        matches!(self, Self::Servfail | Self::Slow | Self::UpstreamFail)
    }
}

/// Rounds to `places` decimals, so the same input always prints the same JSON.
fn round(x: f64, places: i32) -> f64 {
    let m = 10f64.powi(places);
    let r = (x * m).round() / m;
    if r == 0.0 { 0.0 } else { r }
}

#[allow(clippy::cast_precision_loss)] // counts far below 2^52
fn frac(bad: u64, base: u64) -> f64 {
    if base == 0 {
        0.0
    } else {
        bad as f64 / base as f64
    }
}

/// The Wilson 95 % interval of `bad / base`, as fractions.
#[allow(clippy::cast_precision_loss)]
pub fn wilson(bad: u64, base: u64) -> (f64, f64) {
    if base == 0 {
        return (0.0, 1.0);
    }
    let n = base as f64;
    let p = bad as f64 / n;
    let z2 = Z95 * Z95;
    let d = 1.0 + z2 / n;
    let centre = (p + z2 / (2.0 * n)) / d;
    let half = Z95 / d * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt();
    ((centre - half).max(0.0), (centre + half).min(1.0))
}

/// The `q` quantile of a latency histogram, interpolated within its bucket (µs); the overflow
/// bucket reads as its lower bound.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn percentile(hist: &[u64], q: f64) -> Option<u64> {
    let total: u64 = hist.iter().sum();
    if total == 0 {
        return None;
    }
    // Less a hair, so 0.99 × 100 is 99, not 100.
    let target = (q * total as f64 - 1e-9).ceil().max(1.0);
    let mut seen = 0u64;
    for (i, &n) in hist.iter().enumerate() {
        if n == 0 {
            continue;
        }
        if (seen + n) as f64 >= target {
            let lo = if i == 0 { 0 } else { BOUNDS_US[i - 1] };
            let Some(&hi) = BOUNDS_US.get(i) else {
                return Some(lo);
            };
            let share = (target - seen as f64) / n as f64;
            return Some(lo + ((hi - lo) as f64 * share).round() as u64);
        }
        seen += n;
    }
    BOUNDS_US.last().copied()
}

fn median(xs: &mut [f64]) -> f64 {
    xs.sort_by(f64::total_cmp);
    let n = xs.len();
    match n {
        0 => 0.0,
        _ if n % 2 == 1 => xs[n / 2],
        _ => f64::midpoint(xs[n / 2 - 1], xs[n / 2]),
    }
}

/// One node's aligned per-bucket counts and their sum.
struct Prepared {
    input: NodeInput,
    per: Vec<Counts>,
    sum: Counts,
}

/// A node's value for a metric (a fraction, or µs), when it has a base for it.
#[allow(clippy::cast_precision_loss)]
fn value(m: Metric, c: &Counts) -> Option<f64> {
    if let Some((bad, base)) = m.ratio(c) {
        return (base > 0).then(|| frac(bad, base));
    }
    if c.hist_total() < MIN_LATENCY_ANSWERS {
        return None;
    }
    let q = if m == Metric::P50 { 0.50 } else { 0.99 };
    percentile(&c.hist, q).map(|v| v as f64)
}

/// The deviation test: how far `x` sits from the others, and whether it is odd. `others` are
/// the other nodes' counts (at least one).
struct Verdict {
    odd: bool,
    others: f64,
    spread: f64,
}

fn verdict(m: Metric, me: &Counts, others: &[&Counts]) -> Option<Verdict> {
    let x = value(m, me)?;
    let mut xs: Vec<f64> = others.iter().filter_map(|c| value(m, c)).collect();
    if xs.is_empty() {
        return None;
    }
    let single = xs.len() == 1;
    let med = median(&mut xs);
    let floor = if m.ratio(me).is_some() {
        RATIO_FLOOR
    } else {
        LATENCY_FLOOR * med
    };
    let mut dev: Vec<f64> = xs.iter().map(|v| (v - med).abs()).collect();
    let mad = if single { 0.0 } else { median(&mut dev) };
    let spread = MAD_SCALE * mad.max(floor);
    let far = spread > 0.0 && (x - med).abs() / spread >= Z_ODD;
    let odd = match m.ratio(me) {
        // Two nodes: the intervals must not overlap, and the worse one is the odd one.
        Some((bad, base)) if single => {
            let (o_bad, o_base) = others.iter().find_map(|c| m.ratio(c))?;
            let (lo, hi) = wilson(bad, base);
            let (olo, ohi) = wilson(o_bad, o_base);
            let apart = hi < olo || ohi < lo;
            let worse = if m == Metric::FromCache {
                x < med
            } else {
                x > med
            };
            far && apart && worse
        }
        // Three or more: the node's own interval must leave out the others' median, so a
        // handful of answers can't make it odd.
        Some((bad, base)) => {
            let (lo, hi) = wilson(bad, base);
            far && (med < lo || med > hi)
        }
        None if single => far && x > med,
        None => far,
    };
    Some(Verdict {
        odd,
        others: med,
        spread,
    })
}

/// Counts close enough to call the same: within 3, or within a third of the larger.
fn about_the_same(a: u64, b: u64) -> bool {
    a.abs_diff(b) <= 3.max(a.max(b) / 3)
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn median_u64(xs: &[u64]) -> u64 {
    let mut v: Vec<f64> = xs.iter().map(|&x| x as f64).collect();
    median(&mut v).round() as u64
}

/// The change point of the node's excess over the others: the latest bucket before which the
/// cumulative excess is lowest. `None` when the excess runs through the whole window.
#[allow(clippy::cast_precision_loss)]
fn odd_since(m: Metric, me: &Prepared, others: &[&Prepared], higher: bool) -> Option<usize> {
    let pooled = |i: usize| {
        others.iter().fold((0u64, 0u64), |(b, n), o| {
            let (ob, on) = m.ratio(&o.per[i]).unwrap_or((0, 0));
            (b + ob, n + on)
        })
    };
    let window = others.iter().fold((0u64, 0u64), |(b, n), o| {
        let (ob, on) = m.ratio(&o.sum).unwrap_or((0, 0));
        (b + ob, n + on)
    });
    let window_rate = frac(window.0, window.1);
    let sign = if higher { 1.0 } else { -1.0 };
    let mut sum = 0.0;
    let mut sums = Vec::with_capacity(me.per.len() + 1);
    sums.push(0.0);
    for (i, c) in me.per.iter().enumerate() {
        let (bad, base) = m.ratio(c).unwrap_or((0, 0));
        let (ob, on) = pooled(i);
        let rate = if on > 0 { frac(ob, on) } else { window_rate };
        sum += sign * (bad as f64 - base as f64 * rate);
        sums.push(sum);
    }
    let lowest = sums.iter().copied().fold(f64::INFINITY, f64::min);
    let eps = 1e-6 * (me.sum.answered.max(1) as f64);
    let k = sums.iter().rposition(|&s| s <= lowest + eps)?;
    // The last prefix is the whole window: nothing after it to deviate.
    if k == 0 || k >= me.per.len() {
        return None;
    }
    // Still odd from there on?
    let mut mine = Counts::default();
    for c in &me.per[k..] {
        mine.add(c);
    }
    let theirs: Vec<Counts> = others
        .iter()
        .map(|o| {
            let mut c = Counts::default();
            for x in &o.per[k..] {
                c.add(x);
            }
            c
        })
        .collect();
    let refs: Vec<&Counts> = theirs.iter().collect();
    verdict(m, &mine, &refs).is_some_and(|v| v.odd).then_some(k)
}

fn pct_text(f: f64) -> String {
    let p = f * 100.0;
    if p >= 10.0 {
        format!("{p:.1} %")
    } else if p >= 0.1 {
        format!("{p:.2} %")
    } else {
        format!("{p:.3} %")
    }
}

#[allow(clippy::cast_precision_loss)]
fn us_text(us: u64) -> String {
    if us < 1_000 {
        format!("{us} µs")
    } else if us < 1_000_000 {
        format!("{:.1} ms", us as f64 / 1_000.0)
    } else {
        format!("{:.2} s", us as f64 / 1_000_000.0)
    }
}

/// Every node's numbers over `starts`-aligned buckets, and the findings.
#[allow(
    clippy::cast_precision_loss,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn compare(
    inputs: Vec<NodeInput>,
    step_s: u64,
    window_s: u64,
) -> (Vec<NodeNumbers>, Vec<NodeFinding>, bool) {
    // One timeline for everyone: the union of the buckets' starts.
    let mut index: BTreeMap<u64, usize> = inputs
        .iter()
        .flat_map(|n| n.buckets.iter().map(|b| (b.start_unix_seconds, 0)))
        .collect();
    for (i, v) in index.values_mut().enumerate() {
        *v = i;
    }
    let starts: Vec<u64> = index.keys().copied().collect();
    let mut partial = false;
    let prepared: Vec<Prepared> = inputs
        .into_iter()
        .map(|input| {
            let mut per = vec![Counts::default(); starts.len()];
            for b in &input.buckets {
                if let Some(&i) = index.get(&b.start_unix_seconds) {
                    per[i].add(&Counts::of(b));
                }
            }
            let mut sum = Counts::default();
            for c in &per {
                sum.add(c);
            }
            if sum.answered > 0 && sum.hist_total() == 0 {
                partial = true;
            }
            Prepared { input, per, sum }
        })
        .collect();

    let span = starts.len().div_ceil(SERIES_POINTS).max(1);
    let numbers: Vec<NodeNumbers> = prepared
        .iter()
        .map(|p| {
            let c = &p.sum;
            let pct = |bad, base| round(frac(bad, base) * 100.0, 5);
            let mut intervals = BTreeMap::new();
            for m in [
                Metric::Servfail,
                Metric::Slow,
                Metric::FromCache,
                Metric::UpstreamFail,
            ] {
                if let Some((bad, base)) = m.ratio(c).filter(|r| r.1 > 0) {
                    let (lo, hi) = wilson(bad, base);
                    intervals.insert(
                        m.name().to_owned(),
                        [round(lo * 100.0, 5), round(hi * 100.0, 5)],
                    );
                }
            }
            let mut series = NodeSeries::default();
            for (chunk, first) in p.per.chunks(span).zip(starts.iter().step_by(span)) {
                let mut s = Counts::default();
                for x in chunk {
                    s.add(x);
                }
                let opt = |bad, base| (base > 0).then(|| round(frac(bad, base) * 100.0, 5));
                series.start.push(*first);
                series.servfail_pct.push(opt(s.servfail, s.answered));
                series.slow_pct.push(opt(s.slow, s.answered));
                series.from_cache_pct.push(opt(s.cached, s.answered));
                series.upstream_fail_pct.push(opt(s.upf, s.upq));
                series.qps.push(round(
                    s.total as f64 / (chunk.len() as u64 * step_s) as f64,
                    3,
                ));
                series.p99_us.push(percentile(&s.hist, 0.99));
            }
            NodeNumbers {
                node_id: p.input.node_id.clone(),
                label: p.input.label.clone(),
                this_node: p.input.this_node,
                answered: c.answered,
                servfail: c.servfail,
                slow: c.slow,
                from_cache: c.cached,
                upstream_queries: c.upq,
                upstream_failures: c.upf,
                qps: round(c.total as f64 / window_s.max(1) as f64, 3),
                servfail_pct: pct(c.servfail, c.answered),
                slow_pct: pct(c.slow, c.answered),
                from_cache_pct: pct(c.cached, c.answered),
                upstream_fail_pct: pct(c.upf, c.upq),
                intervals,
                p50_us: percentile(&c.hist, 0.50),
                p99_us: percentile(&c.hist, 0.99),
                series,
            }
        })
        .collect();

    let mut findings = Vec::new();
    // Only nodes that answered anything are compared.
    let live: Vec<&Prepared> = prepared.iter().filter(|p| p.sum.total > 0).collect();
    if live.len() >= 2 {
        for m in Metric::ALL {
            for (i, me) in live.iter().enumerate() {
                let others: Vec<&Prepared> = live
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, p)| *p)
                    .collect();
                let other_counts: Vec<&Counts> = others.iter().map(|o| &o.sum).collect();
                let Some(v) = verdict(m, &me.sum, &other_counts) else {
                    continue;
                };
                let Some(x) = value(m, &me.sum) else {
                    continue;
                };
                let ratio = m.ratio(&me.sum).is_some();
                let (who, whose) = if others.len() == 1 {
                    let l = others[0].input.label.clone();
                    (l.clone(), format!("{l}'s"))
                } else {
                    ("the others".to_owned(), "the others'".to_owned())
                };
                let shown = |v: f64| {
                    if ratio {
                        round(v * 100.0, 5)
                    } else {
                        v.round()
                    }
                };
                let text = |v: f64| {
                    if ratio {
                        pct_text(v)
                    } else {
                        us_text(v.round() as u64)
                    }
                };
                if v.odd {
                    let higher = x > v.others;
                    let since = if ratio {
                        odd_since(m, me, &others, higher)
                    } else {
                        None
                    };
                    let odd_since =
                        since.map(|k| crate::time::format_us(starts[k].saturating_mul(1_000_000)));
                    let when = odd_since
                        .as_deref()
                        .map_or(String::new(), |t| format!(", since {t}"));
                    findings.push(NodeFinding {
                        metric: m.name().into(),
                        node_id: me.input.node_id.clone(),
                        label: me.input.label.clone(),
                        level: "odd".into(),
                        observed: shown(x),
                        others: shown(v.others),
                        spread: shown(v.spread),
                        odd_since,
                        detail: format!(
                            "{} {} is {}, {} than {whose} {}{when}",
                            me.input.label,
                            m.words(),
                            text(x),
                            if higher { "higher" } else { "lower" },
                            text(v.others),
                        ),
                    });
                    continue;
                }
                // REQ: OBS-028 — the same bad count on a much smaller base only looks worse.
                if !m.counts_bad() || x <= v.others {
                    continue;
                }
                let Some((bad, base)) = m.ratio(&me.sum) else {
                    continue;
                };
                let their: Vec<(u64, u64)> = others
                    .iter()
                    .filter_map(|o| m.ratio(&o.sum))
                    .filter(|r| r.1 > 0)
                    .collect();
                let o_bad = median_u64(&their.iter().map(|r| r.0).collect::<Vec<_>>());
                let o_base = median_u64(&their.iter().map(|r| r.1).collect::<Vec<_>>());
                if bad > 0 && about_the_same(bad, o_bad) && base.saturating_mul(3) < o_base {
                    findings.push(NodeFinding {
                        metric: m.name().into(),
                        node_id: me.input.node_id.clone(),
                        label: me.input.label.clone(),
                        level: "note".into(),
                        observed: shown(x),
                        others: shown(v.others),
                        spread: shown(v.spread),
                        odd_since: None,
                        detail: format!(
                            "same bad count as {who} ({bad} vs {o_bad}) on {:.0} % of the traffic: \
                             a smaller base, not more failures",
                            frac(base, o_base) * 100.0
                        ),
                    });
                }
            }
        }
    }
    findings.sort_by_key(|f| f.level != "odd");
    (numbers, findings, partial)
}

/// Compare the nodes.
///
/// Every node side by side over the same window: answered count, q/s, SERVFAIL share, slow
/// share, from-cache share, upstream failure share (each with a Wilson 95 % interval), p50 and
/// p99 (from the latency histograms), and per-node sparkline series. `findings` names a node
/// that deviates from the others (`odd`: robust z ≥ 3 against the others' median and MAD with
/// three or more nodes, non-overlapping intervals with two) with the time it started
/// (`oddSince`), and `note`s a node that only looks worse because it has the same bad count on a
/// much smaller base. Use it to answer "is something odd with that node?". Nodes that didn't
/// answer are in `missingNodes`. Example: `GET /api/v1/cluster/compare?from=-24h`.
#[utoipa::path(get, path = "/api/v1/cluster/compare", tag = "system", params(CompareParams),
    responses(
        (status = 200, body = NodeCompare, description = "The nodes and the findings."),
        (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it.")))]
pub(crate) async fn cluster_compare(
    State(b): State<Shared>,
    Query(p): Query<CompareParams>,
) -> Result<Json<NodeCompare>, Problem> {
    let now = b.now_unix_seconds();
    let from = time_param(p.from.as_deref(), now.saturating_sub(86_400), now, "from")?;
    let to = time_param(p.to.as_deref(), now + 1, now, "to")?;
    if from >= to {
        return Err(Problem::invalid("`from` must be before `to`"));
    }
    let step = match p.step.as_deref() {
        None if to - from <= 48 * 3600 + 3600 => Step::Minute,
        None | Some("hour") => Step::Hour,
        Some("minute") => Step::Minute,
        Some(s) => {
            return Err(Problem::invalid(format!(
                "`step`: `{s}` isn't minute or hour"
            )));
        }
    };
    let max_s = if step == Step::Minute {
        48 * 3600
    } else {
        400 * 86_400
    };
    if to - from > max_s + 3600 {
        return Err(
            Problem::invalid("`from`: the window is too long for this step").hint(
                "Minutes reach back 48 hours; use step=hour for longer windows (up to 400 days).",
            ),
        );
    }
    let bk = Arc::clone(&b);
    let view = blocking(move || Ok(bk.cluster())).await?;
    // (node ID, label, this node, scope)
    let targets: Vec<(String, String, bool, Option<String>)> = if view.enabled {
        view.nodes
            .iter()
            .filter(|n| !n.witness)
            .map(|n| {
                let label = n
                    .pod
                    .clone()
                    .filter(|s| !s.is_empty())
                    .or_else(|| Some(n.site.clone()).filter(|s| !s.is_empty()))
                    .unwrap_or_else(|| n.node_id.clone());
                let scope = (!n.this_node).then(|| format!("node:{}", n.node_id));
                (n.node_id.clone(), label, n.this_node, scope)
            })
            .collect()
    } else {
        vec![("local".into(), "this node".into(), true, None)]
    };
    // Every node's read at once.
    let mut reads = Vec::new();
    for (id, label, me, scope) in targets {
        let nb = match scope.as_deref() {
            None => b.local().unwrap_or_else(|| Arc::clone(&b)),
            Some(s) => pick(&b, Some(s))?,
        };
        let task = tokio::task::spawn_blocking(move || {
            let buckets = nb.timeseries(step, from, to);
            (buckets, nb.missing_nodes())
        });
        reads.push((id, label, me, task));
    }
    let mut inputs = Vec::new();
    let mut missing_nodes = Vec::new();
    for (node_id, label, this_node, task) in reads {
        match task.await {
            Ok((buckets, missing)) if missing.is_empty() => inputs.push(NodeInput {
                node_id,
                label,
                this_node,
                buckets,
            }),
            _ => missing_nodes.push(label),
        }
    }
    let step_s = if step == Step::Hour { 3600 } else { 60 };
    let (nodes, findings, partial) = compare(inputs, step_s, to - from);
    Ok(Json(NodeCompare {
        from: crate::time::format_us(from.saturating_mul(1_000_000)),
        to: crate::time::format_us(to.saturating_mul(1_000_000)),
        step: if step == Step::Hour { "hour" } else { "minute" }.into(),
        nodes,
        findings,
        partial,
        missing_nodes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minute bucket with `answered` answers, `servfail` of them SERVFAIL, all in the 1–2.5 ms
    /// latency bucket.
    fn minute(start: u64, answered: u32, servfail: u32) -> TimeBucket {
        let mut b = TimeBucket {
            start_unix_seconds: start,
            total: answered,
            ..TimeBucket::default()
        };
        b.by_status.insert("forwarded".into(), answered);
        if servfail > 0 {
            b.by_rcode.insert("SERVFAIL".into(), servfail);
        }
        b.by_rcode.insert("NOERROR".into(), answered - servfail);
        b.upstream_queries = answered;
        let mut row = vec![0; BOUNDS_US.len() + 1];
        row[5] = answered;
        b.latency_hist.insert("upstream".into(), row);
        b
    }

    fn node(id: &str, buckets: Vec<TimeBucket>) -> NodeInput {
        NodeInput {
            node_id: id.into(),
            label: id.into(),
            this_node: id == "a",
            buckets,
        }
    }

    /// 24 hours of minutes from 00:00 (day 0): 2,000 answers a minute, 1 SERVFAIL (0.05 %);
    /// node `c` has 40 (2 %) from 15:00 when `bad_c` is set.
    fn three(hours: u64, bad_c: bool) -> Vec<NodeInput> {
        let series = |c: bool| {
            (0..hours * 60)
                .map(|m| {
                    let fail = if c && m >= 15 * 60 { 40 } else { 1 };
                    minute(m * 60, 2000, fail)
                })
                .collect::<Vec<_>>()
        };
        vec![
            node("a", series(false)),
            node("b", series(false)),
            node("c", series(bad_c)),
        ]
    }

    // REQ: OBS-028 — three nodes, one failing from 15:00: one odd finding on it, since 15:00;
    // the same fixture up to 15:00 has none.
    #[test]
    fn obs_028_three_nodes_one_odd_since_1500() {
        let (nodes, findings, partial) = compare(three(24, true), 60, 86_400);
        assert!(!partial);
        assert_eq!(nodes.len(), 3);
        let odd: Vec<_> = findings.iter().filter(|f| f.level == "odd").collect();
        assert_eq!(odd.len(), 1, "{findings:#?}");
        assert_eq!(odd[0].node_id, "c");
        assert_eq!(odd[0].metric, "servfailPct");
        assert_eq!(
            odd[0].odd_since.as_deref(),
            Some("1970-01-01T15:00:00.000Z")
        );
        assert!(nodes[2].servfail_pct > 0.7, "{}", nodes[2].servfail_pct);
        let (_, before, _) = compare(three(15, true), 60, 15 * 3600);
        assert!(before.is_empty(), "{before:#?}");
    }

    fn two(pi_bad: u32) -> Vec<NodeInput> {
        // Pi: 38,000 answers over 24 hours; the pods: 300,000.
        let spread = |total: u32, bad: u32| {
            (0..24u32)
                .map(|h| {
                    let n = total / 24 + u32::from(h < total % 24);
                    let f = bad / 24 + u32::from(h < bad % 24);
                    minute(u64::from(h) * 3600, n, f)
                })
                .collect::<Vec<_>>()
        };
        vec![
            node("pi", spread(38_000, pi_bad)),
            node("pods", spread(300_000, 14)),
        ]
    }

    // REQ: OBS-028 — two nodes: the same bad count on a tenth of the traffic is a note, not odd;
    // ten times the bad count is odd.
    #[test]
    fn obs_028_two_nodes_small_base_note_and_odd() {
        let (_, findings, _) = compare(two(15), 3600, 86_400);
        assert!(findings.iter().all(|f| f.level != "odd"), "{findings:#?}");
        let notes: Vec<_> = findings.iter().filter(|f| f.level == "note").collect();
        assert_eq!(notes.len(), 1, "{findings:#?}");
        assert_eq!(notes[0].node_id, "pi");
        assert!(
            notes[0]
                .detail
                .starts_with("same bad count as pods (15 vs 14)")
        );
        let (_, findings, _) = compare(two(150), 3600, 86_400);
        let odd: Vec<_> = findings.iter().filter(|f| f.level == "odd").collect();
        assert_eq!(odd.len(), 1, "{findings:#?}");
        assert_eq!(
            (odd[0].node_id.as_str(), odd[0].metric.as_str()),
            ("pi", "servfailPct")
        );
    }

    // REQ: OBS-028 — the same input prints the same JSON; one node has nothing to compare.
    #[test]
    fn obs_028_deterministic_and_one_node() {
        let a = serde_json::to_string(&compare(three(24, true), 60, 86_400).0).unwrap_or_default();
        let b = serde_json::to_string(&compare(three(24, true), 60, 86_400).0).unwrap_or_default();
        assert_ne!(a, "");
        assert_eq!(a, b);
        let (nodes, findings, _) = compare(vec![node("a", vec![minute(0, 100, 50)])], 60, 60);
        assert_eq!(nodes.len(), 1);
        assert_eq!(findings.len(), 0);
        assert!(nodes[0].series.start.len() <= SERIES_POINTS);
        let (big, _, _) = compare(three(24, false), 60, 86_400);
        assert_eq!(big[0].series.start.len(), 240);
        assert_eq!(big[0].series.start[1], 360);
    }

    // REQ: OBS-028 — Wilson intervals and histogram percentiles.
    #[test]
    fn obs_028_wilson_and_percentiles() {
        let (lo, hi) = wilson(15, 38_000);
        assert!(lo < 15.0 / 38_000.0 && 15.0 / 38_000.0 < hi);
        assert!(lo > 0.0002 && hi < 0.0007, "{lo} {hi}");
        assert_eq!(wilson(0, 0), (0.0, 1.0));
        let mut h = [0u64; 17];
        h[0] = 50;
        h[4] = 50;
        assert_eq!(percentile(&h, 0.5), Some(50));
        assert_eq!(percentile(&h, 0.99), Some(990));
        h[16] = 1000;
        assert_eq!(percentile(&h, 0.99), Some(5_000_000));
        assert_eq!(percentile(&[0; 17], 0.5), None);
    }
}
