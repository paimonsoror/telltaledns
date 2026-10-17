//! REQ: OBS-034 (ADR-134) — one device's day as swimlanes: per registrable domain (the top
//! `lanes` by queries, the rest folded into `other`), queries, blocked, and slow answers per bin,
//! from the query log; a latency lane (p99 per bin); and the events around them: first-seen
//! domains, anomaly findings, blocked bursts, and the change markers.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::model::{Annotation, AnnotationFilter, VqlogResult};
use crate::problem::{Code, Problem};
use crate::{Shared, blocking, time_param, vqlog};

/// The longest window.
pub const MAX_WINDOW_S: u64 = 7 * 86_400;
/// The most bins, and lanes.
pub const MAX_BINS: u64 = 2_016;
pub const MAX_LANES: usize = 50;
/// Blocked answers in one bin that make a burst.
pub const BURST: u32 = 10;
/// How long an answer is kept for the same request.
pub const CACHE_FOR: Duration = Duration::from_secs(30);
/// Groups one read keeps (domains × bins); beyond, the read says `truncated`.
const GROUPS: usize = 100_000;

pub(crate) fn routes(backend: Shared) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/clients/{id}/timeline", get(client_timeline))
        .with_state(backend)
}

/// `GET /api/v1/clients/{id}/timeline` parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TimelineParams {
    /// Start: RFC 3339 or relative (default 24 hours ago; at most 7 days before `to`).
    #[param(example = "-24h")]
    pub from: Option<String>,
    /// End (default now).
    pub to: Option<String>,
    /// How many bins (default 288: 5 minutes over a day; at most 2,016). Bins are whole minutes.
    pub bins: Option<u64>,
    /// Domain lanes before `other` (default 30, at most 50).
    pub lanes: Option<usize>,
}

/// One domain's lane.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TimelineLane {
    /// The registrable domain; `other` for the rest; absent at privacy level 1 (names hashed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// The lane folds every domain below the top ones.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub other: bool,
    /// Queries, blocked answers, and slow answers (over the latency objective's threshold) per
    /// bin.
    pub counts: Vec<u32>,
    pub blocked: Vec<u32>,
    pub slow: Vec<u32>,
    pub total: u64,
    pub blocked_total: u64,
    /// When the device first contacted it, if that's inside the window (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen_time: Option<String>,
}

/// Something that happened to or on the device.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEvent {
    /// RFC 3339.
    pub time: String,
    pub time_unix_seconds: u64,
    /// `firstSeen`, `anomaly`, or `blockedBurst`.
    pub kind: String,
    pub summary: String,
    /// The UI page that shows it (`#/…`).
    pub href: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

/// REQ: OBS-034 — one device's window as lanes and events.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeviceTimeline {
    /// The device's address.
    pub client: String,
    pub from: String,
    pub to: String,
    pub bin_seconds: u64,
    /// Each bin's start, Unix seconds.
    pub bins: Vec<u64>,
    /// Busiest first, `other` last.
    pub lanes: Vec<TimelineLane>,
    /// Every query per bin, and the p99 answer time per bin (ms; null without queries).
    pub queries: Vec<u32>,
    pub p99_ms: Vec<Option<f64>>,
    /// Oldest first.
    pub events: Vec<TimelineEvent>,
    /// The change markers in the window (OBS-033), oldest first.
    pub markers: Vec<Annotation>,
    /// `querylog`.
    pub source: String,
    /// The query log keeps nothing older than this (RFC 3339), when it's inside the window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_from: Option<String>,
    /// A read stopped early (rows, groups, or time): the lanes cover what it read.
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

/// The bins: whole minutes, aligned to the epoch like vqlog's buckets.
pub fn bins(from: u64, to: u64, want: u64) -> (u64, Vec<u64>) {
    let span = to.saturating_sub(from).max(60);
    let bin = span.div_ceil(want.clamp(1, MAX_BINS)).div_ceil(60).max(1) * 60;
    let first = from / bin * bin;
    let n = to.saturating_sub(first).div_ceil(bin);
    let starts = (0..n).map(|i| first + i * bin).collect();
    (bin, starts)
}

fn col(r: &VqlogResult, name: &str) -> Option<usize> {
    r.columns.iter().position(|c| c == name)
}

fn bin_of(row: &[serde_json::Value], t: usize, first: u64, bin: u64, n: usize) -> Option<usize> {
    let s = row.get(t)?.as_str()?;
    let at = crate::time::parse_time(s, 0).ok()?;
    let i = usize::try_from(at.checked_sub(first)? / bin).ok()?;
    (i < n).then_some(i)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn n_of(row: &[serde_json::Value], i: usize) -> u32 {
    row.get(i)
        .and_then(serde_json::Value::as_f64)
        .map_or(0, |v| v.max(0.0).min(f64::from(u32::MAX)) as u32)
}

/// A domain's lane in `by` (made on first use; a row without a domain is `(none)`).
fn lane<'a>(by: &'a mut HashMap<String, TimelineLane>, d: &str, n: usize) -> &'a mut TimelineLane {
    let d = if d.is_empty() { "(none)" } else { d };
    by.entry(d.to_owned()).or_insert_with(|| TimelineLane {
        domain: Some(d.to_owned()),
        counts: vec![0; n],
        blocked: vec![0; n],
        slow: vec![0; n],
        ..TimelineLane::default()
    })
}

/// Folds the three reads into lanes: `by_status` (`time, domain, status, count`), `slow`
/// (`time, domain, count`), `latency` (`time, count, p99(latency)`).
#[allow(clippy::too_many_lines)]
pub fn fold(
    by_status: &VqlogResult,
    slow: &VqlogResult,
    latency: &VqlogResult,
    first: u64,
    bin: u64,
    n: usize,
    lanes: usize,
) -> (Vec<TimelineLane>, Vec<u32>, Vec<Option<f64>>) {
    let mut by: HashMap<String, TimelineLane> = HashMap::new();
    if let (Some(t), Some(d), Some(s), Some(c)) = (
        col(by_status, "time"),
        col(by_status, "domain"),
        col(by_status, "status"),
        col(by_status, "count"),
    ) {
        for row in &by_status.rows {
            let Some(i) = bin_of(row, t, first, bin, n) else {
                continue;
            };
            let domain = row.get(d).and_then(serde_json::Value::as_str).unwrap_or("");
            let k = n_of(row, c);
            let l = lane(&mut by, domain, n);
            l.counts[i] = l.counts[i].saturating_add(k);
            l.total += u64::from(k);
            if row.get(s).and_then(serde_json::Value::as_str) == Some("blocked") {
                l.blocked[i] = l.blocked[i].saturating_add(k);
                l.blocked_total += u64::from(k);
            }
        }
    }
    if let (Some(t), Some(d), Some(c)) =
        (col(slow, "time"), col(slow, "domain"), col(slow, "count"))
    {
        for row in &slow.rows {
            let Some(i) = bin_of(row, t, first, bin, n) else {
                continue;
            };
            let domain = row.get(d).and_then(serde_json::Value::as_str).unwrap_or("");
            let l = lane(&mut by, domain, n);
            l.slow[i] = l.slow[i].saturating_add(n_of(row, c));
        }
    }
    let mut all: Vec<TimelineLane> = by.into_values().collect();
    all.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| a.domain.cmp(&b.domain)));
    let mut out: Vec<TimelineLane> = Vec::new();
    let mut other: Option<TimelineLane> = None;
    for (i, l) in all.into_iter().enumerate() {
        if i < lanes {
            out.push(l);
            continue;
        }
        let o = other.get_or_insert_with(|| TimelineLane {
            domain: Some("other".into()),
            other: true,
            counts: vec![0; n],
            blocked: vec![0; n],
            slow: vec![0; n],
            ..TimelineLane::default()
        });
        for (dst, src) in [
            (&mut o.counts, &l.counts),
            (&mut o.blocked, &l.blocked),
            (&mut o.slow, &l.slow),
        ] {
            for (a, b) in dst.iter_mut().zip(src) {
                *a = a.saturating_add(*b);
            }
        }
        o.total += l.total;
        o.blocked_total += l.blocked_total;
    }
    out.extend(other);
    let mut queries = vec![0u32; n];
    let mut p99: Vec<Option<f64>> = vec![None; n];
    if let (Some(t), Some(c)) = (col(latency, "time"), col(latency, "count")) {
        let p = latency.columns.iter().position(|x| x.starts_with("p99"));
        for row in &latency.rows {
            let Some(i) = bin_of(row, t, first, bin, n) else {
                continue;
            };
            queries[i] = queries[i].saturating_add(n_of(row, c));
            p99[i] = p
                .and_then(|p| row.get(p))
                .and_then(serde_json::Value::as_f64)
                .map(|v| (v * 100.0).round() / 100.0);
        }
    }
    (out, queries, p99)
}

/// Blocked bursts: runs of bins with at least [`BURST`] blocked answers, one event each.
pub fn bursts(
    lanes: &[TimelineLane],
    starts: &[u64],
    bin: u64,
    client: &str,
) -> Vec<TimelineEvent> {
    let n = starts.len();
    let per: Vec<u32> = (0..n)
        .map(|i| {
            lanes
                .iter()
                .map(|l| l.blocked.get(i).copied().unwrap_or(0))
                .sum()
        })
        .collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        if per[i] < BURST {
            i += 1;
            continue;
        }
        let start = i;
        let mut total = 0u64;
        while i < n && per[i] >= BURST {
            total += u64::from(per[i]);
            i += 1;
        }
        let top = lanes
            .iter()
            .filter(|l| !l.other)
            .max_by_key(|l| {
                l.blocked[start..i]
                    .iter()
                    .map(|&x| u64::from(x))
                    .sum::<u64>()
            })
            .and_then(|l| l.domain.clone());
        let mins = (i - start) as u64 * bin / 60;
        out.push(TimelineEvent {
            time: crate::time::format_us(starts[start].saturating_mul(1_000_000)),
            time_unix_seconds: starts[start],
            kind: "blockedBurst".into(),
            summary: match &top {
                Some(d) => format!("{total} blocked in {mins} min, mostly {d}"),
                None => format!("{total} blocked in {mins} min"),
            },
            href: format!("#/queries?client={client}&status=blocked"),
            domain: top,
        });
    }
    out
}

/// The three vqlog reads: queries by domain and status, slow answers by domain, and every
/// query with its p99, per bin of `mins` minutes.
pub fn texts(client: &str, mins: u64, slow_ms: u32) -> [String; 3] {
    let w = format!("where client = \"{client}\"");
    [
        format!("{w} | bucket {mins}m | by domain, status | stats count"),
        format!("{w} and latency > {slow_ms} | bucket {mins}m | by domain | stats count"),
        format!("{w} | bucket {mins}m | stats count, p99(latency)"),
    ]
}

/// Counts reads, for the cache's test.
pub static READS: AtomicU64 = AtomicU64::new(0);

type Cache = Mutex<HashMap<String, (Instant, DeviceTimeline)>>;

fn cache() -> &'static Cache {
    static C: OnceLock<Cache> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The answer for `key` from the last 30 s, else `make`'s (kept for the next 30 s).
pub fn cached(
    key: &str,
    make: impl FnOnce() -> Result<DeviceTimeline, Problem>,
) -> Result<DeviceTimeline, Problem> {
    let now = Instant::now();
    {
        let mut c = cache().lock().unwrap_or_else(PoisonError::into_inner);
        c.retain(|_, (at, _)| now.duration_since(*at) < CACHE_FOR);
        if let Some((_, t)) = c.get(key) {
            return Ok(t.clone());
        }
    }
    READS.fetch_add(1, Ordering::Relaxed);
    let t = make()?;
    let mut c = cache().lock().unwrap_or_else(PoisonError::into_inner);
    if c.len() >= 64 {
        c.clear();
    }
    c.insert(key.to_owned(), (now, t.clone()));
    Ok(t)
}

fn read(b: &Shared, text: &str, from_us: u64, to_us: u64) -> Result<VqlogResult, Problem> {
    let mut q = vqlog::parse(text).map_err(|e| Problem::internal(e.message))?;
    q.limit = GROUPS;
    b.vqlog(&q, from_us, to_us, false)
}

/// A device's day.
///
/// One device over a window (default the last 24 hours, at most 7 days) as swimlanes: a lane per
/// registrable domain (the top `lanes` by queries, the rest in `other`) with its queries, blocked
/// answers, and slow answers (over the latency objective's threshold) per bin (`bins`, whole
/// minutes; 288 by default, 5 minutes over a day); every query and the p99 answer time per bin
/// (the latency lane); `events`: domains first contacted, anomaly findings for the device, and
/// blocked bursts (10 or more blocked in a bin); and the change markers. From the query log, so
/// nothing older than it keeps (`coverageFrom`); every node's rows that reached this one. The
/// same request within 30 seconds is answered from memory. `truncated` says a read stopped
/// early. At privacy level 1 the lanes have no domain; from level 2 it's refused. Use it to
/// answer "when did this start, and what else did the device do?". Example:
/// `GET /api/v1/clients/192.168.2.14/timeline?from=-24h`.
#[utoipa::path(get, path = "/api/v1/clients/{id}/timeline", tag = "stats",
    params(("id" = String, Path, description = "The device's address."), TimelineParams),
    responses(
        (status = 200, body = DeviceTimeline, description = "The lanes and the events."),
        (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it."),
        (status = 422, body = Problem, description = "`privacy_level`: the query log's privacy level hides devices.")))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn client_timeline(
    State(b): State<Shared>,
    Path(id): Path<String>,
    Query(p): Query<TimelineParams>,
) -> Result<Json<DeviceTimeline>, Problem> {
    let ip: std::net::IpAddr = id.parse().map_err(|_| {
        Problem::invalid(format!("`id`: `{id}` isn't an address"))
            .hint("Give the device's IP address (the Clients page lists them).")
    })?;
    let privacy = b.qlog_privacy_level();
    if privacy >= 2 {
        return Err(Problem::new(
            Code::PrivacyLevel,
            format!("the query log's privacy level ({privacy}) hides devices"),
        )
        .hint("The network's heatmap and flow work at every level."));
    }
    let now = b.now_unix_seconds();
    let to = time_param(p.to.as_deref(), now + 1, now, "to")?;
    let from = time_param(p.from.as_deref(), to.saturating_sub(86_400), now, "from")?;
    if from >= to {
        return Err(Problem::invalid("`from` must be before `to`"));
    }
    if to - from > MAX_WINDOW_S + 3600 {
        return Err(Problem::invalid("`from`: the window is longer than 7 days")
            .hint("A device's day reads the query log: use at most 7 days."));
    }
    let lanes = p.lanes.unwrap_or(30).clamp(1, MAX_LANES);
    let (bin, starts) = bins(from, to, p.bins.unwrap_or(288));
    let key = format!(
        "{ip}|{}|{}|{bin}|{lanes}|{privacy}",
        starts[0],
        starts.len()
    );
    let bk = Arc::clone(&b);
    let client = ip.to_string();
    let out = blocking(move || {
        cached(&key, || {
            let first = starts[0];
            let n = starts.len();
            let (from_us, to_us) = (
                first.saturating_mul(1_000_000),
                to.saturating_mul(1_000_000),
            );
            let slow_ms = bk.slo_settings().latency_ms;
            let mins = bin / 60;
            let [q1, q2, q3] = texts(&client, mins, slow_ms);
            let by_status = read(&bk, &q1, from_us, to_us)?;
            let slow = read(&bk, &q2, from_us, to_us)?;
            let latency = read(&bk, &q3, from_us, to_us)?;
            let mut reasons: Vec<String> = [&by_status, &slow, &latency]
                .iter()
                .filter_map(|r| {
                    if r.truncated {
                        Some(
                            r.truncated_reason
                                .clone()
                                .unwrap_or_else(|| "stopped early".into()),
                        )
                    } else if usize::try_from(r.groups).unwrap_or(0) > r.rows.len() {
                        Some(format!("more than {GROUPS} domain-and-bin groups"))
                    } else {
                        None
                    }
                })
                .collect();
            reasons.dedup();
            let (mut lanes, queries, p99_ms) =
                fold(&by_status, &slow, &latency, first, bin, n, lanes);
            // First-seen domains in the window: events, and the lane's "new" tag.
            let mut events: Vec<TimelineEvent> = bk
                .new_domains(first, Some(&client), 500)
                .into_iter()
                .filter_map(|d| {
                    let at = crate::time::parse_time(&d.time, 0).ok()?;
                    (at < to).then(|| TimelineEvent {
                        time: d.time.clone(),
                        time_unix_seconds: at,
                        kind: "firstSeen".into(),
                        summary: format!("first query to {}", d.domain),
                        href: format!("#/queries?client={client}&name={}&match=suffix", d.domain),
                        domain: Some(d.domain),
                    })
                })
                .collect();
            for l in &mut lanes {
                l.first_seen_time = events
                    .iter()
                    .filter(|e| e.domain.is_some() && e.domain == l.domain)
                    .map(|e| e.time.clone())
                    .min();
            }
            for f in bk.anomalies(first) {
                if f.client != client {
                    continue;
                }
                let Ok(at) = crate::time::parse_time(&f.window_start, 0) else {
                    continue;
                };
                if at >= to {
                    continue;
                }
                events.push(TimelineEvent {
                    time: f.window_start.clone(),
                    time_unix_seconds: at,
                    kind: "anomaly".into(),
                    summary: f.detail.clone(),
                    href: "#/anomalies".into(),
                    domain: f.domain.clone(),
                });
            }
            events.extend(bursts(&lanes, &starts, bin, &client));
            events.sort_by(|a, b| {
                a.time_unix_seconds
                    .cmp(&b.time_unix_seconds)
                    .then_with(|| a.kind.cmp(&b.kind))
            });
            // REQ: OBS-034 — privacy level 1: names are hashes, so the lanes keep no domain.
            if privacy >= 1 {
                for l in &mut lanes {
                    if !l.other {
                        l.domain = None;
                    }
                }
                for e in &mut events {
                    e.domain = None;
                }
            }
            let mut markers = bk.annotations(&AnnotationFilter {
                from_ms: first.saturating_mul(1000),
                to_ms: to.saturating_mul(1000),
                kinds: Vec::new(),
                limit: 200,
            });
            markers.sort_by_key(|m| m.t_unix_ms);
            let kept = bk.qlog_retention_days();
            let coverage = (kept > 0)
                .then(|| now.saturating_sub(u64::from(kept) * 86_400))
                .filter(|c| *c > first);
            let mut missing = by_status.missing_nodes.clone();
            missing.extend(bk.missing_nodes());
            missing.sort();
            missing.dedup();
            Ok(DeviceTimeline {
                client: client.clone(),
                from: crate::time::format_us(first.saturating_mul(1_000_000)),
                to: crate::time::format_us(to.saturating_mul(1_000_000)),
                bin_seconds: bin,
                bins: starts.clone(),
                lanes,
                queries,
                p99_ms,
                events,
                markers,
                source: "querylog".into(),
                coverage_from: coverage
                    .map(|c| crate::time::format_us(c.saturating_mul(1_000_000))),
                truncated: !reasons.is_empty(),
                truncated_reason: (!reasons.is_empty()).then(|| reasons.join("; ")),
                missing_nodes: missing,
            })
        })
    })
    .await?;
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    const DAY: u64 = 1_790_000_000 / 86_400 * 86_400;

    fn t(s: u64) -> serde_json::Value {
        json!(crate::time::format_us(s * 1_000_000))
    }

    /// AC 1: `ntp.org` every 2.5 s from 14:00 to 18:30 (120 per 5 minutes), `example.com` 10 an
    /// hour all day, and three blocked bursts of 12 on `ads.example`.
    fn fixture() -> (VqlogResult, VqlogResult, VqlogResult) {
        let mut rows = Vec::new();
        let mut lat = BTreeMap::<u64, u32>::new();
        for i in 0..288u64 {
            let start = DAY + i * 300;
            if (14 * 12..18 * 12 + 6).contains(&i) {
                rows.push(vec![
                    t(start),
                    json!("ntp.org"),
                    json!("cached"),
                    json!(120),
                ]);
                *lat.entry(start).or_default() += 120;
            }
            if i % 12 == 0 {
                rows.push(vec![
                    t(start),
                    json!("example.com"),
                    json!("forwarded"),
                    json!(10),
                ]);
                *lat.entry(start).or_default() += 10;
            }
            if [30, 100, 200].contains(&i) {
                rows.push(vec![
                    t(start),
                    json!("ads.example"),
                    json!("blocked"),
                    json!(12),
                ]);
                *lat.entry(start).or_default() += 12;
            }
        }
        let by_status = VqlogResult {
            columns: vec![
                "time".into(),
                "domain".into(),
                "status".into(),
                "count".into(),
            ],
            groups: rows.len() as u64,
            rows,
            ..VqlogResult::default()
        };
        let slow = VqlogResult {
            columns: vec!["time".into(), "domain".into(), "count".into()],
            rows: vec![vec![t(DAY + 600), json!("example.com"), json!(2)]],
            groups: 1,
            ..VqlogResult::default()
        };
        let latency = VqlogResult {
            columns: vec!["time".into(), "count".into(), "p99(latency)".into()],
            rows: lat
                .iter()
                .map(|(s, n)| vec![t(*s), json!(n), json!(12.345)])
                .collect(),
            groups: lat.len() as u64,
            ..VqlogResult::default()
        };
        (by_status, slow, latency)
    }

    // REQ: OBS-034 (AC 1) — the lanes, the bursts, and no `other` with two domains.
    #[test]
    fn obs_034_a_day_folds_into_lanes_and_bursts() {
        let (bin, starts) = bins(DAY, DAY + 86_400, 288);
        assert_eq!((bin, starts.len()), (300, 288));
        let (a, b, c) = fixture();
        let (lanes, queries, p99) = fold(&a, &b, &c, starts[0], bin, starts.len(), 30);
        assert_eq!(lanes.len(), 3, "no other lane");
        assert!(lanes.iter().all(|l| !l.other));
        let ntp = lanes
            .iter()
            .find(|l| l.domain.as_deref() == Some("ntp.org"))
            .unwrap();
        assert!(ntp.counts[..14 * 12].iter().all(|&n| n == 0));
        assert!(ntp.counts[14 * 12..18 * 12 + 6].iter().all(|&n| n == 120));
        assert_eq!(ntp.total, 54 * 120);
        let ex = lanes
            .iter()
            .find(|l| l.domain.as_deref() == Some("example.com"))
            .unwrap();
        assert_eq!(ex.slow[2], 2);
        let ev = bursts(&lanes, &starts, bin, "192.168.2.14");
        assert_eq!(ev.len(), 3);
        assert!(
            ev.iter()
                .all(|e| e.kind == "blockedBurst" && e.domain.as_deref() == Some("ads.example"))
        );
        assert_eq!(ev[0].time_unix_seconds, DAY + 30 * 300);
        assert_eq!(queries[14 * 12], 130, "ntp.org and the hour's example.com");
        assert_eq!(p99[14 * 12], Some(12.35));
        assert_eq!(p99[1], None);
        // Two lanes: the rest folds into `other`.
        let (two, _, _) = fold(&a, &b, &c, starts[0], bin, starts.len(), 1);
        assert_eq!(two.len(), 2);
        assert!(two[1].other);
        assert_eq!(
            two[0].total + two[1].total,
            lanes.iter().map(|l| l.total).sum::<u64>()
        );
    }

    // REQ: OBS-034 (AC 5) — the same request within 30 s reads once.
    #[test]
    fn obs_034_the_same_request_reads_once() {
        let before = READS.load(Ordering::Relaxed);
        let make = || {
            Ok(DeviceTimeline {
                client: "x".into(),
                ..DeviceTimeline::default()
            })
        };
        let a = cached("obs_034_test|1", make).unwrap_or_default();
        let b = cached("obs_034_test|1", make).unwrap_or_default();
        assert_eq!(a, b);
        assert_eq!(READS.load(Ordering::Relaxed) - before, 1);
        let _ = cached("obs_034_test|2", make);
        assert_eq!(READS.load(Ordering::Relaxed) - before, 2);
    }

    // REQ: OBS-034 — the reads parse, with the columns `fold` reads.
    #[test]
    fn obs_034_the_reads_parse() {
        let [a, b, c] = texts("192.168.2.14", 5, 250);
        let cols = |t: &str| vqlog::parse(t).map(|q| q.columns()).unwrap_or_default();
        assert_eq!(cols(&a), ["time", "domain", "status", "count"]);
        assert_eq!(cols(&b), ["time", "domain", "count"]);
        let c = cols(&c);
        assert_eq!(c.len(), 3);
        assert!(c[2].starts_with("p99"), "{c:?}");
    }

    // REQ: OBS-034 — whole-minute bins aligned like vqlog's buckets.
    #[test]
    fn obs_034_bins() {
        let (bin, s) = bins(DAY + 30, DAY + 7 * 86_400, 288);
        assert_eq!(bin, 2_100);
        assert_eq!(s[0] % bin, 0);
        assert!(s.len() <= 289);
        let (bin, s) = bins(DAY, DAY + 3600, 288);
        assert_eq!((bin, s.len()), (60, 60));
    }
}
