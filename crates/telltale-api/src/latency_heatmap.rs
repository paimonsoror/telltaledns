//! REQ: OBS-030 (ADR-130) — the latency heatmap: answers per `telltale_query_duration_seconds`
//! bucket over time, per path or upstream (from the time buckets), and recent exemplars: real
//! queries in those buckets whose trace IDs open them in the query log.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::model::{Step, TimeBucket};
use crate::problem::{Code, Problem};
use crate::{Shared, blocking, pick, time_param};

/// The most exemplars one read returns.
pub const MAX_EXEMPLARS: usize = 2_048;

/// The buckets' upper bounds in microseconds; the overflow has none.
pub const BOUNDS_US: [u64; 16] = [
    50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
    1_000_000, 2_500_000, 5_000_000,
];

/// `GET /api/v1/stats/latency/heatmap` parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LatencyHeatmapParams {
    /// Start (RFC 3339 or relative; default 6 hours ago).
    #[param(example = "-6h")]
    pub from: Option<String>,
    /// End (default now).
    pub to: Option<String>,
    /// `minute` (up to 48 hours, default) or `hour` (up to 400 days).
    pub step: Option<String>,
    /// `path` (default: `cache`, `upstream`, `local`, `synthesized`) or `upstream` (one series
    /// per upstream, by name).
    pub by: Option<String>,
    /// `cluster` (default), `site:<name>`, `node:<name or ID>`, or `node:local`.
    pub scope: Option<String>,
}

/// REQ: OBS-030 — answers per latency bucket over time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LatencyHeatmap {
    pub from: String,
    pub to: String,
    pub step: String,
    /// `path` or `upstream`.
    pub by: String,
    /// The buckets' upper bounds (µs); the last bucket (beyond 5 s) has none.
    pub bounds_us: Vec<u64>,
    /// Each step's start (Unix seconds), oldest first.
    pub starts: Vec<u64>,
    /// Per path or upstream: for each start, the answers in each of the 17 buckets.
    #[schema(value_type = Object)]
    pub series: BTreeMap<String, Vec<Vec<u32>>>,
    /// Some steps had answers but no bucket counts (stored by an older build, or a node that
    /// doesn't count them yet): their answers are missing here.
    pub partial: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

/// `GET /api/v1/stats/latency/exemplars` parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExemplarParams {
    /// Start (default 6 hours ago).
    pub from: Option<String>,
    /// End (default now).
    pub to: Option<String>,
    /// Only this path (`cache`, `upstream`, `local`, `synthesized`).
    pub path: Option<String>,
    /// `cluster` (default), `site:<name>`, `node:<name or ID>`, or `node:local`.
    pub scope: Option<String>,
}

/// REQ: OBS-030 — a recent query in a latency bucket.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LatencyExemplar {
    /// 32 hex digits: `GET /api/v1/queries?trace=` finds the query.
    pub trace_id: String,
    /// RFC 3339.
    pub time: String,
    pub ts_unix_micros: u64,
    pub latency_us: u32,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
}

/// Recent exemplars, newest first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LatencyExemplars {
    pub items: Vec<LatencyExemplar>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

/// The per-start bucket rows of `buckets`, keyed by path (`by_upstream` false) or upstream.
pub fn series(
    buckets: &[TimeBucket],
    by_upstream: bool,
) -> (Vec<u64>, BTreeMap<String, Vec<Vec<u32>>>, bool) {
    let starts: Vec<u64> = buckets.iter().map(|b| b.start_unix_seconds).collect();
    let mut out: BTreeMap<String, Vec<Vec<u32>>> = BTreeMap::new();
    let mut partial = false;
    for (i, b) in buckets.iter().enumerate() {
        let answered = b
            .total
            .saturating_sub(b.by_status.get("dropped").copied().unwrap_or(0));
        if answered > 0 && b.latency_hist.is_empty() {
            partial = true;
        }
        for (k, row) in &b.latency_hist {
            let key = match (by_upstream, k.strip_prefix("upstream:")) {
                (true, Some(name)) => name,
                (false, None) => k.as_str(),
                _ => continue,
            };
            let rows = out
                .entry(key.to_owned())
                .or_insert_with(|| vec![Vec::new(); buckets.len()]);
            rows[i].clone_from(row);
        }
    }
    for rows in out.values_mut() {
        for r in rows.iter_mut() {
            r.resize(BOUNDS_US.len() + 1, 0);
        }
    }
    (starts, out, partial)
}

/// Answers per latency bucket.
///
/// The latency histogram over time: for each minute (up to 48 hours) or hour (up to 400 days),
/// how many answers landed in each `telltale_query_duration_seconds` bucket (`boundsUs`: 50 µs
/// to 5 s, then everything slower), per answer path (`by=path`: `cache`, `upstream`, `local`,
/// `synthesized` for blocked and special answers) or per upstream (`by=upstream`). Every node's,
/// summed. `partial` says some steps had answers without bucket counts (an older build's). Use
/// it to see a latency tail as a shape over time rather than a p99. Example:
/// `GET /api/v1/stats/latency/heatmap?from=-6h&by=path`.
#[utoipa::path(get, path = "/api/v1/stats/latency/heatmap", tag = "stats", params(LatencyHeatmapParams),
    responses(
        (status = 200, body = LatencyHeatmap, description = "Bucket counts per step."),
        (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it."),
        (status = 422, body = Problem, description = "`heatmap_window`: longer than 48 hours of minutes or 400 days of hours.")))]
pub(crate) async fn latency_heatmap(
    State(b): State<Shared>,
    Query(p): Query<LatencyHeatmapParams>,
) -> Result<Json<LatencyHeatmap>, Problem> {
    let b = pick(&b, p.scope.as_deref())?;
    let now = b.now_unix_seconds();
    let (step, max_s) = match p.step.as_deref().unwrap_or("minute") {
        "minute" => (Step::Minute, 48 * 3600),
        "hour" => (Step::Hour, 400 * 86_400),
        s => {
            return Err(Problem::invalid(format!(
                "`step`: `{s}` isn't minute or hour"
            )));
        }
    };
    let by_upstream = match p.by.as_deref().unwrap_or("path") {
        "path" => false,
        "upstream" => true,
        s => {
            return Err(Problem::invalid(format!(
                "`by`: `{s}` isn't path or upstream"
            )));
        }
    };
    let from = time_param(p.from.as_deref(), now.saturating_sub(6 * 3600), now, "from")?;
    let to = time_param(p.to.as_deref(), now + 1, now, "to")?;
    if from >= to {
        return Err(Problem::invalid("`from` must be before `to`"));
    }
    if to - from > max_s + 3600 {
        return Err(
            Problem::new(Code::HeatmapWindow, "the window is too long for this step").hint(
                "Minutes reach back 48 hours; use step=hour for longer windows (up to 400 days).",
            ),
        );
    }
    let bk = Arc::clone(&b);
    let buckets = blocking(move || Ok(bk.timeseries(step, from, to))).await?;
    let (starts, series, partial) = series(&buckets, by_upstream);
    Ok(Json(LatencyHeatmap {
        from: crate::time::format_us(from.saturating_mul(1_000_000)),
        to: crate::time::format_us(to.saturating_mul(1_000_000)),
        step: if step == Step::Hour { "hour" } else { "minute" }.into(),
        by: if by_upstream { "upstream" } else { "path" }.into(),
        bounds_us: BOUNDS_US.to_vec(),
        starts,
        series,
        partial,
        missing_nodes: b.missing_nodes(),
    }))
}

/// Recent queries in each latency bucket.
///
/// Exemplars: for each answer path and latency bucket, a recent real query (at most one per
/// path and bucket a second; the last 512 per node are kept, in memory only), newest first,
/// at most 2,048. Each `traceId` opens the query in the log (`GET /api/v1/queries?trace=`), so
/// a dot on the latency heatmap leads to the query behind it. Every node's. Needs the
/// `querylog:read` scope for agents (a trace ID names a query).
#[utoipa::path(get, path = "/api/v1/stats/latency/exemplars", tag = "stats", params(ExemplarParams),
    responses(
        (status = 200, body = LatencyExemplars, description = "Exemplars, newest first."),
        (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it.")))]
pub(crate) async fn latency_exemplars(
    State(b): State<Shared>,
    Query(p): Query<ExemplarParams>,
) -> Result<Json<LatencyExemplars>, Problem> {
    let b = pick(&b, p.scope.as_deref())?;
    let now = b.now_unix_seconds();
    let from = time_param(p.from.as_deref(), now.saturating_sub(6 * 3600), now, "from")?;
    let to = time_param(p.to.as_deref(), now + 1, now, "to")?;
    if let Some(path) = p.path.as_deref()
        && !["cache", "upstream", "local", "synthesized"].contains(&path)
    {
        return Err(Problem::invalid(format!("`path`: `{path}` isn't one"))
            .hint("Use cache, upstream, local, or synthesized."));
    }
    let bk = Arc::clone(&b);
    let path = p.path.clone();
    let mut items = blocking(move || {
        Ok(bk.exemplars(
            from.saturating_mul(1_000_000),
            to.saturating_mul(1_000_000),
            path.as_deref(),
        ))
    })
    .await?;
    items.sort_by_key(|a| std::cmp::Reverse(a.ts_unix_micros));
    items.truncate(MAX_EXEMPLARS);
    Ok(Json(LatencyExemplars {
        items,
        missing_nodes: b.missing_nodes(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(start: u64, total: u32, hist: &[(&str, usize, u32)]) -> TimeBucket {
        let mut b = TimeBucket {
            start_unix_seconds: start,
            total,
            ..TimeBucket::default()
        };
        for (k, i, n) in hist {
            b.latency_hist
                .entry((*k).to_owned())
                .or_insert_with(|| vec![0; 17])[*i] += n;
        }
        b
    }

    // REQ: OBS-030 — rows per path or per upstream; a step with answers and no counts makes the
    // answer partial; missing rows are zeros.
    #[test]
    fn obs_030_series_by_path_and_upstream() {
        let buckets = [
            bucket(
                0,
                1000,
                &[
                    ("cache", 0, 900),
                    ("upstream", 9, 100),
                    ("upstream:quad9", 9, 100),
                ],
            ),
            bucket(60, 5, &[]),
        ];
        let (starts, by_path, partial) = series(&buckets, false);
        assert_eq!(starts, [0, 60]);
        assert!(partial);
        assert_eq!(by_path["cache"][0][0], 900);
        assert_eq!(by_path["upstream"][0][9], 100);
        assert_eq!(by_path["cache"][1], vec![0; 17]);
        assert!(!by_path.contains_key("upstream:quad9"));
        let (_, by_up, _) = series(&buckets, true);
        assert_eq!(by_up.keys().collect::<Vec<_>>(), ["quad9"]);
        let (_, _, quiet) = series(&[bucket(0, 0, &[])], false);
        assert!(!quiet, "no answers: nothing missing");
    }
}
