//! REQ: OBS-029 (ADR-129) — the rhythm heatmap's data: queries per slot (an hour, 15 minutes,
//! or a minute) over a window, for the whole network (exact, from the time buckets), or for one
//! device or one name (from each hour's top lists: exact while the key is in the list, and
//! marked uncovered where it isn't). Nothing new is counted or stored.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::model::Step;
use crate::problem::{Code, Problem};
use crate::{Shared, blocking, pick, time_param};

/// The most slots one answer has (7 days of minutes).
pub const MAX_SLOTS: usize = 10_080;

/// `GET /api/v1/stats/heatmap` parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HeatmapParams {
    /// Start (RFC 3339 or relative; default 7 days ago).
    #[param(example = "-7d")]
    pub from: Option<String>,
    /// End (default now).
    pub to: Option<String>,
    /// `hour` (up to 400 days), `15m` or `minute` (up to 7 days, the minutes kept); default
    /// `hour`. A device or a name: `hour` only.
    #[param(example = "15m")]
    pub grain: Option<String>,
    /// `network` (default), `client` (with `key` an address), or `name` (with `key` a name).
    pub kind: Option<String>,
    /// The device's address or the name.
    pub key: Option<String>,
    /// `queries` (default) or `blocked` (the network and names; a device's blocked queries
    /// aren't kept per hour).
    pub measure: Option<String>,
    /// `cluster` (default), `site:<name>`, `node:<name or ID>`, or `node:local`.
    pub scope: Option<String>,
}

/// What each node is asked for a device or a name (hour slots of `[from_s, to_s)`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyQuery {
    pub from_s: u64,
    pub to_s: u64,
    /// `client` or `name`.
    pub kind: String,
    pub key: String,
    pub blocked: bool,
}

/// One node's hours for a device or a name: per hour slot, the count and whether the key was
/// in that hour's top list (or the hour had no list at all: nothing to miss).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPart {
    pub values: Vec<u64>,
    pub covered: Vec<bool>,
}

impl KeyPart {
    /// Every node's together: counts add; an hour is covered when every node covered it.
    pub fn merge(parts: Vec<Self>, n: usize) -> Self {
        let mut out = Self {
            values: vec![0; n],
            covered: vec![true; n],
        };
        for p in parts {
            for (i, v) in p.values.iter().enumerate().take(n) {
                out.values[i] += v;
            }
            for (i, c) in p.covered.iter().enumerate().take(n) {
                out.covered[i] &= *c;
            }
        }
        out
    }
}

/// REQ: OBS-029 — queries per slot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Heatmap {
    pub from: String,
    pub to: String,
    /// `hour`, `15m`, or `minute`.
    pub grain: String,
    /// Seconds per slot.
    pub slot_seconds: u64,
    /// `network`, `client`, or `name`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// `queries` or `blocked`.
    pub measure: String,
    /// Each slot's start (Unix seconds, UTC), oldest first; parallel to `values`.
    pub starts: Vec<u64>,
    pub values: Vec<u64>,
    /// A device or a name: false where the key wasn't in that hour's top list (its count is
    /// then unknown, shown as "below this hour's top list"). Absent for the network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered: Option<Vec<bool>>,
    /// `exact` (the network) or `topList`.
    pub precision: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

fn window_problem(detail: String) -> Problem {
    Problem::new(Code::HeatmapWindow, detail).hint(
        "Hours reach back 400 days; 15-minute and minute slots 7 days (the minutes kept). A device or a name has hours only.",
    )
}

/// Slot seconds for a grain.
fn grain_secs(g: &str) -> Option<u64> {
    match g {
        "hour" => Some(3600),
        "15m" => Some(900),
        "minute" => Some(60),
        _ => None,
    }
}

/// Sums `(start, value)` pairs into the slots of `[from_s, from_s + n × slot)`.
pub fn slots(
    points: impl IntoIterator<Item = (u64, u64)>,
    from_s: u64,
    slot: u64,
    n: usize,
) -> Vec<u64> {
    let mut v = vec![0; n];
    for (start, value) in points {
        if start < from_s {
            continue;
        }
        let i = usize::try_from((start - from_s) / slot).unwrap_or(usize::MAX);
        if let Some(x) = v.get_mut(i) {
            *x += value;
        }
    }
    v
}

/// REQ: OBS-029 — the network's queries (or blocked queries) per slot.
fn network_values(
    buckets: &[crate::model::TimeBucket],
    blocked: bool,
    from_s: u64,
    slot: u64,
    n: usize,
) -> Vec<u64> {
    slots(
        buckets.iter().map(|x| {
            let v = if blocked {
                x.by_status.get("blocked").copied().unwrap_or(0)
            } else {
                x.total
            };
            (x.start_unix_seconds, u64::from(v))
        }),
        from_s,
        slot,
        n,
    )
}

/// REQ: OBS-029 — a device's or a name's key, normalized, or why it can't be shown.
fn check_key(kind: &str, key: Option<&str>, slot: u64, blocked: bool) -> Result<String, Problem> {
    if slot != 3600 {
        return Err(window_problem(format!(
            "a {kind}'s heatmap has hour slots only (from the hourly top lists)"
        )));
    }
    let key = key
        .map(|k| k.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|k| !k.is_empty())
        .ok_or_else(|| Problem::invalid(format!("`key`: the {kind} to show")))?;
    if kind == "client" {
        if key.parse::<std::net::IpAddr>().is_err() {
            return Err(Problem::invalid(format!("`key`: `{key}` isn't an address"))
                .hint("Give the device's IP address (the Clients page lists them)."));
        }
        if blocked {
            return Err(
                Problem::invalid("`measure=blocked` isn't kept per device and hour").hint(
                    "Use measure=queries, or the query log for one device's blocked queries.",
                ),
            );
        }
    }
    Ok(key)
}

/// Queries per slot.
///
/// For the whole network (exact, from the time buckets: hour slots back 400 days, 15-minute or
/// minute slots back 7 days), or for one device (`kind=client`, `key` its address) or one name
/// (`kind=name`) by hour, from each hour's top list of the busiest 100: exact while the key
/// is in the list; `covered` is false for hours where it wasn't (its count is unknown, not
/// zero). `starts` and `values` are parallel arrays in UTC; lay them out by local time. Every
/// node's, summed. A name needs privacy level 0 (names are hashes above it), a device level 1 or
/// lower. Example: `GET /api/v1/stats/heatmap?from=-7d&grain=15m`.
#[utoipa::path(get, path = "/api/v1/stats/heatmap", tag = "stats", params(HeatmapParams),
    responses(
        (status = 200, body = Heatmap, description = "Queries per slot."),
        (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it."),
        (status = 422, body = Problem, description = "`heatmap_window`: the window is too long for the grain, or a device or a name with a finer grain than hours; `privacy_level`: the privacy level hides names or devices.")))]
pub(crate) async fn stats_heatmap(
    State(b): State<Shared>,
    Query(p): Query<HeatmapParams>,
) -> Result<Json<Heatmap>, Problem> {
    let b = pick(&b, p.scope.as_deref())?;
    let now = b.now_unix_seconds();
    let grain = p.grain.unwrap_or_else(|| "hour".into());
    let slot = grain_secs(&grain).ok_or_else(|| {
        Problem::invalid(format!("`grain`: `{grain}` isn't hour, 15m, or minute"))
    })?;
    let kind = p.kind.unwrap_or_else(|| "network".into());
    let blocked = match p.measure.as_deref().unwrap_or("queries") {
        "queries" => false,
        "blocked" => true,
        m => {
            return Err(Problem::invalid(format!(
                "`measure`: `{m}` isn't queries or blocked"
            )));
        }
    };
    let from = time_param(
        p.from.as_deref(),
        now.saturating_sub(7 * 86_400),
        now,
        "from",
    )?;
    let to = time_param(p.to.as_deref(), now + 1, now, "to")?;
    if from >= to {
        return Err(Problem::invalid("`from` must be before `to`"));
    }
    let max_days = if slot == 3600 { 400 } else { 7 };
    if to - from > max_days * 86_400 + 3600 {
        return Err(window_problem(format!(
            "a {grain} heatmap covers at most {max_days} days"
        )));
    }
    let from_s = from - from % slot;
    let n = usize::try_from((to - from_s).div_ceil(slot)).unwrap_or(usize::MAX);
    if n > MAX_SLOTS {
        return Err(window_problem(format!(
            "{n} slots is more than {MAX_SLOTS}"
        )));
    }
    let starts: Vec<u64> = (0..n as u64).map(|i| from_s + i * slot).collect();
    let mut out = Heatmap {
        from: crate::time::format_us(from_s.saturating_mul(1_000_000)),
        to: crate::time::format_us(to.saturating_mul(1_000_000)),
        grain: grain.clone(),
        slot_seconds: slot,
        kind: kind.clone(),
        measure: if blocked { "blocked" } else { "queries" }.into(),
        starts,
        precision: "exact".into(),
        ..Heatmap::default()
    };
    match kind.as_str() {
        "network" => {
            let step = if slot == 3600 {
                Step::Hour
            } else {
                Step::Minute
            };
            let bk = Arc::clone(&b);
            let buckets = blocking(move || Ok(bk.timeseries(step, from_s, to))).await?;
            out.values = network_values(&buckets, blocked, from_s, slot, n);
        }
        "client" | "name" => {
            let key = check_key(&kind, p.key.as_deref(), slot, blocked)?;
            out.key = Some(key.clone());
            let q = KeyQuery {
                from_s,
                to_s: to,
                kind: kind.clone(),
                key,
                blocked,
            };
            let bk = Arc::clone(&b);
            let part = blocking(move || bk.heatmap_key(&q)).await?;
            out.values = part.values;
            out.values.resize(n, 0);
            let mut covered = part.covered;
            covered.resize(n, true);
            out.covered = Some(covered);
            out.precision = "topList".into();
        }
        other => {
            return Err(Problem::invalid(format!(
                "`kind`: `{other}` isn't network, client, or name"
            )));
        }
    }
    out.missing_nodes = b.missing_nodes();
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: OBS-029 — points sum into their slots; points outside are dropped.
    #[test]
    fn obs_029_points_fall_into_slots() {
        let v = slots([(0, 1), (60, 2), (899, 3), (900, 4), (5000, 9)], 0, 900, 2);
        assert_eq!(v, [6, 4]);
        let v = slots([(100, 1)], 200, 60, 3);
        assert_eq!(v, [0, 0, 0]);
    }

    // REQ: OBS-029 — the acceptance fixture: 7 days of minutes with a 4-hour burst on day 4;
    // the 15-minute grid has exactly 16 cells above 3× the median, all on day 4, 14:00–18:00
    // UTC, and each day's cells sum to its minutes.
    #[test]
    fn obs_029_a_burst_stands_out_in_the_15_minute_grid() {
        let day0 = 1_791_072_000; // 2026-10-04T00:00:00Z
        let minutes: Vec<(u64, u64)> = (0..7 * 1440)
            .map(|m| {
                let t = day0 + m * 60;
                let in_burst =
                    (3 * 86_400 + 14 * 3600..3 * 86_400 + 18 * 3600).contains(&(t - day0));
                (t, if in_burst { 40 } else { 10 })
            })
            .collect();
        let cells = slots(minutes.iter().copied(), day0, 900, 7 * 96);
        let mut sorted = cells.clone();
        sorted.sort_unstable();
        let median = sorted[sorted.len() / 2];
        let hot: Vec<usize> = (0..cells.len())
            .filter(|i| cells[*i] > 3 * median)
            .collect();
        assert_eq!(hot.len(), 16);
        assert!(
            hot.iter()
                .all(|i| *i / 96 == 3 && (56..72).contains(&(*i % 96))),
            "{hot:?}"
        );
        for d in 0..7 {
            let cell_sum: u64 = cells[d * 96..(d + 1) * 96].iter().sum();
            let minute_sum: u64 = minutes[d * 1440..(d + 1) * 1440].iter().map(|m| m.1).sum();
            assert_eq!(cell_sum, minute_sum, "day {d}");
        }
    }

    // REQ: OBS-029 — nodes add up; an hour is covered only when every node had the key.
    #[test]
    fn obs_029_key_parts_merge() {
        let a = KeyPart {
            values: vec![5, 0, 2],
            covered: vec![true, false, true],
        };
        let b = KeyPart {
            values: vec![1, 3],
            covered: vec![true, true],
        };
        let m = KeyPart::merge(vec![a, b], 3);
        assert_eq!(m.values, [6, 3, 2]);
        assert_eq!(m.covered, [true, false, true]);
    }
}
