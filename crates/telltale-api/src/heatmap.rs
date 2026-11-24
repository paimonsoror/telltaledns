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

/// The finest slot the API asks for (`grain=minute`), in seconds.
const MIN_SLOT: u64 = 60;

/// REQ: OBS-029 — how many slots of `slot` seconds `[from_s, to_s)` has, as a node answers a
/// read: none when `to_s` isn't after `from_s`, a zero slot counting as a minute (the finest
/// grain the API asks for), and at most [`MAX_SLOTS`]. Every window the API sends (`span`)
/// has at most that many, so for those it is the plain count.
#[must_use]
pub fn window_slots(from_s: u64, to_s: u64, slot: u64) -> usize {
    let n = to_s.saturating_sub(from_s).div_ceil(slot_secs(slot));
    usize::try_from(n.min(MAX_SLOTS as u64)).unwrap_or(MAX_SLOTS)
}

/// A slot's seconds: a zero slot (the API never sends one) is a minute.
fn slot_secs(slot: u64) -> u64 {
    if slot == 0 { MIN_SLOT } else { slot }
}

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

/// What each node is asked for the network: its own queries (or blocked queries) per slot of
/// `[from_s, to_s)`, `from_s` on a slot boundary. Each node sums its own minutes into slots:
/// a week of minute buckets is several megabytes, over the cluster channel's 1 MiB frame.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkQuery {
    pub from_s: u64,
    pub to_s: u64,
    /// Seconds per slot.
    pub slot: u64,
    pub blocked: bool,
}

impl NetworkQuery {
    /// How many slots the answer has ([`window_slots`]).
    #[must_use]
    pub fn slot_count(&self) -> usize {
        window_slots(self.from_s, self.to_s, self.slot)
    }
    /// The time buckets the slots are summed from: hours for hour slots, minutes otherwise.
    #[must_use]
    pub fn step(&self) -> Step {
        if self.slot >= 3600 {
            Step::Hour
        } else {
            Step::Minute
        }
    }
    /// One node's slots from its time buckets.
    #[must_use]
    pub fn slots_of(&self, buckets: &[crate::model::TimeBucket]) -> Vec<u64> {
        network_values(
            buckets,
            self.blocked,
            self.from_s,
            self.slot,
            self.slot_count(),
        )
    }
}

/// Adds one node's slots into the sum.
pub fn add_slots(sum: &mut [u64], part: &[u64]) {
    for (s, p) in sum.iter_mut().zip(part) {
        *s += p;
    }
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

/// REQ: OBS-029 — the slots of `[from, to)` aligned to `slot` (first start, count), or `None`
/// past `max`. Aligning both ends can add one partial slot (`-7d` of minutes is 10,081); that
/// one, the oldest, is dropped, so the answer still ends now. Anything longer is refused.
fn span(from: u64, to: u64, slot: u64, max: u64) -> Option<(u64, usize)> {
    let from_s = from - from % slot;
    let n = (to - from_s).div_ceil(slot);
    let drop = n.saturating_sub(max);
    if drop > 1 {
        return None;
    }
    Some((from_s + drop * slot, usize::try_from(n - drop).ok()?))
}

/// Sums `(start, value)` pairs into the slots of `[from_s, from_s + n × slot)`: at most
/// [`MAX_SLOTS`] of them, a zero slot counting as a minute.
pub fn slots(
    points: impl IntoIterator<Item = (u64, u64)>,
    from_s: u64,
    slot: u64,
    n: usize,
) -> Vec<u64> {
    // REQ: OBS-029 — bounded for any arguments (a peer's read reaches this with its own).
    let slot = slot_secs(slot);
    let mut v = vec![0; n.min(MAX_SLOTS)];
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
    // The days a grain reaches plus an hour of slack, in slots; minutes stop at MAX_SLOTS.
    let max = ((max_days * 86_400 + 3600) / slot).min(MAX_SLOTS as u64);
    let Some((from_s, n)) = span(from, to, slot, max) else {
        return Err(window_problem(format!(
            "a {grain} heatmap covers at most {max_days} days"
        )));
    };
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
            let q = NetworkQuery {
                from_s,
                to_s: to,
                slot,
                blocked,
            };
            let bk = Arc::clone(&b);
            out.values = blocking(move || Ok(bk.heatmap_network(&q))).await?;
            out.values.resize(n, 0);
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

    // REQ: OBS-029 — `-7d` of minutes (to = now + 1, from unaligned) spans 10,081 slots once
    // aligned; only the oldest, partial one is dropped, and the current minute stays. A longer
    // window is refused rather than cut; coarser grains keep their hour of slack.
    #[test]
    fn obs_029_seven_days_of_minutes_fit_the_cap() {
        let cap = MAX_SLOTS as u64;
        let now = 1_791_072_000 + 37;
        let (from_s, n) = span(now - 7 * 86_400, now + 1, 60, cap).unwrap_or_default();
        assert_eq!(n, MAX_SLOTS);
        assert_eq!(from_s % 60, 0);
        assert!(
            from_s + 60 * n as u64 > now,
            "the current minute is in the answer"
        );
        // Aligned already: nothing dropped.
        let day0 = 1_791_072_000;
        assert_eq!(
            span(day0, day0 + 7 * 86_400, 60, cap),
            Some((day0, MAX_SLOTS))
        );
        // Half an hour more of minutes is refused, not silently cut.
        assert_eq!(span(day0, day0 + 7 * 86_400 + 1800, 60, cap), None);
        // 15 minutes: 7 days plus the partial slot, within the hour of slack (676).
        assert_eq!(
            span(now - 7 * 86_400, now + 1, 900, 676).map(|x| x.1),
            Some(673)
        );
        assert!(span(day0, day0 + 7 * 86_400 + 3600, 900, 676).is_some());
    }

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

    // REQ: OBS-029, CLU-002 (regression 2026-11-16) — a peer's part of a week's 15-minute grid
    // is its slots, not its minutes: a week of a busy node's minute buckets is over the
    // cluster channel's 1 MiB frame (the peer was dropped as "didn't answer"); its slots are a
    // few kilobytes, and sum to the same counts.
    #[test]
    fn obs_029_a_peers_network_part_is_its_slots() {
        let day0 = 1_791_072_000;
        let keys = |ks: &[&str]| -> std::collections::BTreeMap<String, u32> {
            ks.iter().map(|k| ((*k).to_owned(), 3)).collect()
        };
        let minutes: Vec<crate::model::TimeBucket> = (0..7 * 1440)
            .map(|m| crate::model::TimeBucket {
                start_unix_seconds: day0 + m * 60,
                total: 30,
                by_status: keys(&["blocked", "cached", "forwarded", "local"]),
                by_qtype: keys(&["A", "AAAA", "HTTPS", "PTR", "SRV", "TXT"]),
                by_rcode: keys(&["NOERROR", "NXDOMAIN", "SERVFAIL"]),
                by_group: keys(&["default", "kids"]),
                ..crate::model::TimeBucket::default()
            })
            .collect();
        assert!(serde_json::to_vec(&minutes).unwrap().len() > 1 << 20);
        let q = NetworkQuery {
            from_s: day0,
            to_s: day0 + 7 * 86_400,
            slot: 900,
            blocked: false,
        };
        assert_eq!(q.step(), Step::Minute);
        assert_eq!(q.slot_count(), 7 * 96);
        let part = q.slots_of(&minutes);
        assert!(serde_json::to_vec(&part).unwrap().len() < 16_384);
        assert!(part.iter().all(|v| *v == 15 * 30));
        let blocked = NetworkQuery { blocked: true, ..q }.slots_of(&minutes);
        assert!(blocked.iter().all(|v| *v == 15 * 3));
        let mut sum = vec![0; q.slot_count()];
        add_slots(&mut sum, &part);
        add_slots(&mut sum, &part);
        assert_eq!(sum[0], 2 * 15 * 30);
    }

    // REQ: OBS-029 — whatever window and slot a caller names, a part has at most `MAX_SLOTS`
    // slots: none when the window doesn't end after it starts, and a zero slot counts as a
    // minute (the finest grain the API asks for).
    #[test]
    fn obs_029_slot_counts_are_bounded_for_any_window() {
        let q = |from_s, to_s, slot| NetworkQuery {
            from_s,
            to_s,
            slot,
            blocked: false,
        };
        assert_eq!(q(0, u64::MAX, 1).slot_count(), MAX_SLOTS);
        assert_eq!(q(0, u64::MAX, 0).slot_count(), MAX_SLOTS);
        assert_eq!(q(0, u64::MAX, u64::MAX).slot_count(), 1);
        assert_eq!(q(5, 0, 60).slot_count(), 0);
        assert_eq!(q(5, 5, 60).slot_count(), 0);
        assert_eq!(q(0, 7200, 0).slot_count(), 120);
        let bucket = |s| crate::model::TimeBucket {
            start_unix_seconds: s,
            total: 2,
            ..crate::model::TimeBucket::default()
        };
        let part = q(0, 7200, 0).slots_of(&[bucket(0), bucket(61), bucket(7199), bucket(7200)]);
        assert_eq!(part.len(), 120);
        assert_eq!((part[0], part[1], part[119]), (2, 2, 2));
        assert_eq!(part.iter().sum::<u64>(), 6);
        assert_eq!(slots([(30, 1)], 0, 0, usize::MAX).len(), MAX_SLOTS);
        assert_eq!(slots([(30, 1), (90, 1)], 0, 0, 3), [1, 1, 0]);
    }

    // REQ: OBS-029 — every window the API sends (`span` of a `from < to` it accepts, for each
    // grain) keeps the slot count it always had (span's, the plain formula's, and
    // `slot_count`'s are one), and its points sum into the same slots.
    #[test]
    fn obs_029_api_windows_keep_their_slot_counts() {
        let now = 1_791_072_000 + 37;
        let backs = [
            1,
            59,
            60,
            61,
            899,
            900,
            3599,
            3600,
            3601,
            86_400,
            7 * 86_400,
            7 * 86_400 + 1800,
            400 * 86_400,
            400 * 86_400 + 1,
        ];
        let mut checked = 0;
        for (slot, max_days) in [(3600u64, 400u64), (900, 7), (60, 7)] {
            let max = ((max_days * 86_400 + 3600) / slot).min(MAX_SLOTS as u64);
            for back in backs {
                for to in [now, now + 1, now + slot - 1] {
                    let Some((from_s, n)) = span(to - back, to, slot, max) else {
                        continue;
                    };
                    let q = NetworkQuery {
                        from_s,
                        to_s: to,
                        slot,
                        blocked: false,
                    };
                    let plain = usize::try_from((to - from_s).div_ceil(slot)).unwrap();
                    assert_eq!((q.slot_count(), plain), (n, n), "{slot} {back} {to}");
                    // A point before the window, one at every slot's start and middle, and two past it.
                    let mut points = vec![(from_s - 1, 7)];
                    for i in 0..n as u64 + 2 {
                        points.push((from_s + i * slot, i + 1));
                        points.push((from_s + i * slot + slot / 2, 1));
                    }
                    let mut plain_slots = vec![0u64; n];
                    for &(start, value) in &points {
                        if start >= from_s
                            && let Some(x) = plain_slots.get_mut(
                                usize::try_from((start - from_s) / slot).unwrap_or(usize::MAX),
                            )
                        {
                            *x += value;
                        }
                    }
                    assert_eq!(slots(points, from_s, slot, n), plain_slots);
                    checked += 1;
                }
            }
        }
        assert!(checked > 80, "{checked}");
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
