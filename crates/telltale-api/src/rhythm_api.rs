//! REQ: OBS-031 (ADR-131) — a device's rhythm: for each registrable domain the anomaly engine
//! tracks for it, how its queries are spaced, as a log-spaced histogram of inter-arrival gaps
//! (1 s … 2 h), this hour and recently. A time-sync loop is one bright bin; a browser is a smear.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::Shared;
use crate::problem::{Code, Problem};

/// The bins' upper bounds in seconds (the same as the engine's, in ms): bin 0 is under 1 s, the
/// last is 7,290 s and longer.
pub const BIN_EDGES_S: [f64; 23] = [
    1.0, 1.5, 2.2, 3.3, 5.0, 7.5, 11.0, 17.0, 25.0, 38.0, 56.0, 84.0, 126.0, 190.0, 285.0, 427.0,
    640.0, 960.0, 1440.0, 2160.0, 3240.0, 4860.0, 7290.0,
];
/// Rows returned (the engine tracks at most 16 domains per device and node).
pub const MAX_DOMAINS: usize = 16;

pub(crate) fn routes(backend: Shared) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/clients/{id}/rhythm", get(client_rhythm))
        .with_state(backend)
}

/// `GET /api/v1/clients/{id}/rhythm` parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RhythmParams {
    /// `false`: the dominant period and share per domain without the bins (default true).
    pub bins: Option<bool>,
}

/// One tracked domain's rhythm.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RhythmDomain {
    /// The registrable domain (eTLD+1).
    pub domain: String,
    /// This hour's gaps per bin (24 counts; see `binsS`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hour: Vec<u32>,
    /// The recent view: each hour's close halves it and adds that hour; this hour included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recent: Vec<u32>,
    /// The bin holding most of `recent`, and its share (percent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dominant_bin: Option<u32>,
    pub dominant_share_pct: f64,
    /// The mean of the latest gaps in whole seconds (1 s to an hour), when there are enough.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typical_gap_s: Option<f64>,
    /// In words, when one bin holds at least half: `every 2.5 s`, `every 5 min`, `in bursts`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<String>,
    /// Consecutive hours the beacon detector found it regular (4 reports a new beacon).
    pub regular_hours: u32,
    /// It was periodic while the device was learning: its usual behaviour.
    pub known_periodic: bool,
    /// Since when it's tracked (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_unix_seconds: Option<u64>,
    /// Its queries per hour, usually.
    pub mean_per_hour: f64,
    /// The cluster nodes that track it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
}

/// REQ: OBS-031 — a device's rhythm per domain.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientRhythm {
    /// The device's address.
    pub client: String,
    /// False when the anomaly engine is off (`reason: disabled`).
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The bins' upper bounds in seconds; the last bin (7,290 s and longer) has none.
    pub bins_s: Vec<f64>,
    /// Sorted by the dominant share, most regular first; at most 16.
    pub domains: Vec<RhythmDomain>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

/// A period in words.
pub fn period_text(bin: usize, typical_gap_s: Option<f64>) -> String {
    if bin == 0 {
        return "in bursts (under 1 s)".into();
    }
    let lo = BIN_EDGES_S[bin - 1];
    let hi = BIN_EDGES_S.get(bin).copied().unwrap_or(f64::INFINITY);
    // The engine's whole-second gaps say it more exactly, when they agree with the bin.
    let s = typical_gap_s
        .filter(|g| *g >= lo - 1.0 && *g < hi + 1.0)
        .unwrap_or(if hi.is_finite() { (lo * hi).sqrt() } else { lo });
    if s < 10.0 {
        format!("every {s:.1} s")
    } else if s < 90.0 {
        format!("every {s:.0} s")
    } else if s < 5400.0 {
        format!("every {:.0} min", s / 60.0)
    } else {
        format!("every {:.1} h", s / 3600.0)
    }
}

/// Merges the same domain from several nodes (a device roams): bins summed, the regular streak
/// and the baseline the largest, the earliest start, the typical gap of the busiest node.
pub fn merge(parts: Vec<(Option<String>, Vec<RhythmDomain>)>) -> Vec<RhythmDomain> {
    let mut by: BTreeMap<String, (RhythmDomain, f64)> = BTreeMap::new();
    for (node, rows) in parts {
        for r in rows {
            let weight = r.mean_per_hour;
            let e = by
                .entry(r.domain.clone())
                .or_insert_with(|| (RhythmDomain::default(), -1.0));
            let m = &mut e.0;
            if m.domain.is_empty() {
                m.domain.clone_from(&r.domain);
            }
            for (dst, src) in [(&mut m.hour, &r.hour), (&mut m.recent, &r.recent)] {
                dst.resize(dst.len().max(src.len()), 0);
                for (d, s) in dst.iter_mut().zip(src) {
                    *d = d.saturating_add(*s);
                }
            }
            m.regular_hours = m.regular_hours.max(r.regular_hours);
            m.known_periodic |= r.known_periodic;
            m.since_unix_seconds = match (m.since_unix_seconds, r.since_unix_seconds) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            m.mean_per_hour = m.mean_per_hour.max(r.mean_per_hour);
            if weight > e.1 {
                e.1 = weight;
                m.typical_gap_s = r.typical_gap_s;
            }
            if let Some(n) = &node {
                m.nodes.push(n.clone());
            }
        }
    }
    by.into_values().map(|(r, _)| r).collect()
}

/// Fills in the dominant bin, its share, the words, and the time; sorts and trims.
#[allow(clippy::cast_precision_loss)]
pub fn finish(mut rows: Vec<RhythmDomain>, bins: bool) -> Vec<RhythmDomain> {
    for r in &mut rows {
        let total: u64 = r.recent.iter().map(|&n| u64::from(n)).sum();
        let top = r
            .recent
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(&a.0)))
            .filter(|(_, n)| **n > 0);
        r.dominant_bin = top.and_then(|(i, _)| u32::try_from(i).ok());
        r.dominant_share_pct = top.map_or(0.0, |(_, &n)| {
            (f64::from(n) / total as f64 * 1000.0).round() / 10.0
        });
        r.period = top
            .filter(|_| r.dominant_share_pct >= 50.0)
            .map(|(i, _)| period_text(i, r.typical_gap_s));
        r.since_time = r
            .since_unix_seconds
            .map(|s| crate::time::format_us(s.saturating_mul(1_000_000)));
        r.mean_per_hour = (r.mean_per_hour * 10.0).round() / 10.0;
        r.nodes.sort();
        r.nodes.dedup();
        if !bins {
            r.hour.clear();
            r.recent.clear();
        }
    }
    rows.sort_by(|a, b| {
        b.dominant_share_pct
            .total_cmp(&a.dominant_share_pct)
            .then_with(|| a.domain.cmp(&b.domain))
    });
    rows.truncate(MAX_DOMAINS);
    rows
}

/// How a device's queries are spaced (OBS-031).
///
/// For each registrable domain the anomaly engine tracks for the device (up to 16 per node),
/// the gaps between its queries as counts in 24 log-spaced bins (`binsS`: under 1 s, then
/// 1–1.5 s, 1.5–2.2 s, … up to 7,290 s and longer): `hour` (this hour) and `recent` (each hour's
/// close halves it and adds that hour). `dominantBin` and `dominantSharePct` say how regular it
/// is (a time-sync loop every 2.5 s puts nearly everything in bin 3, 2.2–3.3 s), `period` says it
/// in words, `knownPeriodic` that it was periodic while the device was learning (usual), and
/// `regularHours` how long the beacon detector has found it regular (4 reports a new beacon).
/// Every node's, summed by domain. `id` is an address, or a named device's name. Needs the
/// anomaly engine (`available: false`, `reason: disabled` without it), which runs only at
/// query-log privacy level 0. `bins=false` leaves the bins out. Example:
/// `GET /api/v1/clients/192.168.2.14/rhythm`.
#[utoipa::path(get, path = "/api/v1/clients/{id}/rhythm", tag = "stats",
    params(("id" = String, Path, description = "An address, or a named device's name."), RhythmParams),
    responses(
        (status = 200, body = ClientRhythm, description = "The device's rhythm per domain."),
        (status = 404, body = Problem, description = "No named device by that name, and not an address."),
        (status = 422, body = Problem, description = "`privacy_level`: the query log's privacy level hides devices and names.")))]
pub(crate) async fn client_rhythm(
    State(b): State<Shared>,
    Path(id): Path<String>,
    Query(p): Query<RhythmParams>,
) -> Result<Json<ClientRhythm>, Problem> {
    let privacy = b.qlog_privacy_level();
    if privacy >= 1 {
        return Err(Problem::new(
            Code::PrivacyLevel,
            format!("the query log's privacy level ({privacy}) hides devices and names"),
        )
        .hint("The anomaly engine, which measures the rhythm, runs only at privacy level 0."));
    }
    let mut out =
        tokio::task::spawn_blocking(move || b.client_rhythm(&id).map(|r| (r, b.missing_nodes())))
            .await
            .map_err(|e| Problem::internal(format!("request worker failed: {e}")))?
            .map(|(mut r, missing)| {
                r.missing_nodes = missing;
                r
            })?;
    out.bins_s = BIN_EDGES_S.to_vec();
    out.domains = finish(std::mem::take(&mut out.domains), p.bins.unwrap_or(true));
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(domain: &str, bin: usize, n: u32, mean: f64) -> RhythmDomain {
        let mut recent = vec![0; 24];
        recent[bin] = n;
        recent[(bin + 5) % 24] = n / 50;
        RhythmDomain {
            domain: domain.into(),
            hour: recent.clone(),
            recent,
            mean_per_hour: mean,
            since_unix_seconds: Some(100),
            typical_gap_s: Some(2.5),
            ..RhythmDomain::default()
        }
    }

    // REQ: OBS-031 (AC 4) — two nodes seeing the same device sum their bins by domain.
    #[test]
    fn obs_031_nodes_sum_bins_by_domain() {
        let merged = finish(
            merge(vec![
                (Some("pi".into()), vec![row("ntp.org", 3, 1000, 1400.0)]),
                (
                    Some("pod".into()),
                    vec![
                        row("ntp.org", 3, 400, 600.0),
                        row("example.com", 9, 10, 20.0),
                    ],
                ),
            ]),
            true,
        );
        assert_eq!(merged.len(), 2);
        let ntp = merged.iter().find(|r| r.domain == "ntp.org").unwrap();
        assert_eq!(ntp.recent[3], 1400);
        assert_eq!(ntp.dominant_bin, Some(3));
        assert!(ntp.dominant_share_pct > 97.0, "{}", ntp.dominant_share_pct);
        assert_eq!(ntp.period.as_deref(), Some("every 2.5 s"));
        assert_eq!(ntp.nodes, ["pi", "pod"]);
        let lean = finish(merge(vec![(None, vec![row("ntp.org", 3, 10, 1.0)])]), false);
        assert!(lean[0].recent.is_empty() && lean[0].dominant_bin == Some(3));
    }

    // REQ: OBS-031 — periods in words.
    #[test]
    fn obs_031_period_text() {
        assert_eq!(period_text(3, Some(2.5)), "every 2.5 s");
        assert_eq!(period_text(15, Some(300.0)), "every 5 min");
        assert_eq!(period_text(15, None), "every 6 min");
        assert_eq!(period_text(0, None), "in bursts (under 1 s)");
        assert_eq!(period_text(23, None), "every 2.0 h");
    }
}
