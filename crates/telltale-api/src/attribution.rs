//! REQ: OBS-027 (ADR-127) — error-budget attribution: who and what spent each objective's
//! budget over its window. Exact where the buckets count it (timeline, status, upstream,
//! response code, node), approximate top lists for clients and names (Space-Saving, with the
//! error bound shown). The bad answers are exactly what `slo::tally` counts.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::model::{TimeBucket, TopItem};
use crate::problem::Problem;
use crate::slo::{self, Kind};
use crate::{Shared, blocking, pick, time_param};

/// The most rows a list returns.
pub const MAX_LIMIT: usize = 20;

/// One node's share of an attribution, as it crosses the cluster channel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Part {
    /// The node's label (federated reads); `None` for this node alone.
    pub node: Option<String>,
    /// Hour buckets over the window.
    pub hours: Vec<TimeBucket>,
    /// The heaviest bad answers' clients and names (approximate), with their error bounds.
    pub clients: Vec<TopItem>,
    pub names: Vec<TopItem>,
    /// Hours whose top lists were found.
    pub top_hours: u64,
    /// The node has no client and name lists for (part of) the window: an older build, or a
    /// resolver pod counted from the minutes it shipped.
    pub partial: bool,
    /// The query log's privacy level on the node.
    pub privacy: u8,
}

/// What each node is asked for its [`Part`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartQuery {
    /// The latency objective (else availability).
    pub latency: bool,
    pub from_s: u64,
    pub to_s: u64,
    /// Rows per top list.
    pub limit: usize,
    /// Nodes answering for themselves: their shipped minutes aren't counted again.
    pub live: Vec<String>,
}

/// `GET /api/v1/stats/slo/attribution` parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AttributionParams {
    /// `availability` (answers that were SERVFAIL) or `latency` (answers slower than the
    /// objective's threshold).
    #[param(example = "availability")]
    pub objective: Option<String>,
    /// Start (RFC 3339 or relative; default: the objective's window, `[slo] window_days`).
    pub from: Option<String>,
    /// End (default now).
    pub to: Option<String>,
    /// `cluster` (default), `site:<name>`, `node:<name or ID>`, or `node:local`.
    pub scope: Option<String>,
    /// Rows per list (1–20, default 10).
    pub limit: Option<usize>,
    /// The timeline's grain: `hour` or `day` (default: `day` over windows longer than 7 days).
    pub step: Option<String>,
}

/// REQ: OBS-027 — the budget over the window.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AttributionBudget {
    /// The objective's target, percent of good answers.
    pub target_pct: f64,
    /// Answers counted (availability: every response; latency: every answer with a timing).
    pub answered: u64,
    /// Bad answers the target allows over the window.
    pub allowed_bad: u64,
    /// Bad answers in the window.
    pub bad: u64,
    /// The budget left, percent (negative: overspent).
    pub remaining_pct: f64,
}

/// REQ: OBS-027 — one node's bad answers in one hour or day.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AttributionPoint {
    /// Start, RFC 3339.
    pub start: String,
    pub start_unix_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    pub answered: u64,
    pub bad: u64,
    /// The window's budget this spent, percent.
    pub budget_spent_pct: f64,
}

/// REQ: OBS-027 — one row of a breakdown.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AttributionRow {
    /// A client address, a name, a status, an upstream (`none`: no upstream on the answer),
    /// a response code, or a node.
    #[schema(example = "192.168.10.185")]
    pub key: String,
    /// A client's device name, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub bad: u64,
    /// Of the window's bad answers, percent.
    pub share_pct: f64,
    /// Exact count (`false` for the client and name lists: their `bad` is an upper bound, and
    /// the true count is at least `bad - errorMax`).
    pub exact: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_max: Option<u64>,
}

/// REQ: OBS-027 — how much of the window the lists cover.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AttributionCoverage {
    /// Hours whose client and name lists were found (summed over nodes).
    pub top_lists_from_hours: u64,
    /// The client and name lists are approximate (always).
    pub approximate: bool,
    /// Nodes without client and name lists for some of the window (an older build; a resolver
    /// pod counted from the minutes it shipped): their bad answers count everywhere else.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partial_nodes: Vec<String>,
    /// Why a list is empty on purpose: `names_hidden` (privacy level 1: names are hashes),
    /// `clients_hidden` (level 2), `timeline_only` (level 3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hidden: Vec<String>,
}

/// REQ: OBS-027 — who and what spent an objective's error budget.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SloAttribution {
    /// `availability` or `latency`.
    pub objective: String,
    pub from: String,
    pub to: String,
    /// The timeline's grain: `hour` or `day`.
    pub step: String,
    pub budget: AttributionBudget,
    /// Per node and hour (or day), oldest first.
    pub timeline: Vec<AttributionPoint>,
    pub by_client: Vec<AttributionRow>,
    pub by_name: Vec<AttributionRow>,
    pub by_status: Vec<AttributionRow>,
    pub by_upstream: Vec<AttributionRow>,
    pub by_rcode: Vec<AttributionRow>,
    pub by_node: Vec<AttributionRow>,
    pub coverage: AttributionCoverage,
    /// A plain note, such as few answers making one failure move the ratio a lot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

/// The objective named by `text`.
pub fn kind_of(text: Option<&str>) -> Result<Kind, Problem> {
    match text.unwrap_or("availability") {
        "availability" => Ok(Kind::Availability),
        "latency" => Ok(Kind::Latency),
        other => Err(
            Problem::invalid(format!("`objective`: `{other}` isn't one"))
                .hint("Use availability (SERVFAIL answers) or latency (slow answers)."),
        ),
    }
}

#[allow(clippy::cast_precision_loss)]
fn pct(a: u64, b: u64) -> f64 {
    if b == 0 {
        0.0
    } else {
        (a as f64 * 1000.0 / b as f64).round() / 10.0
    }
}

/// The bad-answer maps of `b` for `kind`: by status, by upstream, by rcode.
fn maps(b: &TimeBucket, kind: Kind) -> [BTreeMap<String, u32>; 3] {
    match kind {
        Kind::Availability => {
            let mut rc = BTreeMap::new();
            if let Some(n) = b.by_rcode.get("SERVFAIL").filter(|n| **n > 0) {
                rc.insert("SERVFAIL".to_owned(), *n);
            }
            [
                b.servfail_by_status.clone(),
                b.servfail_by_upstream.clone(),
                rc,
            ]
        }
        Kind::Latency => [
            b.slow_by_status.clone(),
            b.slow_by_upstream.clone(),
            b.slow_by_rcode.clone(),
        ],
    }
}

/// Rows from summed counts, heaviest first (ties by key), at most `limit`.
fn rows(sum: BTreeMap<String, u64>, total_bad: u64, limit: usize) -> Vec<AttributionRow> {
    let mut v: Vec<AttributionRow> = sum
        .into_iter()
        .filter(|(_, n)| *n > 0)
        .map(|(key, bad)| AttributionRow {
            share_pct: pct(bad, total_bad),
            key,
            bad,
            exact: true,
            ..AttributionRow::default()
        })
        .collect();
    v.sort_by(|a, b| b.bad.cmp(&a.bad).then_with(|| a.key.cmp(&b.key)));
    v.truncate(limit);
    v
}

/// Approximate rows from every node's top lists: counts and error bounds add per key.
fn top_rows(lists: Vec<&[TopItem]>, total_bad: u64, limit: usize) -> Vec<AttributionRow> {
    let mut by: BTreeMap<String, (u64, u64, Option<String>)> = BTreeMap::new();
    for item in lists.into_iter().flatten() {
        let e = by.entry(item.key.clone()).or_default();
        e.0 += item.count;
        e.1 += item.error_bound;
        if e.2.is_none() {
            e.2.clone_from(&item.name);
        }
    }
    let mut v: Vec<AttributionRow> = by
        .into_iter()
        .map(|(key, (bad, err, name))| AttributionRow {
            share_pct: pct(bad.min(total_bad), total_bad),
            key,
            name,
            bad,
            exact: false,
            error_max: Some(err),
        })
        .collect();
    v.sort_by(|a, b| b.bad.cmp(&a.bad).then_with(|| a.key.cmp(&b.key)));
    v.truncate(limit);
    v
}

/// Grain labels and widths.
fn width(step: &str) -> u64 {
    if step == "day" { 86_400 } else { 3600 }
}

/// The attribution of `kind` over `[from_s, to_s)` from every node's part.
#[allow(
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
pub fn attribute(
    settings: &slo::Settings,
    kind: Kind,
    parts: &[Part],
    from_s: u64,
    to_s: u64,
    step: &str,
    limit: usize,
) -> SloAttribution {
    let target = match kind {
        Kind::Availability => settings.availability_target,
        Kind::Latency => settings.latency_target,
    };
    let grain = width(step);
    let (mut answered, mut bad) = (0u64, 0u64);
    let mut by_node: BTreeMap<String, u64> = BTreeMap::new();
    let mut sums: [BTreeMap<String, u64>; 3] = Default::default();
    let mut points: BTreeMap<(Option<String>, u64), (u64, u64)> = BTreeMap::new();
    let mut partial_nodes = Vec::new();
    let mut top_hours = 0;
    let privacy = parts.iter().map(|p| p.privacy).max().unwrap_or(0);
    for p in parts {
        let label = p.node.clone().unwrap_or_else(|| "this node".to_owned());
        let mut lacks_maps = false;
        for b in &p.hours {
            if b.start_unix_seconds < from_s || b.start_unix_seconds >= to_s {
                continue;
            }
            let (answers, bads) = slo::tally(b, kind);
            answered += answers;
            bad += bads;
            *by_node.entry(label.clone()).or_default() += bads;
            let point = points
                .entry((
                    p.node.clone(),
                    b.start_unix_seconds - b.start_unix_seconds % grain,
                ))
                .or_default();
            point.0 += answers;
            point.1 += bads;
            let breakdown = maps(b, kind);
            // A bucket with bad answers but no breakdown: stored by an older build.
            if bads > 0 && breakdown[0].is_empty() && breakdown[1].is_empty() {
                lacks_maps = true;
            }
            for (sum, map) in sums.iter_mut().zip(breakdown) {
                for (k, n) in map {
                    *sum.entry(k).or_default() += u64::from(n);
                }
            }
        }
        if p.partial || lacks_maps {
            partial_nodes.push(label);
        }
        top_hours += p.top_hours;
    }
    // The share the target allows, as `slo::status` uses it; whole answers (a float's last
    // bit off a whole number isn't one fewer).
    let ratio = (1.0 - target / 100.0).max(f64::EPSILON);
    let allowed = (ratio * answered as f64 + 1e-6).floor().max(0.0) as u64;
    // The same budget left as the Service level card shows.
    let remaining = if answered == 0 {
        100.0
    } else {
        (100.0 * (1.0 - (bad as f64 / answered as f64) / ratio) * 10.0).round() / 10.0
    };
    let timeline = points
        .into_iter()
        .map(|((node, start), (a, x))| AttributionPoint {
            start: crate::time::format_us(start.saturating_mul(1_000_000)),
            start_unix_seconds: start,
            node,
            answered: a,
            bad: x,
            budget_spent_pct: pct(x, allowed.max(1)),
        })
        .collect();
    let mut hidden = Vec::new();
    let [status, upstream, rcode] = sums;
    let mut out = SloAttribution {
        objective: match kind {
            Kind::Availability => "availability",
            Kind::Latency => "latency",
        }
        .to_owned(),
        from: crate::time::format_us(from_s.saturating_mul(1_000_000)),
        to: crate::time::format_us(to_s.saturating_mul(1_000_000)),
        step: step.to_owned(),
        budget: AttributionBudget {
            target_pct: target,
            answered,
            allowed_bad: allowed,
            bad,
            remaining_pct: remaining,
        },
        timeline,
        by_client: top_rows(
            parts.iter().map(|p| p.clients.as_slice()).collect(),
            bad,
            limit,
        ),
        by_name: top_rows(
            parts.iter().map(|p| p.names.as_slice()).collect(),
            bad,
            limit,
        ),
        by_status: rows(status, bad, limit),
        by_upstream: rows(upstream, bad, limit),
        by_rcode: rows(rcode, bad, limit),
        by_node: rows(by_node, bad, limit),
        coverage: AttributionCoverage {
            top_lists_from_hours: top_hours,
            approximate: true,
            partial_nodes,
            hidden: Vec::new(),
        },
        note: None,
        missing_nodes: Vec::new(),
    };
    // REQ: OBS-027 (spec/06 §4) — the privacy level: hashed names at 1, no clients at 2, the
    // timeline only at 3.
    if privacy >= 1 {
        hidden.push("names_hidden".to_owned());
    }
    if privacy >= 2 {
        out.by_client.clear();
        hidden.push("clients_hidden".to_owned());
    }
    if privacy >= 3 {
        out.by_name.clear();
        out.by_status.clear();
        out.by_upstream.clear();
        out.by_rcode.clear();
        out.by_node.clear();
        hidden.push("timeline_only".to_owned());
    }
    out.coverage.hidden = hidden;
    // So few answers that the budget allows fewer than ten bad ones.
    if bad > 0 && allowed < 10 {
        out.note =
            Some("few answers in this window, so one failure moves the ratio a lot".to_owned());
    }
    out
}

/// Who spent the error budget.
///
/// For one objective (`availability`: SERVFAIL answers; `latency`: answers slower than the
/// objective's threshold), the window's bad answers broken down: `byClient` and `byName`
/// (approximate top lists, each row with `errorMax`: the true count is at least
/// `bad - errorMax`), and `byStatus` (`refreshed`, `forwarded`, ...), `byUpstream` (`none`: no
/// upstream on the answer, such as one served from the cache), `byRcode`, `byNode`, exact.
/// `timeline` is every node's bad answers per hour or day (`step`), with the share of the
/// window's budget each spent; `budget` the window's totals. In a cluster every node is asked;
/// `coverage.partialNodes` names nodes whose client and name lists are missing for part of the
/// window (they still count in the exact lists). Follows the query log's privacy level. Use it
/// to answer "why did the error budget drop?". Example:
/// `GET /api/v1/stats/slo/attribution?objective=availability&from=-30d`.
#[utoipa::path(get, path = "/api/v1/stats/slo/attribution", tag = "stats", params(AttributionParams),
    responses(
        (status = 200, body = SloAttribution, description = "The attribution."),
        (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it.")))]
pub(crate) async fn slo_attribution(
    State(b): State<Shared>,
    Query(p): Query<AttributionParams>,
) -> Result<Json<SloAttribution>, Problem> {
    let kind = kind_of(p.objective.as_deref())?;
    let b = pick(&b, p.scope.as_deref())?;
    let settings = b.slo_settings();
    let now = b.now_unix_seconds();
    let window = u64::from(settings.window_days) * 86_400;
    let from = time_param(p.from.as_deref(), now.saturating_sub(window), now, "from")?;
    let to = time_param(p.to.as_deref(), now + 1, now, "to")?;
    if from >= to {
        return Err(Problem::invalid("`from` must be before `to`"));
    }
    let limit = p.limit.unwrap_or(10);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(Problem::invalid(format!("`limit`: 1 to {MAX_LIMIT} rows")));
    }
    let step = match p.step.as_deref() {
        None => {
            if to - from > 7 * 86_400 {
                "day"
            } else {
                "hour"
            }
        }
        Some(s @ ("hour" | "day")) => s,
        Some(s) => {
            return Err(Problem::invalid(format!("`step`: `{s}` isn't hour or day")));
        }
    }
    .to_owned();
    // Whole hours: the buckets are hourly.
    let from_h = from - from % 3600;
    let bk = Arc::clone(&b);
    let latency = kind == Kind::Latency;
    let q = PartQuery {
        latency,
        from_s: from_h,
        to_s: to,
        limit,
        live: Vec::new(),
    };
    let parts = blocking(move || Ok(bk.slo_parts(&q))).await?;
    let mut out = attribute(&settings, kind, &parts, from_h, to, &step, limit);
    out.missing_nodes = b.missing_nodes();
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const H0: u64 = 1_791_072_000; // 2026-10-04T00:00:00Z

    fn bucket(start: u64, total: u32, servfail: u32) -> TimeBucket {
        let mut b = TimeBucket {
            start_unix_seconds: start,
            total,
            ..TimeBucket::default()
        };
        b.by_rcode.insert("NOERROR".into(), total - servfail);
        if servfail > 0 {
            b.by_rcode.insert("SERVFAIL".into(), servfail);
        }
        b
    }

    fn item(key: &str, count: u64, error: u64) -> TopItem {
        TopItem {
            key: key.into(),
            name: None,
            count,
            error_bound: error,
            groups: Vec::new(),
        }
    }

    /// The acceptance fixture: 10,000 answers over 48 h; client A asks name X 10 times →
    /// SERVFAIL from the cache (`refreshed`, no upstream); client B gets 3 SERVFAILs on three
    /// names from `quad9-2`; 2 answers are slower than 250 ms.
    fn fixture() -> Part {
        let mut hours: Vec<TimeBucket> = (0..48).map(|h| bucket(H0 + h * 3600, 208, 0)).collect();
        hours[0].total += 16; // 10,000 in all
        hours[0].by_rcode.insert("NOERROR".into(), 224);
        let a = &mut hours[10];
        *a = bucket(a.start_unix_seconds, 208, 10);
        a.servfail_by_status.insert("refreshed".into(), 10);
        a.servfail_by_upstream.insert("none".into(), 10);
        let b = &mut hours[30];
        *b = bucket(b.start_unix_seconds, 208, 3);
        b.servfail_by_status.insert("forwarded".into(), 3);
        b.servfail_by_upstream.insert("quad9-2".into(), 3);
        b.slow = 2;
        b.slow_by_status.insert("forwarded".into(), 2);
        b.slow_by_upstream.insert("quad9-1".into(), 2);
        b.slow_by_rcode.insert("NOERROR".into(), 2);
        Part {
            node: Some("pi".into()),
            hours,
            clients: vec![item("192.168.10.185", 10, 0), item("192.168.10.20", 3, 0)],
            names: vec![
                item("x.example", 10, 0),
                item("b1.example", 1, 0),
                item("b2.example", 1, 0),
                item("b3.example", 1, 0),
            ],
            top_hours: 48,
            partial: false,
            privacy: 0,
        }
    }

    fn settings() -> slo::Settings {
        slo::Settings::default()
    }

    // REQ: OBS-027 — the acceptance fixture: who, what, and exactly how much.
    #[test]
    fn obs_027_the_fixture_is_attributed() {
        let parts = [fixture()];
        let to = H0 + 48 * 3600;
        let a = attribute(&settings(), Kind::Availability, &parts, H0, to, "hour", 10);
        assert_eq!(a.budget.answered, 10_000);
        assert_eq!(a.budget.bad, 13);
        assert_eq!(a.budget.allowed_bad, 10);
        assert_eq!(
            (
                a.by_client[0].key.as_str(),
                a.by_client[0].bad,
                a.by_client[0].share_pct
            ),
            ("192.168.10.185", 10, 76.9)
        );
        assert_eq!(a.by_client[1].bad, 3);
        assert!(!a.by_client[0].exact);
        assert_eq!(
            (a.by_name[0].key.as_str(), a.by_name[0].bad),
            ("x.example", 10)
        );
        assert_eq!(
            (a.by_status[0].key.as_str(), a.by_status[0].bad),
            ("refreshed", 10)
        );
        let up: Vec<(&str, u64, bool)> = a
            .by_upstream
            .iter()
            .map(|r| (r.key.as_str(), r.bad, r.exact))
            .collect();
        assert_eq!(up, [("none", 10, true), ("quad9-2", 3, true)]);
        assert_eq!(
            a.by_upstream.iter().map(|r| r.bad).sum::<u64>(),
            a.budget.bad
        );
        assert_eq!(a.by_rcode[0].key, "SERVFAIL");
        assert_eq!(
            a.timeline.iter().map(|p| p.bad).sum::<u64>(),
            13,
            "equals the buckets' SERVFAILs"
        );
        assert_eq!(a.timeline.len(), 48);
        assert_eq!(a.by_node[0].key, "pi");
        assert_eq!(a.coverage.partial_nodes, Vec::<String>::new());
        let l = attribute(&settings(), Kind::Latency, &parts, H0, to, "day", 10);
        assert_eq!(l.budget.bad, 2);
        assert_eq!(l.by_rcode[0].key, "NOERROR");
        assert_eq!(l.by_upstream[0].key, "quad9-1");
        assert_eq!(l.timeline.len(), 2, "two days");
    }

    // REQ: OBS-027 — a node on an older build: a timeline from its counts, listed as partial.
    #[test]
    fn obs_027_older_nodes_are_partial_not_errors() {
        let mut old = fixture();
        old.node = Some("old".into());
        for b in &mut old.hours {
            b.servfail_by_status.clear();
            b.servfail_by_upstream.clear();
        }
        old.clients.clear();
        old.names.clear();
        let parts = [fixture(), old];
        let a = attribute(
            &settings(),
            Kind::Availability,
            &parts,
            H0,
            H0 + 48 * 3600,
            "hour",
            10,
        );
        assert_eq!(a.budget.bad, 26);
        assert_eq!(a.coverage.partial_nodes, ["old"]);
        assert_eq!(
            a.timeline
                .iter()
                .filter(|p| p.node.as_deref() == Some("old"))
                .map(|p| p.bad)
                .sum::<u64>(),
            13
        );
        assert_eq!(a.by_node.len(), 2);
    }

    // REQ: OBS-027 — privacy levels: names hidden (hashes) at 1, no clients at 2, the timeline
    // only at 3.
    #[test]
    fn obs_027_privacy_levels() {
        let to = H0 + 48 * 3600;
        let at = |level: u8| {
            let mut p = fixture();
            p.privacy = level;
            attribute(&settings(), Kind::Availability, &[p], H0, to, "hour", 10)
        };
        let one = at(1);
        assert_eq!(one.coverage.hidden, ["names_hidden"]);
        assert_eq!(one.by_client.len(), 2);
        let two = at(2);
        assert_eq!(two.by_client, Vec::<AttributionRow>::new());
        assert_eq!(two.by_name.len(), 4);
        let three = at(3);
        assert_eq!(
            (
                three.by_name.len(),
                three.by_status.len(),
                three.by_node.len()
            ),
            (0, 0, 0)
        );
        assert_eq!(three.timeline.len(), 48);
    }

    // REQ: OBS-027 — two nodes sum; the top lists add per key with their error bounds.
    #[test]
    fn obs_027_nodes_sum() {
        let mut k8s = fixture();
        k8s.node = Some("k8s".into());
        k8s.clients = vec![item("192.168.10.185", 4, 2)];
        let a = attribute(
            &settings(),
            Kind::Availability,
            &[fixture(), k8s],
            H0,
            H0 + 48 * 3600,
            "hour",
            10,
        );
        assert_eq!(a.budget.answered, 20_000);
        assert_eq!(
            (a.by_client[0].bad, a.by_client[0].error_max),
            (14, Some(2))
        );
        assert_eq!(a.coverage.top_lists_from_hours, 96);
    }

    #[test]
    fn obs_027_objectives_parse() {
        assert!(kind_of(None).is_ok());
        assert!(kind_of(Some("latency")).is_ok());
        assert!(kind_of(Some("speed")).is_err());
    }
}
