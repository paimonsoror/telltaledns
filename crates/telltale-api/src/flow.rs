//! REQ: OBS-032 (ADR-132) — the query flow: groups → decision (status) → upstream → response
//! code, every link an exact counter (the time buckets' joint counts, or one device's rows in
//! the query log).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::model::{Step, TimeBucket, VqlogResult};
use crate::problem::{Code, Problem};
use crate::{Shared, blocking, pick, time_param, vqlog};

/// How far back one device's flow reads (the query log, scanned).
pub const DEVICE_WINDOW_S: u64 = 24 * 3600;

/// `GET /api/v1/stats/flow` parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct FlowParams {
    /// Start (RFC 3339 or relative; default 1 hour ago, or 24 hours for a device).
    #[param(example = "-1h")]
    pub from: Option<String>,
    /// End (default now).
    pub to: Option<String>,
    /// One device (its address): its flow from the query log, over at most the last 24 hours.
    pub client: Option<String>,
    /// `cluster` (default), `site:<name>`, `node:<name or ID>`, or `node:local`.
    pub scope: Option<String>,
}

/// One node of the diagram.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FlowNode {
    /// `<stage>:<name>`, what links name.
    pub id: String,
    /// `group`, `status`, `upstream`, or `rcode`.
    pub stage: String,
    pub name: String,
    /// Answers through it (the larger of what comes in and what goes out).
    pub count: u64,
    /// Answers that end here (a dropped query has no response code).
    pub dead_end: u64,
}

/// One link: answers counted for exactly this pair.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FlowLink {
    pub source: String,
    pub target: String,
    pub count: u64,
    /// Into a SERVFAIL (status or response code).
    pub failure: bool,
}

/// REQ: OBS-032 — where queries went.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct QueryFlow {
    pub from: String,
    pub to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// `buckets` (the time buckets' joint counts) or `querylog` (one device's rows).
    pub source: String,
    /// Answers in the window (group → status links add up to it).
    pub total: u64,
    /// By stage (groups, statuses, upstreams, response codes), largest first.
    pub nodes: Vec<FlowNode>,
    pub links: Vec<FlowLink>,
    /// Some buckets had answers but no joint counts (stored by an older build, or a node that
    /// doesn't count them yet): their answers are missing here.
    pub partial: bool,
    /// The query log read stopped early, or had more combinations than it returns: the numbers
    /// cover what it read.
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

const STAGES: [&str; 4] = ["group", "status", "upstream", "rcode"];

/// A joint key's link: `gs:<group>/<status>`, `sr:<status>/<rcode>`, `su:<status>/<upstream>`,
/// `ur:<upstream>/<rcode>` (group and upstream names may hold a `/`; statuses and codes don't).
fn link_of(key: &str) -> Option<(String, String)> {
    let (kind, rest) = key.split_at_checked(3)?;
    let (a, b) = match kind {
        "gs:" | "ur:" => rest.rsplit_once('/')?,
        "sr:" | "su:" => rest.split_once('/')?,
        _ => return None,
    };
    let (sa, sb) = match kind {
        "gs:" => ("group", "status"),
        "sr:" => ("status", "rcode"),
        "su:" => ("status", "upstream"),
        _ => ("upstream", "rcode"),
    };
    Some((format!("{sa}:{a}"), format!("{sb}:{b}")))
}

/// The diagram of `joints`: links as counted, nodes with what flows through them.
pub fn diagram(joints: &BTreeMap<String, u64>) -> (Vec<FlowNode>, Vec<FlowLink>) {
    let mut links: Vec<FlowLink> = joints
        .iter()
        .filter(|(_, n)| **n > 0)
        .filter_map(|(k, n)| {
            let (source, target) = link_of(k)?;
            Some(FlowLink {
                failure: target == "rcode:SERVFAIL" || target == "status:servfail",
                source,
                target,
                count: *n,
            })
        })
        .collect();
    links.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.source.cmp(&b.source)));
    let mut ins: BTreeMap<&str, u64> = BTreeMap::new();
    let mut outs: BTreeMap<&str, u64> = BTreeMap::new();
    for l in &links {
        *outs.entry(l.source.as_str()).or_default() += l.count;
        *ins.entry(l.target.as_str()).or_default() += l.count;
    }
    let mut nodes: Vec<FlowNode> = ins
        .keys()
        .chain(outs.keys())
        .copied()
        .collect::<std::collections::BTreeSet<&str>>()
        .into_iter()
        .filter_map(|id| {
            let (stage, name) = id.split_once(':')?;
            let i = ins.get(id).copied().unwrap_or(0);
            let o = outs.get(id).copied().unwrap_or(0);
            Some(FlowNode {
                id: id.to_owned(),
                stage: stage.to_owned(),
                name: name.to_owned(),
                count: i.max(o),
                dead_end: if stage == "status" || stage == "upstream" {
                    i.saturating_sub(o)
                } else {
                    0
                },
            })
        })
        .collect();
    nodes.sort_by(|a, b| {
        let at = |s: &str| STAGES.iter().position(|x| *x == s).unwrap_or(STAGES.len());
        at(&a.stage)
            .cmp(&at(&b.stage))
            .then(b.count.cmp(&a.count))
            .then_with(|| a.name.cmp(&b.name))
    });
    (nodes, links)
}

/// The buckets' joints summed, their answers, and whether some had answers but no joints.
pub fn from_buckets(buckets: &[TimeBucket]) -> (BTreeMap<String, u64>, u64, bool) {
    let mut joints: BTreeMap<String, u64> = BTreeMap::new();
    let mut total = 0u64;
    let mut partial = false;
    for b in buckets {
        total += u64::from(b.total);
        if b.total > 0 && b.flow.is_empty() {
            partial = true;
        }
        for (k, n) in &b.flow {
            *joints.entry(k.clone()).or_default() += u64::from(*n);
        }
    }
    (joints, total, partial)
}

/// The joints of a vqlog `by group, status, upstream, rcode | stats count` table, counted as
/// the aggregator counts them; and the rows' answers.
pub fn from_rows(table: &VqlogResult) -> (BTreeMap<String, u64>, u64) {
    let col = |name: &str| table.columns.iter().position(|c| c == name);
    let (Some(gi), Some(si), Some(ui), Some(ri), Some(ni)) = (
        col("group"),
        col("status"),
        col("upstream"),
        col("rcode"),
        col("count"),
    ) else {
        return (BTreeMap::new(), 0);
    };
    let mut joints: BTreeMap<String, u64> = BTreeMap::new();
    let mut total = 0;
    for row in &table.rows {
        let text = |i: usize| row.get(i).and_then(|v| v.as_str()).map(str::to_owned);
        let count = row.get(ni).and_then(serde_json::Value::as_u64).unwrap_or(0);
        let (Some(group), Some(status)) = (text(gi), text(si)) else {
            continue;
        };
        total += count;
        let rcode = text(ri).filter(|c| c != "none");
        let mut add = |k: String| *joints.entry(k).or_default() += count;
        add(format!("gs:{group}/{status}"));
        if let Some(up) = text(ui) {
            add(format!("su:{status}/{up}"));
            if let Some(rcode) = &rcode {
                add(format!("ur:{up}/{rcode}"));
            }
        } else if let Some(rcode) = &rcode {
            add(format!("sr:{status}/{rcode}"));
        }
    }
    (joints, total)
}

/// Where queries went.
///
/// The query flow as a diagram's data: groups → decision (status) → upstream → response code.
/// Each link is a counter incremented for exactly that pair as queries were answered (no
/// proportional split): `group:<name> → status:<label>` for every answer, then
/// `status → upstream:<name> → rcode:<name>` for answers an upstream was asked for and
/// `status → rcode` for the rest; a status or upstream whose `count` exceeds what leaves it
/// has `deadEnd` answers (dropped queries get no response code). Every node's, summed, from the
/// time buckets (`source: buckets`; `partial` when some lacked the counts). With `client`, one
/// device's flow from the query log over at most the last 24 hours (`source: querylog`;
/// `truncated` when the read stopped early); refused at privacy level 2 and above. Example:
/// `GET /api/v1/stats/flow?from=-6h`.
#[utoipa::path(get, path = "/api/v1/stats/flow", tag = "stats", params(FlowParams),
    responses(
        (status = 200, body = QueryFlow, description = "Nodes and links."),
        (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it."),
        (status = 422, body = Problem, description = "`privacy_level`: the privacy level hides devices."),
        (status = 503, body = Problem, description = "A device's flow needs the query log, which is off.")))]
pub(crate) async fn stats_flow(
    State(b): State<Shared>,
    Query(p): Query<FlowParams>,
) -> Result<Json<QueryFlow>, Problem> {
    let b = pick(&b, p.scope.as_deref())?;
    let now = b.now_unix_seconds();
    let client = match p.client.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        None => None,
        Some(c) => Some(c.parse::<std::net::IpAddr>().map_err(|_| {
            Problem::invalid(format!("`client`: `{c}` isn't an address"))
                .hint("Give the device's IP address (the Clients page lists them).")
        })?),
    };
    let back = if client.is_some() {
        DEVICE_WINDOW_S
    } else {
        3600
    };
    let mut from = time_param(p.from.as_deref(), now.saturating_sub(back), now, "from")?;
    let to = time_param(p.to.as_deref(), now + 1, now, "to")?;
    if from >= to {
        return Err(Problem::invalid("`from` must be before `to`"));
    }
    let bk = Arc::clone(&b);
    let mut out = if let Some(ip) = client {
        let privacy = b.qlog_privacy_level();
        if privacy >= 2 {
            return Err(Problem::new(
                Code::PrivacyLevel,
                format!("the query log's privacy level ({privacy}) hides devices"),
            )
            .hint("The network's flow works at every level."));
        }
        from = from.max(to.saturating_sub(DEVICE_WINDOW_S));
        let q = vqlog::parse(&format!(
            "where client = \"{ip}\" | by group, status, upstream, rcode | stats count | limit {}",
            vqlog::MAX_LIMIT
        ))
        .map_err(|e| Problem::invalid(e.message))?;
        let (from_us, to_us) = (from.saturating_mul(1_000_000), to.saturating_mul(1_000_000));
        let r = blocking(move || bk.vqlog(&q, from_us, to_us, false)).await?;
        let (joints, total) = from_rows(&r);
        let (nodes, links) = diagram(&joints);
        QueryFlow {
            client: Some(ip.to_string()),
            source: "querylog".into(),
            total,
            nodes,
            links,
            truncated: r.truncated || usize::try_from(r.groups).unwrap_or(0) > r.rows.len(),
            ..QueryFlow::default()
        }
    } else {
        let step = match to - from {
            s if s <= 48 * 3600 => Step::Minute,
            s if s <= 400 * 86_400 => Step::Hour,
            _ => Step::Day,
        };
        let buckets = blocking(move || Ok(bk.timeseries(step, from, to))).await?;
        let (joints, total, partial) = from_buckets(&buckets);
        let (nodes, links) = diagram(&joints);
        QueryFlow {
            source: "buckets".into(),
            total,
            nodes,
            links,
            partial,
            ..QueryFlow::default()
        }
    };
    out.from = crate::time::format_us(from.saturating_mul(1_000_000));
    out.to = crate::time::format_us(to.saturating_mul(1_000_000));
    out.missing_nodes = b.missing_nodes();
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn joints(v: &[(&str, u64)]) -> BTreeMap<String, u64> {
        v.iter().map(|(k, n)| ((*k).to_owned(), *n)).collect()
    }

    // REQ: OBS-032 — links are the counters; every group's out equals its count; a status's in
    // equals its out plus its dead end; the SERVFAILs from one upstream are exactly that link
    // and tinted.
    #[test]
    fn obs_032_diagram_keeps_every_count_exact() {
        let j = joints(&[
            ("gs:default/cached", 500),
            ("gs:kids/blocked", 200),
            ("gs:default/forwarded", 80),
            ("gs:kids/forwarded", 170),
            ("gs:default/servfail", 40),
            ("gs:default/dropped", 10),
            ("sr:cached/NOERROR", 500),
            ("sr:blocked/NXDOMAIN", 200),
            ("su:forwarded/quad9-1", 160),
            ("su:forwarded/quad9-2", 90),
            ("su:servfail/quad9-1", 40),
            ("ur:quad9-1/NOERROR", 160),
            ("ur:quad9-1/SERVFAIL", 40),
            ("ur:quad9-2/NOERROR", 90),
        ]);
        let (nodes, links) = diagram(&j);
        let node = |id: &str| nodes.iter().find(|n| n.id == id).unwrap();
        assert_eq!(node("group:default").count, 630);
        assert_eq!(node("group:kids").count, 370);
        assert_eq!(node("status:dropped").dead_end, 10);
        assert_eq!(node("status:forwarded").count, 250);
        assert_eq!(node("status:forwarded").dead_end, 0);
        assert_eq!(node("upstream:quad9-1").count, 200);
        assert_eq!(node("rcode:NOERROR").count, 750);
        let groups: u64 = links
            .iter()
            .filter(|l| l.source.starts_with("group:"))
            .map(|l| l.count)
            .sum();
        assert_eq!(groups, 1000);
        let sf = links
            .iter()
            .find(|l| l.source == "upstream:quad9-1" && l.target == "rcode:SERVFAIL")
            .unwrap();
        assert_eq!(sf.count, 40);
        assert!(sf.failure);
        assert_eq!(
            nodes.iter().map(|n| n.stage.as_str()).collect::<Vec<_>>()[..2],
            ["group", "group"],
            "by stage, largest first"
        );
        assert_eq!(nodes[0].name, "default");
    }

    // REQ: OBS-032 — buckets without joints make the flow partial; quiet ones don't.
    #[test]
    fn obs_032_buckets_without_joints_are_partial() {
        let mut a = TimeBucket {
            total: 10,
            ..TimeBucket::default()
        };
        a.flow.insert("gs:default/cached".into(), 10);
        let old = TimeBucket {
            total: 5,
            ..TimeBucket::default()
        };
        let (j, total, partial) = from_buckets(&[a.clone(), old]);
        assert_eq!((j["gs:default/cached"], total, partial), (10, 15, true));
        let quiet = TimeBucket::default();
        assert!(!from_buckets(&[a, quiet]).2);
    }

    // REQ: OBS-032 — a device's query-log rows counted like the aggregator: an upstream row
    // goes status → upstream → code; a dropped row (no code) ends at its status.
    #[test]
    fn obs_032_rows_from_the_query_log() {
        let r = VqlogResult {
            columns: ["group", "status", "upstream", "rcode", "count"]
                .map(String::from)
                .to_vec(),
            rows: vec![
                serde_json::json!(["kids", "forwarded", "quad9", "NOERROR", 7])
                    .as_array()
                    .cloned()
                    .unwrap_or_default(),
                serde_json::json!(["kids", "cached", null, "NOERROR", 3])
                    .as_array()
                    .cloned()
                    .unwrap_or_default(),
                serde_json::json!(["kids", "dropped", null, "none", 1])
                    .as_array()
                    .cloned()
                    .unwrap_or_default(),
            ],
            ..VqlogResult::default()
        };
        let (j, total) = from_rows(&r);
        assert_eq!(total, 11);
        assert_eq!(j["su:forwarded/quad9"], 7);
        assert_eq!(j["ur:quad9/NOERROR"], 7);
        assert_eq!(j["sr:cached/NOERROR"], 3);
        assert_eq!(j["gs:kids/dropped"], 1);
        assert_eq!(j.len(), 6, "three groups → status, su, ur, sr");
        let (nodes, _) = diagram(&j);
        let dropped = nodes.iter().find(|n| n.id == "status:dropped").unwrap();
        assert_eq!(dropped.dead_end, 1);
    }
}
