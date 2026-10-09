//! REQ: OBS-015 (ADR-104) — one word for how TelltaleDNS is doing (`healthy`, `degraded`,
//! `severe`) and the reasons, for the web UI's health icon, scripts, and agents.
//!
//! - **severe:** DNS fails for some devices: every upstream of a group down, no node serving, or
//!   SERVFAIL for [`SERVFAIL_SEVERE`]% of the last 5 minutes' queries.
//! - **degraded:** DNS answers, but something needs a look: one upstream down, a node
//!   unreachable, not serving, or behind on configuration, a list failing to download, devices
//!   rate-limited, SERVFAIL for [`SERVFAIL_DEGRADED`]%, a data disk over [`DISK_FULL`]% full.
//!
//! Each condition is judged over a window it already has (the circuit breaker, the last 5
//! minutes, the cluster heartbeat), so a single blip doesn't flip the level. Device anomalies
//! don't count (they have their own badge). Pure functions over what the API already reads;
//! nothing here touches the query path.

use std::collections::{BTreeMap, HashSet};

use telltale_api::model::{ClusterView, Health, HealthReason, ListInfo, TimeBucket, UpstreamInfo};

pub(crate) const DEGRADED: &str = "degraded";
pub(crate) const SEVERE: &str = "severe";
/// SERVFAIL shares (percent) over the last 5 minutes that degrade or are severe...
pub(crate) const SERVFAIL_DEGRADED: f64 = 5.0;
pub(crate) const SERVFAIL_SEVERE: f64 = 25.0;
/// ...once there were at least this many queries.
const MIN_QUERIES: u64 = 50;
/// A data disk fuller than this (percent) degrades.
pub(crate) const DISK_FULL: f64 = 90.0;
/// A replica behind the primary's configuration for this long degrades.
const SYNC_LAG_SECONDS: u64 = 60;

fn reason(level: &str, code: &str, summary: String, link: &str) -> HealthReason {
    HealthReason {
        level: level.to_owned(),
        code: code.to_owned(),
        summary,
        node: None,
        link: Some(link.to_owned()),
    }
}

/// What one node knows about itself.
pub(crate) struct Local<'a> {
    /// Its DNS listeners are bound and it isn't shutting down.
    pub(crate) serving: bool,
    pub(crate) upstreams: &'a [UpstreamInfo],
    /// Minute buckets of the last 5 minutes.
    pub(crate) recent: &'a [TimeBucket],
    /// Its lists, when it downloads them (a replica takes the primary's snapshot instead).
    pub(crate) lists: Option<&'a [ListInfo]>,
    pub(crate) disk_used_percent: Option<f64>,
}

/// One node's own conditions.
pub(crate) fn local_reasons(l: &Local<'_>) -> Vec<HealthReason> {
    let mut out = Vec::new();
    if !l.serving {
        out.push(reason(
            SEVERE,
            "not_serving",
            "isn't answering DNS: its listeners aren't bound, or it's shutting down".into(),
            "#/cluster",
        ));
    }
    upstream_reasons(l.upstreams, &mut out);
    let sum =
        |f: &dyn Fn(&TimeBucket) -> u32| -> u64 { l.recent.iter().map(|b| u64::from(f(b))).sum() };
    let total = sum(&|b| b.total);
    let limited = sum(&|b| b.by_status.get("rate_limited").copied().unwrap_or(0));
    if limited > 0 {
        out.push(reason(
            DEGRADED,
            "rate_limited",
            format!(
                "{limited} quer{} rate-limited in the last 5 minutes: a device asked faster than the per-client limit allows",
                if limited == 1 { "y was" } else { "ies were" }
            ),
            "#/queries?status=rate_limited&from=-5m",
        ));
    }
    let servfail = sum(&|b| b.by_rcode.get("SERVFAIL").copied().unwrap_or(0));
    if total >= MIN_QUERIES {
        #[allow(clippy::cast_precision_loss)] // query counts
        let pct = servfail as f64 * 100.0 / total as f64;
        let level = if pct >= SERVFAIL_SEVERE {
            Some(SEVERE)
        } else if pct >= SERVFAIL_DEGRADED {
            Some(DEGRADED)
        } else {
            None
        };
        if let Some(level) = level {
            out.push(reason(
                level,
                "servfail_rate",
                format!("SERVFAIL for {pct:.1}% of {total} queries in the last 5 minutes"),
                "#/queries?rcode=SERVFAIL&from=-5m",
            ));
        }
    }
    for list in l.lists.unwrap_or_default() {
        if list.enabled
            && let Some(e) = &list.error
        {
            out.push(reason(
                DEGRADED,
                "list_failing",
                format!("list {} fails to update: {e}", list.name),
                "#/lists",
            ));
        }
    }
    if let Some(d) = l.disk_used_percent.filter(|d| *d > DISK_FULL) {
        out.push(reason(
            DEGRADED,
            "disk_full",
            format!("its data disk is {d:.0}% full"),
            "#/settings?tab=system",
        ));
    }
    out
}

/// Upstreams that aren't answering (an open or half-open circuit breaker): severe when that
/// leaves a group with none, degraded otherwise.
fn upstream_reasons(upstreams: &[UpstreamInfo], out: &mut Vec<HealthReason>) {
    let down = |u: &UpstreamInfo| u.breaker != "closed";
    let mut groups: BTreeMap<&str, (usize, Vec<&str>)> = BTreeMap::new();
    for u in upstreams {
        for g in &u.groups {
            let e = groups.entry(g.as_str()).or_default();
            e.0 += 1;
            if down(u) {
                e.1.push(u.name.as_str());
            }
        }
    }
    let mut covered: HashSet<&str> = HashSet::new();
    for (g, (members, down_names)) in &groups {
        if *members > 0 && down_names.len() == *members {
            out.push(reason(
                SEVERE,
                "upstream_group_down",
                format!(
                    "no upstream in group {g} is answering ({}): its devices' lookups fail",
                    down_names.join(", ")
                ),
                "#/upstreams",
            ));
            covered.extend(down_names.iter().copied());
        }
    }
    for u in upstreams
        .iter()
        .filter(|u| down(u) && !covered.contains(u.name.as_str()))
    {
        out.push(reason(
            DEGRADED,
            "upstream_down",
            format!(
                "upstream {} isn't answering (its circuit breaker is {}); the rest of its group answers",
                u.name,
                u.breaker.replace('_', "-")
            ),
            "#/upstreams",
        ));
    }
}

/// The cluster's own conditions, as this node sees them: peers unreachable or behind.
pub(crate) fn cluster_reasons(view: &ClusterView) -> Vec<HealthReason> {
    let mut out = Vec::new();
    if !view.enabled {
        return out;
    }
    for n in view.nodes.iter().filter(|n| !n.this_node && !n.witness) {
        let name = node_name(n);
        if !n.ephemeral && !n.connected {
            let mut r = reason(
                DEGRADED,
                "node_down",
                format!(
                    "cluster node {name} is unreachable (last seen {} s ago)",
                    n.last_seen_seconds_ago
                ),
                "#/cluster",
            );
            r.node = Some(name);
            out.push(r);
        } else if n.connected
            && n.config_lag > 0
            && n.behind_seconds.is_some_and(|s| s >= SYNC_LAG_SECONDS)
        {
            let mut r = reason(
                DEGRADED,
                "sync_lag",
                format!(
                    "{name} is {} configuration version(s) behind the primary (for {} s)",
                    n.config_lag,
                    n.behind_seconds.unwrap_or(0)
                ),
                "#/cluster",
            );
            r.node = Some(name);
            out.push(r);
        }
    }
    out
}

/// REQ: OBS-016 (ADR-105) — `[slo]` as the API's settings.
pub(crate) fn slo_settings(cfg: &telltale_config::Config) -> telltale_api::slo::Settings {
    let s = &cfg.slo;
    telltale_api::slo::Settings {
        enabled: s.enabled,
        availability_target: s.availability_target,
        latency_target: s.latency_target,
        latency_ms: s.latency_ms,
        window_days: s.window_days,
    }
}

/// REQ: OBS-016 (ADR-105) — degraded while an objective spends its error budget fast (the
/// `fast` or `slow` burn-rate pair), from `b`'s minute buckets of the last 6 hours.
pub(crate) fn slo_reasons(b: &dyn telltale_api::Backend, now: u64) -> Vec<HealthReason> {
    let s = b.slo_settings();
    if !s.enabled {
        return Vec::new();
    }
    let minutes = b.timeseries(
        telltale_api::model::Step::Minute,
        now.saturating_sub(telltale_api::slo::MINUTE_SPAN_S),
        now + 1,
    );
    telltale_api::slo::burning(&s, now, &minutes)
        .into_iter()
        .map(|(_, _, summary)| reason(DEGRADED, "slo_burn", summary, "#/"))
        .collect()
}

/// How the cluster page and every other reason name a node: its pod, else its site, else its ID.
fn node_name(n: &telltale_api::model::ClusterNode) -> String {
    if let Some(pod) = n.pod.as_ref().filter(|p| !p.is_empty()) {
        pod.clone()
    } else if n.site.is_empty() {
        n.node_id.clone()
    } else {
        n.site.clone()
    }
}

/// In a cluster, a node that isn't serving leaves DNS to the others: degraded, unless none of
/// the `reporting` nodes serves.
pub(crate) fn soften_not_serving(reasons: &mut [HealthReason], reporting: usize) {
    let down = reasons.iter().filter(|r| r.code == "not_serving").count();
    if down < reporting {
        for r in reasons.iter_mut().filter(|r| r.code == "not_serving") {
            DEGRADED.clone_into(&mut r.level);
        }
    }
}

/// The level and the reasons, most serious first.
pub(crate) fn summarize(
    mut reasons: Vec<HealthReason>,
    missing_nodes: Vec<String>,
    checked_at: String,
) -> Health {
    let rank = |r: &HealthReason| u8::from(r.level == SEVERE);
    reasons.sort_by(|a, b| {
        rank(b)
            .cmp(&rank(a))
            .then_with(|| a.node.cmp(&b.node))
            .then_with(|| a.code.cmp(&b.code))
    });
    let level = if reasons.iter().any(|r| r.level == SEVERE) {
        SEVERE
    } else if reasons.is_empty() {
        "healthy"
    } else {
        DEGRADED
    };
    Health {
        level: level.to_owned(),
        reasons,
        checked_at,
        missing_nodes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_api::model::FailureKinds;

    fn up(name: &str, groups: &[&str], breaker: &str) -> UpstreamInfo {
        UpstreamInfo {
            id: 1,
            name: name.into(),
            endpoint: format!("udp://{name}"),
            groups: groups.iter().map(|g| (*g).to_owned()).collect(),
            breaker: breaker.into(),
            requests: 0,
            failures: 0,
            failures_by_kind: FailureKinds::default(),
            latency_ewma_ms: 0.0,
        }
    }

    fn local<'a>(ups: &'a [UpstreamInfo], recent: &'a [TimeBucket]) -> Local<'a> {
        Local {
            serving: true,
            upstreams: ups,
            recent,
            lists: None,
            disk_used_percent: Some(40.0),
        }
    }

    fn codes(h: &Health) -> Vec<(&str, &str)> {
        h.reasons
            .iter()
            .map(|r| (r.level.as_str(), r.code.as_str()))
            .collect()
    }

    // REQ: OBS-015 — nothing wrong: healthy, no reasons.
    #[test]
    fn obs_015_all_good_is_healthy() {
        let ups = [
            up("quad9", &["default"], "closed"),
            up("cf", &["default"], "closed"),
        ];
        let h = summarize(local_reasons(&local(&ups, &[])), vec![], String::new());
        assert_eq!(h.level, "healthy");
        assert_eq!(h.reasons.len(), 0);
    }

    // REQ: OBS-015 (owner, 2026-10-08) — one upstream down while the group still answers is
    // degraded; the whole group down is severe.
    #[test]
    fn obs_015_one_upstream_down_degrades_a_whole_group_is_severe() {
        let ups = [
            up("quad9", &["default"], "open"),
            up("cf", &["default"], "closed"),
        ];
        let h = summarize(local_reasons(&local(&ups, &[])), vec![], String::new());
        assert_eq!(
            (h.level.as_str(), codes(&h)),
            ("degraded", vec![("degraded", "upstream_down")])
        );

        let ups = [
            up("quad9", &["default"], "open"),
            up("cf", &["default"], "half_open"),
            up("kids-dns", &["kids"], "closed"),
        ];
        let h = summarize(local_reasons(&local(&ups, &[])), vec![], String::new());
        assert_eq!(h.level, "severe");
        assert_eq!(
            codes(&h),
            vec![("severe", "upstream_group_down")],
            "no per-upstream repeats"
        );
        assert!(
            h.reasons[0].summary.contains("quad9, cf"),
            "{}",
            h.reasons[0].summary
        );
    }

    fn minute(total: u32, rate_limited: u32, servfail: u32) -> TimeBucket {
        let mut b = TimeBucket {
            total,
            ..TimeBucket::default()
        };
        b.by_status.insert("rate_limited".into(), rate_limited);
        b.by_rcode.insert("SERVFAIL".into(), servfail);
        b
    }

    // REQ: OBS-015 (owner, 2026-10-08) — a rate-limited device degrades; SERVFAIL degrades at
    // 5% and is severe at 25%, once there were enough queries to judge.
    #[test]
    fn obs_015_rate_limits_and_servfail() {
        let h = summarize(
            local_reasons(&local(&[], &[minute(100, 3, 0)])),
            vec![],
            String::new(),
        );
        assert_eq!(codes(&h), vec![("degraded", "rate_limited")]);
        let h = summarize(
            local_reasons(&local(&[], &[minute(100, 0, 6)])),
            vec![],
            String::new(),
        );
        assert_eq!(codes(&h), vec![("degraded", "servfail_rate")]);
        let h = summarize(
            local_reasons(&local(&[], &[minute(100, 0, 30)])),
            vec![],
            String::new(),
        );
        assert_eq!(codes(&h), vec![("severe", "servfail_rate")]);
        let h = summarize(
            local_reasons(&local(&[], &[minute(20, 0, 20)])),
            vec![],
            String::new(),
        );
        assert_eq!(h.level, "healthy", "too few queries to judge");
    }

    // REQ: OBS-015 — a node not serving is severe alone, degraded when others serve.
    #[test]
    fn obs_015_not_serving_depends_on_the_others() {
        let mut l = local(&[], &[]);
        l.serving = false;
        let mut r = local_reasons(&l);
        soften_not_serving(&mut r, 1);
        assert_eq!(summarize(r, vec![], String::new()).level, "severe");
        let mut r = local_reasons(&l);
        soften_not_serving(&mut r, 3);
        assert_eq!(summarize(r, vec![], String::new()).level, "degraded");
    }

    // REQ: OBS-015 — failing lists and a full disk degrade; severe reasons sort first.
    #[test]
    fn obs_015_lists_disk_and_order() {
        let lists = [ListInfo {
            name: "hagezi".into(),
            kind: "block".into(),
            enabled: true,
            source: "https://lists.example/hagezi.txt".into(),
            state: "failed".into(),
            error: Some("HTTP 404".into()),
            bytes: 0,
            lines: 0,
            entries: 0,
            unique: 0,
            regex_skipped: 0,
            hits: 0,
            overlap: Vec::new(),
            last_checked_unix_seconds: None,
            last_changed_unix_seconds: None,
        }];
        let ups = [up("quad9", &["default"], "open")];
        let recent = [minute(100, 0, 40)];
        let mut l = local(&ups, &recent);
        l.lists = Some(&lists);
        l.disk_used_percent = Some(95.0);
        let h = summarize(local_reasons(&l), vec![], String::new());
        assert_eq!(h.level, "severe");
        let first_two: Vec<&str> = h.reasons[..2].iter().map(|r| r.code.as_str()).collect();
        assert_eq!(
            first_two,
            ["servfail_rate", "upstream_group_down"],
            "severe first"
        );
        assert!(
            h.reasons
                .iter()
                .any(|r| r.code == "list_failing" && r.level == "degraded")
        );
        assert!(h.reasons.iter().any(|r| r.code == "disk_full"));
    }
}
