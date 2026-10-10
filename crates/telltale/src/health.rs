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
    /// REQ: OBS-020 — its synthetic probes, and when a certificate expiring counts.
    pub(crate) probes: &'a [telltale_api::model::ProbeResult],
    pub(crate) cert_warn_days: u32,
}

/// REQ: OBS-020 (ADR-107) — listeners (or extra targets) that failed their probe twice in a
/// row are degraded; when every probed listener does, the node isn't serving DNS (`not_serving`,
/// severe unless other nodes serve). A certificate within `cert_warn_days` is degraded; an
/// expired one is severe: DoT/DoH/DoQ clients can't connect.
fn probe_reasons(l: &Local<'_>, out: &mut Vec<HealthReason>) {
    let failing = |p: &&telltale_api::model::ProbeResult| {
        p.skipped.is_none() && p.consecutive_failures >= crate::probes::FAILING_AFTER
    };
    let listeners: Vec<_> = l
        .probes
        .iter()
        .filter(|p| p.listener && p.skipped.is_none())
        .collect();
    if l.serving && !listeners.is_empty() && listeners.iter().all(failing) {
        out.push(reason(
            SEVERE,
            "not_serving",
            "isn't answering DNS: none of its listeners answers its own probe".into(),
            "#/settings?tab=system",
        ));
    } else {
        for p in l.probes.iter().filter(failing) {
            let what = if p.listener {
                "listener"
            } else {
                "probe target"
            };
            out.push(reason(
                DEGRADED,
                "probe_failing",
                format!(
                    "{what} {} doesn't answer its probe ({} in a row: {})",
                    p.target,
                    p.consecutive_failures,
                    p.error.as_deref().unwrap_or("no answer")
                ),
                "#/settings?tab=system",
            ));
        }
    }
    for p in l.probes {
        match p.cert_days_left {
            Some(d) if d < 0 => out.push(reason(
                SEVERE,
                "cert_expired",
                format!(
                    "the certificate of {} expired {} day(s) ago: encrypted DNS clients can't connect",
                    p.target, -d
                ),
                "#/settings?tab=system",
            )),
            Some(d) if d < i64::from(l.cert_warn_days) => out.push(reason(
                DEGRADED,
                "cert_expiring",
                format!("the certificate of {} expires in {d} day(s)", p.target),
                "#/settings?tab=system",
            )),
            _ => {}
        }
    }
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
    probe_reasons(l, &mut out);
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
        // REQ: OBS-023 (T12.3) — downloads fine, but its content stopped changing.
        if list.enabled
            && list.error.is_none()
            && let Some(days) = list.stale_days
        {
            out.push(reason(
                DEGRADED,
                "list_stale",
                format!(
                    "list {} hasn't changed in {days} days: its source may be abandoned",
                    list.name
                ),
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
        maintenance: Vec::new(),
    }
}

/// REQ: OPS-010 (ADR-118) — leaves out the conditions of nodes in maintenance (by the label
/// reasons carry: pod, site, or ID) and lists those nodes instead. `missing` drops them too:
/// a node stopped during its window is expected to be silent.
pub(crate) fn exclude_maintenance(
    reasons: &mut Vec<HealthReason>,
    missing: &mut Vec<String>,
    view: &ClusterView,
) -> Vec<telltale_api::model::NodeMaintenance> {
    let mut out = Vec::new();
    let mut names: HashSet<String> = HashSet::new();
    for n in &view.nodes {
        if let Some(m) = &n.maintenance {
            let name = node_name(n);
            names.insert(name.clone());
            // Probe and federated labels may use the site or the ID where a pod has none.
            names.insert(n.node_id.clone());
            if !n.site.is_empty() && n.pod.is_none() {
                names.insert(n.site.clone());
            }
            let mut m = m.clone();
            m.node = Some(name);
            out.push(m);
        }
    }
    if names.is_empty() {
        return out;
    }
    reasons.retain(|r| r.node.as_ref().is_none_or(|n| !names.contains(n)));
    missing.retain(|n| !names.contains(n));
    out.sort_by(|a, b| a.node.cmp(&b.node));
    out
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
            probes: &[],
            cert_warn_days: 14,
        }
    }

    fn probe(
        target: &str,
        listener: bool,
        failures: u32,
        cert_days: Option<i64>,
    ) -> telltale_api::model::ProbeResult {
        telltale_api::model::ProbeResult {
            target: target.into(),
            proto: "udp".into(),
            listener,
            ok: failures == 0,
            consecutive_failures: failures,
            cert_days_left: cert_days,
            ..telltale_api::model::ProbeResult::default()
        }
    }

    // REQ: OBS-020 (ADR-107) — a probe failing twice degrades; every listener failing is
    // `not_serving`; one blip doesn't count; certificates degrade near expiry, expired is
    // severe.
    #[test]
    fn obs_020_probes_and_certificates() {
        let ps = [
            probe("udp://127.0.0.1:53", true, 0, None),
            probe("tls://127.0.0.1:853", true, 3, Some(40)),
            probe("udp://192.168.5.112:53", false, 1, None),
        ];
        let mut l = local(&[], &[]);
        l.probes = &ps;
        assert_eq!(
            codes(&summarize(local_reasons(&l), vec![], String::new())),
            vec![("degraded", "probe_failing")]
        );
        let all = [
            probe("udp://127.0.0.1:53", true, 2, None),
            probe("tcp://127.0.0.1:53", true, 5, None),
        ];
        l.probes = &all;
        let mut r = local_reasons(&l);
        assert_eq!(
            codes(&summarize(r.clone(), vec![], String::new())),
            vec![("severe", "not_serving")]
        );
        soften_not_serving(&mut r, 2);
        assert_eq!(
            summarize(r, vec![], String::new()).level,
            "degraded",
            "others serve"
        );
        let certs = [
            probe("tls://127.0.0.1:853", true, 0, Some(5)),
            probe("https://127.0.0.1:443/dns-query", true, 0, Some(-2)),
        ];
        l.probes = &certs;
        let h = summarize(local_reasons(&l), vec![], String::new());
        assert_eq!(
            codes(&h),
            vec![("severe", "cert_expired"), ("degraded", "cert_expiring")]
        );
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

    // REQ: OPS-010 (ADR-118) — a node in maintenance that went silent: its `node_down` and
    // its own reasons are left out, it isn't "missing", and it's listed under `maintenance`;
    // the level stays healthy. Another node's reasons still count.
    #[test]
    fn ops_010_health_leaves_out_nodes_in_maintenance() {
        use telltale_api::model::{ClusterNode, NodeMaintenance};
        let node = |id: &str, site: &str| ClusterNode {
            node_id: id.into(),
            site: site.into(),
            ..ClusterNode::default()
        };
        let mut me = node("a1", "k8s");
        me.this_node = true;
        me.connected = true;
        let mut pi = node("b2", "pi");
        pi.last_seen_seconds_ago = 40;
        pi.maintenance = Some(NodeMaintenance {
            until: "2026-10-09T14:00:00Z".into(),
            reason: "SD card swap".into(),
            by: "alice".into(),
            seconds_left: 600,
            ..NodeMaintenance::default()
        });
        let view = ClusterView {
            enabled: true,
            cluster_id: None,
            name: None,
            this_node: Some("a1".into()),
            newest_config_seq: 1,
            healthy: true,
            checks: Vec::new(),
            nodes: vec![me, pi],
            events: Vec::new(),
            authority: None,
            conflicts: Vec::new(),
            failover: None,
            source: None,
            host: None,
        };
        let mut reasons = cluster_reasons(&view);
        assert_eq!(reasons.len(), 1, "node_down for pi");
        let mut probe = reason(DEGRADED, "probe_failing", "x".into(), "#/");
        probe.node = Some("pi".into());
        reasons.push(probe);
        let mut other = reason(DEGRADED, "disk_full", "y".into(), "#/");
        other.node = Some("k8s".into());
        let mut missing = vec!["pi".to_owned()];
        let m = exclude_maintenance(&mut reasons, &mut missing, &view);
        assert!(
            reasons.is_empty() && missing.is_empty(),
            "{reasons:?} {missing:?}"
        );
        assert_eq!(m.len(), 1);
        assert_eq!(
            (m[0].node.as_deref(), m[0].reason.as_str()),
            (Some("pi"), "SD card swap")
        );
        let mut h = summarize(reasons, missing, String::new());
        h.maintenance = m;
        assert_eq!(h.level, "healthy");
        let mut with_other = vec![other];
        exclude_maintenance(&mut with_other, &mut Vec::new(), &view);
        assert_eq!(
            summarize(with_other, vec![], String::new()).level,
            "degraded"
        );
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

    // REQ: OBS-015, OBS-023 — failing and stale lists and a full disk degrade; severe reasons
    // sort first.
    #[test]
    fn obs_015_lists_disk_and_order() {
        let failing = ListInfo {
            name: "hagezi".into(),
            kind: "block".into(),
            enabled: true,
            mode: "enforce".into(),
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
            stale_days: None,
        };
        let stale = ListInfo {
            name: "old".into(),
            state: "ok".into(),
            error: None,
            stale_days: Some(45),
            ..failing.clone()
        };
        let lists = [failing, stale];
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
        assert!(
            h.reasons
                .iter()
                .any(|r| r.code == "list_stale"
                    && r.summary.contains("old hasn't changed in 45 days")),
            "{:?}",
            h.reasons
        );
        assert!(h.reasons.iter().any(|r| r.code == "disk_full"));
    }
}
