//! Alerts (REQ: OBS-010, `spec/06` §8; T7.12): rules over the node's own read model (the same
//! data the API serves, federated in a cluster), checked every `[alerts] interval_secs` on the
//! primary (or a standalone node), sent to webhooks, ntfy, Gotify, or Slack-compatible hooks
//! when a condition has held for the rule's `for_secs`, and again when it clears.
//!
//! Nothing here is on the DNS path: the task reads the API backend on a blocking thread and
//! sends from its own task, with a timeout per delivery. A failing destination is logged and
//! retried at the next change, never queued without bound.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use telltale_api::Backend;
use telltale_api::model::Step;
use telltale_config::{AlertDestination, AlertKind, AlertRule, AlertWhen, Config};
use tracing::{info, warn};

/// What a rule sees right now: `(subject, summary)` pairs (one per upstream, node, list, ...).
pub(crate) type Observed = Vec<(String, String)>;

/// REQ: OPS-010 (ADR-118) — the nodes in maintenance at this evaluation: their conditions are
/// left out, and an alert about one that was firing resolves with "(maintenance)".
#[derive(Default)]
pub(crate) struct Paused {
    /// Node IDs.
    ids: HashSet<String>,
    /// How conditions name them: pod, site, or ID.
    labels: HashSet<String>,
    /// This node (standalone or the evaluating cluster node) is in maintenance.
    me: bool,
    /// The windows, labelled (the `maintenance` rule and the Alerts page).
    pub(crate) windows: Vec<telltale_api::model::NodeMaintenance>,
    /// The same reads without the nodes in maintenance (cluster-wide shares such as
    /// SERVFAIL), when there are any and this is a cluster.
    without: Option<telltale_api::Shared>,
}

impl std::fmt::Debug for Paused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Paused")
            .field("ids", &self.ids)
            .field("me", &self.me)
            .finish_non_exhaustive()
    }
}

impl Paused {
    /// From the cluster view (or, standalone, this node's own window).
    pub(crate) fn new(
        view: &telltale_api::model::ClusterView,
        local: Option<telltale_api::model::NodeMaintenance>,
        standalone_label: &str,
    ) -> Self {
        let mut p = Self::default();
        if view.enabled {
            for n in &view.nodes {
                let Some(m) = &n.maintenance else { continue };
                let label = n.pod.clone().filter(|x| !x.is_empty()).unwrap_or_else(|| {
                    if n.site.is_empty() {
                        n.node_id.clone()
                    } else {
                        n.site.clone()
                    }
                });
                p.ids.insert(n.node_id.clone());
                p.labels.insert(label.clone());
                p.labels.insert(n.node_id.clone());
                if !n.site.is_empty() {
                    p.labels.insert(n.site.clone());
                }
                p.me |= n.this_node;
                let mut m = m.clone();
                m.node = Some(label);
                p.windows.push(m);
            }
        } else if let Some(mut m) = local {
            p.me = true;
            p.labels.insert("this node".to_owned());
            m.node = Some(standalone_label.to_owned());
            p.windows.push(m);
        }
        p
    }

    fn node(n: &telltale_api::model::ClusterNode) -> bool {
        n.maintenance.is_some()
    }

    /// Whether `label` (a probe's or reason's node) is in maintenance.
    fn label(&self, label: &str) -> bool {
        self.labels.contains(label)
    }

    /// Whether an alert subject is about a node in maintenance: the node itself, or
    /// `<node>|<target>`.
    fn covers(&self, subject: &str) -> bool {
        self.label(subject)
            || subject
                .split_once('|')
                .is_some_and(|(node, _)| self.label(node))
    }
}

/// One alert to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Notice {
    pub(crate) rule: usize,
    pub(crate) subject: String,
    pub(crate) summary: String,
    /// `true` when it starts, `false` when it clears.
    pub(crate) firing: bool,
}

/// Which conditions hold since when, which alerts are out, and which one-off subjects (a
/// finding, a version) were already sent.
#[derive(Debug, Default)]
pub(crate) struct Engine {
    since: HashMap<(usize, String), u64>,
    firing: HashMap<(usize, String), String>,
    sent_once: HashSet<(usize, String)>,
    /// `sent_once` in the order sent, so the oldest go first past [`SENT_ONCE_CAP`].
    sent_order: std::collections::VecDeque<(usize, String)>,
}

/// One-off subjects remembered (REQ: OBS-010, review 04-10).
const SENT_ONCE_CAP: usize = 5000;

/// Conditions that go out once per subject and never "clear".
fn one_off(w: AlertWhen) -> bool {
    matches!(
        w,
        AlertWhen::Anomaly
            | AlertWhen::UpdateAvailable
            | AlertWhen::NewDevice
            | AlertWhen::PlanPending
            | AlertWhen::RolloutFailed
    )
}

impl Engine {
    /// One evaluation at `now` (Unix seconds): `observed[i]` is what rule `i` sees. Returns
    /// the alerts that start and clear. Pure, so it's tested without timers or HTTP.
    #[cfg(test)]
    pub(crate) fn step(
        &mut self,
        now: u64,
        rules: &[AlertRule],
        observed: &[Observed],
    ) -> Vec<Notice> {
        self.step_with(now, rules, observed, &Paused::default())
    }

    /// [`Engine::step`], with `paused` naming the nodes in maintenance: an alert about one of
    /// them that stops being seen resolves with "(maintenance)" (OPS-010).
    pub(crate) fn step_with(
        &mut self,
        now: u64,
        rules: &[AlertRule],
        observed: &[Observed],
        paused: &Paused,
    ) -> Vec<Notice> {
        let mut out = Vec::new();
        for (i, (rule, seen)) in rules.iter().zip(observed).enumerate() {
            if one_off(rule.when) {
                for (subject, summary) in seen {
                    if self.sent_once.insert((i, subject.clone())) {
                        self.sent_order.push_back((i, subject.clone()));
                        out.push(Notice {
                            rule: i,
                            subject: subject.clone(),
                            summary: summary.clone(),
                            firing: true,
                        });
                    }
                }
                // Bounded: keep the most recent few thousand. Forgetting only the oldest means
                // subjects still being observed (the last hour's) aren't sent again
                // (review 04-10: clearing the whole set re-sent all of them at once).
                while self.sent_order.len() > SENT_ONCE_CAP {
                    if let Some(old) = self.sent_order.pop_front() {
                        self.sent_once.remove(&old);
                    }
                }
                continue;
            }
            let now_subjects: HashSet<&str> = seen.iter().map(|(s, _)| s.as_str()).collect();
            for (subject, summary) in seen {
                let key = (i, subject.clone());
                let since = *self.since.entry(key.clone()).or_insert(now);
                if now.saturating_sub(since) >= u64::from(rule.for_secs)
                    && !self.firing.contains_key(&key)
                {
                    self.firing.insert(key, summary.clone());
                    out.push(Notice {
                        rule: i,
                        subject: subject.clone(),
                        summary: summary.clone(),
                        firing: true,
                    });
                }
            }
            // Cleared: not seen any more.
            self.since
                .retain(|(r, s), _| *r != i || now_subjects.contains(s.as_str()));
            let cleared: Vec<(usize, String)> = self
                .firing
                .keys()
                .filter(|(r, s)| *r == i && !now_subjects.contains(s.as_str()))
                .cloned()
                .collect();
            for key in cleared {
                if let Some(summary) = self.firing.remove(&key) {
                    // REQ: OPS-010 — not fixed: its node went into maintenance.
                    let summary = if rule.when != AlertWhen::Maintenance && paused.covers(&key.1) {
                        format!("{summary} (maintenance)")
                    } else {
                        summary
                    };
                    out.push(Notice {
                        rule: i,
                        subject: key.1,
                        summary,
                        firing: false,
                    });
                }
            }
        }
        out
    }
}

impl Engine {
    /// REQ: OBS-010 (T9.6) — the alerts firing now, for the status API.
    pub(crate) fn firing_now(&self, rules: &[AlertRule]) -> Vec<telltale_api::model::FiringAlert> {
        let mut v: Vec<telltale_api::model::FiringAlert> = self
            .firing
            .iter()
            .filter_map(|((r, subject), summary)| {
                Some(telltale_api::model::FiringAlert {
                    rule: rules.get(*r)?.name.to_string(),
                    subject: subject.clone(),
                    summary: summary.clone(),
                })
            })
            .collect();
        v.sort_by(|a, b| (&a.rule, &a.subject).cmp(&(&b.rule, &b.subject)));
        v
    }
}

/// REQ: OBS-010 (T9.6) — a test message to `d`, from `node`.
pub(crate) async fn send_test(d: &AlertDestination, node: &str) -> Result<(), String> {
    let n = Notice {
        rule: 0,
        subject: "test".to_owned(),
        summary: format!(
            "This is a test alert from TelltaleDNS on {node}. If you can read it, the destination `{}` works.",
            d.name.as_str()
        ),
        firing: true,
    };
    let client =
        telltale_filter::fetch::Client::new(Arc::new(telltale_filter::fetch::SystemResolver), &[])?;
    deliver(&client, d, "Test", &n, node).await
}

/// Records a delivery's outcome for the status API (the latest per destination).
fn record_delivery(sources: &crate::http::Sources, destination: &str, r: &Result<(), String>) {
    let mut s = sources
        .alerts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    s.deliveries.retain(|x| x.destination != destination);
    s.deliveries.push(telltale_api::model::AlertDelivery {
        destination: destination.to_owned(),
        unix_seconds: crate::pipeline::unix_now(),
        ok: r.is_ok(),
        error: r.as_ref().err().cloned(),
    });
    s.deliveries
        .sort_by(|a, b| a.destination.cmp(&b.destination));
}

/// What `rule` sees now, read from `b` (blocking: run it on a blocking thread). `pending`:
/// agents' plans waiting for approval on this node, as `(id, summary)`.
#[allow(clippy::too_many_lines)] // one arm per condition
fn observe(
    b: &dyn Backend,
    rule: &AlertRule,
    now: u64,
    pending: &[(String, String)],
    m: &Paused,
) -> Observed {
    let node_label = |n: &telltale_api::model::ClusterNode| {
        if let Some(pod) = n.pod.as_ref().filter(|p| !p.is_empty()) {
            pod.clone()
        } else if n.site.is_empty() {
            n.node_id.clone()
        } else {
            n.site.clone()
        }
    };
    match rule.when {
        // REQ: OBS-010 (T9.5) — the new conditions.
        // REQ: OPS-010 — nodes in maintenance are left out of every per-node condition.
        AlertWhen::SyncLag => b
            .cluster()
            .nodes
            .into_iter()
            .filter(|n| !n.this_node && n.connected && n.config_lag > 0 && !Paused::node(n))
            .map(|n| {
                let s = format!(
                    "{} is {} configuration version(s) behind the primary{}",
                    node_label(&n),
                    n.config_lag,
                    n.behind_seconds
                        .map_or(String::new(), |s| format!(" (for {s} s)"))
                );
                (node_label(&n), s)
            })
            .collect(),
        AlertWhen::NewDevice => {
            // REQ: OBS-025 — say what it looks like, when that's known.
            let ids: std::collections::HashMap<String, telltale_api::model::DeviceIdentity> = b
                .identities()
                .into_iter()
                .map(|i| (i.client.clone(), i))
                .collect();
            b.new_devices(now.saturating_sub(3600))
                .into_iter()
                .map(|d| {
                    let who = d
                        .client_name
                        .clone()
                        .map_or_else(|| d.client.clone(), |n| format!("{n} ({})", d.client));
                    let like = ids
                        .get(&d.client)
                        .and_then(crate::identify::looks_like)
                        .map_or_else(String::new, |l| format!(", which {l}"));
                    (
                        d.client.clone(),
                        format!("a new device started using DNS: {who}{like}"),
                    )
                })
                .collect()
        }
        AlertWhen::DiskFull => {
            let limit = rule.threshold.unwrap_or(90.0);
            let c = b.cluster();
            let mut hosts: Vec<(String, telltale_api::model::HostReport)> = c
                .nodes
                .iter()
                .filter(|n| !Paused::node(n))
                .filter_map(|n| n.host.clone().map(|h| (node_label(n), h)))
                .collect();
            if hosts.is_empty()
                && !c.enabled
                && !m.me
                && let Some(h) = c.host.clone()
            {
                hosts.push(("this node".to_owned(), h));
            }
            hosts
                .into_iter()
                .filter_map(|(name, h)| {
                    let used = h.latest.disk_used_percent?;
                    (used > limit).then(|| {
                        let free = h
                            .latest
                            .disk_free_bytes
                            .map_or(String::new(), |f| format!(", {} MiB free", f / (1 << 20)));
                        (
                            name.clone(),
                            format!(
                                "{name}'s data disk is {used:.0}% full{free} (threshold {limit}%)"
                            ),
                        )
                    })
                })
                .collect()
        }
        AlertWhen::PlanPending => pending
            .iter()
            .map(|(id, summary)| {
                (
                    id.clone(),
                    format!("an AI agent's change waits for approval: {summary}"),
                )
            })
            .collect(),
        AlertWhen::UpstreamDown => b
            .upstreams()
            .into_iter()
            .filter(|u| u.breaker == "open")
            .map(|u| {
                let s = format!(
                    "upstream {} ({}) isn't answering: its circuit breaker is open",
                    u.name, u.endpoint
                );
                (u.name, s)
            })
            .collect(),
        AlertWhen::NodeDown => {
            let c = b.cluster();
            c.nodes
                .into_iter()
                .filter(|n| !n.this_node && !n.ephemeral && !n.connected && !Paused::node(n))
                .map(|n| {
                    let name = if n.site.is_empty() {
                        n.node_id.clone()
                    } else {
                        n.site.clone()
                    };
                    let s = format!(
                        "cluster node {name} is unreachable (last seen {} s ago)",
                        n.last_seen_seconds_ago
                    );
                    (name, s)
                })
                .collect()
        }
        AlertWhen::ListFailing => b
            .lists()
            .into_iter()
            .filter(|l| l.enabled && l.error.is_some())
            .map(|l| {
                let s = format!(
                    "list {} fails to update: {}",
                    l.name,
                    l.error.as_deref().unwrap_or("unknown error")
                );
                (l.name, s)
            })
            .collect(),
        // REQ: OBS-023 (T12.3) — downloads fine, but the content stopped changing.
        AlertWhen::ListStale => b
            .lists()
            .into_iter()
            .filter(|l| l.enabled && l.error.is_none())
            .filter_map(|l| {
                let days = l.stale_days?;
                let s = format!(
                    "list {} hasn't changed in {days} days: its source may be abandoned",
                    l.name
                );
                Some((l.name, s))
            })
            .collect(),
        // REQ: OBS-013, OBS-014 — every node's findings (federated), except ones someone
        // already acknowledged.
        AlertWhen::Anomaly => b
            .anomalies(now.saturating_sub(3600))
            .into_iter()
            .filter(|f| f.acknowledged.is_none())
            .map(|f| {
                let who = f.client_name.clone().unwrap_or_else(|| f.client.clone());
                let key = format!(
                    "{}|{}|{}|{}",
                    f.kind,
                    f.client,
                    f.domain.as_deref().unwrap_or(""),
                    f.window_start
                );
                (key, format!("{who}: {}", f.detail))
            })
            .collect(),
        AlertWhen::ServfailRate => {
            // REQ: OPS-010 — the share of the nodes not in maintenance (a standalone node in
            // maintenance has none).
            if m.me && m.without.is_none() {
                return Vec::new();
            }
            let b = m.without.as_deref().unwrap_or(b);
            let buckets = b.timeseries(Step::Minute, now.saturating_sub(300), now);
            let total: u64 = buckets.iter().map(|x| u64::from(x.total)).sum();
            let servfail: u64 = buckets
                .iter()
                .map(|x| u64::from(x.by_rcode.get("SERVFAIL").copied().unwrap_or(0)))
                .sum();
            let threshold = rule.threshold.unwrap_or(5.0);
            #[allow(clippy::cast_precision_loss)] // query counts
            let pct = if total > 0 {
                servfail as f64 * 100.0 / total as f64
            } else {
                0.0
            };
            if total >= 50 && pct > threshold {
                vec![(
                    "servfail".to_owned(),
                    format!(
                        "SERVFAIL for {pct:.1}% of {total} queries in the last 5 minutes (threshold {threshold}%)"
                    ),
                )]
            } else {
                Vec::new()
            }
        }
        // REQ: OBS-020 (ADR-107) — every node's probes and certificates.
        AlertWhen::ProbeFailing => b
            .probes()
            .into_iter()
            .filter(|p| {
                p.skipped.is_none() && p.consecutive_failures >= crate::probes::FAILING_AFTER
            })
            .map(|p| {
                let node = p.node.clone().unwrap_or_else(|| "this node".to_owned());
                (node, p)
            })
            .filter(|(node, _)| !m.label(node))
            .map(|(node, p)| {
                (
                    format!("{node}|{}", p.target),
                    format!(
                        "{} on {node} doesn't answer its probe ({} in a row: {})",
                        p.target,
                        p.consecutive_failures,
                        p.error.as_deref().unwrap_or("no answer")
                    ),
                )
            })
            .collect(),
        AlertWhen::CertExpiring => {
            let days = rule.threshold.unwrap_or(14.0);
            b.probes()
                .into_iter()
                .filter_map(|p| {
                    let left = p.cert_days_left?;
                    #[allow(clippy::cast_precision_loss)] // days
                    let soon = (left as f64) < days;
                    let node = p.node.clone().unwrap_or_else(|| "this node".to_owned());
                    (soon && !m.label(&node)).then(|| {
                        let when = if left < 0 {
                            format!("expired {} day(s) ago", -left)
                        } else {
                            format!("expires in {left} day(s)")
                        };
                        (
                            format!("{node}|{}", p.target),
                            format!("the certificate of {} on {node} {when}", p.target),
                        )
                    })
                })
                .collect()
        }
        // REQ: OBS-016 (ADR-105) — an objective spending its error budget fast (every node).
        AlertWhen::SloBurn => {
            let s = b.slo_settings();
            if !s.enabled {
                return Vec::new();
            }
            let minutes = b.timeseries(
                Step::Minute,
                now.saturating_sub(telltale_api::slo::MINUTE_SPAN_S),
                now + 1,
            );
            telltale_api::slo::burning(&s, now, &minutes)
                .into_iter()
                .map(|(name, _, summary)| (name, summary))
                .collect()
        }
        // REQ: CLU-013 — once per failed version; and while pinned.
        AlertWhen::RolloutFailed => b
            .cluster()
            .rollout
            .and_then(|r| r.last_failure)
            .map(|f| {
                (
                    f.version.clone(),
                    format!(
                        "a staged rollout failed: version {} ({}); the cluster is pinned to the version before it",
                        f.version, f.reason
                    ),
                )
            })
            .into_iter()
            .collect(),
        AlertWhen::ClusterPinned => b
            .cluster()
            .rollout
            .and_then(|r| r.pinned)
            .map(|p| {
                (
                    "cluster".to_owned(),
                    format!(
                        "the cluster is pinned to version {} since {} by {}: {}",
                        p.to, p.since, p.by, p.reason
                    ),
                )
            })
            .into_iter()
            .collect(),
        // REQ: OPS-010 — once when a node enters maintenance, resolved when it leaves.
        AlertWhen::Maintenance => m
            .windows
            .iter()
            .map(|w| {
                let node = w.node.clone().unwrap_or_else(|| "this node".to_owned());
                let s = format!(
                    "{node} is in maintenance until {} ({}), started by {}; it keeps answering DNS",
                    time_text(now + w.seconds_left),
                    w.reason,
                    w.by
                );
                (node, s)
            })
            .collect(),
        AlertWhen::UpdateAvailable => {
            let u = b.system_info().update;
            match (u.state.as_str(), u.latest) {
                ("available", Some(v)) => vec![(
                    v.clone(),
                    format!("TelltaleDNS {v} is available. {}", u.how),
                )],
                _ => Vec::new(),
            }
        }
    }
}

/// The message for a destination: (body, content type, extra headers).
fn render(
    d: &AlertDestination,
    token: Option<&str>,
    rule: &str,
    n: &Notice,
    node: &str,
) -> (String, &'static str, Vec<(String, String)>) {
    let state = if n.firing { "firing" } else { "resolved" };
    let title = if n.firing {
        format!("{rule}: {}", n.subject)
    } else {
        format!("Resolved: {rule}: {}", n.subject)
    };
    let text = if n.firing {
        n.summary.clone()
    } else {
        format!("Cleared: {}", n.summary)
    };
    match d.kind {
        AlertKind::Webhook => (
            serde_json::json!({
                "rule": rule, "status": state, "subject": n.subject, "summary": n.summary,
                "node": node, "time": crate::pipeline::unix_now(),
            })
            .to_string(),
            "application/json",
            Vec::new(),
        ),
        AlertKind::Ntfy => {
            let mut h = vec![
                ("Title".to_owned(), title),
                ("Priority".to_owned(), if n.firing { "high" } else { "default" }.to_owned()),
                ("Tags".to_owned(), if n.firing { "warning" } else { "white_check_mark" }.to_owned()),
            ];
            if let Some(t) = token {
                h.push(("Authorization".to_owned(), format!("Bearer {t}")));
            }
            (text, "text/plain", h)
        }
        AlertKind::Gotify => (
            serde_json::json!({ "title": title, "message": text, "priority": if n.firing { 8 } else { 4 } }).to_string(),
            "application/json",
            Vec::new(),
        ),
        AlertKind::Slack => (
            serde_json::json!({ "text": format!("*{title}*\n{text}") }).to_string(),
            "application/json",
            Vec::new(),
        ),
        // Sent by `deliver_email`, not as HTTP.
        AlertKind::Email => (text, "text/plain", Vec::new()),
    }
}

/// REQ: OBS-010 (T9.4) — an alert as an email.
async fn deliver_email(
    d: &AlertDestination,
    rule: &str,
    n: &Notice,
    node: &str,
) -> Result<(), String> {
    let (host, port, security) = crate::smtp::parse_url(d.url.as_str())?;
    let login = match (&d.username, &d.password_file) {
        (Some(u), Some(f)) => Some((
            u.to_string(),
            std::fs::read_to_string(f.as_str())
                .map_err(|e| format!("{}: {e}", f.as_str()))?
                .trim()
                .to_owned(),
        )),
        _ => None,
    };
    let extra_roots = match &d.tls_ca {
        Some(f) => {
            use rustls::pki_types::pem::PemObject as _;
            rustls::pki_types::CertificateDer::pem_file_iter(f.as_str())
                .map_err(|e| format!("{}: {e}", f.as_str()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("{}: {e}", f.as_str()))?
        }
        None => Vec::new(),
    };
    let subject = if n.firing {
        format!("[TelltaleDNS] {rule}: {}", n.subject)
    } else {
        format!("[TelltaleDNS] Resolved: {rule}: {}", n.subject)
    };
    let body = format!(
        "{}\n\nRule: {rule}\nStatus: {}\nSubject: {}\nNode: {node}\nTime: {}\n\n-- \nSent by TelltaleDNS alerts ([alerts] in the configuration).\n",
        if n.firing {
            n.summary.clone()
        } else {
            format!("Cleared: {}", n.summary)
        },
        if n.firing { "firing" } else { "resolved" },
        n.subject,
        crate::alerts::time_text(crate::pipeline::unix_now()),
    );
    let server = crate::smtp::Server {
        host,
        port,
        security,
        login,
        extra_roots,
    };
    let m = crate::smtp::Message {
        from: d.from.as_ref().map(ToString::to_string).unwrap_or_default(),
        to: d.to.iter().map(ToString::to_string).collect(),
        subject,
        body,
    };
    tokio::time::timeout(Duration::from_secs(60), crate::smtp::send(&server, &m))
        .await
        .map_err(|_| "timed out".to_owned())?
}

/// `2026-10-06 17:05:52 UTC`.
pub(crate) fn time_text(unix: u64) -> String {
    let t = telltale_store::qlog::format_ts(unix.saturating_mul(1_000_000));
    t.get(..19)
        .map_or(t.clone(), |s| format!("{} UTC", s.replace('T', " ")))
}

/// Sends one alert to one destination.
async fn deliver(
    client: &telltale_filter::fetch::Client,
    d: &AlertDestination,
    rule: &str,
    n: &Notice,
    node: &str,
) -> Result<(), String> {
    if d.kind == AlertKind::Email {
        return deliver_email(d, rule, n, node).await;
    }
    let token = match &d.token_file {
        Some(f) => Some(
            std::fs::read_to_string(f.as_str())
                .map_err(|e| format!("{}: {e}", f.as_str()))?
                .trim()
                .to_owned(),
        ),
        None => None,
    };
    let (body, ct, headers) = render(d, token.as_deref(), rule, n, node);
    let mut url = d.url.to_string();
    if d.kind == AlertKind::Gotify {
        url = format!(
            "{}/message?token={}",
            url.trim_end_matches('/'),
            token.as_deref().unwrap_or_default()
        );
    }
    let mut req = http::Request::post(url)
        .header("content-type", ct)
        .header("user-agent", "TelltaleDNS");
    for (k, v) in headers {
        req = req.header(k, v);
    }
    let req = req.body(body.into_bytes()).map_err(|e| e.to_string())?;
    let resp = tokio::time::timeout(Duration::from_secs(10), client.request(req, 64 * 1024))
        .await
        .map_err(|_| "timed out".to_owned())?
        .map_err(|e| e.message)?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}

/// REQ: OBS-010 (T9.6) — the status API's view after a check.
fn publish_status(
    sources: &crate::http::Sources,
    engine: &Engine,
    rules: &[AlertRule],
    cfg: &Config,
    primary: bool,
    paused: &Paused,
) {
    let mut s = sources
        .alerts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    s.evaluating = primary;
    // REQ: OPS-010 — the Alerts page says whose alerts are paused, until when.
    s.maintenance.clone_from(&paused.windows);
    s.firing = if s.evaluating {
        engine.firing_now(rules)
    } else {
        Vec::new()
    };
    let names: Vec<&str> = cfg
        .alerts
        .destination
        .iter()
        .map(|d| d.name.as_str())
        .collect();
    s.deliveries
        .retain(|x| names.contains(&x.destination.as_str()));
}

/// REQ: OBS-010 (T9.5) — plans waiting for approval on this node, as `(id, summary)`.
fn pending_plans(sources: &crate::http::Sources) -> Vec<(String, String)> {
    sources
        .auth
        .get()
        .map(|a| {
            a.plans()
                .list(None)
                .into_iter()
                .filter(|p| p.state == "pending")
                .map(|p| (p.id, format!("{} (by {})", p.summary, p.requested_by)))
                .collect()
        })
        .unwrap_or_default()
}

/// REQ: OPS-010 — which nodes are in maintenance now (from heartbeats, or this node's own
/// window when standalone), and the reads without them.
async fn paused_now(
    sources: &Arc<crate::http::Sources>,
    backend: &telltale_api::Shared,
    federated: Option<&Arc<crate::federated::Federated>>,
) -> Arc<Paused> {
    let (b, fed, src) = (Arc::clone(backend), federated.cloned(), Arc::clone(sources));
    let paused = tokio::task::spawn_blocking(move || {
        let now = crate::maintenance::now_ms();
        let mut paused = Paused::new(
            &b.cluster(),
            src.maintenance
                .current(now)
                .map(|w| crate::maintenance::api_window(&w.cluster_window(), now, None)),
            &crate::maintenance::label(&src),
        );
        if let Some(fed) = fed.filter(|_| !paused.ids.is_empty()) {
            paused.without = Some(Arc::new(fed.excluding(&paused.ids)));
        }
        paused
    })
    .await
    .unwrap_or_default();
    Arc::new(paused)
}

/// The alert task: every `interval_secs`, evaluate (on the primary or a standalone node) and
/// send what started or cleared.
pub(crate) async fn run(
    sources: Arc<crate::http::Sources>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let local: telltale_api::Shared = Arc::new(crate::api_backend::ApiBackend {
        src: Arc::clone(&sources),
    });
    let federated = sources.cluster.as_ref().map(|c| {
        Arc::new(crate::federated::Federated::new(
            local.clone(),
            Arc::clone(c),
        ))
    });
    let backend: telltale_api::Shared = match &federated {
        Some(f) => Arc::clone(f) as telltale_api::Shared,
        None => local,
    };
    let client = match telltale_filter::fetch::Client::new(
        Arc::new(telltale_filter::fetch::SystemResolver),
        &[],
    ) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            warn!("alerts disabled: {e}");
            return;
        }
    };
    let mut engine = Engine::default();
    let mut rules_for: Option<Vec<AlertRule>> = None;
    loop {
        let cfg: Arc<Config> = sources.config.load_full();
        let interval = Duration::from_secs(u64::from(cfg.alerts.interval_secs.max(5)));
        let rules: Vec<AlertRule> = cfg
            .alerts
            .rule
            .iter()
            .filter(|r| r.enabled)
            .cloned()
            .collect();
        // New rules: start over (indexes changed).
        if rules_for.as_ref() != Some(&rules) {
            engine = Engine::default();
            rules_for = Some(rules.clone());
        }
        let primary = sources.cluster.as_ref().is_none_or(|c| c.is_primary());
        let paused = paused_now(&sources, &backend, federated.as_ref()).await;
        if primary && !rules.is_empty() {
            let now = crate::pipeline::unix_now();
            let b = Arc::clone(&backend);
            let rs = rules.clone();
            let in_maintenance = Arc::clone(&paused);
            let pending = pending_plans(&sources);
            let observed = tokio::task::spawn_blocking(move || {
                rs.iter()
                    .map(|r| observe(b.as_ref(), r, now, &pending, &in_maintenance))
                    .collect::<Vec<_>>()
            })
            .await
            .unwrap_or_default();
            let node = crate::http::node_name(&cfg);
            for n in engine.step_with(now, &rules, &observed, &paused) {
                let rule = &rules[n.rule];
                info!(rule = %rule.name, subject = %n.subject, firing = n.firing, "alert");
                for to in &rule.to {
                    let Some(d) = cfg
                        .alerts
                        .destination
                        .iter()
                        .find(|d| d.name == *to)
                        .cloned()
                    else {
                        continue;
                    };
                    let (client, rname, n, node, src) = (
                        Arc::clone(&client),
                        rule.name.to_string(),
                        n.clone(),
                        node.clone(),
                        Arc::clone(&sources),
                    );
                    tokio::spawn(async move {
                        let r = deliver(&client, &d, &rname, &n, &node).await;
                        if let Err(e) = &r {
                            warn!(destination = %d.name, error = %e, "alert not delivered");
                        }
                        record_delivery(&src, d.name.as_str(), &r);
                    });
                }
            }
        }
        publish_status(&sources, &engine, &rules, &cfg, primary, &paused);
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(interval) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(when: AlertWhen, for_secs: u32) -> AlertRule {
        AlertRule {
            name: telltale_config::SafeString::new("r").unwrap(),
            when,
            for_secs,
            threshold: None,
            to: Vec::new(),
            enabled: true,
        }
    }

    fn seen(subjects: &[&str]) -> Observed {
        subjects
            .iter()
            .map(|s| ((*s).to_owned(), format!("{s} is down")))
            .collect()
    }

    /// REQ: OBS-010 — an alert starts once a condition has held `for_secs`, once per subject,
    /// and clears when it stops; one-off conditions go out once each.
    #[test]
    fn obs_010_alerts_start_after_for_and_clear() {
        let rules = vec![
            rule(AlertWhen::UpstreamDown, 60),
            rule(AlertWhen::Anomaly, 0),
        ];
        let mut e = Engine::default();
        assert!(
            e.step(1000, &rules, &[seen(&["quad9"]), seen(&[])])
                .is_empty(),
            "not for 60 s yet"
        );
        assert!(
            e.step(1030, &rules, &[seen(&["quad9"]), seen(&[])])
                .is_empty(),
            "still not"
        );
        let n = e.step(1060, &rules, &[seen(&["quad9"]), seen(&["tv-burst"])]);
        assert_eq!(n.len(), 2);
        assert!(n.iter().all(|x| x.firing));
        assert!(
            e.step(1090, &rules, &[seen(&["quad9"]), seen(&["tv-burst"])])
                .is_empty(),
            "sent once"
        );
        let n = e.step(1120, &rules, &[seen(&[]), seen(&["tv-burst"])]);
        assert_eq!(
            n,
            vec![Notice {
                rule: 0,
                subject: "quad9".into(),
                summary: "quad9 is down".into(),
                firing: false
            }]
        );
        // A blip shorter than `for_secs` never alerts.
        assert!(
            e.step(1150, &rules, &[seen(&["cloudflare"]), seen(&[])])
                .is_empty(),
            "too soon"
        );
        assert!(
            e.step(1180, &rules, &[seen(&[]), seen(&[])]).is_empty(),
            "never fired"
        );
        assert!(
            e.step(1300, &rules, &[seen(&["cloudflare"]), seen(&[])])
                .is_empty(),
            "the timer restarted"
        );
    }

    /// REQ: OBS-010 (review 04-10) — past the cap, only the oldest one-off subjects are
    /// forgotten: one still being observed isn't sent again.
    #[test]
    fn obs_010_one_off_alerts_forget_only_the_oldest() {
        let rules = vec![rule(AlertWhen::Anomaly, 0)];
        let mut e = Engine::default();
        let all: Vec<String> = (0..=SENT_ONCE_CAP)
            .map(|i| format!("finding-{i}"))
            .collect();
        for chunk in all.chunks(500) {
            let names: Vec<&str> = chunk.iter().map(String::as_str).collect();
            assert_eq!(e.step(0, &rules, &[seen(&names)]).len(), chunk.len());
        }
        let newest = format!("finding-{SENT_ONCE_CAP}");
        assert!(
            e.step(1, &rules, &[seen(&[newest.as_str()])]).is_empty(),
            "still remembered"
        );
        assert_eq!(
            e.step(2, &rules, &[seen(&["finding-0"])]).len(),
            1,
            "the oldest was forgotten"
        );
    }

    /// A read model with a cluster view and probes, nothing else.
    struct Stub {
        view: telltale_api::model::ClusterView,
        probes: Vec<telltale_api::model::ProbeResult>,
    }

    impl Backend for Stub {
        fn system_info(&self) -> telltale_api::model::SystemInfo {
            unreachable!("not read by these rules")
        }
        fn cluster(&self) -> telltale_api::model::ClusterView {
            self.view.clone()
        }
        fn probes(&self) -> Vec<telltale_api::model::ProbeResult> {
            self.probes.clone()
        }
        fn timeseries(&self, _: Step, _: u64, _: u64) -> Vec<telltale_api::model::TimeBucket> {
            Vec::new()
        }
        fn top(
            &self,
            _: telltale_api::model::TopKind,
            _: telltale_api::model::Hour,
            _: usize,
            _: Option<std::net::IpAddr>,
        ) -> Vec<telltale_api::model::TopItem> {
            Vec::new()
        }
        fn latency(
            &self,
            _: telltale_api::model::LatencyBy,
            _: telltale_api::model::Hour,
        ) -> Vec<telltale_api::model::LatencyRow> {
            Vec::new()
        }
        fn queries(
            &self,
            _: &telltale_api::model::QueryParams,
            _: u64,
            _: u64,
            _: usize,
        ) -> Result<telltale_api::model::QueryPage, telltale_api::problem::Problem> {
            Err(telltale_api::problem::Problem::unavailable("stub"))
        }
        fn explain(
            &self,
            _: &telltale_api::model::ExplainParams,
        ) -> Result<telltale_api::model::Explanation, telltale_api::problem::Problem> {
            Err(telltale_api::problem::Problem::unavailable("stub"))
        }
        fn lists(&self) -> Vec<telltale_api::model::ListInfo> {
            Vec::new()
        }
        fn groups(&self) -> Vec<telltale_api::model::GroupInfo> {
            Vec::new()
        }
        fn clients(&self) -> Vec<telltale_api::model::ClientInfo> {
            Vec::new()
        }
        fn upstreams(&self) -> Vec<telltale_api::model::UpstreamInfo> {
            Vec::new()
        }
    }

    /// REQ: OPS-010 (ADR-118) — a node in maintenance raises no `node_down` or probe alert;
    /// one that was firing resolves with "(maintenance)"; the `maintenance` rule fires while
    /// it lasts; after the window, `for_secs` counts from zero again.
    #[test]
    #[allow(clippy::too_many_lines)] // one scenario, step by step
    fn ops_010_alerts_skip_nodes_in_maintenance() {
        use telltale_api::model::{ClusterNode, ClusterView, NodeMaintenance, ProbeResult};
        let node = |id: &str, connected: bool| ClusterNode {
            node_id: id.into(),
            site: id.into(),
            connected,
            up: connected,
            ..ClusterNode::default()
        };
        let mut me = node("pi", true);
        me.this_node = true;
        let view = |maint: bool| {
            let mut away = node("pi2", false);
            if maint {
                away.maintenance = Some(NodeMaintenance {
                    until: "2026-10-09T14:00:00Z".into(),
                    reason: "SD card swap".into(),
                    by: "alice".into(),
                    seconds_left: 1800,
                    ..NodeMaintenance::default()
                });
            }
            ClusterView {
                enabled: true,
                cluster_id: None,
                name: None,
                this_node: None,
                newest_config_seq: 0,
                healthy: true,
                checks: Vec::new(),
                nodes: vec![me.clone(), away, node("k3s", false)],
                events: Vec::new(),
                authority: None,
                conflicts: Vec::new(),
                failover: None,
                source: None,
                rollout: None,
                host: None,
            }
        };
        let probe = |who: &str| ProbeResult {
            node: Some(who.into()),
            target: "udp://127.0.0.1:53".into(),
            listener: true,
            consecutive_failures: 3,
            ..ProbeResult::default()
        };
        let stub = |maint: bool| Stub {
            view: view(maint),
            probes: vec![probe("pi2"), probe("k3s")],
        };
        let rules = vec![
            rule(AlertWhen::NodeDown, 60),
            rule(AlertWhen::ProbeFailing, 0),
            rule(AlertWhen::Maintenance, 0),
        ];
        let seen = |backend: &Stub, paused: &Paused| -> Vec<Observed> {
            rules
                .iter()
                .map(|r| observe(backend, r, 1000, &[], paused))
                .collect()
        };
        let subjects = |o: &Observed| o.iter().map(|(x, _)| x.clone()).collect::<Vec<_>>();
        // Before maintenance: both nodes are down and failing their probes.
        let before = stub(false);
        let quiet = Paused::new(&before.view, None, "pi");
        let observed = seen(&before, &quiet);
        assert_eq!(subjects(&observed[0]), ["pi2", "k3s"]);
        assert_eq!(
            subjects(&observed[1]),
            ["pi2|udp://127.0.0.1:53", "k3s|udp://127.0.0.1:53"]
        );
        assert_eq!(observed[2], Observed::new());
        let mut engine = Engine::default();
        engine.step_with(0, &rules, &observed, &quiet);
        assert_eq!(
            engine.step_with(60, &rules, &observed, &quiet).len(),
            2,
            "both node_down alerts fire"
        );
        // pi2 enters maintenance.
        let during = stub(true);
        let paused = Paused::new(&during.view, None, "pi");
        let observed = seen(&during, &paused);
        assert_eq!(subjects(&observed[0]), ["k3s"]);
        assert_eq!(subjects(&observed[1]), ["k3s|udp://127.0.0.1:53"]);
        assert_eq!(subjects(&observed[2]), ["pi2"]);
        assert!(
            observed[2][0].1.contains("SD card swap"),
            "{}",
            observed[2][0].1
        );
        let notices = engine.step_with(90, &rules, &observed, &paused);
        let resolved: Vec<&Notice> = notices.iter().filter(|x| !x.firing).collect();
        assert_eq!(
            resolved.len(),
            2,
            "node_down and the probe, both pi2's: {resolved:?}"
        );
        assert!(
            resolved
                .iter()
                .all(|x| x.subject.starts_with("pi2") && x.summary.ends_with("(maintenance)")),
            "{resolved:?}"
        );
        assert!(
            notices
                .iter()
                .any(|x| x.firing && x.rule == 2 && x.subject == "pi2")
        );
        // Maintenance ends with pi2 still down: node_down counts its 60 s from now.
        let after = stub(false);
        let observed = seen(&after, &quiet);
        let notices = engine.step_with(120, &rules, &observed, &quiet);
        assert!(
            notices.iter().any(|x| !x.firing && x.rule == 2),
            "the maintenance alert resolves"
        );
        assert!(
            !notices.iter().any(|x| x.firing && x.rule == 0),
            "not before for_secs"
        );
        let notices = engine.step_with(180, &rules, &observed, &quiet);
        assert!(
            notices
                .iter()
                .any(|x| x.firing && x.rule == 0 && x.subject == "pi2")
        );
    }

    /// REQ: OBS-010 — destination formats.
    #[test]
    fn obs_010_destination_formats() {
        let d = |kind| AlertDestination {
            name: telltale_config::SafeString::new("d").unwrap(),
            kind,
            url: telltale_config::SafeString::new("https://example.test/x").unwrap(),
            token_file: None,
            from: None,
            to: Vec::new(),
            username: None,
            password_file: None,
            tls_ca: None,
        };
        let n = Notice {
            rule: 0,
            subject: "quad9".into(),
            summary: "quad9 is down".into(),
            firing: true,
        };
        let (body, ct, _) = render(&d(AlertKind::Webhook), None, "upstreams", &n, "pi");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            (v["status"].as_str(), v["subject"].as_str(), ct),
            (Some("firing"), Some("quad9"), "application/json")
        );
        let (body, ct, h) = render(&d(AlertKind::Ntfy), Some("tk"), "upstreams", &n, "pi");
        assert_eq!((body.as_str(), ct), ("quad9 is down", "text/plain"));
        assert!(h.contains(&("Title".into(), "upstreams: quad9".into())));
        assert!(h.contains(&("Authorization".into(), "Bearer tk".into())));
        let (body, _, _) = render(
            &d(AlertKind::Slack),
            None,
            "upstreams",
            &Notice { firing: false, ..n },
            "pi",
        );
        assert!(body.contains("Resolved: upstreams: quad9"), "{body}");
    }

    /// REQ: CLU-013 — `rollout_failed` goes out once per failed version; `cluster_pinned` fires
    /// while pinned (after its `for_secs`) and resolves when unpinned.
    #[test]
    fn clu_013_rollout_failed_and_cluster_pinned() {
        use telltale_api::model::{ClusterPin, ClusterRollout, ClusterView, RolloutFailure};
        let view = |r: Option<ClusterRollout>| ClusterView {
            enabled: true,
            cluster_id: None,
            name: None,
            this_node: None,
            newest_config_seq: 0,
            healthy: true,
            checks: Vec::new(),
            nodes: Vec::new(),
            events: Vec::new(),
            authority: None,
            conflicts: Vec::new(),
            failover: None,
            source: None,
            rollout: r,
            host: None,
        };
        let pinned = |failed: &str| ClusterRollout {
            stage: "pinned".into(),
            pinned: Some(ClusterPin {
                to: "1.6".into(),
                since: "2026-10-10T12:00:00Z".into(),
                by: "the guard".into(),
                reason: "SERVFAIL 28%".into(),
                ..ClusterPin::default()
            }),
            last_failure: Some(RolloutFailure {
                version: failed.into(),
                reason: "SERVFAIL 28%".into(),
                at: "2026-10-10T12:00:00Z".into(),
            }),
            ..ClusterRollout::default()
        };
        let rules = vec![
            rule(AlertWhen::RolloutFailed, 0),
            rule(AlertWhen::ClusterPinned, 60),
        ];
        let seen = |r: Option<ClusterRollout>| -> Vec<Observed> {
            let b = Stub {
                view: view(r),
                probes: Vec::new(),
            };
            rules
                .iter()
                .map(|x| observe(&b, x, 1000, &[], &Paused::default()))
                .collect()
        };
        let mut e = Engine::default();
        let first = e.step(0, &rules, &seen(Some(pinned("1.7"))));
        assert_eq!(first.len(), 1, "{first:?}");
        assert!(
            first[0].summary.contains("version 1.7") && first[0].summary.contains("SERVFAIL 28%")
        );
        // Still pinned a minute later: the pin alert fires; the failure isn't sent again.
        let later = e.step(60, &rules, &seen(Some(pinned("1.7"))));
        assert_eq!(later.len(), 1, "{later:?}");
        assert_eq!(
            (later[0].rule, later[0].subject.as_str(), later[0].firing),
            (1, "cluster", true)
        );
        assert!(later[0].summary.contains("pinned to version 1.6"));
        // Unpinned: the pin alert resolves. A later failure of another version goes out.
        let cleared = e.step(120, &rules, &seen(None));
        assert_eq!(cleared.len(), 1);
        assert!(!cleared[0].firing);
        let again = e.step(180, &rules, &seen(Some(pinned("1.9"))));
        assert!(
            again.iter().any(|n| n.rule == 0 && n.subject == "1.9"),
            "{again:?}"
        );
    }
}
