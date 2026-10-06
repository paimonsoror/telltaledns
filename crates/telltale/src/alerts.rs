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
}

/// Conditions that go out once per subject and never "clear".
fn one_off(w: AlertWhen) -> bool {
    matches!(w, AlertWhen::Anomaly | AlertWhen::UpdateAvailable)
}

impl Engine {
    /// One evaluation at `now` (Unix seconds): `observed[i]` is what rule `i` sees. Returns
    /// the alerts that start and clear. Pure, so it's tested without timers or HTTP.
    pub(crate) fn step(
        &mut self,
        now: u64,
        rules: &[AlertRule],
        observed: &[Observed],
    ) -> Vec<Notice> {
        let mut out = Vec::new();
        for (i, (rule, seen)) in rules.iter().zip(observed).enumerate() {
            if one_off(rule.when) {
                for (subject, summary) in seen {
                    if self.sent_once.insert((i, subject.clone())) {
                        out.push(Notice {
                            rule: i,
                            subject: subject.clone(),
                            summary: summary.clone(),
                            firing: true,
                        });
                    }
                }
                // Bounded: keep the most recent few thousand.
                if self.sent_once.len() > 5000 {
                    self.sent_once.clear();
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

/// What `rule` sees now, read from `b` (blocking: run it on a blocking thread).
fn observe(b: &dyn Backend, rule: &AlertRule, now: u64) -> Observed {
    match rule.when {
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
                .filter(|n| !n.this_node && !n.ephemeral && !n.connected)
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
        AlertWhen::Anomaly => b
            .anomalies(now.saturating_sub(3600))
            .into_iter()
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
    }
}

/// Sends one alert to one destination.
async fn deliver(
    client: &telltale_filter::fetch::Client,
    d: &AlertDestination,
    rule: &str,
    n: &Notice,
    node: &str,
) -> Result<(), String> {
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

/// The alert task: every `interval_secs`, evaluate (on the primary or a standalone node) and
/// send what started or cleared.
pub(crate) async fn run(
    sources: Arc<crate::http::Sources>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let local: telltale_api::Shared = Arc::new(crate::api_backend::ApiBackend {
        src: Arc::clone(&sources),
    });
    let backend: telltale_api::Shared = match &sources.cluster {
        Some(c) => Arc::new(crate::federated::Federated::new(local, Arc::clone(c))),
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
        if primary && !rules.is_empty() {
            let now = crate::pipeline::unix_now();
            let b = Arc::clone(&backend);
            let rs = rules.clone();
            let observed = tokio::task::spawn_blocking(move || {
                rs.iter()
                    .map(|r| observe(b.as_ref(), r, now))
                    .collect::<Vec<_>>()
            })
            .await
            .unwrap_or_default();
            let node = crate::http::node_name(&cfg);
            for n in engine.step(now, &rules, &observed) {
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
                    let (client, rname, n, node) = (
                        Arc::clone(&client),
                        rule.name.to_string(),
                        n.clone(),
                        node.clone(),
                    );
                    tokio::spawn(async move {
                        if let Err(e) = deliver(&client, &d, &rname, &n, &node).await {
                            warn!(destination = %d.name, error = %e, "alert not delivered");
                        }
                    });
                }
            }
        }
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

    /// REQ: OBS-010 — destination formats.
    #[test]
    fn obs_010_destination_formats() {
        let d = |kind| AlertDestination {
            name: telltale_config::SafeString::new("d").unwrap(),
            kind,
            url: telltale_config::SafeString::new("https://example.test/x").unwrap(),
            token_file: None,
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
}
