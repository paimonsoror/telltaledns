//! OpenTelemetry export (REQ: OBS-006, `spec/06` §5; T7.17) over OTLP/HTTP with the JSON
//! encoding: every `interval_secs`, the same metrics `/metrics` serves are posted to
//! `<endpoint>/v1/metrics` (counters as cumulative monotonic sums, gauges, histograms with
//! their buckets). Query events as OpenTelemetry logs come from an event sink with
//! `format = "otlp_logs"` (`crate::sinks`), which uses [`logs_body`].
//!
//! Converting our own Prometheus exposition keeps the two exports identical by construction.
//! Off the DNS path: a background task, one request per interval, a 10 s timeout; a collector
//! that's down only costs that interval's points.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tracing::{debug, warn};

/// One sample line: labels and value.
#[derive(Debug, Clone, PartialEq)]
struct Sample {
    labels: Vec<(String, String)>,
    value: f64,
}

/// A metric family from the exposition.
#[derive(Debug, Clone, Default, PartialEq)]
struct Family {
    name: String,
    kind: String,
    help: String,
    samples: Vec<(String, Sample)>,
}

/// Parses one `name{a="b",c="d"} value` line.
fn sample(line: &str) -> Option<(String, Sample)> {
    let (head, value) = line.rsplit_once(' ')?;
    let value: f64 = match value {
        "+Inf" => f64::INFINITY,
        "-Inf" => f64::NEG_INFINITY,
        v => v.parse().ok()?,
    };
    let (name, labels) = match head.split_once('{') {
        Some((n, rest)) => (n, rest.strip_suffix('}')?),
        None => (head, ""),
    };
    let mut out = Vec::new();
    let mut rest = labels;
    while !rest.is_empty() {
        let (k, after) = rest.split_once("=\"")?;
        // The value ends at the first unescaped quote.
        let mut v = String::new();
        let mut chars = after.char_indices();
        let mut end = None;
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => {
                    if let Some((_, n)) = chars.next() {
                        v.push(match n {
                            'n' => '\n',
                            other => other,
                        });
                    }
                }
                '"' => {
                    end = Some(i);
                    break;
                }
                c => v.push(c),
            }
        }
        let end = end?;
        out.push((k.trim_start_matches(',').to_owned(), v));
        rest = after[end + 1..].trim_start_matches(',');
    }
    Some((name.to_owned(), Sample { labels: out, value }))
}

/// The exposition's families, in order.
fn parse(text: &str) -> Vec<Family> {
    let mut fams: Vec<Family> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let (n, h) = rest.split_once(' ').unwrap_or((rest, ""));
            fams.push(Family {
                name: n.to_owned(),
                help: h.to_owned(),
                kind: "untyped".into(),
                samples: Vec::new(),
            });
        } else if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (n, k) = rest.split_once(' ').unwrap_or((rest, "untyped"));
            match fams.last_mut() {
                Some(f) if f.name == n => k.clone_into(&mut f.kind),
                _ => fams.push(Family {
                    name: n.to_owned(),
                    kind: k.to_owned(),
                    ..Family::default()
                }),
            }
        } else if !line.starts_with('#')
            && !line.trim().is_empty()
            && let Some(s) = sample(line)
            && let Some(f) = fams.last_mut()
        {
            f.samples.push(s);
        }
    }
    fams
}

fn attrs(labels: &[(String, String)]) -> Value {
    Value::Array(
        labels
            .iter()
            .map(|(k, v)| json!({"key": k, "value": {"stringValue": v}}))
            .collect(),
    )
}

/// A histogram series: `(upper bound, cumulative count)` buckets, the sum, the count.
type HistogramParts = (Vec<(f64, f64)>, f64, f64);

/// The OTLP `ResourceMetrics` JSON for `text` (Prometheus exposition).
fn metrics_body(text: &str, resource: &Value, start_ns: u64, now_ns: u64) -> Value {
    let (start, now) = (start_ns.to_string(), now_ns.to_string());
    let mut metrics = Vec::new();
    for f in parse(text) {
        match f.kind.as_str() {
            "histogram" => {
                // Group bucket/sum/count lines by their labels (minus `le`).
                let mut by: BTreeMap<Vec<(String, String)>, HistogramParts> = BTreeMap::new();
                for (name, s) in &f.samples {
                    let mut labels = s.labels.clone();
                    let le = labels
                        .iter()
                        .position(|(k, _)| k == "le")
                        .map(|i| labels.remove(i).1);
                    let e = by.entry(labels).or_default();
                    if name.ends_with("_bucket") {
                        let bound = match le.as_deref() {
                            Some("+Inf") | None => f64::INFINITY,
                            Some(b) => b.parse().unwrap_or(f64::INFINITY),
                        };
                        e.0.push((bound, s.value));
                    } else if name.ends_with("_sum") {
                        e.1 = s.value;
                    } else if name.ends_with("_count") {
                        e.2 = s.value;
                    }
                }
                let points: Vec<Value> = by
                    .into_iter()
                    .map(|(labels, (mut buckets, sum, count))| {
                        buckets.sort_by(|a, b| a.0.total_cmp(&b.0));
                        // Cumulative → per bucket; the last (+Inf) closes the list.
                        let mut prev = 0.0;
                        let mut counts = Vec::new();
                        let mut bounds = Vec::new();
                        for (b, c) in &buckets {
                            counts.push(format!("{}", (c - prev).max(0.0).round()));
                            prev = *c;
                            if b.is_finite() {
                                bounds.push(*b);
                            }
                        }
                        if buckets.last().is_none_or(|(b, _)| b.is_finite()) {
                            counts.push(format!("{}", (count - prev).max(0.0).round()));
                        }
                        json!({
                            "attributes": attrs(&labels),
                            "startTimeUnixNano": start,
                            "timeUnixNano": now,
                            "count": format!("{}", count.round()),
                            "sum": sum,
                            "bucketCounts": counts,
                            "explicitBounds": bounds,
                        })
                    })
                    .collect();
                metrics.push(json!({
                    "name": f.name,
                    "description": f.help,
                    "histogram": {"aggregationTemporality": 2, "dataPoints": points},
                }));
            }
            kind => {
                let points: Vec<Value> = f
                    .samples
                    .iter()
                    .filter(|(_, s)| s.value.is_finite())
                    .map(|(_, s)| {
                        json!({
                            "attributes": attrs(&s.labels),
                            "startTimeUnixNano": start,
                            "timeUnixNano": now,
                            "asDouble": s.value,
                        })
                    })
                    .collect();
                if points.is_empty() {
                    continue;
                }
                let data = if kind == "counter" {
                    json!({"sum": {"aggregationTemporality": 2, "isMonotonic": true, "dataPoints": points}})
                } else {
                    json!({"gauge": {"dataPoints": points}})
                };
                let mut m = json!({"name": f.name, "description": f.help});
                if let (Some(m), Some(d)) = (m.as_object_mut(), data.as_object()) {
                    m.extend(d.clone());
                }
                metrics.push(m);
            }
        }
    }
    json!({"resourceMetrics": [{
        "resource": resource,
        "scopeMetrics": [{"scope": {"name": "telltaledns", "version": crate::build_info::VERSION}, "metrics": metrics}],
    }]})
}

/// The resource: service and host.
pub(crate) fn resource(node: &str) -> Value {
    json!({"attributes": [
        {"key": "service.name", "value": {"stringValue": "telltaledns"}},
        {"key": "service.version", "value": {"stringValue": crate::build_info::VERSION}},
        {"key": "host.name", "value": {"stringValue": node}},
    ]})
}

/// REQ: OBS-006 — query events (the API's query-row JSON, one per line) as OTLP log records:
/// a one-line body, and the fields as attributes (`dns.question.name`, `client.address`, ...).
pub(crate) fn logs_body(lines: &[String], resource: &Value) -> String {
    let records: Vec<Value> = lines
        .iter()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .map(|e| {
            let s = |k: &str| e.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
            let ts = e.get("tsUnixMicros").and_then(Value::as_u64).unwrap_or(0).saturating_mul(1000);
            let status = s("status");
            let blocked = status == "blocked";
            let mut a = vec![
                ("dns.question.name", s("name")),
                ("dns.question.type", s("qtype")),
                ("dns.response_code", s("rcode")),
                ("client.address", s("client")),
                ("network.transport", s("proto")),
                ("telltale.status", status.clone()),
            ];
            for (k, f) in [("client.name", "clientName"), ("telltale.group", "group"), ("telltale.list", "list"), ("telltale.rule", "rule"), ("telltale.node", "node")] {
                let v = s(f);
                if !v.is_empty() {
                    a.push((k, v));
                }
            }
            let mut attributes: Vec<Value> = a
                .into_iter()
                .map(|(k, v)| json!({"key": k, "value": {"stringValue": v}}))
                .collect();
            if let Some(ms) = e.get("totalMs").and_then(Value::as_f64) {
                attributes.push(json!({"key": "telltale.duration_ms", "value": {"doubleValue": ms}}));
            }
            json!({
                "timeUnixNano": ts.to_string(),
                "observedTimeUnixNano": ts.to_string(),
                "severityNumber": if blocked { 13 } else { 9 },
                "severityText": if blocked { "WARN" } else { "INFO" },
                "body": {"stringValue": format!("{} {} from {}: {}", s("qtype"), s("name"), s("client"), status)},
                "attributes": attributes,
            })
        })
        .collect();
    json!({"resourceLogs": [{
        "resource": resource,
        "scopeLogs": [{"scope": {"name": "telltaledns", "version": crate::build_info::VERSION}, "logRecords": records}],
    }]})
    .to_string()
}

/// The metrics export task.
pub(crate) async fn run(
    sources: Arc<crate::http::Sources>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let cfg = sources.config.load_full();
    let Some(endpoint) = cfg
        .telemetry
        .otlp
        .endpoint
        .as_ref()
        .map(|e| e.trim_end_matches('/').to_owned())
    else {
        return;
    };
    let client = match telltale_filter::fetch::Client::new(
        Arc::new(telltale_filter::fetch::SystemResolver),
        &[],
    ) {
        Ok(c) => c,
        Err(e) => {
            warn!("OTLP export disabled: {e}");
            return;
        }
    };
    let start_ns = crate::pipeline::unix_now().saturating_mul(1_000_000_000);
    let url = format!("{endpoint}/v1/metrics");
    let mut failing = false;
    loop {
        let cfg = sources.config.load_full();
        let interval = Duration::from_secs(u64::from(cfg.telemetry.otlp.interval_secs.max(5)));
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(interval) => {}
        }
        let text = crate::http::render(&sources);
        let now_ns = crate::pipeline::unix_now().saturating_mul(1_000_000_000);
        let body = metrics_body(
            &text,
            &resource(&crate::http::node_name(&cfg)),
            start_ns,
            now_ns,
        )
        .to_string();
        let mut req = http::Request::post(url.as_str())
            .header("content-type", "application/json")
            .header("user-agent", "TelltaleDNS");
        for (k, v) in &cfg.telemetry.otlp.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let Ok(req) = req.body(body.into_bytes()) else {
            continue;
        };
        let result =
            tokio::time::timeout(Duration::from_secs(10), client.request(req, 64 * 1024)).await;
        match result {
            Ok(Ok(r)) if r.status().is_success() => {
                if failing {
                    debug!("OTLP export: delivered again");
                }
                failing = false;
            }
            other => {
                if !failing {
                    let why = match other {
                        Ok(Ok(r)) => format!("HTTP {}", r.status()),
                        Ok(Err(e)) => e.message,
                        Err(_) => "timed out".into(),
                    };
                    warn!(%url, error = %why, "OTLP metrics not delivered (logged once until it works again)");
                }
                failing = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "# HELP telltale_queries_total Queries.\n# TYPE telltale_queries_total counter\ntelltale_queries_total{proto=\"udp\",status=\"cached\"} 42\n# HELP telltale_cache_entries Entries.\n# TYPE telltale_cache_entries gauge\ntelltale_cache_entries 7\n# HELP telltale_query_duration_seconds Latency.\n# TYPE telltale_query_duration_seconds histogram\ntelltale_query_duration_seconds_bucket{path=\"cache\",le=\"0.001\"} 3\ntelltale_query_duration_seconds_bucket{path=\"cache\",le=\"0.01\"} 5\ntelltale_query_duration_seconds_bucket{path=\"cache\",le=\"+Inf\"} 6\ntelltale_query_duration_seconds_sum{path=\"cache\"} 0.5\ntelltale_query_duration_seconds_count{path=\"cache\"} 6\n";

    /// REQ: OBS-006 — the exposition becomes OTLP: a monotonic cumulative sum, a gauge, and a
    /// histogram with per-bucket counts (one more than the bounds).
    #[test]
    fn obs_006_metrics_to_otlp() {
        let v = metrics_body(TEXT, &resource("pi"), 1, 2);
        let ms = &v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"];
        assert_eq!(ms[0]["name"], "telltale_queries_total");
        assert_eq!(ms[0]["sum"]["isMonotonic"], true);
        let p = &ms[0]["sum"]["dataPoints"][0];
        assert_eq!(
            (
                p["asDouble"].as_f64(),
                p["attributes"][1]["value"]["stringValue"].as_str()
            ),
            (Some(42.0), Some("cached"))
        );
        assert_eq!(ms[1]["gauge"]["dataPoints"][0]["asDouble"], 7.0);
        let h = &ms[2]["histogram"]["dataPoints"][0];
        assert_eq!(h["bucketCounts"], json!(["3", "2", "1"]));
        assert_eq!(h["explicitBounds"], json!([0.001, 0.01]));
        assert_eq!(
            (h["count"].as_str(), h["sum"].as_f64()),
            (Some("6"), Some(0.5))
        );
        assert_eq!(
            h["attributes"],
            json!([{"key": "path", "value": {"stringValue": "cache"}}])
        );
        assert_eq!(
            v["resourceMetrics"][0]["resource"]["attributes"][2]["value"]["stringValue"],
            "pi"
        );
    }

    #[test]
    fn obs_006_label_values_unescape() {
        let (n, s) = sample(r#"m{a="x\"y",b="1,2"} 3"#).unwrap();
        assert_eq!(n, "m");
        assert_eq!(
            s.labels,
            vec![("a".into(), "x\"y".into()), ("b".into(), "1,2".into())]
        );
    }

    /// REQ: OBS-006 — query events as log records with attributes.
    #[test]
    fn obs_006_events_to_otlp_logs() {
        let line = r#"{"time":"t","tsUnixMicros":1700000000000000,"client":"192.168.1.5","name":"ads.example","qtype":"A","status":"blocked","rcode":"NOERROR","proto":"udp","list":"ads","totalMs":0.2}"#;
        let v: Value =
            serde_json::from_str(&logs_body(&[line.to_owned()], &resource("pi"))).unwrap();
        let r = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(r["timeUnixNano"], "1700000000000000000");
        assert_eq!(
            (
                r["severityText"].as_str(),
                r["body"]["stringValue"].as_str()
            ),
            (
                Some("WARN"),
                Some("A ads.example from 192.168.1.5: blocked")
            )
        );
        let has = |k: &str, val: &str| {
            r["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["key"] == k && a["value"]["stringValue"] == val)
        };
        assert!(
            has("dns.question.name", "ads.example")
                && has("telltale.list", "ads")
                && has("client.address", "192.168.1.5")
        );
    }
}
