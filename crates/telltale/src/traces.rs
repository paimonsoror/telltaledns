//! REQ: OBS-017 (T11.6, ADR-110, `spec/06` §5.1) — exemplars and traces, built from query
//! events on the telemetry thread (a [`Sink`]; never the query path):
//!
//! - **Exemplars:** for each `telltale_query_duration_seconds` bucket (per path), a recent
//!   query that landed in it: its trace ID, latency, and time. A slot is replaced at most once
//!   a second, so the cost per event is a bucket lookup and a comparison. `/metrics` shows them
//!   to a scraper that asks for OpenMetrics ([`openmetrics`]).
//! - **Traces:** with `[telemetry.otlp] traces_sample_every` or `traces_slow_ms`, the chosen
//!   queries are queued (bounded; more are dropped and counted) and sent every few seconds to
//!   `<endpoint>/v1/traces` as OTLP JSON: a server span for the query and, when upstreams were
//!   asked, a client span for the wait.
//!
//! The trace ID ([`telltale_telemetry::event::trace_id`]) is computed from the query as the
//! query log keeps it (after the privacy level), so `GET /api/v1/queries?trace=` finds it.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde_json::{Value, json};
use tracing::{debug, warn};

use telltale_telemetry::event::{self, Name, QueryEvent, Record};
use telltale_telemetry::ring::Sink;
use telltale_telemetry::{BUCKETS_US, Path, Status};

const N_PATH: usize = Path::ALL.len();
const N_BUCKET: usize = BUCKETS_US.len() + 1;
/// A bucket's exemplar is replaced at most this often.
const EXEMPLAR_REFRESH_US: u64 = 1_000_000;
/// Queries waiting to be sent as traces; more are dropped (counted).
const TRACE_QUEUE: usize = 4096;
/// Queries per export request, and the pause between exports.
const TRACE_BATCH: usize = 512;
const TRACE_INTERVAL: Duration = Duration::from_secs(5);

/// Content type of the OpenMetrics exposition.
pub(crate) const OPENMETRICS: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// A recent query in one latency bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Exemplar {
    pub(crate) trace: [u8; 16],
    pub(crate) value_us: u32,
    pub(crate) ts_us: u64,
}

/// Exemplars by path and bucket.
pub(crate) type ExemplarTable = [[Option<Exemplar>; N_BUCKET]; N_PATH];

/// A query to send as a trace, as the privacy level keeps it.
#[derive(Debug, Clone, Copy)]
struct Traced {
    e: QueryEvent,
    name: Name,
    trace: [u8; 16],
}

/// What the sink shares with `/metrics` and the exporter.
#[derive(Debug, Default)]
pub(crate) struct Traces {
    exemplars: Mutex<ExemplarTable>,
    queue: Mutex<VecDeque<Traced>>,
    /// Queries sent as traces, dropped (the queue was full), and lost to failed requests.
    pub(crate) sent: AtomicU64,
    pub(crate) dropped: AtomicU64,
    pub(crate) failed: AtomicU64,
}

impl Traces {
    pub(crate) fn exemplars(&self) -> ExemplarTable {
        *self
            .exemplars
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn take(&self, n: usize) -> Vec<Traced> {
        let mut q = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        let n = n.min(q.len());
        q.drain(..n).collect()
    }
}

/// The histogram bucket a latency falls in (as [`telltale_telemetry::Metrics`] counts it).
fn bucket(us: u32) -> usize {
    BUCKETS_US
        .iter()
        .position(|&ub| u64::from(us) <= ub)
        .unwrap_or(N_BUCKET - 1)
}

/// The trace ID of `e` (already as the privacy level keeps it).
fn trace_of(e: &QueryEvent, name: &Name) -> [u8; 16] {
    event::trace_id(
        e.ts_us,
        &telltale_telemetry::agg::client_text(e.client_ip),
        &crate::api_backend::qtype_name(e.qtype),
        &name.dotted(),
    )
}

/// Picks exemplars and the queries to trace, on the telemetry thread.
pub(crate) struct TraceSink {
    shared: Arc<Traces>,
    privacy: u8,
    sample_every: u64,
    slow_us: u32,
    seen: u64,
    /// When each exemplar slot was last filled (checked without the lock).
    filled: [[u64; N_BUCKET]; N_PATH],
}

impl TraceSink {
    pub(crate) fn new(shared: Arc<Traces>, cfg: &telltale_config::Config) -> Self {
        let o = &cfg.telemetry.otlp;
        let tracing = o.endpoint.is_some();
        Self {
            shared,
            privacy: cfg.telemetry.qlog.privacy_level,
            sample_every: if tracing {
                u64::from(o.traces_sample_every)
            } else {
                0
            },
            slow_us: if tracing {
                o.traces_slow_ms.saturating_mul(1000)
            } else {
                0
            },
            seen: 0,
            filled: [[0; N_BUCKET]; N_PATH],
        }
    }
}

impl Sink for TraceSink {
    fn record(&mut self, rec: &Record) {
        let Record::Query(e, _) = rec else {
            return;
        };
        if e.status == Status::Dropped {
            return; // not in the latency histogram
        }
        let (path, slot) = (e.status.path() as usize, bucket(e.t_total_us));
        let exemplar = e.ts_us >= self.filled[path][slot].saturating_add(EXEMPLAR_REFRESH_US);
        self.seen = self.seen.wrapping_add(1);
        let traced = (self.slow_us > 0 && e.t_total_us >= self.slow_us)
            || (self.sample_every > 0 && self.seen.is_multiple_of(self.sample_every));
        if !exemplar && !traced {
            return;
        }
        // As the query log keeps it: what the trace ID is computed from (ADR-110).
        let Record::Query(e, name) = event::private(rec, self.privacy) else {
            return;
        };
        let trace = trace_of(&e, &name);
        if exemplar {
            self.filled[path][slot] = e.ts_us;
            self.shared
                .exemplars
                .lock()
                .unwrap_or_else(PoisonError::into_inner)[path][slot] = Some(Exemplar {
                trace,
                value_us: e.t_total_us,
                ts_us: e.ts_us,
            });
        }
        if traced {
            let mut queue = self
                .shared
                .queue
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if queue.len() < TRACE_QUEUE {
                queue.push_back(Traced { e, name, trace });
            } else {
                self.shared.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// ---- OpenMetrics ----------------------------------------------------------------------------

/// The `le` label values of `telltale_query_duration_seconds`, as the exposition writes them.
#[allow(clippy::cast_precision_loss)] // bucket bounds are small
fn le_labels() -> [String; N_BUCKET] {
    std::array::from_fn(|i| {
        BUCKETS_US
            .get(i)
            .map_or_else(|| "+Inf".to_owned(), |ub| format!("{}", *ub as f64 / 1e6))
    })
}

/// A label's value in a sample line (`path="cache"` → `cache`); values here have no escapes.
fn label<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start = line.find(&format!("{key}=\""))? + key.len() + 2;
    let len = line.get(start..)?.find('"')?;
    line.get(start..start + len)
}

/// The OpenMetrics family and type for a family the Prometheus text format declared: a
/// counter's family drops `_total` (its samples keep it); a counter without `_total`, or a
/// name another family already has, becomes `unknown`.
fn om_family<'a>(name: &'a str, kind: &str, names: &[&str]) -> (&'a str, &'static str) {
    match kind {
        "counter" => match name.strip_suffix("_total") {
            Some(base) if !names.contains(&base) => (base, "counter"),
            _ => (name, "unknown"),
        },
        "gauge" => (name, "gauge"),
        "histogram" => (name, "histogram"),
        "summary" => (name, "summary"),
        _ => (name, "unknown"),
    }
}

/// REQ: OBS-017 — the Prometheus text exposition `text` as OpenMetrics 1.0, with each
/// `telltale_query_duration_seconds` bucket's exemplar: `… # {trace_id="…"} 0.000734
/// 1791000000.123456`. HELP text is escaped as OpenMetrics wants (`\\`, `\"`), comments other
/// than HELP and TYPE are left out, and it ends with `# EOF`.
pub(crate) fn openmetrics(text: &str, ex: &ExemplarTable) -> String {
    const BUCKET: &str = "telltale_query_duration_seconds_bucket{";
    let names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("# TYPE "))
        .filter_map(|t| t.split_once(' ').map(|(n, _)| n))
        .collect();
    let les = le_labels();
    let mut out = String::with_capacity(text.len() + 4096);
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let (name, help) = rest.split_once(' ').unwrap_or((rest, ""));
            // `PromWriter::family` writes TYPE right after HELP.
            let kind = match lines.peek().and_then(|l| l.strip_prefix("# TYPE ")) {
                Some(t) if t.split_once(' ').is_some_and(|(n, _)| n == name) => {
                    lines.next();
                    t.split_once(' ').map_or("untyped", |(_, k)| k)
                }
                _ => "untyped",
            };
            let (family, kind) = om_family(name, kind, &names);
            let help = help.replace('\\', "\\\\").replace('"', "\\\"");
            let _ = writeln!(out, "# HELP {family} {help}");
            let _ = writeln!(out, "# TYPE {family} {kind}");
        } else if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest.split_once(' ').unwrap_or((rest, "untyped"));
            let (family, kind) = om_family(name, kind, &names);
            let _ = writeln!(out, "# TYPE {family} {kind}");
        } else if !line.starts_with('#') && !line.trim().is_empty() {
            // (Other comments and blank lines aren't OpenMetrics: left out.)
            out.push_str(line);
            if line.starts_with(BUCKET)
                && let Some(p) =
                    label(line, "path").and_then(|v| Path::ALL.iter().position(|x| x.label() == v))
                && let Some(b) = label(line, "le").and_then(|v| les.iter().position(|x| x == v))
                && let Some(x) = ex[p][b]
            {
                let value = f64::from(x.value_us) / 1e6;
                let _ = write!(
                    out,
                    " # {{trace_id=\"{}\"}} {value} {}.{:06}",
                    event::trace_hex(&x.trace),
                    x.ts_us / 1_000_000,
                    x.ts_us % 1_000_000
                );
            }
            out.push('\n');
        }
    }
    out.push_str("# EOF\n");
    out
}

/// Whether an `Accept` header asks for OpenMetrics (Prometheus does by default).
pub(crate) fn wants_openmetrics(accept: Option<&str>) -> bool {
    accept.is_some_and(|a| {
        a.split(',').any(|part| {
            let mut it = part.split(';').map(str::trim);
            let refused = |p: &str| {
                p.strip_prefix("q=")
                    .and_then(|q| q.parse::<f32>().ok())
                    .is_some_and(|q| q <= 0.0)
            };
            it.next() == Some("application/openmetrics-text") && !it.any(refused)
        })
    })
}

// ---- Traces ---------------------------------------------------------------------------------

/// Names the exporter resolves from the running configuration.
pub(crate) struct Names<'a> {
    pub(crate) node: &'a str,
    pub(crate) upstreams: &'a [(u16, String)],
    pub(crate) groups: &'a [String],
}

fn attr(k: &str, v: impl Into<String>) -> Value {
    json!({"key": k, "value": {"stringValue": v.into()}})
}

fn attr_int(k: &str, v: u64) -> Value {
    json!({"key": k, "value": {"intValue": v.to_string()}})
}

/// The spans of one query: a server span for the whole query and, when upstreams were asked,
/// a client span for the wait (placed at its end: the event has its length, not its start).
fn spans(t: &Traced, n: &Names<'_>) -> Vec<Value> {
    let e = &t.e;
    let trace = event::trace_hex(&t.trace);
    let mut root_id = [0u8; 8];
    root_id.copy_from_slice(&t.trace[8..]);
    if root_id == [0; 8] {
        root_id[7] = 1;
    }
    let mut child_id = root_id;
    child_id[0] ^= 0x80;
    let hex8 = |b: &[u8; 8]| {
        b.iter().fold(String::new(), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
    };
    let start_ns = e.ts_us.saturating_mul(1000);
    let end_ns = e
        .ts_us
        .saturating_add(u64::from(e.t_total_us))
        .saturating_mul(1000);
    let qtype = crate::api_backend::qtype_name(e.qtype);
    let mut attributes = vec![
        attr("dns.question.name", t.name.dotted()),
        attr("dns.question.type", qtype.clone()),
        attr("network.transport", e.proto.label()),
        attr("telltale.status", e.status.label()),
        attr("telltale.node", n.node),
    ];
    if let Some(rc) = e.rcode {
        attributes.push(attr(
            "dns.response_code",
            crate::api_backend::rcode_name(rc),
        ));
    }
    // At privacy level 2 and above the address is all zeros: left out.
    if e.client_ip != [0; 16] {
        attributes.push(attr(
            "client.address",
            telltale_telemetry::agg::client_text(e.client_ip),
        ));
    }
    if let Some(g) = n.groups.get(usize::from(e.group)) {
        attributes.push(attr("telltale.group", g.clone()));
    }
    attributes.push(attr_int("telltale.answers", u64::from(e.answers)));
    let failed = e.status == Status::ServFail || e.rcode == Some(2);
    let mut root = json!({
        "traceId": trace,
        "spanId": hex8(&root_id),
        "name": format!("DNS {qtype}"),
        "kind": 2,
        "startTimeUnixNano": start_ns.to_string(),
        "endTimeUnixNano": end_ns.to_string(),
        "attributes": attributes,
    });
    if failed && let Some(o) = root.as_object_mut() {
        o.insert("status".into(), json!({"code": 2, "message": "SERVFAIL"}));
    }
    let mut out = vec![root];
    if e.t_upstream_us > 0 {
        let upstream = n
            .upstreams
            .iter()
            .find(|(id, _)| *id == e.upstream)
            .map_or_else(|| "upstream".to_owned(), |(_, name)| name.clone());
        let wait_ns = u64::from(e.t_upstream_us).saturating_mul(1000);
        out.push(json!({
            "traceId": trace,
            "spanId": hex8(&child_id),
            "parentSpanId": hex8(&root_id),
            "name": format!("upstream {upstream}"),
            "kind": 3,
            "startTimeUnixNano": end_ns.saturating_sub(wait_ns).max(start_ns).to_string(),
            "endTimeUnixNano": end_ns.to_string(),
            "attributes": [
                attr("telltale.upstream", upstream),
                attr_int("telltale.attempts", u64::from(e.attempts)),
            ],
        }));
    }
    out
}

/// The OTLP `ExportTraceServiceRequest` JSON for `batch`.
fn traces_body(batch: &[Traced], n: &Names<'_>, resource: &Value) -> Value {
    let spans: Vec<Value> = batch.iter().flat_map(|t| spans(t, n)).collect();
    json!({"resourceSpans": [{
        "resource": resource,
        "scopeSpans": [{"scope": {"name": "telltaledns", "version": crate::build_info::VERSION}, "spans": spans}],
    }]})
}

/// The trace export task: every few seconds, what the sink queued.
pub(crate) async fn run(
    sources: Arc<crate::http::Sources>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let cfg = sources.config.load_full();
    let o = &cfg.telemetry.otlp;
    if o.traces_sample_every == 0 && o.traces_slow_ms == 0 {
        return;
    }
    let Some(endpoint) = crate::otlp::endpoint(&cfg) else {
        return;
    };
    let Some(client) = crate::otlp::client() else {
        return;
    };
    let url = format!("{endpoint}/v1/traces");
    let shared = &sources.traces;
    let mut failing = false;
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(TRACE_INTERVAL) => {}
        }
        let cfg = sources.config.load_full();
        let node = crate::http::node_name(&cfg);
        let state = sources.pipeline.current();
        let upstreams: Vec<(u16, String)> = state
            .router
            .upstreams()
            .iter()
            .map(|u| (u.id, u.name.clone()))
            .collect();
        let groups: Vec<String> = state
            .policy
            .clients
            .groups()
            .iter()
            .map(|g| g.name.to_string())
            .collect();
        let names = Names {
            node: &node,
            upstreams: &upstreams,
            groups: &groups,
        };
        let resource = crate::otlp::resource(&node);
        // Up to the queue's size per round; a slow collector costs only what doesn't fit.
        for _ in 0..TRACE_QUEUE / TRACE_BATCH {
            let batch = shared.take(TRACE_BATCH);
            if batch.is_empty() {
                break;
            }
            let body = traces_body(&batch, &names, &resource).to_string();
            let n = batch.len() as u64;
            match crate::otlp::post(&client, &url, &cfg, body).await {
                Ok(()) => {
                    shared.sent.fetch_add(n, Ordering::Relaxed);
                    if failing {
                        debug!("OTLP traces: delivered again");
                    }
                    failing = false;
                }
                Err(why) => {
                    shared.failed.fetch_add(n, Ordering::Relaxed);
                    if !failing {
                        warn!(%url, error = %why, "OTLP traces not delivered (logged once until it works again)");
                    }
                    failing = true;
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_telemetry::Proto;

    fn ev(ts_us: u64, total_us: u32, upstream_us: u32, status: Status) -> QueryEvent {
        let mut ip = [0u8; 16];
        ip[10..].copy_from_slice(&[0xff, 0xff, 192, 168, 1, 5]);
        QueryEvent {
            ts_us,
            client_ip: ip,
            client_ref: 0,
            group: 0,
            qtype: 1,
            qclass: 1,
            rcode: Some(0),
            status,
            proto: Proto::Udp,
            flags: 0,
            rule: None,
            upstream: 1,
            attempts: 1,
            t_total_us: total_us,
            t_upstream_us: upstream_us,
            resp_size: 64,
            answers: 1,
        }
    }

    fn name(n: &str) -> Name {
        Name::from_wire(
            telltale_proto::NameBuf::from_presentation(n)
                .unwrap()
                .as_wire(),
        )
    }

    fn sink(cfg: &str) -> (Arc<Traces>, TraceSink) {
        let cfg = telltale_config::Loader::new()
            .toml_str("t.toml", cfg)
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config;
        let shared = Arc::new(Traces::default());
        let s = TraceSink::new(Arc::clone(&shared), &cfg);
        (shared, s)
    }

    /// REQ: OBS-017 — each bucket keeps a recent query (its trace ID, latency, time), replaced
    /// at most once a second; dropped queries aren't in the histogram; no traces without a
    /// collector.
    #[test]
    fn obs_017_one_recent_exemplar_per_bucket() {
        let _key = crate::privacy::TEST_KEY_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (shared, mut s) = sink("");
        let t0 = 1_791_000_000_000_000;
        let n = name("shop.example");
        s.record(&Record::Query(ev(t0, 700, 0, Status::Cached), n));
        s.record(&Record::Query(ev(t0 + 10, 650, 0, Status::Cached), n));
        s.record(&Record::Query(ev(t0, 30_000, 25_000, Status::Forwarded), n));
        s.record(&Record::Query(ev(t0, 9, 0, Status::Dropped), n));
        let x = shared.exemplars();
        let cache = x[Path::Cache as usize][bucket(700)].unwrap();
        assert_eq!(
            (cache.value_us, cache.ts_us),
            (700, t0),
            "the first, kept for a second"
        );
        assert_eq!(
            cache.trace,
            event::trace_id(t0, "192.168.1.5", "A", "shop.example")
        );
        assert!(x[Path::Upstream as usize][bucket(30_000)].is_some());
        assert_eq!(x.iter().flatten().filter(|e| e.is_some()).count(), 2);
        s.record(&Record::Query(
            ev(t0 + 1_000_000, 800, 0, Status::Cached),
            n,
        ));
        assert_eq!(
            shared.exemplars()[Path::Cache as usize][bucket(800)].map(|e| e.value_us),
            Some(800),
            "a second later, replaced"
        );
        assert!(shared.take(10).is_empty(), "no collector: no traces");
    }

    /// REQ: OBS-017 — 1 in N and every slow query is queued; the queue is bounded (counted);
    /// names and clients as the privacy level keeps them, so the trace ID matches the log.
    #[test]
    fn obs_017_traces_sampled_slow_and_private() {
        let _key = crate::privacy::TEST_KEY_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (shared, mut s) = sink(
            "[telemetry.otlp]\nendpoint = \"http://otel:4318\"\ntraces_sample_every = 3\ntraces_slow_ms = 100\n",
        );
        let n = name("shop.example");
        for i in 0..6 {
            s.record(&Record::Query(ev(10 + i, 50, 0, Status::Cached), n));
        }
        s.record(&Record::Query(
            ev(20, 150_000, 140_000, Status::Forwarded),
            n,
        ));
        let q = shared.take(100);
        assert_eq!(q.len(), 3, "2 sampled + 1 slow");
        for _ in 0..TRACE_QUEUE + 5 {
            s.record(&Record::Query(ev(30, 200_000, 0, Status::Forwarded), n));
        }
        assert_eq!(shared.dropped.load(Ordering::Relaxed), 5);
        let (shared, mut s) = sink(
            "[telemetry.otlp]\nendpoint = \"http://otel:4318\"\ntraces_slow_ms = 1\n[telemetry.qlog]\nprivacy_level = 2\n",
        );
        s.record(&Record::Query(ev(40, 5_000, 0, Status::Cached), n));
        let t = shared.take(1)[0];
        assert_eq!(t.e.client_ip, [0; 16]);
        let hidden = t.name.dotted();
        assert!(hidden.starts_with('h') && !hidden.contains('.'), "{hidden}");
        assert_eq!(t.trace, event::trace_id(40, "::", "A", &hidden));
    }

    /// REQ: OBS-017 — OpenMetrics: counter families without `_total`, HELP quotes escaped,
    /// an exemplar on the bucket that has one, `# EOF` last; Accept negotiation.
    #[test]
    fn obs_017_openmetrics_with_exemplars() {
        let text = "# HELP telltale_queries_total DNS queries.\n# TYPE telltale_queries_total counter\ntelltale_queries_total{proto=\"udp\"} 3\n# HELP telltale_paused Pauses (group=\"*\" = everyone).\n# TYPE telltale_paused gauge\ntelltale_paused 0\n# HELP odd_count Counter without the suffix.\n# TYPE odd_count counter\nodd_count 1\n# HELP telltale_query_duration_seconds Latency.\n# TYPE telltale_query_duration_seconds histogram\ntelltale_query_duration_seconds_bucket{path=\"cache\",le=\"0.001\"} 2\ntelltale_query_duration_seconds_bucket{path=\"cache\",le=\"+Inf\"} 2\ntelltale_query_duration_seconds_sum{path=\"cache\"} 0.0014\ntelltale_query_duration_seconds_count{path=\"cache\"} 2\n";
        let mut ex: ExemplarTable = Default::default();
        let trace = event::trace_id_with(None, 1_791_000_000_123_456, "10.0.0.5", "A", "a.example");
        ex[Path::Cache as usize][bucket(700)] = Some(Exemplar {
            trace,
            value_us: 700,
            ts_us: 1_791_000_000_123_456,
        });
        let om = openmetrics(text, &ex);
        assert!(
            om.contains(
                "# TYPE telltale_queries counter\ntelltale_queries_total{proto=\"udp\"} 3\n"
            ),
            "{om}"
        );
        assert!(
            om.contains("# HELP telltale_paused Pauses (group=\\\"*\\\" = everyone).\n"),
            "{om}"
        );
        assert!(om.contains("# TYPE odd_count unknown\n"), "{om}");
        assert!(
            om.contains(&format!(
                "telltale_query_duration_seconds_bucket{{path=\"cache\",le=\"0.001\"}} 2 # {{trace_id=\"{}\"}} 0.0007 1791000000.123456\n",
                event::trace_hex(&trace)
            )),
            "{om}"
        );
        assert!(
            om.contains("telltale_query_duration_seconds_bucket{path=\"cache\",le=\"+Inf\"} 2\n")
        );
        assert!(om.ends_with("count{path=\"cache\"} 2\n# EOF\n"), "{om}");
        // Prometheus's default Accept, a plain one, and a refusal.
        assert!(wants_openmetrics(Some(
            "application/openmetrics-text;version=1.0.0,application/openmetrics-text;version=0.0.1;q=0.75,text/plain;version=0.0.4;q=0.5,*/*;q=0.1"
        )));
        assert!(!wants_openmetrics(Some("text/plain;version=0.0.4")));
        assert!(!wants_openmetrics(Some("application/openmetrics-text;q=0")));
        assert!(!wants_openmetrics(None));
    }

    /// REQ: OBS-017 — a query becomes a server span (name, type, response code, client,
    /// group) and, when upstreams were asked, a client span for the wait, under one trace ID.
    #[test]
    fn obs_017_spans_from_a_query() {
        let mut query = ev(1_791_000_000_000_000, 30_000, 25_000, Status::Forwarded);
        query.rcode = Some(2);
        let qname = name("shop.example");
        let traced = Traced {
            e: query,
            name: qname,
            trace: trace_of(&query, &qname),
        };
        let names = Names {
            node: "pi",
            upstreams: &[(1, "quad9".to_owned())],
            groups: &["lab".to_owned()],
        };
        let body = traces_body(&[traced], &names, &crate::otlp::resource("pi"));
        let spans = &body["resourceSpans"][0]["scopeSpans"][0]["spans"];
        assert_eq!(spans.as_array().map(Vec::len), Some(2));
        let (root, up) = (&spans[0], &spans[1]);
        assert_eq!(root["traceId"], event::trace_hex(&traced.trace));
        assert_eq!(up["traceId"], root["traceId"]);
        assert_eq!(up["parentSpanId"], root["spanId"]);
        assert_ne!(up["spanId"], root["spanId"]);
        assert_eq!(
            (root["name"].as_str(), root["kind"].as_u64()),
            (Some("DNS A"), Some(2))
        );
        assert_eq!(root["status"]["code"], 2);
        assert_eq!(root["startTimeUnixNano"], "1791000000000000000");
        assert_eq!(root["endTimeUnixNano"], "1791000000030000000");
        assert_eq!(up["startTimeUnixNano"], "1791000000005000000");
        assert_eq!(up["name"], "upstream quad9");
        let has = |s: &Value, k: &str, val: &str| {
            s["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["key"] == k && a["value"]["stringValue"] == val)
        };
        assert!(has(root, "dns.question.name", "shop.example"));
        assert!(has(root, "client.address", "192.168.1.5"));
        assert!(has(root, "telltale.group", "lab"));
        assert!(has(root, "dns.response_code", "SERVFAIL"));
        // A cache hit: one span.
        let hit = Traced {
            e: ev(5, 40, 0, Status::Cached),
            name: qname,
            trace: [1; 16],
        };
        assert_eq!(
            traces_body(&[hit], &names, &Value::Null)["resourceSpans"][0]["scopeSpans"][0]["spans"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
    }
}
