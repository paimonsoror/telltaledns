//! Event sinks (REQ: OBS-010, `spec/06` §5; T7.13): every query event, as the same JSON
//! object the API's query log returns, copied to a JSON-lines file (rotated), syslog
//! (RFC 5424 over UDP, or TCP with octet counting), or a batched HTTP webhook.
//!
//! The aggregator thread formats each event once and hands it to every sink through a
//! bounded channel (`max_buffer`); a sink that can't keep up drops events (counted, logged
//! once a minute), so neither DNS nor the query log waits for it (OBS-002). Each sink writes
//! from its own thread; the webhook thread retries a failed batch a few times, then drops it.

use std::io::Write;
use std::net::{IpAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

use telltale_api::model::QueryRow;
use telltale_config::{Config, SinkConfig, SinkFormat, SinkKind};
use telltale_telemetry::Status;
use telltale_telemetry::event::{QueryEvent, Record};
use telltale_telemetry::ring::Sink;
use tracing::{info, warn};

use crate::pipeline::Pipeline;

/// One sink as the aggregator sees it.
struct Out {
    name: String,
    /// Statuses it wants (empty = all).
    statuses: Vec<Status>,
    syslog: bool,
    tx: SyncSender<String>,
    dropped: Arc<AtomicU64>,
    reported: u64,
}

/// The aggregator-side half: formats events and offers them to each sink.
pub(crate) struct EventSinks {
    outs: Vec<Out>,
    pipeline: Arc<Pipeline>,
    node: String,
    privacy: u8,
    /// List names by ID, for the snapshot at `snapshot` (compared by pointer).
    lists: Vec<String>,
    snapshot: usize,
    last_report: Instant,
}

/// Starts the configured sinks (at startup; changing them needs a restart, like the query
/// log). `rt` runs the webhook requests.
pub(crate) fn start(
    cfg: &Config,
    pipeline: &Arc<Pipeline>,
    rt: &tokio::runtime::Handle,
) -> Option<Box<dyn Sink>> {
    let mut outs = Vec::new();
    for s in &cfg.telemetry.sink {
        let (tx, rx) = sync_channel::<String>(usize::try_from(s.max_buffer).unwrap_or(10_000));
        let dropped = Arc::new(AtomicU64::new(0));
        let name = s.name.to_string();
        let c = s.clone();
        let (d, rt) = (Arc::clone(&dropped), rt.clone());
        let host = crate::http::node_name(cfg);
        let spawned = std::thread::Builder::new()
            .name(format!("sink-{name}"))
            .spawn(move || match c.kind {
                SinkKind::File => file_writer(&c, &rx),
                SinkKind::Syslog => syslog_writer(&c, &rx, &host),
                SinkKind::Webhook => webhook_writer(&c, &rx, &d, &rt, &host),
            });
        if let Err(e) = spawned {
            warn!(sink = %name, error = %e, "event sink disabled: cannot start its thread");
            continue;
        }
        info!(sink = %name, kind = ?s.kind, "event sink started");
        outs.push(Out {
            name,
            statuses: s
                .statuses
                .iter()
                .filter_map(|x| {
                    Status::ALL
                        .iter()
                        .copied()
                        .find(|st| st.label() == x.as_str())
                })
                .collect(),
            syslog: s.kind == SinkKind::Syslog,
            tx,
            dropped,
            reported: 0,
        });
    }
    if outs.is_empty() {
        return None;
    }
    Some(Box::new(EventSinks {
        outs,
        pipeline: Arc::clone(pipeline),
        node: crate::http::node_name(cfg),
        privacy: cfg.telemetry.qlog.privacy_level,
        lists: Vec::new(),
        snapshot: 0,
        last_report: Instant::now(),
    }))
}

impl EventSinks {
    /// List names change with snapshots: re-read them only when the snapshot changed.
    fn refresh_lists(&mut self) {
        let f = self.pipeline.filter.load();
        let snap = f.as_ref().and_then(|f| f.matcher.snapshot());
        let ptr = snap.map_or(0, |s| Arc::as_ptr(s) as usize);
        if ptr != self.snapshot {
            self.lists = snap
                .map(|s| s.manifest.lists.iter().map(|l| l.name.clone()).collect())
                .unwrap_or_default();
            self.snapshot = ptr;
        }
    }

    /// The event as the API's query row (names resolved now, after the privacy level).
    fn row(&self, e: &QueryEvent, wire: &[u8]) -> QueryRow {
        let mut ev = *e;
        if self.privacy >= 2 {
            ev.client_ip = [0; 16];
        }
        let name = if self.privacy >= 1 {
            telltale_telemetry::event::dotted(&telltale_store::qlog::hidden_name(wire))
        } else {
            telltale_telemetry::event::dotted(wire)
        };
        let state = self.pipeline.current();
        let policy = &state.policy;
        let client_name = (self.privacy < 2)
            .then(|| {
                let v6 = std::net::Ipv6Addr::from(ev.client_ip);
                let ip = v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4);
                let id = policy
                    .clients
                    .identify(ip, None, None, &self.pipeline.neighbors);
                policy.clients.client(id).map(|c| c.name.to_string())
            })
            .flatten();
        let schedules = self.pipeline.schedules.load().names.clone();
        let (list, rule) =
            crate::api_backend::rule_labels(ev.rule, &self.lists, &policy.quick, &schedules);
        QueryRow {
            time: telltale_api::time::format_us(ev.ts_us),
            ts_unix_micros: ev.ts_us,
            client: telltale_telemetry::agg::client_text(ev.client_ip),
            client_name,
            group: policy
                .clients
                .groups()
                .get(usize::from(ev.group))
                .map(|g| g.name.to_string()),
            name,
            qtype: crate::api_backend::qtype_name(ev.qtype),
            status: ev.status.label().to_owned(),
            rcode: ev.rcode.map(crate::api_backend::rcode_name),
            proto: ev.proto.label().to_owned(),
            list,
            rule,
            total_ms: crate::api_backend::ms(u64::from(ev.t_total_us)),
            upstream_ms: crate::api_backend::ms(u64::from(ev.t_upstream_us)),
            response_bytes: ev.resp_size,
            answers: ev.answers,
            node: Some(self.node.clone()),
        }
    }
}

impl Sink for EventSinks {
    fn record(&mut self, r: &Record) {
        let Record::Query(e, name) = r else { return };
        let wanted = |o: &Out| o.statuses.is_empty() || o.statuses.contains(&e.status);
        if !self.outs.iter().any(wanted) {
            return;
        }
        if e.rule.is_some() {
            self.refresh_lists();
        }
        let row = self.row(e, name.as_wire());
        let Ok(json) = serde_json::to_string(&row) else {
            return;
        };
        for o in &self.outs {
            if !wanted(o) {
                continue;
            }
            let line = if o.syslog {
                // The syslog writer needs the time and severity; it gets them in front.
                format!(
                    "{}\t{}\t{json}",
                    row.time,
                    u8::from(e.status == Status::Blocked)
                )
            } else {
                json.clone()
            };
            match o.tx.try_send(line) {
                Ok(()) => {}
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                    o.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    fn tick(&mut self, now: Instant) {
        if now.duration_since(self.last_report) >= Duration::from_secs(60) {
            self.last_report = now;
            for o in &mut self.outs {
                let d = o.dropped.load(Ordering::Relaxed);
                if d > o.reported {
                    warn!(sink = %o.name, dropped = d - o.reported, "event sink fell behind; events dropped");
                    o.reported = d;
                }
            }
        }
    }
}

/// JSON lines appended to `path`, rotated at `max_bytes` to `<path>.1` .. `<path>.<keep>`.
fn file_writer(c: &SinkConfig, rx: &Receiver<String>) {
    let Some(path) = c
        .path
        .as_ref()
        .map(|p| std::path::PathBuf::from(p.as_str()))
    else {
        return;
    };
    let open = |p: &std::path::Path| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .map(|f| {
                let len = f.metadata().map_or(0, |m| m.len());
                (std::io::BufWriter::new(f), len)
            })
    };
    let mut file = match open(&path) {
        Ok(f) => Some(f),
        Err(e) => {
            warn!(sink = %c.name, path = %path.display(), error = %e, "event sink can't open its file");
            None
        }
    };
    loop {
        let line = match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(l) => Some(l),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if file.is_none() {
            file = open(&path).ok();
        }
        let Some((w, len)) = file.as_mut() else {
            continue;
        };
        let Some(line) = line else {
            let _ = w.flush();
            continue;
        };
        if writeln!(w, "{line}").is_err() {
            file = None;
            continue;
        }
        *len += line.len() as u64 + 1;
        if *len >= c.max_bytes.bytes() {
            let _ = w.flush();
            drop(file.take()); // closed before it moves
            rotate(&path, c.keep);
            file = open(&path).ok();
        }
    }
    if let Some((mut w, _)) = file {
        let _ = w.flush();
    }
}

/// `path` → `path.1` → ... → `path.<keep>` (the oldest is removed).
fn rotate(path: &std::path::Path, keep: u32) {
    let numbered = |n: u32| {
        let mut s = path.as_os_str().to_owned();
        s.push(format!(".{n}"));
        std::path::PathBuf::from(s)
    };
    if keep == 0 {
        let _ = std::fs::remove_file(path);
        return;
    }
    let _ = std::fs::remove_file(numbered(keep));
    for n in (1..keep).rev() {
        let _ = std::fs::rename(numbered(n), numbered(n + 1));
    }
    let _ = std::fs::rename(path, numbered(1));
}

/// One RFC 5424 message: `<PRI>1 TIME HOST telltale - query - JSON`.
pub(crate) fn syslog_message(
    facility: u8,
    blocked: bool,
    time: &str,
    host: &str,
    json: &str,
) -> String {
    // Severity: notice (5) for blocks, informational (6) for the rest.
    let pri = u16::from(facility) * 8 + if blocked { 5 } else { 6 };
    let host: String = host
        .chars()
        .filter(char::is_ascii_graphic)
        .take(255)
        .collect();
    let host = if host.is_empty() {
        "-".to_owned()
    } else {
        host
    };
    format!("<{pri}>1 {time} {host} telltale - query - {json}")
}

/// Syslog over UDP (one datagram per event) or TCP (octet-counted frames, RFC 6587),
/// reconnecting when the collector goes away.
fn syslog_writer(c: &SinkConfig, rx: &Receiver<String>, host: &str) {
    let addr = c.address.as_ref().map_or("", |a| a.as_str()).to_owned();
    let (udp, target) = match addr.split_once("://") {
        Some(("udp", t)) => (true, t.to_owned()),
        Some((_, t)) => (false, t.to_owned()),
        None => return,
    };
    let mut sock: Option<UdpSocket> = None;
    let mut tcp: Option<TcpStream> = None;
    let mut warned = false;
    while let Ok(line) = rx.recv() {
        let mut parts = line.splitn(3, '\t');
        let (Some(time), Some(blocked), Some(json)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let msg = syslog_message(c.facility, blocked == "1", time, host, json);
        let sent = if udp {
            if sock.is_none() {
                sock = UdpSocket::bind(if target.starts_with('[') {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                })
                .ok();
            }
            sock.as_ref()
                .is_some_and(|s| s.send_to(msg.as_bytes(), target.as_str()).is_ok())
        } else {
            if tcp.is_none() {
                tcp = TcpStream::connect(target.as_str()).ok();
                if let Some(t) = &tcp {
                    let _ = t.set_write_timeout(Some(Duration::from_secs(5)));
                }
            }
            let ok = tcp
                .as_mut()
                .is_some_and(|t| write!(t, "{} {msg}", msg.len()).is_ok());
            if !ok {
                tcp = None;
            }
            ok
        };
        if !sent && !warned {
            warn!(sink = %c.name, address = %addr, "event sink can't reach its syslog collector");
        }
        warned = !sent;
    }
}

/// Batches of `batch` events (or whatever arrived in `flush_secs`) posted to `url`.
fn webhook_writer(
    c: &SinkConfig,
    rx: &Receiver<String>,
    dropped: &AtomicU64,
    rt: &tokio::runtime::Handle,
    host: &str,
) {
    let client = match telltale_filter::fetch::Client::new(
        Arc::new(telltale_filter::fetch::SystemResolver),
        &[],
    ) {
        Ok(cl) => cl,
        Err(e) => {
            warn!(sink = %c.name, error = %e, "event sink disabled");
            return;
        }
    };
    let batch = usize::try_from(c.batch.max(1)).unwrap_or(500);
    let wait = Duration::from_secs(u64::from(c.flush_secs.max(1)));
    let mut buf: Vec<String> = Vec::with_capacity(batch);
    let mut first: Option<Instant> = None;
    let mut open = true;
    while open || !buf.is_empty() {
        let left = first.map_or(wait, |f| wait.saturating_sub(f.elapsed()));
        if open {
            match rx.recv_timeout(left) {
                Ok(l) => {
                    first.get_or_insert_with(Instant::now);
                    buf.push(l);
                    if buf.len() < batch {
                        continue;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => open = false,
            }
        }
        if buf.is_empty() {
            first = None;
            continue;
        }
        let body = match c.format {
            SinkFormat::JsonLines => {
                let mut s = buf.join("\n");
                s.push('\n');
                s
            }
            SinkFormat::JsonArray => format!("[{}]", buf.join(",")),
            // REQ: OBS-006 (T7.17)
            SinkFormat::OtlpLogs => crate::otlp::logs_body(&buf, &crate::otlp::resource(host)),
        };
        let mut delivered = false;
        for attempt in 0..3u32 {
            match rt.block_on(post(&client, c, body.clone())) {
                Ok(()) => {
                    delivered = true;
                    break;
                }
                Err(e) => {
                    if attempt == 2 {
                        warn!(sink = %c.name, error = %e, events = buf.len(), "event sink batch dropped");
                    }
                    std::thread::sleep(Duration::from_secs(1 << attempt));
                }
            }
        }
        if !delivered {
            dropped.fetch_add(buf.len() as u64, Ordering::Relaxed);
        }
        buf.clear();
        first = None;
    }
}

async fn post(
    client: &telltale_filter::fetch::Client,
    c: &SinkConfig,
    body: String,
) -> Result<(), String> {
    let url = c.url.as_ref().map_or("", |u| u.as_str());
    let ct = match c.format {
        SinkFormat::JsonLines => "application/x-ndjson",
        SinkFormat::JsonArray | SinkFormat::OtlpLogs => "application/json",
    };
    let mut req = http::Request::post(url)
        .header("content-type", ct)
        .header("user-agent", "TelltaleDNS");
    if let Some(f) = &c.token_file {
        let t = std::fs::read_to_string(f.as_str()).map_err(|e| format!("{}: {e}", f.as_str()))?;
        req = req.header(
            "authorization",
            format!("{} {}", c.token_scheme.as_str(), t.trim()),
        );
    }
    let req = req.body(body.into_bytes()).map_err(|e| e.to_string())?;
    let resp = tokio::time::timeout(Duration::from_secs(15), client.request(req, 64 * 1024))
        .await
        .map_err(|_| "timed out".to_owned())?
        .map_err(|e| e.message)?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: OBS-010 — RFC 5424 framing: PRI from facility and severity, version 1, host,
    /// app name, the event as the message.
    #[test]
    fn obs_010_syslog_message() {
        let m = syslog_message(16, true, "2026-10-06T10:00:00.000Z", "pi dns", "{\"a\":1}");
        assert_eq!(
            m,
            "<133>1 2026-10-06T10:00:00.000Z pidns telltale - query - {\"a\":1}"
        );
        let m = syslog_message(1, false, "t", "", "{}");
        assert!(m.starts_with("<14>1 t - telltale"), "{m}");
    }

    /// REQ: OBS-010 — file rotation keeps `keep` files and drops the oldest.
    #[test]
    fn obs_010_file_rotation() {
        let dir = std::env::temp_dir().join(format!("tt-sink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("events.jsonl");
        for i in 0..4 {
            std::fs::write(&p, format!("{i}")).unwrap();
            rotate(&p, 2);
        }
        assert!(!p.exists());
        assert_eq!(
            std::fs::read_to_string(dir.join("events.jsonl.1")).unwrap(),
            "3"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("events.jsonl.2")).unwrap(),
            "2"
        );
        assert!(!dir.join("events.jsonl.3").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
