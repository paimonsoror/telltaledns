//! Event sinks (REQ: OBS-010, `spec/06` §5; T7.13): every query event, as the same JSON
//! object the API's query log returns, copied to a JSON-lines file (rotated), syslog
//! (RFC 5424 over UDP, or TCP or (T9.11) TLS with octet counting), or a batched HTTP
//! webhook, which (T9.11) can keep refused batches on disk until the collector is back.
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

/// REQ: OBS-010 (T9.19) — each sink's dropped-event counter, by name, for `/metrics` (set
/// once at startup with the sinks).
static DROPS: std::sync::OnceLock<Vec<(String, Arc<AtomicU64>)>> = std::sync::OnceLock::new();

/// Events each sink dropped since start (buffer full, or a batch the collector refused).
pub(crate) fn drops() -> Vec<(String, u64)> {
    DROPS
        .get()
        .map(|v| {
            v.iter()
                .map(|(n, d)| (n.clone(), d.load(Ordering::Relaxed)))
                .collect()
        })
        .unwrap_or_default()
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
        let spill = Spill::new(s, cfg.node.data_dir.as_str());
        let spawned = std::thread::Builder::new()
            .name(format!("sink-{name}"))
            .spawn(move || match c.kind {
                SinkKind::File => file_writer(&c, &rx),
                SinkKind::Syslog => syslog_writer(&c, &rx, &host),
                SinkKind::Webhook => webhook_writer(&c, &rx, &d, &rt, &host, spill.as_ref()),
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
    let _ = DROPS.set(
        outs.iter()
            .map(|o| (o.name.clone(), Arc::clone(&o.dropped)))
            .collect(),
    );
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
        // REQ: OBS-010 (review 04-09) — borrowed, not cloned per event: this runs on the
        // aggregator thread for every event while a sink is configured.
        let schedules = self.pipeline.schedules.load();
        let (list, rule) =
            crate::api_backend::rule_labels(ev.rule, &self.lists, &policy.quick, &schedules.names);
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

/// REQ: OBS-010 (T9.11) — the TLS client for a `tls://` syslog collector: the public roots
/// plus `tls_ca`.
fn syslog_tls(c: &SinkConfig) -> Result<Arc<rustls::ClientConfig>, String> {
    use rustls::pki_types::pem::PemObject as _;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(f) = &c.tls_ca {
        for cert in rustls::pki_types::CertificateDer::pem_file_iter(f.as_str())
            .map_err(|e| format!("{}: {e}", f.as_str()))?
        {
            roots
                .add(cert.map_err(|e| format!("{}: {e}", f.as_str()))?)
                .map_err(|e| format!("{}: {e}", f.as_str()))?;
        }
    }
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// A stream to a TCP or TLS syslog collector.
fn syslog_connect(
    target: &str,
    tls: Option<&Arc<rustls::ClientConfig>>,
) -> Option<Box<dyn Write + Send>> {
    let t = TcpStream::connect(target).ok()?;
    let _ = t.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = t.set_read_timeout(Some(Duration::from_secs(5)));
    let Some(cfg) = tls else {
        return Some(Box::new(t));
    };
    // REQ: OBS-010 (T9.11) — RFC 5425: the certificate must name the host in the address.
    let host = target
        .rsplit_once(':')
        .map_or(target, |(h, _)| h)
        .trim_matches(|ch| ch == '[' || ch == ']');
    let name = rustls::pki_types::ServerName::try_from(host.to_owned()).ok()?;
    let conn = rustls::ClientConnection::new(Arc::clone(cfg), name).ok()?;
    Some(Box::new(rustls::StreamOwned::new(conn, t)))
}

/// Syslog over UDP (one datagram per event) or TCP or TLS (octet-counted frames, RFC 6587
/// and RFC 5425), reconnecting when the collector goes away.
fn syslog_writer(c: &SinkConfig, rx: &Receiver<String>, host: &str) {
    let addr = c.address.as_ref().map_or("", |a| a.as_str()).to_owned();
    let (udp, target) = match addr.split_once("://") {
        Some(("udp", t)) => (true, t.to_owned()),
        Some((_, t)) => (false, t.to_owned()),
        None => return,
    };
    let tls = if addr.starts_with("tls://") {
        match syslog_tls(c) {
            Ok(t) => Some(t),
            Err(e) => {
                warn!(sink = %c.name, error = %e, "event sink disabled: its TLS settings");
                return;
            }
        }
    } else {
        None
    };
    let mut sock: Option<UdpSocket> = None;
    let mut tcp: Option<Box<dyn Write + Send>> = None;
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
                tcp = syslog_connect(&target, tls.as_ref());
            }
            let ok = tcp
                .as_mut()
                .is_some_and(|t| write!(t, "{} {msg}", msg.len()).is_ok() && t.flush().is_ok());
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
    spill: Option<&Spill>,
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
            // REQ: OBS-010 (T9.11) — quiet: a chance to send what was kept.
            if let Some(s) = spill {
                replay(s, c, &client, rt, host, batch);
            }
            continue;
        }
        let body = webhook_body(c, &buf, host);
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
        match (delivered, spill) {
            // REQ: OBS-010 (T9.11) — the collector is back: send what was kept, oldest first.
            (true, Some(s)) => replay(s, c, &client, rt, host, batch),
            (true, None) => {}
            (false, Some(s)) if s.push(&buf) => {
                info!(sink = %c.name, events = buf.len(), "event sink batch kept on disk until the collector is back");
            }
            (false, _) => {
                dropped.fetch_add(buf.len() as u64, Ordering::Relaxed);
            }
        }
        buf.clear();
        first = None;
    }
}

/// A webhook request body for `events`.
fn webhook_body(c: &SinkConfig, events: &[String], host: &str) -> String {
    match c.format {
        SinkFormat::JsonLines => {
            let mut s = events.join("\n");
            s.push('\n');
            s
        }
        SinkFormat::JsonArray => format!("[{}]", events.join(",")),
        // REQ: OBS-006 (T7.17)
        SinkFormat::OtlpLogs => crate::otlp::logs_body(events, &crate::otlp::resource(host)),
    }
}

/// REQ: OBS-010 (T9.11) — sends up to 20 kept batches, stopping at the first failure (the
/// rest wait for the next chance).
fn replay(
    s: &Spill,
    c: &SinkConfig,
    client: &telltale_filter::fetch::Client,
    rt: &tokio::runtime::Handle,
    host: &str,
    batch: usize,
) {
    for _ in 0..20 {
        let (events, next) = s.take(batch);
        if events.is_empty() {
            return;
        }
        if rt
            .block_on(post(client, c, webhook_body(c, &events, host)))
            .is_err()
        {
            return;
        }
        s.commit(next);
    }
}

/// REQ: OBS-010 (T9.11) — a webhook sink's refused batches on disk: events appended as
/// JSON lines to `<data_dir>/sinks/<name>.spill`, read from the offset in `.pos`; the files
/// go once everything is sent. The file never grows past `spill_max_bytes` (sent events
/// included until it's compacted); events that don't fit are dropped (counted).
pub(crate) struct Spill {
    path: std::path::PathBuf,
    pos: std::path::PathBuf,
    max: u64,
}

impl Spill {
    fn new(c: &SinkConfig, data_dir: &str) -> Option<Self> {
        let max = c.spill_max_bytes?.bytes();
        let safe: String = c
            .name
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '-' {
                    ch
                } else {
                    '_'
                }
            })
            .collect();
        let dir = std::path::Path::new(data_dir).join("sinks");
        Some(Self {
            path: dir.join(format!("{safe}.spill")),
            pos: dir.join(format!("{safe}.spill.pos")),
            max,
        })
    }

    fn offset(&self) -> u64 {
        std::fs::read_to_string(&self.pos)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    /// Appends `events`; false (nothing written) when they don't fit.
    fn push(&self, events: &[String]) -> bool {
        let mut size = std::fs::metadata(&self.path).map_or(0, |m| m.len());
        let add: u64 = events.iter().map(|e| e.len() as u64 + 1).sum();
        if size + add > self.max {
            // Sent events still at the front: drop them to make room.
            self.compact();
            size = std::fs::metadata(&self.path).map_or(0, |m| m.len());
            if size + add > self.max {
                return false;
            }
        }
        if let Some(d) = self.path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        else {
            return false;
        };
        let mut out = String::with_capacity(usize::try_from(add).unwrap_or(0));
        for e in events {
            out.push_str(e);
            out.push('\n');
        }
        f.write_all(out.as_bytes()).is_ok()
    }

    /// Up to `limit` events from the front, and the offset after them.
    fn take(&self, limit: usize) -> (Vec<String>, u64) {
        use std::io::{BufRead as _, Seek as _};
        let start = self.offset();
        let Ok(mut file) = std::fs::File::open(&self.path) else {
            return (Vec::new(), start);
        };
        if file.seek(std::io::SeekFrom::Start(start)).is_err() {
            return (Vec::new(), start);
        }
        let mut reader = std::io::BufReader::new(file);
        let (mut events, mut at) = (Vec::new(), start);
        let mut line = String::new();
        while events.len() < limit {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    at += read as u64;
                    let event = line.trim_end_matches('\n');
                    if !event.is_empty() {
                        events.push(event.to_owned());
                    }
                }
            }
        }
        (events, at)
    }

    /// Marks everything before `next` as sent; removes the files when that's all of it.
    fn commit(&self, next: u64) {
        let size = std::fs::metadata(&self.path).map_or(0, |m| m.len());
        if next >= size {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(&self.pos);
        } else {
            let _ = std::fs::write(&self.pos, next.to_string());
        }
    }

    /// Rewrites the file without its sent events.
    fn compact(&self) {
        let start = self.offset();
        if start == 0 {
            return;
        }
        let Ok(data) = std::fs::read(&self.path) else {
            return;
        };
        let rest = data
            .get(usize::try_from(start).unwrap_or(usize::MAX)..)
            .unwrap_or_default();
        let tmp = self.path.with_extension("spill.tmp");
        if std::fs::write(&tmp, rest).is_ok() && std::fs::rename(&tmp, &self.path).is_ok() {
            let _ = std::fs::remove_file(&self.pos);
        }
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
    #[allow(clippy::many_single_char_names)]
    fn obs_010_spill_keeps_order_and_cap() {
        let d = tempfile::tempdir().unwrap();
        let c: SinkConfig = toml::from_str(
            "name = \"hook/1\"\ntype = \"webhook\"\nurl = \"http://x\"\nspill_max_bytes = \"1MiB\"\n",
        )
        .unwrap();
        let s = Spill::new(&c, d.path().to_str().unwrap()).unwrap();
        assert!(s.path.ends_with("sinks/hook_1.spill"));
        let ev = |i: usize| format!("{{\"n\":{i}}}");
        assert!(s.push(&(0..3).map(ev).collect::<Vec<_>>()));
        assert!(s.push(&(3..5).map(ev).collect::<Vec<_>>()));
        let (a, next) = s.take(2);
        assert_eq!(a, vec![ev(0), ev(1)]);
        // Not committed (the post failed): the same events again.
        assert_eq!(s.take(2).0, a);
        s.commit(next);
        let (b, next) = s.take(10);
        assert_eq!(b, (2..5).map(ev).collect::<Vec<_>>());
        s.commit(next);
        assert!(
            !s.path.exists() && !s.pos.exists(),
            "all sent: files removed"
        );
        // The cap: what doesn't fit is refused, and sent events make room.
        let big = "x".repeat(300 * 1024);
        assert!(s.push(&[big.clone(), big.clone(), big.clone()]));
        assert!(!s.push(std::slice::from_ref(&big)), "over 1 MiB");
        let (_, next) = s.take(2);
        s.commit(next);
        assert!(s.push(std::slice::from_ref(&big)), "room after compaction");
        assert_eq!(s.take(10).0.len(), 2);
    }

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
