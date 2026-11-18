//! REQ: OPS-011 (ADR-156) — the support package: what each part of the node contributes, and the
//! limits that keep it from ever getting in DNS's way.
//!
//! Each part is a *collector*: it reads the running state through the readers the API already
//! uses (typed views, never the user, token, session, or key stores), on a thread of its own with
//! a five-second deadline. One that is slow or fails shows as `missing` in the manifest instead of
//! failing the package; the whole run is capped at 30 seconds. It all runs on a blocking worker,
//! never on the query path. The pure work (redaction, pseudonyms, classification, the archive)
//! is `telltale-support`'s.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use telltale_api::model::{Hour, QueryParams, Step, SupportPackageRequest, TopKind};
use telltale_api::problem::{Code, Problem};
use telltale_api::{Backend as _, SupportPackageOutput};
use telltale_support::Level;
use telltale_support::classify::known_from_config;
use telltale_support::package::{Options, Package};
use telltale_support::pseudo::Category;
use telltale_support::redact::Known;

use crate::api_backend::ApiBackend;
use crate::support_log;

/// How long one collector may take.
const DEADLINE: Duration = Duration::from_secs(5);
/// How long the whole package may take; collectors after it are skipped.
const TOTAL: Duration = Duration::from_secs(30);
/// The most file content in one package (the largest files are cut first).
pub(crate) const MAX_BYTES: usize = 20 * 1024 * 1024;
/// How long the pseudonym map waits for its one download.
const MAP_TTL: Duration = Duration::from_secs(600);

/// One package at a time on a node: they read a lot at once.
static BUSY: AtomicBool = AtomicBool::new(false);

struct BusyGuard;

impl BusyGuard {
    fn take() -> Option<Self> {
        (!BUSY.swap(true, Ordering::AcqRel)).then_some(Self)
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::Release);
    }
}

/// The pseudonym map of the package just made: in memory only, one at a time, once.
struct Held {
    id: String,
    text: String,
    made: Instant,
}

static MAP: Mutex<Option<Held>> = Mutex::new(None);

fn held() -> std::sync::MutexGuard<'static, Option<Held>> {
    MAP.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The map of package `id`, if it is still held; it is gone after this.
pub(crate) fn take_map(id: &str) -> Option<String> {
    take_map_at(id, Instant::now())
}

/// [`take_map`] at time `now` (tests move the clock instead of waiting ten minutes).
fn take_map_at(id: &str, now: Instant) -> Option<String> {
    let mut g = held();
    let current = g.take()?;
    if now.saturating_duration_since(current.made) >= MAP_TTL {
        return None;
    }
    if current.id == id {
        return Some(current.text);
    }
    // Someone else's ID: leave the map for the right one.
    *g = Some(current);
    None
}

fn to_level(s: Option<&str>) -> Level {
    s.and_then(Level::parse).unwrap_or_default()
}

/// Runs `f` on a thread of its own and waits at most the collector deadline (and what is left of
/// the whole run). The thread isn't stopped if it overruns; it is only left behind.
fn gather(
    me: &Arc<ApiBackend>,
    started: Instant,
    f: impl FnOnce(&ApiBackend) -> Value + Send + 'static,
) -> Result<Value, String> {
    gather_for(DEADLINE, me, started, f)
}

/// [`gather`] with the collector's own deadline.
fn gather_for(
    deadline: Duration,
    me: &Arc<ApiBackend>,
    started: Instant,
    f: impl FnOnce(&ApiBackend) -> Value + Send + 'static,
) -> Result<Value, String> {
    let left = TOTAL.saturating_sub(started.elapsed());
    if left.is_zero() {
        return Err("skipped: the package was taking too long".to_owned());
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let b = Arc::clone(me);
    std::thread::Builder::new()
        .name("support-collect".into())
        .spawn(move || {
            let _ = tx.send(f(&b));
        })
        .map_err(|e| format!("couldn't start: {e}"))?;
    match rx.recv_timeout(deadline.min(left)) {
        Ok(v) => Ok(v),
        Err(RecvTimeoutError::Timeout) => Err(format!(
            "timed out after {} s",
            deadline.min(left).as_secs()
        )),
        Err(RecvTimeoutError::Disconnected) => Err("the collector failed".to_owned()),
    }
}

fn val<T: serde::Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

/// Values of the given keys anywhere in `v`, as names of `cat` for the redactor's first pass.
fn names_in(v: &Value, keys: &[&str], cat: Category, known: &mut Known) {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                match child {
                    Value::String(s) if keys.contains(&k.as_str()) => known.add(cat, s),
                    _ => names_in(child, keys, cat, known),
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| names_in(x, keys, cat, known)),
        _ => {}
    }
}

/// A compact UTC time for a file name: `20261116T045632Z`.
pub(crate) fn stamp(us: u64) -> String {
    let t = telltale_api::time::format_us(us);
    let head = t.split('.').next().unwrap_or(&t);
    head.chars()
        .filter(|c| !matches!(c, '-' | ':'))
        .collect::<String>()
        + "Z"
}

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Only WARN and ERROR lines (`2026-11-16T05:14:08.745Z  WARN message`).
fn warnings_only(line: &str) -> bool {
    matches!(line.split_whitespace().nth(1), Some("WARN" | "ERROR"))
}

/// What the collectors gave: a value, or why they didn't.
type Part = Result<Value, String>;

struct Collected {
    info: Part,
    cluster: Part,
    health: Part,
    probes: Part,
    upstreams: Part,
    lists: Part,
    clients: Part,
    groups: Part,
    workloads: Part,
    metrics: Part,
    stats: Part,
    top: Option<Part>,
    sample: Option<Part>,
}

/// Runs every collector (each on a thread of its own, with a deadline). `detailed`: `standard` and
/// `none` also take the top lists, and the query-log sample if one was asked for.
fn collect(
    me: &Arc<ApiBackend>,
    started: Instant,
    detailed: bool,
    sample_rows: u32,
    now: u64,
) -> Collected {
    Collected {
        info: gather(me, started, |b| val(&b.system_info())),
        cluster: gather(me, started, |b| val(&b.cluster())),
        health: gather(me, started, |b| val(&b.health())),
        probes: gather(me, started, |b| val(&b.probes())),
        upstreams: gather(me, started, |b| val(&b.upstreams())),
        lists: gather(me, started, |b| val(&b.lists())),
        clients: gather(me, started, |b| val(&b.clients())),
        groups: gather(me, started, |b| val(&b.groups())),
        workloads: gather(me, started, |b| {
            b.kubernetes_workloads().map_or(Value::Null, |w| val(&w))
        }),
        metrics: gather(me, started, |b| Value::String(crate::http::render(&b.src))),
        stats: gather(me, started, move |b| {
            let hours = b.timeseries(Step::Hour, now.saturating_sub(24 * 3600), now);
            json!({ "last24hByHour": val(&hours), "cache": val(&b.cache_stats()) })
        }),
        top: detailed.then(|| {
            gather(me, started, |b| {
                let mut out = serde_json::Map::new();
                for (name, kind) in [
                    ("domains", TopKind::Domains),
                    ("blocked", TopKind::Blocked),
                    ("nxdomain", TopKind::Nxdomain),
                    ("clients", TopKind::Clients),
                ] {
                    out.insert(name.to_owned(), val(&b.top(kind, Hour::Current, 20, None)));
                }
                Value::Object(out)
            })
        }),
        sample: (detailed && sample_rows > 0).then(|| {
            let n = usize::try_from(sample_rows).unwrap_or(0);
            gather(me, started, move |b| {
                let to_us = now.saturating_mul(1_000_000);
                b.queries(&QueryParams::default(), 0, to_us, n)
                    .map_or(Value::Null, |p| val(&p))
            })
        }),
    }
}

/// The names the redactor replaces everywhere: the configuration's, and live state's (devices the
/// router or mDNS named, groups, nodes, workloads).
fn known_names(cfg_json: &Value, c: &Collected) -> Known {
    let mut known = known_from_config(cfg_json);
    let got = |r: &Part| r.as_ref().ok().cloned().unwrap_or(Value::Null);
    names_in(&got(&c.clients), &["name"], Category::Device, &mut known);
    names_in(&got(&c.groups), &["name"], Category::Group, &mut known);
    names_in(&got(&c.cluster), &["site"], Category::Node, &mut known);
    names_in(&got(&c.info), &["node"], Category::Node, &mut known);
    names_in(
        &got(&c.workloads),
        &["name", "workloadName"],
        Category::Pod,
        &mut known,
    );
    names_in(
        &got(&c.workloads),
        &["namespace"],
        Category::Namespace,
        &mut known,
    );
    known
}

/// The package's files, each through the redactor.
fn add_files(pkg: &mut Package, cfg_json: &Value, c: Collected, detailed: bool) {
    pkg.add_json(
        "node/host.json",
        "node",
        &json!({
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "cpus": std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get),
        }),
    );
    file(pkg, "node/info.json", "node", c.info);
    pkg.add_config("config/effective.json", "config", cfg_json);
    file(pkg, "cluster/view.json", "cluster", c.cluster);
    file(pkg, "health/health.json", "health", c.health);
    file(pkg, "health/probes.json", "health", c.probes);
    file(pkg, "network/upstreams.json", "network", c.upstreams);
    file(pkg, "lists/lists.json", "lists", c.lists);
    file(pkg, "metrics/metrics.txt", "metrics", c.metrics);
    file(pkg, "stats/summary.json", "stats", c.stats);
    if let Some(r) = c.top {
        file(pkg, "stats/top.json", "stats", r);
    }
    if let Some(r) = c.sample {
        file(pkg, "queries/sample.json", "queries", r);
    }
    add_logs(pkg, detailed);
}

/// REQ: OPS-012 (ADR-163) — the newest watchdog dump, if the node wrote one. At `strict` its
/// log lines are left out: the package's own log is warnings and errors only there.
fn add_watchdog(pkg: &mut Package, data_dir: &std::path::Path, detailed: bool) {
    let dir = data_dir.join("watchdog");
    let mut names = crate::watchdog::dump_names(&dir);
    names.sort();
    let Some(newest) = names.pop() else {
        return;
    };
    let Ok(text) = std::fs::read_to_string(dir.join(newest)) else {
        return;
    };
    let text = match text.find("\n== log") {
        Some(at) if !detailed => format!("{}\n== log: left out at the strict level\n", &text[..at]),
        _ => text,
    };
    pkg.add_text("watchdog/latest-dump.txt", "watchdog", &text, true);
}

/// What decides a package's names, key, and size: this node's own package (numbered names, a key
/// of its own), or its part of a cluster package (keyed labels, the asking node's key, and the
/// share of the size cap that node gave it).
struct Basis {
    key: [u8; 32],
    keyed: bool,
    max_bytes: usize,
}

/// This node's data, collected and put through the redactor, not yet finished.
struct Made {
    pkg: Package,
    node_name: String,
    now_us: u64,
}

fn busy() -> Problem {
    Problem::new(
        Code::Conflict,
        "a support package is already being made on this node",
    )
    .hint("Wait for it to finish (a few seconds), then ask again.")
}

/// Collects this node's state and redacts it into a package.
fn make(
    b: &ApiBackend,
    level: Level,
    query_sample: u32,
    reveal: &[String],
    basis: &Basis,
) -> Result<Made, Problem> {
    let started = Instant::now();
    let detailed = level != Level::Strict;
    let me = Arc::new(ApiBackend {
        src: Arc::clone(&b.src),
    });
    let cfg = b.src.config.load_full();
    let cfg_json = serde_json::to_value(&*cfg)
        .map_err(|e| Problem::internal(format!("the configuration doesn't serialize: {e}")))?;
    let now = b.now_unix_seconds();
    let now_us = now.saturating_mul(1_000_000);

    // Collected first, so the redactor knows every name before it writes a line.
    let collected = collect(&me, started, detailed, query_sample, now);
    let known = known_names(&cfg_json, &collected);
    let opts = Options {
        level,
        key: basis.key,
        reveal: reveal.to_vec(),
        created_unix: now,
        created: telltale_api::time::format_us(now_us),
        max_bytes: basis.max_bytes,
        keyed_labels: basis.keyed,
    };
    let mut pkg = Package::new(opts, &known)
        .map_err(|e| Problem::internal(format!("the package couldn't start: {e}")))?;
    add_files(&mut pkg, &cfg_json, collected, detailed);
    add_watchdog(
        &mut pkg,
        std::path::Path::new(cfg.node.data_dir.as_str()),
        detailed,
    );
    Ok(Made {
        pkg,
        node_name: cfg.node.name.as_str().to_owned(),
        now_us,
    })
}

/// The node's label in a file name or a cluster package: a pseudonym, unless the package shows
/// real values.
fn node_label(pkg: &mut Package, level: Level, node_name: &str) -> String {
    let who = if level == Level::Off {
        node_name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>()
    } else {
        pkg.redactor().name(Category::Node, node_name)
    };
    if who.is_empty() {
        "node".to_owned()
    } else {
        who
    }
}

/// The most a part may weigh once compressed: the cluster channel carries about a mebibyte per answer.
const WIRE_LIMIT: usize = 1_000_000;

/// 64 hex digits as 32 bytes.
fn unhex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// REQ: OPS-011 (ADR-172) — this node's part of a cluster package: made and redacted here under the
/// asking node's key, with labels that don't depend on the order names are met in, cut to fit one
/// cluster answer. Nothing real leaves the node.
pub(crate) fn part(
    b: &ApiBackend,
    req: &telltale_api::model::SupportCollectRequest,
) -> Result<Vec<u8>, Problem> {
    let Some(_busy) = BusyGuard::take() else {
        return Err(busy());
    };
    // The asking node is a cluster member we trust to ask, but its request is checked as an API one is.
    telltale_api::support_api::validate(&SupportPackageRequest {
        level: req.level.clone(),
        reveal: req.reveal.clone(),
        query_sample: req.query_sample,
        keep_map: false,
        cluster: false,
    })?;
    let key = unhex32(&req.key).ok_or_else(|| {
        Problem::invalid("`key`: 64 hex digits").hint("It is made by the node that asks.")
    })?;
    let level = to_level(req.level.as_deref());
    let basis = Basis {
        key,
        keyed: true,
        max_bytes: req.max_bytes.clamp(64 * 1024, MAX_BYTES),
    };
    let Made {
        mut pkg, node_name, ..
    } = make(b, level, req.query_sample, &req.reveal, &basis)?;
    let who = node_label(&mut pkg, level, &node_name);
    let (_, wire) = pkg.finish_part_for_wire(&who, WIRE_LIMIT);
    tracing::info!(level = %level, bytes = wire.len(), "a part of a cluster support package was made for another node");
    Ok(wire)
}

/// The package: collect, redact, archive. A `dry_run` stops at the manifest.
pub(crate) fn build(
    b: &ApiBackend,
    req: &SupportPackageRequest,
    dry_run: bool,
) -> Result<SupportPackageOutput, Problem> {
    let Some(_busy) = BusyGuard::take() else {
        return Err(busy());
    };
    let level = to_level(req.level.as_deref());
    let basis = Basis {
        key: rand::random::<[u8; 32]>(),
        keyed: false,
        max_bytes: MAX_BYTES,
    };
    let Made {
        mut pkg,
        node_name,
        now_us,
    } = make(b, level, req.query_sample, &req.reveal, &basis)?;

    // Its name: the node's, as a pseudonym unless the package shows real values.
    let who = node_label(&mut pkg, level, &node_name);
    let file_name = format!("telltale-support-{who}-{}.tar.gz", stamp(now_us));
    let done = pkg.finish();
    let manifest = serde_json::to_value(&done.manifest).unwrap_or(Value::Null);
    if dry_run {
        return Ok(SupportPackageOutput {
            file_name,
            id: None,
            manifest,
            archive: Vec::new(),
        });
    }
    let id = (req.keep_map && !done.map.is_empty()).then(|| hex(&rand::random::<[u8; 16]>()));
    if let Some(id) = &id {
        *held() = Some(Held {
            id: id.clone(),
            text: done.map,
            made: Instant::now(),
        });
    }
    tracing::info!(level = %level, bytes = done.archive.len(), "a support package was made");
    Ok(SupportPackageOutput {
        file_name,
        id,
        manifest,
        archive: done.archive,
    })
}

/// Adds what a collector gave as a file (through the redactor), or says why it gave nothing.
fn file(pkg: &mut Package, path: &str, collector: &str, r: Result<Value, String>) {
    match r {
        Ok(Value::Null) => pkg.add_missing(path, collector, "not available on this node"),
        Ok(Value::String(s)) => pkg.add_text(path, collector, &s, false),
        Ok(v) => pkg.add_text(
            path,
            collector,
            &serde_json::to_string_pretty(&v).unwrap_or_default(),
            false,
        ),
        Err(why) => pkg.add_missing(path, collector, &why),
    }
}

/// Log lines as the package's `logs/node.log`: WARN and ERROR at `strict`, INFO and above otherwise.
fn add_log_lines(pkg: &mut Package, lines: &[String], detailed: bool) {
    let mut text = String::new();
    for l in lines.iter().filter(|l| detailed || warnings_only(l)) {
        text.push_str(l);
        text.push('\n');
    }
    pkg.add_text("logs/node.log", "log", &text, true);
}

/// The node's own log (ADR-156), from this process's ring.
fn add_logs(pkg: &mut Package, detailed: bool) {
    let snap = support_log::global().snapshot();
    add_log_lines(pkg, &snap.lines, detailed);
    let files = match &snap.files {
        support_log::Files::On => "on".to_owned(),
        support_log::Files::Off => "off (only the last lines in memory)".to_owned(),
        support_log::Files::Failed(why) => format!("failed ({why}); only the last lines in memory"),
    };
    pkg.note(&format!(
        "Log: INFO and above from this process, kept in memory (the last 2,000 lines) and, when on, in files under the data directory. Files: {files}. Lines dropped under load: {}.",
        snap.dropped
    ));
}

/// A package made without the node running: the configuration files and the log files under the
/// data directory. Nothing live is in it (no cluster, health, upstreams, metrics, or statistics),
/// and the manifest says so.
pub(crate) fn offline(
    cfg: &telltale_config::Config,
    req: &SupportPackageRequest,
) -> Result<(SupportPackageOutput, String), Problem> {
    let level = to_level(req.level.as_deref());
    let detailed = level != Level::Strict;
    let cfg_json = serde_json::to_value(cfg)
        .map_err(|e| Problem::internal(format!("the configuration doesn't serialize: {e}")))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let now_us = now.saturating_mul(1_000_000);
    let opts = Options {
        level,
        key: rand::random::<[u8; 32]>(),
        reveal: req.reveal.clone(),
        created_unix: now,
        created: telltale_api::time::format_us(now_us),
        max_bytes: MAX_BYTES,
        keyed_labels: false,
    };
    let mut pkg = Package::new(opts, &known_from_config(&cfg_json))
        .map_err(|e| Problem::internal(format!("the package couldn't start: {e}")))?;
    pkg.add_json(
        "node/host.json",
        "node",
        &json!({
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "cpus": std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get),
            "version": crate::build_info::VERSION,
            "commit": crate::build_info::COMMIT,
        }),
    );
    pkg.add_config("config/effective.json", "config", &cfg_json);
    for (path, part) in [
        ("node/info.json", "node"),
        ("cluster/view.json", "cluster"),
        ("health/health.json", "health"),
        ("network/upstreams.json", "network"),
        ("lists/lists.json", "lists"),
        ("metrics/metrics.txt", "metrics"),
        ("stats/summary.json", "stats"),
    ] {
        pkg.add_missing(path, part, "offline: the node's live state isn't read");
    }
    let dir = std::path::Path::new(cfg.node.data_dir.as_str()).join("logs");
    let mut lines: Vec<String> = Vec::new();
    for name in ["telltale.log.1", "telltale.log"] {
        if let Ok(text) = std::fs::read_to_string(dir.join(name)) {
            lines.extend(text.lines().map(str::to_owned));
        }
    }
    if lines.is_empty() {
        pkg.add_missing(
            "logs/node.log",
            "log",
            "no log files under the data directory (the node keeps them there while it runs, unless `[support] persist_logs` is off)",
        );
    } else {
        add_log_lines(&mut pkg, &lines, detailed);
    }
    add_watchdog(
        &mut pkg,
        std::path::Path::new(cfg.node.data_dir.as_str()),
        detailed,
    );
    pkg.note("Offline package: made from the configuration files and the log files, without asking a running node. It has no live state.");
    let node_name = cfg.node.name.as_str();
    let who = if level == Level::Off {
        node_name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>()
    } else {
        pkg.redactor().name(Category::Node, node_name)
    };
    let who = if who.is_empty() {
        "node".to_owned()
    } else {
        who
    };
    let file_name = format!("telltale-support-{who}-{}.tar.gz", stamp(now_us));
    let done = pkg.finish();
    let manifest = serde_json::to_value(&done.manifest).unwrap_or(Value::Null);
    // Offline there is no server to hold the map: the CLI writes it out.
    let map = if req.keep_map {
        done.map
    } else {
        String::new()
    };
    Ok((
        SupportPackageOutput {
            file_name,
            id: None,
            manifest,
            archive: done.archive,
        },
        map,
    ))
}

#[cfg(test)]
#[path = "support_tests.rs"]
mod tests;
