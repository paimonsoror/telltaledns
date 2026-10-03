//! Wiring for the list fetcher and compiler (`spec/05` §3.4): startup, reload, and the
//! `telltale lists` commands.
//!
//! REQ: FLT-003, FLT-004. Both run only where lists are compiled: role `all` or `controller`.
//! Failures here are logged and never affect DNS (AGENTS.md rule 5).

use std::future::Future;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use telltale_config::{Config, Role};
use telltale_filter::compile::{CompileOptions, CompileReport, ListData, ListInput, compile};
use telltale_filter::fetch::{
    Client, FetchSettings, Fetcher, ListSpec, Outcome, Resolve, Store, SystemResolver,
};
use telltale_filter::matcher::{Lookup, Matcher, Overlay};
use telltale_filter::parse::{ListOptions, parse_list};
use telltale_filter::snapshot::{MANIFEST, Manifest, Snapshot};
use telltale_upstream::Bootstrap;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::pipeline::{FilterState, Pipeline};

/// Resolves list hostnames like hostname upstreams do (UPS-009): through the system resolvers
/// minus our own listeners. When the system resolver *is* this server (a Pi pointing
/// `/etc/resolv.conf` at itself), fall back to the OS resolver, which then asks our own
/// listeners. That's safe: a list download is an HTTP client, not a forwarder, so it can't
/// loop, and the listeners are bound before the fetcher starts.
struct ListResolver {
    bootstrap: Option<Bootstrap>,
}

impl ListResolver {
    fn new(listen: &[SocketAddr]) -> Self {
        let b = Bootstrap::system(listen);
        Self {
            bootstrap: (!b.servers().is_empty()).then_some(b),
        }
    }
}

impl Resolve for ListResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, String>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(b) = &self.bootstrap
                && let Ok(ips) = b.resolve(host).await
            {
                return Ok(ips);
            }
            SystemResolver.resolve(host).await
        })
    }
}

fn build_fetcher(cfg: &Config) -> Result<Arc<Fetcher>, String> {
    let data_dir = Path::new(cfg.node.data_dir.as_str());
    let store = Store::open(data_dir).map_err(|e| format!("{}/lists: {e}", data_dir.display()))?;
    let listen: Vec<SocketAddr> = cfg.listen.iter().map(|l| l.addr).collect();
    let client = Client::new(Arc::new(ListResolver::new(&listen)), &[])?;
    Ok(Arc::new(Fetcher::new(
        store,
        client,
        FetchSettings::from_config(cfg),
    )))
}

/// What `/metrics` reads: fetch state and the last compile.
#[derive(Debug)]
pub(crate) struct ListsShared {
    pub(crate) fetcher: Arc<Fetcher>,
    pub(crate) compiled: Mutex<Option<Compiled>>,
}

/// The newest snapshot on disk.
#[derive(Debug, Clone)]
pub(crate) struct Compiled {
    pub(crate) manifest: Manifest,
    /// Wall time of the compile that produced it (0 if it was already on disk).
    pub(crate) seconds: f64,
}

/// What to compile: enabled lists in config order (a list's position is its ID).
#[derive(Debug, Clone, PartialEq, Eq)]
struct CompileSpec {
    name: String,
    options: ListOptions,
}

fn compile_specs(cfg: &Config) -> Vec<CompileSpec> {
    cfg.list
        .iter()
        .filter(|l| l.enabled)
        .map(|l| CompileSpec {
            name: l.name.to_string(),
            options: ListOptions {
                kind: l.kind,
                match_mode: l.match_mode,
            },
        })
        .collect()
}

/// The running fetcher and compiler.
pub(crate) struct Lists {
    pub(crate) shared: Arc<ListsShared>,
    specs: watch::Sender<Arc<Vec<ListSpec>>>,
    compile_specs: watch::Sender<Arc<Vec<CompileSpec>>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Lists {
    /// Starts the background fetcher and compiler if this node compiles lists and any are
    /// configured. Compiled snapshots are published to `pipeline`'s filter.
    pub(crate) fn start(cfg: &Config, pipeline: &Arc<Pipeline>) -> Option<Self> {
        if cfg.node.role == Role::Resolver || cfg.list.is_empty() {
            return None;
        }
        let fetcher = match build_fetcher(cfg) {
            Ok(f) => f,
            Err(e) => {
                error!("lists: {e}; lists won't be downloaded (DNS is unaffected)");
                return None;
            }
        };
        let specs = ListSpec::from_config(cfg);
        info!(
            lists = specs.len(),
            dir = %fetcher.store().dir().display(),
            "list fetcher started"
        );
        let (specs_tx, specs_rx) = watch::channel(Arc::new(specs));
        let (changed_tx, changed) = watch::channel(0);
        let (compile_tx, compile_rx) = watch::channel(Arc::new(compile_specs(cfg)));
        let shared = Arc::new(ListsShared {
            fetcher: Arc::clone(&fetcher),
            compiled: Mutex::new(None),
        });
        let settings = CompileSettings::from_config(cfg);
        let tasks = vec![
            tokio::spawn(Arc::clone(&fetcher).run(specs_rx, changed_tx)),
            tokio::spawn(compile_loop(
                Arc::clone(&shared),
                settings,
                compile_rx,
                changed,
                Publisher {
                    pipeline: Arc::clone(pipeline),
                    generation: Arc::new(AtomicU64::new(0)),
                },
            )),
        ];
        Some(Self {
            shared,
            specs: specs_tx,
            compile_specs: compile_tx,
            tasks,
        })
    }

    /// Applies a reloaded config: new, removed, or edited lists take effect at once.
    /// Fetch settings (`[filter]`) and `data_dir` need a restart.
    pub(crate) fn reload(&self, cfg: &Config) {
        let specs = ListSpec::from_config(cfg);
        self.specs.send_if_modified(|cur| {
            if **cur == specs {
                false
            } else {
                *cur = Arc::new(specs);
                true
            }
        });
        let compile = compile_specs(cfg);
        self.compile_specs.send_if_modified(|cur| {
            if **cur == compile {
                false
            } else {
                *cur = Arc::new(compile);
                true
            }
        });
    }

    pub(crate) fn stop(self) {
        for t in self.tasks {
            t.abort();
        }
    }
}

/// Where and how snapshots are compiled.
#[derive(Debug, Clone)]
struct CompileSettings {
    snapshots: PathBuf,
    threads: usize,
    memory: usize,
}

/// Snapshots kept on disk (`spec/02` §6).
const KEEP_SNAPSHOTS: usize = 3;
/// Changes arriving together (several lists updated in one refresh) compile once.
const DEBOUNCE: Duration = Duration::from_secs(2);

impl CompileSettings {
    fn from_config(cfg: &Config) -> Self {
        Self {
            snapshots: Path::new(cfg.node.data_dir.as_str()).join("snapshots"),
            threads: compile_threads(cfg.filter.compile_threads),
            memory: usize::try_from(cfg.filter.compile_memory.bytes()).unwrap_or(usize::MAX),
        }
    }
}

/// `0` = auto: half the available cores (cgroup-aware), between 1 and 4. Measured on a Pi 4:
/// 2M names compile in 11.6 s on one thread, 6.4 s on two, 4.7 s on three (ADR-018).
fn compile_threads(configured: u8) -> usize {
    if configured > 0 {
        return usize::from(configured);
    }
    (telltale_net::default_workers() / 2).clamp(1, 4)
}

/// Snapshot versions on disk with a manifest, ascending.
fn snapshot_versions(dir: &Path) -> Vec<(u64, PathBuf)> {
    let mut out: Vec<(u64, PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|e| {
            let v = e.file_name().to_str()?.parse::<u64>().ok()?;
            e.path().join(MANIFEST).is_file().then(|| (v, e.path()))
        })
        .collect();
    out.sort_by_key(|(v, _)| *v);
    out
}

fn read_manifest(dir: &Path) -> Option<Manifest> {
    serde_json::from_slice(&std::fs::read(dir.join(MANIFEST)).ok()?).ok()
}

/// Lists that have a stored source, with their content hashes, in ID order.
fn gather(store: &Store, specs: &[CompileSpec]) -> Vec<(CompileSpec, String, u64)> {
    specs
        .iter()
        .filter_map(|s| {
            let meta = store.load_meta(&s.name);
            Some((s.clone(), meta.content_hash?, meta.bytes))
        })
        .collect()
}

/// True if `manifest` was compiled from exactly these lists, options, and sources.
fn up_to_date(manifest: &Manifest, inputs: &[(CompileSpec, String, u64)]) -> bool {
    manifest.lists.len() == inputs.len()
        && manifest.lists.iter().zip(inputs).all(|(m, (s, hash, _))| {
            m.name == s.name
                && m.source_hash == *hash
                && m.kind == s.options.kind
                && m.match_mode == s.options.match_mode
        })
}

/// Compiles a new snapshot if the inputs changed. Blocking: call from a blocking thread.
fn compile_if_changed(
    store: &Store,
    settings: &CompileSettings,
    specs: &[CompileSpec],
    force: bool,
) -> Result<Option<(CompileReport, PathBuf)>, String> {
    let inputs = gather(store, specs);
    // Nothing downloaded yet (first start): wait for the fetcher rather than publish an
    // empty snapshot.
    if inputs.is_empty() && !specs.is_empty() {
        return Ok(None);
    }
    let versions = snapshot_versions(&settings.snapshots);
    if !force
        && let Some((_, dir)) = versions.last()
        && read_manifest(dir).is_some_and(|m| up_to_date(&m, &inputs))
    {
        return Ok(None);
    }
    std::fs::create_dir_all(&settings.snapshots)
        .map_err(|e| format!("{}: {e}", settings.snapshots.display()))?;
    let version = versions.last().map_or(1, |(v, _)| v + 1);
    let out = settings.snapshots.join(version.to_string());
    let lists: Vec<ListInput> = inputs
        .into_iter()
        .map(|(s, hash, size)| ListInput {
            name: s.name,
            options: s.options,
            data: ListData::Stored(store.clone()),
            source_hash: hash,
            size,
        })
        .collect();
    let report = compile(
        lists,
        &out,
        &CompileOptions {
            threads: settings.threads,
            memory_budget: settings.memory,
            version,
        },
    )
    .map_err(|e| e.to_string())?;
    // Keep the newest few; older ones are only useful for rollback.
    let versions = snapshot_versions(&settings.snapshots);
    for (_, dir) in versions.iter().rev().skip(KEEP_SNAPSHOTS) {
        if let Err(e) = std::fs::remove_dir_all(dir) {
            warn!("cannot remove old snapshot {}: {e}", dir.display());
        }
    }
    Ok(Some((report, out)))
}

/// Loads compiled snapshots into the pipeline's filter (FLT-004 atomic swap). A snapshot is
/// served with the FST walk as soon as it's loaded, then again with the hash index once that
/// is built (ADR-020), so neither a cold start nor a recompile waits for the index.
#[derive(Clone)]
struct Publisher {
    pipeline: Arc<Pipeline>,
    /// Bumped per publish; a slow index build for an older snapshot is discarded.
    generation: Arc<AtomicU64>,
}

impl Publisher {
    fn publish(&self, dir: PathBuf) {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let this = self.clone();
        let spawned = std::thread::Builder::new()
            .name("telltale-load".into())
            .spawn(move || this.load(&dir, generation));
        if let Err(e) = spawned {
            error!("cannot start the snapshot loader: {e}");
        }
    }

    fn load(&self, dir: &Path, generation: u64) {
        let t = std::time::Instant::now();
        let snap = match Snapshot::open(dir) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!(dir = %dir.display(), "cannot load filter snapshot; keeping the current filter: {e}");
                return;
            }
        };
        let version = snap.manifest.version;
        let store = |m: Matcher| {
            if self.generation.load(Ordering::SeqCst) == generation {
                self.pipeline
                    .filter
                    .store(Some(Arc::new(FilterState::new(Arc::new(m)))));
                true
            } else {
                false
            }
        };
        let walk =
            match Matcher::with_lookup(Some(Arc::clone(&snap)), Overlay::default(), Lookup::Walk) {
                Ok(m) => m,
                Err(e) => {
                    error!(
                        version,
                        "cannot activate filter snapshot; keeping the current filter: {e}"
                    );
                    return;
                }
            };
        if !store(walk) {
            return; // a newer snapshot was published meanwhile
        }
        info!(
            version,
            seconds = t.elapsed().as_secs_f64(),
            "filter active (building lookup index)"
        );
        // The index build is background work like compiling: never at the cost of queries.
        let _ = telltale_net::lower_thread_priority(10);
        let t = std::time::Instant::now();
        if let Ok(m) = Matcher::with_lookup(Some(snap), Overlay::default(), Lookup::Indexed) {
            #[allow(clippy::cast_precision_loss)] // MiB for a log line
            let mib = m.index_bytes() as f64 / f64::from(1u32 << 20);
            let lookup = m.lookup();
            if store(m) {
                info!(
                    version,
                    ?lookup,
                    index_mib = format!("{mib:.1}"),
                    seconds = t.elapsed().as_secs_f64(),
                    "filter lookup index ready"
                );
            }
        }
    }
}

/// Recompiles whenever stored list content or the list configuration changes, and publishes
/// every new snapshot to the pipeline.
async fn compile_loop(
    shared: Arc<ListsShared>,
    settings: CompileSettings,
    mut specs: watch::Receiver<Arc<Vec<CompileSpec>>>,
    mut changed: watch::Receiver<u64>,
    publisher: Publisher,
) {
    let store = shared.fetcher.store().clone();
    // Serve the newest snapshot on disk right away (cold start, CLU-004), before any compile.
    if let Some((_, dir)) = snapshot_versions(&settings.snapshots).last()
        && let Some(manifest) = read_manifest(dir)
    {
        publisher.publish(dir.clone());
        *shared
            .compiled
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Compiled {
            manifest,
            seconds: 0.0,
        });
    }
    loop {
        let current = Arc::clone(&specs.borrow_and_update());
        changed.borrow_and_update();
        let (store2, settings2) = (store.clone(), settings.clone());
        // A dedicated thread, not tokio's blocking pool: compiling lowers its thread's
        // priority, and pool threads are reused for other work.
        let (tx, rx) = tokio::sync::oneshot::channel();
        let spawned = std::thread::Builder::new()
            .name("telltale-compile".into())
            .spawn(move || {
                let _ = tx.send(compile_if_changed(&store2, &settings2, &current, false));
            });
        let result = match spawned {
            Ok(_) => rx
                .await
                .map_err(|_| "compile thread exited without a result".to_owned()),
            Err(e) => Err(format!("cannot start compile thread: {e}")),
        };
        match result {
            Ok(Ok(Some((report, dir)))) => {
                publisher.publish(dir.clone());
                let st = &report.manifest.stats;
                info!(
                    version = report.manifest.version,
                    lists = report.manifest.lists.len(),
                    names = st.subtree_names + st.exact_names + st.subdomains_names,
                    regexes = st.regexes,
                    modifier_rules = st.modrules,
                    bytes_per_name = st.bytes_per_name,
                    seconds = report.timings.total.as_secs_f64(),
                    dir = %dir.display(),
                    "filter snapshot compiled"
                );
                for (list, line, why) in &report.regex_errors {
                    warn!(list = %list, line, "regex rejected: {why}");
                }
                *shared
                    .compiled
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = Some(Compiled {
                    seconds: report.timings.total.as_secs_f64(),
                    manifest: report.manifest,
                });
            }
            Ok(Ok(None)) => {}
            // REQ: FLT-004 — a failed compile keeps the previous snapshot.
            Ok(Err(e)) => error!("list compile failed; keeping the previous snapshot: {e}"),
            Err(e) => error!("list compile failed; keeping the previous snapshot: {e}"),
        }
        tokio::select! {
            r = changed.changed() => if r.is_err() { return },
            r = specs.changed() => if r.is_err() { return },
        }
        tokio::time::sleep(DEBOUNCE).await;
    }
}

/// `telltale lists compile`: compile the stored lists into a new snapshot now.
pub(crate) fn compile_now(
    cfg: &Config,
    threads: Option<usize>,
    out: &mut dyn Write,
) -> Result<bool, String> {
    let data_dir = Path::new(cfg.node.data_dir.as_str());
    let store = Store::open(data_dir).map_err(|e| format!("{}/lists: {e}", data_dir.display()))?;
    let mut settings = CompileSettings::from_config(cfg);
    if let Some(t) = threads {
        settings.threads = t.max(1);
    }
    let io = |e: std::io::Error| e.to_string();
    let specs = compile_specs(cfg);
    let missing: Vec<&str> = specs
        .iter()
        .filter(|s| store.load_meta(&s.name).content_hash.is_none())
        .map(|s| s.name.as_str())
        .collect();
    if !missing.is_empty() {
        writeln!(out, "not downloaded yet (skipped): {}", missing.join(", ")).map_err(io)?;
    }
    let Some((report, dir)) = compile_if_changed(&store, &settings, &specs, true)? else {
        return Ok(true);
    };
    let st = &report.manifest.stats;
    let t = &report.timings;
    writeln!(
        out,
        "snapshot {} in {}\n  names {} (subtree {}, exact {}, subdomains {}), regexes {}, modifier rules {}, list sets {}, $badfilter removed {}",
        report.manifest.version,
        dir.display(),
        st.subtree_names + st.exact_names + st.subdomains_names,
        st.subtree_names,
        st.exact_names,
        st.subdomains_names,
        st.regexes,
        st.modrules,
        st.listsets,
        st.badfiltered
    )
    .map_err(io)?;
    writeln!(
        out,
        "  {:.2} bytes/name; {:.2?} total (parse {:.2?}, merge {:.2?}, tables {:.2?}) on {} thread(s); {} sort runs spilled",
        st.bytes_per_name, t.total, t.parse, t.merge, t.tables, settings.threads, report.spilled_runs
    )
    .map_err(io)?;
    for (i, l) in st.per_list.iter().enumerate() {
        writeln!(
            out,
            "  {:<24} entries {:>9}  unique {:>9}  unsupported {:>6}  invalid {:>6}",
            report.manifest.lists[i].name, l.entries, l.unique, l.unsupported, l.invalid
        )
        .map_err(io)?;
    }
    for (list, line, why) in &report.regex_errors {
        writeln!(out, "  regex rejected: {list} line {line}: {why}").map_err(io)?;
    }
    Ok(report.regex_errors.is_empty())
}

/// `telltale lists fetch`: refresh every enabled list once and print the result.
pub(crate) async fn fetch_once(cfg: &Config, out: &mut dyn Write) -> Result<bool, String> {
    let fetcher = build_fetcher(cfg)?;
    let specs = ListSpec::from_config(cfg);
    if specs.is_empty() {
        writeln!(out, "no enabled lists in the configuration").map_err(|e| e.to_string())?;
        return Ok(true);
    }
    let results = fetcher.refresh(&specs).await;
    let status = fetcher.status();
    let mut all_ok = true;
    writeln!(
        out,
        "{:<24} {:<10} {:>12} {:>10}  note",
        "list", "result", "bytes", "lines"
    )
    .map_err(|e| e.to_string())?;
    for (name, outcome) in &results {
        let meta = status
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, m)| m.clone())
            .unwrap_or_default();
        let (result, note) = match outcome {
            Outcome::Updated => ("updated", String::new()),
            Outcome::Unchanged => ("unchanged", String::new()),
            Outcome::Failed(e) => {
                all_ok = false;
                let kept = if meta.has_content() {
                    " (kept previous copy)"
                } else {
                    ""
                };
                ("FAILED", format!("{e}{kept}"))
            }
        };
        writeln!(
            out,
            "{name:<24} {result:<10} {:>12} {:>10}  {note}",
            meta.bytes, meta.lines
        )
        .map_err(|e| e.to_string())?;
    }
    writeln!(out, "stored in {}", fetcher.store().dir().display()).map_err(|e| e.to_string())?;
    Ok(all_ok)
}

/// `telltale lists check`: parse stored sources and report (FLT-001, `spec/05` §6 stats).
pub(crate) fn check(
    cfg: &Config,
    only: &[String],
    print_rules: bool,
    out: &mut dyn Write,
) -> Result<bool, String> {
    let data_dir = Path::new(cfg.node.data_dir.as_str());
    let store = Store::open(data_dir).map_err(|e| format!("{}/lists: {e}", data_dir.display()))?;
    let io = |e: std::io::Error| e.to_string();
    let mut clean = true;
    for list in &cfg.list {
        if !only.is_empty() && !only.iter().any(|n| n == list.name.as_str()) {
            continue;
        }
        let name = list.name.as_str();
        let Ok(data) = store.read_source(name) else {
            writeln!(
                out,
                "{name}: not downloaded yet (run `telltale lists fetch`)"
            )
            .map_err(io)?;
            continue;
        };
        let opts = ListOptions {
            kind: list.kind,
            match_mode: list.match_mode,
        };
        let mut rules = Vec::new();
        let stats = parse_list(&data, opts, |line, rule| {
            if print_rules {
                rules.push(format!("  L{line} {rule}"));
            }
        });
        writeln!(
            out,
            "{name}: {} lines, {} rules, {} comments, {} ignored, {} unsupported, {} invalid",
            stats.lines,
            stats.rules,
            stats.comments,
            stats.ignored,
            stats.unsupported,
            stats.invalid
        )
        .map_err(io)?;
        for r in &rules {
            writeln!(out, "{r}").map_err(io)?;
        }
        for s in &stats.samples {
            let kind = if s.unsupported {
                "unsupported"
            } else {
                "invalid"
            };
            writeln!(out, "  L{} {kind}: {}: {}", s.line, s.reason, s.text).map_err(io)?;
        }
        clean &= stats.invalid == 0;
    }
    Ok(clean)
}
