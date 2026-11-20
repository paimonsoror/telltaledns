//! Background list fetcher (`spec/05` §3.4 step 1).
//!
//! REQ: FLT-004 — concurrent downloads (default 4) with `ETag` / `Last-Modified` conditional GETs,
//! size caps, timeouts, and per-list retries. Sources are stored as `lists/<name>.src.zst`.
//! A list that fails keeps its last good copy; the compiler (T2.3) is told only when content
//! actually changed. Nothing here touches the query path.

mod http;
mod store;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use telltale_config::Config;
use tokio::sync::{Notify, Semaphore, watch};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

pub use self::http::{
    BodyStream, Client, Conditional, HttpError, Resolve, Response, SystemResolver,
};
pub use self::store::{ListMeta, Store, content_hash, count_lines};

/// Where a list's rules come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListSource {
    Url(String),
    Path(PathBuf),
    Inline(Vec<String>),
}

impl ListSource {
    /// Identifies the source in stored metadata; a change invalidates the stored copy's
    /// validators. Inline rules are identified by their hash, so editing them re-stores.
    fn key(&self) -> String {
        match self {
            Self::Url(u) => u.clone(),
            Self::Path(p) => format!("file:{}", p.display()),
            Self::Inline(rules) => {
                format!(
                    "{}{}",
                    store::INLINE_SOURCE_PREFIX,
                    &content_hash(rules.join("\n").as_bytes())[..16]
                )
            }
        }
    }
}

/// One list to keep fresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListSpec {
    pub name: String,
    pub source: ListSource,
    pub refresh: Duration,
    pub max_bytes: u64,
    /// Disabled in the configuration: its stored files are kept (so re-enabling it needs no
    /// download, ADR-016), but it is never refreshed.
    pub enabled: bool,
}

impl ListSpec {
    /// The configured lists, disabled ones included (marked), with `[filter]` defaults
    /// applied.
    pub fn from_config(cfg: &Config) -> Vec<Self> {
        let f = &cfg.filter;
        cfg.list
            .iter()
            .filter_map(|l| {
                let source = if let Some(u) = &l.url {
                    ListSource::Url(u.to_string())
                } else if let Some(p) = &l.path {
                    ListSource::Path(PathBuf::from(p.as_str()))
                } else if !l.rules.is_empty() {
                    ListSource::Inline(l.rules.iter().map(ToString::to_string).collect())
                } else {
                    return None;
                };
                Some(Self {
                    name: l.name.to_string(),
                    source,
                    refresh: Duration::from_secs(u64::from(
                        l.refresh_secs.unwrap_or(f.refresh_secs),
                    )),
                    max_bytes: l.max_bytes.unwrap_or(f.max_list_bytes).bytes(),
                    enabled: l.enabled,
                })
            })
            .collect()
    }
}

/// Download behavior.
#[derive(Debug, Clone)]
pub struct FetchSettings {
    pub concurrency: usize,
    /// Per attempt, including the body.
    pub timeout: Duration,
    /// Extra attempts after a retryable failure.
    pub retries: u8,
    /// First retry delay; each later one is 4× longer (±25% jitter, capped at 60 s).
    pub backoff: Duration,
    /// How long a finished update waits for the rest of a refresh round before the compiler
    /// is told: lists that arrive together compile once, and a slow or dead source delays
    /// the others by at most this much (ADR-061).
    pub settle: Duration,
    /// `[filter] max_invalid_percent`: a body with a larger share of invalid lines is refused.
    pub max_invalid_percent: u8,
    /// `[filter] max_shrink_percent`: a URL list that lost a larger share of its lines is held
    /// until the source serves the same content again (100 = never held).
    pub max_shrink_percent: u8,
}

impl FetchSettings {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            max_invalid_percent: cfg.filter.max_invalid_percent,
            max_shrink_percent: cfg.filter.max_shrink_percent,
            concurrency: usize::from(cfg.filter.fetch_concurrency.max(1)),
            timeout: Duration::from_secs(u64::from(cfg.filter.fetch_timeout_secs)),
            retries: cfg.filter.fetch_retries,
            backoff: Duration::from_secs(2),
            settle: Duration::from_secs(10),
        }
    }
}

/// Result of refreshing one list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// New content stored.
    Updated,
    /// The stored copy is current (304, or identical content).
    Unchanged,
    /// Nothing stored; the previous copy (if any) stays in use.
    Failed(String),
    /// REQ: FLT-004 (ADR-147) — the download lost more of the stored copy's lines than
    /// `max_shrink_percent` allows: not stored yet. The previous copy stays in use until a
    /// later refresh (the next scheduled one, or a manual one) brings the same content.
    Held(String),
}

/// Retry a failing URL or file list after 5 min, doubling up to 1 h (but never later than its
/// normal refresh), instead of waiting a whole refresh interval. (Inline rules that were
/// refused are different: see [`Hold`].)
const FAIL_RETRY_BASE: u64 = 300;
const FAIL_RETRY_MAX: u64 = 3600;

/// The wait after the `failures`-th failure in a row: 5 min, doubling to 1 h, never past the
/// list's normal refresh.
fn retry_after(failures: u32, refresh: u64) -> u64 {
    let shift = failures.saturating_sub(1).min(10);
    (FAIL_RETRY_BASE << shift).min(FAIL_RETRY_MAX).min(refresh)
}

/// REQ: FLT-004 — how long an inline list whose attempt failed waits before `due` offers it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hold {
    /// The rules themselves were refused (blank, mostly invalid): the same rules are refused
    /// again, so nothing but a change brings the list back (an edit, off and on, a restart).
    UntilChange,
    /// Something other than the rules failed (storing the list: a full or read-only disk): on
    /// the retry ladder, at this unix time.
    Until(u64),
}

/// Why `accept_body` didn't store a body.
enum Rejected {
    /// The content was refused (`sanity_check`, `usable_check`): the same body fails again.
    Content(String),
    /// The content was fine but could not be stored: it may work later.
    Storage(String),
}

/// Stored copies smaller than this many lines aren't held for shrinking: a short list's size
/// swings a lot from a few edits.
const SHRINK_MIN_LINES: u64 = 1_000;

impl std::fmt::Debug for Fetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fetcher")
            .field("dir", &self.store.dir())
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

pub struct Fetcher {
    store: Store,
    client: Client,
    settings: FetchSettings,
    metas: Mutex<HashMap<String, ListMeta>>,
    /// REQ: FLT-004 — the inline lists this process tried and failed to load, by list name, each
    /// with the source key of the rules that failed and how long it waits ([`Hold`]). Memory
    /// only: a restart tries again, because `[filter]` settings (what counts as usable) and the
    /// parser can have changed since.
    refused: Mutex<HashMap<String, (String, Hold)>>,
    refresh_now: Notify,
}

impl Fetcher {
    pub fn new(store: Store, client: Client, settings: FetchSettings) -> Self {
        Self {
            store,
            client,
            settings,
            metas: Mutex::new(HashMap::new()),
            refused: Mutex::new(HashMap::new()),
            refresh_now: Notify::new(),
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Current metadata for each list seen so far, sorted by name (metrics, API, CLI).
    pub fn status(&self) -> Vec<(String, ListMeta)> {
        let metas = self.metas.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out: Vec<_> = metas.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Makes `run` refresh every list now, regardless of schedule (`SIGUSR1`; there is no HTTP
    /// endpoint for it).
    pub fn request_refresh(&self) {
        self.refresh_now.notify_one();
    }

    fn meta(&self, name: &str) -> ListMeta {
        let mut metas = self.metas.lock().unwrap_or_else(PoisonError::into_inner);
        metas
            .entry(name.to_owned())
            .or_insert_with(|| self.store.load_meta(name))
            .clone()
    }

    fn put_meta(&self, name: &str, meta: ListMeta) {
        if let Err(e) = self.store.save_meta(name, &meta) {
            warn!(list = name, "cannot save list metadata: {e}");
        }
        self.metas
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name.to_owned(), meta);
    }

    /// REQ: FLT-004 — remembers how long an inline list's rules (identified by `key`) wait after
    /// a failed attempt (`Some`), or forgets the list once it loads (`None`).
    fn note_inline_outcome(&self, spec: &ListSpec, key: &str, hold: Option<Hold>) {
        if !matches!(spec.source, ListSource::Inline(_)) {
            return;
        }
        let mut refused = self.refused.lock().unwrap_or_else(PoisonError::into_inner);
        match hold {
            Some(hold) => {
                refused.insert(spec.name.clone(), (key.to_owned(), hold));
            }
            None => {
                refused.remove(&spec.name);
            }
        }
    }

    /// REQ: FLT-004 — when `spec`, an inline list this process already tried and failed to load,
    /// may be tried again (`u64::MAX`: only after a change); `None` if nothing here holds it.
    /// Rules that were refused give the same answer again, and `run` asks `due` straight after a
    /// round, so offering them as due would make it refresh them in a loop (a synced metadata
    /// write and a warning per pass, dozens a second): they wait for a change (their key, off
    /// and on, a restart). A failure the rules didn't cause (a full or read-only disk) can pass,
    /// so that one waits on the retry ladder instead ([`Hold::Until`]).
    fn hold_until(&self, spec: &ListSpec, meta: &ListMeta) -> Option<u64> {
        if !matches!(spec.source, ListSource::Inline(_)) {
            return None;
        }
        let key = spec.source.key();
        if meta.source != key {
            return None;
        }
        match self
            .refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&spec.name)
        {
            Some((k, Hold::UntilChange)) if *k == key => Some(u64::MAX),
            Some((k, Hold::Until(at))) if *k == key => Some(*at),
            _ => None,
        }
    }

    fn spawn_refreshes(self: &Arc<Self>, specs: &[ListSpec]) -> JoinSet<(String, Outcome)> {
        let sem = Arc::new(Semaphore::new(self.settings.concurrency.max(1)));
        let mut set = JoinSet::new();
        // A disabled list is kept in the specs (its files stay) but never fetched.
        for spec in specs.iter().filter(|s| s.enabled).cloned() {
            let (this, sem) = (Arc::clone(self), Arc::clone(&sem));
            set.spawn(async move {
                let _permit = sem.acquire_owned().await;
                let outcome = this.refresh_one(&spec).await;
                (spec.name, outcome)
            });
        }
        set
    }

    /// Refreshes `specs` concurrently (at most `concurrency` at a time).
    pub async fn refresh(self: &Arc<Self>, specs: &[ListSpec]) -> Vec<(String, Outcome)> {
        let mut set = self.spawn_refreshes(specs);
        let mut out = Vec::with_capacity(specs.len());
        while let Some(res) = set.join_next().await {
            match res {
                Ok(r) => out.push(r),
                Err(e) => warn!("list fetch task failed: {e}"),
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Refreshes `specs` like [`Self::refresh`], bumping `changed` once stored content changed:
    /// at the end of the round, or `settle` after the first update if other lists are still
    /// downloading, so one unreachable source (retrying with backoff) doesn't hold back
    /// blocking from the lists that did arrive.
    async fn refresh_and_signal(
        self: &Arc<Self>,
        specs: &[ListSpec],
        changed: &watch::Sender<u64>,
    ) {
        let mut set = self.spawn_refreshes(specs);
        let mut pending: Option<tokio::time::Instant> = None;
        loop {
            let deadline = pending.map(|t| t + self.settings.settle);
            let settled = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                next = set.join_next() => match next {
                    None => break,
                    Some(Ok((_, Outcome::Updated))) => {
                        pending.get_or_insert_with(tokio::time::Instant::now);
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => warn!("list fetch task failed: {e}"),
                },
                () = settled => {
                    debug!("lists updated; compiling without waiting for the rest of the round");
                    changed.send_modify(|g| *g += 1);
                    pending = None;
                }
            }
        }
        if pending.is_some() {
            changed.send_modify(|g| *g += 1);
        }
    }

    /// Fetches one list and records the result. Never removes a good stored copy.
    pub async fn refresh_one(&self, spec: &ListSpec) -> Outcome {
        let key = spec.source.key();
        let mut meta = self.meta(&spec.name);
        let same_source = meta.source == key && meta.has_content();
        let cond = if same_source {
            Conditional {
                etag: meta.etag.clone(),
                last_modified: meta.last_modified.clone(),
            }
        } else {
            Conditional::default()
        };
        let now = unix_now();
        meta.last_attempt = Some(now);

        let fetched = match &spec.source {
            ListSource::Url(url) => self.download(&spec.name, url, &cond, spec.max_bytes).await,
            ListSource::Path(path) => read_file(path, spec.max_bytes).await,
            ListSource::Inline(rules) => {
                let mut text = rules.join("\n");
                text.push('\n');
                Ok(Response::Body {
                    data: text.into_bytes(),
                    etag: None,
                    last_modified: None,
                })
            }
        };

        // Set when the content was fine but could not be stored (see `Hold`).
        let mut storage_failed = false;
        let outcome = match fetched {
            Ok(Response::NotModified) if same_source => Outcome::Unchanged,
            Ok(Response::NotModified) => {
                Outcome::Failed("server answered 304 but no copy is stored".to_owned())
            }
            Ok(Response::Body {
                data,
                etag,
                last_modified,
            }) => {
                // Hashing, checking, and zstd-compressing a large list takes hundreds of ms:
                // never on a runtime worker, which also carries upstream answers (T2.7).
                let (store, name, mut m) = (self.store.clone(), spec.name.clone(), meta.clone());
                let checks = self.checks(spec);
                let processed = tokio::task::spawn_blocking(move || {
                    let r = accept_body(&store, &name, &mut m, same_source, &data, now, checks);
                    (r, m)
                })
                .await;
                match processed {
                    Ok((r, m)) => {
                        meta = m;
                        match r {
                            Ok(outcome) => {
                                // A held body keeps the stored copy's validators, so the next
                                // conditional GET fetches it again rather than answering 304.
                                if !matches!(outcome, Outcome::Held(_)) {
                                    meta.source.clone_from(&key);
                                    meta.etag = etag;
                                    meta.last_modified = last_modified;
                                }
                                outcome
                            }
                            Err(Rejected::Content(e)) => Outcome::Failed(e),
                            Err(Rejected::Storage(e)) => {
                                storage_failed = true;
                                Outcome::Failed(e)
                            }
                        }
                    }
                    Err(e) => Outcome::Failed(format!("processing the list failed: {e}")),
                }
            }
            Err(e) => Outcome::Failed(e),
        };

        record_outcome(spec, &key, same_source, now, &outcome, &mut meta);
        // REQ: FLT-004 — an inline list that failed waits: for a change if its rules were
        // refused, on the retry ladder if only storing it failed.
        let hold = match &outcome {
            Outcome::Failed(_) if storage_failed => Some(Hold::Until(now.saturating_add(
                retry_after(meta.consecutive_failures, spec.refresh.as_secs()),
            ))),
            Outcome::Failed(_) => Some(Hold::UntilChange),
            _ => None,
        };
        self.put_meta(&spec.name, meta);
        self.note_inline_outcome(spec, &key, hold);
        outcome
    }

    /// The checks a download of `spec` must pass.
    fn checks(&self, spec: &ListSpec) -> Checks {
        Checks {
            max_invalid_percent: self.settings.max_invalid_percent,
            // A file or inline list shrinks because someone edited it.
            max_shrink_percent: if matches!(spec.source, ListSource::Url(_)) {
                self.settings.max_shrink_percent
            } else {
                100
            },
        }
    }

    /// One URL download with retries and backoff.
    async fn download(
        &self,
        name: &str,
        url: &str,
        cond: &Conditional,
        max_bytes: u64,
    ) -> Result<Response, String> {
        let attempts = u32::from(self.settings.retries) + 1;
        let mut last = String::new();
        for attempt in 0..attempts {
            if attempt > 0 {
                let delay = backoff(self.settings.backoff, attempt);
                debug!(
                    list = name,
                    attempt,
                    ?delay,
                    "retrying list download: {last}"
                );
                tokio::time::sleep(delay).await;
            }
            match tokio::time::timeout(self.settings.timeout, self.client.get(url, cond, max_bytes))
                .await
            {
                Ok(Ok(resp)) => return Ok(resp),
                Ok(Err(HttpError { message, retryable })) => {
                    last = message;
                    if !retryable {
                        break;
                    }
                }
                Err(_) => {
                    last = format!("timed out after {:?}", self.settings.timeout);
                }
            }
        }
        Err(last)
    }

    /// Lists due for a refresh at `now` (unix seconds), and how long until the next one is.
    pub fn due(&self, specs: &[ListSpec], now: u64) -> (Vec<ListSpec>, Option<Duration>) {
        let mut due = Vec::new();
        let mut next: Option<u64> = None;
        for spec in specs {
            if !spec.enabled {
                // Switching a list off forgets that its rules were refused, so switching it
                // on again is a retry.
                self.refused
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&spec.name);
                continue;
            }
            let meta = self.meta(&spec.name);
            let at = self
                .hold_until(spec, &meta)
                .unwrap_or_else(|| next_attempt(spec, &meta));
            if at <= now {
                due.push(spec.clone());
            } else {
                next = Some(next.map_or(at, |n| n.min(at)));
            }
        }
        (due, next.map(|n| Duration::from_secs(n - now)))
    }

    /// Keeps `specs` fresh until `specs` is closed. Bumps `changed` whenever stored content
    /// changes (new list, new content, list removed), so the compiler can rebuild.
    pub async fn run(
        self: Arc<Self>,
        mut specs: watch::Receiver<Arc<Vec<ListSpec>>>,
        changed: watch::Sender<u64>,
    ) {
        let mut pruned_for: Option<Arc<Vec<ListSpec>>> = None;
        loop {
            let list = Arc::clone(&specs.borrow_and_update());
            if pruned_for.as_ref().is_none_or(|p| !Arc::ptr_eq(p, &list)) {
                if self.prune(&list) {
                    changed.send_modify(|g| *g += 1);
                }
                pruned_for = Some(Arc::clone(&list));
            }

            let (due, next) = self.due(&list, unix_now());
            if !due.is_empty() {
                self.refresh_and_signal(&due, &changed).await;
                continue;
            }
            // Wake at the next due time (re-checked at least hourly, in case the clock jumped).
            let wait = next
                .unwrap_or(Duration::from_secs(3600))
                .min(Duration::from_secs(3600));
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = self.refresh_now.notified() => self.refresh_and_signal(&list, &changed).await,
                r = specs.changed() => if r.is_err() { return },
            }
        }
    }

    /// Drops stored files and metadata for lists no longer configured (disabled lists keep
    /// theirs, so re-enabling one doesn't need a download). Returns true if anything went.
    fn prune(&self, specs: &[ListSpec]) -> bool {
        let keep: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        let removed = self.store.prune(&keep);
        let mut metas = self.metas.lock().unwrap_or_else(PoisonError::into_inner);
        metas.retain(|name, _| keep.contains(&name.as_str()));
        drop(metas);
        self.refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|name, _| keep.contains(&name.as_str()));
        for name in &removed {
            info!(list = %name, "removed stored list (no longer configured)");
        }
        !removed.is_empty()
    }
}

/// Updates `meta` for the result of refreshing `spec` (whose source key is `key`; `same_source`:
/// a stored copy of that source existed) and logs it.
fn record_outcome(
    spec: &ListSpec,
    key: &str,
    same_source: bool,
    now: u64,
    outcome: &Outcome,
    meta: &mut ListMeta,
) {
    match outcome {
        Outcome::Updated | Outcome::Unchanged => {
            meta.last_success = Some(now);
            meta.last_error = None;
            meta.consecutive_failures = 0;
            meta.held_hash = None;
            if *outcome == Outcome::Updated {
                info!(list = %spec.name, bytes = meta.bytes, lines = meta.lines, "list updated");
            } else {
                debug!(list = %spec.name, "list unchanged");
            }
        }
        Outcome::Failed(e) => {
            if !same_source {
                // Schedule retries for the new source with backoff (a stale `source`
                // would make it due again immediately). Its validators don't apply to
                // the previous content, which keeps serving until a download succeeds.
                key.clone_into(&mut meta.source);
                meta.etag = None;
                meta.last_modified = None;
            }
            meta.last_error = Some(e.clone());
            meta.consecutive_failures = meta.consecutive_failures.saturating_add(1);
            let kept = if meta.has_content() {
                "keeping the previous copy"
            } else {
                "no copy available yet"
            };
            warn!(list = %spec.name, "list refresh failed ({kept}): {e}");
        }
        // Not a failure: no early retry, and the list's status says why it waits.
        Outcome::Held(why) => {
            meta.last_error = Some(why.clone());
            warn!(list = %spec.name, "list update held: {why}");
        }
    }
}

/// The `[filter]` checks a downloaded body must pass.
#[derive(Debug, Clone, Copy)]
struct Checks {
    max_invalid_percent: u8,
    max_shrink_percent: u8,
}

/// Checks a downloaded body and stores it if it differs from the stored copy. Updates the
/// content fields of `meta`; the caller sets source and validators on success. Blocking.
fn accept_body(
    store: &Store,
    name: &str,
    meta: &mut ListMeta,
    same_source: bool,
    data: &[u8],
    now: u64,
    checks: Checks,
) -> Result<Outcome, Rejected> {
    sanity_check(data).map_err(Rejected::Content)?;
    usable_check(data, checks.max_invalid_percent).map_err(Rejected::Content)?;
    let hash = content_hash(data);
    if same_source && meta.content_hash.as_deref() == Some(hash.as_str()) {
        return Ok(Outcome::Unchanged);
    }
    let lines = count_lines(data);
    // REQ: FLT-004 (ADR-147) — a list that suddenly lost most of its lines (a truncated
    // mirror, a source mid-rewrite) waits for the source to serve the same content again.
    if same_source
        && meta.lines >= SHRINK_MIN_LINES
        && lines.saturating_mul(100)
            < meta
                .lines
                .saturating_mul(100 - u64::from(checks.max_shrink_percent.min(100)))
        && meta.held_hash.as_deref() != Some(hash.as_str())
    {
        meta.held_hash = Some(hash);
        return Ok(Outcome::Held(format!(
            "it shrank from {} to {lines} lines, more than [filter] max_shrink_percent ({} %) \
             allows; the previous copy stays in use until a later refresh brings the same \
             content (\"Refresh now\" accepts it)",
            meta.lines, checks.max_shrink_percent
        )));
    }
    if meta.held_hash.as_deref() == Some(hash.as_str()) {
        info!(
            list = name,
            from = meta.lines,
            to = lines,
            "list shrank; the source served the same content again, so it's accepted"
        );
    }
    store
        .save_source(name, data)
        .map_err(|e| Rejected::Storage(format!("cannot store source: {e}")))?;
    meta.content_hash = Some(hash);
    meta.bytes = data.len() as u64;
    meta.lines = lines;
    meta.last_changed = Some(now);
    Ok(Outcome::Updated)
}

/// When a list should next be refreshed (unix seconds).
fn next_attempt(spec: &ListSpec, meta: &ListMeta) -> u64 {
    let Some(last) = meta.last_attempt else {
        return 0;
    };
    if meta.source != spec.source.key() || !meta.has_content() && meta.consecutive_failures == 0 {
        return 0;
    }
    if let ListSource::Inline(_) = spec.source {
        // Inline rules only change with the config, which changes the key. A copy of these
        // rules is current. With no copy, or after a failed attempt (earlier rules that were
        // edited to ones that failed: the old copy keeps serving), this is the first try
        // since a restart or an off and on; `Fetcher::hold_until`, which `due` asks first,
        // holds back what this process already tried.
        return if meta.has_content() && meta.consecutive_failures == 0 {
            u64::MAX
        } else {
            0
        };
    }
    let refresh = spec.refresh.as_secs();
    if meta.consecutive_failures > 0 {
        return last.saturating_add(retry_after(meta.consecutive_failures, refresh));
    }
    last.saturating_add(refresh)
}

fn backoff(base: Duration, attempt: u32) -> Duration {
    let exp = base.saturating_mul(4u32.saturating_pow(attempt - 1));
    let capped = exp.min(Duration::from_secs(60));
    // ±25% jitter so lists sharing a host don't retry in lockstep.
    let jitter = 0.75 + rand::random::<f64>() * 0.5;
    capped.mul_f64(jitter)
}

/// Rejects responses that can't be a list: empty bodies and HTML pages (captive portals,
/// error pages served with 200).
fn sanity_check(data: &[u8]) -> Result<(), String> {
    let start = data
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map_or(&[][..], |i| &data[i..]);
    if start.is_empty() {
        return Err("empty response".to_owned());
    }
    let head: Vec<u8> = start.iter().take(15).map(u8::to_ascii_lowercase).collect();
    if head.starts_with(b"<!doctype html") || head.starts_with(b"<html") {
        return Err("got an HTML page, not a list".to_owned());
    }
    Ok(())
}

/// Rejects a body in which more than `max_invalid_percent` of the rule-bearing lines (rules
/// plus invalid lines) are invalid, which includes one that parses to no rules at all: a JSON
/// error, a compressed blob, or an HTML page without the doctype prefix passes
/// [`sanity_check`] and would otherwise replace a good list with nothing. At the default (50)
/// that means more invalid lines than rules. REQ: FLT-004 — a list that fails keeps its last
/// good version.
fn usable_check(data: &[u8], max_invalid_percent: u8) -> Result<(), String> {
    use crate::parse::{ListOptions, parse_list};
    let s = parse_list(data, ListOptions::default(), |_, _| {});
    let (rules, invalid) = (s.rules, s.invalid);
    if invalid > 0 && invalid * 100 > (rules + invalid) * u64::from(max_invalid_percent) {
        let first = s
            .samples
            .iter()
            .find(|x| !x.unsupported)
            .map_or("", |x| x.reason.as_str());
        return Err(format!(
            "not a usable list: {} rules, {} invalid lines (first: {first})",
            s.rules, s.invalid
        ));
    }
    Ok(())
}

async fn read_file(path: &std::path::Path, max_bytes: u64) -> Result<Response, String> {
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > max_bytes {
        return Err(format!(
            "{}: larger than the {max_bytes}-byte limit",
            path.display()
        ));
    }
    let data = tokio::fs::read(path)
        .await
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Response::Body {
        data,
        etag: None,
        last_modified: None,
    })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(source: ListSource) -> ListSpec {
        ListSpec {
            name: "l".into(),
            source,
            refresh: Duration::from_hours(24),
            max_bytes: 1 << 20,
            enabled: true,
        }
    }

    /// REQ: FLT-004 (ADR-016) — a disabled list keeps its stored files (re-enabling it
    /// needs no download), so it stays in the spec set, marked, and is never due.
    #[test]
    fn flt_004_disabled_lists_stay_known_but_never_due() {
        let cfg: Config = telltale_config::Loader::new()
            .toml_str(
                "t.toml",
                "[[list]]\nname = \"on\"\nurl = \"https://example.com/on.txt\"\n\
                 [[list]]\nname = \"off\"\nurl = \"https://example.com/off.txt\"\nenabled = false\n",
            )
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config;
        let specs = ListSpec::from_config(&cfg);
        let flags: Vec<(&str, bool)> = specs.iter().map(|s| (s.name.as_str(), s.enabled)).collect();
        assert_eq!(flags, [("on", true), ("off", false)]);
        let tmp = tempfile::tempdir().unwrap();
        let f = Fetcher::new(
            Store::open(tmp.path()).unwrap(),
            Client::new(Arc::new(SystemResolver), &[]).unwrap(),
            FetchSettings::from_config(&cfg),
        );
        let (due, _) = f.due(&specs, unix_now());
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].name, "on"); // The prune keep-set is the whole spec set: `off`'s files survive.
        f.store().save_source("off", b"x.com\n").unwrap();
        assert!(!f.prune(&specs));
        assert!(f.store().read_source("off").is_ok());
    }

    #[test]
    fn flt_004_schedule() {
        let s = spec(ListSource::Url("https://example.com/l.txt".into()));
        let mut m = ListMeta::default();
        assert_eq!(next_attempt(&s, &m), 0, "never fetched → now");

        m.source = s.source.key();
        m.content_hash = Some("h".into());
        m.last_attempt = Some(1000);
        assert_eq!(next_attempt(&s, &m), 1000 + 86_400);

        m.consecutive_failures = 1;
        assert_eq!(next_attempt(&s, &m), 1000 + 300, "failing → retry sooner");
        m.consecutive_failures = 3;
        assert_eq!(next_attempt(&s, &m), 1000 + 1200);
        m.consecutive_failures = 30;
        assert_eq!(next_attempt(&s, &m), 1000 + 3600, "capped at an hour");

        m.consecutive_failures = 0;
        m.source = "https://example.com/other.txt".into();
        assert_eq!(next_attempt(&s, &m), 0, "source changed → now");

        let inline = spec(ListSource::Inline(vec!["||a.com^".into()]));
        let mut m = ListMeta {
            source: inline.source.key(),
            content_hash: Some("h".into()),
            last_attempt: Some(5),
            ..ListMeta::default()
        };
        assert_eq!(
            next_attempt(&inline, &m),
            u64::MAX,
            "inline: only on config change"
        );
        // A failed attempt behind a copy (earlier rules edited to ones that failed): offered
        // again, and `Fetcher::hold_until` keeps it from looping.
        m.consecutive_failures = 1;
        assert_eq!(next_attempt(&inline, &m), 0, "inline: a failed edit");
        m.consecutive_failures = 0;
        m.source = spec(ListSource::Inline(vec!["||b.com^".into()]))
            .source
            .key();
        assert_eq!(next_attempt(&inline, &m), 0);
    }

    /// REQ: FLT-004 — only inline rules count as inline: their metadata has no download to age.
    #[test]
    fn flt_004_inline_sources_are_recognised() {
        let meta = |source: ListSource| ListMeta {
            source: spec(source).source.key(),
            ..ListMeta::default()
        };
        assert!(meta(ListSource::Inline(vec!["||a.com^".into()])).is_inline());
        assert!(!meta(ListSource::Url("https://example.com/inline.txt".into())).is_inline());
        assert!(!meta(ListSource::Path("inline:a.txt".into())).is_inline());
        assert!(!ListMeta::default().is_inline());
    }

    #[test]
    fn flt_004_backoff_grows_and_caps() {
        let b = Duration::from_secs(2);
        for (attempt, nominal) in [(1, 2.0), (2, 8.0), (3, 32.0), (4, 60.0), (9, 60.0)] {
            let d = backoff(b, attempt).as_secs_f64();
            assert!(
                (nominal * 0.75..=nominal * 1.25).contains(&d),
                "attempt {attempt}: {d}"
            );
        }
    }

    #[test]
    fn flt_004_sanity() {
        assert!(sanity_check(b"ads.example.com\n").is_ok());
        assert!(sanity_check(b"").is_err());
        assert!(sanity_check(b" \n\t").is_err());
        assert!(sanity_check(b"\n<!DOCTYPE html><html>").is_err());
        assert!(sanity_check(b"<HTML><body>").is_err());
        assert!(sanity_check(b"! Title: <html> in a comment\n").is_ok());
    }
}
