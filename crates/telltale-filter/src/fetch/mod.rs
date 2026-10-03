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

pub use self::http::{Client, Conditional, HttpError, Resolve, Response, SystemResolver};
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
                    "inline:{}",
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
}

impl ListSpec {
    /// The enabled lists in `cfg`, with `[filter]` defaults applied.
    pub fn from_config(cfg: &Config) -> Vec<Self> {
        let f = &cfg.filter;
        cfg.list
            .iter()
            .filter(|l| l.enabled)
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
}

impl FetchSettings {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            concurrency: usize::from(cfg.filter.fetch_concurrency.max(1)),
            timeout: Duration::from_secs(u64::from(cfg.filter.fetch_timeout_secs)),
            retries: cfg.filter.fetch_retries,
            backoff: Duration::from_secs(2),
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
}

/// Retry a failing list after 5 min, doubling up to 1 h (but never later than its normal
/// refresh), instead of waiting a whole refresh interval.
const FAIL_RETRY_BASE: u64 = 300;
const FAIL_RETRY_MAX: u64 = 3600;

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
    refresh_now: Notify,
}

impl Fetcher {
    pub fn new(store: Store, client: Client, settings: FetchSettings) -> Self {
        Self {
            store,
            client,
            settings,
            metas: Mutex::new(HashMap::new()),
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

    /// Makes `run` refresh every list now, regardless of schedule (`POST /lists/refresh`).
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

    /// Refreshes `specs` concurrently (at most `concurrency` at a time).
    pub async fn refresh(self: &Arc<Self>, specs: &[ListSpec]) -> Vec<(String, Outcome)> {
        let sem = Arc::new(Semaphore::new(self.settings.concurrency.max(1)));
        let mut set = JoinSet::new();
        for spec in specs.iter().cloned() {
            let (this, sem) = (Arc::clone(self), Arc::clone(&sem));
            set.spawn(async move {
                let _permit = sem.acquire_owned().await;
                let outcome = this.refresh_one(&spec).await;
                (spec.name, outcome)
            });
        }
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
                let processed = tokio::task::spawn_blocking(move || {
                    let r = accept_body(&store, &name, &mut m, same_source, &data, now);
                    (r, m)
                })
                .await;
                match processed {
                    Ok((r, m)) => {
                        meta = m;
                        r.map_or_else(Outcome::Failed, |outcome| {
                            meta.source.clone_from(&key);
                            meta.etag = etag;
                            meta.last_modified = last_modified;
                            outcome
                        })
                    }
                    Err(e) => Outcome::Failed(format!("processing the list failed: {e}")),
                }
            }
            Err(e) => Outcome::Failed(e),
        };

        match &outcome {
            Outcome::Updated | Outcome::Unchanged => {
                meta.last_success = Some(now);
                meta.last_error = None;
                meta.consecutive_failures = 0;
                if outcome == Outcome::Updated {
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
                    meta.source.clone_from(&key);
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
        }
        self.put_meta(&spec.name, meta);
        outcome
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
            let meta = self.meta(&spec.name);
            let at = next_attempt(spec, &meta);
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
                let results = self.refresh(&due).await;
                if results.iter().any(|(_, o)| *o == Outcome::Updated) {
                    changed.send_modify(|g| *g += 1);
                }
                continue;
            }
            // Wake at the next due time (re-checked at least hourly, in case the clock jumped).
            let wait = next
                .unwrap_or(Duration::from_secs(3600))
                .min(Duration::from_secs(3600));
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = self.refresh_now.notified() => {
                    let results = self.refresh(&list).await;
                    if results.iter().any(|(_, o)| *o == Outcome::Updated) {
                        changed.send_modify(|g| *g += 1);
                    }
                }
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
        for name in &removed {
            info!(list = %name, "removed stored list (no longer configured)");
        }
        !removed.is_empty()
    }
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
) -> Result<Outcome, String> {
    sanity_check(data)?;
    let hash = content_hash(data);
    if same_source && meta.content_hash.as_deref() == Some(hash.as_str()) {
        return Ok(Outcome::Unchanged);
    }
    store
        .save_source(name, data)
        .map_err(|e| format!("cannot store source: {e}"))?;
    meta.content_hash = Some(hash);
    meta.bytes = data.len() as u64;
    meta.lines = count_lines(data);
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
        // Inline rules only change with the config, which changes the key.
        return if meta.has_content() { u64::MAX } else { 0 };
    }
    let refresh = spec.refresh.as_secs();
    if meta.consecutive_failures > 0 {
        let shift = (meta.consecutive_failures - 1).min(10);
        let retry = (FAIL_RETRY_BASE << shift).min(FAIL_RETRY_MAX).min(refresh);
        return last.saturating_add(retry);
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
        }
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
        m.source = spec(ListSource::Inline(vec!["||b.com^".into()]))
            .source
            .key();
        assert_eq!(next_attempt(&inline, &m), 0);
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
