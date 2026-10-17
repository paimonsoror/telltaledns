//! REQ: OBS-033 (ADR-133) — change markers. Each node appends one JSON line per event to
//! `<data_dir>/annotations.jsonl`: a configuration version applied, a new build, a restart, a
//! list refresh that changed the rules, a rollout stage, maintenance, a pause, a cache flush,
//! an upstream's circuit breaker, a note. The lines are written by the background task that
//! knows about the event, never by the query path or the telemetry thread. Appends need no
//! fsync (the audit log is the record; a lost marker is acceptable), and a failed write is
//! logged once an hour and changes nothing else (CLU-004). The file keeps at most
//! [`MAX_LINES`] lines and [`MAX_AGE_MS`] of history, compacted at start, once a day, and
//! when it grows past twice the cap.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use telltale_api::annotations_api::KINDS;
use telltale_api::model::{Annotation, AnnotationFilter};
use tracing::{info, warn};

/// The file in the data directory.
pub(crate) const FILE: &str = "annotations.jsonl";
/// The most lines kept.
pub(crate) const MAX_LINES: usize = 20_000;
/// The oldest marker kept.
pub(crate) const MAX_AGE_MS: u64 = 90 * 86_400_000;
/// A failed write is logged at most this often.
const WARN_EVERY: Duration = Duration::from_secs(3600);
/// At most one breaker line per upstream this often.
const BREAKER_EVERY_MS: u64 = 300_000;
/// How long a write's provenance waits for the reload that applies it.
const PROVENANCE_TTL: Duration = Duration::from_secs(60);

/// Where a configuration change came from, left by whoever started it for the reload (or, on
/// a cluster's primary, the publish) that writes its `config.applied` line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Provenance {
    /// `ui`, `api`, `agent`, `gitops`, `file`, or `cluster`.
    pub(crate) source: String,
    pub(crate) actor: Option<String>,
    /// The sequence, when the writer knows it (a replica: the manifest's; a standalone node:
    /// `state.db`'s version).
    pub(crate) seq: Option<u64>,
    /// A replica: the filter snapshot it took.
    pub(crate) filter_version: Option<u64>,
}

/// A change the primary's reload applied, waiting for the sequence the publish gives it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Pending {
    sections: Vec<String>,
    provenance: Option<Provenance>,
}

#[derive(Debug, Default)]
struct State {
    /// Lines appended since the last compaction (a full one is compacted early).
    since_compaction: usize,
    last_warn: Option<Instant>,
    provenance: Option<(Instant, Provenance)>,
    pending: Option<(Instant, Pending)>,
    /// Upstream → (the state last written, when).
    breakers: HashMap<String, (&'static str, u64)>,
}

/// One node's change markers.
#[derive(Debug)]
pub(crate) struct Annotations {
    path: PathBuf,
    state: Mutex<State>,
    /// Held while the file is appended to or rewritten, so a compaction never drops a line
    /// written meanwhile.
    io: Mutex<()>,
    /// Lines written since start, per [`KINDS`] entry (`telltale_annotations_total`).
    counts: Vec<AtomicU64>,
    /// Failed writes since start.
    failures: AtomicU64,
    /// Failed writes that were logged.
    warnings: AtomicU64,
}

static GLOBAL: OnceLock<Arc<Annotations>> = OnceLock::new();

/// This process's markers, once [`init`] ran.
pub(crate) fn get() -> Option<&'static Arc<Annotations>> {
    GLOBAL.get()
}

/// Opens (and compacts) `<data_dir>/annotations.jsonl` for this process.
pub(crate) fn init(data_dir: &Path, now_ms: u64) -> Arc<Annotations> {
    Arc::clone(GLOBAL.get_or_init(|| Arc::new(Annotations::open(data_dir, now_ms))))
}

/// Appends `a` to this process's markers, if they're open. Best effort.
pub(crate) fn record(a: Annotation) {
    if let Some(g) = get() {
        g.record(a);
    }
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

pub(crate) use telltale_api::annotations_api::marker;

impl Annotations {
    /// Opens the file in `data_dir` and compacts it. A file that can't be read is left alone
    /// (appends may still work).
    pub(crate) fn open(data_dir: &Path, now_ms: u64) -> Self {
        let a = Self {
            path: data_dir.join(FILE),
            state: Mutex::default(),
            io: Mutex::new(()),
            counts: KINDS.iter().map(|_| AtomicU64::new(0)).collect(),
            failures: AtomicU64::new(0),
            warnings: AtomicU64::new(0),
        };
        match a.compact(now_ms) {
            Ok(0) => {}
            Ok(n) => info!(dropped = n, "change markers: compacted"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => a.warn(&format!("can't compact {}: {e}", a.path.display())),
        }
        a
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Logs `what` once an hour at most.
    fn warn(&self, what: &str) {
        let mut st = self.state();
        if st.last_warn.is_none_or(|t| t.elapsed() >= WARN_EVERY) {
            st.last_warn = Some(Instant::now());
            drop(st);
            self.warnings.fetch_add(1, Ordering::Relaxed);
            warn!("change markers: {what} (DNS is unaffected; logged once an hour)");
        }
    }

    /// Appends one line. On failure: counted, logged once an hour.
    pub(crate) fn append(&self, mut a: Annotation) -> std::io::Result<Annotation> {
        if a.t.is_empty() {
            a.t = telltale_api::time::format_us(a.t_unix_ms.saturating_mul(1000));
        }
        // The node is the reader's label for it, never stored.
        a.node = None;
        let mut line = serde_json::to_vec(&a).map_err(std::io::Error::other)?;
        line.push(b'\n');
        let written = {
            let _io = self.io.lock().unwrap_or_else(PoisonError::into_inner);
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .and_then(|mut f| f.write_all(&line))
        };
        if let Err(e) = written {
            self.failures.fetch_add(1, Ordering::Relaxed);
            self.warn(&format!("can't write {}: {e}", self.path.display()));
            return Err(e);
        }
        if let Some(i) = KINDS.iter().position(|k| *k == a.kind) {
            self.counts[i].fetch_add(1, Ordering::Relaxed);
        }
        let full = {
            let mut st = self.state();
            st.since_compaction += 1;
            st.since_compaction > MAX_LINES
        };
        if full && let Err(e) = self.compact(a.t_unix_ms.max(now_ms())) {
            self.warn(&format!("can't compact {}: {e}", self.path.display()));
        }
        Ok(a)
    }

    /// Appends one line, best effort.
    pub(crate) fn record(&self, a: Annotation) {
        let _ = self.append(a);
    }

    /// `(kind, lines written since start)` for every kind.
    pub(crate) fn counts(&self) -> Vec<(&'static str, u64)> {
        KINDS
            .iter()
            .zip(&self.counts)
            .map(|(k, n)| (*k, n.load(Ordering::Relaxed)))
            .collect()
    }

    /// Failed writes since start, and how many of them were logged.
    pub(crate) fn failures(&self) -> (u64, u64) {
        (
            self.failures.load(Ordering::Relaxed),
            self.warnings.load(Ordering::Relaxed),
        )
    }

    /// Every readable line, in file (append) order.
    fn lines(&self) -> std::io::Result<Vec<Annotation>> {
        let text = std::fs::read_to_string(&self.path)?;
        Ok(text
            .lines()
            .filter_map(|l| serde_json::from_str::<Annotation>(l).ok())
            .collect())
    }

    /// Keeps the newest [`MAX_LINES`] lines no older than [`MAX_AGE_MS`]; rewrites the file
    /// (atomically) only when something goes. Returns how many lines went.
    pub(crate) fn compact(&self, now_ms: u64) -> std::io::Result<usize> {
        let _io = self.io.lock().unwrap_or_else(PoisonError::into_inner);
        let text = std::fs::read_to_string(&self.path)?;
        let total = text.lines().count();
        let oldest = now_ms.saturating_sub(MAX_AGE_MS);
        let mut keep: Vec<&str> = text
            .lines()
            .filter(|l| serde_json::from_str::<Annotation>(l).is_ok_and(|a| a.t_unix_ms >= oldest))
            .collect();
        if keep.len() > MAX_LINES {
            keep.drain(..keep.len() - MAX_LINES);
        }
        let dropped = total - keep.len();
        // The next early compaction comes when the file holds twice the cap.
        self.state().since_compaction = keep.len().saturating_sub(MAX_LINES);
        if dropped == 0 {
            return Ok(0);
        }
        let tmp = self.path.with_extension("jsonl.tmp");
        let mut body = keep.join("\n");
        if !body.is_empty() {
            body.push('\n');
        }
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(dropped)
    }

    /// The markers `f` asks for, newest first.
    pub(crate) fn read(&self, f: &AnnotationFilter) -> Vec<Annotation> {
        let mut out: Vec<Annotation> = match self.lines() {
            Ok(l) => l,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    self.warn(&format!("can't read {}: {e}", self.path.display()));
                }
                return Vec::new();
            }
        }
        .into_iter()
        .filter(|a| a.t_unix_ms >= f.from_ms && a.t_unix_ms < f.to_ms)
        .filter(|a| f.kinds.is_empty() || f.kinds.contains(&a.kind))
        .collect();
        out.sort_by_key(|a| std::cmp::Reverse(a.t_unix_ms));
        out.truncate(f.limit);
        out
    }

    /// REQ: OBS-033 — at start: `node.restarted` always, and `build.started` first when this
    /// build isn't the one the last restart recorded.
    pub(crate) fn started(&self, version: &str, commit: &str, unclean: bool, at_ms: u64) {
        let last = self
            .lines()
            .unwrap_or_default()
            .into_iter()
            .rev()
            .find(|a| a.kind == "node.restarted");
        let same = last.as_ref().is_some_and(|l| {
            l.version.as_deref() == Some(version) && l.commit.as_deref() == Some(commit)
        });
        if !same {
            let was = last
                .and_then(|l| l.version)
                .map_or(String::new(), |v| format!(" (was {v})"));
            self.record(Annotation {
                version: Some(version.to_owned()),
                commit: Some(commit.to_owned()),
                href: Some("#/settings?tab=system".into()),
                ..marker(
                    "build.started",
                    at_ms,
                    format!("build {version} started{was}"),
                )
            });
        }
        let how = if unclean {
            " after an unclean stop"
        } else {
            ""
        };
        self.record(Annotation {
            version: Some(version.to_owned()),
            commit: Some(commit.to_owned()),
            unclean_shutdown: Some(unclean),
            href: Some("#/settings?tab=system".into()),
            ..marker("node.restarted", at_ms, format!("node restarted{how}"))
        });
    }

    /// Leaves where the next configuration change comes from (an API write, a replica's
    /// manifest) for the reload that applies it.
    pub(crate) fn set_provenance(&self, p: Provenance) {
        self.state().provenance = Some((Instant::now(), p));
    }

    fn take_provenance(&self) -> Option<Provenance> {
        self.state()
            .provenance
            .take()
            .filter(|(at, _)| at.elapsed() < PROVENANCE_TTL)
            .map(|(_, p)| p)
    }

    /// REQ: OBS-033 — a reload changed `sections` of the configuration. On a cluster's
    /// primary the line waits for the sequence the next publish gives it
    /// ([`Annotations::published`]); everywhere else it's written now, with the sequence
    /// from the provenance or `seq`.
    pub(crate) fn reloaded(
        &self,
        sections: Vec<String>,
        primary: bool,
        seq: impl FnOnce() -> Option<u64>,
        at_ms: u64,
    ) {
        if sections.is_empty() {
            let _ = self.take_provenance();
            return;
        }
        let provenance = self.take_provenance();
        if primary {
            self.state().pending = Some((
                Instant::now(),
                Pending {
                    sections,
                    provenance,
                },
            ));
            return;
        }
        let p = provenance.unwrap_or_else(|| Provenance {
            source: "file".into(),
            ..Provenance::default()
        });
        let seq = p.seq.or_else(seq);
        self.record(config_line(seq, &p, sections, at_ms));
    }

    /// REQ: OBS-033 — the primary published configuration `seq`; `git` when its Git commit
    /// changed with it. Writes the line a reload left waiting, if any (a version that only
    /// carries users, tokens, or acknowledgements has none).
    pub(crate) fn published(&self, seq: u64, git: bool, at_ms: u64) {
        let Some((at, pending)) = self.state().pending.take() else {
            return;
        };
        if at.elapsed() >= PROVENANCE_TTL {
            return;
        }
        let mut p = pending.provenance.unwrap_or_else(|| Provenance {
            source: "file".into(),
            ..Provenance::default()
        });
        if git && p.source == "file" {
            p.source = "gitops".into();
        }
        self.record(config_line(Some(seq), &p, pending.sections, at_ms));
    }

    /// REQ: OBS-033 — an upstream's breaker reads `state` (`open` or `closed`; half-open counts
    /// as open). Written when it differs from the last line for that upstream, at most once per
    /// [`BREAKER_EVERY_MS`]; a change inside that time is written once it's over, if it still
    /// holds. Nothing for an upstream that has been closed all along.
    pub(crate) fn breaker(&self, upstream: &str, state: &'static str, at_ms: u64) {
        let write = {
            let mut st = self.state();
            let last = st.breakers.get(upstream).copied();
            let (was, when) = last.unwrap_or(("closed", 0));
            let due = last.is_none() || at_ms.saturating_sub(when) >= BREAKER_EVERY_MS;
            if was == state || !due {
                false
            } else {
                st.breakers.insert(upstream.to_owned(), (state, at_ms));
                true
            }
        };
        if write {
            let what = if state == "open" {
                "opened: its answers are failing, other upstreams answer"
            } else {
                "closed: answering again"
            };
            self.record(Annotation {
                upstream: Some(upstream.to_owned()),
                state: Some(state.to_owned()),
                href: Some("#/upstreams".into()),
                ..marker(
                    "upstream.breaker",
                    at_ms,
                    format!("upstream {upstream}'s breaker {what}"),
                )
            });
        }
    }
}

/// The `config.applied` line.
pub(crate) fn config_line(
    seq: Option<u64>,
    p: &Provenance,
    sections: Vec<String>,
    at_ms: u64,
) -> Annotation {
    let n = sections.len();
    let what = seq.map_or_else(
        || "configuration".to_owned(),
        |s| format!("configuration {s}"),
    );
    let filter = p
        .filter_version
        .map_or(String::new(), |v| format!(", filter snapshot {v}"));
    let plural = if n == 1 { "" } else { "s" };
    Annotation {
        seq,
        source: Some(p.source.clone()),
        actor: p.actor.clone(),
        sections,
        filter_version: p.filter_version,
        href: Some("#/settings?tab=system".into()),
        ..marker(
            "config.applied",
            at_ms,
            format!(
                "{what} applied ({}, {n} section{plural} changed{filter})",
                p.source
            ),
        )
    }
}

/// Blocked names in a snapshot.
fn names(m: &telltale_filter::snapshot::Manifest) -> i64 {
    let s = &m.stats;
    i64::try_from(s.subtree_names + s.exact_names + s.subdomains_names).unwrap_or(i64::MAX)
}

/// REQ: OBS-033 — the `lists.refreshed` line for a newly compiled snapshot: the lists whose
/// content changed since `before` (added, removed, or downloaded anew) and the blocked names
/// gained. `None` when neither changed.
pub(crate) fn lists_line(
    before: Option<&telltale_filter::snapshot::Manifest>,
    after: &telltale_filter::snapshot::Manifest,
    at_ms: u64,
) -> Option<Annotation> {
    let key = |l: &telltale_filter::snapshot::ManifestList| (l.name.clone(), l.source_hash.clone());
    let old: std::collections::BTreeSet<(String, String)> = before
        .map(|m| m.lists.iter().map(key).collect())
        .unwrap_or_default();
    let new: std::collections::BTreeSet<(String, String)> = after.lists.iter().map(key).collect();
    let mut lists: Vec<String> = old
        .symmetric_difference(&new)
        .map(|(n, _)| n.clone())
        .collect();
    lists.sort();
    lists.dedup();
    let delta = names(after) - before.map_or(0, names);
    if lists.is_empty() && delta == 0 {
        return None;
    }
    let sign = if delta >= 0 { "+" } else { "" };
    let which = match lists.len() {
        0 => "lists".to_owned(),
        1 => format!("list {}", lists[0]),
        n => format!("{n} lists"),
    };
    Some(Annotation {
        lists,
        rules_delta: Some(delta),
        filter_version: Some(after.version),
        href: Some("#/lists".into()),
        ..marker(
            "lists.refreshed",
            at_ms,
            format!(
                "{which} refreshed: filter snapshot {} ({sign}{delta} blocked names)",
                after.version
            ),
        )
    })
}

/// The top-level configuration sections whose values differ.
pub(crate) fn changed_sections(
    old: &telltale_config::Config,
    new: &telltale_config::Config,
) -> Vec<String> {
    let (Ok(a), Ok(b)) = (serde_json::to_value(old), serde_json::to_value(new)) else {
        return Vec::new();
    };
    let (Some(a), Some(b)) = (a.as_object(), b.as_object()) else {
        return Vec::new();
    };
    let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter(|k| a.get(*k) != b.get(*k))
        .cloned()
        .collect()
}

/// REQ: OBS-033 — the background work: daily compaction and the upstreams' breakers (read
/// every 5 s from their health state, off the query path), until `stop`.
pub(crate) fn spawn(
    src: Arc<crate::http::Sources>,
    ann: Arc<Annotations>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    use telltale_upstream::health::Breaker;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_compact = Instant::now();
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = stop.wait_for(|s| *s) => return,
            }
            let now = now_ms();
            let router = Arc::clone(&src.pipeline.current().router);
            for u in router.upstreams() {
                let state = match u.health.snapshot().breaker {
                    Breaker::Closed => "closed",
                    Breaker::HalfOpen | Breaker::Open => "open",
                };
                ann.breaker(&u.name, state, now);
            }
            if last_compact.elapsed() >= Duration::from_hours(24) {
                last_compact = Instant::now();
                let a = Arc::clone(&ann);
                let _ = tokio::task::spawn_blocking(move || match a.compact(now) {
                    Ok(0) => {}
                    Ok(n) => info!(dropped = n, "change markers: compacted"),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => a.warn(&format!("can't compact {}: {e}", a.path.display())),
                })
                .await;
            }
        }
    });
}

#[cfg(test)]
mod tests;
