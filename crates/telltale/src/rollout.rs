//! Staged rollouts and pins (REQ: CLU-013; ADR-116, `docs/design/staged-rollouts.md`).
//!
//! The primary keeps two heads (`telltale_cluster::net::Cluster::publish_canary_as`): a new
//! version goes to the canary nodes first; after `bake_secs` under the guard here, everyone
//! else gets it. A failing guard, or an operator, **pins** the cluster: a new version
//! (`seq + 1`, never an old manifest again) that serves an older version's content, until
//! unpinned. This module holds the parts that don't depend on the publish loop: the version
//! history (`versions.json`, whose blobs the primary's store keeps), the guard's arithmetic,
//! which peers are canaries, the persisted state, the operator's commands, and the diff a
//! pinned cluster shows.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use telltale_cluster::sync::{BlobRef, FilterRef, PinInfo};
use telltale_config::RolloutConfig;

/// `<cluster dir>/versions.json`: the published versions kept for pinning back to.
pub(crate) const VERSIONS: &str = "versions.json";
/// `<cluster dir>/rollout.json`: the rollout in progress and the pin.
pub(crate) const STATE: &str = "rollout.json";
/// `<cluster dir>/pinned.json`: the pinned manifest the primary serves itself.
pub(crate) const PINNED: &str = "pinned.json";

/// The fewest answers the bake judges a SERVFAIL share from.
pub(crate) const MIN_ANSWERS: f64 = 50.0;
/// Points over the share before the rollout that still pass.
const MARGIN_POINTS: f64 = 2.0;
/// A canary not ready this long after applying fails the version.
const NOT_READY_MS: u64 = 15_000;
/// A canary gone this long after applying fails it (with `fail_on_disconnect`).
const GONE_MS: u64 = 60_000;
/// A canary still failing to apply this long after the version went out fails it.
const SYNC_ERROR_MS: u64 = 10_000;
/// Samples older than this are dropped (the longest bake, and a margin).
const HISTORY_MS: u64 = 3_700_000;
/// The longest gap one sample stands for (a missed tick isn't an hour of traffic).
const MAX_GAP_MS: u64 = 10_000;

/// What became of a version.
pub(crate) mod outcome {
    pub(crate) const STABLE: &str = "stable";
    pub(crate) const CANARY: &str = "canary";
    pub(crate) const PROMOTED: &str = "canary_promoted";
    pub(crate) const FAILED: &str = "canary_failed";
    pub(crate) const SUPERSEDED: &str = "superseded";
    pub(crate) const ABORTED: &str = "aborted";
    pub(crate) const PINNED_TO: &str = "pinned_to";
}

/// The guard's readings over a bake.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct Readings {
    /// The canaries' SERVFAIL share (percent) over the bake before the rollout, and during it.
    pub(crate) before_pct: Option<f64>,
    pub(crate) after_pct: Option<f64>,
    /// Answers the canaries (and the primary) gave during the bake.
    pub(crate) answers: u64,
    /// Why it failed, if it did.
    pub(crate) reason: Option<String>,
}

/// One published version, as kept for history and pins.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct VersionEntry {
    pub(crate) epoch: u64,
    pub(crate) seq: u64,
    pub(crate) created_ms: u64,
    /// What made it: a user, an agent, a Git commit, `pin by …`.
    pub(crate) by: String,
    pub(crate) outcome: String,
    #[serde(default)]
    pub(crate) readings: Option<Readings>,
    pub(crate) config: BlobRef,
    pub(crate) filter: Option<FilterRef>,
    #[serde(default)]
    pub(crate) identities: Option<BlobRef>,
    #[serde(default)]
    pub(crate) acks: Option<BlobRef>,
    /// For a pin: the version whose content it serves.
    #[serde(default)]
    pub(crate) pinned_to: Option<(u64, u64)>,
    #[serde(default)]
    pub(crate) reason: Option<String>,
}

impl VersionEntry {
    /// Every blob it names (kept while it's in the history).
    pub(crate) fn blobs(&self) -> Vec<BlobRef> {
        let mut v = vec![self.config.clone()];
        if let Some(f) = &self.filter {
            v.extend(f.blobs.iter().cloned());
        }
        v.extend(self.identities.iter().cloned());
        v.extend(self.acks.iter().cloned());
        v
    }
}

/// `versions.json`, oldest first.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct Versions {
    pub(crate) entries: Vec<VersionEntry>,
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

impl Versions {
    pub(crate) fn load(cdir: &Path) -> Self {
        std::fs::read(cdir.join(VERSIONS))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub(crate) fn save(&self, cdir: &Path) -> std::io::Result<()> {
        write_atomic(
            &cdir.join(VERSIONS),
            &serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?,
        )
    }

    /// Adds (or replaces, same version) `e`, keeping the newest `keep`.
    pub(crate) fn record(&mut self, e: VersionEntry, keep: usize) {
        self.entries
            .retain(|x| (x.epoch, x.seq) != (e.epoch, e.seq));
        self.entries.push(e);
        self.entries.sort_by_key(|x| (x.epoch, x.seq));
        let extra = self.entries.len().saturating_sub(keep.max(1));
        self.entries.drain(..extra);
    }

    pub(crate) fn set_outcome(
        &mut self,
        version: (u64, u64),
        outcome: &str,
        readings: Option<Readings>,
    ) {
        if let Some(e) = self
            .entries
            .iter_mut()
            .find(|x| (x.epoch, x.seq) == version)
        {
            outcome.clone_into(&mut e.outcome);
            if readings.is_some() {
                e.readings = readings;
            }
        }
    }

    pub(crate) fn find(&self, version: (u64, u64)) -> Option<&VersionEntry> {
        self.entries.iter().find(|x| (x.epoch, x.seq) == version)
    }

    /// The blobs the primary's store must keep.
    pub(crate) fn protected(&self) -> Vec<BlobRef> {
        self.entries.iter().flat_map(VersionEntry::blobs).collect()
    }
}

/// A rollout in progress, as persisted.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct Active {
    /// The version baking, and the stable one it would replace.
    pub(crate) version: (u64, u64),
    pub(crate) stable: (u64, u64),
    pub(crate) started_ms: u64,
    pub(crate) bake_secs: u32,
    /// The canary nodes it went to.
    pub(crate) canaries: Vec<String>,
    /// The canaries' SERVFAIL share before it (percent).
    pub(crate) before_pct: Option<f64>,
}

/// `rollout.json`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct State {
    #[serde(default)]
    pub(crate) active: Option<Active>,
    #[serde(default)]
    pub(crate) pinned: Option<PinInfo>,
}

impl State {
    pub(crate) fn load(cdir: &Path) -> Self {
        std::fs::read(cdir.join(STATE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub(crate) fn save(&self, cdir: &Path) -> std::io::Result<()> {
        write_atomic(
            &cdir.join(STATE),
            &serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?,
        )
    }
}

/// The pinned manifest the primary serves itself (`pinned.json`), if the cluster is pinned.
pub(crate) fn pinned_manifest(cdir: &Path) -> Option<telltale_cluster::sync::ClusterManifest> {
    let b = std::fs::read(cdir.join(PINNED)).ok()?;
    serde_json::from_slice(&b).ok()
}

/// Whether a node is a canary under `spec` (`[cluster.rollout] canaries`): its ID, its site
/// (`site:<name>`), or `ephemeral` for an ephemeral member.
pub(crate) fn is_canary(spec: &[String], node_id: &str, site: &str, ephemeral: bool) -> bool {
    spec.iter().any(|c| {
        let c = c.trim();
        c == node_id
            || c.strip_prefix("site:").is_some_and(|s| s.trim() == site)
            || (c == "ephemeral" && ephemeral)
    })
}

/// What the primary knows of one node at a tick (from its heartbeats; the primary itself from
/// its own stats).
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Sample {
    pub(crate) node: String,
    pub(crate) qps: u64,
    pub(crate) servfail_permille: u32,
    pub(crate) ready: bool,
    pub(crate) connected: bool,
    pub(crate) applied_seq: u64,
    pub(crate) sync_error: Option<String>,
    pub(crate) probe_failing: bool,
}

/// What the guard decides at a tick.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Verdict {
    Baking,
    Pass(Readings),
    Fail(Readings),
}

/// The guard: per-node serving history (from heartbeats every few seconds) and the timers
/// for the immediate failures.
#[derive(Debug, Default)]
pub(crate) struct Guard {
    history: BTreeMap<String, VecDeque<(u64, u64, u32)>>,
    not_ready_since: BTreeMap<String, u64>,
    gone_since: BTreeMap<String, u64>,
}

impl Guard {
    /// Records one tick's samples.
    pub(crate) fn observe(&mut self, now_ms: u64, samples: &[Sample]) {
        for s in samples {
            let h = self.history.entry(s.node.clone()).or_default();
            if s.connected {
                h.push_back((now_ms, s.qps, s.servfail_permille));
            }
            while h.front().is_some_and(|x| x.0 + HISTORY_MS < now_ms) {
                h.pop_front();
            }
            if s.ready || !s.connected {
                self.not_ready_since.remove(&s.node);
            } else {
                self.not_ready_since.entry(s.node.clone()).or_insert(now_ms);
            }
            if s.connected {
                self.gone_since.remove(&s.node);
            } else {
                self.gone_since.entry(s.node.clone()).or_insert(now_ms);
            }
        }
    }

    /// (answers, SERVFAILs) of `nodes` over `(from, to]`: each sample stands for the time since
    /// the one before it (at most [`MAX_GAP_MS`]).
    pub(crate) fn share(&self, nodes: &BTreeSet<String>, from_ms: u64, to_ms: u64) -> (f64, f64) {
        let (mut answers, mut servfails) = (0.0, 0.0);
        for n in nodes {
            let Some(h) = self.history.get(n) else {
                continue;
            };
            let mut prev: Option<u64> = None;
            for &(t, qps, permille) in h {
                if let Some(p) = prev
                    && t > from_ms
                    && t <= to_ms
                {
                    #[allow(clippy::cast_precision_loss)] // rates for a threshold
                    let a = qps as f64 * (t - p).min(MAX_GAP_MS) as f64 / 1000.0;
                    answers += a;
                    servfails += a * f64::from(permille) / 1000.0;
                }
                prev = Some(t);
            }
        }
        (answers, servfails)
    }

    /// The SERVFAIL share (percent) of `nodes` over the window, if they answered anything.
    pub(crate) fn pct(&self, nodes: &BTreeSet<String>, from_ms: u64, to_ms: u64) -> Option<f64> {
        let (a, s) = self.share(nodes, from_ms, to_ms);
        (a > 0.0).then(|| s / a * 100.0)
    }

    /// The verdict on `a` at `now_ms`: an immediate failure on a canary that applied the
    /// version; a SERVFAIL share over the threshold, judged as soon as the bake so far has
    /// [`MIN_ANSWERS`] (a bad version is pinned before the bake ends); else, once the bake is
    /// over, a pass.
    /// `judged` are the nodes whose answers count (the canaries and the primary).
    pub(crate) fn verdict(
        &self,
        a: &Active,
        cfg: &RolloutConfig,
        now_ms: u64,
        samples: &[Sample],
        judged: &BTreeSet<String>,
    ) -> Verdict {
        let readings = |after: Option<f64>, answers: f64, reason: Option<String>| Readings {
            before_pct: a.before_pct,
            after_pct: after,
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            answers: answers.max(0.0) as u64,
            reason,
        };
        let elapsed = now_ms.saturating_sub(a.started_ms);
        let (answers, servfails) = self.share(judged, a.started_ms, now_ms);
        let after = (answers > 0.0).then(|| servfails / answers * 100.0);
        for s in samples.iter().filter(|s| a.canaries.contains(&s.node)) {
            let applied = s.applied_seq == a.version.1;
            let fail = if s.sync_error.is_some() && !applied && elapsed >= SYNC_ERROR_MS {
                Some(format!(
                    "{} couldn't apply the version: {}",
                    s.node,
                    s.sync_error.as_deref().unwrap_or("")
                ))
            } else if applied
                && self
                    .not_ready_since
                    .get(&s.node)
                    .is_some_and(|t| now_ms - t >= NOT_READY_MS)
            {
                Some(format!(
                    "{} isn't ready since it applied the version",
                    s.node
                ))
            } else if applied && s.probe_failing {
                Some(format!(
                    "{}'s listener checks fail since it applied the version",
                    s.node
                ))
            } else if applied
                && cfg.fail_on_disconnect
                && self
                    .gone_since
                    .get(&s.node)
                    .is_some_and(|t| now_ms - t >= GONE_MS)
            {
                Some(format!(
                    "{} disconnected after applying the version",
                    s.node
                ))
            } else {
                None
            };
            if let Some(r) = fail {
                return Verdict::Fail(readings(after, answers, Some(r)));
            }
        }
        // The SERVFAIL share is judged as soon as there are enough answers: a bad version is
        // pinned before the bake ends, and the nodes waiting for it never get it.
        let limit = a.before_pct.map_or(cfg.servfail_pct, |b| {
            (b + MARGIN_POINTS).max(cfg.servfail_pct)
        });
        let share = after.unwrap_or(0.0);
        if answers >= MIN_ANSWERS && share > limit {
            return Verdict::Fail(readings(
                after,
                answers,
                Some(format!(
                    "SERVFAIL {share:.1}% on the canaries during the bake (limit {limit:.1}%)"
                )),
            ));
        }
        if elapsed < u64::from(a.bake_secs) * 1000 {
            return Verdict::Baking;
        }
        if let Some(s) = samples
            .iter()
            .find(|s| a.canaries.contains(&s.node) && s.applied_seq != a.version.1)
        {
            // A canary that never got it: give it until the longest bake, then fail.
            if elapsed < u64::from(cfg.max_bake_secs) * 1000 {
                return Verdict::Baking;
            }
            return Verdict::Fail(readings(
                after,
                answers,
                Some(format!("{} never applied the version", s.node)),
            ));
        }
        if answers >= MIN_ANSWERS {
            return Verdict::Pass(readings(after, answers, None));
        }
        if cfg.require_traffic {
            if elapsed >= u64::from(cfg.max_bake_secs) * 1000 {
                return Verdict::Fail(readings(
                    after,
                    answers,
                    Some(format!(
                        "fewer than {MIN_ANSWERS} answers on the canaries in {} s",
                        cfg.max_bake_secs
                    )),
                ));
            }
            return Verdict::Baking;
        }
        Verdict::Pass(readings(after, answers, None))
    }
}

/// An RFC 6902-style patch from `a` to `b`: objects compared key by key, everything else
/// (arrays included) replaced whole. Paths are JSON Pointers.
pub(crate) fn json_diff(a: &serde_json::Value, b: &serde_json::Value) -> Vec<serde_json::Value> {
    fn esc(k: &str) -> String {
        k.replace('~', "~0").replace('/', "~1")
    }
    #[allow(clippy::many_single_char_names)] // a → b, and each side's members
    fn walk(
        a: &serde_json::Value,
        b: &serde_json::Value,
        path: &str,
        out: &mut Vec<serde_json::Value>,
    ) {
        use serde_json::{Value, json};
        match (a, b) {
            (Value::Object(x), Value::Object(y)) => {
                let keys: BTreeSet<&String> = x.keys().chain(y.keys()).collect();
                for k in keys {
                    let p = format!("{path}/{}", esc(k));
                    match (x.get(k), y.get(k)) {
                        (Some(u), Some(v)) => walk(u, v, &p, out),
                        (None, Some(v)) => out.push(json!({"op": "add", "path": p, "value": v})),
                        (Some(_), None) => out.push(json!({"op": "remove", "path": p})),
                        (None, None) => {}
                    }
                }
            }
            _ if a == b => {}
            _ => out.push(json!({"op": "replace", "path": path, "value": b})),
        }
    }
    let mut out = Vec::new();
    walk(a, b, "", &mut out);
    out
}

/// One sentence per patch operation, by section (`[[list]] changed`, `[ratelimit] added`).
pub(crate) fn diff_sentences(ops: &[serde_json::Value]) -> Vec<String> {
    let mut by: BTreeMap<String, &str> = BTreeMap::new();
    for op in ops {
        let path = op["path"].as_str().unwrap_or("");
        let mut parts = path.trim_start_matches('/').split('/');
        let section = parts.next().unwrap_or("").to_owned();
        let deeper = parts.next().is_some();
        let what = match (op["op"].as_str().unwrap_or(""), deeper) {
            ("add", false) => "added",
            ("remove", false) => "removed",
            _ => "changed",
        };
        by.entry(section).or_insert(what);
    }
    by.into_iter().map(|(s, w)| format!("{s}: {w}")).collect()
}

/// An operator's request to the publisher (it runs on the primary's publish loop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Cmd {
    /// End the bake now and give the canary version to everyone.
    Promote { by: String },
    /// Stop the rollout: pin to the stable version (the primary runs the change too).
    Abort { by: String },
    /// Serve `to`'s content everywhere, as a new version.
    Pin {
        to: (u64, u64),
        by: String,
        reason: String,
    },
    /// Publish the current configuration again (through a rollout when canaries are set).
    Unpin { by: String },
}

/// What a command answers: done (with a sentence), or why not (an API problem code).
pub(crate) type Reply = Result<String, (telltale_api::problem::Code, String)>;

/// One node as the rollout card shows it.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub(crate) struct NodeRow {
    pub(crate) node: String,
    pub(crate) site: String,
    pub(crate) canary: bool,
    pub(crate) applied_seq: u64,
    pub(crate) ready: bool,
    pub(crate) connected: bool,
    pub(crate) servfail_permille: u32,
}

/// What the publish loop last reported (the API reads it).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub(crate) struct Status {
    /// This node publishes (it's the primary).
    pub(crate) primary: bool,
    pub(crate) emergency: bool,
    /// `[cluster.rollout] canaries`.
    pub(crate) canaries: Vec<String>,
    pub(crate) bake_secs: u32,
    pub(crate) stable: (u64, u64),
    pub(crate) active: Option<Active>,
    /// The guard's readings so far (during a bake), or of the last decision.
    pub(crate) readings: Option<Readings>,
    pub(crate) pinned: Option<PinInfo>,
    pub(crate) nodes: Vec<NodeRow>,
    /// Why the last change wasn't staged although canaries are set.
    pub(crate) skipped: Option<String>,
    /// Since when a change has waited for a canary to come online (Unix ms).
    pub(crate) waiting_since_ms: Option<u64>,
    /// Since when canaries are set but none is online (Unix ms): changes then reach every node
    /// at once (the health condition `rollout_stuck` after 10 minutes).
    pub(crate) canaries_offline_since_ms: Option<u64>,
    /// The last version the guard failed (the `rollout_failed` alert goes out once per version).
    pub(crate) last_failure: Option<Failure>,
    /// Rollouts by outcome since this process started (`started`, `promoted`, `failed`,
    /// `aborted`, `pinned`, `unpinned`, `skipped`): the metrics' counters.
    pub(crate) counts: BTreeMap<String, u64>,
}

/// A version the guard failed.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub(crate) struct Failure {
    pub(crate) version: (u64, u64),
    pub(crate) reason: String,
    pub(crate) at_ms: u64,
}

/// Commands waiting for the publish loop, the replies it sends back, and its status.
#[derive(Debug, Default)]
pub(crate) struct Hub {
    queue: Mutex<VecDeque<(Cmd, tokio::sync::oneshot::Sender<Reply>)>>,
    status: Mutex<Status>,
}

impl Hub {
    pub(crate) fn status(&self) -> Status {
        self.status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn set_status(&self, s: Status) {
        *self.status.lock().unwrap_or_else(PoisonError::into_inner) = s;
    }

    /// Queues `cmd` and waits (bounded) for the publish loop's answer.
    pub(crate) async fn send(&self, cmd: Cmd) -> Reply {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back((cmd, tx));
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(r)) => r,
            _ => Err((
                telltale_api::problem::Code::Unavailable,
                "the primary's publisher didn't answer (is this node the primary?)".to_owned(),
            )),
        }
    }

    /// The next command, if any (the publish loop).
    pub(crate) fn next(&self) -> Option<(Cmd, tokio::sync::oneshot::Sender<Reply>)> {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
    }
}

pub(crate) mod surface;

#[cfg(test)]
mod tests;
