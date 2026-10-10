//! Node maintenance mode (REQ: OPS-010; ADR-118, `docs/design/maintenance-mode.md`): a
//! timeboxed flag on one node that says "stop sending me new traffic, stop worrying about me,
//! but I'll keep answering whatever still arrives".
//!
//! - **State, not configuration:** `<data_dir>/maintenance.json`, written before it takes
//!   effect and read at start, so a node restarted inside its window comes back not ready
//!   with the same `until`. Removed on end or expiry. No configuration version, allowed under
//!   `GitOps`, and sent to the node it concerns (RPC [`KIND_SET`] / [`KIND_CLEAR`]), not to the
//!   primary.
//! - **What changes here:** `/readyz` answers 503 ([`crate::readiness`]); heartbeats carry the
//!   window; the node doesn't stand in elections; a primary under automatic failover hands its
//!   role over first when another eligible node can take it. Every listener keeps answering.
//! - **What changes elsewhere** (alerts, health, the Cluster page's checks) reads the window
//!   from heartbeats: see `alerts.rs`, `health.rs`, `cluster.rs`.
//!
//! Nothing here is on the query path: an `Arc` swap and two atomics, an expiry task.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use telltale_api::MaintenanceWrite;
use telltale_api::maintenance_api::{check_reason, check_secs};
use telltale_api::model::{MaintenanceResult, NodeMaintenance};
use telltale_api::problem::{Code, Problem};
use telltale_cluster::net::{Cluster, MaintenanceWindow};
use tracing::{info, warn};

use crate::readiness::Readiness;

/// The file in the data directory.
pub(crate) const FILE: &str = "maintenance.json";
/// RPCs to the node a request is for: start (or extend) and end.
pub(crate) const KIND_SET: &str = "maint.set";
pub(crate) const KIND_CLEAR: &str = "maint.clear";
/// How long the entry node waits for the target node.
const DEADLINE: Duration = Duration::from_secs(5);
/// A request older than this when the target reads it is dropped: the entry node gave up on
/// it long ago (a paused process resuming must not act on what the user saw fail). Generous
/// for clock differences between nodes.
const STALE_MS: u64 = 30_000;

/// A request on the cluster channel: the write and when the entry node sent it.
#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    write: MaintenanceWrite,
    sent_ms: u64,
}

/// One maintenance window, as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Window {
    pub(crate) until_ms: u64,
    pub(crate) since_ms: u64,
    pub(crate) reason: String,
    pub(crate) by: String,
    /// The primary started handing over (resumed after a restart while it's still primary).
    #[serde(default)]
    pub(crate) handover: bool,
}

impl Window {
    pub(crate) fn cluster_window(&self) -> MaintenanceWindow {
        MaintenanceWindow {
            until_ms: self.until_ms,
            since_ms: self.since_ms,
            reason: self.reason.clone(),
            by: self.by.clone(),
        }
    }
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// A window as the API shows it, `node` in lists.
pub(crate) fn api_window(w: &MaintenanceWindow, now: u64, node: Option<String>) -> NodeMaintenance {
    NodeMaintenance {
        node,
        until: telltale_api::time::format_us(w.until_ms.saturating_mul(1000)),
        since: telltale_api::time::format_us(w.since_ms.saturating_mul(1000)),
        reason: w.reason.clone(),
        by: w.by.clone(),
        seconds_left: w.until_ms.saturating_sub(now).div_ceil(1000),
    }
}

/// This node's maintenance: the window, its effects, and how many were started.
#[derive(Debug)]
pub(crate) struct Maintenance {
    path: PathBuf,
    current: Mutex<Option<Window>>,
    readiness: Arc<Readiness>,
    cluster: Option<Arc<Cluster>>,
    starts: AtomicU64,
    /// Wakes the expiry task when the window changes.
    changed: tokio::sync::Notify,
}

impl Maintenance {
    /// Reads `<data_dir>/maintenance.json`: an open window takes effect at once (before the
    /// node first reports ready); an expired or unreadable one is removed.
    pub(crate) fn open(
        data_dir: &Path,
        readiness: Arc<Readiness>,
        cluster: Option<Arc<Cluster>>,
        now: u64,
    ) -> Self {
        let m = Self {
            path: data_dir.join(FILE),
            current: Mutex::new(None),
            readiness,
            cluster,
            starts: AtomicU64::new(0),
            changed: tokio::sync::Notify::new(),
        };
        match std::fs::read(&m.path) {
            Ok(bytes) => match serde_json::from_slice::<Window>(&bytes) {
                Ok(w) if w.until_ms > now => {
                    info!(
                        until_ms = w.until_ms,
                        reason = %w.reason,
                        "maintenance until {} ({}): not ready until then; DNS keeps answering",
                        telltale_api::time::format_us(w.until_ms.saturating_mul(1000)),
                        w.reason
                    );
                    // A primary that was handing over keeps doing so; a node that isn't
                    // primary any more has nothing to hand over.
                    let handover = w.handover && m.cluster.as_ref().is_some_and(|c| c.is_primary());
                    m.apply(Some(&w), handover);
                    *m.current.lock().unwrap_or_else(PoisonError::into_inner) = Some(w);
                }
                Ok(_) => {
                    info!("maintenance window ended while the node was stopped");
                    let _ = std::fs::remove_file(&m.path);
                }
                Err(e) => {
                    warn!("{}: unreadable ({e}); removed", m.path.display());
                    let _ = std::fs::remove_file(&m.path);
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!("{}: {e}", m.path.display()),
        }
        m
    }

    /// The window, while it's open.
    pub(crate) fn current(&self, now: u64) -> Option<Window> {
        self.current
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .filter(|w| w.until_ms > now)
    }

    /// Windows started since this process did.
    pub(crate) fn starts(&self) -> u64 {
        self.starts.load(Ordering::Relaxed)
    }

    fn apply(&self, w: Option<&Window>, handover: bool) {
        self.readiness.set_maintenance(w.is_some());
        if let Some(c) = &self.cluster {
            c.set_maintenance(w.map(Window::cluster_window), handover);
        }
    }

    /// Starts (or replaces) the window: on disk first, then not ready, heartbeats, elections.
    pub(crate) fn start(&self, w: Window) -> std::io::Result<()> {
        let json = serde_json::to_vec_pretty(&w).map_err(std::io::Error::other)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::File::open(&tmp)?.sync_all()?;
        std::fs::rename(&tmp, &self.path)?;
        self.apply(Some(&w), w.handover);
        info!(
            until_ms = w.until_ms,
            by = %w.by,
            "maintenance started ({}): /readyz answers 503; DNS keeps answering",
            w.reason
        );
        *self.current.lock().unwrap_or_else(PoisonError::into_inner) = Some(w);
        self.starts.fetch_add(1, Ordering::Relaxed);
        self.changed.notify_one();
        Ok(())
    }

    /// Ends the window (if there is one) and returns it.
    pub(crate) fn end(&self) -> std::io::Result<Option<Window>> {
        let was = self
            .current
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                // Still in maintenance on disk: keep it in effect, so a restart agrees.
                *self.current.lock().unwrap_or_else(PoisonError::into_inner) = was;
                return Err(e);
            }
        }
        if was.is_some() {
            self.apply(None, false);
            info!("maintenance ended: ready for traffic again");
        }
        self.changed.notify_one();
        Ok(was)
    }

    /// Ends the window if it has run out; returns it then.
    pub(crate) fn expire(&self, now: u64) -> Option<Window> {
        let due = self
            .current
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|w| w.until_ms <= now);
        if !due {
            return None;
        }
        match self.end() {
            Ok(w) => w,
            Err(e) => {
                warn!("maintenance: can't remove {}: {e}", self.path.display());
                None
            }
        }
    }

    fn next_expiry(&self) -> Option<u64> {
        self.current
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|w| w.until_ms)
    }
}

/// Ends the window when it runs out (and audits it), until `stop`.
pub(crate) fn spawn_expiry(
    src: Arc<crate::http::Sources>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        loop {
            let wait = src
                .maintenance
                .next_expiry()
                .map_or(Duration::from_secs(3600), |until| {
                    Duration::from_millis(until.saturating_sub(now_ms()).clamp(50, 60_000))
                });
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = src.maintenance.changed.notified() => continue,
                _ = stop.wait_for(|s| *s) => return,
            }
            if let Some(w) = src.maintenance.expire(now_ms()) {
                info!(reason = %w.reason, "maintenance window ended by itself");
                if let Some(auth) = src.auth.get() {
                    auth.record(
                        &telltale_api::auth::Actor::system("expired"),
                        "node.maintenance.end",
                        &label(&src),
                        &serde_json::json!({ "reason": w.reason, "by": w.by, "expired": true }),
                    );
                }
            }
        }
    });
}

/// How this node is named in answers: its pod, else its site, else its ID; a standalone node
/// by its name.
pub(crate) fn label(src: &crate::http::Sources) -> String {
    match &src.cluster {
        Some(c) => {
            let pod = c.local_state().pod;
            let m = &c.identity.meta;
            if !pod.is_empty() {
                pod
            } else if m.site.is_empty() {
                m.node_id.clone()
            } else {
                m.site.clone()
            }
        }
        None => crate::http::node_name(&src.config.load()),
    }
}

/// The note for a primary that keeps the role.
const PROMOTE_FIRST: &str =
    "this node stays the primary; promote another node first if you're taking it offline";

/// REQ: OPS-010 (owner 2026-10-09) — what a primary entering maintenance does with its role:
/// `(handover, note, step down)`. It hands over under automatic failover when asked and
/// another eligible node (not in maintenance) and a majority of voters are reachable;
/// otherwise maintenance is still allowed and it stays the primary.
pub(crate) fn handover_plan(
    c: &Cluster,
    requested: bool,
    now: u64,
) -> (&'static str, Option<String>, bool) {
    if !c.is_primary() {
        return ("not_needed", None, false);
    }
    let id = c.identity.reload();
    if !telltale_cluster::failover::active(&id) {
        return (
            "unavailable",
            Some(format!(
                "Failover is manual (or has fewer than 3 voters): {PROMOTE_FIRST}."
            )),
            false,
        );
    }
    if !requested {
        return (
            "declined",
            Some(format!("Handover wasn't asked for: {PROMOTE_FIRST}.")),
            false,
        );
    }
    let registry = id.registry();
    let reachable = c.reachable_peers();
    let can_lead = |node: &str| {
        registry
            .iter()
            .any(|n| n.node_id == node && n.eligible && !n.witness)
    };
    let other = c.members().iter().any(|m| {
        reachable.contains(&m.node_id) && m.in_maintenance(now).is_none() && can_lead(&m.node_id)
    });
    let voters = telltale_cluster::failover::voters(&id);
    let up = voters
        .iter()
        .filter(|v| **v == id.meta.node_id || reachable.contains(v))
        .count();
    if !other || up * 2 <= voters.len() {
        return (
            "unavailable",
            Some(format!(
                "No other eligible node (and majority of voters) is reachable to take over: {PROMOTE_FIRST}."
            )),
            false,
        );
    }
    (
        "started",
        Some("Another node is being elected (configuration changes pause for about 30 s); this node follows it for the rest of the window.".into()),
        true,
    )
}

/// REQ: OPS-010 — starts or ends maintenance on this node (the API checked the request; a
/// forwarded one is checked again by the caller).
pub(crate) fn apply_here(
    src: &crate::http::Sources,
    w: MaintenanceWrite,
) -> Result<MaintenanceResult, Problem> {
    let now = now_ms();
    let this = label(src);
    match w {
        MaintenanceWrite::Start {
            for_secs,
            max_secs,
            reason,
            handover,
            by,
        } => {
            let default = src.config.load().node.maintenance_default_secs;
            let secs = check_secs(for_secs.unwrap_or(default), max_secs)?;
            let reason = check_reason(Some(&reason))?;
            let (outcome, note, step_down) = match &src.cluster {
                Some(c) => handover_plan(c, handover, now),
                None => ("not_needed", None, false),
            };
            let w = Window {
                until_ms: now + u64::from(secs) * 1000,
                since_ms: now,
                reason,
                by,
                handover: step_down,
            };
            src.maintenance
                .start(w.clone())
                .map_err(|e| Problem::internal(format!("can't write {FILE}: {e}")))?;
            Ok(MaintenanceResult {
                window: Some(api_window(&w.cluster_window(), now, None)),
                node: this,
                active: true,
                handover: Some(outcome.to_owned()),
                note,
            })
        }
        MaintenanceWrite::End { .. } => {
            let was = src
                .maintenance
                .end()
                .map_err(|e| Problem::internal(format!("can't remove {FILE}: {e}")))?;
            Ok(MaintenanceResult {
                node: this,
                active: false,
                window: None,
                handover: None,
                note: was
                    .is_none()
                    .then(|| "It wasn't in maintenance.".to_owned()),
            })
        }
    }
}

/// REQ: OPS-010 — a request for a peer, over its cluster stream; the peer's answer, or why
/// there's none (`node_unreachable`).
pub(crate) async fn send(
    cluster: Arc<Cluster>,
    peer: String,
    label: String,
    w: MaintenanceWrite,
) -> Result<MaintenanceResult, Problem> {
    let kind = match w {
        MaintenanceWrite::Start { .. } => KIND_SET,
        MaintenanceWrite::End { .. } => KIND_CLEAR,
    };
    let envelope = |w: &MaintenanceWrite| {
        serde_json::to_vec(&Envelope {
            write: w.clone(),
            sent_ms: now_ms(),
        })
        .map_err(|e| Problem::internal(e.to_string()))
    };
    // One retry: right after a node restarts, an answer can be lost while its streams settle.
    // Asking twice is harmless (a second start replaces the window, a second end does nothing).
    let mut reply = cluster.call(&peer, kind, envelope(&w)?, DEADLINE).await;
    if reply.as_ref().is_err_and(|e| !e.contains("unknown call")) {
        reply = cluster.call(&peer, kind, envelope(&w)?, DEADLINE).await;
    }
    let reply = reply.map_err(|e| {
            let older = e.contains("unknown call");
            Problem::new(
                Code::NodeUnreachable,
                if older {
                    format!("{label} runs a version without maintenance mode")
                } else {
                    format!("{label} isn't reachable over the cluster channel: {e}")
                },
            )
            .hint(if older {
                "Upgrade it first, or stop it the usual way."
            } else {
                "Maintenance is the node's own state, so the node must be up to take it. Check the Cluster page."
            })
        })?;
    crate::forward::decode_answer(&reply)
}

/// A peer's request, unless it's too old to act on.
fn read_request(body: &[u8], now: u64) -> Result<MaintenanceWrite, String> {
    let Envelope { write, sent_ms } =
        serde_json::from_slice(body).map_err(|e| format!("bad maintenance request: {e}"))?;
    if now > sent_ms.saturating_add(STALE_MS) {
        return Err("the request is too old; the node that sent it gave up on it".into());
    }
    Ok(write)
}

/// REQ: OPS-010 — a peer's request for this node: checked again, applied, and audited here
/// with the user and the entry node.
pub(crate) fn handle(
    src: &crate::http::Sources,
    cluster: &Cluster,
    peer: &str,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let w = read_request(body, now_ms())?;
    let via = cluster
        .members()
        .into_iter()
        .find(|m| m.node_id == peer)
        .map(|m| if m.pod.is_empty() { m.site } else { m.pod })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| peer.to_owned());
    let (w, by, action) = match w {
        MaintenanceWrite::Start {
            for_secs,
            max_secs,
            reason,
            handover,
            by,
        } => (
            MaintenanceWrite::Start {
                for_secs,
                max_secs: max_secs.min(telltale_api::maintenance_api::MAX_SECS),
                reason,
                handover,
                by: format!("{by} via {via}"),
            },
            by,
            "node.maintenance.start",
        ),
        MaintenanceWrite::End { by } => (
            MaintenanceWrite::End {
                by: format!("{by} via {via}"),
            },
            by,
            "node.maintenance.end",
        ),
    };
    let r = apply_here(src, w);
    if let (Ok(res), Some(auth)) = (&r, src.auth.get()) {
        let actor = telltale_api::auth::Actor {
            name: format!("{by} via {via}"),
            kind: "cluster",
            remote: Some(format!("node {peer}")),
            reason: None,
        };
        auth.record(
            &actor,
            action,
            &res.node,
            &serde_json::json!({
                "until": res.window.as_ref().map(|w| w.until.clone()),
                "reason": res.window.as_ref().map(|w| w.reason.clone()),
                "handover": res.handover,
            }),
        );
    }
    crate::forward::encode_answer(r)
}

/// Whether `node` names this node (`local`, its ID, or its label).
pub(crate) fn is_local(src: &crate::http::Sources, node: &str) -> bool {
    node == "local"
        || node == label(src)
        || src
            .cluster
            .as_ref()
            .is_some_and(|c| c.identity.meta.node_id == node)
}

/// REQ: OPS-010 — the API's answer for a standalone node (or `local`).
pub(crate) fn local_backend_call(
    src: Arc<crate::http::Sources>,
    node: &str,
    w: MaintenanceWrite,
) -> telltale_api::BoxFuture<Result<MaintenanceResult, Problem>> {
    if !is_local(&src, node) {
        let node = node.to_owned();
        return Box::pin(async move {
            Err(Problem::new(
                Code::NodeUnknown,
                format!("no node `{node}`: this node isn't in a cluster"),
            )
            .hint("Use `local` for this node."))
        });
    }
    Box::pin(async move {
        tokio::task::spawn_blocking(move || apply_here(&src, w))
            .await
            .map_err(|e| Problem::internal(format!("maintenance: {e}")))?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "telltale-maint-{name}-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn window(until_ms: u64) -> Window {
        Window {
            until_ms,
            since_ms: 1_000,
            reason: "SD card swap".into(),
            by: "alice".into(),
            handover: false,
        }
    }

    // REQ: OPS-010 (ADR-118) — the window is written before it takes effect and read at
    // start: a restart inside it comes back not ready with the same `until`; ending or
    // expiry removes the file and makes the node ready again; an expired or broken file is
    // removed at start.
    #[test]
    fn ops_010_window_file_round_trip_and_expiry() {
        let dir = tmp("rt");
        let r = Arc::new(Readiness::ready_now());
        let m = Maintenance::open(&dir, Arc::clone(&r), None, 10_000);
        assert!(m.current(10_000).is_none() && r.ready());
        m.start(window(100_000)).unwrap();
        assert!(dir.join(FILE).exists());
        assert!(!r.ready() && r.serving(), "not ready, still serving");
        assert_eq!(m.starts(), 1);
        // A restart inside the window.
        let r2 = Arc::new(Readiness::ready_now());
        let again = Maintenance::open(&dir, Arc::clone(&r2), None, 50_000);
        assert_eq!(again.current(50_000).map(|w| w.until_ms), Some(100_000));
        assert_eq!(r2.reason(), Some("maintenance"));
        // Not due yet; then due.
        assert!(again.expire(99_999).is_none());
        assert_eq!(
            again.expire(100_000).map(|w| w.reason),
            Some("SD card swap".into())
        );
        assert!(r2.ready() && !dir.join(FILE).exists());
        // Started again, ended by hand.
        again.start(window(200_000)).unwrap();
        assert!(again.end().unwrap().is_some());
        assert!(r2.ready() && again.end().unwrap().is_none());
        // A restart after the window: the stale file goes.
        again.start(window(300_000)).unwrap();
        let r3 = Arc::new(Readiness::ready_now());
        let late = Maintenance::open(&dir, Arc::clone(&r3), None, 400_000);
        assert!(late.current(400_000).is_none() && r3.ready());
        assert!(!dir.join(FILE).exists());
        // Garbage is removed, not trusted.
        std::fs::write(dir.join(FILE), b"{not json").unwrap();
        let r4 = Arc::new(Readiness::ready_now());
        let _ = Maintenance::open(&dir, Arc::clone(&r4), None, 1);
        assert!(r4.ready() && !dir.join(FILE).exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    // REQ: OPS-010 — a request crosses the channel intact; one the entry node gave up on long
    // ago (a paused process resuming) is dropped.
    #[test]
    fn ops_010_forwarded_requests_expire() {
        let w = MaintenanceWrite::Start {
            for_secs: Some(600),
            max_secs: 86_400,
            reason: "SD card swap".into(),
            handover: true,
            by: "alice".into(),
        };
        let body = serde_json::to_vec(&Envelope {
            write: w.clone(),
            sent_ms: 1_000_000,
        })
        .unwrap();
        assert_eq!(read_request(&body, 1_004_000), Ok(w));
        assert!(read_request(&body, 1_000_000 + STALE_MS + 1).is_err());
        assert!(read_request(b"{}", 0).is_err());
    }
}
