//! Readiness (REQ: OPS-006, OPS-007, OPS-010; ADR-118): why `/readyz` says what it says.
//!
//! One answer for balancers and Kubernetes, made of independent reasons: every listener is
//! bound, an ephemeral resolver pod has the cluster's configuration (CLU-009), the process
//! isn't shutting down, and the node isn't in maintenance. *Serving* is the DNS side of it
//! (bound, synced, not stopping): a node in maintenance still serves every query that
//! arrives; it only asks balancers to stop sending new ones. Plain atomics: nothing here is
//! on the query path.

use std::sync::atomic::{AtomicBool, Ordering};

/// The reasons a node is or isn't ready.
#[derive(Debug)]
pub(crate) struct Readiness {
    bound: AtomicBool,
    synced: AtomicBool,
    stopping: AtomicBool,
    maintenance: AtomicBool,
}

impl Readiness {
    /// Not bound yet; `needs_sync` for an ephemeral member that waits for the cluster's
    /// configuration before it serves.
    pub(crate) fn new(needs_sync: bool) -> Self {
        Self {
            bound: AtomicBool::new(false),
            synced: AtomicBool::new(!needs_sync),
            stopping: AtomicBool::new(false),
            maintenance: AtomicBool::new(false),
        }
    }

    /// Ready from the start (tests).
    #[cfg(test)]
    pub(crate) fn ready_now() -> Self {
        let r = Self::new(false);
        r.set_bound();
        r
    }

    /// Every listener is bound.
    pub(crate) fn set_bound(&self) {
        self.bound.store(true, Ordering::Release);
    }

    /// The cluster's configuration is applied (CLU-009).
    pub(crate) fn set_synced(&self) {
        self.synced.store(true, Ordering::Release);
    }

    /// REQ: OPS-007 — shutdown started: not ready from now on.
    pub(crate) fn set_stopping(&self) {
        self.stopping.store(true, Ordering::Release);
    }

    /// REQ: OPS-010 — maintenance started or ended.
    pub(crate) fn set_maintenance(&self, on: bool) {
        self.maintenance.store(on, Ordering::Release);
    }

    /// Answering DNS: listeners bound, configuration in hand, not shutting down. A node in
    /// maintenance serves.
    pub(crate) fn serving(&self) -> bool {
        self.bound.load(Ordering::Acquire)
            && self.synced.load(Ordering::Acquire)
            && !self.stopping.load(Ordering::Acquire)
    }

    /// Wants new traffic: serving and not in maintenance (`/readyz`).
    pub(crate) fn ready(&self) -> bool {
        self.serving() && !self.maintenance.load(Ordering::Acquire)
    }

    /// Ready, leaving maintenance out (`/readyz?startup=1`, the Kubernetes startup probe: a
    /// pod restarted inside its window has started fine and must not be killed for it).
    pub(crate) fn started(&self) -> bool {
        self.serving()
    }

    /// Why it isn't ready, most fundamental first: `shutting_down`, `starting` (listeners not
    /// bound yet), `syncing` (waiting for the cluster's configuration), `maintenance`.
    pub(crate) fn reason(&self) -> Option<&'static str> {
        if self.stopping.load(Ordering::Acquire) {
            Some("shutting_down")
        } else if !self.bound.load(Ordering::Acquire) {
            Some("starting")
        } else if !self.synced.load(Ordering::Acquire) {
            Some("syncing")
        } else if self.maintenance.load(Ordering::Acquire) {
            Some("maintenance")
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: OPS-010, OPS-006 (ADR-118) — the reasons compose: maintenance makes a serving node
    // unready without making it stop serving; the startup view ignores maintenance; each
    // reason is named.
    #[test]
    fn ops_010_readiness_composition() {
        let r = Readiness::new(true);
        assert_eq!((r.ready(), r.reason()), (false, Some("starting")));
        r.set_bound();
        assert_eq!((r.ready(), r.reason()), (false, Some("syncing")));
        assert!(!r.serving());
        r.set_synced();
        assert_eq!((r.ready(), r.serving(), r.reason()), (true, true, None));
        r.set_maintenance(true);
        assert_eq!(
            (r.ready(), r.serving(), r.started(), r.reason()),
            (false, true, true, Some("maintenance"))
        );
        r.set_maintenance(false);
        assert!(r.ready());
        r.set_maintenance(true);
        r.set_stopping();
        assert_eq!(
            (r.ready(), r.serving(), r.started(), r.reason()),
            (false, false, false, Some("shutting_down"))
        );
        // Maintenance ending during shutdown never makes it ready again.
        r.set_maintenance(false);
        assert!(!r.ready());
        let plain = Readiness::new(false);
        plain.set_bound();
        assert!(
            plain.ready(),
            "a node that needs no sync is ready once bound"
        );
    }
}
