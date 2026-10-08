//! REQ: OBS-014 (ADR-103) — acknowledged device anomalies. Someone looked at a finding and
//! marked it as seen: the badge and the default list stop counting it. Findings are identified
//! by a stable ID (kind, device, domain, and window), so one acknowledgement covers the same
//! finding on every node.
//!
//! The primary (or a standalone node) owns the table. In a cluster it publishes the whole set
//! with each configuration version, next to users and tokens, and every replica replaces its
//! copy with it ([`State::replace_anomaly_acks`]), so a node that was down catches up when it
//! reconnects. Acknowledgements of findings older than [`KEEP_DAYS`] are pruned: the engine
//! doesn't keep findings that long.

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use super::{Result, State, i, u};

/// How long an acknowledgement is kept, counted from its finding's window.
pub const KEEP_DAYS: u64 = 60;
/// At most this many are kept (the newest windows win), so the replicated document stays small.
pub const MAX_ACKS: u64 = 10_000;

/// One acknowledged finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnomalyAck {
    /// The finding's ID.
    pub id: String,
    /// Who acknowledged it (`alice`, `alice via home-pi`, `agent:… (owner: alice)`).
    pub by: String,
    /// When, Unix seconds.
    pub at: u64,
    /// Why, when they said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The start of the finding's window, Unix seconds (for pruning).
    pub window_start: u64,
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AnomalyAck> {
    Ok(AnomalyAck {
        id: r.get(0)?,
        by: r.get(1)?,
        at: u(r.get(2)?),
        note: r.get(3)?,
        window_start: u(r.get(4)?),
    })
}

/// Counts changes to the set, so the primary re-reads it only when it changed (its publish
/// loop runs twice a second).
const VERSION_KEY: &str = "anomaly_acks_version";

fn bump(c: &rusqlite::Connection) -> rusqlite::Result<()> {
    c.execute(
        "INSERT INTO meta (key, value) VALUES (?1, '1')
         ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1",
        [VERSION_KEY],
    )?;
    Ok(())
}

impl State {
    /// How many times the set changed (0 before the first acknowledgement): a cheap check
    /// before [`State::anomaly_acks`].
    pub fn anomaly_acks_version(&self) -> Result<u64> {
        self.with(|c| {
            c.query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [VERSION_KEY],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map(|v| v.and_then(|v| v.parse().ok()).unwrap_or(0))
        })
    }

    /// Every acknowledgement, newest window first.
    pub fn anomaly_acks(&self) -> Result<Vec<AnomalyAck>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, by, at, note, window_start FROM anomaly_acks
                 ORDER BY window_start DESC, id",
            )?;
            st.query_map([], row)?.collect()
        })
    }

    /// Acknowledges findings (one already acknowledged keeps its first acknowledgement), then
    /// prunes old ones. Returns how many were new.
    pub fn ack_anomalies(&self, acks: &[AnomalyAck], now: u64) -> Result<u64> {
        let conn = self.lock();
        let tx = conn.unchecked_transaction()?;
        let mut added = 0;
        {
            let mut st = tx.prepare(
                "INSERT INTO anomaly_acks (id, by, at, note, window_start)
                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(id) DO NOTHING",
            )?;
            for a in acks {
                added += st.execute(params![a.id, a.by, i(a.at), a.note, i(a.window_start)])?;
            }
        }
        let pruned = prune(&tx, now)?;
        if added + pruned > 0 {
            bump(&tx)?;
        }
        tx.commit()?;
        Ok(u64::try_from(added).unwrap_or(0))
    }

    /// Takes acknowledgements back. Returns how many there were.
    pub fn unack_anomalies(&self, ids: &[String]) -> Result<u64> {
        let conn = self.lock();
        let tx = conn.unchecked_transaction()?;
        let mut removed = 0;
        {
            let mut st = tx.prepare("DELETE FROM anomaly_acks WHERE id = ?1")?;
            for id in ids {
                removed += st.execute([id])?;
            }
        }
        if removed > 0 {
            bump(&tx)?;
        }
        tx.commit()?;
        Ok(u64::try_from(removed).unwrap_or(0))
    }

    /// A replica takes the primary's set: afterwards this node has exactly `acks`. Returns
    /// whether anything changed.
    pub fn replace_anomaly_acks(&self, acks: &[AnomalyAck]) -> Result<bool> {
        let before = self.anomaly_acks()?;
        let mut want = acks.to_vec();
        want.sort_by(|a, b| b.window_start.cmp(&a.window_start).then(a.id.cmp(&b.id)));
        if before == want {
            return Ok(false);
        }
        let conn = self.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM anomaly_acks", [])?;
        {
            let mut st = tx.prepare(
                "INSERT INTO anomaly_acks (id, by, at, note, window_start)
                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(id) DO NOTHING",
            )?;
            for a in acks {
                st.execute(params![a.id, a.by, i(a.at), a.note, i(a.window_start)])?;
            }
        }
        bump(&tx)?;
        tx.commit()?;
        Ok(true)
    }
}

/// Drops acknowledgements of findings older than [`KEEP_DAYS`], then all but the newest
/// [`MAX_ACKS`].
fn prune(c: &rusqlite::Connection, now: u64) -> rusqlite::Result<usize> {
    let old = c.execute(
        "DELETE FROM anomaly_acks WHERE window_start < ?1",
        [i(now.saturating_sub(KEEP_DAYS * 86_400))],
    )?;
    let over = c.execute(
        "DELETE FROM anomaly_acks WHERE id NOT IN (
            SELECT id FROM anomaly_acks ORDER BY window_start DESC, id LIMIT ?1)",
        [i(MAX_ACKS)],
    )?;
    Ok(old + over)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack(id: &str, window_start: u64) -> AnomalyAck {
        AnomalyAck {
            id: id.into(),
            by: "alice".into(),
            at: window_start + 60,
            note: None,
            window_start,
        }
    }

    // REQ: OBS-014 — acknowledging is idempotent and keeps the first acknowledgement.
    #[test]
    fn obs_014_ack_unack_round_trip() {
        let s = State::in_memory().unwrap();
        let now = 1_800_000_000;
        assert_eq!(
            s.ack_anomalies(&[ack("a", now), ack("b", now - 10)], now)
                .unwrap(),
            2
        );
        let mut again = ack("a", now);
        again.by = "bob".into();
        assert_eq!(
            s.ack_anomalies(&[again], now).unwrap(),
            0,
            "already acknowledged"
        );
        let all = s.anomaly_acks().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].by, "alice", "the first acknowledgement stays");
        let v = s.anomaly_acks_version().unwrap();
        assert!(v > 0);
        assert_eq!(s.unack_anomalies(&["a".into(), "zzz".into()]).unwrap(), 1);
        assert_eq!(s.anomaly_acks().unwrap().len(), 1);
        assert_eq!(
            s.anomaly_acks_version().unwrap(),
            v + 1,
            "a change bumps the version"
        );
        assert_eq!(s.unack_anomalies(&["zzz".into()]).unwrap(), 0);
        assert_eq!(
            s.anomaly_acks_version().unwrap(),
            v + 1,
            "no change, no bump"
        );
    }

    // REQ: OBS-014 — old acknowledgements go, so the replicated set stays bounded.
    #[test]
    fn obs_014_old_acks_are_pruned() {
        let s = State::in_memory().unwrap();
        let now = 1_800_000_000;
        let old = now - (KEEP_DAYS + 1) * 86_400;
        s.ack_anomalies(&[ack("old", old)], old).unwrap();
        s.ack_anomalies(&[ack("new", now)], now).unwrap();
        let ids: Vec<String> = s
            .anomaly_acks()
            .unwrap()
            .into_iter()
            .map(|a| a.id)
            .collect();
        assert_eq!(ids, ["new"]);
    }

    // REQ: OBS-014, CLU-003 — a replica ends up with exactly the primary's set.
    #[test]
    fn obs_014_replica_takes_the_primarys_set() {
        let s = State::in_memory().unwrap();
        let now = 1_800_000_000;
        s.ack_anomalies(&[ack("mine", now)], now).unwrap();
        let primary = vec![ack("p1", now), ack("p2", now - 5)];
        assert!(s.replace_anomaly_acks(&primary).unwrap());
        assert!(!s.replace_anomaly_acks(&primary).unwrap(), "unchanged");
        let ids: Vec<String> = s
            .anomaly_acks()
            .unwrap()
            .into_iter()
            .map(|a| a.id)
            .collect();
        assert_eq!(ids, ["p1", "p2"]);
        assert!(s.replace_anomaly_acks(&[]).unwrap());
        assert_eq!(s.anomaly_acks().unwrap().len(), 0);
    }
}
