//! The audit log (REQ: API-006, `spec/08` §6, ADR-033): append-only and hash-chained. Each
//! entry's hash is BLAKE3 over the previous entry's hash and the entry's own fields, so any
//! edit, deletion, or reordering breaks the chain at that point and `verify` finds it.
//! SQLite triggers refuse UPDATE and DELETE on the table.

use rusqlite::{OptionalExtension, params};

use super::{Result, State, i, u};

/// Hash of "nothing before": the genesis entry's `prev_hash`.
pub const GENESIS: [u8; 32] = [0; 32];

/// What to record.
#[derive(Debug, Clone, Default)]
pub struct NewAudit<'a> {
    pub ts: u64,
    /// Who: a username, `token:<name> (owner: <user>)`, or `system`/`setup`.
    pub actor: &'a str,
    /// `session`, `token`, `basic`, or `system`.
    pub actor_kind: &'a str,
    pub remote: Option<&'a str>,
    /// Dotted verb: `user.create`, `token.revoke`, `config.reload`, ...
    pub action: &'a str,
    /// What it acted on (a username, a token ID, a config file).
    pub target: &'a str,
    /// JSON object with the details (never secrets).
    pub detail: &'a str,
    /// Why, when the caller said (agents must, AGT-005).
    pub reason: Option<&'a str>,
}

/// A stored entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts: u64,
    pub actor: String,
    pub actor_kind: String,
    pub remote: Option<String>,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub reason: Option<String>,
    pub prev_hash: Vec<u8>,
    pub hash: Vec<u8>,
}

/// Result of checking the whole chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verify {
    pub entries: u64,
    /// The first entry whose hash or link doesn't check out.
    pub first_bad: Option<u64>,
    /// Hash of the newest entry (genesis when empty): publish it to detect truncation.
    pub head: Vec<u8>,
}

/// The chained hash of one entry.
pub fn entry_hash(prev: &[u8], seq: u64, e: &NewAudit<'_>) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(b"telltale-audit-v1");
    h.update(prev);
    h.update(&seq.to_le_bytes());
    h.update(&e.ts.to_le_bytes());
    for field in [
        Some(e.actor),
        Some(e.actor_kind),
        e.remote,
        Some(e.action),
        Some(e.target),
        Some(e.detail),
        e.reason,
    ] {
        match field {
            // A presence byte keeps `None` and `Some("")` apart.
            None => {
                h.update(&[0]);
            }
            Some(s) => {
                h.update(&[1]);
                h.update(&u32::try_from(s.len()).unwrap_or(u32::MAX).to_le_bytes());
                h.update(s.as_bytes());
            }
        }
    }
    h.finalize().as_bytes().to_vec()
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
    Ok(AuditEntry {
        seq: u(r.get(0)?),
        ts: u(r.get(1)?),
        actor: r.get(2)?,
        actor_kind: r.get(3)?,
        remote: r.get(4)?,
        action: r.get(5)?,
        target: r.get(6)?,
        detail: r.get(7)?,
        reason: r.get(8)?,
        prev_hash: r.get(9)?,
        hash: r.get(10)?,
    })
}

const COLUMNS: &str =
    "seq, ts, actor, actor_kind, remote, action, target, detail, reason, prev_hash, hash";

impl State {
    /// Appends an entry, linked to the newest one. Returns it.
    pub fn audit_append(&self, e: &NewAudit<'_>) -> Result<AuditEntry> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            let last: Option<(i64, Vec<u8>)> = tx
                .query_row("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            let (seq, prev) = last.map_or((1, GENESIS.to_vec()), |(s, h)| (u(s) + 1, h));
            let hash = entry_hash(&prev, seq, e);
            tx.execute(
                "INSERT INTO audit (seq, ts, actor, actor_kind, remote, action, target, detail, reason, prev_hash, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    i(seq), i(e.ts), e.actor, e.actor_kind, e.remote, e.action, e.target,
                    e.detail, e.reason, prev, hash
                ],
            )?;
            tx.commit()?;
            Ok(AuditEntry {
                seq,
                ts: e.ts,
                actor: e.actor.to_owned(),
                actor_kind: e.actor_kind.to_owned(),
                remote: e.remote.map(str::to_owned),
                action: e.action.to_owned(),
                target: e.target.to_owned(),
                detail: e.detail.to_owned(),
                reason: e.reason.map(str::to_owned),
                prev_hash: prev,
                hash,
            })
        })
    }

    /// Newest first, entries before `before_seq`; `action` matches a prefix (`user.` or
    /// `user.create`), `actor` exactly.
    pub fn audit_page(
        &self,
        before_seq: Option<u64>,
        limit: usize,
        action: Option<&str>,
        actor: Option<&str>,
    ) -> Result<Vec<AuditEntry>> {
        self.with(|c| {
            let mut q = c.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM audit
                 WHERE seq < ?1 AND (?2 IS NULL OR action = ?2 OR action LIKE ?2 || '%')
                   AND (?3 IS NULL OR actor = ?3)
                 ORDER BY seq DESC LIMIT ?4"
            ))?;
            q.query_map(
                params![
                    i(before_seq.unwrap_or(u64::MAX)),
                    action,
                    actor,
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
                row,
            )?
            .collect()
        })
    }

    /// Recomputes every hash and link, oldest first.
    pub fn audit_verify(&self) -> Result<Verify> {
        self.with(|c| {
            let mut q = c.prepare(&format!("SELECT {COLUMNS} FROM audit ORDER BY seq"))?;
            let mut rows = q.query([])?;
            let mut v = Verify {
                entries: 0,
                first_bad: None,
                head: GENESIS.to_vec(),
            };
            let mut expect_seq = 1u64;
            while let Some(r) = rows.next()? {
                let e = row(r)?;
                v.entries += 1;
                let fields = NewAudit {
                    ts: e.ts,
                    actor: &e.actor,
                    actor_kind: &e.actor_kind,
                    remote: e.remote.as_deref(),
                    action: &e.action,
                    target: &e.target,
                    detail: &e.detail,
                    reason: e.reason.as_deref(),
                };
                let ok = e.seq == expect_seq
                    && e.prev_hash == v.head
                    && entry_hash(&e.prev_hash, e.seq, &fields) == e.hash;
                if !ok && v.first_bad.is_none() {
                    v.first_bad = Some(e.seq);
                }
                expect_seq = e.seq + 1;
                v.head = e.hash;
            }
            Ok(v)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add(s: &State, n: u64, action: &str, actor: &str) {
        s.audit_append(&NewAudit {
            ts: 1_791_072_000 + n,
            actor,
            actor_kind: "session",
            remote: Some("192.168.1.20"),
            action,
            target: "ana",
            detail: "{\"role\":\"viewer\"}",
            reason: None,
        })
        .unwrap();
    }

    // REQ: API-006 — entries chain; filters and paging work; the table is append-only.
    #[test]
    fn api_006_audit_chain_paging_and_append_only() {
        let s = State::in_memory().unwrap();
        assert_eq!(s.audit_verify().unwrap().head, GENESIS.to_vec());
        add(&s, 1, "user.create", "root");
        add(&s, 2, "user.update", "root");
        add(&s, 3, "token.create", "ana");
        let v = s.audit_verify().unwrap();
        assert_eq!((v.entries, v.first_bad), (3, None));
        let page = s.audit_page(None, 2, None, None).unwrap();
        assert_eq!(page.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![3, 2]);
        assert_eq!(page[0].prev_hash, page[1].hash, "linked");
        let older = s.audit_page(Some(2), 10, None, None).unwrap();
        assert_eq!(older.len(), 1);
        assert_eq!(
            s.audit_page(None, 10, Some("user."), None).unwrap().len(),
            2
        );
        assert_eq!(s.audit_page(None, 10, None, Some("ana")).unwrap().len(), 1);
        // Triggers refuse edits and deletes.
        let err = s.with(|c| c.execute("UPDATE audit SET target = 'x' WHERE seq = 2", []));
        assert!(err.is_err(), "update refused");
        let err = s.with(|c| c.execute("DELETE FROM audit WHERE seq = 3", []));
        assert!(err.is_err(), "delete refused");
    }

    // REQ: API-006 — tampering (with the triggers removed) is detected at the edited entry,
    // and deleting the last entry changes the head hash.
    #[test]
    fn api_006_tampering_is_detected() {
        let s = State::in_memory().unwrap();
        for n in 1..=4 {
            add(&s, n, "user.update", "root");
        }
        let head = s.audit_verify().unwrap().head;
        s.with(|c| {
            c.execute_batch(
                "DROP TRIGGER audit_no_update; DROP TRIGGER audit_no_delete;
                 UPDATE audit SET detail = '{\"role\":\"admin\"}' WHERE seq = 2;",
            )
        })
        .unwrap();
        assert_eq!(s.audit_verify().unwrap().first_bad, Some(2));
        let s = State::in_memory().unwrap();
        for n in 1..=4 {
            add(&s, n, "user.update", "root");
        }
        s.with(|c| {
            c.execute_batch("DROP TRIGGER audit_no_delete; DELETE FROM audit WHERE seq = 2;")
        })
        .unwrap();
        assert_eq!(
            s.audit_verify().unwrap().first_bad,
            Some(3),
            "a gap breaks the chain"
        );
        s.with(|c| c.execute_batch("DELETE FROM audit WHERE seq = 4;"))
            .unwrap();
        assert_ne!(
            s.audit_verify().unwrap().head,
            head,
            "truncation changes the head"
        );
    }
}
