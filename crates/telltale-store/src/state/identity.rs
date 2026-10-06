//! Identity replication (REQ: CLU-003, API-003; ADR-045; T9.1): the primary's users, recovery
//! codes, and API tokens as one document, and how a replica takes it in.
//!
//! Only hashes travel (Argon2id password hashes, token and recovery-code hashes) plus TOTP
//! secrets, over the cluster's mTLS channel, as ADR-045 decided. Sessions never travel: each
//! node keeps its own.
//!
//! A replica's rows are marked by `origin`: `cluster` (from the primary) or `local` (made on
//! this node before it joined, or an SSO user it signed in itself). Importing:
//! - upserts every primary user by name, keeping the local row ID (so this node's sessions
//!   stay valid); a `local` user of the same name becomes the primary's (the primary wins);
//! - deletes `cluster` users the primary no longer has (their sessions and tokens go too);
//! - keeps `local` users the primary doesn't have, so nobody is locked out of a node;
//! - upserts the primary's tokens by ID (keeping when this node last saw each used) and
//!   deletes `cluster` tokens it dropped;
//! - replaces the primary users' recovery codes, keeping the ones used on this node used;
//! - never moves a TOTP replay window backwards.

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use super::{Result, State, i, u};

/// A user as replicated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdUser {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    /// Hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    pub totp_last_step: u64,
    pub allow_basic_api: bool,
    pub disabled: bool,
    pub created: u64,
    pub password_changed: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_subject: Option<String>,
}

/// A recovery code as replicated (its owner by the primary's user ID).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdRecovery {
    pub user_id: i64,
    /// Hex.
    pub code_hash: String,
    pub used: bool,
}

/// An API token as replicated (its owner by the primary's user ID).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdToken {
    pub id: String,
    pub user_id: i64,
    pub name: String,
    /// Hex.
    pub secret_hash: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
    pub created: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_scopes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_rate_per_minute: Option<u32>,
}

/// Every identity on the primary, in a stable order (so equal content hashes equally).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identities {
    pub users: Vec<IdUser>,
    pub recovery: Vec<IdRecovery>,
    pub tokens: Vec<IdToken>,
}

/// What an import changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub users_added: usize,
    pub users_updated: usize,
    pub users_removed: usize,
    /// Users only on this node, kept.
    pub local_kept: Vec<String>,
    /// Local users the primary also has: the primary's record replaced them.
    pub replaced_local: Vec<String>,
    pub tokens: usize,
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|k| u8::from_str_radix(s.get(k..k + 2)?, 16).ok())
        .collect()
}

fn bad(what: &str) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(format!("identities: bad {what}"))
}

impl State {
    /// This node's identities, to publish (the primary).
    pub fn export_identities(&self) -> Result<Identities> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, username, password_hash, role, totp_secret, totp_enabled, totp_last_step,
                        allow_basic_api, disabled, created, password_changed, oidc_provider, oidc_subject
                 FROM users ORDER BY id",
            )?;
            let users = st
                .query_map([], |r| {
                    Ok(IdUser {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        password_hash: r.get(2)?,
                        role: r.get(3)?,
                        totp_secret: r.get::<_, Option<Vec<u8>>>(4)?.map(|b| hex(&b)),
                        totp_enabled: r.get(5)?,
                        totp_last_step: u(r.get(6)?),
                        allow_basic_api: r.get(7)?,
                        disabled: r.get(8)?,
                        created: u(r.get(9)?),
                        password_changed: u(r.get(10)?),
                        oidc_provider: r.get(11)?,
                        oidc_subject: r.get(12)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut st = c.prepare(
                "SELECT user_id, code_hash, used FROM recovery_codes ORDER BY user_id, code_hash",
            )?;
            let recovery = st
                .query_map([], |r| {
                    Ok(IdRecovery {
                        user_id: r.get(0)?,
                        code_hash: hex(&r.get::<_, Vec<u8>>(1)?),
                        used: r.get(2)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut st = c.prepare(
                "SELECT id, user_id, name, secret_hash, scope, expires, created,
                        agent_scopes, agent_group, agent_rate_per_minute
                 FROM tokens ORDER BY id",
            )?;
            let tokens = st
                .query_map([], |r| {
                    Ok(IdToken {
                        id: r.get(0)?,
                        user_id: r.get(1)?,
                        name: r.get(2)?,
                        secret_hash: hex(&r.get::<_, Vec<u8>>(3)?),
                        scope: r.get(4)?,
                        expires: r.get::<_, Option<i64>>(5)?.map(u),
                        created: u(r.get(6)?),
                        agent_scopes: r.get(7)?,
                        agent_group: r.get(8)?,
                        agent_rate_per_minute: r
                            .get::<_, Option<i64>>(9)?
                            .and_then(|n| u32::try_from(n).ok()),
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(Identities {
                users,
                recovery,
                tokens,
            })
        })
    }

    /// Takes in the primary's identities (a replica); see the module docs. One transaction:
    /// a bad document changes nothing.
    #[allow(clippy::too_many_lines)] // users, then codes, then tokens, in one transaction
    pub fn import_identities(&self, ids: &Identities) -> Result<ImportReport> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let mut rep = ImportReport::default();
        // The primary's user ID → this node's.
        let mut map = std::collections::HashMap::new();
        for p in &ids.users {
            let secret = match &p.totp_secret {
                Some(h) => Some(unhex(h).ok_or_else(|| bad("TOTP secret"))?),
                None => None,
            };
            let existing: Option<(i64, String, i64)> = tx
                .query_row(
                    "SELECT id, origin, totp_last_step FROM users WHERE username = ?1",
                    [&p.username],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let local_id = if let Some((id, origin, step)) = existing {
                if origin == "local" {
                    rep.replaced_local.push(p.username.clone());
                }
                tx.execute(
                    "UPDATE users SET password_hash = ?2, role = ?3, totp_secret = ?4, totp_enabled = ?5,
                         totp_last_step = ?6, allow_basic_api = ?7, disabled = ?8, created = ?9,
                         password_changed = ?10, oidc_provider = ?11, oidc_subject = ?12,
                         origin = 'cluster'
                     WHERE id = ?1",
                    params![
                        id,
                        p.password_hash,
                        p.role,
                        secret,
                        p.totp_enabled,
                        i(p.totp_last_step).max(step),
                        p.allow_basic_api,
                        p.disabled,
                        i(p.created),
                        i(p.password_changed),
                        p.oidc_provider,
                        p.oidc_subject
                    ],
                )?;
                rep.users_updated += 1;
                id
            } else {
                // A local SSO user may hold the same provider identity under another name.
                tx.execute(
                    "DELETE FROM users WHERE origin = 'local' AND oidc_subject IS NOT NULL
                       AND oidc_provider = ?1 AND oidc_subject = ?2",
                    params![p.oidc_provider, p.oidc_subject],
                )?;
                tx.execute(
                    "INSERT INTO users (username, password_hash, role, totp_secret, totp_enabled,
                         totp_last_step, allow_basic_api, disabled, created, password_changed,
                         oidc_provider, oidc_subject, origin)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'cluster')",
                    params![
                        p.username,
                        p.password_hash,
                        p.role,
                        secret,
                        p.totp_enabled,
                        i(p.totp_last_step),
                        p.allow_basic_api,
                        p.disabled,
                        i(p.created),
                        i(p.password_changed),
                        p.oidc_provider,
                        p.oidc_subject
                    ],
                )?;
                rep.users_added += 1;
                tx.last_insert_rowid()
            };
            map.insert(p.id, local_id);
        }
        // Cluster users the primary dropped (their sessions, tokens, and codes cascade).
        let keep: Vec<i64> = map.values().copied().collect();
        let gone: Vec<i64> = {
            let mut st = tx.prepare("SELECT id FROM users WHERE origin = 'cluster'")?;
            st.query_map([], |r| r.get::<_, i64>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .filter(|id| !keep.contains(id))
                .collect()
        };
        for id in &gone {
            tx.execute("DELETE FROM users WHERE id = ?1", [id])?;
        }
        rep.users_removed = gone.len();
        {
            let mut st =
                tx.prepare("SELECT username FROM users WHERE origin = 'local' ORDER BY username")?;
            rep.local_kept = st
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
        }
        // Recovery codes: the primary's, with any used here staying used.
        for local_id in map.values() {
            let used_here: Vec<Vec<u8>> = {
                let mut st = tx.prepare(
                    "SELECT code_hash FROM recovery_codes WHERE user_id = ?1 AND used = 1",
                )?;
                st.query_map([local_id], |r| r.get::<_, Vec<u8>>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            tx.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [local_id])?;
            for rc in ids
                .recovery
                .iter()
                .filter(|rc| map.get(&rc.user_id) == Some(local_id))
            {
                let h = unhex(&rc.code_hash).ok_or_else(|| bad("recovery code"))?;
                let used = rc.used || used_here.contains(&h);
                tx.execute(
                    "INSERT INTO recovery_codes (user_id, code_hash, used) VALUES (?1, ?2, ?3)",
                    params![local_id, h, used],
                )?;
            }
        }
        // Tokens: the primary's by ID (when this node last saw each used is its own).
        let mut ids_seen = Vec::new();
        for t in &ids.tokens {
            let Some(owner) = map.get(&t.user_id) else {
                continue; // a token of a user the document doesn't have: skip it
            };
            let h = unhex(&t.secret_hash).ok_or_else(|| bad("token hash"))?;
            tx.execute(
                "INSERT INTO tokens (id, user_id, name, secret_hash, scope, expires, created,
                     agent_scopes, agent_group, agent_rate_per_minute, origin)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'cluster')
                 ON CONFLICT(id) DO UPDATE SET user_id = excluded.user_id, name = excluded.name,
                     secret_hash = excluded.secret_hash, scope = excluded.scope,
                     expires = excluded.expires, created = excluded.created,
                     agent_scopes = excluded.agent_scopes, agent_group = excluded.agent_group,
                     agent_rate_per_minute = excluded.agent_rate_per_minute, origin = 'cluster'",
                params![
                    t.id,
                    owner,
                    t.name,
                    h,
                    t.scope,
                    t.expires.map(i),
                    i(t.created),
                    t.agent_scopes,
                    t.agent_group,
                    t.agent_rate_per_minute.map(i64::from)
                ],
            )?;
            ids_seen.push(t.id.clone());
        }
        let stale: Vec<String> = {
            let mut st = tx.prepare("SELECT id FROM tokens WHERE origin = 'cluster'")?;
            st.query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .filter(|id| !ids_seen.contains(id))
                .collect()
        };
        for id in &stale {
            tx.execute("DELETE FROM tokens WHERE id = ?1", [id])?;
        }
        rep.tokens = ids_seen.len();
        tx.commit()?;
        Ok(rep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn primary() -> State {
        let s = State::in_memory().unwrap();
        let a = s
            .create_user("admin", "$argon2id$a", "admin", false, 10)
            .unwrap()
            .id;
        let b = s
            .create_user("alice", "$argon2id$b", "viewer", false, 11)
            .unwrap()
            .id;
        s.set_totp(b, Some(&[1, 2, 3, 250]), true).unwrap();
        s.set_recovery_codes(b, &[vec![9, 9], vec![8, 8]]).unwrap();
        s.create_token("tok1", a, "ci", &[7; 32], "read", None, 20)
            .unwrap();
        s.create_token("tok2", b, "agent", &[6; 32], "read", Some(99), 21)
            .unwrap();
        s.set_token_agent("tok2", "analytics:read", Some("kids"), Some(30))
            .unwrap();
        s
    }

    /// REQ: CLU-003, API-003 (T9.1) — a replica takes the primary's users, codes, and
    /// tokens; its own users stay; the primary wins a name both have.
    #[test]
    fn clu_003_identities_replicate() {
        let p = primary();
        let doc = p.export_identities().unwrap();
        assert_eq!(doc.users.len(), 2);
        assert_eq!(doc.tokens.len(), 2);

        let r = State::in_memory().unwrap();
        let own = r
            .create_user("pi-admin", "$argon2id$pi", "admin", false, 5)
            .unwrap()
            .id;
        r.create_user("alice", "$argon2id$other", "admin", false, 6)
            .unwrap();
        r.create_session(&[1; 32], own, "csrf", 5, 1000, None)
            .unwrap();
        let rep = r.import_identities(&doc).unwrap();
        assert_eq!((rep.users_added, rep.users_updated), (1, 1));
        assert_eq!(rep.local_kept, vec!["pi-admin".to_owned()]);
        assert_eq!(rep.replaced_local, vec!["alice".to_owned()]);
        let alice = r.user_by_name("alice").unwrap().unwrap();
        assert_eq!(
            (alice.password_hash.as_str(), alice.role.as_str()),
            ("$argon2id$b", "viewer")
        );
        assert_eq!(alice.totp_secret.as_deref(), Some(&[1, 2, 3, 250][..]));
        assert_eq!(r.recovery_codes_left(alice.id).unwrap(), 2);
        let t = r.token("tok2").unwrap().unwrap();
        assert_eq!(
            (t.user_id, t.agent_group.as_deref(), t.expires),
            (alice.id, Some("kids"), Some(99))
        );
        assert!(
            r.session(&[1; 32]).unwrap().is_some(),
            "this node's sessions stay"
        );

        // Idempotent; a code used here stays used; when a token was used here is kept.
        assert!(r.use_recovery_code(alice.id, &[9, 9]).unwrap());
        r.touch_token("tok1", 500).unwrap();
        r.import_identities(&doc).unwrap();
        assert_eq!(r.recovery_codes_left(alice.id).unwrap(), 1);
        assert_eq!(r.token("tok1").unwrap().unwrap().last_used, Some(500));

        // The primary drops alice and tok1: gone here too, with her tokens.
        let admin = p.user_by_name("admin").unwrap().unwrap().id;
        assert!(p.delete_token("tok1", admin).unwrap());
        let a = p.user_by_name("alice").unwrap().unwrap();
        p.delete_user(a.id).unwrap();
        let rep = r
            .import_identities(&p.export_identities().unwrap())
            .unwrap();
        assert_eq!(rep.users_removed, 1);
        assert!(r.user_by_name("alice").unwrap().is_none());
        assert!(r.token("tok1").unwrap().is_none() && r.token("tok2").unwrap().is_none());
        assert!(r.user_by_name("pi-admin").unwrap().is_some());
    }

    /// REQ: CLU-003 (T9.1) — a damaged document changes nothing.
    #[test]
    fn clu_003_bad_identities_change_nothing() {
        let p = primary();
        let mut doc = p.export_identities().unwrap();
        doc.tokens[0].secret_hash = "zz".into();
        let r = State::in_memory().unwrap();
        assert!(r.import_identities(&doc).is_err());
        assert_eq!(r.user_count().unwrap(), 0);
    }
}
