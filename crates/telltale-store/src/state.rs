//! `state.db` (`spec/02` §6): users, sessions, API tokens, and recovery codes (API-003), and
//! the audit log (API-006).
//!
//! Pure persistence: secrets arrive already hashed, and policy (password hashing, expiry,
//! roles) lives in `telltale-api`. One connection behind a mutex in WAL mode; every call is
//! a short statement, made from a blocking thread.

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use rusqlite::{Connection, OptionalExtension, params};

/// Schema migrations, applied in order; `meta.schema` records how many ran.
const MIGRATIONS: &[&str] = &[
    // 1: authentication (T3.5).
    "CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        totp_secret BLOB,
        totp_enabled INTEGER NOT NULL DEFAULT 0,
        totp_last_step INTEGER NOT NULL DEFAULT 0,
        allow_basic_api INTEGER NOT NULL DEFAULT 0,
        disabled INTEGER NOT NULL DEFAULT 0,
        created INTEGER NOT NULL,
        password_changed INTEGER NOT NULL
    );
    CREATE TABLE recovery_codes (
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash BLOB NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE sessions (
        id_hash BLOB PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        csrf TEXT NOT NULL,
        created INTEGER NOT NULL,
        expires INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        remote TEXT
    );
    CREATE TABLE tokens (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        secret_hash BLOB NOT NULL,
        scope TEXT NOT NULL,
        expires INTEGER,
        created INTEGER NOT NULL,
        last_used INTEGER
    );",
    // 2: audit log (T3.8, API-006): append-only, hash-chained.
    "CREATE TABLE audit (
        seq INTEGER PRIMARY KEY,
        ts INTEGER NOT NULL,
        actor TEXT NOT NULL,
        actor_kind TEXT NOT NULL,
        remote TEXT,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        detail TEXT NOT NULL,
        reason TEXT,
        prev_hash BLOB NOT NULL,
        hash BLOB NOT NULL
    );
    CREATE INDEX audit_action ON audit(action);
    CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
        BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
    CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
        BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;",
    // 3: OIDC sign-in (T3.6, API-004): users linked to a provider's subject; which provider
    // a session came from (for sign-out at the provider).
    "ALTER TABLE users ADD COLUMN oidc_provider TEXT;
    ALTER TABLE users ADD COLUMN oidc_subject TEXT;
    CREATE UNIQUE INDEX users_oidc ON users(oidc_provider, oidc_subject)
        WHERE oidc_subject IS NOT NULL;
    ALTER TABLE sessions ADD COLUMN oidc_provider TEXT;",
    // 4: config made in the UI/API (T3.10, API-002/010, ADR-040): entries merged with the
    // config files by name; a version for If-Match; replayable responses for Idempotency-Key.
    "CREATE TABLE managed (
        kind TEXT NOT NULL,
        name TEXT NOT NULL,
        body TEXT NOT NULL,
        updated INTEGER NOT NULL,
        updated_by TEXT NOT NULL,
        PRIMARY KEY (kind, name)
    );
    CREATE TABLE idempotency (
        key TEXT PRIMARY KEY,
        request BLOB NOT NULL,
        status INTEGER NOT NULL,
        response TEXT NOT NULL,
        created INTEGER NOT NULL
    );
    INSERT INTO meta (key, value) VALUES ('config_version', '0')
        ON CONFLICT(key) DO NOTHING;",
    // 5: agent tokens (T6.5, AGT-004, ADR-064): fine-grained scopes, an optional group
    // restriction, and a rate limit. User tokens keep `scope` and leave these NULL.
    "ALTER TABLE tokens ADD COLUMN agent_scopes TEXT;
    ALTER TABLE tokens ADD COLUMN agent_group TEXT;
    ALTER TABLE tokens ADD COLUMN agent_rate_per_minute INTEGER;",
    // 6: identity replication (T9.1, ADR-045): where a user or token came from — `local`
    // (made on this node) or `cluster` (the primary's, replicated).
    "ALTER TABLE users ADD COLUMN origin TEXT NOT NULL DEFAULT 'local';
    ALTER TABLE tokens ADD COLUMN origin TEXT NOT NULL DEFAULT 'local';",
    // 7: audit retention (review 06 q2): the last entry removed by a trim, so the chain
    // still verifies from there.
    "CREATE TABLE audit_checkpoint (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        seq INTEGER NOT NULL,
        hash BLOB NOT NULL,
        ts INTEGER NOT NULL
    );",
];

/// Stored for OIDC users: no password matches it (they sign in at their provider).
pub const NO_PASSWORD: &str = "!oidc";

pub mod audit;
pub mod identity;
pub mod managed;
pub use audit::{AuditEntry, NewAudit, Verify};
pub use identity::{IdRecovery, IdToken, IdUser, Identities, ImportReport};
pub use managed::{Managed, ManagedError, Replay};

/// A user row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: i64,
    pub username: String,
    /// PHC-format Argon2id hash.
    pub password_hash: String,
    /// `viewer`, `operator`, or `admin`.
    pub role: String,
    /// TOTP secret (also set while enrollment is pending).
    pub totp_secret: Option<Vec<u8>>,
    pub totp_enabled: bool,
    /// Last accepted TOTP time step (codes from it or earlier are replays).
    pub totp_last_step: u64,
    pub allow_basic_api: bool,
    pub disabled: bool,
    pub created: u64,
    pub password_changed: u64,
    /// The OIDC provider this user signs in with (no local password), if any.
    pub oidc_provider: Option<String>,
}

/// A session row (the session ID itself is never stored, only its hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub user_id: i64,
    pub csrf: String,
    pub created: u64,
    pub expires: u64,
    pub last_seen: u64,
    /// The OIDC provider this session came from, if any.
    pub oidc_provider: Option<String>,
}

/// An API token row (the secret is never stored, only its hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub id: String,
    pub user_id: i64,
    pub name: String,
    pub secret_hash: Vec<u8>,
    /// `read`, `write`, or `admin`.
    pub scope: String,
    pub expires: Option<u64>,
    pub created: u64,
    pub last_used: Option<u64>,
    /// An agent token (AGT-004): its scopes, space-separated. `None` for user tokens.
    pub agent_scopes: Option<String>,
    /// An agent token restricted to one client group.
    pub agent_group: Option<String>,
    /// An agent token's own request limit.
    pub agent_rate_per_minute: Option<u32>,
}

/// Errors from the state database.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("state database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("a user named `{0}` already exists")]
    Duplicate(String),
}

pub type Result<T> = std::result::Result<T, StateError>;

/// The node's `state.db`.
#[derive(Debug)]
pub struct State {
    conn: Mutex<Connection>,
}

fn u(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn i(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

impl State {
    /// Opens (creating if needed) `path` and applies pending migrations.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// A database in memory (tests).
    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            [],
        )?;
        let done: usize = conn
            .query_row("SELECT value FROM meta WHERE key = 'schema'", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        for (n, sql) in MIGRATIONS.iter().enumerate().skip(done) {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(sql)?;
            tx.execute(
                "INSERT INTO meta (key, value) VALUES ('schema', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [(n + 1).to_string()],
            )?;
            tx.commit()?;
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let conn = self.conn.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(f(&conn)?)
    }

    // ---- users

    pub fn user_count(&self) -> Result<u64> {
        self.with(|c| c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0)))
            .map(u)
    }

    /// Enabled admins (the last one can't be removed or demoted).
    pub fn admin_count(&self) -> Result<u64> {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0",
                [],
                |r| r.get::<_, i64>(0),
            )
        })
        .map(u)
    }

    pub fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        role: &str,
        allow_basic_api: bool,
        now: u64,
    ) -> Result<User> {
        let id = self.with(|c| {
            c.execute(
                "INSERT INTO users (username, password_hash, role, allow_basic_api, created, password_changed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                params![username, password_hash, role, allow_basic_api, i(now)],
            )
            .map(|_| c.last_insert_rowid())
        });
        match id {
            Ok(id) => self
                .user(id)?
                .ok_or(StateError::Db(rusqlite::Error::QueryReturnedNoRows)),
            Err(StateError::Db(rusqlite::Error::SqliteFailure(e, _)))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(StateError::Duplicate(username.to_owned()))
            }
            Err(e) => Err(e),
        }
    }

    const USER_COLS: &'static str = "id, username, password_hash, role, totp_secret, totp_enabled, \
        totp_last_step, allow_basic_api, disabled, created, password_changed, oidc_provider";

    fn row_user(r: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
        Ok(User {
            id: r.get(0)?,
            username: r.get(1)?,
            password_hash: r.get(2)?,
            role: r.get(3)?,
            totp_secret: r.get(4)?,
            totp_enabled: r.get(5)?,
            totp_last_step: u(r.get(6)?),
            allow_basic_api: r.get(7)?,
            disabled: r.get(8)?,
            created: u(r.get(9)?),
            password_changed: u(r.get(10)?),
            oidc_provider: r.get(11)?,
        })
    }

    /// The user linked to an OIDC provider's subject.
    pub fn user_by_oidc(&self, provider: &str, subject: &str) -> Result<Option<User>> {
        self.with(|c| {
            c.query_row(
                &format!(
                    "SELECT {} FROM users WHERE oidc_provider = ?1 AND oidc_subject = ?2",
                    Self::USER_COLS
                ),
                [provider, subject],
                Self::row_user,
            )
            .optional()
        })
    }

    /// Creates a user who signs in through `provider` (no usable password).
    pub fn create_oidc_user(
        &self,
        username: &str,
        role: &str,
        provider: &str,
        subject: &str,
        now: u64,
    ) -> Result<User> {
        let user = self.create_user(username, NO_PASSWORD, role, false, now)?;
        self.with(|c| {
            c.execute(
                "UPDATE users SET oidc_provider = ?2, oidc_subject = ?3 WHERE id = ?1",
                params![user.id, provider, subject],
            )
        })?;
        self.user(user.id)?
            .ok_or(StateError::Db(rusqlite::Error::QueryReturnedNoRows))
    }

    pub fn user(&self, id: i64) -> Result<Option<User>> {
        self.with(|c| {
            c.query_row(
                &format!("SELECT {} FROM users WHERE id = ?1", Self::USER_COLS),
                [id],
                Self::row_user,
            )
            .optional()
        })
    }

    /// By username, case-insensitively.
    pub fn user_by_name(&self, username: &str) -> Result<Option<User>> {
        self.with(|c| {
            c.query_row(
                &format!("SELECT {} FROM users WHERE username = ?1", Self::USER_COLS),
                [username],
                Self::row_user,
            )
            .optional()
        })
    }

    pub fn users(&self) -> Result<Vec<User>> {
        self.with(|c| {
            let mut st = c.prepare(&format!(
                "SELECT {} FROM users ORDER BY id",
                Self::USER_COLS
            ))?;
            st.query_map([], Self::row_user)?.collect()
        })
    }

    /// Updates role, disabled, and the HTTP Basic opt-in (whichever are given).
    pub fn update_user(
        &self,
        id: i64,
        role: Option<&str>,
        disabled: Option<bool>,
        allow_basic_api: Option<bool>,
    ) -> Result<bool> {
        self.with(|c| {
            c.execute(
                "UPDATE users SET role = COALESCE(?2, role), disabled = COALESCE(?3, disabled),
                 allow_basic_api = COALESCE(?4, allow_basic_api) WHERE id = ?1",
                params![id, role, disabled, allow_basic_api],
            )
            .map(|n| n == 1)
        })
    }

    pub fn set_password(&self, id: i64, password_hash: &str, now: u64) -> Result<bool> {
        self.with(|c| {
            c.execute(
                "UPDATE users SET password_hash = ?2, password_changed = ?3 WHERE id = ?1",
                params![id, password_hash, i(now)],
            )
            .map(|n| n == 1)
        })
    }

    /// Sets (or clears) the TOTP secret and whether it's enforced.
    pub fn set_totp(&self, id: i64, secret: Option<&[u8]>, enabled: bool) -> Result<bool> {
        self.with(|c| {
            c.execute(
                "UPDATE users SET totp_secret = ?2, totp_enabled = ?3, totp_last_step = 0 WHERE id = ?1",
                params![id, secret, enabled],
            )
            .map(|n| n == 1)
        })
    }

    /// Records an accepted TOTP step; false if `step` isn't newer (a replay).
    pub fn advance_totp_step(&self, id: i64, step: u64) -> Result<bool> {
        self.with(|c| {
            c.execute(
                "UPDATE users SET totp_last_step = ?2 WHERE id = ?1 AND totp_last_step < ?2",
                params![id, i(step)],
            )
            .map(|n| n == 1)
        })
    }

    pub fn delete_user(&self, id: i64) -> Result<bool> {
        self.with(|c| {
            c.execute("DELETE FROM users WHERE id = ?1", [id])
                .map(|n| n == 1)
        })
    }

    // ---- recovery codes

    /// Replaces a user's recovery codes (hashes).
    pub fn set_recovery_codes(&self, user_id: i64, hashes: &[Vec<u8>]) -> Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(PoisonError::into_inner);
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [user_id])?;
        for h in hashes {
            tx.execute(
                "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?1, ?2)",
                params![user_id, h],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Uses up a recovery code; true if it existed and wasn't used before.
    pub fn use_recovery_code(&self, user_id: i64, hash: &[u8]) -> Result<bool> {
        self.with(|c| {
            c.execute(
                "UPDATE recovery_codes SET used = 1 WHERE user_id = ?1 AND code_hash = ?2 AND used = 0",
                params![user_id, hash],
            )
            .map(|n| n == 1)
        })
    }

    pub fn recovery_codes_left(&self, user_id: i64) -> Result<u64> {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?1 AND used = 0",
                [user_id],
                |r| r.get::<_, i64>(0),
            )
        })
        .map(u)
    }

    // ---- sessions

    pub fn create_session(
        &self,
        id_hash: &[u8],
        user_id: i64,
        csrf: &str,
        now: u64,
        expires: u64,
        remote: Option<&str>,
    ) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO sessions (id_hash, user_id, csrf, created, expires, last_seen, remote)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?4, ?6)",
                params![id_hash, user_id, csrf, i(now), i(expires), remote],
            )
            .map(|_| ())
        })
    }

    pub fn session(&self, id_hash: &[u8]) -> Result<Option<Session>> {
        self.with(|c| {
            c.query_row(
                "SELECT user_id, csrf, created, expires, last_seen, oidc_provider FROM sessions WHERE id_hash = ?1",
                [id_hash],
                |r| {
                    Ok(Session {
                        user_id: r.get(0)?,
                        csrf: r.get(1)?,
                        created: u(r.get(2)?),
                        expires: u(r.get(3)?),
                        last_seen: u(r.get(4)?),
                        oidc_provider: r.get(5)?,
                    })
                },
            )
            .optional()
        })
    }

    /// Marks a session as started through an OIDC provider.
    pub fn set_session_provider(&self, id_hash: &[u8], provider: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE sessions SET oidc_provider = ?2 WHERE id_hash = ?1",
                params![id_hash, provider],
            )
            .map(|_| ())
        })
    }

    pub fn touch_session(&self, id_hash: &[u8], now: u64) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE sessions SET last_seen = ?2 WHERE id_hash = ?1",
                params![id_hash, i(now)],
            )
            .map(|_| ())
        })
    }

    pub fn delete_session(&self, id_hash: &[u8]) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM sessions WHERE id_hash = ?1", [id_hash])
                .map(|_| ())
        })
    }

    /// Ends a user's sessions, except `keep` (the one changing the password, say).
    pub fn delete_user_sessions(&self, user_id: i64, keep: Option<&[u8]>) -> Result<u64> {
        self.with(|c| {
            c.execute(
                "DELETE FROM sessions WHERE user_id = ?1 AND (?2 IS NULL OR id_hash != ?2)",
                params![user_id, keep],
            )
        })
        .map(|n| n as u64)
    }

    /// Deletes sessions that expired or were idle since before `idle_before`.
    pub fn purge_sessions(&self, now: u64, idle_before: u64) -> Result<u64> {
        self.with(|c| {
            c.execute(
                "DELETE FROM sessions WHERE expires <= ?1 OR last_seen < ?2",
                params![i(now), i(idle_before)],
            )
        })
        .map(|n| n as u64)
    }

    // ---- tokens

    #[allow(clippy::too_many_arguments)]
    pub fn create_token(
        &self,
        id: &str,
        user_id: i64,
        name: &str,
        secret_hash: &[u8],
        scope: &str,
        expires: Option<u64>,
        now: u64,
    ) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO tokens (id, user_id, name, secret_hash, scope, expires, created)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id,
                    user_id,
                    name,
                    secret_hash,
                    scope,
                    expires.map(i),
                    i(now)
                ],
            )
            .map(|_| ())
        })
    }

    fn row_token(r: &rusqlite::Row<'_>) -> rusqlite::Result<Token> {
        Ok(Token {
            id: r.get(0)?,
            user_id: r.get(1)?,
            name: r.get(2)?,
            secret_hash: r.get(3)?,
            scope: r.get(4)?,
            expires: r.get::<_, Option<i64>>(5)?.map(u),
            created: u(r.get(6)?),
            last_used: r.get::<_, Option<i64>>(7)?.map(u),
            agent_scopes: r.get(8)?,
            agent_group: r.get(9)?,
            agent_rate_per_minute: r
                .get::<_, Option<i64>>(10)?
                .and_then(|n| u32::try_from(n).ok()),
        })
    }

    /// Makes a token an agent token (AGT-004). Called right after `create_token`.
    pub fn set_token_agent(
        &self,
        id: &str,
        scopes: &str,
        group: Option<&str>,
        rate_per_minute: Option<u32>,
    ) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE tokens SET agent_scopes = ?2, agent_group = ?3, agent_rate_per_minute = ?4
                 WHERE id = ?1",
                params![id, scopes, group, rate_per_minute.map(i64::from)],
            )
            .map(|_| ())
        })
    }

    pub fn token(&self, id: &str) -> Result<Option<Token>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, user_id, name, secret_hash, scope, expires, created, last_used,
                        agent_scopes, agent_group, agent_rate_per_minute
                 FROM tokens WHERE id = ?1",
                [id],
                Self::row_token,
            )
            .optional()
        })
    }

    pub fn tokens_for(&self, user_id: i64) -> Result<Vec<Token>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, user_id, name, secret_hash, scope, expires, created, last_used,
                        agent_scopes, agent_group, agent_rate_per_minute
                 FROM tokens WHERE user_id = ?1 ORDER BY created",
            )?;
            st.query_map([user_id], Self::row_token)?.collect()
        })
    }

    pub fn touch_token(&self, id: &str, now: u64) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE tokens SET last_used = ?2 WHERE id = ?1",
                params![id, i(now)],
            )
            .map(|_| ())
        })
    }

    pub fn delete_token(&self, id: &str, user_id: i64) -> Result<bool> {
        self.with(|c| {
            c.execute(
                "DELETE FROM tokens WHERE id = ?1 AND user_id = ?2",
                params![id, user_id],
            )
            .map(|n| n == 1)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_003_users_sessions_tokens_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let s = State::open(&path).unwrap();
        assert_eq!(s.user_count().unwrap(), 0);
        let a = s
            .create_user("Admin", "$argon2id$x", "admin", false, 100)
            .unwrap();
        assert_eq!((a.id, a.role.as_str(), a.created), (1, "admin", 100));
        assert!(
            matches!(
                s.create_user("admin", "h", "viewer", false, 1),
                Err(StateError::Duplicate(_))
            ),
            "usernames are case-insensitive"
        );
        let v = s.create_user("viewer1", "h", "viewer", true, 100).unwrap();
        assert_eq!(s.user_by_name("ADMIN").unwrap().unwrap().id, a.id);
        assert_eq!(s.admin_count().unwrap(), 1);
        assert!(
            s.update_user(v.id, Some("operator"), None, Some(false))
                .unwrap()
        );
        let v = s.user(v.id).unwrap().unwrap();
        assert_eq!(
            (v.role.as_str(), v.allow_basic_api, v.disabled),
            ("operator", false, false)
        );

        // TOTP steps only move forward.
        s.set_totp(a.id, Some(b"secret"), true).unwrap();
        assert!(s.advance_totp_step(a.id, 10).unwrap());
        assert!(!s.advance_totp_step(a.id, 10).unwrap(), "replay");
        assert!(!s.advance_totp_step(a.id, 9).unwrap());
        s.set_recovery_codes(a.id, &[vec![1], vec![2]]).unwrap();
        assert!(s.use_recovery_code(a.id, &[1]).unwrap());
        assert!(!s.use_recovery_code(a.id, &[1]).unwrap(), "single use");
        assert_eq!(s.recovery_codes_left(a.id).unwrap(), 1);

        s.create_session(b"h1", a.id, "csrf", 100, 200, Some("10.0.0.1"))
            .unwrap();
        s.create_session(b"h2", a.id, "csrf2", 100, 200, None)
            .unwrap();
        assert_eq!(s.session(b"h1").unwrap().unwrap().csrf, "csrf");
        assert_eq!(s.delete_user_sessions(a.id, Some(b"h1")).unwrap(), 1);
        assert!(s.session(b"h2").unwrap().is_none());
        assert_eq!(s.purge_sessions(201, 0).unwrap(), 1, "expired");

        s.create_token("t1", v.id, "grafana", b"hash", "read", None, 100)
            .unwrap();
        assert_eq!(s.tokens_for(v.id).unwrap().len(), 1);
        assert!(!s.delete_token("t1", a.id).unwrap(), "only the owner's");
        // Deleting a user cascades to its tokens and sessions.
        assert!(s.delete_user(v.id).unwrap());
        assert!(s.token("t1").unwrap().is_none());
        drop(s);
        // Reopening keeps data and doesn't re-run migrations.
        let s = State::open(&path).unwrap();
        assert_eq!(s.user_count().unwrap(), 1);
    }
}
