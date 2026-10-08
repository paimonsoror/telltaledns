//! Authentication and authorization (REQ: API-003, `spec/08` §6).
//!
//! Local users with Argon2id passwords; UI sessions (cookie + CSRF token); API tokens
//! (`Authorization: Bearer tt_<id>_<secret>`, scoped); opt-in HTTP Basic for scrapers and
//! scripts (refused over plain HTTP unless allowed, verified results cached for 60 s); TOTP
//! with single-use recovery codes; login lockout; roles `viewer` < `operator` < `admin`.
//! First run: no default password, a one-time setup token creates the first admin.

pub mod agent;
pub mod crypto;
pub mod oidc;
pub mod routes;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use telltale_store::state::{NewAudit, State, StateError, User};
use utoipa::ToSchema;

use crate::problem::{Code, Problem};

/// What a user may do (`spec/08` §6).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Dashboards and the query log (subject to the privacy level).
    Viewer,
    /// Viewer, plus pause, cache flush, and managing lists, clients, and groups.
    Operator,
    /// Everything, including users, upstreams, and cluster.
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(Self::Viewer),
            "operator" => Some(Self::Operator),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }
}

/// An API token's scope; a token never exceeds its owner's role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Read-only (acts as `viewer`).
    Read,
    /// Read and change (acts as `operator`).
    Write,
    /// Everything the owner can do (acts as `admin`).
    Admin,
}

impl Scope {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }
    const fn role(self) -> Role {
        match self {
            Self::Read => Role::Viewer,
            Self::Write => Role::Operator,
            Self::Admin => Role::Admin,
        }
    }
}

/// How a request authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Via {
    /// UI session: the session ID's hash, and its CSRF token.
    Session {
        id_hash: Vec<u8>,
        csrf: String,
    },
    Token {
        id: String,
    },
    Basic,
}

/// What an agent token may do (REQ: AGT-004, ADR-064).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentGrant {
    pub token_name: String,
    pub scopes: std::collections::BTreeSet<String>,
    /// Restricted to this client group.
    pub group: Option<String>,
    pub rate_per_minute: Option<u32>,
    /// The agent software, from `X-Telltale-Client` (e.g. an MCP client name/version).
    pub client: Option<String>,
}

/// Who is making a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub user_id: i64,
    pub username: String,
    /// The user's role, capped by a token's scope (or an agent token's scopes).
    pub role: Role,
    pub via: Via,
    /// Set for agent tokens: what they may do, checked on every request.
    pub agent: Option<AgentGrant>,
}

/// Who did something, for the audit log (REQ: API-006, AGT-005 attribution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    /// A username, `token:<name> (owner: <user>)`, or a system name.
    pub name: String,
    /// `session`, `token`, `basic`, or `system`.
    pub kind: &'static str,
    pub remote: Option<String>,
    /// From the `X-Telltale-Reason` header, when sent.
    pub reason: Option<String>,
}

impl Actor {
    pub fn system(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            kind: "system",
            remote: None,
            reason: None,
        }
    }
}

/// Settings from `[auth]`.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Absolute session lifetime.
    pub session_ttl_secs: u64,
    /// Sessions unused for this long end.
    pub session_idle_secs: u64,
    /// Accept HTTP Basic over plain HTTP (off: Basic only over HTTPS).
    pub allow_insecure_basic: bool,
    /// Roles that must use TOTP to sign in.
    pub totp_required_roles: Vec<Role>,
    /// Where the first-run setup token is kept (`<data_dir>/setup-token`); deleted once
    /// setup is done.
    pub setup_token_file: Option<std::path::PathBuf>,
    /// OIDC only: password sign-in and HTTP Basic just for admins from `admin_networks`
    /// (break-glass, API-004).
    pub disable_local_login: bool,
    /// `(network, prefix length)`.
    pub admin_networks: Vec<(IpAddr, u8)>,
    /// Proxies (ingress, reverse proxy) whose `X-Forwarded-For` names the real client.
    pub trusted_proxies: Vec<(IpAddr, u8)>,
}

/// `ip` is inside `net/len` (IPv4-mapped IPv6 addresses match IPv4 networks).
pub fn in_network(ip: IpAddr, net: IpAddr, len: u8) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    };
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let m = u32::MAX
                .checked_shl(32 - u32::from(len.min(32)))
                .unwrap_or(0);
            u32::from(a) & m == u32::from(n) & m
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let m = u128::MAX
                .checked_shl(128 - u32::from(len.min(128)))
                .unwrap_or(0);
            u128::from(a) & m == u128::from(n) & m
        }
        _ => false,
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            session_ttl_secs: 7 * 86_400,
            session_idle_secs: 86_400,
            allow_insecure_basic: false,
            totp_required_roles: Vec::new(),
            setup_token_file: None,
            disable_local_login: false,
            admin_networks: Vec::new(),
            trusted_proxies: Vec::new(),
        }
    }
}

/// Login lockout: after this many failures for a username or an address, each further
/// attempt waits `30 s × 2^(n - FREE)`, at most 15 minutes. Counts reset after 15 quiet minutes
/// or a successful login.
const FREE_ATTEMPTS: u32 = 5;
const MAX_LOCK_SECS: u64 = 900;
const BASIC_CACHE_SECS: u64 = 60;
/// REQ: API-003, `02 §8` — password checks run at most this many at a time: each Argon2id
/// verification takes 19 MiB, and the blocking pool would otherwise let hundreds run at once.
const MAX_PASSWORD_CHECKS: u32 = 4;

#[derive(Debug, Default, Clone, Copy)]
struct Failures {
    count: u32,
    last: u64,
    locked_until: u64,
}

/// The authentication service.
#[derive(Debug)]
pub struct Auth {
    state: Arc<State>,
    settings: Settings,
    /// The one-time first-run token, while no user exists.
    setup_token: Mutex<Option<String>>,
    failures: Mutex<HashMap<String, Failures>>,
    /// Verified Basic credentials: hash → (user ID, expiry), so scrapes don't pay Argon2.
    basic_cache: Mutex<HashMap<Vec<u8>, (i64, u64)>>,
    basic_salt: [u8; 16],
    /// OIDC providers, when configured (API-004).
    oidc: std::sync::OnceLock<Arc<oidc::Oidc>>,
    /// `[agents]`: the kill switch and rate limits (AGT-009).
    agents: agent::Policy,
    /// REQ: AGT-007 — agents' change plans on this node.
    plans: crate::plans::Plans,
    /// REQ: CLU-003 (T9.1, ADR-045) — set on a replica: users and tokens come from this
    /// primary (its UI address), so changing them here is refused.
    identity_primary: Mutex<Option<String>>,
    /// Password checks in flight (at most [`MAX_PASSWORD_CHECKS`]).
    password_checks: std::sync::atomic::AtomicU32,
}

/// A slot for one password check; given back when dropped.
#[derive(Debug)]
struct PasswordCheck<'a>(&'a std::sync::atomic::AtomicU32);

impl Drop for PasswordCheck<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

#[allow(clippy::needless_pass_by_value)] // used as `map_err(db)`
fn db(e: StateError) -> Problem {
    Problem::internal(format!("{e}"))
}

/// Rejects names that are empty, too long, or not printable ASCII-ish.
pub fn valid_username(name: &str) -> Result<(), Problem> {
    let ok = (1..=64).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || "._-@".contains(c));
    if ok {
        Ok(())
    } else {
        Err(Problem::invalid(
            "username: 1-64 letters, digits, or . _ - @",
        ))
    }
}

pub fn valid_password(pw: &str) -> Result<(), Problem> {
    let n = pw.chars().count();
    if (crypto::MIN_PASSWORD..=crypto::MAX_PASSWORD).contains(&n) {
        Ok(())
    } else {
        Err(Problem::invalid(format!(
            "password: {}-{} characters",
            crypto::MIN_PASSWORD,
            crypto::MAX_PASSWORD
        ))
        .hint("Use a long passphrase; length matters more than symbols."))
    }
}

/// A new UI session: the cookie value (only the client keeps it) and its CSRF token.
#[derive(Debug, Clone)]
pub struct NewSession {
    pub cookie: String,
    pub csrf: String,
    pub expires: u64,
}

/// Credentials found on a request.
#[derive(Debug, Default)]
pub struct Presented<'a> {
    pub session: Option<&'a str>,
    pub bearer: Option<&'a str>,
    /// Decoded `user:password` from `Authorization: Basic`.
    pub basic: Option<(String, String)>,
    /// The request arrived over HTTPS (directly or via a proxy that said so).
    pub https: bool,
    /// The client's address (break-glass checks and lockouts for HTTP Basic).
    pub remote: Option<IpAddr>,
}

impl Auth {
    pub fn new(state: Arc<State>, settings: Settings) -> Self {
        Self {
            state,
            settings,
            setup_token: Mutex::new(None),
            failures: Mutex::new(HashMap::new()),
            basic_cache: Mutex::new(HashMap::new()),
            basic_salt: rand::random(),
            oidc: std::sync::OnceLock::new(),
            agents: agent::Policy::default(),
            plans: crate::plans::Plans::default(),
            identity_primary: Mutex::new(None),
            password_checks: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// REQ: CLU-003 (T9.1) — the replication sets where identities come from (`None`: here).
    pub fn set_identity_primary(&self, primary: Option<String>) {
        *self
            .identity_primary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = primary;
    }

    /// Where users and tokens are managed when it isn't this node (a replica).
    pub fn identity_primary(&self) -> Option<String> {
        self.identity_primary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// REQ: CLU-003 (T9.1, ADR-045) — refuses identity changes on a replica: they'd be undone
    /// by the next sync from the primary.
    pub fn identity_writable(&self) -> Result<(), Problem> {
        match self.identity_primary() {
            None => Ok(()),
            Some(primary) => Err(Problem::new(
                crate::problem::Code::Conflict,
                "users, passwords, two-factor settings, and tokens are managed on the cluster's primary",
            )
            .hint(if primary.is_empty() {
                "Make this change on the primary node; it reaches this node within seconds.".to_owned()
            } else {
                format!("Make this change on the primary ({primary}); it reaches this node within seconds.")
            })),
        }
    }

    /// REQ: AGT-007 — agents' change plans (MCP `plan_*` tools, `apply_plan`).
    pub fn plans(&self) -> &crate::plans::Plans {
        &self.plans
    }

    /// The agent kill switch and rate limits; the server updates them from `[agents]`.
    pub fn agents(&self) -> &agent::Policy {
        &self.agents
    }

    pub fn state(&self) -> &Arc<State> {
        &self.state
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Attaches OIDC providers (once, at startup).
    pub fn set_oidc(&self, o: oidc::Oidc) {
        let _ = self.oidc.set(Arc::new(o));
    }

    pub fn oidc(&self) -> Option<&Arc<oidc::Oidc>> {
        self.oidc.get()
    }

    /// Password sign-in (and HTTP Basic) may be tried from `ip`: always, unless local
    /// sign-in is off, then only from the break-glass admin networks.
    pub fn local_login_allowed(&self, ip: IpAddr) -> bool {
        !self.settings.disable_local_login
            || self
                .settings
                .admin_networks
                .iter()
                .any(|(n, l)| in_network(ip, *n, *l))
    }

    fn local_login_refused() -> Problem {
        Problem::new(Code::Forbidden, "password sign-in is off on this server")
            .hint("Use your sign-in provider. Admins can still sign in with a password from the break-glass networks.")
    }

    /// True while no user exists (the UI shows the setup screen).
    pub fn setup_required(&self) -> Result<bool, Problem> {
        Ok(self.state.user_count().map_err(db)? == 0)
    }

    /// Creates (once) and returns the first-run setup token, if setup is still required.
    pub fn setup_token(&self) -> Result<Option<String>, Problem> {
        if !self.setup_required()? {
            *self
                .setup_token
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = None;
            return Ok(None);
        }
        let mut t = self
            .setup_token
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Ok(Some(t.get_or_insert_with(crypto::random_secret).clone()))
    }

    /// Uses `token` as the first-run setup token (the server keeps it in a file so that
    /// `telltale auth setup-token` can print it).
    pub fn set_setup_token(&self, token: String) {
        *self
            .setup_token
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(token);
    }

    /// Creates the first admin from deployment secrets (`spec/08` §6: "the Helm chart can
    /// set a bootstrap admin from a Secret"), with a password or an Argon2id PHC hash. Does
    /// nothing once any user exists. Blocking.
    pub fn bootstrap_admin(
        &self,
        username: &str,
        password: Option<&str>,
        password_hash: Option<&str>,
        now: u64,
    ) -> Result<Option<User>, Problem> {
        if !self.setup_required()? {
            return Ok(None);
        }
        let user = match (password, password_hash) {
            (_, Some(hash)) => {
                valid_username(username)?;
                crypto::check_phc(hash)?;
                self.state
                    .create_user(username, hash.trim(), Role::Admin.as_str(), false, now)
                    .map_err(db)?
            }
            (Some(pw), None) => self.create_user(username, pw, Role::Admin, false, now)?,
            (None, None) => {
                return Err(Problem::invalid(
                    "the bootstrap admin needs a password or a password hash",
                ));
            }
        };
        self.setup_done();
        self.record(
            &Actor::system("bootstrap"),
            "user.create",
            &user.username,
            &serde_json::json!({ "role": "admin", "firstRun": true, "from": "environment" }),
        );
        Ok(Some(user))
    }

    fn setup_done(&self) {
        *self
            .setup_token
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        if let Some(f) = &self.settings.setup_token_file {
            let _ = std::fs::remove_file(f);
        }
    }

    /// Ends expired and idle sessions. Blocking.
    pub fn purge_sessions(&self, now: u64) -> Result<u64, Problem> {
        self.state
            .purge_sessions(now, now.saturating_sub(self.settings.session_idle_secs))
            .map_err(db)
    }

    /// Creates a user (validates, hashes the password). Blocking.
    pub fn create_user(
        &self,
        username: &str,
        password: &str,
        role: Role,
        allow_basic_api: bool,
        now: u64,
    ) -> Result<User, Problem> {
        valid_username(username)?;
        valid_password(password)?;
        let hash = crypto::hash_password(password).map_err(Problem::internal)?;
        self.state
            .create_user(username, &hash, role.as_str(), allow_basic_api, now)
            .map_err(|e| match e {
                StateError::Duplicate(n) => {
                    Problem::new(Code::Conflict, format!("a user named `{n}` already exists"))
                }
                e @ StateError::Db(_) => db(e),
            })
    }

    /// First run: the setup token creates the first admin. Blocking.
    pub fn setup(
        &self,
        token: &str,
        username: &str,
        password: &str,
        now: u64,
    ) -> Result<User, Problem> {
        let expected = self.setup_token()?.ok_or_else(|| {
            Problem::new(Code::Conflict, "setup is already done")
                .hint("Sign in instead; an admin can add users.")
        })?;
        if !crypto::ct_eq(token.trim().as_bytes(), expected.as_bytes()) {
            return Err(Problem::new(Code::Unauthorized, "the setup token is wrong")
                .hint("It's in the server log and in <data_dir>/setup-token."));
        }
        let user = self.create_user(username, password, Role::Admin, false, now)?;
        self.setup_done();
        self.record(
            &Actor::system("setup-token"),
            "user.create",
            &user.username,
            &serde_json::json!({ "role": "admin", "firstRun": true }),
        );
        Ok(user)
    }

    /// REQ: API-003, `02 §8` — a slot for one password check, or "busy" (503 with
    /// Retry-After) when [`MAX_PASSWORD_CHECKS`] are running: a burst of sign-in attempts
    /// costs a bounded amount of memory instead of taking the node (and DNS) with it.
    fn password_check(&self) -> Result<PasswordCheck<'_>, Problem> {
        use std::sync::atomic::Ordering;
        if self.password_checks.fetch_add(1, Ordering::AcqRel) >= MAX_PASSWORD_CHECKS {
            self.password_checks.fetch_sub(1, Ordering::AcqRel);
            return Err(Problem::unavailable(
                "the server is busy checking other sign-ins; try again in a moment",
            )
            .retry_after(1));
        }
        Ok(PasswordCheck(&self.password_checks))
    }

    /// Seconds until `key` may try again, if it's locked.
    fn locked(&self, key: &str, now: u64) -> Option<u64> {
        let f = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        f.get(key)
            .filter(|x| x.locked_until > now)
            .map(|x| x.locked_until - now)
    }

    fn fail(&self, key: &str, now: u64) {
        let locked = {
            let mut map = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
            let f = map.entry(key.to_owned()).or_default();
            if now.saturating_sub(f.last) > MAX_LOCK_SECS {
                *f = Failures::default();
            }
            f.count += 1;
            f.last = now;
            let mut locked = None;
            if f.count > FREE_ATTEMPTS {
                let exp = (f.count - FREE_ATTEMPTS - 1).min(10);
                f.locked_until = now + (30u64 << exp).min(MAX_LOCK_SECS);
                locked = Some((f.count, f.locked_until - now));
            }
            // Bound the map: forget the stalest entries when an address sprays usernames.
            if map.len() > 10_000 {
                map.retain(|_, v| now.saturating_sub(v.last) <= MAX_LOCK_SECS);
            }
            locked
        };
        // REQ: API-006 — the first lock of a run is audited (not every failed attempt).
        if let Some((count, secs)) = locked.filter(|(c, _)| *c == FREE_ATTEMPTS + 1) {
            let (field, value) = key.split_once(':').map_or(("key", key), |(k, v)| {
                (if k == "u" { "username" } else { "address" }, v)
            });
            self.record(
                &Actor::system("lockout"),
                "auth.lockout",
                value,
                &serde_json::json!({ field: value, "failures": count, "lockedSeconds": secs }),
            );
        }
    }

    fn succeed(&self, key: &str) {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
    }

    /// Password (+ second factor) sign-in. Returns the user on success. Blocking.
    pub fn login(
        &self,
        username: &str,
        password: &str,
        totp: Option<&str>,
        recovery: Option<&str>,
        remote: IpAddr,
        now: u64,
    ) -> Result<User, Problem> {
        // REQ: API-004 — with local sign-in off, only break-glass admins get this far.
        if !self.local_login_allowed(remote) {
            return Err(Self::local_login_refused());
        }
        let ukey = format!("u:{}", username.to_lowercase());
        let akey = format!("a:{remote}");
        if let Some(wait) = self.locked(&ukey, now).max(self.locked(&akey, now)) {
            return Err(Problem::new(
                Code::RateLimited,
                format!("too many failed sign-ins; try again in {wait} s"),
            ));
        }
        let user = self.state.user_by_name(username).map_err(db)?;
        let ok = {
            let _slot = self.password_check()?;
            match &user {
                Some(u) if !u.disabled => crypto::verify_password(password, &u.password_hash),
                _ => {
                    crypto::dummy_verify(password);
                    false
                }
            }
        };
        let Some(user) = user.filter(|_| ok) else {
            self.fail(&ukey, now);
            self.fail(&akey, now);
            return Err(Problem::new(
                Code::Unauthorized,
                "wrong username or password",
            ));
        };
        let role = Role::parse(&user.role).unwrap_or(Role::Viewer);
        if self.settings.disable_local_login && role != Role::Admin {
            return Err(Self::local_login_refused());
        }
        let must_totp = user.totp_enabled || self.settings.totp_required_roles.contains(&role);
        if must_totp {
            self.second_factor(&user, totp, recovery, now)
                .inspect_err(|e| {
                    if e.code != Code::TotpRequired {
                        self.fail(&ukey, now);
                        self.fail(&akey, now);
                    }
                })?;
        }
        self.succeed(&ukey);
        self.succeed(&akey);
        Ok(user)
    }

    fn second_factor(
        &self,
        user: &User,
        totp: Option<&str>,
        recovery: Option<&str>,
        now: u64,
    ) -> Result<(), Problem> {
        if !user.totp_enabled {
            return Err(
                Problem::new(Code::Forbidden, "this role must use two-factor sign-in")
                    .hint("Ask an admin to enroll TOTP for this account, or to change the policy."),
            );
        }
        if let Some(code) = recovery.filter(|c| !c.trim().is_empty()) {
            return if self
                .state
                .use_recovery_code(user.id, &crypto::recovery_hash(code))
                .map_err(db)?
            {
                Ok(())
            } else {
                Err(Problem::new(
                    Code::Unauthorized,
                    "wrong or used recovery code",
                ))
            };
        }
        let Some(code) = totp.filter(|c| !c.trim().is_empty()) else {
            return Err(Problem::new(
                Code::TotpRequired,
                "enter the code from your authenticator app",
            )
            .hint(
                "Send `totp` (6 digits) or `recoveryCode` with the same username and password.",
            ));
        };
        let secret = user.totp_secret.as_deref().unwrap_or_default();
        match crypto::totp_step(secret, code, now) {
            // A code is accepted once: its step must be newer than the last one used.
            Some(step) if self.state.advance_totp_step(user.id, step).map_err(db)? => Ok(()),
            _ => Err(Problem::new(Code::Unauthorized, "wrong or reused code")),
        }
    }

    /// Starts a UI session for `user`. Blocking.
    pub fn start_session(
        &self,
        user: &User,
        remote: IpAddr,
        now: u64,
    ) -> Result<NewSession, Problem> {
        let cookie = crypto::random_secret();
        let csrf = crypto::random_secret();
        let expires = now + self.settings.session_ttl_secs;
        self.state
            .create_session(
                &crypto::secret_hash(&cookie),
                user.id,
                &csrf,
                now,
                expires,
                Some(&remote.to_string()),
            )
            .map_err(db)?;
        let _ = self
            .state
            .purge_sessions(now, now.saturating_sub(self.settings.session_idle_secs));
        Ok(NewSession {
            cookie,
            csrf,
            expires,
        })
    }

    pub fn end_session(&self, id_hash: &[u8]) -> Result<(), Problem> {
        self.state.delete_session(id_hash).map_err(db)
    }

    /// Who presented these credentials (`None`: no credentials at all). Bearer and Basic
    /// take precedence over a session cookie. Blocking.
    pub fn authenticate(&self, p: &Presented<'_>, now: u64) -> Result<Option<Principal>, Problem> {
        if let Some(t) = p.bearer {
            return self.by_token(t, now).map(Some);
        }
        if let Some((user, pass)) = &p.basic {
            if self.settings.disable_local_login
                && !p.remote.is_some_and(|ip| self.local_login_allowed(ip))
            {
                return Err(Self::local_login_refused());
            }
            let who = self.by_basic(user, pass, p.https, p.remote, now)?;
            if self.settings.disable_local_login && who.role != Role::Admin {
                return Err(Self::local_login_refused());
            }
            return Ok(Some(who));
        }
        match p.session {
            Some(c) => self.by_session(c, now),
            None => Ok(None),
        }
    }

    fn active_user(&self, id: i64) -> Result<User, Problem> {
        self.state
            .user(id)
            .map_err(db)?
            .filter(|u| !u.disabled)
            .ok_or_else(|| Problem::new(Code::Unauthorized, "this account is disabled or gone"))
    }

    fn by_session(&self, cookie: &str, now: u64) -> Result<Option<Principal>, Problem> {
        let id_hash = crypto::secret_hash(cookie);
        let Some(s) = self.state.session(&id_hash).map_err(db)? else {
            return Ok(None); // a stale cookie is just "not signed in"
        };
        if s.expires <= now || now.saturating_sub(s.last_seen) > self.settings.session_idle_secs {
            let _ = self.state.delete_session(&id_hash);
            return Ok(None);
        }
        let user = self.active_user(s.user_id)?;
        // Touch at most once a minute: reads stay reads.
        if now.saturating_sub(s.last_seen) >= 60 {
            let _ = self.state.touch_session(&id_hash, now);
        }
        Ok(Some(Principal {
            user_id: user.id,
            role: Role::parse(&user.role).unwrap_or(Role::Viewer),
            username: user.username,
            via: Via::Session {
                id_hash,
                csrf: s.csrf,
            },
            agent: None,
        }))
    }

    fn by_token(&self, presented: &str, now: u64) -> Result<Principal, Problem> {
        let bad = || {
            Problem::new(Code::Unauthorized, "invalid or expired API token")
                .hint("Tokens look like tt_<id>_<secret>; create one at POST /api/v1/tokens.")
        };
        let rest = presented.trim().strip_prefix("tt_").ok_or_else(bad)?;
        let (id, secret) = rest.split_at_checked(16).ok_or_else(bad)?;
        let secret = secret.strip_prefix('_').ok_or_else(bad)?;
        let token = self.state.token(id).map_err(db)?.ok_or_else(bad)?;
        if !crypto::ct_eq(&crypto::secret_hash(secret), &token.secret_hash)
            || token.expires.is_some_and(|e| e <= now)
        {
            return Err(bad());
        }
        let user = self.active_user(token.user_id)?;
        let user_role = Role::parse(&user.role).unwrap_or(Role::Viewer);
        if token.last_used.is_none_or(|t| now.saturating_sub(t) >= 60) {
            let _ = self.state.touch_token(id, now);
        }
        // REQ: AGT-004 — an agent token acts with its scopes, never above its owner.
        let (role, agent) = match &token.agent_scopes {
            Some(list) => {
                let scopes: std::collections::BTreeSet<String> =
                    list.split_whitespace().map(str::to_owned).collect();
                let role = user_role.min(agent::implied_role(&scopes));
                let grant = AgentGrant {
                    token_name: token.name.clone(),
                    scopes,
                    group: token.agent_group.clone(),
                    rate_per_minute: token.agent_rate_per_minute,
                    client: None,
                };
                (role, Some(grant))
            }
            None => (
                user_role.min(Scope::parse(&token.scope).unwrap_or(Scope::Read).role()),
                None,
            ),
        };
        Ok(Principal {
            user_id: user.id,
            username: user.username,
            role,
            via: Via::Token { id: id.to_owned() },
            agent,
        })
    }

    fn by_basic(
        &self,
        username: &str,
        password: &str,
        https: bool,
        remote: Option<IpAddr>,
        now: u64,
    ) -> Result<Principal, Problem> {
        if !https && !self.settings.allow_insecure_basic {
            return Err(
                Problem::new(Code::Unauthorized, "HTTP Basic is refused over plain HTTP")
                    .hint("Use HTTPS, an API token, or set [auth] allow_insecure_basic = true."),
            );
        }
        let mut k = Vec::with_capacity(16 + username.len() + password.len() + 1);
        k.extend_from_slice(&self.basic_salt);
        k.extend_from_slice(username.to_lowercase().as_bytes());
        k.push(0);
        k.extend_from_slice(password.as_bytes());
        let key = blake3::hash(&k).as_bytes().to_vec();
        let cached = {
            let c = self
                .basic_cache
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            c.get(&key).filter(|(_, exp)| *exp > now).map(|(id, _)| *id)
        };
        let user = if let Some(id) = cached {
            self.active_user(id)?
        } else {
            // REQ: API-003 (ADR-029) — as for the sign-in form: the username and the address.
            let ukey = format!("u:{}", username.to_lowercase());
            let akey = remote.map(|ip| format!("a:{ip}"));
            let locked = self
                .locked(&ukey, now)
                .max(akey.as_deref().and_then(|k| self.locked(k, now)));
            if let Some(wait) = locked {
                return Err(Problem::new(
                    Code::RateLimited,
                    format!("too many failed sign-ins; try again in {wait} s"),
                ));
            }
            let u = self.state.user_by_name(username).map_err(db)?;
            let ok = {
                let _slot = self.password_check()?;
                match &u {
                    Some(u) if !u.disabled => crypto::verify_password(password, &u.password_hash),
                    _ => {
                        crypto::dummy_verify(password);
                        false
                    }
                }
            };
            let Some(u) = u.filter(|_| ok) else {
                self.fail(&ukey, now);
                if let Some(k) = &akey {
                    self.fail(k, now);
                }
                return Err(Problem::new(
                    Code::Unauthorized,
                    "wrong username or password",
                ));
            };
            self.succeed(&ukey);
            if let Some(k) = &akey {
                self.succeed(k);
            }
            let mut c = self
                .basic_cache
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if c.len() > 1000 {
                c.retain(|_, (_, exp)| *exp > now);
            }
            c.insert(key, (u.id, now + BASIC_CACHE_SECS));
            u
        };
        if !user.allow_basic_api {
            return Err(
                Problem::new(Code::Forbidden, "HTTP Basic is off for this user")
                    .hint("An admin can turn on allowBasicApi for the user, or use an API token."),
            );
        }
        if user.totp_enabled {
            return Err(Problem::new(
                Code::Forbidden,
                "users with two-factor sign-in can't use HTTP Basic",
            )
            .hint("Use an API token instead."));
        }
        Ok(Principal {
            user_id: user.id,
            role: Role::parse(&user.role).unwrap_or(Role::Viewer),
            username: user.username,
            via: Via::Basic,
            agent: None,
        })
    }

    /// The audit actor for a request (token actors name the token and its owner).
    pub fn actor(&self, p: &Principal, remote: IpAddr, reason: Option<String>) -> Actor {
        let (name, kind) = match (&p.via, &p.agent) {
            // REQ: AGT-005 — `agent:<token> (owner: <user>)`, and the agent software.
            (_, Some(g)) => {
                let via = g
                    .client
                    .as_deref()
                    .map(|c| format!(" via {c}"))
                    .unwrap_or_default();
                (
                    format!("agent:{} (owner: {}){via}", g.token_name, p.username),
                    "agent",
                )
            }
            (Via::Session { .. }, None) => (p.username.clone(), "session"),
            (Via::Basic, None) => (p.username.clone(), "basic"),
            (Via::Token { id }, None) => {
                let token = self
                    .state
                    .token(id)
                    .ok()
                    .flatten()
                    .map_or_else(|| id.clone(), |t| t.name);
                (format!("token:{token} (owner: {})", p.username), "token")
            }
        };
        Actor {
            name,
            kind,
            remote: Some(remote.to_string()),
            reason,
        }
    }

    /// Appends to the audit log (REQ: API-006). The change has already happened, so a
    /// failure here is logged rather than undoing it. Blocking.
    pub fn record(&self, who: &Actor, action: &str, target: &str, detail: &serde_json::Value) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let detail = detail.to_string();
        let entry = NewAudit {
            ts: now,
            actor: &who.name,
            actor_kind: who.kind,
            remote: who.remote.as_deref(),
            action,
            target,
            detail: &detail,
            reason: who.reason.as_deref(),
        };
        if let Err(e) = self.state.audit_append(&entry) {
            tracing::error!(action, target, "audit log write failed: {e}");
        }
    }

    /// Drops cached Basic results for a user (password, role, or status changed).
    pub fn forget_basic(&self, user_id: i64) {
        self.basic_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, (id, _)| *id != user_id);
    }
}

#[cfg(test)]
mod tests;
