//! Sign-in plumbing for the server and CLI (REQ: API-003, `spec/08` §6): opens
//! `<data_dir>/state.db`, creates the bootstrap admin from deployment secrets, keeps the
//! first-run setup token in `<data_dir>/setup-token`, and ends stale sessions.

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use telltale_api::auth::{Auth, Role, Settings, crypto};
use telltale_config::{Config, UserRole};
use telltale_store::state::State;
use tracing::{error, info, warn};

const SETUP_TOKEN_FILE: &str = "setup-token";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn data_dir(cfg: &Config) -> PathBuf {
    PathBuf::from(cfg.node.data_dir.as_str())
}

fn settings(cfg: &Config) -> Settings {
    let a = &cfg.auth;
    Settings {
        session_ttl_secs: u64::from(a.session_ttl_hours) * 3600,
        session_idle_secs: u64::from(a.session_idle_hours) * 3600,
        allow_insecure_basic: a.allow_insecure_basic,
        totp_required_roles: a
            .totp_required_roles
            .iter()
            .map(|r| match r {
                UserRole::Viewer => Role::Viewer,
                UserRole::Operator => Role::Operator,
                UserRole::Admin => Role::Admin,
            })
            .collect(),
        setup_token_file: Some(data_dir(cfg).join(SETUP_TOKEN_FILE)),
    }
}

fn open_state(cfg: &Config) -> io::Result<State> {
    let dir = data_dir(cfg);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("state.db");
    State::open(&path).map_err(|e| io::Error::other(format!("{}: {e}", path.display())))
}

/// Writes `token` readable by the owner only.
fn write_secret(path: &Path, token: &str) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(token.as_bytes())?;
    f.write_all(b"\n")
}

/// Opens the auth service for the server. Blocking (Argon2 for a bootstrap password).
pub(crate) fn open(cfg: &Config) -> io::Result<Arc<Auth>> {
    let auth = Arc::new(Auth::new(Arc::new(open_state(cfg)?), settings(cfg)));
    bootstrap_from_env(&auth);
    let setup = auth
        .setup_required()
        .map_err(|p| io::Error::other(p.detail))?;
    if setup {
        // Reuse a token from an earlier start so the one already copied keeps working.
        let file = data_dir(cfg).join(SETUP_TOKEN_FILE);
        let token = std::fs::read_to_string(&file)
            .ok()
            .map(|t| t.trim().to_owned())
            .filter(|t| t.len() >= 32)
            .unwrap_or_else(crypto::random_secret);
        if let Err(e) = write_secret(&file, &token) {
            warn!(file = %file.display(), "could not save the setup token: {e}");
        }
        auth.set_setup_token(token.clone());
        warn!(
            setup_token = %token,
            "no users yet: open the web UI (or POST /api/v1/auth/setup) with this setup token to create the first admin; `telltale auth setup-token` prints it again"
        );
    }
    Ok(auth)
}

/// `TELLTALE_BOOTSTRAP_ADMIN_USER` + `..._PASSWORD` or `..._PASSWORD_HASH`: the first admin
/// from a Kubernetes Secret. Ignored once any user exists.
fn bootstrap_from_env(auth: &Auth) {
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
    let Some(user) = var("TELLTALE_BOOTSTRAP_ADMIN_USER") else {
        return;
    };
    let password = var("TELLTALE_BOOTSTRAP_ADMIN_PASSWORD");
    let hash = var("TELLTALE_BOOTSTRAP_ADMIN_PASSWORD_HASH");
    match auth.bootstrap_admin(user.trim(), password.as_deref(), hash.as_deref(), now()) {
        Ok(Some(u)) => info!(user = %u.username, "created the bootstrap admin"),
        Ok(None) => {}
        Err(p) => error!("bootstrap admin `{user}` not created: {}", p.detail),
    }
}

/// Ends expired and idle sessions every hour.
pub(crate) fn spawn_purge(auth: Arc<Auth>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        loop {
            tick.tick().await;
            let a = Arc::clone(&auth);
            if let Ok(Err(p)) = tokio::task::spawn_blocking(move || a.purge_sessions(now())).await {
                warn!("purging sessions: {}", p.detail);
            }
        }
    })
}

/// `telltale auth setup-token`: prints the first-run token, or says setup is done.
pub(crate) fn print_setup_token(cfg: &Config) -> io::Result<bool> {
    let state = open_state(cfg)?;
    if state
        .user_count()
        .map_err(|e| io::Error::other(e.to_string()))?
        > 0
    {
        eprintln!("setup is done: sign in with an admin account");
        return Ok(false);
    }
    let file = data_dir(cfg).join(SETUP_TOKEN_FILE);
    match std::fs::read_to_string(&file) {
        Ok(t) => {
            writeln!(io::stdout().lock(), "{}", t.trim())?;
            Ok(true)
        }
        Err(e) => {
            eprintln!(
                "no setup token yet ({}: {e}); start the server first",
                file.display()
            );
            Ok(false)
        }
    }
}

/// `telltale auth hash-password`: reads a password from stdin, prints an Argon2id PHC hash
/// for `TELLTALE_BOOTSTRAP_ADMIN_PASSWORD_HASH`.
pub(crate) fn hash_password() -> io::Result<bool> {
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let pw = line.trim_end_matches(['\r', '\n']);
    if let Err(p) = telltale_api::auth::valid_password(pw) {
        eprintln!("error: {}", p.detail);
        return Ok(false);
    }
    match crypto::hash_password(pw) {
        Ok(h) => {
            writeln!(io::stdout().lock(), "{h}")?;
            Ok(true)
        }
        Err(e) => {
            eprintln!("error: {e}");
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(dir: &Path) -> Config {
        let mut c = Config::default();
        c.node.data_dir = telltale_config::SafeString::new(dir.to_string_lossy()).unwrap();
        c
    }

    // REQ: API-003 — the setup token survives restarts until the first admin exists.
    #[test]
    fn api_003_setup_token_is_kept_private_and_reused_across_restarts() {
        let dir = std::env::temp_dir().join(format!("tt-auth-{}", crypto::random_id()));
        let c = cfg(&dir);
        let a = open(&c).unwrap();
        let t1 = a.setup_token().unwrap().unwrap();
        let file = dir.join(SETUP_TOKEN_FILE);
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&file).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);
        drop(a);
        let a = open(&c).unwrap();
        assert_eq!(
            a.setup_token().unwrap().as_deref(),
            Some(t1.as_str()),
            "same token after a restart"
        );
        a.setup(&t1, "root", "correct horse battery", now())
            .unwrap();
        assert!(!file.exists());
        drop(a);
        let a = open(&c).unwrap();
        assert!(!a.setup_required().unwrap());
        assert!(!file.exists(), "no new token once set up");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
