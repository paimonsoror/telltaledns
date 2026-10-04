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
        totp_required_roles: a.totp_required_roles.iter().map(|r| role(*r)).collect(),
        setup_token_file: Some(data_dir(cfg).join(SETUP_TOKEN_FILE)),
        disable_local_login: a.oidc.disable_local_login,
        admin_networks: a
            .oidc
            .allowed_admin_networks
            .iter()
            .map(|c| (c.addr, c.prefix))
            .collect(),
        trusted_proxies: cfg
            .api
            .trusted_proxies
            .iter()
            .map(|c| (c.addr, c.prefix))
            .collect(),
    }
}

fn role(r: UserRole) -> Role {
    match r {
        UserRole::Viewer => Role::Viewer,
        UserRole::Operator => Role::Operator,
        UserRole::Admin => Role::Admin,
    }
}

/// REQ: API-004 — OIDC providers from `[auth.oidc]`, reaching them with the same HTTPS client
/// as list downloads (system resolver, Mozilla roots, no redirects, 1 MiB, 15 s).
fn oidc(cfg: &Config) -> io::Result<Option<telltale_api::auth::oidc::Oidc>> {
    use telltale_api::auth::oidc::{Fetch, Oidc, OidcSettings, ProviderSettings};
    let o = &cfg.auth.oidc;
    if o.provider.is_empty() {
        return Ok(None);
    }
    let mut providers = Vec::new();
    for p in &o.provider {
        let client_secret = match (&p.client_secret, &p.client_secret_file) {
            (Some(s), _) => Some(s.to_string()),
            (None, Some(f)) => Some(
                std::fs::read_to_string(f.as_str())
                    .map_err(|e| io::Error::other(format!("{}: {e}", f.as_str())))?
                    .trim()
                    .to_owned(),
            ),
            (None, None) => None,
        };
        providers.push(ProviderSettings {
            id: p.id.to_string(),
            name: if p.name.is_empty() {
                p.id.to_string()
            } else {
                p.name.to_string()
            },
            issuer: p.issuer.to_string(),
            client_id: p.client_id.to_string(),
            client_secret,
            scopes: p.scopes.iter().map(ToString::to_string).collect(),
            username_claim: p.username_claim.to_string(),
            groups_claim: p.groups_claim.to_string(),
            roles: p
                .role
                .iter()
                .map(|r| (r.group.to_string(), role(r.role)))
                .collect(),
            default_role: p.default_role.map(role),
            require_verified_email: p.require_verified_email,
        });
    }
    let client =
        telltale_filter::fetch::Client::new(Arc::new(telltale_filter::fetch::SystemResolver), &[])
            .map_err(io::Error::other)?;
    let fetch: Fetch = Arc::new(move |req| {
        let client = client.clone();
        Box::pin(async move {
            match tokio::time::timeout(Duration::from_secs(15), client.request(req, 1 << 20)).await
            {
                Ok(Ok(r)) => Ok(r),
                Ok(Err(e)) => Err(e.message),
                Err(_) => Err("timed out".to_owned()),
            }
        })
    });
    info!(providers = providers.len(), "OIDC sign-in enabled");
    Ok(Some(Oidc::new(
        OidcSettings {
            public_url: o.public_url.to_string(),
            providers,
        },
        fetch,
    )))
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
    // A broken provider setup (say, a missing secret file) leaves password sign-in working.
    match oidc(cfg) {
        Ok(Some(o)) => auth.set_oidc(o),
        Ok(None) => {}
        Err(e) => error!("OIDC sign-in disabled: {e}"),
    }
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

/// `telltale audit verify`: checks the hash chain (REQ: API-006). `Ok(false)` if broken.
pub(crate) fn verify_audit(cfg: &Config) -> io::Result<bool> {
    let v = open_state(cfg)?
        .audit_verify()
        .map_err(|e| io::Error::other(e.to_string()))?;
    let mut out = io::stdout().lock();
    match v.first_bad {
        None => writeln!(
            out,
            "ok: {} entries, head {}",
            v.entries,
            crypto::hex(&v.head)
        )?,
        Some(seq) => writeln!(
            out,
            "BROKEN at entry {seq} of {}: the audit log was changed outside TelltaleDNS",
            v.entries
        )?,
    }
    Ok(v.first_bad.is_none())
}

/// `telltale audit list`: newest first.
pub(crate) fn list_audit(cfg: &Config, limit: usize, action: Option<&str>) -> io::Result<bool> {
    let rows = open_state(cfg)?
        .audit_page(None, limit, action, None)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let mut out = io::stdout().lock();
    for e in rows {
        let when = telltale_api::time::format_us(e.ts.saturating_mul(1_000_000));
        let reason = e
            .reason
            .map(|r| format!("  reason: {r}"))
            .unwrap_or_default();
        writeln!(
            out,
            "{:>6}  {when}  {} ({})  {}  {}  {}{reason}",
            e.seq, e.actor, e.actor_kind, e.action, e.target, e.detail
        )?;
    }
    Ok(true)
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
