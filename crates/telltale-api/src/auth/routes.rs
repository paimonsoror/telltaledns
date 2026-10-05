//! Authentication endpoints and middleware (REQ: API-003).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, patch, post};
use base64::Engine;
use serde::{Deserialize, Serialize};
use telltale_store::state::User;
use utoipa::ToSchema;

use super::{Actor, Auth, NewSession, Presented, Principal, Role, Scope, Via, crypto};
use crate::problem::{Code, Problem};

/// Header carrying the caller's reason for a change, stored in the audit log (AGT-005).
pub const REASON: &str = "x-telltale-reason";

pub(crate) fn reason(headers: &HeaderMap) -> Option<String> {
    headers
        .get(REASON)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(|r| r.chars().take(500).collect())
}

/// The session cookie's name.
pub const COOKIE: &str = "telltale_session";
const ISSUER: &str = "TelltaleDNS";

type AuthState = Arc<Auth>;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Problem> + Send + 'static,
) -> Result<T, Problem> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|e| Err(Problem::internal(format!("request worker failed: {e}"))))
}

/// A JSON body, or a problem+json 400 (axum's default rejection is plain text).
pub(crate) fn body<T>(b: Result<Json<T>, JsonRejection>) -> Result<T, Problem> {
    b.map(|Json(v)| v)
        .map_err(|e| Problem::invalid(format!("request body: {}", e.body_text())))
}

/// The client's address. Behind a trusted proxy (`[api] trusted_proxies`: an ingress, a
/// reverse proxy) it's the rightmost `X-Forwarded-For` entry that isn't itself a trusted
/// proxy; entries further left are client-supplied and can be forged. Used for lockouts,
/// break-glass networks, and audit entries.
pub(crate) fn remote(auth: &Auth, req_ext: &axum::http::Extensions, headers: &HeaderMap) -> IpAddr {
    let peer = req_ext
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0.ip());
    let trusted = |ip: IpAddr| {
        auth.settings()
            .trusted_proxies
            .iter()
            .any(|(n, l)| super::in_network(ip, *n, *l))
    };
    if !trusted(peer) {
        return peer;
    }
    headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .find(|ip| !trusted(*ip))
        .unwrap_or(peer)
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// HTTPS directly or via a proxy that says so. Only gates HTTP Basic and the cookie's
/// `Secure` flag; a spoofed header can only expose the spoofer's own credentials.
fn is_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("https"))
}

fn presented(headers: &HeaderMap) -> (Option<String>, Option<String>, Option<(String, String)>) {
    let session = cookie(headers, COOKIE).map(str::to_owned);
    let authz = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let bearer = authz.strip_prefix("Bearer ").map(|t| t.trim().to_owned());
    let basic = authz.strip_prefix("Basic ").and_then(|b| {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b.trim())
            .ok()?;
        let s = String::from_utf8(raw).ok()?;
        let (u, p) = s.split_once(':')?;
        Some((u.to_owned(), p.to_owned()))
    });
    (session, bearer, basic)
}

/// Authenticates every request to the routes it wraps; puts the [`Principal`] in the
/// request extensions. Session-authenticated changes need the `X-CSRF-Token` header.
pub async fn authenticate(
    State(auth): State<AuthState>,
    mut req: axum::extract::Request,
    next: Next,
) -> Response {
    let headers = req.headers().clone();
    let https = is_https(&headers);
    let ip = remote(&auth, req.extensions(), &headers);
    let (session, bearer, basic) = presented(&headers);
    let auth2 = Arc::clone(&auth);
    let result = blocking(move || {
        let p = Presented {
            session: session.as_deref(),
            bearer: bearer.as_deref(),
            basic,
            https,
            remote: Some(ip),
        };
        auth2.authenticate(&p, now())
    })
    .await;
    let principal = match result {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Problem::new(Code::Unauthorized, "sign in to use the API")
                .hint("Send a session cookie (POST /api/v1/auth/login), Authorization: Bearer <token>, or HTTP Basic if enabled for the user.")
                .into_response();
        }
        Err(p) => return p.into_response(),
    };
    if let Via::Session { csrf, .. } = &principal.via
        && !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS)
    {
        let sent = headers
            .get("x-csrf-token")
            .map(HeaderValue::as_bytes)
            .unwrap_or_default();
        if !crypto::ct_eq(sent, csrf.as_bytes()) {
            return Problem::new(Code::CsrfRejected, "missing or wrong X-CSRF-Token header")
                .hint(
                    "Send the csrfToken from sign-in (or GET /api/v1/auth/status) as X-CSRF-Token.",
                )
                .into_response();
        }
    }
    // REQ: AGT-004, AGT-005, AGT-009 — agent tokens: scopes, group, rate, reason, kill switch.
    let mut principal = principal;
    if let (Some(grant), Via::Token { id }) = (principal.agent.as_mut(), &principal.via) {
        grant.client = headers
            .get("x-telltale-client")
            .and_then(|v| v.to_str().ok())
            .map(|c| {
                c.chars()
                    .filter(|ch| !ch.is_control())
                    .take(100)
                    .collect::<String>()
            })
            .filter(|c| !c.trim().is_empty());
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let why = reason(&headers);
        if let Err(p) = super::agent::check(
            auth.agents(),
            grant,
            id,
            req.method(),
            req.uri().path(),
            why.as_deref(),
            now_ms,
        ) {
            return p.into_response();
        }
        // REQ: AGT-004 — a group-restricted agent's reads are narrowed to its group,
        // whatever `group` it asked for.
        if let Some(g) = &grant.group
            && matches!(req.uri().path(), "/api/v1/queries" | "/api/v1/stats/top")
            && let Some(uri) = with_group(req.uri(), g)
        {
            *req.uri_mut() = uri;
        }
    }
    req.extensions_mut().insert(principal);
    next.run(req).await
}

/// `uri` with its `group` query parameter replaced by `group`.
fn with_group(uri: &axum::http::Uri, group: &str) -> Option<axum::http::Uri> {
    let mut parts: Vec<String> = uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|kv| !kv.is_empty() && kv.split('=').next() != Some("group"))
        .map(str::to_owned)
        .collect();
    let mut enc = String::new();
    for b in group.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            enc.push(char::from(b));
        } else {
            let _ = std::fmt::Write::write_fmt(&mut enc, format_args!("%{b:02X}"));
        }
    }
    parts.push(format!("group={enc}"));
    format!("{}?{}", uri.path(), parts.join("&")).parse().ok()
}

async fn require(min: Role, req: axum::extract::Request, next: Next) -> Response {
    match req.extensions().get::<Principal>() {
        Some(p) if p.role >= min => next.run(req).await,
        Some(p) => Problem::new(
            Code::Forbidden,
            format!(
                "this needs the {} role; you have {}",
                min.as_str(),
                p.role.as_str()
            ),
        )
        .into_response(),
        None => Problem::new(Code::Unauthorized, "sign in to use the API").into_response(),
    }
}

pub async fn require_viewer(req: axum::extract::Request, next: Next) -> Response {
    require(Role::Viewer, req, next).await
}
pub async fn require_operator(req: axum::extract::Request, next: Next) -> Response {
    require(Role::Operator, req, next).await
}
pub async fn require_admin(req: axum::extract::Request, next: Next) -> Response {
    require(Role::Admin, req, next).await
}

pub(crate) fn principal(ext: &axum::http::Extensions) -> Result<Principal, Problem> {
    ext.get::<Principal>()
        .cloned()
        .ok_or_else(|| Problem::new(Code::Unauthorized, "sign in to use the API"))
}

fn session_cookie(s: &NewSession, ttl: u64, https: bool) -> HeaderValue {
    let secure = if https { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{COOKIE}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={ttl}{secure}",
        s.cookie
    ))
    .unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn clear_cookie() -> HeaderValue {
    HeaderValue::from_static("telltale_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

// ---- types

/// The signed-in user.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Me {
    pub id: i64,
    pub username: String,
    /// Effective role (a token's scope caps its owner's role).
    pub role: Role,
    pub totp_enabled: bool,
    pub allow_basic_api: bool,
    /// Unused recovery codes (when TOTP is on).
    pub recovery_codes_left: u64,
    /// How this request authenticated: `session`, `token`, or `basic`.
    pub via: String,
}

/// Whether setup is needed and who is signed in (public).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthStatus {
    /// No user exists yet: create the first admin with the setup token.
    pub setup_required: bool,
    pub authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<Me>,
    /// For session sign-ins: send as `X-CSRF-Token` on changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,
    /// Password sign-in is offered to this client (off with `disable_local_login`, except
    /// from the break-glass admin networks).
    pub local_login: bool,
    /// OIDC providers: send the browser to `GET /api/v1/auth/oidc/{id}/start`.
    pub oidc: Vec<OidcButton>,
}

/// A "Sign in with ..." button.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OidcButton {
    pub id: String,
    /// Label.
    pub name: String,
}

/// `GET /auth/oidc/{id}/start` parameters.
#[derive(Debug, Clone, Default, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct OidcStart {
    /// UI route to return to after sign-in (`/#/queries`). Default `/#/`.
    pub return_to: Option<String>,
}

/// What the provider sends back to `GET /auth/oidc/{id}/callback`.
#[derive(Debug, Clone, Default, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct OidcCallback {
    /// The authorization code from the provider.
    pub code: Option<String>,
    /// The value TelltaleDNS sent at the start, checked against the sign-in cookie.
    pub state: Option<String>,
    /// Set instead of `code` when the user cancelled or the provider refused.
    pub error: Option<String>,
    /// The provider's explanation of `error`.
    pub error_description: Option<String>,
}

/// Sign-out result for OIDC sessions.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LogoutResult {
    /// Send the browser here to also sign out at the provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logout_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SetupRequest {
    /// From the server log or `<data_dir>/setup-token`.
    pub setup_token: String,
    pub username: String,
    /// At least 10 characters.
    pub password: String,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    /// 6-digit code from the authenticator app, when TOTP is on.
    pub totp: Option<String>,
    /// A recovery code instead of `totp`.
    pub recovery_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub user: Me,
    /// Send as `X-CSRF-Token` on every change made with this session.
    pub csrf_token: String,
    pub expires_unix_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PasswordChange {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpSetup {
    /// For manual entry in an authenticator app.
    pub secret_base32: String,
    /// For a QR code.
    pub otpauth_url: String,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    pub code: String,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PasswordConfirm {
    pub password: String,
}

/// Single-use recovery codes, shown once.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCodes {
    pub codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TokenInfo {
    pub id: String,
    pub name: String,
    /// `user` (acts with `scope`) or `agent` (acts with `scopes`; AGT-004).
    pub kind: TokenKind,
    /// For user tokens. Agent tokens show the closest equivalent.
    pub scope: Scope,
    /// For agent tokens: what it may do (e.g. `analytics:read`, `config:write:clients`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// For agent tokens: restricted to this client group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// For agent tokens: requests per minute (default: `[agents] rate_per_minute`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_per_minute: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_unix_seconds: Option<u64>,
    pub created_unix_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_unix_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateToken {
    /// What it's for (`grafana`, `homepage-widget`, `claude-assistant`).
    pub name: String,
    /// `user` (default) or `agent`: an AI agent or automation, limited to `scopes`, rate
    /// limited, attributed as `agent:<name>` in the audit log, and switched off with
    /// `[agents] enabled = false`.
    pub kind: Option<TokenKind>,
    /// User tokens. Default: `read`.
    pub scope: Option<Scope>,
    /// Agent tokens: any of `analytics:read`, `querylog:read`, `config:read`,
    /// `config:write:clients`, `config:write:records`, `config:write:forwards`
    /// (`config:write:*` for all three), `ops:pause`, `ops:cache`, `cluster:admin`.
    /// Default: `analytics:read` and `config:read` (read-only, no query log). Each needs a
    /// role you have.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Agent tokens: only this client group's devices and queries.
    pub group: Option<String>,
    /// Agent tokens: requests per minute (default: `[agents] rate_per_minute`, 120).
    pub rate_per_minute: Option<u32>,
    /// Default: never expires.
    pub expires_in_days: Option<u32>,
}

/// Whether a token is for a person's scripts or for an agent (AGT-004).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    #[default]
    User,
    Agent,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NewToken {
    /// The token, shown only now: send as `Authorization: Bearer <token>`.
    pub token: String,
    pub info: TokenInfo,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub id: i64,
    pub username: String,
    pub role: Role,
    pub disabled: bool,
    pub totp_enabled: bool,
    pub allow_basic_api: bool,
    pub created_unix_seconds: u64,
    /// The sign-in provider for users created by OIDC sign-in (they have no password here).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_provider: Option<String>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateUser {
    pub username: String,
    pub password: String,
    pub role: Role,
    /// Allow HTTP Basic on the API for scripts and scrapers (default false).
    pub allow_basic_api: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUser {
    pub role: Option<Role>,
    pub disabled: Option<bool>,
    pub allow_basic_api: Option<bool>,
    /// Set a new password (ends the user's sessions).
    pub password: Option<String>,
    /// Turn off the user's TOTP (if they lost their device).
    pub reset_totp: Option<bool>,
}

/// List wrapper.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Listed<T> {
    pub items: Vec<T>,
}

fn user_info(u: &User) -> UserInfo {
    UserInfo {
        id: u.id,
        username: u.username.clone(),
        role: Role::parse(&u.role).unwrap_or(Role::Viewer),
        disabled: u.disabled,
        totp_enabled: u.totp_enabled,
        allow_basic_api: u.allow_basic_api,
        created_unix_seconds: u.created,
        oidc_provider: u.oidc_provider.clone(),
    }
}

fn me(auth: &Auth, u: &User, p: Option<&Principal>) -> Result<Me, Problem> {
    Ok(Me {
        id: u.id,
        username: u.username.clone(),
        role: p.map_or_else(|| Role::parse(&u.role).unwrap_or(Role::Viewer), |p| p.role),
        totp_enabled: u.totp_enabled,
        allow_basic_api: u.allow_basic_api,
        recovery_codes_left: auth
            .state()
            .recovery_codes_left(u.id)
            .map_err(|e| Problem::internal(e.to_string()))?,
        via: match p.map(|p| &p.via) {
            Some(Via::Token { .. }) => "token",
            Some(Via::Basic) => "basic",
            _ => "session",
        }
        .to_owned(),
    })
}

fn token_info(t: &telltale_store::state::Token) -> TokenInfo {
    TokenInfo {
        id: t.id.clone(),
        name: t.name.clone(),
        kind: if t.agent_scopes.is_some() {
            TokenKind::Agent
        } else {
            TokenKind::User
        },
        scope: Scope::parse(&t.scope).unwrap_or(Scope::Read),
        scopes: t
            .agent_scopes
            .as_deref()
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default(),
        group: t.agent_group.clone(),
        rate_per_minute: t.agent_rate_per_minute,
        expires_unix_seconds: t.expires,
        created_unix_seconds: t.created,
        last_used_unix_seconds: t.last_used,
    }
}

#[allow(clippy::needless_pass_by_value)] // used as `map_err(db)`
fn db(e: telltale_store::state::StateError) -> Problem {
    Problem::internal(e.to_string())
}

// ---- routers

/// Routes that need no sign-in: status, first-run setup, sign-in.
pub fn public(auth: AuthState) -> Router {
    Router::new()
        .route("/api/v1/auth/status", get(status))
        .route("/api/v1/auth/setup", post(setup))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/oidc/{id}/start", get(oidc_start))
        .route("/api/v1/auth/oidc/{id}/callback", get(oidc_callback))
        .with_state(auth)
}

/// Routes for any signed-in user (their own session, password, TOTP, tokens).
pub fn self_service(auth: AuthState) -> Router {
    Router::new()
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/me", get(get_me))
        .route("/api/v1/auth/password", post(change_password))
        .route("/api/v1/auth/totp/setup", post(totp_setup))
        .route("/api/v1/auth/totp/enable", post(totp_enable))
        .route("/api/v1/auth/totp/disable", post(totp_disable))
        .route("/api/v1/tokens", get(list_tokens).post(create_token))
        .route("/api/v1/tokens/{id}", delete(delete_token))
        .with_state(auth)
}

/// Admin-only user management and the audit log.
pub fn admin(auth: AuthState) -> Router {
    Router::new()
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/users/{id}", patch(update_user).delete(delete_user))
        .route("/api/v1/audit", get(audit_log))
        .route("/api/v1/audit/verify", get(audit_verify))
        .with_state(auth)
}

/// One audit-log entry.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditInfo {
    /// Position in the chain, from 1.
    pub seq: u64,
    /// RFC 3339.
    pub time: String,
    pub ts_unix_seconds: u64,
    /// A username, `token:<name> (owner: <user>)`, or a system name (`setup-token`,
    /// `bootstrap`, `lockout`, `reload`).
    pub actor: String,
    /// `session`, `token`, `basic`, or `system`.
    pub actor_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    /// `auth.login`, `auth.lockout`, `user.create`, `user.update`, `user.delete`,
    /// `user.password`, `user.totp.enable`, `user.totp.disable`, `token.create`,
    /// `token.revoke`, `config.reload`.
    pub action: String,
    pub target: String,
    /// Details (what changed, as `{field: {from, to}}` for updates). Never secrets.
    #[schema(value_type = Object)]
    pub detail: serde_json::Value,
    /// The caller's `X-Telltale-Reason`, when sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// BLAKE3 of the previous entry's hash and this entry (hex).
    pub hash: String,
}

/// A page of the audit log, newest first.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditPage {
    pub items: Vec<AuditInfo>,
    /// Pass as `cursor` for older entries; absent at the start of the log.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Result of checking the hash chain.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditVerify {
    pub entries: u64,
    /// Every entry's hash and link checks out.
    pub ok: bool,
    /// The first entry that was changed, removed, or reordered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_bad_seq: Option<u64>,
    /// Hash of the newest entry (hex). Record it elsewhere to detect truncation later.
    pub head_hash: String,
}

/// Query parameters for `GET /audit`.
#[derive(Debug, Clone, Default, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AuditParams {
    /// Entries per page (1–500, default 100).
    pub limit: Option<usize>,
    /// From a previous page's `nextCursor`.
    pub cursor: Option<String>,
    /// An action or prefix (`user.`, `token.create`).
    pub action: Option<String>,
    /// Exactly this actor.
    pub actor: Option<String>,
}

fn audit_info(e: telltale_store::state::AuditEntry) -> AuditInfo {
    AuditInfo {
        seq: e.seq,
        time: crate::time::format_us(e.ts.saturating_mul(1_000_000)),
        ts_unix_seconds: e.ts,
        actor: e.actor,
        actor_kind: e.actor_kind,
        remote: e.remote,
        action: e.action,
        target: e.target,
        detail: serde_json::from_str(&e.detail).unwrap_or(serde_json::Value::Null),
        reason: e.reason,
        hash: crypto::hex(&e.hash),
    }
}

/// The audit log (admin).
///
/// Every change to users, passwords, two-factor sign-in, and API tokens, sign-ins and
/// lockouts, and configuration reloads, newest first, with who (attributed to the token and
/// its owner for API tokens), from where, why (`X-Telltale-Reason`), and what changed. Append-only and
/// hash-chained; check it with GET /audit/verify.
#[utoipa::path(get, path = "/api/v1/audit", tag = "auth", params(AuditParams),
    responses((status = 200, body = AuditPage, description = "The result."), (status = 400, body = Problem, description = "Invalid request: problem+json says which parameter and how to fix it."), (status = 403, body = Problem, description = "Signed in, but not allowed to do this (role, token scope, or agent restriction).")))]
pub(crate) async fn audit_log(
    State(auth): State<AuthState>,
    axum::extract::Query(q): axum::extract::Query<AuditParams>,
) -> Result<Json<AuditPage>, Problem> {
    let limit = q.limit.unwrap_or(100);
    if !(1..=500).contains(&limit) {
        return Err(Problem::invalid("`limit`: 1 to 500"));
    }
    let before = match &q.cursor {
        None => None,
        Some(c) => Some(c.parse::<u64>().map_err(|_| {
            Problem::invalid("`cursor`: not a cursor from this API")
                .hint("Pass the nextCursor value from the previous page unchanged.")
        })?),
    };
    blocking(move || {
        let rows = auth
            .state()
            .audit_page(before, limit, q.action.as_deref(), q.actor.as_deref())
            .map_err(db)?;
        let next_cursor = (rows.len() == limit)
            .then(|| rows.last().map(|e| e.seq.to_string()))
            .flatten()
            .filter(|s| s != "1");
        Ok(Json(AuditPage {
            items: rows.into_iter().map(audit_info).collect(),
            next_cursor,
        }))
    })
    .await
}

/// Verify the audit log (admin).
///
/// Recomputes every entry's hash and link. `ok: false` with `firstBadSeq` means the log was
/// edited at or before that entry outside TelltaleDNS. Compare `headHash` with a value you
/// saved earlier to detect removed entries at the end.
#[utoipa::path(get, path = "/api/v1/audit/verify", tag = "auth",
    responses((status = 200, body = AuditVerify, description = "The result."), (status = 403, body = Problem, description = "Signed in, but not allowed to do this (role, token scope, or agent restriction).")))]
pub(crate) async fn audit_verify(
    State(auth): State<AuthState>,
) -> Result<Json<AuditVerify>, Problem> {
    blocking(move || {
        let v = auth.state().audit_verify().map_err(db)?;
        Ok(Json(AuditVerify {
            entries: v.entries,
            ok: v.first_bad.is_none(),
            first_bad_seq: v.first_bad,
            head_hash: crypto::hex(&v.head),
        }))
    })
    .await
}

// ---- handlers

/// Sign-in state.
///
/// Whether first-run setup is needed, and who the request is signed in as (if anyone),
/// with the session's CSRF token. Public; the UI calls it on load.
#[utoipa::path(get, path = "/api/v1/auth/status", tag = "auth",
    responses((status = 200, body = AuthStatus, description = "The result.")))]
pub(crate) async fn status(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    req_ext: axum::http::Extensions,
) -> Result<Json<AuthStatus>, Problem> {
    let (session, bearer, basic) = presented(&headers);
    let https = is_https(&headers);
    let ip = remote(&auth, &req_ext, &headers);
    blocking(move || {
        let setup_required = auth.setup_required()?;
        let p = Presented {
            session: session.as_deref(),
            bearer: bearer.as_deref(),
            basic,
            https,
            remote: Some(ip),
        };
        let who = auth.authenticate(&p, now()).ok().flatten();
        let (user, csrf) = match &who {
            Some(p) => {
                let u = auth.state().user(p.user_id).map_err(db)?;
                let csrf = match &p.via {
                    Via::Session { csrf, .. } => Some(csrf.clone()),
                    _ => None,
                };
                (u.map(|u| me(&auth, &u, Some(p))).transpose()?, csrf)
            }
            None => (None, None),
        };
        let oidc = auth.oidc().map_or_else(Vec::new, |o| {
            o.providers()
                .into_iter()
                .map(|(id, name)| OidcButton { id, name })
                .collect()
        });
        Ok(Json(AuthStatus {
            setup_required,
            authenticated: user.is_some(),
            user,
            csrf_token: csrf,
            local_login: auth.local_login_allowed(ip),
            oidc,
        }))
    })
    .await
}

/// Create the first admin.
///
/// Only while no user exists. `setupToken` is printed in the server log at startup and saved
/// in `<data_dir>/setup-token`. Signs the new admin in (sets the session cookie).
#[utoipa::path(post, path = "/api/v1/auth/setup", tag = "auth", request_body = SetupRequest,
    responses((status = 201, body = LoginResponse, description = "Created."), (status = 401, body = Problem, description = "Not signed in, or the credentials are wrong."),
        (status = 409, body = Problem, description = "Setup is already done.")))]
pub(crate) async fn setup(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    req_ext: axum::http::Extensions,
    b: Result<Json<SetupRequest>, JsonRejection>,
) -> Result<Response, Problem> {
    let r = body(b)?;
    let ip = remote(&auth, &req_ext, &headers);
    let https = is_https(&headers);
    let ttl = auth.settings().session_ttl_secs;
    let (user, sess, info) = blocking(move || {
        let user = auth.setup(&r.setup_token, &r.username, &r.password, now())?;
        let sess = auth.start_session(&user, ip, now())?;
        let info = me(&auth, &user, None)?;
        Ok((user, sess, info))
    })
    .await?;
    let _ = user;
    Ok((
        StatusCode::CREATED,
        [(header::SET_COOKIE, session_cookie(&sess, ttl, https))],
        Json(LoginResponse {
            user: info,
            csrf_token: sess.csrf,
            expires_unix_seconds: sess.expires,
        }),
    )
        .into_response())
}

/// Sign in.
///
/// Username and password, plus `totp` (or `recoveryCode`) when two-factor sign-in is on:
/// without it the answer is 401 `totp_required`. Sets an `HttpOnly; SameSite=Strict` session
/// cookie and returns the CSRF token to send as `X-CSRF-Token` on changes. Repeated failures
/// lock the username and the address out for a while (429).
#[utoipa::path(post, path = "/api/v1/auth/login", tag = "auth", request_body = LoginRequest,
    responses((status = 200, body = LoginResponse, description = "The result."), (status = 401, body = Problem, description = "Not signed in, or the credentials are wrong."),
        (status = 429, body = Problem, description = "Too many requests: wait for Retry-After seconds.")))]
pub(crate) async fn login(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    req_ext: axum::http::Extensions,
    b: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Response, Problem> {
    let r = body(b)?;
    let ip = remote(&auth, &req_ext, &headers);
    let https = is_https(&headers);
    let ttl = auth.settings().session_ttl_secs;
    let (sess, info) = blocking(move || {
        let user = auth.login(
            &r.username,
            &r.password,
            r.totp.as_deref(),
            r.recovery_code.as_deref(),
            ip,
            now(),
        )?;
        let sess = auth.start_session(&user, ip, now())?;
        // REQ: API-006 — sign-ins are audited (failures only when they lock an account).
        let who = Actor {
            name: user.username.clone(),
            kind: "session",
            remote: Some(ip.to_string()),
            reason: None,
        };
        auth.record(&who, "auth.login", &user.username, &serde_json::json!({}));
        Ok((sess, me(&auth, &user, None)?))
    })
    .await?;
    Ok((
        [(header::SET_COOKIE, session_cookie(&sess, ttl, https))],
        Json(LoginResponse {
            user: info,
            csrf_token: sess.csrf,
            expires_unix_seconds: sess.expires,
        }),
    )
        .into_response())
}

/// Sign out.
///
/// Ends this session and clears the cookie. With a token or Basic, does nothing but succeed.
#[utoipa::path(post, path = "/api/v1/auth/logout", tag = "auth",
    responses((status = 204, description = "Signed out."),
        (status = 200, body = LogoutResult, description = "Signed out of an OIDC session: send the browser to `logoutUrl` to sign out at the provider too.")))]
pub(crate) async fn logout(
    State(auth): State<AuthState>,
    req_ext: axum::http::Extensions,
) -> Result<Response, Problem> {
    let p = principal(&req_ext)?;
    let Via::Session { id_hash, .. } = p.via else {
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    let logout_url = blocking(move || {
        let provider = auth
            .state()
            .session(&id_hash)
            .map_err(db)?
            .and_then(|s| s.oidc_provider);
        auth.end_session(&id_hash)?;
        Ok(provider.and_then(|id| auth.oidc()?.logout_url(&id)))
    })
    .await?;
    let cookie = [(header::SET_COOKIE, clear_cookie())];
    Ok(match logout_url {
        // REQ: API-004 — RP-initiated logout: the UI sends the browser on to the provider.
        Some(url) => (
            cookie,
            Json(LogoutResult {
                logout_url: Some(url),
            }),
        )
            .into_response(),
        None => (StatusCode::NO_CONTENT, cookie).into_response(),
    })
}

fn flow_cookie(value: &str, max_age: u64, https: bool) -> HeaderValue {
    let secure = if https { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{}={value}; Path=/api/v1/auth/oidc; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}",
        super::oidc::FLOW_COOKIE
    ))
    .unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn to_ui(path: &str) -> Response {
    let mut r = StatusCode::FOUND.into_response();
    if let Ok(v) = HeaderValue::from_str(path) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    r
}

/// Where a failed sign-in lands: the sign-in page with the reason.
fn login_error(message: &str) -> Response {
    let enc: String = message
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    to_ui(&format!("/#/?loginError={enc}"))
}

/// Start signing in with an OIDC provider.
///
/// Redirects the browser to the provider (Authorization Code + PKCE). The provider sends it
/// back to `/api/v1/auth/oidc/{id}/callback`, which signs in and returns to `returnTo`.
/// Browsers only: link a "Sign in with ..." button here.
#[utoipa::path(get, path = "/api/v1/auth/oidc/{id}/start", tag = "auth",
    params(("id" = String, Path, description = "Provider ID"), OidcStart),
    responses((status = 302, description = "To the provider's sign-in page."),
        (status = 404, body = Problem, description = "Not found."), (status = 503, body = Problem, description = "Not available on this node right now.")))]
pub(crate) async fn oidc_start(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<OidcStart>,
) -> Response {
    let Some(oidc) = auth.oidc().cloned() else {
        return login_error("sign-in providers aren't configured");
    };
    let back = super::oidc::safe_return(q.return_to.as_deref());
    match oidc.start(&id, &back).await {
        Ok(s) => {
            let mut r = to_ui(&s.redirect);
            r.headers_mut().insert(
                header::SET_COOKIE,
                flow_cookie(&s.browser, 600, is_https(&headers)),
            );
            r
        }
        Err(p) => login_error(&p.detail),
    }
}

/// OIDC redirect URI.
///
/// The provider returns here with `code` and `state`. Validates both, exchanges the code,
/// verifies the ID token, maps groups to a role (creating the user on first sign-in), sets
/// the session cookie, and redirects to the UI. Failures redirect to `/#/?loginError=...`.
/// Register `<public_url>/api/v1/auth/oidc/{id}/callback` with the provider.
#[utoipa::path(get, path = "/api/v1/auth/oidc/{id}/callback", tag = "auth",
    params(("id" = String, Path, description = "Provider ID"), OidcCallback),
    responses((status = 302, description = "Signed in (to the UI), or back to sign-in with `loginError`.")))]
pub(crate) async fn oidc_callback(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    req_ext: axum::http::Extensions,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<OidcCallback>,
) -> Response {
    let Some(oidc) = auth.oidc().cloned() else {
        return login_error("sign-in providers aren't configured");
    };
    if let Some(e) = &q.error {
        let why = q.error_description.as_deref().unwrap_or(e);
        return login_error(&format!("the sign-in provider said: {why}"));
    }
    let (Some(code), Some(state)) = (q.code.as_deref(), q.state.as_deref()) else {
        return login_error("the provider's answer was incomplete");
    };
    let browser = cookie(&headers, super::oidc::FLOW_COOKIE).map(str::to_owned);
    let (who, back) = match oidc.finish(&id, code, state, browser.as_deref()).await {
        Ok(v) => v,
        Err(p) => return login_error(&p.detail),
    };
    let ip = remote(&auth, &req_ext, &headers);
    let https = is_https(&headers);
    let ttl = auth.settings().session_ttl_secs;
    let pid = id.clone();
    let signed_in = blocking(move || {
        let user = auth.oidc_user(&oidc, &pid, &who, ip, now())?;
        let sess = auth.start_session(&user, ip, now())?;
        auth.state()
            .set_session_provider(&crypto::secret_hash(&sess.cookie), &pid)
            .map_err(db)?;
        Ok(sess)
    })
    .await;
    match signed_in {
        Ok(sess) => {
            let mut r = to_ui(&back);
            let h = r.headers_mut();
            h.append(header::SET_COOKIE, session_cookie(&sess, ttl, https));
            h.append(header::SET_COOKIE, flow_cookie("", 0, https));
            r
        }
        Err(p) => login_error(&p.detail),
    }
}

/// Who am I.
///
/// The signed-in user: role (capped by a token's scope), two-factor state, unused recovery
/// codes, and how this request authenticated.
#[utoipa::path(get, path = "/api/v1/auth/me", tag = "auth", responses((status = 200, body = Me, description = "The result.")))]
pub(crate) async fn get_me(
    State(auth): State<AuthState>,
    req_ext: axum::http::Extensions,
) -> Result<Json<Me>, Problem> {
    let p = principal(&req_ext)?;
    blocking(move || {
        let u = auth.active_user(p.user_id)?;
        me(&auth, &u, Some(&p)).map(Json)
    })
    .await
}

/// Change my password.
///
/// Needs the current password. Ends every other session of this user.
#[utoipa::path(post, path = "/api/v1/auth/password", tag = "auth", request_body = PasswordChange,
    responses((status = 204, description = "Changed."), (status = 401, body = Problem, description = "Not signed in, or the credentials are wrong.")))]
pub(crate) async fn change_password(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    req_ext: axum::http::Extensions,
    b: Result<Json<PasswordChange>, JsonRejection>,
) -> Result<StatusCode, Problem> {
    let r = body(b)?;
    let p = principal(&req_ext)?;
    let (ip, why) = (remote(&auth, &req_ext, &headers), reason(&headers));
    blocking(move || {
        super::valid_password(&r.new_password)?;
        let u = auth.active_user(p.user_id)?;
        if !crypto::verify_password(&r.current_password, &u.password_hash) {
            return Err(Problem::new(
                Code::Unauthorized,
                "the current password is wrong",
            ));
        }
        let hash = crypto::hash_password(&r.new_password).map_err(Problem::internal)?;
        auth.state().set_password(u.id, &hash, now()).map_err(db)?;
        let keep = match &p.via {
            Via::Session { id_hash, .. } => Some(id_hash.as_slice()),
            _ => None,
        };
        auth.state().delete_user_sessions(u.id, keep).map_err(db)?;
        auth.forget_basic(u.id);
        auth.record(
            &auth.actor(&p, ip, why),
            "user.password",
            &u.username,
            &serde_json::json!({ "by": "self" }),
        );
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

/// Start two-factor enrollment.
///
/// Returns a new TOTP secret (base32 and an `otpauth://` URL for a QR code). Nothing is
/// enforced until POST /auth/totp/enable confirms a code from the app.
#[utoipa::path(post, path = "/api/v1/auth/totp/setup", tag = "auth",
    responses((status = 200, body = TotpSetup, description = "The result."), (status = 409, body = Problem, description = "Conflicts with the current state: problem+json says what to change.")))]
pub(crate) async fn totp_setup(
    State(auth): State<AuthState>,
    req_ext: axum::http::Extensions,
) -> Result<Json<TotpSetup>, Problem> {
    let p = principal(&req_ext)?;
    blocking(move || {
        let u = auth.active_user(p.user_id)?;
        if u.totp_enabled {
            return Err(
                Problem::new(Code::Conflict, "two-factor sign-in is already on")
                    .hint("Turn it off first (POST /auth/totp/disable) to enroll a new device."),
            );
        }
        let secret = crypto::new_totp_secret();
        auth.state()
            .set_totp(u.id, Some(&secret), false)
            .map_err(db)?;
        Ok(Json(TotpSetup {
            secret_base32: crypto::base32(&secret),
            otpauth_url: crypto::otpauth_url(ISSUER, &u.username, &secret),
        }))
    })
    .await
}

/// Turn on two-factor sign-in.
///
/// Confirms a current code from the app enrolled with POST /auth/totp/setup, turns
/// enforcement on, and returns ten single-use recovery codes (shown only now).
#[utoipa::path(post, path = "/api/v1/auth/totp/enable", tag = "auth", request_body = TotpCode,
    responses((status = 200, body = RecoveryCodes, description = "The result."), (status = 401, body = Problem, description = "Not signed in, or the credentials are wrong.")))]
pub(crate) async fn totp_enable(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    req_ext: axum::http::Extensions,
    b: Result<Json<TotpCode>, JsonRejection>,
) -> Result<Json<RecoveryCodes>, Problem> {
    let r = body(b)?;
    let p = principal(&req_ext)?;
    let (ip, why) = (remote(&auth, &req_ext, &headers), reason(&headers));
    blocking(move || {
        let u = auth.active_user(p.user_id)?;
        let Some(secret) = u.totp_secret.as_deref().filter(|_| !u.totp_enabled) else {
            return Err(Problem::new(Code::Conflict, "no enrollment in progress")
                .hint("Call POST /auth/totp/setup first."));
        };
        let Some(step) = crypto::totp_step(secret, &r.code, now()) else {
            return Err(Problem::new(Code::Unauthorized, "that code doesn't match")
                .hint("Check the device clock; codes change every 30 seconds."));
        };
        auth.state()
            .set_totp(u.id, Some(secret), true)
            .map_err(db)?;
        auth.state().advance_totp_step(u.id, step).map_err(db)?;
        let (codes, hashes) = crypto::recovery_codes();
        auth.state().set_recovery_codes(u.id, &hashes).map_err(db)?;
        auth.forget_basic(u.id);
        auth.record(
            &auth.actor(&p, ip, why),
            "user.totp.enable",
            &u.username,
            &serde_json::json!({}),
        );
        Ok(Json(RecoveryCodes { codes }))
    })
    .await
}

/// Turn off two-factor sign-in.
///
/// Needs the current password. Removes the TOTP secret and the unused recovery codes.
#[utoipa::path(post, path = "/api/v1/auth/totp/disable", tag = "auth", request_body = PasswordConfirm,
    responses((status = 204, description = "Off."), (status = 401, body = Problem, description = "Not signed in, or the credentials are wrong.")))]
pub(crate) async fn totp_disable(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    req_ext: axum::http::Extensions,
    b: Result<Json<PasswordConfirm>, JsonRejection>,
) -> Result<StatusCode, Problem> {
    let r = body(b)?;
    let p = principal(&req_ext)?;
    let (ip, why) = (remote(&auth, &req_ext, &headers), reason(&headers));
    blocking(move || {
        let u = auth.active_user(p.user_id)?;
        if !crypto::verify_password(&r.password, &u.password_hash) {
            return Err(Problem::new(Code::Unauthorized, "the password is wrong"));
        }
        auth.state().set_totp(u.id, None, false).map_err(db)?;
        auth.state().set_recovery_codes(u.id, &[]).map_err(db)?;
        auth.record(
            &auth.actor(&p, ip, why),
            "user.totp.disable",
            &u.username,
            &serde_json::json!({ "by": "self" }),
        );
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

/// My API tokens.
///
/// Name, scope, expiry, and last use. The secrets themselves are never shown again.
#[utoipa::path(get, path = "/api/v1/tokens", tag = "auth",
    responses((status = 200, body = Listed<TokenInfo>, description = "The result.")))]
pub(crate) async fn list_tokens(
    State(auth): State<AuthState>,
    req_ext: axum::http::Extensions,
) -> Result<Json<Listed<TokenInfo>>, Problem> {
    let p = principal(&req_ext)?;
    blocking(move || {
        let items = auth.state().tokens_for(p.user_id).map_err(db)?;
        Ok(Json(Listed {
            items: items.iter().map(token_info).collect(),
        }))
    })
    .await
}

/// Create an API token.
///
/// For scripts, dashboards, and agents: send as `Authorization: Bearer <token>`. `scope`
/// `read` acts as viewer, `write` as operator, `admin` as admin, never above the owner's role.
/// The token is shown only in this response.
#[utoipa::path(post, path = "/api/v1/tokens", tag = "auth", request_body = CreateToken,
    responses((status = 201, body = NewToken, description = "Created."), (status = 403, body = Problem, description = "Signed in, but not allowed to do this (role, token scope, or agent restriction).")))]
pub(crate) async fn create_token(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    req_ext: axum::http::Extensions,
    b: Result<Json<CreateToken>, JsonRejection>,
) -> Result<(StatusCode, Json<NewToken>), Problem> {
    let r = body(b)?;
    let p = principal(&req_ext)?;
    let (ip, why) = (remote(&auth, &req_ext, &headers), reason(&headers));
    blocking(move || {
        let name = r.name.trim();
        if name.is_empty() || name.len() > 64 {
            return Err(Problem::invalid("`name`: 1-64 characters"));
        }
        if p.agent.is_some() {
            return Err(Problem::new(Code::Forbidden, "agents can't create tokens"));
        }
        let kind = r.kind.unwrap_or_default();
        let agent = agent_scopes(&r, kind, p.role)?;
        let scope = match &agent {
            Some((_, Role::Admin)) => Scope::Admin,
            Some((_, Role::Operator)) => Scope::Write,
            Some(_) => Scope::Read,
            None => r.scope.unwrap_or(Scope::Read),
        };
        if scope.role() > p.role {
            return Err(Problem::new(
                Code::Forbidden,
                format!(
                    "a `{}` token needs at least the {} role",
                    scope.as_str(),
                    scope.role().as_str()
                ),
            ));
        }
        let (id, secret) = (crypto::random_id(), crypto::random_secret());
        let now = now();
        let expires = r.expires_in_days.map(|d| now + u64::from(d) * 86_400);
        auth.state()
            .create_token(
                &id,
                p.user_id,
                name,
                &crypto::secret_hash(&secret),
                scope.as_str(),
                expires,
                now,
            )
            .map_err(db)?;
        if let Some((scopes, _)) = &agent {
            let list: Vec<&str> = scopes.iter().map(String::as_str).collect();
            auth.state()
                .set_token_agent(&id, &list.join(" "), r.group.as_deref(), r.rate_per_minute)
                .map_err(db)?;
        }
        let t = auth
            .state()
            .token(&id)
            .map_err(db)?
            .ok_or_else(|| Problem::internal("token vanished"))?;
        auth.record(
            &auth.actor(&p, ip, why),
            "token.create",
            &id,
            &serde_json::json!({
                "name": name, "kind": if agent.is_some() { "agent" } else { "user" },
                "scope": scope.as_str(), "scopes": agent.as_ref().map(|(s, _)| s),
                "group": r.group, "owner": p.username, "expiresUnixSeconds": expires
            }),
        );
        Ok((
            StatusCode::CREATED,
            Json(NewToken {
                token: format!("tt_{id}_{secret}"),
                info: token_info(&t),
            }),
        ))
    })
    .await
}

/// REQ: AGT-004 — an agent token's scopes (read-only by default) and the role they need,
/// checked against the creator's role; `None` for user tokens.
fn agent_scopes(
    r: &CreateToken,
    kind: TokenKind,
    creator: Role,
) -> Result<Option<(std::collections::BTreeSet<String>, Role)>, Problem> {
    if kind != TokenKind::Agent {
        if !r.scopes.is_empty() || r.group.is_some() || r.rate_per_minute.is_some() {
            return Err(Problem::invalid(
                "`scopes`, `group`, and `ratePerMinute` are for agent tokens",
            )
            .hint("Send \"kind\": \"agent\"."));
        }
        return Ok(None);
    }
    let wanted: Vec<String> = if r.scopes.is_empty() {
        super::agent::DEFAULT_SCOPES
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    } else {
        r.scopes.clone()
    };
    let scopes = super::agent::parse_scopes(&wanted)?;
    let needs = super::agent::implied_role(&scopes);
    if needs > creator {
        return Err(Problem::new(
            Code::Forbidden,
            format!(
                "these scopes need the {} role; you have {}",
                needs.as_str(),
                creator.as_str()
            ),
        ));
    }
    if let Some(g) = &r.group
        && (g.trim().is_empty() || g.len() > 64)
    {
        return Err(Problem::invalid("`group`: 1-64 characters"));
    }
    if r.rate_per_minute == Some(0) {
        return Err(Problem::invalid("`ratePerMinute`: at least 1"));
    }
    Ok(Some((scopes, needs)))
}

/// Revoke one of my API tokens.
///
/// By the `id` from GET /tokens. Takes effect immediately; other tokens are unaffected.
#[utoipa::path(delete, path = "/api/v1/tokens/{id}", tag = "auth",
    params(("id" = String, Path, description = "Token ID")),
    responses((status = 204, description = "Revoked."), (status = 404, body = Problem, description = "Not found.")))]
pub(crate) async fn delete_token(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    req_ext: axum::http::Extensions,
    Path(id): Path<String>,
) -> Result<StatusCode, Problem> {
    let p = principal(&req_ext)?;
    let (ip, why) = (remote(&auth, &req_ext, &headers), reason(&headers));
    blocking(move || {
        let who = auth.actor(&p, ip, why);
        let name = auth.state().token(&id).map_err(db)?.map(|t| t.name);
        if auth.state().delete_token(&id, p.user_id).map_err(db)? {
            auth.record(
                &who,
                "token.revoke",
                &id,
                &serde_json::json!({ "name": name, "owner": p.username }),
            );
            Ok(StatusCode::NO_CONTENT)
        } else {
            Err(Problem::not_found(format!("you have no token `{id}`")))
        }
    })
    .await
}

/// Users (admin).
///
/// Every user with role, status, and two-factor state.
#[utoipa::path(get, path = "/api/v1/users", tag = "auth",
    responses((status = 200, body = Listed<UserInfo>, description = "The result."), (status = 403, body = Problem, description = "Signed in, but not allowed to do this (role, token scope, or agent restriction).")))]
pub(crate) async fn list_users(
    State(auth): State<AuthState>,
) -> Result<Json<Listed<UserInfo>>, Problem> {
    blocking(move || {
        Ok(Json(Listed {
            items: auth
                .state()
                .users()
                .map_err(db)?
                .iter()
                .map(user_info)
                .collect(),
        }))
    })
    .await
}

/// Add a user (admin).
///
/// `role` is `viewer`, `operator`, or `admin`. The password needs at least 10 characters.
#[utoipa::path(post, path = "/api/v1/users", tag = "auth", request_body = CreateUser,
    responses((status = 201, body = UserInfo, description = "Created."), (status = 409, body = Problem, description = "Conflicts with the current state: problem+json says what to change.")))]
pub(crate) async fn create_user(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    req_ext: axum::http::Extensions,
    b: Result<Json<CreateUser>, JsonRejection>,
) -> Result<(StatusCode, Json<UserInfo>), Problem> {
    let r = body(b)?;
    let p = principal(&req_ext)?;
    let (ip, why) = (remote(&auth, &req_ext, &headers), reason(&headers));
    blocking(move || {
        let u = auth.create_user(
            &r.username,
            &r.password,
            r.role,
            r.allow_basic_api.unwrap_or(false),
            now(),
        )?;
        auth.record(
            &auth.actor(&p, ip, why),
            "user.create",
            &u.username,
            &serde_json::json!({ "role": u.role, "allowBasicApi": u.allow_basic_api }),
        );
        Ok((StatusCode::CREATED, Json(user_info(&u))))
    })
    .await
}

/// Change a user (admin).
///
/// Role, disabled, HTTP Basic opt-in, a new password (ends their sessions), or a TOTP reset.
/// The last enabled admin can't be demoted or disabled.
#[utoipa::path(patch, path = "/api/v1/users/{id}", tag = "auth", request_body = UpdateUser,
    params(("id" = i64, Path, description = "User ID")),
    responses((status = 200, body = UserInfo, description = "The result."), (status = 404, body = Problem, description = "Not found."), (status = 409, body = Problem, description = "Conflicts with the current state: problem+json says what to change.")))]
pub(crate) async fn update_user(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    req_ext: axum::http::Extensions,
    Path(id): Path<i64>,
    b: Result<Json<UpdateUser>, JsonRejection>,
) -> Result<Json<UserInfo>, Problem> {
    let r = body(b)?;
    let p = principal(&req_ext)?;
    let (ip, why) = (remote(&auth, &req_ext, &headers), reason(&headers));
    blocking(move || {
        let st = auth.state();
        let u = st
            .user(id)
            .map_err(db)?
            .ok_or_else(|| Problem::not_found(format!("no user {id}")))?;
        let was_admin = u.role == "admin" && !u.disabled;
        let stays_admin = r.role.map_or(u.role == "admin", |x| x == Role::Admin)
            && !r.disabled.unwrap_or(u.disabled);
        if was_admin && !stays_admin && st.admin_count().map_err(db)? <= 1 {
            return Err(Problem::new(Code::Conflict, "this is the last admin")
                .hint("Make another user an admin first."));
        }
        if let Some(pw) = &r.password {
            super::valid_password(pw)?;
            let hash = crypto::hash_password(pw).map_err(Problem::internal)?;
            st.set_password(id, &hash, now()).map_err(db)?;
            st.delete_user_sessions(id, None).map_err(db)?;
        }
        if r.reset_totp == Some(true) {
            st.set_totp(id, None, false).map_err(db)?;
            st.set_recovery_codes(id, &[]).map_err(db)?;
        }
        st.update_user(id, r.role.map(Role::as_str), r.disabled, r.allow_basic_api)
            .map_err(db)?;
        if r.disabled == Some(true) {
            st.delete_user_sessions(id, None).map_err(db)?;
        }
        auth.forget_basic(id);
        let after = st
            .user(id)
            .map_err(db)?
            .ok_or_else(|| Problem::not_found(format!("no user {id}")))?;
        // What changed, as {field: {from, to}} (passwords and secrets only as "changed").
        let mut changes = serde_json::Map::new();
        let mut diff = |k: &str, a: serde_json::Value, b: serde_json::Value| {
            if a != b {
                changes.insert(k.to_owned(), serde_json::json!({ "from": a, "to": b }));
            }
        };
        diff("role", u.role.clone().into(), after.role.clone().into());
        diff("disabled", u.disabled.into(), after.disabled.into());
        diff(
            "allowBasicApi",
            u.allow_basic_api.into(),
            after.allow_basic_api.into(),
        );
        if r.password.is_some() {
            changes.insert("password".into(), "changed".into());
        }
        if r.reset_totp == Some(true) && u.totp_enabled {
            changes.insert("totp".into(), "reset".into());
        }
        if !changes.is_empty() {
            auth.record(
                &auth.actor(&p, ip, why),
                "user.update",
                &after.username,
                &changes.into(),
            );
        }
        Ok(Json(user_info(&after)))
    })
    .await
}

/// Delete a user (admin).
///
/// Also deletes their sessions and tokens. The last enabled admin can't be deleted.
#[utoipa::path(delete, path = "/api/v1/users/{id}", tag = "auth",
    params(("id" = i64, Path, description = "User ID")),
    responses((status = 204, description = "Deleted."), (status = 404, body = Problem, description = "Not found."), (status = 409, body = Problem, description = "Conflicts with the current state: problem+json says what to change.")))]
pub(crate) async fn delete_user(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    req_ext: axum::http::Extensions,
    Path(id): Path<i64>,
) -> Result<StatusCode, Problem> {
    let p = principal(&req_ext)?;
    let (ip, why) = (remote(&auth, &req_ext, &headers), reason(&headers));
    blocking(move || {
        let st = auth.state();
        let u = st
            .user(id)
            .map_err(db)?
            .ok_or_else(|| Problem::not_found(format!("no user {id}")))?;
        if u.role == "admin" && !u.disabled && st.admin_count().map_err(db)? <= 1 {
            return Err(Problem::new(Code::Conflict, "this is the last admin")
                .hint("Make another user an admin first."));
        }
        st.delete_user(id).map_err(db)?;
        auth.forget_basic(id);
        auth.record(
            &auth.actor(&p, ip, why),
            "user.delete",
            &u.username,
            &serde_json::json!({ "role": u.role }),
        );
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

#[cfg(test)]
mod group_tests {
    // REQ: AGT-004 — the restricted group replaces whatever `group` was asked for.
    #[test]
    fn agt_004_group_is_forced_into_the_query() {
        let u: axum::http::Uri = "/api/v1/queries?group=adults&limit=5".parse().unwrap();
        let out = super::with_group(&u, "kids room").unwrap();
        assert_eq!(out.to_string(), "/api/v1/queries?limit=5&group=kids%20room");
        let bare: axum::http::Uri = "/api/v1/stats/top".parse().unwrap();
        assert_eq!(
            super::with_group(&bare, "kids").unwrap().to_string(),
            "/api/v1/stats/top?group=kids"
        );
    }
}
