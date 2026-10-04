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

use super::{Auth, NewSession, Presented, Principal, Role, Scope, Via, crypto};
use crate::problem::{Code, Problem};

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
fn body<T>(b: Result<Json<T>, JsonRejection>) -> Result<T, Problem> {
    b.map(|Json(v)| v)
        .map_err(|e| Problem::invalid(format!("request body: {}", e.body_text())))
}

fn remote(req_ext: &axum::http::Extensions) -> IpAddr {
    req_ext
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0.ip())
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
    let (session, bearer, basic) = presented(&headers);
    let result = blocking(move || {
        let p = Presented {
            session: session.as_deref(),
            bearer: bearer.as_deref(),
            basic,
            https,
        };
        auth.authenticate(&p, now())
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
    req.extensions_mut().insert(principal);
    next.run(req).await
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

fn principal(ext: &axum::http::Extensions) -> Result<Principal, Problem> {
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
    pub scope: Scope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_unix_seconds: Option<u64>,
    pub created_unix_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_unix_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateToken {
    /// What it's for (`grafana`, `homepage-widget`).
    pub name: String,
    /// Default: `read`.
    pub scope: Option<Scope>,
    /// Default: never expires.
    pub expires_in_days: Option<u32>,
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
        scope: Scope::parse(&t.scope).unwrap_or(Scope::Read),
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

/// Admin-only user management.
pub fn admin(auth: AuthState) -> Router {
    Router::new()
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/users/{id}", patch(update_user).delete(delete_user))
        .with_state(auth)
}

// ---- handlers

/// Sign-in state.
///
/// Whether first-run setup is needed, and who the request is signed in as (if anyone),
/// with the session's CSRF token. Public; the UI calls it on load.
#[utoipa::path(get, path = "/api/v1/auth/status", tag = "auth",
    responses((status = 200, body = AuthStatus)))]
pub(crate) async fn status(
    State(auth): State<AuthState>,
    headers: HeaderMap,
) -> Result<Json<AuthStatus>, Problem> {
    let (session, bearer, basic) = presented(&headers);
    let https = is_https(&headers);
    blocking(move || {
        let setup_required = auth.setup_required()?;
        let p = Presented {
            session: session.as_deref(),
            bearer: bearer.as_deref(),
            basic,
            https,
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
        Ok(Json(AuthStatus {
            setup_required,
            authenticated: user.is_some(),
            user,
            csrf_token: csrf,
        }))
    })
    .await
}

/// Create the first admin.
///
/// Only while no user exists. `setupToken` is printed in the server log at startup and saved
/// in `<data_dir>/setup-token`. Signs the new admin in (sets the session cookie).
#[utoipa::path(post, path = "/api/v1/auth/setup", tag = "auth", request_body = SetupRequest,
    responses((status = 201, body = LoginResponse), (status = 401, body = Problem),
        (status = 409, body = Problem, description = "Setup is already done.")))]
pub(crate) async fn setup(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    req_ext: axum::http::Extensions,
    b: Result<Json<SetupRequest>, JsonRejection>,
) -> Result<Response, Problem> {
    let r = body(b)?;
    let ip = remote(&req_ext);
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
    responses((status = 200, body = LoginResponse), (status = 401, body = Problem),
        (status = 429, body = Problem)))]
pub(crate) async fn login(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    req_ext: axum::http::Extensions,
    b: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Response, Problem> {
    let r = body(b)?;
    let ip = remote(&req_ext);
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
    responses((status = 204, description = "Signed out.")))]
pub(crate) async fn logout(
    State(auth): State<AuthState>,
    req_ext: axum::http::Extensions,
) -> Result<Response, Problem> {
    let p = principal(&req_ext)?;
    if let Via::Session { id_hash, .. } = p.via {
        blocking(move || auth.end_session(&id_hash)).await?;
    }
    Ok((
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, clear_cookie())],
    )
        .into_response())
}

/// Who am I.
///
/// The signed-in user: role (capped by a token's scope), two-factor state, unused recovery
/// codes, and how this request authenticated.
#[utoipa::path(get, path = "/api/v1/auth/me", tag = "auth", responses((status = 200, body = Me)))]
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
    responses((status = 204, description = "Changed."), (status = 401, body = Problem)))]
pub(crate) async fn change_password(
    State(auth): State<AuthState>,
    req_ext: axum::http::Extensions,
    b: Result<Json<PasswordChange>, JsonRejection>,
) -> Result<StatusCode, Problem> {
    let r = body(b)?;
    let p = principal(&req_ext)?;
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
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

/// Start two-factor enrollment.
///
/// Returns a new TOTP secret (base32 and an `otpauth://` URL for a QR code). Nothing is
/// enforced until POST /auth/totp/enable confirms a code from the app.
#[utoipa::path(post, path = "/api/v1/auth/totp/setup", tag = "auth",
    responses((status = 200, body = TotpSetup), (status = 409, body = Problem)))]
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
    responses((status = 200, body = RecoveryCodes), (status = 401, body = Problem)))]
pub(crate) async fn totp_enable(
    State(auth): State<AuthState>,
    req_ext: axum::http::Extensions,
    b: Result<Json<TotpCode>, JsonRejection>,
) -> Result<Json<RecoveryCodes>, Problem> {
    let r = body(b)?;
    let p = principal(&req_ext)?;
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
        Ok(Json(RecoveryCodes { codes }))
    })
    .await
}

/// Turn off two-factor sign-in.
///
/// Needs the current password. Removes the TOTP secret and the unused recovery codes.
#[utoipa::path(post, path = "/api/v1/auth/totp/disable", tag = "auth", request_body = PasswordConfirm,
    responses((status = 204, description = "Off."), (status = 401, body = Problem)))]
pub(crate) async fn totp_disable(
    State(auth): State<AuthState>,
    req_ext: axum::http::Extensions,
    b: Result<Json<PasswordConfirm>, JsonRejection>,
) -> Result<StatusCode, Problem> {
    let r = body(b)?;
    let p = principal(&req_ext)?;
    blocking(move || {
        let u = auth.active_user(p.user_id)?;
        if !crypto::verify_password(&r.password, &u.password_hash) {
            return Err(Problem::new(Code::Unauthorized, "the password is wrong"));
        }
        auth.state().set_totp(u.id, None, false).map_err(db)?;
        auth.state().set_recovery_codes(u.id, &[]).map_err(db)?;
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

/// My API tokens.
///
/// Name, scope, expiry, and last use. The secrets themselves are never shown again.
#[utoipa::path(get, path = "/api/v1/tokens", tag = "auth",
    responses((status = 200, body = Listed<TokenInfo>)))]
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
    responses((status = 201, body = NewToken), (status = 403, body = Problem)))]
pub(crate) async fn create_token(
    State(auth): State<AuthState>,
    req_ext: axum::http::Extensions,
    b: Result<Json<CreateToken>, JsonRejection>,
) -> Result<(StatusCode, Json<NewToken>), Problem> {
    let r = body(b)?;
    let p = principal(&req_ext)?;
    blocking(move || {
        let name = r.name.trim();
        if name.is_empty() || name.len() > 64 {
            return Err(Problem::invalid("`name`: 1-64 characters"));
        }
        let scope = r.scope.unwrap_or(Scope::Read);
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
        let t = auth
            .state()
            .token(&id)
            .map_err(db)?
            .ok_or_else(|| Problem::internal("token vanished"))?;
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

/// Revoke one of my API tokens.
///
/// By the `id` from GET /tokens. Takes effect immediately; other tokens are unaffected.
#[utoipa::path(delete, path = "/api/v1/tokens/{id}", tag = "auth",
    params(("id" = String, Path, description = "Token ID")),
    responses((status = 204, description = "Revoked."), (status = 404, body = Problem)))]
pub(crate) async fn delete_token(
    State(auth): State<AuthState>,
    req_ext: axum::http::Extensions,
    Path(id): Path<String>,
) -> Result<StatusCode, Problem> {
    let p = principal(&req_ext)?;
    blocking(move || {
        if auth.state().delete_token(&id, p.user_id).map_err(db)? {
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
    responses((status = 200, body = Listed<UserInfo>), (status = 403, body = Problem)))]
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
    responses((status = 201, body = UserInfo), (status = 409, body = Problem)))]
pub(crate) async fn create_user(
    State(auth): State<AuthState>,
    b: Result<Json<CreateUser>, JsonRejection>,
) -> Result<(StatusCode, Json<UserInfo>), Problem> {
    let r = body(b)?;
    blocking(move || {
        let u = auth.create_user(
            &r.username,
            &r.password,
            r.role,
            r.allow_basic_api.unwrap_or(false),
            now(),
        )?;
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
    responses((status = 200, body = UserInfo), (status = 404, body = Problem), (status = 409, body = Problem)))]
pub(crate) async fn update_user(
    State(auth): State<AuthState>,
    Path(id): Path<i64>,
    b: Result<Json<UpdateUser>, JsonRejection>,
) -> Result<Json<UserInfo>, Problem> {
    let r = body(b)?;
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
        let u = st
            .user(id)
            .map_err(db)?
            .ok_or_else(|| Problem::not_found(format!("no user {id}")))?;
        Ok(Json(user_info(&u)))
    })
    .await
}

/// Delete a user (admin).
///
/// Also deletes their sessions and tokens. The last enabled admin can't be deleted.
#[utoipa::path(delete, path = "/api/v1/users/{id}", tag = "auth",
    params(("id" = i64, Path, description = "User ID")),
    responses((status = 204, description = "Deleted."), (status = 404, body = Problem), (status = 409, body = Problem)))]
pub(crate) async fn delete_user(
    State(auth): State<AuthState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, Problem> {
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
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}
