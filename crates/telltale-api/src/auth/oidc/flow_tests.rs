//! REQ: API-004 — the whole sign-in flow against an in-process fake identity provider:
//! discovery, JWKS, the token endpoint, RS256-signed ID tokens with a nonce and groups.

// Short names (h, r, v) keep the request/response story readable.
#![allow(clippy::many_single_char_names)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::Json;
use axum::routing::{get, post};
use openidconnect::core::{
    CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreProviderMetadata, CoreResponseType, CoreRsaPrivateSigningKey, CoreSubjectIdentifierType,
};
use openidconnect::{
    AdditionalClaims, Audience, AuthUrl, EmptyAdditionalProviderMetadata, IdToken, IdTokenClaims,
    IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl, Nonce, PrivateSigningKey, ResponseTypes,
    StandardClaims, SubjectIdentifier, TokenUrl,
};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

use super::{Fetch, McpOAuth, Oidc, OidcSettings, ProviderSettings};
use crate::auth::{Auth, Role, Settings};

const ISSUER: &str = "https://idp.test";
const PEM: &str = include_str!("test-key.pem");

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Groups {
    groups: Vec<String>,
}
impl AdditionalClaims for Groups {}

/// What the fake identity provider issues for a code: (subject, username, groups).
type Codes = Arc<Mutex<HashMap<String, (String, String, Vec<String>, String)>>>;

#[derive(Clone)]
struct Idp {
    codes: Codes,
    key: Arc<CoreRsaPrivateSigningKey>,
}

fn key() -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(PEM, Some(JsonWebKeyId::new("k1".into()))).unwrap()
}

fn idp(codes: Codes) -> Router {
    let state = Idp {
        codes,
        key: Arc::new(key()),
    };
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(state)
}

async fn discovery() -> Json<serde_json::Value> {
    let m = CoreProviderMetadata::new(
        IssuerUrl::new(ISSUER.into()).unwrap(),
        AuthUrl::new(format!("{ISSUER}/authorize")).unwrap(),
        JsonWebKeySetUrl::new(format!("{ISSUER}/jwks")).unwrap(),
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        vec![CoreSubjectIdentifierType::Public],
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(TokenUrl::new(format!("{ISSUER}/token")).unwrap()));
    let mut v = serde_json::to_value(&m).unwrap();
    v["end_session_endpoint"] = format!("{ISSUER}/logout").into();
    Json(v)
}

async fn jwks(State(s): State<Idp>) -> Json<serde_json::Value> {
    let k: CoreJsonWebKey = s.key.as_verification_key();
    Json(serde_json::json!({ "keys": [k] }))
}

async fn token(State(s): State<Idp>, body: String) -> Result<Json<serde_json::Value>, StatusCode> {
    let f: HashMap<String, String> = body
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    let code = f.get("code").ok_or(StatusCode::BAD_REQUEST)?;
    assert!(f.contains_key("code_verifier"), "PKCE verifier sent");
    let (sub, name, groups, nonce) = s
        .codes
        .lock()
        .unwrap()
        .remove(code)
        .ok_or(StatusCode::BAD_REQUEST)?;
    let now = chrono::Utc::now();
    let claims = IdTokenClaims::new(
        IssuerUrl::new(ISSUER.into()).unwrap(),
        vec![Audience::new("telltale".into())],
        now + chrono::Duration::minutes(5),
        now,
        StandardClaims::new(SubjectIdentifier::new(sub))
            .set_preferred_username(Some(openidconnect::EndUserUsername::new(name))),
        Groups { groups },
    )
    .set_nonce(Some(Nonce::new(nonce)));
    let id: IdToken<
        Groups,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    > = IdToken::new(
        claims,
        s.key.as_ref(),
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .unwrap();
    Ok(Json(serde_json::json!({
        "access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": id.to_string()
    })))
}

/// Fetch that hands requests to the fake identity provider router instead of the network.
fn fetch(idp: Router) -> Fetch {
    Arc::new(move |req: Request<Vec<u8>>| {
        let idp = idp.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let path = parts
                .uri
                .path_and_query()
                .map_or("/", |p| p.as_str())
                .to_owned();
            let mut b = Request::builder().method(parts.method).uri(path);
            for (k, v) in &parts.headers {
                b = b.header(k, v);
            }
            let resp = idp
                .oneshot(b.body(Body::from(body)).unwrap())
                .await
                .unwrap();
            let (parts, body) = resp.into_parts();
            let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap().to_vec();
            Ok(axum::http::Response::from_parts(parts, bytes))
        })
    })
}

/// A backend with no data (these tests only use the auth routes).
struct NoData;
impl crate::Backend for NoData {
    fn system_info(&self) -> crate::model::SystemInfo {
        unimplemented!()
    }
    fn timeseries(&self, _: crate::model::Step, _: u64, _: u64) -> Vec<crate::model::TimeBucket> {
        Vec::new()
    }
    fn top(
        &self,
        _: crate::model::TopKind,
        _: crate::model::Hour,
        _: usize,
        _: Option<std::net::IpAddr>,
    ) -> Vec<crate::model::TopItem> {
        Vec::new()
    }
    fn latency(
        &self,
        _: crate::model::LatencyBy,
        _: crate::model::Hour,
    ) -> Vec<crate::model::LatencyRow> {
        Vec::new()
    }
    fn queries(
        &self,
        _: &crate::model::QueryParams,
        _: u64,
        _: u64,
        _: usize,
    ) -> Result<crate::model::QueryPage, crate::problem::Problem> {
        unimplemented!()
    }
    fn explain(
        &self,
        _: &crate::model::ExplainParams,
    ) -> Result<crate::model::Explanation, crate::problem::Problem> {
        unimplemented!()
    }
    fn lists(&self) -> Vec<crate::model::ListInfo> {
        Vec::new()
    }
    fn groups(&self) -> Vec<crate::model::GroupInfo> {
        Vec::new()
    }
    fn clients(&self) -> Vec<crate::model::ClientInfo> {
        Vec::new()
    }
    fn upstreams(&self) -> Vec<crate::model::UpstreamInfo> {
        Vec::new()
    }
}

struct Harness {
    app: Router,
    codes: Codes,
    auth: Arc<Auth>,
}

fn harness(settings: Settings) -> Harness {
    let codes: Codes = Arc::default();
    let state = Arc::new(telltale_store::state::State::in_memory().unwrap());
    let auth = Arc::new(Auth::new(state, settings));
    auth.set_oidc(Oidc::new(
        OidcSettings {
            public_url: "https://dns.test".into(),
            providers: vec![ProviderSettings {
                id: "fake".into(),
                name: "Fake IdP".into(),
                issuer: ISSUER.into(),
                client_id: "telltale".into(),
                client_secret: Some("s3cret".into()),
                scopes: vec!["openid".into(), "profile".into()],
                username_claim: "preferred_username".into(),
                groups_claim: "groups".into(),
                roles: vec![
                    ("dns-admins".into(), Role::Admin),
                    ("family".into(), Role::Viewer),
                ],
                default_role: None,
                require_verified_email: false,
            }],
            mcp: Some(McpOAuth {
                provider: "fake".into(),
                audience: "https://dns.test/mcp".into(),
            }),
        },
        fetch(idp(Arc::clone(&codes))),
    ));
    // Someone must exist so the UI isn't in first-run setup.
    auth.create_user("root", "correct horse battery", Role::Admin, false, 1)
        .unwrap();
    let app = crate::router(Arc::new(NoData), Arc::clone(&auth));
    Harness { app, codes, auth }
}

fn query_param(url: &str, k: &str) -> String {
    url.split(['?', '&'])
        .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
        .map(|v| v.replace("%2F", "/").replace("%3A", ":"))
        .unwrap_or_default()
}

fn set_cookie(r: &axum::http::Response<Body>, name: &str) -> Option<String> {
    r.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with(&format!("{name}=")))
        .map(|c| c.split(';').next().unwrap_or_default().to_owned())
}

/// Start → (identity provider: issue code for these claims) → callback. Returns the callback response.
async fn sign_in(
    h: &Harness,
    sub: &str,
    name: &str,
    groups: &[&str],
    tamper_cookie: bool,
) -> axum::http::Response<Body> {
    let start = h
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/oidc/fake/start?returnTo=/%23/queries")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::FOUND);
    let to = start.headers()["location"].to_str().unwrap().to_owned();
    assert!(to.starts_with("https://idp.test/authorize?"), "{to}");
    assert!(to.contains("code_challenge_method=S256"), "PKCE");
    assert!(
        to.contains(
            "redirect_uri=https%3A%2F%2Fdns.test%2Fapi%2Fv1%2Fauth%2Foidc%2Ffake%2Fcallback"
        ),
        "{to}"
    );
    let flow = set_cookie(&start, "telltale_oidc").unwrap();
    assert!(
        start.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("SameSite=Lax")
    );
    let (state, nonce) = (query_param(&to, "state"), query_param(&to, "nonce"));
    h.codes.lock().unwrap().insert(
        "code1".into(),
        (
            sub.into(),
            name.into(),
            groups.iter().map(|g| (*g).to_owned()).collect(),
            nonce,
        ),
    );
    let cookie = if tamper_cookie {
        "telltale_oidc=someone-else".to_owned()
    } else {
        flow
    };
    h.app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/auth/oidc/fake/callback?code=code1&state={state}"
            ))
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap()
}

async fn me(h: &Harness, session: &str) -> serde_json::Value {
    let r = h
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/me")
                .header("cookie", session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap()).unwrap()
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one story through the flow
async fn api_004_oidc_sign_in_end_to_end() {
    let h = harness(Settings::default());

    // Status lists the provider; local sign-in is still on.
    let r = h
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap())
            .unwrap();
    assert_eq!(
        v["oidc"][0],
        serde_json::json!({"id": "fake", "name": "Fake IdP"})
    );
    assert_eq!(v["localLogin"], true);

    // First sign-in creates the user with the role from their groups.
    let r = sign_in(&h, "sub-1", "ana", &["dns-admins", "family"], false).await;
    assert_eq!(r.status(), StatusCode::FOUND);
    assert_eq!(
        r.headers()["location"],
        "/#/queries",
        "returns where it started"
    );
    let session = set_cookie(&r, "telltale_session").expect("signed in");
    let m = me(&h, &session).await;
    assert_eq!(
        (m["username"].as_str(), m["role"].as_str()),
        (Some("ana"), Some("admin"))
    );
    let u = h.auth.state().user_by_name("ana").unwrap().unwrap();
    assert_eq!(u.oidc_provider.as_deref(), Some("fake"));
    assert!(
        !crate::auth::crypto::verify_password("anything", &u.password_hash),
        "no local password"
    );

    // Next sign-in with fewer groups lowers the role, and it's audited.
    let r = sign_in(&h, "sub-1", "ana", &["family"], false).await;
    let session = set_cookie(&r, "telltale_session").unwrap();
    assert_eq!(me(&h, &session).await["role"], "viewer");
    let updates = h
        .auth
        .state()
        .audit_page(None, 10, Some("user.update"), None)
        .unwrap();
    assert!(
        updates[0]
            .detail
            .contains("\"from\":\"admin\",\"to\":\"viewer\""),
        "{}",
        updates[0].detail
    );
    let logins = h
        .auth
        .state()
        .audit_page(None, 10, Some("auth.login"), None)
        .unwrap();
    assert!(
        logins
            .iter()
            .all(|e| e.actor_kind == "oidc" && e.detail.contains("\"provider\":\"fake\""))
    );

    // A local account with the same name is never taken over: the new user gets name@provider.
    let r = sign_in(&h, "sub-2", "root", &["family"], false).await;
    let session = set_cookie(&r, "telltale_session").unwrap();
    assert_eq!(me(&h, &session).await["username"], "root@fake");

    // No mapped group: refused, back to sign-in with the reason.
    let r = sign_in(&h, "sub-3", "eve", &["strangers"], false).await;
    let to = r.headers()["location"].to_str().unwrap();
    assert!(
        to.starts_with("/#/?loginError=") && to.contains("group"),
        "{to}"
    );
    assert!(set_cookie(&r, "telltale_session").is_none());

    // A callback from a different browser (no matching flow cookie) is refused.
    let r = sign_in(&h, "sub-1", "ana", &["family"], true).await;
    assert!(
        r.headers()["location"]
            .to_str()
            .unwrap()
            .contains("another%20browser")
    );
    assert!(set_cookie(&r, "telltale_session").is_none());

    // Signing out of an OIDC session points at the provider's logout.
    let r = sign_in(&h, "sub-1", "ana", &["family"], false).await;
    let session = set_cookie(&r, "telltale_session").unwrap();
    let csrf = h
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/status")
                .header("cookie", &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(csrf.into_body(), 1 << 16)
            .await
            .unwrap(),
    )
    .unwrap();
    let out = h
        .app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/logout")
                .header("cookie", &session)
                .header("x-csrf-token", v["csrfToken"].as_str().unwrap())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(out.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(out.into_body(), 1 << 16)
            .await
            .unwrap(),
    )
    .unwrap();
    let url = v["logoutUrl"].as_str().unwrap();
    assert!(url.starts_with("https://idp.test/logout?client_id=telltale&post_logout_redirect_uri=https%3A%2F%2Fdns.test%2F"), "{url}");
}

#[tokio::test]
async fn api_004_states_are_single_use_and_unknown_providers_404() {
    let h = harness(Settings::default());
    let r = h
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/oidc/fake/callback?code=x&state=never-issued")
                .header("cookie", "telltale_oidc=x")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        r.headers()["location"]
            .to_str()
            .unwrap()
            .contains("expired")
    );
    let r = h
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/oidc/nope/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        r.headers()["location"]
            .to_str()
            .unwrap()
            .contains("no%20sign-in%20provider")
    );
    let r = h.app.clone().oneshot(Request::get("/api/v1/auth/oidc/fake/callback?error=access_denied&error_description=User%20cancelled").body(Body::empty()).unwrap()).await.unwrap();
    assert!(
        r.headers()["location"]
            .to_str()
            .unwrap()
            .contains("loginError=")
    );
}

/// Break-glass: with local sign-in off, passwords work only for admins from admin networks.
#[tokio::test]
async fn api_004_disable_local_login_keeps_a_break_glass_admin() {
    let lan = Settings {
        disable_local_login: true,
        admin_networks: vec![("0.0.0.0".parse().unwrap(), 0)],
        ..Settings::default()
    };
    let h = harness(lan);
    h.auth
        .create_user("kid", "another long password", Role::Viewer, false, 1)
        .unwrap();
    let ip = "192.168.1.5".parse().unwrap();
    assert!(
        h.auth
            .login("root", "correct horse battery", None, None, ip, 10)
            .is_ok(),
        "admin from an admin network"
    );
    let e = h
        .auth
        .login("kid", "another long password", None, None, ip, 10)
        .unwrap_err();
    assert_eq!(
        e.code,
        crate::problem::Code::Forbidden,
        "non-admins must use the provider"
    );

    let closed = Settings {
        disable_local_login: true,
        admin_networks: vec![("10.0.0.0".parse().unwrap(), 8)],
        ..Settings::default()
    };
    let h = harness(closed);
    let e = h
        .auth
        .login("root", "correct horse battery", None, None, ip, 10)
        .unwrap_err();
    assert_eq!(
        e.code,
        crate::problem::Code::Forbidden,
        "not from an admin network"
    );
    let r = h
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap())
            .unwrap();
    assert_eq!(v["localLogin"], false, "the UI hides the password form");
    assert!(crate::auth::in_network(
        "10.1.2.3".parse().unwrap(),
        "10.0.0.0".parse().unwrap(),
        8
    ));
    assert!(crate::auth::in_network(
        "::ffff:10.1.2.3".parse().unwrap(),
        "10.0.0.0".parse().unwrap(),
        8
    ));
    assert!(!crate::auth::in_network(
        "11.1.2.3".parse().unwrap(),
        "10.0.0.0".parse().unwrap(),
        8
    ));
}

// ---- the break-glass gate (issue #63). These tests pin what the code does today, so a change to
// it (the owner's decisions on the default list and on `X-Forwarded-For`) shows up here.

/// `req` as if it arrived from `peer` (the listener puts the connection's address there).
fn from_peer(peer: &str, mut req: Request<Body>) -> Request<Body> {
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::new(
            peer.parse().unwrap(),
            40_000,
        )));
    req
}

async fn answer(app: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let r = app.clone().oneshot(req).await.unwrap();
    let status = r.status();
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// The sign-in form's request: `root`, with the right password.
fn form_login(peer: &str, forwarded_for: Option<&str>) -> Request<Body> {
    let mut b = Request::post("/api/v1/auth/login").header("content-type", "application/json");
    if let Some(f) = forwarded_for {
        b = b.header("x-forwarded-for", f);
    }
    from_peer(
        peer,
        b.body(Body::from(
            serde_json::json!({"username": "root", "password": "correct horse battery"})
                .to_string(),
        ))
        .unwrap(),
    )
}

/// What the sign-in page is told: `localLogin` from `GET /auth/status`.
async fn form_offered(app: &Router, peer: &str, forwarded_for: Option<&str>) -> bool {
    let mut b = Request::get("/api/v1/auth/status");
    if let Some(f) = forwarded_for {
        b = b.header("x-forwarded-for", f);
    }
    let (s, v) = answer(app, from_peer(peer, b.body(Body::empty()).unwrap())).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["localLogin"].as_bool().unwrap()
}

fn net(s: &str, prefix: u8) -> (std::net::IpAddr, u8) {
    (s.parse().unwrap(), prefix)
}

fn refused(v: &serde_json::Value) -> bool {
    v.to_string()
        .contains("password sign-in is off on this server")
}

/// REQ: API-004 (issue #63) — HTTP Basic obeys the same flag and list as the form, and the check
/// comes before the one-minute cache of verified credentials: an admin from inside the list gets
/// in, and the same credentials from outside it, right after, do not; a non-admin never does.
#[tokio::test]
async fn api_004_basic_is_gated_like_the_form() {
    use base64::Engine as _;
    let h = harness(Settings {
        disable_local_login: true,
        admin_networks: vec![net("192.168.1.0", 24)],
        ..Settings::default()
    });
    h.auth
        .create_user("ops", "correct horse battery", Role::Admin, true, 1)
        .unwrap();
    h.auth
        .create_user("kid", "another long password", Role::Viewer, true, 1)
        .unwrap();
    let basic = |u: &str, p: &str| {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
        )
    };
    let me = |peer: &str, credentials: &str| {
        let mut r = from_peer(
            peer,
            Request::get("/api/v1/auth/me")
                .header("authorization", credentials)
                .body(Body::empty())
                .unwrap(),
        );
        // Over the listener's own TLS, so that Basic is allowed at all.
        r.extensions_mut()
            .insert(crate::auth::routes::TlsConnection);
        r
    };
    let ops = basic("ops", "correct horse battery");
    let kid = basic("kid", "another long password");

    let (s, v) = answer(&h.app, me("192.168.1.5", &ops)).await;
    assert_eq!(s, StatusCode::OK, "an admin from inside the list: {v}");
    let (s, v) = answer(&h.app, me("192.168.1.5", &kid)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "a viewer from inside: {v}");
    assert!(refused(&v), "it says why: {v}");
    let (s, v) = answer(&h.app, me("10.9.9.9", &ops)).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "the same admin from outside, with the credentials cached: {v}"
    );
    assert!(refused(&v), "{v}");
    let (s, v) = answer(&h.app, me("10.9.9.9", &kid)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "a viewer from outside: {v}");
    // The page agrees: the form is offered inside the list only.
    assert!(form_offered(&h.app, "192.168.1.5", None).await);
    assert!(!form_offered(&h.app, "10.9.9.9", None).await);
}

/// REQ: API-004 (issue #63) — `allowed_admin_networks = []` leaves no address that may use a
/// password: not loopback, not the LAN, for the form or for Basic, and the page hides the form.
#[tokio::test]
async fn api_004_empty_break_glass_list_refuses_everyone() {
    use base64::Engine as _;
    let h = harness(Settings {
        disable_local_login: true,
        admin_networks: Vec::new(),
        ..Settings::default()
    });
    h.auth
        .create_user("ops", "correct horse battery", Role::Admin, true, 1)
        .unwrap();
    for peer in ["127.0.0.1", "::1", "192.168.1.5", "203.0.113.9"] {
        let (s, v) = answer(&h.app, form_login(peer, None)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "form from {peer}: {v}");
        assert!(refused(&v), "{peer}: {v}");
        assert!(!form_offered(&h.app, peer, None).await, "{peer}");
        let mut r = from_peer(
            peer,
            Request::get("/api/v1/auth/me")
                .header(
                    "authorization",
                    format!(
                        "Basic {}",
                        base64::engine::general_purpose::STANDARD
                            .encode("ops:correct horse battery")
                    ),
                )
                .body(Body::empty())
                .unwrap(),
        );
        r.extensions_mut()
            .insert(crate::auth::routes::TlsConnection);
        let (s, v) = answer(&h.app, r).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "Basic from {peer}: {v}");
    }
}

/// REQ: API-004 (issue #63) — `X-Forwarded-For` is read only from `[api] trusted_proxies`: a
/// client that is not a proxy can't claim to be loopback, and from a proxy it is the rightmost
/// entry that counts (the one the proxy added), not a forged one on the left.
#[tokio::test]
async fn api_004_forwarded_for_from_a_non_proxy_is_ignored_for_break_glass() {
    let h = harness(Settings {
        disable_local_login: true,
        admin_networks: vec![net("127.0.0.0", 8), net("::1", 128)],
        trusted_proxies: vec![net("10.0.0.1", 32)],
        ..Settings::default()
    });
    // A LAN host sending the header itself.
    let (s, v) = answer(&h.app, form_login("192.168.1.50", Some("127.0.0.1"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(!form_offered(&h.app, "192.168.1.50", Some("127.0.0.1")).await);
    // Through the proxy: a forged `127.0.0.1` on the left, the real client added on the right.
    let (s, v) = answer(
        &h.app,
        form_login("10.0.0.1", Some("127.0.0.1, 192.168.1.50")),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(!form_offered(&h.app, "10.0.0.1", Some("127.0.0.1, 192.168.1.50")).await);
    // The machine itself, with no proxy in between, is still let in.
    let (s, v) = answer(&h.app, form_login("127.0.0.1", None)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(form_offered(&h.app, "127.0.0.1", None).await);
}

/// REQ: API-004 (issue #63) — the reason the docs say a proxy on the same host needs
/// `trusted_proxies = ["127.0.0.1/32"]`: loopback is not trusted for `X-Forwarded-For` by itself,
/// so with the list unset every browser the proxy serves looks like loopback and a loopback-only
/// break-glass list is open to all of them; once the proxy is listed, the real client decides.
#[tokio::test]
async fn api_004_a_same_host_proxy_looks_like_loopback_until_it_is_listed() {
    let loopback = || vec![net("127.0.0.0", 8), net("::1", 128)];
    let h = harness(Settings {
        disable_local_login: true,
        admin_networks: loopback(),
        trusted_proxies: Vec::new(),
        ..Settings::default()
    });
    let (s, v) = answer(&h.app, form_login("127.0.0.1", Some("203.0.113.9"))).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "unset: the proxy's address is the client's, a stranger gets the form's answer: {v}"
    );
    assert!(form_offered(&h.app, "127.0.0.1", Some("203.0.113.9")).await);

    let h = harness(Settings {
        disable_local_login: true,
        admin_networks: loopback(),
        trusted_proxies: vec![net("127.0.0.1", 32)],
        ..Settings::default()
    });
    let (s, v) = answer(&h.app, form_login("127.0.0.1", Some("203.0.113.9"))).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "listed: the stranger is refused: {v}"
    );
    assert!(!form_offered(&h.app, "127.0.0.1", Some("203.0.113.9")).await);
}

/// REQ: API-004 (issue #63) — the reason the docs say `trusted_proxies` lists only the proxies,
/// never the LAN: a machine inside a listed range can send `X-Forwarded-For: 127.0.0.1` itself and
/// be believed. This is a misconfiguration, pinned here as what happens today (a hardening that
/// ignores a forwarded loopback address from a non-loopback peer is the owner's decision).
#[tokio::test]
async fn api_004_a_trusted_range_that_covers_the_lan_believes_a_forged_loopback() {
    let h = harness(Settings {
        disable_local_login: true,
        admin_networks: vec![net("127.0.0.0", 8), net("::1", 128)],
        trusted_proxies: vec![net("10.0.0.0", 8)],
        ..Settings::default()
    });
    let (s, v) = answer(&h.app, form_login("10.1.2.3", Some("127.0.0.1"))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(form_offered(&h.app, "10.1.2.3", Some("127.0.0.1")).await);
}

// ---- the policy is visible (issue #63, ADR-175)

/// The whole `GET /auth/status` answer for a client at `peer`.
async fn status_for(app: &Router, peer: &str) -> serde_json::Value {
    let (s, v) = answer(
        app,
        from_peer(
            peer,
            Request::get("/api/v1/auth/status")
                .body(Body::empty())
                .unwrap(),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

/// REQ: API-004, API-005 (issue #63, ADR-175) — the public sign-in status says whether password
/// sign-in is restricted (`disable_local_login`): the same for every client, whatever
/// `localLogin` says for it, and without the networks (those are for admins).
#[tokio::test]
async fn api_004_status_says_when_password_sign_in_is_restricted() {
    // The flag off: not restricted, offered to everyone.
    let h = harness(Settings::default());
    for peer in ["192.168.1.5", "203.0.113.9"] {
        let v = status_for(&h.app, peer).await;
        assert_eq!(v["passwordLoginRestricted"], false, "{peer}: {v}");
        assert_eq!(v["localLogin"], true, "{peer}: {v}");
    }

    // The flag on, with a network: restricted for an allowed client and for one outside the list;
    // `localLogin` keeps saying whether the form is offered to this client.
    let h = harness(Settings {
        disable_local_login: true,
        admin_networks: vec![net("192.168.1.0", 24)],
        ..Settings::default()
    });
    let inside = status_for(&h.app, "192.168.1.5").await;
    assert_eq!(inside["passwordLoginRestricted"], true, "{inside}");
    assert_eq!(inside["localLogin"], true, "{inside}");
    let outside = status_for(&h.app, "10.9.9.9").await;
    assert_eq!(outside["passwordLoginRestricted"], true, "{outside}");
    assert_eq!(outside["localLogin"], false, "{outside}");

    // The flag on and no network at all: still restricted, offered to nobody.
    let h = harness(Settings {
        disable_local_login: true,
        admin_networks: Vec::new(),
        ..Settings::default()
    });
    let v = status_for(&h.app, "127.0.0.1").await;
    assert_eq!(v["passwordLoginRestricted"], true, "{v}");
    assert_eq!(v["localLogin"], false, "{v}");

    // Public: one boolean, and no network list anywhere in the answer.
    let mut keys: Vec<&str> = inside
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "authenticated",
            "localLogin",
            "oidc",
            "passwordLoginRestricted",
            "setupRequired"
        ],
        "{inside}"
    );
    assert!(
        !inside.to_string().contains("192.168.1.0"),
        "a network must not appear in a public answer: {inside}"
    );
}

/// A signed-in session's cookie for `username`, on the real clock.
fn cookie_for(h: &Harness, username: &str) -> String {
    let user = h.auth.state().user_by_name(username).unwrap().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let s = h
        .auth
        .start_session(&user, "127.0.0.1".parse().unwrap(), now)
        .unwrap();
    format!("{}={}", crate::auth::routes::COOKIE, s.cookie)
}

/// `GET /users` as `cookie` (none: anonymous).
async fn users_as(app: &Router, cookie: Option<&str>) -> (StatusCode, serde_json::Value) {
    let mut b = Request::get("/api/v1/users");
    if let Some(c) = cookie {
        b = b.header("cookie", c);
    }
    answer(app, b.body(Body::empty()).unwrap()).await
}

/// REQ: API-004, AGT-004 (issue #63, ADR-175) — the networks password sign-in is limited to are
/// told to admins only, in the admin-only user list: an anonymous caller, a viewer, an operator,
/// and a read token of an admin get a refusal that says nothing about them. An admin gets the
/// block for the default-shaped list, a loopback-only list, and an empty one.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one story: who is refused, then what an admin is told
async fn api_004_the_policy_detail_is_admin_only() {
    let reach = vec![
        net("10.0.0.0", 8),
        net("192.168.0.0", 16),
        net("127.0.0.0", 8),
        net("fc00::", 7),
        net("::1", 128),
    ];
    let h = harness(Settings {
        disable_local_login: true,
        admin_networks: reach,
        ..Settings::default()
    });
    h.auth
        .create_user("vic", "a viewer password", Role::Viewer, false, 1)
        .unwrap();
    h.auth
        .create_user("opal", "an operator password", Role::Operator, false, 1)
        .unwrap();

    // Who is refused, and that the refusal carries no network.
    let (id, secret) = (
        crate::auth::crypto::random_id(),
        crate::auth::crypto::random_secret(),
    );
    let root = h.auth.state().user_by_name("root").unwrap().unwrap();
    h.auth
        .state()
        .create_token(
            &id,
            root.id,
            "reader",
            &crate::auth::crypto::secret_hash(&secret),
            "read",
            None,
            1,
        )
        .unwrap();
    let read_token = Request::get("/api/v1/users")
        .header("authorization", format!("Bearer tt_{id}_{secret}"))
        .body(Body::empty())
        .unwrap();
    for (who, (status, body)) in [
        ("anonymous", users_as(&h.app, None).await),
        (
            "a viewer",
            users_as(&h.app, Some(&cookie_for(&h, "vic"))).await,
        ),
        (
            "an operator",
            users_as(&h.app, Some(&cookie_for(&h, "opal"))).await,
        ),
        ("a read token of an admin", answer(&h.app, read_token).await),
    ] {
        let expected = if who == "anonymous" {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::FORBIDDEN
        };
        assert_eq!(status, expected, "{who}: {body}");
        assert!(
            !body.to_string().contains("10.0.0.0") && body.get("passwordLogin").is_none(),
            "{who} must not be told the policy: {body}"
        );
    }

    // An admin is told: the list as configured, in order, as `address/prefix`.
    let admin = cookie_for(&h, "root");
    let (s, v) = users_as(&h.app, Some(&admin)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["items"].as_array().map(Vec::len), Some(3), "{v}");
    assert_eq!(
        v["passwordLogin"],
        serde_json::json!({
            "restricted": true,
            "networks": ["10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128"],
            "coversWholeNetworks": true,
            "includesLoopback": true,
            "loopbackIsTrustedProxy": false
        })
    );

    // Loopback only, with a proxy listed.
    let h = harness(Settings {
        disable_local_login: true,
        admin_networks: vec![net("127.0.0.0", 8), net("::1", 128)],
        trusted_proxies: vec![net("127.0.0.1", 32)],
        ..Settings::default()
    });
    let (s, v) = users_as(&h.app, Some(&cookie_for(&h, "root"))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["passwordLogin"],
        serde_json::json!({
            "restricted": true,
            "networks": ["127.0.0.0/8", "::1/128"],
            "coversWholeNetworks": false,
            "includesLoopback": true,
            "loopbackIsTrustedProxy": true
        })
    );

    // An empty list: restricted, and nobody may use a password.
    let h = harness(Settings {
        disable_local_login: true,
        admin_networks: Vec::new(),
        ..Settings::default()
    });
    let (_, v) = users_as(&h.app, Some(&cookie_for(&h, "root"))).await;
    assert_eq!(
        v["passwordLogin"],
        serde_json::json!({
            "restricted": true,
            "networks": [],
            "coversWholeNetworks": false,
            "includesLoopback": false,
            "loopbackIsTrustedProxy": false
        })
    );

    // The flag off: not restricted, and the list in the settings (unused) is not reported.
    let h = harness(Settings {
        disable_local_login: false,
        admin_networks: vec![net("10.0.0.0", 8)],
        ..Settings::default()
    });
    let (_, v) = users_as(&h.app, Some(&cookie_for(&h, "root"))).await;
    assert_eq!(
        v["passwordLogin"],
        serde_json::json!({
            "restricted": false,
            "networks": [],
            "coversWholeNetworks": false,
            "includesLoopback": false,
            "loopbackIsTrustedProxy": false
        })
    );
}

/// REQ: API-004 (ADR-175) — what the admin's block says about a list of single hosts and about
/// the proxy list. A host (`/32`, `/128`) is not a whole network, so `coversWholeNetworks` stays
/// false for a list of hosts, and for hosts beside loopback; a `/31` (two hosts), a `/24`, or any
/// range is one. `loopbackIsTrustedProxy` is true exactly when `127.0.0.1` is inside a listed
/// proxy network, the test `remote()` applies to the peer (a proxy on this machine arrives from
/// it): a pod network does not count, a `/32` of it or a `/8` around it does.
#[tokio::test]
async fn api_004_the_policy_reports_single_hosts_and_the_loopback_proxy() {
    let case = |networks: Vec<(std::net::IpAddr, u8)>, proxies: Vec<(std::net::IpAddr, u8)>| {
        harness(Settings {
            disable_local_login: true,
            admin_networks: networks,
            trusted_proxies: proxies,
            ..Settings::default()
        })
    };
    let block = |h: &Harness| {
        let cookie = cookie_for(h, "root");
        let app = h.app.clone();
        async move { users_as(&app, Some(&cookie)).await.1["passwordLogin"].clone() }
    };
    let flags = |v: &serde_json::Value| {
        (
            v["coversWholeNetworks"].as_bool(),
            v["includesLoopback"].as_bool(),
            v["loopbackIsTrustedProxy"].as_bool(),
        )
    };

    // Hosts only: not whole networks. The LAN host is not loopback.
    let v = block(&case(vec![net("192.168.1.10", 32)], Vec::new())).await;
    assert_eq!(v["networks"], serde_json::json!(["192.168.1.10/32"]), "{v}");
    assert_eq!(flags(&v), (Some(false), Some(false), Some(false)), "{v}");
    let v = block(&case(
        vec![net("fd00::5", 128), net("10.0.0.7", 32)],
        Vec::new(),
    ))
    .await;
    assert_eq!(flags(&v), (Some(false), Some(false), Some(false)), "{v}");

    // Hosts beside loopback: still hosts, and loopback is listed.
    let v = block(&case(
        vec![net("127.0.0.1", 32), net("192.168.1.10", 32)],
        Vec::new(),
    ))
    .await;
    assert_eq!(flags(&v), (Some(false), Some(true), Some(false)), "{v}");
    let v = block(&case(
        vec![
            net("127.0.0.0", 8),
            net("::1", 128),
            net("192.168.1.10", 32),
        ],
        Vec::new(),
    ))
    .await;
    assert_eq!(flags(&v), (Some(false), Some(true), Some(false)), "{v}");

    // A range is a whole network, however small: a /31, a /24, a v6 /127 and /64.
    for wide in [
        net("192.168.1.10", 31),
        net("192.168.1.0", 24),
        net("fd00::4", 127),
        net("fd00::", 64),
        net("0.0.0.0", 0),
    ] {
        let v = block(&case(vec![net("192.168.1.10", 32), wide], Vec::new())).await;
        assert_eq!(v["coversWholeNetworks"], true, "{wide:?}: {v}");
    }
    // Loopback ranges are this machine, not whole networks; a /7 around 127.0.0.0 is a network.
    let v = block(&case(
        vec![net("127.0.0.0", 8), net("127.1.2.3", 32)],
        Vec::new(),
    ))
    .await;
    assert_eq!(flags(&v), (Some(false), Some(true), Some(false)), "{v}");
    let v = block(&case(vec![net("127.0.0.0", 7)], Vec::new())).await;
    assert_eq!(v["coversWholeNetworks"], true, "{v}");
    assert_eq!(v["includesLoopback"], false, "{v}");

    // Is loopback a trusted proxy? Only when 127.0.0.1 is inside a listed network.
    for (proxies, trusted) in [
        (Vec::new(), false),
        (vec![net("10.42.0.0", 16)], false),
        (vec![net("10.42.0.5", 32)], false),
        (vec![net("::1", 128)], false),
        (vec![net("127.0.0.2", 32)], false),
        (vec![net("127.0.0.1", 32)], true),
        (vec![net("127.0.0.0", 8)], true),
        (vec![net("10.42.0.0", 16), net("127.0.0.1", 32)], true),
        (vec![net("0.0.0.0", 0)], true),
    ] {
        let v = block(&case(vec![net("127.0.0.1", 32)], proxies.clone())).await;
        assert_eq!(v["loopbackIsTrustedProxy"], trusted, "{proxies:?}: {v}");
    }
}

/// An access token from the fake provider, signed with its key.
fn access_token(claims: &serde_json::Value) -> String {
    use base64::Engine as _;
    let b64 = |v: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    };
    let msg = format!(
        "{}.{}",
        b64(&serde_json::json!({"alg": "RS256", "kid": "k1", "typ": "at+jwt"})),
        b64(claims)
    );
    let sig = key()
        .sign(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            msg.as_bytes(),
        )
        .unwrap();
    format!(
        "{msg}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig)
    )
}

async fn mcp_call(
    app: &Router,
    bearer: &str,
    body: serde_json::Value,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// REQ: OPS-014, AGT-008 (ADR-182) — `cluster:upgrade` (a root service installs a build on the
/// native nodes) is for an agent API token an admin made, never for an OAuth access token: the
/// metadata doesn't offer it, and an identity provider's token that names it (an admin's, even)
/// doesn't get it, so the update route answers 403.
#[tokio::test]
async fn ops_014_an_oauth_token_never_carries_cluster_upgrade() {
    let h = harness(Settings::default());
    let r = h
        .app
        .clone()
        .oneshot(
            Request::get("/.well-known/oauth-protected-resource")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let meta: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap())
            .unwrap();
    let offered = meta["scopes_supported"].as_array().unwrap();
    assert!(offered.contains(&"cluster:admin".into()), "{meta}");
    assert!(!offered.contains(&"cluster:upgrade".into()), "{meta}");
    h.auth
        .state()
        .create_oidc_user("carol", "admin", "fake", "sub-carol", 1)
        .unwrap();
    let now = chrono::Utc::now().timestamp().unsigned_abs();
    let token = access_token(
        &serde_json::json!({"iss": ISSUER, "aud": "https://dns.test/mcp",
        "exp": now + 300, "iat": now, "sub": "sub-carol", "azp": "claude-desktop",
        "scope": "openid analytics:read cluster:upgrade"}),
    );
    let r = h
        .app
        .clone()
        .oneshot(
            Request::post("/api/v1/nodes/dns-02/update")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .header("x-telltale-reason", "release day")
                .body(Body::from(r#"{"to":"0.8.0"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

/// REQ: AGT-008 (T7.4) — OAuth for MCP: the metadata names the provider; a 401 says where
/// to sign in; a valid access token acts as an agent with the consented scopes (never above
/// the user's role); wrong audience, expiry, and unknown users are refused.
#[tokio::test]
async fn agt_008_mcp_oauth_access_tokens() {
    let h = harness(Settings::default());
    let r = h
        .app
        .clone()
        .oneshot(
            Request::get("/.well-known/oauth-protected-resource")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let meta: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap())
            .unwrap();
    assert_eq!(meta["resource"], "https://dns.test/mcp");
    assert_eq!(meta["authorization_servers"][0], ISSUER);
    assert!(
        meta["scopes_supported"]
            .as_array()
            .unwrap()
            .contains(&"config:write:rules".into())
    );

    // No credentials: a challenge pointing at the metadata.
    let r = h
        .app
        .clone()
        .oneshot(Request::post("/mcp").body(Body::from("{}")).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let www = r.headers()["www-authenticate"].to_str().unwrap().to_owned();
    assert!(
        www.contains("resource_metadata=\"https://dns.test/.well-known/oauth-protected-resource\""),
        "{www}"
    );

    let now = chrono::Utc::now().timestamp().unsigned_abs();
    let claims = |aud: &str, exp: u64, sub: &str, scope: &str| serde_json::json!({"iss": ISSUER, "aud": aud, "exp": exp, "iat": now, "sub": sub, "azp": "claude-desktop", "scope": scope});
    // A user who has signed in to the UI with the provider before (an operator).
    h.auth
        .state()
        .create_oidc_user("alice", "operator", "fake", "sub-alice", 1)
        .unwrap();
    let list = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let ok = access_token(&claims(
        "https://dns.test/mcp",
        now + 300,
        "sub-alice",
        "openid analytics:read",
    ));
    assert_eq!(
        mcp_call(&h.app, &ok, list.clone()).await.status(),
        StatusCode::OK
    );
    // Read-only consent: a write tool is refused inside the tool.
    let plan = serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "plan_block_domain", "arguments": {"domain": "x.example", "reason": "test"}}});
    let r = mcp_call(&h.app, &ok, plan).await;
    let v: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap())
            .unwrap();
    assert_eq!(v["result"]["isError"], true, "{v}");
    assert!(v.to_string().contains("config:write:rules"), "{v}");
    // Refused: another audience, expired, a stranger, a forged signature.
    for (token, why) in [
        (
            access_token(&claims(
                "https://other.test/mcp",
                now + 300,
                "sub-alice",
                "",
            )),
            "not issued for",
        ),
        (
            access_token(&claims("https://dns.test/mcp", now - 3600, "sub-alice", "")),
            "expired",
        ),
        (
            access_token(&claims("https://dns.test/mcp", now + 300, "sub-bob", "")),
            "hasn't used TelltaleDNS",
        ),
        (format!("{}x", &ok[..ok.len() - 4]), "signature"),
    ] {
        let r = mcp_call(&h.app, &token, list.clone()).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{why}");
        assert!(
            r.headers()["www-authenticate"]
                .to_str()
                .unwrap()
                .contains("invalid_token"),
            "{why}"
        );
        let body = String::from_utf8(
            axum::body::to_bytes(r.into_body(), 1 << 16)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains(why), "{why}: {body}");
    }
}
