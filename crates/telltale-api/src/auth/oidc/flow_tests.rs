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

use super::{Fetch, Oidc, OidcSettings, ProviderSettings};
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
