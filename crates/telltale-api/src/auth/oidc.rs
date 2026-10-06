//! `OpenID Connect` sign-in (REQ: API-004, `spec/08` §6, ADR-034): Authorization Code + PKCE
//! with discovery, ID-token validation (signature against the provider's JWKS, issuer,
//! audience, expiry, nonce) by `openidconnect`, group/role claims mapped to roles, users
//! created on first sign-in, and RP-initiated sign-out. Sessions are local after sign-in: the
//! provider is only contacted while signing in.
//!
//! The flow state (PKCE verifier, nonce, where to return) lives in memory for 10 minutes,
//! keyed by the `state` parameter and bound to the browser that started it by a short-lived
//! `SameSite=Lax` cookie (Strict cookies aren't sent on the provider's redirect back).

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde_json::Value;
use telltale_store::state::User;

use super::{Actor, Auth, Role, crypto};
use crate::problem::{Code, Problem};

/// What the binary supplies to reach providers (its HTTPS client; no redirects followed).
pub type Fetch = Arc<
    dyn Fn(
            axum::http::Request<Vec<u8>>,
        )
            -> Pin<Box<dyn Future<Output = Result<axum::http::Response<Vec<u8>>, String>> + Send>>
        + Send
        + Sync,
>;

/// How long a started sign-in may take, and how many may be in flight.
const FLOW_TTL: Duration = Duration::from_secs(600);
const MAX_FLOWS: usize = 1000;
/// Discovery (including the signing keys) is refreshed this often, or when a token's
/// signature doesn't verify (key rotation).
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
pub const FLOW_COOKIE: &str = "telltale_oidc";

/// One configured provider.
#[derive(Debug, Clone)]
pub struct ProviderSettings {
    pub id: String,
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub username_claim: String,
    pub groups_claim: String,
    /// (group, role), in config order.
    pub roles: Vec<(String, Role)>,
    pub default_role: Option<Role>,
    pub require_verified_email: bool,
}

/// `[auth.oidc]`.
#[derive(Debug, Clone, Default)]
pub struct OidcSettings {
    /// `https://dns.example.com` (no trailing slash).
    pub public_url: String,
    pub providers: Vec<ProviderSettings>,
    /// REQ: AGT-008 (T7.4) — MCP clients sign in through this provider.
    pub mcp: Option<McpOAuth>,
}

/// OAuth for MCP (REQ: AGT-008, T7.4): which provider issues access tokens, and for whom.
#[derive(Debug, Clone)]
pub struct McpOAuth {
    /// A provider's `id`.
    pub provider: String,
    /// The `aud` tokens must carry (the MCP endpoint's URL).
    pub audience: String,
}

#[derive(Debug)]
struct Discovered {
    metadata: CoreProviderMetadata,
    end_session: Option<String>,
    at: Instant,
}

#[derive(Debug)]
struct Flow {
    provider: String,
    verifier: String,
    nonce: String,
    return_to: String,
    browser: Vec<u8>,
    started: Instant,
}

/// The OIDC service.
pub struct Oidc {
    settings: OidcSettings,
    fetch: Fetch,
    discovered: Mutex<HashMap<String, Arc<Discovered>>>,
    flows: Mutex<HashMap<String, Flow>>,
}

impl std::fmt::Debug for Oidc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oidc")
            .field("providers", &self.settings.providers.len())
            .finish_non_exhaustive()
    }
}

/// A started sign-in: send the browser to `redirect`, and set `browser` as the flow cookie.
#[derive(Debug)]
pub struct Started {
    pub redirect: String,
    pub browser: String,
}

/// Who the provider says signed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub subject: String,
    pub username: String,
    pub email_verified: Option<bool>,
    pub groups: Vec<String>,
}

#[derive(Debug)]
struct HttpFailure(String);

impl std::fmt::Display for HttpFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HttpFailure {}

/// The binary's fetch function as an `openidconnect` HTTP client (a concrete type, so the
/// futures are `Send` for any lifetime, which axum handlers need).
struct Client(Fetch);

type ClientFuture<'c> =
    Pin<Box<dyn Future<Output = Result<axum::http::Response<Vec<u8>>, HttpFailure>> + Send + 'c>>;

impl<'c> openidconnect::AsyncHttpClient<'c> for Client {
    type Error = HttpFailure;
    type Future = ClientFuture<'c>;

    fn call(&'c self, request: axum::http::Request<Vec<u8>>) -> Self::Future {
        let fetch = Arc::clone(&self.0);
        Box::pin(async move { fetch(request).await.map_err(HttpFailure) })
    }
}

fn provider_down(id: &str, e: impl std::fmt::Display) -> Problem {
    Problem::unavailable(format!("can't reach the `{id}` sign-in provider: {e}"))
        .hint("Check the issuer URL and that this server can reach it; sign in locally meanwhile if allowed.")
}

/// A `returnTo` that stays inside the UI (no open redirects).
pub fn safe_return(r: Option<&str>) -> String {
    match r {
        Some(r) if r.starts_with("/#/") && !r.contains("//") && !r.contains('\\') => r.to_owned(),
        _ => "/#/".to_owned(),
    }
}

impl Oidc {
    pub fn new(settings: OidcSettings, fetch: Fetch) -> Self {
        Self {
            settings,
            fetch,
            discovered: Mutex::new(HashMap::new()),
            flows: Mutex::new(HashMap::new()),
        }
    }

    /// `(id, name)` of each provider, for sign-in buttons.
    pub fn providers(&self) -> Vec<(String, String)> {
        self.settings
            .providers
            .iter()
            .map(|p| (p.id.clone(), p.name.clone()))
            .collect()
    }

    fn provider(&self, id: &str) -> Result<&ProviderSettings, Problem> {
        self.settings
            .providers
            .iter()
            .find(|p| p.id == id)
            .ok_or_else(|| Problem::not_found(format!("no sign-in provider `{id}`")))
    }

    fn redirect_uri(&self, id: &str) -> String {
        format!(
            "{}/api/v1/auth/oidc/{id}/callback",
            self.settings.public_url.trim_end_matches('/')
        )
    }

    async fn discover(
        &self,
        p: &ProviderSettings,
        fresh: bool,
    ) -> Result<Arc<Discovered>, Problem> {
        if !fresh {
            let cached = self
                .discovered
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&p.id)
                .cloned();
            if let Some(d) = cached.filter(|d| d.at.elapsed() < DISCOVERY_TTL) {
                return Ok(d);
            }
        }
        let http = Client(Arc::clone(&self.fetch));
        let issuer = IssuerUrl::new(p.issuer.clone()).map_err(|e| provider_down(&p.id, e))?;
        let metadata = CoreProviderMetadata::discover_async(issuer, &http)
            .await
            .map_err(|e| provider_down(&p.id, e))?;
        // `end_session_endpoint` (RP-initiated logout) isn't in the core metadata type.
        let doc_url = format!(
            "{}/.well-known/openid-configuration",
            p.issuer.trim_end_matches('/')
        );
        let end_session = match axum::http::Request::get(&doc_url).body(Vec::new()) {
            Ok(req) => (self.fetch)(req)
                .await
                .ok()
                .and_then(|r| serde_json::from_slice::<Value>(r.body()).ok())
                .and_then(|v| v.get("end_session_endpoint")?.as_str().map(str::to_owned)),
            Err(_) => None,
        };
        let d = Arc::new(Discovered {
            metadata,
            end_session,
            at: Instant::now(),
        });
        self.discovered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(p.id.clone(), Arc::clone(&d));
        Ok(d)
    }

    /// Begins a sign-in with provider `id`; afterwards the browser returns to `return_to`.
    pub async fn start(&self, id: &str, return_to: &str) -> Result<Started, Problem> {
        let p = self.provider(id)?;
        let d = self.discover(p, false).await?;
        let client = CoreClient::from_provider_metadata(
            d.metadata.clone(),
            ClientId::new(p.client_id.clone()),
            p.client_secret.clone().map(ClientSecret::new),
        )
        .set_redirect_uri(
            RedirectUrl::new(self.redirect_uri(id))
                .map_err(|e| Problem::internal(e.to_string()))?,
        );
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut req = client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for s in p.scopes.iter().filter(|s| s.as_str() != "openid") {
            req = req.add_scope(Scope::new(s.clone()));
        }
        let (url, state, nonce) = req.set_pkce_challenge(challenge).url();
        let browser = crypto::random_secret();
        let mut flows = self.flows.lock().unwrap_or_else(PoisonError::into_inner);
        flows.retain(|_, f| f.started.elapsed() < FLOW_TTL);
        if flows.len() >= MAX_FLOWS {
            return Err(Problem::new(
                Code::RateLimited,
                "too many sign-ins in progress; try again shortly",
            ));
        }
        flows.insert(
            state.secret().clone(),
            Flow {
                provider: id.to_owned(),
                verifier: verifier.secret().clone(),
                nonce: nonce.secret().clone(),
                return_to: return_to.to_owned(),
                browser: crypto::secret_hash(&browser),
                started: Instant::now(),
            },
        );
        Ok(Started {
            redirect: url.to_string(),
            browser,
        })
    }

    /// Completes a sign-in: checks the state and browser binding, exchanges the code, and
    /// validates the ID token. Returns the identity and where to send the browser.
    pub async fn finish(
        &self,
        id: &str,
        code: &str,
        state: &str,
        browser: Option<&str>,
    ) -> Result<(Identity, String), Problem> {
        let flow = self
            .flows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(state)
            .filter(|f| f.started.elapsed() < FLOW_TTL)
            .ok_or_else(|| {
                Problem::new(
                    Code::Unauthorized,
                    "this sign-in expired or was already used",
                )
                .hint("Start again from the sign-in page.")
            })?;
        let same_browser =
            browser.is_some_and(|b| crypto::ct_eq(&crypto::secret_hash(b), &flow.browser));
        if flow.provider != id || !same_browser {
            return Err(Problem::new(
                Code::Unauthorized,
                "this sign-in was started in another browser or for another provider",
            )
            .hint("Start again from the sign-in page in this browser."));
        }
        let p = self.provider(id)?;
        let http = Client(Arc::clone(&self.fetch));
        let mut d = self.discover(p, false).await?;
        let client = |d: &Discovered| -> Result<_, Problem> {
            Ok(CoreClient::from_provider_metadata(
                d.metadata.clone(),
                ClientId::new(p.client_id.clone()),
                p.client_secret.clone().map(ClientSecret::new),
            )
            .set_redirect_uri(
                RedirectUrl::new(self.redirect_uri(id))
                    .map_err(|e| Problem::internal(e.to_string()))?,
            ))
        };
        let tokens = client(&d)?
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .map_err(|e| provider_down(id, e))?
            .set_pkce_verifier(PkceCodeVerifier::new(flow.verifier.clone()))
            .request_async(&http)
            .await
            .map_err(|e| {
                Problem::new(
                    Code::Unauthorized,
                    format!("the `{id}` provider refused the sign-in: {e}"),
                )
            })?;
        let id_token = tokens
            .id_token()
            .ok_or_else(|| Problem::new(Code::Unauthorized, "the provider sent no ID token"))?;
        let nonce = Nonce::new(flow.nonce.clone());
        let verified = match id_token.claims(
            &client(&d)?.id_token_verifier().set_allowed_algs(algs()),
            &nonce,
        ) {
            Ok(_) => true,
            Err(openidconnect::ClaimsVerificationError::SignatureVerification(_)) => {
                // Maybe the provider rotated its keys: rediscover once and retry.
                d = self.discover(p, true).await?;
                id_token
                    .claims(
                        &client(&d)?.id_token_verifier().set_allowed_algs(algs()),
                        &nonce,
                    )
                    .is_ok()
            }
            Err(e) => {
                return Err(Problem::new(
                    Code::Unauthorized,
                    format!("the ID token isn't valid: {e}"),
                ));
            }
        };
        if !verified {
            return Err(Problem::new(
                Code::Unauthorized,
                "the ID token's signature doesn't verify",
            ));
        }
        // The token is verified; read every claim (groups etc. aren't standard) from it.
        let raw = id_token.to_string();
        let payload = raw
            .split('.')
            .nth(1)
            .and_then(|p| URL_SAFE_NO_PAD.decode(p.trim_end_matches('=')).ok())
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .ok_or_else(|| Problem::internal("unreadable ID token payload"))?;
        Ok((
            identity(&payload, &p.username_claim, &p.groups_claim),
            flow.return_to,
        ))
    }

    /// REQ: AGT-008 (T7.4) — OAuth for MCP, when configured.
    pub fn mcp(&self) -> Option<&McpOAuth> {
        self.settings.mcp.as_ref()
    }

    /// The RFC 9728 protected-resource metadata for `/mcp`: this resource, its authorization
    /// server (the provider), and the scopes agents can ask for. `None` when not configured.
    pub fn resource_metadata(&self) -> Option<Value> {
        let m = self.mcp()?;
        let p = self.provider(&m.provider).ok()?;
        let scopes: Vec<&str> = super::agent::SCOPES.iter().map(|(s, _)| *s).collect();
        Some(serde_json::json!({
            "resource": m.audience,
            "authorization_servers": [p.issuer],
            "scopes_supported": scopes,
            "bearer_methods_supported": ["header"],
            "resource_name": "TelltaleDNS",
            "resource_documentation": "https://paimonsoror.github.io/telltaledns/",
        }))
    }

    /// Where the protected-resource metadata is.
    pub fn resource_metadata_url(&self) -> String {
        format!(
            "{}/.well-known/oauth-protected-resource",
            self.settings.public_url.trim_end_matches('/')
        )
    }

    /// REQ: AGT-008 (T7.4) — an MCP access token from the configured provider, verified: a JWT
    /// signed with one of the provider's keys (asymmetric algorithms only), from its issuer,
    /// for this resource's audience, and current. Its claims. Opaque (non-JWT) tokens aren't
    /// accepted: there's no introspection.
    pub async fn verify_access_token(&self, token: &str, now: u64) -> Result<Value, Problem> {
        use openidconnect::JsonWebKey as _;
        let bad = |why: &str| {
            Problem::new(
                Code::Unauthorized,
                format!("the access token isn't valid: {why}"),
            )
            .hint("Sign in again from your MCP client to get a new token.")
        };
        let mcp = self
            .mcp()
            .ok_or_else(|| bad("OAuth for MCP isn't configured"))?;
        let provider = self.provider(&mcp.provider)?;
        let mut parts = token.split('.');
        let (Some(head), Some(body), Some(sig64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad("not a JWT"));
        };
        let decode = |text: &str| URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).ok();
        let header: Value = decode(head)
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(|| bad("unreadable header"))?;
        let alg: openidconnect::core::CoreJwsSigningAlgorithm = header
            .get("alg")
            .cloned()
            .and_then(|a| serde_json::from_value(a).ok())
            .filter(|a| algs().contains(a))
            .ok_or_else(|| bad("unsupported signing algorithm"))?;
        let kid = header.get("kid").and_then(Value::as_str);
        let signature = decode(sig64).ok_or_else(|| bad("unreadable signature"))?;
        let signed_part = format!("{head}.{body}");
        let signed = |found: &Discovered| {
            found
                .metadata
                .jwks()
                .keys()
                .iter()
                .filter(|key| {
                    kid.is_none_or(|id| key.key_id().is_some_and(|key_id| key_id.as_str() == id))
                })
                .any(|key| {
                    key.verify_signature(&alg, signed_part.as_bytes(), &signature)
                        .is_ok()
                })
        };
        let known = self.discover(provider, false).await?;
        // Maybe the provider rotated its keys: rediscover once.
        if !signed(&known) && !signed(&*self.discover(provider, true).await?) {
            return Err(bad("the signature doesn't verify"));
        }
        let claims: Value = decode(body)
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(|| bad("unreadable claims"))?;
        let issuer = claims
            .get("iss")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if issuer.trim_end_matches('/') != provider.issuer.trim_end_matches('/') {
            return Err(bad("issued by another provider"));
        }
        let for_us = match claims.get("aud") {
            Some(Value::String(aud)) => *aud == mcp.audience,
            Some(Value::Array(auds)) => auds
                .iter()
                .any(|aud| aud.as_str() == Some(mcp.audience.as_str())),
            _ => false,
        };
        if !for_us {
            return Err(bad(&format!("not issued for {}", mcp.audience)));
        }
        let expires = claims
            .get("exp")
            .and_then(Value::as_u64)
            .ok_or_else(|| bad("no expiry"))?;
        if expires.saturating_add(60) < now {
            return Err(bad("expired"));
        }
        if claims
            .get("nbf")
            .and_then(Value::as_u64)
            .is_some_and(|not_before| not_before > now.saturating_add(60))
        {
            return Err(bad("not valid yet"));
        }
        Ok(claims)
    }

    /// Where to send the browser to also sign out at the provider, if it supports that.
    pub fn logout_url(&self, id: &str) -> Option<String> {
        let p = self.provider(id).ok()?;
        let end = self
            .discovered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)?
            .end_session
            .clone()?;
        let back = format!("{}/", self.settings.public_url.trim_end_matches('/'));
        let sep = if end.contains('?') { '&' } else { '?' };
        Some(format!(
            "{end}{sep}client_id={}&post_logout_redirect_uri={}",
            enc(&p.client_id),
            enc(&back)
        ))
    }

    /// The role for `groups`, or why there's none.
    pub fn role(&self, id: &str, who: &Identity) -> Result<Role, Problem> {
        let p = self.provider(id)?;
        if p.require_verified_email && who.email_verified != Some(true) {
            return Err(Problem::new(
                Code::Forbidden,
                "your email address isn't verified at the sign-in provider",
            ));
        }
        role_for(&who.groups, &p.roles, p.default_role).ok_or_else(|| {
            Problem::new(
                Code::Forbidden,
                "your account at the sign-in provider isn't in a group that may use TelltaleDNS",
            )
            .hint("Ask an admin to add you to a group mapped in [[auth.oidc.provider.role]].")
        })
    }
}

/// Asymmetric signatures only (keys from the provider's JWKS): every common provider uses
/// one of these, and refusing HMAC keeps the client secret out of token verification.
fn algs() -> Vec<openidconnect::core::CoreJwsSigningAlgorithm> {
    use openidconnect::core::CoreJwsSigningAlgorithm as A;
    vec![
        A::RsaSsaPkcs1V15Sha256,
        A::RsaSsaPkcs1V15Sha384,
        A::RsaSsaPkcs1V15Sha512,
        A::RsaSsaPssSha256,
        A::RsaSsaPssSha384,
        A::RsaSsaPssSha512,
        A::EcdsaP256Sha256,
        A::EcdsaP384Sha384,
        A::EdDsa,
    ]
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// A claim by dotted path (`realm_access.roles`).
fn claim<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(v, |v, k| v.get(k))
}

/// Identity from verified ID-token claims.
pub fn identity(claims: &Value, username_claim: &str, groups_claim: &str) -> Identity {
    let text = |path: &str| {
        claim(claims, path)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let subject = text("sub").unwrap_or_default();
    let username = text(username_claim)
        .or_else(|| text("email"))
        .unwrap_or_else(|| subject.clone());
    let groups = match claim(claims, groups_claim) {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .map(|g| g.trim_start_matches('/').to_owned())
            .collect(),
        Some(Value::String(s)) => s
            .split([',', ' '])
            .filter(|g| !g.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    let email_verified = match claim(claims, "email_verified") {
        Some(Value::Bool(b)) => Some(*b),
        Some(Value::String(s)) => Some(s == "true"),
        _ => None,
    };
    Identity {
        subject,
        username,
        email_verified,
        groups,
    }
}

/// The highest role any group maps to, else the default.
pub fn role_for(
    groups: &[String],
    rules: &[(String, Role)],
    default: Option<Role>,
) -> Option<Role> {
    rules
        .iter()
        .filter(|(g, _)| groups.iter().any(|x| x == g))
        .map(|(_, r)| *r)
        .max()
        .or(default)
}

/// A username for a new OIDC user: the claim made safe; `name@provider` if a different
/// account already has it (never merged into an existing local account).
fn username_for(auth: &Auth, provider: &str, wanted: &str) -> Result<String, Problem> {
    let clean: String = wanted
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || "._-@".contains(c) {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    let clean = if clean.is_empty() {
        "user".to_owned()
    } else {
        clean
    };
    for candidate in [clean.clone(), format!("{clean}@{provider}")] {
        if auth
            .state()
            .user_by_name(&candidate)
            .map_err(super::db)?
            .is_none()
        {
            return Ok(candidate);
        }
    }
    Err(Problem::new(
        Code::Conflict,
        format!("the username `{clean}` is taken by another account"),
    )
    .hint("Ask an admin to rename or remove the other account."))
}

impl Auth {
    /// REQ: AGT-008 (T7.4, ADR-071) — the agent an MCP access token stands for: the user who
    /// signed in (they must have signed in to the web UI with the provider before), with the
    /// TelltaleDNS scopes they consented to (read-only when it names none), never above their
    /// role. Blocking.
    pub fn oauth_principal(
        &self,
        oidc: &Oidc,
        claims: &Value,
    ) -> Result<super::Principal, Problem> {
        let provider = oidc
            .mcp()
            .map(|m| m.provider.clone())
            .ok_or_else(|| Problem::new(Code::Unauthorized, "OAuth for MCP isn't configured"))?;
        let sub = claims
            .get("sub")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let user = self
            .state()
            .user_by_oidc(&provider, sub)
            .map_err(super::db)?
            .filter(|_| !sub.is_empty())
            .ok_or_else(|| {
                Problem::new(
                    Code::Unauthorized,
                    "this account hasn't used TelltaleDNS yet",
                )
                .hint("Sign in to the web UI with the same provider once, then connect the MCP client again.")
            })?;
        if user.disabled {
            return Err(Problem::new(
                Code::Forbidden,
                "this account is disabled in TelltaleDNS",
            ));
        }
        // `scope` (space-separated) or `scp` (a list): the TelltaleDNS scopes among them.
        let asked: Vec<String> = match (claims.get("scope"), claims.get("scp")) {
            (Some(Value::String(s)), _) => s.split_whitespace().map(str::to_owned).collect(),
            (_, Some(Value::Array(v))) => v
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            _ => Vec::new(),
        };
        let known: Vec<String> = asked
            .into_iter()
            .filter(|s| s == "config:write:*" || super::agent::SCOPES.iter().any(|(k, _)| k == s))
            .collect();
        let mut scopes = super::agent::parse_scopes(&known).unwrap_or_default();
        if scopes.is_empty() {
            scopes = super::agent::DEFAULT_SCOPES
                .iter()
                .map(|s| (*s).to_owned())
                .collect();
        }
        let user_role = Role::parse(&user.role).unwrap_or(Role::Viewer);
        let role = user_role.min(super::agent::implied_role(&scopes));
        // The MCP client the token was issued to names the agent in the audit log.
        let client = claims
            .get("azp")
            .or_else(|| claims.get("client_id"))
            .and_then(Value::as_str)
            .unwrap_or("mcp")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || "-_.:".contains(*c))
            .take(64)
            .collect::<String>();
        Ok(super::Principal {
            user_id: user.id,
            username: user.username,
            role,
            via: super::Via::Token {
                id: format!("oauth:{client}:{sub}"),
            },
            agent: Some(super::AgentGrant {
                token_name: format!("oauth:{client}"),
                scopes,
                group: None,
                rate_per_minute: None,
                client: None,
            }),
        })
    }

    /// Signs in (and on first sign-in creates) the user `who` from provider `id`, updating
    /// their role from their groups. Blocking.
    pub fn oidc_user(
        &self,
        oidc: &Oidc,
        id: &str,
        who: &Identity,
        remote: IpAddr,
        now: u64,
    ) -> Result<User, Problem> {
        if who.subject.is_empty() {
            return Err(Problem::new(
                Code::Unauthorized,
                "the ID token has no subject",
            ));
        }
        let role = oidc.role(id, who)?;
        let actor = |u: &User| Actor {
            name: u.username.clone(),
            kind: "oidc",
            remote: Some(remote.to_string()),
            reason: None,
        };
        let existing = self
            .state()
            .user_by_oidc(id, &who.subject)
            .map_err(super::db)?;
        let user = if let Some(u) = existing {
            {
                if u.disabled {
                    return Err(Problem::new(
                        Code::Forbidden,
                        "this account is disabled in TelltaleDNS",
                    ));
                }
                let was = Role::parse(&u.role).unwrap_or(Role::Viewer);
                if was != role {
                    self.state()
                        .update_user(u.id, Some(role.as_str()), None, None)
                        .map_err(super::db)?;
                    self.forget_basic(u.id);
                    self.record(
                        &actor(&u),
                        "user.update",
                        &u.username,
                        &serde_json::json!({ "role": { "from": was.as_str(), "to": role.as_str() }, "via": "oidc", "provider": id }),
                    );
                }
                self.state().user(u.id).map_err(super::db)?.unwrap_or(u)
            }
        } else {
            {
                let name = username_for(self, id, &who.username)?;
                let u = self
                    .state()
                    .create_oidc_user(&name, role.as_str(), id, &who.subject, now)
                    .map_err(super::db)?;
                self.record(
                    &actor(&u),
                    "user.create",
                    &u.username,
                    &serde_json::json!({ "role": role.as_str(), "via": "oidc", "provider": id }),
                );
                u
            }
        };
        self.record(
            &actor(&user),
            "auth.login",
            &user.username,
            &serde_json::json!({ "via": "oidc", "provider": id }),
        );
        Ok(user)
    }
}

#[cfg(test)]
mod flow_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_004_claims_to_identity_and_role() {
        let c = serde_json::json!({
            "sub": "1234",
            "preferred_username": "Ana Maria",
            "email": "ana@example.com",
            "email_verified": true,
            "groups": ["/dns-admins", "family"],
            "realm_access": { "roles": ["dns-operator"] },
        });
        let i = identity(&c, "preferred_username", "groups");
        assert_eq!(i.subject, "1234");
        assert_eq!(i.username, "Ana Maria");
        assert_eq!(i.email_verified, Some(true));
        assert_eq!(
            i.groups,
            ["dns-admins", "family"],
            "Keycloak's leading / is dropped"
        );
        let nested = identity(&c, "missing", "realm_access.roles");
        assert_eq!(nested.username, "ana@example.com", "falls back to email");
        assert_eq!(nested.groups, ["dns-operator"]);
        let rules = vec![
            ("family".to_owned(), Role::Viewer),
            ("dns-admins".to_owned(), Role::Admin),
        ];
        assert_eq!(
            role_for(&i.groups, &rules, None),
            Some(Role::Admin),
            "highest wins"
        );
        assert_eq!(role_for(&["other".into()], &rules, None), None);
        assert_eq!(
            role_for(&["other".into()], &rules, Some(Role::Viewer)),
            Some(Role::Viewer)
        );
    }

    #[test]
    fn api_004_return_paths_stay_inside_the_ui() {
        assert_eq!(
            safe_return(Some("/#/queries?client=1.2.3.4")),
            "/#/queries?client=1.2.3.4"
        );
        for bad in [
            "https://evil.example",
            "//evil.example",
            "/#//evil",
            "/\\evil",
            "javascript:x",
        ] {
            assert_eq!(safe_return(Some(bad)), "/#/", "{bad}");
        }
        assert_eq!(safe_return(None), "/#/");
    }
}
