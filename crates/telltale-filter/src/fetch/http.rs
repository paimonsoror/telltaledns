//! Minimal HTTP/1.1 GET client for list downloads: rustls, conditional requests, redirects,
//! and a hard body-size cap. One connection per request (lists refresh daily; pooling would
//! only hold sockets open).

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{
    ACCEPT_ENCODING, ETAG, HOST, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION,
    USER_AGENT,
};
use http::{Request, StatusCode, Uri};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const MAX_REDIRECTS: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolves list hostnames. The binary supplies one that never loops through our own
/// listeners (UPS-009 bootstrap rules); tests supply fixed answers.
pub trait Resolve: Send + Sync + 'static {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, String>> + Send + 'a>>;
}

/// The OS resolver (`getaddrinfo` / musl's `/etc/resolv.conf` reader).
#[derive(Debug, Default)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, String>> + Send + 'a>> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host, 0))
                .await
                .map_err(|e| format!("cannot resolve {host}: {e}"))?;
            Ok(addrs.map(|a| a.ip()).collect())
        })
    }
}

/// Validators from the previous download.
#[derive(Debug, Default, Clone)]
pub struct Conditional {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug)]
pub enum Response {
    /// 304: the stored copy is current.
    NotModified,
    /// 200 with the full body.
    Body {
        data: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

/// A failed attempt, and whether trying again might help.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpError {
    pub message: String,
    pub retryable: bool,
}

impl HttpError {
    fn retry(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: true,
        }
    }
    fn fatal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: false,
        }
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("user_agent", &self.user_agent)
            .finish_non_exhaustive()
    }
}

/// HTTP client settings shared by all downloads.
#[derive(Clone)]
pub struct Client {
    tls: TlsConnector,
    resolver: Arc<dyn Resolve>,
    user_agent: String,
}

impl Client {
    /// Trusts the built-in Mozilla roots (no CA files needed in a scratch image) plus
    /// `extra_roots` (private list servers, tests).
    pub fn new(
        resolver: Arc<dyn Resolve>,
        extra_roots: &[CertificateDer<'static>],
    ) -> Result<Self, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for der in extra_roots {
            roots.add(der.clone()).map_err(|e| e.to_string())?;
        }
        let mut cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            tls: TlsConnector::from(Arc::new(cfg)),
            resolver,
            user_agent: format!(
                "TelltaleDNS/{} (+https://github.com/paimonsoror/telltaledns)",
                env!("CARGO_PKG_VERSION")
            ),
        })
    }

    /// A client that also trusts the certificates in the PEM file at `path` (a self-signed
    /// router console, a private CA).
    pub fn with_ca_file(resolver: Arc<dyn Resolve>, path: &str) -> Result<Self, String> {
        use rustls::pki_types::pem::PemObject;
        let roots = CertificateDer::pem_file_iter(path)
            .map_err(|e| format!("{path}: {e}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{path}: {e}"))?;
        Self::new(resolver, &roots)
    }

    /// A client that skips certificate verification (signatures are still checked, so the
    /// handshake is sound, but not the server's identity): only for the explicit
    /// `tls_insecure_skip_verify` of router integrations with self-signed consoles.
    pub fn insecure(resolver: Arc<dyn Resolve>) -> Result<Self, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            tls: TlsConnector::from(Arc::new(cfg)),
            resolver,
            user_agent: format!(
                "TelltaleDNS/{} (+https://github.com/paimonsoror/telltaledns)",
                env!("CARGO_PKG_VERSION")
            ),
        })
    }

    /// GETs `url`, following up to 5 redirects (never from https to http), and fails once
    /// the body exceeds `max_bytes`. The caller applies the overall timeout.
    pub async fn get(
        &self,
        url: &str,
        cond: &Conditional,
        max_bytes: u64,
    ) -> Result<Response, HttpError> {
        let mut uri: Uri = url
            .parse()
            .map_err(|e| HttpError::fatal(format!("invalid URL: {e}")))?;
        for _ in 0..=MAX_REDIRECTS {
            match self.get_once(&uri, cond, max_bytes).await? {
                Step::Done(r) => return Ok(r),
                Step::Redirect(location) => {
                    let next = resolve_location(&uri, &location)?;
                    if uri.scheme_str() == Some("https") && next.scheme_str() != Some("https") {
                        return Err(HttpError::fatal(format!(
                            "refusing redirect from https to {next}"
                        )));
                    }
                    uri = next;
                }
            }
        }
        Err(HttpError::fatal(format!(
            "more than {MAX_REDIRECTS} redirects"
        )))
    }

    async fn get_once(
        &self,
        uri: &Uri,
        cond: &Conditional,
        max_bytes: u64,
    ) -> Result<Step, HttpError> {
        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            other => {
                return Err(HttpError::fatal(format!(
                    "unsupported scheme {}",
                    other.unwrap_or("(none)")
                )));
            }
        };
        let host = uri
            .host()
            .ok_or_else(|| HttpError::fatal("URL has no host"))?;
        let bare_host = host.trim_start_matches('[').trim_end_matches(']');
        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        let tcp = self.connect(bare_host, port).await?;

        let path = uri.path_and_query().map_or("/", |p| p.as_str());
        let authority = uri.authority().map_or(host, |a| a.as_str());
        let mut req = Request::get(path)
            .header(HOST, authority)
            .header(USER_AGENT, &self.user_agent)
            // Lists are text; asking for identity keeps the size cap meaningful.
            .header(ACCEPT_ENCODING, "identity");
        if let Some(etag) = &cond.etag {
            req = req.header(IF_NONE_MATCH, etag);
        }
        if let Some(lm) = &cond.last_modified {
            req = req.header(IF_MODIFIED_SINCE, lm);
        }
        let req = req
            .body(Empty::<Bytes>::new())
            .map_err(|e| HttpError::fatal(format!("bad request: {e}")))?;

        let resp = if https {
            let name = ServerName::try_from(bare_host.to_owned())
                .map_err(|e| HttpError::fatal(format!("invalid TLS name {bare_host}: {e}")))?;
            let tls = self
                .tls
                .connect(name, tcp)
                .await
                .map_err(|e| HttpError::retry(format!("TLS with {bare_host}: {e}")))?;
            send(TokioIo::new(tls), req).await?
        } else {
            send(TokioIo::new(tcp), req).await?
        };

        let status = resp.status();
        let header = |name| {
            resp.headers()
                .get(name)
                .and_then(|v: &http::HeaderValue| v.to_str().ok())
                .map(str::to_owned)
        };
        if status == StatusCode::NOT_MODIFIED {
            return Ok(Step::Done(Response::NotModified));
        }
        if status.is_redirection() {
            return header(LOCATION)
                .map(Step::Redirect)
                .ok_or_else(|| HttpError::fatal(format!("{status} without a Location header")));
        }
        if !status.is_success() {
            let msg = format!("HTTP {status}");
            let retryable = status.is_server_error()
                || status == StatusCode::TOO_MANY_REQUESTS
                || status == StatusCode::REQUEST_TIMEOUT;
            return Err(HttpError {
                message: msg,
                retryable,
            });
        }
        let (etag, last_modified) = (header(ETAG), header(LAST_MODIFIED));
        if let Some(len) = resp
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            && len > max_bytes
        {
            return Err(HttpError::fatal(too_big(max_bytes)));
        }
        let mut body = resp.into_body();
        let mut data = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| HttpError::retry(format!("reading body: {e}")))?;
            if let Some(chunk) = frame.data_ref() {
                if data.len() as u64 + chunk.len() as u64 > max_bytes {
                    return Err(HttpError::fatal(too_big(max_bytes)));
                }
                data.extend_from_slice(chunk);
            }
        }
        Ok(Step::Done(Response::Body {
            data,
            etag,
            last_modified,
        }))
    }

    /// Sends one request as is (no redirects followed: OAuth endpoints must not redirect)
    /// and returns the whole response, failing past `max_bytes`. Used by OIDC sign-in
    /// (API-004) for discovery, keys, and the token exchange. The caller applies a timeout.
    pub async fn request(
        &self,
        req: http::Request<Vec<u8>>,
        max_bytes: u64,
    ) -> Result<http::Response<Vec<u8>>, HttpError> {
        let (parts, body) = req.into_parts();
        let uri = parts.uri.clone();
        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            other => {
                return Err(HttpError::fatal(format!(
                    "unsupported scheme {}",
                    other.unwrap_or("(none)")
                )));
            }
        };
        let host = uri
            .host()
            .ok_or_else(|| HttpError::fatal("URL has no host"))?;
        let bare_host = host.trim_start_matches('[').trim_end_matches(']');
        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        let tcp = self.connect(bare_host, port).await?;
        let path = uri.path_and_query().map_or("/", |p| p.as_str());
        let authority = uri.authority().map_or(host, |a| a.as_str()).to_owned();
        let mut out = Request::builder().method(parts.method).uri(path);
        for (k, v) in &parts.headers {
            out = out.header(k, v);
        }
        let req = out
            .header(HOST, authority)
            .header(USER_AGENT, &self.user_agent)
            .body(http_body_util::Full::new(Bytes::from(body)))
            .map_err(|e| HttpError::fatal(format!("bad request: {e}")))?;
        let resp = if https {
            let name = ServerName::try_from(bare_host.to_owned())
                .map_err(|e| HttpError::fatal(format!("invalid TLS name {bare_host}: {e}")))?;
            let tls = self
                .tls
                .connect(name, tcp)
                .await
                .map_err(|e| HttpError::retry(format!("TLS with {bare_host}: {e}")))?;
            send(TokioIo::new(tls), req).await?
        } else {
            send(TokioIo::new(tcp), req).await?
        };
        let (parts, mut body) = resp.into_parts();
        let mut data = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| HttpError::retry(format!("reading body: {e}")))?;
            if let Some(chunk) = frame.data_ref() {
                if data.len() as u64 + chunk.len() as u64 > max_bytes {
                    return Err(HttpError::fatal(format!(
                        "response larger than {max_bytes} bytes"
                    )));
                }
                data.extend_from_slice(chunk);
            }
        }
        Ok(http::Response::from_parts(parts, data))
    }

    async fn connect(&self, host: &str, port: u16) -> Result<TcpStream, HttpError> {
        let ips = match host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => self
                .resolver
                .resolve(host)
                .await
                .map_err(HttpError::retry)?,
        };
        if ips.is_empty() {
            return Err(HttpError::retry(format!("{host} has no addresses")));
        }
        let mut last = String::new();
        for ip in ips {
            let addr = SocketAddr::new(ip, port);
            match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => return Ok(s),
                Ok(Err(e)) => last = format!("connect {addr}: {e}"),
                Err(_) => last = format!("connect {addr}: timed out"),
            }
        }
        Err(HttpError::retry(last))
    }
}

enum Step {
    Done(Response),
    Redirect(String),
}

async fn send<I, B>(
    io: I,
    req: Request<B>,
) -> Result<http::Response<hyper::body::Incoming>, HttpError>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| HttpError::retry(format!("HTTP handshake: {e}")))?;
    // The connection task ends when the response body is consumed or dropped.
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
        .send_request(req)
        .await
        .map_err(|e| HttpError::retry(format!("request: {e}")))
}

fn too_big(max: u64) -> String {
    format!("larger than the {max}-byte limit (raise max_bytes for this list)")
}

/// Absolute or relative `Location` against the current URI.
fn resolve_location(base: &Uri, location: &str) -> Result<Uri, HttpError> {
    let bad =
        |e: &dyn std::fmt::Display| HttpError::fatal(format!("bad redirect `{location}`: {e}"));
    if location.contains("://") {
        return location.parse().map_err(|e| bad(&e));
    }
    let scheme = base.scheme_str().unwrap_or("https");
    let authority = base.authority().map_or("", |a| a.as_str());
    let path = if location.starts_with("//") {
        return format!("{scheme}:{location}").parse().map_err(|e| bad(&e));
    } else if location.starts_with('/') {
        location.to_owned()
    } else {
        let dir = base.path().rsplit_once('/').map_or("", |(d, _)| d);
        format!("{dir}/{location}")
    };
    format!("{scheme}://{authority}{path}")
        .parse()
        .map_err(|e| bad(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_locations() {
        let base: Uri = "https://lists.example.com/a/b/list.txt?x=1"
            .parse()
            .unwrap();
        let r = |l| resolve_location(&base, l).unwrap().to_string();
        assert_eq!(
            r("https://cdn.example.net/l.txt"),
            "https://cdn.example.net/l.txt"
        );
        assert_eq!(r("/other.txt"), "https://lists.example.com/other.txt");
        assert_eq!(r("next.txt"), "https://lists.example.com/a/b/next.txt");
        assert_eq!(r("//mirror.example.org/l"), "https://mirror.example.org/l");
    }
}

/// Accepts any server certificate (see [`Client::insecure`]).
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
