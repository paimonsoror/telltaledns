//! REQ: API-003 (ADR-149) — HTTPS on the API listener (`[api] tls`).
//!
//! The certificate is the operator's PEM files, re-read within 10 s of a change like the DNS
//! listeners', or a self-signed one made on first start and kept in `<data_dir>/api-tls/`, for
//! this host's name and addresses. The listener tells TLS from plain HTTP by a connection's
//! first byte: plain requests are redirected to `https://`, except the health probes, which
//! keep answering health checks that speak plain HTTP.

use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router as HttpRouter;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use hyper::body::Incoming;
use hyper::service::Service as _;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use telltale_api::auth::routes::TlsConnection;
use telltale_config::{ApiTls, Config};
use telltale_net::CertStore;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// How long a connection may take to send its first byte, and then to finish the TLS handshake.
const HANDSHAKE: Duration = Duration::from_secs(10);

/// How long a request's headers may take to arrive.
const HEADERS: Duration = Duration::from_secs(30);

/// A TLS `ClientHello` starts with this record type; HTTP starts with a method's letter.
const TLS_HANDSHAKE_RECORD: u8 = 0x16;

/// Paths a plain HTTP request is still answered on: the health probes (`telltale health`, the
/// Compose healthcheck), which say nothing worth protecting.
const PLAIN_PATHS: [&str; 3] = ["/livez", "/healthz", "/readyz"];

/// Serves `app` on `addr` over TLS (and the redirect for plain HTTP) until `shutdown`.
pub(crate) async fn serve(
    addr: SocketAddr,
    app: HttpRouter,
    tls: &ApiTlsSetup,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls.store.server_config(&[b"http/1.1"])?);
    if !tls.self_signed {
        crate::server::watch_cert(Arc::clone(&tls.store));
    }
    let hsts = tls.hsts;
    let (stop_tx, stop) = watch::channel(false);
    tokio::spawn(async move {
        shutdown.await;
        let _ = stop_tx.send(true);
    });
    tokio::spawn(async move {
        let mut stopping = stop.clone();
        loop {
            let accepted = tokio::select! {
                r = listener.accept() => r,
                () = stopped(&mut stopping) => return,
            };
            let Ok((tcp, peer)) = accepted else {
                // Out of file descriptors and the like: don't spin.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };
            let (app, acceptor, stop) = (app.clone(), acceptor.clone(), stop.clone());
            tokio::spawn(async move {
                let _ = connection(tcp, peer, app, acceptor, hsts, stop).await;
            });
        }
    });
    Ok(bound)
}

/// One connection: TLS if its first byte says so, else plain HTTP for the redirect.
async fn connection(
    tcp: TcpStream,
    peer: SocketAddr,
    app: HttpRouter,
    acceptor: tokio_rustls::TlsAcceptor,
    hsts: bool,
    stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut first = [0u8; 1];
    let n = tokio::time::timeout(HANDSHAKE, tcp.peek(&mut first))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    if n == 0 {
        return Ok(());
    }
    if first[0] == TLS_HANDSHAKE_RECORD {
        let s = tokio::time::timeout(HANDSHAKE, acceptor.accept(tcp))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
        http1(TokioIo::new(s), peer, app, true, hsts, stop).await;
    } else {
        http1(TokioIo::new(tcp), peer, app, false, false, stop).await;
    }
    Ok(())
}

/// Serves HTTP/1.1 on `io`, with the peer's address (and, over TLS, the [`TlsConnection`]
/// marker) on every request, as `axum::serve` would.
async fn http1<I>(
    io: I,
    peer: SocketAddr,
    app: HttpRouter,
    tls: bool,
    hsts: bool,
    mut stop: watch::Receiver<bool>,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |mut req: Request<Incoming>| {
        let app = TowerToHyperService::new(app.clone());
        async move {
            req.extensions_mut().insert(ConnectInfo(peer));
            if tls {
                req.extensions_mut().insert(TlsConnection);
            } else if !PLAIN_PATHS.contains(&req.uri().path()) {
                return Ok::<_, Infallible>(redirect(&req));
            }
            let mut resp = app.call(req.map(Body::new)).await?;
            if hsts {
                resp.headers_mut().insert(
                    header::STRICT_TRANSPORT_SECURITY,
                    HeaderValue::from_static("max-age=31536000"),
                );
            }
            Ok(resp)
        }
    });
    let conn = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADERS)
        .serve_connection(io, svc);
    tokio::pin!(conn);
    tokio::select! {
        _ = conn.as_mut() => {}
        () = stopped(&mut stop) => {
            conn.as_mut().graceful_shutdown();
            let _ = conn.await;
        }
    }
}

/// Resolves once `stop` turns true (without holding its guard across an await).
async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|s| *s).await;
}

/// `307` to the same URL over `https://` (temporary: turning TLS off again mustn't leave
/// browsers stuck on a cached redirect).
fn redirect<B>(req: &Request<B>) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .filter(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_graphic()));
    let Some(host) = host else {
        return (StatusCode::BAD_REQUEST, "use https://\n").into_response();
    };
    let path = req.uri().path_and_query().map_or("/", |p| p.as_str());
    let to = format!("https://{host}{path}");
    match HeaderValue::from_str(&to) {
        Ok(v) => (
            StatusCode::TEMPORARY_REDIRECT,
            [(header::LOCATION, v)],
            "use https://\n",
        )
            .into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, "use https://\n").into_response(),
    }
}

/// The API listener's TLS: the certificate, and whether to send HSTS.
#[derive(Clone)]
pub(crate) struct ApiTlsSetup {
    pub store: Arc<CertStore>,
    /// Only with the operator's own certificate: HSTS tells a browser to refuse plain HTTP
    /// and certificate warnings for the name, and a self-signed certificate is one long
    /// warning until it's trusted, so the browser would leave no way in.
    pub hsts: bool,
    /// The certificate is ours (self-signed), not the operator's.
    pub self_signed: bool,
}

/// Where the self-signed certificate and key are kept.
pub(crate) fn self_signed_paths(data_dir: &Path) -> (PathBuf, PathBuf) {
    let dir = data_dir.join("api-tls");
    (dir.join("cert.pem"), dir.join("key.pem"))
}

/// Loads the configured certificate, making the self-signed one first if it doesn't exist.
pub(crate) fn setup(cfg: &Config, tls: &ApiTls) -> io::Result<ApiTlsSetup> {
    if let (Some(cert), Some(key)) = (&tls.cert, &tls.key) {
        return Ok(ApiTlsSetup {
            store: CertStore::load(cert.as_str(), key.as_str())?,
            hsts: true,
            self_signed: false,
        });
    }
    let (cert, key) = self_signed_paths(Path::new(cfg.node.data_dir.as_str()));
    if !cert.exists() || !key.exists() {
        let names = names(cfg.api.listen);
        make_self_signed(&cert, &key, &names)?;
        tracing::info!(
            cert = %cert.display(),
            names = %names.join(", "),
            "made a self-signed certificate for the API (browsers warn until it's trusted)"
        );
    }
    Ok(ApiTlsSetup {
        store: CertStore::load(&cert, &key)?,
        hsts: false,
        self_signed: true,
    })
}

/// The names a self-signed certificate covers: localhost and loopback, this host's name (and
/// `<name>.local` for mDNS), the listen address if it's a specific one, and the addresses this
/// host reaches the network from.
fn names(listen: SocketAddr) -> Vec<String> {
    let mut v: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    if let Some(h) = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty() && h != "localhost")
    {
        if !h.contains('.') {
            v.push(format!("{h}.local"));
        }
        v.push(h);
    }
    let mut ips = vec![listen.ip()];
    // The address a socket would send from toward a public address (nothing is sent).
    for probe in [
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    ] {
        let local = if probe.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        if let Ok(s) = UdpSocket::bind(local)
            && s.connect((probe, 53)).is_ok()
            && let Ok(a) = s.local_addr()
        {
            ips.push(a.ip());
        }
    }
    for ip in ips {
        let s = ip.to_string();
        if !ip.is_unspecified() && !v.contains(&s) {
            v.push(s);
        }
    }
    v
}

/// Writes a new self-signed certificate (ECDSA P-256, which every browser accepts) for `names`.
fn make_self_signed(cert: &Path, key: &Path, names: &[String]) -> io::Result<()> {
    let other = |e: rcgen::Error| io::Error::other(format!("self-signed certificate: {e}"));
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(other)?;
    let mut params = rcgen::CertificateParams::new(names.to_vec()).map_err(other)?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "TelltaleDNS (self-signed)");
    let c = params.self_signed(&pair).map_err(other)?;
    if let Some(dir) = cert.parent() {
        std::fs::create_dir_all(dir)?;
    }
    write_private(key, pair.serialize_pem().as_bytes())?;
    std::fs::write(cert, c.pem())
}

/// Writes `bytes` readable by this user only.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path)?.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: API-003 (ADR-149) — the self-signed certificate is made once, covers loopback
    /// and the listen address, and loads; its key is private to the user.
    #[test]
    fn api_003_self_signed_certificate_is_made_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.node.data_dir = telltale_config::SafeString::new(dir.path().to_string_lossy()).unwrap();
        cfg.api.listen = "192.0.2.53:8053".parse().unwrap();
        let tls = ApiTls {
            self_signed: true,
            ..ApiTls::default()
        };
        let s = setup(&cfg, &tls).unwrap();
        assert!(s.self_signed && !s.hsts);
        let (cert, key) = self_signed_paths(dir.path());
        let pem = std::fs::read_to_string(&cert).unwrap();
        let first = std::fs::metadata(&cert).unwrap().modified().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&key).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "the key is private");
        }
        let names = names(cfg.api.listen);
        assert!(names.iter().any(|n| n == "127.0.0.1"));
        assert!(names.iter().any(|n| n == "192.0.2.53"));
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        // A second start keeps it.
        setup(&cfg, &tls).unwrap();
        assert_eq!(std::fs::metadata(&cert).unwrap().modified().unwrap(), first);
    }

    /// REQ: API-003 (ADR-149) — over TLS a request is marked HTTPS and carries the peer's
    /// address (`telltale ctl`'s client, trusting the self-signed certificate, gets through);
    /// plain HTTP on the same port is redirected to https://, except the probes; HSTS only
    /// with the operator's own certificate.
    #[tokio::test]
    async fn api_003_https_listener_and_the_plain_http_redirect() {
        use axum::routing::get;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.node.data_dir = telltale_config::SafeString::new(dir.path().to_string_lossy()).unwrap();
        cfg.api.listen = "127.0.0.1:0".parse().unwrap();
        let tls = setup(
            &cfg,
            &ApiTls {
                self_signed: true,
                ..ApiTls::default()
            },
        )
        .unwrap();
        let app =
            HttpRouter::new()
                .route(
                    "/who",
                    get(
                        |ConnectInfo(peer): ConnectInfo<SocketAddr>,
                         ext: axum::http::Extensions| async move {
                            format!("{} tls={}", peer.ip(), ext.get::<TlsConnection>().is_some())
                        },
                    ),
                )
                .route("/livez", get(|| async { "ok\n" }));
        let (_stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let addr = serve(cfg.api.listen, app, &tls, async {
            let _ = stop_rx.await;
        })
        .await
        .unwrap();

        let (cert, _) = self_signed_paths(dir.path());
        let client = crate::ctl::client(Some(&cert)).unwrap();
        let get = |url: String| http::Request::get(url).body(Vec::new()).unwrap();
        let r = client
            .request(
                get(format!("https://127.0.0.1:{}/who", addr.port())),
                1 << 16,
            )
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(String::from_utf8_lossy(r.body()), "127.0.0.1 tls=true");
        assert!(
            r.headers().get("strict-transport-security").is_none(),
            "no HSTS when self-signed"
        );

        // Without trusting the certificate, the handshake fails.
        let plain_client = crate::ctl::client(None).unwrap();
        assert!(
            plain_client
                .request(
                    get(format!("https://127.0.0.1:{}/who", addr.port())),
                    1 << 16
                )
                .await
                .is_err()
        );

        // Plain HTTP: a redirect to the same URL over https://; the probes still answer.
        let r = plain_client
            .request(
                get(format!("http://127.0.0.1:{}/who?x=1", addr.port())),
                1 << 16,
            )
            .await
            .unwrap();
        assert_eq!(r.status(), 307);
        assert_eq!(
            r.headers()["location"],
            format!("https://127.0.0.1:{}/who?x=1", addr.port()).as_str()
        );
        let r = plain_client
            .request(
                get(format!("http://127.0.0.1:{}/livez", addr.port())),
                1 << 16,
            )
            .await
            .unwrap();
        assert_eq!(
            (r.status().as_u16(), r.body().as_slice()),
            (200, &b"ok\n"[..])
        );
    }
}
