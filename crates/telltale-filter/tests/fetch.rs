//! REQ: FLT-004 — list fetcher against a scripted local HTTP(S) server.

#![allow(clippy::unwrap_used, clippy::format_push_string)]

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use telltale_filter::fetch::{
    Client, FetchSettings, Fetcher, ListSource, ListSpec, Outcome, Resolve, Store,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

// ---------------------------------------------------------------- scripted server

#[derive(Debug, Clone)]
struct Req {
    path: String,
    headers: HashMap<String, String>,
}

#[derive(Clone, Default)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    delay: Duration,
    /// Omit Content-Length and close after the body (forces streaming size checks).
    no_length: bool,
}

fn ok(body: &str) -> Reply {
    Reply {
        status: 200,
        body: body.as_bytes().to_vec(),
        ..Reply::default()
    }
}

fn status(code: u16) -> Reply {
    Reply {
        status: code,
        ..Reply::default()
    }
}

impl Reply {
    fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
}

type Handler = Arc<dyn Fn(&Req, usize) -> Reply + Send + Sync>;

struct Server {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<Req>>>,
    max_in_flight: Arc<AtomicUsize>,
}

impl Server {
    fn url(&self, scheme: &str, host: &str, path: &str) -> String {
        format!("{scheme}://{host}:{}{path}", self.addr.port())
    }
    fn requests(&self) -> Vec<Req> {
        self.requests.lock().unwrap().clone()
    }
}

async fn serve(handler: Handler, tls: Option<tokio_rustls::TlsAcceptor>) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_in_flight = Arc::new(AtomicUsize::new(0));
    let (reqs, inf, maxf) = (requests.clone(), in_flight, max_in_flight.clone());
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let (handler, reqs, inf, maxf, tls) = (
                handler.clone(),
                reqs.clone(),
                inf.clone(),
                maxf.clone(),
                tls.clone(),
            );
            tokio::spawn(async move {
                match tls {
                    Some(acceptor) => {
                        if let Ok(s) = acceptor.accept(sock).await {
                            handle(s, handler, reqs, inf, maxf).await;
                        }
                    }
                    None => handle(sock, handler, reqs, inf, maxf).await,
                }
            });
        }
    });
    Server {
        addr,
        requests,
        max_in_flight,
    }
}

async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    handler: Handler,
    reqs: Arc<Mutex<Vec<Req>>>,
    in_flight: Arc<AtomicUsize>,
    max_in_flight: Arc<AtomicUsize>,
) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    let mut lines = text.split("\r\n");
    let path = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .unwrap_or("/")
        .to_owned();
    let headers = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_owned()))
        .collect();
    let req = Req { path, headers };
    let n = {
        let mut r = reqs.lock().unwrap();
        r.push(req.clone());
        r.len()
    };
    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    max_in_flight.fetch_max(now, Ordering::SeqCst);
    let reply = handler(&req, n);
    tokio::time::sleep(reply.delay).await;
    in_flight.fetch_sub(1, Ordering::SeqCst);

    let mut head = format!("HTTP/1.1 {} X\r\nConnection: close\r\n", reply.status);
    if !reply.no_length {
        head.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
    }
    for (k, v) in &reply.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let _ = s.write_all(head.as_bytes()).await;
    let _ = s.write_all(&reply.body).await;
    let _ = s.shutdown().await;
}

// ---------------------------------------------------------------- fetcher setup

/// Every name resolves to loopback.
struct Loopback;

impl Resolve for Loopback {
    fn resolve<'a>(
        &'a self,
        _host: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, String>> + Send + 'a>> {
        Box::pin(async { Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]) })
    }
}

fn settings() -> FetchSettings {
    FetchSettings {
        concurrency: 4,
        timeout: Duration::from_secs(5),
        retries: 2,
        backoff: Duration::from_millis(10),
        settle: Duration::from_secs(10),
    }
}

fn fetcher(
    dir: &std::path::Path,
    settings: FetchSettings,
    roots: &[CertificateDer<'static>],
) -> Arc<Fetcher> {
    let client = Client::new(Arc::new(Loopback), roots).unwrap();
    Arc::new(Fetcher::new(Store::open(dir).unwrap(), client, settings))
}

fn spec(name: &str, url: String) -> ListSpec {
    ListSpec {
        name: name.into(),
        source: ListSource::Url(url),
        refresh: Duration::from_hours(24),
        max_bytes: 1024,
    }
}

fn handler(f: impl Fn(&Req, usize) -> Reply + Send + Sync + 'static) -> Handler {
    Arc::new(f)
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn flt_004_download_then_conditional_get() {
    let srv = serve(
        handler(|req, _| {
            if req.headers.get("if-none-match").map(String::as_str) == Some("\"v1\"") {
                status(304)
            } else {
                ok("ads.example.com\ntracker.example.net\n")
                    .header("ETag", "\"v1\"")
                    .header("Last-Modified", "Sat, 03 Oct 2026 00:00:00 GMT")
            }
        }),
        None,
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let f = fetcher(tmp.path(), settings(), &[]);
    let s = spec("l", srv.url("http", "lists.test", "/l.txt"));

    assert_eq!(f.refresh_one(&s).await, Outcome::Updated);
    assert_eq!(
        f.store().read_source("l").unwrap(),
        b"ads.example.com\ntracker.example.net\n"
    );
    assert_eq!(f.refresh_one(&s).await, Outcome::Unchanged);

    let reqs = srv.requests();
    assert_eq!(reqs.len(), 2);
    assert!(!reqs[0].headers.contains_key("if-none-match"));
    assert_eq!(reqs[1].headers["if-none-match"], "\"v1\"");
    assert_eq!(
        reqs[1].headers["if-modified-since"],
        "Sat, 03 Oct 2026 00:00:00 GMT"
    );
    assert_eq!(reqs[1].headers["accept-encoding"], "identity");
    assert!(reqs[1].headers["user-agent"].starts_with("TelltaleDNS/"));
    assert_eq!(
        reqs[1].headers["host"],
        format!("lists.test:{}", srv.addr.port())
    );

    let status = f.status();
    let meta = &status[0].1;
    assert_eq!((meta.bytes, meta.lines), (36, 2));
    assert!(meta.last_success.is_some() && meta.last_error.is_none());
}

#[tokio::test]
async fn flt_004_identical_content_without_validators_is_unchanged() {
    let srv = serve(
        handler(|_, n| ok(if n < 3 { "a.com\n" } else { "b.com\n" })),
        None,
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let f = fetcher(tmp.path(), settings(), &[]);
    let s = spec("l", srv.url("http", "lists.test", "/"));
    assert_eq!(f.refresh_one(&s).await, Outcome::Updated);
    assert_eq!(f.refresh_one(&s).await, Outcome::Unchanged);
    assert_eq!(f.refresh_one(&s).await, Outcome::Updated);
    assert_eq!(f.store().read_source("l").unwrap(), b"b.com\n");
}

#[tokio::test]
async fn flt_004_size_cap_keeps_last_good() {
    let big = "x".repeat(2000);
    let srv = serve(
        handler(move |req, _| match req.path.as_str() {
            "/small" => ok("a.com\n"),
            "/big" => ok(&big),
            _ => Reply {
                no_length: true,
                ..ok(&big)
            },
        }),
        None,
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let f = fetcher(tmp.path(), settings(), &[]);
    assert_eq!(
        f.refresh_one(&spec("l", srv.url("http", "h", "/small")))
            .await,
        Outcome::Updated
    );
    for path in ["/big", "/streamed"] {
        let Outcome::Failed(e) = f.refresh_one(&spec("l", srv.url("http", "h", path))).await else {
            panic!("{path}: oversized list accepted");
        };
        assert!(e.contains("1024-byte limit"), "{e}");
        assert_eq!(
            f.store().read_source("l").unwrap(),
            b"a.com\n",
            "last good kept"
        );
    }
    // Oversize isn't retried: one request per attempt.
    assert_eq!(srv.requests().len(), 3);
}

#[tokio::test]
async fn flt_004_retries_server_errors_not_client_errors() {
    let srv = serve(
        handler(|req, n| match req.path.as_str() {
            "/flaky" if n <= 2 => status(503),
            "/flaky" => ok("a.com\n"),
            _ => status(404),
        }),
        None,
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let f = fetcher(tmp.path(), settings(), &[]);
    assert_eq!(
        f.refresh_one(&spec("a", srv.url("http", "h", "/flaky")))
            .await,
        Outcome::Updated
    );
    assert_eq!(srv.requests().len(), 3, "two 503s, then success");

    let Outcome::Failed(e) = f
        .refresh_one(&spec("b", srv.url("http", "h", "/gone")))
        .await
    else {
        panic!("404 accepted");
    };
    assert!(e.contains("404"), "{e}");
    assert_eq!(srv.requests().len(), 4, "404 is not retried");
    let meta = f.status().into_iter().find(|(n, _)| n == "b").unwrap().1;
    assert_eq!(meta.consecutive_failures, 1);
    assert!(!meta.has_content());
}

#[tokio::test]
async fn flt_004_timeout_is_retried_then_fails() {
    let srv = serve(
        handler(|_, _| Reply {
            delay: Duration::from_secs(3),
            ..ok("a.com\n")
        }),
        None,
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let f = fetcher(
        tmp.path(),
        FetchSettings {
            timeout: Duration::from_millis(200),
            retries: 1,
            ..settings()
        },
        &[],
    );
    let Outcome::Failed(e) = f.refresh_one(&spec("l", srv.url("http", "h", "/"))).await else {
        panic!("slow server accepted");
    };
    assert!(e.contains("timed out"), "{e}");
    assert_eq!(srv.requests().len(), 2);
}

#[tokio::test]
async fn flt_004_redirects_and_html_rejection() {
    let srv = serve(
        handler(|req, _| match req.path.as_str() {
            "/old" => status(301).header("Location", "/new"),
            "/new" => ok("a.com\n"),
            "/portal" => ok("\n<!DOCTYPE html>\n<html><body>Please log in</body></html>"),
            _ => status(404),
        }),
        None,
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let f = fetcher(tmp.path(), settings(), &[]);
    assert_eq!(
        f.refresh_one(&spec("l", srv.url("http", "h", "/old")))
            .await,
        Outcome::Updated
    );
    let Outcome::Failed(e) = f
        .refresh_one(&spec("l", srv.url("http", "h", "/portal")))
        .await
    else {
        panic!("HTML accepted");
    };
    assert!(e.contains("HTML"), "{e}");
    assert_eq!(f.store().read_source("l").unwrap(), b"a.com\n");
}

fn tls_pair() -> (tokio_rustls::TlsAcceptor, CertificateDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["lists.test".to_owned()]).unwrap();
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    (tokio_rustls::TlsAcceptor::from(Arc::new(cfg)), cert)
}

#[tokio::test]
async fn flt_004_https_verifies_and_refuses_downgrade() {
    let (acceptor, cert) = tls_pair();
    let plain = serve(handler(|_, _| ok("evil.com\n")), None).await;
    let plain_url = plain.url("http", "lists.test", "/l.txt");
    let srv = serve(
        handler(move |req, _| match req.path.as_str() {
            "/l.txt" => ok("a.com\n"),
            _ => status(302).header("Location", &plain_url),
        }),
        Some(acceptor),
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();

    // Trusted via the extra root: works.
    let f = fetcher(tmp.path(), settings(), &[cert]);
    assert_eq!(
        f.refresh_one(&spec("l", srv.url("https", "lists.test", "/l.txt")))
            .await,
        Outcome::Updated
    );
    // https → http redirect: refused, previous copy kept.
    let Outcome::Failed(e) = f
        .refresh_one(&spec("l", srv.url("https", "lists.test", "/redirect")))
        .await
    else {
        panic!("downgrade followed");
    };
    assert!(e.contains("refusing redirect"), "{e}");
    assert!(plain.requests().is_empty());

    // Without the root: certificate rejected.
    let tmp2 = tempfile::tempdir().unwrap();
    let f = fetcher(
        tmp2.path(),
        FetchSettings {
            retries: 0,
            ..settings()
        },
        &[],
    );
    let Outcome::Failed(e) = f
        .refresh_one(&spec("l", srv.url("https", "lists.test", "/l.txt")))
        .await
    else {
        panic!("untrusted certificate accepted");
    };
    assert!(e.contains("TLS"), "{e}");
}

#[tokio::test]
async fn flt_004_concurrency_is_bounded() {
    let srv = serve(
        handler(|_, _| Reply {
            delay: Duration::from_millis(150),
            ..ok("a.com\n")
        }),
        None,
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let f = fetcher(
        tmp.path(),
        FetchSettings {
            concurrency: 2,
            ..settings()
        },
        &[],
    );
    let specs: Vec<_> = (0..6)
        .map(|i| spec(&format!("l{i}"), srv.url("http", "h", &format!("/{i}"))))
        .collect();
    let results = f.refresh(&specs).await;
    assert_eq!(results.len(), 6);
    assert!(results.iter().all(|(_, o)| *o == Outcome::Updated));
    assert_eq!(srv.max_in_flight.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn flt_004_file_and_inline_sources() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("my.txt");
    std::fs::write(&file, "0.0.0.0 ads.example.com\n").unwrap();
    let f = fetcher(tmp.path(), settings(), &[]);
    let file_spec = ListSpec {
        source: ListSource::Path(file.clone()),
        ..spec("file", String::new())
    };
    assert_eq!(f.refresh_one(&file_spec).await, Outcome::Updated);
    assert_eq!(f.refresh_one(&file_spec).await, Outcome::Unchanged);
    std::fs::remove_file(&file).unwrap();
    assert!(matches!(
        f.refresh_one(&file_spec).await,
        Outcome::Failed(_)
    ));
    assert_eq!(
        f.store().read_source("file").unwrap(),
        b"0.0.0.0 ads.example.com\n"
    );

    let inline = ListSpec {
        source: ListSource::Inline(vec![
            "||ads.example.com^".into(),
            "@@||ok.example.com^".into(),
        ]),
        ..spec("manual", String::new())
    };
    assert_eq!(f.refresh_one(&inline).await, Outcome::Updated);
    assert_eq!(
        f.store().read_source("manual").unwrap(),
        b"||ads.example.com^\n@@||ok.example.com^\n"
    );
}

// REQ: FLT-004 — a slow or unreachable source doesn't hold back the lists that arrived: the
// compiler is told `settle` after the first update, not at the end of the round.
#[tokio::test]
async fn flt_004_a_slow_list_does_not_delay_the_others() {
    let srv = serve(
        handler(|r, _| {
            if r.path == "/slow" {
                Reply {
                    delay: Duration::from_secs(3),
                    ..ok("slow.com\n")
                }
            } else {
                ok("fast.com\n")
            }
        }),
        None,
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let f = fetcher(
        tmp.path(),
        FetchSettings {
            settle: Duration::from_millis(200),
            ..settings()
        },
        &[],
    );
    let specs = vec![
        spec("fast", srv.url("http", "h", "/fast")),
        spec("slow", srv.url("http", "h", "/slow")),
    ];
    let (_specs_tx, specs_rx) = watch::channel(Arc::new(specs));
    let (changed_tx, mut changed_rx) = watch::channel(0u64);
    let started = std::time::Instant::now();
    let task = tokio::spawn(Arc::clone(&f).run(specs_rx, changed_tx));
    tokio::time::timeout(Duration::from_secs(2), changed_rx.changed())
        .await
        .expect("signalled before the slow list finished")
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(f.store().read_source("fast").is_ok());
    assert!(f.store().read_source("slow").is_err(), "still downloading");
    // The slow list's arrival is signalled too.
    tokio::time::timeout(Duration::from_secs(5), changed_rx.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(f.store().read_source("slow").is_ok());
    task.abort();
}

#[tokio::test]
async fn flt_004_run_loop_signals_changes_and_prunes() {
    let srv = serve(handler(|_, _| ok("a.com\n")), None).await;
    let tmp = tempfile::tempdir().unwrap();
    let f = fetcher(tmp.path(), settings(), &[]);
    let a = spec("a", srv.url("http", "h", "/a"));
    let b = spec("b", srv.url("http", "h", "/b"));
    let (specs_tx, specs_rx) = watch::channel(Arc::new(vec![a.clone(), b]));
    let (changed_tx, mut changed_rx) = watch::channel(0u64);
    let task = tokio::spawn(Arc::clone(&f).run(specs_rx, changed_tx));

    tokio::time::timeout(Duration::from_secs(5), changed_rx.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(f.status().len(), 2);
    assert_eq!(
        srv.requests().len(),
        2,
        "both fetched once, then idle until due"
    );

    // Dropping `b` from the config deletes its stored copy and signals a change.
    specs_tx.send(Arc::new(vec![a])).unwrap();
    tokio::time::timeout(Duration::from_secs(5), changed_rx.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(f.store().read_source("b").is_err());
    assert!(f.store().read_source("a").is_ok());
    assert_eq!(f.status().len(), 1);

    // A manual refresh fetches again; content is identical, so no change signal.
    f.request_refresh();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(srv.requests().len(), 3);
    assert!(!changed_rx.has_changed().unwrap());

    drop(specs_tx);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}
