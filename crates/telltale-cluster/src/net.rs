//! The cluster channel (REQ: CLU-001; `spec/12` §3): mTLS over HTTP/2 on the cluster port.
//!
//! - `POST /cluster/v1/join`: no client certificate needed; the joining node verified *us*
//!   by the CA fingerprint in its token and proves the token secret; it gets a certificate.
//! - `POST /cluster/v1/stream`: client certificate required (signed by the cluster CA). One
//!   persistent bidirectional stream per peer pair: length-prefixed protobuf frames, a Hello
//!   each way, then heartbeats every [`HEARTBEAT`]. Replicas dial out (so only the primary's
//!   port must be reachable, across sites and NAT) and reconnect with jittered backoff.
//!
//! Peers verify each other's certificate against the cluster CA and the shared name
//! [`CLUSTER_NAME`], so trust doesn't depend on the address a peer was dialed at. This module
//! never touches DNS answering (CLU-004): a dead cluster link only marks peers down.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited, channel::Channel};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::node::{Identity, JoinRequest, JoinResponse};
use crate::pki::CLUSTER_NAME;
use crate::token::Token;
use crate::wire::{self, Body, Frame, Heartbeat, Hello, PROTOCOL};

/// Heartbeat interval; a peer silent for three intervals is down.
pub const HEARTBEAT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("certificate: {e}"))
}

fn key(pem: &str) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|e| format!("key: {e}"))
}

fn roots(ca_pem: &str) -> Result<RootCertStore, String> {
    let mut r = RootCertStore::empty();
    for c in certs(ca_pem)? {
        r.add(c).map_err(|e| format!("CA: {e}"))?;
    }
    Ok(r)
}

/// The listener's TLS: our chain (node + CA, so joiners can pin the CA), client certificates
/// from the cluster CA verified when presented (the join route takes none).
pub fn server_config(id: &Identity) -> Result<Arc<ServerConfig>, String> {
    let p = provider();
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots(&id.ca_pem)?), Arc::clone(&p))
            .allow_unauthenticated()
            .build()
            .map_err(|e| e.to_string())?;
    let mut chain = certs(&id.cert_pem)?;
    chain.extend(certs(&id.ca_pem)?);
    let mut cfg = ServerConfig::builder_with_provider(p)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key(&id.key_pem)?)
        .map_err(|e| e.to_string())?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

/// Our TLS as a member dialing a peer: present our certificate, trust the cluster CA.
pub fn client_config(id: &Identity) -> Result<Arc<ClientConfig>, String> {
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots(&id.ca_pem)?)
        .with_client_auth_cert(certs(&id.cert_pem)?, key(&id.key_pem)?)
        .map_err(|e| e.to_string())?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

/// Verifies a server by the CA fingerprint in a join token: the CA must be in the chain the
/// server sends, hash to the pinned value, and have signed the server's certificate.
#[derive(Debug)]
struct PinnedCa {
    fp: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCa {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ca = intermediates
            .iter()
            .find(|c| ring::digest::digest(&ring::digest::SHA256, c).as_ref() == self.fp)
            .ok_or_else(|| {
                rustls::Error::General("the server's CA doesn't match the join token".into())
            })?;
        let mut r = RootCertStore::empty();
        r.add(ca.clone().into_owned())
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(r),
            Arc::clone(&self.provider),
        )
        .build()
        .map_err(|e| rustls::Error::General(e.to_string()))?
        .verify_server_cert(end_entity, &[], server_name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The node ID in a certificate (`<id>.node.telltale.invalid`).
pub fn peer_node_id(cert: &CertificateDer<'_>) -> Option<String> {
    let (_, c) = x509_parser::parse_x509_certificate(cert).ok()?;
    let san = c.subject_alternative_name().ok()??;
    san.value.general_names.iter().find_map(|n| match n {
        x509_parser::extensions::GeneralName::DNSName(d) => {
            d.strip_suffix(".node.telltale.invalid").map(str::to_owned)
        }
        _ => None,
    })
}

/// What this node knows about a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub node_id: String,
    pub site: String,
    pub version: String,
    pub advertise: Vec<String>,
    pub eligible: bool,
    pub primary: bool,
    pub last_seen_ms: u64,
    pub epoch: u64,
    pub applied_seq: u64,
    pub qps: u64,
    /// `inbound` (it dialed us) or `outbound`.
    pub via: &'static str,
}

impl Member {
    /// Up when heard from within three heartbeats.
    pub fn up(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_seen_ms)
            <= 3 * u64::try_from(HEARTBEAT.as_millis()).unwrap_or(15_000)
    }
}

/// Values this node reports in its Hello and heartbeats.
#[derive(Debug, Clone, Default)]
pub struct LocalState {
    pub epoch: u64,
    pub applied_seq: u64,
    pub qps: u64,
}

/// A node's cluster runtime: identity, peers, and its own reported state.
#[derive(Debug)]
pub struct Cluster {
    pub identity: Identity,
    pub version: String,
    members: Mutex<BTreeMap<String, Member>>,
    local: Mutex<LocalState>,
}

impl Cluster {
    pub fn new(identity: Identity, version: &str) -> Arc<Self> {
        Arc::new(Self {
            local: Mutex::new(LocalState {
                epoch: identity.meta.epoch,
                ..LocalState::default()
            }),
            identity,
            version: version.to_owned(),
            members: Mutex::new(BTreeMap::new()),
        })
    }

    /// Peers, by node ID.
    pub fn members(&self) -> Vec<Member> {
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    /// Updates what this node reports (qps from telemetry, applied version from replication).
    pub fn set_local(&self, f: impl FnOnce(&mut LocalState)) {
        f(&mut self.local.lock().unwrap_or_else(PoisonError::into_inner));
    }

    fn hello(&self) -> Frame {
        let m = &self.identity.meta;
        let l = self
            .local
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        Frame {
            body: Some(Body::Hello(Hello {
                protocol: PROTOCOL,
                cluster_id: m.cluster_id.clone(),
                node_id: m.node_id.clone(),
                version: self.version.clone(),
                site: m.site.clone(),
                eligible: m.eligible,
                advertise: m.advertise.clone(),
                epoch: l.epoch,
                applied_seq: l.applied_seq,
                primary: self.identity.holds_ca(),
            })),
        }
    }

    fn heartbeat(&self) -> Frame {
        let l = self
            .local
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        Frame {
            body: Some(Body::Heartbeat(Heartbeat {
                ts_ms: now_ms(),
                epoch: l.epoch,
                applied_seq: l.applied_seq,
                qps: l.qps,
            })),
        }
    }

    /// Applies a frame from `peer` (whose ID the TLS certificate proved, when known).
    fn on_frame(
        &self,
        peer: &mut Option<String>,
        f: Frame,
        via: &'static str,
    ) -> Result<(), String> {
        let mut members = self.members.lock().unwrap_or_else(PoisonError::into_inner);
        match f.body {
            Some(Body::Hello(h)) => {
                if h.protocol != PROTOCOL {
                    return Err(format!(
                        "peer speaks protocol {}, we speak {PROTOCOL}",
                        h.protocol
                    ));
                }
                if h.cluster_id != self.identity.meta.cluster_id {
                    return Err("peer is in another cluster".into());
                }
                if let Some(p) = peer.as_ref()
                    && *p != h.node_id
                {
                    return Err("peer's Hello doesn't match its certificate".into());
                }
                *peer = Some(h.node_id.clone());
                members.insert(
                    h.node_id.clone(),
                    Member {
                        node_id: h.node_id,
                        site: h.site,
                        version: h.version,
                        advertise: h.advertise,
                        eligible: h.eligible,
                        primary: h.primary,
                        last_seen_ms: now_ms(),
                        epoch: h.epoch,
                        applied_seq: h.applied_seq,
                        qps: 0,
                        via,
                    },
                );
            }
            Some(Body::Heartbeat(hb)) => {
                let id = peer.as_ref().ok_or("heartbeat before Hello")?;
                if let Some(m) = members.get_mut(id) {
                    m.last_seen_ms = now_ms();
                    m.epoch = hb.epoch;
                    m.applied_seq = hb.applied_seq;
                    m.qps = hb.qps;
                }
            }
            None => {}
        }
        Ok(())
    }
}

/// Reads frames from `body` into `cluster` until it ends.
async fn read_frames(
    cluster: &Cluster,
    mut body: Incoming,
    mut peer: Option<String>,
    via: &'static str,
) -> Result<(), String> {
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| e.to_string())?;
        if let Ok(data) = frame.into_data() {
            buf.extend_from_slice(&data);
            for f in wire::decode_all(&mut buf)? {
                cluster.on_frame(&mut peer, f, via)?;
            }
        }
    }
    Ok(())
}

/// Sends our Hello, then heartbeats, until the receiver goes away.
async fn write_frames(cluster: Arc<Cluster>, mut tx: http_body_util::channel::Sender<Bytes>) {
    if tx
        .send_data(Bytes::from(wire::encode(&cluster.hello())))
        .await
        .is_err()
    {
        return;
    }
    let mut tick = tokio::time::interval(HEARTBEAT);
    tick.tick().await;
    loop {
        tick.tick().await;
        if tx
            .send_data(Bytes::from(wire::encode(&cluster.heartbeat())))
            .await
            .is_err()
        {
            return;
        }
    }
}

type HttpBody = http_body_util::Either<Full<Bytes>, Channel<Bytes>>;

fn reply(status: StatusCode, text: String) -> Response<HttpBody> {
    let mut r = Response::new(http_body_util::Either::Left(Full::new(Bytes::from(text))));
    *r.status_mut() = status;
    r
}

async fn handle(
    cluster: Arc<Cluster>,
    peer: Option<String>,
    req: Request<Incoming>,
) -> Response<HttpBody> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/cluster/v1/join") => {
            if !cluster.identity.holds_ca() {
                return reply(
                    StatusCode::FORBIDDEN,
                    "this node can't issue certificates; join through the primary".into(),
                );
            }
            let body = match Limited::new(req.into_body(), 64 * 1024).collect().await {
                Ok(b) => b.to_bytes(),
                Err(_) => return reply(StatusCode::PAYLOAD_TOO_LARGE, "request too large".into()),
            };
            let Ok(jr) = serde_json::from_slice::<JoinRequest>(&body) else {
                return reply(StatusCode::BAD_REQUEST, "bad join request".into());
            };
            match cluster.identity.accept_join(&jr) {
                Ok(resp) => {
                    info!(node = %resp.node_id, site = %jr.site, "a node joined the cluster");
                    reply(
                        StatusCode::OK,
                        serde_json::to_string(&resp).unwrap_or_default(),
                    )
                }
                Err(e) => {
                    warn!("join refused: {e}");
                    reply(StatusCode::FORBIDDEN, e)
                }
            }
        }
        (&Method::POST, "/cluster/v1/stream") => {
            let Some(id) = peer else {
                return reply(
                    StatusCode::UNAUTHORIZED,
                    "a cluster certificate is required".into(),
                );
            };
            let (tx, body) = Channel::<Bytes>::new(16);
            let c = Arc::clone(&cluster);
            tokio::spawn(write_frames(Arc::clone(&cluster), tx));
            tokio::spawn(async move {
                if let Err(e) = read_frames(&c, req.into_body(), Some(id.clone()), "inbound").await
                {
                    debug!(peer = %id, "cluster stream ended: {e}");
                }
            });
            Response::new(http_body_util::Either::Right(body))
        }
        _ => reply(StatusCode::NOT_FOUND, "not found".into()),
    }
}

/// Serves the cluster port until `stop` changes.
pub async fn serve(
    cluster: Arc<Cluster>,
    addr: SocketAddr,
    mut stop: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let tls = tokio_rustls::TlsAcceptor::from(
        server_config(&cluster.identity).map_err(std::io::Error::other)?,
    );
    info!(%addr, "cluster port listening");
    loop {
        let (sock, remote) = tokio::select! {
            _ = stop.changed() => return Ok(()),
            r = listener.accept() => if let Ok(x) = r { x } else {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            },
        };
        let (tls, cluster) = (tls.clone(), Arc::clone(&cluster));
        tokio::spawn(async move {
            let Ok(Ok(stream)) = tokio::time::timeout(CONNECT_TIMEOUT, tls.accept(sock)).await
            else {
                debug!(%remote, "cluster TLS handshake failed");
                return;
            };
            let peer = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .and_then(peer_node_id);
            let svc = hyper::service::service_fn(move |req| {
                let (cluster, peer) = (Arc::clone(&cluster), peer.clone());
                async move { Ok::<_, Infallible>(handle(cluster, peer, req).await) }
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .timer(TokioTimer::new())
                .keep_alive_interval(Some(HEARTBEAT * 2))
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
    }
}

/// `host:port` of a cluster URL.
fn authority(url: &str) -> Result<String, String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let a = rest.split('/').next().unwrap_or("");
    if a.is_empty() {
        return Err(format!("bad cluster URL `{url}`"));
    }
    Ok(if a.contains(':') && !a.ends_with(']') {
        a.to_owned()
    } else {
        format!("{a}:8443")
    })
}

async fn tls_connect(
    url: &str,
    cfg: Arc<ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let a = authority(url)?;
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&a))
        .await
        .map_err(|_| format!("{a}: timed out"))?
        .map_err(|e| format!("{a}: {e}"))?;
    let name = ServerName::try_from(CLUSTER_NAME).map_err(|e| e.to_string())?;
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_rustls::TlsConnector::from(cfg).connect(name, tcp),
    )
    .await
    .map_err(|_| format!("{a}: TLS timed out"))?
    .map_err(|e| format!("{a}: {e}"))
}

/// Joins the cluster in `token`: tries each URL, pins the CA, proves the secret.
pub async fn join(token: &Token, req: &JoinRequest) -> Result<JoinResponse, String> {
    let mut fp = [0u8; 32];
    for (i, b) in fp.iter_mut().enumerate() {
        *b = u8::from_str_radix(token.ca_fp.get(i * 2..i * 2 + 2).unwrap_or("zz"), 16)
            .map_err(|_| "the token's CA fingerprint is damaged".to_owned())?;
    }
    let p = provider();
    let mut cfg = ClientConfig::builder_with_provider(Arc::clone(&p))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCa { fp, provider: p }))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let cfg = Arc::new(cfg);
    let mut last = String::from("the token lists no URLs");
    for url in &token.urls {
        match join_one(url, Arc::clone(&cfg), req).await {
            Ok(r) => return Ok(r),
            Err(e) => last = e,
        }
    }
    Err(last)
}

async fn join_one(
    url: &str,
    cfg: Arc<ClientConfig>,
    req: &JoinRequest,
) -> Result<JoinResponse, String> {
    let tls = tls_connect(url, cfg).await?;
    let (mut send, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let body = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    let r = send
        .send_request(
            Request::post(format!("https://{CLUSTER_NAME}/cluster/v1/join"))
                .body(Full::new(Bytes::from(body)))
                .map_err(|e| e.to_string())?,
        )
        .await
        .map_err(|e| e.to_string())?;
    let status = r.status();
    let bytes = Limited::new(r.into_body(), 256 * 1024)
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    if !status.is_success() {
        return Err(format!("{url}: {}", String::from_utf8_lossy(&bytes)));
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("{url}: bad join response: {e}"))
}

/// Keeps a stream to the first reachable URL open, reconnecting with jittered backoff until
/// `stop` changes.
pub async fn dial(cluster: Arc<Cluster>, urls: Vec<String>, mut stop: watch::Receiver<bool>) {
    let cfg = match client_config(&cluster.identity) {
        Ok(c) => c,
        Err(e) => {
            warn!("cluster: can't build TLS settings: {e}");
            return;
        }
    };
    let mut backoff = Duration::from_secs(1);
    loop {
        for url in &urls {
            let started = tokio::time::Instant::now();
            tokio::select! {
                _ = stop.changed() => return,
                r = stream_once(Arc::clone(&cluster), url, Arc::clone(&cfg)) => match r {
                    Ok(()) => debug!(%url, "cluster stream closed"),
                    Err(e) => debug!(%url, "cluster stream: {e}"),
                },
            }
            if started.elapsed() > Duration::from_secs(60) {
                backoff = Duration::from_secs(1); // it was up for a while
            }
        }
        // Full jitter: wait a random share of the backoff.
        let wait = backoff
            .mul_f64(f64::from(rand::random::<u16>()) / f64::from(u16::MAX))
            .max(Duration::from_millis(200));
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(wait) => {}
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn stream_once(
    cluster: Arc<Cluster>,
    url: &str,
    cfg: Arc<ClientConfig>,
) -> Result<(), String> {
    let tls = tls_connect(url, cfg).await?;
    let server_id = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .and_then(peer_node_id);
    let (mut send, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(HEARTBEAT * 2))
        .handshake(TokioIo::new(tls))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let (tx, body) = Channel::<Bytes>::new(16);
    let writer = tokio::spawn(write_frames(Arc::clone(&cluster), tx));
    let r = send
        .send_request(
            Request::post(format!("https://{CLUSTER_NAME}/cluster/v1/stream"))
                .body(body)
                .map_err(|e| e.to_string())?,
        )
        .await
        .map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        writer.abort();
        return Err(format!("{url}: {}", r.status()));
    }
    let result = read_frames(&cluster, r.into_body(), server_id, "outbound").await;
    writer.abort();
    result
}

#[cfg(test)]
#[path = "net_tests.rs"]
mod tests;
