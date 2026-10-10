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

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
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
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::node::{Identity, JoinRequest, JoinResponse, Role};
use crate::pki::CLUSTER_NAME;
use crate::sync::{BlobRef, BlobStore, ClusterManifest, Signed};
use crate::token::Token;
use crate::wire::{
    self, Body, Frame, Heartbeat, Hello, KeyShare, ManifestMsg, PROTOCOL, RpcRequest, RpcResponse,
};

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

/// The wall clock in Unix ms (maintenance windows and handover timing are on it).
pub(crate) fn wall_ms() -> u64 {
    now_ms()
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

/// Where the bootstrap secret comes from.
#[derive(Debug)]
enum BootstrapSecret {
    Value(String),
    File(PathBuf),
}

/// What `POST /cluster/v1/ca` returns: the CA, and proof the server knows the bootstrap secret.
#[derive(Debug, Serialize, Deserialize)]
struct BootstrapCa {
    cluster_id: String,
    cluster_name: String,
    ca_pem: String,
    /// HMAC-SHA256(secret, nonce + ":" + CA fingerprint), hex.
    proof: String,
}

fn bootstrap_proof(secret: &str, nonce: &str, ca_fp_hex: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let tag = ring::hmac::sign(&key, format!("{nonce}:{ca_fp_hex}").as_bytes());
    crate::pki::hex(tag.as_ref())
}

/// Accepts any server certificate: used only to fetch the CA, which is then checked by the
/// bootstrap proof before anything trusts it.
#[derive(Debug)]
struct AnyServer(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyServer {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
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
            &self.0.signature_verification_algorithms,
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
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Builds a join token from a bootstrap secret (CLU-009): fetches the CA from `url` and
/// trusts it only if the server proves it knows `secret` (HMAC over a fresh nonce and the CA's
/// fingerprint). The token never expires; it's never stored.
pub async fn bootstrap_token(url: &str, secret: &str) -> Result<crate::token::Token, String> {
    let p = provider();
    let mut cfg = ClientConfig::builder_with_provider(Arc::clone(&p))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyServer(p)))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tls = tls_connect(url, Arc::new(cfg)).await?;
    let (mut send, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let nonce = crate::pki::hex(&rand::random::<[u8; 16]>());
    let r = send
        .send_request(
            Request::post(format!("https://{CLUSTER_NAME}/cluster/v1/ca"))
                .body(Full::new(Bytes::from(nonce.clone())))
                .map_err(|e| e.to_string())?,
        )
        .await
        .map_err(|e| e.to_string())?;
    let status = r.status();
    let bytes = Limited::new(r.into_body(), 64 * 1024)
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    if !status.is_success() {
        return Err(format!("{url}: {}", String::from_utf8_lossy(&bytes)));
    }
    let b: BootstrapCa =
        serde_json::from_slice(&bytes).map_err(|e| format!("{url}: bad answer: {e}"))?;
    let fp = crate::pki::hex(&crate::pki::fingerprint(&b.ca_pem).map_err(|e| e.to_string())?);
    let want = bootstrap_proof(secret, &nonce, &fp);
    if !crate::node::same(want.as_bytes(), b.proof.as_bytes()) {
        return Err(format!(
            "{url} didn't prove it knows the bootstrap secret; not trusting its CA"
        ));
    }
    Ok(crate::token::Token {
        v: 1,
        cluster_id: b.cluster_id,
        cluster_name: b.cluster_name,
        ca_fp: fp,
        urls: vec![url.to_owned()],
        secret: secret.to_owned(),
        exp: u64::MAX,
    })
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
#[allow(clippy::struct_excessive_bools)] // a record of independent flags
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
    /// Whether a stream to it is open right now.
    pub connected: bool,
    /// When the current (or last) stream came up (Unix ms).
    pub connected_ms: u64,
    /// Round-trip time measured from heartbeat echoes.
    pub rtt_ms: Option<u32>,
    pub ready: bool,
    pub servfail_permille: u32,
    pub p90_us: u64,
    pub uptime_s: u64,
    /// Since when its applied configuration has been older than the newest known (Unix ms).
    pub behind_since_ms: Option<u64>,
    /// `gitops` or `file` (ADR-048).
    pub config_source: String,
    /// The cluster protocol it speaks (CLU-010).
    pub protocol: u32,
    /// The Git commit of the configuration it serves (ADR-049).
    pub source_commit: String,
    /// The CAs it trusts ([`crate::pki::trust_fp`]) and the CA that issued its certificate
    /// (hex fingerprint), from its heartbeats: CA rotation readiness (T5.4c).
    pub trust_fp: String,
    pub issuer_fp: String,
    /// The machine it runs on, from its heartbeats (T6.11); absent from older nodes.
    pub host: Option<crate::wire::HostStats>,
    /// Its clock minus ours, estimated from heartbeat timestamps and the round-trip time.
    pub clock_offset_ms: Option<i64>,
    /// REQ: CLU-008 (T6.14) — Kubernetes node and pod (empty elsewhere), process start, how
    /// often we've seen it restart, and its cache, from its heartbeats.
    pub kube_node: String,
    pub pod: String,
    pub started_ms: u64,
    pub restarts: u32,
    pub cache_entries: Option<u64>,
    pub cache_hit_permille: Option<u32>,
    /// REQ: OPS-010 — its maintenance window, from its heartbeats (kept while it's silent, so a
    /// node stopped during its window stays in maintenance until the window ends).
    pub maintenance: Option<MaintenanceWindow>,
    /// REQ: CLU-013 — it can be a canary (older nodes: never), why it couldn't apply the
    /// newest version, and whether its listener probes fail, from its heartbeats.
    pub rollouts: bool,
    pub sync_error: String,
    pub probe_failing: bool,
    /// REQ: CLU-013 — while it runs a canary version, the stable `seq` that one would replace.
    pub canary_of: u64,
}

/// REQ: CLU-013 — the stable version a node is at: its applied version, or, while it runs a
/// canary version, the stable one that would replace (configuration lag counts only stable
/// versions, so nodes waiting out a bake aren't behind).
fn stable_seq(applied_seq: u64, canary_of: u64) -> u64 {
    if canary_of > 0 {
        canary_of
    } else {
        applied_seq
    }
}

/// REQ: OPS-010 (ADR-118) — a node's maintenance window, as heartbeats carry it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaintenanceWindow {
    /// When it ends and when it started (Unix ms, the node's clock).
    pub until_ms: u64,
    pub since_ms: u64,
    pub reason: String,
    /// `alice`, `alice via pi`, or an agent.
    pub by: String,
}

impl MaintenanceWindow {
    /// Whether the window is still open at `now_ms`.
    pub fn active(&self, now_ms: u64) -> bool {
        now_ms < self.until_ms
    }
}

impl Member {
    /// REQ: CLU-013 — the stable version it's at (see [`stable_seq`]).
    pub fn stable_seq(&self) -> u64 {
        stable_seq(self.applied_seq, self.canary_of)
    }

    /// REQ: OPS-010 — its maintenance window, while it's open.
    pub fn in_maintenance(&self, now_ms: u64) -> Option<&MaintenanceWindow> {
        self.maintenance.as_ref().filter(|w| w.active(now_ms))
    }

    /// Up when heard from within three heartbeats.
    pub fn up(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_seen_ms)
            <= 3 * u64::try_from(HEARTBEAT.as_millis()).unwrap_or(15_000)
    }
}

/// Values this node reports in its Hello and heartbeats.
#[derive(Debug, Clone, Default)]
pub struct LocalState {
    /// The Git commit of the configuration this node serves (ADR-049).
    pub source_commit: String,
    pub epoch: u64,
    pub applied_seq: u64,
    pub qps: u64,
    pub ready: bool,
    pub servfail_permille: u32,
    pub p90_us: u64,
    pub uptime_s: u64,
    /// The machine this node runs on (T6.11), refreshed by the binary's collector.
    pub host: Option<crate::wire::HostStats>,
    /// T6.14 — Kubernetes node and pod names, process start (Unix ms), and the cache.
    pub kube_node: String,
    pub pod: String,
    pub started_ms: u64,
    pub cache_entries: Option<u64>,
    pub cache_hit_permille: Option<u32>,
    /// REQ: OPS-010 — this node's maintenance window (heartbeats carry it).
    pub maintenance: Option<MaintenanceWindow>,
    /// REQ: CLU-013 — one of this node's listener probes is failing.
    pub probe_failing: bool,
    /// REQ: CLU-013 — while this node runs a canary version, the stable `seq` it would replace.
    pub canary_of: u64,
}

/// REQ: CLU-013 (T13.2, ADR-116) — the canary head: a version sent only to these peers (node
/// IDs) while it bakes; everyone else gets the stable head.
#[derive(Debug, Clone)]
pub struct Canary {
    pub signed: Arc<Signed>,
    pub peers: Arc<std::collections::BTreeSet<String>>,
}

/// REQ: OPS-010 — a handover that hasn't produced a new primary after this long is given up:
/// the primary renews again (four lease windows: a replica that could win would have).
pub const HANDOVER_GIVE_UP_MS: u64 = 60_000;

/// Host samples kept per peer: one hour at the collector's 15 s interval (T6.11).
pub const HOST_HISTORY: usize = 240;

/// Something that happened in the cluster, for the Cluster page's timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub ts_ms: u64,
    /// `joined`, `connected`, `disconnected`, `restarted`, `published`, `applied`, `sync_failed`,
    /// `rejected`.
    pub kind: &'static str,
    /// The node it's about.
    pub node: String,
    pub detail: String,
}

/// The RPC an ephemeral member sends when it shuts down (CLU-009).
pub const LEAVE: &str = "cluster.leave";

/// Events kept in memory.
const MAX_EVENTS: usize = 200;

/// Answers peers' RPCs (CLU-002): `(peer node ID, kind, body)` → body, or an error. The peer
/// ID comes from the stream's mTLS certificate, so a handler can trust it.
pub type RpcHandler = Arc<
    dyn Fn(
            String,
            String,
            Vec<u8>,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send>>
        + Send
        + Sync,
>;

/// The installed [`RpcHandler`] (a closure has no `Debug`).
struct HandlerSlot(RpcHandler);

impl std::fmt::Debug for HandlerSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RpcHandler")
    }
}

/// RPCs awaiting an answer, by request ID.
type PendingCalls = HashMap<u64, tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>>;

/// Largest RPC answer (the frame limit, less framing).
const MAX_RPC: usize = crate::wire::MAX_FRAME - 1024;

/// The last heartbeat received on a stream, echoed back on the same stream.
type EchoSlot = Arc<Mutex<Option<(u64, tokio::time::Instant)>>>;

/// Where the primary reads a blob it serves.
#[derive(Debug, Clone)]
pub enum BlobSource {
    Bytes(Bytes),
    File(PathBuf),
}

/// Largest blob a replica accepts (FST shards of a few million names are ~5 MB).
const MAX_BLOB: usize = 256 << 20;
/// Blobs fetched at once.
const FETCH_PARALLEL: usize = 8;

/// A node's cluster runtime: identity, peers, and its own reported state.
#[derive(Debug)]
pub struct Cluster {
    pub identity: Identity,
    pub version: String,
    members: Mutex<BTreeMap<String, Member>>,
    local: Mutex<LocalState>,
    /// The manifest this node publishes (primary), sent on every stream: the stable head.
    published: watch::Sender<Option<Arc<Signed>>>,
    /// REQ: CLU-013 — the canary head, sent instead of the stable one to its peers.
    canary: watch::Sender<Option<Canary>>,
    /// Blobs this node serves, by hash.
    served: Mutex<HashMap<String, BlobSource>>,
    /// The newest manifest received from a peer (verified by whoever applies it).
    incoming: watch::Sender<Option<Arc<Signed>>>,
    /// The primary URL of the stream that's up (blobs are fetched from there).
    connected: Mutex<Option<String>>,
    /// Replication state, for the API and the Cluster page.
    sync: Mutex<SyncStatus>,
    /// Bumped when the applied version changes, so the next heartbeat goes out at once.
    local_changed: watch::Sender<u64>,
    events: Mutex<VecDeque<Event>>,
    /// Since when this node's own applied version has been behind the newest known.
    behind_since: Mutex<Option<u64>>,
    /// This node's role and the epoch it holds it in (ADR-051); persisted on change.
    role: watch::Sender<(Role, u64)>,
    /// ADR-051 — held while the role changes and while a manifest is published, so a primary
    /// that's being fenced never publishes in the new epoch (see [`Cluster::publish_as`]).
    fence: Mutex<()>,
    /// `gitops` or `file`: how this node's own configuration is managed (ADR-048).
    config_source: Mutex<String>,
    /// Extra frames to send on the stream to each peer (RPC), by peer node ID.
    outbox: Mutex<HashMap<String, tokio::sync::mpsc::Sender<Frame>>>,
    /// RPCs awaiting an answer, by request ID.
    pending: Mutex<PendingCalls>,
    next_rpc: std::sync::atomic::AtomicU64,
    rpc_handler: std::sync::OnceLock<HandlerSlot>,
    /// The running election, in automatic failover (ADR-056).
    pub(crate) election: Mutex<Option<crate::election::Elector>>,
    /// Whether this node may publish: a primary holding a valid lease (always, in manual mode).
    lease_ok: std::sync::atomic::AtomicBool,
    failover_view: Mutex<crate::failover::FailoverView>,
    /// Bumped when this node's certificate is renewed: TLS settings are rebuilt (T5.4c).
    cert_gen: AtomicU64,
    /// The shared join secret this node accepts (CLU-009).
    bootstrap: std::sync::OnceLock<BootstrapSecret>,
    /// When this process started (Unix ms), for expiring ephemeral members.
    started_ms: u64,
    /// Each peer's recent host samples, oldest first (T6.11).
    host_history: Mutex<HashMap<String, VecDeque<crate::wire::HostStats>>>,
    /// REQ: OPS-010 — when this primary started handing over (Unix ms; 0: it isn't).
    handover_since_ms: AtomicU64,
}

/// What this node has applied from the primary (replica) or published (primary).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncStatus {
    pub epoch: u64,
    pub seq: u64,
    /// When the manifest was created on the primary (Unix ms).
    pub created_ms: u64,
    /// When this node applied (or published) it (Unix ms).
    pub applied_ms: u64,
    /// Blobs fetched for it (0 on the primary).
    pub fetched: usize,
    /// Fetch + apply time.
    pub duration_ms: u64,
    /// The last failure, cleared by the next success.
    pub error: Option<String>,
}

impl Cluster {
    pub fn new(identity: Identity, version: &str) -> Arc<Self> {
        let identity_role = identity.meta.role.unwrap_or(Role::Replica);
        let identity_epoch = identity.meta.epoch;
        let wait_for_lease = crate::failover::active(&identity) && identity.is_primary();
        Arc::new(Self {
            local: Mutex::new(LocalState {
                epoch: identity.meta.epoch,
                ..LocalState::default()
            }),
            identity,
            version: version.to_owned(),
            members: Mutex::new(BTreeMap::new()),
            published: watch::Sender::new(None),
            canary: watch::Sender::new(None),
            served: Mutex::new(HashMap::new()),
            incoming: watch::Sender::new(None),
            connected: Mutex::new(None),
            sync: Mutex::new(SyncStatus::default()),
            local_changed: watch::Sender::new(0),
            events: Mutex::new(VecDeque::new()),
            host_history: Mutex::new(HashMap::new()),
            behind_since: Mutex::new(None),
            role: watch::Sender::new((identity_role, identity_epoch)),
            fence: Mutex::new(()),
            config_source: Mutex::new("file".into()),
            outbox: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            next_rpc: std::sync::atomic::AtomicU64::new(1),
            rpc_handler: std::sync::OnceLock::new(),
            election: Mutex::new(None),
            // ADR-056 — a primary in automatic failover waits for its first renewal.
            lease_ok: std::sync::atomic::AtomicBool::new(!wait_for_lease),
            failover_view: Mutex::new(crate::failover::FailoverView::default()),
            cert_gen: AtomicU64::new(0),
            bootstrap: std::sync::OnceLock::new(),
            started_ms: now_ms(),
            handover_since_ms: AtomicU64::new(0),
        })
    }

    /// REQ: OPS-010 (ADR-118) — starts (`Some`) or ends (`None`) this node's maintenance: the
    /// next heartbeat (sent at once) carries it, elections leave the node out as a candidate,
    /// and with `handover` a primary stops renewing its lease so another node is elected.
    pub fn set_maintenance(&self, w: Option<MaintenanceWindow>, handover: bool) {
        let me = self.identity.meta.node_id.clone();
        let detail = w.as_ref().map(|w| {
            format!(
                "for {} min ({}), by {}",
                w.until_ms.saturating_sub(w.since_ms).div_ceil(60_000),
                w.reason,
                w.by
            )
        });
        let starting = handover && w.is_some();
        self.handover_since_ms
            .store(if starting { now_ms() } else { 0 }, Ordering::Release);
        {
            let mut l = self.local.lock().unwrap_or_else(PoisonError::into_inner);
            l.maintenance = w;
        }
        self.local_changed.send_modify(|n| *n += 1);
        match detail {
            Some(d) => self.event("maintenance", &me, d),
            None => self.event("maintenance_ended", &me, "back in service"),
        }
        if starting {
            self.event(
                "handover",
                &me,
                "maintenance: this primary stops renewing its lease so another node is elected",
            );
        }
    }

    /// REQ: OPS-010 — whether this node is in maintenance now.
    pub fn in_maintenance(&self) -> bool {
        self.local
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .maintenance
            .as_ref()
            .is_some_and(|w| w.active(now_ms()))
    }

    /// REQ: OPS-010 — whether this primary is handing over (it stops renewing its lease).
    pub fn stepping_down(&self) -> bool {
        self.handover_since_ms.load(Ordering::Acquire) != 0
    }

    /// REQ: OPS-010 — a handover running past [`HANDOVER_GIVE_UP_MS`] without a new primary
    /// is given up (the node renews again); returns whether it was.
    pub(crate) fn give_up_handover(&self, now: u64) -> bool {
        let since = self.handover_since_ms.load(Ordering::Acquire);
        if since == 0 || now.saturating_sub(since) < HANDOVER_GIVE_UP_MS {
            return false;
        }
        self.handover_since_ms.store(0, Ordering::Release);
        warn!("cluster: no other node took over within 60 s; this primary keeps the role");
        self.event(
            "handover_failed",
            &self.identity.meta.node_id.clone(),
            "no other node was elected within 60 s; this node stays the primary (promote another node first)",
        );
        true
    }

    /// The key-share frame for `peer`, when this node is the primary, holds the key, and the
    /// registry marks `peer` eligible.
    fn key_share_for(&self, peer: &str) -> Option<Frame> {
        if !self.is_primary() {
            return None;
        }
        let eligible = self
            .identity
            .registry()
            .iter()
            .any(|n| n.node_id == peer && n.eligible);
        if !eligible {
            return None;
        }
        let id = self.identity.reload();
        let key = id.ca_key_pem().ok()?;
        Some(Frame {
            body: Some(Body::KeyShare(KeyShare {
                ca_key_pem: key,
                // During a CA rotation, the new CA's key too (T5.4c).
                next_ca_key_pem: id.next_ca_key_pem().unwrap_or_default(),
            })),
        })
    }

    /// Adds or updates `node_id` in the primary's registry from what its Hello said.
    fn record_member(&self, node_id: &str) {
        let Some(m) = self.members().into_iter().find(|m| m.node_id == node_id) else {
            return;
        };
        let mut nodes = self.identity.registry();
        let known = nodes.iter().find(|n| n.node_id == node_id);
        let rec = crate::node::NodeRecord {
            node_id: m.node_id.clone(),
            site: m.site.clone(),
            // ADR-051, ADR-058 — eligibility was decided at join (a node from before the
            // registry existed is taken at its word once): a Hello can't raise it, so the
            // key share never follows a peer's claim.
            eligible: known.map_or(m.eligible, |n| n.eligible),
            advertise: m.advertise.clone(),
            joined: known.map_or_else(|| now_ms() / 1000, |n| n.joined),
            // Set at join (ADR-056, CLU-009); Hello doesn't carry them.
            witness: known.is_some_and(|n| n.witness),
            ephemeral: known.is_some_and(|n| n.ephemeral),
        };
        if nodes.contains(&rec) {
            return;
        }
        nodes.retain(|n| n.node_id != node_id);
        nodes.push(rec);
        if let Err(e) = self.identity.save_registry(&nodes) {
            warn!("cluster: can't record {node_id} in the registry: {e}");
        }
    }

    /// Changes whenever this node's certificate is renewed.
    pub fn cert_generation(&self) -> u64 {
        self.cert_gen.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn bump_cert_generation(&self) {
        self.cert_gen
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Whether this node may publish configuration now (ADR-056): in automatic failover, only a
    /// primary whose lease holds.
    pub fn may_publish(&self) -> bool {
        self.lease_ok.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn set_lease_ok(&self, ok: bool) {
        let was = self.lease_ok.swap(ok, std::sync::atomic::Ordering::AcqRel);
        if was && !ok && self.is_primary() && self.stepping_down() {
            // REQ: OPS-010 — expected: the lease ran out on purpose.
            info!(
                "cluster: handing over for maintenance: publishing stopped; another node is elected within seconds"
            );
            self.event(
                "lease_released",
                &self.identity.meta.node_id.clone(),
                "handing over for maintenance",
            );
        } else if was && !ok && self.is_primary() {
            warn!(
                "cluster: this primary's lease lapsed; publishing paused until a majority renews it"
            );
            self.event(
                "lease_lost",
                &self.identity.meta.node_id.clone(),
                "publishing paused",
            );
        }
    }

    /// The election as the Cluster page shows it.
    pub fn failover_view(&self) -> crate::failover::FailoverView {
        self.failover_view
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn set_failover_view(&self, v: crate::failover::FailoverView) {
        *self
            .failover_view
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = v;
    }

    /// Records a vote this node granted, in the event log.
    pub(crate) fn note_vote(&self, candidate: &str, epoch: u64) {
        let last = self.events().last().map(|e| (e.kind, e.detail.clone()));
        let detail = format!("voted for {candidate} in epoch {epoch}");
        if last != Some(("voted", detail.clone())) {
            self.event("voted", &self.identity.meta.node_id.clone(), detail);
        }
    }

    /// The shared bootstrap secret this node accepts for joins (CLU-009), once.
    pub fn set_bootstrap_secret(&self, secret: String) {
        let _ = self.bootstrap.set(BootstrapSecret::Value(secret));
    }

    /// Like [`Self::set_bootstrap_secret`], read from `path` at every use, so a rotated
    /// Kubernetes Secret takes effect without a restart.
    pub fn set_bootstrap_file(&self, path: PathBuf) {
        let _ = self.bootstrap.set(BootstrapSecret::File(path));
    }

    /// The bootstrap secret, now.
    fn bootstrap_secret(&self) -> Option<String> {
        let s = match self.bootstrap.get()? {
            BootstrapSecret::Value(v) => v.clone(),
            BootstrapSecret::File(p) => std::fs::read_to_string(p).ok()?,
        };
        let s = s.trim();
        (!s.is_empty()).then(|| s.to_owned())
    }

    /// Drops ephemeral members not heard from for `ttl` from the registry (primary only, CLU-009).
    /// Returns the IDs dropped.
    pub fn gc_ephemeral(&self, ttl: Duration) -> Vec<String> {
        if !self.is_primary() {
            return Vec::new();
        }
        let now = now_ms();
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        let members = self.members();
        let mut nodes = self.identity.registry();
        let mut gone = Vec::new();
        nodes.retain(|n| {
            if !n.ephemeral {
                return true;
            }
            // Last heard: from its stream, else when it joined, else when this node started.
            let heard = members.iter().find(|m| m.node_id == n.node_id).map_or_else(
                || (n.joined * 1000).max(self.started_ms),
                |m| m.last_seen_ms,
            );
            let keep = members
                .iter()
                .any(|m| m.node_id == n.node_id && m.connected)
                || now.saturating_sub(heard) < ttl_ms;
            if !keep {
                gone.push(n.node_id.clone());
            }
            keep
        });
        if !gone.is_empty() {
            let _ = self.identity.save_registry(&nodes);
            let mut m = self.members.lock().unwrap_or_else(PoisonError::into_inner);
            for id in &gone {
                m.remove(id);
                self.event("expired", id, "ephemeral member not heard from");
            }
        }
        gone
    }

    /// REQ: CLU-009 — an ephemeral member (a resolver pod) that's shutting down leaves at once
    /// instead of showing as down until it expires (primary only). Members that aren't
    /// ephemeral stay: a Pi or a controller restarting is still part of the cluster.
    pub fn remove_ephemeral(&self, id: &str) -> Result<(), String> {
        if !self.is_primary() {
            return Err("only the primary keeps the member list".into());
        }
        let mut nodes = self.identity.registry();
        match nodes.iter().find(|n| n.node_id == id) {
            Some(n) if !n.ephemeral => {
                return Err("only ephemeral members (resolver pods) leave this way".into());
            }
            Some(_) => {
                nodes.retain(|n| n.node_id != id);
                self.identity.save_registry(&nodes)?;
            }
            None => {}
        }
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        // Nothing can be asked of a member that left (the reply to its own leave goes out on a
        // sender the caller already holds). Without this its stream lingered in the outbox and
        // every federated read listed it as a node that didn't answer, by bare node ID.
        self.outbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        self.event("left", id, "shut down (scaled in, replaced, or deleted)");
        Ok(())
    }

    /// REQ: CLU-009 — on shutdown, an ephemeral member asks the primary to drop it now (see
    /// [`Self::remove_ephemeral`], which refuses members that aren't ephemeral). Bounded by
    /// `timeout`.
    pub async fn leave(&self, timeout: Duration) -> Result<(), String> {
        // The stream may be reconnecting right now: wait for it (within `timeout`).
        let deadline = tokio::time::Instant::now() + timeout;
        let primary = loop {
            if let Some(p) = self.reachable_primary() {
                break p;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("the primary isn't reachable; this member will expire instead".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let left = deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .max(Duration::from_millis(500));
        self.call(&primary, LEAVE, Vec::new(), left)
            .await
            .map(|_| ())
    }

    /// Sets what answers peers' federated reads (once).
    pub fn set_rpc_handler(&self, h: RpcHandler) {
        let _ = self.rpc_handler.set(HandlerSlot(h));
    }

    /// Peers with an open stream (their node IDs). A stream whose write side has ended is
    /// dropped here: the read side ends first, and it purges before the writer notices, so a
    /// peer that left would otherwise stay listed (and show up as a node that didn't answer).
    pub fn reachable_peers(&self) -> Vec<String> {
        let mut outbox = self.outbox.lock().unwrap_or_else(PoisonError::into_inner);
        outbox.retain(|_, tx| !tx.is_closed());
        outbox.keys().cloned().collect()
    }

    /// Calls `kind` on `peer` over its stream; fails fast when no stream is open, and after
    /// `timeout` when the peer doesn't answer (CLU-002: a dead node never hangs a read).
    pub async fn call(
        &self,
        peer: &str,
        kind: &str,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        let tx = self
            .outbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(peer)
            .cloned()
            .ok_or_else(|| format!("no stream to {peer}"))?;
        let id = self
            .next_rpc
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (done, answer) = tokio::sync::oneshot::channel();
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, done);
        let frame = Frame {
            body: Some(Body::RpcRequest(RpcRequest {
                id,
                kind: kind.to_owned(),
                body,
            })),
        };
        let result = async {
            tx.send(frame)
                .await
                .map_err(|_| format!("the stream to {peer} closed"))?;
            answer
                .await
                .map_err(|_| format!("the stream to {peer} closed"))?
        };
        let r = tokio::time::timeout(timeout, result).await;
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        r.unwrap_or_else(|_| Err(format!("{peer} didn't answer within {timeout:?}")))
    }

    /// Calls `kind` on every reachable peer at once: `(peer, answer)` per peer.
    pub async fn call_all(
        &self,
        kind: &str,
        body: &[u8],
        timeout: Duration,
    ) -> Vec<(String, Result<Vec<u8>, String>)> {
        let peers = self.reachable_peers();
        let calls = peers
            .iter()
            .map(|p| self.call(p, kind, body.to_vec(), timeout));
        let answers = futures_join_all(calls).await;
        peers.into_iter().zip(answers).collect()
    }

    /// Answers an RPC from a peer on its stream.
    fn on_rpc(self: &Arc<Self>, peer: &str, req: RpcRequest) {
        let Some(tx) = self
            .outbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(peer)
            .cloned()
        else {
            return;
        };
        let handler = self.rpc_handler.get().map(|h| Arc::clone(&h.0));
        let peer = peer.to_owned();
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let result = if req.kind == LEAVE {
                // The peer's ID comes from its certificate: a member can only remove itself.
                me.remove_ephemeral(&peer).map(|()| Vec::new())
            } else {
                match handler {
                    Some(h) => h(peer, req.kind, req.body).await,
                    None => Err("this node doesn't answer federated reads".into()),
                }
            };
            let (body, error) = match result {
                Ok(b) if b.len() <= MAX_RPC => (b, String::new()),
                Ok(b) => (Vec::new(), format!("answer too large ({} bytes)", b.len())),
                Err(e) => (Vec::new(), e),
            };
            let _ = tx
                .send(Frame {
                    body: Some(Body::RpcResponse(RpcResponse {
                        id: req.id,
                        error,
                        body,
                    })),
                })
                .await;
        });
    }

    /// The primary's node ID while a stream to it is open.
    pub fn reachable_primary(&self) -> Option<String> {
        let reachable = self.reachable_peers();
        self.members()
            .into_iter()
            .find(|m| m.primary && reachable.contains(&m.node_id))
            .map(|m| m.node_id)
    }

    /// This node's role and epoch.
    pub fn role(&self) -> (Role, u64) {
        *self.role.borrow()
    }

    /// Role changes (promotion, fencing).
    pub fn role_watch(&self) -> watch::Receiver<(Role, u64)> {
        self.role.subscribe()
    }

    pub fn is_primary(&self) -> bool {
        matches!(self.role().0, Role::Primary | Role::Emergency)
    }

    /// Where to reach the primary or other eligible nodes, best first (ADR-051): the advertise
    /// URLs of the peer that's primary in the highest epoch, then the URLs from joining, then
    /// every eligible node in the registry. This node's own URLs are left out.
    pub fn candidate_urls(&self) -> Vec<String> {
        let own = &self.identity.meta.advertise;
        let mut out: Vec<String> = Vec::new();
        let mut push = |u: &String| {
            if !own.contains(u) && !out.contains(u) {
                out.push(u.clone());
            }
        };
        let mut members = self.members();
        members.sort_by_key(|m| std::cmp::Reverse((m.primary, m.epoch)));
        for m in members.iter().filter(|m| m.primary) {
            m.advertise.iter().for_each(&mut push);
        }
        if !self.is_primary() {
            self.identity.meta.primary_urls.iter().for_each(&mut push);
        }
        for n in self.identity.registry() {
            if n.eligible && n.node_id != self.identity.meta.node_id {
                n.advertise.iter().for_each(&mut push);
            }
        }
        out
    }

    /// The URL to fetch blobs from: the current primary's, else the connected stream's.
    ///
    /// The URL this node's stream to the primary uses comes first: it's the one known to work
    /// from here. The primary's first advertised URL can be one only some nodes reach (an
    /// in-cluster Service name, unknown to a node outside Kubernetes), so it's the fallback.
    fn primary_url(&self) -> Option<String> {
        self.connected_primary().or_else(|| {
            let mut members = self.members();
            members.sort_by_key(|m| std::cmp::Reverse(m.epoch));
            members
                .iter()
                .find(|m| m.primary && m.connected)
                .and_then(|m| m.advertise.first().cloned())
        })
    }

    /// Changes the role (persisted in `cluster.json`) and tells every stream and task.
    pub fn set_role(&self, role: Role, epoch: u64) -> Result<(), String> {
        let _fence = self.fence.lock().unwrap_or_else(PoisonError::into_inner);
        let mut id = self.identity.reload();
        id.save_role(role, epoch)?;
        self.role.send_replace((role, epoch));
        self.set_local(|l| l.epoch = l.epoch.max(epoch));
        Ok(())
    }

    /// How this node's own configuration is managed (`gitops` or `file`), for Hello.
    pub fn set_config_source(&self, s: &str) {
        s.clone_into(
            &mut self
                .config_source
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    pub fn config_source(&self) -> String {
        self.config_source
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether `node` may announce an epoch (ADR-051): a voter, that is an eligible node or a
    /// witness, in the registry. A member the registry doesn't know is taken at its word (a
    /// cluster from before registries existed); a known member that can't vote is not.
    pub fn may_announce_epoch(&self, node: &str) -> bool {
        self.identity
            .registry()
            .iter()
            .find(|n| n.node_id == node)
            .is_none_or(crate::node::NodeRecord::voter)
    }

    /// Fencing (ADR-051): a primary that hears of a higher epoch steps down at once.
    fn observe_epoch(&self, epoch: u64, from: &str) {
        let (role, mine) = self.role();
        if epoch > mine && !self.may_announce_epoch(from) {
            // Hellos and heartbeats aren't signed: a member that can't vote (a resolver pod)
            // could otherwise fence the primary and freeze the cluster with one frame.
            debug!(
                epoch,
                from, "ignoring a newer epoch from a member that can't vote"
            );
            return;
        }
        if epoch > mine {
            if role == Role::Primary {
                warn!(epoch, mine, from, "a newer primary exists: stepping down");
                self.event(
                    "fenced",
                    &self.identity.meta.node_id,
                    format!("epoch {epoch} from {from} is newer than ours ({mine}); now a replica"),
                );
            }
            if let Err(e) = self.set_role(Role::Replica, epoch) {
                warn!("cluster: can't record the newer epoch: {e}");
            }
        }
    }

    /// Records an event (newest last; the oldest are dropped past [`MAX_EVENTS`]).
    pub fn event(&self, kind: &'static str, node: &str, detail: impl Into<String>) {
        let mut ev = self.events.lock().unwrap_or_else(PoisonError::into_inner);
        if ev.len() == MAX_EVENTS {
            ev.pop_front();
        }
        ev.push_back(Event {
            ts_ms: now_ms(),
            kind,
            node: node.to_owned(),
            detail: detail.into(),
        });
    }

    /// Recent events, oldest first.
    pub fn events(&self) -> Vec<Event> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    /// The newest configuration version any node reports (this one included).
    ///
    /// REQ: CLU-013 — counting stable versions only: a canary version baking isn't "newest" for
    /// the nodes that wait for it.
    pub fn newest_seq(&self) -> u64 {
        let own = self.own_stable_seq();
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .map(Member::stable_seq)
            .fold(own, u64::max)
    }

    /// REQ: CLU-013 — the stable version this node is at.
    pub fn own_stable_seq(&self) -> u64 {
        let l = self.local.lock().unwrap_or_else(PoisonError::into_inner);
        stable_seq(l.applied_seq, l.canary_of)
    }

    /// Since when this node's applied version has been behind the newest known (Unix ms).
    pub fn behind_since(&self) -> Option<u64> {
        let newest = self.newest_seq();
        let own = self.own_stable_seq();
        let mut b = self
            .behind_since
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if own >= newest {
            *b = None;
        } else if b.is_none() {
            *b = Some(now_ms());
        }
        *b
    }

    /// This node's own reported state.
    pub fn local_state(&self) -> LocalState {
        self.local
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Replication state.
    pub fn sync_status(&self) -> SyncStatus {
        self.sync
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Records replication state (the primary records what it published).
    pub fn set_sync_status(&self, f: impl FnOnce(&mut SyncStatus)) {
        f(&mut self.sync.lock().unwrap_or_else(PoisonError::into_inner));
    }

    /// Publishes a manifest and the blobs it names (primary): every connected peer gets it at
    /// once, and peers that connect later get it first thing. It's the stable head: a canary
    /// head ends.
    pub fn publish(&self, signed: Signed, blobs: HashMap<String, BlobSource>) {
        *self.served.lock().unwrap_or_else(PoisonError::into_inner) = blobs;
        self.canary.send_replace(None);
        self.published.send_replace(Some(Arc::new(signed)));
    }

    /// REQ: CLU-013 (ADR-116) — publishes `signed` to `peers` only, as the canary head (if
    /// this node is still the primary of `epoch`); every other peer keeps the stable head. The
    /// blobs are served beside the stable head's. Returns whether it was published.
    pub fn publish_canary_as(
        &self,
        epoch: u64,
        signed: Signed,
        peers: std::collections::BTreeSet<String>,
        blobs: HashMap<String, BlobSource>,
    ) -> bool {
        let _fence = self.fence.lock().unwrap_or_else(PoisonError::into_inner);
        let (role, current) = self.role();
        if !matches!(role, Role::Primary | Role::Emergency) || current != epoch {
            return false;
        }
        self.served
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(blobs);
        self.canary.send_replace(Some(Canary {
            signed: Arc::new(signed),
            peers: Arc::new(peers),
        }));
        true
    }

    /// REQ: CLU-013 — the canary head, if a version is baking.
    pub fn canary(&self) -> Option<Canary> {
        self.canary.borrow().clone()
    }

    /// REQ: CLU-013 — the head `peer` is sent: the canary one when it's among the canary's
    /// peers, else the stable one. Every path that sends a manifest goes through here.
    pub fn head_for(&self, peer: Option<&str>) -> Option<Arc<Signed>> {
        if let (Some(p), Some(c)) = (peer, self.canary.borrow().as_ref())
            && c.peers.contains(p)
        {
            return Some(Arc::clone(&c.signed));
        }
        self.published.borrow().clone()
    }

    /// REQ: CLU-005 (ADR-051) — publishes `signed` only if this node is still the primary (or
    /// emergency primary) in `epoch`, checked under the same lock as role changes: a step-down
    /// either happens first (nothing is published) or after (a version of the old epoch, which
    /// the new primary's newer epoch outranks). Returns whether it was published.
    pub fn publish_as(
        &self,
        epoch: u64,
        signed: Signed,
        blobs: HashMap<String, BlobSource>,
    ) -> bool {
        let _fence = self.fence.lock().unwrap_or_else(PoisonError::into_inner);
        let (role, current) = self.role();
        if !matches!(role, Role::Primary | Role::Emergency) || current != epoch {
            return false;
        }
        self.publish(signed, blobs);
        true
    }

    /// The manifest this node publishes, if any.
    pub fn published(&self) -> Option<Arc<Signed>> {
        self.published.borrow().clone()
    }

    /// Manifests received from peers (latest wins).
    pub fn incoming(&self) -> watch::Receiver<Option<Arc<Signed>>> {
        self.incoming.subscribe()
    }

    /// The primary URL this node's stream is connected to.
    pub fn connected_primary(&self) -> Option<String> {
        self.connected
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Fetches the blobs in `refs` that `store` lacks from the connected primary; returns how
    /// many were fetched. Each is checked against its hash before it's stored.
    pub async fn fetch(&self, refs: &[BlobRef], store: &BlobStore) -> Result<usize, String> {
        let mut missing: Vec<BlobRef> = refs.iter().filter(|b| !store.has(b)).cloned().collect();
        missing.sort_by(|a, b| a.hash.cmp(&b.hash));
        missing.dedup_by(|a, b| a.hash == b.hash);
        if missing.is_empty() {
            return Ok(0);
        }
        let url = self.primary_url().ok_or("not connected to the primary")?;
        // The current certificate and trusted CAs: they change with renewals and CA rotations.
        let tls = tls_connect(&url, client_config(&self.identity.reload())?).await?;
        let (send, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .map_err(|e| e.to_string())?;
        let conn = tokio::spawn(conn);
        let n = missing.len();
        let mut set = tokio::task::JoinSet::new();
        let mut queue = missing.into_iter();
        let mut result = Ok(n);
        loop {
            while set.len() < FETCH_PARALLEL {
                let Some(b) = queue.next() else { break };
                let (mut send, store) = (send.clone(), store.clone());
                set.spawn(async move {
                    let r = send
                        .send_request(
                            Request::get(format!(
                                "https://{CLUSTER_NAME}/cluster/v1/blob/{}",
                                b.hash
                            ))
                            .body(Full::new(Bytes::new()))
                            .map_err(|e| e.to_string())?,
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                    if !r.status().is_success() {
                        return Err(format!("blob {}: {}", b.name, r.status()));
                    }
                    let bytes = Limited::new(r.into_body(), MAX_BLOB)
                        .collect()
                        .await
                        .map_err(|e| format!("blob {}: {e}", b.name))?
                        .to_bytes();
                    tokio::task::spawn_blocking(move || store.put(&b, &bytes))
                        .await
                        .map_err(|e| e.to_string())?
                });
            }
            match set.join_next().await {
                None => break,
                Some(Ok(Ok(()))) => {}
                Some(Ok(Err(e))) => result = Err(e),
                Some(Err(e)) => result = Err(e.to_string()),
            }
        }
        conn.abort();
        result
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

    /// A peer's recent host samples, oldest first (T6.11).
    pub fn host_history(&self, node_id: &str) -> Vec<crate::wire::HostStats> {
        self.host_history
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(node_id)
            .map(|h| h.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Updates what this node reports (qps from telemetry, applied version from replication).
    pub fn set_local(&self, f: impl FnOnce(&mut LocalState)) {
        let mut l = self.local.lock().unwrap_or_else(PoisonError::into_inner);
        let before = (l.epoch, l.applied_seq);
        f(&mut l);
        if (l.epoch, l.applied_seq) != before {
            self.local_changed.send_modify(|n| *n += 1);
        }
    }

    /// Appends a peer's host sample to its history, once per sample (heartbeats repeat it).
    fn record_host(&self, node_id: &str, h: &crate::wire::HostStats) {
        let mut all = self
            .host_history
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let q = all.entry(node_id.to_owned()).or_default();
        if q.back().is_some_and(|last| last.ts_ms == h.ts_ms) {
            return;
        }
        if q.len() == HOST_HISTORY {
            q.pop_front();
        }
        q.push_back(h.clone());
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
                source_commit: l.source_commit.clone(),
                protocol: PROTOCOL,
                cluster_id: m.cluster_id.clone(),
                node_id: m.node_id.clone(),
                version: self.version.clone(),
                site: m.site.clone(),
                eligible: m.eligible,
                advertise: m.advertise.clone(),
                epoch: l.epoch.max(self.role().1),
                applied_seq: l.applied_seq,
                primary: self.is_primary(),
                config_source: self.config_source(),
            })),
        }
    }

    fn heartbeat(&self, echo: &EchoSlot) -> Frame {
        let l = self
            .local
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let (echo_ms, echo_delay_ms) =
            echo.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .map_or((0, 0), |(ts, at)| {
                    (
                        ts,
                        u32::try_from(at.elapsed().as_millis()).unwrap_or(u32::MAX),
                    )
                });
        // T5.4c — what this node trusts, and who issued its certificate.
        let id = self.identity.reload();
        let trust_fp = crate::pki::trust_fp(&id.ca_pem);
        let issuer_fp = crate::pki::issuer_fp(&id.cert_pem, &id.ca_pem).unwrap_or_default();
        Frame {
            body: Some(Body::Heartbeat(Heartbeat {
                source_commit: l.source_commit.clone(),
                trust_fp,
                issuer_fp,
                ts_ms: now_ms(),
                epoch: l.epoch.max(self.role().1),
                applied_seq: l.applied_seq,
                qps: l.qps,
                echo_ms,
                echo_delay_ms,
                ready: l.ready,
                servfail_permille: l.servfail_permille,
                p90_us: l.p90_us,
                uptime_s: l.uptime_s,
                host: l.host.clone().map(Box::new),
                kube_node: l.kube_node.clone(),
                pod: l.pod.clone(),
                started_ms: l.started_ms,
                cache_entries: l.cache_entries,
                cache_hit_permille: l.cache_hit_permille,
                maintenance_until_ms: l.maintenance.as_ref().map_or(0, |w| w.until_ms),
                maintenance_since_ms: l.maintenance.as_ref().map_or(0, |w| w.since_ms),
                maintenance_reason: l
                    .maintenance
                    .as_ref()
                    .map(|w| w.reason.clone())
                    .unwrap_or_default(),
                maintenance_by: l
                    .maintenance
                    .as_ref()
                    .map(|w| w.by.clone())
                    .unwrap_or_default(),
                rollouts: true,
                sync_error: self
                    .sync
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .error
                    .clone()
                    .unwrap_or_default(),
                probe_failing: l.probe_failing,
                canary_of: l.canary_of,
            })),
        }
    }

    #[allow(clippy::too_many_lines)] // one match over the frame types
    /// Applies a frame from `peer` (whose ID the TLS certificate proved, when known).
    fn on_frame(
        self: &Arc<Self>,
        peer: &mut Option<String>,
        f: Frame,
        via: &'static str,
        echo: &EchoSlot,
    ) -> Result<(), String> {
        let mut members = self.members.lock().unwrap_or_else(PoisonError::into_inner);
        match f.body {
            Some(Body::Hello(h)) => {
                // REQ: CLU-010 — N and N-1 interoperate.
                if !crate::wire::protocol_compatible(h.protocol) {
                    return Err(format!(
                        "peer speaks protocol {}, we speak {PROTOCOL}: more than one version apart (upgrade it)",
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
                let detail = format!("{} at site {}, version {}", via, h.site, h.version);
                let prev = members.get(&h.node_id).cloned();
                members.insert(
                    h.node_id.clone(),
                    Member {
                        node_id: h.node_id.clone(),
                        site: h.site,
                        version: h.version,
                        advertise: h.advertise,
                        eligible: h.eligible,
                        primary: h.primary,
                        last_seen_ms: now_ms(),
                        epoch: h.epoch,
                        applied_seq: h.applied_seq,
                        qps: prev.as_ref().map_or(0, |p| p.qps),
                        via,
                        connected: true,
                        connected_ms: now_ms(),
                        rtt_ms: prev.as_ref().and_then(|p| p.rtt_ms),
                        ready: prev.as_ref().is_some_and(|p| p.ready),
                        servfail_permille: prev.as_ref().map_or(0, |p| p.servfail_permille),
                        p90_us: prev.as_ref().map_or(0, |p| p.p90_us),
                        uptime_s: prev.as_ref().map_or(0, |p| p.uptime_s),
                        behind_since_ms: prev.as_ref().and_then(|p| p.behind_since_ms),
                        config_source: h.config_source,
                        protocol: h.protocol,
                        source_commit: h.source_commit,
                        trust_fp: prev
                            .as_ref()
                            .map(|p| p.trust_fp.clone())
                            .unwrap_or_default(),
                        issuer_fp: prev
                            .as_ref()
                            .map(|p| p.issuer_fp.clone())
                            .unwrap_or_default(),
                        host: prev.as_ref().and_then(|p| p.host.clone()),
                        clock_offset_ms: prev.as_ref().and_then(|p| p.clock_offset_ms),
                        kube_node: prev
                            .as_ref()
                            .map(|p| p.kube_node.clone())
                            .unwrap_or_default(),
                        pod: prev.as_ref().map(|p| p.pod.clone()).unwrap_or_default(),
                        started_ms: prev.as_ref().map_or(0, |p| p.started_ms),
                        restarts: prev.as_ref().map_or(0, |p| p.restarts),
                        cache_entries: prev.as_ref().and_then(|p| p.cache_entries),
                        cache_hit_permille: prev.as_ref().and_then(|p| p.cache_hit_permille),
                        maintenance: prev.as_ref().and_then(|p| p.maintenance.clone()),
                        rollouts: prev.as_ref().is_some_and(|p| p.rollouts),
                        sync_error: prev
                            .as_ref()
                            .map(|p| p.sync_error.clone())
                            .unwrap_or_default(),
                        probe_failing: prev.as_ref().is_some_and(|p| p.probe_failing),
                        canary_of: prev.as_ref().map_or(0, |p| p.canary_of),
                    },
                );
                drop(members);
                self.event("connected", &h.node_id, detail);
                self.observe_epoch(h.epoch, &h.node_id);
                // ADR-051 — the primary keeps the registry current: nodes that joined before it
                // existed, or whose URLs changed, are recorded from their (authenticated) Hello.
                if self.is_primary() {
                    self.record_member(&h.node_id);
                }
                return Ok(());
            }
            Some(Body::Heartbeat(mut hb)) => {
                let id = peer.as_ref().ok_or("heartbeat before Hello")?;
                *echo.lock().unwrap_or_else(PoisonError::into_inner) =
                    Some((hb.ts_ms, tokio::time::Instant::now()));
                let now = now_ms();
                let own = {
                    let l = self.local.lock().unwrap_or_else(PoisonError::into_inner);
                    stable_seq(l.applied_seq, l.canary_of)
                };
                let newest = members
                    .values()
                    .map(Member::stable_seq)
                    .fold(own, u64::max)
                    .max(stable_seq(hb.applied_seq, hb.canary_of));
                let mut restarted = false;
                let mut maintenance_changed = None;
                if let Some(m) = members.get_mut(id) {
                    // REQ: OPS-010 — its maintenance window (an older node sends none).
                    let window = (hb.maintenance_until_ms > 0).then(|| MaintenanceWindow {
                        until_ms: hb.maintenance_until_ms,
                        since_ms: hb.maintenance_since_ms,
                        reason: std::mem::take(&mut hb.maintenance_reason),
                        by: std::mem::take(&mut hb.maintenance_by),
                    });
                    if window.as_ref().map(|w| w.until_ms)
                        != m.maintenance.as_ref().map(|w| w.until_ms)
                        && (window.is_some() || m.in_maintenance(now).is_some())
                    {
                        maintenance_changed = Some(window.as_ref().map_or_else(
                            || "back in service".to_owned(),
                            |w| {
                                format!(
                                    "for {} min ({}), by {}",
                                    w.until_ms.saturating_sub(w.since_ms).div_ceil(60_000),
                                    w.reason,
                                    w.by
                                )
                            },
                        ));
                    }
                    m.maintenance = window;
                    m.rollouts = hb.rollouts;
                    m.sync_error = std::mem::take(&mut hb.sync_error);
                    m.probe_failing = hb.probe_failing;
                    m.canary_of = hb.canary_of;
                    m.last_seen_ms = now;
                    if !hb.trust_fp.is_empty() {
                        m.trust_fp.clone_from(&hb.trust_fp);
                        m.issuer_fp.clone_from(&hb.issuer_fp);
                    }
                    m.epoch = hb.epoch;
                    m.applied_seq = hb.applied_seq;
                    m.qps = hb.qps;
                    m.ready = hb.ready;
                    m.servfail_permille = hb.servfail_permille;
                    m.p90_us = hb.p90_us;
                    m.uptime_s = hb.uptime_s;
                    m.source_commit = hb.source_commit;
                    // T6.14 — a new start time on a node we already knew: it restarted.
                    if m.started_ms != 0 && hb.started_ms != 0 && hb.started_ms != m.started_ms {
                        m.restarts = m.restarts.saturating_add(1);
                        restarted = true;
                    }
                    if hb.started_ms != 0 {
                        m.started_ms = hb.started_ms;
                    }
                    m.kube_node = hb.kube_node;
                    m.pod = hb.pod;
                    m.cache_entries = hb.cache_entries;
                    m.cache_hit_permille = hb.cache_hit_permille;
                    if hb.echo_ms > 0 {
                        let rtt = now
                            .saturating_sub(hb.echo_ms)
                            .saturating_sub(u64::from(hb.echo_delay_ms));
                        m.rtt_ms = Some(u32::try_from(rtt).unwrap_or(u32::MAX));
                        // T6.11 — its clock was at ts_ms about half a round trip ago.
                        let theirs = i128::from(hb.ts_ms) + i128::from(rtt / 2);
                        m.clock_offset_ms = i64::try_from(theirs - i128::from(now)).ok();
                    }
                    if let Some(h) = hb.host {
                        self.record_host(id, &h);
                        m.host = Some(*h);
                    }
                    if m.stable_seq() >= newest {
                        m.behind_since_ms = None;
                    } else if m.behind_since_ms.is_none() {
                        m.behind_since_ms = Some(now);
                    }
                }
                let id = id.clone();
                drop(members);
                if restarted {
                    self.event("restarted", &id, "its process started again");
                }
                if let Some(detail) = maintenance_changed {
                    let kind = if detail == "back in service" {
                        "maintenance_ended"
                    } else {
                        "maintenance"
                    };
                    self.event(kind, &id, detail);
                }
                self.observe_epoch(hb.epoch, &id);
                return Ok(());
            }
            Some(Body::RpcRequest(r)) => {
                let id = peer.as_ref().ok_or("request before Hello")?.clone();
                drop(members);
                self.on_rpc(&id, r);
                return Ok(());
            }
            Some(Body::RpcResponse(r)) => {
                drop(members);
                if let Some(done) = self
                    .pending
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&r.id)
                {
                    let _ = done.send(if r.error.is_empty() {
                        Ok(r.body)
                    } else {
                        Err(r.error)
                    });
                }
                return Ok(());
            }
            Some(Body::KeyShare(k)) => {
                let id = peer.as_ref().ok_or("key before Hello")?;
                let from_primary = members
                    .get(id)
                    .is_some_and(|m| m.primary && m.epoch >= self.role().1);
                drop(members);
                if !from_primary {
                    // Refused, but the stream stays up: an old primary that comes back sends
                    // its key before it learns the newer epoch. Ending the read side here left
                    // its writer on a stream nobody read, and its RPC answers were lost
                    // (found by the T13.4 failover e2e).
                    warn!(from = %id, "cluster: ignoring a cluster key from a node that isn't the primary");
                    return Ok(());
                }
                if !k.next_ca_key_pem.is_empty()
                    && let Err(e) = self.identity.store_ca_key(&k.next_ca_key_pem)
                {
                    warn!("cluster: the next CA key was refused: {e}");
                }
                match self.identity.store_ca_key(&k.ca_key_pem) {
                    Ok(true) => {
                        info!(from = %id, "received the cluster signing key (this node can now be promoted)");
                        self.event(
                            "key_received",
                            &self.identity.meta.node_id,
                            format!("from {id}"),
                        );
                    }
                    Ok(false) => {}
                    Err(e) => return Err(format!("cluster key refused: {e}")),
                }
                return Ok(());
            }
            Some(Body::Manifest(m)) => {
                peer.as_ref().ok_or("manifest before Hello")?;
                self.incoming.send_replace(Some(Arc::new(Signed {
                    json: m.json,
                    sig: m.sig,
                })));
            }
            None => {}
        }
        Ok(())
    }
}

/// Reads frames from `body` into `cluster` until it ends.
async fn read_frames(
    cluster: &Arc<Cluster>,
    body: Incoming,
    mut peer: Option<String>,
    via: &'static str,
    echo: &EchoSlot,
) -> Result<(), String> {
    let result = read_loop(cluster, body, &mut peer, via, echo).await;
    // Streams that ended can't carry RPCs any more.
    cluster
        .outbox
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .retain(|_, tx| !tx.is_closed());
    if let Some(id) = &peer {
        let mut members = cluster
            .members
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(m) = members.get_mut(id) {
            m.connected = false;
        }
        drop(members);
        let why = result
            .as_ref()
            .err()
            .map_or("stream closed".to_owned(), Clone::clone);
        cluster.event("disconnected", id, why);
    }
    result
}

async fn read_loop(
    cluster: &Arc<Cluster>,
    mut body: Incoming,
    peer: &mut Option<String>,
    via: &'static str,
    echo: &EchoSlot,
) -> Result<(), String> {
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| e.to_string())?;
        if let Ok(data) = frame.into_data() {
            buf.extend_from_slice(&data);
            for f in wire::decode_all(&mut buf)? {
                cluster.on_frame(peer, f, via, echo)?;
            }
        }
    }
    Ok(())
}

/// Sends our Hello, then heartbeats, until the receiver goes away.
async fn write_frames(
    cluster: Arc<Cluster>,
    mut tx: http_body_util::channel::Sender<Bytes>,
    echo: EchoSlot,
    peer: Option<String>,
) {
    if tx
        .send_data(Bytes::from(wire::encode(&cluster.hello())))
        .await
        .is_err()
    {
        return;
    }
    let mut manifests = cluster.published.subscribe();
    // REQ: CLU-013 — the canary head reaches only its peers (`head_for`).
    let mut canaries = cluster.canary.subscribe();
    let mut changed = cluster.local_changed.subscribe();
    // RPC frames for this peer go out on this stream (CLU-002).
    let (out_tx, mut outbox) = tokio::sync::mpsc::channel::<Frame>(64);
    if let Some(p) = &peer {
        cluster
            .outbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(p.clone(), out_tx);
    }
    let mut tick = tokio::time::interval(HEARTBEAT);
    tick.tick().await;
    // A heartbeat right away, so the peer can echo it and both sides know the round-trip
    // time within one exchange.
    if tx
        .send_data(Bytes::from(wire::encode(&cluster.heartbeat(&echo))))
        .await
        .is_err()
    {
        return;
    }
    // ADR-051 — the primary shares the signing key with eligible peers (by certified ID),
    // as soon as the registry lists them (checked again on every heartbeat), and again whenever
    // the share changes (a CA rotation adds the next key, T5.4c).
    let mut key_shared: Option<Vec<u8>> = None;
    // The current manifest first (a peer that just connected), then whatever happens next:
    // the head for this peer, sent again only when it changes.
    manifests.borrow_and_update();
    canaries.borrow_and_update();
    let mut pending = cluster.head_for(peer.as_deref());
    let mut sent: Option<Arc<Signed>> = None;
    loop {
        if let Some(frame) = peer.as_deref().and_then(|p| cluster.key_share_for(p)) {
            let bytes = wire::encode(&frame);
            if key_shared.as_deref() != Some(bytes.as_slice()) {
                if tx.send_data(Bytes::from(bytes.clone())).await.is_err() {
                    return;
                }
                key_shared = Some(bytes);
            }
        }
        let frame = if let Some(m) = pending.take() {
            if sent.as_ref().is_some_and(|s| Arc::ptr_eq(s, &m)) {
                continue;
            }
            let f = manifest_frame(&m);
            sent = Some(m);
            f
        } else {
            tokio::select! {
                _ = tick.tick() => cluster.heartbeat(&echo),
                r = changed.changed() => {
                    if r.is_err() { return; }
                    cluster.heartbeat(&echo)
                }
                r = manifests.changed() => {
                    if r.is_err() { return; }
                    manifests.borrow_and_update();
                    pending = cluster.head_for(peer.as_deref());
                    continue;
                }
                r = canaries.changed() => {
                    if r.is_err() { return; }
                    canaries.borrow_and_update();
                    pending = cluster.head_for(peer.as_deref());
                    continue;
                }
                Some(f) = outbox.recv() => f,
            }
        };
        if tx
            .send_data(Bytes::from(wire::encode(&frame)))
            .await
            .is_err()
        {
            return;
        }
    }
}

fn manifest_frame(m: &Signed) -> Frame {
    Frame {
        body: Some(Body::Manifest(ManifestMsg {
            json: m.json.clone(),
            sig: m.sig.clone(),
        })),
    }
}

type HttpBody = http_body_util::Either<Full<Bytes>, Channel<Bytes>>;

fn reply(status: StatusCode, text: String) -> Response<HttpBody> {
    let mut r = Response::new(http_body_util::Either::Left(Full::new(Bytes::from(text))));
    *r.status_mut() = status;
    r
}

/// `POST /cluster/v1/ca` (CLU-009): the CA, with proof this node knows the bootstrap secret.
async fn serve_ca(cluster: &Cluster, req: Request<Incoming>) -> Response<HttpBody> {
    let (Some(secret), true) = (cluster.bootstrap_secret(), cluster.identity.holds_ca()) else {
        return reply(StatusCode::NOT_FOUND, "no bootstrap secret here".into());
    };
    let Ok(body) = Limited::new(req.into_body(), 1024).collect().await else {
        return reply(StatusCode::PAYLOAD_TOO_LARGE, "request too large".into());
    };
    let nonce = String::from_utf8_lossy(&body.to_bytes()).into_owned();
    let ca_pem = cluster.identity.reload().ca_pem;
    let Ok(fp) = crate::pki::fingerprint(&ca_pem) else {
        return reply(StatusCode::INTERNAL_SERVER_ERROR, "CA unreadable".into());
    };
    let r = BootstrapCa {
        cluster_id: cluster.identity.meta.cluster_id.clone(),
        cluster_name: cluster.identity.meta.cluster_name.clone(),
        proof: bootstrap_proof(&secret, &nonce, &crate::pki::hex(&fp)),
        ca_pem,
    };
    reply(
        StatusCode::OK,
        serde_json::to_string(&r).unwrap_or_default(),
    )
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
            match cluster
                .identity
                .accept_join(&jr, cluster.bootstrap_secret().as_deref())
            {
                Ok(resp) => {
                    info!(node = %resp.node_id, site = %jr.site, "a node joined the cluster");
                    cluster.event(
                        "joined",
                        &resp.node_id,
                        format!("site {}, version {}", jr.site, jr.version),
                    );
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
        // REQ: CLU-009 — a node joining with the bootstrap secret asks for the CA first, and
        // trusts it only if this node proves it knows the secret too.
        (&Method::POST, "/cluster/v1/ca") => serve_ca(&cluster, req).await,
        (&Method::POST, "/cluster/v1/stream") => {
            let Some(id) = peer else {
                return reply(
                    StatusCode::UNAUTHORIZED,
                    "a cluster certificate is required".into(),
                );
            };
            let (tx, body) = Channel::<Bytes>::new(16);
            let c = Arc::clone(&cluster);
            let echo = EchoSlot::default();
            tokio::spawn(write_frames(
                Arc::clone(&cluster),
                tx,
                Arc::clone(&echo),
                Some(id.clone()),
            ));
            tokio::spawn(async move {
                if let Err(e) =
                    read_frames(&c, req.into_body(), Some(id.clone()), "inbound", &echo).await
                {
                    debug!(peer = %id, "cluster stream ended: {e}");
                }
            });
            Response::new(http_body_util::Either::Right(body))
        }
        (&Method::GET, path) if path.starts_with("/cluster/v1/blob/") => {
            if peer.is_none() {
                return reply(
                    StatusCode::UNAUTHORIZED,
                    "a cluster certificate is required".into(),
                );
            }
            let hash = &path["/cluster/v1/blob/".len()..];
            let source = cluster
                .served
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(hash)
                .cloned();
            let bytes = match source {
                None => return reply(StatusCode::NOT_FOUND, "no such blob".into()),
                Some(BlobSource::Bytes(b)) => b,
                Some(BlobSource::File(p)) => match tokio::fs::read(&p).await {
                    Ok(b) => Bytes::from(b),
                    Err(e) => return reply(StatusCode::GONE, format!("blob unavailable: {e}")),
                },
            };
            Response::new(http_body_util::Either::Left(Full::new(bytes)))
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
    let mut tls = tokio_rustls::TlsAcceptor::from(
        server_config(&cluster.identity).map_err(std::io::Error::other)?,
    );
    let mut generation = cluster.cert_generation();
    info!(%addr, "cluster port listening");
    loop {
        let (sock, remote) = tokio::select! {
            _ = stop.changed() => return Ok(()),
            r = listener.accept() => if let Ok(x) = r { x } else {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            },
        };
        // A renewed certificate is served from the next handshake on (T5.4c).
        if cluster.cert_generation() != generation {
            generation = cluster.cert_generation();
            match server_config(&cluster.identity.reload()) {
                Ok(c) => tls = tokio_rustls::TlsAcceptor::from(c),
                Err(e) => warn!("cluster: renewed certificate unusable, keeping the old one: {e}"),
            }
        }
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
            // The URL that worked is the first to dial afterwards (CLU-009: a node outside
            // Kubernetes joined through an address that reaches the controller).
            Ok(mut r) => {
                r.primary_urls.retain(|u| u != url);
                r.primary_urls.insert(0, url.clone());
                return Ok(r);
            }
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

/// In automatic failover, keeps a stream to every other voter (ADR-056): votes need one.
/// Of each pair, the node with the lower ID dials; the other side gets an inbound stream.
pub async fn mesh(cluster: Arc<Cluster>, mut stop: watch::Receiver<bool>) {
    let dialing: Arc<Mutex<std::collections::HashSet<String>>> = Arc::default();
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(Duration::from_secs(3)) => {}
        }
        let id = cluster.identity.reload();
        let Ok(cfg) = client_config(&id) else {
            continue;
        };
        if !crate::failover::active(&id) {
            continue;
        }
        let me = id.meta.node_id.clone();
        let reachable = cluster.reachable_peers();
        for n in id.registry() {
            if !n.voter() || n.node_id <= me || reachable.contains(&n.node_id) {
                continue;
            }
            if !dialing
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(n.node_id.clone())
            {
                continue;
            }
            let (c, cfg, dialing, stop) = (
                Arc::clone(&cluster),
                Arc::clone(&cfg),
                Arc::clone(&dialing),
                stop.clone(),
            );
            tokio::spawn(async move {
                let mut stop = stop;
                for url in &n.advertise {
                    tokio::select! {
                        _ = stop.changed() => break,
                        r = stream_once(Arc::clone(&c), url, Arc::clone(&cfg), false) => {
                            if let Err(e) = r {
                                debug!(%url, "voter stream: {e}");
                            }
                        }
                    }
                }
                dialing
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&n.node_id);
            });
        }
    }
}

/// Keeps a stream to the first reachable URL open, reconnecting with jittered backoff until
/// `stop` changes.
pub async fn dial(cluster: Arc<Cluster>, mut stop: watch::Receiver<bool>) {
    let mut cfg = match client_config(&cluster.identity.reload()) {
        Ok(c) => c,
        Err(e) => {
            warn!("cluster: can't build TLS settings: {e}");
            return;
        }
    };
    let mut generation = cluster.cert_generation();
    let mut backoff = Duration::from_secs(1);
    loop {
        // A renewed certificate is used from the next connection on (T5.4c).
        if cluster.cert_generation() != generation {
            generation = cluster.cert_generation();
            match client_config(&cluster.identity.reload()) {
                Ok(c) => cfg = c,
                Err(e) => warn!("cluster: renewed certificate unusable, keeping the old one: {e}"),
            }
        }
        // The candidates change: a promotion names a new primary, the registry grows.
        for url in cluster.candidate_urls() {
            let started = tokio::time::Instant::now();
            tokio::select! {
                _ = stop.changed() => return,
                r = stream_once(Arc::clone(&cluster), &url, Arc::clone(&cfg), true) => match r {
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
    main: bool,
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
    let echo = EchoSlot::default();
    let writer = tokio::spawn(write_frames(
        Arc::clone(&cluster),
        tx,
        Arc::clone(&echo),
        server_id.clone(),
    ));
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
    // Only the main link (to the primary) is what replication fetches from.
    if main {
        *cluster
            .connected
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(url.to_owned());
    }
    let result = read_frames(&cluster, r.into_body(), server_id, "outbound", &echo).await;
    writer.abort();
    cluster
        .connected
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take_if(|u| u == url);
    result
}

/// Runs futures concurrently and returns their outputs in order (no `futures` dependency).
async fn futures_join_all<F: std::future::Future>(
    fs: impl IntoIterator<Item = F>,
) -> Vec<F::Output> {
    let mut pinned: Vec<std::pin::Pin<Box<F>>> = fs.into_iter().map(Box::pin).collect();
    let mut out: Vec<Option<F::Output>> = pinned.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (i, f) in pinned.iter_mut().enumerate() {
            if out[i].is_none() {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(v) => out[i] = Some(v),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    out.into_iter().flatten().collect()
}

/// How long a failed fetch or apply waits before trying the same manifest again.
const SYNC_RETRY: Duration = Duration::from_secs(2);

/// REQ: CLU-001 (T5.4c) — adopts the CAs a verified manifest says to trust (step by step,
/// never dropping every CA this node trusts) and rebuilds TLS for new connections.
pub fn adopt_manifest_trust(cluster: &Cluster, m: &ClusterManifest) {
    if m.ca_bundle.is_empty() {
        return;
    }
    match cluster.identity.adopt_trust(&m.ca_bundle) {
        Ok(true) => {
            cluster.bump_cert_generation();
            let n = crate::pki::certs_of(&m.ca_bundle).len();
            info!(cas = n, "cluster: trusted CAs updated from the primary");
            cluster.event(
                "trust_updated",
                &cluster.identity.meta.node_id,
                format!("{n} CA(s) trusted"),
            );
        }
        Ok(false) => {}
        Err(e) => warn!("cluster: the primary's CA bundle was refused: {e}"),
    }
}

/// For nodes that don't apply configuration (witnesses): follows the primary's manifests only
/// for the CAs to trust, so a CA rotation reaches them too (T5.4c).
pub async fn follow_trust(cluster: Arc<Cluster>, mut stop: watch::Receiver<bool>) {
    let mut incoming = cluster.incoming();
    incoming.mark_changed();
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            r = incoming.changed() => if r.is_err() { return },
        }
        let Some(signed) = incoming.borrow_and_update().clone() else {
            continue;
        };
        match signed.verify(&cluster.identity.reload().ca_pem) {
            Ok(m) if m.cluster_id == cluster.identity.meta.cluster_id => {
                adopt_manifest_trust(&cluster, &m);
            }
            Ok(_) => {}
            Err(e) => warn!("ignoring a cluster manifest: {e}"),
        }
    }
}

/// Replica side of CLU-003: follows the manifests the primary sends, starting after
/// `(epoch, seq)` (what's already applied). For each newer manifest whose signature verifies,
/// fetches the missing blobs into `store` and calls `apply`; on success the new version is
/// reported in heartbeats. A newer manifest arriving mid-sync supersedes the one in progress.
pub async fn follow<F, Fut>(
    cluster: Arc<Cluster>,
    store: BlobStore,
    applied: (u64, u64),
    mut apply: F,
    mut stop: watch::Receiver<bool>,
) where
    F: FnMut(ClusterManifest) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let (mut epoch, mut seq) = applied;
    cluster.set_local(|l| l.applied_seq = seq);
    let mut incoming = cluster.incoming();
    // A manifest that arrived before this follower started counts too: without this, a
    // replica whose stream came up first waited for the primary's next change (CLU-003).
    incoming.mark_changed();
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            r = incoming.changed() => if r.is_err() { return },
        }
        loop {
            let Some(signed) = incoming.borrow_and_update().clone() else {
                break;
            };
            // T5.4c — the trusted CAs change during a rotation: read them fresh.
            let m = match signed.verify(&cluster.identity.reload().ca_pem) {
                Ok(m) if m.cluster_id == cluster.identity.meta.cluster_id => m,
                Ok(_) => {
                    warn!("ignoring a manifest from another cluster");
                    break;
                }
                Err(e) => {
                    warn!("ignoring a cluster manifest: {e}");
                    cluster.event("rejected", &cluster.identity.meta.node_id, e.clone());
                    cluster.set_sync_status(|s| s.error = Some(e));
                    break;
                }
            };
            adopt_manifest_trust(&cluster, &m);
            if !m.newer_than(epoch, seq) || m.epoch < cluster.role().1 {
                break;
            }
            let t = tokio::time::Instant::now();
            let refs: Vec<BlobRef> = m.blobs().into_iter().cloned().collect();
            let result = match cluster.fetch(&refs, &store).await {
                Ok(n) => apply(m.clone()).await.map(|()| n),
                Err(e) => Err(format!("fetching from the primary: {e}")),
            };
            match result {
                Ok(fetched) => {
                    (epoch, seq) = (m.epoch, m.seq);
                    // REQ: CLU-013 — a canary version says which stable one it would replace.
                    let canary_of = m.rollout.as_ref().map_or(0, |r| r.of.1);
                    cluster.set_local(|l| {
                        l.applied_seq = seq;
                        l.epoch = l.epoch.max(epoch);
                        l.canary_of = canary_of;
                    });
                    let duration_ms = u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX);
                    cluster.set_sync_status(|s| {
                        *s = SyncStatus {
                            epoch,
                            seq,
                            created_ms: m.created_ms,
                            applied_ms: now_ms(),
                            fetched,
                            duration_ms,
                            error: None,
                        };
                    });
                    info!(
                        seq,
                        epoch,
                        fetched,
                        ms = duration_ms,
                        "applied cluster configuration"
                    );
                    cluster.event(
                        "applied",
                        &cluster.identity.meta.node_id,
                        format!("version {seq}: {fetched} blob(s) fetched, {duration_ms} ms"),
                    );
                    store.retain(&m.blobs());
                }
                Err(e) => {
                    warn!(
                        seq = m.seq,
                        "cluster configuration not applied (will retry): {e}"
                    );
                    cluster.event(
                        "sync_failed",
                        &cluster.identity.meta.node_id,
                        format!("version {}: {e}", m.seq),
                    );
                    cluster.set_sync_status(|s| s.error = Some(e));
                    tokio::select! {
                        _ = stop.changed() => return,
                        () = tokio::time::sleep(SYNC_RETRY) => {}
                    }
                    // Retry the newest manifest (this one, unless a newer one arrived).
                    incoming.mark_changed();
                }
            }
            if !incoming.has_changed().unwrap_or(false) {
                break;
            }
        }
    }
}

#[cfg(test)]
#[path = "net_tests.rs"]
mod tests;
