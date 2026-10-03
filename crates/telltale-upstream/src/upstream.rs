//! One upstream server: how to talk to it, and how healthy it is.
//!
//! REQ: UPS-001 (UDP, TCP, DoT, DoH/h2), UPS-006 (health per upstream), UPS-008 (pooled,
//! pipelined connections), UPS-009 (bootstrap for hostnames), `spec/04` §7 (loop detection).

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use telltale_proto::{
    EdnsOut, FlagBit, HEADER_LEN, NameBuf, build_query, header, opt, rcode, read_name, summarize,
};
use tokio::net::{TcpStream, UdpSocket};

use crate::bootstrap::Bootstrap;
use crate::conn::{BoxIo, Connector, Pool};
use crate::doh::Doh;
use crate::endpoint::{Endpoint, Host, Protocol};
use crate::health::Health;
use crate::tls::{TlsOptions, client_config, server_name};

/// The question being forwarded, detached from the client's packet so it can move into
/// async tasks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: NameBuf,
    pub qtype: u16,
    pub qclass: u16,
    /// Ask upstream for DNSSEC records (client DO=1).
    pub dnssec_ok: bool,
    /// Client set CD (checking disabled).
    pub checking_disabled: bool,
}

impl Question {
    pub fn from_query(q: &telltale_proto::Query<'_>) -> Self {
        Self {
            name: q.qname,
            qtype: q.qtype,
            qclass: q.qclass,
            dnssec_ok: q.edns.is_some_and(|e| e.dnssec_ok),
            checking_disabled: q.header.flags.cd(),
        }
    }
}

/// Why an attempt failed.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("timed out")]
    Timeout,
    #[error("network error: {0}")]
    Io(#[from] io::Error),
    #[error("malformed or mismatched response")]
    BadResponse,
    #[error("could not resolve the upstream's hostname")]
    Unresolved,
}

/// Our advertised EDNS payload toward upstreams (DNS Flag Day 2020).
const UPSTREAM_EDNS_PAYLOAD: u16 = 1232;

static NODE_TAG: OnceLock<[u8; 8]> = OnceLock::new();

/// Sets this node's loop-detection tag (once, at startup). Outbound queries carry it in EDNS
/// option 65429; a client query arriving with our own tag means we are forwarding to ourselves.
pub fn set_node_tag(tag: u64) {
    let _ = NODE_TAG.set(tag.to_be_bytes());
}

/// True if `q` carries this node's loop tag (`spec/04` §7).
pub fn is_own_loop_tag(q: &telltale_proto::Query<'_>) -> bool {
    match (NODE_TAG.get(), q.edns.and_then(|e| e.loop_tag())) {
        (Some(ours), Some(theirs)) => ours.as_slice() == theirs,
        _ => false,
    }
}

/// Builds the outbound query: fresh ID, RD=1, our own OPT (client EDNS options such as ECS,
/// cookies, and MAC are never forwarded) with the loop tag, CD copied from the client.
pub fn encode_query(q: &Question, id: u16, out: &mut [u8]) -> Option<usize> {
    let edns = EdnsOut {
        udp_payload: UPSTREAM_EDNS_PAYLOAD,
        dnssec_ok: q.dnssec_ok,
        ede: None,
    };
    let mut len = build_query(out, id, &q.name, q.qtype, q.qclass, true, Some(edns)).ok()?;
    if q.checking_disabled {
        let f = header::flags(out).with(FlagBit::Cd, true);
        header::set_flags(out, f);
    }
    if let Some(tag) = NODE_TAG.get() {
        // The OPT record is last with RDLENGTH 0 in its final two bytes: append the option.
        const OPT_LEN: u16 = 4 + 8;
        let dst = out.get_mut(len..len + usize::from(OPT_LEN))?;
        dst[..2].copy_from_slice(&opt::TELLTALE_LOOP.to_be_bytes());
        dst[2..4].copy_from_slice(&8u16.to_be_bytes());
        dst[4..].copy_from_slice(tag);
        out[len - 2..len].copy_from_slice(&OPT_LEN.to_be_bytes());
        len += usize::from(OPT_LEN);
    }
    Some(len)
}

/// Accepts a response only if it answers exactly our query: same ID, QR=1, QUERY opcode,
/// one question equal to ours (case-insensitively). Defends against spoofed or stray packets.
pub fn matches_query(resp: &[u8], query: &[u8], id: u16) -> bool {
    let (Some(rh), Some(qh)) = (
        telltale_proto::Header::parse(resp),
        telltale_proto::Header::parse(query),
    ) else {
        return false;
    };
    if rh.id != id || !rh.flags.qr() || rh.flags.opcode() != 0 || rh.qdcount != 1 || qh.qdcount != 1
    {
        return false;
    }
    let mut a = NameBuf::default();
    let mut b = NameBuf::default();
    let (Ok(ra), Ok(qb)) = (
        read_name(resp, HEADER_LEN, &mut a),
        read_name(query, HEADER_LEN, &mut b),
    ) else {
        return false;
    };
    a == b && resp.get(ra..ra + 4).is_some() && resp.get(ra..ra + 4) == query.get(qb..qb + 4)
}

/// Per-upstream settings (from `[[upstream]]`).
#[derive(Clone, Debug)]
pub struct UpstreamOptions {
    pub timeout: Duration,
    pub weight: u32,
    pub pool_size: usize,
    pub idle_timeout: Duration,
    pub tls_server_name: Option<String>,
    pub tls_insecure_skip_verify: bool,
    pub headers: Vec<(String, String)>,
    /// Resolver for hostname URLs.
    pub bootstrap: Option<Arc<Bootstrap>>,
}

impl Default for UpstreamOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(400),
            weight: 1,
            pool_size: 4,
            idle_timeout: Duration::from_secs(30),
            tls_server_name: None,
            tls_insecure_skip_verify: false,
            headers: Vec::new(),
            bootstrap: None,
        }
    }
}

/// Where to connect: a fixed address, or a hostname resolved through bootstrap.
#[derive(Debug)]
struct Target {
    host: Host,
    port: u16,
    bootstrap: Option<Arc<Bootstrap>>,
}

impl Target {
    async fn addr(&self) -> Result<SocketAddr, ExchangeError> {
        match &self.host {
            Host::Ip(ip) => Ok(SocketAddr::new(*ip, self.port)),
            Host::Name(name) => {
                let bs = self.bootstrap.as_ref().ok_or(ExchangeError::Unresolved)?;
                let ips = bs.resolve(name).await?;
                ips.first()
                    .map(|ip| SocketAddr::new(*ip, self.port))
                    .ok_or(ExchangeError::Unresolved)
            }
        }
    }
}

enum Transport {
    /// UDP, with a TCP pool for truncated answers.
    Udp {
        tcp: Pool,
    },
    Tcp(Pool),
    Tls(Pool),
    Https(Doh),
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Udp { .. } => "Udp",
            Self::Tcp(_) => "Tcp",
            Self::Tls(_) => "Tls",
            Self::Https(_) => "Https",
        })
    }
}

/// A configured upstream.
#[derive(Debug)]
pub struct Upstream {
    /// Small stable ID for telemetry (index in config order, starting at 1).
    pub id: u16,
    pub name: String,
    pub endpoint: Endpoint,
    /// Per-attempt timeout ceiling.
    pub timeout: Duration,
    pub weight: u32,
    pub health: Health,
    target: Arc<Target>,
    transport: Transport,
}

fn tcp_connector(target: Arc<Target>) -> Connector {
    Arc::new(move || {
        let target = Arc::clone(&target);
        Box::pin(async move {
            let addr = target.addr().await.map_err(io::Error::other)?;
            let s = TcpStream::connect(addr).await?;
            s.set_nodelay(true)?;
            Ok(Box::new(s) as BoxIo)
        })
    })
}

fn tls_connector(
    target: Arc<Target>,
    cfg: Arc<rustls::ClientConfig>,
    name: ServerName<'static>,
) -> Connector {
    let tls = tokio_rustls::TlsConnector::from(cfg);
    Arc::new(move || {
        let (target, tls, name) = (Arc::clone(&target), tls.clone(), name.clone());
        Box::pin(async move {
            let addr = target.addr().await.map_err(io::Error::other)?;
            let s = TcpStream::connect(addr).await?;
            s.set_nodelay(true)?;
            Ok(Box::new(tls.connect(name, s).await?) as BoxIo)
        })
    })
}

impl Upstream {
    /// An upstream with default options apart from timeout and weight (tests, embedding).
    pub fn new(
        id: u16,
        name: impl Into<String>,
        endpoint: Endpoint,
        timeout: Duration,
        weight: u32,
    ) -> Result<Self, String> {
        let opts = UpstreamOptions {
            timeout,
            weight,
            ..UpstreamOptions::default()
        };
        Self::build(id, name, endpoint, &opts, &TlsOptions::default())
    }

    /// Builds any upstream. Fails on invalid TLS names, headers, or missing bootstrap.
    pub fn build(
        id: u16,
        name: impl Into<String>,
        endpoint: Endpoint,
        opts: &UpstreamOptions,
        tls: &TlsOptions,
    ) -> Result<Self, String> {
        let name = name.into();
        if matches!(endpoint.host, Host::Name(_)) && opts.bootstrap.is_none() {
            return Err(format!(
                "upstream `{name}`: hostname URL needs bootstrap servers"
            ));
        }
        let target = Arc::new(Target {
            host: endpoint.host.clone(),
            port: endpoint.port,
            bootstrap: opts.bootstrap.clone(),
        });
        // TLS name to verify: tls_server_name, else the URL host (DNS name or IP literal).
        let tls_name = match (&opts.tls_server_name, &endpoint.host) {
            (Some(n), _) => n.clone(),
            (None, Host::Name(h)) => h.clone(),
            (None, Host::Ip(ip)) => ip.to_string(),
        };
        let pool = |c: Connector| Pool::new(c, opts.pool_size, opts.idle_timeout);
        let transport = match endpoint.protocol {
            Protocol::Udp => Transport::Udp {
                tcp: pool(tcp_connector(Arc::clone(&target))),
            },
            Protocol::Tcp => Transport::Tcp(pool(tcp_connector(Arc::clone(&target)))),
            Protocol::Tls => {
                let cfg = client_config(tls, &[], opts.tls_insecure_skip_verify)
                    .map_err(|e| e.to_string())?;
                Transport::Tls(pool(tls_connector(
                    Arc::clone(&target),
                    cfg,
                    server_name(&tls_name)?,
                )))
            }
            Protocol::Https => {
                let cfg = client_config(tls, &[b"h2"], opts.tls_insecure_skip_verify)
                    .map_err(|e| e.to_string())?;
                let host = match (&opts.tls_server_name, &endpoint.host) {
                    (None, Host::Ip(std::net::IpAddr::V6(ip))) => format!("[{ip}]"),
                    _ => tls_name.clone(),
                };
                let authority = if endpoint.port == 443 {
                    host
                } else {
                    format!("{host}:{}", endpoint.port)
                };
                let conn = tls_connector(Arc::clone(&target), cfg, server_name(&tls_name)?);
                Transport::Https(Doh::new(conn, &authority, &endpoint.path, &opts.headers)?)
            }
        };
        Ok(Self {
            id,
            name,
            endpoint,
            timeout: opts.timeout,
            weight: opts.weight.max(1),
            health: Health::default(),
            target,
            transport,
        })
    }

    /// Per-attempt timeout: min(configured, 3 × EWMA + 50 ms, 1 s) per `spec/04` §4.
    pub fn attempt_timeout(&self) -> Duration {
        let adaptive = self
            .health
            .ewma()
            .map_or(self.timeout, |e| e * 3 + Duration::from_millis(50));
        self.timeout.min(adaptive).min(Duration::from_secs(1))
    }

    /// How long to wait before hedging to the next upstream (ADR-013): about 3 × EWMA,
    /// bounded to [20 ms, attempt timeout]; 100 ms until there is data.
    pub fn hedge_delay(&self) -> Duration {
        let d = self.health.ewma().map_or(Duration::from_millis(100), |e| {
            e * 3 + Duration::from_millis(10)
        });
        d.clamp(Duration::from_millis(20), self.attempt_timeout())
    }

    /// Open pooled connections (TCP/DoT), for tests and metrics.
    pub fn pooled_connections(&self) -> usize {
        match &self.transport {
            Transport::Udp { tcp } => tcp.len(),
            Transport::Tcp(p) | Transport::Tls(p) => p.len(),
            Transport::Https(_) => 0,
        }
    }

    /// Sends `q` and returns a validated response. Records the outcome in `health`: NOERROR
    /// and NXDOMAIN are successes; SERVFAIL/REFUSED and transport errors are failures.
    pub async fn exchange(
        &self,
        q: &Question,
        timeout: Duration,
    ) -> Result<Vec<u8>, ExchangeError> {
        let start = Instant::now();
        let result = tokio::time::timeout(timeout, self.exchange_inner(q))
            .await
            .unwrap_or(Err(ExchangeError::Timeout));
        let ok = match &result {
            Ok(resp) => {
                let rc = summarize(resp).map_or(rcode::SERVFAIL, |s| s.rcode);
                rc == rcode::NOERROR || rc == rcode::NXDOMAIN
            }
            Err(_) => false,
        };
        let latency = if ok {
            start.elapsed()
        } else {
            start.elapsed().max(timeout)
        };
        self.health.record(ok, latency, Instant::now());
        result
    }

    async fn exchange_inner(&self, q: &Question) -> Result<Vec<u8>, ExchangeError> {
        // DoH uses ID 0 (RFC 8484 §4.1, cache-friendly); the stream identifies the response.
        let id: u16 = if matches!(self.transport, Transport::Https(_)) {
            0
        } else {
            rand::random()
        };
        let mut buf = [0u8; 512];
        let len = encode_query(q, id, &mut buf).ok_or(ExchangeError::BadResponse)?;
        let query = &buf[..len];
        let resp = match &self.transport {
            Transport::Udp { tcp } => {
                let addr = self.target.addr().await?;
                let resp = udp_exchange(addr, query, id).await?;
                if header::flags(&resp).tc() {
                    // Truncated: retry over TCP (RFC 7766 §1).
                    tcp.exchange(query.to_vec(), id).await?
                } else {
                    resp
                }
            }
            Transport::Tcp(pool) | Transport::Tls(pool) => {
                pool.exchange(query.to_vec(), id).await?
            }
            Transport::Https(doh) => doh.exchange(query).await?,
        };
        if matches_query(&resp, query, id) && summarize(&resp).is_ok() {
            Ok(resp)
        } else {
            Err(ExchangeError::BadResponse)
        }
    }
}

async fn udp_exchange(addr: SocketAddr, query: &[u8], id: u16) -> Result<Vec<u8>, ExchangeError> {
    let bind: SocketAddr = if addr.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    // A fresh socket per query gives a random source port (RFC 5452).
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await?;
        if matches_query(&buf[..n], query, id) && summarize(&buf[..n]).is_ok() {
            buf.truncate(n);
            return Ok(buf);
        }
        // Mismatched or malformed: ignore and keep waiting (possible spoofing attempt).
    }
}
