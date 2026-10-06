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
use crate::doh3::Doh3;
use crate::doq::Doq;
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
    /// REQ: DNS-015 (T9.9) — the client's subnet, packed by [`client_subnet`] (0 = none), for
    /// upstreams with `ecs = "client"`.
    pub client_subnet: u64,
}

impl Question {
    pub fn from_query(q: &telltale_proto::Query<'_>) -> Self {
        Self {
            name: q.qname,
            qtype: q.qtype,
            qclass: q.qclass,
            dnssec_ok: q.edns.is_some_and(|e| e.dnssec_ok),
            checking_disabled: q.header.flags.cd(),
            client_subnet: 0,
        }
    }
}

/// REQ: DNS-015 (T9.9) — RFC 7871 §11.1's privacy defaults for a client's own subnet.
const ECS_V4_PREFIX: u8 = 24;
const ECS_V6_PREFIX: u8 = 56;

/// REQ: DNS-015 (T9.9) — a client's subnet (/24 or /56) packed into a `u64` for the cache key:
/// family in the top 2 bits, then the address bits. 0 for an address that isn't public
/// (private, loopback, link-local, CGNAT, ULA…): announcing it would tell a CDN nothing and
/// leak the network's layout.
pub fn client_subnet(ip: std::net::IpAddr) -> u64 {
    let ip = match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(v6), std::net::IpAddr::V4),
        v4 @ std::net::IpAddr::V4(_) => v4,
    };
    match ip {
        std::net::IpAddr::V4(a) => {
            let o = a.octets();
            let cgnat = o[0] == 100 && (o[1] & 0xc0) == 64;
            if a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || a.is_multicast()
                || cgnat
                || o[0] == 0
            {
                return 0;
            }
            (1u64 << 62) | u64::from(u32::from(a) >> (32 - ECS_V4_PREFIX))
        }
        std::net::IpAddr::V6(a) => {
            let s = a.segments();
            let ula = (s[0] & 0xfe00) == 0xfc00;
            let link_local = (s[0] & 0xffc0) == 0xfe80;
            if a.is_loopback() || a.is_unspecified() || a.is_multicast() || ula || link_local {
                return 0;
            }
            let bits = u64::try_from(u128::from(a) >> (128 - ECS_V6_PREFIX)).unwrap_or(0);
            (2u64 << 62) | bits
        }
    }
}

/// REQ: DNS-015 (T9.9) — the ECS option for a packed [`client_subnet`], if any.
pub(crate) fn ecs_for_client(packed: u64) -> Option<Vec<u8>> {
    let bits = packed & ((1u64 << 62) - 1);
    match packed >> 62 {
        1 => {
            let a = u32::try_from(bits << (32 - ECS_V4_PREFIX)).ok()?;
            Some(ecs_option(
                std::net::Ipv4Addr::from(a).into(),
                ECS_V4_PREFIX,
            ))
        }
        2 => {
            let a = u128::from(bits) << (128 - ECS_V6_PREFIX);
            Some(ecs_option(
                std::net::Ipv6Addr::from(a).into(),
                ECS_V6_PREFIX,
            ))
        }
        _ => None,
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
    encode_query_with(q, id, out, &[])
}

/// [`encode_query`] with `extra` EDNS options (already encoded) after the loop tag.
pub(crate) fn encode_query_with(
    q: &Question,
    id: u16,
    out: &mut [u8],
    extra: &[u8],
) -> Option<usize> {
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
    // The OPT record is last with RDLENGTH 0 in its final two bytes: append the options.
    let rdlen_at = len - 2;
    let mut rdlen = 0u16;
    if let Some(tag) = NODE_TAG.get() {
        let dst = out.get_mut(len..len + 12)?;
        dst[..2].copy_from_slice(&opt::TELLTALE_LOOP.to_be_bytes());
        dst[2..4].copy_from_slice(&8u16.to_be_bytes());
        dst[4..].copy_from_slice(tag);
        len += 12;
        rdlen += 12;
    }
    if !extra.is_empty() {
        out.get_mut(len..len + extra.len())?.copy_from_slice(extra);
        len += extra.len();
        rdlen += u16::try_from(extra.len()).ok()?;
    }
    out[rdlen_at..rdlen_at + 2].copy_from_slice(&rdlen.to_be_bytes());
    Some(len)
}

/// REQ: DNS-015 (T7.23) — the EDNS Client Subnet option (RFC 7871 §6) announcing `subnet`
/// instead of the client: family, source prefix, scope 0, and the address cut to the prefix.
pub(crate) fn ecs_option(addr: std::net::IpAddr, prefix: u8) -> Vec<u8> {
    let (family, bytes, max): (u16, Vec<u8>, u8) = match addr {
        std::net::IpAddr::V4(a) => (1, a.octets().to_vec(), 32),
        std::net::IpAddr::V6(a) => (2, a.octets().to_vec(), 128),
    };
    let prefix = prefix.min(max);
    let n = usize::from(prefix.div_ceil(8));
    let mut a = bytes[..n].to_vec();
    if prefix % 8 != 0
        && let Some(last) = a.last_mut()
    {
        *last &= 0xff << (8 - prefix % 8);
    }
    let mut o = Vec::with_capacity(8 + n);
    o.extend_from_slice(&opt::ECS.to_be_bytes());
    o.extend_from_slice(&u16::try_from(4 + n).unwrap_or(0).to_be_bytes());
    o.extend_from_slice(&family.to_be_bytes());
    o.push(prefix);
    o.push(0);
    o.extend(a);
    o
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
    /// REQ: DNS-012 — `recursive://` settings.
    pub recursive: telltale_recursor::Settings,
    /// REQ: UPS-010 — connect through this proxy (TCP-based protocols).
    pub proxy: Option<Arc<crate::proxy::Proxy>>,
    /// REQ: DNS-015 (T7.23) — an ECS option sent instead of the client's subnet.
    pub ecs: Option<Vec<u8>>,
    /// REQ: DNS-015 (T9.9) — `ecs = "client"`: send each client's own subnet.
    pub ecs_client: bool,
    /// REQ: UPS-003 (T7.24) — a DNSCrypt stamp's provider key and name.
    pub dnscrypt: Option<([u8; 32], String)>,
    /// REQ: UPS-003 (T9.9) — the anonymized DNSCrypt relay to go through.
    pub dnscrypt_relay: Option<SocketAddr>,
    /// REQ: UPS-011 — this upstream's CA, client certificate, and pins.
    pub tls: crate::tls::UpstreamTls,
    /// REQ: UPS-011 — `exec://`: the program's arguments, and the directory for its socket.
    pub plugin_args: Vec<String>,
    pub plugin_dir: Option<std::path::PathBuf>,
    /// REQ: UPS-011 (T9.9) — DoH over GET (`?dns=`) instead of POST.
    pub doh_get: bool,
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
            recursive: telltale_recursor::Settings::default(),
            proxy: None,
            ecs: None,
            ecs_client: false,
            dnscrypt: None,
            dnscrypt_relay: None,
            plugin_args: Vec::new(),
            plugin_dir: None,
            tls: crate::tls::UpstreamTls::default(),
            doh_get: false,
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
    /// UDP, with a TCP pool for truncated answers, and (T9.9) through a SOCKS5 relay when
    /// the upstream has a proxy.
    Udp {
        tcp: Pool,
        relay: Option<RelayPool>,
    },
    Tcp(Pool),
    Tls(Pool),
    Https(Doh),
    /// REQ: UPS-002 (T7.7) — DNS over QUIC.
    Quic(Box<Doq>),
    /// REQ: UPS-002 (T7.8) — DoH over HTTP/3.
    H3(Box<Doh3>),
    /// REQ: UPS-012 (T7.15) — our own iterative resolver.
    Recursive(Box<telltale_recursor::Recursor>),
    /// REQ: UPS-003 (T7.24) — DNSCrypt v2.
    DnsCrypt(Box<crate::dnscrypt::DnsCrypt>),
    /// REQ: UPS-011 (T7.16) — a plugin on a Unix socket; for `exec://`, with the process
    /// that serves it.
    Plugin(
        Pool,
        #[allow(dead_code)] // held for its Drop, which stops the process
        Option<crate::plugin::Supervisor>,
    ),
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Udp { .. } => "Udp",
            Self::Tcp(_) => "Tcp",
            Self::Tls(_) => "Tls",
            Self::Https(_) => "Https",
            Self::Quic(_) => "Quic",
            Self::H3(_) => "H3",
            Self::Recursive(_) => "Recursive",
            Self::Plugin(..) => "Plugin",
            Self::DnsCrypt(_) => "DnsCrypt",
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
    /// REQ: DNS-015 — the ECS option added to every query (substitute mode).
    ecs: Option<Vec<u8>>,
    /// REQ: DNS-015 (T9.9) — send the client's subnet (`ecs = "client"`).
    pub ecs_client: bool,
}

/// A TCP stream to the target: directly, or through the proxy (REQ: UPS-010), which gets a
/// hostname as is, so it resolves it.
async fn open_tcp(target: &Target, proxy: Option<&crate::proxy::Proxy>) -> io::Result<TcpStream> {
    let s = if let Some(p) = proxy {
        let dest = match &target.host {
            Host::Ip(ip) => crate::proxy::Dest::Addr(SocketAddr::new(*ip, target.port)),
            Host::Name(n) => crate::proxy::Dest::Name(n.clone(), target.port),
        };
        p.connect(&dest).await?
    } else {
        let addr = target.addr().await.map_err(io::Error::other)?;
        TcpStream::connect(addr).await?
    };
    s.set_nodelay(true)?;
    Ok(s)
}

fn tcp_connector(target: Arc<Target>, proxy: Option<Arc<crate::proxy::Proxy>>) -> Connector {
    Arc::new(move || {
        let (target, proxy) = (Arc::clone(&target), proxy.clone());
        Box::pin(async move { Ok(Box::new(open_tcp(&target, proxy.as_deref()).await?) as BoxIo) })
    })
}

fn unix_connector(path: std::path::PathBuf) -> Connector {
    Arc::new(move || {
        let path = path.clone();
        Box::pin(
            async move { Ok(Box::new(tokio::net::UnixStream::connect(&path).await?) as BoxIo) },
        )
    })
}

fn tls_connector(
    target: Arc<Target>,
    cfg: Arc<rustls::ClientConfig>,
    name: ServerName<'static>,
    proxy: Option<Arc<crate::proxy::Proxy>>,
) -> Connector {
    let tls = tokio_rustls::TlsConnector::from(cfg);
    Arc::new(move || {
        let (target, tls, name, proxy) = (
            Arc::clone(&target),
            tls.clone(),
            name.clone(),
            proxy.clone(),
        );
        Box::pin(async move {
            let s = open_tcp(&target, proxy.as_deref()).await?;
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
    #[allow(clippy::too_many_lines)] // one arm per protocol
    pub fn build(
        id: u16,
        name: impl Into<String>,
        endpoint: Endpoint,
        opts: &UpstreamOptions,
        tls: &TlsOptions,
    ) -> Result<Self, String> {
        let name = name.into();
        // REQ: UPS-010 — TCP-based protocols only (UDP through SOCKS5 is P2).
        if opts.proxy.is_some()
            && !matches!(
                endpoint.protocol,
                Protocol::Tcp | Protocol::Tls | Protocol::Https
            )
        {
            return Err(format!(
                "upstream `{name}`: a proxy works with tcp://, tls://, and https:// upstreams (use tcp:// instead of udp://)"
            ));
        }
        if matches!(endpoint.host, Host::Name(_))
            && opts.bootstrap.is_none()
            && opts.proxy.is_none()
            && !matches!(
                endpoint.protocol,
                Protocol::Recursive | Protocol::Unix | Protocol::Exec
            )
        {
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
                // REQ: UPS-010 (T9.9) — with a SOCKS5 proxy, UDP goes through its relay and a
                // truncated answer's TCP retry through the proxy too.
                tcp: pool(tcp_connector(Arc::clone(&target), opts.proxy.clone())),
                relay: opts.proxy.clone().map(RelayPool::new),
            },
            Protocol::Tcp => {
                Transport::Tcp(pool(tcp_connector(Arc::clone(&target), opts.proxy.clone())))
            }
            Protocol::Tls => {
                let cfg = client_config(tls, &opts.tls, &[], opts.tls_insecure_skip_verify)
                    .map_err(|e| e.to_string())?;
                Transport::Tls(pool(tls_connector(
                    Arc::clone(&target),
                    cfg,
                    server_name(&tls_name)?,
                    opts.proxy.clone(),
                )))
            }
            Protocol::Https => {
                let cfg = client_config(tls, &opts.tls, &[b"h2"], opts.tls_insecure_skip_verify)
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
                let conn = tls_connector(
                    Arc::clone(&target),
                    cfg,
                    server_name(&tls_name)?,
                    opts.proxy.clone(),
                );
                Transport::Https(Doh::new(
                    conn,
                    &authority,
                    &endpoint.path,
                    &opts.headers,
                    opts.doh_get,
                )?)
            }
            Protocol::H3 => {
                let cfg = client_config(tls, &opts.tls, &[b"h3"], opts.tls_insecure_skip_verify)
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
                let t = Arc::clone(&target);
                let resolve: crate::doq::Resolve = Arc::new(move || {
                    let t = Arc::clone(&t);
                    Box::pin(async move { t.addr().await })
                });
                Transport::H3(Box::new(Doh3::new(
                    resolve,
                    cfg,
                    &server_name(&tls_name)?,
                    &authority,
                    &endpoint.path,
                    &opts.headers,
                    opts.idle_timeout,
                )?))
            }
            Protocol::Recursive => Transport::Recursive(Box::new(
                telltale_recursor::Recursor::new(opts.recursive.clone()),
            )),
            Protocol::DnsCrypt => {
                let (pk, name) = opts
                    .dnscrypt
                    .clone()
                    .ok_or_else(|| format!("upstream `{name}`: DNSCrypt needs a stamp"))?;
                let addr = match endpoint.host {
                    Host::Ip(ip) => SocketAddr::new(ip, endpoint.port),
                    Host::Name(_) => {
                        return Err(format!(
                            "upstream `{name}`: DNSCrypt stamps carry an address"
                        ));
                    }
                };
                Transport::DnsCrypt(Box::new(crate::dnscrypt::DnsCrypt::new(
                    addr,
                    pk,
                    &name,
                    opts.dnscrypt_relay,
                )?))
            }
            Protocol::Unix => {
                Transport::Plugin(pool(unix_connector(endpoint.path.clone().into())), None)
            }
            Protocol::Exec => {
                let dir = opts
                    .plugin_dir
                    .clone()
                    .unwrap_or_else(|| std::env::temp_dir().join("telltale-plugins"));
                let safe: String = name
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                            c
                        } else {
                            '_'
                        }
                    })
                    .collect();
                let socket = dir.join(format!("{safe}.sock"));
                let sup = crate::plugin::supervise(
                    &name,
                    endpoint.path.clone().into(),
                    opts.plugin_args.clone(),
                    socket.clone(),
                );
                Transport::Plugin(pool(unix_connector(socket)), Some(sup))
            }
            Protocol::Quic => {
                let cfg = client_config(tls, &opts.tls, &[b"doq"], opts.tls_insecure_skip_verify)
                    .map_err(|e| e.to_string())?;
                let t = Arc::clone(&target);
                let resolve: crate::doq::Resolve = Arc::new(move || {
                    let t = Arc::clone(&t);
                    Box::pin(async move { t.addr().await })
                });
                Transport::Quic(Box::new(Doq::new(
                    resolve,
                    cfg,
                    &server_name(&tls_name)?,
                    opts.idle_timeout,
                )?))
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
            ecs: opts.ecs.clone(),
            ecs_client: opts.ecs_client,
        })
    }

    /// Per-attempt timeout: min(configured, 3 × EWMA + 50 ms, 1 s) per `spec/04` §4.
    pub fn attempt_timeout(&self) -> Duration {
        // REQ: DNS-012 — a cold recursion walks several servers: give it the time it needs
        // (the query's overall budget still bounds it).
        if matches!(self.transport, Transport::Recursive(_)) {
            return self.timeout.max(Duration::from_secs(3));
        }
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
            Transport::Udp { tcp, .. } => tcp.len(),
            Transport::Tcp(p) | Transport::Tls(p) | Transport::Plugin(p, _) => p.len(),
            Transport::Https(_)
            | Transport::Quic(_)
            | Transport::H3(_)
            | Transport::Recursive(_)
            | Transport::DnsCrypt(_) => 0,
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
        let result = self.exchange_inner(q, timeout).await;
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

    /// One exchange within `timeout`. Over UDP, a truncated answer's TCP retry gets the
    /// configured timeout of its own: the adaptive one is calibrated on small UDP answers, and
    /// large ones (DNSKEY sets with signatures, long TXT) would never fit in it.
    async fn exchange_inner(
        &self,
        q: &Question,
        timeout: Duration,
    ) -> Result<Vec<u8>, ExchangeError> {
        // DoH uses ID 0 (RFC 8484 §4.1, cache-friendly) and DoQ must (RFC 9250 §4.2.1); the
        // stream identifies the response.
        let id: u16 = if matches!(
            self.transport,
            Transport::Https(_) | Transport::Quic(_) | Transport::H3(_)
        ) {
            0
        } else {
            rand::random()
        };
        let mut buf = [0u8; 512];
        // REQ: DNS-015 (T9.9) — the client's subnet, when this upstream passes it on.
        let client = if self.ecs_client {
            ecs_for_client(q.client_subnet)
        } else {
            None
        };
        let ecs = client
            .as_deref()
            .or(self.ecs.as_deref())
            .unwrap_or_default();
        let len = encode_query_with(q, id, &mut buf, ecs).ok_or(ExchangeError::BadResponse)?;
        let query = &buf[..len];
        let resp = match &self.transport {
            Transport::Udp { tcp, relay } => {
                let udp = async {
                    let addr = self.target.addr().await?;
                    match relay {
                        Some(r) => r.exchange(addr, query, id).await,
                        None => udp_exchange(addr, query, id).await,
                    }
                };
                let resp = timed(tokio::time::timeout(timeout, udp).await)?;
                if header::flags(&resp).tc() {
                    // Truncated: retry over TCP (RFC 7766 §1), with time of its own.
                    let t = self.timeout.max(timeout);
                    timed(tokio::time::timeout(t, tcp.exchange(query.to_vec(), id)).await)?
                } else {
                    resp
                }
            }
            Transport::Tcp(pool) | Transport::Tls(pool) | Transport::Plugin(pool, _) => {
                timed(tokio::time::timeout(timeout, pool.exchange(query.to_vec(), id)).await)?
            }
            Transport::Https(doh) => {
                timed(tokio::time::timeout(timeout, doh.exchange(query)).await)?
            }
            Transport::Quic(doq) => {
                timed(tokio::time::timeout(timeout, doq.exchange(query)).await)?
            }
            Transport::H3(h3) => timed(tokio::time::timeout(timeout, h3.exchange(query)).await)?,
            Transport::DnsCrypt(d) => d.exchange(query, timeout).await?,
            Transport::Recursive(r) => tokio::time::timeout(timeout, r.answer(query))
                .await
                .map_err(|_| ExchangeError::Timeout)?
                .map_err(|e| {
                    tracing::debug!(error = %e, "recursion failed");
                    ExchangeError::BadResponse
                })?,
        };
        if matches_query(&resp, query, id) && summarize(&resp).is_ok() {
            Ok(resp)
        } else {
            Err(ExchangeError::BadResponse)
        }
    }
}

/// A timed-out exchange is a timeout.
fn timed(
    r: Result<Result<Vec<u8>, ExchangeError>, tokio::time::error::Elapsed>,
) -> Result<Vec<u8>, ExchangeError> {
    r.unwrap_or(Err(ExchangeError::Timeout))
}

/// REQ: UPS-010 (T9.9) — SOCKS5 UDP associations kept for reuse (a few, each used by one
/// query at a time); one that fails is dropped and a new one made next time.
pub(crate) struct RelayPool {
    proxy: Arc<crate::proxy::Proxy>,
    idle: parking_lot::Mutex<Vec<crate::proxy::UdpRelay>>,
}

impl std::fmt::Debug for RelayPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayPool")
            .field("proxy", &self.proxy)
            .finish_non_exhaustive()
    }
}

impl RelayPool {
    fn new(proxy: Arc<crate::proxy::Proxy>) -> Self {
        Self {
            proxy,
            idle: parking_lot::Mutex::new(Vec::new()),
        }
    }

    async fn exchange(
        &self,
        dest: SocketAddr,
        query: &[u8],
        id: u16,
    ) -> Result<Vec<u8>, ExchangeError> {
        let held = self.idle.lock().pop();
        let relay = match held {
            Some(r) => r,
            None => self.proxy.udp_associate().await?,
        };
        let resp = relay.exchange(dest, query, id).await?;
        let mut idle = self.idle.lock();
        if idle.len() < 4 {
            idle.push(relay);
        }
        Ok(resp)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: DNS-015 (T7.23) — the substitute ECS option (RFC 7871 §6): family, prefix, scope
    /// 0, the address cut to the prefix; appended to the query's OPT with the right length.
    #[test]
    fn dns_015_ecs_client_subnet() {
        let p = client_subnet("203.0.113.77".parse().unwrap());
        assert_ne!(p, 0);
        assert_eq!(p, client_subnet("203.0.113.1".parse().unwrap()), "same /24");
        assert_ne!(p, client_subnet("203.0.114.1".parse().unwrap()));
        assert_eq!(
            p,
            client_subnet("::ffff:203.0.113.9".parse().unwrap()),
            "v4-mapped"
        );
        assert_eq!(
            ecs_for_client(p).unwrap(),
            ecs_option("203.0.113.0".parse().unwrap(), 24)
        );
        let v6 = client_subnet("2001:db8:abcd:ef01::1".parse().unwrap());
        assert_eq!(
            v6,
            client_subnet("2001:db8:abcd:efff::2".parse().unwrap()),
            "same /56"
        );
        assert_eq!(
            ecs_for_client(v6).unwrap(),
            ecs_option("2001:db8:abcd:ef00::".parse().unwrap(), 56)
        );
        for private in [
            "10.1.2.3",
            "192.168.3.2",
            "172.16.0.1",
            "127.0.0.1",
            "100.64.1.1",
            "169.254.1.1",
            "fd00::1",
            "fe80::1",
            "::1",
        ] {
            assert_eq!(client_subnet(private.parse().unwrap()), 0, "{private}");
        }
        assert!(ecs_for_client(0).is_none());
    }

    #[test]
    fn dns_015_ecs_substitute() {
        let o = ecs_option("203.0.113.77".parse().unwrap(), 24);
        assert_eq!(o, vec![0, 8, 0, 7, 0, 1, 24, 0, 203, 0, 113]);
        let o = ecs_option("2001:db8:abcd:ef01::1".parse().unwrap(), 50);
        assert_eq!(&o[4..8], &[0, 2, 50, 0]);
        assert_eq!(
            &o[8..],
            &[0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0xc0],
            "the last byte keeps 2 bits"
        );
        let q = Question {
            name: telltale_proto::NameBuf::from_presentation("example.com").unwrap(),
            qtype: telltale_proto::rtype::A,
            qclass: 1,
            dnssec_ok: false,
            checking_disabled: false,
            client_subnet: 0,
        };
        let mut buf = [0u8; 512];
        let ecs = ecs_option("203.0.113.0".parse().unwrap(), 24);
        let len = encode_query_with(&q, 7, &mut buf, &ecs).unwrap();
        let parsed = telltale_proto::parse_query(&buf[..len]).unwrap();
        let edns = parsed.edns.unwrap();
        assert_eq!(edns.client_subnet(), Some(&ecs[4..]));
        // Without an option, no ECS (strip).
        let len = encode_query(&q, 7, &mut buf).unwrap();
        let parsed = telltale_proto::parse_query(&buf[..len]).unwrap();
        assert!(parsed.edns.unwrap().client_subnet().is_none());
    }
}
