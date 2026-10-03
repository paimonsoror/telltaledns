//! One upstream server: how to talk to it, and how healthy it is.
//!
//! REQ: UPS-001 (UDP/TCP here; DoT/DoH in T1.5b), UPS-006 (health per upstream).

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use telltale_proto::{
    EdnsOut, FlagBit, HEADER_LEN, NameBuf, build_query, header, rcode, read_name, summarize,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::endpoint::{Endpoint, Protocol};
use crate::health::Health;

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
    #[error("hostname upstreams need bootstrap resolution (not yet supported)")]
    Unresolved,
    #[error("{0} upstreams are not supported yet")]
    Unsupported(Protocol),
}

/// Our advertised EDNS payload toward upstreams (DNS Flag Day 2020).
const UPSTREAM_EDNS_PAYLOAD: u16 = 1232;

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
}

impl Upstream {
    pub fn new(
        id: u16,
        name: impl Into<String>,
        endpoint: Endpoint,
        timeout: Duration,
        weight: u32,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            endpoint,
            timeout,
            weight: weight.max(1),
            health: Health::default(),
        }
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

    async fn exchange_inner(
        &self,
        q: &Question,
        timeout: Duration,
    ) -> Result<Vec<u8>, ExchangeError> {
        let addr = self
            .endpoint
            .socket_addr()
            .ok_or(ExchangeError::Unresolved)?;
        let id: u16 = rand::random();
        let mut buf = [0u8; 512];
        let len = encode_query(q, id, &mut buf).ok_or(ExchangeError::BadResponse)?;
        let query = &buf[..len];
        let deadline = tokio::time::Instant::now() + timeout;
        match self.endpoint.protocol {
            Protocol::Udp => {
                let resp = tokio::time::timeout_at(deadline, udp_exchange(addr, query, id))
                    .await
                    .map_err(|_| ExchangeError::Timeout)??;
                if header::flags(&resp).tc() {
                    // Truncated: retry over TCP within the same deadline (RFC 7766 §1).
                    return tokio::time::timeout_at(deadline, tcp_exchange(addr, query, id))
                        .await
                        .map_err(|_| ExchangeError::Timeout)?;
                }
                Ok(resp)
            }
            Protocol::Tcp => tokio::time::timeout_at(deadline, tcp_exchange(addr, query, id))
                .await
                .map_err(|_| ExchangeError::Timeout)?,
            p @ (Protocol::Tls | Protocol::Https) => Err(ExchangeError::Unsupported(p)),
        }
    }
}

/// Builds the outbound query: fresh random ID, RD=1, our own OPT (client EDNS options such as
/// ECS, cookies, and MAC are never forwarded), CD copied from the client.
pub fn encode_query(q: &Question, id: u16, out: &mut [u8]) -> Option<usize> {
    let edns = EdnsOut {
        udp_payload: UPSTREAM_EDNS_PAYLOAD,
        dnssec_ok: q.dnssec_ok,
        ede: None,
    };
    let len = build_query(out, id, &q.name, q.qtype, q.qclass, true, Some(edns)).ok()?;
    if q.checking_disabled {
        let f = header::flags(out).with(FlagBit::Cd, true);
        header::set_flags(out, f);
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

async fn tcp_exchange(addr: SocketAddr, query: &[u8], id: u16) -> Result<Vec<u8>, ExchangeError> {
    let mut s = TcpStream::connect(addr).await?;
    s.set_nodelay(true)?;
    let len = u16::try_from(query.len()).map_err(|_| ExchangeError::BadResponse)?;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    s.write_all(&framed).await?;
    let mut lenb = [0u8; 2];
    s.read_exact(&mut lenb).await?;
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(lenb))];
    s.read_exact(&mut buf).await?;
    if matches_query(&buf, query, id) && summarize(&buf).is_ok() {
        Ok(buf)
    } else {
        Err(ExchangeError::BadResponse)
    }
}
