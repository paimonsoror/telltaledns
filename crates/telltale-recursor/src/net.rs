//! One iterative query to one authoritative server (REQ: DNS-012): UDP from a fresh random
//! port with a random ID (RFC 5452), TCP when the answer is truncated, optional 0x20 case
//! randomization of the name (checked on the way back).

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use telltale_proto::{EdnsOut, HEADER_LEN, Header, NameBuf, build_query, read_name, summarize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Why a server gave nothing usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    #[error("timed out")]
    Timeout,
    #[error("network error")]
    Io,
    #[error("malformed or mismatched response")]
    Bad,
    #[error("the name's letter case came back changed (0x20)")]
    CaseMismatch,
}

/// The query: the name with each letter's case randomized when `mix_case`.
fn wire_query(
    id: u16,
    name: &NameBuf,
    qtype: u16,
    dnssec_ok: bool,
    mix_case: bool,
) -> Option<Vec<u8>> {
    let mut buf = [0u8; 512];
    let edns = EdnsOut {
        udp_payload: 1232,
        dnssec_ok,
        ede: None,
    };
    let len = build_query(&mut buf, id, name, qtype, 1, false, Some(edns)).ok()?;
    let mut q = buf[..len].to_vec();
    if mix_case {
        let end = HEADER_LEN + name.wire_len();
        let mut pos = HEADER_LEN;
        while pos < end {
            let l = usize::from(q[pos]);
            for b in q.get_mut(pos + 1..pos + 1 + l)? {
                if b.is_ascii_alphabetic() && rand::random::<bool>() {
                    *b ^= 0x20;
                }
            }
            pos += 1 + l;
        }
    }
    Some(q)
}

/// The response answers `query`: same ID, QR, opcode 0, the same question (exactly, letter
/// case included, when `exact`).
fn check(resp: &[u8], query: &[u8], exact: bool) -> Result<(), NetError> {
    let (Some(rh), Some(qh)) = (Header::parse(resp), Header::parse(query)) else {
        return Err(NetError::Bad);
    };
    if rh.id != qh.id || !rh.flags.qr() || rh.flags.opcode() != 0 || rh.qdcount != 1 {
        return Err(NetError::Bad);
    }
    // The question sits uncompressed right after the header in both (nothing earlier to
    // point to): compare those bytes.
    let mut a = NameBuf::default();
    let end = read_name(query, HEADER_LEN, &mut a).map_err(|_| NetError::Bad)?;
    let (Some(rq), Some(qq)) = (
        resp.get(HEADER_LEN..end + 4),
        query.get(HEADER_LEN..end + 4),
    ) else {
        return Err(NetError::Bad);
    };
    if rq.eq_ignore_ascii_case(qq) {
        if exact && rq != qq {
            return Err(NetError::CaseMismatch);
        }
    } else {
        return Err(NetError::Bad);
    }
    summarize(resp).map(|_| ()).map_err(|_| NetError::Bad)
}

/// Sends the query to `server` and returns its response.
pub(crate) async fn ask(
    server: SocketAddr,
    name: &NameBuf,
    qtype: u16,
    dnssec_ok: bool,
    mix_case: bool,
    timeout: Duration,
) -> Result<Vec<u8>, NetError> {
    let id: u16 = rand::random();
    let query = wire_query(id, name, qtype, dnssec_ok, mix_case).ok_or(NetError::Bad)?;
    // REQ: DNS-012 — a reply whose letter case differs is not taken as the server's word: it
    // may be a spoof that guessed the ID and port but not the case. The one with the case
    // intact is waited for; only when none comes in time does the server count as one that
    // doesn't echo the case.
    let case_changed = AtomicBool::new(false);
    let resp =
        match tokio::time::timeout(timeout, udp(server, &query, mix_case, &case_changed)).await {
            Ok(r) => r?,
            Err(_) if case_changed.load(Ordering::Relaxed) => return Err(NetError::CaseMismatch),
            Err(_) => return Err(NetError::Timeout),
        };
    if Header::parse(&resp).is_some_and(|h| h.flags.tc()) {
        // Truncated: the whole answer over TCP (RFC 7766), with a little more time.
        return tokio::time::timeout(timeout * 2, tcp(server, &query, mix_case))
            .await
            .map_err(|_| NetError::Timeout)?;
    }
    Ok(resp)
}

async fn udp(
    server: SocketAddr,
    query: &[u8],
    exact: bool,
    case_changed: &AtomicBool,
) -> Result<Vec<u8>, NetError> {
    let bind: SocketAddr = match server.ip() {
        IpAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let sock = UdpSocket::bind(bind).await.map_err(|_| NetError::Io)?;
    sock.connect(server).await.map_err(|_| NetError::Io)?;
    sock.send(query).await.map_err(|_| NetError::Io)?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await.map_err(|_| NetError::Io)?;
        match check(&buf[..n], query, exact) {
            Ok(()) => {
                buf.truncate(n);
                return Ok(buf);
            }
            // The case changed: noted, and the wait for an intact one goes on.
            Err(NetError::CaseMismatch) => case_changed.store(true, Ordering::Relaxed),
            // Stray or spoofed: keep waiting for the real one.
            Err(_) => {}
        }
    }
}

async fn tcp(server: SocketAddr, query: &[u8], exact: bool) -> Result<Vec<u8>, NetError> {
    let mut s = TcpStream::connect(server).await.map_err(|_| NetError::Io)?;
    let len = u16::try_from(query.len()).map_err(|_| NetError::Bad)?;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    s.write_all(&framed).await.map_err(|_| NetError::Io)?;
    let mut lb = [0u8; 2];
    s.read_exact(&mut lb).await.map_err(|_| NetError::Io)?;
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(lb))];
    s.read_exact(&mut buf).await.map_err(|_| NetError::Io)?;
    check(&buf, query, exact)?;
    Ok(buf)
}
