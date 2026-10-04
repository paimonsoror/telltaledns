//! PROXY protocol v2 (REQ: DNS-020): the client address a load balancer puts in front of a
//! TCP stream (`HAProxy` spec, "2.2. Binary header format (version 2)").
//!
//! When a listener has `proxy_protocol = true`, every connection must start with a v2 header
//! (version 1 text headers and bare connections are refused: accepting both would let any
//! client choose which to send). `LOCAL` connections (the balancer's own health checks) keep
//! the socket's address. TLVs are skipped.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

/// The 12-byte signature that starts every v2 header.
pub const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
/// Largest header accepted (addresses plus TLVs); real balancers send far less.
const MAX_LEN: usize = 1024;

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("PROXY v2: {msg}"))
}

/// Reads one v2 header from `r`. Returns the original client address, or `None` for a
/// `LOCAL` command or an unspecified/unix address family (use the socket's peer).
pub async fn read_header<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<SocketAddr>> {
    let mut head = [0u8; 16];
    r.read_exact(&mut head).await?;
    if head[..12] != SIGNATURE {
        return Err(bad("missing signature"));
    }
    let (ver, cmd) = (head[12] >> 4, head[12] & 0x0F);
    if ver != 2 {
        return Err(bad("unsupported version"));
    }
    let len = usize::from(u16::from_be_bytes([head[14], head[15]]));
    if len > MAX_LEN {
        return Err(bad("header too long"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    match cmd {
        0x0 => return Ok(None), // LOCAL
        0x1 => {}               // PROXY
        _ => return Err(bad("unknown command")),
    }
    parse_addresses(head[13], &body)
}

/// The source address from the address block (`fam` = family << 4 | transport).
fn parse_addresses(fam: u8, body: &[u8]) -> io::Result<Option<SocketAddr>> {
    match fam >> 4 {
        // AF_INET: src addr, dst addr, src port, dst port.
        0x1 => {
            let b: &[u8; 12] = body.first_chunk().ok_or_else(|| bad("short IPv4 block"))?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            Ok(Some(SocketAddr::new(
                IpAddr::V4(ip),
                u16::from_be_bytes([b[8], b[9]]),
            )))
        }
        // AF_INET6
        0x2 => {
            let b: &[u8; 36] = body.first_chunk().ok_or_else(|| bad("short IPv6 block"))?;
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[..16]);
            Ok(Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(a)),
                u16::from_be_bytes([b[32], b[33]]),
            )))
        }
        // AF_UNSPEC, AF_UNIX: no usable address.
        0x0 | 0x3 => Ok(None),
        _ => Err(bad("unknown address family")),
    }
}

/// Builds a v2 `PROXY` header for `src` → `dst` (tests and tools).
pub fn encode(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let mut v = SIGNATURE.to_vec();
    v.push(0x21); // version 2, PROXY
    if let (SocketAddr::V4(s), SocketAddr::V4(d)) = (src, dst) {
        v.push(0x11); // AF_INET, STREAM
        v.extend_from_slice(&12u16.to_be_bytes());
        v.extend_from_slice(&s.ip().octets());
        v.extend_from_slice(&d.ip().octets());
        v.extend_from_slice(&s.port().to_be_bytes());
        v.extend_from_slice(&d.port().to_be_bytes());
    } else {
        let six = |a: SocketAddr| match a.ip() {
            IpAddr::V4(x) => x.to_ipv6_mapped(),
            IpAddr::V6(x) => x,
        };
        v.push(0x21); // AF_INET6, STREAM
        v.extend_from_slice(&36u16.to_be_bytes());
        v.extend_from_slice(&six(src).octets());
        v.extend_from_slice(&six(dst).octets());
        v.extend_from_slice(&src.port().to_be_bytes());
        v.extend_from_slice(&dst.port().to_be_bytes());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read(bytes: &[u8]) -> io::Result<Option<SocketAddr>> {
        let mut r = bytes;
        read_header(&mut r).await
    }

    #[tokio::test]
    async fn dns_020_parses_v4_v6_and_local() {
        let src: SocketAddr = "192.168.1.50:51000".parse().unwrap();
        let dst: SocketAddr = "10.0.0.1:853".parse().unwrap();
        assert_eq!(read(&encode(src, dst)).await.unwrap(), Some(src));
        let src6: SocketAddr = "[2001:db8::7]:4000".parse().unwrap();
        let dst6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(read(&encode(src6, dst6)).await.unwrap(), Some(src6));
        // LOCAL with an empty block: keep the socket's address.
        let mut local = SIGNATURE.to_vec();
        local.extend_from_slice(&[0x20, 0x00, 0, 0]);
        assert_eq!(read(&local).await.unwrap(), None);
        // TLVs after the addresses are skipped, and the stream continues after the header.
        let mut h = encode(src, dst);
        h[15] += 4;
        h.extend_from_slice(&[0x04, 0x00, 0x01, 0xAA, b'D', b'N', b'S']);
        let mut r = &h[..];
        assert_eq!(read_header(&mut r).await.unwrap(), Some(src));
        assert_eq!(r, b"DNS");
    }

    #[tokio::test]
    async fn dns_020_rejects_bad_headers() {
        let src: SocketAddr = "192.168.1.50:51000".parse().unwrap();
        let dst: SocketAddr = "10.0.0.1:853".parse().unwrap();
        // A bare DNS-over-TCP message, a v1 text header, wrong version, unknown command,
        // short address block, oversized length, truncated stream.
        assert!(
            read(&[0, 29, 0xAB, 0xCD, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0])
                .await
                .is_err()
        );
        assert!(
            read(b"PROXY TCP4 192.168.1.50 10.0.0.1 1 2\r\n")
                .await
                .is_err()
        );
        let mut h = encode(src, dst);
        h[12] = 0x11;
        assert!(read(&h).await.is_err());
        let mut h = encode(src, dst);
        h[12] = 0x2F;
        assert!(read(&h).await.is_err());
        let mut h = encode(src, dst);
        h[15] = 4;
        h.truncate(20);
        assert!(read(&h).await.is_err());
        let mut h = encode(src, dst);
        h[14] = 0xFF;
        assert!(read(&h).await.is_err());
        assert!(read(&encode(src, dst)[..20]).await.is_err());
    }
}
