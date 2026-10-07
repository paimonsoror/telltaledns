//! Upstreams through a proxy (REQ: UPS-010, `spec/04` §2; T7.16): SOCKS5 (RFC 1928, with
//! RFC 1929 username/password) or HTTP CONNECT, for the TCP-based protocols (tcp, tls, https),
//! and (T9.9) plain UDP through a SOCKS5 proxy's UDP ASSOCIATE relay.
//! A hostname upstream is handed to the proxy by name, so the proxy resolves it (Tor:
//! `proxy = "socks5://127.0.0.1:9050"` with `url = "tls://dns.quad9.net"` needs no bootstrap
//! and leaks no lookup).

use std::fmt::Write as _;
use std::io;
use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// A configured proxy.
#[derive(Clone, PartialEq, Eq)]
pub enum Proxy {
    Socks5 {
        addr: SocketAddr,
        auth: Option<(String, String)>,
    },
    HttpConnect {
        addr: SocketAddr,
        /// `user:password`, sent as Basic credentials.
        auth: Option<String>,
    },
}

impl std::fmt::Debug for Proxy {
    // Never print credentials.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Socks5 { addr, auth } => write!(
                f,
                "socks5://{}{addr}",
                if auth.is_some() { "***@" } else { "" }
            ),
            Self::HttpConnect { addr, auth } => write!(
                f,
                "http://{}{addr}",
                if auth.is_some() { "***@" } else { "" }
            ),
        }
    }
}

/// Where the proxy should connect.
#[derive(Debug, Clone)]
pub(crate) enum Dest {
    Addr(SocketAddr),
    Name(String, u16),
}

impl std::fmt::Display for Dest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Addr(a) => write!(f, "{a}"),
            Self::Name(n, p) => write!(f, "{n}:{p}"),
        }
    }
}

impl Proxy {
    /// Parses `socks5://[user:pass@]host:port` or `http://[user:pass@]host:port`; the host is
    /// an IP address or `localhost`.
    pub fn parse(url: &str) -> Result<Self, String> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| "a proxy URL looks like socks5://127.0.0.1:9050".to_owned())?;
        let rest = rest.trim_end_matches('/');
        let (auth, hostport) = match rest.rsplit_once('@') {
            Some((a, h)) => (Some(a), h),
            None => (None, rest),
        };
        let addr = match hostport.rsplit_once(':') {
            Some(("localhost", p)) => p
                .parse::<u16>()
                .map(|p| SocketAddr::new(IpAddr::from([127, 0, 0, 1]), p))
                .map_err(|_| format!("proxy `{scheme}://…`: bad port"))?,
            _ => hostport.parse::<SocketAddr>().map_err(|_| {
                format!("proxy `{scheme}://…`: use an IP address and port (e.g. 127.0.0.1:9050)")
            })?,
        };
        match scheme {
            "socks5" | "socks5h" => {
                let auth = match auth {
                    Some(a) => {
                        let (u, p) = a
                            .split_once(':')
                            .ok_or("proxy credentials look like user:password")?;
                        if u.len() > 255 || p.len() > 255 {
                            return Err("proxy credentials are limited to 255 bytes each".into());
                        }
                        Some((u.to_owned(), p.to_owned()))
                    }
                    None => None,
                };
                Ok(Self::Socks5 { addr, auth })
            }
            "http" => Ok(Self::HttpConnect {
                addr,
                auth: auth.map(str::to_owned),
            }),
            other => Err(format!(
                "proxy scheme `{other}://` isn't supported (socks5:// or http://)"
            )),
        }
    }

    /// REQ: UPS-010 (T9.9) — a UDP relay through a SOCKS5 proxy (RFC 1928 §7). HTTP proxies
    /// can't carry UDP.
    pub(crate) async fn udp_associate(&self) -> io::Result<UdpRelay> {
        let Self::Socks5 { addr, auth } = self else {
            return Err(fail(
                "an HTTP proxy can't carry UDP: use tcp:// or a socks5:// proxy",
            ));
        };
        let mut s = socks5_greet(*addr, auth.as_ref()).await?;
        // UDP ASSOCIATE; our UDP address isn't known yet, so all zeros (the proxy takes the
        // datagrams' source).
        s.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await?;
        if head[0] != 5 || head[1] != 0 {
            return Err(fail(format!(
                "SOCKS5 proxy refused UDP (reply {}): it may not support UDP ASSOCIATE (Tor doesn't; use tcp://)",
                head[1]
            )));
        }
        let ip: IpAddr = match head[3] {
            1 => {
                let mut b = [0u8; 4];
                s.read_exact(&mut b).await?;
                IpAddr::from(b)
            }
            4 => {
                let mut b = [0u8; 16];
                s.read_exact(&mut b).await?;
                IpAddr::from(b)
            }
            _ => return Err(fail("SOCKS5 proxy sent an unusable UDP relay address")),
        };
        let mut port = [0u8; 2];
        s.read_exact(&mut port).await?;
        // An unspecified relay address means "the proxy's own".
        let ip = if ip.is_unspecified() { addr.ip() } else { ip };
        let relay = SocketAddr::new(ip, u16::from_be_bytes(port));
        let bind: SocketAddr = if relay.is_ipv4() {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let sock = UdpSocket::bind(bind).await?;
        sock.connect(relay).await?;
        Ok(UdpRelay { _control: s, sock })
    }

    /// A TCP stream to `dest` through the proxy.
    pub(crate) async fn connect(&self, dest: &Dest) -> io::Result<TcpStream> {
        match self {
            Self::Socks5 { addr, auth } => socks5(*addr, auth.as_ref(), dest).await,
            Self::HttpConnect { addr, auth } => http_connect(*addr, auth.as_deref(), dest).await,
        }
    }
}

fn fail(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

/// REQ: UPS-010 (T9.9) — a SOCKS5 UDP association: the control connection (the relay lasts as
/// long as it's open) and a socket connected to the relay.
#[derive(Debug)]
pub(crate) struct UdpRelay {
    _control: TcpStream,
    sock: UdpSocket,
}

impl UdpRelay {
    /// Sends `query` to `dest` through the relay and returns the reply with ID `id`.
    pub(crate) async fn exchange(
        &self,
        dest: SocketAddr,
        query: &[u8],
        id: u16,
    ) -> io::Result<Vec<u8>> {
        // RFC 1928 §7: RSV RSV FRAG ATYP DST.ADDR DST.PORT DATA.
        let mut d = vec![0u8, 0, 0];
        match dest.ip() {
            IpAddr::V4(v4) => {
                d.push(1);
                d.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                d.push(4);
                d.extend_from_slice(&v6.octets());
            }
        }
        d.extend_from_slice(&dest.port().to_be_bytes());
        d.extend_from_slice(query);
        self.sock.send(&d).await?;
        let mut buf = vec![0u8; 4096 + 32];
        loop {
            let n = self.sock.recv(&mut buf).await?;
            let b = &buf[..n];
            // No fragments; skip the header to the payload.
            if b.len() < 4 || b[2] != 0 {
                continue;
            }
            let start = match b[3] {
                1 => 4 + 4 + 2,
                4 => 4 + 16 + 2,
                3 => 4 + 1 + usize::from(*b.get(4).unwrap_or(&0)) + 2,
                _ => continue,
            };
            let Some(payload) = b.get(start..) else {
                continue;
            };
            if payload.len() >= 2 && u16::from_be_bytes([payload[0], payload[1]]) == id {
                return Ok(payload.to_vec());
            }
        }
    }
}

/// Connects to a SOCKS5 proxy and authenticates (no auth, or RFC 1929).
#[allow(clippy::many_single_char_names)] // protocol byte buffers
async fn socks5_greet(proxy: SocketAddr, auth: Option<&(String, String)>) -> io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy).await?;
    s.set_nodelay(true)?;
    // Greeting: no authentication, or username/password.
    let methods: &[u8] = if auth.is_some() {
        &[0x00, 0x02]
    } else {
        &[0x00]
    };
    let mut hello = vec![5, u8::try_from(methods.len()).unwrap_or(1)];
    hello.extend_from_slice(methods);
    s.write_all(&hello).await?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    match (r, auth) {
        ([5, 0x00], _) => {}
        ([5, 0x02], Some((u, p))) => {
            let mut m = vec![1, u8::try_from(u.len()).unwrap_or(0)];
            m.extend_from_slice(u.as_bytes());
            m.push(u8::try_from(p.len()).unwrap_or(0));
            m.extend_from_slice(p.as_bytes());
            s.write_all(&m).await?;
            let mut a = [0u8; 2];
            s.read_exact(&mut a).await?;
            if a[1] != 0 {
                return Err(fail("SOCKS5 proxy refused the username or password"));
            }
        }
        _ => {
            return Err(fail(
                "SOCKS5 proxy offers no authentication method we can use",
            ));
        }
    }
    Ok(s)
}

#[allow(clippy::many_single_char_names)] // protocol byte buffers
async fn socks5(
    proxy: SocketAddr,
    auth: Option<&(String, String)>,
    dest: &Dest,
) -> io::Result<TcpStream> {
    let mut s = socks5_greet(proxy, auth).await?;
    // CONNECT.
    let mut req = vec![5, 1, 0];
    let port = match dest {
        Dest::Addr(a) => {
            match a.ip() {
                IpAddr::V4(v4) => {
                    req.push(1);
                    req.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    req.push(4);
                    req.extend_from_slice(&v6.octets());
                }
            }
            a.port()
        }
        Dest::Name(n, p) => {
            req.push(3);
            req.push(u8::try_from(n.len()).map_err(|_| fail("name too long for SOCKS5"))?);
            req.extend_from_slice(n.as_bytes());
            *p
        }
    };
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 5 || head[1] != 0 {
        return Err(fail(format!(
            "SOCKS5 proxy couldn't connect to {dest} (reply {})",
            head[1]
        )));
    }
    // Skip the bound address.
    let skip = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            usize::from(l[0]) + 2
        }
        _ => return Err(fail("SOCKS5 proxy sent a malformed reply")),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest).await?;
    Ok(s)
}

/// Base64 (standard alphabet, padded): Basic credentials, SPKI pins.
pub(crate) fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(
                    T[usize::try_from((n >> shift) & 63).unwrap_or(0)],
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

async fn http_connect(proxy: SocketAddr, auth: Option<&str>, dest: &Dest) -> io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy).await?;
    s.set_nodelay(true)?;
    let target = match dest {
        Dest::Addr(SocketAddr::V6(a)) => format!("[{}]:{}", a.ip(), a.port()),
        other => other.to_string(),
    };
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(a) = auth {
        let _ = write!(
            req,
            "Proxy-Authorization: Basic {}\r\n",
            base64(a.as_bytes())
        );
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;
    // The response head, byte by byte (the tunnel starts right after it).
    let mut head = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8192 {
            return Err(fail("HTTP proxy sent an oversized response"));
        }
        s.read_exact(&mut b).await?;
        head.push(b[0]);
    }
    let line = String::from_utf8_lossy(&head);
    let status = line.split_whitespace().nth(1).unwrap_or("");
    if status != "200" {
        return Err(fail(format!(
            "HTTP proxy answered {status} to CONNECT {target}"
        )));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ups_010_parse_and_redact() {
        let p = Proxy::parse("socks5://alice:s3cret@127.0.0.1:9050").unwrap();
        assert_eq!(
            format!("{p:?}"),
            "socks5://***@127.0.0.1:9050",
            "credentials never printed"
        );
        assert!(matches!(
            Proxy::parse("http://localhost:3128").unwrap(),
            Proxy::HttpConnect { auth: None, .. }
        ));
        assert!(Proxy::parse("socks4://127.0.0.1:1080").is_err());
        assert!(
            Proxy::parse("socks5://proxy.example:1080").is_err(),
            "an IP, not a name"
        );
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64(b"ab"), "YWI=");
    }

    /// A fake SOCKS5 proxy: no auth, UDP ASSOCIATE, a relay socket that unwraps and forwards.
    /// Returns its address and how many associations it made.
    #[allow(clippy::many_single_char_names)] // protocol byte buffers
    async fn fake_socks5_udp() -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use tokio::net::TcpListener;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let associations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = std::sync::Arc::clone(&associations);
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut g = [0u8; 3];
                    c.read_exact(&mut g).await.unwrap();
                    c.write_all(&[5, 0]).await.unwrap();
                    let mut req = [0u8; 10];
                    c.read_exact(&mut req).await.unwrap();
                    assert_eq!(&req[..4], &[5, 3, 0, 1], "UDP ASSOCIATE");
                    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let port = relay.local_addr().unwrap().port().to_be_bytes();
                    // An unspecified relay address: "the proxy's own".
                    c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, port[0], port[1]])
                        .await
                        .unwrap();
                    let mut b = [0u8; 1024];
                    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    loop {
                        tokio::select! {
                            r = relay.recv_from(&mut b) => {
                                let Ok((n, client)) = r else { return };
                                let d = &b[..n];
                                assert_eq!(&d[..4], &[0, 0, 0, 1]);
                                let dest = SocketAddr::new(IpAddr::from([d[4], d[5], d[6], d[7]]), u16::from_be_bytes([d[8], d[9]]));
                                upstream.send_to(&d[10..], dest).await.unwrap();
                                let mut rb = [0u8; 1024];
                                let (m, from) = upstream.recv_from(&mut rb).await.unwrap();
                                let mut out = vec![0, 0, 0, 1];
                                if let IpAddr::V4(v4) = from.ip() {
                                    out.extend_from_slice(&v4.octets());
                                }
                                out.extend_from_slice(&from.port().to_be_bytes());
                                out.extend_from_slice(&rb[..m]);
                                relay.send_to(&out, client).await.unwrap();
                            }
                            r = c.read_u8() => { if r.is_err() { return; } }
                        }
                    }
                });
            }
        });
        (addr, associations)
    }

    /// REQ: UPS-010 (T9.9) — UDP through a SOCKS5 UDP ASSOCIATE relay: the datagram carries
    /// the destination in its header, the reply comes back through the relay, and the relay is
    /// reused while its control connection stays open.
    #[tokio::test]
    #[allow(clippy::many_single_char_names)] // protocol byte buffers
    async fn ups_010_socks5_udp_associate() {
        // The "DNS server": answers with the query's ID and a marker byte.
        let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_addr = dns.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 512];
            while let Ok((n, from)) = dns.recv_from(&mut b).await {
                let mut r = b[..n].to_vec();
                r.push(0xAB);
                let _ = dns.send_to(&r, from).await;
            }
        });
        let (addr, associations) = fake_socks5_udp().await;
        let p = Proxy::Socks5 { addr, auth: None };
        let relay = p.udp_associate().await.unwrap();
        for id in [0x1234u16, 0x5678] {
            let q = [id.to_be_bytes().to_vec(), vec![1, 0, 0, 1]].concat();
            let r = relay.exchange(dns_addr, &q, id).await.unwrap();
            assert_eq!(&r[..2], &id.to_be_bytes());
            assert_eq!(r.last(), Some(&0xAB));
        }
        assert_eq!(
            associations.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "one association, reused"
        );
        assert!(
            Proxy::parse("http://127.0.0.1:3128")
                .unwrap()
                .udp_associate()
                .await
                .is_err()
        );
    }

    /// REQ: UPS-010 — a SOCKS5 CONNECT by name (the proxy resolves it), with credentials, and
    /// an HTTP CONNECT; the tunnel carries bytes both ways.
    #[tokio::test]
    #[allow(clippy::many_single_char_names)]
    async fn ups_010_socks5_and_http_connect() {
        use tokio::net::TcpListener;
        // A fake SOCKS5 proxy that checks the request and echoes the tunnel.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut g = [0u8; 4];
            c.read_exact(&mut g).await.unwrap();
            assert_eq!(g, [5, 2, 0, 2]);
            c.write_all(&[5, 2]).await.unwrap();
            let mut a = [0u8; 2];
            c.read_exact(&mut a).await.unwrap();
            let mut u = vec![0u8; usize::from(a[1])];
            c.read_exact(&mut u).await.unwrap();
            let mut pl = [0u8; 1];
            c.read_exact(&mut pl).await.unwrap();
            let mut p = vec![0u8; usize::from(pl[0])];
            c.read_exact(&mut p).await.unwrap();
            assert_eq!((u.as_slice(), p.as_slice()), (&b"alice"[..], &b"pw"[..]));
            c.write_all(&[1, 0]).await.unwrap();
            let mut h = [0u8; 5];
            c.read_exact(&mut h).await.unwrap();
            assert_eq!(&h[..4], &[5, 1, 0, 3], "CONNECT by name");
            let mut n = vec![0u8; usize::from(h[4]) + 2];
            c.read_exact(&mut n).await.unwrap();
            assert_eq!(&n[..n.len() - 2], b"dns.example");
            c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            let mut x = [0u8; 4];
            c.read_exact(&mut x).await.unwrap();
            c.write_all(&x).await.unwrap();
        });
        let p = Proxy::parse(&format!("socks5://alice:pw@{addr}")).unwrap();
        let mut s = p
            .connect(&Dest::Name("dns.example".into(), 853))
            .await
            .unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");

        // HTTP CONNECT.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                c.read_exact(&mut b).await.unwrap();
                head.push(b[0]);
            }
            let h = String::from_utf8(head).unwrap();
            assert!(h.starts_with("CONNECT 9.9.9.9:853 HTTP/1.1\r\n"), "{h}");
            assert!(h.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"), "{h}");
            c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            let mut x = [0u8; 4];
            c.read_exact(&mut x).await.unwrap();
            c.write_all(&x).await.unwrap();
        });
        let p = Proxy::parse(&format!("http://user:pass@{addr}")).unwrap();
        let mut s = p
            .connect(&Dest::Addr("9.9.9.9:853".parse().unwrap()))
            .await
            .unwrap();
        s.write_all(b"pong").await.unwrap();
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"pong");
    }

    /// REQ: UPS-010 (T9.9, T9.24) — a `udp://` upstream built with a `socks5://` proxy resolves
    /// through the relay (the path a configuration takes; `Upstream::build` refused it before).
    #[tokio::test]
    async fn ups_010_udp_upstream_through_socks5() {
        let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_addr = dns.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 512];
            while let Ok((n, from)) = dns.recv_from(&mut b).await {
                let q = telltale_proto::parse_query(&b[..n]).unwrap();
                let mut out = [0u8; 512];
                let mut rb = telltale_proto::ResponseBuilder::new(
                    &q,
                    &mut out,
                    telltale_proto::rcode::NOERROR,
                )
                .unwrap();
                rb.answer_a(60, std::net::Ipv4Addr::new(192, 0, 2, 9))
                    .unwrap();
                let len = rb.finish(None).unwrap();
                let _ = dns.send_to(&out[..len], from).await;
            }
        });
        let (proxy, associations) = fake_socks5_udp().await;
        let ep = crate::Endpoint::parse(&format!("udp://{dns_addr}")).unwrap();
        let opts = crate::UpstreamOptions {
            proxy: Some(std::sync::Arc::new(Proxy::Socks5 {
                addr: proxy,
                auth: None,
            })),
            ..crate::UpstreamOptions::default()
        };
        let up = crate::Upstream::build(1, "socks-udp", ep, &opts, &crate::TlsOptions::default())
            .unwrap();
        let q = crate::Question {
            name: telltale_proto::NameBuf::from_presentation("through.socks.test").unwrap(),
            qtype: telltale_proto::rtype::A,
            qclass: 1,
            dnssec_ok: false,
            checking_disabled: false,
            client_subnet: 0,
        };
        for _ in 0..2 {
            let r = up
                .exchange(&q, std::time::Duration::from_secs(2))
                .await
                .unwrap();
            assert!(r.ends_with(&[192, 0, 2, 9]));
        }
        assert_eq!(
            associations.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "one association, reused across queries"
        );
    }
}
