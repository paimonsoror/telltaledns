//! PROXY protocol v2 (REQ: DNS-020): the client address a load balancer puts in front of a
//! TCP stream (`HAProxy` spec, "2.2. Binary header format (version 2)").
//!
//! When a listener has `proxy_protocol = true`, every connection must start with a v2 header
//! (version 1 text headers and bare connections are refused: accepting both would let any
//! client choose which to send). `LOCAL` connections (the balancer's own health checks) keep
//! the socket's address, and so do headers with the `AF_UNSPEC` or `AF_UNIX` address family;
//! each listener counts those by kind ([`NoAddressStats`]). TLVs are skipped.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::log_line::OncePerMinute;

/// The 12-byte signature that starts every v2 header.
pub const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
/// Largest header accepted (addresses plus TLVs); real balancers send far less.
const MAX_LEN: usize = 1024;

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("PROXY v2: {msg}"))
}

/// What a v2 header says about where the connection comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// `PROXY` over TCP4 or TCP6: the client's address.
    Client(SocketAddr),
    /// No client address: the connection keeps the socket's peer (ADR-039).
    NoAddress(NoAddress),
}

/// A header that names no client address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoAddress {
    /// The `LOCAL` command: the balancer's own connection, such as a health check.
    Local,
    /// `PROXY` with the `AF_UNSPEC` address family.
    Unspec,
    /// `PROXY` with the `AF_UNIX` address family.
    Unix,
}

impl NoAddress {
    /// Every kind.
    pub const ALL: [Self; 3] = [Self::Local, Self::Unspec, Self::Unix];

    /// The `kind` label of `telltale_proxy_protocol_no_address_total`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Unspec => "unspec",
            Self::Unix => "unix",
        }
    }

    /// The header's own name for it, for the log.
    fn header(self) -> &'static str {
        match self {
            Self::Local => "LOCAL",
            Self::Unspec => "AF_UNSPEC",
            Self::Unix => "AF_UNIX",
        }
    }
}

/// REQ: DNS-020 (ADR-039) — one listener's connections whose PROXY header named no client
/// address, by kind (they keep the socket's peer, as before), and when the line about one from a
/// loopback peer was last logged. Touched only on that path: a header with an address, and every
/// query, cost nothing more.
#[derive(Debug)]
pub struct NoAddressStats {
    pub local: AtomicU64,
    pub unspec: AtomicU64,
    pub unix: AtomicU64,
    /// The info line's minute (`AF_UNSPEC`, `AF_UNIX`), on the clock below.
    info_line: OncePerMinute,
    /// The debug line's (`LOCAL`), kept apart so a balancer's health checks never take the
    /// minute of an info line.
    local_line: OncePerMinute,
    /// The clock's origin: monotonic, from when the listener was made.
    #[cfg_attr(test, allow(dead_code))]
    since: Instant,
    /// In tests the clock is this, moved on by hand ([`NoAddressStats::advance`]): no test waits
    /// for a minute or races the real clock.
    #[cfg(test)]
    skew_ms: AtomicU64,
}

impl Default for NoAddressStats {
    fn default() -> Self {
        Self {
            local: AtomicU64::new(0),
            unspec: AtomicU64::new(0),
            unix: AtomicU64::new(0),
            info_line: OncePerMinute::default(),
            local_line: OncePerMinute::default(),
            since: Instant::now(),
            #[cfg(test)]
            skew_ms: AtomicU64::new(0),
        }
    }
}

impl NoAddressStats {
    /// The counter for `kind`.
    pub fn counter(&self, kind: NoAddress) -> &AtomicU64 {
        match kind {
            NoAddress::Local => &self.local,
            NoAddress::Unspec => &self.unspec,
            NoAddress::Unix => &self.unix,
        }
    }

    /// REQ: DNS-020 (ADR-039, ADR-014) — counts a connection to `listener` from `peer` whose
    /// header was `kind`. When `peer` is loopback (a proxy on this machine), the log says so, at
    /// most once a minute for this listener: at info for `AF_UNSPEC` and `AF_UNIX`, at debug for
    /// `LOCAL` (a balancer's own health checks, the case ADR-039 keeps the socket's address
    /// for). Nothing about the connection changes.
    pub(crate) fn note(&self, kind: NoAddress, peer: SocketAddr, listener: SocketAddr) {
        self.counter(kind).fetch_add(1, Ordering::Relaxed);
        let ip = peer.ip();
        if is_loopback(ip) && self.line_due(kind, self.now_ms()) {
            let line = format!(
                "listener {listener}: a PROXY protocol v2 header from {ip} named no client address \
                 ({}); with `proxy_protocol = true` such a connection keeps the socket address, \
                 {ip}, and the settings for that address apply. Counted in \
                 telltale_proxy_protocol_no_address_total; this line comes at most once a minute \
                 per listener",
                kind.header()
            );
            if kind == NoAddress::Local {
                tracing::debug!("{line}");
            } else {
                tracing::info!("{line}");
            }
        }
    }

    /// Whether the line for `kind` is due at `now_ms`: the first time, then once a minute has
    /// passed (`LOCAL`'s debug line on a minute of its own). Of any number of connections that
    /// find it due together, exactly one is told so. The gate is the listeners' one limiter
    /// ([`crate::log_line::OncePerMinute`]).
    pub(crate) fn line_due(&self, kind: NoAddress, now_ms: u64) -> bool {
        match kind {
            NoAddress::Local => &self.local_line,
            NoAddress::Unspec | NoAddress::Unix => &self.info_line,
        }
        .due(now_ms)
    }

    /// The clock the line's interval is measured on.
    #[cfg(not(test))]
    fn now_ms(&self) -> u64 {
        u64::try_from(self.since.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    #[cfg(test)]
    fn now_ms(&self) -> u64 {
        self.skew_ms.load(Ordering::Relaxed)
    }

    /// Moves the clock on (tests).
    #[cfg(test)]
    pub(crate) fn advance(&self, by: std::time::Duration) {
        let ms = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        self.skew_ms.fetch_add(ms, Ordering::Relaxed);
    }
}

/// `ip` is this machine: `127.0.0.0/8`, `::1`, or either as an IPv4-mapped address.
fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_loopback(),
        IpAddr::V6(a) => a.is_loopback() || a.to_ipv4_mapped().is_some_and(|m| m.is_loopback()),
    }
}

/// Reads one v2 header from `r`. Returns the original client address, or `None` for a
/// `LOCAL` command or an unspecified/unix address family (use the socket's peer).
pub async fn read_header<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<SocketAddr>> {
    Ok(match read_source(r).await? {
        Source::Client(a) => Some(a),
        Source::NoAddress(_) => None,
    })
}

/// Reads one v2 header from `r`: the original client address, or which kind of header named
/// none (the connection then keeps the socket's peer).
pub async fn read_source<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Source> {
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
        0x0 => return Ok(Source::NoAddress(NoAddress::Local)),
        0x1 => {} // PROXY
        _ => return Err(bad("unknown command")),
    }
    parse_addresses(head[13], &body)
}

/// The source address from the address block (`fam` = family << 4 | transport).
fn parse_addresses(fam: u8, body: &[u8]) -> io::Result<Source> {
    match fam >> 4 {
        // AF_INET: src addr, dst addr, src port, dst port.
        0x1 => {
            let b: &[u8; 12] = body.first_chunk().ok_or_else(|| bad("short IPv4 block"))?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            Ok(Source::Client(SocketAddr::new(
                IpAddr::V4(ip),
                u16::from_be_bytes([b[8], b[9]]),
            )))
        }
        // AF_INET6
        0x2 => {
            let b: &[u8; 36] = body.first_chunk().ok_or_else(|| bad("short IPv6 block"))?;
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[..16]);
            Ok(Source::Client(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(a)),
                u16::from_be_bytes([b[32], b[33]]),
            )))
        }
        // AF_UNSPEC, AF_UNIX: no usable address.
        0x0 => Ok(Source::NoAddress(NoAddress::Unspec)),
        0x3 => Ok(Source::NoAddress(NoAddress::Unix)),
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

    /// A v2 header: `cmd` (version 2 included), `fam`, then `block`.
    fn header(cmd: u8, fam: u8, block: &[u8]) -> Vec<u8> {
        let mut v = SIGNATURE.to_vec();
        v.extend_from_slice(&[cmd, fam]);
        v.extend_from_slice(&u16::try_from(block.len()).unwrap().to_be_bytes());
        v.extend_from_slice(block);
        v
    }

    /// REQ: DNS-020 (ADR-039) — a header without a client address says which kind it is, and
    /// still reads as "keep the socket's address" (`None`), as before.
    #[tokio::test]
    async fn dns_020_a_header_without_an_address_says_which_kind() {
        let mut v4 = [0u8; 12];
        v4[..4].copy_from_slice(&[127, 0, 0, 1]);
        for (h, want) in [
            (header(0x20, 0x00, &[]), NoAddress::Local),
            // LOCAL ignores whatever address block follows.
            (header(0x20, 0x11, &v4), NoAddress::Local),
            (header(0x21, 0x00, &[]), NoAddress::Unspec),
            (header(0x21, 0x31, &[0; 216]), NoAddress::Unix),
        ] {
            let mut r = &h[..];
            assert_eq!(
                read_source(&mut r).await.unwrap(),
                Source::NoAddress(want),
                "{h:?}"
            );
            assert_eq!(read(&h).await.unwrap(), None, "unchanged: {h:?}");
        }
        let src: SocketAddr = "192.168.1.50:51000".parse().unwrap();
        let dst: SocketAddr = "10.0.0.1:853".parse().unwrap();
        let mut r = &encode(src, dst)[..];
        assert_eq!(read_source(&mut r).await.unwrap(), Source::Client(src));
        let labels: Vec<_> = NoAddress::ALL.iter().map(|k| k.label()).collect();
        assert_eq!(labels, ["local", "unspec", "unix"]);
    }

    /// What the test subscriber saw: each event's level and its whole text.
    #[derive(Clone, Default)]
    struct Lines(std::sync::Arc<std::sync::Mutex<Vec<(tracing::Level, String)>>>);

    impl tracing::Subscriber for Lines {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Text(String);
            impl tracing::field::Visit for Text {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    use std::fmt::Write as _;
                    let _ = write!(self.0, " {}={value:?}", field.name());
                }
            }
            let mut text = Text(String::new());
            event.record(&mut text);
            if let Ok(mut v) = self.0.lock() {
                v.push((*event.metadata().level(), text.0));
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Runs `body` with the subscriber installed on this thread; returns what was logged.
    fn said(body: impl FnOnce()) -> Vec<(tracing::Level, String)> {
        let lines = Lines::default();
        tracing::subscriber::with_default(lines.clone(), body);
        lines.0.lock().map(|v| v.clone()).unwrap_or_default()
    }

    /// The texts of the lines at `level`.
    fn at(lines: &[(tracing::Level, String)], level: tracing::Level) -> Vec<&str> {
        lines
            .iter()
            .filter(|(l, _)| *l == level)
            .map(|(_, t)| t.as_str())
            .collect()
    }

    /// REQ: DNS-020 (ADR-039, ADR-014) — every header without an address is counted by kind; from
    /// a loopback peer the log says so at most once a minute per listener (info for `AF_UNSPEC`
    /// and `AF_UNIX`, debug for `LOCAL`), and never for another peer. The clock is injected, so
    /// nothing waits for a minute.
    #[test]
    fn dns_020_no_address_from_loopback_is_logged_once_a_minute_per_listener() {
        use tracing::Level;
        let listener: SocketAddr = "127.0.0.1:8853".parse().unwrap();
        let lo: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let stats = NoAddressStats::default();
        let lines = said(|| {
            for kind in NoAddress::ALL {
                for _ in 0..10 {
                    stats.note(kind, lo, listener);
                }
            }
        });
        for kind in NoAddress::ALL {
            assert_eq!(stats.counter(kind).load(Ordering::Relaxed), 10, "{kind:?}");
        }
        assert_eq!(
            lines.len(),
            2,
            "two lines for thirty connections: {lines:?}"
        );
        let debug = at(&lines, Level::DEBUG);
        assert_eq!(debug.len(), 1, "{lines:?}");
        assert!(
            debug[0].contains("named no client address (LOCAL)"),
            "{lines:?}"
        );
        let info = at(&lines, Level::INFO);
        assert_eq!(
            info.len(),
            1,
            "one info line for AF_UNSPEC and AF_UNIX: {lines:?}"
        );
        let text = info[0];
        for want in [
            "127.0.0.1:8853",
            "from 127.0.0.1 ",
            "named no client address (AF_UNSPEC)",
            "`proxy_protocol = true`",
            "keeps the socket address, 127.0.0.1,",
            "the settings for that address apply",
            "telltale_proxy_protocol_no_address_total",
            "once a minute per listener",
        ] {
            assert!(text.contains(want), "no `{want}` in: {text}");
        }
        for never in ["allowed_networks", "ratelimit"] {
            assert!(!text.contains(never), "`{never}` is in: {text}");
        }

        // A millisecond short of a minute: quiet. A minute after the lines: once more each.
        stats.advance(std::time::Duration::from_millis(59_999));
        let lines = said(|| {
            stats.note(NoAddress::Unix, lo, listener);
            stats.note(NoAddress::Local, lo, listener);
        });
        assert!(lines.is_empty(), "{lines:?}");
        stats.advance(std::time::Duration::from_millis(1));
        let lines = said(|| {
            stats.note(NoAddress::Unix, lo, listener);
            stats.note(NoAddress::Unix, lo, listener);
            stats.note(NoAddress::Local, lo, listener);
        });
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            at(&lines, Level::INFO)[0].contains("(AF_UNIX)"),
            "{lines:?}"
        );
        assert!(at(&lines, Level::DEBUG)[0].contains("(LOCAL)"), "{lines:?}");
        assert_eq!(stats.unix.load(Ordering::Relaxed), 13);
        assert_eq!(stats.local.load(Ordering::Relaxed), 12);

        // Health checks (`LOCAL`) never take the minute of the info line.
        let s = NoAddressStats::default();
        let lines = said(|| {
            for _ in 0..30 {
                s.note(NoAddress::Local, lo, listener);
            }
            s.note(NoAddress::Unspec, lo, listener);
        });
        assert_eq!(at(&lines, Level::DEBUG).len(), 1, "{lines:?}");
        assert_eq!(at(&lines, Level::INFO).len(), 1, "{lines:?}");

        // Another listener has a minute of its own.
        let other = NoAddressStats::default();
        let lines = said(|| other.note(NoAddress::Unspec, lo, "[::1]:443".parse().unwrap()));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].1.contains("[::1]:443"), "{lines:?}");
        assert!(lines[0].1.contains("(AF_UNSPEC)"), "{lines:?}");
    }

    /// REQ: DNS-020 (ADR-039) — every form of loopback is logged; any other peer is counted and
    /// never logged.
    #[test]
    fn dns_020_no_address_is_logged_only_for_a_loopback_peer() {
        use tracing::Level;
        let listener: SocketAddr = "127.0.0.1:8853".parse().unwrap();
        for peer in ["[::1]:40000", "[::ffff:127.0.0.1]:40000", "127.0.0.9:1"] {
            let s = NoAddressStats::default();
            let lines = said(|| s.note(NoAddress::Unix, peer.parse().unwrap(), listener));
            assert_eq!(at(&lines, Level::INFO).len(), 1, "{peer}: {lines:?}");
        }
        for peer in [
            "192.168.1.5:40000",
            "10.0.0.1:1",
            "[2001:db8::1]:1",
            "[fe80::1]:1",
        ] {
            let s = NoAddressStats::default();
            let lines = said(|| {
                for kind in NoAddress::ALL {
                    s.note(kind, peer.parse().unwrap(), listener);
                }
            });
            assert!(lines.is_empty(), "{peer}: {lines:?}");
            for kind in NoAddress::ALL {
                assert_eq!(
                    s.counter(kind).load(Ordering::Relaxed),
                    1,
                    "{peer} {kind:?}"
                );
            }
        }
    }

    #[test]
    fn dns_020_the_line_is_due_once_a_minute_whatever_the_number_of_threads() {
        for kind in NoAddress::ALL {
            let s = NoAddressStats::default();
            assert!(s.line_due(kind, 0), "the first time");
            assert!(!s.line_due(kind, 1));
            assert!(!s.line_due(kind, 59_999), "a millisecond short of a minute");
            assert!(s.line_due(kind, 60_000), "a minute after the line");
            assert!(!s.line_due(kind, 60_001));
            assert!(s.line_due(kind, 120_000));
        }
        // `AF_UNSPEC` and `AF_UNIX` share the info line's minute; `LOCAL` has its own.
        let s = NoAddressStats::default();
        assert!(s.line_due(NoAddress::Unspec, 0));
        assert!(!s.line_due(NoAddress::Unix, 1));
        assert!(s.line_due(NoAddress::Local, 1));

        let s = NoAddressStats::default();
        let gate = std::sync::Barrier::new(16);
        let told = std::thread::scope(|scope| {
            let all: Vec<_> = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        gate.wait();
                        s.line_due(NoAddress::Unix, 5_000_000)
                    })
                })
                .collect();
            all.into_iter()
                .map(|h| h.join().is_ok_and(|due| due))
                .filter(|due| *due)
                .count()
        });
        assert_eq!(told, 1);
    }
}
