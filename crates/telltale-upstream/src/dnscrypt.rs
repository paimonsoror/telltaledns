//! DNSCrypt v2 upstreams and DNS stamps (REQ: UPS-003, `spec/04` §2; T7.24).
//!
//! `sdns://` stamps name a server: DNSCrypt stamps become this transport; DoH, DoT, and DoQ
//! stamps become the matching URL (the router maps them). For DNSCrypt:
//! 1. The resolver's certificate is a TXT record of the provider name, fetched in clear and
//!    checked with the provider's Ed25519 key from the stamp (and its validity dates); the
//!    best one wins (newest construction, then highest serial), refreshed hourly.
//! 2. Each query is padded (ISO 7816-4, to 64 bytes, at least 256 over UDP) and boxed
//!    (X25519 + XChaCha20-Poly1305 or XSalsa20-Poly1305, as the certificate says) with a
//!    fresh nonce, then sent as `client-magic || client-pk || nonce/2 || box`. The answer
//!    `r6fnvWj8 || nonce || box` must echo our nonce half; a truncated one is asked again
//!    over TCP.

use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crypto_box::aead::AeadInPlace;
#[allow(deprecated)] // generic-array 0.14, through crypto_box 0.9 (aead 0.5)
use crypto_box::aead::generic_array::GenericArray;
use crypto_box::{ChaChaBox, PublicKey, SalsaBox, SecretKey};
use parking_lot::Mutex;
use telltale_proto::{NameBuf, rtype};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::upstream::ExchangeError;

const RESOLVER_MAGIC: &[u8; 8] = b"r6fnvWj8";
const CERT_MAGIC: &[u8; 4] = b"DNSC";
const TAG: usize = 16;

/// A parsed `sdns://` stamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stamp {
    DnsCrypt {
        addr: SocketAddr,
        provider_pk: [u8; 32],
        provider_name: String,
    },
    /// DoH: the server address (if pinned), its TLS name, and the path.
    Doh {
        addr: Option<String>,
        hostname: String,
        port: u16,
        path: String,
        /// REQ: UPS-003 (T9.17) — SHA-256 of the TBS part of a certificate in the server's
        /// chain; one must match (empty: no pinning).
        hashes: Vec<[u8; 32]>,
    },
    /// DoT or DoQ: the server address (if pinned) and its TLS name.
    Dot {
        addr: Option<String>,
        hostname: String,
        port: u16,
        quic: bool,
        /// REQ: UPS-003 (T9.17) — as for DoH.
        hashes: Vec<[u8; 32]>,
    },
}

/// URL-safe base64 without padding (the stamp encoding).
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        }))
    };
    let bytes: Vec<u8> = s.bytes().filter(|b| *b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            n |= val(*b)? << (18 - 6 * i);
        }
        let take = match chunk.len() {
            4 => 3,
            3 => 2,
            2 => 1,
            _ => return None,
        };
        for i in 0..take {
            out.push(u8::try_from((n >> (16 - 8 * i)) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// A length-prefixed field.
fn lp<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = usize::from(*b.first()?);
    let v = b.get(1..1 + len)?;
    *b = &b[1 + len..];
    Some(v)
}

/// A variable-length set (the certificate hashes): items whose length has the high bit set
/// continue. Empty items are skipped; a hash that isn't 32 bytes is malformed.
fn vlp_hashes(b: &mut &[u8]) -> Option<Vec<[u8; 32]>> {
    let mut out = Vec::new();
    loop {
        let l = *b.first()?;
        let len = usize::from(l & 0x7f);
        let item = b.get(1..1 + len)?;
        if !item.is_empty() {
            out.push(item.try_into().ok()?);
        }
        *b = &b[1 + len..];
        if l & 0x80 == 0 {
            return Some(out);
        }
    }
}

fn text(b: &[u8]) -> Option<String> {
    String::from_utf8(b.to_vec()).ok()
}

/// REQ: UPS-003 (T9.9) — an anonymized DNSCrypt relay: a relay stamp (type 0x81, just an
/// address, no properties) or `ip:port`.
pub fn parse_relay(s: &str) -> Result<SocketAddr, String> {
    let Some(body) = s.strip_prefix("sdns://") else {
        return parse_addr(s, 443).ok_or_else(|| format!("relay `{s}`: not ip:port"));
    };
    let raw = b64url_decode(body).ok_or("not a valid relay stamp (base64)")?;
    match raw.split_first() {
        Some((0x81, mut b)) => {
            let addr = lp(&mut b).and_then(text).ok_or("a malformed relay stamp")?;
            parse_addr(&addr, 443).ok_or_else(|| format!("relay stamp address `{addr}`"))
        }
        _ => Err("not a relay stamp (sdns://g…)".to_owned()),
    }
}

/// REQ: UPS-003 (T9.9) — what goes to the relay: the anonymized-DNSCrypt header (magic,
/// the server's address as IPv6, its port), then the packet unchanged.
fn relayed(server: SocketAddr, packet: &[u8]) -> Vec<u8> {
    let ip = match server.ip() {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        std::net::IpAddr::V6(v6) => v6,
    };
    let mut out = Vec::with_capacity(28 + packet.len());
    out.extend_from_slice(&[0xff; 8]);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&ip.octets());
    out.extend_from_slice(&server.port().to_be_bytes());
    out.extend_from_slice(packet);
    out
}

/// Parses `sdns://…` (DNSCrypt, DoH, DoT, DoQ stamps).
pub fn parse_stamp(s: &str) -> Result<Stamp, String> {
    let body = s
        .strip_prefix("sdns://")
        .ok_or("a stamp starts with sdns://")?;
    let raw = b64url_decode(body).ok_or("not a valid stamp (base64)")?;
    let bad = || "a malformed stamp".to_owned();
    let (&kind, rest) = raw.split_first().ok_or_else(bad)?;
    let mut b = rest.get(8..).ok_or_else(bad)?; // props (u64, little-endian)
    match kind {
        0x01 => {
            let addr = text(lp(&mut b).ok_or_else(bad)?).ok_or_else(bad)?;
            let addr = parse_addr(&addr, 443).ok_or_else(|| format!("stamp address `{addr}`"))?;
            let pk: [u8; 32] = lp(&mut b)
                .and_then(|k| k.try_into().ok())
                .ok_or("the stamp's provider key isn't 32 bytes")?;
            let name = text(lp(&mut b).ok_or_else(bad)?).ok_or_else(bad)?;
            Ok(Stamp::DnsCrypt {
                addr,
                provider_pk: pk,
                provider_name: name,
            })
        }
        0x02..=0x04 => {
            let addr = text(lp(&mut b).ok_or_else(bad)?).ok_or_else(bad)?;
            let hashes = vlp_hashes(&mut b).ok_or_else(bad)?;
            let host_port = text(lp(&mut b).ok_or_else(bad)?).ok_or_else(bad)?;
            // The host name may carry a port (`dns.example:443`).
            let default_port = if kind == 0x02 { 443 } else { 853 };
            let (hostname, port) = match host_port.rsplit_once(':') {
                Some((h, p)) if !h.contains(':') => (h.to_owned(), p.parse().map_err(|_| bad())?),
                _ => (host_port, default_port),
            };
            let addr = (!addr.is_empty()).then_some(addr);
            if kind == 0x02 {
                let path = text(lp(&mut b).ok_or_else(bad)?).ok_or_else(bad)?;
                Ok(Stamp::Doh {
                    addr,
                    hostname,
                    port,
                    path,
                    hashes,
                })
            } else {
                Ok(Stamp::Dot {
                    addr,
                    hostname,
                    port,
                    quic: kind == 0x04,
                    hashes,
                })
            }
        }
        other => Err(format!(
            "stamp type {other:#04x} isn't supported (DNSCrypt, DoH, DoT, DoQ are)"
        )),
    }
}

/// `1.2.3.4`, `1.2.3.4:443`, `[2001:db8::1]:443`.
fn parse_addr(s: &str, default_port: u16) -> Option<SocketAddr> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Some(a);
    }
    let ip = s.trim_start_matches('[').trim_end_matches(']');
    ip.parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, default_port))
}

/// The construction a certificate names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Construction {
    XSalsa20Poly1305 = 1,
    XChaCha20Poly1305 = 2,
}

/// A checked resolver certificate.
#[derive(Debug, Clone)]
struct Cert {
    construction: Construction,
    resolver_pk: [u8; 32],
    client_magic: [u8; 8],
    serial: u32,
    valid_until: u32,
    fetched: Instant,
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
}

/// Parses and checks one certificate (the TXT record's bytes).
fn parse_cert(b: &[u8], provider: &ed25519_dalek::VerifyingKey, now: u32) -> Option<Cert> {
    if b.len() < 124 || &b[..4] != CERT_MAGIC {
        return None;
    }
    let construction = match u16::from_be_bytes([b[4], b[5]]) {
        1 => Construction::XSalsa20Poly1305,
        2 => Construction::XChaCha20Poly1305,
        _ => return None,
    };
    let sig = ed25519_dalek::Signature::from_slice(&b[8..72]).ok()?;
    provider.verify_strict(&b[72..], &sig).ok()?;
    let u32_at = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    let (serial, start, end) = (u32_at(112), u32_at(116), u32_at(120));
    if now < start || now > end {
        return None;
    }
    Some(Cert {
        construction,
        resolver_pk: b[72..104].try_into().ok()?,
        client_magic: b[104..112].try_into().ok()?,
        serial,
        valid_until: end,
        fetched: Instant::now(),
    })
}

/// ISO/IEC 7816-4 padding to a multiple of 64 (at least `min`).
fn pad(msg: &[u8], min: usize) -> Vec<u8> {
    let len = (msg.len() + 1).max(min).div_ceil(64) * 64;
    let mut v = Vec::with_capacity(len + TAG);
    v.extend_from_slice(msg);
    v.push(0x80);
    v.resize(len, 0);
    v
}

fn unpad(mut v: Vec<u8>) -> Option<Vec<u8>> {
    let end = v.iter().rposition(|b| *b != 0)?;
    if v[end] != 0x80 {
        return None;
    }
    v.truncate(end);
    Some(v)
}

/// The box for a certificate's construction.
enum Box2 {
    Salsa(SalsaBox),
    ChaCha(ChaChaBox),
}

#[allow(deprecated)] // generic-array 0.14, through crypto_box 0.9 (aead 0.5)
impl Box2 {
    fn new(c: Construction, their: &[u8; 32], ours: &SecretKey) -> Self {
        let pk = PublicKey::from(*their);
        match c {
            Construction::XSalsa20Poly1305 => Self::Salsa(SalsaBox::new(&pk, ours)),
            Construction::XChaCha20Poly1305 => Self::ChaCha(ChaChaBox::new(&pk, ours)),
        }
    }

    /// libsodium's `crypto_box_easy` layout: tag, then ciphertext.
    fn seal(&self, nonce: &[u8; 24], mut msg: Vec<u8>) -> Option<Vec<u8>> {
        let n = GenericArray::from_slice(nonce);
        let tag = match self {
            Self::Salsa(b) => b.encrypt_in_place_detached(n, b"", &mut msg).ok()?,
            Self::ChaCha(b) => b.encrypt_in_place_detached(n, b"", &mut msg).ok()?,
        };
        let mut out = Vec::with_capacity(TAG + msg.len());
        out.extend_from_slice(&tag);
        out.extend(msg);
        Some(out)
    }

    fn open(&self, nonce: &[u8; 24], sealed: &[u8]) -> Option<Vec<u8>> {
        let (tag, ct) = sealed.split_at_checked(TAG)?;
        let n = GenericArray::from_slice(nonce);
        let mut msg = ct.to_vec();
        let t = GenericArray::from_slice(tag);
        match self {
            Self::Salsa(b) => b.decrypt_in_place_detached(n, b"", &mut msg, t).ok()?,
            Self::ChaCha(b) => b.decrypt_in_place_detached(n, b"", &mut msg, t).ok()?,
        }
        Some(msg)
    }
}

/// The DNSCrypt transport of one upstream.
pub(crate) struct DnsCrypt {
    addr: SocketAddr,
    /// REQ: UPS-003 (T9.9) — everything goes through this anonymized relay when set.
    relay: Option<SocketAddr>,
    provider: ed25519_dalek::VerifyingKey,
    provider_name: NameBuf,
    secret: SecretKey,
    public: [u8; 32],
    cert: Mutex<Option<Cert>>,
    fetching: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for DnsCrypt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsCrypt")
            .field("addr", &self.addr)
            .field("relay", &self.relay)
            .finish_non_exhaustive()
    }
}

impl DnsCrypt {
    pub(crate) fn new(
        addr: SocketAddr,
        provider_pk: [u8; 32],
        provider_name: &str,
        relay: Option<SocketAddr>,
    ) -> Result<Self, String> {
        let provider = ed25519_dalek::VerifyingKey::from_bytes(&provider_pk)
            .map_err(|_| "the stamp's provider key isn't a valid Ed25519 key".to_owned())?;
        let name = NameBuf::from_presentation(provider_name)
            .map_err(|_| format!("provider name `{provider_name}`"))?;
        let secret = SecretKey::generate(&mut crypto_box::aead::OsRng);
        let public = *secret.public_key().as_bytes();
        Ok(Self {
            addr,
            relay,
            provider,
            provider_name: name,
            secret,
            public,
            cert: Mutex::new(None),
            fetching: tokio::sync::Mutex::new(()),
        })
    }

    /// The current certificate (fetched when missing, older than an hour, or expired).
    async fn cert(&self, timeout: Duration) -> Result<Cert, ExchangeError> {
        let fresh = |c: &Option<Cert>| {
            c.as_ref()
                .filter(|c| {
                    c.fetched.elapsed() < Duration::from_secs(3600) && c.valid_until > unix_now()
                })
                .cloned()
        };
        if let Some(c) = fresh(&self.cert.lock()) {
            return Ok(c);
        }
        let _one = self.fetching.lock().await;
        if let Some(c) = fresh(&self.cert.lock()) {
            return Ok(c);
        }
        let resp = plain_query(
            self.addr,
            self.relay,
            &self.provider_name,
            rtype::TXT,
            timeout,
        )
        .await?;
        let now = unix_now();
        let best = txt_records(&resp)
            .iter()
            .filter_map(|t| parse_cert(t, &self.provider, now))
            .max_by_key(|c| (c.construction, c.serial))
            .ok_or(ExchangeError::BadResponse)?;
        *self.cert.lock() = Some(best.clone());
        Ok(best)
    }

    /// One encrypted exchange of `query` (a whole DNS message).
    pub(crate) async fn exchange(
        &self,
        query: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, ExchangeError> {
        let started = Instant::now();
        let cert = self.cert(timeout).await?;
        let left = timeout
            .saturating_sub(started.elapsed())
            .max(Duration::from_millis(200));
        let b = Box2::new(cert.construction, &cert.resolver_pk, &self.secret);
        let resp = self.round(&b, &cert, query, false, left).await?;
        if telltale_proto::Header::parse(&resp).is_some_and(|h| h.flags.tc()) {
            return self.round(&b, &cert, query, true, left).await;
        }
        Ok(resp)
    }

    async fn round(
        &self,
        b: &Box2,
        cert: &Cert,
        query: &[u8],
        tcp: bool,
        timeout: Duration,
    ) -> Result<Vec<u8>, ExchangeError> {
        let half: [u8; 12] = rand::random();
        let mut nonce = [0u8; 24];
        nonce[..12].copy_from_slice(&half);
        let sealed = b
            .seal(&nonce, pad(query, if tcp { 0 } else { 256 }))
            .ok_or(ExchangeError::BadResponse)?;
        let mut packet = Vec::with_capacity(52 + sealed.len());
        packet.extend_from_slice(&cert.client_magic);
        packet.extend_from_slice(&self.public);
        packet.extend_from_slice(&half);
        packet.extend(sealed);
        let (to, packet) = match self.relay {
            Some(r) => (r, relayed(self.addr, &packet)),
            None => (self.addr, packet),
        };
        let raw = tokio::time::timeout(timeout, async {
            if tcp {
                tcp_round(to, &packet).await
            } else {
                udp_round(to, &packet, &half).await
            }
        })
        .await
        .map_err(|_| ExchangeError::Timeout)??;
        if raw.len() < 32 + TAG || &raw[..8] != RESOLVER_MAGIC || raw[8..20] != half {
            return Err(ExchangeError::BadResponse);
        }
        let n: [u8; 24] = raw[8..32]
            .try_into()
            .map_err(|_| ExchangeError::BadResponse)?;
        let plain = b.open(&n, &raw[32..]).ok_or(ExchangeError::BadResponse)?;
        unpad(plain).ok_or(ExchangeError::BadResponse)
    }
}

async fn udp_round(
    addr: SocketAddr,
    packet: &[u8],
    half: &[u8; 12],
) -> Result<Vec<u8>, ExchangeError> {
    let bind: SocketAddr = if addr.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let s = UdpSocket::bind(bind).await?;
    s.connect(addr).await?;
    s.send(packet).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = s.recv(&mut buf).await?;
        // Ignore anything that isn't an answer to this query (stray or spoofed).
        if n >= 20 && &buf[..8] == RESOLVER_MAGIC && buf[8..20] == *half {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

async fn tcp_round(addr: SocketAddr, packet: &[u8]) -> Result<Vec<u8>, ExchangeError> {
    let mut s = TcpStream::connect(addr).await?;
    let mut framed = Vec::with_capacity(packet.len() + 2);
    framed.extend_from_slice(
        &u16::try_from(packet.len())
            .map_err(|_| ExchangeError::BadResponse)?
            .to_be_bytes(),
    );
    framed.extend_from_slice(packet);
    s.write_all(&framed).await?;
    let mut lb = [0u8; 2];
    s.read_exact(&mut lb).await?;
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(lb))];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

/// A plain (unencrypted) query: the certificate fetch.
async fn plain_query(
    server: SocketAddr,
    relay: Option<SocketAddr>,
    name: &NameBuf,
    qtype: u16,
    timeout: Duration,
) -> Result<Vec<u8>, ExchangeError> {
    let id: u16 = rand::random();
    let mut buf = [0u8; 512];
    let edns = telltale_proto::EdnsOut {
        udp_payload: 1232,
        dnssec_ok: false,
        ede: None,
    };
    let len = telltale_proto::build_query(&mut buf, id, name, qtype, 1, true, Some(edns))
        .map_err(|_| ExchangeError::BadResponse)?;
    let q = &buf[..len];
    // REQ: UPS-003 (T9.9) — through the relay, the certificate query carries the header too.
    let (addr, sent) = match relay {
        Some(r) => (r, relayed(server, q)),
        None => (server, q.to_vec()),
    };
    let resp = tokio::time::timeout(timeout, async {
        let bind: SocketAddr = if addr.is_ipv4() {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let s = UdpSocket::bind(bind).await?;
        s.connect(addr).await?;
        s.send(&sent).await?;
        let mut r = vec![0u8; 4096];
        loop {
            let n = s.recv(&mut r).await?;
            if crate::upstream::matches_query(&r[..n], q, id) {
                r.truncate(n);
                return Ok::<_, ExchangeError>(r);
            }
        }
    })
    .await
    .map_err(|_| ExchangeError::Timeout)??;
    if telltale_proto::Header::parse(&resp).is_some_and(|h| h.flags.tc()) {
        // Certificates sets can be large: ask again over TCP.
        let mut s = TcpStream::connect(addr).await?;
        let mut framed = u16::try_from(sent.len())
            .unwrap_or(0)
            .to_be_bytes()
            .to_vec();
        framed.extend_from_slice(&sent);
        s.write_all(&framed).await?;
        let mut lb = [0u8; 2];
        s.read_exact(&mut lb).await?;
        let mut r = vec![0u8; usize::from(u16::from_be_bytes(lb))];
        s.read_exact(&mut r).await?;
        return Ok(r);
    }
    Ok(resp)
}

/// Each TXT record's data (its character-strings joined).
fn txt_records(msg: &[u8]) -> Vec<Vec<u8>> {
    let Ok(it) = telltale_proto::records(msg) else {
        return Vec::new();
    };
    it.flatten()
        .filter(|r| r.section == telltale_proto::Section::Answer && r.rtype == rtype::TXT)
        .map(|r| {
            let mut d = r.rdata(msg);
            let mut out = Vec::new();
            while let Some((&l, rest)) = d.split_first() {
                let l = usize::from(l).min(rest.len());
                out.extend_from_slice(&rest[..l]);
                d = &rest[l..];
            }
            out
        })
        .collect()
}

/// A test resolver's side of the protocol (tests here and in `tests/`).
#[doc(hidden)]
pub mod server {
    use super::{Box2, CERT_MAGIC, Construction, RESOLVER_MAGIC, pad, unpad};
    use crypto_box::SecretKey;
    use ed25519_dalek::Signer;

    /// A resolver key pair and its signed certificate.
    pub struct TestResolver {
        pub secret: SecretKey,
        pub provider: ed25519_dalek::SigningKey,
        pub cert: Vec<u8>,
        pub client_magic: [u8; 8],
        construction: Construction,
    }

    impl std::fmt::Debug for TestResolver {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TestResolver").finish_non_exhaustive()
        }
    }

    impl TestResolver {
        /// `xchacha`: es-version 2, else 1.
        pub fn new(xchacha: bool) -> Self {
            let secret = SecretKey::generate(&mut crypto_box::aead::OsRng);
            let provider = ed25519_dalek::SigningKey::from_bytes(&rand::random());
            let construction = if xchacha {
                Construction::XChaCha20Poly1305
            } else {
                Construction::XSalsa20Poly1305
            };
            let client_magic: [u8; 8] = rand::random();
            let now = super::unix_now();
            let mut signed = Vec::new();
            signed.extend_from_slice(secret.public_key().as_bytes());
            signed.extend_from_slice(&client_magic);
            signed.extend_from_slice(&7u32.to_be_bytes());
            signed.extend_from_slice(&(now - 60).to_be_bytes());
            signed.extend_from_slice(&(now + 86_400).to_be_bytes());
            let sig = provider.sign(&signed);
            let mut cert = CERT_MAGIC.to_vec();
            cert.extend_from_slice(&(construction as u16).to_be_bytes());
            cert.extend_from_slice(&0u16.to_be_bytes());
            cert.extend_from_slice(&sig.to_bytes());
            cert.extend(signed);
            Self {
                secret,
                provider,
                cert,
                client_magic,
                construction,
            }
        }

        /// Decrypts a query packet: (the DNS query, the client key, the client nonce half).
        pub fn open(&self, packet: &[u8]) -> Option<(Vec<u8>, [u8; 32], [u8; 12])> {
            if packet.len() < 52 || packet[..8] != self.client_magic {
                return None;
            }
            let pk: [u8; 32] = packet[8..40].try_into().ok()?;
            let half: [u8; 12] = packet[40..52].try_into().ok()?;
            let mut nonce = [0u8; 24];
            nonce[..12].copy_from_slice(&half);
            let b = Box2::new(self.construction, &pk, &self.secret);
            let q = unpad(b.open(&nonce, &packet[52..])?)?;
            Some((q, pk, half))
        }

        /// Encrypts a response for that client.
        pub fn seal(&self, resp: &[u8], pk: &[u8; 32], half: &[u8; 12]) -> Option<Vec<u8>> {
            let mut nonce = [0u8; 24];
            nonce[..12].copy_from_slice(half);
            nonce[12..].copy_from_slice(&rand::random::<[u8; 12]>());
            let b = Box2::new(self.construction, pk, &self.secret);
            let sealed = b.seal(&nonce, pad(resp, 0))?;
            let mut out = RESOLVER_MAGIC.to_vec();
            out.extend_from_slice(&nonce);
            out.extend(sealed);
            Some(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: UPS-003 — stamps: DNSCrypt (address, provider key, name), DoH, DoT.
    #[test]
    fn ups_003_stamps() {
        // Built here: 0x01, props, "127.0.0.1:5443", 32-byte key, "2.dnscrypt-cert.test".
        let mut raw = vec![0x01];
        raw.extend_from_slice(&1u64.to_le_bytes());
        for f in [
            b"127.0.0.1:5443".as_slice(),
            &[7u8; 32],
            b"2.dnscrypt-cert.test",
        ] {
            raw.push(u8::try_from(f.len()).unwrap());
            raw.extend_from_slice(f);
        }
        let stamp = format!("sdns://{}", b64url(&raw));
        let s = parse_stamp(&stamp).unwrap();
        assert_eq!(
            s,
            Stamp::DnsCrypt {
                addr: "127.0.0.1:5443".parse().unwrap(),
                provider_pk: [7u8; 32],
                provider_name: "2.dnscrypt-cert.test".into()
            }
        );
        // DoH: addr, empty hash set, hostname, path.
        let mut raw = vec![0x02];
        raw.extend_from_slice(&0u64.to_le_bytes());
        raw.extend_from_slice(&[7]);
        raw.extend_from_slice(b"9.9.9.9");
        raw.push(0);
        raw.push(13);
        raw.extend_from_slice(b"dns.quad9.net");
        raw.push(10);
        raw.extend_from_slice(b"/dns-query");
        assert_eq!(
            parse_stamp(&format!("sdns://{}", b64url(&raw))).unwrap(),
            Stamp::Doh {
                addr: Some("9.9.9.9".into()),
                hostname: "dns.quad9.net".into(),
                port: 443,
                path: "/dns-query".into(),
                hashes: vec![],
            }
        );
        // REQ: UPS-003 (T9.17) — DoT with two certificate hashes (the first flagged "more").
        let mut raw = vec![0x03];
        raw.extend_from_slice(&0u64.to_le_bytes());
        raw.push(0);
        raw.push(0x80 | 32);
        raw.extend_from_slice(&[1u8; 32]);
        raw.push(32);
        raw.extend_from_slice(&[2u8; 32]);
        raw.push(15);
        raw.extend_from_slice(b"dns.example:853");
        assert_eq!(
            parse_stamp(&format!("sdns://{}", b64url(&raw))).unwrap(),
            Stamp::Dot {
                addr: None,
                hostname: "dns.example".into(),
                port: 853,
                quic: false,
                hashes: vec![[1u8; 32], [2u8; 32]],
            }
        );
        // A hash that isn't 32 bytes.
        let mut bad = vec![0x03];
        bad.extend_from_slice(&0u64.to_le_bytes());
        bad.extend_from_slice(&[0, 3, 1, 2, 3, 3]);
        bad.extend_from_slice(b"x.y");
        assert!(parse_stamp(&format!("sdns://{}", b64url(&bad))).is_err());
        assert!(parse_stamp("sdns://AAAA").is_err());
        assert!(parse_stamp("https://x").is_err());
    }

    fn b64url(b: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut s = String::new();
        for c in b.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..=c.len() {
                s.push(char::from(
                    T[usize::try_from((n >> (18 - 6 * i)) & 63).unwrap()],
                ));
            }
        }
        s
    }

    /// REQ: UPS-003 — padding round trip and the certificate check (signature, dates).
    #[test]
    fn ups_003_padding_and_certs() {
        let p = pad(b"abc", 256);
        assert_eq!((p.len(), p[3]), (256, 0x80));
        assert_eq!(unpad(p).unwrap(), b"abc");
        assert_eq!(pad(&[1u8; 63], 0).len(), 64);
        assert_eq!(pad(&[1u8; 64], 0).len(), 128);
        let r = server::TestResolver::new(true);
        let vk = r.provider.verifying_key();
        let c = parse_cert(&r.cert, &vk, unix_now()).unwrap();
        assert_eq!(
            (c.construction, c.serial, c.client_magic),
            (Construction::XChaCha20Poly1305, 7, r.client_magic)
        );
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(
            parse_cert(&r.cert, &other, unix_now()).is_none(),
            "another provider's key"
        );
        assert!(
            parse_cert(&r.cert, &vk, unix_now() + 2 * 86_400).is_none(),
            "expired"
        );
    }
}
