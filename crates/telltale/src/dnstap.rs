//! dnstap output (REQ: OBS-007, `spec/06` §5; T7.18): client queries and responses as dnstap
//! messages (`CLIENT_QUERY`, `CLIENT_RESPONSE`) over Frame Streams, to a Unix socket or TCP
//! (`dnstap-read`, `fstrm_capture`, Vector, Logstash and others read it).
//!
//! The query path pays one relaxed atomic load while dnstap is off. When it's on, one query in
//! `sample_every` is copied (its query and response messages) into a bounded queue with
//! `try_send`; a full queue drops the copy (counted), never the query. A writer thread speaks
//! Frame Streams (the bidirectional handshake: READY → ACCEPT → START) and reconnects with
//! backoff when the reader goes away.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use telltale_net::Transport;
use tracing::{info, warn};

const CONTENT_TYPE: &[u8] = b"protobuf:dnstap.Dnstap";

/// Control frame types (Frame Streams).
const ACCEPT: u32 = 1;
const START: u32 = 2;
const STOP: u32 = 3;
const READY: u32 = 4;
const FIELD_CONTENT_TYPE: u32 = 1;

/// dnstap `Message.Type`.
const CLIENT_QUERY: u64 = 5;
const CLIENT_RESPONSE: u64 = 6;

/// One sampled exchange.
struct Copy {
    peer: IpAddr,
    transport: Transport,
    query: Vec<u8>,
    response: Option<Vec<u8>>,
    /// Wall clock of the query and of the response, in nanoseconds since the epoch.
    query_ns: u128,
    response_ns: u128,
}

/// The query path's handle: sampling and the queue.
pub(crate) struct Tap {
    every: u64,
    seen: AtomicU64,
    tx: SyncSender<Copy>,
    pub(crate) dropped: AtomicU64,
}

impl std::fmt::Debug for Tap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tap")
            .field("every", &self.every)
            .finish_non_exhaustive()
    }
}

fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}

impl Tap {
    /// Offers one answered (or dropped) query; copies it if it's sampled.
    pub(crate) fn offer(
        &self,
        peer: IpAddr,
        transport: Transport,
        query: &[u8],
        response: Option<&[u8]>,
        query_us: u64,
    ) {
        if !self
            .seen
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(self.every)
        {
            return;
        }
        let c = Copy {
            peer,
            transport,
            query: query.to_vec(),
            response: response.map(<[u8]>::to_vec),
            query_ns: u128::from(query_us) * 1000,
            response_ns: now_ns(),
        };
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) = self.tx.try_send(c) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Starts the writer for `[telemetry.dnstap]`, if configured.
pub(crate) fn start(cfg: &telltale_config::Config) -> Option<std::sync::Arc<Tap>> {
    let d = &cfg.telemetry.dnstap;
    let target = match (&d.socket, &d.address) {
        (Some(s), _) => Target::Unix(s.to_string()),
        (None, Some(a)) => Target::Tcp(a.trim_start_matches("tcp://").to_owned()),
        (None, None) => return None,
    };
    let (tx, rx) = sync_channel::<Copy>(usize::try_from(d.buffer).unwrap_or(10_000));
    let identity = crate::http::node_name(cfg);
    let spawned = std::thread::Builder::new()
        .name("dnstap".into())
        .spawn(move || writer(&target, &rx, identity.as_bytes()));
    if let Err(e) = spawned {
        warn!("dnstap disabled: cannot start its thread: {e}");
        return None;
    }
    info!(sample_every = d.sample_every, "dnstap output started");
    Some(std::sync::Arc::new(Tap {
        every: u64::from(d.sample_every.max(1)),
        seen: AtomicU64::new(0),
        tx,
        dropped: AtomicU64::new(0),
    }))
}

#[derive(Debug, Clone)]
enum Target {
    Unix(String),
    Tcp(String),
}

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

fn connect(t: &Target) -> std::io::Result<Box<dyn Stream>> {
    let mut s: Box<dyn Stream> = match t {
        Target::Unix(p) => {
            let s = std::os::unix::net::UnixStream::connect(p)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            Box::new(s)
        }
        Target::Tcp(a) => {
            let s = TcpStream::connect(a)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            s.set_nodelay(true)?;
            Box::new(s)
        }
    };
    // Bidirectional handshake: READY (our content type), the reader's ACCEPT, then START.
    s.write_all(&control(READY, true))?;
    let accepted = read_control(&mut s)?;
    if accepted != ACCEPT {
        return Err(std::io::Error::other(format!(
            "expected ACCEPT, got control frame {accepted}"
        )));
    }
    s.write_all(&control(START, true))?;
    Ok(s)
}

/// A control frame: escape (0), length, type, and the content-type field.
fn control(kind: u32, with_type: bool) -> Vec<u8> {
    let mut body = kind.to_be_bytes().to_vec();
    if with_type {
        body.extend_from_slice(&FIELD_CONTENT_TYPE.to_be_bytes());
        body.extend_from_slice(&u32::try_from(CONTENT_TYPE.len()).unwrap_or(0).to_be_bytes());
        body.extend_from_slice(CONTENT_TYPE);
    }
    let mut f = 0u32.to_be_bytes().to_vec();
    f.extend_from_slice(&u32::try_from(body.len()).unwrap_or(0).to_be_bytes());
    f.extend(body);
    f
}

/// Reads one control frame and returns its type.
fn read_control(s: &mut dyn Stream) -> std::io::Result<u32> {
    let mut w = [0u8; 4];
    s.read_exact(&mut w)?;
    if u32::from_be_bytes(w) != 0 {
        return Err(std::io::Error::other("expected a control frame"));
    }
    s.read_exact(&mut w)?;
    let len = u32::from_be_bytes(w) as usize;
    if !(4..=512).contains(&len) {
        return Err(std::io::Error::other("bad control frame length"));
    }
    let mut body = vec![0u8; len];
    s.read_exact(&mut body)?;
    Ok(u32::from_be_bytes([body[0], body[1], body[2], body[3]]))
}

fn writer(target: &Target, rx: &Receiver<Copy>, identity: &[u8]) {
    let version = format!("TelltaleDNS {}", crate::build_info::VERSION);
    let mut conn: Option<Box<dyn Stream>> = None;
    let mut backoff = Duration::from_secs(1);
    let mut next_try = std::time::Instant::now();
    let mut warned = false;
    loop {
        let c = match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(c) => Some(c),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if conn.is_none() && std::time::Instant::now() >= next_try {
            match connect(target) {
                Ok(s) => {
                    info!(?target, "dnstap: connected");
                    conn = Some(s);
                    backoff = Duration::from_secs(1);
                    warned = false;
                }
                Err(e) => {
                    if !warned {
                        warn!(?target, error = %e, "dnstap: can't reach the reader; retrying (copies are dropped meanwhile)");
                        warned = true;
                    }
                    next_try = std::time::Instant::now() + backoff;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
        let (Some(c), Some(s)) = (c, conn.as_mut()) else {
            continue;
        };
        let mut frames = Vec::with_capacity(1024);
        for kind in [CLIENT_QUERY, CLIENT_RESPONSE] {
            if kind == CLIENT_RESPONSE && c.response.is_none() {
                continue;
            }
            let payload = dnstap(identity, version.as_bytes(), kind, &c);
            frames.extend_from_slice(&u32::try_from(payload.len()).unwrap_or(0).to_be_bytes());
            frames.extend(payload);
        }
        if s.write_all(&frames).is_err() {
            conn = None;
        }
    }
    if let Some(mut s) = conn {
        let _ = s.write_all(&control(STOP, false));
    }
}

// Protobuf encoding, by hand (the dnstap schema is small and fixed).
fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push(u8::try_from(v & 0x7f).unwrap_or(0) | 0x80);
        v >>= 7;
    }
    out.push(u8::try_from(v).unwrap_or(0));
}
fn key(out: &mut Vec<u8>, field: u32, wire: u8) {
    varint(out, (u64::from(field) << 3) | u64::from(wire));
}
fn bytes(out: &mut Vec<u8>, field: u32, b: &[u8]) {
    key(out, field, 2);
    varint(out, b.len() as u64);
    out.extend_from_slice(b);
}
fn uint(out: &mut Vec<u8>, field: u32, v: u64) {
    key(out, field, 0);
    varint(out, v);
}
fn fixed32(out: &mut Vec<u8>, field: u32, v: u32) {
    key(out, field, 5);
    out.extend_from_slice(&v.to_le_bytes());
}

/// One `Dnstap` message wrapping a `Message` of `kind`.
fn dnstap(identity: &[u8], version: &[u8], kind: u64, c: &Copy) -> Vec<u8> {
    let mut m = Vec::with_capacity(64 + c.query.len() + c.response.as_ref().map_or(0, Vec::len));
    uint(&mut m, 1, kind);
    let (family, addr) = match c.peer {
        IpAddr::V4(v4) => (1, v4.octets().to_vec()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => (1, v4.octets().to_vec()),
            None => (2, v6.octets().to_vec()),
        },
    };
    uint(&mut m, 2, family);
    // SocketProtocol: UDP 1, TCP 2, DOT 3, DOH 4, DOQ 7.
    let proto = match c.transport {
        Transport::Udp => 1,
        Transport::Tcp => 2,
        Transport::Dot => 3,
        Transport::Doh => 4,
        Transport::Doq => 7,
    };
    uint(&mut m, 3, proto);
    bytes(&mut m, 4, &addr);
    let secs = |ns: u128| u64::try_from(ns / 1_000_000_000).unwrap_or(0);
    let nanos = |ns: u128| u32::try_from(ns % 1_000_000_000).unwrap_or(0);
    uint(&mut m, 8, secs(c.query_ns));
    fixed32(&mut m, 9, nanos(c.query_ns));
    bytes(&mut m, 10, &c.query);
    if kind == CLIENT_RESPONSE
        && let Some(r) = &c.response
    {
        uint(&mut m, 12, secs(c.response_ns));
        fixed32(&mut m, 13, nanos(c.response_ns));
        bytes(&mut m, 14, r);
    }
    let mut d = Vec::with_capacity(m.len() + 64);
    bytes(&mut d, 1, identity);
    bytes(&mut d, 2, version);
    bytes(&mut d, 14, &m);
    uint(&mut d, 15, 1); // Dnstap.Type MESSAGE
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal protobuf reader for the test: (field, wire, value bytes / varint).
    #[allow(clippy::many_single_char_names)]
    fn fields(mut b: &[u8]) -> Vec<(u32, Vec<u8>, u64)> {
        let mut out = Vec::new();
        let rd = |b: &mut &[u8]| {
            let mut v = 0u64;
            let mut shift = 0;
            loop {
                let x = b[0];
                *b = &b[1..];
                v |= u64::from(x & 0x7f) << shift;
                if x & 0x80 == 0 {
                    return v;
                }
                shift += 7;
            }
        };
        while !b.is_empty() {
            let k = rd(&mut b);
            let (f, w) = (u32::try_from(k >> 3).unwrap(), k & 7);
            match w {
                0 => {
                    let v = rd(&mut b);
                    out.push((f, Vec::new(), v));
                }
                2 => {
                    let n = usize::try_from(rd(&mut b)).unwrap();
                    out.push((f, b[..n].to_vec(), 0));
                    b = &b[n..];
                }
                5 => {
                    out.push((f, b[..4].to_vec(), 0));
                    b = &b[4..];
                }
                _ => panic!("wire type {w}"),
            }
        }
        out
    }

    /// REQ: OBS-007 — the Frame Streams handshake, then `CLIENT_QUERY` and `CLIENT_RESPONSE`
    /// messages carrying the client, the transport, and both wire messages; sampling.
    #[test]
    fn obs_007_dnstap_over_frame_streams() {
        let dir = std::env::temp_dir().join(format!("tt-dnstap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dnstap.sock");
        let l = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let reader = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut s: &mut dyn Stream = &mut s;
            assert_eq!(read_control(s).unwrap(), READY);
            s.write_all(&control(ACCEPT, true)).unwrap();
            assert_eq!(read_control(s).unwrap(), START);
            let mut msgs = Vec::new();
            for _ in 0..2 {
                let mut l = [0u8; 4];
                s.read_exact(&mut l).unwrap();
                let mut f = vec![0u8; u32::from_be_bytes(l) as usize];
                s.read_exact(&mut f).unwrap();
                msgs.push(f);
            }
            let _ = &mut s;
            msgs
        });
        let mut cfg = telltale_config::Config::default();
        cfg.telemetry.dnstap.socket =
            Some(telltale_config::SafeString::new(path.to_str().unwrap()).unwrap());
        cfg.telemetry.dnstap.sample_every = 2;
        let tap = start(&cfg).unwrap();
        let q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01".to_vec();
        let mut r = q.clone();
        r[2] = 0x81;
        let peer: IpAddr = "192.168.1.5".parse().unwrap();
        // The writer connects on its first loop: give it a moment, then offer 3 (2 sampled).
        std::thread::sleep(Duration::from_millis(200));
        tap.offer(peer, Transport::Dot, &q, Some(&r), 1_700_000_000_000_000);
        tap.offer(peer, Transport::Dot, &q, Some(&r), 1_700_000_000_000_000);
        let msgs = reader.join().unwrap();
        for (i, m) in msgs.iter().enumerate() {
            let top = fields(m);
            assert_eq!(
                top.iter().find(|x| x.0 == 15).unwrap().2,
                1,
                "Dnstap.Type MESSAGE"
            );
            let inner = fields(&top.iter().find(|x| x.0 == 14).unwrap().1);
            let get = |f: u32| inner.iter().find(|x| x.0 == f).unwrap();
            let kind = get(1).2;
            assert_eq!(
                kind,
                if i == 0 {
                    CLIENT_QUERY
                } else {
                    CLIENT_RESPONSE
                }
            );
            assert_eq!((get(2).2, get(3).2), (1, 3), "INET, DOT");
            assert_eq!(get(4).1, vec![192, 168, 1, 5]);
            assert_eq!(get(8).2, 1_700_000_000, "query time");
            assert_eq!(get(10).1, q);
            if kind == CLIENT_RESPONSE {
                assert_eq!(get(14).1, r);
            }
        }
        assert_eq!(tap.seen.load(Ordering::Relaxed), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
