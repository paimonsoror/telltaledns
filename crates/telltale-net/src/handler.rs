//! The transport-independent query handler interface.
//!
//! `spec/02` §3: every transport calls the same synchronous `handle()` first. Answers that
//! need I/O (cache misses) come back as a future that the transport drives and replies from
//! later — UDP through the worker's socket, TCP out of order on the same connection.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use crate::udp::LocalAddr;

/// Which transport a query arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
    /// DNS over TLS.
    Dot,
    /// DNS over HTTPS (one request per HTTP exchange).
    Doh,
}

/// Facts about a request that the pipeline may need.
#[derive(Clone, Copy, Debug)]
pub struct RequestMeta {
    pub peer: SocketAddr,
    /// Destination address of the packet (UDP wildcard binds only).
    pub local: Option<LocalAddr>,
    pub transport: Transport,
    /// Client ID from the DoT SNI or the DoH path (FLT-006), if any.
    pub client_id: Option<ClientId>,
}

/// A client ID (one DNS label: letters, digits, `-`, at most 63 bytes), stored inline so
/// [`RequestMeta`] stays `Copy` and allocation-free.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClientId {
    len: u8,
    bytes: [u8; 63],
}

impl ClientId {
    /// Lowercases `s`; `None` unless it's a valid label.
    pub fn new(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        let ok = !b.is_empty()
            && b.len() <= 63
            && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
            && b[0] != b'-'
            && b[b.len() - 1] != b'-';
        if !ok {
            return None;
        }
        let mut bytes = [0u8; 63];
        for (d, s) in bytes.iter_mut().zip(b) {
            *d = s.to_ascii_lowercase();
        }
        Some(Self {
            len: u8::try_from(b.len()).ok()?,
            bytes,
        })
    }

    pub fn as_str(&self) -> &str {
        // Built from ASCII only.
        std::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or_default()
    }
}

impl std::fmt::Debug for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClientId({})", self.as_str())
    }
}

/// A response produced later; resolves to the full response message, or `None` to drop.
pub type Deferred = Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'static>>;

/// What to do with a request.
pub enum Response {
    /// The response is in `out[..len]`; send it now.
    Ready(usize),
    /// The response will come from this future (e.g. after an upstream round trip).
    Deferred(Deferred),
    /// Send nothing.
    Drop,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready(n) => write!(f, "Ready({n})"),
            Self::Deferred(_) => f.write_str("Deferred(..)"),
            Self::Drop => f.write_str("Drop"),
        }
    }
}

/// Handles DNS messages for every transport. `handle` runs on hot-path threads and must not
/// block; put waiting work in a [`Response::Deferred`] future.
pub trait QueryHandler: Send + Sync + 'static {
    fn handle(&self, req: &[u8], meta: &RequestMeta, out: &mut [u8]) -> Response;
}

impl<F> QueryHandler for F
where
    F: Fn(&[u8], &RequestMeta, &mut [u8]) -> Response + Send + Sync + 'static,
{
    fn handle(&self, req: &[u8], meta: &RequestMeta, out: &mut [u8]) -> Response {
        self(req, meta, out)
    }
}
