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
}

/// Facts about a request that the pipeline may need.
#[derive(Clone, Copy, Debug)]
pub struct RequestMeta {
    pub peer: SocketAddr,
    /// Destination address of the packet (UDP wildcard binds only).
    pub local: Option<LocalAddr>,
    pub transport: Transport,
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
