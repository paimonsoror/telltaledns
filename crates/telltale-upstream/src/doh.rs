//! DNS over HTTPS upstreams (RFC 8484) over HTTP/2.
//!
//! REQ: UPS-001, UPS-008 — one HTTP/2 connection per upstream multiplexes every in-flight
//! query as its own stream; it is re-established on failure.

use std::io;

use bytes::Bytes;
use h2::client::SendRequest;
use http::{HeaderName, HeaderValue, Method, Request};
use tokio::sync::Mutex;

use crate::conn::Connector;
use crate::upstream::ExchangeError;

const DNS_MESSAGE: &str = "application/dns-message";

pub(crate) struct Doh {
    connector: Connector,
    uri: String,
    /// REQ: UPS-011 (T9.9) — GET with `?dns=` instead of POST.
    get: bool,
    headers: Vec<(HeaderName, HeaderValue)>,
    sender: Mutex<Option<SendRequest<Bytes>>>,
}

impl std::fmt::Debug for Doh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Doh")
            .field("uri", &self.uri)
            .finish_non_exhaustive()
    }
}

fn io_err(e: impl std::fmt::Display) -> ExchangeError {
    ExchangeError::Io(io::Error::other(e.to_string()))
}

impl Doh {
    /// `authority` is the HTTP host (the URL host, or `tls_server_name`).
    pub(crate) fn new(
        connector: Connector,
        authority: &str,
        path: &str,
        headers: &[(String, String)],
        get: bool,
    ) -> Result<Self, String> {
        let mut hs = Vec::new();
        for (k, v) in headers {
            let name =
                HeaderName::try_from(k.as_str()).map_err(|e| format!("header `{k}`: {e}"))?;
            let value =
                HeaderValue::try_from(v.as_str()).map_err(|e| format!("header `{k}`: {e}"))?;
            hs.push((name, value));
        }
        Ok(Self {
            connector,
            uri: format!("https://{authority}{path}"),
            get,
            headers: hs,
            sender: Mutex::new(None),
        })
    }

    async fn ready_sender(&self, fresh: bool) -> Result<SendRequest<Bytes>, ExchangeError> {
        let mut guard = self.sender.lock().await;
        if !fresh && let Some(s) = guard.as_ref() {
            return Ok(s.clone());
        }
        let io = (self.connector)().await?;
        let (send, conn) = h2::client::handshake(io).await.map_err(io_err)?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        *guard = Some(send.clone());
        Ok(send)
    }

    /// POSTs `query` (ID 0 per RFC 8484 §4.1) and returns the response body.
    pub(crate) async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, ExchangeError> {
        let body = Bytes::copy_from_slice(query);
        for attempt in 0..2 {
            let sender = self.ready_sender(attempt > 0).await?;
            match self.send(sender, body.clone()).await {
                Ok(v) => return Ok(v),
                // A broken connection (GOAWAY, reset) gets one retry on a new one.
                Err(SendError::Connection(_)) if attempt == 0 => {}
                Err(SendError::Connection(e) | SendError::Other(e)) => return Err(e),
            }
        }
        Err(io_err("DoH connection failed"))
    }

    async fn send(&self, sender: SendRequest<Bytes>, body: Bytes) -> Result<Vec<u8>, SendError> {
        let mut sender = sender
            .ready()
            .await
            .map_err(|e| SendError::Connection(io_err(e)))?;
        let builder = if self.get {
            // RFC 8484 §4.1: base64url without padding, in `dns=`.
            let sep = if self.uri.contains('?') { '&' } else { '?' };
            Request::builder()
                .method(Method::GET)
                .uri(format!("{}{sep}dns={}", self.uri, b64url(&body)))
                .header(http::header::ACCEPT, DNS_MESSAGE)
        } else {
            Request::builder()
                .method(Method::POST)
                .uri(&self.uri)
                .header(http::header::CONTENT_TYPE, DNS_MESSAGE)
                .header(http::header::ACCEPT, DNS_MESSAGE)
                .header(http::header::CONTENT_LENGTH, body.len())
        };
        let mut req = builder.body(()).map_err(|e| SendError::Other(io_err(e)))?;
        for (k, v) in &self.headers {
            req.headers_mut().insert(k.clone(), v.clone());
        }
        let (resp, mut stream) = sender
            .send_request(req, self.get)
            .map_err(|e| SendError::Connection(io_err(e)))?;
        if !self.get {
            stream
                .send_data(body, true)
                .map_err(|e| SendError::Connection(io_err(e)))?;
        }
        let resp = resp.await.map_err(|e| SendError::Connection(io_err(e)))?;
        if resp.status() != http::StatusCode::OK {
            return Err(SendError::Other(io_err(format!("HTTP {}", resp.status()))));
        }
        let mut body = resp.into_body();
        let mut out = Vec::with_capacity(512);
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(|e| SendError::Other(io_err(e)))?;
            let _ = body.flow_control().release_capacity(chunk.len());
            if out.len() + chunk.len() > usize::from(u16::MAX) {
                return Err(SendError::Other(ExchangeError::BadResponse));
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

/// URL-safe base64 without padding (RFC 4648 §5).
fn b64url(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            s.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    s
}

enum SendError {
    Connection(ExchangeError),
    Other(ExchangeError),
}
