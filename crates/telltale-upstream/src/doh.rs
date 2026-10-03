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
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(&self.uri)
            .header(http::header::CONTENT_TYPE, DNS_MESSAGE)
            .header(http::header::ACCEPT, DNS_MESSAGE)
            .header(http::header::CONTENT_LENGTH, body.len())
            .body(())
            .map_err(|e| SendError::Other(io_err(e)))?;
        for (k, v) in &self.headers {
            req.headers_mut().insert(k.clone(), v.clone());
        }
        let (resp, mut stream) = sender
            .send_request(req, false)
            .map_err(|e| SendError::Connection(io_err(e)))?;
        stream
            .send_data(body, true)
            .map_err(|e| SendError::Connection(io_err(e)))?;
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

enum SendError {
    Connection(ExchangeError),
    Other(ExchangeError),
}
