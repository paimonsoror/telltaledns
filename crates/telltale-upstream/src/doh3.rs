//! DNS over HTTPS over HTTP/3 upstreams (REQ: UPS-002; T7.8): `h3://host/path`, or an
//! `https://` upstream with `http_version = "3"`.
//!
//! One QUIC connection per upstream with an HTTP/3 session on it, opened on first use and again
//! after it closes; every query is its own request (`POST application/dns-message`, ID 0), so
//! they run side by side.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::ServerName;
use tokio::sync::Mutex;

use crate::doq::{Endpoints, Resolve};
use crate::upstream::ExchangeError;

const DNS_MESSAGE: &str = "application/dns-message";
const MAX_RESPONSE: usize = 65_535;

type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

pub(crate) struct Doh3 {
    resolve: Resolve,
    client: quinn::ClientConfig,
    name: String,
    uri: String,
    headers: Vec<(http::HeaderName, http::HeaderValue)>,
    endpoints: Endpoints,
    session: Mutex<Option<(quinn::Connection, Sender)>>,
}

impl std::fmt::Debug for Doh3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Doh3")
            .field("uri", &self.uri)
            .finish_non_exhaustive()
    }
}

fn io(e: &dyn std::fmt::Display) -> ExchangeError {
    ExchangeError::Io(std::io::Error::other(e.to_string()))
}

impl Doh3 {
    pub(crate) fn new(
        resolve: Resolve,
        tls: Arc<rustls::ClientConfig>,
        name: &ServerName<'static>,
        authority: &str,
        path: &str,
        headers: &[(String, String)],
        idle: Duration,
    ) -> Result<Self, String> {
        let crypto =
            QuicClientConfig::try_from(tls).map_err(|e| format!("HTTP/3 needs TLS 1.3: {e}"))?;
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(quinn::IdleTimeout::try_from(idle).ok());
        client.transport_config(Arc::new(transport));
        let headers = headers
            .iter()
            .map(|(k, v)| {
                Ok((
                    http::HeaderName::try_from(k.as_str())
                        .map_err(|e| format!("header `{k}`: {e}"))?,
                    http::HeaderValue::try_from(v.as_str())
                        .map_err(|e| format!("header `{k}`: {e}"))?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self {
            resolve,
            client,
            name: name.to_str().into_owned(),
            uri: format!("https://{authority}{path}"),
            headers,
            endpoints: Endpoints::default(),
            session: Mutex::new(None),
        })
    }

    /// The open HTTP/3 session, or a new one.
    async fn sender(&self) -> Result<Sender, ExchangeError> {
        let mut slot = self.session.lock().await;
        if let Some((c, s)) = slot.as_ref()
            && c.close_reason().is_none()
        {
            return Ok(s.clone());
        }
        let addr: SocketAddr = (self.resolve)().await?;
        let endpoint = self.endpoints.for_addr(addr).await?;
        let conn = endpoint
            .connect_with(self.client.clone(), addr, &self.name)
            .map_err(|e| io(&e))?
            .await
            .map_err(|e| io(&e))?;
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .map_err(|e| io(&e))?;
        // The session's own work (settings, GOAWAY); it ends when the connection does.
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        *slot = Some((conn, send.clone()));
        Ok(send)
    }

    /// One query (ID 0) and its answer.
    pub(crate) async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, ExchangeError> {
        let mut send = self.sender().await?;
        let mut req = http::Request::post(&self.uri)
            .header(http::header::CONTENT_TYPE, DNS_MESSAGE)
            .header(http::header::ACCEPT, DNS_MESSAGE);
        for (k, v) in &self.headers {
            req = req.header(k, v);
        }
        let req = req.body(()).map_err(|e| io(&e))?;
        let mut stream = match send.send_request(req).await {
            Ok(s) => s,
            Err(e) => {
                *self.session.lock().await = None;
                return Err(io(&e));
            }
        };
        stream
            .send_data(Bytes::copy_from_slice(query))
            .await
            .map_err(|e| io(&e))?;
        stream.finish().await.map_err(|e| io(&e))?;
        let resp = stream.recv_response().await.map_err(|e| io(&e))?;
        if resp.status() != http::StatusCode::OK {
            return Err(ExchangeError::BadResponse);
        }
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.map_err(|e| io(&e))? {
            if body.len() + chunk.remaining() > MAX_RESPONSE {
                return Err(ExchangeError::BadResponse);
            }
            while chunk.has_remaining() {
                let part = chunk.chunk();
                body.extend_from_slice(part);
                let n = part.len();
                chunk.advance(n);
            }
        }
        Ok(body)
    }
}
