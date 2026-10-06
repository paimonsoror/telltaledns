//! DNS over QUIC upstreams (REQ: UPS-002, RFC 9250; T7.7): `quic://host[:853]`.
//!
//! One QUIC connection per upstream, opened on first use and again after it closes (idle,
//! error, server restart); one bidirectional stream per query, so queries never wait on each
//! other. 0-RTT stays off: an early query could be replayed (`spec/04` §2).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::ServerName;
use tokio::sync::Mutex;

use crate::upstream::ExchangeError;

/// A query's length prefix plus the largest DNS message.
const MAX_RESPONSE: usize = 2 + 65_535;

/// Where to connect, resolved per connection (hostnames through bootstrap).
pub(crate) type Resolve = Arc<
    dyn Fn() -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<SocketAddr, ExchangeError>> + Send>,
        > + Send
        + Sync,
>;

pub(crate) struct Doq {
    resolve: Resolve,
    client: quinn::ClientConfig,
    name: String,
    /// The client endpoints (one per address family), made on first use: they need a runtime.
    endpoints: Mutex<[Option<quinn::Endpoint>; 2]>,
    conn: Mutex<Option<quinn::Connection>>,
}

impl std::fmt::Debug for Doq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Doq")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Doq {
    pub(crate) fn new(
        resolve: Resolve,
        tls: Arc<rustls::ClientConfig>,
        name: &ServerName<'static>,
        idle: Duration,
    ) -> Result<Self, String> {
        let crypto =
            QuicClientConfig::try_from(tls).map_err(|e| format!("DoQ needs TLS 1.3: {e}"))?;
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_idle_timeout(quinn::IdleTimeout::try_from(idle).ok())
            .keep_alive_interval(None);
        client.transport_config(Arc::new(transport));
        Ok(Self {
            resolve,
            client,
            name: name.to_str().into_owned(),
            endpoints: Mutex::new([None, None]),
            conn: Mutex::new(None),
        })
    }

    /// The open connection, or a new one.
    async fn connection(&self) -> Result<quinn::Connection, ExchangeError> {
        let mut slot = self.conn.lock().await;
        if let Some(c) = slot.as_ref().filter(|c| c.close_reason().is_none()) {
            return Ok(c.clone());
        }
        let addr = (self.resolve)().await?;
        let endpoint = {
            let mut eps = self.endpoints.lock().await;
            let i = usize::from(addr.is_ipv6());
            if eps[i].is_none() {
                let bind: SocketAddr = if addr.is_ipv6() {
                    (Ipv6Addr::UNSPECIFIED, 0).into()
                } else {
                    (Ipv4Addr::UNSPECIFIED, 0).into()
                };
                eps[i] = Some(quinn::Endpoint::client(bind)?);
            }
            eps[i].clone().ok_or(ExchangeError::Unresolved)?
        };
        let conn = endpoint
            .connect_with(self.client.clone(), addr, &self.name)
            .map_err(|e| ExchangeError::Io(std::io::Error::other(e.to_string())))?
            .await
            .map_err(|e| ExchangeError::Io(std::io::Error::other(e.to_string())))?;
        *slot = Some(conn.clone());
        Ok(conn)
    }

    /// One query (its ID already 0) and its answer.
    pub(crate) async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, ExchangeError> {
        let io =
            |e: &dyn std::fmt::Display| ExchangeError::Io(std::io::Error::other(e.to_string()));
        let len = u16::try_from(query.len()).map_err(|_| ExchangeError::BadResponse)?;
        let conn = self.connection().await?;
        let (mut send, mut recv) = match conn.open_bi().await {
            Ok(s) => s,
            Err(e) => {
                // The connection went away between checks: forget it so the next query reconnects.
                *self.conn.lock().await = None;
                return Err(io(&e));
            }
        };
        let mut framed = Vec::with_capacity(2 + query.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(query);
        send.write_all(&framed).await.map_err(|e| io(&e))?;
        send.finish().map_err(|e| io(&e))?;
        let data = recv.read_to_end(MAX_RESPONSE).await.map_err(|e| io(&e))?;
        let (n, msg) = data
            .split_first_chunk::<2>()
            .ok_or(ExchangeError::BadResponse)?;
        if usize::from(u16::from_be_bytes(*n)) != msg.len() {
            return Err(ExchangeError::BadResponse);
        }
        Ok(msg.to_vec())
    }
}
