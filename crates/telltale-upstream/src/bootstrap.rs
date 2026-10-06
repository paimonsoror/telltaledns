//! Bootstrap resolution for hostname upstreams (`tls://dns.quad9.net`).
//!
//! REQ: UPS-009 — hostnames resolve through bootstrap DNS servers (per upstream `bootstrap`,
//! else the system resolvers from `/etc/resolv.conf`), never through ourselves. Results are
//! cached for their TTL (clamped to 1 min – 1 h).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use telltale_proto::{NameBuf, Section, records, rtype};
use tokio::net::UdpSocket;

use crate::upstream::{ExchangeError, Question, encode_query, matches_query};

const MIN_TTL: u32 = 60;
const MAX_TTL: u32 = 3600;
const TIMEOUT: Duration = Duration::from_secs(2);

/// Resolves upstream hostnames via plain DNS to a fixed set of servers.
#[derive(Debug)]
pub struct Bootstrap {
    servers: Vec<SocketAddr>,
    cache: Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>,
}

impl Bootstrap {
    pub fn new(servers: Vec<SocketAddr>) -> Self {
        Self {
            servers,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Uses the `nameserver` lines of `/etc/resolv.conf`, minus any address in `exclude`
    /// (our own listeners — resolving our upstreams through ourselves would loop).
    pub fn system(exclude: &[SocketAddr]) -> Self {
        let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        Self::new(parse_resolv_conf(&text, exclude))
    }

    pub fn servers(&self) -> &[SocketAddr] {
        &self.servers
    }

    /// IPv4 addresses first, then IPv6.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ExchangeError> {
        if let Some((ips, exp)) = self.cache.lock().get(host)
            && Instant::now() < *exp
        {
            return Ok(ips.clone());
        }
        let name = NameBuf::from_presentation(host).map_err(|_| ExchangeError::Unresolved)?;
        let mut ips = Vec::new();
        let mut ttl = MAX_TTL;
        for qtype in [rtype::A, rtype::AAAA] {
            if let Ok((found, t)) = self.query(name, qtype).await {
                ips.extend(found);
                ttl = ttl.min(t);
            }
        }
        if ips.is_empty() {
            return Err(ExchangeError::Unresolved);
        }
        let ttl = Duration::from_secs(u64::from(ttl.clamp(MIN_TTL, MAX_TTL)));
        self.cache
            .lock()
            .insert(host.to_owned(), (ips.clone(), Instant::now() + ttl));
        Ok(ips)
    }

    async fn query(&self, name: NameBuf, qtype: u16) -> Result<(Vec<IpAddr>, u32), ExchangeError> {
        let q = Question {
            name,
            qtype,
            qclass: 1,
            dnssec_ok: false,
            checking_disabled: false,
            client_subnet: 0,
        };
        for &server in &self.servers {
            let id: u16 = rand::random();
            let mut buf = [0u8; 512];
            let Some(len) = encode_query(&q, id, &mut buf) else {
                continue;
            };
            let Ok(Ok(resp)) =
                tokio::time::timeout(TIMEOUT, udp_query(server, &buf[..len], id)).await
            else {
                continue;
            };
            let mut ips = Vec::new();
            let mut ttl = MAX_TTL;
            if let Ok(iter) = records(&resp) {
                for r in iter.flatten() {
                    if r.section != Section::Answer {
                        continue;
                    }
                    let rd = r.rdata(&resp);
                    let ip = match (r.rtype, rd.len()) {
                        (rtype::A, 4) => IpAddr::V4(Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3])),
                        (rtype::AAAA, 16) => {
                            let mut o = [0u8; 16];
                            o.copy_from_slice(rd);
                            IpAddr::V6(Ipv6Addr::from(o))
                        }
                        _ => continue,
                    };
                    ips.push(ip);
                    ttl = ttl.min(r.ttl);
                }
            }
            return Ok((ips, ttl));
        }
        Err(ExchangeError::Unresolved)
    }
}

async fn udp_query(server: SocketAddr, query: &[u8], id: u16) -> std::io::Result<Vec<u8>> {
    let bind: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(server).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await?;
        if matches_query(&buf[..n], query, id) {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

/// Extracts `nameserver` addresses (port 53), skipping excluded ones.
pub(crate) fn parse_resolv_conf(text: &str, exclude: &[SocketAddr]) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|rest| rest.trim().split('%').next()?.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .filter(|sa| {
            !exclude.iter().any(|ex| {
                ex.port() == 53
                    && (ex.ip() == sa.ip() || (ex.ip().is_unspecified() && sa.ip().is_loopback()))
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ups_009_resolv_conf_parsing_excludes_our_listeners() {
        let text = "# comment\nnameserver 127.0.0.53\nnameserver 192.168.1.1\nsearch lan\nnameserver fe80::1%eth0\n";
        let all = parse_resolv_conf(text, &[]);
        assert_eq!(all.len(), 3);
        // Listening on 0.0.0.0:53 means loopback resolvers would be us.
        let ours = parse_resolv_conf(text, &["0.0.0.0:53".parse().unwrap()]);
        assert_eq!(
            ours,
            vec![
                "192.168.1.1:53".parse().unwrap(),
                "[fe80::1]:53".parse().unwrap()
            ]
        );
    }
}
