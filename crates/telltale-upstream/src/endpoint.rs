//! Upstream URLs (`spec/04` §2): the scheme picks the protocol.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Upstream wire protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    /// Plain DNS over UDP, with TCP fallback on truncation.
    Udp,
    /// Plain DNS over TCP.
    Tcp,
    /// DNS over TLS (RFC 7858).
    Tls,
    /// DNS over HTTPS (RFC 8484).
    Https,
    /// REQ: UPS-002 (T7.7) — DNS over QUIC (RFC 9250).
    Quic,
}

impl Protocol {
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => 53,
            Self::Tls | Self::Quic => 853,
            Self::Https => 443,
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Https => "https",
            Self::Quic => "quic",
        })
    }
}

/// Server host: an IP literal or a hostname (which needs bootstrap resolution, UPS-009).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Host {
    Ip(IpAddr),
    Name(String),
}

/// A parsed upstream URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub protocol: Protocol,
    pub host: Host,
    pub port: u16,
    /// HTTP path for DoH (default `/dns-query`).
    pub path: String,
}

impl Endpoint {
    /// Parses `udp://1.1.1.1`, `tcp://[2606:4700::1111]:53`, `tls://dns.quad9.net`,
    /// `https://dns.google/dns-query`, ...
    pub fn parse(url: &str) -> Result<Self, String> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| format!("`{url}`: missing scheme (e.g. udp://9.9.9.9)"))?;
        let protocol = match scheme {
            "udp" => Protocol::Udp,
            "tcp" => Protocol::Tcp,
            "tls" => Protocol::Tls,
            "https" => Protocol::Https,
            "quic" => Protocol::Quic,
            other => return Err(format!("`{url}`: scheme `{other}://` is not supported yet")),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if protocol != Protocol::Https && !path.is_empty() && path != "/" {
            return Err(format!(
                "`{url}`: a path is only valid for https:// upstreams"
            ));
        }
        let (host, port) = split_host_port(authority).map_err(|e| format!("`{url}`: {e}"))?;
        let host = match host.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) if is_hostname(host) => Host::Name(host.to_ascii_lowercase()),
            Err(_) => return Err(format!("`{url}`: invalid host `{host}`")),
        };
        Ok(Self {
            protocol,
            host,
            port: port.unwrap_or(protocol.default_port()),
            path: if protocol == Protocol::Https {
                if path.is_empty() {
                    "/dns-query".into()
                } else {
                    path.into()
                }
            } else {
                String::new()
            },
        })
    }

    /// The socket address when the host is an IP literal.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self.host {
            Host::Ip(ip) => Some(SocketAddr::new(ip, self.port)),
            Host::Name(_) => None,
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(ip)) => {
                write!(f, "{}://[{ip}]:{}{}", self.protocol, self.port, self.path)
            }
            Host::Ip(ip) => write!(f, "{}://{ip}:{}{}", self.protocol, self.port, self.path),
            Host::Name(n) => write!(f, "{}://{n}:{}{}", self.protocol, self.port, self.path),
        }
    }
}

fn split_host_port(a: &str) -> Result<(&str, Option<u16>), String> {
    let parse_port = |p: &str| p.parse::<u16>().map_err(|_| format!("invalid port `{p}`"));
    if let Some(rest) = a.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or("unterminated `[`")?;
        return match after.strip_prefix(':') {
            Some(p) => Ok((host, Some(parse_port(p)?))),
            None if after.is_empty() => Ok((host, None)),
            None => Err(format!("unexpected `{after}` after IPv6 address")),
        };
    }
    match a.rsplit_once(':') {
        // A bare IPv6 address without brackets has several colons; treat it as host only.
        Some((h, p)) if !h.contains(':') => Ok((h, Some(parse_port(p)?))),
        _ => Ok((a, None)),
    }
}

fn is_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ups_001_endpoint_parsing() {
        let e = Endpoint::parse("udp://9.9.9.9").unwrap();
        assert_eq!(e.socket_addr(), Some("9.9.9.9:53".parse().unwrap()));
        let e = Endpoint::parse("tcp://[2606:4700::1111]:5353").unwrap();
        assert_eq!(
            e.socket_addr(),
            Some("[2606:4700::1111]:5353".parse().unwrap())
        );
        let e = Endpoint::parse("tls://Dns.Quad9.net").unwrap();
        assert_eq!((e.protocol, e.port), (Protocol::Tls, 853));
        assert_eq!(e.host, Host::Name("dns.quad9.net".into()));
        let e = Endpoint::parse("https://dns.google").unwrap();
        assert_eq!(e.path, "/dns-query");
        let e = Endpoint::parse("https://1.1.1.1/custom-path").unwrap();
        assert_eq!(e.path, "/custom-path");
        assert!(Endpoint::parse("9.9.9.9").is_err());
        assert!(Endpoint::parse("udp://9.9.9.9:99999").is_err());
        assert!(Endpoint::parse("udp://bad_host!").is_err());
        assert!(Endpoint::parse("udp://9.9.9.9/path").is_err());
        // UPS-002 (T7.7) — DoQ.
        let e = Endpoint::parse("quic://dns.adguard-dns.com").unwrap();
        assert_eq!((e.protocol, e.port), (Protocol::Quic, 853));
        assert!(Endpoint::parse("quic://9.9.9.9/path").is_err());
        assert!(Endpoint::parse("h3://dns.google/dns-query").is_err());
    }
}
