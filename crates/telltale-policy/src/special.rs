//! Special-use names (`spec/03` §3 step 4; RFC 6761, RFC 6303; ADR-014).

use std::sync::OnceLock;

use telltale_config::SpecialConfig;
use telltale_proto::{NameBuf, Query, class};

/// How a special name is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Special {
    /// Answer NXDOMAIN (Firefox canary, `*.invalid`).
    Nxdomain,
    /// Answer REFUSED (CHAOS-class queries such as `version.bind`).
    Refused,
    /// Answer with loopback addresses (`localhost`, RFC 6761 §6.3).
    Localhost,
    /// Reverse lookup for a private address: NXDOMAIN unless local data or a route covers it.
    PrivatePtr,
}

struct Names {
    canary: NameBuf,
    invalid: NameBuf,
    localhost: NameBuf,
    in_addr: NameBuf,
    ip6: NameBuf,
}

fn names() -> &'static Names {
    static N: OnceLock<Names> = OnceLock::new();
    N.get_or_init(|| {
        let n = |s: &str| NameBuf::from_presentation(s).unwrap_or_default();
        Names {
            canary: n("use-application-dns.net"),
            invalid: n("invalid"),
            localhost: n("localhost"),
            in_addr: n("in-addr.arpa"),
            ip6: n("ip6.arpa"),
        }
    })
}

/// Classifies `q`; `None` for ordinary names. Allocation-free.
pub fn classify(q: &Query<'_>, cfg: &SpecialConfig) -> Option<Special> {
    let n = names();
    if cfg.refuse_chaos && q.qclass == class::CH {
        return Some(Special::Refused);
    }
    if cfg.block_firefox_canary && q.qname == n.canary {
        return Some(Special::Nxdomain);
    }
    if q.qname.is_subdomain_of(&n.invalid) {
        return Some(Special::Nxdomain);
    }
    if cfg.localhost && q.qname.is_subdomain_of(&n.localhost) {
        return Some(Special::Localhost);
    }
    if cfg.private_ptr_nxdomain && is_private_reverse(&q.qname, n) {
        return Some(Special::PrivatePtr);
    }
    None
}

/// True for reverse names inside private/local address space (RFC 6303 locally served zones:
/// `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `169.254/16`, `127/8`, `0/8`; `fc00::/7`,
/// `fe80::/10`, `::1`).
fn is_private_reverse(name: &NameBuf, n: &Names) -> bool {
    let count = name.labels().count();
    // k = 0 is the last label ("arpa"), k = 1 "in-addr"/"ip6", k = 2 the most significant part.
    let from_end = |k: usize| name.labels().nth(count.checked_sub(k + 1)?);
    if name.is_subdomain_of(&n.in_addr) {
        let octet = |k| from_end(k).and_then(|l| std::str::from_utf8(l).ok()?.parse::<u8>().ok());
        return match (octet(2), octet(3)) {
            (Some(10 | 127 | 0), _) | (Some(192), Some(168)) | (Some(169), Some(254)) => true,
            (Some(172), Some(b)) => (16..=31).contains(&b),
            (Some(100), Some(b)) => (64..=127).contains(&b),
            _ => false,
        };
    }
    if name.is_subdomain_of(&n.ip6) {
        let nibble = |k| {
            from_end(k).and_then(|l| match l {
                [c] => char::from(*c).to_digit(16),
                _ => None,
            })
        };
        let (a, b, c) = (nibble(2), nibble(3), nibble(4));
        if a == Some(0xf) && matches!(b, Some(0xc | 0xd)) {
            return true; // fc00::/7
        }
        if a == Some(0xf) && b == Some(0xe) && matches!(c, Some(0x8..=0xb)) {
            return true; // fe80::/10
        }
        // ::1 — 32 nibble labels, least significant first: "1" then 31 × "0".
        return count == 34
            && name.labels().take(32).enumerate().all(|(i, l)| {
                l == if i == 0 {
                    b"1".as_slice()
                } else {
                    b"0".as_slice()
                }
            });
    }
    false
}

#[cfg(test)]
mod tests {
    use telltale_proto::{build_query, parse_query, rtype};

    use super::*;

    fn classify_name(name: &str, qclass: u16) -> Option<Special> {
        let mut buf = [0u8; 512];
        let n = NameBuf::from_presentation(name).unwrap();
        let len = build_query(&mut buf, 1, &n, rtype::A, qclass, true, None).unwrap();
        let q = parse_query(&buf[..len]).unwrap();
        classify(&q, &SpecialConfig::default())
    }

    #[test]
    fn dns_019_special_names() {
        assert_eq!(
            classify_name("use-application-dns.net", 1),
            Some(Special::Nxdomain)
        );
        assert_eq!(classify_name("foo.invalid", 1), Some(Special::Nxdomain));
        assert_eq!(classify_name("localhost", 1), Some(Special::Localhost));
        assert_eq!(classify_name("app.localhost", 1), Some(Special::Localhost));
        assert_eq!(
            classify_name("version.bind", class::CH),
            Some(Special::Refused)
        );
        assert_eq!(classify_name("example.com", 1), None);
        assert_eq!(
            classify_name("printer.local", 1),
            None,
            ".local is left alone"
        );
    }

    #[test]
    fn dns_019_private_reverse_zones() {
        for private in [
            "1.1.168.192.in-addr.arpa",
            "5.0.0.10.in-addr.arpa",
            "1.0.20.172.in-addr.arpa",
            "9.9.64.100.in-addr.arpa",
            "168.192.in-addr.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
        ] {
            assert_eq!(
                classify_name(private, 1),
                Some(Special::PrivatePtr),
                "{private}"
            );
        }
        for public in [
            "8.8.8.8.in-addr.arpa",
            "1.0.32.172.in-addr.arpa",
            "1.0.0.2.ip6.arpa",
        ] {
            assert_eq!(classify_name(public, 1), None, "{public}");
        }
    }
}
