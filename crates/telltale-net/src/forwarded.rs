//! REQ: DNS-003, DNS-020 (ADR-194) — a `doh` listener behind proxies the operator lists
//! (`trusted_proxies`, `x_forwarded_for`): which peers may connect, which `X-Forwarded-For` entry
//! names the client, and which addresses never stand for a client.
//!
//! `X-Forwarded-For` is read the way the API reads it (ADR-034): from the right, skipping the
//! listed proxies, the first other entry is the client. Unlike a filter that drops what it
//! can't parse, the walk stops at the first entry that isn't a bare IP literal and refuses the
//! request: the entries further left were written by the client. Nothing here allocates.

use std::net::IpAddr;

/// An IP network (`10.0.5.20/32`): a peer a listener accepts, and a hop the walk skips.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Network {
    /// `ip` is inside this network (IPv4-mapped IPv6 addresses match IPv4 networks).
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        match (ip, self.addr) {
            (IpAddr::V4(a), IpAddr::V4(n)) => {
                let m = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix.min(32)))
                    .unwrap_or(0);
                u32::from(a) & m == u32::from(n) & m
            }
            (IpAddr::V6(a), IpAddr::V6(n)) => {
                let m = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix.min(128)))
                    .unwrap_or(0);
                u128::from(a) & m == u128::from(n) & m
            }
            _ => false,
        }
    }
}

/// `ip` is inside one of `networks`.
pub fn listed(networks: &[Network], ip: IpAddr) -> bool {
    networks.iter().any(|n| n.contains(ip))
}

/// The most `X-Forwarded-For` entries read, from the right.
pub const MAX_ENTRIES: usize = 16;
/// The longest entry read: the longest IPv6 literal
/// (`ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255`).
pub const MAX_ENTRY_LEN: usize = 45;

/// Why there is no usable client address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoClient {
    /// No `X-Forwarded-For` field at all.
    Missing,
    /// The selected entry isn't a bare IPv4 or IPv6 literal of at most 45 bytes (a port,
    /// brackets, a zone, a token such as `unknown`, an empty entry).
    Unusable,
    /// Every entry is a listed proxy.
    OnlyProxies,
    /// More than [`MAX_ENTRIES`] entries were walked.
    TooManyEntries,
    /// The client would be an unspecified or a loopback address.
    NotAClient,
}

/// Whether `ip` can stand for a client behind a proxy: not unspecified (`0.0.0.0`, `::`) and not
/// loopback (`127.0.0.0/8`, `::1`), IPv4-mapped forms included. Such an address would stand for
/// this host, not for a client behind the proxy.
pub fn is_client(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    !(ip.is_unspecified() || ip.is_loopback())
}

/// The address in one entry, or `None` when it isn't a bare literal.
fn literal(entry: &[u8]) -> Option<IpAddr> {
    let entry = entry.trim_ascii();
    if entry.is_empty() || entry.len() > MAX_ENTRY_LEN {
        return None;
    }
    std::str::from_utf8(entry).ok()?.parse().ok()
}

/// REQ: DNS-003 (ADR-194) — the client named by the `X-Forwarded-For` field lines `lines` (in
/// the order they arrived; together they are one comma-separated list, RFC 9110 §5.3), behind
/// the proxies `proxies`: the rightmost entry that isn't inside one of them. An entry that isn't
/// a bare literal is never skipped to reach one further left. At most [`MAX_ENTRIES`] entries
/// are read, and the client must pass [`is_client`]. An IPv4-mapped IPv6 entry is the IPv4
/// client it maps.
pub fn client<'a, I>(lines: I, proxies: &[Network]) -> Result<IpAddr, NoClient>
where
    I: IntoIterator<Item = &'a [u8]>,
    I::IntoIter: DoubleEndedIterator,
{
    let mut walked = 0usize;
    for line in lines.into_iter().rev() {
        for entry in line.rsplit(|b| *b == b',') {
            walked += 1;
            if walked > MAX_ENTRIES {
                return Err(NoClient::TooManyEntries);
            }
            let ip = literal(entry).ok_or(NoClient::Unusable)?;
            if listed(proxies, ip) {
                continue;
            }
            return if is_client(ip) {
                Ok(ip.to_canonical())
            } else {
                Err(NoClient::NotAClient)
            };
        }
    }
    Err(if walked == 0 {
        NoClient::Missing
    } else {
        NoClient::OnlyProxies
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]))
    }

    fn net(s: &str) -> Network {
        let (a, p) = s.split_once('/').unwrap_or((s, "32"));
        Network {
            addr: ip(a),
            prefix: p.parse().unwrap_or(32),
        }
    }

    fn pick(lines: &[&str], proxies: &[&str]) -> Result<IpAddr, NoClient> {
        let proxies: Vec<Network> = proxies.iter().copied().map(net).collect();
        client(lines.iter().map(|l| l.as_bytes()), &proxies)
    }

    /// REQ: DNS-003 (ADR-194, R7) — the rightmost entry that isn't a listed proxy; field lines
    /// are one list in the order they came, so the last line's entries are read first.
    #[test]
    fn dns_003_xff_rightmost_untrusted_entry() {
        assert_eq!(pick(&["198.51.100.1, 192.0.2.7"], &[]), Ok(ip("192.0.2.7")));
        assert_eq!(
            pick(&["192.0.2.7, 127.0.0.2"], &["127.0.0.2/32"]),
            Ok(ip("192.0.2.7"))
        );
        assert_eq!(
            pick(&["203.0.113.5", "192.0.2.7"], &[]),
            Ok(ip("192.0.2.7")),
            "the last line's entry"
        );
        assert_eq!(
            pick(&["203.0.113.5", "192.0.2.7, 10.0.5.20"], &["10.0.5.20/32"]),
            Ok(ip("192.0.2.7"))
        );
        assert_eq!(
            pick(
                &["203.0.113.5", "10.0.5.21", "10.0.5.20"],
                &["10.0.5.20/31"]
            ),
            Ok(ip("203.0.113.5")),
            "a chain of listed proxies across lines"
        );
        assert_eq!(
            pick(&["  2001:db8::7 ,\t10.0.5.20"], &["10.0.5.20/32"]),
            Ok(ip("2001:db8::7")),
            "spaces and tabs around entries; IPv6"
        );
        assert_eq!(
            pick(&["::ffff:192.0.2.9"], &["192.0.2.0/24"]),
            Err(NoClient::OnlyProxies),
            "an IPv4-mapped address is inside its IPv4 network"
        );
        assert_eq!(
            pick(&["::ffff:192.0.2.9"], &[]),
            Ok(ip("192.0.2.9")),
            "and stands for that IPv4 client"
        );
        assert_eq!(pick(&[], &[]), Err(NoClient::Missing));
        assert_eq!(
            pick(&["10.0.5.20, 10.0.5.20"], &["10.0.5.20/32"]),
            Err(NoClient::OnlyProxies)
        );
    }

    /// REQ: DNS-003 (ADR-194, R7) — the selected entry must be a bare literal; when it isn't,
    /// the request has no client, and the entry to its left (the client wrote it) is never
    /// taken instead.
    #[test]
    fn dns_003_xff_unparsable_entry_is_not_skipped() {
        let long = format!("{}1", "0".repeat(MAX_ENTRY_LEN));
        assert_eq!(long.len(), 46);
        for bad in [
            "203.0.113.9:4711",
            "[2001:db8::1]",
            "[2001:db8::1]:443",
            "fe80::1%eth0",
            "unknown",
            "_hidden",
            "",
            " ",
            long.as_str(),
            "192.0.2.300",
            "010.0.0.1",
        ] {
            let one = format!("10.0.0.1, {bad}");
            assert_eq!(
                pick(&[one.as_str()], &[]),
                Err(NoClient::Unusable),
                "{one:?}"
            );
            let two = ["10.0.0.1", bad];
            assert_eq!(pick(&two, &[]), Err(NoClient::Unusable), "{two:?}");
        }
        assert_eq!(
            pick(&["10.0.0.1, unknown, 10.0.5.20"], &["10.0.5.20/32"]),
            Err(NoClient::Unusable),
            "behind a listed proxy too"
        );
        assert_eq!(pick(&["10.0.0.1,"], &[]), Err(NoClient::Unusable));
        assert_eq!(
            pick(&["10.0.0.1, 192.0.2.\u{e9}"], &[]),
            Err(NoClient::Unusable)
        );
        // The longest literal is read.
        assert_eq!(
            pick(&["ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], &[]),
            Ok(ip("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"))
        );
    }

    /// REQ: DNS-003 (ADR-194, R7) — at most 16 entries are walked: a client in the 16th entry
    /// from the right is found, one further left is not, and 16 listed proxies are refused.
    #[test]
    fn dns_003_xff_walk_is_bounded() {
        let proxies = ["10.0.5.0/24"];
        let hops = |n: usize| -> Vec<String> { (1..=n).map(|i| format!("10.0.5.{i}")).collect() };
        let header = |client: Option<&str>, n: usize| {
            let mut all: Vec<String> = client.map(str::to_owned).into_iter().collect();
            all.extend(hops(n));
            all.join(", ")
        };
        assert_eq!(
            pick(&[header(Some("192.0.2.7"), 15).as_str()], &proxies),
            Ok(ip("192.0.2.7"))
        );
        assert_eq!(
            pick(&[header(Some("192.0.2.7"), 16).as_str()], &proxies),
            Err(NoClient::TooManyEntries)
        );
        assert_eq!(
            pick(&[header(None, 16).as_str()], &proxies),
            Err(NoClient::OnlyProxies)
        );
        assert_eq!(
            pick(&[header(None, 17).as_str()], &proxies),
            Err(NoClient::TooManyEntries)
        );
        // Field lines count together.
        let each: Vec<String> = hops(17);
        let separate: Vec<&str> = each.iter().map(String::as_str).collect();
        assert_eq!(pick(&separate, &proxies), Err(NoClient::TooManyEntries));
    }

    /// REQ: DNS-020, DNS-003 (ADR-194, R5) — unspecified and loopback addresses never stand
    /// for a client, in any form; other addresses do.
    #[test]
    fn dns_020_forwarded_unspecified_or_loopback_is_not_a_client() {
        for no in [
            "0.0.0.0",
            "::",
            "127.0.0.5",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:0.0.0.0",
        ] {
            assert!(!is_client(ip(no)), "{no}");
            assert_eq!(pick(&[no], &[]), Err(NoClient::NotAClient), "{no}");
        }
        for yes in [
            "192.0.2.7",
            "10.0.0.1",
            "2001:db8::7",
            "::ffff:192.0.2.7",
            "fe80::1",
        ] {
            assert!(is_client(ip(yes)), "{yes}");
        }
        assert_eq!(
            pick(&["192.0.2.7, 127.0.0.1"], &["127.0.0.1/32"]),
            Ok(ip("192.0.2.7")),
            "a listed loopback hop is skipped, not refused"
        );
    }

    /// REQ: DNS-003 (ADR-194) — networks match like `[api] trusted_proxies`: by prefix, IPv4
    /// mapped into IPv6 as IPv4, families apart.
    #[test]
    fn dns_003_trusted_networks_match_by_prefix() {
        assert!(net("10.0.5.20/32").contains(ip("10.0.5.20")));
        assert!(!net("10.0.5.20/32").contains(ip("10.0.5.21")));
        assert!(net("10.0.5.0/24").contains(ip("::ffff:10.0.5.9")));
        assert!(net("2001:db8::/32").contains(ip("2001:db8:1::5")));
        assert!(!net("2001:db8::/32").contains(ip("10.0.5.9")));
        assert!(!net("10.0.0.0/8").contains(ip("2001:db8::1")));
        assert!(listed(
            &[net("10.0.5.20/32"), net("127.0.0.1/32")],
            ip("127.0.0.1")
        ));
        assert!(!listed(&[], ip("127.0.0.1")));
    }
}
