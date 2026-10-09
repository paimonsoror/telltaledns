//! REQ: OBS-022 (T12.1, ADR-111) — queries left out of everything the aggregator feeds: the
//! analytics, the query log, the live view, and every export. Checked on the aggregator thread
//! (never the query path), once per event, allocation-free: a name is looked up suffix by
//! suffix (a handful of hash lookups), a client against a short list of networks. The query
//! counters in [`crate::Metrics`] are kept on the query path and still count them.

use std::collections::HashSet;

use crate::event::Record;

/// What to leave out. Build it once per configuration ([`Exclusions::new`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Exclusions {
    /// Wire-format names (lowercase), each excluding itself and its subdomains.
    names: HashSet<Box<[u8]>>,
    /// Networks as (address mapped into IPv6, prefix length in IPv6 terms).
    nets: Vec<([u8; 16], u8)>,
}

/// `a` and `b` agree on their first `bits` bits.
fn prefix_eq(a: &[u8; 16], b: &[u8; 16], bits: u8) -> bool {
    let bits = usize::from(bits.min(128));
    let (whole, rest) = (bits / 8, bits % 8);
    if a[..whole] != b[..whole] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    (a[whole] & mask) == (b[whole] & mask)
}

impl Exclusions {
    /// `names` in wire format (lowercased here); `nets` as (address, prefix length), IPv4
    /// addresses with an IPv4 prefix.
    pub fn new(names: impl IntoIterator<Item = Vec<u8>>, nets: &[(std::net::IpAddr, u8)]) -> Self {
        Self {
            names: names
                .into_iter()
                .map(|mut n| {
                    n.make_ascii_lowercase();
                    n.into_boxed_slice()
                })
                .collect(),
            nets: nets
                .iter()
                .map(|(ip, prefix)| match ip {
                    std::net::IpAddr::V4(v4) => {
                        (v4.to_ipv6_mapped().octets(), prefix.saturating_add(96))
                    }
                    std::net::IpAddr::V6(v6) => (v6.octets(), *prefix),
                })
                .collect(),
        }
    }

    /// Whether there's anything to leave out.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty() && self.nets.is_empty()
    }

    /// Whether `name` (wire format, lowercase as events carry it) is one of the names or under
    /// one.
    pub fn name(&self, name: &[u8]) -> bool {
        if self.names.is_empty() {
            return false;
        }
        let mut pos = 0;
        while let Some(&len) = name.get(pos) {
            if len == 0 {
                break;
            }
            if self.names.contains(&name[pos..]) {
                return true;
            }
            pos += usize::from(len) + 1;
        }
        false
    }

    /// Whether the client address (IPv4 mapped into IPv6, as events carry it) is excluded.
    pub fn client(&self, ip: &[u8; 16]) -> bool {
        self.nets
            .iter()
            .any(|(net, bits)| prefix_eq(net, ip, *bits))
    }

    /// Whether a record is left out (upstream exchanges never are: they name no query).
    pub fn excludes(&self, r: &Record) -> bool {
        match r {
            Record::Query(e, n) => self.client(&e.client_ip) || self.name(n.as_wire()),
            Record::Upstream(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(name: &str) -> Vec<u8> {
        let mut w = Vec::new();
        for l in name.split('.') {
            w.push(u8::try_from(l.len()).unwrap());
            w.extend_from_slice(l.as_bytes());
        }
        w.push(0);
        w
    }

    fn mapped(ip: &str) -> [u8; 16] {
        match ip.parse::<std::net::IpAddr>().unwrap() {
            std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            std::net::IpAddr::V6(v6) => v6.octets(),
        }
    }

    // REQ: OBS-022 — a name covers itself and its subdomains, not names that merely end the
    // same way; clients by address or network, IPv4 and IPv6.
    #[test]
    fn obs_022_names_and_networks() {
        let x = Exclusions::new(
            [wire("NTP.org"), wire("connectivitycheck.gstatic.com")],
            &[
                ("192.168.1.10".parse().unwrap(), 32),
                ("10.20.0.0".parse().unwrap(), 16),
                ("fd00::".parse().unwrap(), 64),
            ],
        );
        assert!(x.name(&wire("ntp.org")));
        assert!(x.name(&wire("0.pool.ntp.org")));
        assert!(x.name(&wire("connectivitycheck.gstatic.com")));
        assert!(!x.name(&wire("gstatic.com")));
        assert!(
            !x.name(&wire("notntp.org")),
            "a label boundary, not a string suffix"
        );
        assert!(!x.name(&wire("org")));
        assert!(!x.name(&[0]));
        assert!(x.client(&mapped("192.168.1.10")));
        assert!(!x.client(&mapped("192.168.1.11")));
        assert!(x.client(&mapped("10.20.255.1")));
        assert!(!x.client(&mapped("10.21.0.1")));
        assert!(x.client(&mapped("fd00::1234")));
        assert!(!x.client(&mapped("fd00:0:0:1::1")));
        assert!(Exclusions::default().is_empty());
        assert!(!Exclusions::default().name(&wire("ntp.org")));
    }
}
