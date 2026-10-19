//! REQ: OBS-037 (ADR-152) — internal names: the Kubernetes cluster domain and reverse lookups
//! of private addresses. They count in the hour's own "internal" top list instead of the top
//! domains and NXDOMAIN lists (a pod's `ndots: 5` search list alone would fill both). The
//! query log, the live view, the exports, and `/metrics` keep them. Checked on the aggregator
//! thread (never the query path), once per event, allocation-free.

use std::collections::HashSet;

/// Which names are internal. Build it once per configuration ([`InternalNames::new`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalNames {
    /// Wire-format names (lowercase), each covering itself and its subdomains.
    suffixes: HashSet<Box<[u8]>>,
    /// Reverse names inside private and local address space (RFC 6303).
    private_reverse: bool,
}

impl Default for InternalNames {
    /// Private reverse lookups only (no cluster domain).
    fn default() -> Self {
        Self::new([], true)
    }
}

const IN_ADDR: &[u8] = b"\x07in-addr\x04arpa\x00";
const IP6: &[u8] = b"\x03ip6\x04arpa\x00";
/// Labels in the longest reverse name: 32 nibbles, `ip6`, `arpa`.
const MAX_REVERSE_LABELS: usize = 34;

impl InternalNames {
    /// `suffixes` in wire format (lowercased here).
    pub fn new(suffixes: impl IntoIterator<Item = Vec<u8>>, private_reverse: bool) -> Self {
        Self {
            suffixes: suffixes
                .into_iter()
                .filter(|n| n.len() > 1)
                .map(|mut n| {
                    n.make_ascii_lowercase();
                    n.into_boxed_slice()
                })
                .collect(),
            private_reverse,
        }
    }

    /// Whether `name` (wire format, lowercase as events carry it) is internal.
    pub fn is_internal(&self, name: &[u8]) -> bool {
        (self.private_reverse && is_private_reverse(name)) || self.under_suffix(name)
    }

    fn under_suffix(&self, name: &[u8]) -> bool {
        if self.suffixes.is_empty() {
            return false;
        }
        let mut pos = 0;
        while let Some(&len) = name.get(pos) {
            if len == 0 {
                break;
            }
            if self.suffixes.contains(&name[pos..]) {
                return true;
            }
            pos += usize::from(len) + 1;
        }
        false
    }
}

/// True for reverse names inside private/local address space, as the resolver's special-name
/// handling defines it (RFC 6303: `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `169.254/16`,
/// `127/8`, `0/8`; `fc00::/7`, `fe80::/10`, `::1`).
fn is_private_reverse(name: &[u8]) -> bool {
    let v4 = name.ends_with(IN_ADDR);
    if !v4 && !name.ends_with(IP6) {
        return false;
    }
    // The labels, most significant last (wire order), without the trailing `in-addr.arpa`.
    let mut labels: [&[u8]; MAX_REVERSE_LABELS] = [&[]; MAX_REVERSE_LABELS];
    let mut count = 0;
    let mut pos = 0;
    while let Some(&len) = name.get(pos) {
        if len == 0 {
            break;
        }
        let Some(l) = name.get(pos + 1..pos + 1 + usize::from(len)) else {
            return false;
        };
        let Some(slot) = labels.get_mut(count) else {
            return false;
        };
        *slot = l;
        count += 1;
        pos += usize::from(len) + 1;
    }
    let count = count.saturating_sub(2);
    // k = 0 is the most significant part.
    let from_top = |k: usize| count.checked_sub(k + 1).map(|i| labels[i]);
    if v4 {
        let octet = |k| from_top(k).and_then(|l| std::str::from_utf8(l).ok()?.parse::<u8>().ok());
        return match (octet(0), octet(1)) {
            (Some(10 | 127 | 0), _) | (Some(192), Some(168)) | (Some(169), Some(254)) => true,
            (Some(172), Some(b)) => (16..=31).contains(&b),
            (Some(100), Some(b)) => (64..=127).contains(&b),
            _ => false,
        };
    }
    let nibble = |k| {
        from_top(k).and_then(|l| match l {
            [c] => char::from(*c).to_digit(16),
            _ => None,
        })
    };
    let (a, b, c) = (nibble(0), nibble(1), nibble(2));
    if a == Some(0xf) && matches!(b, Some(0xc | 0xd)) {
        return true; // fc00::/7
    }
    if a == Some(0xf) && b == Some(0xe) && matches!(c, Some(0x8..=0xb)) {
        return true; // fe80::/10
    }
    // ::1 — 32 nibbles, least significant first: "1" then 31 × "0".
    count == 32
        && labels[..32].iter().enumerate().all(|(i, l)| {
            *l == if i == 0 {
                b"1".as_slice()
            } else {
                b"0".as_slice()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(name: &str) -> Vec<u8> {
        let mut w = Vec::new();
        for l in name.split('.').filter(|l| !l.is_empty()) {
            w.push(u8::try_from(l.len()).unwrap());
            w.extend_from_slice(l.as_bytes());
        }
        w.push(0);
        w
    }

    // REQ: OBS-037 — the cluster domain covers itself and its subdomains (the `ndots` search
    // expansions too); private reverse names match the resolver's RFC 6303 list; public ones,
    // ordinary names, and look-alikes don't.
    #[test]
    fn obs_037_internal_names() {
        let x = InternalNames::new([wire("Cluster.Local")], true);
        for name in [
            "cluster.local",
            "kubernetes.default.svc.cluster.local",
            "api.github.com.argocd.svc.cluster.local",
            "1.1.168.192.in-addr.arpa",
            "5.0.0.10.in-addr.arpa",
            "1.0.20.172.in-addr.arpa",
            "9.9.64.100.in-addr.arpa",
            "4.3.254.169.in-addr.arpa",
            "168.192.in-addr.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
        ] {
            assert!(x.is_internal(&wire(name)), "{name}");
        }
        for name in [
            "example.com",
            "notcluster.local",
            "local",
            "8.8.8.8.in-addr.arpa",
            "1.0.32.172.in-addr.arpa",
            "1.0.0.2.ip6.arpa",
            "in-addr.arpa",
            "10.in-addr.arpa.example.com",
        ] {
            assert!(!x.is_internal(&wire(name)), "{name}");
        }
        assert!(!x.is_internal(&[0]), "the root");
        assert!(!x.is_internal(&[]));
        let none = InternalNames::new([], false);
        assert!(!none.is_internal(&wire("1.1.168.192.in-addr.arpa")));
        assert!(!InternalNames::default().is_internal(&wire("a.svc.cluster.local")));
        assert!(InternalNames::default().is_internal(&wire("1.1.168.192.in-addr.arpa")));
    }
}
