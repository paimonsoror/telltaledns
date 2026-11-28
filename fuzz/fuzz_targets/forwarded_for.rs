//! NFR-004 (ADR-194): the `X-Forwarded-For` walk of a `doh` listener behind listed proxies.
//! The first byte picks how many of three proxy networks are listed; the rest is the header's
//! field lines, split at `\n`. Whatever the input, the walk ends and agrees with a plain reference
//! model of the same rules (every entry collected from the right into a `Vec`), so the entry that
//! decides is never skipped for one further left; a client it returns is a usable address outside
//! the listed proxies; and bytes put left of the first line change nothing unless the walk read
//! every entry.
#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use telltale_net::forwarded::{
    MAX_ENTRIES, MAX_ENTRY_LEN, Network, NoClient, client, is_client, listed,
};

const PROXIES: [Network; 3] = [
    Network {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 5, 20)),
        prefix: 32,
    },
    Network {
        addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        prefix: 8,
    },
    Network {
        addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 5, 0, 0, 0, 0, 0)),
        prefix: 48,
    },
];

/// The rules written out plainly: every entry from the right; the first that isn't a listed
/// proxy decides. Also returns where the decision fell (the entry's index from the right; the
/// number of entries when every one was a listed proxy).
fn reference(lines: &[&[u8]], proxies: &[Network]) -> (Result<IpAddr, NoClient>, usize) {
    let entries: Vec<&[u8]> = lines
        .iter()
        .rev()
        .flat_map(|l| l.rsplit(|b| *b == b','))
        .collect();
    for (i, entry) in entries.iter().enumerate() {
        if i == MAX_ENTRIES {
            return (Err(NoClient::TooManyEntries), i);
        }
        let t = entry.trim_ascii();
        let ip = if t.is_empty() || t.len() > MAX_ENTRY_LEN {
            None
        } else {
            std::str::from_utf8(t)
                .ok()
                .and_then(|s| s.parse::<IpAddr>().ok())
        };
        match ip {
            None => return (Err(NoClient::Unusable), i),
            Some(ip) if listed(proxies, ip) => {}
            Some(ip) if is_client(ip) => return (Ok(ip.to_canonical()), i),
            Some(_) => return (Err(NoClient::NotAClient), i),
        }
    }
    let end = entries.len();
    let none = if end == 0 {
        NoClient::Missing
    } else {
        NoClient::OnlyProxies
    };
    (Err(none), end)
}

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let proxies = &PROXIES[..usize::from(pick % 4).min(PROXIES.len())];
    let lines: Vec<&[u8]> = rest.split(|b| *b == b'\n').collect();
    let got = client(lines.iter().copied(), proxies);
    let (want, decided_at) = reference(&lines, proxies);
    assert_eq!(got, want, "{lines:?}");
    if let Ok(ip) = got {
        assert!(is_client(ip), "{ip} is not a usable client");
        assert!(!listed(proxies, ip), "{ip} is a listed proxy");
    }
    // Bytes put left of the first line's entries (the input itself, then a comma) never matter
    // when the decision fell on one of the entries that were there.
    let entries: usize = lines
        .iter()
        .map(|l| l.split(|b| *b == b',').count())
        .sum();
    if decided_at < entries {
        let mut first = rest.to_vec();
        first.push(b',');
        first.extend_from_slice(lines[0]);
        let mut longer: Vec<&[u8]> = lines.clone();
        longer[0] = &first;
        assert_eq!(
            client(longer.iter().copied(), proxies),
            got,
            "bytes left of the deciding entry changed the result: {lines:?}"
        );
    }
});
