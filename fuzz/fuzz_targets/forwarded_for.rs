//! NFR-004 (ADR-194): the `X-Forwarded-For` walk of a `doh` listener behind listed proxies.
//! The first byte picks how many of three proxy networks are listed; the rest is the header's
//! field lines, split at `\n`. Whatever the input, the walk ends, and a client it returns is a
//! usable address outside the listed proxies.
#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use telltale_net::forwarded::{Network, NoClient, client, is_client, listed};

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

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let proxies = &PROXIES[..usize::from(pick % 4).min(PROXIES.len())];
    let lines: Vec<&[u8]> = rest.split(|b| *b == b'\n').collect();
    match client(lines.iter().copied(), proxies) {
        Ok(ip) => {
            assert!(is_client(ip), "{ip} is not a usable client");
            assert!(!listed(proxies, ip), "{ip} is a listed proxy");
        }
        // There is always at least one field line here.
        Err(NoClient::Missing) => panic!("lines were given"),
        Err(_) => {}
    }
});
