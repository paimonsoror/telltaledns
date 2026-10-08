//! Per-client-address connection cap for the stream listeners (REQ: DNS-001..004; review 01
//! q2): one host can't take every connection slot. The address is the client's, after the PROXY
//! header and after a QUIC handshake, never the balancer's or a spoofable one. IPv4 clients
//! count per address; IPv6 clients per /64, since a host rotates through its prefix.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

/// How many connections one client address may hold open at once, by default.
pub const DEFAULT_PER_ADDRESS: usize = 32;

/// Counts open connections per client address.
#[derive(Debug)]
pub struct PeerLimit {
    /// 0 = no limit.
    max: usize,
    open: Mutex<HashMap<IpAddr, usize>>,
}

/// One connection's place in the count; dropping it frees the place.
#[derive(Debug)]
pub struct PeerSlot {
    limit: Arc<PeerLimit>,
    key: Option<IpAddr>,
}

/// What counts as one client: an IPv4 address, or an IPv6 /64 (IPv4-mapped addresses count as
/// IPv4).
fn key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6((u128::from(v6) & !u128::from(u64::MAX)).into()),
        },
    }
}

impl PeerLimit {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            max,
            open: Mutex::new(HashMap::new()),
        })
    }

    /// A place for a connection from `ip`, or `None` when that client already holds `max`.
    pub fn acquire(self: &Arc<Self>, ip: IpAddr) -> Option<PeerSlot> {
        if self.max == 0 {
            return Some(PeerSlot {
                limit: Arc::clone(self),
                key: None,
            });
        }
        let k = key(ip);
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        let n = open.entry(k).or_insert(0);
        if *n >= self.max {
            return None;
        }
        *n += 1;
        Some(PeerSlot {
            limit: Arc::clone(self),
            key: Some(k),
        })
    }

    /// Clients with at least one open connection (tests).
    #[cfg(test)]
    fn clients(&self) -> usize {
        self.open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        let Some(k) = self.key else { return };
        let mut open = self
            .limit
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = open.get_mut(&k) {
            *n -= 1;
            if *n == 0 {
                open.remove(&k);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: DNS-001 — a client address holds at most `max` connections; a slot comes back when
    /// its connection ends; IPv6 clients share a /64; 0 means no limit.
    #[test]
    fn dns_001_per_address_cap() {
        let l = PeerLimit::new(2);
        let a: IpAddr = "192.0.2.1".parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let b: IpAddr = "192.0.2.2".parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let s1 = l.acquire(a);
        let s2 = l.acquire(a);
        assert!(s1.is_some() && s2.is_some());
        assert!(l.acquire(a).is_none(), "a third from the same address");
        let held_b = l.acquire(b);
        assert!(held_b.is_some(), "another address is unaffected");
        drop(s1);
        assert!(l.acquire(a).is_some(), "a freed slot is reusable");
        drop(s2);
        assert_eq!(
            l.clients(),
            1,
            "only b's connection is left, and a has no entry"
        );

        let v6 = |s: &str| s.parse::<IpAddr>().unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let l = PeerLimit::new(1);
        let held = l.acquire(v6("2001:db8:1:2::1"));
        assert!(held.is_some());
        assert!(
            l.acquire(v6("2001:db8:1:2:aaaa:bbbb:cccc:dddd")).is_none(),
            "the same /64"
        );
        assert!(l.acquire(v6("2001:db8:1:3::1")).is_some(), "another /64");
        let mapped = PeerLimit::new(1);
        let _m = mapped.acquire(v6("::ffff:192.0.2.9"));
        assert!(mapped.acquire(v6("192.0.2.9")).is_none(), "mapped = IPv4");

        let unlimited = PeerLimit::new(0);
        let slots: Vec<_> = (0..100).map(|_| unlimited.acquire(a)).collect();
        assert!(slots.iter().all(Option::is_some));
    }
}
