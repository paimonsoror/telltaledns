//! What the resolver remembers between queries (REQ: DNS-012), all bounded: zone cuts and
//! their servers (from referrals), server-name addresses, and each server's smoothed RTT.
//! Final answers aren't kept here: the server's answer cache holds them.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use telltale_proto::NameBuf;

/// Entries per table before the expired (then the oldest) are dropped.
const MAX_ENTRIES: usize = 20_000;
/// TTL bounds for delegations and addresses.
const MIN_TTL: Duration = Duration::from_secs(30);
const MAX_TTL: Duration = Duration::from_hours(24);

pub(crate) fn ttl(secs: u32) -> Duration {
    Duration::from_secs(u64::from(secs)).clamp(MIN_TTL, MAX_TTL)
}

/// A zone cut: the zone's server names and the addresses known for them.
#[derive(Debug, Clone)]
pub(crate) struct Delegation {
    pub(crate) ns: Vec<NameBuf>,
    pub(crate) addrs: Vec<IpAddr>,
    expires: Instant,
}

#[derive(Debug)]
struct Table<V> {
    map: HashMap<NameBuf, V>,
}

impl<V> Default for Table<V> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

fn prune<V>(map: &mut HashMap<NameBuf, V>, expired: impl Fn(&V) -> bool) {
    if map.len() < MAX_ENTRIES {
        return;
    }
    map.retain(|_, v| !expired(v));
    if map.len() >= MAX_ENTRIES {
        // Still full of live entries: drop an arbitrary half rather than grow.
        let drop: Vec<NameBuf> = map.keys().take(map.len() / 2).copied().collect();
        for k in drop {
            map.remove(&k);
        }
    }
}

/// Smoothed RTT per server, in microseconds; unknown servers start optimistic, so each
/// gets tried.
#[derive(Debug, Clone, Copy)]
struct Rtt {
    srtt_us: u32,
    /// Leaves 0x20 off for this server (it doesn't echo the letter case).
    no_case: bool,
}

#[derive(Debug, Default)]
pub(crate) struct Caches {
    zones: Mutex<Table<Delegation>>,
    addrs: Mutex<Table<(Vec<IpAddr>, Instant)>>,
    rtt: Mutex<HashMap<IpAddr, Rtt>>,
}

impl Caches {
    /// The deepest cached zone cut at or above `name` with addresses, skipping `name` itself
    /// when `parent_only` (DS records live in the parent).
    pub(crate) fn closest(
        &self,
        name: &NameBuf,
        parent_only: bool,
    ) -> Option<(NameBuf, Delegation)> {
        let now = Instant::now();
        let zones = self.zones.lock();
        let wire = name.as_wire();
        let mut pos = 0usize;
        let mut first = true;
        loop {
            let mut z = NameBuf::default();
            telltale_proto::read_name(wire, pos, &mut z).ok()?;
            if !(first && parent_only)
                && let Some(d) = zones.map.get(&z)
                && d.expires > now
            {
                return Some((z, d.clone()));
            }
            first = false;
            let len = usize::from(*wire.get(pos)?);
            if len == 0 {
                return None;
            }
            pos += 1 + len;
        }
    }

    pub(crate) fn put_zone(&self, zone: NameBuf, ns: Vec<NameBuf>, addrs: Vec<IpAddr>, ttl_s: u32) {
        let mut z = self.zones.lock();
        let now = Instant::now();
        prune(&mut z.map, |d: &Delegation| d.expires <= now);
        z.map.insert(
            zone,
            Delegation {
                ns,
                addrs,
                expires: now + ttl(ttl_s),
            },
        );
    }

    /// Adds addresses to a cached zone cut (found for its server names later).
    pub(crate) fn add_zone_addrs(&self, zone: &NameBuf, addrs: &[IpAddr]) {
        if let Some(d) = self.zones.lock().map.get_mut(zone) {
            for a in addrs {
                if !d.addrs.contains(a) {
                    d.addrs.push(*a);
                }
            }
        }
    }

    pub(crate) fn addrs(&self, name: &NameBuf) -> Option<Vec<IpAddr>> {
        let a = self.addrs.lock();
        a.map
            .get(name)
            .filter(|(_, exp)| *exp > Instant::now())
            .map(|(v, _)| v.clone())
    }

    pub(crate) fn put_addrs(&self, name: NameBuf, addrs: Vec<IpAddr>, ttl_s: u32) {
        let mut a = self.addrs.lock();
        let now = Instant::now();
        prune(&mut a.map, |(_, exp): &(Vec<IpAddr>, Instant)| *exp <= now);
        a.map.insert(name, (addrs, now + ttl(ttl_s)));
    }

    /// `servers` ordered fastest first, with their smoothed RTT (`None`: never asked; those
    /// sort as a small random RTT, so each gets tried).
    pub(crate) fn order(&self, servers: &[IpAddr]) -> Vec<(IpAddr, Option<u32>, bool)> {
        let r = self.rtt.lock();
        let mut v: Vec<(IpAddr, Option<u32>, bool, u32)> = servers
            .iter()
            .map(|ip| match r.get(ip) {
                Some(x) => (*ip, Some(x.srtt_us), x.no_case, x.srtt_us),
                None => (*ip, None, false, rand::random::<u32>() % 20_000),
            })
            .collect();
        v.sort_by_key(|x| x.3);
        v.into_iter().map(|(a, s, n, _)| (a, s, n)).collect()
    }

    /// Folds in an answer after `rtt`, or a failure (`None`: timeouts count as slow).
    pub(crate) fn record(&self, ip: IpAddr, rtt: Option<Duration>, timeout: Duration) {
        let mut r = self.rtt.lock();
        if r.len() >= MAX_ENTRIES {
            r.clear();
        }
        let sample = u32::try_from(rtt.unwrap_or(timeout * 2).as_micros()).unwrap_or(u32::MAX);
        r.entry(ip)
            .and_modify(|x| {
                // EWMA, 0.3 new / 0.7 old.
                x.srtt_us = u32::try_from((u64::from(x.srtt_us) * 7 + u64::from(sample) * 3) / 10)
                    .unwrap_or(u32::MAX);
            })
            .or_insert(Rtt {
                srtt_us: sample,
                no_case: false,
            });
    }

    pub(crate) fn no_case(&self, ip: IpAddr) {
        self.rtt
            .lock()
            .entry(ip)
            .or_insert(Rtt {
                srtt_us: 50_000,
                no_case: true,
            })
            .no_case = true;
    }

    /// Cached zone cuts (metrics, tests).
    pub(crate) fn zones(&self) -> usize {
        self.zones.lock().map.len()
    }
}
