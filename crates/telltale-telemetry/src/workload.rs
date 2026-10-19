//! Kubernetes workloads in the analytics (REQ: FLT-017; T15.1, ADR-150).
//!
//! Every per-device structure (top clients, anomaly baselines, identities, rhythm, recent
//! windows, new devices) is keyed by a 16-byte client address. A workload gets a synthetic
//! one in the IPv6 discard prefix `100::/64` (RFC 6666), so a Deployment's replicas are one
//! device across rollouts and the key can never be a real client's. The aggregator thread
//! substitutes it for a pod's address where it drains events, for the analytics only: the
//! query log, the live tail, and the exports keep the pod's address.

use std::collections::HashMap;

/// The first 8 bytes of every workload key: `0100:0000:0000:0000`, RFC 6666's discard prefix.
pub const PREFIX: [u8; 8] = [0x01, 0, 0, 0, 0, 0, 0, 0];

/// The analytics address of the workload `text` (`ns/kind/name`): the discard prefix and the
/// first 8 bytes of BLAKE3(`text`).
pub fn key(text: &str) -> [u8; 16] {
    let h = blake3::hash(text.as_bytes());
    let mut k = [0u8; 16];
    k[..8].copy_from_slice(&PREFIX);
    k[8..].copy_from_slice(&h.as_bytes()[..8]);
    k
}

/// Whether `ip` (v4-mapped) is a workload key.
#[inline]
pub fn is_key(ip: &[u8; 16]) -> bool {
    ip[..8] == PREFIX
}

/// Pod address (v4-mapped) → workload key.
pub type Keys = HashMap<[u8; 16], [u8; 16]>;

/// Hours a workload's counts cover.
pub const HOURS: usize = 24;

/// REQ: FLT-017 — one workload's queries and blocks per hour over the last day, and when it
/// was last seen (the Workloads tab). Bounded by the number of workloads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counts {
    /// (hour index, queries, blocked), by `hour % HOURS`.
    hours: [(u64, u32, u32); HOURS],
    pub last_seen_s: u64,
}

impl Counts {
    pub fn add(&mut self, ts_s: u64, blocked: bool) {
        let hour = ts_s / 3600;
        let slot = &mut self.hours[usize::try_from(hour % HOURS as u64).unwrap_or(0)];
        if slot.0 != hour {
            *slot = (hour, 0, 0);
        }
        slot.1 = slot.1.saturating_add(1);
        slot.2 = slot.2.saturating_add(u32::from(blocked));
        self.last_seen_s = self.last_seen_s.max(ts_s);
    }

    /// The hours with any query: (hour index, queries, blocked), for saving.
    pub fn slots(&self) -> impl Iterator<Item = (u64, u32, u32)> + '_ {
        self.hours.iter().copied().filter(|s| s.1 > 0)
    }

    /// REQ: FLT-017 — folds a saved hour back in (after a restart): added to the same hour
    /// counted since, in place of an older one, ignored if a newer one holds the slot.
    pub fn merge(&mut self, hour: u64, queries: u32, blocked: u32) {
        let slot = &mut self.hours[usize::try_from(hour % HOURS as u64).unwrap_or(0)];
        if slot.0 == hour {
            slot.1 = slot.1.saturating_add(queries);
            slot.2 = slot.2.saturating_add(blocked);
        } else if slot.0 < hour {
            *slot = (hour, queries, blocked);
        }
    }

    /// Queries and blocked in the `HOURS` hours up to `now_s`.
    pub fn day(&self, now_s: u64) -> (u64, u64) {
        let now_h = now_s / 3600;
        self.hours
            .iter()
            .filter(|(h, _, _)| *h + HOURS as u64 > now_h && *h <= now_h)
            .fold((0, 0), |(q, b), (_, hq, hb)| {
                (q + u64::from(*hq), b + u64::from(*hb))
            })
    }
}

/// Most workloads counted; a new one past this replaces the least recently seen.
pub const MAX_COUNTED: usize = 20_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flt_017_keys_are_in_the_discard_prefix() {
        let k = key("media/deploy/jellyfin");
        assert!(is_key(&k));
        assert_eq!(&k[..8], &[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(k, key("media/deploy/jellyfin"), "stable");
        assert_ne!(k, key("media/deploy/sonarr"));
        let v4 = std::net::Ipv4Addr::new(10, 42, 0, 5)
            .to_ipv6_mapped()
            .octets();
        assert!(!is_key(&v4));
        assert_eq!(
            std::net::Ipv6Addr::from(k).segments()[..4],
            [0x0100, 0, 0, 0],
            "100::/64"
        );
    }

    #[test]
    fn flt_017_counts_roll_by_hour() {
        let mut c = Counts::default();
        let h = 1_000 * 3600;
        c.add(h, false);
        c.add(h + 10, true);
        c.add(h + 3600, false);
        assert_eq!(c.day(h + 3600), (3, 1));
        // A day later the first hour has left the window.
        assert_eq!(c.day(h + 24 * 3600), (1, 0));
        c.add(h + 24 * 3600, true); // reuses the first hour's slot
        assert_eq!(c.day(h + 24 * 3600), (2, 1));
        assert_eq!(c.last_seen_s, h + 24 * 3600);
    }
}
