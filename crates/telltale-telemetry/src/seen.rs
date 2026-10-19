//! REQ: CLU-014 (ADR-151) — who uses this node, for failover drills and the affinity view.
//!
//! - [`Seen`]: per client key (a workload's key for pods, FLT-017) the first and last time it
//!   asked this node, how often in all, and per day over the last week. A drill's baseline is
//!   the devices seen in the hour before it; the affinity view sums the days. Capped at
//!   [`MAX_CLIENTS`]: past it, new clients aren't tracked and `overflow` counts them. Saved by
//!   the binary hourly and at shutdown; entries unseen for [`EXPIRY_S`] go.
//! - [`Window`]: while a drill runs anywhere in the cluster, every node keeps per client the
//!   first and last query, how many, how many it dropped, and the first one it dropped. The
//!   drilled node merges every node's window into the report.
//!
//! Both are updated on the telemetry thread with the analytics (after exclusions and probes),
//! never on the query path.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{QueryEvent, Status};

/// Most clients a table keeps.
pub const MAX_CLIENTS: usize = 4_096;
/// A client unseen this long leaves the seen table.
pub const EXPIRY_S: u64 = 30 * 86_400;
/// Days kept per client for the affinity view (today and the six before).
pub const DAYS: usize = 7;

/// One client in the seen table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeenEntry {
    pub first_s: u64,
    pub last_s: u64,
    pub queries: u64,
    /// `(day index, queries)` by `day % DAYS`.
    #[serde(default)]
    pub days: [(u32, u32); DAYS],
}

impl SeenEntry {
    /// Queries in the `n` days up to `now_s` (today included).
    pub fn recent(&self, now_s: u64, n: usize) -> u64 {
        let today = day(now_s);
        let n = u32::try_from(n.clamp(1, DAYS)).unwrap_or(1);
        self.days
            .iter()
            .filter(|(d, _)| *d + n > today && *d <= today)
            .map(|(_, q)| u64::from(*q))
            .sum()
    }
}

fn day(ts_s: u64) -> u32 {
    u32::try_from(ts_s / 86_400).unwrap_or(u32::MAX)
}

/// Every client that asked this node, bounded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    /// Keyed by the client's 16-byte address (or analytics key).
    #[serde(with = "pairs")]
    pub clients: HashMap<[u8; 16], SeenEntry>,
    /// Clients not tracked because the table was full.
    pub overflow: u64,
}

impl Seen {
    /// Counts one query from `client` at `ts_s`.
    pub fn add(&mut self, client: [u8; 16], ts_s: u64) {
        let full = self.clients.len() >= MAX_CLIENTS;
        let e = match self.clients.get_mut(&client) {
            Some(e) => e,
            None if full => {
                self.overflow = self.overflow.saturating_add(1);
                return;
            }
            None => self.clients.entry(client).or_insert_with(|| SeenEntry {
                first_s: ts_s,
                ..SeenEntry::default()
            }),
        };
        e.first_s = e.first_s.min(ts_s);
        e.last_s = e.last_s.max(ts_s);
        e.queries = e.queries.saturating_add(1);
        let d = day(ts_s);
        let slot = &mut e.days[usize::try_from(d).unwrap_or(0) % DAYS];
        if slot.0 != d {
            *slot = (d, 0);
        }
        slot.1 = slot.1.saturating_add(1);
    }

    /// Clients seen in `[from_s, to_s]`.
    pub fn between(&self, from_s: u64, to_s: u64) -> impl Iterator<Item = (&[u8; 16], &SeenEntry)> {
        self.clients
            .iter()
            .filter(move |(_, e)| e.last_s >= from_s && e.first_s <= to_s)
    }

    /// Drops clients unseen for [`EXPIRY_S`].
    pub fn expire(&mut self, now_s: u64) {
        self.clients
            .retain(|_, e| e.last_s.saturating_add(EXPIRY_S) >= now_s);
    }

    /// Folds a saved table in (after a restart): earliest first, latest last, counts added.
    pub fn merge(&mut self, other: Seen) {
        for (k, o) in other.clients {
            if !self.clients.contains_key(&k) && self.clients.len() >= MAX_CLIENTS {
                self.overflow = self.overflow.saturating_add(1);
                continue;
            }
            let e = self.clients.entry(k).or_insert_with(|| SeenEntry {
                first_s: o.first_s,
                ..SeenEntry::default()
            });
            e.first_s = e.first_s.min(o.first_s);
            e.last_s = e.last_s.max(o.last_s);
            e.queries = e.queries.saturating_add(o.queries);
            for (d, q) in o.days {
                let slot = &mut e.days[usize::try_from(d).unwrap_or(0) % DAYS];
                if slot.0 == d {
                    slot.1 = slot.1.saturating_add(q);
                } else if slot.0 < d {
                    *slot = (d, q);
                }
            }
        }
        self.overflow = self.overflow.saturating_add(other.overflow);
    }
}

/// One client during a drill window, on one node.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowEntry {
    pub first_ms: u64,
    pub last_ms: u64,
    pub queries: u32,
    /// Queries this node didn't answer because of the drill.
    pub drilled: u32,
    /// The first and last of those (0: none).
    pub first_drilled_ms: u64,
    pub last_drilled_ms: u64,
}

/// What one node saw while a drill ran (its "part" of the report).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Window {
    pub id: String,
    pub since_ms: u64,
    #[serde(with = "pairs")]
    pub clients: HashMap<[u8; 16], WindowEntry>,
    pub overflow: u64,
}

impl Window {
    pub fn new(id: &str, since_ms: u64) -> Self {
        Self {
            id: id.to_owned(),
            since_ms,
            ..Self::default()
        }
    }

    /// Counts one query.
    pub fn add(&mut self, e: &QueryEvent) {
        let ms = e.ts_us / 1_000;
        if ms < self.since_ms {
            return;
        }
        let full = self.clients.len() >= MAX_CLIENTS;
        let w = match self.clients.get_mut(&e.client_ip) {
            Some(w) => w,
            None if full => {
                self.overflow = self.overflow.saturating_add(1);
                return;
            }
            None => self.clients.entry(e.client_ip).or_insert(WindowEntry {
                first_ms: ms,
                ..WindowEntry::default()
            }),
        };
        w.first_ms = w.first_ms.min(ms);
        w.last_ms = w.last_ms.max(ms);
        w.queries = w.queries.saturating_add(1);
        if e.status == Status::Drilled {
            w.drilled = w.drilled.saturating_add(1);
            if w.first_drilled_ms == 0 || ms < w.first_drilled_ms {
                w.first_drilled_ms = ms;
            }
            w.last_drilled_ms = w.last_drilled_ms.max(ms);
        }
    }
}

/// `HashMap<[u8; 16], V>` as a list of pairs (JSON keys must be strings).
mod pairs {
    use std::collections::HashMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer, V: Serialize>(
        m: &HashMap<[u8; 16], V>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut v: Vec<(&[u8; 16], &V)> = m.iter().collect();
        v.sort_by_key(|(k, _)| **k);
        v.serialize(s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>, V: Deserialize<'de>>(
        d: D,
    ) -> Result<HashMap<[u8; 16], V>, D::Error> {
        Ok(Vec::<([u8; 16], V)>::deserialize(d)?.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> [u8; 16] {
        std::net::Ipv4Addr::new(192, 168, 1, last)
            .to_ipv6_mapped()
            .octets()
    }

    // REQ: CLU-014 (AC 6) — the seen table: first/last/counts per client, capped with
    // `overflow` counted, days for the affinity view, expiry, and a lossless round trip.
    #[test]
    fn clu_014_seen_table_caps_counts_and_round_trips() {
        let mut s = Seen::default();
        let t = 20_000 * 86_400;
        s.add(ip(10), t);
        s.add(ip(10), t + 60);
        s.add(ip(10), t + 86_400);
        let e = &s.clients[&ip(10)];
        assert_eq!((e.first_s, e.last_s, e.queries), (t, t + 86_400, 3));
        assert_eq!(e.recent(t + 86_400, 1), 1, "today only");
        assert_eq!(e.recent(t + 86_400, 7), 3, "the week");
        for i in 0..MAX_CLIENTS {
            let mut k = [0u8; 16];
            k[..8].copy_from_slice(&(i as u64).to_be_bytes());
            s.add(k, t);
        }
        assert_eq!(s.clients.len(), MAX_CLIENTS);
        assert_eq!(s.overflow, 1, "one past the cap");
        assert_eq!(s.between(t + 86_400, t + 86_400).count(), 1);
        let json = serde_json::to_vec(&s).unwrap();
        assert_eq!(serde_json::from_slice::<Seen>(&json).unwrap(), s);
        s.expire(t + EXPIRY_S + 1);
        assert_eq!(s.clients.len(), 1, "the one seen a day later stays");
        // A restart: the saved table merges into what was counted since.
        let mut after = Seen::default();
        after.add(ip(10), t + 2 * 86_400);
        after.merge(s);
        let e = &after.clients[&ip(10)];
        assert_eq!((e.first_s, e.queries), (t, 4));
    }

    // REQ: CLU-014 — a drill window counts queries and dropped ones per client, from its start.
    #[test]
    fn clu_014_window_counts_drilled_queries() {
        let mut w = Window::new("d1", 1_000);
        let ev = |ms: u64, status| QueryEvent {
            ts_us: ms * 1_000,
            client_ip: ip(14),
            client_ref: 0,
            group: 0,
            qtype: 1,
            qclass: 1,
            rcode: None,
            status,
            proto: crate::Proto::Udp,
            flags: 0,
            rule: None,
            upstream: 0,
            attempts: 0,
            t_total_us: 0,
            t_upstream_us: 0,
            resp_size: 0,
            answers: 0,
        };
        w.add(&ev(999, Status::Cached));
        w.add(&ev(1_500, Status::Drilled));
        w.add(&ev(2_500, Status::Drilled));
        w.add(&ev(3_000, Status::Cached));
        let e = w.clients[&ip(14)];
        assert_eq!(
            (e.queries, e.drilled),
            (3, 2),
            "the one before the start isn't counted"
        );
        assert_eq!((e.first_drilled_ms, e.last_drilled_ms), (1_500, 2_500));
        assert_eq!((e.first_ms, e.last_ms), (1_500, 3_000));
    }
}
