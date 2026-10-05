//! Cumulative series for Prometheus that need per-event detail (`spec/06` §5, OBS-005,
//! OBS-011): the upstream-wait stage histogram, per-upstream request outcomes and latency,
//! blocks by group and list, and opt-in per-client query counts. Built by the aggregator
//! thread from events, so the query path stays untouched (OBS-002); like every event-fed
//! view they omit events dropped by a full ring (counted in `telltale_telemetry_dropped_total`).
//! Memory is bounded: upstream and list IDs are small, and clients are capped.

use std::collections::HashMap;

use crate::event::{QueryEvent, UpstreamEvent};
use crate::{BUCKETS_US, Status};

const N_BUCKET: usize = BUCKETS_US.len() + 1;
/// Highest upstream ID with its own series (higher IDs share the last).
const MAX_UPSTREAMS: usize = 256;
/// (group, list) pairs tracked for `telltale_blocked_total`; beyond this, the rest share one.
const MAX_BLOCK_PAIRS: usize = 4096;

/// A classic Prometheus histogram: per-bucket counts (non-cumulative; the last is +Inf).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Buckets {
    pub counts: [u64; N_BUCKET],
    pub sum_us: u64,
}

impl Default for Buckets {
    fn default() -> Self {
        Self {
            counts: [0; N_BUCKET],
            sum_us: 0,
        }
    }
}

impl Buckets {
    pub fn record(&mut self, us: u64) {
        let b = BUCKETS_US
            .iter()
            .position(|&ub| us <= ub)
            .unwrap_or(N_BUCKET - 1);
        self.counts[b] += 1;
        self.sum_us = self.sum_us.saturating_add(us);
    }

    pub fn count(&self) -> u64 {
        self.counts.iter().sum()
    }
}

/// One upstream's exchanges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpstreamTotals {
    pub ok: u64,
    pub failed: u64,
    pub latency: Buckets,
}

/// Everything [`crate::Aggregates`] exports cumulatively.
#[derive(Debug, Clone, Default)]
pub struct Exported {
    /// Time spent waiting for upstreams, per client query that waited.
    pub stage_upstream: Buckets,
    /// By upstream ID.
    pub upstreams: Vec<UpstreamTotals>,
    /// Blocked queries by (primary group index, list ID).
    pub blocked: HashMap<(u16, u16), u64>,
    /// Blocks past [`MAX_BLOCK_PAIRS`] distinct pairs.
    pub blocked_other: u64,
    /// Queries by primary group index and status (ADR-050), groups capped at 64.
    pub groups: Vec<[u64; crate::N_STATUS]>,
    /// Queries per client (v4-mapped), when enabled; at most `client_cap` clients.
    pub clients: HashMap<[u8; 16], u64>,
    /// Queries from clients past the cap.
    pub clients_other: u64,
    /// 0 = per-client series off (the default: high cardinality, OBS-005).
    pub client_cap: usize,
}

impl Exported {
    pub(crate) fn add_query(&mut self, e: &QueryEvent) {
        let g = usize::from(e.group).min(63);
        if self.groups.len() <= g {
            self.groups.resize(g + 1, [0; crate::N_STATUS]);
        }
        self.groups[g][e.status as usize] += 1;
        if e.t_upstream_us > 0 && e.status != Status::Dropped {
            self.stage_upstream.record(u64::from(e.t_upstream_us));
        }
        if e.status == Status::Blocked {
            let list = e.rule.map_or(u16::MAX, |r| r.list);
            let key = (e.group, list);
            if let Some(n) = self.blocked.get_mut(&key) {
                *n += 1;
            } else if self.blocked.len() < MAX_BLOCK_PAIRS {
                self.blocked.insert(key, 1);
            } else {
                self.blocked_other += 1;
            }
        }
        if self.client_cap > 0 {
            if let Some(n) = self.clients.get_mut(&e.client_ip) {
                *n += 1;
            } else if self.clients.len() < self.client_cap {
                self.clients.insert(e.client_ip, 1);
            } else {
                self.clients_other += 1;
            }
        }
    }

    pub(crate) fn add_upstream(&mut self, e: &UpstreamEvent) {
        let i = usize::from(e.upstream).min(MAX_UPSTREAMS - 1);
        if self.upstreams.len() <= i {
            self.upstreams.resize(i + 1, UpstreamTotals::default());
        }
        let u = &mut self.upstreams[i];
        if e.ok {
            u.ok += 1;
        } else {
            u.failed += 1;
        }
        u.latency.record(u64::from(e.latency_us));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Proto;
    use crate::event::{Rule, RuleKind};

    fn query(client: u8, status: Status, list: Option<u16>, upstream_us: u32) -> QueryEvent {
        let mut ip = [0u8; 16];
        ip[10] = 0xff;
        ip[11] = 0xff;
        ip[15] = client;
        QueryEvent {
            ts_us: 0,
            client_ip: ip,
            client_ref: 0,
            group: 1,
            qtype: 1,
            qclass: 1,
            rcode: Some(0),
            status,
            proto: Proto::Udp,
            flags: 0,
            rule: list.map(|l| Rule {
                list: l,
                kind: RuleKind::Domain,
                allow: false,
            }),
            upstream: 0,
            attempts: 0,
            t_total_us: upstream_us + 50,
            t_upstream_us: upstream_us,
            resp_size: 64,
            answers: 1,
        }
    }

    #[test]
    fn obs_005_exported_blocks_stage_upstreams_and_capped_clients() {
        let mut x = Exported {
            client_cap: 2,
            ..Exported::default()
        };
        x.add_query(&query(1, Status::Blocked, Some(3), 0));
        x.add_query(&query(1, Status::Blocked, Some(3), 0));
        x.add_query(&query(2, Status::Forwarded, None, 20_000));
        x.add_query(&query(3, Status::Cached, None, 0));
        assert_eq!(x.blocked.get(&(1, 3)), Some(&2));
        assert_eq!(x.stage_upstream.count(), 1, "only queries that waited");
        assert_eq!(x.clients.len(), 2);
        assert_eq!(x.clients_other, 1, "the third client is over the cap");
        for ok in [true, true, false] {
            x.add_upstream(&UpstreamEvent {
                upstream: 2,
                latency_us: 1_500,
                ok,
                ts_us: 0,
                attempts: 1,
            });
        }
        assert_eq!((x.upstreams[2].ok, x.upstreams[2].failed), (2, 1));
        assert_eq!(
            x.upstreams[2].latency.counts[5], 3,
            "1.5 ms lands in the 2.5 ms bucket"
        );
        let off = Exported::default();
        assert_eq!(off.client_cap, 0, "per-client series are opt-in");
    }
}
