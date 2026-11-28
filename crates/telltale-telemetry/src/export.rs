//! Cumulative series for Prometheus that need per-event detail (`spec/06` §5, OBS-005,
//! OBS-011): the upstream-wait stage histogram, per-upstream request outcomes and latency,
//! blocks by group and list, and opt-in per-client query counts. Built by the aggregator
//! thread from events, so the query path stays untouched (OBS-002); like every event-fed
//! view they omit events dropped by a full ring (counted in `telltale_telemetry_dropped_total`).
//! Memory is bounded: upstream and list IDs are small, and clients are capped.

use std::collections::HashMap;

use crate::event::{QueryEvent, Rule, RuleKind, UpstreamEvent};
use crate::{BUCKETS_US, Status};

const N_BUCKET: usize = BUCKETS_US.len() + 1;
/// Highest upstream ID with its own series (higher IDs share the last).
const MAX_UPSTREAMS: usize = 256;
/// (group, list) pairs tracked for `telltale_blocked_total`; beyond this, the rest share one.
const MAX_BLOCK_PAIRS: usize = 4096;
/// Rows of [`Exported::groups`]: one per group index, the last shared by every higher index.
const GROUP_ROWS: usize = 64;

/// `telltale_blocked_total{list}` keys that aren't list IDs. `Rule::list` names a filter list
/// only for list rules: a quick rule carries its 16-bit reference, a schedule its reference,
/// and an answer-address block 0, which would all read as some list's name (FLT-013).
pub const LIST_NONE: u16 = u16::MAX;
pub const LIST_QUICK: u16 = u16::MAX - 1;
pub const LIST_SCHEDULE: u16 = u16::MAX - 2;
pub const LIST_ANSWER_IP: u16 = u16::MAX - 3;

/// What blocked a query, as the `list` key: a list ID, or one of the `LIST_*` keys.
pub fn blocked_by(rule: Option<Rule>) -> u16 {
    match rule {
        None => LIST_NONE,
        Some(r) => match r.kind {
            RuleKind::Quick => LIST_QUICK,
            RuleKind::Schedule => LIST_SCHEDULE,
            RuleKind::AnswerIp => LIST_ANSWER_IP,
            RuleKind::Domain | RuleKind::Modifier | RuleKind::Regex | RuleKind::Cname => r.list,
        },
    }
}

/// The `list` label for a [`blocked_by`] key (`lists` by ID).
pub fn blocked_label(key: u16, lists: &[String]) -> &str {
    match key {
        LIST_NONE => "none",
        LIST_QUICK => "quick",
        LIST_SCHEDULE => "schedule",
        LIST_ANSWER_IP => "answer_ip",
        id => lists.get(usize::from(id)).map_or("unknown", String::as_str),
    }
}

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

    /// Adds `other`'s counts (two rows that become one).
    fn merge(&mut self, other: &Self) {
        for (n, add) in self.counts.iter_mut().zip(&other.counts) {
            *n = n.saturating_add(*add);
        }
        self.sum_us = self.sum_us.saturating_add(other.sum_us);
    }
}

/// One upstream's exchanges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpstreamTotals {
    pub ok: u64,
    pub failed: u64,
    pub latency: Buckets,
}

impl UpstreamTotals {
    fn merge(&mut self, other: &Self) {
        self.ok = self.ok.saturating_add(other.ok);
        self.failed = self.failed.saturating_add(other.failed);
        self.latency.merge(&other.latency);
    }
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
        let g = usize::from(e.group).min(GROUP_ROWS - 1);
        if self.groups.len() <= g {
            self.groups.resize(g + 1, [0; crate::N_STATUS]);
        }
        self.groups[g][e.status as usize] += 1;
        if e.t_upstream_us > 0 && e.status.answered() {
            self.stage_upstream.record(u64::from(e.t_upstream_us));
        }
        if e.status == Status::Blocked {
            let key = (e.group, blocked_by(e.rule));
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

    /// REQ: OBS-005 (issue #108) — for a reload that renumbers the groups (`old` and `new`: the
    /// group names by index, before and after): moves each group's query and block counts to
    /// its name's new index. `/metrics` names these rows from the group table in force, so a
    /// group added in front of another (an implicit `default` is always last) would otherwise
    /// show that group's count, and a removed one would hand its count to the next. A name that
    /// is gone takes its counts along (its series end), and a new name starts at zero. A row
    /// with no name in `old` is dropped; the last row still holds every index past it, under
    /// the name it was shown with. The same table moves nothing. Reload path only: it
    /// allocates, the query path never calls it.
    pub fn regroup(&mut self, old: &[&str], new: &[&str]) {
        if old == new {
            return;
        }
        let mut index: HashMap<&str, usize> = HashMap::with_capacity(new.len());
        for (i, name) in new.iter().enumerate() {
            index.entry(*name).or_insert(i);
        }
        let to = |g: usize| old.get(g).and_then(|name| index.get(name)).copied();
        let mut groups: Vec<[u64; crate::N_STATUS]> = Vec::new();
        for (g, row) in self.groups.iter().enumerate() {
            let Some(i) = to(g).map(|i| i.min(GROUP_ROWS - 1)) else {
                continue;
            };
            if groups.len() <= i {
                groups.resize(i + 1, [0; crate::N_STATUS]);
            }
            for (n, add) in groups[i].iter_mut().zip(row) {
                *n = n.saturating_add(*add);
            }
        }
        self.groups = groups;
        // Moving keys never adds pairs, so the pair cap still holds; the blocks past it
        // (`group="other"`) belong to no group and stay.
        let blocked = std::mem::take(&mut self.blocked);
        self.blocked.reserve(blocked.len());
        for ((g, list), n) in blocked {
            if let Some(i) = to(usize::from(g)).and_then(|i| u16::try_from(i).ok()) {
                let total = self.blocked.entry((i, list)).or_insert(0);
                *total = total.saturating_add(n);
            }
        }
    }

    /// REQ: OBS-005 (issue #108) — [`Self::regroup`] for upstream IDs (an upstream's place in
    /// the configuration, from 1), for a reload that builds a new router (`old` and `new`: each
    /// upstream's ID and name, before and after): moves each upstream's exchange totals and
    /// latency histogram to the ID its name has now. A name that is gone takes its row along, a
    /// new one starts empty, and ID 0 (every attempt failed: no upstream's) stays. A row no
    /// upstream had is dropped; the last row still holds every ID past it, under the upstream
    /// it was shown with. The same table moves nothing. Reload path only.
    pub fn reupstream(&mut self, old: &[(u16, &str)], new: &[(u16, &str)]) {
        if old == new {
            return;
        }
        let mut index: HashMap<&str, u16> = HashMap::with_capacity(new.len());
        for (id, name) in new {
            index.entry(*name).or_insert(*id);
        }
        let mut name_of: HashMap<u16, &str> = HashMap::with_capacity(old.len());
        for (id, name) in old {
            name_of.entry(*id).or_insert(*name);
        }
        let mut upstreams: Vec<UpstreamTotals> = Vec::new();
        for (row, totals) in self.upstreams.iter().enumerate() {
            let to = if row == 0 {
                Some(0)
            } else {
                u16::try_from(row)
                    .ok()
                    .and_then(|id| name_of.get(&id))
                    .and_then(|name| index.get(name))
                    .map(|&id| usize::from(id).min(MAX_UPSTREAMS - 1))
            };
            let Some(i) = to else {
                continue;
            };
            if upstreams.len() <= i {
                upstreams.resize(i + 1, UpstreamTotals::default());
            }
            upstreams[i].merge(totals);
        }
        self.upstreams = upstreams;
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

    /// REQ: OBS-005, FLT-013 — blocks by a quick rule, a schedule, or an answer address are
    /// keyed by what decided, never by a list that happens to share the number.
    #[test]
    fn obs_005_blocks_are_keyed_by_what_decided() {
        let mut x = Exported::default();
        let mut q = query(1, Status::Blocked, Some(3), 0);
        x.add_query(&q);
        for kind in [RuleKind::Quick, RuleKind::Schedule, RuleKind::AnswerIp] {
            q.rule = Some(Rule {
                list: 3,
                kind,
                allow: false,
            });
            x.add_query(&q);
        }
        q.rule = None;
        x.add_query(&q);
        assert_eq!(
            x.blocked.get(&(1, 3)),
            Some(&1),
            "only the list rule is list 3's"
        );
        assert_eq!(x.blocked.get(&(1, LIST_QUICK)), Some(&1));
        assert_eq!(x.blocked.get(&(1, LIST_SCHEDULE)), Some(&1));
        assert_eq!(x.blocked.get(&(1, LIST_ANSWER_IP)), Some(&1));
        assert_eq!(x.blocked.get(&(1, LIST_NONE)), Some(&1));
        let lists = vec!["ads".to_owned()];
        assert_eq!(blocked_label(0, &lists), "ads");
        assert_eq!(blocked_label(LIST_QUICK, &lists), "quick");
        assert_eq!(blocked_label(LIST_SCHEDULE, &lists), "schedule");
        assert_eq!(blocked_label(LIST_ANSWER_IP, &lists), "answer_ip");
        assert_eq!(blocked_label(LIST_NONE, &lists), "none");
        assert_eq!(blocked_label(7, &lists), "unknown");
    }

    /// `n` queries of group index `group` (a block: list 3's).
    fn add(x: &mut Exported, group: u16, status: Status, n: usize) {
        let mut q = query(1, status, (status == Status::Blocked).then_some(3), 0);
        q.group = group;
        for _ in 0..n {
            x.add_query(&q);
        }
    }

    fn forwarded(x: &Exported, row: usize) -> u64 {
        x.groups
            .get(row)
            .map_or(0, |r| r[Status::Forwarded as usize])
    }

    /// REQ: OBS-005 (issue #108) — `regroup` moves each row to its name's new index: the same
    /// table moves nothing, a gone name and a row with no name are dropped, a new name starts at
    /// zero, the blocks past the pair cap stay, and the last row still holds every index past
    /// it (under the name it is shown with), also when names move past the cap.
    #[test]
    fn obs_005_regroup_moves_rows_by_name() {
        let mut x = Exported::default();
        add(&mut x, 0, Status::Forwarded, 1);
        add(&mut x, 1, Status::Forwarded, 2);
        add(&mut x, 1, Status::Blocked, 1);
        add(&mut x, 5, Status::Forwarded, 7);
        x.blocked_other = 9;
        x.regroup(&["a", "b"], &["a", "b"]);
        assert_eq!(forwarded(&x, 5), 7, "the same table moves nothing");
        x.regroup(&["a", "b"], &["new", "b"]);
        assert_eq!((forwarded(&x, 0), forwarded(&x, 1)), (0, 2));
        assert_eq!(x.groups.len(), 2, "the row with no name is dropped");
        assert_eq!(x.blocked.get(&(1, 3)), Some(&1));
        x.regroup(&["new", "b"], &["b", "new"]);
        assert_eq!((forwarded(&x, 0), forwarded(&x, 1)), (2, 0));
        assert_eq!(x.groups[0][Status::Blocked as usize], 1);
        assert_eq!(x.blocked.get(&(0, 3)), Some(&1));
        assert_eq!(x.blocked.len(), 1);
        assert_eq!(
            x.blocked_other, 9,
            "the blocks past the pair cap are no group's"
        );

        let names: Vec<String> = (0..70).map(|i| format!("g{i}")).collect();
        let many: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut x = Exported::default();
        add(&mut x, 62, Status::Forwarded, 1);
        add(&mut x, 63, Status::Forwarded, 2);
        add(&mut x, 69, Status::Forwarded, 4);
        add(&mut x, 69, Status::Blocked, 1);
        assert_eq!(forwarded(&x, 63), 6, "index 69 shares the last row");
        let mut front = vec!["x0", "x1"];
        front.extend_from_slice(&many);
        x.regroup(&many, &front);
        assert_eq!(x.groups.len(), GROUP_ROWS);
        assert_eq!(
            forwarded(&x, 63),
            7,
            "g62 moved past the cap: it joins the last row"
        );
        assert_eq!(
            x.blocked.get(&(71, 3)),
            Some(&1),
            "block keys aren't capped"
        );
        // The last row is shown as the 64th name, now g61: it goes with that name.
        x.regroup(&front, &["g61", "g69"]);
        assert_eq!((forwarded(&x, 0), forwarded(&x, 1)), (7, 0));
        assert_eq!(x.groups.len(), 1);
        assert_eq!(
            x.blocked.get(&(1, 3)),
            Some(&1),
            "g69's block, by its own index"
        );
        assert_eq!(x.blocked.len(), 1);
    }

    /// `n` exchanges with upstream ID `id`.
    fn exchange(x: &mut Exported, id: u16, n: usize) {
        for _ in 0..n {
            x.add_upstream(&UpstreamEvent {
                upstream: id,
                latency_us: 1_500,
                ok: true,
                ts_us: 0,
                attempts: 1,
            });
        }
    }

    fn exchanges(x: &Exported, id: usize) -> u64 {
        x.upstreams.get(id).map_or(0, |u| u.latency.count())
    }

    /// REQ: OBS-005 (issue #108) — `reupstream` moves each row to its name's new ID: the same
    /// table moves nothing, ID 0 stays, a gone name and a row no upstream had are dropped, a new
    /// one starts empty, and the last row still holds every ID past it.
    #[test]
    fn obs_005_reupstream_moves_histograms_by_name() {
        let mut x = Exported::default();
        exchange(&mut x, 0, 1);
        exchange(&mut x, 1, 2);
        exchange(&mut x, 2, 3);
        exchange(&mut x, 7, 4);
        let ab = [(1, "a"), (2, "b")];
        x.reupstream(&ab, &ab);
        assert_eq!(exchanges(&x, 7), 4, "the same table moves nothing");
        x.reupstream(&ab, &[(1, "c"), (2, "b"), (3, "a")]);
        assert_eq!(
            (0..4).map(|i| exchanges(&x, i)).collect::<Vec<_>>(),
            [1, 0, 3, 2]
        );
        assert_eq!(x.upstreams.len(), 4, "the row no upstream had is dropped");
        assert_eq!((x.upstreams[3].ok, x.upstreams[3].failed), (2, 0));
        x.reupstream(&[(1, "c"), (2, "b"), (3, "a")], &[(1, "b")]);
        assert_eq!((exchanges(&x, 0), exchanges(&x, 1)), (1, 3));
        assert_eq!(x.upstreams.len(), 2);

        let mut x = Exported::default();
        exchange(&mut x, 255, 1);
        exchange(&mut x, 300, 2);
        assert_eq!(exchanges(&x, 255), 3, "ID 300 shares the last row");
        x.reupstream(&[(255, "u255"), (300, "u300")], &[(1, "u300"), (2, "u255")]);
        assert_eq!(
            (exchanges(&x, 1), exchanges(&x, 2)),
            (0, 3),
            "the last row goes with the upstream it was shown with"
        );
        x.reupstream(&[(2, "u255")], &[(400, "u255")]);
        assert_eq!(x.upstreams.len(), MAX_UPSTREAMS);
        assert_eq!(
            exchanges(&x, MAX_UPSTREAMS - 1),
            3,
            "past the cap: the last row"
        );
    }
}
