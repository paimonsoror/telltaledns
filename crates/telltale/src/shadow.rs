//! REQ: OBS-018 (T11.5, ADR-109, `spec/06` §7.2) — tuning the blocklists with evidence, on the
//! telemetry thread (a [`Sink`]; never the query path):
//!
//! - **Shadow lists** (`mode = "shadow"`): compiled with the rest but left out of every
//!   enforcing mask, so they never block. For each query answered normally, the filter decides
//!   again with the group's mask plus its shadow lists; a block by a shadow list is what it
//!   would have done, counted per list (queries, devices, top names). Nothing to do, and no cost,
//!   while no list is in shadow mode.
//! - **Over-blocking suspects:** blocked names a device asked for 10 or more times within a
//!   minute (apps that break retry), or got answered normally within 10 minutes of a block
//!   (someone paused blocking or allowed it). Bounded maps; the oldest are forgotten.
//!
//! Names are kept as the query log's privacy level allows (hashed at 1 and above), devices not
//! at all at 2 and above. Everything is since start, per node.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::hash::BuildHasher;
use std::sync::{Arc, Mutex, PoisonError};

use telltale_api::model::{NameCount, OverblockSuspect, ShadowListStats};
use telltale_filter::matcher::{ClientCtx, Decision, Scratch};
use telltale_telemetry::event::{QueryEvent, Record};
use telltale_telemetry::ring::Sink;
use telltale_telemetry::topk::SpaceSaving;
use telltale_telemetry::{RuleKind, Status};

/// Asking again within this long counts toward a burst...
const RETRY_WINDOW_US: u64 = 60_000_000;
/// ...of this many blocked queries for the same name from the same device.
const RETRY_BURST: u32 = 10;
/// A normal answer this soon after a block suggests someone wanted the name.
const ALLOWED_AFTER_US: u64 = 600_000_000;
/// Recent blocks remembered (device, name), suspects kept, devices counted per item.
const MAX_RECENT: usize = 8192;
const MAX_SUSPECTS: usize = 512;
const MAX_DEVICES_PER_LIST: usize = 4096;
const MAX_DEVICES_PER_SUSPECT: usize = 64;
/// Names tracked per shadow list (Space-Saving), and reported.
const TOP_CAPACITY: usize = 256;
const TOP_REPORTED: usize = 20;

#[derive(Debug)]
struct ListShadow {
    since_us: u64,
    hits: u64,
    devices: HashSet<[u8; 16]>,
    top: SpaceSaving<Box<[u8]>>,
    last_us: u64,
}

#[derive(Debug)]
struct RecentBlock {
    list: String,
    name: Box<[u8]>,
    first_us: u64,
    last_us: u64,
    count: u32,
    burst_noted: bool,
}

#[derive(Debug, Default)]
struct Suspect {
    lists: BTreeSet<String>,
    devices: HashSet<[u8; 16]>,
    retry_bursts: u64,
    allowed_after_block: u64,
    last_us: u64,
}

#[derive(Debug, Default)]
struct State {
    lists: BTreeMap<String, ListShadow>,
    recent: HashMap<([u8; 16], u64), RecentBlock>,
    order: VecDeque<([u8; 16], u64)>,
    /// By name (wire format, as kept).
    suspects: HashMap<Box<[u8]>, Suspect>,
}

/// The shared counts (the sink writes, the API reads).
#[derive(Debug)]
pub(crate) struct Shadow {
    state: Mutex<State>,
    /// The query log's privacy level (read at start, like the event sinks).
    privacy: u8,
    hasher: std::collections::hash_map::RandomState,
    started_us: u64,
}

fn lock(s: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    s.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shadow {
    pub(crate) fn new(privacy: u8, started_us: u64) -> Self {
        Self {
            state: Mutex::default(),
            privacy,
            hasher: std::collections::hash_map::RandomState::new(),
            started_us,
        }
    }

    /// A name as it may be kept.
    fn kept(&self, wire: &[u8]) -> Box<[u8]> {
        if self.privacy >= 1 {
            telltale_store::qlog::hidden_name(wire)
        } else {
            wire.into()
        }
    }

    /// A device, if it may be counted.
    fn device(&self, e: &QueryEvent) -> Option<[u8; 16]> {
        (self.privacy < 2).then_some(e.client_ip)
    }

    fn suspect<'a>(state: &'a mut State, name: &[u8]) -> &'a mut Suspect {
        if !state.suspects.contains_key(name) && state.suspects.len() >= MAX_SUSPECTS {
            // The least recently seen makes room.
            if let Some(old) = state
                .suspects
                .iter()
                .min_by_key(|(_, s)| s.last_us)
                .map(|(k, _)| k.clone())
            {
                state.suspects.remove(&old);
            }
        }
        state.suspects.entry(name.into()).or_default()
    }

    /// A block by `list`: remembered, and a retry burst once a device asks often enough.
    pub(crate) fn note_block(&self, e: &QueryEvent, wire: &[u8], list: &str) {
        let name = self.kept(wire);
        let key = (e.client_ip, self.hasher.hash_one(&*name));
        let mut st = lock(&self.state);
        let burst = match st.recent.get_mut(&key) {
            Some(b) if e.ts_us.saturating_sub(b.first_us) <= RETRY_WINDOW_US => {
                b.count += 1;
                b.last_us = e.ts_us;
                let now = b.count >= RETRY_BURST && !b.burst_noted;
                b.burst_noted |= now;
                now
            }
            Some(b) => {
                (b.first_us, b.last_us, b.count, b.burst_noted) = (e.ts_us, e.ts_us, 1, false);
                false
            }
            None => {
                if st.recent.len() >= MAX_RECENT
                    && let Some(old) = st.order.pop_front()
                {
                    st.recent.remove(&old);
                }
                st.order.push_back(key);
                st.recent.insert(
                    key,
                    RecentBlock {
                        list: list.to_owned(),
                        name: name.clone(),
                        first_us: e.ts_us,
                        last_us: e.ts_us,
                        count: 1,
                        burst_noted: false,
                    },
                );
                false
            }
        };
        if burst {
            let device = self.device(e);
            let s = Self::suspect(&mut st, &name);
            s.retry_bursts += 1;
            s.lists.insert(list.to_owned());
            s.last_us = s.last_us.max(e.ts_us);
            if let Some(d) = device
                && s.devices.len() < MAX_DEVICES_PER_SUSPECT
            {
                s.devices.insert(d);
            }
        }
    }

    /// A normal answer: if the same device had it blocked moments ago, someone wanted it.
    pub(crate) fn note_resolved(&self, e: &QueryEvent, wire: &[u8]) {
        let name = self.kept(wire);
        let key = (e.client_ip, self.hasher.hash_one(&*name));
        let mut st = lock(&self.state);
        let Some(b) = st.recent.remove(&key) else {
            return;
        };
        if e.ts_us.saturating_sub(b.last_us) > ALLOWED_AFTER_US || b.name != name {
            return;
        }
        let device = self.device(e);
        let s = Self::suspect(&mut st, &name);
        s.allowed_after_block += 1;
        s.lists.insert(b.list);
        s.last_us = s.last_us.max(e.ts_us);
        if let Some(d) = device
            && s.devices.len() < MAX_DEVICES_PER_SUSPECT
        {
            s.devices.insert(d);
        }
    }

    /// A shadow list would have blocked this query.
    pub(crate) fn note_shadow(&self, e: &QueryEvent, wire: &[u8], list: &str) {
        let name = self.kept(wire);
        let device = self.device(e);
        let started = self.started_us;
        let mut st = lock(&self.state);
        let l = st
            .lists
            .entry(list.to_owned())
            .or_insert_with(|| ListShadow {
                since_us: started,
                hits: 0,
                devices: HashSet::new(),
                top: SpaceSaving::new(TOP_CAPACITY),
                last_us: 0,
            });
        l.hits += 1;
        l.last_us = l.last_us.max(e.ts_us);
        if let Some(d) = device
            && l.devices.len() < MAX_DEVICES_PER_LIST
        {
            l.devices.insert(d);
        }
        l.top.offer(&*name, |k: &[u8]| Box::from(k));
    }

    /// Would-be blocks per shadow list, for `/metrics`.
    pub(crate) fn hits(&self) -> Vec<(String, u64)> {
        lock(&self.state)
            .lists
            .iter()
            .map(|(k, v)| (k.clone(), v.hits))
            .collect()
    }

    /// The API's view: every list in `shadow` (counted or not yet).
    pub(crate) fn lists_view(&self, shadow: &[Box<str>]) -> Vec<ShadowListStats> {
        let st = lock(&self.state);
        shadow
            .iter()
            .map(|name| match st.lists.get(&**name) {
                Some(l) => ShadowListStats {
                    list: name.to_string(),
                    since: Some(telltale_api::time::format_us(l.since_us)),
                    hits: l.hits,
                    devices: l.devices.len() as u64,
                    top_names: l
                        .top
                        .top(TOP_REPORTED)
                        .into_iter()
                        .map(|t| NameCount {
                            name: telltale_telemetry::event::dotted(&t.key),
                            count: t.count,
                        })
                        .collect(),
                    last_hit_at: (l.last_us > 0).then(|| telltale_api::time::format_us(l.last_us)),
                    nodes: Vec::new(),
                },
                None => ShadowListStats {
                    list: name.to_string(),
                    since: Some(telltale_api::time::format_us(self.started_us)),
                    ..ShadowListStats::default()
                },
            })
            .collect()
    }

    /// The API's view of the suspects, best first, at most `limit`.
    pub(crate) fn suspects_view(&self, limit: usize) -> Vec<OverblockSuspect> {
        let st = lock(&self.state);
        let rows = st
            .suspects
            .iter()
            .map(|(name, s)| OverblockSuspect {
                name: telltale_telemetry::event::dotted(name),
                lists: s.lists.iter().cloned().collect(),
                devices: s.devices.len() as u64,
                retry_bursts: s.retry_bursts,
                allowed_after_block: s.allowed_after_block,
                last_seen: telltale_api::time::format_us(s.last_us),
                nodes: Vec::new(),
            })
            .collect();
        telltale_api::federation::merge_overblocking(vec![rows], limit)
    }
}

/// Feeds query events to [`Shadow`] on the telemetry thread.
pub(crate) struct ShadowSink {
    shared: Arc<Shadow>,
    pipeline: Arc<crate::pipeline::Pipeline>,
    scratch: Scratch,
}

impl ShadowSink {
    pub(crate) fn new(shared: Arc<Shadow>, pipeline: Arc<crate::pipeline::Pipeline>) -> Self {
        Self {
            shared,
            pipeline,
            scratch: Scratch::default(),
        }
    }
}

impl Sink for ShadowSink {
    fn record(&mut self, r: &Record) {
        let Record::Query(e, name) = r else {
            return;
        };
        let guard = self.pipeline.filter.load();
        let Some(f) = guard.as_deref() else {
            return;
        };
        match e.status {
            Status::Blocked => {
                if let Some(rule) = e.rule
                    && !rule.allow
                    && matches!(
                        rule.kind,
                        RuleKind::Domain | RuleKind::Modifier | RuleKind::Regex | RuleKind::Cname
                    )
                    && let Some(list) = f.list_names.get(usize::from(rule.list))
                {
                    self.shared.note_block(e, name.as_wire(), list);
                }
            }
            Status::Cached | Status::Forwarded | Status::Stale | Status::Refreshed => {
                self.shared.note_resolved(e, name.as_wire());
                if f.shadow_group_masks.is_empty() || e.rule.is_some_and(|r| r.allow) {
                    return;
                }
                let Some(mask) = f.shadow_group_masks.get(usize::from(e.group)) else {
                    return;
                };
                let ip = std::net::Ipv6Addr::from(e.client_ip);
                let client = ClientCtx {
                    ip: ip
                        .to_ipv4_mapped()
                        .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
                    name: e
                        .client_ref
                        .checked_sub(1)
                        .and_then(|i| f.clients.clients().get(usize::try_from(i).ok()?))
                        .map(|c| &*c.name),
                    client_id: None,
                };
                if let Decision::Block(a) =
                    f.matcher
                        .decide(name.as_wire(), e.qtype, &client, mask, &mut self.scratch)
                    && f.shadow_ids.contains(a.list)
                    && let Some(list) = f.list_names.get(usize::from(a.list))
                {
                    self.shared.note_shadow(e, name.as_wire(), list);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_telemetry::Proto;

    const NAME: &[u8] = b"\x04shop\x07example\x00";

    fn ev(ts_us: u64, client: u8, status: Status) -> QueryEvent {
        let mut ip = [0u8; 16];
        ip[10..].copy_from_slice(&[0xff, 0xff, 192, 168, 1, client]);
        QueryEvent {
            ts_us,
            client_ip: ip,
            client_ref: 0,
            group: 0,
            qtype: 1,
            qclass: 1,
            rcode: Some(0),
            status,
            proto: Proto::Udp,
            flags: 0,
            rule: None,
            upstream: 0,
            attempts: 0,
            t_total_us: 100,
            t_upstream_us: 0,
            resp_size: 64,
            answers: 1,
        }
    }

    // REQ: OBS-018 — a burst of blocked retries is a suspect once per burst; a normal answer
    // soon after a block is one too; much later, or another device, isn't.
    #[test]
    fn obs_018_overblocking_signals() {
        let s = Shadow::new(0, 0);
        let t0 = 1_800_000_000_000_000;
        for i in 0..12 {
            s.note_block(&ev(t0 + i * 1_000_000, 5, Status::Blocked), NAME, "hagezi");
        }
        let v = s.suspects_view(10);
        assert_eq!(
            (v.len(), v[0].retry_bursts, v[0].allowed_after_block),
            (1, 1, 0)
        );
        assert_eq!(
            (v[0].name.as_str(), v[0].lists.clone()),
            ("shop.example", vec!["hagezi".to_owned()])
        );
        // Another device getting it normally doesn't count; the same one does.
        s.note_resolved(&ev(t0 + 20_000_000, 6, Status::Forwarded), NAME);
        assert_eq!(s.suspects_view(10)[0].allowed_after_block, 0);
        s.note_resolved(&ev(t0 + 20_000_000, 5, Status::Forwarded), NAME);
        let v = s.suspects_view(10);
        assert_eq!((v[0].allowed_after_block, v[0].devices), (1, 1));
        // A block, then an answer an hour later: no signal.
        let other = b"\x03cdn\x07example\x00";
        s.note_block(&ev(t0, 7, Status::Blocked), other, "oisd");
        s.note_resolved(&ev(t0 + 3_600_000_000, 7, Status::Cached), other);
        assert_eq!(s.suspects_view(10).len(), 1);
    }

    // REQ: OBS-018 — would-be blocks counted per shadow list (queries, devices, top names);
    // configured lists without any yet are listed with zero; names hashed at privacy level 1,
    // devices not counted at 2.
    #[test]
    fn obs_018_shadow_counts_and_privacy() {
        let s = Shadow::new(0, 5);
        for c in [1, 1, 2] {
            s.note_shadow(&ev(10, c, Status::Forwarded), NAME, "new-list");
        }
        let v = s.lists_view(&["new-list".into(), "quiet".into()]);
        assert_eq!((v[0].hits, v[0].devices), (3, 2));
        assert_eq!(v[0].top_names[0].name, "shop.example");
        assert_eq!((v[1].list.as_str(), v[1].hits), ("quiet", 0));
        assert_eq!(s.hits(), vec![("new-list".to_owned(), 3)]);
        let private = Shadow::new(2, 5);
        private.note_shadow(&ev(10, 1, Status::Forwarded), NAME, "new-list");
        let v = private.lists_view(&["new-list".into()]);
        assert_eq!(v[0].devices, 0, "no devices at level 2");
        assert!(
            v[0].top_names[0].name.starts_with('h'),
            "hashed: {}",
            v[0].top_names[0].name
        );
    }
}
