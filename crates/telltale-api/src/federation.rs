//! Federated reads (REQ: CLU-002, OBS-012; `spec/12` §6): merging what every node answers.
//!
//! - Counters sum (time buckets, by status, type, rcode, group).
//! - Top lists merge Space-Saving counts: per key, counts and error bounds add up, so the true
//!   count still lies in `[count - errorBound, count]`.
//! - Latency rows merge by count-weighted percentiles: approximate (each node sends its
//!   percentiles, not its histogram); exact HDR merging is a follow-up.
//! - Query-log pages are a k-way merge by time with a per-node position in the cursor.

use std::collections::{BTreeMap, HashMap};

use crate::model::{
    ClientStatusCounts, LatencyRow, QueryPage, QueryRow, ScanStats, TimeBucket, TopItem,
};

/// The most buckets one peer is asked for at once. A bucket is about 0.5–2 KB of JSON, so a
/// chunk stays well under the cluster channel's 1 MiB answer.
pub const TIMESERIES_CHUNK: u64 = 240;

/// REQ: CLU-004, CLU-002 (ADR-174, final review F1) — the most windows ([`timeseries_chunks`]) one
/// peer is asked for in one read. The longest range any step documents is 87 (`day`, since
/// 1970; 43 for 7 days of minutes, 41 for 400 days of hours, 4 for 15 minutes of seconds), so
/// this is nearly three times that; what it bounds is a request's reach: one window is one
/// call to each peer.
pub const TIMESERIES_MAX_WINDOWS: u64 = 256;

/// REQ: CLU-002 (regression 2026-11-16) — `[from_s, to_s)` split into consecutive windows of
/// at most [`TIMESERIES_CHUNK`] buckets of `step`, each asked of a peer on its own: a busy
/// node's 24 hours of minutes is over the cluster channel's 1 MiB frame, and a peer whose
/// answer is too large is dropped as "didn't answer". Ranges are half-open, so the windows
/// partition the buckets: none is counted twice.
///
/// REQ: CLU-004 (ADR-174, final review F1) — `None` when the range is more than
/// [`TIMESERIES_MAX_WINDOWS`] windows: the count is worked out first, so a range of any length
/// (a `from` long before the data, a `to` years ahead) costs a division, not a list as long as it.
/// The range is not clipped: the caller doesn't ask the peers at all.
#[must_use]
pub fn timeseries_chunks(
    step: crate::model::Step,
    from_s: u64,
    to_s: u64,
) -> Option<Vec<(u64, u64)>> {
    use crate::model::Step;
    let width = match step {
        Step::Second => 1,
        Step::Minute => 60,
        Step::Hour => 3600,
        Step::Day => 86_400,
    };
    let span = width * TIMESERIES_CHUNK;
    if to_s.saturating_sub(from_s).div_ceil(span) > TIMESERIES_MAX_WINDOWS {
        return None;
    }
    let mut out = Vec::new();
    let mut at = from_s;
    while at < to_s {
        let end = to_s.min(at.saturating_add(span));
        out.push((at, end));
        at = end;
    }
    Some(out)
}

/// Sums buckets with the same start.
pub fn merge_timeseries(parts: Vec<Vec<TimeBucket>>) -> Vec<TimeBucket> {
    let mut by_start: BTreeMap<u64, TimeBucket> = BTreeMap::new();
    let add = |into: &mut BTreeMap<String, u32>, from: BTreeMap<String, u32>| {
        for (k, v) in from {
            *into.entry(k).or_default() += v;
        }
    };
    for b in parts.into_iter().flatten() {
        let t = by_start
            .entry(b.start_unix_seconds)
            .or_insert_with(|| TimeBucket {
                start_unix_seconds: b.start_unix_seconds,
                ..TimeBucket::default()
            });
        t.total += b.total;
        t.upstream_queries += b.upstream_queries;
        t.upstream_failures += b.upstream_failures;
        t.slow += b.slow;
        add(&mut t.by_status, b.by_status);
        add(&mut t.by_qtype, b.by_qtype);
        add(&mut t.by_rcode, b.by_rcode);
        add(&mut t.by_group, b.by_group);
        add(&mut t.blocked_by_group, b.blocked_by_group);
        // REQ: OBS-027 — the bad answers broken down add up the same way.
        add(&mut t.servfail_by_status, b.servfail_by_status);
        add(&mut t.slow_by_status, b.slow_by_status);
        add(&mut t.servfail_by_upstream, b.servfail_by_upstream);
        add(&mut t.slow_by_upstream, b.slow_by_upstream);
        add(&mut t.slow_by_rcode, b.slow_by_rcode);
        // REQ: OBS-032 — flow joints add by key.
        add(&mut t.flow, b.flow);
        // REQ: OBS-030 — latency rows add element-wise.
        for (k, row) in b.latency_hist {
            let into = t.latency_hist.entry(k).or_default();
            if into.len() < row.len() {
                into.resize(row.len(), 0);
            }
            for (x, y) in into.iter_mut().zip(row) {
                *x += y;
            }
        }
    }
    by_start.into_values().collect()
}

/// REQ: OBS-018 (ADR-109) — every node's shadow-list counts, merged by list: hits and devices
/// add (a device seen by two nodes counts twice), the top names add by name (20 kept), the
/// earliest start and the latest hit win.
pub fn merge_shadow(
    parts: Vec<Vec<crate::model::ShadowListStats>>,
) -> Vec<crate::model::ShadowListStats> {
    let mut by: BTreeMap<String, crate::model::ShadowListStats> = BTreeMap::new();
    for s in parts.into_iter().flatten() {
        let Some(t) = by.get_mut(&s.list) else {
            by.insert(s.list.clone(), s);
            continue;
        };
        t.hits += s.hits;
        t.devices += s.devices;
        t.since = match (t.since.take(), s.since) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        t.last_hit_at = t.last_hit_at.take().max(s.last_hit_at);
        for n in s.top_names {
            match t.top_names.iter_mut().find(|x| x.name == n.name) {
                Some(x) => x.count += n.count,
                None => t.top_names.push(n),
            }
        }
        t.nodes.extend(s.nodes);
    }
    by.into_values()
        .map(|mut s| {
            s.top_names
                .sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
            s.top_names.truncate(20);
            s
        })
        .collect()
}

/// REQ: OBS-009 (T7.14) — every node's hits per list, added up by list name.
pub fn merge_list_hits(parts: Vec<BTreeMap<String, u64>>) -> BTreeMap<String, u64> {
    let mut by: BTreeMap<String, u64> = BTreeMap::new();
    for (list, n) in parts.into_iter().flatten() {
        *by.entry(list).or_insert(0) += n;
    }
    by
}

/// REQ: OBS-018 (ADR-109) — every node's over-blocking suspects, merged by name and ranked:
/// a normal answer soon after a block weighs ten retry bursts; at most `limit`.
pub fn merge_overblocking(
    parts: Vec<Vec<crate::model::OverblockSuspect>>,
    limit: usize,
) -> Vec<crate::model::OverblockSuspect> {
    let mut by: BTreeMap<String, crate::model::OverblockSuspect> = BTreeMap::new();
    for s in parts.into_iter().flatten() {
        let Some(t) = by.get_mut(&s.name) else {
            by.insert(s.name.clone(), s);
            continue;
        };
        t.devices += s.devices;
        t.retry_bursts += s.retry_bursts;
        t.allowed_after_block += s.allowed_after_block;
        if s.last_seen > t.last_seen {
            t.last_seen = s.last_seen;
        }
        for l in s.lists {
            if !t.lists.contains(&l) {
                t.lists.push(l);
            }
        }
        t.nodes.extend(s.nodes);
    }
    let mut v: Vec<_> = by.into_values().collect();
    let score = |s: &crate::model::OverblockSuspect| s.allowed_after_block * 10 + s.retry_bursts;
    v.sort_by(|a, b| {
        score(b)
            .cmp(&score(a))
            .then_with(|| b.last_seen.cmp(&a.last_seen))
            .then_with(|| a.name.cmp(&b.name))
    });
    v.truncate(limit);
    v
}

/// Merges top lists: counts and error bounds add per key; heaviest `limit` first.
pub fn merge_top(parts: Vec<Vec<TopItem>>, limit: usize) -> Vec<TopItem> {
    let mut by_key: HashMap<String, TopItem> = HashMap::new();
    for item in parts.into_iter().flatten() {
        match by_key.get_mut(&item.key) {
            Some(t) => {
                t.count += item.count;
                t.error_bound += item.error_bound;
                if t.name.is_none() {
                    t.name = item.name;
                }
                if t.groups.is_empty() {
                    t.groups = item.groups;
                }
                // A peer on an older build sends no split: its queries count in `count` only.
                t.by_status = match (t.by_status, item.by_status) {
                    (Some(a), Some(b)) => Some(ClientStatusCounts {
                        blocked: a.blocked + b.blocked,
                        cached: a.cached + b.cached,
                        forwarded: a.forwarded + b.forwarded,
                    }),
                    (a, b) => a.or(b),
                };
            }
            None => {
                by_key.insert(item.key.clone(), item);
            }
        }
    }
    let mut v: Vec<TopItem> = by_key.into_values().collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    v.truncate(limit);
    v
}

/// Merges latency rows per key: counts add, percentiles are count-weighted (approximate),
/// the maximum is exact.
pub fn merge_latency(parts: Vec<Vec<LatencyRow>>) -> Vec<LatencyRow> {
    let mut by_key: BTreeMap<String, Vec<LatencyRow>> = BTreeMap::new();
    for r in parts.into_iter().flatten() {
        by_key.entry(r.key.clone()).or_default().push(r);
    }
    by_key
        .into_iter()
        .map(|(key, rows)| {
            let count: u64 = rows.iter().map(|r| r.count).sum();
            #[allow(clippy::cast_precision_loss)] // counts far below 2^52
            let w = |f: fn(&LatencyRow) -> f64| {
                if count == 0 {
                    0.0
                } else {
                    rows.iter().map(|r| f(r) * r.count as f64).sum::<f64>() / count as f64
                }
            };
            LatencyRow {
                key,
                count,
                p50_ms: w(|r| r.p50_ms),
                p90_ms: w(|r| r.p90_ms),
                p99_ms: w(|r| r.p99_ms),
                p999_ms: w(|r| r.p999_ms),
                max_ms: rows.iter().map(|r| r.max_ms).fold(0.0, f64::max),
            }
        })
        .collect()
}

/// Prefix of a federated query-log cursor.
pub const CURSOR_PREFIX: &str = "fed:";

/// Where each node's next page starts: before this time (exclusive, Unix µs), or `None` once
/// the node has nothing more.
pub type Bounds = BTreeMap<String, Option<u64>>;

/// Reads a federated cursor (`None` for no cursor or a node-local one).
pub fn decode_cursor(c: Option<&str>) -> Option<Bounds> {
    let body = c?.strip_prefix(CURSOR_PREFIX)?;
    let bytes = data_encoding_base64url(body)?;
    serde_json::from_slice(&bytes).ok()
}

fn encode_cursor(b: &Bounds) -> String {
    let json = serde_json::to_vec(b).unwrap_or_default();
    format!("{CURSOR_PREFIX}{}", base64url(&json))
}

/// Where `node`'s next page ends (exclusive, Unix µs; 0 = no end), or `None` to skip it: it
/// ran out, or it wasn't part of the paging when it started.
pub fn until(prev: &Bounds, node: &str, to_us: u64) -> Option<u64> {
    match prev.get(node) {
        None if prev.is_empty() => Some(to_us),
        None | Some(None) => None,
        Some(Some(b)) => Some(if to_us == 0 { *b } else { to_us.min(*b) }),
    }
}

/// One node's page for a federated read.
#[derive(Debug)]
pub struct NodePage {
    /// The node's ID (the cursor key).
    pub node: String,
    /// What to show in each row's `node` (its site).
    pub label: String,
    pub page: QueryPage,
    /// How many rows were asked of it.
    pub asked: usize,
}

/// Merges nodes' pages newest first and builds the cursor for the next page. Rows sharing the
/// exact microsecond with the last row taken from a node may be skipped on the next page.
pub fn merge_queries(pages: Vec<NodePage>, limit: usize, prev: &Bounds) -> QueryPage {
    let mut rows: Vec<(String, QueryRow)> = Vec::new();
    let mut scanned = ScanStats::default();
    let mut returned: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let client_truncated = pages.iter().any(|p| p.page.client_truncated);
    for p in pages {
        scanned.segments += p.page.scanned.segments;
        scanned.blocks_read += p.page.scanned.blocks_read;
        scanned.blocks_total += p.page.scanned.blocks_total;
        scanned.rows_scanned += p.page.scanned.rows_scanned;
        returned.insert(p.node.clone(), (p.page.items.len(), p.asked));
        for mut r in p.page.items {
            // Rows a node stores for others (ship mode) already name their node.
            if r.node.is_none() {
                r.node = Some(p.label.clone());
            }
            rows.push((p.node.clone(), r));
        }
    }
    rows.sort_by_key(|r| std::cmp::Reverse(r.1.ts_unix_micros));
    rows.truncate(limit);
    let mut bounds = prev.clone();
    let mut more = false;
    for (node, (n, asked)) in &returned {
        let taken: Vec<&QueryRow> = rows
            .iter()
            .filter(|(k, _)| k == node)
            .map(|(_, r)| r)
            .collect();
        let exhausted = *n < *asked && taken.len() == *n;
        let bound = if exhausted {
            None
        } else {
            more = true;
            taken.last().map_or_else(
                || prev.get(node).copied().flatten(),
                |r| Some(r.ts_unix_micros),
            )
        };
        bounds.insert(node.clone(), bound);
    }
    QueryPage {
        items: rows.into_iter().map(|(_, r)| r).collect(),
        next_cursor: more.then(|| encode_cursor(&bounds)),
        scanned,
        missing_nodes: Vec::new(),
        client_truncated,
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(char::from(B64[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

fn data_encoding_base64url(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = u32::try_from(B64.iter().position(|&b| b == c)?).ok()?;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{NameCount, OverblockSuspect, ShadowListStats};

    // REQ: OBS-009 (T7.14) — list hits add up by name over nodes; a list only one node has
    // used keeps its count, and a node with none (the API's own, say) adds nothing.
    #[test]
    fn obs_009_list_hits_merge() {
        let node = |rows: &[(&str, u64)]| {
            rows.iter()
                .map(|(l, n)| ((*l).to_owned(), *n))
                .collect::<BTreeMap<_, _>>()
        };
        let m = merge_list_hits(vec![
            node(&[("ads", 0), ("trackers", 0)]),
            node(&[("ads", 40), ("trackers", 2)]),
            node(&[("ads", 9), ("malware", 1)]),
        ]);
        assert_eq!(
            m.into_iter().collect::<Vec<_>>(),
            vec![
                ("ads".to_owned(), 49),
                ("malware".to_owned(), 1),
                ("trackers".to_owned(), 2)
            ]
        );
        assert!(merge_list_hits(Vec::new()).is_empty());
    }

    // REQ: CLU-002 (regression 2026-11-16) — 48 hours of minutes go to a peer as 12 windows of
    // 4 hours, end to end; a short window is one; an empty one none.
    #[test]
    fn clu_002_timeseries_windows_partition_the_range() {
        use crate::model::Step;
        let from = 1_791_072_030;
        let w = timeseries_chunks(Step::Minute, from, from + 48 * 3600).unwrap();
        assert_eq!(w.len(), 12);
        assert_eq!(w[0], (from, from + 4 * 3600));
        assert!(w.windows(2).all(|p| p[0].1 == p[1].0));
        assert_eq!(w.last().map(|x| x.1), Some(from + 48 * 3600));
        assert_eq!(
            timeseries_chunks(Step::Minute, from, from + 3600),
            Some(vec![(from, from + 3600)])
        );
        assert_eq!(
            timeseries_chunks(Step::Hour, from, from + 400 * 86_400)
                .unwrap()
                .len(),
            40
        );
        assert_eq!(timeseries_chunks(Step::Second, from, from), Some(vec![]));
    }

    // REQ: CLU-002, CLU-004 (final review, F1) — a time range of any length is at most 256
    // windows a peer: a range over that is not chunked at all (and so nothing proportional to it
    // is allocated). Before: a range from the epoch at one second a bucket made 7.5 million
    // windows a peer, and one to the year 9999 a thousand million.
    #[test]
    fn clu_002_timeseries_windows_stop_at_the_cap() {
        use crate::model::Step;
        let now = 1_791_072_000;
        // The request that was the report: from the epoch, a second at a time.
        assert_eq!(timeseries_chunks(Step::Second, 0, now), None);
        // And the ends of the line: the whole of time, to the year 9999 or to the end of the
        // counter, answers at once and without overflowing.
        for step in [Step::Second, Step::Minute, Step::Hour, Step::Day] {
            assert_eq!(timeseries_chunks(step, 0, u64::MAX), None, "{step:?}");
            assert_eq!(
                timeseries_chunks(step, 0, 253_402_300_799),
                None,
                "{step:?}"
            );
        }
        // A range that ends at the end of time but is short is still chunked, without a wrap.
        assert_eq!(
            timeseries_chunks(Step::Second, u64::MAX - 100, u64::MAX),
            Some(vec![(u64::MAX - 100, u64::MAX)])
        );
        // The cap is exact: 256 windows are chunked, 257 are not, at every step.
        for (step, window) in [
            (Step::Second, 240),
            (Step::Minute, 14_400),
            (Step::Hour, 864_000),
            (Step::Day, 20_736_000),
        ] {
            let from = 1_000_000;
            let at_cap = timeseries_chunks(step, from, from + 256 * window).unwrap();
            assert_eq!(at_cap.len(), 256, "{step:?}");
            assert_eq!(
                timeseries_chunks(step, from, from + 256 * window + 1),
                None,
                "{step:?}"
            );
        }
        // No range, or a backwards one, is no window.
        assert_eq!(timeseries_chunks(Step::Hour, 50, 40), Some(vec![]));
    }

    // REQ: CLU-002 (final review, F1) — what the cap must not touch: the longest range each step
    // documents (`step=second` 15 minutes, `minute` 7 days, `hour` 400 days, `day` everything,
    // here since 1970), each as the exact windows it always was, partitioning the range.
    #[test]
    fn clu_002_the_documented_ranges_are_chunked_in_full() {
        use crate::model::Step;
        let now = 1_791_072_000;
        let cases = [
            (Step::Second, now - 900, now + 1, 4),
            (Step::Minute, now - 7 * 86_400, now + 1, 43),
            (Step::Hour, now - 400 * 86_400, now + 1, 41),
            (Step::Day, 0, now + 1, 87),
        ];
        for (step, from, to, n) in cases {
            let w = timeseries_chunks(step, from, to).unwrap();
            assert_eq!(w.len(), n, "{step:?}");
            assert_eq!(w.first().map(|x| x.0), Some(from), "{step:?}");
            assert_eq!(w.last().map(|x| x.1), Some(to), "{step:?}");
            assert!(w.windows(2).all(|p| p[0].1 == p[1].0), "{step:?}");
        }
    }

    // REQ: OBS-018 — two nodes' shadow counts add up by list, top names by name, the earliest
    // start and latest hit win; suspects merge by name and rank allows above retries.
    #[test]
    fn obs_018_shadow_and_suspects_merge() {
        let s = |node: &str, hits, since: &str, top: &[(&str, u64)]| ShadowListStats {
            list: "candidate".into(),
            since: Some(since.into()),
            hits,
            devices: 1,
            top_names: top
                .iter()
                .map(|(n, c)| NameCount {
                    name: (*n).into(),
                    count: *c,
                })
                .collect(),
            last_hit_at: Some(format!("{since}-last")),
            nodes: vec![node.into()],
        };
        let m = merge_shadow(vec![
            vec![s(
                "pi",
                3,
                "2026-10-09T01",
                &[("a.example", 2), ("b.example", 1)],
            )],
            vec![s("pod", 5, "2026-10-08T23", &[("b.example", 4)])],
        ]);
        assert_eq!(m.len(), 1);
        assert_eq!((m[0].hits, m[0].devices), (8, 2));
        assert_eq!(m[0].since.as_deref(), Some("2026-10-08T23"));
        assert_eq!(
            (m[0].top_names[0].name.as_str(), m[0].top_names[0].count),
            ("b.example", 5)
        );
        assert_eq!(m[0].nodes, ["pi", "pod"]);
        let o = |name: &str, retries, allowed, list: &str| OverblockSuspect {
            name: name.into(),
            lists: vec![list.into()],
            devices: 1,
            retry_bursts: retries,
            allowed_after_block: allowed,
            last_seen: "2026-10-09T00:00:00.000Z".into(),
            nodes: Vec::new(),
        };
        let v = merge_overblocking(
            vec![
                vec![
                    o("ads.example", 9, 0, "oisd"),
                    o("shop.example", 0, 1, "hagezi"),
                ],
                vec![o("shop.example", 1, 0, "oisd")],
            ],
            10,
        );
        assert_eq!(
            v[0].name, "shop.example",
            "an allow after a block weighs more"
        );
        assert_eq!(
            (v[0].retry_bursts, v[0].allowed_after_block, v[0].devices),
            (1, 1, 2)
        );
        assert_eq!(v[0].lists, ["hagezi", "oisd"]);
        assert_eq!(merge_overblocking(vec![v], 1).len(), 1, "limited");
    }

    fn bucket(start: u64, total: u32, blocked: u32, group: &str) -> TimeBucket {
        let mut b = TimeBucket {
            start_unix_seconds: start,
            total,
            ..TimeBucket::default()
        };
        b.by_status.insert("blocked".into(), blocked);
        b.by_group.insert(group.into(), total);
        b
    }

    fn row(ts: u64, name: &str) -> QueryRow {
        QueryRow {
            time: String::new(),
            ts_unix_micros: ts,
            client: "192.168.1.2".into(),
            client_name: None,
            group: None,
            name: name.into(),
            qtype: "A".into(),
            status: "forwarded".into(),
            rcode: None,
            proto: "udp".into(),
            list: None,
            rule: None,
            total_ms: 1.0,
            upstream_ms: 0.5,
            response_bytes: 40,
            answers: 1,
            node: None,
        }
    }

    // REQ: CLU-002 — counters sum per bucket, by every breakdown.
    #[test]
    fn clu_002_timeseries_sum_per_bucket() {
        let m = merge_timeseries(vec![
            vec![bucket(60, 10, 2, "IOT"), bucket(120, 5, 0, "IOT")],
            vec![bucket(60, 7, 1, "Trust")],
        ]);
        assert_eq!(m.len(), 2);
        assert_eq!(
            (
                m[0].start_unix_seconds,
                m[0].total,
                m[0].by_status["blocked"]
            ),
            (60, 17, 3)
        );
        assert_eq!((m[0].by_group["IOT"], m[0].by_group["Trust"]), (10, 7));
        assert_eq!(m[1].total, 5);
    }

    // REQ: OBS-012 — Space-Saving lists merge by adding counts and error bounds.
    #[test]
    fn obs_012_top_lists_merge_counts_and_bounds() {
        let item = |k: &str, c, e| TopItem {
            key: k.into(),
            name: None,
            count: c,
            error_bound: e,
            groups: Vec::new(),
            by_status: None,
        };
        let m = merge_top(
            vec![
                vec![item("a.test", 10, 1), item("b.test", 8, 0)],
                vec![item("b.test", 5, 2), item("c.test", 1, 0)],
            ],
            2,
        );
        assert_eq!(m.len(), 2);
        assert_eq!(
            (m[0].key.as_str(), m[0].count, m[0].error_bound),
            ("b.test", 13, 2)
        );
        assert_eq!((m[1].key.as_str(), m[1].count), ("a.test", 10));
    }

    // REQ: OBS-012 — clients' status splits add up across nodes; a node that sends none (an
    // older build) leaves the others' split as it is.
    #[test]
    fn obs_012_top_clients_merge_status_splits() {
        let item = |c, s: Option<(u64, u64, u64)>| TopItem {
            key: "10.0.0.7".into(),
            name: None,
            count: c,
            error_bound: 0,
            groups: Vec::new(),
            by_status: s.map(|(blocked, cached, forwarded)| ClientStatusCounts {
                blocked,
                cached,
                forwarded,
            }),
        };
        let m = merge_top(
            vec![
                vec![item(10, Some((4, 3, 2)))],
                vec![item(5, Some((1, 1, 3)))],
                vec![item(7, None)],
            ],
            5,
        );
        assert_eq!(m[0].count, 22);
        assert_eq!(
            m[0].by_status,
            Some(ClientStatusCounts {
                blocked: 5,
                cached: 4,
                forwarded: 5
            })
        );
        let only_old = merge_top(vec![vec![item(7, None)], vec![item(2, None)]], 5);
        assert_eq!(only_old[0].by_status, None);
    }

    #[test]
    fn obs_012_latency_merges_weighted_with_the_exact_max() {
        let r = |c, p, max| LatencyRow {
            key: "cache/udp".into(),
            count: c,
            p50_ms: p,
            p90_ms: p,
            p99_ms: p,
            p999_ms: p,
            max_ms: max,
        };
        let m = merge_latency(vec![vec![r(30, 1.0, 5.0)], vec![r(10, 5.0, 9.0)]]);
        assert_eq!(m[0].count, 40);
        assert!((m[0].p50_ms - 2.0).abs() < 1e-9);
        assert!((m[0].max_ms - 9.0).abs() < 1e-9);
    }

    // REQ: CLU-002 — query pages merge newest first, and the cursor resumes each node where
    // its rows stopped; a node that ran out stays out.
    #[test]
    fn clu_002_query_pages_merge_and_resume() {
        let page = |rows: Vec<QueryRow>| QueryPage {
            items: rows,
            next_cursor: None,
            scanned: ScanStats::default(),
            missing_nodes: Vec::new(),
            client_truncated: false,
        };
        let first = merge_queries(
            vec![
                NodePage {
                    node: "a".into(),
                    label: "k8s".into(),
                    page: page(vec![row(100, "a1"), row(80, "a2"), row(60, "a3")]),
                    asked: 3,
                },
                NodePage {
                    node: "b".into(),
                    label: "pi".into(),
                    page: page(vec![row(90, "b1")]),
                    asked: 3,
                },
            ],
            3,
            &Bounds::new(),
        );
        let names: Vec<_> = first.items.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["a1", "b1", "a2"]);
        assert_eq!(first.items[1].node.as_deref(), Some("pi"));
        let bounds = decode_cursor(first.next_cursor.as_deref()).unwrap();
        assert_eq!(bounds["a"], Some(80));
        assert_eq!(
            bounds["b"], None,
            "b returned fewer rows than asked and all were taken"
        );
        assert!(decode_cursor(Some("not-federated")).is_none());
        // Everything exhausted: no next cursor.
        let last = merge_queries(
            vec![NodePage {
                node: "a".into(),
                label: "k8s".into(),
                page: page(vec![row(60, "a3")]),
                asked: 3,
            }],
            3,
            &bounds,
        );
        assert!(last.next_cursor.is_none());
        assert_eq!(base64url(b"hello?"), "aGVsbG8_");
        assert_eq!(data_encoding_base64url("aGVsbG8_").unwrap(), b"hello?");
    }
}
