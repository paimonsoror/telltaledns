//! Federated reads (REQ: CLU-002, OBS-012; `spec/12` §6): merging what every node answers.
//!
//! - Counters sum (time buckets, by status, type, rcode, group).
//! - Top lists merge Space-Saving counts: per key, counts and error bounds add up, so the true
//!   count still lies in `[count - errorBound, count]`.
//! - Latency rows merge by count-weighted percentiles: approximate (each node sends its
//!   percentiles, not its histogram); exact HDR merging is a follow-up.
//! - Query-log pages are a k-way merge by time with a per-node position in the cursor.

use std::collections::{BTreeMap, HashMap};

use crate::model::{LatencyRow, QueryPage, QueryRow, ScanStats, TimeBucket, TopItem};

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
    }
    by_start.into_values().collect()
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
