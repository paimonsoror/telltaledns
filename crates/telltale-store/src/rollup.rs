//! Rollups (`spec/06` §3, OBS-004, ADR-031): per-minute counts kept 7 days, per-hour 400 days,
//! per-day forever, plus each hour's top-K lists and latency percentiles, in SQLite
//! (`<data_dir>/rollups.db`). Fed once a minute from the aggregator's in-memory windows by a
//! background task, so long-range charts survive restarts and reach back past the 48-hour
//! memory window. Never on the query path.
//!
//! Hour and day rows are recomputed from the rows below them whenever minutes are written,
//! so writing the same minute twice (late events, a re-flush) is harmless.

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use rusqlite::{Connection, OptionalExtension, params};
use telltale_telemetry::agg::Counts;
use telltale_telemetry::{N_PROTO, N_QTYPE, N_RCODE, N_STATUS};

use crate::state::StateError;

type Result<T> = std::result::Result<T, StateError>;

/// Seconds kept per level (`spec/06` §3); day rows are kept forever.
pub const MINUTE_RETENTION_S: u64 = 7 * 86_400;
pub const HOUR_RETENTION_S: u64 = 400 * 86_400;

/// Bucket size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Minute,
    Hour,
    Day,
}

impl Level {
    const fn table(self) -> &'static str {
        match self {
            Self::Minute => "rollup_minute",
            Self::Hour => "rollup_hour",
            Self::Day => "rollup_day",
        }
    }
    pub const fn width_s(self) -> u64 {
        match self {
            Self::Minute => 60,
            Self::Hour => 3600,
            Self::Day => 86_400,
        }
    }
}

/// One stored top-K entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopRow {
    pub key: String,
    pub count: u64,
    pub error: u64,
}

/// One stored latency summary, in microseconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatencyRow {
    pub key: String,
    pub count: u64,
    pub p50: u64,
    pub p90: u64,
    pub p99: u64,
    pub p999: u64,
    pub max: u64,
}

/// The rollup database.
#[derive(Debug)]
pub struct Rollups {
    conn: Mutex<Connection>,
}

/// Version 2 added the transport-column count (DoT and DoH, T4.5); version 1 rows had two.
const VERSION: u8 = 2;

/// `Counts` → bytes: a header with the column counts (so a build with more statuses, qtypes,
/// or transports can still read old rows), then little-endian u32s.
pub fn encode(c: &Counts) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + 4 * (3 + N_STATUS + N_QTYPE + N_RCODE + N_PROTO));
    #[allow(clippy::cast_possible_truncation)] // all < 256
    out.extend_from_slice(&[
        VERSION,
        N_STATUS as u8,
        N_QTYPE as u8,
        N_RCODE as u8,
        N_PROTO as u8,
    ]);
    let mut put = |v: u32| out.extend_from_slice(&v.to_le_bytes());
    put(c.total);
    c.status.iter().for_each(|v| put(*v));
    c.qtype.iter().for_each(|v| put(*v));
    c.rcode.iter().for_each(|v| put(*v));
    c.proto.iter().for_each(|v| put(*v));
    put(c.upstreams.iter().fold(0u32, |a, v| a.saturating_add(*v)));
    put(c.upstream_failures);
    // REQ: OBS-004 (T6.16) — groups by name, after the fixed columns: builds that predate it
    // stop reading before this section, so the version stays 2 and rows stay readable.
    if !c.named_groups.is_empty() {
        out.push(GROUPS_TAG);
        let n = u16::try_from(c.named_groups.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&n.to_le_bytes());
        for g in c.named_groups.iter().take(usize::from(n)) {
            let name = g.name.as_bytes();
            let len = u8::try_from(name.len()).unwrap_or(u8::MAX);
            out.push(len);
            out.extend_from_slice(&name[..usize::from(len)]);
            out.extend_from_slice(&g.total.to_le_bytes());
            out.extend_from_slice(&g.blocked.to_le_bytes());
        }
    }
    // REQ: OBS-016 (T11.1) — slow answers, after the groups: builds that predate it read the
    // group section and stop (or, with no groups, see an unknown tag and read none).
    if c.slow > 0 {
        out.push(SLOW_TAG);
        out.extend_from_slice(&c.slow.to_le_bytes());
    }
    out
}

/// Marks the named-group section (T6.16).
const GROUPS_TAG: u8 = b'G';
/// Marks the slow-answer count (T11.1).
const SLOW_TAG: u8 = b'S';

/// The tagged sections after the fixed columns (see [`encode`]): the named groups and the
/// slow-answer count. A damaged section ends the reading; what came before it is kept.
fn decode_tail(mut b: &[u8]) -> (Vec<telltale_telemetry::agg::NamedGroup>, u32) {
    let mut groups = Vec::new();
    let mut slow = 0;
    while let Some((&tag, rest)) = b.split_first() {
        match tag {
            GROUPS_TAG => match decode_groups(rest) {
                Some((g, r)) => {
                    groups = g;
                    b = r;
                }
                None => break,
            },
            SLOW_TAG => match rest.split_first_chunk::<4>() {
                Some((n, r)) => {
                    slow = u32::from_le_bytes(*n);
                    b = r;
                }
                None => break,
            },
            _ => break,
        }
    }
    (groups, slow)
}

/// The named-group section's body (after its tag) and what follows it; `None` when damaged.
fn decode_groups(b: &[u8]) -> Option<(Vec<telltale_telemetry::agg::NamedGroup>, &[u8])> {
    let mut out = Vec::new();
    let (n, mut rest) = b.split_first_chunk::<2>()?;
    for _ in 0..u16::from_le_bytes(*n) {
        let (&len, r) = rest.split_first()?;
        let len = usize::from(len);
        if r.len() < len + 8 {
            return None;
        }
        let name = String::from_utf8_lossy(&r[..len]);
        let total = u32::from_le_bytes([r[len], r[len + 1], r[len + 2], r[len + 3]]);
        let blocked = u32::from_le_bytes([r[len + 4], r[len + 5], r[len + 6], r[len + 7]]);
        telltale_telemetry::agg::add_named(&mut out, &name, total, blocked);
        rest = &r[len + 8..];
    }
    Some((out, rest))
}

/// Bytes → `Counts` (upstream exchanges come back as a single total in `upstreams[0]`).
pub fn decode(b: &[u8]) -> Option<Counts> {
    let (&[version, ns, nq, nr], rest) = b.split_first_chunk::<4>()?;
    let (np, rest) = match version {
        1 => (2, rest),
        VERSION => rest.split_first().map(|(np, r)| (*np, r))?,
        _ => return None,
    };
    // Where the fixed columns end (the named groups follow, T6.16).
    let words_len =
        4 * (1 + usize::from(ns) + usize::from(nq) + usize::from(nr) + usize::from(np) + 2);
    let tail = rest.get(words_len..).unwrap_or_default();
    let mut words = rest
        .as_chunks::<4>()
        .0
        .iter()
        .map(|w| u32::from_le_bytes(*w));
    let mut c = Counts {
        total: words.next()?,
        ..Counts::default()
    };
    for i in 0..usize::from(ns) {
        let v = words.next()?;
        if let Some(x) = c.status.get_mut(i) {
            *x = v;
        }
    }
    for i in 0..usize::from(nq) {
        let v = words.next()?;
        // Unknown extra qtype columns fold into "other" (the last one).
        let j = i.min(N_QTYPE - 1);
        c.qtype[j] = c.qtype[j].saturating_add(v);
    }
    for i in 0..usize::from(nr) {
        let v = words.next()?;
        let j = i.min(N_RCODE - 1);
        c.rcode[j] = c.rcode[j].saturating_add(v);
    }
    for i in 0..usize::from(np) {
        let v = words.next()?;
        if let Some(x) = c.proto.get_mut(i) {
            *x = v;
        }
    }
    c.upstreams = vec![words.next()?];
    c.upstream_failures = words.next()?;
    (c.named_groups, c.slow) = decode_tail(tail);
    Some(c)
}

/// Adds `b` into `a`.
pub fn merge(a: &mut Counts, b: &Counts) {
    a.total = a.total.saturating_add(b.total);
    for (x, y) in a.status.iter_mut().zip(&b.status) {
        *x = x.saturating_add(*y);
    }
    for (x, y) in a.qtype.iter_mut().zip(&b.qtype) {
        *x = x.saturating_add(*y);
    }
    for (x, y) in a.rcode.iter_mut().zip(&b.rcode) {
        *x = x.saturating_add(*y);
    }
    for (x, y) in a.proto.iter_mut().zip(&b.proto) {
        *x = x.saturating_add(*y);
    }
    let up = b.upstreams.iter().fold(0u32, |s, v| s.saturating_add(*v));
    if a.upstreams.is_empty() {
        a.upstreams.push(0);
    }
    let total = a.upstreams.iter().fold(0u32, |s, v| s.saturating_add(*v));
    a.upstreams = vec![total.saturating_add(up)];
    a.upstream_failures = a.upstream_failures.saturating_add(b.upstream_failures);
    a.slow = a.slow.saturating_add(b.slow);
    for g in &b.named_groups {
        telltale_telemetry::agg::add_named(&mut a.named_groups, &g.name, g.total, g.blocked);
    }
}

impl Rollups {
    pub fn open(path: &Path) -> Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS rollup_minute (start INTEGER PRIMARY KEY, data BLOB NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS rollup_hour (start INTEGER PRIMARY KEY, data BLOB NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS rollup_day (start INTEGER PRIMARY KEY, data BLOB NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS hour_top (
                 start INTEGER NOT NULL, kind TEXT NOT NULL, rank INTEGER NOT NULL,
                 key TEXT NOT NULL, count INTEGER NOT NULL, error INTEGER NOT NULL,
                 PRIMARY KEY (start, kind, rank)) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS hour_latency (
                 start INTEGER NOT NULL, key TEXT NOT NULL, count INTEGER NOT NULL,
                 p50 INTEGER NOT NULL, p90 INTEGER NOT NULL, p99 INTEGER NOT NULL,
                 p999 INTEGER NOT NULL, max INTEGER NOT NULL,
                 PRIMARY KEY (start, key)) WITHOUT ROWID;
             -- REQ: CLU-007 (T9.3) — minutes other nodes (ephemeral pods) shipped here.
             CREATE TABLE IF NOT EXISTS shipped_minute (
                 node TEXT NOT NULL, start INTEGER NOT NULL, data BLOB NOT NULL,
                 PRIMARY KEY (node, start)) WITHOUT ROWID;",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes minute buckets (replacing any with the same start) and recomputes the hours
    /// and days they fall in, in one transaction.
    pub fn put_minutes(&self, rows: &[(u64, Counts)]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        {
            let mut put = tx.prepare_cached(
                "INSERT OR REPLACE INTO rollup_minute (start, data) VALUES (?1, ?2)",
            )?;
            for (start, c) in rows {
                put.execute(params![
                    i64::try_from(*start).unwrap_or(i64::MAX),
                    encode(c)
                ])?;
            }
        }
        let mut hours: Vec<u64> = rows.iter().map(|(s, _)| s - s % 3600).collect();
        hours.dedup();
        for h in &hours {
            let sum = sum_range(&tx, Level::Minute, *h, h + 3600)?;
            upsert(&tx, Level::Hour, *h, &sum)?;
        }
        let mut days: Vec<u64> = hours.iter().map(|h| h - h % 86_400).collect();
        days.dedup();
        for d in days {
            let sum = sum_range(&tx, Level::Hour, d, d + 86_400)?;
            upsert(&tx, Level::Day, d, &sum)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// REQ: CLU-007 (T9.3) — stores minutes `node` shipped (replacing ones with the same
    /// start). Undecodable rows are refused before anything is written.
    pub fn put_shipped(&self, node: &str, rows: &[(u64, Vec<u8>)]) -> Result<()> {
        if rows.iter().any(|(_, b)| decode(b).is_none()) {
            return Err(
                rusqlite::Error::InvalidParameterName("undecodable shipped minute".into()).into(),
            );
        }
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        {
            let mut put = tx.prepare_cached(
                "INSERT OR REPLACE INTO shipped_minute (node, start, data) VALUES (?1, ?2, ?3)",
            )?;
            for (start, data) in rows {
                put.execute(params![node, sql(*start), data])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// REQ: CLU-007 (T9.3) — shipped minutes in `[from_s, to_s)` summed per minute over every
    /// node except `exclude` (nodes answering live, whose own numbers already count).
    pub fn shipped_range(
        &self,
        from_s: u64,
        to_s: u64,
        exclude: &[String],
    ) -> Result<Vec<(u64, Counts)>> {
        let conn = self.conn();
        let mut st = conn.prepare_cached(
            "SELECT node, start, data FROM shipped_minute WHERE start >= ?1 AND start < ?2 ORDER BY start",
        )?;
        let mut by: std::collections::BTreeMap<u64, Counts> = std::collections::BTreeMap::new();
        let rows = st.query_map(params![sql(from_s), sql(to_s)], |r| {
            Ok((
                r.get::<_, String>(0)?,
                unsql(r.get(1)?),
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        for row in rows {
            let (node, start, data) = row?;
            if exclude.contains(&node) {
                continue;
            }
            if let Some(c) = decode(&data) {
                merge(by.entry(start).or_default(), &c);
            }
        }
        Ok(by.into_iter().collect())
    }

    /// Buckets of `level` with start in `[from_s, to_s)`, oldest first.
    pub fn range(&self, level: Level, from_s: u64, to_s: u64) -> Result<Vec<(u64, Counts)>> {
        let conn = self.conn();
        rows(&conn, level, from_s, to_s)
    }

    /// The newest stored minute.
    pub fn last_minute(&self) -> Result<Option<u64>> {
        let conn = self.conn();
        let v: Option<i64> = conn
            .query_row("SELECT MAX(start) FROM rollup_minute", [], |r| r.get(0))
            .optional()?
            .flatten();
        Ok(v.and_then(|v| u64::try_from(v).ok()))
    }

    /// Saves an hour's top-K lists (`kind` → rows, heaviest first) and latency summaries,
    /// replacing what was stored for that hour.
    pub fn put_hour_extras(
        &self,
        hour_start: u64,
        tops: &[(&str, Vec<TopRow>)],
        latency: &[LatencyRow],
    ) -> Result<()> {
        let h = i64::try_from(hour_start).unwrap_or(i64::MAX);
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM hour_top WHERE start = ?1", [h])?;
        tx.execute("DELETE FROM hour_latency WHERE start = ?1", [h])?;
        {
            let mut put = tx.prepare_cached(
                "INSERT INTO hour_top (start, kind, rank, key, count, error) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for (kind, rows) in tops {
                for (rank, r) in rows.iter().enumerate() {
                    put.execute(params![
                        h,
                        kind,
                        i64::try_from(rank).unwrap_or(0),
                        r.key,
                        sql(r.count),
                        sql(r.error)
                    ])?;
                }
            }
            let mut put = tx.prepare_cached(
                "INSERT INTO hour_latency (start, key, count, p50, p90, p99, p999, max) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for r in latency {
                put.execute(params![
                    h,
                    r.key,
                    sql(r.count),
                    sql(r.p50),
                    sql(r.p90),
                    sql(r.p99),
                    sql(r.p999),
                    sql(r.max)
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// An hour's stored top-K list.
    pub fn top(&self, hour_start: u64, kind: &str, n: usize) -> Result<Vec<TopRow>> {
        let conn = self.conn();
        let mut q = conn.prepare_cached(
            "SELECT key, count, error FROM hour_top WHERE start = ?1 AND kind = ?2 ORDER BY rank LIMIT ?3",
        )?;
        let rows = q
            .query_map(
                params![sql(hour_start), kind, i64::try_from(n).unwrap_or(i64::MAX)],
                |r| {
                    Ok(TopRow {
                        key: r.get(0)?,
                        count: unsql(r.get(1)?),
                        error: unsql(r.get(2)?),
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// An hour's stored latency summaries.
    pub fn latency(&self, hour_start: u64) -> Result<Vec<LatencyRow>> {
        let conn = self.conn();
        let mut q = conn.prepare_cached(
            "SELECT key, count, p50, p90, p99, p999, max FROM hour_latency WHERE start = ?1 ORDER BY key",
        )?;
        let rows = q
            .query_map([sql(hour_start)], |r| {
                Ok(LatencyRow {
                    key: r.get(0)?,
                    count: unsql(r.get(1)?),
                    p50: unsql(r.get(2)?),
                    p90: unsql(r.get(3)?),
                    p99: unsql(r.get(4)?),
                    p999: unsql(r.get(5)?),
                    max: unsql(r.get(6)?),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Applies retention: minutes older than 7 days, hours (and their extras) older than
    /// 400 days. Days are kept forever. Returns the rows removed.
    pub fn purge(&self, now_s: u64) -> Result<u64> {
        let conn = self.conn();
        let m = sql(now_s.saturating_sub(MINUTE_RETENTION_S));
        let h = sql(now_s.saturating_sub(HOUR_RETENTION_S));
        let mut n = conn.execute("DELETE FROM rollup_minute WHERE start < ?1", [m])?;
        n += conn.execute("DELETE FROM shipped_minute WHERE start < ?1", [m])?;
        n += conn.execute("DELETE FROM rollup_hour WHERE start < ?1", [h])?;
        n += conn.execute("DELETE FROM hour_top WHERE start < ?1", [h])?;
        n += conn.execute("DELETE FROM hour_latency WHERE start < ?1", [h])?;
        Ok(u64::try_from(n).unwrap_or(0))
    }
}

fn sql(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn unsql(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn rows(conn: &Connection, level: Level, from_s: u64, to_s: u64) -> Result<Vec<(u64, Counts)>> {
    let mut q = conn.prepare_cached(&format!(
        "SELECT start, data FROM {} WHERE start >= ?1 AND start < ?2 ORDER BY start",
        level.table()
    ))?;
    let out = q
        .query_map(params![sql(from_s), sql(to_s)], |r| {
            Ok((unsql(r.get(0)?), r.get::<_, Vec<u8>>(1)?))
        })?
        .filter_map(|r| match r {
            Ok((s, b)) => decode(&b).map(|c| Ok((s, c))),
            Err(e) => Some(Err(e)),
        })
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(out)
}

fn sum_range(conn: &Connection, level: Level, from_s: u64, to_s: u64) -> Result<Counts> {
    let mut sum = Counts::default();
    for (_, c) in rows(conn, level, from_s, to_s)? {
        merge(&mut sum, &c);
    }
    Ok(sum)
}

fn upsert(conn: &Connection, level: Level, start: u64, c: &Counts) -> Result<()> {
    conn.prepare_cached(&format!(
        "INSERT OR REPLACE INTO {} (start, data) VALUES (?1, ?2)",
        level.table()
    ))?
    .execute(params![sql(start), encode(c)])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(total: u32, blocked: u32) -> Counts {
        let mut c = Counts {
            total,
            ..Counts::default()
        };
        c.status[telltale_telemetry::Status::Blocked as usize] = blocked;
        c.qtype[0] = total;
        c.rcode[0] = total;
        c.proto[0] = total;
        c.upstreams = vec![0, 2, 3];
        c.upstream_failures = 1;
        c
    }

    #[test]
    fn obs_004_counts_round_trip() {
        let c = counts(10, 4);
        let d = decode(&encode(&c)).unwrap();
        assert_eq!(d.total, 10);
        assert_eq!(d.status, c.status);
        assert_eq!(d.upstreams, vec![5], "upstream exchanges kept as one total");
        assert_eq!(d.upstream_failures, 1);
        assert!(decode(&[9, 0, 0, 0]).is_none(), "unknown version");
        assert!(decode(&encode(&c)[..10]).is_none(), "truncated");
    }

    // DNS-002/003 (T4.5): version 1 rows (two transport columns) still decode.
    #[test]
    fn dns_002_version_1_rows_decode() {
        let mut c = counts(10, 4);
        c.proto[1] = 3;
        let v2 = encode(&c);
        // Rebuild the same row in the version-1 layout: no transport count, two columns.
        let words = |b: &[u8]| -> Vec<u32> {
            b.as_chunks::<4>()
                .0
                .iter()
                .map(|w| u32::from_le_bytes(*w))
                .collect()
        };
        let w = words(&v2[5..]);
        let proto_at = 1 + N_STATUS + N_QTYPE + N_RCODE;
        let mut v1 = vec![1, v2[1], v2[2], v2[3]];
        for (i, x) in w.iter().enumerate() {
            if i < proto_at + 2 || i >= proto_at + N_PROTO {
                v1.extend_from_slice(&x.to_le_bytes());
            }
        }
        let d = decode(&v1).unwrap();
        assert_eq!(d.total, 10);
        assert_eq!(d.proto, [10, 3, 0, 0, 0]);
        assert_eq!(d.upstreams, vec![5]);
        assert_eq!(d.upstream_failures, 1);
        assert_eq!(decode(&v2).unwrap().proto, [10, 3, 0, 0, 0]);
    }

    // REQ: OBS-004, `spec/06` §3 — minutes roll up into hours and days; rewriting a minute
    // replaces it; retention keeps days forever.
    #[test]
    fn obs_004_minutes_roll_up_and_rewrites_are_idempotent() {
        let r = Rollups::in_memory().unwrap();
        let day: u64 = 1_791_072_000; // a UTC midnight
        let h0 = day + 3600;
        r.put_minutes(&[
            (h0, counts(10, 1)),
            (h0 + 60, counts(5, 0)),
            (h0 + 3600, counts(7, 7)),
        ])
        .unwrap();
        // A late re-flush of the first minute with more events replaces it.
        r.put_minutes(&[(h0, counts(12, 2))]).unwrap();
        let hours = r.range(Level::Hour, day, day + 86_400).unwrap();
        assert_eq!(
            hours.iter().map(|(s, c)| (*s, c.total)).collect::<Vec<_>>(),
            vec![(h0, 17), (h0 + 3600, 7)]
        );
        let days = r.range(Level::Day, day, day + 86_400).unwrap();
        assert_eq!(days.len(), 1);
        assert_eq!(days[0].1.total, 24);
        assert_eq!(
            days[0].1.status[telltale_telemetry::Status::Blocked as usize],
            9
        );
        assert_eq!(days[0].1.upstreams, vec![15]);
        assert_eq!(r.last_minute().unwrap(), Some(h0 + 3600));

        r.put_hour_extras(
            h0,
            &[(
                "blocked",
                vec![TopRow {
                    key: "ads.example.com".into(),
                    count: 9,
                    error: 0,
                }],
            )],
            &[LatencyRow {
                key: "upstream/udp".into(),
                count: 3,
                p50: 900,
                p90: 2000,
                p99: 5000,
                p999: 5000,
                max: 5100,
            }],
        )
        .unwrap();
        assert_eq!(r.top(h0, "blocked", 10).unwrap()[0].key, "ads.example.com");
        assert_eq!(r.latency(h0).unwrap()[0].p90, 2000);

        // Ten days later: minutes are gone, hours and days stay.
        let removed = r.purge(h0 + 10 * 86_400).unwrap();
        assert_eq!(removed, 3);
        assert_eq!(r.range(Level::Minute, 0, u64::MAX / 2).unwrap().len(), 0);
        assert_eq!(r.range(Level::Hour, 0, u64::MAX / 2).unwrap().len(), 2);
        // 401 days later: hours and extras are gone, the day stays.
        r.purge(h0 + 401 * 86_400).unwrap();
        assert_eq!(r.range(Level::Hour, 0, u64::MAX / 2).unwrap().len(), 0);
        assert_eq!(r.top(h0, "blocked", 10).unwrap(), Vec::new());
        assert_eq!(r.range(Level::Day, 0, u64::MAX / 2).unwrap().len(), 1);
    }

    /// REQ: OBS-004 (T6.16) — groups are stored by name: they round-trip, merge by name into
    /// hours and days, and rows without them (older builds) still read; the fixed columns
    /// come first, so a build that predates the section reads the rest as before.
    #[test]
    fn obs_004_group_names_round_trip_and_roll_up() {
        let mut c = counts(10, 4);
        c.groups = vec![6, 4];
        c.group_blocked = vec![1, 3];
        c.name_groups(&["kids", "lab"]);
        assert_eq!(c.named_groups.len(), 2);
        let bytes = encode(&c);
        let d = decode(&bytes).unwrap();
        assert_eq!(d.named_groups, c.named_groups);
        assert_eq!((d.total, d.upstream_failures), (10, 1));
        // Without the section: the bytes an older build wrote, and what it reads of ours.
        let mut plain = c.clone();
        plain.named_groups.clear();
        let old = encode(&plain);
        assert_eq!(decode(&old).unwrap().named_groups, Vec::new());
        assert_eq!(
            &bytes[..old.len()],
            &old[..],
            "the fixed columns are unchanged"
        );
        // A damaged section is ignored, not an error.
        let mut bad = bytes.clone();
        bad.truncate(old.len() + 4);
        assert_eq!(decode(&bad).unwrap().named_groups, Vec::new());
        // Unknown indexes are "other"; minutes roll up by name.
        let mut other = counts(5, 0);
        other.groups = vec![0, 2, 3];
        other.name_groups(&["kids"]);
        let r = Rollups::in_memory().unwrap();
        let h0 = 1_759_700_000 - 1_759_700_000 % 3600;
        r.put_minutes(&[(h0, c), (h0 + 60, other)]).unwrap();
        let hour = &r.range(Level::Hour, h0, h0 + 3600).unwrap()[0].1;
        let by: Vec<(&str, u32, u32)> = hour
            .named_groups
            .iter()
            .map(|g| (&*g.name, g.total, g.blocked))
            .collect();
        assert_eq!(by, [("kids", 6, 1), ("lab", 4, 3), ("other", 5, 0)]);
    }

    /// The group section as a build before T11.1 reads it: only a leading `G` section.
    fn old_build_groups(row: &[u8]) -> usize {
        let fixed = encode(&Counts::default()).len();
        match row.get(fixed..) {
            Some([GROUPS_TAG, rest @ ..]) => decode_groups(rest).map_or(0, |(g, _)| g.len()),
            _ => 0,
        }
    }

    /// REQ: OBS-016 (T11.1) — the slow-answer count round-trips after the groups (or alone),
    /// sums into hours and days, and leaves the bytes a build without it reads unchanged.
    #[test]
    fn obs_016_slow_answers_round_trip_and_roll_up() {
        let mut c = counts(10, 0);
        c.slow = 3;
        c.groups = vec![10];
        c.name_groups(&["kids"]);
        let bytes = encode(&c);
        let d = decode(&bytes).unwrap();
        assert_eq!((d.slow, d.named_groups.len()), (3, 1));
        assert_eq!(
            old_build_groups(&bytes),
            1,
            "older builds still read the groups"
        );
        let mut alone = counts(10, 0);
        alone.slow = 2;
        let bytes = encode(&alone);
        assert_eq!(decode(&bytes).unwrap().slow, 2);
        assert_eq!(
            old_build_groups(&bytes),
            0,
            "and see no groups when there are none"
        );
        // Truncated: what came before is kept.
        let mut cut = encode(&c);
        cut.pop();
        let d = decode(&cut).unwrap();
        assert_eq!((d.slow, d.named_groups.len()), (0, 1));
        // Hours and days add them up.
        let r = Rollups::in_memory().unwrap();
        let h0 = 1_759_700_000 - 1_759_700_000 % 3600;
        r.put_minutes(&[(h0, c), (h0 + 60, alone)]).unwrap();
        assert_eq!(r.range(Level::Hour, h0, h0 + 3600).unwrap()[0].1.slow, 5);
        assert_eq!(r.range(Level::Day, 0, u64::MAX / 2).unwrap()[0].1.slow, 5);
    }
}
