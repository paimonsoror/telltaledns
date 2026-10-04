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
use telltale_telemetry::{N_QTYPE, N_RCODE, N_STATUS};

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

const VERSION: u8 = 1;

/// `Counts` → bytes: a header with the column counts (so a build with more statuses or
/// qtypes can still read old rows), then little-endian u32s.
pub fn encode(c: &Counts) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 4 * (5 + N_STATUS + N_QTYPE + N_RCODE));
    #[allow(clippy::cast_possible_truncation)] // all < 256
    out.extend_from_slice(&[VERSION, N_STATUS as u8, N_QTYPE as u8, N_RCODE as u8]);
    let mut put = |v: u32| out.extend_from_slice(&v.to_le_bytes());
    put(c.total);
    c.status.iter().for_each(|v| put(*v));
    c.qtype.iter().for_each(|v| put(*v));
    c.rcode.iter().for_each(|v| put(*v));
    c.proto.iter().for_each(|v| put(*v));
    put(c.upstreams.iter().fold(0u32, |a, v| a.saturating_add(*v)));
    put(c.upstream_failures);
    out
}

/// Bytes → `Counts` (upstream exchanges come back as a single total in `upstreams[0]`).
pub fn decode(b: &[u8]) -> Option<Counts> {
    let (&[version, ns, nq, nr], rest) = b.split_first_chunk::<4>()?;
    if version != VERSION {
        return None;
    }
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
    c.proto = [words.next()?, words.next()?];
    c.upstreams = vec![words.next()?];
    c.upstream_failures = words.next()?;
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
                 PRIMARY KEY (start, key)) WITHOUT ROWID;",
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
}
