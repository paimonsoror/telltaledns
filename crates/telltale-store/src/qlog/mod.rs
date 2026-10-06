//! The query log (OBS-003): hourly columnar segments under `<data_dir>/qlog/`.
//!
//! Files are `qlog/YYYY/MM/DD/HH-<node>-<part>.seg`: one or more parts per hour and node
//! (a new part starts after a restart, when the segment dictionary fills up, or after a
//! dropped block). See [`format`] for the layout, [`writer`] for the write path, and
//! [`search`] for queries.

pub mod format;
pub mod reader;
pub mod retention;
pub mod search;
pub mod writer;

use std::io;
use std::path::{Path, PathBuf};

pub use search::{
    Cursor, Estimate, Filter, NameMatch, Options, Page, Row, SearchStats, estimate, search,
    search_with,
};
pub use writer::{Builder, Settings, Stats, hidden_name};

/// Identifies a segment file. Orders oldest first (hour, then node, then part).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SegmentId {
    /// Hours since the Unix epoch.
    pub hour: u64,
    pub node: u16,
    pub part: u32,
}

/// Civil date (UTC) of a day number since the epoch (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        y,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

/// ISO 8601 UTC with milliseconds (`2026-10-03T12:34:56.789Z`) for microseconds since epoch.
pub fn format_ts(us: u64) -> String {
    let secs = us / 1_000_000;
    let (y, m, d) = civil(i64::try_from(secs / 86_400).unwrap_or(0));
    let s = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        s / 3600,
        s / 60 % 60,
        s % 60,
        us / 1000 % 1000
    )
}

/// Path of a segment part.
pub fn segment_path(dir: &Path, hour: u64, node: u16, part: u32) -> PathBuf {
    let days = i64::try_from(hour / 24).unwrap_or(0);
    let (y, m, d) = civil(days);
    dir.join(format!("{y:04}"))
        .join(format!("{m:02}"))
        .join(format!("{d:02}"))
        .join(format!("{:02}-{node}-{part}.seg", hour % 24))
}

/// Parses `HH-<node>-<part>.seg` under `YYYY/MM/DD` back into an ID.
fn parse_id(day_hours: u64, file: &str) -> Option<SegmentId> {
    let stem = file.strip_suffix(".seg")?;
    let mut it = stem.split('-');
    let hh: u64 = it.next()?.parse().ok()?;
    let node = it.next()?.parse().ok()?;
    let part = it.next()?.parse().ok()?;
    (hh < 24 && it.next().is_none()).then_some(SegmentId {
        hour: day_hours + hh,
        node,
        part,
    })
}

/// Days since the epoch of a civil date (inverse of [`civil`]).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Every segment under `dir`, unsorted. A missing directory is empty; unrecognized files
/// are ignored.
pub fn list_segments(dir: &Path) -> io::Result<Vec<(SegmentId, PathBuf)>> {
    let mut out = Vec::new();
    let read = |p: &Path| -> io::Result<Vec<(String, PathBuf)>> {
        match std::fs::read_dir(p) {
            Ok(rd) => Ok(rd
                .filter_map(Result::ok)
                .filter_map(|e| Some((e.file_name().to_str()?.to_owned(), e.path())))
                .collect()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    };
    for (y, yp) in read(dir)? {
        let Ok(y) = y.parse::<i64>() else { continue };
        for (m, mp) in read(&yp)? {
            let Ok(m) = m.parse::<u32>() else { continue };
            for (d, dp) in read(&mp)? {
                let Ok(d) = d.parse::<u32>() else { continue };
                let Ok(days) = u64::try_from(days_from_civil(y, m, d)) else {
                    continue;
                };
                for (f, fp) in read(&dp)? {
                    if let Some(id) = parse_id(days * 24, &f) {
                        out.push((id, fp));
                    }
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
