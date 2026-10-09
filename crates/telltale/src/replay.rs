//! REQ: OBS-004 (T6.16) — after a restart, the dashboard's top lists (domains, blocked names,
//! NXDOMAIN, clients, per group and per device) and latency for the current and previous hour
//! come back: this node's queries from those hours are read from its query log and folded into
//! the in-memory hours, oldest hours first, page by page, on a background thread. Counts that
//! survive restarts already live in the rollups, so the time windows, Prometheus counters, and
//! masked-client windows aren't touched.
//!
//! Only when the query log is on, kept locally (not shipped), and holds full names
//! (privacy level 0); otherwise the hours start empty as before.

use std::sync::Arc;
use std::time::{Duration, Instant};

use telltale_config::{Config, TelemetryMode};
use telltale_store::qlog::search::{Cursor, Filter, Row, search};
use telltale_telemetry::event::{Name, QueryEvent};
use tracing::{info, warn};

use crate::pipeline::Pipeline;

/// Rows per page (one aggregates lock per page).
const PAGE: usize = 2_000;
/// Stop after this many rows (a very busy node keeps the newest part of the two hours).
const MAX_ROWS: usize = 2_000_000;

/// Set once the startup replay is over (or wasn't needed): the in-memory hours are then as
/// complete as they'll get, and the rollup writer may store the previous hour's top lists
/// (review 04-11).
static DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether the startup replay is over (see [`DONE`]).
pub(crate) fn done() -> bool {
    DONE.load(std::sync::atomic::Ordering::Acquire)
}

fn finished() {
    DONE.store(true, std::sync::atomic::Ordering::Release);
}

pub(crate) fn spawn(cfg: &Config, pipeline: &Arc<Pipeline>) {
    let q = &cfg.telemetry.qlog;
    if !q.enabled || q.privacy_level != 0 || cfg.telemetry.mode == TelemetryMode::Ship {
        finished();
        return;
    }
    let dir = std::path::Path::new(cfg.node.data_dir.as_str()).join("qlog");
    if !dir.is_dir() {
        finished();
        return;
    }
    let started_us = now_us();
    let pipeline = Arc::clone(pipeline);
    // REQ: OBS-022 — queries logged before a name or device was excluded stay out too.
    let excluded = crate::server::exclusions(cfg);
    let spawned = std::thread::Builder::new()
        .name("qlog-replay".into())
        .spawn(move || {
            telltale_net::background_thread();
            let t = Instant::now();
            let fold = |events: &[(QueryEvent, Name)]| {
                let mut agg = pipeline.telemetry.aggregates();
                for (e, name) in events {
                    if excluded
                        .as_ref()
                        .is_some_and(|x| x.client(&e.client_ip) || x.name(name.as_wire()))
                    {
                        continue;
                    }
                    agg.replay_hours(started_us / 1_000_000, e, name);
                }
            };
            match replay(&dir, started_us, fold) {
                Ok(n) if n > 0 => info!(
                    queries = n,
                    ms = u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX),
                    "analytics: the last two hours' top lists restored from the query log"
                ),
                Ok(_) => {}
                Err(e) => {
                    warn!("analytics: couldn't restore the top lists from the query log: {e}");
                }
            }
            finished();
        });
    if let Err(e) = spawned {
        warn!("analytics: no replay thread ({e})");
        finished();
    }
}

/// Reads this node's queries from the previous hour's start up to `started_us` and hands
/// them to `fold` page by page (newest first; the aggregates take them in any order).
fn replay(
    dir: &std::path::Path,
    started_us: u64,
    mut fold: impl FnMut(&[(QueryEvent, Name)]),
) -> std::io::Result<usize> {
    let now_s = started_us / 1_000_000;
    let filter = Filter {
        // The previous hour's start, up to this process's start (later queries are live).
        from_us: (now_s / 3600).saturating_sub(1) * 3600 * 1_000_000,
        to_us: started_us,
        ..Filter::default()
    };
    let mut cursor: Option<Cursor> = None;
    let mut n = 0usize;
    loop {
        let page = search(dir, &filter, PAGE, cursor)?;
        let events: Vec<(QueryEvent, Name)> = page
            .rows
            .iter()
            // This node's own queries: shipped segments from other nodes share the directory.
            .filter(|r| r.node == 0)
            .filter_map(event)
            .collect();
        fold(&events);
        n += events.len();
        match page.next {
            Some(c) if n < MAX_ROWS && !page.rows.is_empty() => cursor = Some(c),
            _ => break,
        }
        // Let live traffic have the aggregates between pages.
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(n)
}

/// A logged query as the aggregator saw it.
fn event(r: &Row) -> Option<(QueryEvent, Name)> {
    let wire = telltale_proto::NameBuf::from_presentation(&r.name).ok()?;
    Some((
        QueryEvent {
            ts_us: r.ts_us,
            client_ip: r.client_ip,
            client_ref: r.client_ref,
            group: r.group,
            qtype: r.qtype,
            qclass: r.qclass,
            rcode: r.rcode,
            status: r.status,
            proto: r.proto,
            flags: r.flags,
            rule: r.rule,
            upstream: r.upstream,
            attempts: r.attempts,
            t_total_us: r.t_total_us,
            t_upstream_us: r.t_upstream_us,
            resp_size: r.resp_size,
            answers: r.answers,
        },
        Name::from_wire(wire.as_wire()),
    ))
}

fn now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_store::qlog::{Builder, Settings};
    use telltale_telemetry::agg::{Aggregates, HourSel, TopKind};
    use telltale_telemetry::{Proto, Status};

    const HOUR_US: u64 = 3_600_000_000;

    fn ev(ts_us: u64) -> QueryEvent {
        QueryEvent {
            ts_us,
            client_ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 9],
            client_ref: 0,
            group: 0,
            qtype: 1,
            qclass: 1,
            rcode: Some(0),
            status: Status::Forwarded,
            proto: Proto::Udp,
            flags: 0x8180,
            rule: None,
            upstream: 1,
            attempts: 1,
            t_total_us: 900,
            t_upstream_us: 800,
            resp_size: 60,
            answers: 1,
        }
    }

    fn write(dir: &std::path::Path, node: u16, rows: &[(u64, &str)]) {
        let mut b = Builder::spawn(Settings {
            dir: dir.to_owned(),
            node,
            privacy: 0,
            flush_interval: Duration::from_secs(3600),
            fsync: false,
            retention_days: 30,
            retention_bytes: u64::MAX,
            rotate_after: None,
        })
        .unwrap();
        for (ts, name) in rows {
            let wire = telltale_proto::NameBuf::from_presentation(name).unwrap();
            b.push(&ev(*ts), wire.as_wire());
        }
    }

    /// REQ: OBS-004 (T6.16) — after a restart the current and previous hour's top lists come
    /// back from the query log: this node's queries only, nothing from before the previous
    /// hour or after the process started.
    #[test]
    fn obs_004_replay_restores_the_hours_top_lists() {
        let tmp = tempfile::tempdir().unwrap();
        let h = now_us() / HOUR_US; // this hour (older ones would fall to retention)
        let started_us = (h * 3600 + 1800) * 1_000_000; // half past
        let mut local = Vec::new();
        for i in 0..30 {
            local.push((h * HOUR_US + i * 1_000_000, "now.example")); // this hour, before start
        }
        for i in 0..10 {
            local.push(((h - 1) * HOUR_US + i * 1_000_000, "before.example")); // previous hour
            local.push(((h - 2) * HOUR_US + i * 1_000_000, "old.example")); // too old
            local.push((started_us + i * 1_000_000, "live.example")); // after the start
        }
        write(tmp.path(), 0, &local);
        let shipped: Vec<(u64, &str)> = (0..50).map(|i| (h * HOUR_US + i, "pod.example")).collect();
        write(tmp.path(), 7, &shipped);

        let mut agg = Aggregates::new();
        let n = replay(tmp.path(), started_us, |events| {
            for (e, name) in events {
                agg.replay_hours(started_us / 1_000_000, e, name);
            }
        })
        .unwrap();
        assert_eq!(
            n, 40,
            "this hour and the previous one, this node, before the start"
        );
        let names = |sel| -> Vec<(String, u64)> {
            agg.top_names(TopKind::Domains, sel, 10)
                .into_iter()
                .map(|t| (t.key, t.count))
                .collect()
        };
        assert_eq!(names(HourSel::Current), [("now.example".to_owned(), 30)]);
        assert_eq!(
            names(HourSel::Previous),
            [("before.example".to_owned(), 10)]
        );
    }
}
