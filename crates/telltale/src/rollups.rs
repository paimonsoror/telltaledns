//! Feeds `<data_dir>/rollups.db` from the aggregator's in-memory windows (REQ: OBS-004,
//! `spec/06` §3, ADR-031). Once a minute: completed minute buckets (the last few again, to
//! pick up late events), the last complete hour's top-K lists and latency percentiles once
//! it closes, and retention once an hour. All SQLite work runs on a blocking thread;
//! failures are logged and never touch DNS (rule 5).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use telltale_config::Config;
use telltale_store::rollup::{LatencyRow, Rollups, TopRow};
use telltale_telemetry::agg::{HourSel, LatencyKey, Percentiles, Resolution, TopKind};
use telltale_telemetry::{Path as AnswerPath, Proto, QTYPES};
use tracing::{info, warn};

use crate::pipeline::Pipeline;

const TOP_KEPT: usize = 100;
/// Minutes re-written on every flush, for events that arrive after their minute closed.
const REFLUSH_S: u64 = 180;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Opens the rollup database, or logs why not (the API then serves memory only).
pub(crate) fn open(cfg: &Config) -> Option<Arc<Rollups>> {
    let dir = Path::new(cfg.node.data_dir.as_str());
    let path = dir.join("rollups.db");
    match std::fs::create_dir_all(dir)
        .map_err(|e| e.to_string())
        .and_then(|()| Rollups::open(&path).map_err(|e| e.to_string()))
    {
        Ok(r) => Some(Arc::new(r)),
        Err(e) => {
            warn!(path = %path.display(), "rollups off: {e}");
            None
        }
    }
}

/// Opens the database and starts its writer (both `None` if it can't be opened).
pub(crate) fn start(
    cfg: &Config,
    pipeline: &Arc<Pipeline>,
) -> (Option<Arc<Rollups>>, Option<tokio::task::JoinHandle<()>>) {
    let db = open(cfg);
    let privacy = cfg.telemetry.qlog.privacy_level;
    let writer = db
        .as_ref()
        .map(|d| spawn(Arc::clone(d), Arc::clone(pipeline), privacy));
    (db, writer)
}
/// Starts the once-a-minute writer. `privacy` is the query log's privacy level, which the
/// stored top lists follow ([`hour_tops`]).
pub(crate) fn spawn(
    db: Arc<Rollups>,
    pipeline: Arc<Pipeline>,
    privacy: u8,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Minutes before this process started are already on disk (or lost); never replace
        // them with this process's partial view.
        let started_minute = now() - now() % 60;
        let mut flushed_to = started_minute;
        // The hour that closed before this process started was saved by the one before it:
        // the startup replay (T6.16) refills it in memory, but never rewrites it on disk.
        let mut extras_for: Option<u64> = Some((started_minute / 3600).saturating_sub(1) * 3600);
        // REQ: OBS-004 (review 04-11) — unless the predecessor stopped before it got to it
        // (it writes an hour's lists a minute after the hour closes): then that hour is
        // written once the replay is over, if nothing is stored for it.
        let mut backfill_for = extras_for;
        let mut purged_at = 0u64;
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let t = now();
            let done_to = t - t % 60; // minutes before this one are complete
            let from = flushed_to.saturating_sub(REFLUSH_S).max(started_minute);
            let (rows, extras, backfill) = {
                let agg = pipeline.telemetry.aggregates();
                let mut rows = agg.series(Resolution::Minute, from, done_to);
                // REQ: OBS-004 (T6.16) — groups by name, so stored minutes keep their meaning
                // after a restart or a change to the group table.
                let names: Vec<String> = pipeline
                    .current()
                    .policy
                    .clients
                    .groups()
                    .iter()
                    .map(|g| g.name.to_string())
                    .collect();
                let names: Vec<&str> = names.iter().map(String::as_str).collect();
                for (_, c) in &mut rows {
                    c.name_groups(&names);
                }
                let extras = agg
                    .previous_hour_start()
                    .filter(|h| extras_for != Some(*h))
                    .map(|h| (h, hour_extras(&agg, &pipeline, privacy)));
                let replayed = crate::replay::done();
                let backfill = backfill_for
                    .filter(|h| replayed && agg.previous_hour_start() == Some(*h))
                    .map(|h| (h, hour_extras(&agg, &pipeline, privacy)));
                if replayed {
                    backfill_for = None;
                }
                (rows, extras, backfill)
            };
            let d = Arc::clone(&db);
            let purge = t.saturating_sub(purged_at) >= 3600;
            let result = tokio::task::spawn_blocking(move || {
                d.put_minutes(&rows)?;
                if let Some((h, (tops, lat))) = &backfill
                    && d.latency(*h)?.is_empty()
                    && d.top(*h, "domains", 1)?.is_empty()
                {
                    let tops: Vec<(&str, Vec<TopRow>)> =
                        tops.iter().map(|(k, v)| (*k, v.clone())).collect();
                    d.put_hour_extras(*h, &tops, lat)?;
                }
                if let Some((h, (tops, lat))) = &extras {
                    let tops: Vec<(&str, Vec<TopRow>)> =
                        tops.iter().map(|(k, v)| (*k, v.clone())).collect();
                    d.put_hour_extras(*h, &tops, lat)?;
                }
                let removed = if purge { d.purge(t)? } else { 0 };
                Ok::<_, telltale_store::state::StateError>((extras.map(|(h, _)| h), removed))
            })
            .await;
            match result {
                Ok(Ok((hour, removed))) => {
                    flushed_to = done_to;
                    if hour.is_some() {
                        extras_for = hour;
                    }
                    if purge {
                        purged_at = t;
                        if removed > 0 {
                            info!(rows = removed, "rollups: retention removed old rows");
                        }
                    }
                }
                Ok(Err(e)) => warn!("rollups: {e}"),
                Err(e) => warn!("rollups: {e}"),
            }
        }
    })
}

type Tops = Vec<(&'static str, Vec<TopRow>)>;
type Extras = (Tops, Vec<LatencyRow>);

/// REQ: OBS-003, OBS-004 (`spec/06` §4; review 04-04) — the last complete hour's top-K lists,
/// as the query log's privacy level lets them be kept for 400 days. The analytics already
/// hold names hashed as the query log stores them at 1 and above (`Hub::set_privacy`); at 2
/// and above there is no list of clients (they're all one).
fn hour_tops(agg: &telltale_telemetry::Aggregates, privacy: u8) -> Tops {
    [
        ("domains", TopKind::Domains),
        ("blocked", TopKind::Blocked),
        ("nxdomain", TopKind::Nxdomain),
        ("clients", TopKind::Clients),
    ]
    .into_iter()
    .filter(|(_, kind)| privacy < 2 || *kind != TopKind::Clients)
    .map(|(name, kind)| {
        let rows = agg
            .top_names(kind, HourSel::Previous, TOP_KEPT)
            .into_iter()
            .map(|t| TopRow {
                key: t.key,
                count: t.count,
                error: t.error,
            })
            .collect();
        (name, rows)
    })
    .collect()
}

/// The last complete hour's top-K lists and latency summaries.
fn hour_extras(agg: &telltale_telemetry::Aggregates, pipeline: &Pipeline, privacy: u8) -> Extras {
    let tops = hour_tops(agg, privacy);

    let row = |key: String, p: Percentiles| LatencyRow {
        key,
        count: p.count,
        p50: p.p50,
        p90: p.p90,
        p99: p.p99,
        p999: p.p999,
        max: p.max,
    };
    let mut lat = Vec::new();
    for path in AnswerPath::ALL {
        for proto in Proto::ALL {
            if let Some(p) = agg.latency(LatencyKey::Total(path, proto), HourSel::Previous) {
                lat.push(row(format!("{}/{}", path.label(), proto.label()), p));
            }
        }
    }
    for (i, (_, name)) in QTYPES.iter().enumerate() {
        if let Some(p) = agg.latency(LatencyKey::Qtype(i), HourSel::Previous) {
            lat.push(row(format!("qtype:{name}"), p));
        }
    }
    if let Some(p) = agg.latency(LatencyKey::StageUpstream, HourSel::Previous) {
        lat.push(row("stage:upstream".to_owned(), p));
    }
    for u in pipeline.current().router.upstreams() {
        if let Some(p) = agg.latency(LatencyKey::Upstream(u.id), HourSel::Previous) {
            lat.push(row(format!("upstream:{}", u.name), p));
        }
    }
    (tops, lat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_telemetry::event::{Name, Record};
    use telltale_telemetry::{Aggregates, Proto, QueryEvent, Status};

    const ADS: &[u8] = b"\x03ads\x07example\x00";

    fn query(ts_us: u64, status: Status) -> QueryEvent {
        let mut client_ip = [0u8; 16];
        client_ip[10..].copy_from_slice(&[0xff, 0xff, 192, 168, 1, 5]);
        QueryEvent {
            ts_us,
            client_ip,
            client_ref: 0,
            group: 0,
            qtype: 1,
            qclass: 1,
            rcode: Some(0),
            status,
            proto: Proto::Udp,
            flags: 0x8180,
            rule: None,
            upstream: 0,
            attempts: 0,
            t_total_us: 100,
            t_upstream_us: 0,
            resp_size: 64,
            answers: 1,
        }
    }

    /// An hour with one blocked query for `ads.example` from 192.168.1.5, then the next hour,
    /// as the analytics see them at privacy level `level`.
    fn closed_hour(level: u8) -> Aggregates {
        let mut agg = Aggregates::new();
        let hour = 1_700_000_000 / 3600 * 3600 * 1_000_000;
        let seen = |r: Record| telltale_telemetry::event::private(&r, level);
        agg.record(&seen(Record::Query(
            query(hour + 5, Status::Blocked),
            Name::from_wire(ADS),
        )));
        agg.record(&seen(Record::Query(
            query(hour + 3_600_000_000, Status::Cached),
            Name::from_wire(b"\x03new\x07example\x00"),
        )));
        agg
    }

    fn keys<'a>(tops: &'a Tops, kind: &str) -> Option<Vec<&'a str>> {
        tops.iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, rows)| rows.iter().map(|r| r.key.as_str()).collect())
    }

    /// REQ: OBS-003, OBS-004 (review 04-04) — the hourly top lists kept in rollups.db follow
    /// the query log's privacy level: names hashed the way the log stores them at 1, and no
    /// client list at 2 and above.
    #[test]
    fn obs_003_stored_top_lists_follow_the_privacy_level() {
        let hashed = telltale_telemetry::event::dotted(&telltale_store::qlog::hidden_name(ADS));
        let plain = telltale_telemetry::event::dotted(ADS);
        assert_ne!(hashed, plain);

        let full = hour_tops(&closed_hour(0), 0);
        assert_eq!(keys(&full, "blocked"), Some(vec![plain.as_str()]));
        assert_eq!(keys(&full, "clients"), Some(vec!["192.168.1.5"]));

        let level1 = hour_tops(&closed_hour(1), 1);
        assert_eq!(keys(&level1, "domains"), Some(vec![hashed.as_str()]));
        assert_eq!(keys(&level1, "blocked"), Some(vec![hashed.as_str()]));
        assert_eq!(keys(&level1, "clients"), Some(vec!["192.168.1.5"]));

        for level in [2, 3] {
            let hidden = hour_tops(&closed_hour(level), level);
            assert_eq!(keys(&hidden, "blocked"), Some(vec![hashed.as_str()]));
            assert_eq!(keys(&hidden, "clients"), None, "level {level}");
        }
    }
}
