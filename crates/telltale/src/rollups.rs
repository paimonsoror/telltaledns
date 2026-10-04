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

/// Starts the once-a-minute writer.
pub(crate) fn spawn(db: Arc<Rollups>, pipeline: Arc<Pipeline>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Minutes before this process started are already on disk (or lost); never replace
        // them with this process's partial view.
        let started_minute = now() - now() % 60;
        let mut flushed_to = started_minute;
        let mut extras_for: Option<u64> = None;
        let mut purged_at = 0u64;
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let t = now();
            let done_to = t - t % 60; // minutes before this one are complete
            let from = flushed_to.saturating_sub(REFLUSH_S).max(started_minute);
            let (rows, extras) = {
                let agg = pipeline.telemetry.aggregates();
                let rows = agg.series(Resolution::Minute, from, done_to);
                let extras = agg
                    .previous_hour_start()
                    .filter(|h| extras_for != Some(*h))
                    .map(|h| (h, hour_extras(&agg, &pipeline)));
                (rows, extras)
            };
            let d = Arc::clone(&db);
            let purge = t.saturating_sub(purged_at) >= 3600;
            let result = tokio::task::spawn_blocking(move || {
                d.put_minutes(&rows)?;
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

type Extras = (Vec<(&'static str, Vec<TopRow>)>, Vec<LatencyRow>);

/// The last complete hour's top-K lists and latency summaries.
fn hour_extras(agg: &telltale_telemetry::Aggregates, pipeline: &Pipeline) -> Extras {
    let tops = [
        ("domains", TopKind::Domains),
        ("blocked", TopKind::Blocked),
        ("nxdomain", TopKind::Nxdomain),
        ("clients", TopKind::Clients),
    ]
    .into_iter()
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
    .collect();

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
