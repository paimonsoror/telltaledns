//! Cache-warm hints (REQ: CLU-011, P2; T8.1): a node that joins a cluster (a new resolver
//! pod, a replica after a restart with an empty cache) asks the cluster for its hot names —
//! the top queried names this hour and last, merged across the other nodes — and resolves
//! them in the background, so its first clients find them cached.
//!
//! Gentle by design: once per start, after the cluster's configuration is applied, at most
//! `[cache] warm_names` names, A and AAAA, paced (20 lookups a second), through the normal
//! upstream path (coalesced, cached like any answer, no query events). Never on the DNS path;
//! a failure only means a colder start.

use std::sync::Arc;
use std::time::Duration;

use telltale_api::Backend as _;
use telltale_api::model::{Hour, TopKind};
use tracing::{debug, info};

/// Lookups per second while warming.
const RATE: u64 = 20;

/// The names to warm: the cluster's top queried names (`top(hour)`), this hour then the
/// last, at most `limit`.
fn hot_names(top: impl Fn(Hour) -> Vec<telltale_api::model::TopItem>, limit: usize) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for hour in [Hour::Current, Hour::Previous] {
        for item in top(hour) {
            if !names.contains(&item.key) {
                names.push(item.key);
            }
        }
    }
    names.truncate(limit);
    names
}

/// The warm task: waits for the cluster, fetches the hot names, resolves them.
pub(crate) async fn run(
    sources: Arc<crate::http::Sources>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let cfg = sources.config.load_full();
    let limit = usize::try_from(cfg.cache.warm_names).unwrap_or(0);
    let Some(cluster) = sources.cluster.clone() else {
        return;
    };
    if limit == 0 {
        return;
    }
    // The cluster's configuration first (routes and groups decide where names go).
    for _ in 0..600 {
        if cluster.sync_status().applied_ms != 0 || cluster.is_primary() {
            break;
        }
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    }
    // Then a peer to ask (a moment for the streams to come up).
    tokio::select! {
        _ = stop.changed() => return,
        () = tokio::time::sleep(Duration::from_secs(3)) => {}
    }
    let local: telltale_api::Shared = Arc::new(crate::api_backend::ApiBackend {
        src: Arc::clone(&sources),
    });
    let fed = crate::federated::Federated::new(local, Arc::clone(&cluster));
    let names = tokio::task::spawn_blocking(move || {
        hot_names(|h| fed.top(TopKind::Domains, h, limit, None), limit)
    })
    .await
    .unwrap_or_default();
    if names.is_empty() {
        debug!("cache warm: the cluster has no hot names yet");
        return;
    }
    info!(
        names = names.len(),
        "cache warm: resolving the cluster's hot names"
    );
    let pipeline = Arc::clone(&sources.pipeline);
    let groups: Vec<Box<str>> = vec!["default".into()];
    let mut done = 0usize;
    let mut tick = tokio::time::interval(Duration::from_millis(1000 / RATE));
    for name in &names {
        for qtype in [telltale_proto::rtype::A, telltale_proto::rtype::AAAA] {
            tokio::select! {
                _ = stop.changed() => return,
                _ = tick.tick() => {}
            }
            let Ok(n) = telltale_proto::NameBuf::from_presentation(name) else {
                continue;
            };
            let mut buf = [0u8; 512];
            let Ok(len) =
                telltale_proto::build_query(&mut buf, rand::random(), &n, qtype, 1, true, None)
            else {
                continue;
            };
            if pipeline
                .lookup_internal(buf[..len].to_vec(), &groups)
                .await
                .is_some()
            {
                done += 1;
            }
        }
    }
    info!(names = names.len(), answers = done, "cache warm: done");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn top(hour: Hour) -> Vec<telltale_api::model::TopItem> {
        let names: &[&str] = match hour {
            Hour::Current => &["a.example", "b.example"],
            Hour::Previous => &["b.example", "c.example", "d.example"],
        };
        names
            .iter()
            .map(|n| telltale_api::model::TopItem {
                key: (*n).to_owned(),
                name: None,
                count: 1,
                error_bound: 0,
                groups: Vec::new(),
            })
            .collect()
    }

    /// REQ: CLU-011 — this hour's names first, then last hour's new ones, at most `limit`.
    #[test]
    fn clu_011_hot_names() {
        assert_eq!(
            hot_names(top, 3),
            vec!["a.example", "b.example", "c.example"]
        );
        assert_eq!(hot_names(top, 10).len(), 4);
    }
}
