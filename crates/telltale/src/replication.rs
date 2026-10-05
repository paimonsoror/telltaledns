//! Config replication wiring (REQ: CLU-003, CLU-004, CLU-006; ADR-047).
//!
//! - The **primary** publishes a signed manifest naming its shared configuration and its
//!   newest filter snapshot whenever either changes.
//! - A **replica** follows: it fetches missing blobs, checks the merged configuration, installs
//!   the snapshot, records what it applied in `<data_dir>/cluster/applied.json`, and reloads.
//!   Once a replica has synced, its configuration is its own node-local sections plus the
//!   primary's shared ones, it stops downloading lists (the primary compiles them), and it
//!   keeps serving the last applied version whatever happens to the primary.
//!
//! None of this is on the query path, and a failure here never stops DNS (rule 5).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use telltale_cluster::net::{BlobSource, Cluster};
use telltale_cluster::node;
use telltale_cluster::sync::{
    BlobRef, BlobStore, ClusterManifest, FilterRef, Signed, blob_ref, hash,
};
use telltale_config::Config;
use telltale_config::shared::{shared_part, with_shared};
use telltale_filter::snapshot::{MANIFEST, Manifest};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{error, info, warn};

use crate::http::Sources;
use crate::lists::Publisher;

/// How often the primary looks for a changed configuration or snapshot.
const PUBLISH_EVERY: Duration = Duration::from_millis(500);
const APPLIED: &str = "applied.json";
const PUBLISHED: &str = "published.json";

fn data_dir(cfg: &Config) -> &Path {
    Path::new(cfg.node.data_dir.as_str())
}

/// The manifest this node last applied, if it's a replica that has synced.
pub(crate) fn applied(cfg: &Config) -> Option<ClusterManifest> {
    let dir = node::dir_of(data_dir(cfg));
    if !dir.join("cluster.json").is_file() || dir.join("ca.key").exists() {
        return None; // standalone, or the primary
    }
    serde_json::from_slice(&std::fs::read(dir.join(APPLIED)).ok()?).ok()
}

/// Whether this node follows a primary's configuration (a replica that has synced).
pub(crate) fn follows_primary(cfg: &Config) -> bool {
    applied(cfg).is_some()
}

/// The effective configuration for `file` (the config files + environment): a synced
/// replica's is its node-local sections plus the primary's shared ones; otherwise the files
/// plus what the UI/API stored (ADR-040).
pub(crate) fn effective(file: &Config) -> Config {
    let Some(m) = applied(file) else {
        return crate::managed::effective(file);
    };
    match merged(file, &m) {
        Ok(c) => c,
        Err(e) => {
            error!(
                "cluster configuration seq {} unusable ({e}); using this node's own configuration",
                m.seq
            );
            crate::managed::effective(file)
        }
    }
}

fn merged(file: &Config, m: &ClusterManifest) -> Result<Config, String> {
    let store = BlobStore::open(data_dir(file)).map_err(|e| e.to_string())?;
    let shared: serde_json::Value = serde_json::from_slice(&store.read(&m.config)?)
        .map_err(|e| format!("shared configuration: {e}"))?;
    with_shared(file, &shared).map_err(|errs| {
        errs.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    })
}

/// The snapshot directory a filter manifest installs to.
fn snapshot_dir(cfg: &Config, f: &FilterRef) -> PathBuf {
    data_dir(cfg).join("snapshots").join(f.version.to_string())
}

fn safe_name(n: &str) -> bool {
    !n.is_empty()
        && !n.starts_with('.')
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// Installs a replicated filter snapshot as `<data_dir>/snapshots/<version>` (unless that's
/// already it) and removes the others, so `explain` and cold starts see exactly what the
/// primary compiled.
fn install_filter(cfg: &Config, store: &BlobStore, f: &FilterRef) -> Result<PathBuf, String> {
    let dir = snapshot_dir(cfg, f);
    let want = f
        .blobs
        .iter()
        .find(|b| b.name == MANIFEST)
        .ok_or("the filter has no manifest")?;
    let installed = std::fs::read(dir.join(MANIFEST)).is_ok_and(|b| hash(&b) == want.hash);
    let parent = data_dir(cfg).join("snapshots");
    if !installed {
        std::fs::create_dir_all(&parent).map_err(|e| e.to_string())?;
        let tmp = parent.join(format!(".incoming-{}", f.version));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
        for b in &f.blobs {
            if !safe_name(&b.name) {
                return Err(format!("unsafe blob name `{}`", b.name));
            }
            let src = store.path(&b.hash).ok_or("bad blob hash")?;
            let dst = tmp.join(&b.name);
            if std::fs::hard_link(&src, &dst).is_err() {
                std::fs::copy(&src, &dst).map_err(|e| format!("{}: {e}", dst.display()))?;
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::rename(&tmp, &dir).map_err(|e| e.to_string())?;
    }
    for e in std::fs::read_dir(&parent).into_iter().flatten().flatten() {
        if e.path() != dir
            && e.file_name()
                .to_str()
                .is_some_and(|n| n.parse::<u64>().is_ok())
        {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
    Ok(dir)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// Starts replication: the publisher on the primary, the follower on a replica.
pub(crate) fn start(
    cluster: &Arc<Cluster>,
    files: Vec<PathBuf>,
    sources: &Arc<Sources>,
    reload: mpsc::Sender<oneshot::Sender<bool>>,
    stop: &watch::Receiver<bool>,
) {
    tokio::spawn(serving_loop(
        Arc::clone(cluster),
        Arc::clone(sources),
        stop.clone(),
    ));
    let cfg = sources.config.load_full();
    if cluster.identity.holds_ca() {
        tokio::spawn(publish_loop(
            Arc::clone(cluster),
            Arc::clone(sources),
            stop.clone(),
        ));
        return;
    }
    let store = match BlobStore::open(data_dir(&cfg)) {
        Ok(s) => s,
        Err(e) => {
            error!("cluster: can't open the blob store ({e}); not following the primary");
            return;
        }
    };
    let publisher = Publisher::new(Arc::clone(&sources.pipeline));
    // CLU-004 — serve the last applied snapshot right away, before any contact.
    let last = applied(&cfg);
    if let Some(f) = last.as_ref().and_then(|m| m.filter.as_ref()) {
        let dir = snapshot_dir(&cfg, f);
        if dir.join(MANIFEST).is_file() {
            publisher.publish(dir);
        }
    }
    let at = last.as_ref().map_or((0, 0), |m| (m.epoch, m.seq));
    let last_filter = Arc::new(std::sync::Mutex::new(
        last.and_then(|m| m.filter).map(|f| f.blobs),
    ));
    let sources = Arc::clone(sources);
    let store2 = store.clone();
    tokio::spawn(telltale_cluster::net::follow(
        Arc::clone(cluster),
        store,
        at,
        move |m: ClusterManifest| {
            let (store, files, reload, publisher, last_filter) = (
                store2.clone(),
                files.clone(),
                reload.clone(),
                publisher.clone(),
                Arc::clone(&last_filter),
            );
            let _ = &sources;
            async move {
                let blobs = m.filter.as_ref().map(|f| f.blobs.clone());
                let changed = *last_filter
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    != blobs;
                apply(m, &store, &files, &reload, &publisher, changed).await?;
                *last_filter
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = blobs;
                Ok(())
            }
        },
        stop.clone(),
    ));
}

/// Applies one replicated manifest on a replica.
async fn apply(
    m: ClusterManifest,
    store: &BlobStore,
    files: &[PathBuf],
    reload: &mpsc::Sender<oneshot::Sender<bool>>,
    publisher: &Publisher,
    filter_changed: bool,
) -> Result<(), String> {
    // Check the merged configuration before anything changes on disk.
    let file = crate::server::load_files(files)
        .ok_or("this node's own configuration files are invalid")?;
    merged(&file, &m)?;
    let dir = match &m.filter {
        Some(f) => {
            let (cfg, store, f) = (file.clone(), store.clone(), f.clone());
            Some(
                tokio::task::spawn_blocking(move || install_filter(&cfg, &store, &f))
                    .await
                    .map_err(|e| e.to_string())??,
            )
        }
        None => None,
    };
    let json = serde_json::to_vec_pretty(&m).map_err(|e| e.to_string())?;
    write_atomic(&node::dir_of(data_dir(&file)).join(APPLIED), &json).map_err(|e| e.to_string())?;
    // The normal reload path: validate, swap, audit-free (the primary audited the change).
    let (tx, rx) = oneshot::channel();
    reload
        .send(tx)
        .await
        .map_err(|_| "the server is shutting down")?;
    if !rx.await.unwrap_or(false) {
        return Err("the reload with the new configuration failed".into());
    }
    if filter_changed && let Some(dir) = dir {
        publisher.publish(dir);
    }
    Ok(())
}

/// What the primary last published (persisted, so `seq` only grows across restarts).
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Published {
    seq: u64,
    config: String,
    filter: Option<u64>,
}

/// The newest filter snapshot as replicated blobs (its own manifest included).
fn filter_ref(dir: &Path, manifest: &Manifest) -> Option<(FilterRef, Vec<(String, PathBuf)>)> {
    let manifest_bytes = std::fs::read(dir.join(MANIFEST)).ok()?;
    let mut blobs = vec![blob_ref(MANIFEST, &manifest_bytes)];
    let mut paths = vec![(blobs[0].hash.clone(), dir.join(MANIFEST))];
    for b in &manifest.blobs {
        blobs.push(BlobRef {
            name: b.name.clone(),
            hash: b.blake3.clone(),
            bytes: b.bytes,
        });
        paths.push((b.blake3.clone(), dir.join(&b.name)));
    }
    Some((
        FilterRef {
            version: manifest.version,
            blobs,
        },
        paths,
    ))
}

/// Primary side: republishes whenever the shared configuration or the snapshot changes.
#[allow(clippy::too_many_lines)] // one loop: gather, compare, sign, publish, persist
async fn publish_loop(
    cluster: Arc<Cluster>,
    sources: Arc<Sources>,
    mut stop: watch::Receiver<bool>,
) {
    let cfg = sources.config.load_full();
    let state_path = node::dir_of(data_dir(&cfg)).join(PUBLISHED);
    let mut last: Published = std::fs::read(&state_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let mut first = true;
    let key = match cluster.identity.ca_key_pem() {
        Ok(k) => k,
        Err(e) => {
            error!("cluster: {e}; not publishing configuration");
            return;
        }
    };
    loop {
        let cfg = sources.config.load_full();
        let shared = serde_json::to_vec(&shared_part(&cfg)).unwrap_or_default();
        let config_hash = hash(&shared);
        let compiled = sources.lists.load_full().and_then(|l| {
            l.compiled
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        });
        let filter = compiled.and_then(|c| {
            let dir = data_dir(&cfg)
                .join("snapshots")
                .join(c.manifest.version.to_string());
            filter_ref(&dir, &c.manifest)
        });
        let filter_version = filter.as_ref().map(|(f, _)| f.version);
        let changed = config_hash != last.config || filter_version != last.filter;
        if changed || first {
            let seq = if changed {
                last.seq + 1
            } else {
                last.seq.max(1)
            };
            let mut blobs = HashMap::new();
            let config = blob_ref("config.json", &shared);
            blobs.insert(config.hash.clone(), BlobSource::Bytes(Bytes::from(shared)));
            if let Some((_, paths)) = &filter {
                for (h, p) in paths {
                    blobs.insert(h.clone(), BlobSource::File(p.clone()));
                }
            }
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            let m = ClusterManifest {
                cluster_id: cluster.identity.meta.cluster_id.clone(),
                epoch: cluster.identity.meta.epoch,
                seq,
                created_ms: now_ms,
                primary: cluster.identity.meta.node_id.clone(),
                config,
                filter: filter.map(|(f, _)| f),
            };
            match Signed::sign(&m, &key) {
                Ok(signed) => {
                    cluster.publish(signed, blobs);
                    cluster.set_local(|l| l.applied_seq = seq);
                    cluster.set_sync_status(|s| {
                        s.epoch = m.epoch;
                        s.seq = seq;
                        s.created_ms = now_ms;
                        s.applied_ms = now_ms;
                        s.error = None;
                    });
                    if changed {
                        info!(seq, filter = ?filter_version, "published cluster configuration");
                        cluster.event(
                            "published",
                            &cluster.identity.meta.node_id,
                            format!(
                                "version {seq}{}",
                                filter_version
                                    .map_or(String::new(), |v| format!(", filter snapshot {v}"))
                            ),
                        );
                    }
                    last = Published {
                        seq,
                        config: config_hash,
                        filter: filter_version,
                    };
                    if let Ok(b) = serde_json::to_vec(&last)
                        && let Err(e) = write_atomic(&state_path, &b)
                    {
                        warn!("cluster: can't record the published version: {e}");
                    }
                }
                Err(e) => error!("cluster: can't sign the configuration manifest: {e}"),
            }
            first = false;
        }
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(PUBLISH_EVERY) => {}
        }
    }
}

/// REQ: CLU-008 — what this node reports in its heartbeats: queries per second and SERVFAIL
/// share over the last minute, upstream p90 this hour, readiness, uptime. Every 5 s, off the
/// query path (the aggregator's data).
async fn serving_loop(
    cluster: Arc<Cluster>,
    sources: Arc<Sources>,
    mut stop: watch::Receiver<bool>,
) {
    use telltale_telemetry::agg::{HourSel, LatencyKey, Resolution};
    loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let (total, servfail, p90) = {
            let agg = sources.pipeline.telemetry.aggregates();
            let (t, s) = agg
                .series(Resolution::Second, now.saturating_sub(60), now)
                .iter()
                .fold((0u64, 0u64), |(t, s), (_, c)| {
                    (t + u64::from(c.total), s + u64::from(c.rcode[2]))
                });
            (
                t,
                s,
                agg.latency(LatencyKey::StageUpstream, HourSel::Current)
                    .map_or(0, |p| p.p90),
            )
        };
        let ready = sources.ready.load(std::sync::atomic::Ordering::Acquire);
        let uptime = sources.started.elapsed().as_secs();
        cluster.set_local(|l| {
            l.qps = total / 60;
            l.servfail_permille =
                u32::try_from((servfail * 1000).checked_div(total).unwrap_or(0)).unwrap_or(1000);
            l.p90_us = p90;
            l.ready = ready;
            l.uptime_s = uptime;
        });
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clu_003_blob_names_from_the_network_are_plain_file_names() {
        assert!(safe_name("subtree-0.fst") && safe_name("manifest.json"));
        assert!(!safe_name("../x") && !safe_name("a/b") && !safe_name(".hidden") && !safe_name(""));
    }
}
