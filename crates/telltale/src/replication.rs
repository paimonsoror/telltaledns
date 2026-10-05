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
use telltale_cluster::node::{self, Role};
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

/// This node's cluster identity, if it's in a cluster.
fn identity(cfg: &Config) -> Option<node::Identity> {
    node::Identity::load(data_dir(cfg)).ok().flatten()
}

/// The last manifest this node applied as a replica (kept after a promotion: a promoted node
/// builds on it).
pub(crate) fn last_applied(cfg: &Config) -> Option<ClusterManifest> {
    let dir = node::dir_of(data_dir(cfg));
    serde_json::from_slice(&std::fs::read(dir.join(APPLIED)).ok()?).ok()
}

/// The manifest this node follows: a synced replica's, or an emergency primary's (ADR-048: it
/// keeps the last authoritative version). `None` for a standalone node or a regular primary.
pub(crate) fn applied(cfg: &Config) -> Option<ClusterManifest> {
    match identity(cfg)?.meta.role {
        Some(node::Role::Primary) => None,
        _ => last_applied(cfg),
    }
}

/// Whether this node takes its configuration and lists from the primary.
pub(crate) fn follows_primary(cfg: &Config) -> bool {
    applied(cfg).is_some()
}

/// The effective configuration for `file` (the config files + environment), by role:
/// - standalone: the files plus what the UI/API stored (ADR-040);
/// - replica or emergency primary that has synced: its node-local sections plus the cluster's
///   shared ones (ADR-047);
/// - primary: its own files plus UI/API entries, except a primary promoted from replica (not
///   the Git-managed source itself), which builds on the last cluster version it applied so the
///   cluster's configuration carries on (ADR-051).
pub(crate) fn effective(file: &Config) -> Config {
    let Some(id) = identity(file) else {
        return crate::managed::effective(file);
    };
    let base = last_applied(file);
    // REQ: CLU-003 (ADR-049) — a primary with a Git source uses the commit in use, else
    // (before its first fetch) the last version the cluster published.
    if file.cluster.git.is_some() && matches!(id.meta.role, Some(node::Role::Primary)) {
        if let Some(shared) = crate::gitsource::shared(file) {
            match telltale_config::shared::with_shared(file, &shared) {
                Ok(c) => return c,
                Err(e) => {
                    error!("the Git commit in use doesn't merge with this node's settings: {e:?}");
                }
            }
        }
        if let Some(m) = &base
            && let Ok(c) = merged(file, m)
        {
            return c;
        }
        return file.clone();
    }
    let gitops_source = id.meta.config_authority == "gitops" && gitops_capable(file);
    let m = match id.meta.role {
        Some(node::Role::Primary) if gitops_source => None,
        Some(node::Role::Primary) => base.map(|m| (m, true)),
        _ => base.map(|m| (m, false)),
    };
    let Some((m, with_managed)) = m else {
        return crate::managed::effective(file);
    };
    if !with_managed {
        let ignored = telltale_config::shared::ignored_on_replica(file);
        if !ignored.is_empty() {
            warn!(
                sections = ?ignored,
                "this node's configuration file sets shared settings that the cluster's primary replaces; they're ignored (CLU-006)"
            );
        }
    }
    match merged(file, &m) {
        Ok(c) if with_managed => crate::managed::effective(&c),
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

/// Whether this node's own configuration comes from Git: rendered from a repository (the Helm
/// chart under Argo CD), or fetched from a `[cluster.git]` source (ADR-048, ADR-049).
pub(crate) fn gitops_capable(cfg: &Config) -> bool {
    cfg.cluster.config_source.as_str() == "gitops" || cfg.cluster.git.is_some()
}

/// The provenance of the configuration this primary publishes, from its Git source.
fn git_source(cfg: &Config) -> Option<telltale_cluster::sync::SourceInfo> {
    let g = cfg.cluster.git.as_ref()?;
    let s = crate::gitsource::status(cfg)?;
    Some(telltale_cluster::sync::SourceInfo {
        repo: g.repo.to_string(),
        git_ref: g.git_ref.to_string(),
        path: g.path.to_string(),
        commit: s.commit?,
        author: s.author,
        time: s.time,
        subject: s.subject,
        signed_by: s.signed_by,
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

/// Starts replication: a supervisor runs the publisher while this node is primary and the
/// follower while it's a replica, switching when a promotion or fencing changes the role.
pub(crate) fn start(
    cluster: &Arc<Cluster>,
    files: Vec<PathBuf>,
    sources: &Arc<Sources>,
    reload: mpsc::Sender<oneshot::Sender<bool>>,
    stop: &watch::Receiver<bool>,
) {
    cluster.set_config_source(if gitops_capable(&sources.config.load()) {
        "gitops"
    } else {
        "file"
    });
    tokio::spawn(serving_loop(
        Arc::clone(cluster),
        Arc::clone(sources),
        stop.clone(),
    ));
    tokio::spawn(supervise(
        Arc::clone(cluster),
        files,
        Arc::clone(sources),
        reload,
        stop.clone(),
    ));
}

async fn supervise(
    cluster: Arc<Cluster>,
    files: Vec<PathBuf>,
    sources: Arc<Sources>,
    reload: mpsc::Sender<oneshot::Sender<bool>>,
    mut stop: watch::Receiver<bool>,
) {
    let mut roles = cluster.role_watch();
    let mut first = true;
    loop {
        let (role, epoch) = *roles.borrow_and_update();
        let (child_stop, child) = watch::channel(false);
        match role {
            Role::Primary | Role::Emergency => {
                info!(
                    epoch,
                    emergency = role == Role::Emergency,
                    "cluster role: primary"
                );
                tokio::spawn(publish_loop(
                    Arc::clone(&cluster),
                    Arc::clone(&sources),
                    child,
                    role == Role::Emergency,
                ));
            }
            Role::Replica => {
                info!(epoch, "cluster role: replica");
                start_follower(&cluster, files.clone(), &sources, reload.clone(), &child);
            }
        }
        if !first {
            // The effective configuration and whether this node fetches lists depend on the
            // role: re-evaluate both now.
            let (tx, _rx) = oneshot::channel();
            let _ = reload.send(tx).await;
        }
        first = false;
        tokio::select! {
            _ = stop.changed() => {
                let _ = child_stop.send(true);
                return;
            }
            r = roles.changed() => {
                let _ = child_stop.send(true);
                if r.is_err() { return; }
            }
        }
    }
}

/// Follows the primary (replica side, CLU-003).
fn start_follower(
    cluster: &Arc<Cluster>,
    files: Vec<PathBuf>,
    sources: &Arc<Sources>,
    reload: mpsc::Sender<oneshot::Sender<bool>>,
    stop: &watch::Receiver<bool>,
) {
    let cfg = sources.config.load_full();
    let store = match BlobStore::open(data_dir(&cfg)) {
        Ok(s) => s,
        Err(e) => {
            error!("cluster: can't open the blob store ({e}); not following the primary");
            return;
        }
    };
    let publisher = Publisher::new(Arc::clone(&sources.pipeline));
    // CLU-004 — serve the last applied snapshot right away, before any contact.
    let last = last_applied(&cfg);
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
    let store2 = store.clone();
    let cluster2 = Arc::clone(cluster);
    tokio::spawn(telltale_cluster::net::follow(
        Arc::clone(cluster),
        store,
        at,
        move |m: ClusterManifest| {
            let (store, files, reload, publisher, last_filter, cluster) = (
                store2.clone(),
                files.clone(),
                reload.clone(),
                publisher.clone(),
                Arc::clone(&last_filter),
                Arc::clone(&cluster2),
            );
            async move {
                let blobs = m.filter.as_ref().map(|f| f.blobs.clone());
                let changed = *last_filter
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    != blobs;
                apply(m, &cluster, &store, &files, &reload, &publisher, changed).await?;
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
    cluster: &Cluster,
    store: &BlobStore,
    files: &[PathBuf],
    reload: &mpsc::Sender<oneshot::Sender<bool>>,
    publisher: &Publisher,
    filter_changed: bool,
) -> Result<(), String> {
    // Check the merged configuration before anything changes on disk.
    let file = crate::server::load_files(files)
        .ok_or("this node's own configuration files are invalid")?;
    // REQ: CLU-010 — a newer primary's settings this build doesn't know: keep serving the
    // last version and say what to do.
    merged(&file, &m).map_err(|e| {
        if m.schema > telltale_cluster::sync::SCHEMA {
            format!(
                "the primary publishes configuration schema {} and this node reads up to {}: upgrade this node ({e})",
                m.schema,
                telltale_cluster::sync::SCHEMA
            )
        } else {
            e
        }
    })?;
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
    let cdir = node::dir_of(data_dir(&file));
    // ADR-051 — versions this node published as primary after the new primary's base are
    // orphaned: keep them for the Conflicts list, never apply them.
    if let Err(e) = record_orphans(&cdir, store, &m) {
        warn!("cluster: can't record orphaned versions: {e}");
    }
    // The registry and the cluster's authority travel in the manifest.
    if !m.nodes.is_empty() {
        let _ = cluster.identity.save_registry(&m.nodes);
    }
    if !m.authority.is_empty() {
        let _ = cluster.identity.save_authority(&m.authority);
    }
    if !m.failover.is_empty() {
        let _ = cluster.identity.save_failover(&m.failover);
    }
    // ADR-049 — the Git source the cluster is pinned to, and the commit this node serves.
    if let Some(s) = &m.source {
        crate::gitsource::save_pin(&file, &s.repo, &s.git_ref, &s.path);
    }
    let commit = m
        .source
        .as_ref()
        .map(|s| s.commit.clone())
        .unwrap_or_default();
    cluster.set_local(|l| l.source_commit = commit);
    let json = serde_json::to_vec_pretty(&m).map_err(|e| e.to_string())?;
    write_atomic(&cdir.join(APPLIED), &json).map_err(|e| e.to_string())?;
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

/// A version this node published that the cluster moved on without (ADR-051).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct Conflict {
    pub epoch: u64,
    pub seq: u64,
    /// When it was published (Unix ms).
    pub created_ms: u64,
    /// When the newer primary's version arrived (Unix ms).
    pub detected_ms: u64,
    /// The newer primary and the version it continued from.
    pub new_primary: String,
    pub base: (u64, u64),
    /// Settings that differ from the newer primary's version (dotted paths).
    pub changed: Vec<String>,
}

fn record_orphans(cdir: &Path, store: &BlobStore, m: &ClusterManifest) -> Result<(), String> {
    let path = cdir.join(PUBLISHED);
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(()); // never published
    };
    let mine: Published = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if m.epoch <= mine.epoch {
        return Ok(()); // not a newer primary's version
    }
    if let Some((be, bs)) = m.base
        && mine.epoch == be
        && mine.seq > bs
    {
        let old = std::fs::read(cdir.join("published-config.json")).unwrap_or_default();
        let new = store.read(&m.config).unwrap_or_default();
        let (a, b) = (
            serde_json::from_slice::<serde_json::Value>(&old).unwrap_or_default(),
            serde_json::from_slice::<serde_json::Value>(&new).unwrap_or_default(),
        );
        let mut changed = Vec::new();
        crate::server::changed_paths(&b, &a, String::new(), &mut changed);
        let c = Conflict {
            epoch: mine.epoch,
            seq: mine.seq,
            created_ms: mine.created_ms,
            detected_ms: now_ms(),
            new_primary: m.primary.clone(),
            base: (be, bs),
            changed,
        };
        let dir = cdir.join("conflicts");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let name = format!("{}-{}", c.epoch, c.seq);
        write_atomic(
            &dir.join(format!("{name}.json")),
            &serde_json::to_vec_pretty(&c).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        if !old.is_empty() {
            write_atomic(&dir.join(format!("{name}.config.json")), &old)
                .map_err(|e| e.to_string())?;
        }
        warn!(
            epoch = c.epoch,
            seq = c.seq,
            "this node's last versions were never seen by the new primary: kept under Conflicts"
        );
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Orphaned versions on this node, newest first.
pub(crate) fn conflicts(cfg: &Config) -> Vec<Conflict> {
    let dir = node::dir_of(data_dir(cfg)).join("conflicts");
    let mut v: Vec<Conflict> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            e.file_name().to_str().is_some_and(|n| {
                std::path::Path::new(n)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("json"))
                    && !n.ends_with(".config.json")
            })
        })
        .filter_map(|e| serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok())
        .collect();
    v.sort_by_key(|c: &Conflict| std::cmp::Reverse((c.epoch, c.seq)));
    v
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// What the primary last published (persisted, so `seq` only grows across restarts).
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Published {
    #[serde(default)]
    epoch: u64,
    seq: u64,
    config: String,
    filter: Option<u64>,
    #[serde(default)]
    created_ms: u64,
    /// Hash of the cluster-level settings that travel with the configuration (the member
    /// registry and the config authority): a change there is a new version too.
    #[serde(default)]
    meta: String,
    /// The version this epoch continued from (ADR-051), carried by every manifest of the
    /// epoch: peers only see the newest, and an old primary needs it to find its orphans.
    #[serde(default)]
    base: Option<(u64, u64)>,
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

/// An installed snapshot named by a filter reference (an inherited or emergency filter).
fn filter_paths(cfg: &Config, f: &FilterRef) -> Option<Vec<(String, PathBuf)>> {
    let dir = snapshot_dir(cfg, f);
    dir.join(MANIFEST).is_file().then(|| {
        f.blobs
            .iter()
            .map(|b| (b.hash.clone(), dir.join(&b.name)))
            .collect()
    })
}

/// Primary side: republishes whenever the shared configuration or the snapshot changes. An
/// emergency primary (ADR-048) republishes the last authoritative version once, in its new
/// epoch, and never changes it.
#[allow(clippy::too_many_lines)] // one loop: gather, compare, sign, publish, persist
async fn publish_loop(
    cluster: Arc<Cluster>,
    sources: Arc<Sources>,
    mut stop: watch::Receiver<bool>,
    emergency: bool,
) {
    let cfg = sources.config.load_full();
    let cdir = node::dir_of(data_dir(&cfg));
    let state_path = cdir.join(PUBLISHED);
    let mut last: Published = std::fs::read(&state_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let inherited = last_applied(&cfg);
    let key = match cluster.identity.ca_key_pem() {
        Ok(k) => k,
        Err(e) => {
            error!("cluster: {e}; not publishing configuration");
            return;
        }
    };
    let store = BlobStore::open(data_dir(&cfg)).ok();
    let mut first = true;
    loop {
        // REQ: CLU-005 — in automatic failover, publish only while the lease holds (ADR-056).
        // ADR-049 — with a Git source, nothing is published before the first good commit.
        let git_waiting = {
            let c = sources.config.load();
            c.cluster.git.is_some()
                && crate::gitsource::status(&c)
                    .and_then(|s| s.commit)
                    .is_none()
        };
        if !cluster.may_publish() || git_waiting {
            tokio::select! {
                r = stop.changed() => if r.is_err() || *stop.borrow() { return; },
                () = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
            }
            continue;
        }
        // ADR-051 — the role and epoch together: a node fenced since the check above must not
        // publish (least of all in the new primary's epoch); `publish_as` checks again.
        let (role, epoch) = cluster.role();
        if !matches!(role, node::Role::Primary | node::Role::Emergency) {
            tokio::select! {
                r = stop.changed() => if r.is_err() || *stop.borrow() { return; },
                () = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
            }
            continue;
        }
        let cfg = sources.config.load_full();
        // What to publish: this node's configuration and newest snapshot, or (emergency) the
        // last authoritative version unchanged.
        let (shared, filter) = if emergency {
            let Some(m) = inherited.as_ref() else {
                error!(
                    "cluster: an emergency primary needs a version to keep, and this node never synced"
                );
                return;
            };
            let Some(bytes) = store.as_ref().and_then(|s| s.read(&m.config).ok()) else {
                error!("cluster: the last applied configuration is missing from the blob store");
                return;
            };
            let filter = m
                .filter
                .as_ref()
                .and_then(|f| filter_paths(&cfg, f).map(|p| (f.clone(), p)));
            (bytes, filter)
        } else {
            let shared = serde_json::to_vec(&shared_part(&cfg)).unwrap_or_default();
            let compiled = sources.lists.load_full().and_then(|l| {
                l.compiled
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            });
            let filter = compiled
                .and_then(|c| {
                    let dir = data_dir(&cfg)
                        .join("snapshots")
                        .join(c.manifest.version.to_string());
                    filter_ref(&dir, &c.manifest)
                })
                // A newly promoted node serves the inherited snapshot until it compiles its own.
                .or_else(|| {
                    let f = inherited.as_ref()?.filter.as_ref()?;
                    filter_paths(&cfg, f).map(|p| (f.clone(), p))
                });
            (shared, filter)
        };
        let config_hash = hash(&shared);
        let filter_version = filter.as_ref().map(|(f, _)| f.version);
        let nodes = cluster.identity.registry();
        let meta = cluster.identity.reload().meta;
        let (mut authority, failover) = (meta.config_authority, meta.failover);
        // REQ: CLU-003 (ADR-049) — a Git source makes the cluster GitOps-managed, and every
        // version names its commit.
        let source = git_source(&cfg);
        if source.is_some() {
            "gitops".clone_into(&mut authority);
            let _ = cluster.identity.save_authority("gitops");
        }
        // REQ: CLU-001 (T5.4c) — the trusted CAs travel with every version; a CA rotation
        // step is a new version.
        let id_now = cluster.identity.reload();
        let ca_bundle = id_now.ca_pem.clone();
        let meta_hash = hash(
            &serde_json::to_vec(&(&nodes, &authority, &failover, &source, &ca_bundle))
                .unwrap_or_default(),
        );
        let new_epoch = epoch > last.epoch;
        let changed = new_epoch
            || config_hash != last.config
            || filter_version != last.filter
            || meta_hash != last.meta;
        if changed || first {
            let base = inherited
                .as_ref()
                .map_or((last.epoch, last.seq), |m| (m.epoch, m.seq));
            // The epoch's base: set by its first manifest, then carried by every later one.
            let epoch_base = if new_epoch { Some(base) } else { last.base };
            let seq = if changed {
                last.seq.max(base.1) + 1
            } else {
                last.seq.max(1)
            };
            let mut blobs = HashMap::new();
            let config = blob_ref("config.json", &shared);
            if let Some(s) = &store {
                let _ = s.put(&config, &shared);
            }
            let _ = write_atomic(&cdir.join("published-config.json"), &shared);
            blobs.insert(config.hash.clone(), BlobSource::Bytes(Bytes::from(shared)));
            if let Some((_, paths)) = &filter {
                for (h, p) in paths {
                    blobs.insert(h.clone(), BlobSource::File(p.clone()));
                }
            }
            let now = now_ms();
            let m = ClusterManifest {
                cluster_id: cluster.identity.meta.cluster_id.clone(),
                epoch,
                seq,
                created_ms: now,
                primary: cluster.identity.meta.node_id.clone(),
                config,
                filter: filter.map(|(f, _)| f),
                nodes,
                authority,
                base: epoch_base,
                emergency,
                failover,
                schema: telltale_cluster::sync::SCHEMA,
                source: source.clone(),
                ca_bundle,
            };
            // The signing key changes when a CA rotation switches (T5.4c).
            let key = id_now.ca_key_pem().unwrap_or_else(|_| key.clone());
            match Signed::sign(&m, &key) {
                Ok(signed) => {
                    if !cluster.publish_as(epoch, signed, blobs) {
                        // The next pass finds the new role and waits.
                        warn!(
                            epoch,
                            "cluster: no longer the primary of this epoch; not publishing"
                        );
                        continue;
                    }
                    let commit = m
                        .source
                        .as_ref()
                        .map(|s| s.commit.clone())
                        .unwrap_or_default();
                    cluster.set_local(|l| {
                        l.applied_seq = seq;
                        l.source_commit = commit;
                    });
                    cluster.set_sync_status(|s| {
                        s.epoch = m.epoch;
                        s.seq = seq;
                        s.created_ms = now;
                        s.applied_ms = now;
                        s.error = None;
                    });
                    if changed {
                        info!(epoch, seq, filter = ?filter_version, emergency, "published cluster configuration");
                        cluster.event(
                            "published",
                            &cluster.identity.meta.node_id,
                            format!(
                                "version {seq}{}{}",
                                filter_version
                                    .map_or(String::new(), |v| format!(", filter snapshot {v}")),
                                if new_epoch {
                                    format!(" (epoch {epoch})")
                                } else {
                                    String::new()
                                }
                            ),
                        );
                    }
                    last = Published {
                        epoch,
                        seq,
                        config: config_hash,
                        filter: filter_version,
                        created_ms: now,
                        meta: meta_hash,
                        base: epoch_base,
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
/// share over the last minute, upstream p90 this hour, readiness, uptime, and (T6.14) where it
/// runs in Kubernetes, when it started, and its cache. Every 5 s, off the query path (the
/// aggregator's data and the cache's counters).
async fn serving_loop(
    cluster: Arc<Cluster>,
    sources: Arc<Sources>,
    mut stop: watch::Receiver<bool>,
) {
    use telltale_telemetry::agg::{HourSel, LatencyKey, Resolution};
    let (kube_node, pod) = kube_names(|k| std::env::var(k).ok());
    let started_ms =
        now_ms().saturating_sub(u64::try_from(sources.started.elapsed().as_millis()).unwrap_or(0));
    // Cache hits and misses at each pass for the last minute (12 passes of 5 s).
    let mut cache_window: std::collections::VecDeque<(u64, u64)> =
        std::collections::VecDeque::with_capacity(13);
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
        let host = sources.host.latest();
        let c = sources.cache.stats();
        cache_window.push_back((c.hits, c.misses));
        if cache_window.len() > 13 {
            cache_window.pop_front();
        }
        let cache_hit_permille = cache_window.front().and_then(|&(h0, m0)| {
            hit_permille(c.hits.saturating_sub(h0), c.misses.saturating_sub(m0))
        });
        let cache_entries = u64::try_from(c.entries).ok();
        cluster.set_local(|l| {
            l.qps = total / 60;
            l.servfail_permille =
                u32::try_from((servfail * 1000).checked_div(total).unwrap_or(0)).unwrap_or(1000);
            l.p90_us = p90;
            l.ready = ready;
            l.uptime_s = uptime;
            l.host = host;
            l.kube_node.clone_from(&kube_node);
            l.pod.clone_from(&pod);
            l.started_ms = started_ms;
            l.cache_entries = cache_entries;
            l.cache_hit_permille = cache_hit_permille;
        });
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }
}

/// REQ: CLU-008 (T6.14) — the Kubernetes node and pod this process runs in: the chart passes
/// them through the downward API (`TELLTALE_KUBE_NODE`, `TELLTALE_POD`); in a pod without them,
/// the pod name is the host name. Both are empty outside Kubernetes.
fn kube_names(env: impl Fn(&str) -> Option<String>) -> (String, String) {
    let get = |k: &str| {
        env(k)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    let node = get("TELLTALE_KUBE_NODE").unwrap_or_default();
    let pod = get("TELLTALE_POD")
        .or_else(|| get("KUBERNETES_SERVICE_HOST").and_then(|_| get("HOSTNAME")))
        .unwrap_or_default();
    (node, pod)
}

/// Hits per thousand lookups; none without lookups.
fn hit_permille(hits: u64, misses: u64) -> Option<u32> {
    let looked = hits.checked_add(misses)?;
    (looked > 0).then(|| u32::try_from(hits.saturating_mul(1000) / looked).unwrap_or(1000))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: CLU-008 (T6.14) — node and pod names from the chart's variables, the pod name from
    /// HOSTNAME in other pods, nothing outside Kubernetes.
    #[test]
    fn clu_008_kube_names() {
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                vars.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        assert_eq!(
            kube_names(env(&[
                ("TELLTALE_KUBE_NODE", "k3s-1"),
                ("TELLTALE_POD", "telltale-0"),
                ("HOSTNAME", "x")
            ])),
            ("k3s-1".into(), "telltale-0".into())
        );
        assert_eq!(
            kube_names(env(&[
                ("KUBERNETES_SERVICE_HOST", "10.43.0.1"),
                ("HOSTNAME", "dns-7f9c")
            ])),
            (String::new(), "dns-7f9c".into())
        );
        assert_eq!(
            kube_names(env(&[("HOSTNAME", "pi")])),
            (String::new(), String::new())
        );
        assert_eq!(hit_permille(0, 0), None);
        assert_eq!(hit_permille(812, 188), Some(812));
        assert_eq!(hit_permille(5, 0), Some(1000));
    }

    #[test]
    fn clu_003_blob_names_from_the_network_are_plain_file_names() {
        assert!(safe_name("subtree-0.fst") && safe_name("manifest.json"));
        assert!(!safe_name("../x") && !safe_name("a/b") && !safe_name(".hidden") && !safe_name(""));
    }
}
