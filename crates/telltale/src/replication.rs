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

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use telltale_cluster::net::{BlobSource, Cluster};
use telltale_cluster::node::{self, Role};
use telltale_cluster::sync::{
    BlobRef, BlobStore, ClusterManifest, FilterRef, PinInfo, Signed, blob_ref, hash,
};
use telltale_config::Config;
use telltale_config::shared::{shared_part, with_shared};
use telltale_filter::snapshot::{MANIFEST, Manifest};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{error, info, warn};

use crate::http::Sources;
use crate::lists::Publisher;
use crate::rollout;

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
    // REQ: CLU-013 — a pinned primary serves the pinned version, whatever its own source says.
    if let Some(id) = identity(file)
        && matches!(id.meta.role, Some(node::Role::Primary))
        && let Some(pm) = rollout::pinned_manifest(&node::dir_of(data_dir(file)))
    {
        match merged(file, &pm) {
            Ok(c) => return c,
            Err(e) => {
                error!("the pinned cluster version doesn't merge with this node's settings: {e}");
            }
        }
    }
    unpinned(file)
}

/// REQ: CLU-013 — [`effective`] as if the cluster weren't pinned: what the primary would
/// publish once unpinned (the pin's diff compares the two).
pub(crate) fn unpinned(file: &Config) -> Config {
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
                // REQ: CLU-003 (T9.1) — the primary is where users and tokens are managed.
                if let Some(a) = sources.auth.get() {
                    a.set_identity_primary(None);
                }
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
    let sources2 = Arc::clone(sources);
    tokio::spawn(telltale_cluster::net::follow(
        Arc::clone(cluster),
        store,
        at,
        move |m: ClusterManifest| {
            let (store, files, reload, publisher, last_filter, cluster, sources) = (
                store2.clone(),
                files.clone(),
                reload.clone(),
                publisher.clone(),
                Arc::clone(&last_filter),
                Arc::clone(&cluster2),
                Arc::clone(&sources2),
            );
            async move {
                let blobs = m.filter.as_ref().map(|f| f.blobs.clone());
                let changed = *last_filter
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    != blobs;
                apply(
                    m, &cluster, &store, &files, &reload, &publisher, changed, &sources,
                )
                .await?;
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
#[allow(clippy::too_many_arguments)]
async fn apply(
    m: ClusterManifest,
    cluster: &Cluster,
    store: &BlobStore,
    files: &[PathBuf],
    reload: &mpsc::Sender<oneshot::Sender<bool>>,
    publisher: &Publisher,
    filter_changed: bool,
    sources: &Sources,
) -> Result<(), String> {
    // Check the merged configuration before anything changes on disk.
    let file = crate::server::load_files_quiet(files)
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
    // REQ: OBS-003 (review 04-05) — hash level-1 names as the primary does.
    if let Some(k) = &m.privacy_key {
        crate::privacy::adopt(data_dir(&file), k);
    }
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
    // REQ: CLU-003 (T9.1, ADR-045) — the primary's users and tokens.
    if let Some(b) = &m.identities {
        import_identities(sources, store, b, &primary_label(&m)).await?;
    }
    // REQ: OBS-014 (ADR-103) — the primary's acknowledged anomalies. Best effort: a failure
    // costs only the badge's accuracy, never the version.
    if let Some(b) = &m.anomaly_acks
        && let Err(e) = import_acks(sources, store, b).await
    {
        warn!("cluster: acknowledged anomalies not taken in: {e}");
    }
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

/// The primary's identities as published (T9.1), or `None` before the API opened `state.db`.
async fn export_identities(sources: &Arc<Sources>) -> Option<Vec<u8>> {
    let auth = Arc::clone(sources.auth.get()?);
    tokio::task::spawn_blocking(move || {
        auth.state()
            .export_identities()
            .map_err(|e| warn!("cluster: can't read users and tokens to publish: {e}"))
            .ok()
            .and_then(|d| serde_json::to_vec(&d).ok())
    })
    .await
    .ok()
    .flatten()
}

/// The acknowledged anomalies as last exported: the set's change counter, the document, and its
/// hash.
type AcksCache = Option<(u64, Vec<u8>, String)>;

/// REQ: OBS-014 (ADR-103) — refreshes `cache` with the acknowledged anomalies to publish and
/// returns their hash, or `None` before the API opened `state.db`. Read again only when the set
/// changed (the loop runs twice a second). An empty set is published too, so taking the last one
/// back reaches every node.
async fn export_acks(sources: &Arc<Sources>, cache: &mut AcksCache) -> Option<String> {
    let auth = Arc::clone(sources.auth.get()?);
    let known = cache.as_ref().map(|(v, _, _)| *v);
    let fresh = tokio::task::spawn_blocking(move || {
        let state = auth.state();
        let version = state.anomaly_acks_version().ok()?;
        if known == Some(version) {
            return Some(None);
        }
        state
            .anomaly_acks()
            .map_err(|e| warn!("cluster: can't read acknowledged anomalies to publish: {e}"))
            .ok()
            .and_then(|d| serde_json::to_vec(&d).ok())
            .map(|bytes| Some((version, bytes)))
    })
    .await
    .ok()
    .flatten()?;
    if let Some((version, bytes)) = fresh {
        let h = hash(&bytes);
        *cache = Some((version, bytes, h));
    }
    cache.as_ref().map(|(_, _, h)| h.clone())
}

/// REQ: OBS-014 (ADR-103) — a replica takes the primary's acknowledged anomalies.
async fn import_acks(sources: &Sources, store: &BlobStore, b: &BlobRef) -> Result<(), String> {
    let Some(auth) = sources.auth.get().cloned() else {
        return Ok(()); // the API isn't up yet: the next version brings them again
    };
    let bytes = store.read(b)?;
    let acks: Vec<telltale_store::state::AnomalyAck> =
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let state = Arc::clone(auth.state());
    let n = acks.len();
    let changed = tokio::task::spawn_blocking(move || state.replace_anomaly_acks(&acks))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    if changed {
        info!(
            acknowledged = n,
            "cluster: acknowledged anomalies synced from the primary"
        );
    }
    Ok(())
}

/// How the refusal on a replica names the primary: its site, else its node ID.
fn primary_label(m: &ClusterManifest) -> String {
    m.nodes
        .iter()
        .find(|n| n.node_id == m.primary)
        .map(|n| n.site.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| m.primary.clone())
}

/// Takes in the primary's identities on a replica (T9.1), skipping an unchanged document.
async fn import_identities(
    sources: &Sources,
    store: &BlobStore,
    b: &BlobRef,
    primary: &str,
) -> Result<(), String> {
    let Some(auth) = sources.auth.get().cloned() else {
        return Ok(()); // the API isn't up yet: the next version brings them again
    };
    auth.set_identity_primary(Some(primary.to_owned()));
    let applied = || {
        sources
            .identities_applied
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    };
    if applied() == b.hash {
        return Ok(());
    }
    let bytes = store.read(b)?;
    let doc: telltale_store::state::Identities =
        serde_json::from_slice(&bytes).map_err(|e| format!("identities: {e}"))?;
    let state = Arc::clone(auth.state());
    let rep = tokio::task::spawn_blocking(move || state.import_identities(&doc))
        .await
        .map_err(|e| format!("identities: {e}"))?
        .map_err(|e| format!("identities: {e}"))?;
    info!(
        added = rep.users_added,
        updated = rep.users_updated,
        removed = rep.users_removed,
        tokens = rep.tokens,
        "cluster: users and tokens synced from the primary"
    );
    if !rep.replaced_local.is_empty() {
        warn!(users = ?rep.replaced_local, "cluster: users made on this node now use the primary's account of the same name");
    }
    if !rep.local_kept.is_empty() {
        info!(users = ?rep.local_kept, "cluster: users only on this node are kept (manage them on the primary to share them)");
    }
    b.hash.clone_into(
        &mut sources
            .identities_applied
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
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
    /// REQ: CLU-003 (T9.1) — hash of the published identities.
    #[serde(default)]
    identities: String,
    /// REQ: OBS-014 — hash of the published acknowledged anomalies.
    #[serde(default)]
    acks: String,
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

/// What one pass gathered to publish: the content (the shared configuration and the snapshot)
/// and what travels with it.
struct Gathered {
    shared: Vec<u8>,
    filter: Option<(FilterRef, Vec<(String, PathBuf)>)>,
    config_hash: String,
    filter_version: Option<u64>,
    nodes: Vec<node::NodeRecord>,
    authority: String,
    failover: String,
    source: Option<telltale_cluster::sync::SourceInfo>,
    ca_bundle: String,
    privacy_key: Option<String>,
    meta_hash: String,
    identities: Option<Vec<u8>>,
    identities_hash: String,
    acks: Option<Vec<u8>>,
    acks_hash: String,
    /// The key that signs (a CA rotation switches it, T5.4c).
    key: String,
}

enum Gather {
    Ready(Box<Gathered>),
    /// Nothing to publish this pass (a pinned version's files are missing).
    Skip,
    /// Never anything to publish (an emergency primary that never synced).
    Stop,
}

/// How a version goes out.
enum Mode {
    /// To every node.
    Stable,
    /// To these canary nodes first (REQ: CLU-013).
    Canary(BTreeSet<String>),
}

/// Waiting this long after the publisher starts for a canary to come online before a change
/// goes to every node (a restart shouldn't skip the rollout because no peer reconnected yet).
const CANARY_GRACE: Duration = Duration::from_secs(60);
/// The guard looks every this often (heartbeats come every 5 s).
const GUARD_EVERY: Duration = Duration::from_secs(5);

/// The version baking, as the primary keeps it to promote: the manifest, its blobs, its
/// shared configuration, and the key it was signed with.
struct Canary {
    manifest: ClusterManifest,
    blobs: HashMap<String, BlobSource>,
    shared: Vec<u8>,
    key: String,
}

/// The primary's publisher: what it published, the rollout in progress, the pin.
struct Primary {
    cluster: Arc<Cluster>,
    sources: Arc<Sources>,
    emergency: bool,
    cdir: PathBuf,
    state_path: PathBuf,
    last: Published,
    inherited: Option<ClusterManifest>,
    key: String,
    store: Option<BlobStore>,
    acks_cache: AcksCache,
    first: bool,
    /// Publish the content as new even if it's what was published last (a rollout that a
    /// restart interrupted, an unpin).
    force: bool,
    // REQ: CLU-013
    ro: rollout::State,
    versions: rollout::Versions,
    guard: rollout::Guard,
    last_guard: Option<std::time::Instant>,
    started: std::time::Instant,
    /// The stable head's version and shared configuration.
    stable: (u64, u64),
    stable_shared: Vec<u8>,
    /// The canary head as signed, its blobs, and its shared configuration (for promotion).
    canary: Option<Canary>,
    skipped: Option<String>,
    waiting_since_ms: Option<u64>,
    last_readings: Option<rollout::Readings>,
    last_failure: Option<rollout::Failure>,
    counts: std::collections::BTreeMap<String, u64>,
    canaries_offline_since: Option<u64>,
}

impl Primary {
    fn open(cluster: Arc<Cluster>, sources: Arc<Sources>, emergency: bool) -> Option<Self> {
        let cfg = sources.config.load_full();
        let cdir = node::dir_of(data_dir(&cfg));
        let state_path = cdir.join(PUBLISHED);
        let last: Published = std::fs::read(&state_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let inherited = last_applied(&cfg);
        let key = match cluster.identity.ca_key_pem() {
            Ok(k) => k,
            Err(e) => {
                error!("cluster: {e}; not publishing configuration");
                return None;
            }
        };
        let store = BlobStore::open(data_dir(&cfg)).ok();
        let mut ro = rollout::State::load(&cdir);
        let mut versions = rollout::Versions::load(&cdir);
        let mut force = false;
        // REQ: CLU-013 — a rollout a restart interrupted starts again (the canary version is
        // published anew, to the canaries first).
        if let Some(a) = ro.active.take() {
            versions.set_outcome(a.version, rollout::outcome::SUPERSEDED, None);
            force = true;
            info!(
                seq = a.version.1,
                "cluster: the rollout in progress starts again after the restart"
            );
        }
        // REQ: CLU-013 — a pin survives failover: a replica promoted from a pinned version keeps
        // serving it, pinned.
        if ro.pinned.is_none()
            && let Some(m) = inherited.as_ref()
            && let Some(pin) = m.pinned.clone()
        {
            info!(to = ?pin.to, "cluster: the cluster is pinned: staying pinned as its primary");
            ro.pinned = Some(pin);
            if let Ok(b) = serde_json::to_vec_pretty(m) {
                let _ = write_atomic(&cdir.join(rollout::PINNED), &b);
            }
        }
        let stable = (last.epoch, last.seq);
        let stable_shared = std::fs::read(cdir.join("published-config.json")).unwrap_or_default();
        Some(Self {
            cluster,
            sources,
            emergency,
            cdir,
            state_path,
            last,
            inherited,
            key,
            store,
            acks_cache: None,
            first: true,
            force,
            ro,
            versions,
            guard: rollout::Guard::default(),
            last_guard: None,
            started: std::time::Instant::now(),
            stable,
            stable_shared,
            canary: None,
            skipped: None,
            waiting_since_ms: None,
            last_readings: None,
            last_failure: None,
            counts: std::collections::BTreeMap::new(),
            canaries_offline_since: None,
        })
    }

    /// The pinned manifest the primary serves, when pinned.
    fn pinned_manifest(&self) -> Option<ClusterManifest> {
        self.ro.pinned.as_ref()?;
        rollout::pinned_manifest(&self.cdir)
    }

    /// A filter whose blobs are all in the store, as paths in the store.
    fn store_paths(&self, f: &FilterRef) -> Option<Vec<(String, PathBuf)>> {
        let s = self.store.as_ref()?;
        f.blobs
            .iter()
            .map(|b| {
                s.has(b)
                    .then(|| s.path(&b.hash).map(|p| (b.hash.clone(), p)))
                    .flatten()
            })
            .collect()
    }

    #[allow(clippy::too_many_lines)] // one pass: content, metadata, users, acknowledgements
    async fn gather(&mut self) -> Gather {
        let cfg = self.sources.config.load_full();
        let inherited = self.inherited.as_ref();
        // What to publish: this node's configuration and newest snapshot; an emergency
        // primary's last authoritative version unchanged; or a pinned version's content.
        let content = if self.emergency || self.ro.pinned.is_some() {
            let m = if self.emergency {
                inherited.cloned()
            } else {
                self.pinned_manifest()
            };
            let Some(m) = m else {
                if self.emergency {
                    error!(
                        "cluster: an emergency primary needs a version to keep, and this node never synced"
                    );
                    return Gather::Stop;
                }
                error!(
                    "cluster: the pinned version is missing ({}); not publishing",
                    rollout::PINNED
                );
                return Gather::Skip;
            };
            let Some(bytes) = self.store.as_ref().and_then(|s| s.read(&m.config).ok()) else {
                error!("cluster: the configuration to keep is missing from the blob store");
                return if self.emergency {
                    Gather::Stop
                } else {
                    Gather::Skip
                };
            };
            let filter = m.filter.as_ref().and_then(|f| {
                filter_paths(&cfg, f)
                    .or_else(|| self.store_paths(f))
                    .map(|p| (f.clone(), p))
            });
            (bytes, filter)
        } else {
            let shared = serde_json::to_vec(&shared_part(&cfg)).unwrap_or_default();
            let compiled = self.sources.lists.load_full().and_then(|l| {
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
                    let f = inherited?.filter.as_ref()?;
                    filter_paths(&cfg, f).map(|p| (f.clone(), p))
                });
            (shared, filter)
        };
        let (shared, filter) = content;
        let config_hash = hash(&shared);
        let filter_version = filter.as_ref().map(|(f, _)| f.version);
        let nodes = self.cluster.identity.registry();
        let meta = self.cluster.identity.reload().meta;
        let (mut authority, failover) = (meta.config_authority, meta.failover);
        // REQ: CLU-003 (ADR-049) — a Git source makes the cluster GitOps-managed, and every
        // version names its commit.
        let source = git_source(&cfg);
        if source.is_some() {
            "gitops".clone_into(&mut authority);
            let _ = self.cluster.identity.save_authority("gitops");
        }
        // REQ: CLU-001 (T5.4c) — the trusted CAs travel with every version; a CA rotation
        // step is a new version.
        let id_now = self.cluster.identity.reload();
        let ca_bundle = id_now.ca_pem.clone();
        // REQ: OBS-003 (review 04-05) — the cluster's level-1 hash key (an emergency primary
        // passes on the one it inherited).
        let privacy_key = if self.emergency {
            inherited.and_then(|m| m.privacy_key.clone())
        } else {
            crate::privacy::current_hex(data_dir(&cfg))
        };
        let meta_hash = hash(
            &serde_json::to_vec(&(
                &nodes,
                &authority,
                &failover,
                &source,
                &ca_bundle,
                &privacy_key,
            ))
            .unwrap_or_default(),
        );
        // REQ: CLU-003 (T9.1, ADR-045) — users and tokens travel too (an emergency primary
        // keeps the last authoritative ones).
        let identities: Option<Vec<u8>> = if self.emergency {
            inherited
                .and_then(|m| m.identities.as_ref())
                .and_then(|b| self.store.as_ref().and_then(|s| s.read(b).ok()))
        } else {
            export_identities(&self.sources).await
        };
        let identities_hash = identities.as_deref().map(hash).unwrap_or_default();
        // REQ: OBS-014 (ADR-103) — acknowledged anomalies travel the same way. An emergency
        // primary passes on the set it inherited.
        let (acks, acks_hash) = if self.emergency {
            let a: Option<Vec<u8>> = inherited
                .and_then(|m| m.anomaly_acks.as_ref())
                .and_then(|b| self.store.as_ref().and_then(|s| s.read(b).ok()));
            let h = a.as_deref().map(hash).unwrap_or_default();
            (a, h)
        } else {
            let h = export_acks(&self.sources, &mut self.acks_cache)
                .await
                .unwrap_or_default();
            (self.acks_cache.as_ref().map(|(_, b, _)| b.clone()), h)
        };
        let key = id_now.ca_key_pem().unwrap_or_else(|_| self.key.clone());
        Gather::Ready(Box::new(Gathered {
            shared,
            filter,
            config_hash,
            filter_version,
            nodes,
            authority,
            failover,
            source,
            ca_bundle,
            privacy_key,
            meta_hash,
            identities,
            identities_hash,
            acks,
            acks_hash,
            key,
        }))
    }

    /// The manifest for `g` as version `(epoch, seq)`, and the blobs it names (stored too).
    fn build(
        &self,
        g: &Gathered,
        epoch: u64,
        seq: u64,
        epoch_base: Option<(u64, u64)>,
        rollout_info: Option<telltale_cluster::sync::RolloutInfo>,
    ) -> (ClusterManifest, HashMap<String, BlobSource>) {
        let mut blobs = HashMap::new();
        let config = blob_ref("config.json", &g.shared);
        if let Some(s) = &self.store {
            let _ = s.put(&config, &g.shared);
        }
        let _ = write_atomic(&self.cdir.join("published-config.json"), &g.shared);
        blobs.insert(
            config.hash.clone(),
            BlobSource::Bytes(Bytes::from(g.shared.clone())),
        );
        let put = |name: &str, bytes: &Option<Vec<u8>>, blobs: &mut HashMap<String, BlobSource>| {
            bytes.as_ref().map(|bytes| {
                let r = blob_ref(name, bytes);
                if let Some(s) = &self.store {
                    let _ = s.put(&r, bytes);
                }
                blobs.insert(
                    r.hash.clone(),
                    BlobSource::Bytes(Bytes::from(bytes.clone())),
                );
                r
            })
        };
        let identities = put("identities.json", &g.identities, &mut blobs);
        let anomaly_acks = put("anomaly-acks.json", &g.acks, &mut blobs);
        if let Some((_, paths)) = &g.filter {
            for (h, p) in paths {
                blobs.insert(h.clone(), BlobSource::File(p.clone()));
            }
        }
        let m = ClusterManifest {
            cluster_id: self.cluster.identity.meta.cluster_id.clone(),
            epoch,
            seq,
            created_ms: now_ms(),
            primary: self.cluster.identity.meta.node_id.clone(),
            config,
            filter: g.filter.as_ref().map(|(f, _)| f.clone()),
            nodes: g.nodes.clone(),
            authority: g.authority.clone(),
            base: epoch_base,
            emergency: self.emergency,
            failover: g.failover.clone(),
            schema: telltale_cluster::sync::SCHEMA,
            source: g.source.clone(),
            ca_bundle: g.ca_bundle.clone(),
            identities,
            privacy_key: g.privacy_key.clone(),
            anomaly_acks,
            rollout: rollout_info,
            // REQ: CLU-013 — every version published while pinned says so (and a promoted
            // node inherits the pin from it).
            pinned: self.ro.pinned.clone(),
        };
        (m, blobs)
    }

    /// The canary peers online now: connected, able to take part, and named by `spec`.
    fn canary_peers(&self, spec: &[String]) -> BTreeSet<String> {
        if spec.is_empty() {
            return BTreeSet::new();
        }
        let registry = self.cluster.identity.registry();
        self.cluster
            .members()
            .into_iter()
            .filter(|m| m.connected && m.rollouts)
            .filter(|m| {
                let ephemeral = registry
                    .iter()
                    .any(|r| r.node_id == m.node_id && r.ephemeral);
                rollout::is_canary(spec, &m.node_id, &m.site, ephemeral)
            })
            .map(|m| m.node_id)
            .collect()
    }

    /// Whether `shared` differs from the stable version only in `[cluster.rollout]`: such a
    /// change is published at once (a bad canary set must be fixable).
    fn rollout_only(&self, shared: &[u8]) -> bool {
        let strip = |b: &[u8]| {
            let mut v: serde_json::Value = serde_json::from_slice(b).ok()?;
            v.as_object_mut()?.remove("cluster");
            Some(v)
        };
        match (strip(shared), strip(&self.stable_shared)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// The history entry for a manifest just published.
    fn entry(m: &ClusterManifest, outcome: &str) -> rollout::VersionEntry {
        rollout::VersionEntry {
            epoch: m.epoch,
            seq: m.seq,
            created_ms: m.created_ms,
            by: m.source.as_ref().map_or_else(
                || "this node's configuration".to_owned(),
                |s| {
                    format!(
                        "Git commit {}",
                        s.commit.chars().take(8).collect::<String>()
                    )
                },
            ),
            outcome: outcome.to_owned(),
            readings: None,
            config: m.config.clone(),
            filter: m.filter.clone(),
            identities: m.identities.clone(),
            acks: m.anomaly_acks.clone(),
            pinned_to: m.pinned.as_ref().map(|p| p.to),
            reason: m.pinned.as_ref().map(|p| p.reason.clone()),
        }
    }

    /// Records the published version, persists the state, and keeps the blobs the history,
    /// the inherited version, and the pin need (the snapshot's files hard-linked in).
    fn persist(&mut self, filter: Option<&(FilterRef, Vec<(String, PathBuf)>)>) {
        if let Ok(b) = serde_json::to_vec(&self.last)
            && let Err(e) = write_atomic(&self.state_path, &b)
        {
            warn!("cluster: can't record the published version: {e}");
        }
        let keep =
            usize::try_from(self.sources.config.load().cluster.rollout.history).unwrap_or(20);
        let trimmed = self.versions.entries.len() > keep;
        if trimmed {
            let extra = self.versions.entries.len() - keep;
            self.versions.entries.drain(..extra);
        }
        let _ = self.versions.save(&self.cdir);
        let _ = self.ro.save(&self.cdir);
        let Some(store) = &self.store else { return };
        if let Some((f, paths)) = filter {
            for b in &f.blobs {
                if let Some((_, p)) = paths.iter().find(|(h, _)| *h == b.hash)
                    && let Err(e) = store.link(b, p)
                {
                    warn!("cluster: can't keep {} for pinning: {e}", b.name);
                }
            }
        }
        let mut keep: Vec<BlobRef> = self.versions.protected();
        for m in self.inherited.iter().chain(self.pinned_manifest().as_ref()) {
            keep.extend(m.blobs().into_iter().cloned());
        }
        let refs: Vec<&BlobRef> = keep.iter().collect();
        store.retain(&refs);
    }

    /// Publishes `g` if anything changed: to the canaries first when a rollout applies, else
    /// to every node.
    #[allow(clippy::too_many_lines)] // decide, build, sign, publish, record
    fn publish(&mut self, epoch: u64, g: &Gathered) {
        let new_epoch = epoch > self.last.epoch;
        let content_changed =
            self.force || g.config_hash != self.last.config || g.filter_version != self.last.filter;
        let changed = new_epoch
            || content_changed
            || g.meta_hash != self.last.meta
            || g.identities_hash != self.last.identities
            || g.acks_hash != self.last.acks;
        if !(changed || self.first) {
            return;
        }
        // REQ: CLU-013 — while a version bakes, a change of users, tokens, or the member list
        // waits for the bake to end: a version for everyone now would carry the canary's
        // content.
        if self.ro.active.is_some() && !content_changed && !new_epoch {
            return;
        }
        let rcfg = self.sources.config.load().cluster.rollout.clone();
        let spec: Vec<String> = rcfg.canaries.iter().map(ToString::to_string).collect();
        let mut mode = Mode::Stable;
        if content_changed
            && !self.emergency
            && self.ro.pinned.is_none()
            && !spec.is_empty()
            && !self.rollout_only(&g.shared)
        {
            let peers = self.canary_peers(&spec);
            if peers.is_empty() {
                if self.started.elapsed() < CANARY_GRACE {
                    self.waiting_since_ms.get_or_insert_with(now_ms);
                    return; // a canary may still reconnect
                }
                if self.skipped.is_none() {
                    self.count("skipped");
                    warn!(
                        "cluster: rollout skipped: no canary online; the change goes to every node"
                    );
                }
                self.skipped = Some("no canary online".to_owned());
            } else {
                self.skipped = None;
                mode = Mode::Canary(peers);
            }
        }
        self.waiting_since_ms = None;
        let base = self
            .inherited
            .as_ref()
            .map_or((self.last.epoch, self.last.seq), |m| (m.epoch, m.seq));
        // The epoch's base: set by its first manifest, then carried by every later one.
        let epoch_base = if new_epoch {
            Some(base)
        } else {
            self.last.base
        };
        let seq = if changed {
            self.last.seq.max(base.1) + 1
        } else {
            self.last.seq.max(1)
        };
        let now = now_ms();
        let rollout_info = match &mode {
            Mode::Canary(peers) => Some(telltale_cluster::sync::RolloutInfo {
                stage: "canary".to_owned(),
                of: self.stable,
                started_ms: now,
                bake_secs: rcfg.bake_secs,
                canaries: peers.iter().cloned().collect(),
            }),
            Mode::Stable => None,
        };
        let (m, blobs) = self.build(g, epoch, seq, epoch_base, rollout_info);
        let signed = match Signed::sign(&m, &g.key) {
            Ok(s) => s,
            Err(e) => {
                error!("cluster: can't sign the configuration manifest: {e}");
                return;
            }
        };
        let to = match mode {
            Mode::Canary(peers) => {
                let n = peers.len();
                if !self.cluster.publish_canary_as(
                    epoch,
                    signed.clone(),
                    peers.clone(),
                    blobs.clone(),
                ) {
                    warn!(
                        epoch,
                        "cluster: no longer the primary of this epoch; not publishing"
                    );
                    return;
                }
                if let Some(old) = self.ro.active.take() {
                    self.versions
                        .set_outcome(old.version, rollout::outcome::SUPERSEDED, None);
                }
                let mut judged = peers.clone();
                judged.insert(self.cluster.identity.meta.node_id.clone());
                let bake_ms = u64::from(rcfg.bake_secs) * 1000;
                self.ro.active = Some(rollout::Active {
                    version: (epoch, seq),
                    stable: self.stable,
                    started_ms: now,
                    bake_secs: rcfg.bake_secs,
                    canaries: peers.into_iter().collect(),
                    before_pct: self.guard.pct(&judged, now.saturating_sub(bake_ms), now),
                });
                self.count("started");
                // The status shows the bake at once.
                self.last_guard = None;
                self.canary = Some(Canary {
                    manifest: m.clone(),
                    blobs,
                    shared: g.shared.clone(),
                    key: g.key.clone(),
                });
                self.versions
                    .record(Self::entry(&m, rollout::outcome::CANARY), usize::MAX);
                self.cluster.event(
                    "rollout_started",
                    &self.cluster.identity.meta.node_id,
                    format!(
                        "version {seq} to {n} canary node(s); everyone else after {} s if the guard passes",
                        rcfg.bake_secs
                    ),
                );
                format!(" to {n} canary node(s)")
            }
            Mode::Stable => {
                if !self.cluster.publish_as(epoch, signed, blobs) {
                    // The next pass finds the new role and waits.
                    warn!(
                        epoch,
                        "cluster: no longer the primary of this epoch; not publishing"
                    );
                    return;
                }
                if let Some(old) = self.ro.active.take() {
                    self.versions
                        .set_outcome(old.version, rollout::outcome::SUPERSEDED, None);
                }
                self.stable = (epoch, seq);
                self.stable_shared.clone_from(&g.shared);
                self.canary = None;
                let outcome = if self.ro.pinned.is_some() {
                    rollout::outcome::PINNED_TO
                } else {
                    rollout::outcome::STABLE
                };
                self.versions.record(Self::entry(&m, outcome), usize::MAX);
                String::new()
            }
        };
        let commit = m
            .source
            .as_ref()
            .map(|s| s.commit.clone())
            .unwrap_or_default();
        // REQ: CLU-013 — while a canary version bakes, the nodes waiting for it aren't behind.
        let canary_of = if self.ro.active.is_some() {
            self.stable.1
        } else {
            0
        };
        self.cluster.set_local(|l| {
            l.applied_seq = seq;
            l.source_commit = commit;
            l.canary_of = canary_of;
        });
        self.cluster.set_sync_status(|s| {
            s.epoch = m.epoch;
            s.seq = seq;
            s.created_ms = now;
            s.applied_ms = now;
            s.error = None;
        });
        if changed {
            info!(epoch, seq, filter = ?g.filter_version, emergency = self.emergency, "published cluster configuration{to}");
            self.cluster.event(
                "published",
                &self.cluster.identity.meta.node_id,
                format!(
                    "version {seq}{}{}{to}",
                    g.filter_version
                        .map_or(String::new(), |v| format!(", filter snapshot {v}")),
                    if new_epoch {
                        format!(" (epoch {epoch})")
                    } else {
                        String::new()
                    }
                ),
            );
        }
        self.last = Published {
            epoch,
            seq,
            config: g.config_hash.clone(),
            filter: g.filter_version,
            created_ms: now,
            meta: g.meta_hash.clone(),
            base: epoch_base,
            identities: g.identities_hash.clone(),
            acks: g.acks_hash.clone(),
        };
        self.persist(g.filter.as_ref());
        self.first = false;
        self.force = false;
    }

    /// What the primary knows of every node now (the rollout's inputs).
    fn samples(&self) -> Vec<rollout::Sample> {
        let me = self.cluster.local_state();
        let mut v = vec![rollout::Sample {
            node: self.cluster.identity.meta.node_id.clone(),
            qps: me.qps,
            servfail_permille: me.servfail_permille,
            ready: me.ready,
            connected: true,
            applied_seq: self.last.seq,
            sync_error: None,
            probe_failing: me.probe_failing,
        }];
        v.extend(self.cluster.members().into_iter().map(|m| rollout::Sample {
            node: m.node_id,
            qps: m.qps,
            servfail_permille: m.servfail_permille,
            ready: m.ready,
            connected: m.connected,
            applied_seq: m.applied_seq,
            sync_error: (!m.sync_error.is_empty()).then_some(m.sync_error),
            probe_failing: m.probe_failing,
        }));
        v
    }

    /// Every few seconds: the guard's samples, its verdict on a version baking, and the status.
    async fn tick(&mut self, epoch: u64) {
        if self.last_guard.is_some_and(|t| t.elapsed() < GUARD_EVERY) {
            return;
        }
        self.last_guard = Some(std::time::Instant::now());
        let now = now_ms();
        let samples = self.samples();
        self.guard.observe(now, &samples);
        let rcfg = self.sources.config.load().cluster.rollout.clone();
        // REQ: CLU-013 — canaries set and none online: changes skip the bake (rollout_stuck).
        let spec: Vec<String> = rcfg.canaries.iter().map(ToString::to_string).collect();
        if spec.is_empty() || !self.canary_peers(&spec).is_empty() {
            self.canaries_offline_since = None;
        } else {
            self.canaries_offline_since.get_or_insert(now);
        }
        if let Some(a) = self.ro.active.clone() {
            let mut judged: BTreeSet<String> = a.canaries.iter().cloned().collect();
            judged.insert(self.cluster.identity.meta.node_id.clone());
            match self.guard.verdict(&a, &rcfg, now, &samples, &judged) {
                rollout::Verdict::Baking => {
                    let (answers, servfails) = self.guard.share(&judged, a.started_ms, now);
                    self.last_readings = Some(rollout::Readings {
                        before_pct: a.before_pct,
                        after_pct: (answers > 0.0).then(|| servfails / answers * 100.0),
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        answers: answers as u64,
                        reason: None,
                    });
                }
                rollout::Verdict::Pass(r) => {
                    let _ = self.promote(epoch, r, "the guard");
                }
                rollout::Verdict::Fail(r) => {
                    let reason = r
                        .reason
                        .clone()
                        .unwrap_or_else(|| "the guard failed".into());
                    warn!(seq = a.version.1, "cluster: rollout failed: {reason}");
                    self.cluster.event(
                        "rollout_failed",
                        &self.cluster.identity.meta.node_id,
                        format!("version {}: {reason}", a.version.1),
                    );
                    self.last_readings = Some(r.clone());
                    self.last_failure = Some(rollout::Failure {
                        version: a.version,
                        reason: reason.clone(),
                        at_ms: now,
                    });
                    self.count("failed");
                    let _ = self
                        .pin(
                            epoch,
                            a.stable,
                            "the guard",
                            &reason,
                            rollout::outcome::FAILED,
                            Some(r),
                        )
                        .await;
                }
            }
        }
        self.report(&rcfg, &samples);
    }

    /// The status the API shows.
    fn report(&self, rcfg: &telltale_config::RolloutConfig, samples: &[rollout::Sample]) {
        let spec: Vec<String> = rcfg.canaries.iter().map(ToString::to_string).collect();
        let registry = self.cluster.identity.registry();
        let members = self.cluster.members();
        let nodes = samples
            .iter()
            .map(|s| {
                let site = members.iter().find(|m| m.node_id == s.node).map_or_else(
                    || self.cluster.identity.meta.site.clone(),
                    |m| m.site.clone(),
                );
                let ephemeral = registry.iter().any(|r| r.node_id == s.node && r.ephemeral);
                rollout::NodeRow {
                    canary: self.ro.active.as_ref().map_or_else(
                        || rollout::is_canary(&spec, &s.node, &site, ephemeral),
                        |a| a.canaries.contains(&s.node),
                    ),
                    node: s.node.clone(),
                    site,
                    applied_seq: s.applied_seq,
                    ready: s.ready,
                    connected: s.connected,
                    servfail_permille: s.servfail_permille,
                }
            })
            .collect();
        self.sources.rollout.set_status(rollout::Status {
            primary: true,
            emergency: self.emergency,
            canaries: spec,
            bake_secs: rcfg.bake_secs,
            stable: self.stable,
            active: self.ro.active.clone(),
            readings: self.last_readings.clone(),
            pinned: self.ro.pinned.clone(),
            nodes,
            skipped: self.skipped.clone(),
            waiting_since_ms: self.waiting_since_ms,
            canaries_offline_since_ms: self.canaries_offline_since,
            last_failure: self.last_failure.clone(),
            counts: self.counts.clone(),
        });
    }

    fn count(&mut self, outcome: &str) {
        *self.counts.entry(outcome.to_owned()).or_default() += 1;
    }

    /// The canary version to everyone (the guard passed, or an operator said so).
    fn promote(&mut self, epoch: u64, readings: rollout::Readings, by: &str) -> rollout::Reply {
        let Some(active) = self.ro.active.clone() else {
            return Err((
                telltale_api::problem::Code::NoRollout,
                "no version is baking".into(),
            ));
        };
        let Some(canary) = self.canary.take() else {
            return Err((
                telltale_api::problem::Code::NoRollout,
                "the canary version is gone".into(),
            ));
        };
        // The same content as a new version for everyone, marked stable: versions never go
        // backwards, and no node keeps a manifest that says "canary" after the bake.
        let now = now_ms();
        let seq = self.last.seq + 1;
        let mut next = canary.manifest.clone();
        next.seq = seq;
        next.created_ms = now;
        next.rollout = None;
        let signed = match Signed::sign(&next, &canary.key) {
            Ok(s) => s,
            Err(e) => {
                self.canary = Some(canary);
                return Err((
                    telltale_api::problem::Code::Internal,
                    format!("signing: {e}"),
                ));
            }
        };
        if !self.cluster.publish_as(epoch, signed, canary.blobs) {
            return Err((
                telltale_api::problem::Code::Conflict,
                "this node isn't the primary of the epoch any more".into(),
            ));
        }
        self.versions.set_outcome(
            active.version,
            rollout::outcome::PROMOTED,
            Some(readings.clone()),
        );
        let mut entry = Self::entry(&next, rollout::outcome::STABLE);
        entry.by = format!("version {} promoted ({by})", active.version.1);
        self.versions.record(entry, usize::MAX);
        self.stable = (epoch, seq);
        self.stable_shared = canary.shared;
        self.ro.active = None;
        self.last_readings = Some(readings);
        self.last.seq = seq;
        self.last.created_ms = now;
        self.cluster.set_local(|l| {
            l.applied_seq = seq;
            l.canary_of = 0;
        });
        self.cluster.set_sync_status(|s| {
            s.seq = seq;
            s.created_ms = now;
            s.applied_ms = now;
        });
        self.count("promoted");
        self.cluster.event(
            "rollout_promoted",
            &self.cluster.identity.meta.node_id,
            format!("version {} to every node as {seq} ({by})", active.version.1),
        );
        info!(
            seq,
            canary = active.version.1,
            "cluster: rollout promoted ({by})"
        );
        self.persist(None);
        Ok(format!(
            "version {}.{} goes to every node (as {}.{seq})",
            active.version.0, active.version.1, epoch
        ))
    }

    /// REQ: CLU-013 — pins the cluster to `to`: a new version serving `to`'s content, on every
    /// node and on this one, until unpinned. A rollout in progress ends with `outcome`.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)] // check, build, publish, apply
    async fn pin(
        &mut self,
        epoch: u64,
        to: (u64, u64),
        by: &str,
        reason: &str,
        outcome: &str,
        readings: Option<rollout::Readings>,
    ) -> rollout::Reply {
        use telltale_api::problem::Code;
        if self.emergency {
            return Err((
                Code::Conflict,
                "an emergency primary doesn't publish new versions".into(),
            ));
        }
        let Some(entry) = self.versions.find(to).cloned() else {
            return Err((
                Code::VersionUnknown,
                format!("version {}.{} isn't among the kept versions", to.0, to.1),
            ));
        };
        let Some(store) = self.store.clone() else {
            return Err((Code::Internal, "the blob store isn't open".into()));
        };
        if let Some(b) = entry.blobs().iter().find(|b| !store.has(b)) {
            return Err((
                Code::VersionBlobsMissing,
                format!(
                    "version {}.{}'s file {} is no longer kept",
                    to.0, to.1, b.name
                ),
            ));
        }
        let Gather::Ready(mut g) = self.gather().await else {
            return Err((Code::Internal, "nothing to publish".into()));
        };
        let Ok(shared) = store.read(&entry.config) else {
            return Err((
                Code::VersionBlobsMissing,
                "the version's configuration is missing".into(),
            ));
        };
        g.config_hash.clone_from(&entry.config.hash);
        g.shared = shared;
        g.filter = entry
            .filter
            .as_ref()
            .and_then(|f| self.store_paths(f).map(|p| (f.clone(), p)));
        g.filter_version = entry.filter.as_ref().map(|f| f.version);
        let pin = PinInfo {
            to,
            since_ms: now_ms(),
            by: by.to_owned(),
            reason: reason.to_owned(),
        };
        let previous_pin = self.ro.pinned.replace(pin.clone());
        let seq = self.last.seq + 1;
        let (m, blobs) = self.build(&g, epoch, seq, self.last.base, None);
        let signed = match Signed::sign(&m, &g.key) {
            Ok(s) => s,
            Err(e) => {
                self.ro.pinned = previous_pin;
                return Err((Code::Internal, format!("signing: {e}")));
            }
        };
        if !self.cluster.publish_as(epoch, signed, blobs) {
            self.ro.pinned = previous_pin;
            return Err((
                Code::Conflict,
                "this node isn't the primary of the epoch any more".into(),
            ));
        }
        if let Some(a) = self.ro.active.take() {
            self.versions.set_outcome(a.version, outcome, readings);
        }
        self.canary = None;
        if let Ok(b) = serde_json::to_vec_pretty(&m) {
            let _ = write_atomic(&self.cdir.join(rollout::PINNED), &b);
        }
        self.versions
            .record(Self::entry(&m, rollout::outcome::PINNED_TO), usize::MAX);
        self.stable = (epoch, seq);
        self.stable_shared.clone_from(&g.shared);
        let now = now_ms();
        self.last = Published {
            epoch,
            seq,
            config: g.config_hash.clone(),
            filter: g.filter_version,
            created_ms: now,
            meta: g.meta_hash.clone(),
            base: self.last.base,
            identities: g.identities_hash.clone(),
            acks: g.acks_hash.clone(),
        };
        self.cluster.set_local(|l| {
            l.applied_seq = seq;
            l.canary_of = 0;
        });
        self.persist(None);
        self.cluster.event(
            "pinned",
            &self.cluster.identity.meta.node_id,
            format!("to version {}.{} by {by}: {reason}", to.0, to.1),
        );
        warn!(to = ?to, by, reason, "cluster: pinned");
        apply_pin_locally(&self.sources, &store, &m).await;
        Ok(format!(
            "pinned to version {}.{} (published as {seq})",
            to.0, to.1
        ))
    }

    /// REQ: CLU-013 — unpins: this node serves its own configuration again, and the next pass
    /// publishes it (through a rollout when canaries are set).
    async fn unpin(&mut self, by: &str) -> rollout::Reply {
        if self.ro.pinned.take().is_none() {
            return Err((
                telltale_api::problem::Code::Conflict,
                "the cluster isn't pinned".into(),
            ));
        }
        let _ = std::fs::remove_file(self.cdir.join(rollout::PINNED));
        let _ = self.ro.save(&self.cdir);
        self.force = true;
        self.cluster.event(
            "unpinned",
            &self.cluster.identity.meta.node_id,
            format!("by {by}"),
        );
        info!(by, "cluster: unpinned");
        unapply_pin_locally(&self.sources).await;
        Ok("unpinned: the current configuration is published again".to_owned())
    }

    /// The operators' commands queued since the last pass.
    async fn commands(&mut self, epoch: u64) {
        while let Some((cmd, reply)) = self.sources.rollout.next() {
            let what = match &cmd {
                rollout::Cmd::Promote { .. } => None,
                rollout::Cmd::Abort { .. } => Some("aborted"),
                rollout::Cmd::Pin { .. } => Some("pinned"),
                rollout::Cmd::Unpin { .. } => Some("unpinned"),
            };
            let r = match cmd {
                rollout::Cmd::Promote { by } => {
                    let r = self.last_readings.clone().unwrap_or_default();
                    self.promote(epoch, r, &format!("promoted by {by}"))
                }
                rollout::Cmd::Abort { by } => match self.ro.active.clone() {
                    Some(a) => {
                        self.pin(
                            epoch,
                            a.stable,
                            &by,
                            &format!("aborted by {by}"),
                            rollout::outcome::ABORTED,
                            self.last_readings.clone(),
                        )
                        .await
                    }
                    None => Err((
                        telltale_api::problem::Code::NoRollout,
                        "no version is baking".into(),
                    )),
                },
                rollout::Cmd::Pin { to, by, reason } => {
                    self.pin(epoch, to, &by, &reason, rollout::outcome::ABORTED, None)
                        .await
                }
                rollout::Cmd::Unpin { by } => self.unpin(&by).await,
            };
            if let (Ok(_), Some(w)) = (&r, what) {
                self.count(w);
            }
            // The status shows the outcome before the answer goes back.
            let rcfg = self.sources.config.load().cluster.rollout.clone();
            let samples = self.samples();
            self.report(&rcfg, &samples);
            let _ = reply.send(r);
        }
    }
}

/// REQ: CLU-013 — this node serves the pinned version: its snapshot (installed beside the
/// compiled ones, under `snapshots/pinned-<version>`, which no compile prunes) and, through
/// the reload, its configuration (`replication::effective` reads `pinned.json`).
async fn apply_pin_locally(sources: &Arc<Sources>, store: &BlobStore, m: &ClusterManifest) {
    let cfg = sources.config.load_full();
    if let Some(f) = &m.filter {
        let dir = data_dir(&cfg)
            .join("snapshots")
            .join(format!("pinned-{}", f.version));
        let installed = (|| -> Result<(), String> {
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            for b in &f.blobs {
                if !safe_name(&b.name) {
                    return Err(format!("unsafe blob name `{}`", b.name));
                }
                let src = store.path(&b.hash).ok_or("bad blob hash")?;
                let dst = dir.join(&b.name);
                if std::fs::hard_link(&src, &dst).is_err() {
                    std::fs::copy(&src, &dst).map_err(|e| e.to_string())?;
                }
            }
            Ok(())
        })();
        match installed {
            Ok(()) => {
                sources
                    .pipeline
                    .filter_pin
                    .store(Some(Arc::new(dir.clone())));
                Publisher::new(Arc::clone(&sources.pipeline)).publish(dir);
            }
            Err(e) => error!("cluster: can't install the pinned snapshot: {e}"),
        }
    }
    reload_now(sources).await;
}

/// Back to this node's own snapshot (the newest compiled) and configuration.
async fn unapply_pin_locally(sources: &Arc<Sources>) {
    let cfg = sources.config.load_full();
    let snapshots = data_dir(&cfg).join("snapshots");
    sources.pipeline.filter_pin.store(None);
    let newest = std::fs::read_dir(&snapshots)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let v = e.file_name().to_str()?.parse::<u64>().ok()?;
            e.path().join(MANIFEST).is_file().then(|| (v, e.path()))
        })
        .max_by_key(|(v, _)| *v);
    if let Some((_, dir)) = newest {
        Publisher::new(Arc::clone(&sources.pipeline)).publish(dir);
    }
    for e in std::fs::read_dir(&snapshots)
        .into_iter()
        .flatten()
        .flatten()
    {
        if e.file_name()
            .to_str()
            .is_some_and(|n| n.starts_with("pinned-"))
        {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
    reload_now(sources).await;
}

/// Reloads the configuration and waits for it (bounded).
async fn reload_now(sources: &Sources) {
    let (tx, rx) = oneshot::channel();
    if sources.reload.send(tx).await.is_ok() {
        let _ = tokio::time::timeout(Duration::from_secs(15), rx).await;
    }
}

/// Primary side (CLU-003, CLU-013): republishes whenever the shared configuration or the
/// snapshot changes, to the canary nodes first when `[cluster.rollout] canaries` names some
/// that are online, then to everyone once the guard passes. An emergency primary (ADR-048)
/// republishes the last authoritative version once, in its new epoch, and never changes it; a
/// pinned cluster publishes the pinned version's content until it's unpinned.
async fn publish_loop(
    cluster: Arc<Cluster>,
    sources: Arc<Sources>,
    mut stop: watch::Receiver<bool>,
    emergency: bool,
) {
    let Some(mut p) = Primary::open(Arc::clone(&cluster), Arc::clone(&sources), emergency) else {
        return;
    };
    // REQ: CLU-013 — a pinned primary serves the pinned version from the start.
    if let (Some(m), Some(store)) = (p.pinned_manifest(), p.store.clone()) {
        apply_pin_locally(&sources, &store, &m).await;
    }
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
        // ADR-051 — the role and epoch together: a node fenced since the check above must not
        // publish (least of all in the new primary's epoch); `publish_as` checks again.
        let (role, epoch) = cluster.role();
        if !cluster.may_publish()
            || git_waiting
            || !matches!(role, node::Role::Primary | node::Role::Emergency)
        {
            // REQ: CLU-013 — a node that stopped publishing doesn't report a rollout.
            if sources.rollout.status().primary {
                sources.rollout.set_status(rollout::Status::default());
            }
            tokio::select! {
                r = stop.changed() => if r.is_err() || *stop.borrow() { return; },
                () = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
            }
            continue;
        }
        p.commands(epoch).await;
        match p.gather().await {
            Gather::Ready(g) => p.publish(epoch, &g),
            Gather::Skip => {}
            Gather::Stop => return,
        }
        p.tick(epoch).await;
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
        // REQ: OPS-010 — heartbeats say whether it *serves* DNS: a node in maintenance does
        // (it only asks balancers to stop sending), and carries its window separately.
        let ready = sources.readiness.serving();
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
