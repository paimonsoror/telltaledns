//! A node's cluster identity on disk (REQ: CLU-001; `spec/12` §3), in `<data_dir>/cluster/`:
//! `cluster.json` (IDs, site, URLs), `node.key` + `node.crt` (its identity), `ca.crt`, and on
//! the node that created the cluster (or any node holding it) `ca.key` and `tokens.json`
//! (hashes of the join-token secrets, never the secrets). Keys are written owner-only.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use serde::{Deserialize, Serialize};

use crate::pki::{self, Ca};
use crate::token::{self, Token};

/// REQ: CLU-001 (ADR-155) — how many removed nodes the cluster remembers. A node certificate
/// lasts 90 days ([`pki::NODE_CERT_DAYS`]), so a list this long outlives every certificate it
/// names unless the cluster removes more than a few nodes a week.
pub const MAX_REMOVED: usize = 512;

/// `cluster.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub cluster_id: String,
    pub cluster_name: String,
    pub node_id: String,
    pub site: String,
    pub eligible: bool,
    /// This node's cluster URLs (what peers dial).
    pub advertise: Vec<String>,
    /// URLs of the primary (what this node dials; empty on the primary).
    pub primary_urls: Vec<String>,
    /// Highest epoch seen (CLU-005).
    pub epoch: u64,
    /// This node's role in `epoch` (ADR-051). Absent in files from before roles existed:
    /// [`Identity::load`] then derives it (the CA holder was the primary).
    #[serde(default)]
    pub role: Option<Role>,
    /// Where the cluster's configuration comes from (ADR-048): `api` or `gitops`.
    #[serde(default = "default_authority")]
    pub config_authority: String,
    /// A witness only votes in elections (ADR-056): never primary, serves no DNS.
    #[serde(default)]
    pub witness: bool,
    /// How the cluster fails over (ADR-056): `manual` or `auto` (from the primary's manifests).
    #[serde(default = "default_failover")]
    pub failover: String,
}

fn default_authority() -> String {
    "api".into()
}

fn default_failover() -> String {
    "manual".into()
}

/// A node's role (ADR-051).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Primary,
    Replica,
    /// Promoted while no authority-matching node was reachable (ADR-048): coordinates the
    /// cluster but publishes no new configuration.
    Emergency,
}

/// A member in the signed registry (ADR-051): what every node needs to know to find (and
/// promote) the others.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node_id: String,
    pub site: String,
    pub eligible: bool,
    pub advertise: Vec<String>,
    /// Unix seconds.
    pub joined: u64,
    /// Votes in elections only (ADR-056).
    #[serde(default)]
    pub witness: bool,
    /// A Kubernetes resolver pod (CLU-009): dropped when no longer heard from.
    #[serde(default)]
    pub ephemeral: bool,
}

impl NodeRecord {
    /// Whether it votes in automatic failover: eligible nodes and witnesses.
    pub fn voter(&self) -> bool {
        self.eligible || self.witness
    }
}

/// A stored join-token record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TokenRecord {
    hash: String,
    exp: u64,
    /// What a node joining with it may be (tokens from before this field: neither).
    #[serde(default)]
    eligible: bool,
    #[serde(default)]
    witness: bool,
}

/// REQ: CLU-001 (review 05 q1, ADR-051) — what a join token may bring besides a plain
/// member: an eligible node (which gets the cluster key) or a witness (which votes). A
/// leaked plain token then buys membership, not the key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TokenGrants {
    pub eligible: bool,
    pub witness: bool,
}

/// A join token's ID: the first 12 hex characters of its secret's hash. It names the token
/// in `telltale cluster token list` and `revoke` without revealing it.
pub fn token_id(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

/// What a joining node sends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub secret: String,
    pub csr_pem: String,
    pub advertise: Vec<String>,
    pub site: String,
    pub eligible: bool,
    pub version: String,
    /// Joins as a witness (ADR-056).
    #[serde(default)]
    pub witness: bool,
    /// Joins as an ephemeral member (CLU-009).
    #[serde(default)]
    pub ephemeral: bool,
}

/// What it gets back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinResponse {
    pub cluster_id: String,
    pub cluster_name: String,
    pub node_id: String,
    pub cert_pem: String,
    pub ca_pem: String,
    pub primary_urls: Vec<String>,
}

/// REQ: CLU-001, CLU-005 (ADR-177) — the file beside `ca.crt` that says which manifest this
/// node last took its trusted CAs from ([`TrustVersion`]).
const TRUST_MARK: &str = "ca.version";

/// REQ: CLU-001, CLU-005 (ADR-177) — the version of the manifest a trust step comes from. Trust
/// follows manifests in order: [`Identity::adopt_trust`] takes nothing from a manifest older
/// (epoch first, then seq) than the one it last took the CAs from, and keeps that version in
/// `ca.version`. A mark of another cluster is no mark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustVersion {
    pub cluster_id: String,
    pub epoch: u64,
    pub seq: u64,
}

impl TrustVersion {
    fn order(&self) -> (u64, u64) {
        (self.epoch, self.seq)
    }
}

/// What [`Identity::adopt_trust`] did with a manifest's CA bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStep {
    /// The bundle is this node's trust now (`ca.crt` was replaced).
    Changed,
    /// This node trusts that bundle already (or the bundle holds no certificate).
    Unchanged,
    /// The manifest is older than the one this node last took its CAs from: nothing changed.
    Older,
}

/// A node's loaded identity.
#[derive(Debug, Clone)]
pub struct Identity {
    pub dir: PathBuf,
    pub meta: Meta,
    pub key_pem: String,
    pub cert_pem: String,
    pub ca_pem: String,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Writes `data` to `path` atomically; owner-only when `secret`.
pub(crate) fn write(path: &Path, data: &[u8], secret: bool) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    // A name per write: two streams can store the same thing at once (a key share arrives on
    // both directions of a link).
    static N: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    // Secrets are owner-only from the first byte.
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let result = opts.open(&tmp).and_then(|mut f| f.write_all(data));
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, path)
}

/// REQ: CLU-001, CLU-005 (ADR-066) — the lock for the CA key files of the cluster directory
/// `dir` (`ca.key`, `ca-next.key`, `ca-pending.key`, `ca-old.key`). A replica changes them from
/// two tasks, the key-share handler ([`Identity::store_ca_key`]) and the manifest trust path
/// ([`Identity::adopt_trust`]), and both look at a file before they change it. Each holds this
/// lock for its whole run, so one never sees the other half done. It is per directory, and kept
/// here and not in [`Identity`] because every `reload()` returns a new value (a lock on the
/// struct wouldn't be shared by the two callers).
pub(crate) fn key_files_lock(dir: &Path) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    let mut locks = LOCKS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    Arc::clone(locks.entry(dir.to_owned()).or_default())
}

#[cfg(test)]
thread_local! {
    /// A test seam: what to run inside [`Identity::adopt_trust`] on this thread, after the key
    /// files moved and before the new bundle is written (the window a key share could slip into).
    static AFTER_KEY_MOVES: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn after_key_moves() {
    AFTER_KEY_MOVES.with(|h| {
        if let Some(f) = h.borrow_mut().as_mut() {
            f();
        }
    });
}

/// The host part of each URL (`https://pi.lan:8443` → `pi.lan`), for certificate names.
pub fn hosts(urls: &[String]) -> Vec<String> {
    urls.iter()
        .filter_map(|u| {
            let rest = u.split_once("://").map_or(u.as_str(), |(_, r)| r);
            let authority = rest.split('/').next()?;
            let host = if let Some(v6) = authority.strip_prefix('[') {
                v6.split(']').next()?
            } else {
                authority.rsplit_once(':').map_or(authority, |(h, _)| h)
            };
            (!host.is_empty()).then(|| host.to_owned())
        })
        .collect()
}

pub fn dir_of(data_dir: &Path) -> PathBuf {
    data_dir.join("cluster")
}

impl Identity {
    /// The identity under `data_dir`, if this node is in a cluster.
    pub fn load(data_dir: &Path) -> Result<Option<Self>, String> {
        let dir = dir_of(data_dir);
        let meta_path = dir.join("cluster.json");
        if !meta_path.exists() {
            return Ok(None);
        }
        let read = |n: &str| {
            std::fs::read_to_string(dir.join(n))
                .map_err(|e| format!("{}: {e}", dir.join(n).display()))
        };
        let mut meta: Meta = serde_json::from_str(&read("cluster.json")?)
            .map_err(|e| format!("cluster.json: {e}"))?;
        if meta.role.is_none() {
            meta.role = Some(
                if dir.join("ca.key").exists() && meta.primary_urls.is_empty() {
                    Role::Primary
                } else {
                    Role::Replica
                },
            );
        }
        Ok(Some(Self {
            key_pem: read("node.key")?,
            cert_pem: read("node.crt")?,
            ca_pem: read("ca.crt")?,
            dir,
            meta,
        }))
    }

    /// Whether this node holds the CA key (can issue certificates and sign manifests).
    pub fn holds_ca(&self) -> bool {
        self.dir.join("ca.key").exists()
    }

    /// Whether this node is the primary of the epoch in its `cluster.json` (ADR-051).
    pub fn is_primary(&self) -> bool {
        matches!(self.meta.role, Some(Role::Primary | Role::Emergency))
    }

    /// The member registry this node keeps (the primary's `nodes.json`), this node included.
    pub fn registry(&self) -> Vec<NodeRecord> {
        let mut v: Vec<NodeRecord> = std::fs::read(self.dir.join("nodes.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        if !v.iter().any(|n| n.node_id == self.meta.node_id) {
            v.insert(
                0,
                NodeRecord {
                    node_id: self.meta.node_id.clone(),
                    site: self.meta.site.clone(),
                    eligible: self.meta.eligible,
                    advertise: self.meta.advertise.clone(),
                    joined: 0,
                    witness: self.meta.witness,
                    ephemeral: false,
                },
            );
        }
        v
    }

    /// Replaces the registry (a promoted node takes over the one it last received).
    pub fn save_registry(&self, nodes: &[NodeRecord]) -> Result<(), String> {
        let b = serde_json::to_vec_pretty(nodes).map_err(|e| e.to_string())?;
        write(&self.dir.join("nodes.json"), &b, false).map_err(|e| e.to_string())
    }

    /// REQ: CLU-001 (ADR-155, GitHub issue #5) — the IDs of nodes removed from the cluster, oldest
    /// first. Their certificates are still valid until they expire, but no node accepts a stream
    /// from them. The primary adds to the list ([`Self::add_removed`]); every other node keeps
    /// what the manifest carries ([`Self::save_removed`]).
    pub fn removed(&self) -> Vec<String> {
        std::fs::read(self.dir.join("removed.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Replaces the list of removed nodes (what the primary's manifest carries).
    pub fn save_removed(&self, ids: &[String]) -> Result<(), String> {
        let b = serde_json::to_vec_pretty(ids).map_err(|e| e.to_string())?;
        write(&self.dir.join("removed.json"), &b, false).map_err(|e| e.to_string())
    }

    /// Adds `node_id` to the removed nodes (the oldest entries go once there are
    /// [`MAX_REMOVED`]).
    pub fn add_removed(&self, node_id: &str) -> Result<(), String> {
        let mut ids = self.removed();
        if ids.iter().any(|n| n == node_id) {
            return Ok(());
        }
        ids.push(node_id.to_owned());
        if ids.len() > MAX_REMOVED {
            ids.drain(..ids.len() - MAX_REMOVED);
        }
        self.save_removed(&ids)
    }

    /// Stores the CA key received from the primary (eligible nodes, ADR-051), after checking it
    /// belongs to this cluster's CA certificate: the signing CA's key as `ca.key`, and during a
    /// rotation the other CA's as `ca-next.key` (T5.4c).
    pub fn store_ca_key(&self, key_pem: &str) -> Result<bool, String> {
        let public = crate::sync::public_of(key_pem)?;
        // REQ: CLU-001, CLU-005 — not while a trust change moves the key files (see
        // `key_files_lock`): the check below and the write after it must see one state.
        let lock = key_files_lock(&self.dir);
        let _held = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let cas = pki::certs_of(&self.reload().ca_pem);
        let Some(pos) = cas
            .iter()
            .position(|c| crate::sync::ca_public_key(c).is_ok_and(|k| k == public))
        else {
            // A rotation's next key can arrive before the manifest that adds its CA: hold it
            // until a verified bundle includes it (`adopt_trust`). It came from the primary
            // over the authenticated channel, and is used only once its CA is trusted.
            write(&self.dir.join("ca-pending.key"), key_pem.as_bytes(), true)
                .map_err(|e| e.to_string())?;
            return Ok(false);
        };
        let file = if pos == 0 { "ca.key" } else { "ca-next.key" };
        let path = self.dir.join(file);
        if path.exists()
            && std::fs::read_to_string(&path)
                .ok()
                .and_then(|k| crate::sync::public_of(&k).ok())
                .is_some_and(|k| k == public)
        {
            return Ok(false);
        }
        write(&path, key_pem.as_bytes(), true).map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Replaces the trusted CAs (`ca.crt`) with `bundle` from a verified manifest of version
    /// `at` (T5.4c). The new bundle must keep a CA this node trusts now, so trust only ever moves
    /// step by step. When a CA held as `ca-next.key` becomes the signing one, its key becomes
    /// `ca.key`.
    ///
    /// REQ: CLU-001, CLU-005 (ADR-177) — and trust only moves forward: a manifest older than the
    /// one this node last took its CAs from changes nothing ([`TrustStep::Older`]). The same
    /// version is taken again (sent again, it finishes a step a crash cut short). The version is
    /// recorded in `ca.version` after `ca.crt`, also when the bundle doesn't change, so a node
    /// with no mark (upgraded from a build without one) or with one a crash left behind has the
    /// current one after its next manifest.
    pub fn adopt_trust(&self, bundle: &str, at: &TrustVersion) -> Result<TrustStep, String> {
        // REQ: CLU-001, CLU-005 — one change of the key files at a time (see `key_files_lock`).
        // The mark is read and written under the same lock.
        let lock = key_files_lock(&self.dir);
        let _held = lock.lock().unwrap_or_else(PoisonError::into_inner);
        // REQ: CLU-001 (ADR-177) — a mark another cluster left in this directory is no mark.
        let mark = self.trust_mark().filter(|m| m.cluster_id == at.cluster_id);
        if mark.as_ref().is_some_and(|m| at.order() < m.order()) {
            return Ok(TrustStep::Older);
        }
        let moves_on = mark.as_ref().is_none_or(|m| at.order() > m.order());
        let me = self.reload();
        let new = pki::certs_of(bundle);
        if new.is_empty() {
            return Ok(TrustStep::Unchanged);
        }
        if bundle.trim() == me.ca_pem.trim() {
            if moves_on {
                self.save_trust_mark(at);
            }
            return Ok(TrustStep::Unchanged);
        }
        let old: Vec<[u8; 32]> = pki::certs_of(&me.ca_pem)
            .iter()
            .filter_map(|c| pki::fingerprint(c).ok())
            .collect();
        if !new
            .iter()
            .any(|c| pki::fingerprint(c).is_ok_and(|f| old.contains(&f)))
        {
            return Err("the new CA bundle shares no CA with this node's trust".into());
        }
        let signer = crate::sync::ca_public_key(&new[0])?;
        let next = self.dir.join("ca-next.key");
        // A key received before its CA was trusted (see `store_ca_key`).
        let pending = self.dir.join("ca-pending.key");
        if let Some(k) = std::fs::read_to_string(&pending)
            .ok()
            .and_then(|k| crate::sync::public_of(&k).ok())
            && new
                .iter()
                .skip(1)
                .any(|c| crate::sync::ca_public_key(c).is_ok_and(|x| x == k))
        {
            std::fs::rename(&pending, &next).map_err(|e| e.to_string())?;
        }
        let held = |p: &Path| {
            std::fs::read_to_string(p)
                .ok()
                .and_then(|k| crate::sync::public_of(&k).ok())
        };
        // The signing CA changed to the one whose key this node received ahead of time.
        if held(&next).is_some_and(|k| k == signer) {
            let cur = self.dir.join("ca.key");
            if held(&cur).is_some_and(|k| k == signer) {
                // REQ: CLU-001, CLU-005 — `ca.key` already is the signing CA's key, so `next`
                // is a second copy of it (a key share stored it after an earlier switch moved
                // it). Rotating `ca.key` into `ca-old.key` would keep that key as the "old"
                // one for good: its CA stays trusted, so nothing would ever remove it.
                let _ = std::fs::remove_file(&next);
            } else {
                if cur.exists() {
                    let _ = std::fs::rename(&cur, self.dir.join("ca-old.key"));
                }
                std::fs::rename(&next, &cur).map_err(|e| e.to_string())?;
            }
        }
        // A CA key whose certificate left the bundle is no longer needed, and neither is a
        // second copy of the signing key (REQ: CLU-001, CLU-005: a key share that raced an
        // earlier step can leave one; the lock above stops new ones, this repairs a leftover).
        let signing = held(&self.dir.join("ca.key"));
        for f in ["ca-old.key", "ca-next.key", "ca-pending.key"] {
            let p = self.dir.join(f);
            if let Some(k) = held(&p)
                && (signing.as_ref() == Some(&k)
                    || !new
                        .iter()
                        .any(|c| crate::sync::ca_public_key(c).is_ok_and(|x| x == k)))
            {
                let _ = std::fs::remove_file(&p);
            }
        }
        #[cfg(test)]
        after_key_moves();
        write(&self.dir.join("ca.crt"), new.concat().as_bytes(), false)
            .map_err(|e| e.to_string())?;
        if moves_on {
            self.save_trust_mark(at);
        }
        Ok(TrustStep::Changed)
    }

    /// REQ: CLU-001, CLU-005 (ADR-177) — the version of the manifest this node last took its
    /// trusted CAs from (`ca.version`), if it has one. An unreadable file is no mark.
    pub fn trust_mark(&self) -> Option<TrustVersion> {
        std::fs::read(self.dir.join(TRUST_MARK))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    }

    /// Records `at` as the version this node last took its CAs from. Best effort: a mark that
    /// can't be written is as if absent (order is enforced again from the next one written),
    /// which never stops trust from moving.
    fn save_trust_mark(&self, at: &TrustVersion) {
        if let Ok(b) = serde_json::to_vec(at) {
            let _ = write(&self.dir.join(TRUST_MARK), &b, false);
        }
    }

    /// Whether this node holds the key of the CA that signs now (the bundle's first): after a
    /// CA rotation switches, a node that missed the new key must not sign with the old one.
    pub fn signs_now(&self) -> bool {
        let Ok(key) = std::fs::read_to_string(self.dir.join("ca.key")) else {
            return false;
        };
        let signer = pki::certs_of(&self.ca_pem).into_iter().next();
        match (
            crate::sync::public_of(&key),
            signer.map(|c| crate::sync::ca_public_key(&c)),
        ) {
            (Ok(k), Some(Ok(s))) => k == s,
            _ => false,
        }
    }

    /// The next CA's key during a rotation, on nodes holding it (T5.4c).
    pub fn next_ca_key_pem(&self) -> Option<String> {
        std::fs::read_to_string(self.dir.join("ca-next.key")).ok()
    }

    /// This identity as it is on disk now (another task may have updated `cluster.json`).
    #[must_use]
    pub fn reload(&self) -> Self {
        self.dir
            .parent()
            .and_then(|d| Self::load(d).ok().flatten())
            .unwrap_or_else(|| self.clone())
    }

    /// Records the cluster's config authority (from the primary's manifests).
    pub fn save_authority(&self, authority: &str) -> Result<(), String> {
        let mut id = self.reload();
        if id.meta.config_authority == authority {
            return Ok(());
        }
        authority.clone_into(&mut id.meta.config_authority);
        let b = serde_json::to_string_pretty(&id.meta).map_err(|e| e.to_string())?;
        write(&id.dir.join("cluster.json"), b.as_bytes(), false).map_err(|e| e.to_string())
    }

    /// Records how the cluster fails over (`manual` or `auto`, ADR-056).
    pub fn save_failover(&self, mode: &str) -> Result<(), String> {
        if !matches!(mode, "manual" | "auto") {
            return Err(format!("failover must be `manual` or `auto`, not `{mode}`"));
        }
        let mut id = self.reload();
        if id.meta.failover == mode {
            return Ok(());
        }
        mode.clone_into(&mut id.meta.failover);
        let b = serde_json::to_string_pretty(&id.meta).map_err(|e| e.to_string())?;
        write(&id.dir.join("cluster.json"), b.as_bytes(), false).map_err(|e| e.to_string())
    }

    /// Marks this node a witness (right after joining as one).
    pub fn mark_witness(&mut self) -> Result<(), String> {
        self.meta.witness = true;
        self.meta.eligible = false;
        let b = serde_json::to_string_pretty(&self.meta).map_err(|e| e.to_string())?;
        write(&self.dir.join("cluster.json"), b.as_bytes(), false).map_err(|e| e.to_string())
    }

    /// This node's election ballot (ADR-056): what it voted, and the lease it granted.
    pub fn ballot(&self) -> crate::election::Ballot {
        std::fs::read(self.dir.join("ballot.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Stores the ballot durably before any vote is answered (a vote must survive a crash).
    pub fn save_ballot(&self, b: &crate::election::Ballot) -> Result<(), String> {
        let bytes = serde_json::to_vec(b).map_err(|e| e.to_string())?;
        let path = self.dir.join("ballot.json");
        let tmp = path.with_extension("tmp");
        let e = |e: std::io::Error| e.to_string();
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&tmp).map_err(e)?;
            f.write_all(&bytes).map_err(e)?;
            f.sync_all().map_err(e)?;
        }
        std::fs::rename(&tmp, &path).map_err(e)
    }

    /// Persists a new role and epoch (promotion or fencing).
    pub fn save_role(&mut self, role: Role, epoch: u64) -> Result<(), String> {
        self.meta.role = Some(role);
        self.meta.epoch = epoch;
        let b = serde_json::to_string_pretty(&self.meta).map_err(|e| e.to_string())?;
        write(&self.dir.join("cluster.json"), b.as_bytes(), false).map_err(|e| e.to_string())
    }

    /// Signs a node's CSR with the cluster key (renewal, T5.4c): `(node_id, cert_pem)`.
    pub fn issue_for(&self, csr_pem: &str, hosts: &[String]) -> Result<(String, String), String> {
        let ca = self.ca()?;
        pki::issue(&ca, csr_pem, hosts).map_err(|e| e.to_string())
    }

    /// Replaces this node's certificate (same key) after renewal.
    pub fn save_cert(&self, cert_pem: &str) -> Result<(), String> {
        write(&self.dir.join("node.crt"), cert_pem.as_bytes(), false).map_err(|e| e.to_string())
    }

    /// The CA key (primary only), for signing manifests (CLU-003).
    pub fn ca_key_pem(&self) -> Result<String, String> {
        self.ca().map(|c| c.key_pem)
    }

    fn ca(&self) -> Result<Ca, String> {
        // The signing CA is the first of the bundle; `ca.key` is its key.
        let first = pki::certs_of(&self.ca_pem)
            .into_iter()
            .next()
            .unwrap_or_else(|| self.ca_pem.clone());
        Ok(Ca {
            cert_pem: first,
            key_pem: std::fs::read_to_string(self.dir.join("ca.key")).map_err(|_| {
                "this node doesn't hold the cluster CA (run this on the primary)".to_owned()
            })?,
        })
    }

    /// Creates a cluster with this node as its first member and primary.
    pub fn init(
        data_dir: &Path,
        name: &str,
        advertise: Vec<String>,
        site: &str,
    ) -> Result<Self, String> {
        Self::init_with(data_dir, name, advertise, site, "api")
    }

    /// [`Self::init`] with the cluster's config authority (`api` or `gitops`, ADR-048).
    pub fn init_with(
        data_dir: &Path,
        name: &str,
        advertise: Vec<String>,
        site: &str,
        config_authority: &str,
    ) -> Result<Self, String> {
        if !matches!(config_authority, "api" | "gitops") {
            return Err(format!(
                "config authority must be `api` or `gitops`, not `{config_authority}`"
            ));
        }
        let dir = dir_of(data_dir);
        if dir.join("cluster.json").exists() {
            return Err(format!(
                "this node is already in a cluster ({})",
                dir.display()
            ));
        }
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let ca = pki::new_ca(name).map_err(|e| e.to_string())?;
        let key = pki::new_node_key().map_err(|e| e.to_string())?;
        let (node_id, cert) =
            pki::issue(&ca, &key.csr_pem, &hosts(&advertise)).map_err(|e| e.to_string())?;
        let meta = Meta {
            cluster_id: pki::hex(&pki::fingerprint(&ca.cert_pem).map_err(|e| e.to_string())?[..8]),
            cluster_name: name.to_owned(),
            node_id,
            site: site.to_owned(),
            eligible: true,
            advertise,
            primary_urls: Vec::new(),
            epoch: 1,
            role: Some(Role::Primary),
            config_authority: config_authority.to_owned(),
            witness: false,
            failover: default_failover(),
        };
        let e = |e: std::io::Error| e.to_string();
        // REQ: CLU-001 (ADR-177) — a trust mark left here belongs to an identity before this one.
        let _ = std::fs::remove_file(dir.join(TRUST_MARK));
        write(&dir.join("ca.key"), ca.key_pem.as_bytes(), true).map_err(e)?;
        write(&dir.join("ca.crt"), ca.cert_pem.as_bytes(), false).map_err(e)?;
        write(&dir.join("node.key"), key.key_pem.as_bytes(), true).map_err(e)?;
        write(&dir.join("node.crt"), cert.as_bytes(), false).map_err(e)?;
        write(&dir.join("tokens.json"), b"[]", true).map_err(e)?;
        write(
            &dir.join("cluster.json"),
            serde_json::to_string_pretty(&meta)
                .unwrap_or_default()
                .as_bytes(),
            false,
        )
        .map_err(e)?;
        Self::load(data_dir)?.ok_or_else(|| "cluster state vanished".to_owned())
    }

    fn token_records(&self) -> Vec<TokenRecord> {
        std::fs::read(self.dir.join("tokens.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// REQ: CLU-001 (review 05-07) — the join tokens still valid: each one's ID (the start
    /// of its secret's hash, [`token_id`]) and when it expires (Unix seconds), soonest first.
    pub fn tokens(&self) -> Vec<(String, u64, TokenGrants)> {
        let t = now();
        let mut v: Vec<(String, u64, TokenGrants)> = self
            .token_records()
            .into_iter()
            .filter(|r| r.exp > t)
            .map(|r| {
                let grants = TokenGrants {
                    eligible: r.eligible,
                    witness: r.witness,
                };
                (token_id(&r.hash).to_owned(), r.exp, grants)
            })
            .collect();
        v.sort_by_key(|(_, exp, _)| *exp);
        v
    }

    /// REQ: CLU-001 (review 05-07) — revokes the join tokens whose secret hash starts with
    /// `id` (a token's ID from [`Self::tokens`], at least 8 characters, or a whole hash);
    /// returns how many. Nodes that already joined keep their membership.
    pub fn revoke_token(&self, id: &str) -> Result<usize, String> {
        let id = id.trim().to_ascii_lowercase();
        if id.len() < 8 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("give a token's ID (at least 8 hex characters; `telltale cluster token list` shows them)".into());
        }
        let mut recs = self.token_records();
        let before = recs.len();
        recs.retain(|r| !r.hash.starts_with(&id));
        let removed = before - recs.len();
        if removed > 0 {
            write(
                &self.dir.join("tokens.json"),
                serde_json::to_string(&recs).unwrap_or_default().as_bytes(),
                true,
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(removed)
    }

    /// A join token valid for `ttl_s` for a plain member, listing `urls` (default: this
    /// node's advertise URLs).
    pub fn create_token(&self, ttl_s: u64, urls: Option<Vec<String>>) -> Result<Token, String> {
        self.create_token_for(ttl_s, urls, TokenGrants::default())
    }

    /// A join token that may also bring what `grants` allows (an eligible node, a witness).
    pub fn create_token_for(
        &self,
        ttl_s: u64,
        urls: Option<Vec<String>>,
        grants: TokenGrants,
    ) -> Result<Token, String> {
        let _ = self.ca()?;
        let urls = urls.unwrap_or_else(|| self.meta.advertise.clone());
        if urls.is_empty() {
            return Err(
                "no cluster URLs to put in the token: init with --advertise, or pass --url".into(),
            );
        }
        let secret = token::new_secret();
        let exp = now() + ttl_s;
        let path = self.dir.join("tokens.json");
        let mut recs: Vec<TokenRecord> = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let t = now();
        recs.retain(|r| r.exp > t);
        recs.push(TokenRecord {
            hash: Token::secret_hash(&secret),
            exp,
            eligible: grants.eligible,
            witness: grants.witness,
        });
        write(
            &path,
            serde_json::to_string(&recs).unwrap_or_default().as_bytes(),
            true,
        )
        .map_err(|e| e.to_string())?;
        Ok(Token {
            v: 1,
            cluster_id: self.meta.cluster_id.clone(),
            cluster_name: self.meta.cluster_name.clone(),
            ca_fp: pki::hex(&pki::fingerprint(&self.ca_pem).map_err(|e| e.to_string())?),
            urls,
            secret,
            exp,
        })
    }

    /// Checks a join request's secret against the stored tokens (constant time over the
    /// hash) and issues the node's certificate.
    pub fn accept_join(
        &self,
        req: &JoinRequest,
        bootstrap: Option<&str>,
    ) -> Result<JoinResponse, String> {
        let ca = self.ca()?;
        let recs: Vec<TokenRecord> = std::fs::read(self.dir.join("tokens.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let h = Token::secret_hash(&req.secret);
        let t = now();
        let token = recs
            .iter()
            .find(|r| r.exp > t && same(r.hash.as_bytes(), h.as_bytes()));
        let by_token = token.is_some();
        // REQ: CLU-009 — the shared bootstrap secret works like a token that never expires.
        let by_bootstrap = !by_token
            && bootstrap
                .is_some_and(|b| !b.is_empty() && same(b.as_bytes(), req.secret.as_bytes()));
        if !by_token && !by_bootstrap {
            return Err("the join token is unknown or expired".into());
        }
        // REQ: CLU-001, CLU-009 (ADR-051, ADR-058) — standing is decided here, not claimed.
        // The bootstrap secret is in every resolver pod, so a join with it is an ephemeral
        // member whatever it asks for: eligibility (and with it the cluster key) and a
        // witness's vote come only with a join token.
        let ephemeral = req.ephemeral || by_bootstrap;
        // REQ: CLU-001 (review 05 q1) — and the token says whether it may bring an eligible
        // node or a witness; a plain token brings a plain member.
        if let Some(r) = token.filter(|_| !ephemeral) {
            if req.eligible && !req.witness && !r.eligible {
                return Err("this join token can't bring an eligible node: create one with `telltale cluster token create --eligible`".into());
            }
            if req.witness && !r.witness {
                return Err("this join token can't bring a witness: create one with `telltale cluster token create --witness`".into());
            }
        }
        let (node_id, cert_pem) =
            pki::issue(&ca, &req.csr_pem, &hosts(&req.advertise)).map_err(|e| e.to_string())?;
        let mut nodes = self.registry();
        nodes.retain(|n| n.node_id != node_id);
        nodes.push(NodeRecord {
            node_id: node_id.clone(),
            site: req.site.clone(),
            eligible: req.eligible && !req.witness && !ephemeral,
            advertise: req.advertise.clone(),
            joined: t,
            witness: req.witness && !ephemeral,
            ephemeral,
        });
        self.save_registry(&nodes)?;
        let mut primary_urls = self.meta.advertise.clone();
        primary_urls.extend(self.meta.primary_urls.iter().cloned());
        Ok(JoinResponse {
            cluster_id: self.meta.cluster_id.clone(),
            cluster_name: self.meta.cluster_name.clone(),
            node_id,
            cert_pem,
            ca_pem: self.ca_pem.clone(),
            primary_urls,
        })
    }

    /// Stores what a successful join returned.
    pub fn save_joined(
        data_dir: &Path,
        key_pem: &str,
        r: &JoinResponse,
        site: &str,
        eligible: bool,
        advertise: Vec<String>,
    ) -> Result<Self, String> {
        let dir = dir_of(data_dir);
        if dir.join("cluster.json").exists() {
            return Err(format!(
                "this node is already in a cluster ({})",
                dir.display()
            ));
        }
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let meta = Meta {
            cluster_id: r.cluster_id.clone(),
            cluster_name: r.cluster_name.clone(),
            node_id: r.node_id.clone(),
            site: site.to_owned(),
            eligible,
            advertise,
            primary_urls: r.primary_urls.clone(),
            epoch: 1,
            role: Some(Role::Replica),
            config_authority: default_authority(),
            witness: false,
            failover: default_failover(),
        };
        let e = |e: std::io::Error| e.to_string();
        // REQ: CLU-001 (ADR-177) — a trust mark left here belongs to an identity before this one.
        let _ = std::fs::remove_file(dir.join(TRUST_MARK));
        write(&dir.join("ca.crt"), r.ca_pem.as_bytes(), false).map_err(e)?;
        write(&dir.join("node.key"), key_pem.as_bytes(), true).map_err(e)?;
        write(&dir.join("node.crt"), r.cert_pem.as_bytes(), false).map_err(e)?;
        write(
            &dir.join("cluster.json"),
            serde_json::to_string_pretty(&meta)
                .unwrap_or_default()
                .as_bytes(),
            false,
        )
        .map_err(e)?;
        Self::load(data_dir)?.ok_or_else(|| "cluster state vanished".to_owned())
    }
}

/// Compares secrets in time independent of where they differ.
pub(crate) fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
#[allow(clippy::many_single_char_names)]
mod tests {
    use super::*;

    #[test]
    fn clu_001_init_token_and_join_on_disk() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let p = Identity::init(
            a.path(),
            "home",
            vec!["https://192.168.3.2:8443".into()],
            "home-pi",
        )
        .unwrap();
        assert!(p.holds_ca());
        assert!(
            Identity::init(a.path(), "home", vec![], "x").is_err(),
            "only once"
        );
        let t = p
            .create_token_for(
                3600,
                None,
                TokenGrants {
                    eligible: true,
                    witness: false,
                },
            )
            .unwrap();
        assert_eq!(t.urls, ["https://192.168.3.2:8443"]);
        let key = pki::new_node_key().unwrap();
        let mut req = JoinRequest {
            witness: false,
            ephemeral: false,
            secret: t.secret.clone(),
            csr_pem: key.csr_pem.clone(),
            advertise: vec!["https://10.0.0.5:8443".into()],
            site: "k8s".into(),
            eligible: true,
            version: "0.1.0".into(),
        };
        let resp = p.accept_join(&req, None).unwrap();
        assert_eq!(resp.primary_urls, ["https://192.168.3.2:8443"]);
        let r = Identity::save_joined(
            b.path(),
            &key.key_pem,
            &resp,
            "k8s",
            true,
            req.advertise.clone(),
        )
        .unwrap();
        assert!(!r.holds_ca());
        assert_eq!(r.meta.cluster_id, p.meta.cluster_id);
        assert_ne!(r.meta.node_id, p.meta.node_id);
        assert!(
            r.create_token(60, None).is_err(),
            "replicas don't hold the CA"
        );
        // A wrong secret is refused.
        req.secret = token::new_secret();
        assert!(p.accept_join(&req, None).is_err());
        // Keys are owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(a.path().join("cluster/ca.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
    }

    // REQ: CLU-001 (ADR-177) — a new identity (created, or joined) starts without a trust mark:
    // one left in the directory by an identity before it belongs to that one.
    #[test]
    fn clu_001_a_new_identity_starts_without_a_trust_mark() {
        let stale = br#"{"cluster_id":"0123456789abcdef","epoch":9,"seq":999}"#;
        let a = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir_of(a.path())).unwrap();
        std::fs::write(dir_of(a.path()).join("ca.version"), stale).unwrap();
        let p = Identity::init(a.path(), "home", vec!["https://p:8443".into()], "x").unwrap();
        assert!(
            !p.dir.join("ca.version").exists(),
            "init kept another identity's mark"
        );
        let t = p
            .create_token_for(60, None, TokenGrants::default())
            .unwrap();
        let key = pki::new_node_key().unwrap();
        let resp = p
            .accept_join(
                &JoinRequest {
                    witness: false,
                    ephemeral: false,
                    secret: t.secret,
                    csr_pem: key.csr_pem,
                    advertise: vec![],
                    site: "r".into(),
                    eligible: false,
                    version: "0.1.0".into(),
                },
                None,
            )
            .unwrap();
        let b = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir_of(b.path())).unwrap();
        std::fs::write(dir_of(b.path()).join("ca.version"), stale).unwrap();
        let r = Identity::save_joined(b.path(), &key.key_pem, &resp, "r", false, vec![]).unwrap();
        assert!(
            !r.dir.join("ca.version").exists(),
            "join kept another identity's mark"
        );
    }

    #[test]
    fn clu_001_hosts_from_urls() {
        assert_eq!(
            hosts(&[
                "https://pi.lan:8443".into(),
                "https://[fd00::1]:8443/x".into(),
                "10.0.0.1:8443".into()
            ]),
            ["pi.lan", "fd00::1", "10.0.0.1"]
        );
    }
}

/// REQ: CLU-001, CLU-005 (T5.4c, ADR-066) — a replica's CA key files (`ca.key`, `ca-next.key`,
/// `ca-pending.key`, `ca-old.key`) are changed by two tasks: the key-share handler
/// ([`Identity::store_ca_key`]) and the manifest trust path ([`Identity::adopt_trust`]). They
/// must not interleave, and a stray copy of the signing key must not outlive a step.
#[cfg(test)]
mod rotation_race_tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::{Barrier, mpsc};
    use std::thread::JoinHandle;
    use std::time::Duration;

    /// A replica being rotated: its own CA `old` (`Identity::init` makes the files a replica
    /// that holds the key would have), and the `new` CA a rotation adds.
    struct Replica {
        _dir: tempfile::TempDir,
        id: Identity,
        old_cert: String,
        new: Ca,
    }

    impl Replica {
        /// The bundle of the trust phase: the old CA signs, the new one is trusted.
        fn trusting(&self) -> String {
            format!("{}{}", self.old_cert, self.new.cert_pem)
        }
        /// The bundle of the switch phase: the new CA signs, the old one is still trusted.
        fn switched(&self) -> String {
            format!("{}{}", self.new.cert_pem, self.old_cert)
        }
        fn has(&self, file: &str) -> bool {
            self.id.dir.join(file).exists()
        }
        /// The public key of a key file in the cluster directory.
        fn key(&self, file: &str) -> Option<Vec<u8>> {
            std::fs::read_to_string(self.id.dir.join(file))
                .ok()
                .and_then(|k| crate::sync::public_of(&k).ok())
        }
        fn new_key(&self) -> Vec<u8> {
            crate::sync::public_of(&self.new.key_pem).unwrap()
        }
        /// Takes `bundle` as from the rotation's manifest number `step` (ADR-177's version):
        /// 1 the trust phase, 2 the switch, 3 the retire. Returns whether trust changed.
        fn adopt(&self, bundle: &str, step: u64) -> bool {
            self.id.adopt_trust(bundle, &at(&self.id, step)).unwrap() == TrustStep::Changed
        }
    }

    /// The version of the rotation's manifest number `step` in `id`'s cluster.
    fn at(id: &Identity, step: u64) -> TrustVersion {
        TrustVersion {
            cluster_id: id.meta.cluster_id.clone(),
            epoch: 1,
            seq: step,
        }
    }

    fn replica() -> Replica {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::init(
            dir.path(),
            "home",
            vec!["https://127.0.0.1:1".into()],
            "lab",
        )
        .unwrap();
        let new = pki::new_ca_labeled("home", "next").unwrap();
        Replica {
            old_cert: id.ca_pem.clone(),
            _dir: dir,
            id,
            new,
        }
    }

    /// Before the primary's trust manifest: one CA, and the new key already received.
    fn before_trust() -> Replica {
        let r = replica();
        assert!(!r.id.store_ca_key(&r.new.key_pem).unwrap());
        assert!(r.has("ca-pending.key"));
        r
    }

    /// After the trust phase: both CAs trusted, the old one signs, the new key is `ca-next.key`.
    fn after_trust() -> Replica {
        let r = before_trust();
        assert!(r.adopt(&r.trusting(), 1));
        assert!(r.has("ca-next.key") && !r.has("ca-pending.key"));
        r
    }

    /// What every run must end with: one CA, its key as `ca.key`, and no other key file.
    fn assert_retired(r: &Replica) {
        let cas = pki::certs_of(&r.id.reload().ca_pem);
        assert_eq!(cas.len(), 1, "one CA is trusted");
        assert_eq!(
            r.key("ca.key"),
            Some(r.new_key()),
            "ca.key is the new CA's key"
        );
        for f in ["ca-old.key", "ca-next.key", "ca-pending.key"] {
            assert!(!r.has(f), "{f} is left behind");
        }
    }

    /// Runs `during` (on a second thread, started inside) at the point in `adopt_trust` where
    /// the key files have moved and the bundle isn't written yet, waiting up to a second for it
    /// to finish: unserialised, it finishes right there; serialised, it waits for the adoption.
    /// Returns the thread's handle, to join after the adoption.
    fn interleave(
        r: &Replica,
        during: impl Fn(&Identity) + Send + Clone + 'static,
    ) -> Rc<RefCell<Option<JoinHandle<()>>>> {
        let handle = Rc::new(RefCell::new(None));
        let (id, slot) = (r.id.clone(), Rc::clone(&handle));
        AFTER_KEY_MOVES.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                let (id, during) = (id.clone(), during.clone());
                let (tx, rx) = mpsc::channel();
                let t = std::thread::spawn(move || {
                    during(&id);
                    let _ = tx.send(());
                });
                let _ = rx.recv_timeout(Duration::from_secs(1));
                *slot.borrow_mut() = Some(t);
            }));
        });
        handle
    }

    fn join(handle: &Rc<RefCell<Option<JoinHandle<()>>>>) {
        AFTER_KEY_MOVES.with(|h| *h.borrow_mut() = None);
        handle.borrow_mut().take().unwrap().join().unwrap();
    }

    // The end state of the interleaving (a plain sequence): the key share stored the new key
    // as `ca-next.key` after the switch moved it to `ca.key`. The retire must not turn that
    // copy into a permanent `ca-old.key` (found as `FAIL: r kept ca-old.key`).
    #[test]
    fn clu_001_retire_drops_a_stray_copy_of_the_new_key() {
        let r = after_trust();
        assert!(r.adopt(&r.switched(), 2));
        assert_eq!(r.key("ca.key"), Some(r.new_key()));
        assert!(r.has("ca-old.key"), "the old key stays until the retire");
        // What the losing key share writes.
        write(
            &r.id.dir.join("ca-next.key"),
            r.new.key_pem.as_bytes(),
            true,
        )
        .unwrap();
        assert!(r.adopt(&r.new.cert_pem, 3));
        assert_retired(&r);
    }

    // The trust phase's sibling: a second copy of the new key as `ca-pending.key`, left after
    // the first was promoted. The switch must not keep it.
    #[test]
    fn clu_001_switch_drops_a_stray_pending_copy_of_the_new_key() {
        let r = after_trust();
        write(
            &r.id.dir.join("ca-pending.key"),
            r.new.key_pem.as_bytes(),
            true,
        )
        .unwrap();
        assert!(r.adopt(&r.switched(), 2));
        assert!(!r.has("ca-pending.key"), "a copy of ca.key is kept");
        assert!(!r.has("ca-next.key"));
        assert_eq!(r.key("ca.key"), Some(r.new_key()));
        assert!(r.has("ca-old.key"));
        assert!(r.adopt(&r.new.cert_pem, 3));
        assert_retired(&r);
    }

    // The switch, with the key share (the new key, as the primary sends it after switching)
    // arriving between the key move and the bundle write.
    #[test]
    fn clu_001_a_key_share_cannot_slip_into_a_switch() {
        let r = after_trust();
        let key = r.new.key_pem.clone();
        let share = interleave(&r, move |id| {
            let _ = id.store_ca_key(&key);
        });
        assert!(r.adopt(&r.switched(), 2));
        join(&share);
        assert!(
            !r.has("ca-next.key"),
            "the share stored a copy of the signing key as the next key"
        );
        assert!(r.has("ca-old.key") && r.key("ca.key") == Some(r.new_key()));
        assert!(r.adopt(&r.new.cert_pem, 3));
        assert_retired(&r);
    }

    // The trust phase: the next key arrives a second time (on the other stream) while the first
    // copy, held as pending, is promoted.
    #[test]
    fn clu_001_a_key_share_cannot_slip_into_a_trust_step() {
        let r = before_trust();
        let key = r.new.key_pem.clone();
        let share = interleave(&r, move |id| {
            let _ = id.store_ca_key(&key);
        });
        assert!(r.adopt(&r.trusting(), 1));
        join(&share);
        assert!(
            !r.has("ca-pending.key"),
            "the share was held as pending after the promotion"
        );
        assert!(r.has("ca-next.key"));
        assert!(r.adopt(&r.switched(), 2));
        assert!(r.adopt(&r.new.cert_pem, 3));
        assert_retired(&r);
    }

    /// Copies a replica's cluster directory into a new data directory.
    fn clone_of(from: &Replica) -> (tempfile::TempDir, Identity) {
        let dir = tempfile::tempdir().unwrap();
        let to = dir.path().join("cluster");
        std::fs::create_dir_all(&to).unwrap();
        for e in std::fs::read_dir(&from.id.dir).unwrap() {
            let e = e.unwrap();
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
        let id = Identity::load(dir.path()).unwrap().unwrap();
        (dir, id)
    }

    /// One round of the race: the key share (the new key) and the trust step (`bundle`) are
    /// released together; one of them is held back by `lag` spins. Returns the files that
    /// shouldn't exist afterwards.
    fn race(start: &Replica, bundle: &str, lag: usize, share_lags: bool) -> Vec<&'static str> {
        let (_dir, id) = clone_of(start);
        let key = start.new.key_pem.clone();
        let barrier = Arc::new(Barrier::new(2));
        let spin = |n: usize| {
            for _ in 0..n {
                std::hint::spin_loop();
            }
        };
        let t = {
            let (id, barrier) = (id.clone(), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                if share_lags {
                    spin(lag);
                }
                let _ = id.store_ca_key(&key);
            })
        };
        barrier.wait();
        if !share_lags {
            spin(lag);
        }
        let step = if bundle == start.trusting() { 1 } else { 2 };
        let _ = id.adopt_trust(bundle, &at(&id, step));
        t.join().unwrap();
        ["ca-next.key", "ca-pending.key"]
            .into_iter()
            .filter(|f| {
                // After a trust step the next key is expected; after a switch, neither is.
                id.dir.join(f).exists() && !(*f == "ca-next.key" && bundle == start.trusting())
            })
            .collect()
    }

    // Many rounds of the real race: the two steps released together, one lagging by a varying
    // number of spins (so the windows overlap at many offsets). `TT_RACE_ROUNDS` raises the count
    // for a hunt; the count and the survivors are printed.
    #[test]
    fn clu_001_key_share_and_trust_step_race_leaves_no_stray_key() {
        let rounds: usize = std::env::var("TT_RACE_ROUNDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);
        let trust = before_trust();
        let switch = after_trust();
        let (mut after_trust_step, mut after_switch) = (0usize, 0usize);
        for round in 0..rounds {
            let lag = (round % 64) * 40;
            if !race(&trust, &trust.trusting(), lag, round % 2 == 0).is_empty() {
                after_trust_step += 1;
            }
            if !race(&switch, &switch.switched(), lag, round % 2 == 1).is_empty() {
                after_switch += 1;
            }
        }
        eprintln!(
            "rotation race: {rounds} rounds of each step; stray key after a trust step: \
             {after_trust_step}, after a switch: {after_switch}"
        );
        assert_eq!((after_trust_step, after_switch), (0, 0));
    }
}
