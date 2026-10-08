//! A node's cluster identity on disk (REQ: CLU-001; `spec/12` §3), in `<data_dir>/cluster/`:
//! `cluster.json` (IDs, site, URLs), `node.key` + `node.crt` (its identity), `ca.crt`, and on
//! the node that created the cluster (or any node holding it) `ca.key` and `tokens.json`
//! (hashes of the join-token secrets, never the secrets). Keys are written owner-only.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::pki::{self, Ca};
use crate::token::{self, Token};

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
fn write(path: &Path, data: &[u8], secret: bool) -> std::io::Result<()> {
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

    /// Stores the CA key received from the primary (eligible nodes, ADR-051), after checking it
    /// belongs to this cluster's CA certificate: the signing CA's key as `ca.key`, and during a
    /// rotation the other CA's as `ca-next.key` (T5.4c).
    pub fn store_ca_key(&self, key_pem: &str) -> Result<bool, String> {
        let public = crate::sync::public_of(key_pem)?;
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

    /// Replaces the trusted CAs (`ca.crt`) with `bundle` from a verified manifest (T5.4c). The
    /// new bundle must keep a CA this node trusts now, so trust only ever moves step by step.
    /// When a CA held as `ca-next.key` becomes the signing one, its key becomes `ca.key`.
    /// Returns whether anything changed.
    pub fn adopt_trust(&self, bundle: &str) -> Result<bool, String> {
        let me = self.reload();
        let new = pki::certs_of(bundle);
        if new.is_empty() || bundle.trim() == me.ca_pem.trim() {
            return Ok(false);
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
            if cur.exists() {
                let _ = std::fs::rename(&cur, self.dir.join("ca-old.key"));
            }
            std::fs::rename(&next, &cur).map_err(|e| e.to_string())?;
        }
        // A CA key whose certificate left the bundle is no longer needed.
        for f in ["ca-old.key", "ca-next.key", "ca-pending.key"] {
            let p = self.dir.join(f);
            if let Some(k) = held(&p)
                && !new
                    .iter()
                    .any(|c| crate::sync::ca_public_key(c).is_ok_and(|x| x == k))
            {
                let _ = std::fs::remove_file(&p);
            }
        }
        write(&self.dir.join("ca.crt"), new.concat().as_bytes(), false)
            .map_err(|e| e.to_string())?;
        Ok(true)
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

    /// A join token valid for `ttl_s`, listing `urls` (default: this node's advertise URLs).
    pub fn create_token(&self, ttl_s: u64, urls: Option<Vec<String>>) -> Result<Token, String> {
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
        let by_token = recs
            .iter()
            .any(|r| r.exp > t && same(r.hash.as_bytes(), h.as_bytes()));
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
        let t = p.create_token(3600, None).unwrap();
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
