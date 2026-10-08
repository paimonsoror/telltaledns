//! Config replication (REQ: CLU-003; `spec/02` §5, `spec/12` §4; ADR-047): a signed cluster
//! manifest naming content-addressed blobs (BLAKE3), and the store replicas keep them in.
//!
//! The primary publishes a new manifest whenever its shared configuration or filter snapshot
//! changes. Replicas fetch only blobs they don't have, so a list change ships only the FST
//! shards that changed. The manifest is signed with the cluster CA's Ed25519 key and checked
//! against the CA certificate every node already trusts.

use std::path::{Path, PathBuf};

use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::pki;

/// One content-addressed file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRef {
    /// The file name it's installed under (e.g. `subtree-0.fst`, `config.json`).
    pub name: String,
    /// BLAKE3, lowercase hex.
    pub hash: String,
    pub bytes: u64,
}

/// The filter snapshot: its own manifest (`manifest.json`) plus its blobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterRef {
    /// The primary's snapshot version.
    pub version: u64,
    pub blobs: Vec<BlobRef>,
}

/// What the primary publishes. Versions order by `(epoch, seq)`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterManifest {
    pub cluster_id: String,
    pub epoch: u64,
    pub seq: u64,
    /// Unix milliseconds, from the primary's clock (display and lag only).
    pub created_ms: u64,
    /// The node that published it.
    pub primary: String,
    /// The shared configuration (`telltale_config::shared::shared_part`) as JSON.
    pub config: BlobRef,
    pub filter: Option<FilterRef>,
    /// The member registry (ADR-051): every node, its site, eligibility, and URLs.
    #[serde(default)]
    pub nodes: Vec<crate::node::NodeRecord>,
    /// The cluster's config authority (ADR-048): `api` or `gitops`.
    #[serde(default)]
    pub authority: String,
    /// The first manifest of an epoch: the `(epoch, seq)` the new primary had applied when it
    /// was promoted. Versions the old primary published after it are orphaned (ADR-051).
    #[serde(default)]
    pub base: Option<(u64, u64)>,
    /// Emergency primary (ADR-048): coordinates, publishes no new configuration.
    #[serde(default)]
    pub emergency: bool,
    /// How the cluster fails over (ADR-056): `manual` or `auto`.
    #[serde(default)]
    pub failover: String,
    /// Where the configuration came from, when it's a Git commit (ADR-049).
    #[serde(default)]
    pub source: Option<SourceInfo>,
    /// The configuration schema of `config` (CLU-010): a replica that reads an older schema
    /// keeps its last version when it can't read this one, and says to upgrade.
    #[serde(default)]
    pub schema: u32,
    /// The CAs every node should trust (T5.4c): one normally, two during a CA rotation, the
    /// first being the one that signs. Empty from older primaries.
    #[serde(default)]
    pub ca_bundle: String,
    /// REQ: CLU-003 (T9.1, ADR-045) — the primary's users, recovery codes, and API tokens
    /// (hashes only), as one JSON document. Absent from older primaries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identities: Option<BlobRef>,
    /// REQ: OBS-003 (review 04-05) — the key privacy level 1 hashes names with (hex), so
    /// every node's logs group the same way. Absent from older primaries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_key: Option<String>,
}

/// A Git commit as a configuration's provenance (ADR-049). `repo`, `git_ref` and `path` also
/// pin the source: a promoted node fetches only from the same place.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SourceInfo {
    pub repo: String,
    pub git_ref: String,
    pub path: String,
    pub commit: String,
    pub author: String,
    /// Committer time, Unix seconds.
    pub time: i64,
    pub subject: String,
    #[serde(default)]
    pub signed_by: Option<String>,
}

/// The configuration schema this build writes and reads (CLU-010). Raised when the shared
/// configuration gains settings an older build would reject.
pub const SCHEMA: u32 = 1;

impl ClusterManifest {
    /// Every blob it references.
    pub fn blobs(&self) -> Vec<&BlobRef> {
        let mut v = vec![&self.config];
        if let Some(f) = &self.filter {
            v.extend(f.blobs.iter());
        }
        v.extend(self.identities.iter());
        v
    }

    /// Whether `self` is newer than `(epoch, seq)`.
    pub fn newer_than(&self, epoch: u64, seq: u64) -> bool {
        (self.epoch, self.seq) > (epoch, seq)
    }
}

/// A manifest as sent: its exact JSON bytes and the signature over them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub json: Vec<u8>,
    pub sig: Vec<u8>,
}

impl Signed {
    /// Signs `m` with the CA key (PKCS#8 PEM).
    pub fn sign(m: &ClusterManifest, ca_key_pem: &str) -> Result<Self, String> {
        let key = ed25519_key(ca_key_pem)?;
        let json = serde_json::to_vec(m).map_err(|e| e.to_string())?;
        let sig = key.sign(&json).as_ref().to_vec();
        Ok(Self { json, sig })
    }

    /// Checks the signature against the CA certificate (any CA of a bundle, during a
    /// rotation) and returns the manifest.
    pub fn verify(&self, ca_cert_pem: &str) -> Result<ClusterManifest, String> {
        let ok = pki::certs_of(ca_cert_pem).iter().any(|ca| {
            ca_public_key(ca).is_ok_and(|public| {
                UnparsedPublicKey::new(&ED25519, &public)
                    .verify(&self.json, &self.sig)
                    .is_ok()
            })
        });
        if !ok {
            return Err("the cluster manifest's signature doesn't verify".to_owned());
        }
        serde_json::from_slice(&self.json).map_err(|e| format!("bad cluster manifest: {e}"))
    }
}

/// The raw Ed25519 public key in a certificate.
pub fn ca_public_key(cert_pem: &str) -> Result<Vec<u8>, String> {
    let der = pki::der_of(cert_pem).map_err(|e| e.to_string())?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(&der).map_err(|e| format!("CA certificate: {e}"))?;
    Ok(cert.public_key().subject_public_key.data.to_vec())
}

/// The public key matching a CA key, for tests and self-checks.
pub fn public_of(ca_key_pem: &str) -> Result<Vec<u8>, String> {
    Ok(ed25519_key(ca_key_pem)?.public_key().as_ref().to_vec())
}

/// An Ed25519 key from a PKCS#8 PEM.
fn ed25519_key(pem: &str) -> Result<Ed25519KeyPair, String> {
    use rustls_pki_types::PrivatePkcs8KeyDer;
    use rustls_pki_types::pem::PemObject;
    let der = PrivatePkcs8KeyDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| format!("cluster CA key: {e}"))?;
    Ed25519KeyPair::from_pkcs8_maybe_unchecked(der.secret_pkcs8_der())
        .map_err(|_| "the cluster CA key isn't an Ed25519 key".to_owned())
}

/// BLAKE3 of `bytes`, lowercase hex.
pub fn hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// A [`BlobRef`] for `bytes` named `name`.
pub fn blob_ref(name: &str, bytes: &[u8]) -> BlobRef {
    BlobRef {
        name: name.to_owned(),
        hash: hash(bytes),
        bytes: bytes.len() as u64,
    }
}

/// Blobs by hash, under `<data_dir>/cluster/blobs`.
#[derive(Debug, Clone)]
pub struct BlobStore {
    dir: PathBuf,
}

fn valid_hash(h: &str) -> bool {
    h.len() == 64
        && h.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl BlobStore {
    pub fn open(data_dir: &Path) -> std::io::Result<Self> {
        let dir = crate::node::dir_of(data_dir).join("blobs");
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn path(&self, hash: &str) -> Option<PathBuf> {
        valid_hash(hash).then(|| self.dir.join(hash))
    }

    pub fn has(&self, b: &BlobRef) -> bool {
        self.path(&b.hash)
            .and_then(|p| std::fs::metadata(p).ok())
            .is_some_and(|m| m.len() == b.bytes)
    }

    /// Stores `bytes` if they hash to `b.hash` (temp file + rename).
    pub fn put(&self, b: &BlobRef, bytes: &[u8]) -> Result<(), String> {
        let path = self.path(&b.hash).ok_or("bad blob hash")?;
        if hash(bytes) != b.hash || bytes.len() as u64 != b.bytes {
            return Err(format!("blob {} doesn't match its hash", b.name));
        }
        let tmp = self.dir.join(format!(".{}.tmp", b.hash));
        std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|e| e.to_string())
    }

    pub fn read(&self, b: &BlobRef) -> Result<Vec<u8>, String> {
        let path = self.path(&b.hash).ok_or("bad blob hash")?;
        std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Removes blobs not in `keep` (after a manifest is applied).
    pub fn retain(&self, keep: &[&BlobRef]) {
        let keep: std::collections::HashSet<&str> = keep.iter().map(|b| b.hash.as_str()).collect();
        for e in std::fs::read_dir(&self.dir).into_iter().flatten().flatten() {
            let name = e.file_name();
            let Some(name) = name.to_str() else { continue };
            if valid_hash(name) && !keep.contains(name) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> ClusterManifest {
        ClusterManifest {
            cluster_id: "c".into(),
            epoch: 1,
            seq: 7,
            created_ms: 1,
            primary: "n1".into(),
            config: blob_ref("config.json", b"{}"),
            filter: Some(FilterRef {
                version: 3,
                blobs: vec![blob_ref("subtree-0.fst", b"fst")],
            }),
            ..ClusterManifest::default()
        }
    }

    #[test]
    fn clu_003_manifests_are_signed_by_the_cluster_ca() {
        let ca = pki::new_ca("home").unwrap();
        let signed = Signed::sign(&manifest(), &ca.key_pem).unwrap();
        assert_eq!(signed.verify(&ca.cert_pem).unwrap(), manifest());
        // Another cluster's CA, or a changed byte, fails.
        let other = pki::new_ca("other").unwrap();
        assert!(signed.verify(&other.cert_pem).is_err());
        let mut bad = signed.clone();
        bad.json[5] ^= 1;
        assert!(bad.verify(&ca.cert_pem).is_err());
        assert_eq!(
            public_of(&ca.key_pem).unwrap(),
            ca_public_key(&ca.cert_pem).unwrap()
        );
    }

    #[test]
    fn clu_003_blob_store_checks_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path()).unwrap();
        let b = blob_ref("x", b"hello");
        assert!(!store.has(&b));
        assert!(store.put(&b, b"jello").is_err());
        store.put(&b, b"hello").unwrap();
        assert!(store.has(&b));
        assert_eq!(store.read(&b).unwrap(), b"hello");
        assert!(store.path("../etc/passwd").is_none());
        store.retain(&[]);
        assert!(!store.has(&b));
        assert!(
            manifest().newer_than(1, 6)
                && !manifest().newer_than(1, 7)
                && !manifest().newer_than(2, 0)
        );
    }
}
