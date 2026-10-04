//! TLS certificates for DoT and DoH (REQ: DNS-002, DNS-003; `spec/03` §1).
//!
//! The certificate and key come from PEM files and are re-read when either file changes
//! (cert-manager renews by swapping the Secret's files), so new handshakes use the new
//! certificate without a restart; established connections keep theirs. A failed reload keeps
//! the previous certificate.
//!
//! Client IDs from SNI (FLT-006): when the certificate has a wildcard name `*.dns.example.com`
//! and a client connects with SNI `kids-tablet.dns.example.com`, the client ID is
//! `kids-tablet`. No extra configuration: the certificate says which names are ours.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::SystemTime;

use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::handler::ClientId;

/// File identity used to notice changes: (modified time, length) of each file.
type Stamp = [(Option<SystemTime>, u64); 2];

#[derive(Debug)]
struct Loaded {
    key: Arc<CertifiedKey>,
    stamp: Stamp,
    /// Lowercased base names of the certificate's wildcard names (`dns.example.com`).
    wildcard_bases: Vec<String>,
}

/// A certificate and key from files, reloadable.
#[derive(Debug)]
pub struct CertStore {
    cert: PathBuf,
    key: PathBuf,
    provider: Arc<CryptoProvider>,
    current: RwLock<Arc<Loaded>>,
}

fn invalid(path: &Path, e: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{}: {e}", path.display()),
    )
}

fn stamp(cert: &Path, key: &Path) -> Stamp {
    let one = |p: &Path| std::fs::metadata(p).map_or((None, 0), |m| (m.modified().ok(), m.len()));
    [one(cert), one(key)]
}

impl CertStore {
    /// Loads `cert` (a PEM chain, leaf first) and `key` (PEM PKCS#8, PKCS#1, or SEC1).
    pub fn load(cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> io::Result<Arc<Self>> {
        let (cert, key) = (cert.into(), key.into());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let loaded = read(&cert, &key, &provider)?;
        Ok(Arc::new(Self {
            cert,
            key,
            provider,
            current: RwLock::new(Arc::new(loaded)),
        }))
    }

    fn get(&self) -> Arc<Loaded> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Re-reads the files if either changed. `Ok(true)` when a new certificate is in use;
    /// on error the previous one stays.
    pub fn reload_if_changed(&self) -> io::Result<bool> {
        let now = stamp(&self.cert, &self.key);
        if now == self.get().stamp {
            return Ok(false);
        }
        let loaded = read(&self.cert, &self.key, &self.provider)?;
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(loaded);
        Ok(true)
    }

    /// The certificate file (for logs).
    pub fn cert_path(&self) -> &Path {
        &self.cert
    }

    /// A server config that resolves to this store's current certificate, offering `alpn`.
    pub fn server_config(self: &Arc<Self>, alpn: &[&[u8]]) -> io::Result<Arc<ServerConfig>> {
        let mut cfg = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| invalid(&self.cert, e))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(self) as Arc<dyn ResolvesServerCert>);
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Ok(Arc::new(cfg))
    }

    /// The client ID carried in `sni`: the single label in front of one of the
    /// certificate's wildcard names.
    pub fn client_id(&self, sni: &str) -> Option<ClientId> {
        let sni = sni.trim_end_matches('.').to_ascii_lowercase();
        let (label, rest) = sni.split_once('.')?;
        self.get()
            .wildcard_bases
            .iter()
            .any(|b| b == rest)
            .then(|| ClientId::new(label))
            .flatten()
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.get().key))
    }
}

fn read(cert: &Path, key: &Path, provider: &CryptoProvider) -> io::Result<Loaded> {
    // Stamp first: a change while reading is picked up by the next check.
    let stamp = stamp(cert, key);
    let chain = CertificateDer::pem_file_iter(cert)
        .map_err(|e| invalid(cert, e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| invalid(cert, e))?;
    let leaf = chain
        .first()
        .ok_or_else(|| invalid(cert, "no certificate"))?;
    let wildcard_bases = webpki::EndEntityCert::try_from(leaf)
        .map_err(|e| invalid(cert, e))?
        .valid_dns_names()
        .filter_map(|n| n.strip_prefix("*.").map(str::to_ascii_lowercase))
        .collect();
    let key_der = PrivateKeyDer::from_pem_file(key).map_err(|e| invalid(key, e))?;
    let certified = CertifiedKey::from_der(chain, key_der, provider).map_err(|e| {
        invalid(
            key,
            format!("doesn't match the certificate or isn't supported: {e}"),
        )
    })?;
    Ok(Loaded {
        key: Arc::new(certified),
        stamp,
        wildcard_bases,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join(name)
    }

    #[test]
    fn dns_002_loads_and_reloads_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (dir.path().join("tls.crt"), dir.path().join("tls.key"));
        std::fs::copy(fixture("a.crt"), &cert).unwrap();
        std::fs::copy(fixture("a.key"), &key).unwrap();
        let store = CertStore::load(&cert, &key).unwrap();
        let leaf = |s: &CertStore| s.get().key.end_entity_cert().unwrap().as_ref().to_vec();
        let first = leaf(&store);
        assert!(!store.reload_if_changed().unwrap(), "unchanged");

        // A renewal: both files replaced.
        std::fs::copy(fixture("b.crt"), &cert).unwrap();
        std::fs::copy(fixture("b.key"), &key).unwrap();
        assert!(store.reload_if_changed().unwrap());
        assert_ne!(leaf(&store), first);

        // A broken file keeps the last good certificate.
        std::fs::write(&key, "not a key, and a different length").unwrap();
        assert!(store.reload_if_changed().is_err());
        assert_ne!(leaf(&store), first);
        // A key that doesn't match the certificate is refused at load.
        assert!(CertStore::load(fixture("a.crt"), fixture("b.key")).is_err());
    }

    #[test]
    fn flt_006_client_id_from_sni() {
        // a.crt: dns.test and *.dns.test.
        let store = CertStore::load(fixture("a.crt"), fixture("a.key")).unwrap();
        assert_eq!(
            store.client_id("kids-tablet.dns.test").unwrap().as_str(),
            "kids-tablet"
        );
        assert_eq!(
            store.client_id("Kids-Tablet.DNS.test.").unwrap().as_str(),
            "kids-tablet"
        );
        assert!(store.client_id("dns.test").is_none());
        assert!(store.client_id("a.b.dns.test").is_none());
        assert!(store.client_id("x.other.test").is_none());
    }
}
