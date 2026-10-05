//! The cluster PKI (REQ: CLU-001; `spec/12` §3, ADR-044): an Ed25519 CA per cluster and node
//! certificates it issues from the node's certificate signing request.
//!
//! Every node certificate carries two names: [`CLUSTER_NAME`] (what peers verify, so a node is
//! trusted because the cluster CA signed it, whatever address it was dialed at) and
//! `<node-id>.node.telltale.invalid` (who it is). `.invalid` names can never resolve or be
//! issued by a public CA.

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, PublicKeyData,
    SanType,
};
use time::{Duration, OffsetDateTime};

/// The name every node certificate carries and every peer verifies.
pub const CLUSTER_NAME: &str = "cluster.telltale.invalid";
/// Node certificates last this long; nodes renew at two thirds of it.
pub const NODE_CERT_DAYS: i64 = 90;
/// The CA lasts this long.
const CA_YEARS: i64 = 10;

/// A PKI failure.
#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("certificate: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("{0}")]
    Invalid(String),
}

/// The CA certificate and its private key (only on the primary and eligible nodes).
pub struct Ca {
    pub cert_pem: String,
    pub key_pem: String,
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ca").finish_non_exhaustive()
    }
}

/// A new CA for cluster `name`.
pub fn new_ca(name: &str) -> Result<Ca, PkiError> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("TelltaleDNS cluster {name} CA"));
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::hours(1);
    p.not_after = now + Duration::days(365 * CA_YEARS);
    let cert = p.self_signed(&key)?;
    Ok(Ca {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// A node's key pair and the CSR to send when joining.
#[derive(Debug)]
pub struct NodeKey {
    pub key_pem: String,
    pub csr_pem: String,
}

/// A new node key and a CSR for it.
pub fn new_node_key() -> Result<NodeKey, PkiError> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let p = CertificateParams::new(vec![CLUSTER_NAME.to_owned()])?;
    let csr = p.serialize_request(&key)?;
    Ok(NodeKey {
        key_pem: key.serialize_pem(),
        csr_pem: csr.pem()?,
    })
}

/// A CSR for an existing node key (certificate renewal keeps the key, so the node ID stays).
pub fn csr_for(key_pem: &str) -> Result<String, PkiError> {
    let key = KeyPair::from_pem(key_pem)?;
    let p = CertificateParams::new(vec![CLUSTER_NAME.to_owned()])?;
    Ok(p.serialize_request(&key)?.pem()?)
}

/// Checks that `cert_pem` was signed by the CA in `ca_pem` (Ed25519) and is valid now.
pub fn verify_issued(cert_pem: &str, ca_pem: &str) -> Result<(), PkiError> {
    let bad = |m: &str| PkiError::Invalid(m.to_owned());
    let der = der_of(cert_pem)?;
    let ca_der = der_of(ca_pem)?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(&der).map_err(|e| bad(&format!("certificate: {e}")))?;
    let (_, ca) =
        x509_parser::parse_x509_certificate(&ca_der).map_err(|e| bad(&format!("CA: {e}")))?;
    if cert.issuer() != ca.subject() {
        return Err(bad("not issued by this cluster's CA"));
    }
    let key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        ca.public_key().subject_public_key.data.as_ref(),
    );
    key.verify(
        cert.tbs_certificate.as_ref(),
        cert.signature_value.data.as_ref(),
    )
    .map_err(|_| bad("the CA's signature doesn't verify"))?;
    if !cert.validity().is_valid() {
        return Err(bad("the certificate isn't valid now"));
    }
    Ok(())
}

/// The node ID for a public key: the first 16 hex digits of its SHA-256.
pub fn node_id(public_key_der: &[u8]) -> String {
    hex(&ring::digest::digest(&ring::digest::SHA256, public_key_der).as_ref()[..8])
}

/// Signs a node's CSR: the names are chosen here (cluster name, node ID name, and the node's
/// advertised hosts), never taken from the request. Returns `(node_id, cert_pem)`.
pub fn issue(
    ca: &Ca,
    csr_pem: &str,
    advertise_hosts: &[String],
) -> Result<(String, String), PkiError> {
    let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
    let id = node_id(csr.public_key.der_bytes());
    let mut sans = vec![
        SanType::DnsName(CLUSTER_NAME.try_into()?),
        SanType::DnsName(format!("{id}.node.telltale.invalid").try_into()?),
    ];
    for h in advertise_hosts {
        match h.parse::<std::net::IpAddr>() {
            Ok(ip) => sans.push(SanType::IpAddress(ip)),
            Err(_) => {
                if let Ok(n) = h.as_str().try_into() {
                    sans.push(SanType::DnsName(n));
                }
            }
        }
    }
    let p = &mut csr.params;
    p.subject_alt_names = sans;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("{id}.node.telltale.invalid"));
    p.distinguished_name = dn;
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::hours(1);
    p.not_after = now + Duration::days(NODE_CERT_DAYS);
    let ca_key = KeyPair::from_pem(&ca.key_pem)?;
    let issuer = Issuer::from_ca_cert_pem(&ca.cert_pem, ca_key)?;
    let cert = csr.signed_by(&issuer)?;
    Ok((id, cert.pem()))
}

/// SHA-256 of a PEM certificate's DER (what join tokens pin).
pub fn fingerprint(cert_pem: &str) -> Result<[u8; 32], PkiError> {
    let der = der_of(cert_pem)?;
    let d = ring::digest::digest(&ring::digest::SHA256, &der);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    Ok(out)
}

/// The DER of the first certificate in `pem`.
pub fn der_of(pem: &str) -> Result<Vec<u8>, PkiError> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    CertificateDer::from_pem_slice(pem.as_bytes())
        .map(|c| c.to_vec())
        .map_err(|e| PkiError::Invalid(format!("not a PEM certificate: {e}")))
}

/// Seconds until a PEM certificate expires, and its total lifetime (for renewal at 2/3).
pub fn validity(cert_pem: &str) -> Result<(i64, i64), PkiError> {
    let der = der_of(cert_pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| PkiError::Invalid(format!("certificate: {e}")))?;
    let v = cert.validity();
    let (nb, na) = (v.not_before.timestamp(), v.not_after.timestamp());
    let now = OffsetDateTime::now_utc().unix_timestamp();
    Ok((na - now, na - nb))
}

pub(crate) fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clu_001_ca_issues_node_certs_with_chosen_names() {
        let ca = new_ca("home").unwrap();
        let k = new_node_key().unwrap();
        let (id, cert) = issue(&ca, &k.csr_pem, &["pi.lan".into(), "192.168.3.2".into()]).unwrap();
        assert_eq!(id.len(), 16);
        let der = der_of(&cert).unwrap();
        let (_, c) = x509_parser::parse_x509_certificate(&der).unwrap();
        let sans: Vec<String> = c
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .iter()
            .map(|n| format!("{n}"))
            .collect();
        assert!(sans.iter().any(|s| s.contains(CLUSTER_NAME)), "{sans:?}");
        assert!(
            sans.iter()
                .any(|s| s.contains(&format!("{id}.node.telltale.invalid")))
        );
        assert!(sans.iter().any(|s| s.contains("pi.lan")));
        assert!(sans.iter().any(|s| s.contains("c0:a8:03:02")), "{sans:?}");
        // The issuer is the cluster CA, and the lifetime is 90 days.
        let ca_der = der_of(&ca.cert_pem).unwrap();
        let (_, cac) = x509_parser::parse_x509_certificate(&ca_der).unwrap();
        assert_eq!(c.issuer(), cac.subject());
        let (left, total) = validity(&cert).unwrap();
        assert!((total - (NODE_CERT_DAYS * 86_400 + 3600)).abs() < 5);
        assert!(left > 89 * 86_400);
        // Same key, same ID.
        let csr = CertificateSigningRequestParams::from_pem(&k.csr_pem).unwrap();
        assert_eq!(node_id(csr.public_key.der_bytes()), id);
        assert_eq!(fingerprint(&ca.cert_pem).unwrap().len(), 32);
    }
}
