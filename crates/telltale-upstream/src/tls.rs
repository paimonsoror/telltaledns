//! TLS client configuration for DoT and DoH upstreams (rustls, ring backend).
//!
//! Trust roots: the Mozilla set compiled in via `webpki-roots`, so the binary verifies
//! certificates in a `FROM scratch` image with no CA files (OPS-001). Extra roots can be added
//! (private resolvers, tests).

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// Shared TLS settings for all upstreams.
#[derive(Clone, Debug, Default)]
pub struct TlsOptions {
    /// Additional trusted roots (DER).
    pub extra_roots: Vec<CertificateDer<'static>>,
}

/// REQ: UPS-011 (T7.16) — one upstream's own TLS settings: a CA to trust, a client
/// certificate (mTLS), and SPKI pins.
#[derive(Clone, Default)]
pub struct UpstreamTls {
    pub ca: Vec<CertificateDer<'static>>,
    pub client: Option<Arc<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>>,
    /// Base64 SHA-256 of the server certificate's `SubjectPublicKeyInfo` (HPKP style).
    pub pins: Vec<String>,
}

impl std::fmt::Debug for UpstreamTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamTls")
            .field("ca", &self.ca.len())
            .field("client_cert", &self.client.is_some())
            .field("pins", &self.pins)
            .finish()
    }
}

/// Builds a client config; `alpn` is e.g. `[b"h2"]` for DoH. `insecure` disables certificate
/// verification entirely (config `tls_insecure_skip_verify`, warned about at startup) except
/// for pins, which are still checked.
pub(crate) fn client_config(
    opts: &TlsOptions,
    up: &UpstreamTls,
    alpn: &[&[u8]],
    insecure: bool,
) -> Result<Arc<ClientConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()?;
    let verifier: Arc<dyn ServerCertVerifier> = if insecure {
        Arc::new(NoVerify(Arc::clone(&provider)))
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for der in opts.extra_roots.iter().chain(&up.ca) {
            roots.add(der.clone())?;
        }
        rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&provider),
        )
        .build()
        .map_err(|e| rustls::Error::General(e.to_string()))?
    };
    let verifier: Arc<dyn ServerCertVerifier> = if up.pins.is_empty() {
        verifier
    } else {
        Arc::new(Pinned {
            inner: verifier,
            pins: up.pins.clone(),
        })
    };
    let builder = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut cfg = match &up.client {
        Some(c) => builder.with_client_auth_cert(c.0.clone(), c.1.clone_key())?,
        None => builder.with_no_client_auth(),
    };
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    // Session resumption is on by default (in-memory cache), which speeds up reconnects.
    Ok(Arc::new(cfg))
}

/// The name to verify: `tls_server_name` if set, else the URL host (DNS name or IP literal).
pub(crate) fn server_name(name: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(name.to_owned())
        .map_err(|e| format!("invalid TLS server name `{name}`: {e}"))
}

/// The DER of a certificate's `SubjectPublicKeyInfo` (a minimal walk of the X.509 structure).
pub(crate) fn spki(cert: &[u8]) -> Option<&[u8]> {
    /// One TLV: (tag, content, the whole TLV, what follows).
    type Tlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);
    fn tlv(d: &[u8]) -> Option<Tlv<'_>> {
        let tag = *d.first()?;
        let first = *d.get(1)?;
        let (len, head) = if first & 0x80 == 0 {
            (usize::from(first), 2)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 3 {
                return None;
            }
            let mut len = 0usize;
            for b in d.get(2..2 + n)? {
                len = (len << 8) | usize::from(*b);
            }
            (len, 2 + n)
        };
        let end = head.checked_add(len)?;
        let whole = d.get(..end)?;
        Some((tag, &whole[head..], whole, &d[end..]))
    }
    let (_, certificate, _, _) = tlv(cert)?;
    let (_, tbs, _, _) = tlv(certificate)?;
    let mut rest = tbs;
    // [0] version (optional), then serial, signature, issuer, validity, subject.
    if rest.first() == Some(&0xa0) {
        rest = tlv(rest)?.3;
    }
    for _ in 0..5 {
        rest = tlv(rest)?.3;
    }
    let (tag, _, whole, _) = tlv(rest)?;
    (tag == 0x30).then_some(whole)
}

/// The pin of a certificate: base64 SHA-256 of its `SubjectPublicKeyInfo`.
pub fn spki_pin(cert: &[u8]) -> Option<String> {
    let d = ring::digest::digest(&ring::digest::SHA256, spki(cert)?);
    Some(crate::proxy::base64(d.as_ref()))
}

/// REQ: UPS-011 — the usual verification (or none, when insecure), then the key must match one
/// of the pins.
#[derive(Debug)]
struct Pinned {
    inner: Arc<dyn ServerCertVerifier>,
    pins: Vec<String>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ok =
            self.inner
                .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)?;
        match spki_pin(end_entity.as_ref()) {
            Some(pin) if self.pins.contains(&pin) => Ok(ok),
            _ => Err(rustls::Error::General(
                "the server's key doesn't match spki_pins".into(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Accepts any certificate (signatures are still checked, so the handshake is sound, but the
/// server's identity is not). Only for `tls_insecure_skip_verify = true`.
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: UPS-011 — the SPKI walked out of a certificate is exactly the key's SPKI.
    #[test]
    fn ups_011_spki_from_certificate() {
        let g = rcgen::generate_simple_self_signed(vec!["dns.test".into()]).unwrap();
        let der = g.cert.der();
        assert_eq!(
            spki(der.as_ref()).unwrap(),
            rcgen::PublicKeyData::subject_public_key_info(&g.signing_key).as_slice()
        );
        assert_eq!(spki_pin(der.as_ref()).unwrap().len(), 44);
        assert!(
            spki(&der.as_ref()[..20]).is_none(),
            "truncated: no panic, no key"
        );
    }
}
