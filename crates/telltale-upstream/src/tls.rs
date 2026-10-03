//! TLS client configuration for DoT and DoH upstreams (rustls, ring backend).
//!
//! Trust roots: the Mozilla set compiled in via `webpki-roots`, so the binary verifies
//! certificates in a `FROM scratch` image with no CA files (OPS-001). Extra roots can be added
//! (private resolvers, tests).

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// Shared TLS settings for all upstreams.
#[derive(Clone, Debug, Default)]
pub struct TlsOptions {
    /// Additional trusted roots (DER).
    pub extra_roots: Vec<CertificateDer<'static>>,
}

/// Builds a client config; `alpn` is e.g. `[b"h2"]` for DoH. `insecure` disables certificate
/// verification entirely (config `tls_insecure_skip_verify`, warned about at startup).
pub(crate) fn client_config(
    opts: &TlsOptions,
    alpn: &[&[u8]],
    insecure: bool,
) -> Result<Arc<ClientConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()?;
    let mut cfg = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for der in &opts.extra_roots {
            roots.add(der.clone())?;
        }
        builder.with_root_certificates(roots).with_no_client_auth()
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
