//! Node certificate renewal (REQ: CLU-001; T5.4c, ADR-057).
//!
//! Node certificates last [`pki::NODE_CERT_DAYS`] (90 days); a node renews when fewer than
//! [`RENEW_DAYS_LEFT`] remain. It keeps its key, so its node ID never changes.
//! - A node holding the cluster key (the primary, eligible nodes) issues its own.
//! - Others send a CSR for their key to the primary over the cluster channel (`cert.renew`).
//!   The primary signs only for the peer the stream's certificate says is asking, and takes the
//!   certificate's names from the signed registry, never from the request.
//!
//! New connections use the new certificate at once ([`Cluster::cert_generation`]); open
//! streams keep their session, since certificates are checked only at handshake. None of this
//! touches DNS (CLU-004).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::net::{Cluster, peer_node_id};
use crate::node::hosts;
use crate::pki;

/// The renewal RPC; its body is a PEM CSR, its answer a PEM certificate.
pub const KIND: &str = "cert.renew";
/// Renew when fewer days than this remain (two thirds of the lifetime used).
pub const RENEW_DAYS_LEFT: i64 = 30;
/// How often the certificate is checked.
const EVERY: Duration = Duration::from_hours(6);
/// After a failed renewal.
const RETRY: Duration = Duration::from_secs(600);

/// Whether a certificate is due for renewal.
pub fn due(cert_pem: &str) -> bool {
    pki::validity(cert_pem).map_or(true, |(left, _)| left < RENEW_DAYS_LEFT * 86_400)
}

/// Whether a certificate wasn't issued by the bundle's signing CA (the first): after a CA
/// rotation switches, every node renews (T5.4c).
pub fn stale_issuer(cert_pem: &str, ca_bundle: &str) -> bool {
    pki::certs_of(ca_bundle)
        .first()
        .is_some_and(|signer| pki::verify_issued(cert_pem, signer).is_err())
}

/// Signs `peer`'s renewal request (on a node holding the cluster key).
pub fn answer(cluster: &Cluster, peer: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let id = cluster.identity.reload();
    if !id.holds_ca() {
        return Err("this node doesn't hold the cluster key".into());
    }
    let csr = std::str::from_utf8(body).map_err(|_| "the CSR isn't text")?;
    let advertise = id
        .registry()
        .into_iter()
        .find(|n| n.node_id == peer)
        .map(|n| n.advertise)
        .ok_or_else(|| format!("node {peer} isn't in the registry"))?;
    let (node_id, cert) = id.issue_for(csr, &hosts(&advertise))?;
    if node_id != peer {
        return Err("a node can only renew its own certificate".into());
    }
    cluster.event("cert_issued", peer, "renewed node certificate");
    Ok(cert.into_bytes())
}

/// Renews this node's certificate now.
pub async fn renew_now(cluster: &Cluster) -> Result<(), String> {
    let id = cluster.identity.reload();
    let csr = pki::csr_for(&id.key_pem).map_err(|e| e.to_string())?;
    // Self-issue only with the signing CA's key (a node that missed a rotation's new key asks).
    let cert = if id.holds_ca() && id.signs_now() {
        id.issue_for(&csr, &hosts(&id.meta.advertise))?.1
    } else {
        let primary = cluster
            .reachable_primary()
            .ok_or("the primary isn't reachable")?;
        let b = cluster
            .call(&primary, KIND, csr.into_bytes(), Duration::from_secs(10))
            .await?;
        String::from_utf8(b).map_err(|_| "the certificate isn't text")?
    };
    // It must be for this node and signed by the cluster CA.
    let der = pki::der_of(&cert).map_err(|e| e.to_string())?;
    let who = peer_node_id(&der.into()).ok_or("the new certificate names no node")?;
    if who != id.meta.node_id {
        return Err(format!("the new certificate is for {who}, not this node"));
    }
    pki::verify_issued(&cert, &id.ca_pem).map_err(|e| e.to_string())?;
    id.save_cert(&cert)?;
    cluster.bump_cert_generation();
    let left = pki::validity(&cert).map_or(0, |(l, _)| l / 86_400);
    info!(days_left = left, "cluster: node certificate renewed");
    cluster.event(
        "cert_renewed",
        &id.meta.node_id,
        format!("valid for {left} more days"),
    );
    Ok(())
}

/// Renews this node's certificate whenever it's due, or once a CA rotation has switched the
/// signing CA, until `stop`.
pub async fn run(cluster: Arc<Cluster>, mut stop: watch::Receiver<bool>) {
    // Expiry is checked every 6 hours; a switched CA (cheap to see) every minute.
    let tick = Duration::from_secs(60);
    let mut next_expiry_check = tokio::time::Instant::now() + tick;
    let mut retry_at: Option<tokio::time::Instant> = None;
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(tick) => {}
        }
        let now = tokio::time::Instant::now();
        if retry_at.is_some_and(|t| now < t) {
            continue;
        }
        let id = cluster.identity.reload();
        let stale = stale_issuer(&id.cert_pem, &id.ca_pem);
        let expiring = now >= next_expiry_check && due(&id.cert_pem);
        if now >= next_expiry_check {
            next_expiry_check = now + EVERY;
        }
        if !stale && !expiring {
            continue;
        }
        if stale {
            info!("cluster: the cluster CA was rotated; renewing this node's certificate");
        }
        retry_at = None;
        if let Err(e) = renew_now(&cluster).await {
            // A rotation retries every minute (the primary may be mid-switch); expiry every 10.
            let wait = if stale { tick } else { RETRY };
            warn!(
                retry_s = wait.as_secs(),
                "cluster: node certificate renewal failed: {e}"
            );
            cluster.event(
                "cert_renew_failed",
                &cluster.identity.meta.node_id.clone(),
                e,
            );
            retry_at = Some(now + wait);
        }
    }
}
