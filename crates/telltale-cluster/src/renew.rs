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
    let cert = if id.holds_ca() {
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

/// Renews this node's certificate whenever it's due, until `stop`.
pub async fn run(cluster: Arc<Cluster>, mut stop: watch::Receiver<bool>) {
    let mut wait = Duration::from_secs(60);
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(wait) => {}
        }
        wait = EVERY;
        if !due(&cluster.identity.reload().cert_pem) {
            continue;
        }
        if let Err(e) = renew_now(&cluster).await {
            warn!("cluster: node certificate renewal failed (retrying in 10 min): {e}");
            cluster.event(
                "cert_renew_failed",
                &cluster.identity.meta.node_id.clone(),
                e,
            );
            wait = RETRY;
        }
    }
}
