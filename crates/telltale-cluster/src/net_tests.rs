use std::time::Duration;

use tokio::sync::watch;

use super::*;
use crate::node::{Identity, JoinRequest};
use crate::pki;

async fn free_port() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap()
}

async fn wait_for(mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("condition not met in time");
}

#[tokio::test(flavor = "multi_thread")]
async fn clu_001_join_then_mutual_stream_registers_both_peers() {
    let (pdir, rdir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let addr = free_port().await;
    let url = format!("https://{addr}");

    let primary = Identity::init(pdir.path(), "home", vec![url.clone()], "k8s").unwrap();
    let token = primary.create_token(600, Some(vec![url.clone()])).unwrap();
    let primary = Cluster::new(primary, "0.1.0");
    let (stop_tx, stop) = watch::channel(false);
    tokio::spawn(serve(Arc::clone(&primary), addr, stop.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The replica joins: the token pins the CA; the secret earns a certificate.
    let key = pki::new_node_key().unwrap();
    let req = JoinRequest {
        secret: token.secret.clone(),
        csr_pem: key.csr_pem.clone(),
        advertise: vec![],
        site: "pi".into(),
        eligible: true,
        version: "0.1.0".into(),
    };
    let resp = join(&token, &req).await.unwrap();
    let replica =
        Identity::save_joined(rdir.path(), &key.key_pem, &resp, "pi", true, vec![]).unwrap();
    assert_eq!(replica.meta.cluster_id, token.cluster_id);
    assert!(!replica.holds_ca());

    // Tokens are reusable until they expire (a Kubernetes Secret holds one for every pod,
    // spec/12 §2); a wrong secret is refused.
    let mut bad = req.clone();
    bad.secret = "tt_wrong".into();
    assert!(
        join(&token, &bad)
            .await
            .unwrap_err()
            .contains("unknown or expired")
    );

    // The replica dials out; each side learns the other.
    let replica = Cluster::new(replica, "0.1.0");
    tokio::spawn(dial(Arc::clone(&replica), vec![url.clone()], stop.clone()));
    let (p, r) = (Arc::clone(&primary), Arc::clone(&replica));
    wait_for(|| p.members().len() == 1 && r.members().len() == 1).await;
    let seen_by_primary = &primary.members()[0];
    assert_eq!(seen_by_primary.node_id, replica.identity.meta.node_id);
    assert_eq!(seen_by_primary.site, "pi");
    assert_eq!(seen_by_primary.via, "inbound");
    let seen_by_replica = &replica.members()[0];
    assert_eq!(seen_by_replica.node_id, primary.identity.meta.node_id);
    assert!(seen_by_replica.primary);
    assert!(seen_by_replica.up(now_ms()));
    let _ = stop_tx.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn clu_001_a_token_for_another_ca_is_refused_before_the_secret_is_sent() {
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let addr = free_port().await;
    let url = format!("https://{addr}");
    let real = Identity::init(a.path(), "real", vec![url.clone()], "k8s").unwrap();
    let other = Identity::init(b.path(), "other", vec![url.clone()], "k8s").unwrap();
    // A token from `other` pointed at `real`'s address: the CA pin fails in the handshake.
    let token = other.create_token(600, Some(vec![url.clone()])).unwrap();
    let (_stop_tx, stop) = watch::channel(false);
    tokio::spawn(serve(Cluster::new(real, "0.1.0"), addr, stop));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let key = pki::new_node_key().unwrap();
    let req = JoinRequest {
        secret: token.secret.clone(),
        csr_pem: key.csr_pem,
        advertise: vec![],
        site: "x".into(),
        eligible: false,
        version: "0.1.0".into(),
    };
    let err = join(&token, &req).await.unwrap_err();
    assert!(err.contains("doesn't match the join token"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn clu_001_streams_need_a_cluster_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let addr = free_port().await;
    let url = format!("https://{addr}");
    let id = Identity::init(dir.path(), "home", vec![url.clone()], "k8s").unwrap();
    let token = id.create_token(600, Some(vec![url.clone()])).unwrap();
    let (_stop_tx, stop) = watch::channel(false);
    tokio::spawn(serve(Cluster::new(id, "0.1.0"), addr, stop));
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Connect with the join-time TLS (CA pinned, no client certificate) and ask for a stream.
    let mut fp = [0u8; 32];
    for (i, b) in fp.iter_mut().enumerate() {
        *b = u8::from_str_radix(&token.ca_fp[i * 2..i * 2 + 2], 16).unwrap();
    }
    let p = provider();
    let mut cfg = ClientConfig::builder_with_provider(Arc::clone(&p))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCa { fp, provider: p }))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tls = tls_connect(&url, Arc::new(cfg)).await.unwrap();
    let (mut send, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    let r = send
        .send_request(
            Request::post(format!("https://{CLUSTER_NAME}/cluster/v1/stream"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn clu_001_cluster_urls_default_to_port_8443() {
    assert_eq!(authority("https://10.0.0.1").unwrap(), "10.0.0.1:8443");
    assert_eq!(authority("https://pi.lan:9443/x").unwrap(), "pi.lan:9443");
    assert_eq!(authority("[fd00::1]").unwrap(), "[fd00::1]:8443");
    assert!(authority("https://").is_err());
}
