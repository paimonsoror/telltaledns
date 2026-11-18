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

/// [`wait_for`] for a test with several waits: the panic says which one timed out.
async fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("not met in time: {what}");
}

// REQ: CLU-009 — resolver pods join with the shared bootstrap secret: they trust the CA only
// after the primary proves it knows the secret, join as ephemeral members, and leave the
// registry once they're gone for the TTL.
#[tokio::test(flavor = "multi_thread")]
async fn clu_009_bootstrap_secret_joins_ephemeral_members_that_expire() {
    let (pdir, rdir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let addr = free_port().await;
    let url = format!("https://{addr}");
    let primary = Identity::init(pdir.path(), "home", vec![url.clone()], "k8s").unwrap();
    let primary = Cluster::new(primary, "0.1.0");
    primary.set_bootstrap_secret("s3cret-shared-by-helm".into());
    let (stop_tx, stop) = watch::channel(false);
    tokio::spawn(serve(Arc::clone(&primary), addr, stop.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The wrong secret: the primary's proof doesn't match, so its CA isn't trusted.
    let e = bootstrap_token(&url, "guess").await.unwrap_err();
    assert!(e.contains("didn't prove"), "{e}");
    let token = bootstrap_token(&url, "s3cret-shared-by-helm")
        .await
        .unwrap();
    assert_eq!(
        token.ca_fp,
        pki::hex(&pki::fingerprint(&primary.identity.ca_pem).unwrap())
    );

    let key = pki::new_node_key().unwrap();
    let req = JoinRequest {
        witness: false,
        ephemeral: true,
        secret: token.secret.clone(),
        csr_pem: key.csr_pem.clone(),
        advertise: vec![],
        site: "k8s".into(),
        eligible: true,
        version: "0.1.0".into(),
    };
    let resp = join(&token, &req).await.unwrap();
    let pod =
        Identity::save_joined(rdir.path(), &key.key_pem, &resp, "k8s", false, vec![]).unwrap();
    let rec = primary
        .identity
        .registry()
        .into_iter()
        .find(|n| n.node_id == pod.meta.node_id)
        .unwrap();
    assert!(rec.ephemeral && !rec.eligible && !rec.voter(), "{rec:?}");

    // A second pod joins but never connects (it died at once).
    let key2 = pki::new_node_key().unwrap();
    let mut req2 = req.clone();
    req2.csr_pem = key2.csr_pem.clone();
    let ghost = join(&token, &req2).await.unwrap().node_id;
    // The connected pod stays; the one never heard from goes once the TTL passes.
    let pod = Cluster::new(pod, "0.1.0");
    let (pod_stop_tx, pod_stop) = watch::channel(false);
    tokio::spawn(dial(Arc::clone(&pod), pod_stop));
    let p = Arc::clone(&primary);
    wait_for(|| p.members().iter().any(|m| m.connected)).await;
    assert_eq!(primary.gc_ephemeral(Duration::ZERO), vec![ghost.clone()]);
    let ids: Vec<String> = primary
        .identity
        .registry()
        .into_iter()
        .map(|n| n.node_id)
        .collect();
    assert!(ids.contains(&pod.identity.meta.node_id) && !ids.contains(&ghost));
    // Within the TTL, nothing goes.
    assert_eq!(primary.gc_ephemeral(Duration::from_secs(600)).len(), 0);
    let _ = pod_stop_tx.send(true);
    let _ = stop_tx.send(true);
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)] // one scenario: join, stream, RPCs, renewal
async fn clu_001_join_then_mutual_stream_registers_both_peers() {
    let (pdir, rdir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let addr = free_port().await;
    let url = format!("https://{addr}");

    let primary = Identity::init(pdir.path(), "home", vec![url.clone()], "k8s").unwrap();
    let token = primary
        .create_token_for(
            600,
            Some(vec![url.clone()]),
            crate::node::TokenGrants {
                eligible: true,
                witness: false,
            },
        )
        .unwrap();
    let primary = Cluster::new(primary, "0.1.0");
    let (stop_tx, stop) = watch::channel(false);
    tokio::spawn(serve(Arc::clone(&primary), addr, stop.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The replica joins: the token pins the CA; the secret earns a certificate.
    let key = pki::new_node_key().unwrap();
    let req = JoinRequest {
        witness: false,
        ephemeral: false,
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
    tokio::spawn(dial(Arc::clone(&replica), stop.clone()));
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

    // CLU-002 — federated reads ride the same stream, both ways.
    let echo: RpcHandler = Arc::new(|_peer, kind, body| {
        Box::pin(async move {
            if kind == "fail" {
                return Err("asked to fail".to_owned());
            }
            let mut b = body;
            b.extend_from_slice(b"!");
            Ok(b)
        })
    });
    // The primary also signs certificate renewals (T5.4c, below).
    let (p, e) = (Arc::clone(&primary), Arc::clone(&echo));
    primary.set_rpc_handler(Arc::new(move |peer, kind, body| {
        if kind == crate::renew::KIND {
            let p = Arc::clone(&p);
            return Box::pin(async move { crate::renew::answer(&p, &peer, &body) });
        }
        e(peer, kind, body)
    }));
    replica.set_rpc_handler(echo);
    let pid = primary.identity.meta.node_id.clone();
    let rid = replica.identity.meta.node_id.clone();
    let p = Arc::clone(&primary);
    wait_for(|| p.reachable_peers().contains(&rid)).await;
    let t = Duration::from_secs(2);
    assert_eq!(
        replica.call(&pid, "echo", b"hi".to_vec(), t).await.unwrap(),
        b"hi!"
    );
    assert_eq!(
        primary.call(&rid, "echo", b"yo".to_vec(), t).await.unwrap(),
        b"yo!"
    );
    assert_eq!(
        primary.call(&rid, "fail", vec![], t).await.unwrap_err(),
        "asked to fail"
    );
    assert!(
        primary
            .call("nobody", "echo", vec![], t)
            .await
            .unwrap_err()
            .contains("no stream")
    );
    let all = primary.call_all("echo", b"x", t).await;
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].1.as_deref().unwrap(), b"x!");

    // REQ: CLU-001 (T5.4c) — certificate renewal. The primary answers `cert.renew` for the
    // asking peer only; the replica keeps its key and node ID and gets a fresh certificate.
    // The replica is eligible and holds the cluster key; set it aside so it must ask.
    let rdir = replica.identity.dir.clone();
    let key = rdir.join("ca.key");
    let had_key = key.exists();
    if had_key {
        std::fs::rename(&key, rdir.join("ca.key.aside")).unwrap();
    }
    let before = replica.identity.reload().cert_pem;
    std::thread::sleep(Duration::from_millis(1100)); // a later notBefore
    crate::renew::renew_now(&replica).await.unwrap();
    if had_key {
        std::fs::rename(rdir.join("ca.key.aside"), &key).unwrap();
    }
    let after = replica.identity.reload();
    assert!(
        primary.events().iter().any(|e| e.kind == "cert_issued"),
        "the primary signed it"
    );
    assert_ne!(after.cert_pem, before, "a new certificate");
    assert_eq!(after.meta.node_id, rid, "same node ID");
    crate::pki::verify_issued(&after.cert_pem, &after.ca_pem).unwrap();
    assert_eq!(replica.cert_generation(), 1);
    assert!(!crate::renew::due(&after.cert_pem));
    // Someone else's CSR is refused: the certificate names come from the asking peer.
    let csr = crate::pki::csr_for(&after.key_pem).unwrap();
    assert!(crate::renew::answer(&primary, "0123456789abcdef", csr.as_bytes()).is_err());
    // The primary (it holds the key) renews itself.
    crate::renew::renew_now(&primary).await.unwrap();
    // A forged certificate (another CA) fails verification.
    let other = crate::pki::new_ca("other").unwrap();
    assert!(crate::pki::verify_issued(&other.cert_pem, &after.ca_pem).is_err());
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
        witness: false,
        ephemeral: false,
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

/// A TCP proxy that delays every byte by `one_way` in each direction (latency without a
/// bandwidth cap): a simulated WAN for the CLU-003 propagation test.
async fn delay_proxy(to: SocketAddr, one_way: Duration) -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let Ok(server) = TcpStream::connect(to).await else {
                    return;
                };
                let (cr, cw) = client.into_split();
                let (sr, sw) = server.into_split();
                for (mut r, mut w) in [
                    (
                        Box::new(cr) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                        Box::new(sw) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                    ),
                    (Box::new(sr), Box::new(cw)),
                ] {
                    let (tx, mut rx) =
                        tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 64 * 1024];
                        loop {
                            match r.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => {
                                    if tx
                                        .send((
                                            tokio::time::Instant::now() + one_way,
                                            buf[..n].to_vec(),
                                        ))
                                        .is_err()
                                    {
                                        return;
                                    }
                                }
                            }
                        }
                    });
                    tokio::spawn(async move {
                        while let Some((at, data)) = rx.recv().await {
                            tokio::time::sleep_until(at).await;
                            if w.write_all(&data).await.is_err() {
                                return;
                            }
                        }
                        let _ = w.shutdown().await;
                    });
                }
            });
        }
    });
    addr
}

fn random_blob(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| {
            u8::try_from(i % 251)
                .unwrap_or(0)
                .wrapping_mul(31)
                .wrapping_add(seed)
        })
        .collect()
}

/// Publishes `config` + `shards` as manifest `seq`, signed with the CA key in `dir`.
fn publish(primary: &Cluster, dir: &std::path::Path, seq: u64, config: &[u8], shards: &[Vec<u8>]) {
    use crate::sync::{FilterRef, blob_ref};
    let ca_key = std::fs::read_to_string(crate::node::dir_of(dir).join("ca.key")).unwrap();
    let mut blobs = HashMap::new();
    let config_ref = blob_ref("config.json", config);
    blobs.insert(
        config_ref.hash.clone(),
        BlobSource::Bytes(Bytes::from(config.to_vec())),
    );
    let mut refs = Vec::new();
    for (i, s) in shards.iter().enumerate() {
        let r = blob_ref(&format!("subtree-{i}.fst"), s);
        blobs.insert(r.hash.clone(), BlobSource::Bytes(Bytes::from(s.clone())));
        refs.push(r);
    }
    let m = ClusterManifest {
        cluster_id: primary.identity.meta.cluster_id.clone(),
        epoch: 1,
        seq,
        created_ms: now_ms(),
        primary: primary.identity.meta.node_id.clone(),
        config: config_ref,
        filter: Some(FilterRef {
            version: seq,
            blobs: refs,
        }),
        ..ClusterManifest::default()
    };
    primary.publish(Signed::sign(&m, &ca_key).unwrap(), blobs);
}

// REQ: CLU-003 (T5.2 AC) — a list change ships only the changed blobs, and propagation is
// ≤ 5 s p95 across a simulated WAN (50 ms RTT).
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)] // one scenario, start to finish
async fn clu_003_replicas_fetch_only_changed_blobs_and_converge_fast_over_a_wan() {
    let (pdir, rdir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let addr = free_port().await;
    let wan = delay_proxy(addr, Duration::from_millis(25)).await;
    let url = format!("https://{wan}");
    let primary_id = Identity::init(pdir.path(), "home", vec![url.clone()], "home-pi").unwrap();
    let token = primary_id
        .create_token_for(
            600,
            None,
            crate::node::TokenGrants {
                eligible: true,
                witness: false,
            },
        )
        .unwrap();
    let primary = Cluster::new(primary_id, "0.1.0");
    let (stop_tx, stop) = watch::channel(false);
    tokio::spawn(serve(Arc::clone(&primary), addr, stop.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let key = pki::new_node_key().unwrap();
    let req = JoinRequest {
        witness: false,
        ephemeral: false,
        secret: token.secret.clone(),
        csr_pem: key.csr_pem.clone(),
        advertise: vec![],
        site: "k8s".into(),
        eligible: true,
        version: "0.1.0".into(),
    };
    let resp = join(&token, &req).await.unwrap();
    let replica_id =
        Identity::save_joined(rdir.path(), &key.key_pem, &resp, "k8s", true, vec![]).unwrap();
    let replica = Cluster::new(replica_id, "0.1.0");
    let store = BlobStore::open(rdir.path()).unwrap();

    // What the replica applied: (seq, config bytes, fetched blobs, when).
    let applied = Arc::new(Mutex::new(
        Vec::<(u64, Vec<u8>, usize, tokio::time::Instant)>::new(),
    ));
    {
        let (applied, store2) = (Arc::clone(&applied), store.clone());
        tokio::spawn(follow(
            Arc::clone(&replica),
            store.clone(),
            (0, 0),
            move |m| {
                let (applied, store) = (Arc::clone(&applied), store2.clone());
                async move {
                    let config = store.read(&m.config)?;
                    applied
                        .lock()
                        .unwrap()
                        .push((m.seq, config, 0, tokio::time::Instant::now()));
                    Ok(())
                }
            },
            stop.clone(),
        ));
    }
    tokio::spawn(dial(Arc::clone(&replica), stop.clone()));

    // Manifest 1: config + 8 shards of 512 KiB, all fetched.
    let mut shards: Vec<Vec<u8>> = (0..8).map(|i| random_blob(512 * 1024, i)).collect();
    publish(&primary, pdir.path(), 1, b"{\"v\":1}", &shards);
    for _ in 0..200 {
        if applied.lock().unwrap().iter().any(|x| x.0 == 1) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        applied.lock().unwrap().iter().any(|x| x.0 == 1),
        "not applied: {:?}; connected {:?}; members {}",
        replica.sync_status(),
        replica.connected_primary(),
        replica.members().len()
    );
    assert_eq!(replica.sync_status().fetched, 9);

    // Manifest 2: one shard changes; only it is fetched.
    shards[3] = random_blob(512 * 1024, 99);
    publish(&primary, pdir.path(), 2, b"{\"v\":1}", &shards);
    let a = Arc::clone(&applied);
    wait_for(|| a.lock().unwrap().iter().any(|x| x.0 == 2)).await;
    assert_eq!(
        replica.sync_status().fetched,
        1,
        "a list change ships only the changed blob"
    );
    // The primary's heartbeats learn what the replica applied.
    let p = Arc::clone(&primary);
    wait_for(|| p.members().first().is_some_and(|m| m.applied_seq == 2)).await;

    // 20 config changes over the 50 ms RTT link: p95 propagation ≤ 5 s.
    let mut times = Vec::new();
    for seq in 3..23u64 {
        let config = format!("{{\"v\":{seq}}}");
        let t0 = tokio::time::Instant::now();
        publish(&primary, pdir.path(), seq, config.as_bytes(), &shards);
        let a = Arc::clone(&applied);
        let mut done = None;
        for _ in 0..400 {
            if let Some(x) = a.lock().unwrap().iter().find(|x| x.0 == seq) {
                done = Some(x.3);
                assert_eq!(x.1, config.as_bytes());
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        times.push(
            done.expect("change never arrived")
                .saturating_duration_since(t0),
        );
    }
    times.sort();
    let p95 = times[(times.len() * 95).div_ceil(100) - 1];
    eprintln!(
        "propagation over 50 ms RTT: p50 {:?}, p95 {p95:?}",
        times[times.len() / 2]
    );
    assert!(p95 <= Duration::from_secs(5), "p95 {p95:?}");
    assert!(replica.sync_status().error.is_none());
    // CLU-008 — the round-trip time comes from heartbeat echoes (the proxy adds 50 ms), and the
    // timeline has the connection and the applies.
    let p = Arc::clone(&primary);
    wait_for(|| p.members().first().and_then(|m| m.rtt_ms).is_some()).await;
    let rtt = primary.members()[0].rtt_ms.unwrap();
    // At least the proxy's 50 ms. A first echo can queue behind a blob transfer on the same
    // stream, so the upper bound is loose.
    assert!((50..10_000).contains(&rtt), "rtt {rtt} ms");
    assert!(primary.members()[0].connected);
    let kinds: Vec<&str> = replica.events().iter().map(|e| e.kind).collect();
    assert!(
        kinds.contains(&"connected") && kinds.contains(&"applied"),
        "{kinds:?}"
    );
    assert!(primary.events().iter().any(|e| e.kind == "joined"));
    assert_eq!(replica.newest_seq(), 22);
    assert!(replica.behind_since().is_none());
    let _ = stop_tx.send(true);
}

// REQ: CLU-003 — a manifest that isn't signed by the cluster CA is ignored.
#[tokio::test(flavor = "multi_thread")]
async fn clu_003_unsigned_manifests_are_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::init(dir.path(), "home", vec!["https://127.0.0.1:1".into()], "x").unwrap();
    let node = Cluster::new(id, "0.1.0");
    let other = pki::new_ca("evil").unwrap();
    let m = ClusterManifest {
        cluster_id: node.identity.meta.cluster_id.clone(),
        epoch: 1,
        seq: 1,
        created_ms: 0,
        primary: "x".into(),
        config: crate::sync::blob_ref("config.json", b"{}"),
        filter: None,
        ..ClusterManifest::default()
    };
    let applied = Arc::new(Mutex::new(0));
    let (stop_tx, stop) = watch::channel(false);
    let a = Arc::clone(&applied);
    tokio::spawn(follow(
        Arc::clone(&node),
        BlobStore::open(dir.path()).unwrap(),
        (0, 0),
        move |_| {
            let a = Arc::clone(&a);
            async move {
                *a.lock().unwrap() += 1;
                Ok(())
            }
        },
        stop,
    ));
    node.incoming
        .send_replace(Some(Arc::new(Signed::sign(&m, &other.key_pem).unwrap())));
    let n = Arc::clone(&node);
    wait_for(|| n.sync_status().error.is_some()).await;
    assert_eq!(*applied.lock().unwrap(), 0);
    let _ = stop_tx.send(true);
}

// REQ: CLU-005 (ADR-051) — a primary that's fenced (stepped down to a newer epoch) can't
// publish any more, least of all in the new primary's epoch; before that, it publishes as usual.
#[test]
fn clu_005_a_fenced_primary_never_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::init(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "k8s",
    )
    .unwrap();
    let c = Cluster::new(id, "0.1.0");
    let (role, epoch) = c.role();
    assert_eq!(role, Role::Primary);
    let signed = || crate::sync::Signed {
        json: b"{}".to_vec(),
        sig: Vec::new(),
    };
    assert!(c.publish_as(epoch, signed(), HashMap::new()));
    assert!(c.published().is_some());
    // A newer primary appears: this node steps down.
    c.set_role(Role::Replica, epoch + 1).unwrap();
    assert!(
        !c.publish_as(epoch, signed(), HashMap::new()),
        "old epoch: fenced"
    );
    assert!(
        !c.publish_as(epoch + 1, signed(), HashMap::new()),
        "the new epoch isn't this node's to publish in"
    );
}

// REQ: CLU-013 (ADR-116) — two heads: a canary version reaches only its peers (every send
// path asks `head_for`), everyone else and an unknown peer get the stable one; a new stable
// publish ends the canary head; a fenced node can't start one.
#[test]
fn clu_013_the_canary_head_reaches_only_its_peers() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::init(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "k8s",
    )
    .unwrap();
    let c = Cluster::new(id, "0.1.0");
    let (_, epoch) = c.role();
    let signed = |v: &str| crate::sync::Signed {
        json: v.as_bytes().to_vec(),
        sig: Vec::new(),
    };
    assert!(c.publish_as(epoch, signed("stable"), HashMap::new()));
    assert!(c.canary().is_none());
    let peers: std::collections::BTreeSet<String> = ["pod-a".to_owned()].into();
    let mut blobs = HashMap::new();
    blobs.insert("h".repeat(64), BlobSource::Bytes(Bytes::from_static(b"x")));
    assert!(c.publish_canary_as(epoch, signed("canary"), peers, blobs));
    let json = |s: Option<Arc<Signed>>| String::from_utf8(s.unwrap().json.clone()).unwrap();
    assert_eq!(json(c.head_for(Some("pod-a"))), "canary");
    assert_eq!(json(c.head_for(Some("pi"))), "stable", "a non-canary peer");
    assert_eq!(json(c.head_for(None)), "stable", "an unknown peer");
    assert_eq!(json(c.published()), "stable");
    assert!(
        c.served.lock().unwrap().contains_key(&"h".repeat(64)),
        "canary blobs served"
    );
    // Promotion (or a pin) publishes a new stable head: the canary head ends.
    assert!(c.publish_as(epoch, signed("next"), HashMap::new()));
    assert!(c.canary().is_none());
    assert_eq!(json(c.head_for(Some("pod-a"))), "next");
    c.set_role(Role::Replica, epoch + 1).unwrap();
    assert!(!c.publish_canary_as(
        epoch,
        signed("late"),
        ["pod-a".into()].into(),
        HashMap::new()
    ));
}

// REQ: CLU-009 — a resolver pod shutting down leaves at once (no "down" member until it
// expires); a member that isn't ephemeral can't be removed that way. A pod that dies without
// leaving still expires as before (see the test above).
#[tokio::test(flavor = "multi_thread")]
async fn clu_009_a_pod_that_shuts_down_leaves_at_once() {
    let (pdir, rdir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let addr = free_port().await;
    let url = format!("https://{addr}");
    let primary = Identity::init(pdir.path(), "home", vec![url.clone()], "k8s").unwrap();
    let primary = Cluster::new(primary, "0.1.0");
    primary.set_bootstrap_secret("s3cret-shared-by-helm".into());
    let (stop_tx, stop) = watch::channel(false);
    tokio::spawn(serve(Arc::clone(&primary), addr, stop.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let token = bootstrap_token(&url, "s3cret-shared-by-helm")
        .await
        .unwrap();
    let key = pki::new_node_key().unwrap();
    let req = JoinRequest {
        witness: false,
        ephemeral: true,
        secret: token.secret.clone(),
        csr_pem: key.csr_pem.clone(),
        advertise: vec![],
        site: "k8s".into(),
        eligible: false,
        version: "0.1.0".into(),
    };
    let resp = join(&token, &req).await.unwrap();
    let pod =
        Identity::save_joined(rdir.path(), &key.key_pem, &resp, "k8s", false, vec![]).unwrap();
    let pod = Cluster::new(pod, "0.1.0");
    let id = pod.identity.meta.node_id.clone();
    let (pod_stop_tx, pod_stop) = watch::channel(false);
    tokio::spawn(dial(Arc::clone(&pod), pod_stop));
    let (p, q) = (Arc::clone(&primary), Arc::clone(&pod));
    wait_for(|| p.members().iter().any(|m| m.connected)).await;
    wait_for(|| q.reachable_primary().is_some()).await;

    pod.leave(Duration::from_secs(2)).await.unwrap();
    assert!(
        !primary.members().iter().any(|m| m.node_id == id),
        "gone from the members"
    );
    assert!(
        !primary.identity.registry().iter().any(|n| n.node_id == id),
        "gone from the registry"
    );
    assert!(
        primary
            .events()
            .iter()
            .any(|e| e.kind == "left" && e.node == id)
    );

    // The primary itself (not ephemeral) can't be removed that way.
    let me = primary.identity.meta.node_id.clone();
    assert!(primary.remove_ephemeral(&me).is_err());

    let _ = pod_stop_tx.send(true);
    let _ = stop_tx.send(true);
}

// REQ: CLU-002, CLU-009 — a pod that left isn't a reachable peer any more. Otherwise every
// federated read asked it, timed out, and the dashboard said "<node id> didn't answer".
#[tokio::test(flavor = "multi_thread")]
async fn clu_002_a_pod_that_left_is_not_asked_by_federated_reads() {
    let (pdir, rdir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let addr = free_port().await;
    let url = format!("https://{addr}");
    let primary = Identity::init(pdir.path(), "home", vec![url.clone()], "k8s").unwrap();
    let primary = Cluster::new(primary, "0.1.0");
    primary.set_bootstrap_secret("s3cret-shared-by-helm".into());
    let (stop_tx, stop) = watch::channel(false);
    tokio::spawn(serve(Arc::clone(&primary), addr, stop.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let token = bootstrap_token(&url, "s3cret-shared-by-helm")
        .await
        .unwrap();
    let key = pki::new_node_key().unwrap();
    let req = JoinRequest {
        witness: false,
        ephemeral: true,
        secret: token.secret.clone(),
        csr_pem: key.csr_pem.clone(),
        advertise: vec![],
        site: "k8s".into(),
        eligible: false,
        version: "0.1.0".into(),
    };
    let resp = join(&token, &req).await.unwrap();
    let pod =
        Identity::save_joined(rdir.path(), &key.key_pem, &resp, "k8s", false, vec![]).unwrap();
    let pod = Cluster::new(pod, "0.1.0");
    let id = pod.identity.meta.node_id.clone();
    let (pod_stop_tx, pod_stop) = watch::channel(false);
    tokio::spawn(dial(Arc::clone(&pod), pod_stop));
    let (p, q) = (Arc::clone(&primary), Arc::clone(&pod));
    wait_for(|| p.reachable_peers().contains(&id)).await;
    wait_for(|| q.reachable_primary().is_some()).await;

    pod.leave(Duration::from_secs(2)).await.unwrap();
    assert!(
        !primary.reachable_peers().contains(&id),
        "a pod that left is still listed as a reachable peer"
    );
    let _ = pod_stop_tx.send(true);
    let _ = stop_tx.send(true);
}

// REQ: CLU-001, CLU-009 (ADR-051, ADR-058) — a member decides nothing about its own standing:
// a join with the shared bootstrap secret is an ephemeral member whatever it asks for, and a
// Hello can't make a known member eligible, so the cluster key is never shared on a peer's
// say-so. A join token may still bring an eligible node, which then gets the key.
#[test]
fn clu_009_a_bootstrap_join_or_a_hello_cannot_claim_eligibility() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::init(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "k8s",
    )
    .unwrap();
    let primary = Cluster::new(id, "0.1.0");
    let key = pki::new_node_key().unwrap();
    let req = JoinRequest {
        witness: true,
        ephemeral: false,
        secret: "s3cret".into(),
        csr_pem: key.csr_pem.clone(),
        advertise: vec![],
        site: "k8s".into(),
        eligible: true,
        version: "0.1.0".into(),
    };
    let resp = primary.identity.accept_join(&req, Some("s3cret")).unwrap();
    let record = |id: &str| {
        primary
            .identity
            .registry()
            .into_iter()
            .find(|n| n.node_id == id)
            .unwrap()
    };
    let rec = record(&resp.node_id);
    assert!(
        rec.ephemeral && !rec.eligible && !rec.witness && !rec.voter(),
        "a bootstrap join is ephemeral: {rec:?}"
    );
    // Its Hello claims eligibility: the registry keeps what the join decided, and no key
    // share is due.
    let mut peer = Some(resp.node_id.clone());
    let hello = Frame {
        body: Some(Body::Hello(Hello {
            protocol: PROTOCOL,
            cluster_id: primary.identity.meta.cluster_id.clone(),
            node_id: resp.node_id.clone(),
            version: "0.1.0".into(),
            site: "k8s".into(),
            eligible: true,
            advertise: vec![],
            epoch: 1,
            applied_seq: 0,
            primary: false,
            config_source: String::new(),
            source_commit: String::new(),
        })),
    };
    primary
        .on_frame(&mut peer, hello, "inbound", &EchoSlot::default())
        .unwrap();
    assert!(
        !record(&resp.node_id).eligible,
        "a Hello can't raise eligibility"
    );
    assert!(primary.key_share_for(&resp.node_id).is_none());
    // An eligible token may bring an eligible node, and then the key share is due.
    let token = primary
        .identity
        .create_token_for(
            60,
            None,
            crate::node::TokenGrants {
                eligible: true,
                witness: false,
            },
        )
        .unwrap();
    let key2 = pki::new_node_key().unwrap();
    let req2 = JoinRequest {
        witness: false,
        ephemeral: false,
        secret: token.secret,
        csr_pem: key2.csr_pem,
        advertise: vec![],
        site: "pi".into(),
        eligible: true,
        version: "0.1.0".into(),
    };
    let resp2 = primary.identity.accept_join(&req2, Some("s3cret")).unwrap();
    assert!(record(&resp2.node_id).eligible && !record(&resp2.node_id).ephemeral);
    assert!(primary.key_share_for(&resp2.node_id).is_some());
}

// REQ: CLU-005 (ADR-051) — a newer epoch in a Hello or heartbeat fences the primary only when
// it comes from a voter: an ephemeral member's frames (unsigned, from a resolver pod that
// could be compromised) never demote it.
#[test]
fn clu_005_only_voters_can_fence_the_primary() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::init(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "k8s",
    )
    .unwrap();
    let primary = Cluster::new(id, "0.1.0");
    let join = |eligible: bool, ephemeral: bool, site: &str| {
        let key = pki::new_node_key().unwrap();
        let grants = crate::node::TokenGrants {
            eligible,
            witness: false,
        };
        let token = primary.identity.create_token_for(60, None, grants).unwrap();
        primary
            .identity
            .accept_join(
                &JoinRequest {
                    witness: false,
                    ephemeral,
                    secret: token.secret,
                    csr_pem: key.csr_pem,
                    advertise: vec![],
                    site: site.into(),
                    eligible,
                    version: "0.1.0".into(),
                },
                None,
            )
            .unwrap()
            .node_id
    };
    let pod = join(false, true, "k8s");
    let pi = join(true, false, "pi");
    let hello = |node_id: &str, epoch: u64, eligible: bool| Frame {
        body: Some(Body::Hello(Hello {
            protocol: PROTOCOL,
            cluster_id: primary.identity.meta.cluster_id.clone(),
            node_id: node_id.to_owned(),
            version: "0.1.0".into(),
            site: "x".into(),
            eligible,
            advertise: vec![],
            epoch,
            applied_seq: 0,
            primary: true,
            config_source: String::new(),
            source_commit: String::new(),
        })),
    };
    let heartbeat = |epoch: u64| Frame {
        body: Some(Body::Heartbeat(Heartbeat {
            ts_ms: 1,
            epoch,
            ..Heartbeat::default()
        })),
    };
    assert_eq!(primary.role(), (Role::Primary, 1));
    let echo = EchoSlot::default();
    // The pod claims to be the primary of epoch 99: ignored.
    let mut peer = Some(pod.clone());
    primary
        .on_frame(&mut peer, hello(&pod, 99, false), "inbound", &echo)
        .unwrap();
    primary
        .on_frame(&mut peer, heartbeat(100), "inbound", &echo)
        .unwrap();
    assert_eq!(
        primary.role(),
        (Role::Primary, 1),
        "a pod can't fence the primary"
    );
    // Claiming eligibility in the same Hello doesn't make it a voter first (review 05-01).
    primary
        .on_frame(&mut peer, hello(&pod, 101, true), "inbound", &echo)
        .unwrap();
    assert_eq!(
        primary.role(),
        (Role::Primary, 1),
        "nor by claiming to be eligible"
    );
    assert!(primary.is_primary());
    // REQ: CLU-005 — an old primary's key (it came back before it learned the newer epoch)
    // is refused without ending the stream: the frame is ignored, nothing is stored.
    let mut peer = Some(pi.clone());
    primary
        .on_frame(&mut peer, hello(&pi, 0, true), "inbound", &echo)
        .unwrap();
    let key = Frame {
        body: Some(Body::KeyShare(crate::wire::KeyShare {
            ca_key_pem: "not a key".into(),
            next_ca_key_pem: String::new(),
        })),
    };
    assert_eq!(primary.on_frame(&mut peer, key, "inbound", &echo), Ok(()));
    // An eligible node announcing epoch 2 (it was promoted): fenced.
    primary
        .on_frame(&mut peer, hello(&pi, 2, false), "inbound", &echo)
        .unwrap();
    assert_eq!(primary.role(), (Role::Replica, 2));
}

// REQ: CLU-001 (review 05-07) — join tokens are listed by ID (never the secret) and can be
// revoked before they expire; a revoked token no longer joins.
#[test]
fn clu_001_join_tokens_can_be_listed_and_revoked() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::init(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "k8s",
    )
    .unwrap();
    let a = id.create_token(600, None).unwrap();
    let b = id.create_token(60, None).unwrap();
    let id_of = |t: &crate::token::Token| {
        crate::node::token_id(&crate::token::Token::secret_hash(&t.secret)).to_owned()
    };
    let listed: Vec<String> = id.tokens().into_iter().map(|(t, _, _)| t).collect();
    assert_eq!(
        listed,
        vec![id_of(&b), id_of(&a)],
        "soonest to expire first"
    );
    assert!(listed.iter().all(|t| !a.secret.contains(t.as_str())));
    assert!(id.revoke_token("abc").is_err(), "too short to be safe");
    assert_eq!(id.revoke_token(&id_of(&a)).unwrap(), 1);
    assert_eq!(id.revoke_token(&id_of(&a)).unwrap(), 0, "already gone");
    assert_eq!(id.tokens().len(), 1);
    let join = |secret: String| JoinRequest {
        witness: false,
        ephemeral: false,
        secret,
        csr_pem: pki::new_node_key().unwrap().csr_pem,
        advertise: vec![],
        site: "pi".into(),
        eligible: false,
        version: "0.1.0".into(),
    };
    assert!(
        id.accept_join(&join(a.secret.clone()), None).is_err(),
        "revoked"
    );
    assert!(id.accept_join(&join(b.secret.clone()), None).is_ok());
}

// REQ: CLU-001 (review 05 q1, ADR-051) — a join token says what it may bring: a plain one
// brings a plain member, never an eligible node (which would get the cluster key) or a witness.
#[test]
fn clu_001_a_plain_join_token_brings_a_plain_member() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::init(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "k8s",
    )
    .unwrap();
    let primary = Cluster::new(id, "0.1.0");
    let plain = primary.identity.create_token(60, None).unwrap();
    let asks_eligible = |secret: String| JoinRequest {
        witness: false,
        ephemeral: false,
        secret,
        csr_pem: pki::new_node_key().unwrap().csr_pem,
        advertise: vec![],
        site: "pi".into(),
        eligible: true,
        version: "0.1.0".into(),
    };
    let e = primary
        .identity
        .accept_join(&asks_eligible(plain.secret.clone()), Some("s3cret"))
        .unwrap_err();
    assert!(e.contains("--eligible"), "{e}");
    let mut as_witness = asks_eligible(plain.secret);
    as_witness.witness = true;
    assert!(
        primary
            .identity
            .accept_join(&as_witness, None)
            .unwrap_err()
            .contains("--witness")
    );
    let mut plain_member = asks_eligible(primary.identity.create_token(60, None).unwrap().secret);
    plain_member.eligible = false;
    assert!(primary.identity.accept_join(&plain_member, None).is_ok());
}

// REQ: CLU-013 — a node running a canary version counts as at the stable version it would
// replace, so the nodes waiting out the bake aren't behind; without a canary version it's at
// its applied version.
#[test]
fn clu_013_lag_counts_stable_versions_only() {
    assert_eq!(stable_seq(8, 7), 7, "a canary of 7 running 8");
    assert_eq!(stable_seq(8, 0), 8);
    // Plain replicas at 7, a canary and the primary at 8 (of 7): nobody is behind.
    let newest = [stable_seq(7, 0), stable_seq(8, 7), stable_seq(8, 7)]
        .into_iter()
        .max()
        .unwrap();
    assert_eq!(newest, 7);
    // A replica still at 6 is.
    assert!(stable_seq(6, 0) < newest);
}

// REQ: CLU-005, CLU-009 (T10.7, ADR-143) — a member the registry doesn't know (a resolver pod
// that left, or expired, and reconnected with its still-valid certificate) is trusted with
// nothing: its Hello's claim of eligibility doesn't stick, it gets no key share, its higher
// epoch doesn't fence the primary, and its vote requests are refused.
#[test]
fn clu_005_an_unknown_member_is_trusted_with_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::init(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "k8s",
    )
    .unwrap();
    let primary = Cluster::new(id, "0.1.0");
    let key = pki::new_node_key().unwrap();
    let req = JoinRequest {
        witness: false,
        ephemeral: true,
        secret: "s3cret".into(),
        csr_pem: key.csr_pem.clone(),
        advertise: vec![],
        site: "k8s".into(),
        eligible: false,
        version: "0.1.0".into(),
    };
    let resp = primary.identity.accept_join(&req, Some("s3cret")).unwrap();
    let pod = resp.node_id.clone();
    // It leaves: the registry forgets it, but its certificate still opens a stream.
    primary.remove_ephemeral(&pod).unwrap();
    assert!(!primary.identity.registry().iter().any(|n| n.node_id == pod));
    let before = primary.role();

    let mut peer = Some(pod.clone());
    let hello = Frame {
        body: Some(Body::Hello(Hello {
            protocol: PROTOCOL,
            cluster_id: primary.identity.meta.cluster_id.clone(),
            node_id: pod.clone(),
            version: "0.1.0".into(),
            site: "k8s".into(),
            eligible: true,
            advertise: vec![],
            epoch: before.1 + 50,
            applied_seq: 0,
            primary: false,
            config_source: String::new(),
            source_commit: String::new(),
        })),
    };
    primary
        .on_frame(&mut peer, hello, "inbound", &EchoSlot::default())
        .unwrap();
    let rec = primary
        .identity
        .registry()
        .into_iter()
        .find(|n| n.node_id == pod)
        .unwrap();
    assert!(
        rec.ephemeral && !rec.eligible && !rec.witness,
        "back as a plain ephemeral member: {rec:?}"
    );
    assert!(primary.key_share_for(&pod).is_none(), "no cluster key");
    assert!(!primary.may_announce_epoch(&pod));
    assert!(!primary.may_announce_epoch("never-seen"));
    assert_eq!(
        primary.role(),
        before,
        "its epoch doesn't fence the primary"
    );

    let ask = crate::election::Ask {
        epoch: before.1 + 50,
        candidate: pod.clone(),
        round: 1,
        pre: false,
        applied: Default::default(),
    };
    let err =
        crate::failover::answer(&primary, &pod, &serde_json::to_vec(&ask).unwrap()).unwrap_err();
    assert!(err.contains("eligible"), "{err}");
    assert_eq!(primary.identity.ballot().epoch, 0, "the ballot didn't move");
}

// REQ: CLU-002 (T10.7) — an RPC answer counts only on the stream of the peer that was asked:
// another member can't answer, or fail, a call made to someone else.
#[test]
fn clu_002_an_answer_counts_only_from_the_peer_asked() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::init(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "k8s",
    )
    .unwrap();
    let c = Cluster::new(id, "0.1.0");
    let (done, mut answer) = tokio::sync::oneshot::channel();
    c.pending
        .lock()
        .unwrap()
        .insert(7, ("node-a".to_owned(), done));
    let reply = |text: &str| Frame {
        body: Some(Body::RpcResponse(RpcResponse {
            id: 7,
            body: text.as_bytes().to_vec(),
            error: String::new(),
        })),
    };
    let mut other = Some("node-b".to_owned());
    c.on_frame(&mut other, reply("forged"), "inbound", &EchoSlot::default())
        .unwrap();
    assert!(answer.try_recv().is_err(), "not from node-b");
    let mut before_hello = None;
    c.on_frame(
        &mut before_hello,
        reply("forged"),
        "inbound",
        &EchoSlot::default(),
    )
    .unwrap();
    assert!(answer.try_recv().is_err(), "not before a Hello");
    let mut asked = Some("node-a".to_owned());
    c.on_frame(&mut asked, reply("real"), "inbound", &EchoSlot::default())
        .unwrap();
    assert_eq!(answer.try_recv().unwrap().unwrap(), b"real");
}

// REQ: CLU-003 (T10.7, ADR-143) — the users and tokens (password hashes, TOTP secrets) aren't
// served to a resolver pod: it fetches everything else in the manifest, and is refused that.
#[tokio::test(flavor = "multi_thread")]
async fn clu_003_users_and_tokens_are_not_served_to_pods() {
    use crate::sync::blob_ref;
    let (pdir, rdir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let addr = free_port().await;
    let url = format!("https://{addr}");
    let primary = Identity::init(pdir.path(), "home", vec![url.clone()], "k8s").unwrap();
    let primary = Cluster::new(primary, "0.1.0");
    primary.set_bootstrap_secret("s3cret-shared-by-helm".into());
    let (stop_tx, stop) = watch::channel(false);
    tokio::spawn(serve(Arc::clone(&primary), addr, stop.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let token = bootstrap_token(&url, "s3cret-shared-by-helm")
        .await
        .unwrap();
    let key = pki::new_node_key().unwrap();
    let req = JoinRequest {
        witness: false,
        ephemeral: true,
        secret: token.secret.clone(),
        csr_pem: key.csr_pem.clone(),
        advertise: vec![],
        site: "k8s".into(),
        eligible: false,
        version: "0.1.0".into(),
    };
    let resp = join(&token, &req).await.unwrap();
    let pod =
        Identity::save_joined(rdir.path(), &key.key_pem, &resp, "k8s", false, vec![]).unwrap();
    let pod = Cluster::new(pod, "0.1.0");
    let (pod_stop_tx, pod_stop) = watch::channel(false);
    tokio::spawn(dial(Arc::clone(&pod), pod_stop));
    let q = Arc::clone(&pod);
    wait_for(|| q.reachable_primary().is_some()).await;

    let ca_key = std::fs::read_to_string(crate::node::dir_of(pdir.path()).join("ca.key")).unwrap();
    let (config, users) = (b"{}".to_vec(), br#"{"users":[]}"#.to_vec());
    let (config_ref, users_ref) = (
        blob_ref("config.json", &config),
        blob_ref("identities.json", &users),
    );
    let mut blobs = HashMap::new();
    blobs.insert(
        config_ref.hash.clone(),
        BlobSource::Bytes(Bytes::from(config)),
    );
    blobs.insert(
        users_ref.hash.clone(),
        BlobSource::Bytes(Bytes::from(users)),
    );
    let m = ClusterManifest {
        cluster_id: primary.identity.meta.cluster_id.clone(),
        epoch: 1,
        seq: 1,
        created_ms: now_ms(),
        primary: primary.identity.meta.node_id.clone(),
        config: config_ref.clone(),
        identities: Some(users_ref.clone()),
        ..ClusterManifest::default()
    };
    primary.publish(Signed::sign(&m, &ca_key).unwrap(), blobs);
    assert_eq!(
        m.blobs_for(true),
        vec![&config_ref],
        "a pod doesn't ask for them"
    );
    assert_eq!(m.blobs_for(false).len(), 2);

    let store = BlobStore::open(rdir.path()).unwrap();
    assert_eq!(pod.fetch(&[config_ref], &store).await.unwrap(), 1);
    let err = pod.fetch(&[users_ref], &store).await.unwrap_err();
    assert!(err.contains("403"), "{err}");
    let _ = pod_stop_tx.send(true);
    let _ = stop_tx.send(true);
}

// REQ: CLU-001 (ADR-051; GitHub issue #4) — a replica that couldn't reach the primary and
// settled on a peer goes back to the primary once it answers. The primary advertises a URL
// that nothing answers on (like an in-cluster Service name seen from outside Kubernetes), and
// a peer replica is another candidate. The stream to that peer used to be kept for good, and
// the primary's URLs were never tried again.
#[tokio::test(flavor = "multi_thread")]
async fn clu_001_a_replica_on_a_peer_goes_back_to_the_primary() {
    replica_with_a_dead_primary_url(Start::After).await;
}

// REQ: CLU-001 (GitHub issue #43) — the same, when the primary has opened its own stream to the
// replica before it answers on its URL (the primary dials eligible nodes too). That stream
// made the replica look attached to the primary, so it stayed on the peer and fetched every
// blob from it: 404 on each new blocklist.
#[tokio::test(flavor = "multi_thread")]
async fn clu_001_a_replica_on_a_peer_goes_back_while_the_primary_dials_it() {
    replica_with_a_dead_primary_url(Start::AfterDialingIn).await;
}

// The same cluster with the primary up from the start: the dead URL is skipped and the
// replica reaches the primary at once. It keeps the test above honest: when that one fails,
// it's the return to the primary that doesn't happen, not the set-up.
#[tokio::test(flavor = "multi_thread")]
async fn clu_001_a_replica_skips_a_dead_primary_url() {
    replica_with_a_dead_primary_url(Start::First).await;
}

/// When the primary of [`replica_with_a_dead_primary_url`] comes up.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Start {
    /// Before the replica starts.
    First,
    /// After the replica has settled on the peer.
    After,
    /// After the replica has settled on the peer, and only once the primary has opened its
    /// own stream to the replica.
    AfterDialingIn,
}

/// One replica, one peer replica, and a primary whose first advertised URL is dead; `start`
/// says when the primary comes up.
#[allow(clippy::too_many_lines)] // one scenario: join, settle on the peer, go back
async fn replica_with_a_dead_primary_url(start: Start) {
    let primary_first = start == Start::First;
    let (pdir, adir, bdir) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let (p_addr, b_addr, dead) = (free_port().await, free_port().await, free_port().await);
    let (p_url, b_url) = (format!("https://{p_addr}"), format!("https://{b_addr}"));
    // Where the replica serves, for the primary's own stream to it.
    let r_addr = free_port().await;
    let primary = Identity::init(
        pdir.path(),
        "home",
        vec![format!("https://{dead}"), p_url.clone()],
        "k8s",
    )
    .unwrap();
    let token = primary
        .create_token_for(
            600,
            Some(vec![p_url.clone()]),
            crate::node::TokenGrants {
                eligible: true,
                witness: false,
            },
        )
        .unwrap();
    let join_node = |dir: &std::path::Path, site: &str, eligible: bool, advertise: Vec<String>| {
        let key = pki::new_node_key().unwrap();
        let req = JoinRequest {
            witness: false,
            ephemeral: false,
            secret: token.secret.clone(),
            csr_pem: key.csr_pem.clone(),
            advertise: advertise.clone(),
            site: site.into(),
            eligible,
            version: "0.1.0".into(),
        };
        let resp = primary.accept_join(&req, None).unwrap();
        Identity::save_joined(dir, &key.key_pem, &resp, site, eligible, advertise).unwrap()
    };
    let peer = join_node(bdir.path(), "pi", true, vec![b_url.clone()]);
    let replica = join_node(adir.path(), "lxc", false, vec![]);
    // What replication gives a replica: the registry, with the peer in it.
    replica.save_registry(&primary.registry()).unwrap();
    let (primary_id, peer_id) = (primary.meta.node_id.clone(), peer.meta.node_id.clone());

    let (peer, replica) = (Cluster::new(peer, "0.1.0"), Cluster::new(replica, "0.1.0"));
    let (stop_tx, stop) = watch::channel(false);
    tokio::spawn(serve(Arc::clone(&peer), b_addr, stop.clone()));
    tokio::spawn(serve(Arc::clone(&replica), r_addr, stop.clone()));
    let mut primary = Some(primary);
    let mut start_primary = || {
        let c = Cluster::new(primary.take().unwrap(), "0.1.0");
        if start == Start::AfterDialingIn {
            // The primary's stream to the replica comes up first; its URL answers later.
            let cfg = client_config(&c.identity.reload()).unwrap();
            let (c2, r_url) = (Arc::clone(&c), format!("https://{r_addr}"));
            tokio::spawn(async move {
                let _ = stream_once(c2, &r_url, cfg, true, Arc::new(Notify::new())).await;
            });
        }
        c
    };
    let serve_primary = |c: &Arc<Cluster>| {
        tokio::spawn(serve(Arc::clone(c), p_addr, stop.clone()));
    };
    let _primary = primary_first.then(|| {
        let c = start_primary();
        serve_primary(&c);
        c
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    tokio::spawn(dial(Arc::clone(&replica), stop.clone()));
    let connected_to = |id: String| {
        let r = Arc::clone(&replica);
        move || r.members().iter().any(|m| m.node_id == id && m.connected)
    };
    if primary_first {
        wait_until("the replica reaches the primary", connected_to(primary_id)).await;
    } else {
        // Nothing but the peer answers: the replica settles on it.
        wait_until("the replica attaches to the peer", connected_to(peer_id)).await;
        // The primary comes up. The replica must find its way back, not stay on the peer.
        let c = start_primary();
        if start == Start::AfterDialingIn {
            let r = Arc::clone(&replica);
            let id = primary_id.clone();
            wait_until("the primary's stream to the replica is up", move || {
                r.members()
                    .iter()
                    .any(|m| m.node_id == id && m.primary && m.connected)
            })
            .await;
            assert_eq!(replica.connected_primary(), Some(b_url.clone()));
            // Its own stream is still to the peer, which serves no blobs: fetches go to the
            // primary's URLs, never the peer's.
            assert!(!replica.main_link_to_primary());
            let urls = replica.fetch_urls();
            assert!(!urls.contains(&b_url), "{urls:?}");
            assert!(urls.contains(&p_url), "{urls:?}");
        }
        serve_primary(&c);
        let (r, p) = (Arc::clone(&replica), p_url.clone());
        // Wait for both halves of what is asserted next: the stream's URL is the primary's, and the
        // member table, which is updated separately, flags that stream's server as the primary.
        // Waiting on the URL alone let the assertion run before the flag was set (GitHub issue #69).
        wait_until(
            "the replica's own stream goes back to the primary, and the member table flags it",
            move || r.connected_primary().as_ref() == Some(&p) && r.main_link_to_primary(),
        )
        .await;
        assert!(replica.main_link_to_primary());
        let _primary = c;
    }
    assert_eq!(replica.connected_primary(), Some(p_url));
    let _ = stop_tx.send(true);
}

// REQ: CLU-001 (ADR-051; GitHub issue #4) — the URLs a replica looks at for the primary leave out
// the nodes it knows are not primary. A joining URL can belong to an old primary that is a
// replica now: moving to it would only leave the replica to move again.
#[test]
fn clu_001_primary_urls_leave_out_nodes_known_not_to_be_primary() {
    let (pdir, rdir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (old, new) = (
        "https://127.0.0.1:1".to_owned(),
        "https://127.0.0.1:2".to_owned(),
    );
    let primary = Identity::init(pdir.path(), "home", vec![old.clone()], "k8s").unwrap();
    let token = primary
        .create_token_for(
            60,
            None,
            crate::node::TokenGrants {
                eligible: false,
                witness: false,
            },
        )
        .unwrap();
    let key = pki::new_node_key().unwrap();
    let req = JoinRequest {
        witness: false,
        ephemeral: false,
        secret: token.secret.clone(),
        csr_pem: key.csr_pem.clone(),
        advertise: vec![],
        site: "pi".into(),
        eligible: false,
        version: "0.1.0".into(),
    };
    let resp = primary.accept_join(&req, None).unwrap();
    let replica =
        Identity::save_joined(rdir.path(), &key.key_pem, &resp, "pi", false, vec![]).unwrap();
    assert_eq!(replica.meta.primary_urls, [old.as_str()]);
    let replica = Cluster::new(replica, "0.1.0");
    let hello = |node: &str, url: &str, primary: bool, epoch: u64| Frame {
        body: Some(Body::Hello(Hello {
            protocol: PROTOCOL,
            cluster_id: replica.identity.meta.cluster_id.clone(),
            node_id: node.into(),
            version: "0.1.0".into(),
            site: "k8s".into(),
            eligible: true,
            advertise: vec![url.into()],
            epoch,
            applied_seq: 0,
            primary,
            config_source: String::new(),
            source_commit: String::new(),
        })),
    };
    // Nothing is known yet: the URL it joined with.
    assert_eq!(replica.primary_urls(), [old.as_str()]);
    // The old primary says it isn't one any more: its URL is left out.
    let mut peer = None;
    replica
        .on_frame(
            &mut peer,
            hello("old", &old, false, 2),
            "outbound",
            &EchoSlot::default(),
        )
        .unwrap();
    assert!(
        replica.primary_urls().is_empty(),
        "{:?}",
        replica.primary_urls()
    );
    // The new primary says so: its URL is the one to look at.
    let mut peer = None;
    replica
        .on_frame(
            &mut peer,
            hello("new", &new, true, 3),
            "outbound",
            &EchoSlot::default(),
        )
        .unwrap();
    assert_eq!(replica.primary_urls(), [new]);
}

/// REQ: CLU-005 (ADR-154, GitHub issue #3) — a node that isn't Git-managed leaves the election
/// to one that is, only under the `GitOps` authority and only while an eligible Git-managed node
/// is up.
#[test]
fn clu_005_only_a_node_that_isnt_git_managed_defers_to_one_that_is() {
    // (is Git-managed, is up, is an eligible voter)
    let git_up = [(true, true, true)];
    assert!(defers_to_git("gitops", "", git_up));
    assert!(defers_to_git("gitops", "api", git_up));
    // A Git-managed node never defers to another.
    assert!(!defers_to_git("gitops", "gitops", git_up));
    // Outside the GitOps authority nothing changes.
    assert!(!defers_to_git("", "", git_up));
    assert!(!defers_to_git("api", "", git_up));
    // No Git-managed node that could win: down, a witness or not eligible, or not Git-managed.
    assert!(!defers_to_git("gitops", "", [(true, false, true)]));
    assert!(!defers_to_git("gitops", "", [(true, true, false)]));
    assert!(!defers_to_git("gitops", "", [(false, true, true)]));
    assert!(!defers_to_git("gitops", "", []));
    // One usable node among others is enough.
    assert!(defers_to_git(
        "gitops",
        "",
        [(false, true, true), (true, false, true), (true, true, true)]
    ));
}

/// REQ: CLU-005 (ADR-154) — the deference is bounded: a primary being up (the handover window)
/// always defers, but with no primary up it ends after [`DEFER_MAX_MS`], so an emergency primary
/// is still elected when the Git-managed node is up but can't win; and it starts over after.
#[test]
fn clu_005_deference_with_no_primary_is_bounded_in_time() {
    let since = AtomicU64::new(0);
    let t0 = 1_000_000;
    // Not wanting to defer: no, and nothing is remembered.
    assert!(!bounded_deference(false, false, &since, t0));
    assert_eq!(since.load(Ordering::Acquire), 0);
    // A primary is up: it defers for as long as that holds, and nothing is timed.
    assert!(bounded_deference(true, true, &since, t0));
    assert!(bounded_deference(
        true,
        true,
        &since,
        t0 + 10 * DEFER_MAX_MS
    ));
    assert_eq!(since.load(Ordering::Acquire), 0);
    // No primary: it defers for the bound, then stands.
    assert!(bounded_deference(true, false, &since, t0));
    assert!(bounded_deference(
        true,
        false,
        &since,
        t0 + DEFER_MAX_MS - 1
    ));
    assert!(!bounded_deference(true, false, &since, t0 + DEFER_MAX_MS));
    assert!(!bounded_deference(
        true,
        false,
        &since,
        t0 + 5 * DEFER_MAX_MS
    ));
    // A primary appears and goes away again: the clock starts over.
    assert!(bounded_deference(true, true, &since, t0 + 6 * DEFER_MAX_MS));
    assert!(bounded_deference(
        true,
        false,
        &since,
        t0 + 7 * DEFER_MAX_MS
    ));
    assert!(bounded_deference(
        true,
        false,
        &since,
        t0 + 7 * DEFER_MAX_MS + DEFER_MAX_MS - 1
    ));
    // The Git-managed node going down ends the wish: it stands at once, and the clock is reset.
    assert!(!bounded_deference(
        false,
        false,
        &since,
        t0 + 7 * DEFER_MAX_MS + 1
    ));
    assert_eq!(since.load(Ordering::Acquire), 0);
}

// REQ: CLU-005 (ADR-154, GitHub issue #3) — the wiring behind the hold-back: under the GitOps
// authority a node that isn't Git-managed defers to an eligible voter that is (and is up), not
// to a pod that claims it, and a Git-managed node never defers.
#[test]
fn clu_005_a_node_defers_to_an_eligible_git_managed_voter_that_is_up() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::init(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "k8s",
    )
    .unwrap();
    let c = Cluster::new(id, "0.1.0");
    let join = |eligible: bool, ephemeral: bool, site: &str| {
        let key = pki::new_node_key().unwrap();
        let grants = crate::node::TokenGrants {
            eligible,
            witness: false,
        };
        let token = c.identity.create_token_for(60, None, grants).unwrap();
        c.identity
            .accept_join(
                &JoinRequest {
                    witness: false,
                    ephemeral,
                    secret: token.secret,
                    csr_pem: key.csr_pem,
                    advertise: vec![],
                    site: site.into(),
                    eligible,
                    version: "0.1.0".into(),
                },
                None,
            )
            .unwrap()
            .node_id
    };
    let (pod, git) = (join(false, true, "k8s"), join(true, false, "k8s"));
    let hello = |node_id: &str, source: &str| Frame {
        body: Some(Body::Hello(Hello {
            protocol: PROTOCOL,
            cluster_id: c.identity.meta.cluster_id.clone(),
            node_id: node_id.to_owned(),
            version: "0.1.0".into(),
            site: "k8s".into(),
            eligible: false,
            advertise: vec![],
            epoch: 0,
            applied_seq: 0,
            primary: false,
            config_source: source.into(),
            source_commit: String::new(),
        })),
    };
    let echo = EchoSlot::default();
    for (n, source) in [(&pod, "gitops"), (&git, "gitops")] {
        let mut peer = Some(n.clone());
        c.on_frame(&mut peer, hello(n, source), "inbound", &echo)
            .unwrap();
    }
    let defers = || c.defers_to_git_node(&c.identity.reload(), false);
    // Configuration from the API: no Git-managed primary can exist, nothing is held back.
    assert!(!defers());
    c.identity.save_authority("gitops").unwrap();
    assert!(defers(), "an eligible Git-managed voter is up");
    // A Git-managed node leaves the election to no one.
    c.set_config_source("gitops");
    assert!(!defers());
}

// REQ: CLU-005 (ADR-154, GitHub issue #3) — a replica's view of "a primary is up" is the lease it
// granted, not a member's Hello flag (stale when a node is elected on a stream that was open):
// while the lease runs it defers however long that lasts, and its clock for "no primary up" starts
// only when the lease has run out.
#[test]
fn clu_005_deference_follows_the_lease_not_a_members_hello_flag() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::init(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "k8s",
    )
    .unwrap();
    let c = Cluster::new(id, "0.1.0");
    // A Git-managed eligible node is up (its Hello says so); the primary role isn't on any
    // member's flag, as for an emergency primary that was elected on an open stream.
    let key = pki::new_node_key().unwrap();
    let token = c
        .identity
        .create_token_for(
            60,
            None,
            crate::node::TokenGrants {
                eligible: true,
                witness: false,
            },
        )
        .unwrap();
    let git = c
        .identity
        .accept_join(
            &JoinRequest {
                witness: false,
                ephemeral: false,
                secret: token.secret,
                csr_pem: key.csr_pem,
                advertise: vec![],
                site: "k8s".into(),
                eligible: true,
                version: "0.1.0".into(),
            },
            None,
        )
        .unwrap()
        .node_id;
    let mut peer = Some(git.clone());
    c.on_frame(
        &mut peer,
        Frame {
            body: Some(Body::Hello(Hello {
                protocol: PROTOCOL,
                cluster_id: c.identity.meta.cluster_id.clone(),
                node_id: git,
                version: "0.1.0".into(),
                site: "k8s".into(),
                eligible: false,
                advertise: vec![],
                epoch: 0,
                applied_seq: 0,
                primary: false,
                config_source: "gitops".into(),
                source_commit: String::new(),
            })),
        },
        "inbound",
        &EchoSlot::default(),
    )
    .unwrap();
    c.identity.save_authority("gitops").unwrap();
    c.set_role(Role::Replica, 3).unwrap();
    let id = c.identity.reload();
    // With a lease running it defers, for as long as that lasts (the clock never starts).
    c.defer_since_ms.store(1, Ordering::Release);
    assert!(c.defers_to_git_node(&id, true));
    assert_eq!(c.defer_since_ms.load(Ordering::Acquire), 0, "reset");
    // With none it defers for the bound, then stands.
    assert!(c.defers_to_git_node(&id, false));
    c.defer_since_ms
        .store(now_ms() - DEFER_MAX_MS - 1_000, Ordering::Release);
    assert!(!c.defers_to_git_node(&id, false), "the bound is over");
    // A lease again (a new primary) starts it over.
    assert!(c.defers_to_git_node(&id, true));
}

// REQ: CLU-005 (ADR-154) — a handover a Git-managed node asked for runs once, ends with the
// step-down, and leaves a maintenance handover alone (its window ends it).
#[test]
fn clu_005_a_git_node_handover_ends_with_the_step_down() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::init(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "k8s",
    )
    .unwrap();
    let c = Cluster::new(id, "0.1.0");
    assert!(!c.stepping_down());
    assert!(c.start_handover("git-node"));
    assert!(c.stepping_down());
    assert!(!c.start_handover("another"), "one handover at a time");
    c.end_handover();
    assert!(!c.stepping_down());
    // In maintenance with a handover, the step-down doesn't end it: the window does.
    let now = now_ms();
    c.set_maintenance(
        Some(MaintenanceWindow {
            until_ms: now + 600_000,
            since_ms: now,
            reason: "test".into(),
            by: "test".into(),
        }),
        true,
    );
    assert!(c.stepping_down());
    c.end_handover();
    assert!(c.stepping_down());
    c.set_maintenance(None, false);
    assert!(!c.stepping_down());
}

// REQ: CLU-001 (ADR-155, GitHub issue #5) — removing a node: the primary drops it from the
// registry (it stops voting) and adds it to the removed list, a node that is up needs `force`,
// the primary can't be removed, a dry run changes nothing, and a removed node's stream is
// refused even though its certificate is still valid.
#[test]
#[allow(clippy::too_many_lines)] // one story: the refusals, the dry run, the removal, the refusal after
fn clu_001_removing_a_node_drops_it_and_refuses_it() {
    use crate::removal::RemoveError;
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::init(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "k8s",
    )
    .unwrap();
    let c = Cluster::new(id, "0.1.0");
    let join = |eligible: bool, ephemeral: bool, site: &str| {
        let key = pki::new_node_key().unwrap();
        let grants = crate::node::TokenGrants {
            eligible,
            witness: false,
        };
        let token = c.identity.create_token_for(60, None, grants).unwrap();
        c.identity
            .accept_join(
                &JoinRequest {
                    witness: false,
                    ephemeral,
                    secret: token.secret,
                    csr_pem: key.csr_pem,
                    advertise: vec![],
                    site: site.into(),
                    eligible,
                    version: "0.1.0".into(),
                },
                None,
            )
            .unwrap()
            .node_id
    };
    let (stale, live, pod) = (
        join(true, false, "pi"),
        join(true, false, "lxc"),
        join(false, true, "k8s"),
    );
    let hello = |node_id: &str| Frame {
        body: Some(Body::Hello(Hello {
            protocol: PROTOCOL,
            cluster_id: c.identity.meta.cluster_id.clone(),
            node_id: node_id.to_owned(),
            version: "0.1.0".into(),
            site: "x".into(),
            eligible: false,
            advertise: vec![],
            epoch: 0,
            applied_seq: 0,
            primary: false,
            config_source: String::new(),
            source_commit: String::new(),
        })),
    };
    let echo = EchoSlot::default();
    let registry_ids = || -> Vec<String> {
        c.identity
            .registry()
            .into_iter()
            .map(|n| n.node_id)
            .collect()
    };
    let me = c.identity.meta.node_id.clone();

    // Refusals: no such member, and the primary itself.
    assert_eq!(
        c.remove_member("nobody", false, false, "t"),
        Err(RemoveError::Unknown)
    );
    assert_eq!(
        c.remove_member(&me, true, false, "t"),
        Err(RemoveError::IsSelf)
    );

    // A node that is up needs `force`: its Hello made it up.
    let mut peer = Some(live.clone());
    c.on_frame(&mut peer, hello(&live), "inbound", &echo)
        .unwrap();
    assert_eq!(
        c.remove_member(&live, false, false, "t"),
        Err(RemoveError::Up)
    );
    assert!(registry_ids().contains(&live), "refused: still listed");

    // A dry run says what would happen and changes nothing.
    let plan = c.remove_member(&stale, false, true, "t").unwrap();
    assert!(!plan.removed && plan.eligible && plan.held_cluster_key && !plan.up);
    assert_eq!(
        plan.voters_after, 2,
        "the primary and the other eligible node"
    );
    assert!(
        plan.notes
            .iter()
            .any(|n| n.contains("rotate the cluster CA")),
        "{:?}",
        plan.notes
    );
    assert!(registry_ids().contains(&stale) && !c.is_removed(&stale));

    // The stale record goes: out of the registry, onto the removed list, with an event.
    let done = c.remove_member(&stale, false, false, "alice").unwrap();
    assert!(done.removed && !done.up);
    assert!(!registry_ids().contains(&stale));
    assert!(c.is_removed(&stale) && c.identity.removed() == [stale.clone()]);
    assert!(
        c.events()
            .iter()
            .any(|e| e.kind == "removed" && e.node == stale && e.detail.contains("alice")),
        "{:?}",
        c.events()
    );
    assert_eq!(
        c.remove_member(&stale, false, false, "t"),
        Err(RemoveError::Unknown),
        "gone"
    );

    // Its certificate is still valid, but its stream is refused (a Hello, and a stream that
    // was open before the removal).
    let mut peer = Some(stale.clone());
    let err = c
        .on_frame(&mut peer, hello(&stale), "inbound", &echo)
        .unwrap_err();
    assert!(err.contains("removed"), "{err}");
    let mut open = Some(stale.clone());
    let hb = Frame {
        body: Some(Body::Heartbeat(Heartbeat {
            ts_ms: 1,
            ..Heartbeat::default()
        })),
    };
    assert!(c.on_frame(&mut open, hb, "inbound", &echo).is_err());
    assert!(
        !c.members().iter().any(|m| m.node_id == stale),
        "it isn't listed as a member"
    );

    // A node that is up goes with `force`, and the answer says so.
    let forced = c.remove_member(&live, true, false, "alice").unwrap();
    assert!(forced.up && forced.removed);
    assert!(
        forced.notes.iter().any(|n| n.contains("It was up")),
        "{:?}",
        forced.notes
    );
    assert!(c.is_removed(&live));

    // An ephemeral member (a pod) can be removed too, and doesn't mention the key.
    let p = c.remove_member(&pod, false, false, "t").unwrap();
    assert!(p.ephemeral && !p.held_cluster_key);

    // The removed list is what a replica adopts from the manifest: an empty list (an older
    // primary) leaves it alone.
    let dir2 = tempfile::tempdir().unwrap();
    let id2 = Identity::init(
        dir2.path(),
        "other",
        vec!["https://127.0.0.1:2".into()],
        "k8s",
    )
    .unwrap();
    let r = Cluster::new(id2, "0.1.0");
    r.adopt_removed(&c.identity.removed());
    assert!(r.is_removed(&stale) && r.is_removed(&live));
    r.adopt_removed(&[]);
    assert!(r.is_removed(&stale), "an empty list changes nothing");
}

// REQ: CLU-001 (ADR-155) — the removed list is capped: the oldest entries go first.
#[test]
fn clu_001_the_removed_list_keeps_the_newest() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::init(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "k8s",
    )
    .unwrap();
    for i in 0..(crate::node::MAX_REMOVED + 5) {
        id.add_removed(&format!("n{i}")).unwrap();
    }
    id.add_removed("n7").unwrap();
    let list = id.removed();
    assert_eq!(list.len(), crate::node::MAX_REMOVED);
    assert_eq!(list.first().map(String::as_str), Some("n5"));
    assert_eq!(
        list.last().cloned(),
        Some(format!("n{}", crate::node::MAX_REMOVED + 4))
    );
}
