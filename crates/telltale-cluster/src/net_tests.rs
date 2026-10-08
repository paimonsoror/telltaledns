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
    let token = primary.create_token(600, Some(vec![url.clone()])).unwrap();
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
    let token = primary_id.create_token(600, None).unwrap();
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
    // A token join may be eligible, and then the key share is due.
    let token = primary.identity.create_token(60, None).unwrap();
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
