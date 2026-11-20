//! REQ: CLU-001, CLU-005 (T5.4c, ADR-066, ADR-177) — trust follows the primary's manifests in
//! order: a node takes the CAs of a manifest only if it isn't older than the one it last took
//! them from, and isn't of an epoch older than the one the node knows. A replayed or late
//! manifest that still verifies can't move trust back to a retired CA, or drop the CA a rotation
//! is adding.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::watch;

use super::*;
use crate::pki;

/// A node taken through a CA rotation by the primary's manifests: its own CA (`old`, whose key
/// it holds, like an eligible replica) and the `new` one the rotation adds. The new key came
/// first (the primary's key share), so it is held as pending until a bundle trusts its CA.
struct Rotating {
    data: tempfile::TempDir,
    node: Arc<Cluster>,
    old: pki::Ca,
    new: pki::Ca,
}

/// The mark file beside `ca.crt` (ADR-177), as a test writes it to stand for an older state.
const MARK: &str = "ca.version";

impl Rotating {
    fn new() -> Self {
        let data = tempfile::tempdir().unwrap();
        let id = Identity::init(
            data.path(),
            "home",
            vec!["https://127.0.0.1:1".into()],
            "lab",
        )
        .unwrap();
        let old = pki::Ca {
            cert_pem: id.ca_pem.clone(),
            key_pem: std::fs::read_to_string(id.dir.join("ca.key")).unwrap(),
        };
        let new = pki::new_ca_labeled("home", "next").unwrap();
        assert!(!id.store_ca_key(&new.key_pem).unwrap());
        Self {
            data,
            node: Cluster::new(id, "0.1.0"),
            old,
            new,
        }
    }

    fn dir(&self) -> &std::path::Path {
        &self.node.identity.dir
    }

    // The bundles of a rotation: before it, the trust phase, the switch, and after the retire.
    fn before(&self) -> String {
        self.old.cert_pem.clone()
    }
    fn trusting(&self) -> String {
        format!("{}{}", self.old.cert_pem, self.new.cert_pem)
    }
    fn switched(&self) -> String {
        format!("{}{}", self.new.cert_pem, self.old.cert_pem)
    }
    fn retired(&self) -> String {
        self.new.cert_pem.clone()
    }

    /// A manifest of this cluster, version `(epoch, seq)`, carrying `bundle`.
    fn manifest(&self, epoch: u64, seq: u64, bundle: &str) -> ClusterManifest {
        ClusterManifest {
            cluster_id: self.node.identity.meta.cluster_id.clone(),
            epoch,
            seq,
            created_ms: seq,
            primary: "p".into(),
            config: crate::sync::blob_ref("config.json", b"{}"),
            ca_bundle: bundle.to_owned(),
            ..ClusterManifest::default()
        }
    }

    /// `m` signed the way the primary signs it: by its bundle's first CA.
    fn signed(&self, m: &ClusterManifest) -> Arc<Signed> {
        let first = pki::certs_of(&m.ca_bundle).remove(0);
        let key =
            if pki::fingerprint(&first).unwrap() == pki::fingerprint(&self.new.cert_pem).unwrap() {
                &self.new.key_pem
            } else {
                &self.old.key_pem
            };
        Arc::new(Signed::sign(m, key).unwrap())
    }

    /// Takes the CAs of each manifest in turn, as the node's follower does.
    fn take(&self, steps: &[(u64, u64, String)]) {
        for (epoch, seq, bundle) in steps {
            adopt_manifest_trust(&self.node, &self.manifest(*epoch, *seq, bundle));
        }
    }

    /// The CAs the node trusts now (`ca.crt` on disk), in order: `old`, `new`, or `other`.
    fn trust(&self) -> Vec<&'static str> {
        let (old, new) = (
            pki::fingerprint(&self.old.cert_pem).unwrap(),
            pki::fingerprint(&self.new.cert_pem).unwrap(),
        );
        pki::certs_of(&self.node.identity.reload().ca_pem)
            .iter()
            .map(|c| match pki::fingerprint(c).unwrap() {
                f if f == old => "old",
                f if f == new => "new",
                _ => "other",
            })
            .collect()
    }

    fn has(&self, file: &str) -> bool {
        self.dir().join(file).exists()
    }

    /// Which CA's key a key file holds: `old`, `new`, `other`, or nothing.
    fn key(&self, file: &str) -> Option<&'static str> {
        let k = std::fs::read_to_string(self.dir().join(file)).ok()?;
        let k = crate::sync::public_of(&k).ok()?;
        Some(if k == crate::sync::public_of(&self.old.key_pem).unwrap() {
            "old"
        } else if k == crate::sync::public_of(&self.new.key_pem).unwrap() {
            "new"
        } else {
            "other"
        })
    }

    /// Writes the mark file as a node in another state would have left it.
    fn write_mark(&self, cluster_id: &str, epoch: u64, seq: u64) {
        std::fs::write(
            self.dir().join(MARK),
            format!(r#"{{"cluster_id":"{cluster_id}","epoch":{epoch},"seq":{seq}}}"#),
        )
        .unwrap();
    }

    /// Hands `signed` to the node's running follower and returns once the follower has dealt
    /// with it. The follower is held at the key-file lock (every manifest that verifies and isn't
    /// of an older epoch reaches it), told to stop while it waits there, and joined once let go:
    /// so it can't miss the frame or have it replaced by a later one, and nothing sleeps.
    #[allow(clippy::await_holding_lock)] // holding the lock across the wait is the point
    async fn deliver(
        &self,
        signed: Arc<Signed>,
        stop: &watch::Sender<bool>,
        follower: tokio::task::JoinHandle<()>,
    ) {
        let lock = crate::node::key_files_lock(self.dir());
        let held = lock.lock().unwrap();
        self.node.incoming.send_replace(Some(signed));
        // The map of locks and this test hold one handle each; a waiting follower holds a third.
        let mut waited = 0;
        while Arc::strong_count(&lock) < 3 {
            assert!(waited < 2_000, "the follower never reached the trust step");
            waited += 1;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        stop.send(true).unwrap();
        drop(held);
        tokio::time::timeout(Duration::from_secs(10), follower)
            .await
            .expect("the follower didn't stop")
            .unwrap();
    }
}

// The rotation's four manifests, in order (epoch 1, versions 1 to 4).
fn whole_rotation(r: &Rotating) -> Vec<(u64, u64, String)> {
    vec![
        (1, 1, r.before()),
        (1, 2, r.trusting()),
        (1, 3, r.switched()),
        (1, 4, r.retired()),
    ]
}

// REQ: CLU-001, CLU-005 (ADR-177) — after a rotation, none of its earlier manifests (each still
// verifies against a CA the node trusted at some point) moves trust back.
#[test]
fn clu_001_trust_is_not_taken_from_an_older_manifest() {
    let r = Rotating::new();
    let steps = whole_rotation(&r);
    r.take(&steps);
    assert_eq!(r.trust(), ["new"]);
    assert!(!r.has("ca-old.key"));
    for (epoch, seq, bundle) in steps[..3].iter().rev() {
        adopt_manifest_trust(&r.node, &r.manifest(*epoch, *seq, bundle));
        assert_eq!(
            r.trust(),
            ["new"],
            "the CAs of the older version {seq} were taken"
        );
    }
    assert_eq!(r.key("ca.key"), Some("new"));
    for f in ["ca-old.key", "ca-next.key", "ca-pending.key"] {
        assert!(!r.has(f), "{f} is back");
    }
}

// REQ: CLU-001, CLU-003 (ADR-177) — a replica's follower, after the retire: the switch's manifest
// (`[new, old]`, signed by the new CA, so it verifies) replayed leaves the trust at `[new]`, and
// isn't applied either, though it is newer than the configuration this node applied (it took the
// CA steps 3 and 4 but couldn't apply them).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clu_001_follow_ignores_the_cas_of_an_older_manifest() {
    let r = Rotating::new();
    r.take(&whole_rotation(&r));
    let store = BlobStore::open(r.data.path()).unwrap();
    store
        .put(&crate::sync::blob_ref("config.json", b"{}"), b"{}")
        .unwrap();
    let applied = Arc::new(AtomicU64::new(0));
    let (stop_tx, stop) = watch::channel(false);
    let a = Arc::clone(&applied);
    let follower = tokio::spawn(follow(
        Arc::clone(&r.node),
        store,
        (1, 2),
        move |_| {
            let a = Arc::clone(&a);
            async move {
                a.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        },
        stop,
    ));
    let replay = r.signed(&r.manifest(1, 3, &r.switched()));
    r.deliver(replay, &stop_tx, follower).await;
    assert_eq!(r.trust(), ["new"], "the retired CA is trusted again");
    assert!(!r.has("ca-old.key"));
    assert_eq!(
        applied.load(Ordering::SeqCst),
        0,
        "an older manifest was applied"
    );
}

// REQ: CLU-001 (ADR-177) — a witness's follower, in the trust phase: the manifest from before the
// rotation (`[old]`, still signed by the CA that signs) replayed leaves the bundle as it is, and
// the next CA's key in place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clu_001_follow_trust_ignores_the_cas_of_an_older_manifest() {
    let r = Rotating::new();
    r.take(&whole_rotation(&r)[..2]);
    assert_eq!(r.trust(), ["old", "new"]);
    assert_eq!(r.key("ca-next.key"), Some("new"));
    let (stop_tx, stop) = watch::channel(false);
    let follower = tokio::spawn(follow_trust(Arc::clone(&r.node), stop));
    let replay = r.signed(&r.manifest(1, 1, &r.before()));
    r.deliver(replay, &stop_tx, follower).await;
    assert_eq!(r.trust(), ["old", "new"], "the new CA was dropped");
    assert_eq!(
        r.key("ca-next.key"),
        Some("new"),
        "the next CA's key was deleted"
    );
}

// REQ: CLU-001 (ADR-177) — a manifest of the version trust was last taken from is taken again: it
// finishes a step a crash cut short (the key files moved, `ca.crt` not yet written), it moves on a
// mark a crash left behind (`ca.crt` written, the mark not), and a second manifest of that version
// (a primary that published it, crashed before it recorded it, and published it again) counts. An
// older one still doesn't.
#[test]
fn clu_001_the_same_version_again_is_taken_and_mends_a_crash() {
    let r = Rotating::new();
    r.take(&whole_rotation(&r)[..2]);
    // The switch (version 3) crashed after the key moves, before `ca.crt`.
    std::fs::rename(r.dir().join("ca.key"), r.dir().join("ca-old.key")).unwrap();
    std::fs::rename(r.dir().join("ca-next.key"), r.dir().join("ca.key")).unwrap();
    assert_eq!(r.trust(), ["old", "new"]);
    // The primary sends its head again (to every new stream): the step is finished.
    r.take(&[(1, 3, r.switched())]);
    assert_eq!(r.trust(), ["new", "old"]);
    assert_eq!(r.key("ca.key"), Some("new"));
    assert_eq!(r.key("ca-old.key"), Some("old"));
    assert!(!r.has("ca-next.key") && !r.has("ca-pending.key"));
    // A crash between `ca.crt` and the mark: the mark still says version 2.
    r.write_mark(&r.node.identity.meta.cluster_id, 1, 2);
    r.take(&[(1, 3, r.switched())]);
    // So version 2 again is older than what trust was taken from.
    r.take(&[(1, 2, r.trusting())]);
    assert_eq!(
        r.trust(),
        ["new", "old"],
        "the trust phase came back (the mark stayed behind)"
    );
    // Another manifest of version 3, with the bundle after the retire, is taken.
    r.take(&[(1, 3, r.retired())]);
    assert_eq!(
        r.trust(),
        ["new"],
        "a manifest of the version trust was taken from was refused"
    );
    assert!(!r.has("ca-old.key"));
    r.take(&[(1, 2, r.trusting())]);
    assert_eq!(
        r.trust(),
        ["new"],
        "the CAs of an older manifest were taken"
    );
}

// REQ: CLU-001 (ADR-177) — the mark belongs to the cluster it was written in. A mark another
// cluster left in this directory (far ahead of this cluster's versions) never blocks this
// cluster's trust; from the first step on, this cluster's own mark counts.
#[test]
fn clu_001_a_trust_mark_from_another_cluster_is_ignored() {
    let r = Rotating::new();
    assert_ne!(r.node.identity.meta.cluster_id, "0123456789abcdef");
    r.write_mark("0123456789abcdef", 9, 999);
    r.take(&whole_rotation(&r)[..2]);
    assert_eq!(
        r.trust(),
        ["old", "new"],
        "another cluster's mark blocked this cluster's trust"
    );
    assert_eq!(r.key("ca-next.key"), Some("new"));
    r.take(&[(1, 1, r.before())]);
    assert_eq!(r.trust(), ["old", "new"], "the new CA was dropped");
    assert_eq!(r.key("ca-next.key"), Some("new"));
}

// REQ: CLU-005, CLU-001 (ADR-051, ADR-177) — epochs come first: the first manifests of a new
// epoch (a promotion after a failover) move trust though their seq is lower than the old epoch's,
// and then a late manifest of the old epoch (its primary published it before it heard of the new
// one) doesn't. A node that knows of a newer epoch (from a voter's Hello) takes no trust from an
// older one, mark or not.
#[test]
fn clu_005_a_new_epoch_moves_trust_though_its_seq_is_lower() {
    let r = Rotating::new();
    r.take(&[(1, 5, r.before()), (1, 20, r.trusting())]);
    r.take(&[(2, 3, r.switched())]);
    assert_eq!(
        r.trust(),
        ["new", "old"],
        "the new epoch's manifest was refused"
    );
    r.take(&[(1, 21, r.trusting())]);
    assert_eq!(
        r.trust(),
        ["new", "old"],
        "the old epoch's late manifest moved trust"
    );
    // No mark, and the node has heard of epoch 3.
    let _ = std::fs::remove_file(r.dir().join(MARK));
    r.node.set_role(Role::Replica, 3).unwrap();
    r.take(&[(2, 30, r.retired())]);
    assert_eq!(
        r.trust(),
        ["new", "old"],
        "a manifest of an older epoch than the node knows moved trust"
    );
    r.take(&[(3, 1, r.retired())]);
    assert_eq!(
        r.trust(),
        ["new"],
        "the current epoch's manifest was refused"
    );
}

// REQ: CLU-001 (ADR-177) — a node upgraded from a build without marks: it has none, so its next
// manifest is taken (nothing to trust anew, here) and gives it one; from then on an older
// manifest is refused. Downgraded again for a while (the older build moves trust and never
// touches the mark) and upgraded: the mark it finds is behind its trust, so it blocks nothing
// newer, and moves on with the next manifest.
#[test]
fn clu_001_a_node_without_a_trust_mark_starts_one_with_its_next_manifest() {
    let r = Rotating::new();
    r.take(&whole_rotation(&r));
    // What an older build leaves: the same files, no mark.
    let _ = std::fs::remove_file(r.dir().join(MARK));
    r.take(&[(1, 5, r.retired())]);
    r.take(&[(1, 3, r.switched())]);
    assert_eq!(r.trust(), ["new"], "the retired CA is trusted again");
    assert!(r.has(MARK), "no mark was written");
    // The older build again: a second rotation's trust step (version 7), the mark left at 5.
    let third = pki::new_ca_labeled("home", "third").unwrap();
    let second = format!("{}{}", r.new.cert_pem, third.cert_pem);
    std::fs::write(r.dir().join("ca.crt"), &second).unwrap();
    r.take(&[(1, 8, second.clone())]);
    assert_eq!(r.trust(), ["new", "other"]);
    r.take(&[(1, 6, r.retired())]);
    assert_eq!(
        r.trust(),
        ["new", "other"],
        "a manifest older than the head was taken"
    );
}
