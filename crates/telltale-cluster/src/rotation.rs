//! Cluster CA rotation (REQ: CLU-001, CLU-005; T5.4c, ADR-066).
//!
//! Three phases, driven by the primary as members report in (heartbeats carry what each node
//! trusts and who issued its certificate):
//! 1. **trust:** a new CA joins the bundle every node trusts (`ca.crt`), after the old one,
//!    which still signs. The bundle travels in the signed manifest; eligible nodes also get the
//!    new key (`ca-next.key`).
//! 2. **switch:** once every member trusts both, the new CA signs: it comes first in the
//!    bundle and its key becomes `ca.key`. Every node renews its certificate (same key) from
//!    the new CA.
//! 3. **finish:** once every member's certificate is from the new CA, the old one leaves the
//!    bundle and its key is deleted.
//!
//! Nothing is cut over until every member is ready, so links never break. A member that's
//! away holds the rotation until it's back (or is removed). Ephemeral members don't count:
//! they rejoin with the bootstrap secret.

use std::path::{Path, PathBuf};
use std::sync::PoisonError;

use serde::{Deserialize, Serialize};

use crate::net::Cluster;
use crate::node::Identity;
use crate::pki;

const FILE: &str = "rotation.json";

/// The rotation in progress (`cluster/rotation.json` on the primary).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rotation {
    /// `trust` or `switch`.
    pub phase: String,
    pub started_ms: u64,
    /// The new CA (hex fingerprint).
    pub new_fp: String,
    /// The CA being retired.
    pub old_fp: String,
    /// Members not ready for the next phase, as of the last step.
    #[serde(default)]
    pub pending: Vec<String>,
}

fn path(id: &Identity) -> PathBuf {
    id.dir.join(FILE)
}

/// The rotation in progress, if any.
pub fn current(id: &Identity) -> Option<Rotation> {
    std::fs::read(path(id))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

fn save(id: &Identity, r: &Rotation) -> Result<(), String> {
    let b = serde_json::to_vec_pretty(r).map_err(|e| e.to_string())?;
    write(&path(id), &b, false)
}

/// REQ: CLU-001 (ADR-066) — the cluster directory's one way to write a file: atomically, through a
/// temporary file named for this write alone (removed if the write fails), and a secret is
/// owner-only from its first byte. The gain is the CLI's `ca-next.key` (a CA private key), which
/// was created with the default mode and made owner-only only before its rename. The old fixed
/// name (`<stem>.tmp`) was shared only by two writes of the same file, never by two files a
/// rotation writes.
fn write(p: &Path, data: &[u8], secret: bool) -> Result<(), String> {
    crate::node::write(p, data, secret).map_err(|e| e.to_string())
}

#[cfg(test)]
thread_local! {
    /// A test seam: what to run inside [`step`] on this thread, after the switch moved the key
    /// files and before it writes the new bundle (the window a key share could slip into).
    static AFTER_SWITCH_MOVES: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn after_switch_moves() {
    AFTER_SWITCH_MOVES.with(|h| {
        if let Some(f) = h.borrow_mut().as_mut() {
            f();
        }
    });
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn fp(cert: &str) -> String {
    pki::fingerprint(cert).map_or_else(|_| String::new(), |f| pki::hex(&f))
}

/// Starts a rotation on the primary: a new CA, trusted after the current one. `label` names
/// it (a date), so the two CAs never share a subject.
pub fn start(id: &Identity, label: &str) -> Result<Rotation, String> {
    let id = id.reload();
    if !id.is_primary() || !id.holds_ca() {
        return Err("run this on the primary".into());
    }
    if let Some(r) = current(&id) {
        return Err(format!(
            "a CA rotation is already in its `{}` phase",
            r.phase
        ));
    }
    let cas = pki::certs_of(&id.ca_pem);
    let [old] = cas.as_slice() else {
        return Err(
            "the trusted CAs aren't a single CA: finish the previous rotation first".into(),
        );
    };
    let new = pki::new_ca_labeled(&id.meta.cluster_name, label).map_err(|e| e.to_string())?;
    write(&id.dir.join("ca-next.key"), new.key_pem.as_bytes(), true)?;
    write(
        &id.dir.join("ca.crt"),
        format!("{old}{}", new.cert_pem).as_bytes(),
        false,
    )?;
    let r = Rotation {
        phase: "trust".into(),
        started_ms: now_ms(),
        new_fp: fp(&new.cert_pem),
        old_fp: fp(old),
        pending: Vec::new(),
    };
    save(&id, &r)?;
    Ok(r)
}

/// The members that must be ready: every registry node but this one and ephemeral members.
fn required(id: &Identity) -> Vec<String> {
    id.registry()
        .into_iter()
        .filter(|n| n.node_id != id.meta.node_id && !n.ephemeral)
        .map(|n| n.node_id)
        .collect()
}

/// Advances the rotation if every member is ready (on the primary; call every few seconds).
/// Returns what happened, for the log and the event list.
pub fn step(cluster: &Cluster) -> Option<String> {
    // REQ: CLU-001, CLU-005 — the key files change under their lock, as on a replica (see
    // `key_files_lock`): a key share (a primary takes one from a newer-epoch primary) must not
    // see the switch half done. Read the identity under it.
    let lock = crate::node::key_files_lock(&cluster.identity.dir);
    let _held = lock.lock().unwrap_or_else(PoisonError::into_inner);
    let id = cluster.identity.reload();
    if !id.is_primary() {
        return None;
    }
    let mut r = current(&id)?;
    let members = cluster.members();
    let seen = |node: &str, ok: &dyn Fn(&crate::net::Member) -> bool| {
        members.iter().any(|m| m.node_id == node && ok(m))
    };
    match r.phase.as_str() {
        "trust" => {
            let want = pki::trust_fp(&id.ca_pem);
            r.pending = required(&id)
                .into_iter()
                .filter(|n| !seen(n, &|m| m.trust_fp == want))
                .collect();
            if !r.pending.is_empty() {
                let _ = save(&id, &r);
                return None;
            }
            // Everyone trusts both: the new CA signs from now on.
            let cas = pki::certs_of(&id.ca_pem);
            let (Some(old), Some(new)) = (cas.first(), cas.get(1)) else {
                return Some("CA rotation: the bundle lost a CA; not switching".into());
            };
            let next = id.dir.join("ca-next.key");
            if !next.exists() {
                return Some("CA rotation: the new CA's key is missing; not switching".into());
            }
            if let Err(e) = std::fs::rename(id.dir.join("ca.key"), id.dir.join("ca-old.key"))
                .and_then(|()| std::fs::rename(&next, id.dir.join("ca.key")))
            {
                return Some(format!("CA rotation: can't switch keys: {e}"));
            }
            #[cfg(test)]
            after_switch_moves();
            if let Err(e) = write(
                &id.dir.join("ca.crt"),
                format!("{new}{old}").as_bytes(),
                false,
            ) {
                return Some(format!("CA rotation: can't write the bundle: {e}"));
            }
            r.phase = "switch".into();
            r.pending.clear();
            let _ = save(&id, &r);
            cluster.bump_cert_generation();
            Some("CA rotation: every member trusts the new CA; it now signs, and nodes renew their certificates".into())
        }
        "switch" => {
            let me_stale = crate::renew::stale_issuer(&id.cert_pem, &id.ca_pem);
            r.pending = required(&id)
                .into_iter()
                .filter(|n| !seen(n, &|m| m.issuer_fp == r.new_fp))
                .collect();
            if me_stale {
                r.pending.push(id.meta.node_id.clone());
            }
            if !r.pending.is_empty() {
                let _ = save(&id, &r);
                return None;
            }
            // Everyone's certificate is from the new CA: retire the old one.
            let cas = pki::certs_of(&id.ca_pem);
            let new = cas.first()?;
            if let Err(e) = write(&id.dir.join("ca.crt"), new.as_bytes(), false) {
                return Some(format!("CA rotation: can't write the bundle: {e}"));
            }
            let _ = std::fs::remove_file(id.dir.join("ca-old.key"));
            let _ = std::fs::remove_file(path(&id));
            cluster.bump_cert_generation();
            Some(format!(
                "CA rotation finished: the old CA ({}) is retired",
                &r.old_fp[..r.old_fp.len().min(16)]
            ))
        }
        other => Some(format!("CA rotation: unknown phase `{other}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn primary() -> (tempfile::TempDir, Identity) {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::init(
            dir.path(),
            "home",
            vec!["https://127.0.0.1:1".into()],
            "lab",
        )
        .unwrap();
        (dir, id)
    }

    // REQ: CLU-001 (T5.4c) — a rotation starts once, on the primary, with both CAs trusted and
    // the old one still signing.
    #[test]
    fn clu_001_rotation_starts_with_both_cas_trusted() {
        let (_d, id) = primary();
        let old = pki::certs_of(&id.ca_pem).remove(0);
        let r = start(&id, "test").unwrap();
        assert_eq!(r.phase, "trust");
        let now = id.reload();
        let cas = pki::certs_of(&now.ca_pem);
        assert_eq!(cas.len(), 2);
        assert_eq!(
            pki::fingerprint(&cas[0]).unwrap(),
            pki::fingerprint(&old).unwrap(),
            "the old CA still signs"
        );
        assert!(now.signs_now());
        assert!(now.next_ca_key_pem().is_some());
        assert!(start(&id, "again").is_err(), "one rotation at a time");
    }

    // A node adopts a bundle only if it keeps a CA it trusts; a key that arrives before its CA
    // is held, then used once a verified bundle trusts it.
    #[test]
    fn clu_001_trust_moves_step_by_step() {
        use crate::node::{TrustStep, TrustVersion};
        // The version of the rotation's manifest number `seq` (ADR-177).
        let at = |id: &Identity, seq: u64| TrustVersion {
            cluster_id: id.meta.cluster_id.clone(),
            epoch: 1,
            seq,
        };
        let (_d, id) = primary();
        let stranger = pki::new_ca("evil").unwrap();
        assert!(
            id.adopt_trust(&stranger.cert_pem, &at(&id, 1)).is_err(),
            "an unrelated CA can't replace trust"
        );
        let next = pki::new_ca_labeled("home", "next").unwrap();
        // The next key arrives first: held, not trusted.
        let (_d2, replica) = primary();
        // A replica-like node: its own single CA, and a pending key for a CA it doesn't trust yet.
        assert!(!replica.store_ca_key(&next.key_pem).unwrap());
        assert!(replica.dir.join("ca-pending.key").exists());
        let bundle = format!("{}{}", replica.ca_pem, next.cert_pem);
        let take = |b: &str, seq| replica.adopt_trust(b, &at(&replica, seq)).unwrap();
        assert_eq!(take(&bundle, 1), TrustStep::Changed);
        assert!(
            replica.dir.join("ca-next.key").exists(),
            "held key promoted"
        );
        assert!(!replica.dir.join("ca-pending.key").exists());
        // The switch: the new CA first; its key becomes ca.key.
        let flipped = format!("{}{}", next.cert_pem, replica.ca_pem);
        assert_eq!(take(&flipped, 2), TrustStep::Changed);
        assert!(replica.reload().signs_now());
        assert!(replica.dir.join("ca-old.key").exists());
        // The end: only the new CA; the old key goes.
        assert_eq!(take(&next.cert_pem, 3), TrustStep::Changed);
        assert!(!replica.dir.join("ca-old.key").exists());
        assert_eq!(pki::certs_of(&replica.reload().ca_pem).len(), 1);
    }

    // REQ: CLU-001, CLU-005 (ADR-066) — the primary's switch moves the key files under their lock,
    // as a replica's trust change does: a key share arriving in the middle (a primary takes one
    // only from a newer-epoch primary, which holds the same next key) waits for the switch,
    // instead of storing a second copy of the signing key as `ca-next.key`, which no later step
    // removes.
    #[test]
    fn clu_001_a_key_share_cannot_slip_into_the_primarys_switch() {
        use std::cell::RefCell;
        use std::rc::Rc;
        use std::sync::{Arc, mpsc};
        use std::thread::JoinHandle;
        use std::time::Duration;
        let (_d, id) = primary();
        start(&id, "test").unwrap();
        let next_key = std::fs::read_to_string(id.dir.join("ca-next.key")).unwrap();
        let cluster = Cluster::new(id.reload(), "0.1.0");
        let lock = crate::node::key_files_lock(&id.dir);
        let share: Rc<RefCell<Option<JoinHandle<()>>>> = Rc::default();
        let (slot, by) = (Rc::clone(&share), id.clone());
        AFTER_SWITCH_MOVES.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                // Whether the step holds the key-file lock here (it can't be taken from this
                // thread then), and the handles on the lock before the share starts.
                let serialised = lock.try_lock().is_err();
                let before = Arc::strong_count(&lock);
                let (by, key) = (by.clone(), next_key.clone());
                let (tx, rx) = mpsc::channel();
                let t = std::thread::spawn(move || {
                    let _ = by.store_ca_key(&key);
                    let _ = tx.send(());
                });
                // Unserialised, the share runs to its end right here, inside the switch.
                // Serialised, it can only wait: once it holds a handle on the lock, it does.
                let not_yet = || {
                    if serialised {
                        Arc::strong_count(&lock) == before
                    } else {
                        rx.try_recv().is_err()
                    }
                };
                let mut waited = 0;
                while not_yet() {
                    assert!(waited < 10_000, "the key share neither ran nor waited");
                    waited += 1;
                    std::thread::sleep(Duration::from_millis(1));
                }
                *slot.borrow_mut() = Some(t);
            }));
        });
        let msg = step(&cluster).unwrap();
        AFTER_SWITCH_MOVES.with(|h| *h.borrow_mut() = None);
        share.borrow_mut().take().unwrap().join().unwrap();
        assert!(msg.contains("now signs"), "{msg}");
        assert!(
            !id.dir.join("ca-next.key").exists(),
            "the share stored a copy of the signing key as the next key"
        );
        assert!(id.reload().signs_now());
    }

    // REQ: CLU-001 (ADR-066) — each write has a temporary file of its own. The property, shown on
    // two files of one stem written at the same moment (a rotation never writes this pair: the
    // old fixed name was shared only by two writes of one file): they never trade contents, and
    // neither write fails because the other renamed its temporary file away.
    #[test]
    fn clu_001_rotation_writes_never_share_a_temporary_file() {
        use std::sync::{Arc, Barrier};
        let dir = tempfile::tempdir().unwrap();
        let (key, crt) = (dir.path().join("ca.key"), dir.path().join("ca.crt"));
        let rounds = 500;
        let mut clashes = 0;
        for round in 0..rounds {
            let barrier = Arc::new(Barrier::new(2));
            let t = {
                let (key, barrier) = (key.clone(), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    write(&key, format!("key {round}").as_bytes(), true)
                })
            };
            barrier.wait();
            let wrote_crt = write(&crt, format!("crt {round}").as_bytes(), false);
            let wrote_key = t.join().unwrap();
            let read = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
            if wrote_key.is_err()
                || wrote_crt.is_err()
                || read(&key) != format!("key {round}")
                || read(&crt) != format!("crt {round}")
            {
                clashes += 1;
            }
        }
        assert_eq!(clashes, 0, "{clashes} of {rounds} rounds clashed");
    }
}
