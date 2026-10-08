//! REQ: OBS-003 (`spec/06` §4, review 04-05) — the key privacy level 1 hashes names with.
//!
//! An unkeyed hash let anyone holding a level-1 log confirm a guessed name by hashing it. Each
//! node keeps a random key in `<data_dir>/privacy.key` (owner-only); in a cluster the primary
//! publishes its key with every version and the other nodes adopt it, so names hash the same
//! everywhere and shipped logs group with the primary's.

use std::io;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

fn path(data_dir: &Path) -> PathBuf {
    data_dir.join("privacy.key")
}

fn parse(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(key)
}

fn write(data_dir: &Path, hex: &str) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::create_dir_all(data_dir)?;
    let tmp = data_dir.join("privacy.key.tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(hex.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(tmp, path(data_dir))
}

/// This node's key as hex, creating one on first use.
pub(crate) fn current_hex(data_dir: &Path) -> Option<String> {
    if let Some(k) = std::fs::read_to_string(path(data_dir))
        .ok()
        .filter(|s| parse(s).is_some())
    {
        return Some(k.trim().to_owned());
    }
    let key: [u8; 32] = rand::random();
    let hex = telltale_api::auth::crypto::hex(&key);
    match write(data_dir, &hex) {
        Ok(()) => Some(hex),
        Err(e) => {
            warn!("privacy key: can't store it: {e}");
            None
        }
    }
}

/// Loads (or creates) this node's key and hashes level-1 names with it from now on.
pub(crate) fn init(data_dir: &Path) {
    if let Some(k) = current_hex(data_dir).as_deref().and_then(parse) {
        telltale_telemetry::event::set_privacy_key(k);
    } else {
        warn!("privacy key unavailable: level-1 names are hashed without a key");
    }
}

/// Adopts the cluster's key from the primary's manifest: stored, and used from now on.
pub(crate) fn adopt(data_dir: &Path, hex: &str) {
    let Some(key) = parse(hex) else {
        warn!("privacy key from the primary isn't 32 bytes of hex: ignored");
        return;
    };
    if current_hex(data_dir).as_deref() == Some(hex.trim()) {
        return;
    }
    if let Err(e) = write(data_dir, hex.trim()) {
        warn!("privacy key: can't store the cluster's: {e}");
    }
    telltale_telemetry::event::set_privacy_key(key);
    info!("privacy key: using the cluster's (level-1 names now hash as on the primary)");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: OBS-003 (review 04-05) — a node makes its key once and keeps it; a replica adopts
    /// the primary's; nonsense is ignored.
    #[test]
    fn obs_003_privacy_key_is_made_once_and_adopted_from_the_primary() {
        let dir = tempfile::tempdir().unwrap();
        let first = current_hex(dir.path()).unwrap();
        assert_eq!(first.len(), 64);
        assert_eq!(
            current_hex(dir.path()).as_deref(),
            Some(first.as_str()),
            "kept"
        );
        let primary = "ab".repeat(32);
        adopt(dir.path(), &primary);
        assert_eq!(current_hex(dir.path()), Some(primary.clone()));
        adopt(dir.path(), "not hex");
        assert_eq!(current_hex(dir.path()), Some(primary), "nonsense ignored");
    }
}
