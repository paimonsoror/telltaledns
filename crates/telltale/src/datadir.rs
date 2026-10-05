//! REQ: CLU-008, OPS-002 (T6.14, ADR-068) — one process per data directory. A node's identity,
//! `state.db`, query log, and cache dump belong to exactly one process: two replicas of a
//! single-volume Deployment (or two `telltale run` on one machine) would share and corrupt them.
//! `telltale run` takes an exclusive lock on `<data_dir>/telltale.lock` and keeps it until it
//! exits; the operating system releases it even after a crash, so a stale lock can't block a
//! restart.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::Path;
use std::time::{Duration, Instant};

/// The lock file, inside the data directory.
pub(crate) const LOCK_FILE: &str = "telltale.lock";

/// Held for as long as the process runs.
#[derive(Debug)]
pub(crate) struct DataDirLock {
    _file: File,
}

/// Why the lock wasn't taken.
#[derive(Debug)]
pub(crate) enum LockError {
    /// Another process holds it; the text is what it wrote about itself.
    Held(String),
    /// The lock file couldn't be opened (e.g. a read-only data directory).
    Io(std::io::Error),
}

/// Takes the lock, retrying for up to `wait` while another process holds it (a previous process
/// may still be shutting down).
pub(crate) fn lock(dir: &Path, wait: Duration) -> Result<DataDirLock, LockError> {
    fs::create_dir_all(dir).map_err(LockError::Io)?;
    let path = dir.join(LOCK_FILE);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(LockError::Io)?;
    let deadline = Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(TryLockError::WouldBlock) => {
                let mut holder = String::new();
                let _ = file.read_to_string(&mut holder);
                return Err(LockError::Held(holder.trim().replace('\n', ", ")));
            }
            Err(TryLockError::Error(e)) => return Err(LockError::Io(e)),
        }
    }
    // Who holds it, for the next process's error message (best effort).
    let now_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
    let me = format!(
        "pid {}\nhost {}\nsince {}",
        std::process::id(),
        host_name(),
        telltale_api::time::format_us(now_us)
    );
    let _ = file
        .set_len(0)
        .and_then(|()| file.seek(SeekFrom::Start(0)))
        .and_then(|_| file.write_all(me.as_bytes()));
    Ok(DataDirLock { _file: file })
}

/// The pod or machine name.
fn host_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| fs::read_to_string("/proc/sys/kernel/hostname").ok())
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: CLU-008 (T6.14) — a second holder is refused and told who has it; the lock comes
    /// back once the first lets go.
    #[test]
    fn clu_008_one_process_per_data_dir() {
        let dir = std::env::temp_dir().join(format!("tt-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let first = lock(&dir, Duration::ZERO).expect("first lock");
        match lock(&dir, Duration::from_millis(300)) {
            Err(LockError::Held(who)) => {
                assert!(
                    who.contains(&format!("pid {}", std::process::id())),
                    "{who}"
                );
                assert!(who.contains("since "), "{who}");
            }
            other => panic!("expected Held, got {other:?}"),
        }
        drop(first);
        let again = lock(&dir, Duration::ZERO);
        assert!(again.is_ok(), "{again:?}");
        drop(again);
        let _ = fs::remove_dir_all(&dir);
    }
}
