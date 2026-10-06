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

/// REQ: OBS-002 (T9.13) — the run record, inside the data directory.
pub(crate) const RUNS_FILE: &str = "runs.json";

/// REQ: OBS-002 (T9.13) — how often a node has started on this data directory, and how many
/// of those followed a run that never stopped cleanly (a crash, an OOM kill, a power cut).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Runs {
    pub(crate) starts: u64,
    pub(crate) unclean: u64,
    /// Set while a process runs; still set at the next start means the last one didn't stop.
    #[serde(default)]
    pub(crate) running: bool,
}

/// This process's view of the run record (zero until [`record_start`]).
static RUNS: std::sync::OnceLock<Runs> = std::sync::OnceLock::new();

/// The run record as of this process's start.
pub(crate) fn runs() -> Runs {
    RUNS.get().copied().unwrap_or_default()
}

/// REQ: OBS-002 (T9.13) — counts this start (and an unclean one when the last run never
/// stopped) and marks the record running. A missing or unreadable record starts over.
pub(crate) fn record_start(dir: &Path) -> Runs {
    let path = dir.join(RUNS_FILE);
    let mut r: Runs = fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    if r.running {
        r.unclean += 1;
    }
    r.starts += 1;
    r.running = true;
    write_runs(&path, &r);
    let _ = RUNS.set(r);
    r
}

/// REQ: OBS-002 (T9.13) — a clean stop: the next start isn't counted as unclean.
pub(crate) fn record_stop(dir: &Path) {
    let mut r = runs();
    if r.starts == 0 {
        return;
    }
    r.running = false;
    write_runs(&dir.join(RUNS_FILE), &r);
}

fn write_runs(path: &Path, r: &Runs) {
    let tmp = path.with_extension("json.tmp");
    let ok = serde_json::to_vec(r)
        .is_ok_and(|b| fs::write(&tmp, b).is_ok() && fs::rename(&tmp, path).is_ok());
    if !ok {
        tracing::warn!(path = %path.display(), "couldn't write the run record (restart counts)");
    }
}

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
    /// REQ: OBS-002 (T9.13) — starts count up; a run that never stopped makes the next
    /// start unclean; a clean stop doesn't.
    #[test]
    fn obs_002_run_record() {
        let dir = std::env::temp_dir().join(format!("tt-runs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let read =
            || -> Runs { serde_json::from_slice(&fs::read(dir.join(RUNS_FILE)).unwrap()).unwrap() };
        // `record_start` also sets the process-wide copy once; the file is what's checked.
        record_start(&dir);
        assert_eq!(
            read(),
            Runs {
                starts: 1,
                unclean: 0,
                running: true
            }
        );
        record_start(&dir); // the first never stopped
        assert_eq!(
            read(),
            Runs {
                starts: 2,
                unclean: 1,
                running: true
            }
        );
        let mut r = read();
        r.running = false;
        write_runs(&dir.join(RUNS_FILE), &r);
        record_start(&dir);
        assert_eq!(
            read(),
            Runs {
                starts: 3,
                unclean: 1,
                running: true
            }
        );
        fs::write(dir.join(RUNS_FILE), b"not json").unwrap();
        record_start(&dir);
        assert_eq!(
            read(),
            Runs {
                starts: 1,
                unclean: 0,
                running: true
            },
            "starts over"
        );
        let _ = fs::remove_dir_all(&dir);
    }

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
