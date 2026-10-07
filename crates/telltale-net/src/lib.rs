//! Network listeners (UDP/TCP/DoT/DoH/DoQ). The only crate allowed `unsafe`.
//!
//! Part of TelltaleDNS. See `spec/02-architecture.md` §2–3 and `spec/03` §1.
//!
//! REQ: NFR-003 — all `unsafe` lives in the private `sys` module (Linux syscalls), and every
//! block carries a `// SAFETY:` justification (enforced by `clippy::undocumented_unsafe_blocks`).

pub mod doh;
pub mod doh3;
pub mod doq;
pub mod handler;
pub mod neigh;
pub mod proxy;
#[cfg(target_os = "linux")]
mod sys;
pub mod tcp;
pub mod tls;
pub mod udp;

pub use doh::{DohConfig, DohServer, DohStats};
pub use doh3::{Doh3Config, Doh3Server};
pub use doq::{DoqConfig, DoqServer, DoqStats};
pub use handler::{ClientId, Deferred, QueryHandler, RequestMeta, Response, Transport};
pub use neigh::{Neighbor, neighbors};
#[cfg(target_os = "linux")]
pub use sys::MappedFile;

/// REQ: NFR-002 (T10.2) — elsewhere a "mapped" file is read into memory.
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct MappedFile(Box<[u8]>);

#[cfg(not(target_os = "linux"))]
impl MappedFile {
    pub fn open(path: &std::path::Path) -> std::io::Result<Self> {
        Ok(Self(std::fs::read(path)?.into_boxed_slice()))
    }

    pub fn release(&self) {}
}

#[cfg(not(target_os = "linux"))]
impl std::ops::Deref for MappedFile {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(not(target_os = "linux"))]
impl AsRef<[u8]> for MappedFile {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
pub use tcp::{TcpConfig, TcpServer, TcpStats};
pub use tls::CertStore;
pub use udp::{LocalAddr, UdpConfig, UdpListener, WorkerStats};

/// Lowers the calling thread's CPU priority to at least `nice` (0–19), for background work
/// that must never slow queries, such as list compilation (`spec/05` §3.4). Best effort: a
/// no-op off Linux.
pub fn lower_thread_priority(nice: i32) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        sys::lower_thread_priority(nice)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = nice;
        Ok(())
    }
}

/// Makes the calling thread background-only, for work that must never delay a query (list
/// compilation, index builds; `spec/05` §3.4): `SCHED_IDLE` on Linux, so it only uses CPU
/// nobody else wants and yields the moment a worker wakes. Falls back to nice 19 where
/// `SCHED_IDLE` isn't allowed. Best effort: a no-op off Linux.
pub fn background_thread() {
    #[cfg(target_os = "linux")]
    {
        if sys::idle_thread().is_err() {
            let _ = sys::lower_thread_priority(19);
        }
    }
}

/// Default worker count: available parallelism (which honors cgroup CPU quotas on Linux),
/// per `spec/08` §3.3.
pub fn default_workers() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

/// REQ: CLU-008 (T6.11) — the size and free space (for unprivileged users) of the filesystem
/// holding `path`, in bytes: `(total, available)`. `None` off Linux or when it can't be read.
/// Lives here because it needs a syscall, and only this crate may use `unsafe`.
pub fn filesystem_space(path: &std::path::Path) -> Option<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        sys::statvfs(path).ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}
