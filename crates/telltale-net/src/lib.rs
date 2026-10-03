//! Network listeners (UDP/TCP/DoT/DoH/DoQ). The only crate allowed `unsafe`.
//!
//! Part of TelltaleDNS. See `spec/02-architecture.md` §2–3 and `spec/03` §1.
//!
//! REQ: NFR-003 — all `unsafe` lives in the private `sys` module (Linux syscalls), and every
//! block carries a `// SAFETY:` justification (enforced by `clippy::undocumented_unsafe_blocks`).

pub mod handler;
#[cfg(target_os = "linux")]
mod sys;
pub mod tcp;
pub mod udp;

pub use handler::{Deferred, QueryHandler, RequestMeta, Response, Transport};
pub use tcp::{TcpConfig, TcpServer, TcpStats};
pub use udp::{LocalAddr, UdpConfig, UdpListener, WorkerStats};

/// Default worker count: available parallelism (which honors cgroup CPU quotas on Linux),
/// per `spec/08` §3.3.
pub fn default_workers() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}
