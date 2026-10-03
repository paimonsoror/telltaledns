//! Client identification, groups, schedules, rate limiting, rewrites, and local data.
//!
//! Part of TelltaleDNS. See `spec/02-architecture.md` §2 and `spec/03` §3.

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]

pub mod local;

pub use local::{LoadReport, LocalData, reverse_name};
