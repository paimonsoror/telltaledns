//! Columnar query-log segment store and SQLite state.
//!
//! Part of TelltaleDNS. See `spec/02-architecture.md` §2 and `spec/06` §3–4.

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]

pub mod qlog;
