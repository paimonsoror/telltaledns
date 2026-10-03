//! Blocklist parsers, rule compiler, FST/DFA snapshot format, and matcher.
//!
//! Part of TelltaleDNS. See `spec/02-architecture.md` §2.

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]

pub mod compile;
pub mod explain;
pub mod fetch;
pub mod matcher;
pub mod parse;
pub mod snapshot;
