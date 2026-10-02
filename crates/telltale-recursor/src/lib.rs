//! Iterative resolver and DNSSEC validator.
//!
//! Part of TelltaleDNS. See `spec/02-architecture.md` §2.

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]
