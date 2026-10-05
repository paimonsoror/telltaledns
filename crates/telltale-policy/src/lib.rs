//! Client identification, groups, schedules, rate limiting, rewrites, and local data.
//!
//! Part of TelltaleDNS. See `spec/02-architecture.md` §2 and `spec/03` §3.

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]

pub mod clients;
pub mod local;
pub mod quick;
pub mod ratelimit;
pub mod special;

use std::net::IpAddr;

use telltale_config::Cidr;

pub use clients::{BlockPolicy, Client, ClientTable, Group, IdSource, Identity, Neighbors, Pause};
pub use local::{LoadReport, LocalData, reverse_name};
pub use quick::{QuickMatch, QuickRule, QuickRules, RuleScope, quick_ref};
pub use ratelimit::RateLimiter;
pub use special::{Special, classify};

/// True if `ip` may use the resolver (`spec/08` §6: refuse everyone outside these networks).
pub fn is_allowed(networks: &[Cidr], ip: IpAddr) -> bool {
    networks.iter().any(|n| n.contains(ip))
}
