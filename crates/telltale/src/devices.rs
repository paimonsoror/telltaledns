//! Names devices have outside TelltaleDNS (REQ: API-010; T8.2, T8.3): the DHCP clients of
//! the routers (`[[router]]`) and the names devices announce over mDNS, by IPv4 address.
//! TelltaleDNS doesn't hand out addresses itself (ADR-091): the router's DHCP does.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// One device as a router or mDNS knows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Lease {
    /// Empty when unknown (mDNS).
    pub(crate) mac: String,
    pub(crate) ip: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) hostname: Option<String>,
    /// Unix seconds (0 when unknown).
    pub(crate) expires: u64,
}

/// Devices by address.
pub(crate) type Leases = HashMap<Ipv4Addr, Lease>;
