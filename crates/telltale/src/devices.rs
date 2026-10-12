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

/// REQ: CLU-002, API-010 (ADR-125) — the device names other nodes know: the ones their
/// routers and mDNS saw. Only one node usually reads the router (the one holding its API
/// key), and a pod can't hear the LAN's mDNS, so without these a resolver pod's query-log
/// rows name a device by its address while the primary's rows name it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Names {
    pub(crate) routers: Leases,
    pub(crate) mdns: Leases,
}

/// The cluster call that asks a peer for its own device names.
pub(crate) const KIND: &str = "devices.names";
/// How often a node asks its peers (routers are read every few minutes).
const EVERY: std::time::Duration = std::time::Duration::from_secs(60);
/// How long a peer has to answer.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

/// What this node answers: only the names it learned itself, never ones it got from peers
/// (a name a router forgot doesn't keep circulating between nodes).
pub(crate) fn own(pipeline: &crate::pipeline::Pipeline) -> Result<Vec<u8>, String> {
    let names = Names {
        routers: (**pipeline.router_leases.load()).clone(),
        mdns: (**pipeline.mdns_names.load()).clone(),
    };
    serde_json::to_vec(&names).map_err(|e| e.to_string())
}

/// The peers' answers as one table: the primary's first, then by node ID; the first node to
/// know an address names it.
fn merge(mut answers: Vec<(String, Names)>, primary: Option<&str>) -> Names {
    answers.sort_by(|a, b| {
        (Some(a.0.as_str()) != primary)
            .cmp(&(Some(b.0.as_str()) != primary))
            .then_with(|| a.0.cmp(&b.0))
    });
    let mut out = Names::default();
    for (_, n) in answers {
        for (ip, l) in n.routers {
            out.routers.entry(ip).or_insert(l);
        }
        for (ip, l) in n.mdns {
            out.mdns.entry(ip).or_insert(l);
        }
    }
    out
}

/// The task: every minute, ask every reachable peer for its device names. Off the DNS path;
/// a peer that doesn't answer (or is on an older build, "unknown call") is skipped, and when
/// none answer the last table stays.
pub(crate) async fn run(
    sources: std::sync::Arc<crate::http::Sources>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let Some(cluster) = sources.cluster.clone() else {
        return;
    };
    let mut tick = tokio::time::interval(EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            _ = tick.tick() => {}
        }
        let answers: Vec<(String, Names)> = cluster
            .call_all(KIND, &[], DEADLINE)
            .await
            .into_iter()
            .filter_map(|(peer, r)| {
                let body = r.ok()?;
                serde_json::from_slice(&body).ok().map(|n| (peer, n))
            })
            .collect();
        if answers.is_empty() {
            continue;
        }
        let primary = cluster.reachable_primary();
        let names = merge(answers, primary.as_deref());
        if **sources.pipeline.peer_names.load() != names {
            sources
                .pipeline
                .peer_names
                .store(std::sync::Arc::new(names));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(ip: [u8; 4], name: &str) -> Lease {
        Lease {
            mac: String::new(),
            ip: Ipv4Addr::from(ip),
            hostname: Some(name.into()),
            expires: 0,
        }
    }

    fn names(routers: &[Lease], mdns: &[Lease]) -> Names {
        Names {
            routers: routers.iter().map(|l| (l.ip, l.clone())).collect(),
            mdns: mdns.iter().map(|l| (l.ip, l.clone())).collect(),
        }
    }

    // REQ: CLU-002, API-010 — the primary's names win; others fill in what it doesn't know.
    #[test]
    fn clu_002_peer_names_merge_primary_first() {
        let a = names(&[lease([10, 0, 0, 2], "k8s-from-a")], &[]);
        let p = names(
            &[lease([10, 0, 0, 2], "k8s")],
            &[lease([10, 0, 0, 9], "printer")],
        );
        let z = names(&[lease([10, 0, 0, 3], "nas")], &[]);
        let m = merge(
            vec![("a".into(), a), ("z".into(), z), ("p".into(), p)],
            Some("p"),
        );
        let host =
            |t: &Leases, ip: [u8; 4]| t.get(&Ipv4Addr::from(ip)).and_then(|l| l.hostname.clone());
        assert_eq!(host(&m.routers, [10, 0, 0, 2]).as_deref(), Some("k8s"));
        assert_eq!(host(&m.routers, [10, 0, 0, 3]).as_deref(), Some("nas"));
        assert_eq!(host(&m.mdns, [10, 0, 0, 9]).as_deref(), Some("printer"));
    }

    // The wire form round-trips (addresses as map keys).
    #[test]
    fn clu_002_peer_names_wire_form() {
        let n = names(&[lease([192, 168, 5, 2], "k8s")], &[]);
        let back: Names = serde_json::from_slice(&serde_json::to_vec(&n).unwrap()).unwrap();
        assert_eq!(back, n);
    }
}
