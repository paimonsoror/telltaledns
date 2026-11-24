//! Names devices have outside TelltaleDNS (REQ: API-010; T8.2, T8.3): the DHCP clients of
//! the routers (`[[router]]`) and the names devices announce over mDNS, by IPv4 address.
//! TelltaleDNS doesn't hand out addresses itself (ADR-091): the router's DHCP does.

use std::collections::{HashMap, HashSet};
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
    /// REQ: T8.2 (ADR-166) — a client the router remembers but doesn't see now (UniFi's offline
    /// clients): it names an address in the query log, but it isn't "seen", so device
    /// identification doesn't count it. Not written when false, so a node on an older build,
    /// which doesn't know the field, reads the same form as before.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) offline: bool,
    /// REQ: FLT-006, CLU-002 (ADR-183) — a connected client whose binding of this address to this
    /// MAC can't be trusted to identify a device: the routers disagree on the address, one MAC
    /// sits at several addresses (a range extender), UniFi gave the address from its last-known
    /// one, or the router that said so hasn't answered for 15 minutes. It still names the
    /// address (display), but it never identifies, and no lower source fills the address.
    /// Not written when false, so a node on an older build, which doesn't know the field, reads
    /// the same form as before.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) unsure: bool,
    /// REQ: FLT-006, CLU-002 (ADR-183) — the router that gave this row has been silent for 15
    /// minutes: the row is its last answer, kept for display and (always also `unsure`) to
    /// withhold its own address on the node that reads that router. A row like this is never
    /// counted as "a MAC at another address": a router that has gone silent doesn't veto what
    /// the fresh ones say, here or on another node, and another node drops the row altogether.
    /// Not written when false, so a node on an older build, which doesn't know the field,
    /// reads the same form as before (and still takes the row for an `unsure` one).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) stale: bool,
}

/// Devices by address.
pub(crate) type Leases = HashMap<Ipv4Addr, Lease>;

/// REQ: FLT-006 (ADR-183) — the MAC a lease can identify a device by: its client is connected
/// (not offline), its binding is not `unsure` and not `stale` (a stale row is always also `unsure`
/// as `rebuild` makes it, but this doesn't rely on it), and the MAC parses (`aa:bb:..` or
/// `aa-bb-..`), isn't all zero, and is unicast. Locally administered ("private") MACs count. MACs
/// are compared as parsed bytes, never as text.
pub(crate) fn eligible(l: &Lease) -> Option<[u8; 6]> {
    if l.offline || l.unsure || l.stale {
        return None;
    }
    usable_mac(&l.mac)
}

/// REQ: FLT-006 (ADR-183) — a MAC (as text) that can identify a device: it parses (`aa:bb:..` or
/// `aa-bb-..`), isn't all zero and is unicast.
pub(crate) fn usable_mac(mac: &str) -> Option<[u8; 6]> {
    let mac = crate::identify::oui::parse_mac(mac)?;
    (mac != [0; 6] && mac[0] & 1 == 0).then_some(mac)
}

/// REQ: CLU-002, API-010 (ADR-125) — the device names other nodes know: the ones their
/// routers and mDNS saw. Only one node usually reads the router (the one holding its API
/// key), and a pod can't hear the LAN's mDNS, so without these a resolver pod's query-log
/// rows name a device by its address while the primary's rows name it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Names {
    pub(crate) routers: Leases,
    pub(crate) mdns: Leases,
    /// REQ: FLT-006, CLU-010 (ADR-183) — written (true) by a node that marks its router bindings
    /// the way ADR-183 says (`unsure`, silence, one MAC at several addresses): another node
    /// takes MAC bindings only from an answer that carries it. An answer from an older node
    /// has no such field, so its lists name devices but identify none. Not written when false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) vetted: bool,
}

/// The cluster call that asks a peer for its own device names.
pub(crate) const KIND: &str = "devices.names";
/// How often a node asks its peers (routers are read every few minutes).
const EVERY: std::time::Duration = std::time::Duration::from_secs(60);
/// How long a peer has to answer.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);
/// REQ: CLU-002 (ADR-183) — until a full member has answered, a node asks again this often,
/// for at most [`RETRY_FOR_S`] seconds after it started, so a new pod or a restarted node
/// doesn't wait a minute for the first answer.
const RETRY: std::time::Duration = std::time::Duration::from_secs(5);
/// How long after start the quick retry lasts.
const RETRY_FOR_S: u64 = 120;
/// REQ: FLT-006, CLU-002 (ADR-183) — how long a member's last answer keeps identifying devices
/// here (monotonic seconds). With the router's own 15-minute bound, a stale binding lives about
/// 30 minutes plus one exchange: a node passes on only what its own routers said.
pub(crate) const PEER_MACS_FOR_S: u64 = 900;

/// What this node answers: only the names it learned itself, never ones it got from peers
/// (a name a router forgot doesn't keep circulating between nodes). REQ: FLT-006 (ADR-183) —
/// marked `vetted`: its router bindings follow the rules of ADR-183.
pub(crate) fn own(pipeline: &crate::pipeline::Pipeline) -> Result<Vec<u8>, String> {
    let names = Names {
        routers: (**pipeline.router_leases.load()).clone(),
        mdns: (**pipeline.mdns_names.load()).clone(),
        vetted: true,
    };
    serde_json::to_vec(&names).map_err(|e| e.to_string())
}

/// REQ: FLT-006, CLU-002 (ADR-183) — what the other full members' routers say, as this node uses it
/// to identify devices: an address to a MAC they agree on, and the addresses any of them withholds
/// (a connected lease that is `unsure` or whose MAC can't identify) or that two of them disagree on
/// (tombstones: no lower source fills them).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PeerMacs {
    pub(crate) macs: HashMap<Ipv4Addr, [u8; 6]>,
    pub(crate) tombstones: HashSet<Ipv4Addr>,
    /// Every (address, MAC) pair a member reported at an address that ended up withheld (a lease
    /// that is `unsure`, or an address two members disagree about): the MAC is still a MAC seen
    /// there, so [`router_bindings`] counts it toward the shared-MAC rule.
    pub(crate) withheld: HashSet<(Ipv4Addr, [u8; 6])>,
}

/// What a member's answer said about one address: the MAC its lease carries when that MAC can
/// identify a device (parses, isn't zero or multicast), and whether the lease is sure (connected,
/// not `unsure`, with such a MAC): only a sure lease binds the address; any other withholds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemberBinding {
    mac: Option<[u8; 6]>,
    sure: bool,
}

/// Each full member's last vetted answer, as the bindings it gave (by address) and when it came
/// (monotonic seconds).
pub(crate) type MemberBindings = HashMap<String, (HashMap<Ipv4Addr, MemberBinding>, u64)>;

/// REQ: FLT-006, CLU-002, CLU-010 (ADR-183) — keeps, per member, the bindings of its last answer
/// at `now`: only from answers that carry `vetted` and come from a full member (`full`: the
/// registry lists it and it isn't ephemeral), each connected lease as a [`MemberBinding`] (a lease
/// that is `unsure` or whose MAC can't identify withholds its address, as this node's own does).
/// Offline ones are skipped, and so are `stale` ones (the member's router has been silent for 15
/// minutes: its old rows withhold nothing here and count toward nothing). An answer that is not `vetted` (the member was rolled back to a build
/// without the marks) removes the member's bindings kept so far, at once. Then forgets every
/// member that is no longer full or hasn't answered for more than [`PEER_MACS_FOR_S`] seconds.
/// Saturating: a time in the future is not old.
pub(crate) fn keep_answers(
    last: &mut MemberBindings,
    answers: &[(String, Names)],
    now: u64,
    full: impl Fn(&str) -> bool,
) {
    for (peer, names) in answers {
        if !names.vetted {
            last.remove(peer);
            continue;
        }
        if !full(peer) {
            continue;
        }
        // A stale row (its router has been silent for 15 minutes) is dropped like an offline one:
        // it withholds nothing here and counts toward nothing (its own node keeps its address
        // withheld, and an older node, which doesn't know the mark, reads it as `unsure`).
        let bindings = names
            .routers
            .iter()
            .filter(|(_, l)| !l.offline && !l.stale)
            .map(|(ip, l)| {
                let b = MemberBinding {
                    mac: usable_mac(&l.mac),
                    sure: eligible(l).is_some(),
                };
                (*ip, b)
            })
            .collect();
        last.insert(peer.clone(), (bindings, now));
    }
    last.retain(|peer, (_, at)| full(peer) && now.saturating_sub(*at) <= PEER_MACS_FOR_S);
}

/// REQ: FLT-006, CLU-002 (ADR-183) — the bindings the members agree on: an address that any
/// member withholds, or that two members give different MACs for, is a tombstone, and every MAC
/// the members gave at a tombstoned address is kept in `withheld` (it still counts toward the
/// shared-MAC rule). The result doesn't depend on the order of the members.
pub(crate) fn peer_macs(last: &MemberBindings) -> PeerMacs {
    let mut agreed: HashMap<Ipv4Addr, [u8; 6]> = HashMap::new();
    let mut tombstones: HashSet<Ipv4Addr> = HashSet::new();
    let mut seen: HashSet<(Ipv4Addr, [u8; 6])> = HashSet::new();
    for (bindings, _) in last.values() {
        for (ip, b) in bindings {
            if let Some(m) = b.mac {
                seen.insert((*ip, m));
            }
            match (b.mac.filter(|_| b.sure), agreed.get(ip)) {
                (None, _) => {
                    tombstones.insert(*ip);
                }
                (Some(m), Some(other)) if other != &m => {
                    tombstones.insert(*ip);
                }
                (Some(m), None) => {
                    agreed.insert(*ip, m);
                }
                (Some(_), Some(_)) => {}
            }
        }
    }
    agreed.retain(|ip, _| !tombstones.contains(ip));
    seen.retain(|(ip, _)| tombstones.contains(ip));
    PeerMacs {
        macs: agreed,
        tombstones,
        withheld: seen,
    }
}

/// REQ: FLT-006, CLU-002 (ADR-183) — the MAC bindings that identify a device on this node, from
/// this node's routers and the members' (see [`router_bindings`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Bindings {
    /// This node's routers' sure bindings.
    pub(crate) own: HashMap<Ipv4Addr, [u8; 6]>,
    /// The members' bindings, for addresses this node has no binding or tombstone for.
    pub(crate) peer: HashMap<Ipv4Addr, [u8; 6]>,
    /// Addresses no router or member entry fills, and that this node has no binding of its own
    /// for: this node's connected leases that are `unsure` or whose MAC can't identify, and the
    /// members' (a tombstone a member gives for an address this node binds itself is not one).
    pub(crate) tombstones: HashSet<Ipv4Addr>,
    /// The addresses of a MAC that sits at two or more addresses (counted over every binding and
    /// withheld lease, this node's and the members', tombstoned addresses included), with that
    /// MAC: it identifies a device at none of them. The rows of a router that has gone silent
    /// (`Lease::stale`) are not counted, here or on another node: they never veto fresh data.
    /// Not also tombstones.
    pub(crate) shared: HashMap<Ipv4Addr, [u8; 6]>,
    /// How many addresses are withheld, each once: the tombstones and the shared addresses (the
    /// metric `telltale_router_macs_unsure`).
    pub(crate) unsure: usize,
}

/// REQ: FLT-006, CLU-002 (ADR-183) — what this node's routers (`own`) and the other full members'
/// (`peers`) say about which MAC is at an address, as far as identifying a device goes. The table
/// and `recognize()` (the identity's `recognition`) both read this one function's answer.
/// 1. this node's connected leases: a sure one binds its address (`eligible`); any other (`unsure`,
///    or a MAC that can't identify) withholds it (a tombstone); offline ones are skipped;
/// 2. the members' tombstones join, except for addresses this node binds itself; the members'
///    bindings fill the addresses that are neither this node's binding nor a tombstone;
/// 3. every MAC that is at two or more addresses, counted over this node's bindings and `unsure`
///    leases and every member binding and withheld lease (`PeerMacs::withheld`; tombstoned
///    addresses included, so a MAC-sharing extender can't hide behind an address one node
///    withholds), moves its addresses from the bindings to `shared`; the rows of a router that
///    has gone silent (`stale`) are not counted: they never veto fresh data (a stale row's own
///    address is still a tombstone here);
/// 4. `unsure` is the number of tombstones plus shared addresses.
pub(crate) fn router_bindings(own: &Leases, peers: &PeerMacs) -> Bindings {
    let mut b = Bindings::default();
    // Per MAC: its first address, and whether it has been seen at another.
    let mut at: HashMap<[u8; 6], (Ipv4Addr, bool)> = HashMap::new();
    let mut count = |ip: Ipv4Addr, mac: [u8; 6]| {
        at.entry(mac)
            .and_modify(|(first, many)| *many |= *first != ip)
            .or_insert((ip, false));
    };
    for (ip, l) in own {
        if l.offline {
            continue;
        }
        if let Some(mac) = eligible(l) {
            b.own.insert(*ip, mac);
            count(*ip, mac);
        } else {
            // Its address stays withheld here; a stale row (its router has been silent) is not
            // a MAC seen at an address, so it doesn't make anything shared (D5).
            b.tombstones.insert(*ip);
            if !l.stale
                && let Some(mac) = usable_mac(&l.mac)
            {
                count(*ip, mac);
            }
        }
    }
    for (ip, mac) in &peers.macs {
        count(*ip, *mac);
    }
    // The members' withheld addresses count too: a MAC a member isn't sure of at X is still at X.
    for (ip, mac) in &peers.withheld {
        count(*ip, *mac);
    }
    b.tombstones.extend(peers.tombstones.iter().copied());
    b.tombstones.retain(|ip| !b.own.contains_key(ip));
    for (ip, mac) in &peers.macs {
        if !b.own.contains_key(ip) && !b.tombstones.contains(ip) {
            b.peer.insert(*ip, *mac);
        }
    }
    let mut shared = HashMap::new();
    for map in [&mut b.own, &mut b.peer] {
        map.retain(|ip, mac| {
            let many = at.get(mac).is_some_and(|(_, many)| *many);
            if many {
                shared.insert(*ip, *mac);
            }
            !many
        });
    }
    b.unsure = b.tombstones.len() + shared.len();
    b.shared = shared;
    b
}

/// REQ: FLT-006 (ADR-183) — the MAC table: the kernel's entries first, then this node's routers',
/// then the members'. `None`: only the kernel's (no device is named by its MAC, or
/// `router_macs` is off), and nothing of the routers is built.
pub(crate) fn build_table(
    kernel: &[(std::net::IpAddr, [u8; 6])],
    bindings: Option<&Bindings>,
) -> telltale_policy::MacTable {
    let v4 = |m: &HashMap<Ipv4Addr, [u8; 6]>| -> Vec<(std::net::IpAddr, [u8; 6])> {
        m.iter()
            .map(|(ip, mac)| (std::net::IpAddr::V4(*ip), *mac))
            .collect()
    };
    match bindings {
        None => telltale_policy::MacTable::from_sources(
            kernel.iter().copied(),
            std::iter::empty(),
            std::iter::empty(),
            0,
        ),
        Some(b) => telltale_policy::MacTable::from_sources(
            kernel.iter().copied(),
            v4(&b.own),
            v4(&b.peer),
            b.unsure,
        ),
    }
}

/// REQ: CLU-002 (ADR-183) — whether the answers of this round end the quick retry: an answer that
/// is *kept* (a full member's, `vetted`) and carries router leases (it reads a router: its
/// bindings are what the retry is for). A full replica with no router key answers first in some
/// clusters, the primary can answer before its first read of its router, and a replica's first
/// round can come before its registry lists the answerer: none of those ends the retry.
pub(crate) fn answered_now(answers: &[(String, Names)], full: impl Fn(&str) -> bool) -> bool {
    answers
        .iter()
        .any(|(p, n)| full(p) && n.vetted && !n.routers.is_empty())
}

/// REQ: FLT-006, CLU-002 (ADR-183) — whether `peer` is a full cluster member: the member registry
/// lists it and it isn't ephemeral (as `rpc_handler` decides for a peer's requests). Nothing a peer
/// says about itself counts: its Hello's `primary` flag is a claim any node with a valid
/// certificate can make, and the rest of the cluster code refuses it too. A replica's first round
/// can come before its registry is written; the answer is then not used, and the quick retry goes
/// on until the registry lists the answerer.
pub(crate) fn is_full_member(registry: &[telltale_cluster::node::NodeRecord], peer: &str) -> bool {
    registry.iter().any(|n| n.node_id == peer && !n.ephemeral)
}

/// REQ: FLT-006, CLU-002 (ADR-183) — the check one round of [`run`] makes of each answering peer
/// ("is it a full member?"), built in one place that `run` and the tests both use. `_claimed_primary`
/// is the primary `reachable_primary()` reports: it is a parameter only so that the one call `run`
/// makes, and a test, can show it changes nothing; the check is the registry's alone, and the test
/// pins that.
pub(crate) fn full_check<'a>(
    registry: &'a [telltale_cluster::node::NodeRecord],
    _claimed_primary: Option<&str>,
) -> impl Fn(&str) -> bool + Copy + 'a {
    move |p: &str| is_full_member(registry, p)
}

/// REQ: FLT-006, CLU-002 (ADR-183) — how many rows of routers (this node's connected leases, and
/// the members' bindings and withheld addresses) have reached this node: what the "no router MAC
/// reaches this node" notice counts, from the same data [`router_bindings`] reads (a kernel entry
/// that shadows a router entry in the table doesn't hide it).
pub(crate) fn bindings_reaching(own: &Leases, peers: &PeerMacs) -> usize {
    // This node's connected rows (a stale router's are old news: nothing there identifies), and
    // what the members gave: a binding, or an address they withhold (the two never overlap).
    own.values().filter(|l| !l.offline && !l.stale).count()
        + peers.macs.len()
        + peers.tombstones.len()
}

/// REQ: CLU-002 (ADR-183) — how long to wait before asking the members again: [`RETRY`] while no
/// full member has answered and the node is under [`RETRY_FOR_S`] seconds old, else a minute.
pub(crate) fn next_wait(full_member_answered: bool, since_start_s: u64) -> std::time::Duration {
    if !full_member_answered && since_start_s < RETRY_FOR_S {
        RETRY
    } else {
        EVERY
    }
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
/// none answer the last table stays. REQ: CLU-002, FLT-006 (ADR-183) — until a full member has
/// answered, and for the first two minutes at most, every 5 seconds; and each round, answered
/// or not, the members' MAC bindings are brought up to date (a silent member's age out).
pub(crate) async fn run(
    sources: std::sync::Arc<crate::http::Sources>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let Some(cluster) = sources.cluster.clone() else {
        return;
    };
    // Time for the bindings is this task's monotonic clock, never the wall clock.
    let started = std::time::Instant::now();
    let mut last = MemberBindings::new();
    let mut answered = false;
    let mut wait = std::time::Duration::ZERO;
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(wait) => {}
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
        // A full member: in the registry and not ephemeral (as `rpc_handler` decides). The
        // registry is a small file: read off the async task.
        let registry = {
            let c = std::sync::Arc::clone(&cluster);
            tokio::task::spawn_blocking(move || c.identity.registry())
                .await
                .unwrap_or_default()
        };
        // The registry alone says who is a full member; `primary` below only orders display names.
        let primary = cluster.reachable_primary();
        let full = full_check(&registry, primary.as_deref());
        answered |= answered_now(&answers, full);
        let now = started.elapsed().as_secs();
        keep_answers(&mut last, &answers, now, full);
        let macs = peer_macs(&last);
        tracing::debug!(
            answers = answers.len(),
            vetted = answers.iter().filter(|(_, n)| n.vetted).count(),
            full = answers.iter().filter(|(p, _)| full(p)).count(),
            registry = registry.len(),
            kept_members = last.len(),
            bindings = macs.macs.len(),
            tombstones = macs.tombstones.len(),
            "devices.names round"
        );
        if **sources.pipeline.peer_router_macs.load() != macs {
            sources
                .pipeline
                .peer_router_macs
                .store(std::sync::Arc::new(macs));
        }
        wait = next_wait(answered, now);
        if answers.is_empty() {
            continue;
        }
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
            offline: false,
            unsure: false,
            stale: false,
        }
    }

    fn names(routers: &[Lease], mdns: &[Lease]) -> Names {
        Names {
            routers: routers.iter().map(|l| (l.ip, l.clone())).collect(),
            mdns: mdns.iter().map(|l| (l.ip, l.clone())).collect(),
            vetted: false,
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

    // REQ: T8.2, CLU-002 (ADR-166) — the offline mark travels to peers that know it, and costs
    // nothing on the wire for a connected device: its form is what older nodes already read, and
    // an answer from an older node (no field) is a connected device.
    #[test]
    fn t8_2_offline_mark_is_compatible_on_the_wire() {
        let connected = serde_json::to_string(&lease([10, 0, 0, 2], "k8s")).unwrap();
        assert!(!connected.contains("offline"), "{connected}");
        let gone = Lease {
            offline: true,
            ..lease([10, 0, 0, 3], "old phone")
        };
        let text = serde_json::to_string(&gone).unwrap();
        assert!(text.contains("\"offline\":true"), "{text}");
        assert_eq!(serde_json::from_str::<Lease>(&text).unwrap(), gone);
        let older = r#"{"mac":"","ip":"10.0.0.2","hostname":"k8s","expires":0}"#;
        assert!(!serde_json::from_str::<Lease>(older).unwrap().offline);
    }

    // REQ: FLT-006, CLU-002, CLU-010 (ADR-183) — the unsure mark travels to nodes that know it and
    // costs nothing on the wire for a sure binding: its form is what older nodes already read; an
    // answer from an older node (no field) is a sure binding; an older node, which has no such
    // field, reads the new form and ignores it.
    #[test]
    fn flt_006_unsure_mark_is_compatible_on_the_wire() {
        // What the previous version's `Lease` looks like: the same fields, none for `unsure`.
        #[derive(Debug, PartialEq, Deserialize)]
        struct PreviousLease {
            mac: String,
            ip: Ipv4Addr,
            #[serde(default)]
            hostname: Option<String>,
            expires: u64,
            #[serde(default)]
            offline: bool,
        }
        let sure = serde_json::to_string(&lease([10, 0, 0, 2], "k8s")).unwrap();
        assert!(!sure.contains("unsure"), "{sure}");
        let doubtful = Lease {
            unsure: true,
            mac: "aa:bb:cc:00:00:01".into(),
            ..lease([10, 0, 0, 3], "tv")
        };
        let text = serde_json::to_string(&doubtful).unwrap();
        assert!(text.contains("\"unsure\":true"), "{text}");
        assert_eq!(serde_json::from_str::<Lease>(&text).unwrap(), doubtful);
        let older = r#"{"mac":"aa:bb:cc:00:00:01","ip":"10.0.0.2","hostname":"k8s","expires":0}"#;
        assert!(!serde_json::from_str::<Lease>(older).unwrap().unsure);
        let old: PreviousLease = serde_json::from_str(&text).unwrap();
        assert_eq!(
            old,
            PreviousLease {
                mac: "aa:bb:cc:00:00:01".into(),
                ip: Ipv4Addr::new(10, 0, 0, 3),
                hostname: Some("tv".into()),
                expires: 0,
                offline: false,
            }
        );
        // The stale mark is written only when true, and an older answer has none; an older node
        // reads the row (still `unsure`) as before and ignores the mark.
        assert!(!sure.contains("stale"), "{sure}");
        assert!(!serde_json::from_str::<Lease>(older).unwrap().stale);
        let stale = Lease {
            stale: true,
            ..doubtful
        };
        let text = serde_json::to_string(&stale).unwrap();
        assert!(text.contains("\"stale\":true"), "{text}");
        assert_eq!(serde_json::from_str::<Lease>(&text).unwrap(), stale);
        let old: PreviousLease = serde_json::from_str(&text).unwrap();
        assert_eq!(old.ip, Ipv4Addr::new(10, 0, 0, 3), "{old:?}");
    }

    // REQ: FLT-006 (ADR-183) — a stale row (its router has been silent for 15 minutes) never
    // identifies a device by itself: `eligible` doesn't rely on `rebuild` also marking it `unsure`,
    // so a producer of `Lease` values that forgets to is not a way in.
    #[test]
    fn flt_006_a_stale_lease_never_identifies_even_when_not_marked_unsure() {
        let row = |stale: bool, unsure: bool| Lease {
            mac: "aa:bb:cc:00:00:01".into(),
            stale,
            unsure,
            ..lease([10, 0, 0, 2], "x")
        };
        assert_eq!(
            eligible(&row(false, false)),
            Some(MAC_A),
            "a fresh sure row does"
        );
        assert_eq!(
            eligible(&row(true, false)),
            None,
            "stale alone is not eligible"
        );
        assert_eq!(
            eligible(&row(true, true)),
            None,
            "stale and unsure (as rebuild makes it)"
        );
        assert_eq!(eligible(&row(false, true)), None, "unsure alone");
    }

    // REQ: FLT-006 (ADR-183) — only a connected client whose binding is sure, with a MAC that
    // parses (either separator, any case), isn't all zero and is unicast, can identify a device.
    // A locally administered ("private") MAC can.
    #[test]
    fn flt_006_offline_and_unsure_leases_never_identify() {
        let with = |mac: &str, offline: bool, unsure: bool| Lease {
            mac: mac.into(),
            offline,
            unsure,
            ..lease([10, 0, 0, 2], "x")
        };
        let desk = Some([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]);
        assert_eq!(eligible(&with("aa:bb:cc:00:00:01", false, false)), desk);
        assert_eq!(eligible(&with("AA-BB-CC-00-00-01", false, false)), desk);
        assert_eq!(
            eligible(&with("02:00:00:00:00:01", false, false)),
            Some([0x02, 0, 0, 0, 0, 0x01]),
            "a private MAC counts"
        );
        for (mac, offline, unsure, why) in [
            ("aa:bb:cc:00:00:01", true, false, "offline"),
            ("aa:bb:cc:00:00:01", false, true, "unsure"),
            ("aa:bb:cc:00:00:01", true, true, "both"),
            ("", false, false, "no MAC (mDNS)"),
            ("zz:bb:cc:00:00:01", false, false, "unparsable"),
            ("aa:bb:cc:00:01", false, false, "too short"),
            ("00:00:00:00:00:00", false, false, "all zero"),
            ("01:00:5e:00:00:01", false, false, "multicast"),
            ("ff:ff:ff:ff:ff:ff", false, false, "broadcast"),
        ] {
            assert_eq!(eligible(&with(mac, offline, unsure)), None, "{why}");
        }
    }

    const MAC_A: [u8; 6] = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01];
    const MAC_B: [u8; 6] = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02];

    fn at(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, last)
    }

    /// A connected client at 10.0.0.`last` with `mac`.
    fn bound(last: u8, mac: &str, unsure: bool) -> Lease {
        Lease {
            mac: mac.into(),
            unsure,
            ..lease([10, 0, 0, last], "x")
        }
    }

    /// A node's answer: its router leases, marked `vetted`.
    fn vetted(leases: &[Lease]) -> Names {
        Names {
            vetted: true,
            ..names(leases, &[])
        }
    }

    fn from_nodes(answers: Vec<(&str, Names)>) -> Vec<(String, Names)> {
        answers
            .into_iter()
            .map(|(p, n)| (p.to_owned(), n))
            .collect()
    }

    fn members(last: &MemberBindings) -> Vec<&str> {
        let mut m: Vec<&str> = last.keys().map(String::as_str).collect();
        m.sort_unstable();
        m
    }

    /// A registry entry: a full member, or an ephemeral one (a resolver pod).
    fn rec(id: &str, ephemeral: bool) -> telltale_cluster::node::NodeRecord {
        telltale_cluster::node::NodeRecord {
            node_id: id.into(),
            site: "s".into(),
            eligible: !ephemeral,
            advertise: Vec::new(),
            joined: 0,
            witness: false,
            ephemeral,
        }
    }

    /// Whether `peer` is a full member, as the task decides it. `claimed_primary` is the primary
    /// `reachable_primary()` reports: it must change nothing.
    fn full_by(
        registry: &[telltale_cluster::node::NodeRecord],
        claimed_primary: Option<&str>,
        peer: &str,
    ) -> bool {
        // The task's own check (what `run` builds each round), not just the function under it.
        full_check(registry, claimed_primary)(peer)
    }

    /// Whether these answers end the quick retry, as the task decides it (same `claimed_primary`,
    /// which changes nothing).
    fn retry_ends(
        answers: &[(String, Names)],
        full: impl Fn(&str) -> bool,
        claimed_primary: Option<&str>,
    ) -> bool {
        let _ = claimed_primary;
        answered_now(answers, full)
    }

    /// A connected lease of a router that has gone silent (15 minutes): it still names its address
    /// and never identifies (`unsure`), and says its router is stale.
    fn stale_row(last: u8, mac: &str) -> Lease {
        Lease {
            stale: true,
            ..bound(last, mac, true)
        }
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — a member's bindings count only from a full member (the
    // registry lists it, it isn't ephemeral): a resolver pod or a node the registry doesn't list
    // can send what it likes, and gives none. Its mDNS names, its offline clients and a lease
    // whose MAC can't identify give none either.
    #[test]
    fn clu_002_peer_router_macs_come_only_from_full_members() {
        let full = |p: &str| p == "pi" || p == "k8s";
        let mut last = MemberBindings::new();
        let answers = from_nodes(vec![
            (
                "pi",
                vetted(&[
                    bound(5, "aa:bb:cc:00:00:01", false),
                    bound(6, "AA-BB-CC-00-00-02", false),
                ]),
            ),
            ("pod-1", vetted(&[bound(7, "aa:bb:cc:00:00:03", false)])),
            ("ghost", vetted(&[bound(8, "aa:bb:cc:00:00:04", false)])),
        ]);
        keep_answers(&mut last, &answers, 10, full);
        assert_eq!(members(&last), ["pi"]);
        let m = peer_macs(&last);
        assert_eq!(m.macs, HashMap::from([(at(5), MAC_A), (at(6), MAC_B)]));
        assert!(m.tombstones.is_empty());

        let mut n = vetted(&[bound(9, "aa:bb:cc:00:00:05", false)]);
        n.mdns = names(&[], &[bound(10, "aa:bb:cc:00:00:06", false)]).mdns;
        for l in [
            Lease {
                offline: true,
                ..bound(11, "aa:bb:cc:00:00:07", false)
            },
            bound(12, "", false),
            bound(13, "01:00:5e:00:00:01", false),
            bound(14, "00:00:00:00:00:00", false),
        ] {
            n.routers.insert(l.ip, l);
        }
        keep_answers(&mut last, &from_nodes(vec![("pi", n)]), 20, full);
        let m = peer_macs(&last);
        assert_eq!(
            m.macs,
            HashMap::from([(at(9), [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x05])])
        );
        assert_eq!(
            m.tombstones,
            HashSet::from([at(12), at(13), at(14)]),
            "a connected lease whose MAC can't identify withholds its address; an offline one doesn't"
        );
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — a member that isn't sure of an address (its lease is
    // `unsure`) withdraws it for this node as well: the other members' binding for it is dropped
    // and the address is a tombstone, so no lower source fills it.
    #[test]
    fn clu_002_a_peers_unsure_lease_counts_as_a_disagreement() {
        let full = |p: &str| matches!(p, "pi" | "k8s" | "nas");
        let mut last = MemberBindings::new();
        let answers = from_nodes(vec![
            (
                "pi",
                vetted(&[
                    bound(5, "aa:bb:cc:00:00:01", false),
                    bound(6, "aa:bb:cc:00:00:02", false),
                ]),
            ),
            (
                "k8s",
                vetted(&[
                    bound(5, "aa:bb:cc:00:00:01", true),
                    bound(7, "aa:bb:cc:00:00:01", false),
                ]),
            ),
        ]);
        keep_answers(&mut last, &answers, 10, full);
        let m = peer_macs(&last);
        assert!(!m.macs.contains_key(&at(5)), "{m:?}");
        assert_eq!(m.tombstones, HashSet::from([at(5)]));
        assert_eq!(m.macs[&at(6)], MAC_B);
        assert_eq!(m.macs[&at(7)], MAC_A);

        // An unsure lease with no other member's binding is a tombstone all the same.
        let mut alone = MemberBindings::new();
        keep_answers(
            &mut alone,
            &from_nodes(vec![(
                "nas",
                vetted(&[bound(9, "aa:bb:cc:00:00:01", true)]),
            )]),
            10,
            full,
        );
        let m = peer_macs(&alone);
        assert!(m.macs.is_empty());
        assert_eq!(m.tombstones, HashSet::from([at(9)]));
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — two members that give an address different MACs both
    // lose it; one they agree on stays. What comes out doesn't depend on which answered first.
    #[test]
    fn clu_002_peers_disagreeing_on_an_address_drop_it() {
        let full = |_: &str| true;
        let pi = vetted(&[
            bound(5, "aa:bb:cc:00:00:01", false),
            bound(6, "aa:bb:cc:00:00:01", false),
        ]);
        let k8s = vetted(&[
            bound(5, "aa:bb:cc:00:00:02", false),
            bound(6, "aa-bb-cc-00-00-01", false),
        ]);
        let mut results = Vec::new();
        for order in [["pi", "k8s"], ["k8s", "pi"]] {
            let mut last = MemberBindings::new();
            for (i, who) in order.iter().enumerate() {
                let names = if *who == "pi" {
                    pi.clone()
                } else {
                    k8s.clone()
                };
                keep_answers(
                    &mut last,
                    &from_nodes(vec![(*who, names)]),
                    10 + i as u64,
                    full,
                );
            }
            results.push(peer_macs(&last));
        }
        assert_eq!(results[0], results[1]);
        let m = &results[0];
        assert!(!m.macs.contains_key(&at(5)));
        assert_eq!(m.tombstones, HashSet::from([at(5)]));
        assert_eq!(
            m.macs[&at(6)],
            MAC_A,
            "the same MAC written two ways is agreement"
        );
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — a member's last answer is used for 900 seconds (on the
    // monotonic clock), then forgotten; at once when the member leaves the registry; an answer
    // renews it; a time in the future (a clock that stepped) is not old, and nothing panics.
    #[test]
    fn clu_002_a_silent_member_is_dropped_after_15_minutes() {
        let full = |p: &str| p == "pi";
        let mut last = MemberBindings::new();
        let answer = from_nodes(vec![(
            "pi",
            vetted(&[bound(5, "aa:bb:cc:00:00:01", false)]),
        )]);
        keep_answers(&mut last, &answer, 100, full);
        for (now, kept) in [
            (100, true),
            (100 + PEER_MACS_FOR_S - 1, true),
            (100 + PEER_MACS_FOR_S, true),
            (100 + PEER_MACS_FOR_S + 1, false),
            (u64::MAX, false),
        ] {
            let mut l = last.clone();
            keep_answers(&mut l, &[], now, full);
            assert_eq!(!l.is_empty(), kept, "at {now}");
            assert_eq!(peer_macs(&l).macs.len(), usize::from(kept), "at {now}");
        }
        let mut l = last.clone();
        keep_answers(&mut l, &[], 101, |_| false);
        assert!(l.is_empty(), "a member the registry no longer lists");
        let mut l = last.clone();
        keep_answers(&mut l, &[], 5, full);
        assert!(!l.is_empty(), "now before the answer: not old, no panic");
        // A new answer renews the time.
        let mut l = last.clone();
        keep_answers(&mut l, &answer, 1_000, full);
        keep_answers(&mut l, &[], 1_000 + PEER_MACS_FOR_S, full);
        assert!(!l.is_empty());
        keep_answers(&mut l, &[], 1_000 + PEER_MACS_FOR_S + 1, full);
        assert!(l.is_empty());
        // An answer that isn't vetted doesn't renew it either.
        let mut l = last.clone();
        let unvetted = from_nodes(vec![(
            "pi",
            names(&[bound(5, "aa:bb:cc:00:00:01", false)], &[]),
        )]);
        keep_answers(&mut l, &unvetted, 500, full);
        keep_answers(&mut l, &[], 100 + PEER_MACS_FOR_S + 1, full);
        assert!(l.is_empty());
    }

    // REQ: FLT-006, CLU-010 (ADR-183) — an answer from a member on an earlier build (no `vetted`)
    // gives no bindings, since its lists have none of the rules, but it still names devices (the
    // display merge is unchanged). `vetted` is written only when true: the form is the old one
    // plus that field, which an older node ignores, and this node's own answer carries it.
    #[test]
    fn clu_010_bindings_from_an_older_member_are_not_used() {
        // What the previous version's answer looks like: the same fields, none for `vetted`.
        #[derive(Debug, Deserialize)]
        struct PreviousNames {
            routers: Leases,
            mdns: Leases,
        }
        let older = r#"{"routers":{"10.0.0.5":{"mac":"aa:bb:cc:00:00:01","ip":"10.0.0.5","hostname":"desk","expires":0}},"mdns":{}}"#;
        let n: Names = serde_json::from_str(older).unwrap();
        assert!(!n.vetted);
        let answers = vec![("pi".to_owned(), n)];
        let mut last = MemberBindings::new();
        keep_answers(&mut last, &answers, 10, |_| true);
        assert!(last.is_empty());
        assert_eq!(peer_macs(&last), PeerMacs::default());
        let merged = merge(answers, None);
        assert_eq!(
            merged.routers[&at(5)].hostname.as_deref(),
            Some("desk"),
            "display names are unchanged"
        );

        // The wire form.
        let plain = names(&[bound(5, "aa:bb:cc:00:00:01", false)], &[]);
        let text = serde_json::to_string(&plain).unwrap();
        assert!(!text.contains("vetted"), "{text}");
        let marked = Names {
            vetted: true,
            ..plain.clone()
        };
        let marked_text = serde_json::to_string(&marked).unwrap();
        assert!(marked_text.contains("\"vetted\":true"), "{marked_text}");
        let mut with_field: serde_json::Value = serde_json::from_str(&marked_text).unwrap();
        with_field.as_object_mut().unwrap().remove("vetted");
        assert_eq!(
            with_field,
            serde_json::from_str::<serde_json::Value>(&text).unwrap(),
            "the old form plus the one field"
        );
        let prev: PreviousNames = serde_json::from_str(&marked_text).unwrap();
        assert_eq!((prev.routers.len(), prev.mdns.len()), (1, 0));
        assert!(serde_json::from_str::<Names>(&marked_text).unwrap().vetted);

        // This node's own answer carries it (and keeps `unsure`).
        let p = crate::pipeline::tests_support::pipeline_from(&telltale_config::Config::default());
        p.router_leases.store(std::sync::Arc::new(HashMap::from([(
            at(6),
            bound(6, "aa:bb:cc:00:00:02", true),
        )])));
        let mine: Names = serde_json::from_slice(&own(&p).unwrap()).unwrap();
        assert!(mine.vetted);
        assert!(mine.routers[&at(6)].unsure);
    }

    // REQ: CLU-002 (ADR-183) — until a full member has answered, a node asks again every 5
    // seconds for the first two minutes (a new pod or a restarted node doesn't wait a minute);
    // after that, or once one has answered, every minute.
    #[test]
    fn clu_002_names_are_asked_again_soon_until_a_full_member_answers() {
        use std::time::Duration;
        let soon = Duration::from_secs(5);
        let minute = Duration::from_secs(60);
        assert_eq!(next_wait(false, 0), soon);
        assert_eq!(next_wait(false, 119), soon);
        assert_eq!(next_wait(false, 120), minute, "the retry is bounded");
        assert_eq!(next_wait(false, u64::MAX), minute);
        assert_eq!(next_wait(true, 0), minute);
        assert_eq!(next_wait(true, 60), minute);
    }

    // REQ: CLU-002 (ADR-183) — the quick retry isn't ended by a full replica that holds no router
    // key and answers first (its empty answer carries nothing the pods need), nor by an older
    // member's answer or an ephemeral member's, nor by the primary's own answer when it carries
    // no router leases (it may come before the primary's first read): only an answer that is
    // kept (a full member's, `vetted`) and carries router leases ends it.
    #[test]
    fn clu_002_the_quick_retry_waits_for_an_answer_that_carries_routers() {
        use std::time::Duration;
        let full = |p: &str| matches!(p, "replica" | "primary" | "old");
        let leased = |last: u8| bound(last, "aa:bb:cc:00:00:01", false);
        let replica_no_key = vetted(&[]);
        let with_router = vetted(&[leased(5)]);
        let older = names(&[leased(5)], &[]);
        let ask = |a: Vec<(&str, Names)>, primary: Option<&str>| {
            retry_ends(&from_nodes(a), full, primary)
        };
        // A replica without the router key, vetted and empty: not yet.
        assert!(!ask(vec![("replica", replica_no_key.clone())], None));
        assert!(!ask(
            vec![("replica", replica_no_key.clone())],
            Some("primary")
        ));
        // A vetted answer with router leases from a full member: done.
        assert!(ask(vec![("primary", with_router.clone())], None));
        assert!(ask(
            vec![
                ("replica", replica_no_key.clone()),
                ("primary", with_router.clone())
            ],
            None
        ));
        // An older member (no `vetted`), an ephemeral pod or an unlisted node, with leases: not done.
        assert!(!ask(vec![("old", older)], None));
        assert!(!ask(vec![("pod-1", with_router.clone())], None));
        assert!(!ask(vec![("ghost", with_router)], None));
        // The primary's own answer doesn't end it when it carries no router leases (it may come
        // before the primary's first read of its router), whoever says it is the primary.
        assert!(!ask(
            vec![("primary", replica_no_key.clone())],
            Some("primary")
        ));
        assert!(!ask(vec![("replica", replica_no_key)], Some("primary")));
        assert!(!ask(vec![], Some("primary")), "nobody answered");
        // The whole story, with `next_wait`: the replica answers at 5 s, the primary (before its
        // first read) at 10 s, and the primary with its leases at 15 s.
        let mut answered = false;
        answered |= ask(vec![("replica", vetted(&[]))], Some("primary"));
        assert_eq!(next_wait(answered, 5), Duration::from_secs(5));
        answered |= ask(vec![("primary", vetted(&[]))], Some("primary"));
        assert_eq!(next_wait(answered, 10), Duration::from_secs(5));
        answered |= ask(vec![("primary", vetted(&[leased(5)]))], Some("primary"));
        assert_eq!(next_wait(answered, 15), Duration::from_secs(60));
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — a member is full only if the member registry lists it and
    // it isn't ephemeral. Nothing else makes it one, not even being the node `reachable_primary()`
    // reports. (A replica's first round can come before its registry is written; the quick retry
    // simply goes on until it is, a few seconds.)
    #[test]
    fn clu_002_a_member_is_full_only_if_the_registry_lists_it_and_it_is_not_ephemeral() {
        // The registry as a replica has it at its first round: itself only.
        let early = [rec("replica", false)];
        assert!(!full_by(&early, Some("primary"), "primary"));
        assert!(!full_by(&early, None, "primary"));
        assert!(!full_by(&early, Some("primary"), "other"));
        // Once it has arrived: listed members count, ephemeral ones and strangers don't, whoever
        // is said to be the primary.
        let later = [
            rec("primary", false),
            rec("replica", false),
            rec("pod-1", true),
        ];
        assert!(full_by(&later, None, "primary"));
        assert!(full_by(&later, Some("pod-1"), "replica"));
        assert!(!full_by(&later, Some("pod-1"), "pod-1"));
        assert!(!full_by(&later, Some("stranger"), "stranger"));
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — a resolver pod (a member the registry lists as ephemeral)
    // whose own Hello says it is the primary gets no bindings, and doesn't end the quick retry:
    // its vetted answer, with an address it made up, is not used.
    #[test]
    fn clu_002_a_peer_claiming_to_be_primary_gets_no_bindings_when_the_registry_lists_it_ephemeral()
    {
        let registry = [rec("primary", false), rec("pod-1", true)];
        let claimed = Some("pod-1");
        let full = |p: &str| full_by(&registry, claimed, p);
        let answers = from_nodes(vec![(
            "pod-1",
            vetted(&[bound(5, "aa:bb:cc:00:00:01", false)]),
        )]);
        assert!(!full("pod-1"));
        let mut last = MemberBindings::new();
        keep_answers(&mut last, &answers, 10, full);
        assert!(last.is_empty(), "{:?}", members(&last));
        assert_eq!(peer_macs(&last), PeerMacs::default());
        assert!(!retry_ends(&answers, full, claimed));
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — the same for a node the registry doesn't list at all, once
    // this node has the registry (it holds the primary and itself): a stranger that says it is the
    // primary gets no bindings.
    #[test]
    fn clu_002_a_peer_claiming_to_be_primary_gets_no_bindings_when_the_registry_does_not_list_it() {
        let registry = [rec("primary", false), rec("replica", false)];
        let claimed = Some("stranger");
        let full = |p: &str| full_by(&registry, claimed, p);
        let answers = from_nodes(vec![(
            "stranger",
            vetted(&[bound(5, "aa:bb:cc:00:00:01", false)]),
        )]);
        let mut last = MemberBindings::new();
        keep_answers(&mut last, &answers, 10, full);
        assert!(last.is_empty(), "{:?}", members(&last));
        assert_eq!(peer_macs(&last), PeerMacs::default());
        assert!(!retry_ends(&answers, full, claimed));
    }

    // REQ: CLU-002 (ADR-183) — found by `deploy/cluster/router-macs-e2e.sh`: a replica's first
    // round can come before its copy of the registry is written. The primary's answer is then not
    // used, and it must not end the quick retry either: the retry goes on every 5 seconds until the
    // registry lists the answerer, then the answer is kept and the retry ends.
    #[test]
    fn clu_002_the_quick_retry_goes_on_until_the_registry_lists_the_answerer() {
        let answers = from_nodes(vec![(
            "primary",
            vetted(&[bound(5, "aa:bb:cc:00:00:01", false)]),
        )]);
        let early = [rec("replica", false)];
        let full = |p: &str| full_by(&early, Some("primary"), p);
        let mut last = MemberBindings::new();
        keep_answers(&mut last, &answers, 5, full);
        assert!(last.is_empty(), "not listed yet: not used");
        assert!(
            !retry_ends(&answers, full, Some("primary")),
            "so the retry goes on"
        );
        // The registry arrives: the same answer is kept, and the retry ends.
        let later = [rec("primary", false), rec("replica", false)];
        let full = |p: &str| full_by(&later, Some("primary"), p);
        keep_answers(&mut last, &answers, 10, full);
        assert_eq!(members(&last), ["primary"]);
        assert!(retry_ends(&answers, full, Some("primary")));
    }

    // REQ: CLU-002 (ADR-183) — the primary's vetted answer without router leases (it came before
    // the primary's first read of its router, on a chart roll) doesn't end the quick retry: the
    // next round, 5 seconds on, is the one that has the bindings.
    #[test]
    fn clu_002_the_quick_retry_does_not_end_on_the_primarys_empty_answer() {
        let registry = [rec("primary", false), rec("replica", false)];
        let full = |p: &str| full_by(&registry, Some("primary"), p);
        let empty = from_nodes(vec![("primary", vetted(&[]))]);
        assert!(!retry_ends(&empty, full, Some("primary")));
        assert!(!retry_ends(&empty, full, None));
        let leased = from_nodes(vec![(
            "primary",
            vetted(&[bound(5, "aa:bb:cc:00:00:01", false)]),
        )]);
        assert!(retry_ends(&leased, full, Some("primary")));
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — an answer without `vetted` from a member that was kept
    // (it was rolled back to a build without the marks) drops that member's bindings now, not
    // after 15 minutes: its lists no longer follow the rules.
    #[test]
    fn clu_002_an_unvetted_answer_drops_the_members_bindings() {
        let full = |p: &str| p == "pi";
        let mut last = MemberBindings::new();
        keep_answers(
            &mut last,
            &from_nodes(vec![(
                "pi",
                vetted(&[bound(5, "aa:bb:cc:00:00:01", false)]),
            )]),
            10,
            full,
        );
        assert_eq!(members(&last), ["pi"]);
        assert_eq!(peer_macs(&last).macs.len(), 1);
        keep_answers(
            &mut last,
            &from_nodes(vec![(
                "pi",
                names(&[bound(5, "aa:bb:cc:00:00:01", false)], &[]),
            )]),
            20,
            full,
        );
        assert!(last.is_empty(), "{:?}", members(&last));
        assert_eq!(peer_macs(&last), PeerMacs::default());
    }

    fn leases_of(l: &[Lease]) -> Leases {
        l.iter().map(|l| (l.ip, l.clone())).collect()
    }

    /// What the members agree on, as the task makes it from their answers.
    fn peers_of(answers: Vec<(&str, Names)>) -> PeerMacs {
        let mut last = MemberBindings::new();
        keep_answers(&mut last, &from_nodes(answers), 10, |_| true);
        peer_macs(&last)
    }

    // REQ: FLT-006 (ADR-183) — an address this node binds itself (its router is sure) isn't withheld
    // because a member isn't sure of it: this node's binding wins, so it is no tombstone, and it
    // isn't counted as withheld. (`recognize()` and the table share `router_bindings`, so they
    // can't disagree about it.)
    #[test]
    fn flt_006_a_binding_this_node_has_is_not_withheld_by_a_members_tombstone() {
        let own = leases_of(&[bound(5, "aa:bb:cc:00:00:01", false)]);
        let peers = peers_of(vec![("pi", vetted(&[bound(5, "aa:bb:cc:00:00:02", true)]))]);
        let b = router_bindings(&own, &peers);
        assert_eq!(b.own, HashMap::from([(at(5), MAC_A)]));
        assert!(b.tombstones.is_empty(), "{b:?}");
        assert_eq!(b.unsure, 0, "nothing is withheld");
        assert!(b.peer.is_empty() && b.shared.is_empty());
    }

    // REQ: FLT-006 (ADR-183) — an address is counted as withheld once: this node's own `unsure`
    // lease and a member's tombstone for the same address are one address, and `unsure` is the
    // number of tombstones plus the shared addresses.
    #[test]
    fn flt_006_a_withheld_address_is_counted_once() {
        let own = leases_of(&[
            bound(5, "aa:bb:cc:00:00:01", true),
            bound(6, "aa:bb:cc:00:00:02", false),
        ]);
        let peers = peers_of(vec![
            (
                "pi",
                vetted(&[
                    bound(5, "aa:bb:cc:00:00:01", true),
                    bound(7, "aa:bb:cc:00:00:03", true),
                ]),
            ),
            ("k8s", vetted(&[bound(8, "aa:bb:cc:00:00:04", false)])),
        ]);
        let b = router_bindings(&own, &peers);
        assert_eq!(b.tombstones, HashSet::from([at(5), at(7)]));
        assert_eq!(b.own, HashMap::from([(at(6), MAC_B)]));
        assert_eq!(
            b.peer,
            HashMap::from([(at(8), [0xaa, 0xbb, 0xcc, 0, 0, 0x04])])
        );
        assert_eq!(b.unsure, 2, "{b:?}");
    }

    // REQ: FLT-006 (ADR-183) — the shared-MAC rule counts a MAC over everything that says where it
    // is, the addresses this node withholds included: this node's router is unsure about X (two MACs
    // there, one of them m), and a member reports m at Y (a MAC-sharing extender does this): m is at
    // two addresses, so Y identifies nobody, and both are counted.
    #[test]
    fn flt_006_a_mac_at_a_withheld_address_still_counts_toward_sharing() {
        let own = leases_of(&[bound(5, "aa:bb:cc:00:00:01", true)]);
        let peers = peers_of(vec![(
            "pi",
            vetted(&[bound(6, "aa:bb:cc:00:00:01", false)]),
        )]);
        let b = router_bindings(&own, &peers);
        assert!(
            b.peer.is_empty(),
            "m is at X and Y: Y doesn't identify: {b:?}"
        );
        assert_eq!(b.shared, HashMap::from([(at(6), MAC_A)]));
        assert_eq!(b.tombstones, HashSet::from([at(5)]));
        assert_eq!(b.unsure, 2);
        // A member's own binding at the withheld address counts as well.
        let peers = peers_of(vec![
            ("pi", vetted(&[bound(5, "aa:bb:cc:00:00:01", false)])),
            ("k8s", vetted(&[bound(6, "aa:bb:cc:00:00:01", false)])),
        ]);
        let b = router_bindings(&leases_of(&[bound(5, "aa:bb:cc:00:00:09", true)]), &peers);
        assert!(b.peer.is_empty() && b.tombstones.contains(&at(5)), "{b:?}");
        assert_eq!(b.shared, HashMap::from([(at(6), MAC_A)]));
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — a MAC a member withholds counts toward sharing here too:
    // member A isn't sure of X (its lease is `unsure`, and carries m), member B binds Y to m, and
    // this node has no router: m is at two addresses, so Y identifies nobody on this node either,
    // as it wouldn't on a node that reads A's router itself.
    #[test]
    fn flt_006_a_mac_withheld_by_one_member_still_counts_toward_sharing() {
        let peers = peers_of(vec![
            ("pi", vetted(&[bound(5, "aa:bb:cc:00:00:01", true)])),
            ("k8s", vetted(&[bound(6, "aa:bb:cc:00:00:01", false)])),
        ]);
        let b = router_bindings(&Leases::new(), &peers);
        assert!(b.peer.is_empty(), "m is at X and Y: {b:?}");
        assert_eq!(b.shared, HashMap::from([(at(6), MAC_A)]));
        assert_eq!(b.tombstones, HashSet::from([at(5)]));
        assert_eq!(b.unsure, 2);
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — a router that has gone silent never vetoes fresh data: the
    // rows it still lists (its last answer, kept while it fails) don't count toward "one MAC at two
    // addresses" on any node, so a device that moved is recognized at its new address, on this
    // node (its own stale rows) and on the others (a member's). The stale row's own address stays
    // withheld on the node that owns the router, and nowhere else.
    #[test]
    fn flt_006_a_dead_routers_old_rows_do_not_withhold_a_moved_device() {
        // This node's own rows: its dead router still lists m at X; the fresh one has m at Y.
        let own = leases_of(&[
            stale_row(5, "aa:bb:cc:00:00:01"),
            bound(6, "aa:bb:cc:00:00:01", false),
        ]);
        let b = router_bindings(&own, &PeerMacs::default());
        assert_eq!(b.own, HashMap::from([(at(6), MAC_A)]), "{b:?}");
        assert!(b.shared.is_empty(), "{b:?}");
        assert_eq!(
            b.tombstones,
            HashSet::from([at(5)]),
            "its own address stays withheld"
        );
        assert_eq!(b.unsure, 1);

        // A member's stale row (its dead router's last answer) is no binding here and withholds
        // nothing here: not its address, not the MAC.
        let peers = peers_of(vec![("pi", vetted(&[stale_row(5, "aa:bb:cc:00:00:01")]))]);
        assert_eq!(peers, PeerMacs::default(), "{peers:?}");
        let b = router_bindings(&leases_of(&[bound(6, "aa:bb:cc:00:00:01", false)]), &peers);
        assert_eq!(b.own, HashMap::from([(at(6), MAC_A)]), "{b:?}");
        assert!(b.shared.is_empty() && b.tombstones.is_empty(), "{b:?}");

        // A node with no router of its own takes another member's fresh binding at Y, whatever a
        // third member's dead router still says about X.
        let peers = peers_of(vec![
            ("pi", vetted(&[stale_row(5, "aa:bb:cc:00:00:01")])),
            ("k8s", vetted(&[bound(6, "aa:bb:cc:00:00:01", false)])),
        ]);
        let b = router_bindings(&Leases::new(), &peers);
        assert_eq!(b.peer, HashMap::from([(at(6), MAC_A)]), "{b:?}");
        assert!(b.shared.is_empty() && b.tombstones.is_empty(), "{b:?}");

        // A MAC that is at two addresses on fresh routers is still shared (the rule is intact).
        let b = router_bindings(
            &leases_of(&[
                bound(5, "aa:bb:cc:00:00:01", false),
                bound(6, "aa:bb:cc:00:00:01", false),
            ]),
            &PeerMacs::default(),
        );
        assert_eq!(b.shared.len(), 2, "{b:?}");
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — the "no router MAC reaches this node" notice counts what
    // reached this node, from the data the bindings are made from, not from table entries: a router
    // lease or a member's binding counts even when a kernel entry shadows it in the table (an offline
    // client, which binds nothing and withholds nothing, doesn't).
    #[test]
    fn flt_006_rows_that_reached_this_node_are_counted_from_the_bindings_data() {
        assert_eq!(bindings_reaching(&Leases::new(), &PeerMacs::default()), 0);
        let offline = Lease {
            offline: true,
            ..bound(5, "aa:bb:cc:00:00:01", false)
        };
        assert_eq!(
            bindings_reaching(&leases_of(&[offline]), &PeerMacs::default()),
            0
        );
        // A stale router's old row is not a row that reached this node: nothing there identifies.
        let stale = stale_row(5, "aa:bb:cc:00:00:01");
        assert_eq!(
            bindings_reaching(&leases_of(&[stale]), &PeerMacs::default()),
            0
        );
        // A connected lease, sure or not, is a row that reached this node.
        for l in [
            bound(5, "aa:bb:cc:00:00:01", false),
            bound(6, "aa:bb:cc:00:00:02", true),
        ] {
            assert_eq!(bindings_reaching(&leases_of(&[l]), &PeerMacs::default()), 1);
        }
        // So is a member's binding, or an address a member withholds.
        let bound_by_member = peers_of(vec![(
            "pi",
            vetted(&[bound(5, "aa:bb:cc:00:00:01", false)]),
        )]);
        assert_eq!(bindings_reaching(&Leases::new(), &bound_by_member), 1);
        let withheld_by_member =
            peers_of(vec![("pi", vetted(&[bound(5, "aa:bb:cc:00:00:01", true)]))]);
        assert_eq!(bindings_reaching(&Leases::new(), &withheld_by_member), 1);
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — the F1 tests test the check the task builds each round
    // (`full_check`), not only the function under it: whichever node `reachable_primary()` reports,
    // nothing changes: the registry's listing, and not being ephemeral, is the whole of it.
    // (Putting `|| claimed_primary == Some(p)` back into `full_check` breaks this test.)
    #[test]
    fn clu_002_a_claimed_primary_is_not_full_in_the_tasks_own_check() {
        let registry = [
            rec("primary", false),
            rec("replica", false),
            rec("pod-1", true),
        ];
        for claimed in [None, Some("pod-1"), Some("stranger"), Some("primary")] {
            let full = full_check(&registry, claimed);
            assert!(full("primary") && full("replica"), "{claimed:?}");
            assert!(
                !full("pod-1"),
                "an ephemeral member that claims it: {claimed:?}"
            );
            assert!(
                !full("stranger"),
                "an unlisted node that claims it: {claimed:?}"
            );
        }
        // Before the registry arrives (itself only), nobody else is full, claimed or not.
        let early = [rec("replica", false)];
        assert!(!full_check(&early, Some("primary"))("primary"));
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — the same when two members disagree about X (so both are
    // dropped there): the MAC each gave for X is still a MAC seen at X, so a third member's binding
    // of one of them at Y is shared, not used.
    #[test]
    fn flt_006_a_mac_at_a_disagreed_address_still_counts_toward_sharing() {
        let peers = peers_of(vec![
            ("pi", vetted(&[bound(5, "aa:bb:cc:00:00:01", false)])),
            ("k8s", vetted(&[bound(5, "aa:bb:cc:00:00:02", false)])),
            ("nas", vetted(&[bound(6, "aa:bb:cc:00:00:01", false)])),
        ]);
        let b = router_bindings(&Leases::new(), &peers);
        assert!(b.peer.is_empty(), "m is at X (disagreed) and Y: {b:?}");
        assert_eq!(b.shared, HashMap::from([(at(6), MAC_A)]));
        assert_eq!(b.tombstones, HashSet::from([at(5)]));
    }

    // REQ: FLT-006, CLU-002 (ADR-183) — a connected lease whose MAC can't identify a device (empty,
    // all zero, multicast, in a form `parse_mac` rejects) withholds its address, this node's and a
    // member's: a member's binding for it doesn't fill it, which is the same fail-closed rule as for
    // an `unsure` lease (two sites reusing a range). An offline lease with such a MAC doesn't.
    #[test]
    fn flt_006_a_connected_lease_that_cannot_identify_withholds_its_address() {
        let member = |junk: &str| {
            peers_of(vec![
                (
                    "pi",
                    vetted(&[
                        bound(5, "aa:bb:cc:00:00:01", false),
                        bound(6, "aa:bb:cc:00:00:02", false),
                    ]),
                ),
                ("k8s", vetted(&[bound(5, junk, false)])),
            ])
        };
        for junk in [
            "",
            "00:00:00:00:00:00",
            "01:00:5e:00:00:01",
            "aabb.ccdd.eeff",
            "zz:zz:zz:zz:zz:zz",
        ] {
            // This node's own router has the junk MAC; a member binds the address.
            let own = leases_of(&[bound(5, junk, false)]);
            let peers = peers_of(vec![(
                "pi",
                vetted(&[
                    bound(5, "aa:bb:cc:00:00:01", false),
                    bound(6, "aa:bb:cc:00:00:02", false),
                ]),
            )]);
            let b = router_bindings(&own, &peers);
            assert!(b.tombstones.contains(&at(5)), "own `{junk}`: {b:?}");
            assert!(!b.peer.contains_key(&at(5)), "own `{junk}`");
            assert_eq!(b.peer[&at(6)], MAC_B);
            assert_eq!(b.unsure, 1, "own `{junk}`");
            // A member's router has the junk MAC, another member binds it.
            let m = member(junk);
            assert!(m.tombstones.contains(&at(5)), "member `{junk}`: {m:?}");
            assert!(!m.macs.contains_key(&at(5)), "member `{junk}`");
            assert_eq!(m.macs[&at(6)], MAC_B);
        }
        // Offline: skipped, as before: the member's binding fills the address.
        let off = Lease {
            offline: true,
            ..bound(5, "", false)
        };
        let peers = peers_of(vec![(
            "pi",
            vetted(&[bound(5, "aa:bb:cc:00:00:01", false)]),
        )]);
        let b = router_bindings(&leases_of(&[off]), &peers);
        assert_eq!(b.peer, HashMap::from([(at(5), MAC_A)]));
        assert!(b.tombstones.is_empty());
    }
}
