//! Client identification and group membership (`spec/03` §3 step 2, `spec/05` §1).
//!
//! REQ: FLT-005, FLT-006. Precedence: client ID (DoH path / DoT SNI) → EDNS MAC (only from
//! trusted forwarders) → MAC from the neighbor table → exact IP → most specific CIDR →
//! the `default` group. All lookups are hash maps or a short prefix list built once per
//! config, so identifying a client allocates nothing.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use arc_swap::ArcSwap;
use telltale_config::{BlockMode, Cidr, Config, EdeKind, GroupConfig, MatchKey};

/// A client group (FLT-005).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub name: Box<str>,
    /// List names; `None` = every enabled list.
    pub lists: Option<Vec<Box<str>>>,
    pub priority: i32,
    pub block: BlockPolicy,
    /// Networks whose devices belong to it (ADR-050).
    pub networks: Vec<Cidr>,
    /// `#rrggbb`, when configured.
    pub color: Option<Box<str>>,
}

/// How a group's blocked queries are answered (FLT-008).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockPolicy {
    pub mode: BlockMode,
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
    pub ttl: u32,
    /// RFC 8914 code: 15 (Blocked) or 17 (Filtered).
    pub ede_code: u16,
    /// Name the list in the EDE text.
    pub ede_text: bool,
}

impl Default for BlockPolicy {
    fn default() -> Self {
        Self {
            mode: BlockMode::NullIp,
            v4: Vec::new(),
            v6: Vec::new(),
            ttl: 60,
            ede_code: telltale_proto::ede::BLOCKED,
            ede_text: true,
        }
    }
}

impl BlockPolicy {
    fn from_config(g: &GroupConfig) -> Self {
        Self {
            mode: g.block_mode,
            v4: g
                .block_ips
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v) => Some(*v),
                    IpAddr::V6(_) => None,
                })
                .collect(),
            v6: g
                .block_ips
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(v) => Some(*v),
                    IpAddr::V4(_) => None,
                })
                .collect(),
            ttl: g.block_ttl,
            ede_code: match g.ede {
                EdeKind::Blocked => telltale_proto::ede::BLOCKED,
                EdeKind::Filtered => telltale_proto::ede::FILTERED,
            },
            ede_text: g.ede_text,
        }
    }
}

/// Pause state (FLT-009): blocking off globally or for a group until a deadline (unix
/// seconds). Kept by name, so pauses survive config reloads. Reading it costs one atomic load
/// when nothing is paused.
#[derive(Debug, Default)]
pub struct Pause {
    global_until: AtomicU64,
    any_group: AtomicBool,
    groups: ArcSwap<HashMap<Box<str>, u64>>,
}

impl Pause {
    /// Pauses blocking for everyone until `until` (unix seconds); 0 resumes.
    pub fn pause_all(&self, until: u64) {
        self.global_until.store(until, Ordering::Release);
    }

    /// Pauses one group until `until`; 0 resumes it.
    pub fn pause_group(&self, group: &str, until: u64) {
        let mut map = (**self.groups.load()).clone();
        if until == 0 {
            map.remove(group);
        } else {
            map.insert(group.into(), until);
        }
        self.any_group.store(!map.is_empty(), Ordering::Release);
        self.groups.store(Arc::new(map));
    }

    /// Is blocking paused for a client whose settings come from `group` at `now`?
    pub fn is_paused(&self, group: &str, now: impl Fn() -> u64) -> bool {
        let global = self.global_until.load(Ordering::Acquire);
        let any = self.any_group.load(Ordering::Acquire);
        if global == 0 && !any {
            return false;
        }
        let now = now();
        global > now || (any && self.groups.load().get(group).is_some_and(|&u| u > now))
    }

    /// Active pauses: (`None` = global, group) → deadline. For metrics and the API.
    pub fn active(&self, now: u64) -> Vec<(Option<Box<str>>, u64)> {
        let mut v = Vec::new();
        let g = self.global_until.load(Ordering::Acquire);
        if g > now {
            v.push((None, g));
        }
        for (name, &until) in self.groups.load().iter() {
            if until > now {
                v.push((Some(name.clone()), until));
            }
        }
        v
    }
}

/// A configured device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub name: Box<str>,
    /// Group indices, highest priority first (the first one's settings apply).
    pub groups: Vec<u16>,
    /// The same groups by name (routing `match_group`, `$client`).
    pub group_names: Vec<Box<str>>,
    /// No groups of its own: it takes its network's group (ADR-050).
    pub inherit: bool,
}

/// How a client was recognized (shown in the query log and explain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdSource {
    ClientId,
    EdnsMac,
    NeighborMac,
    Ip,
    Cidr,
    /// Unknown device: the `default` group.
    Default,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    /// Index into [`ClientTable::clients`], or `None` for an unknown device.
    pub client: Option<u16>,
    pub source: IdSource,
    /// The group of the most specific network the device is in (ADR-050).
    pub net: Option<u16>,
}

/// The kernel neighbor table (IP → MAC), refreshed in the background and read lock-free.
#[derive(Debug, Default)]
pub struct Neighbors {
    map: ArcSwap<HashMap<IpAddr, [u8; 6]>>,
}

impl Neighbors {
    pub fn replace(&self, entries: impl IntoIterator<Item = (IpAddr, [u8; 6])>) {
        let map: HashMap<IpAddr, [u8; 6]> = entries
            .into_iter()
            .map(|(ip, mac)| (ip.to_canonical(), mac))
            .collect();
        self.map.store(Arc::new(map));
    }

    pub fn get(&self, ip: IpAddr) -> Option<[u8; 6]> {
        self.map.load().get(&ip).copied()
    }

    pub fn len(&self) -> usize {
        self.map.load().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Every configured group and client, indexed for identification.
#[derive(Debug, Clone)]
pub struct ClientTable {
    groups: Vec<Group>,
    clients: Vec<Client>,
    by_id: HashMap<Box<str>, u16>,
    by_mac: HashMap<[u8; 6], u16>,
    by_ip: HashMap<IpAddr, u16>,
    /// Most specific first.
    cidrs: Vec<(Cidr, u16)>,
    /// Group networks → group index, most specific first (ADR-050).
    group_nets: Vec<(Cidr, u16)>,
    /// One-group slices for network membership, by group index.
    single: Vec<[u16; 1]>,
    single_names: Vec<[Box<str>; 1]>,
    trust_mac: Vec<Cidr>,
    /// Index of the `default` group, and its name for unknown clients.
    default_group: [u16; 1],
    default_names: Vec<Box<str>>,
}

impl Default for ClientTable {
    fn default() -> Self {
        Self::from_config(&Config::default())
    }
}

impl ClientTable {
    /// Builds the table. The config is assumed validated (`telltale config check` rules);
    /// unparseable keys and unknown groups are skipped.
    pub fn from_config(cfg: &Config) -> Self {
        let mut groups: Vec<Group> = cfg
            .group
            .iter()
            .map(|g| Group {
                name: g.name.as_str().into(),
                lists: g
                    .lists
                    .as_ref()
                    .map(|l| l.iter().map(|n| n.as_str().into()).collect()),
                priority: g.priority,
                block: BlockPolicy::from_config(g),
                networks: g.networks.clone(),
                color: g.color.as_ref().map(|c| c.as_str().into()),
            })
            .collect();
        let default_idx = if let Some(i) = groups.iter().position(|g| &*g.name == "default") {
            i
        } else {
            groups.push(Group {
                name: "default".into(),
                lists: None,
                priority: i32::MIN,
                block: BlockPolicy::default(),
                networks: Vec::new(),
                color: None,
            });
            groups.len() - 1
        };
        let index: HashMap<&str, u16> = groups
            .iter()
            .enumerate()
            .filter_map(|(i, g)| Some((&*g.name, u16::try_from(i).ok()?)))
            .collect();
        let mut t = Self {
            by_id: HashMap::new(),
            by_mac: HashMap::new(),
            by_ip: HashMap::new(),
            cidrs: Vec::new(),
            group_nets: Vec::new(),
            single: Vec::new(),
            single_names: Vec::new(),
            trust_mac: cfg.clients.trust_edns_mac_from.clone(),
            default_group: [u16::try_from(default_idx).unwrap_or(0)],
            default_names: vec!["default".into()],
            clients: Vec::new(),
            groups: Vec::new(),
        };
        for c in &cfg.client {
            let Ok(ci) = u16::try_from(t.clients.len()) else {
                break;
            };
            let mut gs: Vec<u16> = c
                .groups
                .iter()
                .filter_map(|g| index.get(g.as_str()).copied())
                .collect();
            let inherit = gs.is_empty();
            if inherit {
                gs.push(t.default_group[0]);
            }
            gs.sort_by_key(|&g| std::cmp::Reverse(groups[usize::from(g)].priority));
            gs.dedup();
            t.clients.push(Client {
                name: c.name.as_str().into(),
                group_names: gs
                    .iter()
                    .map(|&g| groups[usize::from(g)].name.clone())
                    .collect(),
                groups: gs,
                inherit,
            });
            for key in &c.match_keys {
                match MatchKey::parse(key) {
                    Ok(MatchKey::ClientId(id)) => {
                        t.by_id.entry(id.into()).or_insert(ci);
                    }
                    Ok(MatchKey::Mac(m)) => {
                        t.by_mac.entry(m).or_insert(ci);
                    }
                    Ok(MatchKey::Ip(ip)) => {
                        t.by_ip.entry(ip.to_canonical()).or_insert(ci);
                    }
                    Ok(MatchKey::Cidr(n)) => t.cidrs.push((n, ci)),
                    Err(_) => {}
                }
            }
        }
        t.cidrs.sort_by_key(|(n, _)| std::cmp::Reverse(n.prefix));
        for (i, g) in groups.iter().enumerate() {
            let Ok(gi) = u16::try_from(i) else { break };
            t.group_nets.extend(g.networks.iter().map(|n| (*n, gi)));
            t.single.push([gi]);
            t.single_names.push([g.name.clone()]);
        }
        t.group_nets
            .sort_by_key(|(n, _)| std::cmp::Reverse(n.prefix));
        t.groups = groups;
        t
    }

    /// True if some client is identified by MAC, so the neighbor table is worth reading.
    pub fn uses_macs(&self) -> bool {
        !self.by_mac.is_empty()
    }

    pub fn groups(&self) -> &[Group] {
        &self.groups
    }

    pub fn clients(&self) -> &[Client] {
        &self.clients
    }

    pub fn client(&self, id: Identity) -> Option<&Client> {
        self.clients.get(usize::from(id.client?))
    }

    /// Identifies the sender of a query.
    pub fn identify(
        &self,
        peer: IpAddr,
        client_id: Option<&str>,
        edns_mac: Option<[u8; 6]>,
        neighbors: &Neighbors,
    ) -> Identity {
        let peer = peer.to_canonical();
        // A short scan (a home has a handful of networks), no allocation: query path.
        let net = self
            .group_nets
            .iter()
            .find(|(n, _)| n.contains(peer))
            .map(|(_, g)| *g);
        let found = |client, source| Identity {
            client: Some(client),
            source,
            net,
        };
        if let Some(id) = client_id
            && let Some(&c) = self.by_id.get(id)
        {
            return found(c, IdSource::ClientId);
        }
        if !self.by_mac.is_empty() {
            // An EDNS MAC is only as trustworthy as whoever added it.
            if let Some(mac) = edns_mac
                && self.trust_mac.iter().any(|n| n.contains(peer))
                && let Some(&c) = self.by_mac.get(&mac)
            {
                return found(c, IdSource::EdnsMac);
            }
            if let Some(mac) = neighbors.get(peer)
                && let Some(&c) = self.by_mac.get(&mac)
            {
                return found(c, IdSource::NeighborMac);
            }
        }
        if let Some(&c) = self.by_ip.get(&peer) {
            return found(c, IdSource::Ip);
        }
        if let Some((_, c)) = self.cidrs.iter().find(|(n, _)| n.contains(peer)) {
            return found(*c, IdSource::Cidr);
        }
        Identity {
            client: None,
            source: IdSource::Default,
            net,
        }
    }

    /// The group a network gives a device, if any (ADR-050).
    pub fn network_group(&self, ip: IpAddr) -> Option<u16> {
        let ip = ip.to_canonical();
        self.group_nets
            .iter()
            .find(|(n, _)| n.contains(ip))
            .map(|(_, g)| *g)
    }

    /// Group indices for an identity, highest priority first.
    pub fn group_ids(&self, id: Identity) -> &[u16] {
        match self.client(id) {
            Some(c) if !c.inherit => &c.groups,
            _ => id
                .net
                .and_then(|g| self.single.get(usize::from(g)))
                .map_or(&self.default_group, |s| s.as_slice()),
        }
    }

    /// Group names for an identity, highest priority first (for routing `match_group`).
    pub fn group_names(&self, id: Identity) -> &[Box<str>] {
        match self.client(id) {
            Some(c) if !c.inherit => &c.group_names,
            _ => id
                .net
                .and_then(|g| self.single_names.get(usize::from(g)))
                .map_or(&self.default_names, |s| s.as_slice()),
        }
    }

    /// The group whose settings apply (highest priority).
    pub fn primary_group(&self, id: Identity) -> &Group {
        let g = self
            .group_ids(id)
            .first()
            .copied()
            .unwrap_or(self.default_group[0]);
        &self.groups[usize::from(g)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: FLT-005 (ADR-050) — VLANs as groups.
    #[test]
    fn flt_005_network_groups() {
        let cfg: Config = telltale_config::Loader::new()
            .toml_str(
                "t.toml",
                r#"
[[group]]
name = "iot"
networks = ["192.168.2.0/24"]

[[group]]
name = "lab"
networks = ["192.168.5.0/24"]

[[group]]
name = "kids"
priority = 10

[[group]]
name = "printers"
networks = ["192.168.2.128/25"]

[[client]]
name = "Living room TV"
match = ["192.168.2.40"]

[[client]]
name = "Kids tablet"
match = ["192.168.2.41"]
groups = ["kids"]
"#,
            )
            .load()
            .unwrap()
            .config;
        let t = ClientTable::from_config(&cfg);
        let n = Neighbors::default();
        let names = |ip: &str| -> Vec<String> {
            let id = t.identify(ip.parse().unwrap(), None, None, &n);
            t.group_names(id).iter().map(ToString::to_string).collect()
        };
        // An unknown device on the IoT VLAN is in `iot`.
        assert_eq!(names("192.168.2.99"), ["iot"]);
        // Naming a device keeps its network group.
        assert_eq!(names("192.168.2.40"), ["iot"]);
        let tv = t.identify("192.168.2.40".parse().unwrap(), None, None, &n);
        assert_eq!(t.client(tv).unwrap().name.as_ref(), "Living room TV");
        // Explicit groups win over the network.
        assert_eq!(names("192.168.2.41"), ["kids"]);
        // The most specific network wins.
        assert_eq!(names("192.168.2.200"), ["printers"]);
        assert_eq!(names("192.168.5.10"), ["lab"]);
        // Outside every network: `default`.
        assert_eq!(names("10.1.1.1"), ["default"]);
        assert_eq!(
            t.network_group("192.168.5.10".parse().unwrap())
                .map(|g| &*t.groups()[usize::from(g)].name),
            Some("lab")
        );
        assert_eq!(
            t.primary_group(t.identify("192.168.5.10".parse().unwrap(), None, None, &n))
                .name
                .as_ref(),
            "lab"
        );
    }

    fn table() -> ClientTable {
        let cfg: Config = telltale_config::Loader::new()
            .toml_str(
                "t.toml",
                r#"
[[list]]
name = "ads"
rules = ["||ads.example.com^"]

[[group]]
name = "kids"
lists = ["ads"]
priority = 10

[[group]]
name = "iot"
priority = 5

[[client]]
name = "tablet"
match = ["id:kids-tablet", "aa:bb:cc:dd:ee:01"]
groups = ["kids", "iot"]

[[client]]
name = "tv"
match = ["192.168.1.30", "fd00::30"]
groups = ["iot"]

[[client]]
name = "office"
match = ["10.0.0.0/8", "10.5.0.0/16"]

[[client]]
name = "printer"
match = ["10.5.5.5"]

[clients]
trust_edns_mac_from = ["192.168.1.1/32"]
"#,
            )
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config;
        ClientTable::from_config(&cfg)
    }

    fn who(
        t: &ClientTable,
        ip: &str,
        id: Option<&str>,
        mac: Option<[u8; 6]>,
        n: &Neighbors,
    ) -> (String, IdSource) {
        let i = t.identify(ip.parse().unwrap(), id, mac, n);
        (
            t.client(i).map_or("-".into(), |c| c.name.to_string()),
            i.source,
        )
    }

    #[test]
    fn flt_006_identification_chain() {
        let t = table();
        let n = Neighbors::default();
        let tablet_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
        assert_eq!(
            who(&t, "192.168.1.99", Some("kids-tablet"), None, &n),
            ("tablet".into(), IdSource::ClientId)
        );
        // EDNS MAC: only from the trusted forwarder.
        assert_eq!(
            who(&t, "192.168.1.1", None, Some(tablet_mac), &n),
            ("tablet".into(), IdSource::EdnsMac)
        );
        assert_eq!(
            who(&t, "192.168.1.77", None, Some(tablet_mac), &n),
            ("-".into(), IdSource::Default)
        );
        // Neighbor table, including IPv4-mapped IPv6 peers on dual-stack sockets.
        n.replace([("192.168.1.77".parse().unwrap(), tablet_mac)]);
        assert_eq!(
            who(&t, "192.168.1.77", None, None, &n),
            ("tablet".into(), IdSource::NeighborMac)
        );
        assert_eq!(
            who(&t, "::ffff:192.168.1.77", None, None, &n),
            ("tablet".into(), IdSource::NeighborMac)
        );
        assert_eq!(
            who(&t, "192.168.1.30", None, None, &n),
            ("tv".into(), IdSource::Ip)
        );
        assert_eq!(
            who(&t, "fd00::30", None, None, &n),
            ("tv".into(), IdSource::Ip)
        );
        // Exact IP beats CIDR; the most specific CIDR wins.
        assert_eq!(
            who(&t, "10.5.5.5", None, None, &n),
            ("printer".into(), IdSource::Ip)
        );
        assert_eq!(
            who(&t, "10.5.9.9", None, None, &n),
            ("office".into(), IdSource::Cidr)
        );
        assert_eq!(
            who(&t, "172.16.0.1", None, None, &n),
            ("-".into(), IdSource::Default)
        );
        assert!(t.uses_macs());
    }

    #[test]
    fn flt_009_pause_global_and_per_group() {
        let p = Pause::default();
        let now = || 1000;
        assert!(!p.is_paused("kids", now));
        p.pause_group("kids", 1600);
        assert!(p.is_paused("kids", now));
        assert!(!p.is_paused("default", now));
        assert!(!p.is_paused("kids", || 1600), "expires");
        p.pause_all(2000);
        assert!(p.is_paused("default", now));
        assert_eq!(p.active(1000).len(), 2);
        p.pause_all(0);
        p.pause_group("kids", 0);
        assert!(!p.is_paused("kids", now));
        assert_eq!(p.active(0), vec![]);
    }

    #[test]
    fn flt_005_groups_by_priority() {
        let t = table();
        let n = Neighbors::default();
        let tablet = t.identify("1.2.3.4".parse().unwrap(), Some("kids-tablet"), None, &n);
        let names: Vec<&str> = t.group_names(tablet).iter().map(|g| &**g).collect();
        assert_eq!(names, ["kids", "iot"]);
        assert_eq!(&*t.primary_group(tablet).name, "kids");
        let unknown = t.identify("172.16.0.1".parse().unwrap(), None, None, &n);
        assert_eq!(t.group_names(unknown).len(), 1);
        assert_eq!(&*t.primary_group(unknown).name, "default");
        assert_eq!(
            t.primary_group(unknown).lists,
            None,
            "implicit default: every list"
        );
        let office = t.identify("10.1.1.1".parse().unwrap(), None, None, &n);
        assert_eq!(&*t.primary_group(office).name, "default");
    }
}
