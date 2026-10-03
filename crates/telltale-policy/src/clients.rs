//! Client identification and group membership (`spec/03` §3 step 2, `spec/05` §1).
//!
//! REQ: FLT-005, FLT-006. Precedence: client ID (DoH path / DoT SNI) → EDNS MAC (only from
//! trusted forwarders) → MAC from the neighbor table → exact IP → most specific CIDR →
//! the `default` group. All lookups are hash maps or a short prefix list built once per
//! config, so identifying a client allocates nothing.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use telltale_config::{Cidr, Config, MatchKey};

/// A client group (FLT-005).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub name: Box<str>,
    /// List names; `None` = every enabled list.
    pub lists: Option<Vec<Box<str>>>,
    pub priority: i32,
}

/// A configured device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub name: Box<str>,
    /// Group indices, highest priority first (the first one's settings apply).
    pub groups: Vec<u16>,
    /// The same groups by name (routing `match_group`, `$client`).
    pub group_names: Vec<Box<str>>,
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
            })
            .collect();
        let default_idx = if let Some(i) = groups.iter().position(|g| &*g.name == "default") {
            i
        } else {
            groups.push(Group {
                name: "default".into(),
                lists: None,
                priority: i32::MIN,
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
            if gs.is_empty() {
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
        let found = |client, source| Identity {
            client: Some(client),
            source,
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
        }
    }

    /// Group indices for an identity, highest priority first.
    pub fn group_ids(&self, id: Identity) -> &[u16] {
        self.client(id).map_or(&self.default_group, |c| &c.groups)
    }

    /// Group names for an identity, highest priority first (for routing `match_group`).
    pub fn group_names(&self, id: Identity) -> &[Box<str>] {
        self.client(id)
            .map_or(&self.default_names, |c| &c.group_names)
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
