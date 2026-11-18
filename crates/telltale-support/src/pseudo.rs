//! REQ: OPS-011 (ADR-156) — pseudonyms that are stable inside one package, can't be reversed from
//! it, and keep what triage needs: names become `device-N`, `group-N` and so on in the order they
//! are first met; addresses are permuted prefix-preservingly with a keyed BLAKE3 function
//! (Crypto-PAn style), so addresses that share a /24 (or a /64) still share one, a private address
//! stays private, and a public one stays public; loopback, link-local, multicast, and the
//! well-known public resolvers are left alone.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What a name stands for, which decides its pseudonym's shape and its own counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    Device,
    Group,
    Node,
    Pod,
    Namespace,
    /// A host name with no public domain (`pi`, `kube.cluster.local`).
    Host,
    /// A public domain name (`dns.quad9.net`).
    Site,
    Zone,
    Email,
    /// A person's name in a home path.
    User,
    Cluster,
}

impl Category {
    /// The pseudonym's stem (`device` in `device-3`).
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Group => "group",
            Self::Node => "node",
            Self::Pod => "pod",
            Self::Namespace => "ns",
            Self::Host => "host",
            Self::Site => "site",
            Self::Zone => "zone",
            Self::Email | Self::User => "user",
            Self::Cluster => "cluster",
        }
    }

    /// The name used in the manifest's counts.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Group => "group",
            Self::Node => "node",
            Self::Pod => "pod",
            Self::Namespace => "namespace",
            Self::Host | Self::Site => "host",
            Self::Zone => "zone",
            Self::Email => "email",
            Self::User => "path",
            Self::Cluster => "cluster",
        }
    }
}

/// How a name's label is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Labels {
    /// A number, in the order names are first met (`device-3`): readable, but a different node
    /// would number the same device differently.
    #[default]
    Counted,
    /// REQ: OPS-011 (ADR-172) — a few bytes of a keyed hash of the name (`device-a3f9c2e1`): the
    /// same name gets the same label in every package made under one key, whatever order it is
    /// met in, which is how the nodes of one cluster package agree on a device's label.
    Keyed,
}

/// The package's pseudonyms, under one random key.
#[derive(Debug)]
pub struct Pseudonyms {
    key: [u8; 32],
    labels: Labels,
    names: HashMap<(Category, String), (String, String)>,
    /// Keyed labels in use, so two names that land on one label can be told apart.
    taken: HashMap<String, (Category, String)>,
    next: BTreeMap<Category, u32>,
    reveal: HashSet<String>,
    ips: HashMap<IpAddr, IpAddr>,
    macs: HashMap<[u8; 6], [u8; 6]>,
}

/// A name's pseudonym from its tag: `device-3`, `zone-3.example`, `user-3@example.invalid`.
fn label(cat: Category, tag: &str) -> String {
    match cat {
        Category::Zone => format!("zone-{tag}.example"),
        Category::Email => format!("user-{tag}@example.invalid"),
        _ => format!("{}-{tag}", cat.prefix()),
    }
}

/// Top-level domains of names nobody can look up; the rest of the names are public.
const PRIVATE_TLDS: &[&str] = &[
    "local",
    "lan",
    "internal",
    "home",
    "corp",
    "localdomain",
    "intranet",
    "private",
    "arpa",
    "svc",
    "cluster",
    "test",
    "example",
    "invalid",
    "localhost",
    "home-assistant",
    "box",
    "router",
    "domain",
    "workgroup",
];

fn is_public_tld(tld: &str) -> bool {
    tld.len() >= 2
        && tld.bytes().all(|b| b.is_ascii_alphabetic())
        && !PRIVATE_TLDS.contains(&tld.to_ascii_lowercase().as_str())
}

/// Public resolvers everyone knows: seeing them is not identifying, and a triage needs them.
const WELL_KNOWN_V4: &[[u8; 4]] = &[
    [1, 1, 1, 1],
    [1, 0, 0, 1],
    [1, 1, 1, 2],
    [1, 0, 0, 2],
    [1, 1, 1, 3],
    [1, 0, 0, 3],
    [8, 8, 8, 8],
    [8, 8, 4, 4],
    [9, 9, 9, 9],
    [9, 9, 9, 10],
    [9, 9, 9, 11],
    [149, 112, 112, 112],
    [149, 112, 112, 10],
    [208, 67, 222, 222],
    [208, 67, 220, 220],
    [94, 140, 14, 14],
    [94, 140, 15, 15],
    [94, 140, 14, 140],
    [94, 140, 14, 141],
    [185, 228, 168, 9],
    [185, 228, 169, 9],
];

const WELL_KNOWN_V6: &[[u16; 8]] = &[
    [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111],
    [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001],
    [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888],
    [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844],
    [0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe],
    [0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x0009],
    [0x2620, 0x0119, 0x0035, 0, 0, 0, 0, 0x0035],
    [0x2620, 0x0119, 0x0053, 0, 0, 0, 0, 0x0053],
];

/// The first bits of a private IPv4 address that make it private (its range's prefix length).
fn private4(a: Ipv4Addr) -> Option<usize> {
    let o = a.octets();
    match o {
        [10, ..] => Some(8),
        [172, b, ..] if (16..32).contains(&b) => Some(12),
        [192, 168, ..] => Some(16),
        [100, b, ..] if (64..128).contains(&b) => Some(10),
        _ => None,
    }
}

/// Addresses that stay as they are: not a person's, or known to everyone.
fn exempt4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_loopback()
        || a.is_unspecified()
        || a.is_link_local()
        || a.is_multicast()
        || a.is_broadcast()
        || o[0] == 0
        || o[0] >= 240
        || o[..3] == [192, 0, 0]
        || o[..3] == [192, 0, 2]
        || o[..3] == [198, 51, 100]
        || o[..3] == [203, 0, 113]
        || o[..3] == [192, 88, 99]
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || WELL_KNOWN_V4.contains(&o)
}

fn exempt6(a: Ipv6Addr) -> bool {
    let s = a.segments();
    a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || (s[0] == 0x0064 && s[1] == 0xff9b)
        || WELL_KNOWN_V6.contains(&s)
}

fn arr<const N: usize>(v: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let n = v.len().min(N);
    out[..n].copy_from_slice(&v[..n]);
    out
}

impl Pseudonyms {
    /// A fresh set under `key`.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            labels: Labels::Counted,
            names: HashMap::new(),
            taken: HashMap::new(),
            next: BTreeMap::new(),
            reveal: HashSet::new(),
            ips: HashMap::new(),
            macs: HashMap::new(),
        }
    }

    /// Names that stay readable (`--reveal`), whatever their category.
    #[must_use]
    pub fn with_reveal(mut self, names: impl IntoIterator<Item = String>) -> Self {
        self.reveal = names.into_iter().map(|n| n.to_ascii_lowercase()).collect();
        self
    }

    /// Labels from a keyed hash instead of numbers (see [`Labels::Keyed`]).
    #[must_use]
    pub fn with_keyed_labels(mut self) -> Self {
        self.labels = Labels::Keyed;
        self
    }

    /// A name's tag under keyed labels: eight hex digits of a keyed hash of what it is, two more
    /// bytes each time a different name already holds that label.
    fn keyed_tag(&mut self, cat: Category, lower: &str) -> String {
        let h = blake3::keyed_hash(
            &self.key,
            format!("label\0{}\0{lower}", cat.prefix()).as_bytes(),
        );
        let bytes = h.as_bytes();
        let mut len = 4;
        loop {
            let mut tag = String::with_capacity(len * 2);
            for b in &bytes[..len] {
                let _ = write!(tag, "{b:02x}");
            }
            let name = label(cat, &tag);
            let held = self
                .taken
                .get(&name)
                .is_some_and(|(c, other)| (*c, other.as_str()) != (cat, lower));
            if !held || len >= bytes.len() {
                self.taken.insert(name, (cat, lower.to_owned()));
                return tag;
            }
            len += 2;
        }
    }

    fn revealed(&self, name: &str) -> bool {
        self.reveal.contains(&name.to_ascii_lowercase())
    }

    /// The pseudonym of `original` in `cat`: the same one every time, a new number each first time.
    pub fn name(&mut self, cat: Category, original: &str) -> String {
        if self.revealed(original) {
            return original.to_owned();
        }
        let lower = original.to_ascii_lowercase();
        if let Some((p, _)) = self.names.get(&(cat, lower.clone())) {
            return p.clone();
        }
        let tag = match self.labels {
            Labels::Counted => {
                let n = self.next.entry(cat).or_insert(0);
                *n += 1;
                n.to_string()
            }
            Labels::Keyed => self.keyed_tag(cat, &lower),
        };
        let p = label(cat, &tag);
        self.names
            .insert((cat, lower), (p.clone(), original.to_owned()));
        p
    }

    /// A host name: an address literal as an address; a name keeps its last label
    /// (`site-3.com`, `host-2.local`) so the kind of name stays readable.
    pub fn host(&mut self, host: &str) -> String {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.ip(ip).to_string();
        }
        let h = host.trim_end_matches('.');
        if self.revealed(h) {
            return h.to_owned();
        }
        match h.rsplit_once('.') {
            None => self.name(Category::Host, h),
            Some((_, tld)) => {
                let cat = if is_public_tld(tld) {
                    Category::Site
                } else {
                    Category::Host
                };
                let stem = self.name(cat, h);
                format!("{stem}.{tld}")
            }
        }
    }

    /// An e-mail address, as `user-N@example.invalid`.
    pub fn email(&mut self, address: &str) -> String {
        self.name(Category::Email, address)
    }

    /// One address, permuted (or left alone: see the module's text).
    pub fn ip(&mut self, ip: IpAddr) -> IpAddr {
        if let Some(&p) = self.ips.get(&ip) {
            return p;
        }
        let out = match ip {
            IpAddr::V4(a) => IpAddr::V4(self.ip4(a)),
            IpAddr::V6(a) => IpAddr::V6(self.ip6(a)),
        };
        self.ips.insert(ip, out);
        out
    }

    /// A network `ip/prefix`: the address permuted, then cut back to its prefix, so a network
    /// stays a network.
    pub fn network(&mut self, ip: IpAddr, prefix: u8) -> IpAddr {
        let bits = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = usize::from(prefix).min(bits);
        let moved = self.ip(ip);
        let mut o = match moved {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        for (i, b) in o.iter_mut().enumerate() {
            let lo = i * 8;
            if lo >= prefix {
                *b = 0;
            } else if lo + 8 > prefix {
                *b &= 0xffu8 << (lo + 8 - prefix);
            }
        }
        match ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(arr::<4>(&o))),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(arr::<16>(&o))),
        }
    }

    /// A MAC address: the make (its first three bytes) stays for a universal address; a locally
    /// administered one (random, per network) has nothing to keep. The rest is replaced.
    pub fn mac(&mut self, m: [u8; 6]) -> [u8; 6] {
        if let Some(&p) = self.macs.get(&m) {
            return p;
        }
        let mut h = blake3::Hasher::new_keyed(&self.key);
        h.update(&[9]);
        h.update(&m);
        let d = *h.finalize().as_bytes();
        let mut out = [0u8; 6];
        if m[0] & 0x02 != 0 {
            out[0] = (d[0] & 0xfc) | (m[0] & 0x03);
            out[1..3].copy_from_slice(&d[1..3]);
        } else {
            out[..3].copy_from_slice(&m[..3]);
        }
        out[3..].copy_from_slice(&d[3..6]);
        self.macs.insert(m, out);
        out
    }

    /// Flips each bit at and after `keep` by a keyed function of the original bits before it:
    /// a permutation of the address space that keeps every shared prefix (Crypto-PAn).
    fn permute(&self, bytes: &[u8], keep: usize, family: u8) -> Vec<u8> {
        let mut out = bytes.to_vec();
        for i in keep..bytes.len() * 8 {
            let mut h = blake3::Hasher::new_keyed(&self.key);
            h.update(&[family]);
            h.update(&u16::try_from(i).unwrap_or(0).to_be_bytes());
            let full = i / 8;
            h.update(&bytes[..full]);
            let rest = i % 8;
            if rest != 0 {
                h.update(&[bytes[full] & (0xffu8 << (8 - rest))]);
            }
            let flip = h.finalize().as_bytes()[0] & 1;
            out[full] ^= flip << (7 - rest);
        }
        out
    }

    fn ip4(&self, a: Ipv4Addr) -> Ipv4Addr {
        if exempt4(a) {
            return a;
        }
        if let Some(keep) = private4(a) {
            return Ipv4Addr::from(arr::<4>(&self.permute(&a.octets(), keep, 4)));
        }
        // Cycle-walking: permute again until the result is a public address, so a public address
        // never turns into a private, special, or well-known one (and the map stays one-to-one).
        let mut x = a.octets();
        for _ in 0..64 {
            x = arr::<4>(&self.permute(&x, 0, 4));
            let y = Ipv4Addr::from(x);
            if !exempt4(y) && private4(y).is_none() {
                break;
            }
        }
        Ipv4Addr::from(x)
    }

    fn ip6(&self, a: Ipv6Addr) -> Ipv6Addr {
        if let Some(v4) = a.to_ipv4_mapped() {
            return self.ip4(v4).to_ipv6_mapped();
        }
        if exempt6(a) {
            return a;
        }
        let o = a.octets();
        if o[0] & 0xfe == 0xfc {
            // A unique local address keeps its first byte (`fd`): it stays one.
            return Ipv6Addr::from(arr::<16>(&self.permute(&o, 8, 6)));
        }
        if o[0] & 0xe0 == 0x20 {
            // Global unicast (2000::/3) keeps its first three bits and is walked like IPv4.
            let mut x = o;
            for _ in 0..64 {
                x = arr::<16>(&self.permute(&x, 3, 6));
                if !exempt6(Ipv6Addr::from(x)) {
                    break;
                }
            }
            return Ipv6Addr::from(x);
        }
        a
    }

    /// Everything replaced so far, one `pseudonym<TAB>original` line each, for `--keep-map`.
    #[must_use]
    pub fn map(&self) -> String {
        let mut rows: Vec<(String, String)> = self.names.values().cloned().collect();
        rows.extend(self.ips.iter().map(|(a, b)| (b.to_string(), a.to_string())));
        rows.extend(self.macs.iter().map(|(a, b)| (mac_text(*b), mac_text(*a))));
        rows.sort();
        rows.dedup();
        let mut out = String::new();
        for (p, o) in rows {
            out.push_str(&p);
            out.push('\t');
            out.push_str(&o);
            out.push('\n');
        }
        out
    }
}

/// `aa:bb:cc:dd:ee:ff`.
#[must_use]
pub fn mac_text(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(seed: u8) -> Pseudonyms {
        Pseudonyms::new([seed; 32])
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn octets(ip: IpAddr) -> Vec<u8> {
        match ip {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        }
    }

    #[test]
    fn ops_011_names_are_stable_and_numbered_by_first_encounter() {
        let mut s = p(1);
        assert_eq!(s.name(Category::Device, "Living-Room-TV"), "device-1");
        assert_eq!(s.name(Category::Device, "kitchen"), "device-2");
        assert_eq!(
            s.name(Category::Device, "living-room-tv"),
            "device-1",
            "case doesn't matter"
        );
        assert_eq!(
            s.name(Category::Group, "kids"),
            "group-1",
            "each category counts alone"
        );
        assert_eq!(s.name(Category::Namespace, "media"), "ns-1");
        assert_eq!(s.name(Category::Zone, "home.example.com"), "zone-1.example");
        assert_eq!(s.email("Me@Example.org"), "user-1@example.invalid");
    }

    // REQ: OPS-011 (ADR-172) — under keyed labels a name's label depends on the key and the name, not on
    // what was met before it, so two nodes under one key agree.
    #[test]
    fn ops_011_keyed_labels_are_the_same_whatever_the_order() {
        let mut a = Pseudonyms::new([7; 32]).with_keyed_labels();
        let mut b = Pseudonyms::new([7; 32]).with_keyed_labels();
        let x1 = a.name(Category::Device, "Living-TV");
        let y1 = a.name(Category::Device, "printer");
        let y2 = b.name(Category::Device, "printer");
        let x2 = b.name(Category::Device, "living-tv");
        assert_eq!(
            (&x1, &y1),
            (&x2, &y2),
            "met in another order, the same labels"
        );
        assert_ne!(x1, y1);
        assert!(
            x1.starts_with("device-") && x1.len() == "device-".len() + 8,
            "{x1}"
        );
        let mut c = Pseudonyms::new([8; 32]).with_keyed_labels();
        assert_ne!(
            c.name(Category::Device, "Living-TV"),
            x1,
            "another key, another label"
        );
        assert!(a.name(Category::Zone, "home.lan").ends_with(".example"));
        assert!(
            a.name(Category::Email, "me@x.io")
                .ends_with("@example.invalid")
        );
        // The same name in another kind is another label, and the map still lists each pair.
        assert_ne!(a.name(Category::Group, "Living-TV"), x1);
        assert!(a.map().contains("Living-TV"));
        // Counted labels are unchanged.
        let mut n = Pseudonyms::new([7; 32]);
        assert_eq!(n.name(Category::Device, "Living-TV"), "device-1");
        assert_eq!(n.name(Category::Device, "printer"), "device-2");
    }

    #[test]
    fn ops_011_reveal_keeps_that_name_and_only_it() {
        let mut s = p(1).with_reveal(["Pi".to_owned()]);
        assert_eq!(s.name(Category::Node, "pi"), "pi");
        assert_eq!(s.host("PI"), "PI");
        assert_eq!(s.name(Category::Node, "k8s"), "node-1");
    }

    #[test]
    fn ops_011_a_host_name_keeps_its_last_label() {
        let mut s = p(1);
        assert_eq!(s.host("pi"), "host-1");
        assert_eq!(s.host("dns.quad9.net"), "site-1.net");
        assert_eq!(s.host("dns.quad9.net."), "site-1.net");
        assert_eq!(s.host("nas.lan"), "host-2.lan");
        assert_eq!(s.host("8.8.8.8"), "8.8.8.8", "a well-known resolver stays");
        assert_ne!(s.host("192.168.1.20"), "192.168.1.20");
    }

    #[test]
    fn ops_011_private_stays_private_and_a_subnet_stays_a_subnet() {
        let mut s = p(7);
        let mapped: Vec<IpAddr> = (1..=254).map(|d| s.ip(v4(192, 168, 1, d))).collect();
        for m in &mapped {
            let o = octets(*m);
            assert_eq!(o[..2], [192, 168], "{m}");
            assert_eq!(o[..3], octets(mapped[0])[..3], "one /24 stays one /24: {m}");
        }
        let distinct: HashSet<_> = mapped.iter().collect();
        assert_eq!(distinct.len(), 254);
        assert_ne!(mapped[0], v4(192, 168, 1, 1), "it did move");
        // The other private ranges keep what makes them private.
        assert_eq!(octets(s.ip(v4(10, 3, 4, 5)))[0], 10);
        assert_eq!(octets(s.ip(v4(172, 20, 4, 5)))[0..1], [172]);
        let o = octets(s.ip(v4(172, 20, 4, 5)));
        assert!((16..32).contains(&o[1]), "{o:?}");
        let o = octets(s.ip(v4(100, 70, 1, 2)));
        assert!(o[0] == 100 && (64..128).contains(&o[1]), "{o:?}");
    }

    #[test]
    fn ops_011_public_stays_public_distinct_and_in_its_subnet() {
        let mut s = p(9);
        let mut seen = HashSet::new();
        for b in 0..40u8 {
            for c in 0..40u8 {
                let a = s.ip(v4(34, b, c, 7));
                let b2 = s.ip(v4(34, b, c, 200));
                assert_eq!(octets(a)[..3], octets(b2)[..3], "one /24 stays one /24");
                assert!(
                    matches!(a, IpAddr::V4(m) if !exempt4(m) && private4(m).is_none()),
                    "{a} is public"
                );
                assert!(seen.insert(a), "{a} twice: the map must be one-to-one");
            }
        }
    }

    #[test]
    fn ops_011_special_and_well_known_addresses_are_left_alone() {
        let mut s = p(3);
        for same in [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.1",
            "224.0.0.251",
            "255.255.255.255",
            "1.1.1.1",
            "8.8.4.4",
            "9.9.9.9",
            "192.0.2.5",
            "::1",
            "::",
            "fe80::1",
            "ff02::fb",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "2001:db8::5",
        ] {
            let ip: IpAddr = same.parse().unwrap();
            assert_eq!(s.ip(ip), ip, "{same}");
        }
        // And nothing else turns into one of them.
        for b in 0..255u8 {
            let m = s.ip(v4(35, b, 3, 4));
            assert_ne!(m, v4(1, 1, 1, 1));
            assert_ne!(m, v4(8, 8, 8, 8));
        }
    }

    #[test]
    fn ops_011_ipv6_keeps_its_kind_and_its_64() {
        let mut set = p(5);
        let first = set.ip("fd12:3456:789a:1::10".parse().unwrap());
        let second = set.ip("fd12:3456:789a:1::beef".parse().unwrap());
        assert_eq!(octets(first)[0], 0xfd, "a unique local address stays one");
        assert_eq!(
            octets(first)[..8],
            octets(second)[..8],
            "one /64 stays one /64"
        );
        assert_ne!(first, second);
        let global = set.ip("2a01:4f8:1234:5678::1".parse().unwrap());
        assert_eq!(
            octets(global)[0] & 0xe0,
            0x20,
            "global unicast stays global: {global}"
        );
        let mapped = set.ip("::ffff:192.168.1.9".parse().unwrap());
        assert!(
            matches!(mapped, IpAddr::V6(x) if x.to_ipv4_mapped().is_some()),
            "{mapped}"
        );
    }

    #[test]
    fn ops_011_the_same_key_gives_the_same_map_and_another_key_another() {
        let a = p(1).ip(v4(34, 5, 6, 7));
        assert_eq!(a, p(1).ip(v4(34, 5, 6, 7)));
        let moved = (0..20u8).any(|k| p(k + 2).ip(v4(34, 5, 6, 7)) != a);
        assert!(moved);
    }

    #[test]
    fn ops_011_a_network_stays_a_network() {
        let mut s = p(2);
        let n = s.network(v4(192, 168, 0, 0), 16);
        assert_eq!(octets(n)[2..], [0, 0]);
        assert_eq!(octets(n)[..2], [192, 168]);
        let n = s.network(v4(34, 1, 2, 0), 24);
        assert_eq!(octets(n)[3], 0);
        let n = s.network(v4(10, 0, 0, 0), 8);
        assert_eq!(octets(n)[1..], [0, 0, 0]);
    }

    #[test]
    fn ops_011_a_mac_keeps_its_make_and_is_otherwise_replaced() {
        let mut s = p(4);
        let m = [0x3c, 0x5a, 0xb4, 0x11, 0x22, 0x33];
        let o = s.mac(m);
        assert_eq!(o[..3], m[..3], "the OUI is the make, not a person");
        assert_ne!(o[3..], m[3..]);
        assert_eq!(s.mac(m), o);
        // A randomized (locally administered) MAC keeps only its flag bits.
        let r = [0xda, 0xa1, 0x19, 0x11, 0x22, 0x33];
        let o = s.mac(r);
        assert_eq!(o[0] & 0x03, r[0] & 0x03);
        assert_ne!(o[1..3], r[1..3]);
    }

    #[test]
    fn ops_011_the_map_lists_every_pair() {
        let mut s = p(1);
        s.name(Category::Device, "tv");
        s.ip(v4(192, 168, 1, 5));
        let map = s.map();
        assert!(map.contains("device-1\ttv\n"), "{map}");
        assert!(map.contains("\t192.168.1.5\n"), "{map}");
    }
}
