//! DHCPv4 server (REQ: OPS-008, `spec/08` §7; T7.19): optional, off by default, for Linux and
//! Pi installs that want TelltaleDNS to hand out addresses too. One pool, static reservations,
//! options 1/3/6/15/42/51/54/58/59/119, a lease file, and lease hostnames that name devices.
//!
//! RFC 2131 behavior: DISCOVER → OFFER (held for a minute), REQUEST → ACK or NAK (selecting,
//! init-reboot, renewing/rebinding), RELEASE, DECLINE (the address is avoided for 10 minutes),
//! INFORM. Replies go to the relay (`giaddr`), to `ciaddr` when the client has one, else are
//! broadcast. Authoritative for its subnet: a client asking for an address that isn't its is
//! told NAK, so it starts over. In a cluster, run it on one node (no failover protocol).
//!
//! Never on the DNS path: its own task and socket; a failure is logged and DHCP stops, DNS
//! goes on.

#![allow(clippy::many_single_char_names, clippy::similar_names)] // wire buffers and protocol fields

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

const MAGIC: [u8; 4] = [99, 130, 83, 99];
const OFFER_HOLD_SECS: u64 = 60;
const DECLINE_SECS: u64 = 600;

// Message types (option 53).
const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const DECLINE: u8 = 4;
const ACK: u8 = 5;
const NAK: u8 = 6;
const RELEASE: u8 = 7;
const INFORM: u8 = 8;

/// A parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Packet {
    pub(crate) op: u8,
    pub(crate) xid: u32,
    pub(crate) flags: u16,
    pub(crate) ciaddr: Ipv4Addr,
    pub(crate) giaddr: Ipv4Addr,
    pub(crate) chaddr: [u8; 16],
    pub(crate) hlen: u8,
    pub(crate) msg_type: u8,
    pub(crate) requested: Option<Ipv4Addr>,
    pub(crate) server_id: Option<Ipv4Addr>,
    pub(crate) hostname: Option<String>,
}

fn ip_at(b: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(b[at], b[at + 1], b[at + 2], b[at + 3])
}

/// Parses a BOOTREQUEST with the DHCP magic cookie.
pub(crate) fn parse(b: &[u8]) -> Option<Packet> {
    if b.len() < 240 || b[0] != 1 || b[236..240] != MAGIC {
        return None;
    }
    let mut chaddr = [0u8; 16];
    chaddr.copy_from_slice(&b[28..44]);
    let mut p = Packet {
        op: b[0],
        xid: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        flags: u16::from_be_bytes([b[10], b[11]]),
        ciaddr: ip_at(b, 12),
        giaddr: ip_at(b, 24),
        chaddr,
        hlen: b[2].min(16),
        msg_type: 0,
        requested: None,
        server_id: None,
        hostname: None,
    };
    let mut i = 240;
    while i < b.len() {
        let code = b[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let len = usize::from(*b.get(i + 1)?);
        let v = b.get(i + 2..i + 2 + len)?;
        match (code, len) {
            (53, 1) => p.msg_type = v[0],
            (50, 4) => p.requested = Some(ip_at(v, 0)),
            (54, 4) => p.server_id = Some(ip_at(v, 0)),
            (12, 1..) => {
                let h: String = String::from_utf8_lossy(v)
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
                    .take(63)
                    .collect();
                if !h.is_empty() {
                    p.hostname = Some(h.to_ascii_lowercase());
                }
            }
            _ => {}
        }
        i += 2 + len;
    }
    (p.msg_type != 0).then_some(p)
}

/// `aa:bb:cc:dd:ee:ff`.
pub(crate) fn mac_text(p: &Packet) -> String {
    p.chaddr[..usize::from(p.hlen)]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The DHCP settings the server needs (from `[dhcp]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Settings {
    pub(crate) server_ip: Ipv4Addr,
    pub(crate) range: (Ipv4Addr, Ipv4Addr),
    pub(crate) mask: Ipv4Addr,
    pub(crate) router: Option<Ipv4Addr>,
    pub(crate) dns: Vec<Ipv4Addr>,
    pub(crate) ntp: Vec<Ipv4Addr>,
    pub(crate) domain: Option<String>,
    pub(crate) search: Vec<String>,
    pub(crate) lease_secs: u32,
    /// MAC (lowercase, colon-separated) → (address, hostname).
    pub(crate) statics: Vec<(String, Ipv4Addr, Option<String>)>,
}

/// One lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Lease {
    pub(crate) mac: String,
    pub(crate) ip: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) hostname: Option<String>,
    /// Unix seconds.
    pub(crate) expires: u64,
    #[serde(default)]
    pub(crate) reserved: bool,
}

/// What the server knows: leases by MAC, held offers, declined addresses.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct State {
    pub(crate) leases: HashMap<String, Lease>,
    #[serde(skip)]
    offers: HashMap<String, (Ipv4Addr, u64)>,
    #[serde(skip)]
    declined: HashMap<Ipv4Addr, u64>,
}

/// A reply to send: the packet and the message type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reply {
    pub(crate) msg_type: u8,
    pub(crate) yiaddr: Ipv4Addr,
}

fn in_range(s: &Settings, ip: Ipv4Addr) -> bool {
    u32::from(ip) >= u32::from(s.range.0) && u32::from(ip) <= u32::from(s.range.1)
}

fn same_subnet(s: &Settings, ip: Ipv4Addr) -> bool {
    u32::from(ip) & u32::from(s.mask) == u32::from(s.server_ip) & u32::from(s.mask)
}

impl State {
    fn taken(&self, s: &Settings, ip: Ipv4Addr, mac: &str, now: u64) -> bool {
        ip == s.server_ip
            || s.statics.iter().any(|(m, a, _)| *a == ip && m != mac)
            || self
                .leases
                .values()
                .any(|l| l.ip == ip && l.mac != mac && l.expires > now)
            || self
                .offers
                .iter()
                .any(|(m, (a, until))| *a == ip && m != mac && *until > now)
            || self.declined.get(&ip).is_some_and(|until| *until > now)
    }

    /// The address for `mac`: its reservation, its lease, the one it asks for, or the first
    /// free one in the pool.
    fn pick(
        &self,
        s: &Settings,
        mac: &str,
        wanted: Option<Ipv4Addr>,
        now: u64,
    ) -> Option<Ipv4Addr> {
        if let Some((_, ip, _)) = s.statics.iter().find(|(m, _, _)| m == mac) {
            return Some(*ip);
        }
        if let Some(l) = self.leases.get(mac)
            && in_range(s, l.ip)
            && !self.taken(s, l.ip, mac, now)
        {
            return Some(l.ip);
        }
        if let Some(w) = wanted
            && in_range(s, w)
            && !self.taken(s, w, mac, now)
        {
            return Some(w);
        }
        (u32::from(s.range.0)..=u32::from(s.range.1))
            .map(Ipv4Addr::from)
            .find(|ip| !self.taken(s, *ip, mac, now))
    }

    /// What may `mac` have? (Its reservation, or a pool address nobody else holds.)
    fn allowed(&self, s: &Settings, mac: &str, ip: Ipv4Addr, now: u64) -> bool {
        match s.statics.iter().find(|(m, _, _)| m == mac) {
            Some((_, a, _)) => *a == ip,
            None => in_range(s, ip) && !self.taken(s, ip, mac, now),
        }
    }

    fn bind(&mut self, s: &Settings, mac: &str, ip: Ipv4Addr, hostname: Option<String>, now: u64) {
        let reserved = s.statics.iter().find(|(m, _, _)| m == mac);
        let hostname = reserved
            .and_then(|(_, _, h)| h.clone())
            .or(hostname)
            .or_else(|| self.leases.get(mac).and_then(|l| l.hostname.clone()));
        self.offers.remove(mac);
        self.leases.insert(
            mac.to_owned(),
            Lease {
                mac: mac.to_owned(),
                ip,
                hostname,
                expires: now + u64::from(s.lease_secs),
                reserved: reserved.is_some(),
            },
        );
    }

    /// RFC 2131 §4.3: the reply to `p` at `now`, if any. `changed` says the leases changed.
    pub(crate) fn handle(&mut self, s: &Settings, p: &Packet, now: u64) -> (Option<Reply>, bool) {
        let mac = mac_text(p);
        self.offers.retain(|_, (_, until)| *until > now);
        self.declined.retain(|_, until| *until > now);
        match p.msg_type {
            DISCOVER => {
                if let Some(ip) = self.pick(s, &mac, p.requested, now) {
                    self.offers.insert(mac, (ip, now + OFFER_HOLD_SECS));
                    (
                        Some(Reply {
                            msg_type: OFFER,
                            yiaddr: ip,
                        }),
                        false,
                    )
                } else {
                    warn!(%mac, "DHCP pool exhausted");
                    (None, false)
                }
            }
            REQUEST => {
                // Selecting: the client chose a server; if not us, forget the offer.
                if let Some(sid) = p.server_id
                    && sid != s.server_ip
                {
                    self.offers.remove(&mac);
                    return (None, false);
                }
                let ip = if p.ciaddr.is_unspecified() {
                    p.requested
                } else {
                    Some(p.ciaddr)
                };
                let Some(ip) = ip else {
                    return (
                        Some(Reply {
                            msg_type: NAK,
                            yiaddr: Ipv4Addr::UNSPECIFIED,
                        }),
                        false,
                    );
                };
                if !same_subnet(s, ip) && p.giaddr.is_unspecified() {
                    return (
                        Some(Reply {
                            msg_type: NAK,
                            yiaddr: Ipv4Addr::UNSPECIFIED,
                        }),
                        false,
                    );
                }
                if self.allowed(s, &mac, ip, now) {
                    self.bind(s, &mac, ip, p.hostname.clone(), now);
                    (
                        Some(Reply {
                            msg_type: ACK,
                            yiaddr: ip,
                        }),
                        true,
                    )
                } else {
                    (
                        Some(Reply {
                            msg_type: NAK,
                            yiaddr: Ipv4Addr::UNSPECIFIED,
                        }),
                        false,
                    )
                }
            }
            RELEASE => {
                let gone = self
                    .leases
                    .get(&mac)
                    .is_some_and(|l| l.ip == p.ciaddr && !l.reserved);
                if gone {
                    self.leases.remove(&mac);
                }
                (None, gone)
            }
            DECLINE => {
                if let Some(ip) = p.requested {
                    warn!(%mac, %ip, "DHCP address declined (in use by something else); avoiding it for 10 minutes");
                    self.declined.insert(ip, now + DECLINE_SECS);
                    let had = self.leases.get(&mac).is_some_and(|l| l.ip == ip);
                    if had {
                        self.leases.remove(&mac);
                    }
                    return (None, had);
                }
                (None, false)
            }
            INFORM => (
                Some(Reply {
                    msg_type: ACK,
                    yiaddr: Ipv4Addr::UNSPECIFIED,
                }),
                false,
            ),
            _ => (None, false),
        }
    }
}

/// A domain search list (option 119, RFC 3397): DNS names in wire format, uncompressed.
fn search_list(names: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for n in names {
        for label in n.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
            out.push(u8::try_from(label.len().min(63)).unwrap_or(63));
            out.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
        }
        out.push(0);
    }
    out
}

/// Appends option `code` (split into 255-byte pieces when longer, RFC 3396).
fn opt(out: &mut Vec<u8>, code: u8, v: &[u8]) {
    for chunk in v.chunks(255) {
        out.push(code);
        out.push(u8::try_from(chunk.len()).unwrap_or(255));
        out.extend_from_slice(chunk);
    }
}

fn ips(v: &[Ipv4Addr]) -> Vec<u8> {
    v.iter().flat_map(std::net::Ipv4Addr::octets).collect()
}

/// The BOOTREPLY for `reply` to `p`.
pub(crate) fn build(s: &Settings, p: &Packet, reply: &Reply) -> Vec<u8> {
    let mut b = vec![0u8; 240];
    b[0] = 2; // BOOTREPLY
    b[1] = 1; // Ethernet
    b[2] = p.hlen;
    b[4..8].copy_from_slice(&p.xid.to_be_bytes());
    b[10..12].copy_from_slice(&p.flags.to_be_bytes());
    if reply.msg_type == ACK && p.msg_type == INFORM {
        b[12..16].copy_from_slice(&p.ciaddr.octets());
    }
    b[16..20].copy_from_slice(&reply.yiaddr.octets());
    b[24..28].copy_from_slice(&p.giaddr.octets());
    b[28..44].copy_from_slice(&p.chaddr);
    b[236..240].copy_from_slice(&MAGIC);
    opt(&mut b, 53, &[reply.msg_type]);
    opt(&mut b, 54, &s.server_ip.octets());
    if reply.msg_type != NAK {
        if p.msg_type != INFORM {
            let l = s.lease_secs;
            opt(&mut b, 51, &l.to_be_bytes());
            opt(&mut b, 58, &(l / 2).to_be_bytes());
            opt(&mut b, 59, &(l / 8 * 7).to_be_bytes());
        }
        opt(&mut b, 1, &s.mask.octets());
        if let Some(r) = s.router {
            opt(&mut b, 3, &r.octets());
        }
        let dns = if s.dns.is_empty() {
            vec![s.server_ip]
        } else {
            s.dns.clone()
        };
        opt(&mut b, 6, &ips(&dns));
        if let Some(d) = &s.domain {
            opt(&mut b, 15, d.as_bytes());
        }
        if !s.ntp.is_empty() {
            opt(&mut b, 42, &ips(&s.ntp));
        }
        if !s.search.is_empty() {
            opt(&mut b, 119, &search_list(&s.search));
        }
        // Broadcast address (option 28).
        let bcast = u32::from(s.server_ip) | !u32::from(s.mask);
        opt(&mut b, 28, &Ipv4Addr::from(bcast).octets());
    }
    b.push(255);
    while b.len() < 300 {
        b.push(0); // BOOTP minimum size
    }
    b
}

/// Where a reply goes (RFC 2131 §4.1): the relay, the client's address, or broadcast.
pub(crate) fn destination(
    p: &Packet,
    reply: &Reply,
    client_port: u16,
    server_port: u16,
) -> SocketAddrV4 {
    if !p.giaddr.is_unspecified() {
        return SocketAddrV4::new(p.giaddr, server_port);
    }
    if reply.msg_type != NAK && !p.ciaddr.is_unspecified() {
        return SocketAddrV4::new(p.ciaddr, client_port);
    }
    SocketAddrV4::new(Ipv4Addr::BROADCAST, client_port)
}

/// Settings from `[dhcp]`.
pub(crate) fn settings(cfg: &telltale_config::DhcpConfig) -> Option<Settings> {
    Some(Settings {
        server_ip: cfg.server_ip?,
        range: (cfg.range_start?, cfg.range_end?),
        mask: cfg.subnet_mask,
        router: cfg.router,
        dns: cfg.dns.clone(),
        ntp: cfg.ntp.clone(),
        domain: cfg.domain.as_ref().map(ToString::to_string),
        search: cfg.search.iter().map(ToString::to_string).collect(),
        lease_secs: cfg.lease_secs,
        statics: cfg
            .reservation
            .iter()
            .map(|r| {
                (
                    r.mac.to_ascii_lowercase().replace('-', ":"),
                    r.ip,
                    r.hostname.as_ref().map(ToString::to_string),
                )
            })
            .collect(),
    })
}

/// The leases for naming and the API: address → lease.
pub(crate) type Leases = HashMap<Ipv4Addr, Lease>;

fn publish(state: &State, view: &arc_swap::ArcSwap<Leases>, now: u64) {
    let m: Leases = state
        .leases
        .values()
        .filter(|l| l.expires > now || l.reserved)
        .map(|l| (l.ip, l.clone()))
        .collect();
    view.store(Arc::new(m));
}

fn save(path: &PathBuf, state: &State) {
    let Ok(json) = serde_json::to_vec_pretty(state) else {
        return;
    };
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, json).and_then(|()| std::fs::rename(&tmp, path)) {
        warn!(path = %path.display(), error = %e, "DHCP leases not saved");
    }
}

/// Runs the server on `cfg.listen` until `stop`.
pub(crate) async fn run(
    cfg: telltale_config::DhcpConfig,
    data_dir: PathBuf,
    view: Arc<arc_swap::ArcSwap<Leases>>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let Some(s) = settings(&cfg) else { return };
    let path = data_dir.join("dhcp-leases.json");
    let mut state: State = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    publish(&state, &view, crate::pipeline::unix_now());
    let sock = match bind(&cfg) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, port = cfg.port, "DHCP server not started (binding port 67 needs CAP_NET_BIND_SERVICE; an interface needs CAP_NET_RAW)");
            return;
        }
    };
    info!(range = %format!("{}-{}", s.range.0, s.range.1), leases = state.leases.len(), "DHCP server started");
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, from) = tokio::select! {
            _ = stop.changed() => {
                save(&path, &state);
                return;
            }
            r = sock.recv_from(&mut buf) => match r {
                Ok(x) => x,
                Err(e) => {
                    warn!(error = %e, "DHCP receive failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let Some(p) = parse(&buf[..n]) else { continue };
        let now = crate::pipeline::unix_now();
        let (reply, changed) = state.handle(&s, &p, now);
        if changed {
            save(&path, &state);
            publish(&state, &view, now);
        }
        if let Some(r) = reply {
            let pkt = build(&s, &p, &r);
            let dest = if cfg.reply_to_source {
                from // tests: no broadcast on loopback
            } else {
                SocketAddr::V4(destination(&p, &r, cfg.client_port, cfg.port))
            };
            if let Err(e) = sock.send_to(&pkt, dest).await {
                warn!(error = %e, %dest, "DHCP reply not sent");
            }
            if r.msg_type == ACK && p.msg_type == REQUEST {
                info!(mac = %mac_text(&p), ip = %r.yiaddr, hostname = p.hostname.as_deref().unwrap_or(""), "DHCP lease");
            }
        }
    }
}

fn bind(cfg: &telltale_config::DhcpConfig) -> std::io::Result<tokio::net::UdpSocket> {
    let s = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    s.set_reuse_address(true)?;
    s.set_broadcast(true)?;
    if let Some(dev) = &cfg.interface {
        s.bind_device(Some(dev.as_bytes()))?;
    }
    let addr = SocketAddr::new(cfg.bind.into(), cfg.port);
    s.bind(&addr.into())?;
    s.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(s.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        Settings {
            server_ip: Ipv4Addr::new(192, 168, 1, 2),
            range: (
                Ipv4Addr::new(192, 168, 1, 100),
                Ipv4Addr::new(192, 168, 1, 102),
            ),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            router: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns: Vec::new(),
            ntp: vec![Ipv4Addr::new(192, 168, 1, 1)],
            domain: Some("lan".into()),
            search: vec!["lan".into(), "home.arpa".into()],
            lease_secs: 3600,
            statics: vec![(
                "aa:aa:aa:aa:aa:01".into(),
                Ipv4Addr::new(192, 168, 1, 10),
                Some("nas".into()),
            )],
        }
    }

    /// A client message.
    fn msg(
        t: u8,
        mac_last: u8,
        requested: Option<Ipv4Addr>,
        server: Option<Ipv4Addr>,
        ciaddr: Ipv4Addr,
    ) -> Packet {
        let mut chaddr = [0u8; 16];
        chaddr[..6].copy_from_slice(&[0xaa, 0xaa, 0xaa, 0xaa, 0xaa, mac_last]);
        Packet {
            op: 1,
            xid: 0x1234_5678,
            flags: 0x8000,
            ciaddr,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            hlen: 6,
            msg_type: t,
            requested,
            server_id: server,
            hostname: Some(format!("host{mac_last}")),
        }
    }

    const NONE: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

    /// REQ: OPS-008 — DORA, renewals, reservations, NAK for someone else's address, release,
    /// decline, and pool exhaustion.
    #[test]
    fn ops_008_lease_lifecycle() {
        let s = settings();
        let sid = Some(s.server_ip);
        let mut st = State::default();
        let (r, _) = st.handle(&s, &msg(DISCOVER, 2, None, None, NONE), 1000);
        let offered = r.unwrap().yiaddr;
        assert_eq!(offered, Ipv4Addr::new(192, 168, 1, 100));
        // Another client doesn't get the held offer.
        let (r, _) = st.handle(&s, &msg(DISCOVER, 3, Some(offered), None, NONE), 1000);
        assert_eq!(r.unwrap().yiaddr, Ipv4Addr::new(192, 168, 1, 101));
        let (r, changed) = st.handle(&s, &msg(REQUEST, 2, Some(offered), sid, NONE), 1001);
        assert_eq!(
            (r.unwrap(), changed),
            (
                Reply {
                    msg_type: ACK,
                    yiaddr: offered
                },
                true
            )
        );
        assert_eq!(
            st.leases["aa:aa:aa:aa:aa:02"].hostname.as_deref(),
            Some("host2")
        );
        // Renewing (ciaddr set, no server id).
        let (r, _) = st.handle(&s, &msg(REQUEST, 2, None, None, offered), 2000);
        assert_eq!(r.unwrap().msg_type, ACK);
        // Someone else asking for it: NAK.
        let (r, _) = st.handle(&s, &msg(REQUEST, 4, Some(offered), None, NONE), 2000);
        assert_eq!(r.unwrap().msg_type, NAK);
        // A request to another server drops our offer silently.
        let (r, _) = st.handle(
            &s,
            &msg(
                REQUEST,
                3,
                Some(Ipv4Addr::new(192, 168, 1, 101)),
                Some(Ipv4Addr::new(192, 168, 1, 9)),
                NONE,
            ),
            1001,
        );
        assert!(r.is_none());
        // The reservation, with its hostname.
        let (r, _) = st.handle(&s, &msg(DISCOVER, 1, None, None, NONE), 2000);
        assert_eq!(r.unwrap().yiaddr, Ipv4Addr::new(192, 168, 1, 10));
        st.handle(
            &s,
            &msg(REQUEST, 1, Some(Ipv4Addr::new(192, 168, 1, 10)), sid, NONE),
            2000,
        );
        assert_eq!(
            st.leases["aa:aa:aa:aa:aa:01"].hostname.as_deref(),
            Some("nas")
        );
        // Decline: avoided.
        let (_, changed) = st.handle(&s, &msg(DECLINE, 2, Some(offered), sid, NONE), 2001);
        assert!(changed);
        let (r, _) = st.handle(&s, &msg(DISCOVER, 5, Some(offered), None, NONE), 2002);
        assert_ne!(
            r.unwrap().yiaddr,
            offered,
            "a declined address isn't offered"
        );
        // Release.
        st.handle(
            &s,
            &msg(REQUEST, 5, Some(Ipv4Addr::new(192, 168, 1, 101)), sid, NONE),
            2003,
        );
        let (_, changed) = st.handle(
            &s,
            &msg(RELEASE, 5, None, sid, Ipv4Addr::new(192, 168, 1, 101)),
            2004,
        );
        assert!(changed && !st.leases.contains_key("aa:aa:aa:aa:aa:05"));
        // Exhaustion: .100 declined, .101/.102 taken.
        st.handle(&s, &msg(DISCOVER, 6, None, None, NONE), 2005);
        st.handle(
            &s,
            &msg(REQUEST, 6, Some(Ipv4Addr::new(192, 168, 1, 101)), sid, NONE),
            2005,
        );
        st.handle(&s, &msg(DISCOVER, 7, None, None, NONE), 2005);
        st.handle(
            &s,
            &msg(REQUEST, 7, Some(Ipv4Addr::new(192, 168, 1, 102)), sid, NONE),
            2005,
        );
        let (r, _) = st.handle(&s, &msg(DISCOVER, 8, None, None, NONE), 2006);
        assert!(r.is_none(), "pool exhausted");
    }

    /// REQ: OPS-008 — the reply's wire format: header, cookie, and the options.
    #[test]
    fn ops_008_reply_options() {
        let s = settings();
        let p = msg(DISCOVER, 2, None, None, NONE);
        let b = build(
            &s,
            &p,
            &Reply {
                msg_type: OFFER,
                yiaddr: Ipv4Addr::new(192, 168, 1, 100),
            },
        );
        assert_eq!(
            (b[0], &b[4..8], &b[16..20]),
            (2, &[0x12, 0x34, 0x56, 0x78][..], &[192, 168, 1, 100][..])
        );
        assert_eq!(&b[236..240], &MAGIC);
        let mut opts = HashMap::new();
        let mut i = 240;
        while b[i] != 255 {
            let (c, l) = (b[i], usize::from(b[i + 1]));
            opts.entry(c)
                .or_insert_with(Vec::new)
                .extend_from_slice(&b[i + 2..i + 2 + l]);
            i += 2 + l;
        }
        assert_eq!(opts[&53], vec![OFFER]);
        assert_eq!(opts[&54], vec![192, 168, 1, 2]);
        assert_eq!(opts[&3], vec![192, 168, 1, 1]);
        assert_eq!(opts[&6], vec![192, 168, 1, 2], "DNS: ourselves by default");
        assert_eq!(opts[&15], b"lan".to_vec());
        assert_eq!(opts[&119], b"\x03lan\x00\x04home\x04arpa\x00".to_vec());
        assert_eq!(opts[&51], 3600u32.to_be_bytes().to_vec());
        assert_eq!(opts[&28], vec![192, 168, 1, 255]);
        assert!(b.len() >= 300);
        // Round trip of the request side.
        let mut req = b.clone();
        req[0] = 1;
        let q = parse(&req).unwrap();
        assert_eq!((q.xid, q.msg_type), (0x1234_5678, OFFER));
        assert_eq!(mac_text(&q), "aa:aa:aa:aa:aa:02");
    }

    #[test]
    fn ops_008_reply_destination() {
        let mut p = msg(DISCOVER, 2, None, None, NONE);
        let offer = Reply {
            msg_type: OFFER,
            yiaddr: Ipv4Addr::new(192, 168, 1, 100),
        };
        assert_eq!(
            destination(&p, &offer, 68, 67),
            SocketAddrV4::new(Ipv4Addr::BROADCAST, 68)
        );
        p.giaddr = Ipv4Addr::new(10, 0, 0, 1);
        assert_eq!(
            destination(&p, &offer, 68, 67),
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 67)
        );
        let mut p = msg(REQUEST, 2, None, None, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(
            destination(
                &p,
                &Reply {
                    msg_type: ACK,
                    yiaddr: p.ciaddr
                },
                68,
                67
            ),
            SocketAddrV4::new(p.ciaddr, 68)
        );
        p.giaddr = Ipv4Addr::UNSPECIFIED;
        assert_eq!(
            destination(
                &p,
                &Reply {
                    msg_type: NAK,
                    yiaddr: NONE
                },
                68,
                67
            )
            .ip(),
            &Ipv4Addr::BROADCAST
        );
    }
}
