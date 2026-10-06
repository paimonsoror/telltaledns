//! mDNS device naming (REQ: API-010 naming sources, M8 "mDNS client naming"; T8.3): devices
//! announce themselves on the local network (`Kitchen-HomePod.local`, `brw123.local`,
//! `nas.local`), so listening to those announcements names them with no setup.
//!
//! Passive only: TelltaleDNS joins the mDNS group (224.0.0.251:5353, sharing the port with
//! avahi or the OS responder) and reads A and AAAA answers for `<name>.local` in the
//! responses others send; it never sends. Needs to be on the LAN (native installs, or a pod
//! with host networking). Bounded: at most 4096 names, oldest dropped.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use telltale_proto::{NameBuf, Section, read_name, records, rtype};
use tracing::{info, warn};

use crate::dhcp::{Lease, Leases};

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MAX_NAMES: usize = 4096;

/// The `(address, name)` pairs a response announces: A records owned by `<name>.local`.
pub(crate) fn announced(msg: &[u8]) -> Vec<(Ipv4Addr, String)> {
    // A response (QR set); queries carry no answers worth reading.
    if msg.len() < 12 || msg[2] & 0x80 == 0 {
        return Vec::new();
    }
    let local = NameBuf::from_presentation("local").unwrap_or_default();
    let Ok(it) = records(msg) else {
        return Vec::new();
    };
    it.flatten()
        .filter(|r| {
            matches!(r.section, Section::Answer | Section::Additional)
                && r.rtype == rtype::A
                && r.rdlen == 4
        })
        .filter_map(|r| {
            let mut owner = NameBuf::default();
            read_name(msg, r.name_off, &mut owner).ok()?;
            // `<one label>.local` only (service instance names have more labels).
            if !owner.is_subdomain_of(&local) || owner.label_count() != 2 {
                return None;
            }
            let label = owner.labels().next()?;
            let name: String = String::from_utf8_lossy(label)
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .take(63)
                .collect();
            let d = r.rdata(msg);
            let ip = Ipv4Addr::new(d[0], d[1], d[2], d[3]);
            (!name.is_empty() && !ip.is_unspecified() && !ip.is_link_local()).then_some((ip, name))
        })
        .collect()
}

/// Listens until `stop`, publishing the names seen into `view`.
pub(crate) async fn run(
    port: u16,
    view: Arc<ArcSwap<Leases>>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let sock = match bind(port) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "mDNS naming not started");
            return;
        }
    };
    info!(port, "mDNS naming: listening for device announcements");
    let mut names: HashMap<Ipv4Addr, (String, u64)> = HashMap::new();
    let mut buf = vec![0u8; 9000];
    let mut changed = false;
    let mut publish = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            _ = publish.tick() => {
                if changed {
                    let m: Leases = names
                        .iter()
                        .map(|(ip, (name, _))| {
                            (*ip, Lease { mac: String::new(), ip: *ip, hostname: Some(name.clone()), expires: 0, reserved: false })
                        })
                        .collect();
                    view.store(Arc::new(m));
                    changed = false;
                }
            }
            r = sock.recv_from(&mut buf) => {
                let Ok((n, _)) = r else { continue };
                let now = crate::pipeline::unix_now();
                for (ip, name) in announced(&buf[..n]) {
                    if names.get(&ip).is_none_or(|(old, _)| *old != name) {
                        changed = true;
                    }
                    names.insert(ip, (name, now));
                }
                if names.len() > MAX_NAMES {
                    // Drop the oldest tenth.
                    let mut by_age: Vec<(Ipv4Addr, u64)> = names.iter().map(|(ip, (_, t))| (*ip, *t)).collect();
                    by_age.sort_by_key(|(_, t)| *t);
                    for (ip, _) in by_age.into_iter().take(MAX_NAMES / 10) {
                        names.remove(&ip);
                    }
                    changed = true;
                }
            }
        }
    }
}

fn bind(port: u16) -> std::io::Result<tokio::net::UdpSocket> {
    let s = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true)?;
    s.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port).into())?;
    if let Err(e) = s.join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED) {
        // Unicast still arrives (tests); on a LAN without multicast there's nothing to hear.
        warn!(error = %e, "mDNS naming: can't join the mDNS group");
    }
    s.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(s.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An mDNS response announcing `name.local A ip`, plus a service record to ignore.
    fn announcement(name: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut m = vec![0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 0];
        let wire = |n: &str| NameBuf::from_presentation(n).unwrap().as_wire().to_vec();
        m.extend(wire(&format!("{name}.local")));
        m.extend([0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4]);
        m.extend(ip);
        m.extend(wire("_airplay._tcp.local"));
        m.extend([0, 12, 0, 1, 0, 0, 0, 120]);
        let target = wire(&format!("{name}._airplay._tcp.local"));
        m.extend(u16::try_from(target.len()).unwrap().to_be_bytes());
        m.extend(target);
        m
    }

    /// REQ: T8.3 — A records for `<name>.local` in responses; queries, service names, and
    /// link-local addresses are ignored.
    #[test]
    fn mdns_announcements() {
        let a = announcement("Kitchen-HomePod", [192, 168, 1, 44]);
        assert_eq!(
            announced(&a),
            vec![(Ipv4Addr::new(192, 168, 1, 44), "kitchen-homepod".to_owned())]
        );
        let mut q = a.clone();
        q[2] = 0;
        assert!(announced(&q).is_empty(), "a query");
        assert!(
            announced(&announcement("printer", [169, 254, 3, 3])).is_empty(),
            "link-local"
        );
    }

    /// REQ: T8.3 — the listener publishes what it hears.
    #[tokio::test]
    async fn mdns_listener_names_devices() {
        let port = {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap().port()
        };
        let view: Arc<ArcSwap<Leases>> = Arc::default();
        let (_tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(run(port, Arc::clone(&view), rx));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.send_to(&announcement("nas", [192, 168, 1, 9]), ("127.0.0.1", port))
            .unwrap();
        for _ in 0..80 {
            if view.load().get(&Ipv4Addr::new(192, 168, 1, 9)).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            view.load()
                .get(&Ipv4Addr::new(192, 168, 1, 9))
                .and_then(|l| l.hostname.clone()),
            Some("nas".into())
        );
    }
}
