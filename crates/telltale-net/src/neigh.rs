//! Kernel neighbor table (ARP for IPv4, NDP for IPv6) via an rtnetlink dump, for client
//! identification by MAC (FLT-006, `spec/03` §3 step 2).
//!
//! The syscalls live in `sys`; this module builds the request and parses the reply, all in
//! safe code. No privileges are needed: reading the table is allowed for any user, and with
//! host networking (a Pi) it shows the LAN's devices.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const NLMSG_HDRLEN: usize = 16;
const NDMSG_LEN: usize = 12;
const RTM_NEWNEIGH: u16 = 28;
const RTM_GETNEIGH: u16 = 30;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
/// Usable entries: REACHABLE, STALE, DELAY, PROBE, PERMANENT (not INCOMPLETE, FAILED, NOARP).
const NUD_USABLE: u16 = 0x02 | 0x04 | 0x08 | 0x10 | 0x80;

/// One neighbor: an address and the MAC it was last seen at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Neighbor {
    pub ip: IpAddr,
    pub mac: [u8; 6],
}

/// The `RTM_GETNEIGH` dump request for all address families.
pub(crate) fn dump_request(seq: u32) -> [u8; NLMSG_HDRLEN + NDMSG_LEN] {
    let mut m = [0u8; NLMSG_HDRLEN + NDMSG_LEN];
    #[allow(clippy::cast_possible_truncation)] // 28 bytes
    let len = m.len() as u32;
    m[0..4].copy_from_slice(&len.to_ne_bytes());
    m[4..6].copy_from_slice(&RTM_GETNEIGH.to_ne_bytes());
    m[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    m[8..12].copy_from_slice(&seq.to_ne_bytes());
    // ndmsg: family AF_UNSPEC (0) = every family; the rest zero.
    m
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(i..i + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

/// What one received buffer contained.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Chunk {
    /// More messages follow in the next datagram.
    More,
    Done,
}

/// Parses one netlink datagram, appending usable neighbors.
pub(crate) fn parse(buf: &[u8], out: &mut Vec<Neighbor>) -> io::Result<Chunk> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "malformed netlink message");
    let mut off = 0;
    while off + NLMSG_HDRLEN <= buf.len() {
        let len = u32_at(buf, off).ok_or_else(bad)? as usize;
        let kind = u16_at(buf, off + 4).ok_or_else(bad)?;
        if len < NLMSG_HDRLEN || off + len > buf.len() {
            return Err(bad());
        }
        let msg = &buf[off..off + len];
        match kind {
            NLMSG_DONE => return Ok(Chunk::Done),
            NLMSG_ERROR => {
                let code = msg
                    .get(NLMSG_HDRLEN..NLMSG_HDRLEN + 4)
                    .and_then(|b| b.try_into().ok())
                    .map_or(0, i32::from_ne_bytes);
                if code != 0 {
                    return Err(io::Error::from_raw_os_error(-code));
                }
            }
            RTM_NEWNEIGH => {
                if let Some(n) = parse_neigh(&msg[NLMSG_HDRLEN..]) {
                    out.push(n);
                }
            }
            _ => {}
        }
        off += (len + 3) & !3;
    }
    Ok(Chunk::More)
}

/// `ndmsg` + attributes → a neighbor, if it's usable and has both an address and a MAC.
fn parse_neigh(body: &[u8]) -> Option<Neighbor> {
    let family = *body.first()?;
    let state = u16_at(body, 8)?;
    if state & NUD_USABLE == 0 {
        return None;
    }
    let (mut ip, mut mac) = (None, None);
    let mut off = NDMSG_LEN;
    while off + 4 <= body.len() {
        let alen = usize::from(u16_at(body, off)?);
        let atype = u16_at(body, off + 2)?;
        if alen < 4 || off + alen > body.len() {
            return None;
        }
        let data = &body[off + 4..off + alen];
        match (atype, family, data.len()) {
            (NDA_DST, AF_INET, 4) => {
                ip = Some(IpAddr::V4(Ipv4Addr::new(
                    data[0], data[1], data[2], data[3],
                )));
            }
            (NDA_DST, AF_INET6, 16) => {
                let o: [u8; 16] = data.try_into().ok()?;
                ip = Some(IpAddr::V6(Ipv6Addr::from(o)));
            }
            (NDA_LLADDR, _, 6) => mac = data.try_into().ok(),
            _ => {}
        }
        off += (alen + 3) & !3;
    }
    let mac = mac.filter(|m| *m != [0; 6])?;
    Some(Neighbor { ip: ip?, mac })
}

/// Reads the whole neighbor table. Linux only; elsewhere returns an empty table.
pub fn neighbors() -> io::Result<Vec<Neighbor>> {
    #[cfg(target_os = "linux")]
    {
        crate::sys::neighbor_dump()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(kind: u16, data: &[u8]) -> Vec<u8> {
        let len = u16::try_from(4 + data.len()).unwrap();
        let mut a = Vec::new();
        a.extend_from_slice(&len.to_ne_bytes());
        a.extend_from_slice(&kind.to_ne_bytes());
        a.extend_from_slice(data);
        while a.len() % 4 != 0 {
            a.push(0);
        }
        a
    }

    fn neigh_msg(family: u8, state: u16, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut body = vec![family, 0, 0, 0, 2, 0, 0, 0];
        body.extend_from_slice(&state.to_ne_bytes());
        body.extend_from_slice(&[0, 0]);
        for a in attrs {
            body.extend_from_slice(a);
        }
        let len = u32::try_from(NLMSG_HDRLEN + body.len()).unwrap();
        let mut m = Vec::new();
        m.extend_from_slice(&len.to_ne_bytes());
        m.extend_from_slice(&RTM_NEWNEIGH.to_ne_bytes());
        m.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        m.extend_from_slice(&body);
        m
    }

    #[test]
    fn flt_006_parses_neighbor_dump() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut buf = neigh_msg(
            AF_INET,
            0x02,
            &[attr(NDA_DST, &[192, 168, 1, 20]), attr(NDA_LLADDR, &mac)],
        );
        let v6: [u8; 16] = "fe80::1".parse::<Ipv6Addr>().unwrap().octets();
        buf.extend(neigh_msg(
            AF_INET6,
            0x04,
            &[attr(NDA_DST, &v6), attr(NDA_LLADDR, &mac)],
        ));
        // FAILED entry and one without a MAC: skipped.
        buf.extend(neigh_msg(
            AF_INET,
            0x20,
            &[attr(NDA_DST, &[10, 0, 0, 1]), attr(NDA_LLADDR, &mac)],
        ));
        buf.extend(neigh_msg(AF_INET, 0x02, &[attr(NDA_DST, &[10, 0, 0, 2])]));
        let mut out = Vec::new();
        assert_eq!(parse(&buf, &mut out).unwrap(), Chunk::More);
        assert_eq!(
            out,
            vec![
                Neighbor {
                    ip: "192.168.1.20".parse().unwrap(),
                    mac
                },
                Neighbor {
                    ip: "fe80::1".parse().unwrap(),
                    mac
                },
            ]
        );
        let mut done = Vec::new();
        done.extend_from_slice(&16u32.to_ne_bytes());
        done.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        done.extend_from_slice(&[0; 10]);
        assert_eq!(parse(&done, &mut out).unwrap(), Chunk::Done);
        assert!(parse(&[1, 0, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &mut out).is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn flt_006_reads_the_live_table() {
        // Any Linux host has a table (possibly empty); the dump itself must succeed.
        let n = neighbors().unwrap();
        assert!(n.iter().all(|x| x.mac != [0; 6]));
    }
}
