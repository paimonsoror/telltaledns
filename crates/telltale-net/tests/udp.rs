//! DNS-001: UDP workers answer queries, spread load across `SO_REUSEPORT` sockets, and stop.

#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::unnecessary_wraps
)]

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use telltale_net::{Datagram, UdpConfig, UdpListener};

/// Echo handler: replies with the request bytes and the QR bit set.
fn echo(d: &Datagram<'_>, out: &mut [u8]) -> Option<usize> {
    let n = d.data.len().min(out.len());
    out[..n].copy_from_slice(&d.data[..n]);
    if n > 2 {
        out[2] |= 0x80;
    }
    Some(n)
}

fn client() -> UdpSocket {
    let c = UdpSocket::bind("127.0.0.1:0").unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    c
}

#[test]
fn dns_001_udp_workers_answer_and_shut_down() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = UdpListener::spawn(&UdpConfig::new(addr, 4), &Arc::new(echo)).unwrap();
    let server = listener.local_addr();
    assert_ne!(server.port(), 0);

    // Many client sockets so the kernel's 4-tuple hash spreads them across workers.
    let mut buf = [0u8; 512];
    for i in 0..64u16 {
        let c = client();
        let req = [(i >> 8) as u8, i as u8, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        c.send_to(&req, server).unwrap();
        let (n, from) = c.recv_from(&mut buf).unwrap();
        assert_eq!(from, server);
        assert_eq!(n, req.len());
        assert_eq!(&buf[..2], &req[..2]);
        assert_eq!(buf[2] & 0x80, 0x80);
    }
    let total: u64 = listener
        .stats()
        .iter()
        .map(|s| s.replied.load(std::sync::atomic::Ordering::Relaxed))
        .sum();
    assert_eq!(total, 64);
    let busy = listener
        .stats()
        .iter()
        .filter(|s| s.received.load(std::sync::atomic::Ordering::Relaxed) > 0)
        .count();
    assert!(
        busy >= 2,
        "SO_REUSEPORT should spread 64 flows over >1 of 4 workers, got {busy}"
    );
    listener.shutdown();
}

#[test]
fn dns_001_wildcard_bind_replies_from_destination_address() {
    // Bound to 0.0.0.0: PKTINFO must make the reply come from 127.0.0.1, not some other IP.
    let listener = UdpListener::spawn(
        &UdpConfig::new("0.0.0.0:0".parse().unwrap(), 1),
        &Arc::new(echo),
    )
    .unwrap();
    let port = listener.local_addr().port();
    let c = client();
    let target: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    c.send_to(&[0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0], target)
        .unwrap();
    let mut buf = [0u8; 64];
    let (_, from) = c.recv_from(&mut buf).unwrap();
    assert_eq!(from, target);
    listener.shutdown();
}

#[test]
fn dns_001_handler_can_drop() {
    let drop_all = |_: &Datagram<'_>, _: &mut [u8]| -> Option<usize> { None };
    let listener = UdpListener::spawn(
        &UdpConfig::new("127.0.0.1:0".parse().unwrap(), 1),
        &Arc::new(drop_all),
    )
    .unwrap();
    let c = client();
    c.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    c.send_to(&[0; 12], listener.local_addr()).unwrap();
    let mut buf = [0u8; 64];
    assert!(c.recv_from(&mut buf).is_err(), "no reply expected");
    listener.shutdown();
}
