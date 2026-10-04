//! DNS-001: UDP workers answer queries (now or deferred), spread load across `SO_REUSEPORT`
//! sockets, reply from the right source address, and stop.

#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::needless_pass_by_value
)]

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use telltale_net::{RequestMeta, Response, UdpConfig, UdpListener};

/// Echo handler: replies with the request bytes and the QR bit set.
fn echo(req: &[u8], _: &RequestMeta, out: &mut [u8]) -> Response {
    let n = req.len().min(out.len());
    out[..n].copy_from_slice(&req[..n]);
    if n > 2 {
        out[2] |= 0x80;
    }
    Response::Ready(n)
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn client() -> UdpSocket {
    let c = UdpSocket::bind("127.0.0.1:0").unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    c
}

#[test]
fn dns_001_udp_workers_answer_and_shut_down() {
    let rt = rt();
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener =
        UdpListener::spawn(&UdpConfig::new(addr, 4), &Arc::new(echo), rt.handle()).unwrap();
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
    // Workers count a reply after sending it, so the last answer can arrive before its
    // count does (this raced on busy CI runners): wait briefly for the counters to settle.
    let replied = || -> u64 {
        listener
            .stats()
            .iter()
            .map(|s| s.replied.load(Ordering::Relaxed))
            .sum()
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while replied() < 64 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(replied(), 64);
    let busy = listener
        .stats()
        .iter()
        .filter(|s| s.received.load(Ordering::Relaxed) > 0)
        .count();
    assert!(
        busy >= 2,
        "SO_REUSEPORT should spread 64 flows over >1 of 4 workers, got {busy}"
    );
    listener.shutdown();
}

#[test]
fn dns_001_deferred_answers_reply_from_the_runtime() {
    let rt = rt();
    let deferred = |req: &[u8], _: &RequestMeta, _: &mut [u8]| -> Response {
        let mut owned = req.to_vec();
        Response::Deferred(Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            owned[2] |= 0x80;
            Some(owned)
        }))
    };
    let listener = UdpListener::spawn(
        &UdpConfig::new("0.0.0.0:0".parse().unwrap(), 1),
        &Arc::new(deferred),
        rt.handle(),
    )
    .unwrap();
    let target: SocketAddr = format!("127.0.0.1:{}", listener.local_addr().port())
        .parse()
        .unwrap();
    let c = client();
    c.send_to(&[0, 9, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0], target)
        .unwrap();
    let mut buf = [0u8; 64];
    let (n, from) = c.recv_from(&mut buf).unwrap();
    assert_eq!(
        (n, from),
        (12, target),
        "deferred reply also uses the PKTINFO source"
    );
    assert_eq!(buf[2] & 0x80, 0x80);
    // Counted after the send: allow the count to land.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while listener.stats()[0].deferred_replied.load(Ordering::Relaxed) < 1
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        listener.stats()[0].deferred_replied.load(Ordering::Relaxed),
        1
    );
    listener.shutdown();
}

#[test]
fn dns_001_wildcard_bind_replies_from_destination_address() {
    // Bound to 0.0.0.0: PKTINFO must make the reply come from 127.0.0.1, not some other IP.
    let rt = rt();
    let listener = UdpListener::spawn(
        &UdpConfig::new("0.0.0.0:0".parse().unwrap(), 1),
        &Arc::new(echo),
        rt.handle(),
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
    let rt = rt();
    let drop_all = |_: &[u8], _: &RequestMeta, _: &mut [u8]| Response::Drop;
    let listener = UdpListener::spawn(
        &UdpConfig::new("127.0.0.1:0".parse().unwrap(), 1),
        &Arc::new(drop_all),
        rt.handle(),
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
