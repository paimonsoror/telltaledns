//! DNS-001 over TCP (RFC 7766): pipelining, idle timeout, connection cap, shutdown.

#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::unnecessary_wraps
)]

use std::sync::Arc;
use std::time::Duration;

use telltale_net::{RequestMeta, Response, TcpConfig, TcpServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn echo(req: &[u8], _: &RequestMeta, out: &mut [u8]) -> Response {
    out[..req.len()].copy_from_slice(req);
    out[2] |= 0x80;
    Response::Ready(req.len())
}

fn frame(id: u16) -> Vec<u8> {
    let msg = [(id >> 8) as u8, id as u8, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    let mut f = (msg.len() as u16).to_be_bytes().to_vec();
    f.extend_from_slice(&msg);
    f
}

async fn read_frame(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await?;
    let mut buf = vec![0; usize::from(u16::from_be_bytes(len))];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

fn cfg() -> TcpConfig {
    TcpConfig::new("127.0.0.1:0".parse().unwrap())
}

#[tokio::test]
async fn dns_001_tcp_pipelined_queries() {
    let server = TcpServer::bind(cfg(), Arc::new(echo)).unwrap();
    let mut s = TcpStream::connect(server.local_addr()).await.unwrap();
    // Three queries in a single write (RFC 7766 §6.2.1.1 pipelining).
    let mut batch = Vec::new();
    for id in [1u16, 2, 3] {
        batch.extend(frame(id));
    }
    s.write_all(&batch).await.unwrap();
    for id in [1u16, 2, 3] {
        let r = read_frame(&mut s).await.unwrap();
        assert_eq!(u16::from_be_bytes([r[0], r[1]]), id);
        assert_eq!(r[2] & 0x80, 0x80);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn dns_001_tcp_deferred_answers_are_written_out_of_order() {
    // ID 1 is slow (simulated upstream), ID 2 is immediate: 2 must not wait behind 1.
    let handler = |req: &[u8], _: &RequestMeta, out: &mut [u8]| -> Response {
        if req[1] == 1 {
            let mut owned = req.to_vec();
            return Response::Deferred(Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                owned[2] |= 0x80;
                Some(owned)
            }));
        }
        echo(
            req,
            &RequestMeta {
                peer: "0.0.0.0:0".parse().unwrap(),
                local: None,
                transport: telltale_net::Transport::Tcp,
                client_id: None,
            },
            out,
        )
    };
    let server = TcpServer::bind(cfg(), Arc::new(handler)).unwrap();
    let mut s = TcpStream::connect(server.local_addr()).await.unwrap();
    let mut batch = frame(1);
    batch.extend(frame(2));
    s.write_all(&batch).await.unwrap();
    let first = read_frame(&mut s).await.unwrap();
    let second = read_frame(&mut s).await.unwrap();
    assert_eq!(first[1], 2, "fast answer first");
    assert_eq!(second[1], 1, "slow answer still delivered");
    server.shutdown().await;
}

#[tokio::test]
async fn dns_001_tcp_idle_timeout_closes() {
    let mut c = cfg();
    c.idle_timeout = Duration::from_millis(200);
    let server = TcpServer::bind(c, Arc::new(echo)).unwrap();
    let mut s = TcpStream::connect(server.local_addr()).await.unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
        .await
        .expect("server should close the idle connection");
    assert_eq!(n.unwrap_or(0), 0, "EOF after idle timeout");
    assert_eq!(
        server
            .stats()
            .idle_closed
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    server.shutdown().await;
}

#[tokio::test]
async fn dns_001_tcp_connection_cap() {
    let mut c = cfg();
    c.max_connections = 1;
    let server = TcpServer::bind(c, Arc::new(echo)).unwrap();
    let mut first = TcpStream::connect(server.local_addr()).await.unwrap();
    first.write_all(&frame(1)).await.unwrap();
    read_frame(&mut first).await.unwrap(); // first is established and served

    let mut second = TcpStream::connect(server.local_addr()).await.unwrap();
    let _ = second.write_all(&frame(2)).await;
    let r = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut second)).await;
    assert!(
        matches!(r, Ok(Err(_))),
        "second connection should be closed"
    );
    assert_eq!(
        server
            .stats()
            .rejected
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    server.shutdown().await;
}

/// REQ: DNS-001 (RFC 7766 §6.2.3) — a client that sends queries but never reads the answers
/// must not hold its connection (and its slot) forever: once a write stalls for the idle
/// timeout the server closes it, and the slot serves the next client.
#[tokio::test]
async fn dns_001_tcp_slow_reader_is_closed() {
    // Big answers fill the socket buffers quickly.
    fn big(req: &[u8], _: &RequestMeta, out: &mut [u8]) -> Response {
        out[..12].copy_from_slice(&req[..12]);
        out[2] |= 0x80;
        Response::Ready(60_000)
    }
    let mut c = cfg();
    c.idle_timeout = Duration::from_millis(300);
    c.max_connections = 1;
    let server = TcpServer::bind(c, Arc::new(big)).unwrap();
    let mut stuck = TcpStream::connect(server.local_addr()).await.unwrap();
    // Queries without ever reading: the kernel buffers fill and the server's writes stall.
    let mut batch = Vec::new();
    for id in 0..2000u16 {
        batch.extend(frame(id));
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), stuck.write_all(&batch)).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let mut next = TcpStream::connect(server.local_addr()).await.unwrap();
    next.write_all(&frame(7)).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut next)).await;
    assert!(
        matches!(r, Ok(Ok(_))),
        "the stalled connection should have been closed and its slot freed: {r:?}"
    );
    assert_eq!(
        server
            .stats()
            .stalled_closed
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    drop(stuck);
    server.shutdown().await;
}

#[tokio::test]
async fn dns_001_tcp_runt_length_closes_connection() {
    let server = TcpServer::bind(cfg(), Arc::new(echo)).unwrap();
    let mut s = TcpStream::connect(server.local_addr()).await.unwrap();
    s.write_all(&[0, 3, 1, 2, 3]).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut s)).await;
    assert!(matches!(r, Ok(Err(_))));
    server.shutdown().await;
}
