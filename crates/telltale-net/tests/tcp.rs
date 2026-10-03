//! DNS-001 over TCP (RFC 7766): pipelining, idle timeout, connection cap, shutdown.

#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::unnecessary_wraps
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use telltale_net::{TcpConfig, TcpServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn echo(req: &[u8], _: SocketAddr, out: &mut [u8]) -> Option<usize> {
    out[..req.len()].copy_from_slice(req);
    out[2] |= 0x80;
    Some(req.len())
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

#[tokio::test]
async fn dns_001_tcp_runt_length_closes_connection() {
    let server = TcpServer::bind(cfg(), Arc::new(echo)).unwrap();
    let mut s = TcpStream::connect(server.local_addr()).await.unwrap();
    s.write_all(&[0, 3, 1, 2, 3]).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut s)).await;
    assert!(matches!(r, Ok(Err(_))));
    server.shutdown().await;
}
