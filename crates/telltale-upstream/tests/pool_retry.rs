//! REQ: UPS-008 (T10.9) — a pooled stream connection the server closes after reading a query,
//! without answering (an idle connection closed just as the query went out), is retried once
//! on a fresh connection instead of failing the query.

#![allow(clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use telltale_proto::{NameBuf, ResponseBuilder, parse_query, rcode, rtype, summarize};
use telltale_upstream::{Endpoint, Question, TlsOptions, Upstream, UpstreamOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The first connection reads a query and closes; later ones answer every query.
async fn flaky_server(connections: Arc<AtomicUsize>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let nth = connections.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 2];
                    if stream.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut msg = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    if stream.read_exact(&mut msg).await.is_err() {
                        return;
                    }
                    if nth == 0 {
                        return; // closed without answering
                    }
                    let query = parse_query(&msg).unwrap();
                    let mut out = [0u8; 512];
                    let mut builder =
                        ResponseBuilder::new(&query, &mut out, rcode::NOERROR).unwrap();
                    builder.answer_a(60, Ipv4Addr::new(192, 0, 2, 9)).unwrap();
                    let olen = builder.finish(None).unwrap();
                    let mut framed = u16::try_from(olen).unwrap().to_be_bytes().to_vec();
                    framed.extend_from_slice(&out[..olen]);
                    if stream.write_all(&framed).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn ups_008_closed_before_answering_is_retried_on_a_fresh_connection() {
    let connections = Arc::new(AtomicUsize::new(0));
    let addr = flaky_server(Arc::clone(&connections)).await;
    let ep = Endpoint::parse(&format!("tcp://{addr}")).unwrap();
    let up = Upstream::build(
        1,
        "flaky",
        ep,
        &UpstreamOptions::default(),
        &TlsOptions::default(),
    )
    .unwrap();
    let q = Question {
        name: NameBuf::from_presentation("retry.example").unwrap(),
        qtype: rtype::A,
        qclass: 1,
        dnssec_ok: false,
        checking_disabled: false,
        client_subnet: 0,
    };
    let resp = up.exchange(&q, Duration::from_secs(3)).await.unwrap();
    assert_eq!(summarize(&resp).unwrap().rcode, rcode::NOERROR);
    assert_eq!(
        connections.load(Ordering::SeqCst),
        2,
        "a second connection answered"
    );
}
