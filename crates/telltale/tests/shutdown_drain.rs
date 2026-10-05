//! REQ: OPS-007 — with `[node] drain_delay_secs`, a node keeps answering for that long after
//! SIGTERM (reporting not ready), then exits: Kubernetes Services drop it before it stops.

#![allow(clippy::expect_used)] // test helpers

use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
    s.local_addr().expect("addr").port()
}

/// An A query for nas.drain.test; true when an answer comes back.
fn answers(port: u16) -> bool {
    let Ok(s) = UdpSocket::bind("127.0.0.1:0") else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
    let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["nas", "drain", "test"] {
        q.push(u8::try_from(label.len()).unwrap_or(0));
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    if s.send_to(&q, ("127.0.0.1", port)).is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    matches!(s.recv(&mut buf), Ok(n) if n > 12 && buf[0..2] == [0x12, 0x34] && buf[7] == 1)
}

#[test]
fn ops_007_drain_delay_keeps_answering_after_sigterm() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (dns, api, metrics) = (free_port(), free_port(), free_port());
    let cfg = tmp.path().join("t.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"[node]
data_dir = "{}"
drain_delay_secs = 2

[[listen]]
proto = "udp"
addr = "127.0.0.1:{dns}"

[[upstream]]
name = "nowhere"
url = "udp://127.0.0.1:9"

[[upstream_group]]
name = "default"
members = ["nowhere"]

[[record]]
name = "nas.drain.test"
type = "A"
value = "192.168.1.10"

[telemetry.metrics]
listen = "127.0.0.1:{metrics}"

[api]
listen = "127.0.0.1:{api}"
"#,
            tmp.path().join("data").display()
        ),
    )
    .expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["run", "-c"])
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start");
    let start = Instant::now();
    while !answers(dns) {
        assert!(start.elapsed() < Duration::from_secs(30), "never answered");
        std::thread::sleep(Duration::from_millis(100));
    }
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill");
    assert!(status.success());
    let sent = Instant::now();
    std::thread::sleep(Duration::from_millis(700));
    assert!(answers(dns), "still answering during the drain delay");
    let code = child.wait().expect("wait");
    let took = sent.elapsed();
    assert!(code.success(), "clean exit: {code:?}");
    assert!(
        took >= Duration::from_secs(2) && took < Duration::from_secs(10),
        "exited after the delay, not long after: {took:?}"
    );
}
