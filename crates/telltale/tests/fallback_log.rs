//! REQ: API-010, CLU-003 (ADR-191; GitHub issue #113) — a node whose devices made in the UI don't
//! apply on its config files logs the reasons, then the fallback's line, which names the stored
//! device the reasons point at (the row to delete) with the request that removes it, and not a
//! stored device that has nothing to do with it. The real binary runs in a process of its own, so
//! what it logs is all its own (a test subscriber in the unit tests' shared process can miss
//! events while other tests log).

#![allow(clippy::expect_used)] // test helpers

use std::io::{BufRead, BufReader};
use std::net::{TcpListener, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// A UDP port nothing uses now (for DNS).
fn free_udp_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
    s.local_addr().expect("addr").port()
}

/// Two TCP ports nothing listens on now (for the API and the metrics), both held until both are
/// chosen, so they differ.
fn free_tcp_ports() -> (u16, u16) {
    let a = TcpListener::bind("127.0.0.1:0").expect("bind");
    let b = TcpListener::bind("127.0.0.1:0").expect("bind");
    (
        a.local_addr().expect("addr").port(),
        b.local_addr().expect("addr").port(),
    )
}

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn api_010_a_node_logs_the_stored_devices_its_fallback_sets_aside() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    // Made in the UI earlier: `nas-copy` has the address of the files' `nas`, so the merge doesn't
    // validate; `tablet` has nothing to do with it.
    {
        let state =
            telltale_store::state::State::open(&data.join("state.db")).expect("open state.db");
        for (name, key) in [("nas-copy", "192.168.1.10"), ("tablet", "id:tablet")] {
            let body = format!(r#"{{"name":"{name}","match":["{key}"],"groups":["default"]}}"#);
            state
                .put_managed("client", name, &body, None, None, 0, "earlier")
                .expect("store a device");
        }
    }
    let dns = free_udp_port();
    let (api, metrics) = free_tcp_ports();
    let cfg = tmp.path().join("t.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"[node]
data_dir = "{}"

[[listen]]
proto = "udp"
addr = "127.0.0.1:{dns}"

[[upstream]]
name = "nowhere"
url = "udp://127.0.0.1:9"

[[upstream_group]]
name = "default"
members = ["nowhere"]

[[client]]
name = "nas"
match = ["192.168.1.10"]

[telemetry.metrics]
listen = "127.0.0.1:{metrics}"

[api]
listen = "127.0.0.1:{api}"
"#,
            data.display()
        ),
    )
    .expect("write config");
    let mut node = Kill(
        Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args(["run", "-c"])
            .arg(&cfg)
            // The node's own log level, whatever the shell running the tests sets.
            .env_remove("TELLTALE_LOG")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the node"),
    );
    let stderr = node.0.stderr.take().expect("its stderr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut before = Vec::new();
    let fallback = loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(l) if l.contains("ignoring config made in the UI") => break Some(l),
            Ok(l) => before.push(l),
            Err(_) => break None,
        }
    };
    let Some(fallback) = fallback else {
        panic!("no fallback line within 60 s; the node logged: {before:#?}");
    };
    assert!(
        fallback.contains("`nas-copy`")
            && fallback.contains("DELETE /api/v1/clients/")
            && !fallback.contains("tablet"),
        "{fallback}"
    );
    assert!(
        before
            .iter()
            .any(|l| l.contains("config made in the UI/API") && l.contains("`192.168.1.10`")),
        "the reasons come before it: {before:#?}"
    );
}
