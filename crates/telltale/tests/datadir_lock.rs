//! REQ: CLU-008 (T6.14 AC) — a second process on the same data directory exits with a clear
//! error, and the first keeps serving.

#![allow(clippy::expect_used)] // test helpers

use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
    s.local_addr().expect("addr").port()
}

fn config(dir: &std::path::Path, data: &std::path::Path, name: &str) -> std::path::PathBuf {
    let (dns, api, metrics) = (free_port(), free_port(), free_port());
    let path = dir.join(format!("{name}.toml"));
    std::fs::write(
        &path,
        format!(
            r#"[node]
data_dir = "{}"
name = "{name}"

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
name = "nas.lock.test"
type = "A"
value = "192.168.1.10"

[telemetry.metrics]
listen = "127.0.0.1:{metrics}"

[api]
listen = "127.0.0.1:{api}"
"#,
            data.display()
        ),
    )
    .expect("write config");
    std::fs::write(dir.join(format!("{name}.port")), dns.to_string()).expect("port");
    path
}

/// An A query for nas.lock.test; true when an answer comes back.
fn answers(port: u16) -> bool {
    let Ok(s) = UdpSocket::bind("127.0.0.1:0") else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
    let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["nas", "lock", "test"] {
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

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn clu_008_second_process_on_a_data_dir_is_refused() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data");
    let bin = env!("CARGO_BIN_EXE_telltale");

    let first_cfg = config(tmp.path(), &data, "first");
    let first_port: u16 = std::fs::read_to_string(tmp.path().join("first.port"))
        .expect("port")
        .parse()
        .expect("port");
    let first = Kill(
        Command::new(bin)
            .args(["run", "-c"])
            .arg(&first_cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start first"),
    );
    let start = Instant::now();
    while !answers(first_port) {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "first never answered"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    let second_cfg = config(tmp.path(), &data, "second");
    let out = Command::new(bin)
        .args(["run", "-c"])
        .arg(&second_cfg)
        .output()
        .expect("run second");
    assert!(
        !out.status.success(),
        "the second process should exit non-zero"
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        log.contains("another TelltaleDNS process is using this data directory"),
        "{log}"
    );
    assert!(log.contains(&format!("pid {}", first.0.id())), "{log}");

    assert!(answers(first_port), "the first process should still answer");
}
