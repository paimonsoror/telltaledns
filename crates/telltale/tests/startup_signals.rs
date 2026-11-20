//! REQ: OPS-007, OPS-009, CLU-009 — a signal that arrives while the node is still starting (DNS
//! already answers; the API, the state database and the rest are still being set up) is acted on
//! once the node is up: SIGTERM drains and exits cleanly, SIGHUP reloads. Before, the signal's
//! default action ended the process (review round 3, F2). A stop during a cluster join that can't
//! finish (a loopback port where nothing listens) ends the join and the node at once, with exit
//! 0, rather than after the join's two minutes (review round 4, N1).
//!
//! The join holds start-up open for two minutes, so the tests that send a signal during it are
//! deterministic: they fail on a build without the fix every time. The drain and the reload
//! themselves can only be seen once start-up ends, and a stop during a join doesn't drain (by
//! design), so those two still send their signal at DNS's first answer, with a bootstrap
//! administrator (a password hash) to make the start-up a little longer: guards, not certain to
//! catch a regression on every run. The tests take turns (one node at a time), a node that exits
//! early fails its test at once with its exit status, and every failed check prints the node's
//! log.

#![allow(clippy::expect_used)] // test helpers

use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// One node at a time: the tests take turns.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn turn() -> MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A UDP port nothing uses now (for DNS).
fn free_udp_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
    s.local_addr().expect("addr").port()
}

/// A TCP port nothing listens on now (for the API, the metrics, a join URL that can't answer).
fn free_tcp_port() -> u16 {
    let s = TcpListener::bind("127.0.0.1:0").expect("bind");
    s.local_addr().expect("addr").port()
}

/// An A query for nas.signals.test; true when an answer comes back within 300 ms.
fn answers(port: u16) -> bool {
    let Ok(s) = UdpSocket::bind("127.0.0.1:0") else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
    let mut q = vec![0x43, 0x21, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["nas", "signals", "test"] {
        q.push(u8::try_from(label.len()).unwrap_or(0));
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    if s.send_to(&q, ("127.0.0.1", port)).is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    matches!(s.recv(&mut buf), Ok(n) if n > 12 && buf[0..2] == [0x43, 0x21] && buf[7] == 1)
}

/// [`answers`], tried again until one comes back or `bound` has passed.
fn answers_within(port: u16, bound: Duration) -> bool {
    let started = Instant::now();
    loop {
        if answers(port) {
            return true;
        }
        if started.elapsed() >= bound {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A running node, its DNS port and its log.
struct Node {
    child: Child,
    dns: u16,
    log: PathBuf,
}

impl Node {
    /// The last 20 lines of the node's log, newest first (for a failed check's message).
    fn tail(&self) -> String {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        let tail: Vec<&str> = text.lines().rev().take(20).collect();
        format!("the node's log, last lines first:\n{}", tail.join("\n"))
    }

    fn logged(&self, what: &str) -> bool {
        std::fs::read_to_string(&self.log).is_ok_and(|t| t.contains(what))
    }

    /// Waits (at most `bound`) until the log holds `what`.
    fn wait_logged(&self, what: &str, bound: Duration) -> bool {
        let started = Instant::now();
        while !self.logged(what) {
            if started.elapsed() >= bound {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        true
    }

    fn signal(&self, sig: &str) {
        let status = Command::new("kill")
            .args([sig, &self.child.id().to_string()])
            .status()
            .expect("kill");
        assert!(status.success(), "kill {sig}");
    }

    /// The exit status once the node has exited (at most `bound`); `None` while it runs.
    fn wait_exit(&mut self, bound: Duration) -> Option<ExitStatus> {
        let started = Instant::now();
        loop {
            if let Some(s) = self.child.try_wait().expect("try_wait") {
                return Some(s);
            }
            if started.elapsed() >= bound {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts a node in `dir` (with `extra` appended to its configuration) and returns it once DNS
/// first answers. A query that isn't answered waits its 300 ms, so until the node is up it is
/// asked about every 300 ms, and once it is up the first answer comes back at once: the signal
/// that follows lands in the start-up.
fn start(dir: &Path, extra: &str) -> Node {
    let (dns, api, metrics) = (free_udp_port(), free_tcp_port(), free_tcp_port());
    let cfg = dir.join("t.toml");
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
name = "nas.signals.test"
type = "A"
value = "192.168.1.10"

[telemetry.metrics]
listen = "127.0.0.1:{metrics}"

[api]
listen = "127.0.0.1:{api}"
{extra}"#,
            dir.join("data").display()
        ),
    )
    .expect("write config");
    let log = dir.join("node.log");
    let child = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["run", "-c"])
        .arg(&cfg)
        .env("TELLTALE_BOOTSTRAP_ADMIN_USER", "admin")
        .env(
            "TELLTALE_BOOTSTRAP_ADMIN_PASSWORD",
            "a start-up signal test password",
        )
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).expect("log file"))
        .spawn()
        .expect("start");
    let mut node = Node { child, dns, log };
    let started = Instant::now();
    while !answers(node.dns) {
        let exited = node.child.try_wait().expect("try_wait");
        assert!(
            exited.is_none(),
            "the node exited during start-up: {exited:?}; {}",
            node.tail()
        );
        assert!(
            started.elapsed() <= Duration::from_secs(60),
            "never answered; {}",
            node.tail()
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    node
}

/// The `[cluster]` lines of a node that joins at a loopback port where nothing listens (the
/// join retries for two minutes), with its secret file in `dir`.
fn joining(dir: &Path) -> String {
    let secret = dir.join("join-secret");
    std::fs::write(&secret, "a join secret nobody checks").expect("secret");
    format!(
        "\n[cluster]\njoin_url = \"https://127.0.0.1:{}\"\nbootstrap_secret_file = \"{}\"\n",
        free_tcp_port(),
        secret.display()
    )
}

/// [`start`] with a join that can't finish, once the log says the join is retrying.
fn start_joining(dir: &Path) -> Node {
    let node = start(dir, &joining(dir));
    assert!(
        node.wait_logged("joining failed, retrying", Duration::from_secs(30)),
        "not joining; {}",
        node.tail()
    );
    node
}

#[test]
fn ops_007_a_stop_during_start_up_drains_and_exits_cleanly() {
    let _turn = turn();
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut node = start(tmp.path(), "");
    node.signal("-TERM");
    let sent = Instant::now();
    std::thread::sleep(Duration::from_millis(700));
    assert!(
        answers_within(node.dns, Duration::from_millis(1000)),
        "a stop during start-up ended the node instead of draining it; {}",
        node.tail()
    );
    let code = node.wait_exit(Duration::from_secs(30));
    assert!(
        code.is_some_and(|c| c.success()),
        "clean exit: {code:?}; {}",
        node.tail()
    );
    assert!(
        sent.elapsed() >= Duration::from_secs(2),
        "exited before the drain delay: {:?}; {}",
        sent.elapsed(),
        node.tail()
    );
}

#[test]
fn ops_009_a_reload_during_start_up_reloads() {
    let _turn = turn();
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut node = start(tmp.path(), "");
    node.signal("-HUP");
    assert!(
        node.wait_logged("configuration reloaded", Duration::from_secs(20)),
        "no reload; {}",
        node.tail()
    );
    assert!(node.logged("reloading configuration"), "{}", node.tail());
    assert!(
        node.wait_exit(Duration::from_millis(100)).is_none(),
        "a reload during start-up ended the node; {}",
        node.tail()
    );
    assert!(
        answers_within(node.dns, Duration::from_secs(2)),
        "answers after the reload; {}",
        node.tail()
    );
    node.signal("-TERM");
    let code = node.wait_exit(Duration::from_secs(30));
    assert!(
        code.is_some_and(|c| c.success()),
        "clean exit: {code:?}; {}",
        node.tail()
    );
}

/// A node joining a cluster whose join URL can't answer, stopped by `sig` during the join.
fn stop_during_a_join(sig: &str) {
    let _turn = turn();
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut node = start_joining(tmp.path());
    node.signal(sig);
    let sent = Instant::now();
    let code = node.wait_exit(Duration::from_secs(10));
    assert!(
        code.is_some_and(|c| c.success()),
        "a stop during the join didn't end the node at once with exit 0: {code:?} after {:?}; {}",
        sent.elapsed(),
        node.tail()
    );
    assert!(
        node.logged("during the cluster join"),
        "the log says why; {}",
        node.tail()
    );
}

#[test]
fn ops_007_a_stop_during_a_cluster_join_ends_the_node() {
    stop_during_a_join("-TERM");
}

#[test]
fn ops_007_ctrl_c_during_a_cluster_join_ends_the_node() {
    stop_during_a_join("-INT");
}

/// REQ: OPS-009 (review round 3, F2) — held open by the join: a SIGHUP during start-up doesn't
/// end the node (before, its default action did); it is kept for the main loop, which reloads once
/// the join ends. The node stays up and answering, and a stop still ends it at once.
#[test]
fn ops_009_a_reload_during_a_cluster_join_keeps_the_node() {
    let _turn = turn();
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut node = start_joining(tmp.path());
    node.signal("-HUP");
    assert!(
        node.wait_exit(Duration::from_secs(2)).is_none(),
        "a reload during the join ended the node; {}",
        node.tail()
    );
    assert!(
        answers_within(node.dns, Duration::from_secs(2)),
        "answers during the join; {}",
        node.tail()
    );
    node.signal("-TERM");
    let code = node.wait_exit(Duration::from_secs(10));
    assert!(
        code.is_some_and(|c| c.success()),
        "a stop still ends it: {code:?}; {}",
        node.tail()
    );
}
