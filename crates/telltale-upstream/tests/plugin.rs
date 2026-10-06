//! REQ: UPS-011 (T7.16) — plugin upstreams: a Unix socket served by someone else, and an
//! `exec://` program TelltaleDNS starts, restarts, and stops.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use telltale_proto::{NameBuf, rcode, rtype, summarize};
use telltale_upstream::{Endpoint, Question, TlsOptions, Upstream, UpstreamOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn question() -> Question {
    Question {
        name: NameBuf::from_presentation("plugin.test").unwrap(),
        qtype: rtype::A,
        qclass: 1,
        dnssec_ok: false,
        checking_disabled: false,
    }
}

/// The answer a plugin gives: the question, and A 10.9.9.9.
fn answer(q: &[u8]) -> Vec<u8> {
    let mut end = 12;
    while q[end] != 0 {
        end += 1 + usize::from(q[end]);
    }
    end += 5;
    let mut r = q[..2].to_vec();
    r.extend([0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    r.extend(&q[12..end]);
    r.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 9, 9, 9]);
    r
}

fn opts() -> UpstreamOptions {
    UpstreamOptions {
        timeout: Duration::from_secs(1),
        ..UpstreamOptions::default()
    }
}

/// A fresh scratch directory for one test.
fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("tt-plugin-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// REQ: UPS-011 — `unix://`: framed DNS over a socket someone else serves.
#[tokio::test]
async fn ups_011_unix_socket_plugin() {
    let dir = scratch("unix");
    let path = dir.join("p.sock");
    let l = tokio::net::UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        loop {
            let (mut c, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 2];
                    if c.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    c.read_exact(&mut q).await.unwrap();
                    let r = answer(&q);
                    let mut out = u16::try_from(r.len()).unwrap().to_be_bytes().to_vec();
                    out.extend(r);
                    c.write_all(&out).await.unwrap();
                }
            });
        }
    });
    let ep = Endpoint::parse(&format!("unix://{}", path.display())).unwrap();
    let up = Upstream::build(1, "sock", ep, &opts(), &TlsOptions::default()).unwrap();
    let resp = up
        .exchange(&question(), Duration::from_secs(1))
        .await
        .unwrap();
    let s = summarize(&resp).unwrap();
    assert_eq!((s.rcode, s.answers), (rcode::NOERROR, 1));
    assert!(resp.ends_with(&[10, 9, 9, 9]));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A plugin in Python: listens where TelltaleDNS says, writes its PID to argv[1].
const PLUGIN: &str = r#"
import os, socket, struct, sys, threading
path = os.environ["TELLTALE_PLUGIN_SOCKET"]
open(sys.argv[1], "w").write(str(os.getpid()))
print("listening on", path, flush=True)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(8)
def serve(c):
    while True:
        h = c.recv(2, socket.MSG_WAITALL)
        if len(h) < 2:
            return
        q = c.recv(struct.unpack("!H", h)[0], socket.MSG_WAITALL)
        end = 12
        while q[end] != 0:
            end += 1 + q[end]
        end += 5
        r = q[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:end] + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x0a\x09\x09\x09"
        c.sendall(struct.pack("!H", len(r)) + r)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
"#;

fn pid(file: &Path) -> Option<i32> {
    std::fs::read_to_string(file).ok()?.trim().parse().ok()
}

/// Running, and not a zombie.
fn alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| !s.contains(") Z "))
}

fn which(prog: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(prog))
            .find(|f| f.is_file())
    })
}

/// REQ: UPS-011 — `exec://`: TelltaleDNS starts the program (it learns its socket from
/// `TELLTALE_PLUGIN_SOCKET`), restarts it when it dies, and stops it with the upstream.
#[tokio::test]
async fn ups_011_exec_plugin_is_supervised() {
    let Some(python) = which("python3") else {
        eprintln!("skipped: no python3");
        return;
    };
    let dir = scratch("exec");
    let script = dir.join("plugin.py");
    std::fs::write(&script, PLUGIN).unwrap();
    let pidfile = dir.join("pid");
    let o = UpstreamOptions {
        plugin_args: vec![script.display().to_string(), pidfile.display().to_string()],
        plugin_dir: Some(dir.join("plugins")),
        ..opts()
    };
    let ep = Endpoint::parse(&format!("exec://{}", python.display())).unwrap();
    let up = Upstream::build(1, "py", ep, &o, &TlsOptions::default()).unwrap();
    let mut first = None;
    for _ in 0..100 {
        if let Ok(r) = up.exchange(&question(), Duration::from_millis(500)).await {
            assert!(r.ends_with(&[10, 9, 9, 9]));
            first = pid(&pidfile);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let first = first.expect("the plugin answered");
    // Kill it: it comes back (after a 1 s backoff) under a new PID.
    std::process::Command::new("kill")
        .arg("-9")
        .arg(first.to_string())
        .status()
        .unwrap();
    let mut second = None;
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Some(p) = pid(&pidfile).filter(|p| *p != first)
            && up
                .exchange(&question(), Duration::from_millis(500))
                .await
                .is_ok()
        {
            second = Some(p);
            break;
        }
    }
    let second = second.expect("the plugin was restarted");
    // Dropping the upstream stops the process.
    drop(up);
    let mut gone = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if !alive(second) {
            gone = true;
            break;
        }
    }
    assert!(gone, "the plugin stops with its upstream");
    let _ = std::fs::remove_dir_all(&dir);
}
