//! Plugin upstreams (REQ: UPS-011, `spec/04` §6; T7.16): any program that speaks DNS over a
//! stream (RFC 7766 framing: a 2-byte length, then the message) on a Unix socket.
//! - `unix:///run/my-plugin.sock`: TelltaleDNS connects to a socket someone else serves.
//! - `exec:///usr/local/bin/my-plugin` (with `args`): TelltaleDNS starts the program, tells it
//!   where to listen (`TELLTALE_PLUGIN_SOCKET`), restarts it with backoff when it exits, and
//!   logs its output. It's stopped when the upstream goes away (a reload or shutdown).
//!
//! A plugin can't take the resolver down: it's another process, every exchange has the
//! upstream's timeout, and a dead plugin is just a failing upstream (health, breaker, the
//! group's other members).

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::{info, warn};

/// Supervises one plugin process; dropping it stops the process.
#[derive(Debug)]
pub(crate) struct Supervisor {
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort(); // the child is killed with its handle (kill_on_drop)
        }
    }
}

/// Starts `program args` with `TELLTALE_PLUGIN_SOCKET=socket`, restarting it when it exits
/// (1 s, doubling to 60 s; back to 1 s after a minute of running). Without a Tokio runtime
/// (config checks), nothing is started.
pub(crate) fn supervise(
    name: &str,
    program: PathBuf,
    args: Vec<String>,
    socket: PathBuf,
) -> Supervisor {
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        return Supervisor { task: None };
    };
    let name = name.to_owned();
    let task = rt.spawn(async move {
        let mut backoff = Duration::from_secs(1);
        loop {
            if let Some(dir) = socket.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::remove_file(&socket);
            let started = Instant::now();
            let child = Command::new(&program)
                .args(&args)
                .env("TELLTALE_PLUGIN_SOCKET", &socket)
                .env("TELLTALE_UPSTREAM", &name)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn();
            match child {
                Ok(mut child) => {
                    info!(upstream = %name, program = %program.display(), "plugin started");
                    for (out, err) in [(child.stdout.take().map(Either::Out), false), (child.stderr.take().map(Either::Err), true)] {
                        if let Some(o) = out {
                            let n = name.clone();
                            tokio::spawn(async move { o.forward(&n, err).await });
                        }
                    }
                    let status = child.wait().await;
                    warn!(upstream = %name, ?status, "plugin exited; restarting in {}s", backoff.as_secs());
                }
                Err(e) => warn!(upstream = %name, program = %program.display(), error = %e, "plugin can't start"),
            }
            if started.elapsed() > Duration::from_secs(60) {
                backoff = Duration::from_secs(1);
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    });
    Supervisor { task: Some(task) }
}

enum Either {
    Out(tokio::process::ChildStdout),
    Err(tokio::process::ChildStderr),
}

impl Either {
    /// The plugin's output, line by line, in our log.
    async fn forward(self, name: &str, err: bool) {
        let mut lines: Box<dyn tokio::io::AsyncBufRead + Unpin + Send> = match self {
            Self::Out(o) => Box::new(BufReader::new(o)),
            Self::Err(e) => Box::new(BufReader::new(e)),
        };
        let mut line = String::new();
        loop {
            line.clear();
            match lines.read_line(&mut line).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    let l = line.trim_end();
                    if err {
                        warn!(upstream = %name, "plugin: {l}");
                    } else {
                        info!(upstream = %name, "plugin: {l}");
                    }
                }
            }
        }
    }
}
