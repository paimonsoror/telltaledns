//! `telltale self-update` for native installs (REQ: OPS-004, `spec/08` §4, ADR-038).
//!
//! A release publishes one static binary per architecture, `SHA256SUMS`, and
//! `SHA256SUMS.minisig` (minisign, Ed25519). The update downloads the checksums and their
//! signature, verifies the signature against the release key built into this binary, compares
//! this binary's SHA-256 with the release's, and only if they differ downloads the new
//! binary, checks its SHA-256, test-runs it (`--version`), and swaps it in with an atomic
//! rename (the previous binary stays next to it as `telltale.old`). Containers are refused:
//! they update by pulling a new image.
//!
//! REQ: OPS-014 (ADR-182) — `--to <version>` installs that version only: a release from its own
//! release page, or an edge build while it is the newest on the edge channel (edge binaries are
//! replaced on every build). The release's signed `releases.json` must name that version and
//! list the same SHA-256 as `SHA256SUMS`, so a version is never installed under another's name.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use telltale_filter::fetch::{Client, Conditional, Response, SystemResolver};

/// The release signing key (`deploy/release/telltale-release.pub`).
pub(crate) const RELEASE_KEY: &str = "RWQSVukPYI4mZximvuqnLSiH56cyTwz6uEWQEFyWDhqvpBHC8DdyYK5T";
const RELEASES: &str = "https://github.com/paimonsoror/telltaledns/releases";
const MAX_SUMS: u64 = 64 * 1024;
const MAX_BINARY: u64 = 128 * 1024 * 1024;
/// REQ: OPS-014 (ADR-182) — one deadline for all the downloads of an update (the checksums,
/// their signature, the signed index and the binary): past it nothing is installed. Part of the
/// root update service's time budget (`node_update::run_budget_secs`).
pub(crate) const FETCH_DEADLINE: Duration = Duration::from_secs(480);
/// How long the new binary's test run (`--version`) may take before it is killed and refused.
pub(crate) const VERSION_WAIT: Duration = Duration::from_secs(10);
/// How many times in all a program that is "text file busy" (ETXTBSY) is started, and how long the
/// pause between the tries is. Nothing else is tried again.
const EXEC_TRIES: u32 = 5;
const EXEC_PAUSE: Duration = Duration::from_millis(100);

/// REQ: OPS-004, OPS-014 — the most the pauses between those tries add to `runs` bounded runs
/// (each one is started, tried again while "text file busy", and only then waited for), in whole
/// seconds, rounded up. Part of the root update service's time budget
/// (`node_update::run_budget_secs`), so raising [`EXEC_TRIES`] or [`EXEC_PAUSE`] can't quietly use
/// up the room the unit's `TimeoutStartSec=` leaves.
#[cfg(test)]
pub(crate) const fn exec_retry_secs(runs: u32) -> u64 {
    let pauses = EXEC_PAUSE
        .saturating_mul(EXEC_TRIES.saturating_sub(1))
        .saturating_mul(runs);
    if pauses.subsec_nanos() == 0 {
        pauses.as_secs()
    } else {
        pauses.as_secs() + 1
    }
}
/// How long `systemctl restart telltale` is waited for: twice the node unit's `TimeoutStopSec=30`
/// (a graceful drain, then systemd's SIGKILL), so the old process is gone by then. The restart
/// itself goes on if it takes longer, and neither that nor a non-zero exit fails the build: the
/// health check after it decides (`node_update::restart_and_check`).
pub(crate) const RESTART_WAIT: Duration = Duration::from_secs(60);

/// Which releases to follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Channel {
    /// The newest tagged release.
    Stable,
    /// Built from every commit to main.
    Edge,
}

#[derive(Debug)]
pub(crate) struct Options {
    pub(crate) channel: Channel,
    /// Only report whether an update is available.
    pub(crate) check: bool,
    /// Run `systemctl restart telltale` after updating.
    pub(crate) restart: bool,
    /// REQ: OPS-014 — install this version only (its channel must be `channel`).
    pub(crate) to: Option<String>,
    /// Where to download from (tests, mirrors); default: GitHub releases for the channel.
    pub(crate) base_url: Option<String>,
    /// The binary to replace (default: this one).
    pub(crate) exe: Option<PathBuf>,
}

/// What happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    UpToDate,
    Available {
        sha256: String,
    },
    Updated {
        previous: PathBuf,
    },
    /// REQ: OPS-014 (ADR-182) — the edge build asked for (`--to`) isn't served any more: the edge
    /// channel now serves `serves` (commit `commit`). Nothing was installed.
    Unavailable {
        serves: String,
        commit: String,
    },
}

/// This build's release asset name.
pub(crate) fn asset_name() -> Option<&'static str> {
    if cfg!(target_arch = "x86_64") {
        Some("telltale-x86_64-linux")
    } else if cfg!(target_arch = "aarch64") {
        Some("telltale-aarch64-linux")
    } else if cfg!(target_arch = "arm") {
        Some("telltale-armv7-linux")
    } else {
        None
    }
}

fn base_url(o: &Options) -> String {
    o.base_url
        .clone()
        .unwrap_or_else(|| match (o.channel, &o.to) {
            (Channel::Stable, Some(v)) => format!("{RELEASES}/download/v{v}"),
            (Channel::Stable, None) => format!("{RELEASES}/latest/download"),
            (Channel::Edge, _) => format!("{RELEASES}/download/edge"),
        })
}

/// REQ: OPS-014 — the signed index of the release at `base` must name `to` and list `want` for
/// `asset`. `Ok(Some((serves, commit)))`: `to` is an edge build the edge channel has moved past.
fn check_pinned(
    key: &str,
    index: &[u8],
    sig: &[u8],
    to: &str,
    asset: &str,
    want: &str,
) -> Result<Option<(String, String)>, String> {
    let ix = crate::updates::verified(key, index, sig)?;
    // REQ: OPS-014 (ADR-182) — the index is of the version's own channel (an edge build's is the
    // edge channel's, a release's the stable one's): a request never moves a stable node to edge.
    let channel = if telltale_api::update_api::is_edge(to) {
        "edge"
    } else {
        "stable"
    };
    if ix.channel != channel {
        return Err(format!(
            "the signed index is of the {} channel, not {channel} as {to} is: not installed",
            ix.channel
        ));
    }
    if ix.version != to {
        if telltale_api::update_api::is_edge(to) {
            return Ok(Some((ix.version, ix.commit)));
        }
        return Err(format!(
            "the index of release v{to} names {}: not trusted",
            ix.version
        ));
    }
    match ix.assets.values().find(|a| a.name == asset) {
        None => Err(format!("{to} has no {asset}")),
        Some(a) if !a.sha256.eq_ignore_ascii_case(want) => Err(format!(
            "{asset}: the release index and SHA256SUMS disagree: not installed"
        )),
        Some(_) => Ok(None),
    }
}

/// REQ: OPS-014 (ADR-182) — what [`Outcome::Unavailable`] says.
pub(crate) fn unavailable_text(to: &str, serves: &str, commit: &str) -> String {
    format!(
        "the edge channel now serves {serves} (commit {commit}), not {to}: only the newest edge build can be downloaded. Ask for {serves} instead, or wait for the release"
    )
}

fn in_container() -> bool {
    Path::new("/.dockerenv").exists()
        || Path::new("/run/.containerenv").exists()
        || std::env::var_os("KUBERNETES_SERVICE_HOST").is_some()
}

/// Runs the update with the built-in release key.
pub(crate) fn run(o: &Options) -> Result<Outcome, String> {
    if o.exe.is_none() && in_container() {
        return Err("running in a container: update by pulling a newer image \
                    (ghcr.io/paimonsoror/telltale) instead"
            .into());
    }
    let asset = asset_name().ok_or("no release binaries for this architecture")?;
    let exe = match &o.exe {
        Some(p) => p.clone(),
        None => std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|e| format!("cannot locate this binary: {e}"))?,
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let outcome = rt.block_on(update(o, &exe, asset, RELEASE_KEY))?;
    if o.restart && matches!(outcome, Outcome::Updated { .. }) {
        restart_node().map_err(|e| format!("updated, but {e}"))?;
    }
    Ok(outcome)
}

/// REQ: OPS-014 (ADR-182) — `systemctl`, by its absolute path, never through `PATH` (the root
/// update service may write `/usr/local/bin`, early in systemd's default `PATH`): `/usr/bin`, or
/// `/bin` on a system whose `/usr` isn't merged.
pub(crate) fn systemctl() -> &'static str {
    if Path::new("/usr/bin/systemctl").exists() {
        "/usr/bin/systemctl"
    } else {
        "/bin/systemctl"
    }
}

/// REQ: OPS-004, OPS-014 — "text file busy" (`ETXTBSY`): the kernel won't run a file some process
/// still has open for writing. A binary written a moment ago can be one: a process that forks in
/// parallel holds a copy of the descriptor until it execs itself.
fn text_file_busy(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::ExecutableFileBusy || e.raw_os_error() == Some(26)
}

/// Runs `exec` and, only when it fails with "text file busy", again, up to `tries` times in all and
/// `pause` apart. Any other error, and the last one when it stays busy, is returned as it is.
fn retry_text_busy<T>(
    tries: u32,
    pause: Duration,
    mut exec: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    let mut attempt = 1;
    loop {
        match exec() {
            Err(e) if text_file_busy(&e) && attempt < tries => {
                attempt += 1;
                std::thread::sleep(pause);
            }
            done => return done,
        }
    }
}

/// REQ: OPS-014 (ADR-182) — runs `cmd` (its output discarded) and waits for it at most `limit`:
/// past that it is killed (for the restart, only `systemctl` itself: the restart goes on). A program
/// that is "text file busy" at the start is started again (see [`retry_text_busy`]).
pub(crate) fn run_bounded(
    cmd: &mut std::process::Command,
    limit: Duration,
) -> Result<std::process::ExitStatus, String> {
    run_bounded_via(cmd, limit, std::process::Command::spawn)
}

/// [`run_bounded`], with the way the program is started given (a test closes a file between two
/// tries, so the second one finds it free, with no clock to race).
fn run_bounded_via(
    cmd: &mut std::process::Command,
    limit: Duration,
    mut start: impl FnMut(&mut std::process::Command) -> std::io::Result<std::process::Child>,
) -> Result<std::process::ExitStatus, String> {
    let cmd = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child =
        retry_text_busy(EXEC_TRIES, EXEC_PAUSE, || start(cmd)).map_err(|e| e.to_string())?;
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if started.elapsed() < limit => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("didn't finish within {} s", limit.as_secs()));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// `systemctl restart telltale`, waited for at most [`RESTART_WAIT`].
pub(crate) fn restart_node() -> Result<(), String> {
    let status = run_bounded(
        std::process::Command::new(systemctl())
            .args(["restart", "telltale"])
            .env_clear(),
        RESTART_WAIT,
    )
    .map_err(|e| format!("`systemctl restart telltale`: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`systemctl restart telltale` exited with {status}"))
    }
}

/// Verifies and installs the release binary for `asset` over `exe`.
pub(crate) async fn update(
    o: &Options,
    exe: &Path,
    asset: &str,
    key: &str,
) -> Result<Outcome, String> {
    update_within(o, exe, asset, key, FETCH_DEADLINE).await
}

/// [`update`], with every download done within `fetch_for` of the start (nothing is installed
/// past it: the old binary stays).
pub(crate) async fn update_within(
    o: &Options,
    exe: &Path,
    asset: &str,
    key: &str,
    fetch_for: Duration,
) -> Result<Outcome, String> {
    let deadline = tokio::time::Instant::now() + fetch_for;
    let base = base_url(o);
    let client = Client::new(Arc::new(SystemResolver), &[])?;
    let get = |url: String, max: u64| {
        let client = &client;
        async move { fetch(client, &url, max, deadline, fetch_for).await }
    };
    let sums = get(format!("{base}/SHA256SUMS"), MAX_SUMS).await?;
    let sig = get(format!("{base}/SHA256SUMS.minisig"), MAX_SUMS).await?;
    verify_signature(key, &sums, &sig)?;
    let want = expected_sha256(&sums, asset)?;
    if let Some(to) = &o.to {
        let index = get(format!("{base}/releases.json"), MAX_SUMS).await?;
        let isig = get(format!("{base}/releases.json.minisig"), MAX_SUMS).await?;
        if let Some((serves, commit)) = check_pinned(key, &index, &isig, to, asset, &want)? {
            return Ok(Outcome::Unavailable { serves, commit });
        }
    }
    let current = std::fs::read(exe).map_err(|e| format!("cannot read {}: {e}", exe.display()))?;
    if sha256_hex(&current) == want {
        return Ok(Outcome::UpToDate);
    }
    if o.check {
        return Ok(Outcome::Available { sha256: want });
    }
    let new = get(format!("{base}/{asset}"), MAX_BINARY).await?;
    if sha256_hex(&new) != want {
        return Err(format!("{asset}: checksum mismatch, not installed"));
    }
    let previous = install(exe, &new)?;
    Ok(Outcome::Updated { previous })
}

async fn fetch(
    client: &Client,
    url: &str,
    max: u64,
    deadline: tokio::time::Instant,
    fetch_for: Duration,
) -> Result<Vec<u8>, String> {
    match tokio::time::timeout_at(deadline, client.get(url, &Conditional::default(), max)).await {
        Err(_) => Err(format!(
            "{url}: the downloads didn't finish within {} s: nothing installed",
            fetch_for.as_secs()
        )),
        Ok(Err(e)) => Err(format!("{url}: {}", e.message)),
        Ok(Ok(Response::Body { data, .. })) => Ok(data),
        Ok(Ok(Response::NotModified)) => Err(format!("{url}: unexpected 304")),
    }
}

/// Checks `sig` (a `.minisig` file) over `data` with the base64 public key `key`.
pub(crate) fn verify_signature(key: &str, data: &[u8], sig: &[u8]) -> Result<(), String> {
    let pk = minisign_verify::PublicKey::from_base64(key).map_err(|e| e.to_string())?;
    let text = std::str::from_utf8(sig).map_err(|_| "signature file is not text")?;
    let sig =
        minisign_verify::Signature::decode(text).map_err(|e| format!("bad signature file: {e}"))?;
    pk.verify(data, &sig, false)
        .map_err(|_| "the signature does not verify with the release key: not trusted".into())
}

/// The SHA-256 listed for `asset` (`sha256sum` format: `<hex>  <name>` or `<hex> *<name>`).
pub(crate) fn expected_sha256(sums: &[u8], asset: &str) -> Result<String, String> {
    let text = std::str::from_utf8(sums).map_err(|_| "SHA256SUMS is not text")?;
    text.lines()
        .filter_map(|l| l.split_once(char::is_whitespace))
        .find(|(_, name)| name.trim().trim_start_matches('*') == asset)
        .map(|(hex, _)| hex.to_ascii_lowercase())
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| format!("SHA256SUMS has no entry for {asset}"))
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    d.as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Writes `new` beside `exe`, test-runs it, keeps the current binary as `<exe>.old`, and
/// renames the new one over `exe` (atomic on one filesystem). Returns the backup's path.
fn install(exe: &Path, new: &[u8]) -> Result<PathBuf, String> {
    let dir = exe.parent().ok_or("binary has no parent directory")?;
    let name = exe
        .file_name()
        .ok_or("binary has no file name")?
        .to_string_lossy();
    let staged = dir.join(format!(".{name}.new"));
    let backup = dir.join(format!("{name}.old"));
    let err = |what: &str, e: std::io::Error| format!("{what} in {}: {e}", dir.display());
    {
        let mut f = std::fs::File::create(&staged).map_err(|e| err("cannot write", e))?;
        f.write_all(new).map_err(|e| err("cannot write", e))?;
        f.sync_all().map_err(|e| err("cannot sync", e))?;
    }
    set_executable(&staged).map_err(|e| err("cannot chmod", e))?;
    // A binary that can't even print its version (wrong arch, truncated), or hangs at it, never
    // goes live.
    let ok = run_bounded(
        std::process::Command::new(&staged).arg("--version"),
        VERSION_WAIT,
    )
    .is_ok_and(|s| s.success());
    if !ok {
        let _ = std::fs::remove_file(&staged);
        return Err("the downloaded binary doesn't run on this system: not installed".into());
    }
    let _ = std::fs::remove_file(&backup);
    std::fs::hard_link(exe, &backup)
        .or_else(|_| std::fs::copy(exe, &backup).map(|_| ()))
        .map_err(|e| err("cannot keep the previous binary", e))?;
    std::fs::rename(&staged, exe).map_err(|e| err("cannot replace the binary", e))?;
    Ok(backup)
}

#[cfg(unix)]
fn set_executable(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755))
}

#[cfg(not(unix))]
fn set_executable(_: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
#[path = "selfupdate_tests.rs"]
mod tests;
