//! `telltale self-update` for native installs (REQ: OPS-004, `spec/08` §4, ADR-038).
//!
//! A release publishes one static binary per architecture, `SHA256SUMS`, and
//! `SHA256SUMS.minisig` (minisign, Ed25519). The update downloads the checksums and their
//! signature, verifies the signature against the release key built into this binary, compares
//! this binary's SHA-256 with the release's, and only if they differ downloads the new
//! binary, checks its SHA-256, test-runs it (`--version`), and swaps it in with an atomic
//! rename (the previous binary stays next to it as `telltale.old`). Containers are refused:
//! they update by pulling a new image.

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
const TIMEOUT: Duration = Duration::from_secs(300);

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
    /// Where to download from (tests, mirrors); default: GitHub releases for the channel.
    pub(crate) base_url: Option<String>,
    /// The binary to replace (default: this one).
    pub(crate) exe: Option<PathBuf>,
}

/// What happened.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    UpToDate,
    Available { sha256: String },
    Updated { previous: PathBuf },
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
    o.base_url.clone().unwrap_or_else(|| match o.channel {
        Channel::Stable => format!("{RELEASES}/latest/download"),
        Channel::Edge => format!("{RELEASES}/download/edge"),
    })
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
        let status = std::process::Command::new("systemctl")
            .args(["restart", "telltale"])
            .status()
            .map_err(|e| format!("updated, but `systemctl restart telltale` failed: {e}"))?;
        if !status.success() {
            return Err(format!(
                "updated, but `systemctl restart telltale` exited with {status}"
            ));
        }
    }
    Ok(outcome)
}

/// Verifies and installs the release binary for `asset` over `exe`.
pub(crate) async fn update(
    o: &Options,
    exe: &Path,
    asset: &str,
    key: &str,
) -> Result<Outcome, String> {
    let base = base_url(o);
    let client = Client::new(Arc::new(SystemResolver), &[])?;
    let sums = fetch(&client, &format!("{base}/SHA256SUMS"), MAX_SUMS).await?;
    let sig = fetch(&client, &format!("{base}/SHA256SUMS.minisig"), MAX_SUMS).await?;
    verify_signature(key, &sums, &sig)?;
    let want = expected_sha256(&sums, asset)?;
    let current = std::fs::read(exe).map_err(|e| format!("cannot read {}: {e}", exe.display()))?;
    if sha256_hex(&current) == want {
        return Ok(Outcome::UpToDate);
    }
    if o.check {
        return Ok(Outcome::Available { sha256: want });
    }
    let new = fetch(&client, &format!("{base}/{asset}"), MAX_BINARY).await?;
    if sha256_hex(&new) != want {
        return Err(format!("{asset}: checksum mismatch, not installed"));
    }
    let previous = install(exe, &new)?;
    Ok(Outcome::Updated { previous })
}

async fn fetch(client: &Client, url: &str, max: u64) -> Result<Vec<u8>, String> {
    match tokio::time::timeout(TIMEOUT, client.get(url, &Conditional::default(), max)).await {
        Err(_) => Err(format!("{url}: timed out")),
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
    pk.verify(data, &sig, false).map_err(|_| {
        "SHA256SUMS signature does not verify with the release key: not installing".into()
    })
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
    // A binary that can't even print its version (wrong arch, truncated) never goes live.
    let ok = std::process::Command::new(&staged)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
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
