//! Git as the cluster's config source (REQ: CLU-003, OPS-005; T5.12, ADR-049).
//!
//! On the primary, when `[cluster.git]` is set, this polls the repository (or reacts to the
//! webhook) and keeps `<data_dir>/cluster/git-shared.toml`: the shared settings at the last
//! commit that passed every check. The primary's effective configuration uses that file, and
//! replication publishes it to every node, with the commit as provenance.
//!
//! A commit is used only if:
//! - it descends from the one in use (unless `allow_rewind`);
//! - it's signed by an allowed key (with `require_signed`);
//! - its file loads and validates merged with this node's own settings.
//!
//! Otherwise the cluster stays on the last good commit, and the refusal shows on the Cluster
//! page, in the event log and metrics, and as an alert. With the repository unreachable,
//! nothing changes: every node keeps serving (CLU-004).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use telltale_cluster::net::Cluster;
use telltale_config::{Config, GitSourceConfig, Loader};
use tokio::sync::{Notify, watch};
use tracing::{info, warn};

const STATUS: &str = "git.json";
const SHARED: &str = "git-shared.toml";
const PIN: &str = "git-pin.json";
/// How long one poll may take.
const DEADLINE: Duration = Duration::from_secs(60);

fn cluster_dir(cfg: &Config) -> PathBuf {
    telltale_cluster::node::dir_of(Path::new(cfg.node.data_dir.as_str()))
}

/// What the Git source last did, as kept on disk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Status {
    /// The commit in use (its file passed every check).
    pub(crate) commit: Option<String>,
    pub(crate) author: String,
    pub(crate) time: i64,
    pub(crate) subject: String,
    pub(crate) signed_by: Option<String>,
    /// When the ref was last checked (Unix ms).
    pub(crate) checked_ms: u64,
    /// The last poll's failure, if it failed.
    pub(crate) error: Option<String>,
    /// The repository answered, but the newest commit isn't acceptable.
    pub(crate) refused: bool,
    /// The commit that was refused.
    pub(crate) refused_commit: Option<String>,
}

pub(crate) fn status(cfg: &Config) -> Option<Status> {
    let b = std::fs::read(cluster_dir(cfg).join(STATUS)).ok()?;
    serde_json::from_slice(&b).ok()
}

fn save_status(cfg: &Config, s: &Status) {
    let path = cluster_dir(cfg).join(STATUS);
    if let Ok(b) = serde_json::to_vec_pretty(s)
        && let Err(e) = write_atomic(&path, &b)
    {
        warn!("cluster: can't store the Git source status: {e}");
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// The shared settings from the commit in use, as the JSON `with_shared` takes.
pub(crate) fn shared(cfg: &Config) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(cluster_dir(cfg).join(SHARED)).ok()?;
    parse(&text).ok()
}

/// Loads a commit's file as a TelltaleDNS configuration and returns its shared part.
fn parse(text: &str) -> Result<serde_json::Value, String> {
    let loaded = Loader::new().toml_str("git", text).load().map_err(|errs| {
        errs.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    })?;
    Ok(telltale_config::shared::shared_part(&loaded.config))
}

/// Checks a commit's file: it must load, and the cluster's configuration it makes (merged
/// with this node's own settings) must validate.
fn check(file: &Config, text: &str) -> Result<(), String> {
    let shared = parse(text)?;
    let merged = telltale_config::shared::with_shared(file, &shared).map_err(|errs| {
        errs.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    })?;
    telltale_config::validate_config(&merged)
        .map(|_| ())
        .map_err(|errs| {
            errs.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        })
}

/// The source the cluster is pinned to (from the manifests this node applied or published).
pub(crate) fn pin(cfg: &Config) -> Option<(String, String, String)> {
    let b = std::fs::read(cluster_dir(cfg).join(PIN)).ok()?;
    serde_json::from_slice(&b).ok()
}

pub(crate) fn save_pin(cfg: &Config, repo: &str, git_ref: &str, path: &str) {
    let v = (repo, git_ref, path);
    if pin(cfg).is_some_and(|p| (p.0.as_str(), p.1.as_str(), p.2.as_str()) == v) {
        return;
    }
    if let Ok(b) = serde_json::to_vec(&v) {
        let _ = write_atomic(&cluster_dir(cfg).join(PIN), &b);
    }
}

/// The repository over HTTPS (smart HTTP, protocol v2).
struct Https {
    client: telltale_filter::fetch::Client,
    repo: String,
    auth: Option<String>,
    max: u64,
}

impl Https {
    async fn send(&self, req: http::request::Builder, body: Vec<u8>) -> Result<Vec<u8>, String> {
        let mut req = req.header("Git-Protocol", "version=2");
        if let Some(a) = &self.auth {
            req = req.header("Authorization", a);
        }
        let req = req.body(body).map_err(|e| e.to_string())?;
        let resp = self
            .client
            .request(req, self.max)
            .await
            .map_err(|e| e.message)?;
        if !resp.status().is_success() {
            return Err(format!("{}: HTTP {}", self.repo, resp.status()));
        }
        Ok(resp.into_body())
    }
}

impl telltale_git::Transport for Https {
    fn advertise(&self) -> telltale_git::BoxFut<'_, Result<Vec<u8>, String>> {
        Box::pin(async move {
            let url = format!("{}/info/refs?service=git-upload-pack", self.repo);
            self.send(http::Request::get(url), Vec::new()).await
        })
    }
    fn upload_pack(&self, body: Vec<u8>) -> telltale_git::BoxFut<'_, Result<Vec<u8>, String>> {
        Box::pin(async move {
            let url = format!("{}/git-upload-pack", self.repo);
            let req = http::Request::post(url)
                .header("Content-Type", "application/x-git-upload-pack-request")
                .header("Accept", "application/x-git-upload-pack-result");
            self.send(req, body).await
        })
    }
}

/// `Authorization` from a credentials file: `user:password`, or a bare token (GitHub's
/// `x-access-token` user).
fn auth_header(path: &str) -> Result<String, String> {
    use base64::Engine as _;
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let text = text.trim();
    let pair = if text.contains(':') {
        text.to_owned()
    } else {
        format!("x-access-token:{text}")
    };
    Ok(format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(pair)
    ))
}

/// One poll: fetch, check, and keep the result. Returns whether the commit in use changed.
async fn poll(cfg: &Config, g: &GitSourceConfig) -> Result<bool, (String, bool)> {
    // A promoted node fetches only from the source the cluster is pinned to.
    if let Some((repo, git_ref, path)) = pin(cfg)
        && (repo.as_str(), git_ref.as_str(), path.as_str())
            != (g.repo.as_str(), g.git_ref.as_str(), g.path.as_str())
    {
        return Err((
            format!(
                "this node's [cluster.git] ({} {} {}) differs from the cluster's source ({repo} {git_ref} {path}): not fetching",
                g.repo, g.git_ref, g.path
            ),
            true,
        ));
    }
    let auth = g
        .credentials_file
        .as_ref()
        .map(|f| auth_header(f.as_str()))
        .transpose()
        .map_err(|e| (e, false))?;
    let signers = if g.require_signed {
        let file = g
            .allowed_signers_file
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default();
        let text = std::fs::read_to_string(&file).map_err(|e| (format!("{file}: {e}"), true))?;
        let s = telltale_git::AllowedSigners::parse(&text);
        if s.is_empty() {
            return Err((format!("{file} has no ssh-ed25519 keys"), true));
        }
        Some(s)
    } else {
        None
    };
    let client =
        telltale_filter::fetch::Client::new(Arc::new(telltale_filter::fetch::SystemResolver), &[])
            .map_err(|e| (e, false))?;
    let max_file = usize::try_from(g.max_bytes.bytes()).unwrap_or(usize::MAX);
    let t = Https {
        client,
        repo: g.repo.as_str().trim_end_matches('/').to_owned(),
        auth,
        // Pack responses carry more than the file: commits for the history check, trees.
        max: g.max_bytes.bytes().saturating_mul(16).max(64 << 20),
    };
    let mut st = status(cfg).unwrap_or_default();
    let req = telltale_git::Request {
        git_ref: g.git_ref.to_string(),
        path: g.path.to_string(),
        last: st.commit.clone(),
        allow_rewind: g.allow_rewind,
        signers,
        max_file,
    };
    let outcome = tokio::time::timeout(DEADLINE, telltale_git::fetch_file(&t, &req))
        .await
        .map_err(|_| {
            (
                format!("{} didn't answer within {DEADLINE:?}", g.repo),
                false,
            )
        })?
        .map_err(|e| (e.message, e.refused))?;
    st.checked_ms = now_ms();
    let changed = match outcome {
        telltale_git::Outcome::Unchanged(_) => false,
        telltale_git::Outcome::Changed(f) => {
            let text = String::from_utf8(f.content)
                .map_err(|_| (format!("{} isn't UTF-8", g.path), true))?;
            check(cfg, &text).map_err(|e| (format!("commit {}: {e}", short(&f.commit)), true))?;
            write_atomic(&cluster_dir(cfg).join(SHARED), text.as_bytes())
                .map_err(|e| (e.to_string(), false))?;
            info!(commit = %short(&f.commit), author = %f.author, "cluster configuration from Git: new commit");
            st.commit = Some(f.commit);
            st.author = f.author;
            st.time = f.time;
            st.subject = f.subject;
            st.signed_by = f.signed_by;
            true
        }
    };
    st.error = None;
    st.refused = false;
    st.refused_commit = None;
    save_status(cfg, &st);
    save_pin(cfg, g.repo.as_str(), g.git_ref.as_str(), g.path.as_str());
    Ok(changed)
}

pub(crate) fn short(commit: &str) -> &str {
    commit.get(..12).unwrap_or(commit)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The poll loop: on the primary only; `poke` (the webhook) checks at once.
pub(crate) async fn run(
    cluster: Arc<Cluster>,
    sources: Arc<crate::http::Sources>,
    poke: Arc<Notify>,
    mut stop: watch::Receiver<bool>,
) {
    let mut first = true;
    loop {
        let cfg = sources.config.load_full();
        let Some(g) = cfg.cluster.git.clone() else {
            return;
        };
        if !first {
            tokio::select! {
                _ = stop.changed() => return,
                () = poke.notified() => {}
                () = tokio::time::sleep(Duration::from_secs(u64::from(g.poll_secs))) => {}
            }
        }
        first = false;
        if !cluster.is_primary() {
            continue;
        }
        match poll(&cfg, &g).await {
            Ok(true) => {
                cluster.event(
                    "git_commit",
                    &cluster.identity.meta.node_id,
                    status(&cfg)
                        .and_then(|s| s.commit)
                        .map(|c| format!("commit {}", short(&c)))
                        .unwrap_or_default(),
                );
                if let Some(a) = sources.auth.get()
                    && let Some(s) = status(&cfg)
                {
                    a.record(
                        &telltale_api::auth::Actor::system("git"),
                        "config.git",
                        s.commit.as_deref().unwrap_or(""),
                        &serde_json::json!({ "author": s.author, "subject": s.subject, "signedBy": s.signed_by, "repo": g.repo.as_str() }),
                    );
                }
                // Apply: the effective configuration now uses the new commit's file.
                let (tx, rx) = tokio::sync::oneshot::channel();
                if sources.reload.send(tx).await.is_ok() && !rx.await.unwrap_or(false) {
                    warn!("cluster: the new Git commit's configuration didn't apply; see the log");
                }
            }
            Ok(false) => {}
            Err((e, refused)) => {
                let mut st = status(&cfg).unwrap_or_default();
                let fresh = st.error.as_deref() != Some(e.as_str());
                st.checked_ms = now_ms();
                st.error = Some(e.clone());
                st.refused = refused;
                save_status(&cfg, &st);
                if fresh {
                    warn!(refused, "cluster: Git source: {e}");
                    cluster.event(
                        if refused { "git_refused" } else { "git_failed" },
                        &cluster.identity.meta.node_id,
                        e,
                    );
                }
            }
        }
    }
}

/// The Git source as the Cluster page shows it: from this primary's polls, or from the
/// manifest a replica applied.
pub(crate) fn view(cfg: &Config, primary: bool) -> Option<telltale_api::model::ClusterSource> {
    use telltale_api::time::format_us;
    let at = |ms: u64| (ms > 0).then(|| format_us(ms.saturating_mul(1000)));
    let secs = |t: i64| {
        (t > 0).then(|| format_us(u64::try_from(t).unwrap_or(0).saturating_mul(1_000_000)))
    };
    if primary && let Some(g) = &cfg.cluster.git {
        let s = status(cfg).unwrap_or_default();
        return Some(telltale_api::model::ClusterSource {
            repo: g.repo.to_string(),
            git_ref: g.git_ref.to_string(),
            path: g.path.to_string(),
            commit: s.commit.clone(),
            author: s.commit.as_ref().map(|_| s.author.clone()),
            committed_at: secs(s.time),
            subject: s.commit.as_ref().map(|_| s.subject.clone()),
            signed_by: s.signed_by,
            checked_at: at(s.checked_ms),
            error: s.error,
            refused: s.refused,
        });
    }
    let m = crate::replication::last_applied(cfg)?.source?;
    Some(telltale_api::model::ClusterSource {
        repo: m.repo,
        git_ref: m.git_ref,
        path: m.path,
        commit: Some(m.commit),
        author: Some(m.author),
        committed_at: secs(m.time),
        subject: Some(m.subject),
        signed_by: m.signed_by,
        checked_at: None,
        error: None,
        refused: false,
    })
}

/// Checks a webhook's `X-Hub-Signature-256` (`sha256=<hex HMAC of the body>`).
pub(crate) fn webhook_ok(cfg: &Config, signature: Option<&str>, body: &[u8]) -> Result<(), String> {
    let g = cfg
        .cluster
        .git
        .as_ref()
        .ok_or("this node has no Git source")?;
    let file = g
        .webhook_secret_file
        .as_ref()
        .ok_or("no webhook_secret_file is set")?;
    let secret = std::fs::read_to_string(file.as_str()).map_err(|e| format!("{file}: {e}"))?;
    let sig = signature
        .and_then(|s| s.strip_prefix("sha256="))
        .ok_or("missing X-Hub-Signature-256")?;
    let mut want = vec![0u8; sig.len() / 2];
    for (i, b) in want.iter_mut().enumerate() {
        *b = u8::from_str_radix(sig.get(i * 2..i * 2 + 2).unwrap_or("zz"), 16)
            .map_err(|_| "bad signature")?;
    }
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.trim().as_bytes());
    ring::hmac::verify(&key, body, &want).map_err(|_| "the signature doesn't match".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: CLU-003 — a commit's file must load and validate before it's used.
    #[test]
    fn clu_003_commits_are_checked_before_use() {
        let file = Config::default();
        assert!(
            check(
                &file,
                "[[record]]\nname = \"nas.home.arpa\"\ntype = \"A\"\nvalue = \"10.0.0.5\"\n"
            )
            .is_ok()
        );
        assert!(
            check(&file, "[[record]]\nname = \"x\"\nvalue = ").is_err(),
            "not TOML"
        );
        assert!(
            check(
                &file,
                "[[upstream_group]]\nname = \"default\"\nmembers = [\"no-such-upstream\"]\n"
            )
            .is_err(),
            "invalid"
        );
        assert!(
            check(&file, "[nonsense]\nx = 1\n").is_err(),
            "unknown section"
        );
    }

    #[test]
    fn clu_003_webhooks_need_the_right_signature() {
        let tmp = tempfile::tempdir().unwrap();
        let secret = tmp.path().join("hook");
        std::fs::write(&secret, "s3cret\n").unwrap();
        let mut cfg = Config::default();
        cfg.cluster.git = Some(GitSourceConfig {
            repo: "https://example.com/r".into(),
            git_ref: "main".into(),
            path: "t.toml".into(),
            credentials_file: None,
            poll_secs: 60,
            require_signed: false,
            allowed_signers_file: None,
            allow_rewind: false,
            max_bytes: telltale_config::ByteSize::mib(1),
            webhook_secret_file: Some(
                telltale_config::SafeString::new(secret.to_string_lossy().into_owned()).unwrap(),
            ),
        });
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"s3cret");
        let tag = ring::hmac::sign(&key, b"{}");
        let hex = tag.as_ref().iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        });
        assert!(webhook_ok(&cfg, Some(&format!("sha256={hex}")), b"{}").is_ok());
        assert!(webhook_ok(&cfg, Some(&format!("sha256={hex}")), b"{\"x\":1}").is_err());
        assert!(webhook_ok(&cfg, None, b"{}").is_err());
    }
}
