//! Update status (REQ: OPS-004; T6.9, ADR-046): once a day, read this build's channel's
//! signed `releases.json`, verify it with the release key built into this binary, and compare
//! versions. Off with `[updates] check = false`, and then nothing leaves the node. Never on the
//! DNS path: a failing check only shows as `unknown`.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::Deserialize;
use telltale_api::model::UpdateStatus;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::build_info;
use crate::selfupdate::{RELEASE_KEY, verify_signature};

const RELEASES: &str = "https://github.com/paimonsoror/telltaledns/releases";
const MAX_INDEX: u64 = 256 * 1024;

/// The signed index CI publishes next to each release's binaries.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub(crate) struct Index {
    pub channel: String,
    pub version: String,
    pub commit: String,
    pub date: String,
    #[serde(default)]
    pub notes: Option<String>,
}

/// Where this build's channel publishes its index (`[updates] index_url` overrides, e.g. a
/// local mirror; the signature is still checked with the built-in key).
fn index_url(override_url: Option<&str>) -> String {
    if let Some(u) = override_url {
        return u.to_owned();
    }
    if build_info::CHANNEL == "edge" {
        format!("{RELEASES}/download/edge/releases.json")
    } else {
        format!("{RELEASES}/latest/download/releases.json")
    }
}

/// `(major, minor, patch, edge run)`; a release sorts after every edge build of its version.
fn key(v: &str) -> Option<(u64, u64, u64, u64)> {
    let (core, pre) = v.split_once('-').unwrap_or((v, ""));
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    let (a, b, c) = (it.next()??, it.next()??, it.next()??);
    let run = if pre.is_empty() {
        u64::MAX
    } else {
        pre.strip_prefix("edge.")?.parse().ok()?
    };
    Some((a, b, c, run))
}

/// `up_to_date`, `available`, or `newer` for this build against the index's latest.
pub(crate) fn compare(current: &str, latest: &str) -> &'static str {
    match (key(current), key(latest)) {
        (Some(c), Some(l)) if l > c => "available",
        (Some(c), Some(l)) if l == c => "up_to_date",
        // A dev build, or one newer than what's published.
        _ => "newer",
    }
}

/// How to update this kind of install (ADR-046): the UI never updates a node itself.
pub(crate) fn how(install: &str, channel: &str) -> String {
    let edge = channel == "edge";
    match install {
        "helm" => format!(
            "Upgrade the chart: helm upgrade <release> oci://ghcr.io/paimonsoror/charts/telltale{} (or bump the chart version in your GitOps values). In a cluster, replicas first.",
            if edge { " --devel" } else { "" }
        ),
        "container" => format!(
            "Pull the new image and restart: docker compose pull && docker compose up -d (image tag :{}). In a cluster, replicas first.",
            if edge {
                "edge"
            } else {
                "latest or the new version"
            }
        ),
        _ => format!(
            "Run: sudo telltale self-update{} --restart. In a cluster, replicas first.",
            if edge { " --channel edge" } else { "" }
        ),
    }
}

/// Parses and verifies an index and its `.minisig` with `key`.
pub(crate) fn verified(key: &str, index: &[u8], sig: &[u8]) -> Result<Index, String> {
    verify_signature(key, index, sig).map_err(|_| {
        "the release index's signature doesn't verify with the release key: ignored".to_owned()
    })?;
    serde_json::from_slice(index).map_err(|e| format!("release index: {e}"))
}

/// The status before any check.
pub(crate) fn initial(check: bool) -> UpdateStatus {
    let b = build_info::api();
    UpdateStatus {
        state: if check { "unknown" } else { "off" }.into(),
        latest: None,
        latest_commit: None,
        latest_date: None,
        notes_url: None,
        checked_unix_seconds: None,
        error: None,
        how: how(&b.install, &b.channel),
    }
}

async fn fetch(client: &telltale_filter::fetch::Client, url: &str) -> Result<Vec<u8>, String> {
    use telltale_filter::fetch::{Conditional, Response};
    match client.get(url, &Conditional::default(), MAX_INDEX).await {
        Ok(Response::Body { data, .. }) => Ok(data),
        Ok(Response::NotModified) => Err(format!("{url}: unexpected 304")),
        Err(e) => Err(format!("{url}: {}", e.message)),
    }
}

/// One check: the index and its signature, verified, compared.
async fn check_once(override_url: Option<&str>) -> Result<Index, String> {
    let client =
        telltale_filter::fetch::Client::new(Arc::new(telltale_filter::fetch::SystemResolver), &[])?;
    let url = index_url(override_url);
    let index = fetch(&client, &url).await?;
    let sig = fetch(&client, &format!("{url}.minisig")).await?;
    verified(RELEASE_KEY, &index, &sig)
}

/// Checks now and then once a day until `stop`, keeping `status` current.
pub(crate) async fn run(
    status: Arc<Mutex<UpdateStatus>>,
    check: bool,
    override_url: Option<String>,
    mut stop: watch::Receiver<bool>,
) {
    if !check {
        return;
    }
    // A local build has no channel to compare with.
    if build_info::CHANNEL == "dev" {
        let mut st = status.lock().unwrap_or_else(PoisonError::into_inner);
        st.state = "newer".into();
        st.error = Some("a development build: not compared with releases".into());
        return;
    }
    // Not at start-up: let the node settle (and keep restarts from hammering GitHub).
    let mut wait = Duration::from_secs(60);
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(wait) => {}
        }
        wait = Duration::from_hours(24);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let result = check_once(override_url.as_deref()).await;
        let mut s = status.lock().unwrap_or_else(PoisonError::into_inner);
        match result {
            Ok(ix) => {
                let state = compare(build_info::VERSION, &ix.version);
                if state == "available" && s.state != "available" {
                    info!(latest = %ix.version, "a newer TelltaleDNS build is available");
                }
                debug!(latest = %ix.version, state, "update check");
                s.state = state.into();
                s.latest = Some(ix.version);
                s.latest_commit = Some(ix.commit);
                s.latest_date = Some(ix.date);
                s.notes_url = ix.notes;
                s.checked_unix_seconds = Some(now);
                s.error = None;
            }
            Err(e) => {
                warn!("update check failed: {e}");
                if s.checked_unix_seconds.is_none() {
                    s.state = "unknown".into();
                }
                s.error = Some(e);
                // Try again sooner after a failure.
                wait = Duration::from_secs(3600);
            }
        }
    }
}

#[cfg(test)]
mod tests;
