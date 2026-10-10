//! REQ: CLU-013 — what the API shows of rollouts and pins, and its commands, on this node (the
//! primary, or a replica answering from the version it applied), and the RPC that brings a
//! replica's request to the primary.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use telltale_api::model::{
    ClusterPin, ClusterVersion, ClusterVersions, GuardReadings, RolloutAction, RolloutNode,
    RolloutStatus,
};
use telltale_api::problem::{Code, Problem};
use telltale_api::time::format_us;
use telltale_api::{RolloutWrite, Shared};
use telltale_cluster::net::Cluster;
use telltale_cluster::node;
use telltale_cluster::sync::{BlobStore, PinInfo};
use telltale_config::shared::shared_part;

use super::{Cmd, Readings, State, Status, Versions, diff_sentences, json_diff};
use crate::http::Sources;

/// The RPC for a replica's rollout request; its body is a JSON [`Call`].
pub(crate) const KIND: &str = "rollout.call";
const DEADLINE: Duration = Duration::from_secs(15);

/// A replica's request, as sent to the primary.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "call", rename_all = "snake_case")]
pub(crate) enum Call {
    Status,
    Versions,
    Command(RolloutWrite),
}

fn version(v: (u64, u64)) -> String {
    format!("{}.{}", v.0, v.1)
}

fn time(ms: u64) -> String {
    format_us(ms.saturating_mul(1000))
}

fn readings(r: &Readings) -> GuardReadings {
    GuardReadings {
        before_percent: r.before_pct,
        after_percent: r.after_pct,
        answers: r.answers,
        reason: r.reason.clone(),
    }
}

fn cluster_dir(src: &Sources) -> std::path::PathBuf {
    node::dir_of(Path::new(src.config.load().node.data_dir.as_str()))
}

fn store(src: &Sources) -> Option<BlobStore> {
    BlobStore::open(Path::new(src.config.load().node.data_dir.as_str())).ok()
}

/// A shared configuration from the blob store, as JSON.
fn shared_of(store: &BlobStore, b: &telltale_cluster::sync::BlobRef) -> Option<serde_json::Value> {
    serde_json::from_slice(&store.read(b).ok()?).ok()
}

/// The shared configuration this primary would publish without the pin.
fn unpinned_shared(src: &Sources) -> Option<serde_json::Value> {
    let file = crate::server::load_files_quiet(&src.config_files)?;
    Some(shared_part(&crate::replication::unpinned(&file)))
}

/// The shared configuration in effect on this node now.
fn served_shared(src: &Sources) -> serde_json::Value {
    shared_part(&src.config.load())
}

/// REQ: CLU-013 — what a pin holds back: JSON Patch from the pinned version to what this
/// primary would publish, and one sentence per section.
pub(crate) fn pin_diff(src: &Sources) -> Option<(Vec<serde_json::Value>, Vec<String>)> {
    let m = super::pinned_manifest(&cluster_dir(src))?;
    let pinned = shared_of(&store(src)?, &m.config)?;
    let ops = json_diff(&pinned, &unpinned_shared(src)?);
    let sentences = diff_sentences(&ops);
    Some((ops, sentences))
}

fn pin_model(p: &PinInfo, diff: Option<(Vec<serde_json::Value>, Vec<String>)>) -> ClusterPin {
    let (diff, changes) = diff.unwrap_or_default();
    ClusterPin {
        to: version(p.to),
        since: time(p.since_ms),
        by: p.by.clone(),
        reason: p.reason.clone(),
        diff,
        changes,
    }
}

/// REQ: CLU-013 — the `409 cluster_pinned` a configuration write gets on a pinned primary,
/// with the diff the pin holds back. `None` when not pinned.
pub(crate) fn pinned_problem(src: &Sources) -> Option<Problem> {
    src.cluster.as_ref()?;
    let pin = State::load(&cluster_dir(src)).pinned?;
    let (ops, sentences) = pin_diff(src).unwrap_or_default();
    let since = time(pin.since_ms);
    let mut p = Problem::new(
        Code::ClusterPinned,
        format!(
            "the cluster is pinned to version {} since {since} by {}: {}",
            version(pin.to),
            pin.by,
            pin.reason
        ),
    )
    .hint(if sentences.is_empty() {
        "Unpin to publish changes (Cluster page, or DELETE /api/v1/cluster/pin).".to_owned()
    } else {
        format!(
            "Unpin to publish changes (Cluster page, or DELETE /api/v1/cluster/pin). Held back since the pin: {}.",
            sentences.join("; ")
        )
    });
    p = p.diff(serde_json::Value::Array(ops));
    Some(p)
}

/// REQ: CLU-013 — the rollout and the pin in brief, for the cluster view (health, alerts, the
/// Cluster page): the publisher's on the primary, else what the applied version says. `None`
/// when nothing is going on.
pub(crate) fn summary(src: &Sources) -> Option<telltale_api::model::ClusterRollout> {
    let s = src.rollout.status();
    let now = crate::maintenance::now_ms();
    let r = if s.primary {
        let a = s.active.as_ref();
        telltale_api::model::ClusterRollout {
            stage: if s.pinned.is_some() {
                "pinned"
            } else if a.is_some() {
                "canary"
            } else if s.waiting_since_ms.is_some() {
                "waiting"
            } else {
                "none"
            }
            .into(),
            version: a.map(|a| version(a.version)),
            canaries: a.map(|a| a.canaries.clone()).unwrap_or_default(),
            bake_ends: a.map(|a| time(a.started_ms + u64::from(a.bake_secs) * 1000)),
            pinned: s.pinned.as_ref().map(|p| pin_model(p, None)),
            canaries_offline_seconds: s
                .canaries_offline_since_ms
                .map(|w| now.saturating_sub(w) / 1000),
            last_failure: s
                .last_failure
                .as_ref()
                .map(|f| telltale_api::model::RolloutFailure {
                    version: version(f.version),
                    reason: f.reason.clone(),
                    at: time(f.at_ms),
                }),
        }
    } else {
        let m = crate::replication::last_applied(&src.config.load())?;
        let c = m.rollout.as_ref();
        telltale_api::model::ClusterRollout {
            stage: if m.pinned.is_some() {
                "pinned"
            } else if c.is_some() {
                "canary"
            } else {
                "none"
            }
            .into(),
            version: c.map(|_| version((m.epoch, m.seq))),
            canaries: c.map(|c| c.canaries.clone()).unwrap_or_default(),
            bake_ends: c.map(|c| time(c.started_ms + u64::from(c.bake_secs) * 1000)),
            pinned: m.pinned.as_ref().map(|p| pin_model(p, None)),
            ..Default::default()
        }
    };
    (r.stage != "none" || r.last_failure.is_some() || r.canaries_offline_seconds.is_some())
        .then_some(r)
}

/// The rollout status: the publisher's on the primary; on a replica, what the version it
/// applied says.
pub(crate) fn status(src: &Sources) -> Result<RolloutStatus, Problem> {
    if src.cluster.is_none() {
        return Err(telltale_api::rollout_api::no_cluster());
    }
    let s = src.rollout.status();
    if s.primary {
        return Ok(primary_status(src, &s));
    }
    let cfg = src.config.load();
    let m = crate::replication::last_applied(&cfg);
    let r = &cfg.cluster.rollout;
    let stable = m.as_ref().map_or((0, 0), |m| {
        m.rollout.as_ref().map_or((m.epoch, m.seq), |r| r.of)
    });
    let pinned = m.as_ref().and_then(|m| m.pinned.as_ref());
    let canary = m.as_ref().and_then(|m| m.rollout.as_ref());
    Ok(RolloutStatus {
        from_primary: false,
        canaries: r.canaries.iter().map(ToString::to_string).collect(),
        bake_secs: r.bake_secs,
        stable: version(stable),
        stage: if pinned.is_some() {
            "pinned"
        } else if canary.is_some() {
            "canary"
        } else {
            "none"
        }
        .into(),
        version: canary.and(m.as_ref()).map(|m| version((m.epoch, m.seq))),
        started: canary.map(|c| time(c.started_ms)),
        bake_ends: canary.map(|c| time(c.started_ms + u64::from(c.bake_secs) * 1000)),
        rollout_canaries: canary.map(|c| c.canaries.clone()).unwrap_or_default(),
        pinned: pinned.map(|p| pin_model(p, None)),
        ..RolloutStatus::default()
    })
}

fn primary_status(src: &Sources, s: &Status) -> RolloutStatus {
    let now = crate::maintenance::now_ms();
    let stage = if s.pinned.is_some() {
        "pinned"
    } else if s.active.is_some() {
        "canary"
    } else if s.waiting_since_ms.is_some() {
        "waiting"
    } else {
        "none"
    };
    let a = s.active.as_ref();
    let ends = a.map(|a| a.started_ms + u64::from(a.bake_secs) * 1000);
    RolloutStatus {
        from_primary: true,
        canaries: s.canaries.clone(),
        bake_secs: s.bake_secs,
        stable: version(s.stable),
        stage: stage.into(),
        version: a.map(|a| version(a.version)),
        started: a.map(|a| time(a.started_ms)),
        bake_ends: ends.map(time),
        seconds_left: ends.map(|e| e.saturating_sub(now).div_ceil(1000)),
        rollout_canaries: a.map(|a| a.canaries.clone()).unwrap_or_default(),
        readings: s.readings.as_ref().map(readings),
        pinned: s.pinned.as_ref().map(|p| pin_model(p, pin_diff(src))),
        nodes: s
            .nodes
            .iter()
            .map(|n| RolloutNode {
                node: n.node.clone(),
                site: n.site.clone(),
                canary: n.canary,
                applied_seq: n.applied_seq,
                ready: n.ready,
                connected: n.connected,
                servfail_percent: f64::from(n.servfail_permille) / 10.0,
            })
            .collect(),
        skipped: s.skipped.clone(),
        waiting_since: s.waiting_since_ms.map(time),
    }
}

/// The kept versions, newest first (the primary).
pub(crate) fn versions(src: &Sources) -> Result<ClusterVersions, Problem> {
    if src.cluster.is_none() {
        return Err(telltale_api::rollout_api::no_cluster());
    }
    let s = src.rollout.status();
    if !s.primary {
        return Err(
            Problem::unavailable("the primary keeps the versions, and it isn't reachable")
                .hint("Retry when the primary is back; DNS keeps working meanwhile."),
        );
    }
    let v = Versions::load(&cluster_dir(src));
    let store = store(src);
    let items = v
        .entries
        .iter()
        .rev()
        .map(|e| ClusterVersion {
            version: version((e.epoch, e.seq)),
            created: time(e.created_ms),
            by: e.by.clone(),
            outcome: e.outcome.clone(),
            readings: e.readings.as_ref().map(readings),
            pinned_to: e.pinned_to.map(version),
            reason: e.reason.clone(),
            filter_version: e.filter.as_ref().map(|f| f.version),
            current: (e.epoch, e.seq) == s.stable,
            pinnable: store
                .as_ref()
                .is_some_and(|st| e.blobs().iter().all(|b| st.has(b))),
        })
        .collect();
    Ok(ClusterVersions {
        items,
        history: src.config.load().cluster.rollout.history,
    })
}

fn problem((code, msg): (Code, String)) -> Problem {
    Problem::new(code, msg)
}

/// A command on the primary: checked here (dry runs end here), then run by the publisher.
pub(crate) async fn command(
    src: &Sources,
    config_version: u64,
    w: RolloutWrite,
) -> Result<RolloutAction, Problem> {
    if src.cluster.is_none() {
        return Err(telltale_api::rollout_api::no_cluster());
    }
    if !src.rollout.status().primary {
        return Err(Problem::new(Code::Conflict, "this node isn't the primary")
            .hint("Retry: requests to another node go to the current primary."));
    }
    let dry_run = w.dry_run();
    let mut out = RolloutAction {
        dry_run,
        config_version,
        ..RolloutAction::default()
    };
    let cmd = match w {
        RolloutWrite::Promote { by } => Cmd::Promote { by },
        RolloutWrite::Abort { by } => Cmd::Abort { by },
        RolloutWrite::Pin {
            epoch,
            seq,
            reason,
            expect,
            by,
            ..
        } => {
            check_expect(expect, config_version)?;
            let to = (epoch, seq);
            let entry = Versions::load(&cluster_dir(src))
                .find(to)
                .cloned()
                .ok_or_else(|| {
                    Problem::new(
                        Code::VersionUnknown,
                        format!("version {} isn't among the kept versions", version(to)),
                    )
                    .hint("GET /api/v1/cluster/versions lists them.")
                })?;
            let st = store(src).ok_or_else(|| Problem::internal("the blob store isn't open"))?;
            if let Some(b) = entry.blobs().iter().find(|b| !st.has(b)) {
                return Err(Problem::new(
                    Code::VersionBlobsMissing,
                    format!(
                        "version {}'s file {} is no longer kept",
                        version(to),
                        b.name
                    ),
                ));
            }
            if let Some(target) = shared_of(&st, &entry.config) {
                out.diff = json_diff(&served_shared(src), &target);
                out.changes = diff_sentences(&out.diff);
            }
            if dry_run {
                out.done = format!("would pin the cluster to version {}", version(to));
                return Ok(out);
            }
            Cmd::Pin { to, by, reason }
        }
        RolloutWrite::Unpin { expect, by, .. } => {
            check_expect(expect, config_version)?;
            if State::load(&cluster_dir(src)).pinned.is_none() {
                return Err(Problem::new(Code::Conflict, "the cluster isn't pinned"));
            }
            if let Some((ops, sentences)) = pin_diff(src) {
                out.diff = ops;
                out.changes = sentences;
            }
            if dry_run {
                out.done = "would unpin: the current configuration is published again".into();
                return Ok(out);
            }
            Cmd::Unpin { by }
        }
    };
    out.done = src.rollout.send(cmd).await.map_err(problem)?;
    Ok(out)
}

fn check_expect(expect: Option<u64>, current: u64) -> Result<(), Problem> {
    match expect {
        Some(v) if v != current => Err(Problem::new(
            Code::VersionConflict,
            format!("the configuration is now at version {current}"),
        )
        .hint(
            "The configuration changed since the request was made: check the diff again and retry.",
        )),
        _ => Ok(()),
    }
}

/// A replica's request on this node (the primary): answered by the local backend, and a
/// command audited with the user and the entry node.
pub(crate) async fn handle(
    src: Arc<Sources>,
    local: Shared,
    cluster: Arc<Cluster>,
    peer: String,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let call: Call = serde_json::from_slice(&body).map_err(|e| format!("bad call: {e}"))?;
    if !cluster.is_primary() {
        return crate::forward::encode_answer::<()>(Err(Problem::new(
            Code::Conflict,
            "this node isn't the primary any more",
        )
        .hint("retry: the entry node asks the current primary")));
    }
    match call {
        Call::Status => crate::forward::encode_answer(local.rollout_status().await),
        Call::Versions => crate::forward::encode_answer(local.cluster_versions().await),
        Call::Command(w) => {
            let via = cluster
                .members()
                .into_iter()
                .find(|m| m.node_id == peer)
                .map(|m| m.site)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| peer.clone());
            let (action, target) = match &w {
                RolloutWrite::Promote { .. } => ("rollout.promote", "rollout".to_owned()),
                RolloutWrite::Abort { .. } => ("rollout.abort", "rollout".to_owned()),
                RolloutWrite::Pin { epoch, seq, .. } => ("cluster.pin", version((*epoch, *seq))),
                RolloutWrite::Unpin { .. } => ("cluster.unpin", "cluster".to_owned()),
            };
            let dry = w.dry_run();
            let by = match &w {
                RolloutWrite::Promote { by }
                | RolloutWrite::Abort { by }
                | RolloutWrite::Pin { by, .. }
                | RolloutWrite::Unpin { by, .. } => by.clone(),
            };
            let who = format!("{by} via {via}");
            let r = local.rollout_command(w.with_by(who.clone())).await;
            if let (Ok(res), false, Some(auth)) = (&r, dry, src.auth.get()) {
                let actor = telltale_api::auth::Actor {
                    name: who,
                    kind: "cluster",
                    remote: Some(format!("node {peer}")),
                    reason: None,
                };
                auth.record(
                    &actor,
                    action,
                    &target,
                    &serde_json::json!({ "done": res.done, "changes": res.changes }),
                );
            }
            crate::forward::encode_answer(r)
        }
    }
}

/// Sends `call` to the primary and decodes the answer.
pub(crate) async fn send<T: serde::de::DeserializeOwned>(
    cluster: Arc<Cluster>,
    primary: Option<String>,
    call: Call,
) -> Result<T, Problem> {
    let Some(primary) = primary else {
        return Err(Problem::unavailable(
            "this node is a cluster replica and can't reach the primary, which runs rollouts and pins",
        )
        .hint("Retry when the primary is back, or use the primary's UI; DNS keeps working meanwhile."));
    };
    let body = serde_json::to_vec(&call).map_err(|e| Problem::internal(e.to_string()))?;
    let reply = cluster
        .call(&primary, KIND, body, DEADLINE)
        .await
        .map_err(|e| {
            Problem::unavailable(format!("the primary didn't answer: {e}"))
                .hint("Retry; if the primary runs an older version, it has no staged rollouts yet.")
        })?;
    crate::forward::decode_answer(&reply)
}
