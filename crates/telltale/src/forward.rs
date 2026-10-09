//! Write forwarding (REQ: CLU-002; T5.7, ADR-054): a configuration change made on a replica's
//! API goes to the primary over the cluster channel, carrying who made it. The primary trusts
//! the entry node by its mTLS certificate, applies the change as if it had been made locally,
//! stores `<user> via <node>` with the entry, and audits it; the change then reaches every node
//! with the next published version. The entry node audits it too, under the user's name.
//!
//! Forwarding never involves DNS answering (CLU-004): with the primary unreachable, a write on
//! a replica fails fast with 503 and nothing else changes.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use telltale_api::auth::Actor;
use telltale_api::model::{ClientChange, ClientInput, ConfigChange};
use telltale_api::problem::{Code, Problem};
use telltale_api::{AnomalyAckWrite, ClientWrite, ManagedKind, ManagedWrite, Shared};
use telltale_cluster::net::Cluster;

use crate::http::Sources;

/// The RPC for forwarded writes; its body is a JSON [`Write`].
pub(crate) const KIND: &str = "api.write";
/// Writes validate, store, and apply on the primary before answering.
const DEADLINE: Duration = Duration::from_secs(10);

/// A configuration write, as sent to the primary.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "write", rename_all = "snake_case")]
pub(crate) enum Write {
    Managed {
        kind: ManagedKind,
        name: String,
        body: Option<serde_json::Value>,
        dry_run: bool,
        expect: Option<u64>,
        by: String,
    },
    Client {
        name: String,
        input: Option<ClientInput>,
        dry_run: bool,
        expect: Option<u64>,
        by: String,
    },
    /// REQ: OBS-014 (ADR-103) — acknowledging anomalies (not configuration, so a Git-managed cluster takes it too).
    AnomalyAck(AnomalyAckWrite),
}

impl From<ManagedWrite> for Write {
    fn from(w: ManagedWrite) -> Self {
        Self::Managed {
            kind: w.kind,
            name: w.name,
            body: w.body,
            dry_run: w.dry_run,
            expect: w.expect,
            by: w.by,
        }
    }
}

impl From<ClientWrite> for Write {
    fn from(w: ClientWrite) -> Self {
        Self::Client {
            name: w.name,
            input: w.input,
            dry_run: w.dry_run,
            expect: w.expect,
            by: w.by,
        }
    }
}

/// A [`Problem`] across the channel (its code, so the entry node answers with the same status).
#[derive(Debug, Serialize, Deserialize)]
struct WireProblem {
    code: Code,
    detail: String,
    hint: Option<String>,
}

impl From<Problem> for WireProblem {
    fn from(p: Problem) -> Self {
        Self {
            code: p.code,
            detail: p.detail,
            hint: p.hint,
        }
    }
}

impl From<WireProblem> for Problem {
    fn from(w: WireProblem) -> Self {
        let p = Problem::new(w.code, w.detail);
        match w.hint {
            Some(h) => p.hint(h),
            None => p,
        }
    }
}

/// The primary's answer: the change, or why it was refused.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Answer {
    Ok(serde_json::Value),
    Err(WireProblem),
}

/// Applies a peer's forwarded write on this node (the primary), with the user's identity.
pub(crate) async fn handle(
    src: Arc<Sources>,
    local: Shared,
    cluster: Arc<Cluster>,
    peer: String,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let write: Write = serde_json::from_slice(&body).map_err(|e| format!("bad write: {e}"))?;
    let answer = if cluster.is_primary() {
        apply(&src, &local, &cluster, &peer, write).await
    } else {
        Answer::Err(
            Problem::new(Code::Conflict, "this node isn't the primary any more")
                .hint("retry: the entry node forwards to the current primary")
                .into(),
        )
    };
    serde_json::to_vec(&answer).map_err(|e| e.to_string())
}

async fn apply(src: &Sources, local: &Shared, cluster: &Cluster, peer: &str, w: Write) -> Answer {
    let via = cluster
        .members()
        .into_iter()
        .find(|m| m.node_id == peer)
        .map(|m| m.site)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| peer.to_owned());
    let (action, target, result) = match w {
        Write::Managed {
            kind,
            name,
            body,
            dry_run,
            expect,
            by,
        } => {
            let action = match kind {
                ManagedKind::Record => "record",
                ManagedKind::Forward => "forward",
                ManagedKind::Rule => "rule",
                ManagedKind::Upstream => "upstream",
                ManagedKind::UpstreamGroup => "upstream_group",
                ManagedKind::List => "list",
                ManagedKind::Group => "group",
                ManagedKind::AlertDestination => "alert_destination",
                ManagedKind::AlertRule => "alert_rule",
                ManagedKind::Schedule => "schedule",
                ManagedKind::RateLimit => "ratelimit",
                ManagedKind::Exclusions => "exclusions",
            };
            let deleting = body.is_none();
            let r = local
                .write_managed(ManagedWrite {
                    kind,
                    name: name.clone(),
                    body,
                    dry_run,
                    expect,
                    by: format!("{by} via {via}"),
                })
                .await
                .map(|c| serde_json::to_value(c).unwrap_or_default());
            (verb(action, deleting), (name, by), r)
        }
        Write::Client {
            name,
            input,
            dry_run,
            expect,
            by,
        } => {
            let deleting = input.is_none();
            let r = local
                .write_client(ClientWrite {
                    name: name.clone(),
                    input,
                    dry_run,
                    expect,
                    by: format!("{by} via {via}"),
                })
                .await
                .map(|c| serde_json::to_value(c).unwrap_or_default());
            (verb("client", deleting), (name, by), r)
        }
        Write::AnomalyAck(w) => return apply_ack(src, local, peer, &via, w).await,
    };
    match result {
        Ok(c) => {
            // REQ: CLU-002 — the primary's audit log shows both the user and the entry node.
            if c["applied"].as_bool() == Some(true)
                && let Some(auth) = src.auth.get()
            {
                let actor = Actor {
                    name: format!("{} via {via}", target.1),
                    kind: "cluster",
                    remote: Some(format!("node {peer}")),
                    reason: None,
                };
                auth.record(
                    &actor,
                    &action,
                    &target.0,
                    &serde_json::json!({ "before": c["before"], "after": c["after"], "configVersion": c["configVersion"] }),
                );
            }
            Answer::Ok(c)
        }
        Err(p) => Answer::Err(p.into()),
    }
}

/// REQ: OBS-014 — a forwarded acknowledge or unacknowledge, recorded here (the primary) and
/// audited with the user and the entry node.
async fn apply_ack(
    src: &Sources,
    local: &Shared,
    peer: &str,
    via: &str,
    mut w: AnomalyAckWrite,
) -> Answer {
    let action = if w.ack {
        "anomaly.ack"
    } else {
        "anomaly.unack"
    };
    let by = w.by.clone();
    let ids = w.ids.clone();
    w.by = format!("{by} via {via}");
    let r = local.anomaly_ack(w).await;
    if let (Ok(res), Some(auth)) = (&r, src.auth.get()) {
        let actor = Actor {
            name: format!("{by} via {via}"),
            kind: "cluster",
            remote: Some(format!("node {peer}")),
            reason: None,
        };
        let target = match ids.as_slice() {
            [one] => one.clone(),
            _ => format!("{} findings", ids.len()),
        };
        auth.record(
            &actor,
            action,
            &target,
            &serde_json::json!({ "ids": ids, "changed": res.changed }),
        );
    }
    match r {
        Ok(res) => Answer::Ok(serde_json::to_value(res).unwrap_or_default()),
        Err(p) => Answer::Err(p.into()),
    }
}

fn verb(kind: &str, deleting: bool) -> String {
    format!("{kind}.{}", if deleting { "delete" } else { "put" })
}

/// Sends a write to the primary and decodes its answer.
async fn send<T: serde::de::DeserializeOwned>(
    cluster: &Cluster,
    primary: Option<String>,
    w: Write,
) -> Result<T, Problem> {
    let Some(primary) = primary else {
        return Err(Problem::unavailable(
            "this node is a cluster replica and can't reach the primary to make the change",
        )
        .hint("retry when the primary is back, or make the change on the primary; DNS keeps working meanwhile"));
    };
    let body = serde_json::to_vec(&w).map_err(|e| Problem::internal(e.to_string()))?;
    let reply = cluster
        .call(&primary, KIND, body, DEADLINE)
        .await
        .map_err(|e| {
            Problem::unavailable(format!("the primary didn't take the change: {e}"))
                .hint("retry; if it keeps failing, check the Cluster page")
        })?;
    match serde_json::from_slice::<Answer>(&reply) {
        Ok(Answer::Ok(v)) => serde_json::from_value(v)
            .map_err(|e| Problem::internal(format!("unreadable answer from the primary: {e}"))),
        Ok(Answer::Err(p)) => Err(p.into()),
        Err(e) => Err(Problem::internal(format!(
            "unreadable answer from the primary: {e}"
        ))),
    }
}

/// Forwards a local-name or forwarded-domain write.
pub(crate) async fn managed(
    cluster: Arc<Cluster>,
    primary: Option<String>,
    w: ManagedWrite,
) -> Result<ConfigChange, Problem> {
    send(&cluster, primary, w.into()).await
}

/// REQ: OBS-014 — forwards an acknowledge or unacknowledge.
pub(crate) async fn anomaly_ack(
    cluster: Arc<Cluster>,
    primary: Option<String>,
    w: AnomalyAckWrite,
) -> Result<telltale_api::model::AnomalyAckResult, Problem> {
    send(&cluster, primary, Write::AnomalyAck(w)).await
}

/// Forwards a device write.
pub(crate) async fn client(
    cluster: Arc<Cluster>,
    primary: Option<String>,
    w: ClientWrite,
) -> Result<ClientChange, Problem> {
    send(&cluster, primary, w.into()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: CLU-002 — a refused write keeps its code across the channel (409 stays 409).
    #[test]
    fn clu_002_problems_keep_their_code_across_the_channel() {
        let p = Problem::new(Code::Conflict, "version moved").hint("re-read");
        let wire = serde_json::to_vec(&Answer::Err(p.into())).unwrap();
        let back: Answer = serde_json::from_slice(&wire).unwrap();
        let Answer::Err(w) = back else {
            panic!("expected an error")
        };
        let p: Problem = w.into();
        assert_eq!(p.code, Code::Conflict);
        assert_eq!(p.hint.as_deref(), Some("re-read"));
    }

    // REQ: OBS-014 — an acknowledgement crosses the channel intact.
    #[test]
    fn obs_014_acks_round_trip() {
        let w = Write::AnomalyAck(AnomalyAckWrite {
            ids: vec!["6ab0f180a1b2c3d4".into()],
            note: Some("seen".into()),
            ack: true,
            by: "alice".into(),
        });
        let back: Write = serde_json::from_slice(&serde_json::to_vec(&w).unwrap()).unwrap();
        let Write::AnomalyAck(a) = back else {
            panic!("expected an acknowledgement")
        };
        assert_eq!((a.ids.len(), a.ack, a.by.as_str()), (1, true, "alice"));
    }

    #[test]
    fn clu_002_writes_round_trip() {
        let w: Write = ManagedWrite {
            kind: ManagedKind::Forward,
            name: "corp.example".into(),
            body: Some(serde_json::json!({"servers": ["10.0.0.1"]})),
            dry_run: true,
            expect: Some(7),
            by: "alice".into(),
        }
        .into();
        let back: Write = serde_json::from_slice(&serde_json::to_vec(&w).unwrap()).unwrap();
        let Write::Managed {
            kind, expect, by, ..
        } = back
        else {
            panic!("expected managed")
        };
        assert_eq!(
            (kind, expect, by.as_str()),
            (ManagedKind::Forward, Some(7), "alice")
        );
    }
}
