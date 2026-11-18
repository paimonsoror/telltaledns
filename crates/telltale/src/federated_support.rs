//! REQ: OPS-011 (ADR-172) — a cluster support package, from the node that was asked.
//!
//! This node makes a key for the package and sends it, over the cluster's mutually authenticated
//! stream, to every reachable node; each makes and redacts its own part under that key and sends
//! back compressed text, so no real name or address ever crosses the network. This node's own part is
//! made meanwhile, and the parts go side by side into one archive. A node that doesn't answer, or
//! doesn't know the request (an older build), is listed in the manifest with a fixed reason: nothing
//! a peer says is copied into the package.

use std::sync::Arc;
use std::time::Duration;

use telltale_api::SupportPackageOutput;
use telltale_api::model::{SupportCollectRequest, SupportPackageRequest};
use telltale_api::problem::Problem;
use telltale_support::Level;
use telltale_support::cluster::{NodeResult, Part, assemble};
use telltale_support::pseudo::{Category, Pseudonyms};

use super::{Federated, KIND, Read};

/// How long a peer may take to make its part (its collectors have 30 s in all, and then it
/// compresses and cuts).
const DEADLINE: Duration = Duration::from_secs(45);
/// The least a node's share of the size cap may be.
const LEAST_SHARE: usize = 256 * 1024;

/// What to tell the reader about a node that didn't give a part: fixed words, never the peer's own.
fn why(error: &str) -> &'static str {
    let e = error.to_ascii_lowercase();
    if e.contains("unknown variant") || e.contains("bad read") || e.contains("unknown call") {
        "older than cluster packages: it doesn't know the request"
    } else if e.contains("already being made") {
        "busy making another package"
    } else if e.contains("too large") {
        "its part was too large for the cluster channel"
    } else if e.contains("timed out") || e.contains("timeout") {
        "did not answer in time"
    } else {
        "did not answer"
    }
}

impl Federated {
    /// A package of every reachable node's part (see the module's text).
    pub(super) fn cluster_support(
        &self,
        req: &SupportPackageRequest,
        dry_run: bool,
    ) -> Result<SupportPackageOutput, Problem> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| Problem::unavailable("a cluster package can't be made from here"))?;
        let level = req
            .level
            .as_deref()
            .and_then(Level::parse)
            .unwrap_or_default();
        let key = rand::random::<[u8; 32]>();
        let peers = self.peers();
        let share = (crate::support::MAX_BYTES / (peers.len() + 1)).max(LEAST_SHARE);
        let collect = SupportCollectRequest {
            level: req.level.clone(),
            reveal: req.reveal.clone(),
            query_sample: req.query_sample,
            key: crate::support::hex(&key),
            max_bytes: share,
        };
        let body = serde_json::to_vec(&Read::SupportCollect {
            req: Box::new(collect.clone()),
        })
        .map_err(|e| Problem::internal(format!("the request doesn't serialize: {e}")))?;
        let cluster = Arc::clone(&self.cluster);
        // The peers work in parallel, and so does this node.
        let (mine, answers) = std::thread::scope(|s| {
            let calls: Vec<_> = peers
                .iter()
                .map(|peer| {
                    let (rt, cluster, body, peer) =
                        (rt.clone(), Arc::clone(&cluster), body.clone(), peer.clone());
                    s.spawn(move || {
                        let r = rt.block_on(cluster.call(&peer, KIND, body, DEADLINE));
                        (peer, r)
                    })
                })
                .collect();
            let mine = self.local.support_part(&collect);
            let answers: Vec<(String, Result<Vec<u8>, String>)> =
                calls.into_iter().filter_map(|h| h.join().ok()).collect();
            (mine, answers)
        });
        // Our own part failing fails the package (busy, a bad request): there is nothing to add to.
        let mine = Part::from_wire(&mine?)
            .ok_or_else(|| Problem::internal("this node's part couldn't be read back"))?;
        let mut names = Pseudonyms::new(key).with_keyed_labels();
        let mut label = |name: String| {
            if level == Level::Off {
                name
            } else {
                names.name(Category::Node, &name)
            }
        };
        let mut results = vec![NodeResult::Part(mine)];
        for (peer, r) in answers {
            let node = label(self.label_of(&peer));
            results.push(match r {
                Ok(bytes) => Part::from_wire(&bytes).map_or_else(
                    || NodeResult::Missing {
                        node: node.clone(),
                        why: "its answer wasn't a package part".to_owned(),
                    },
                    NodeResult::Part,
                ),
                Err(e) => NodeResult::Missing {
                    node,
                    why: why(&e).to_owned(),
                },
            });
        }
        for m in self
            .cluster
            .members()
            .into_iter()
            .filter(|m| !m.connected && !peers.contains(&m.node_id))
        {
            results.push(NodeResult::Missing {
                node: label(self.label_of(&m.node_id)),
                why: "not connected".to_owned(),
            });
        }
        let asked = results.len();
        let now = self.local.now_unix_seconds();
        let now_us = now.saturating_mul(1_000_000);
        let done = assemble(
            &telltale_api::time::format_us(now_us),
            now,
            level,
            share,
            results,
        );
        tracing::info!(level = %level, nodes = asked, bytes = done.archive.len(), "a cluster support package was made");
        Ok(SupportPackageOutput {
            file_name: format!(
                "telltale-support-cluster-{}.tar.gz",
                crate::support::stamp(now_us)
            ),
            id: None,
            manifest: done.manifest,
            archive: if dry_run { Vec::new() } else { done.archive },
        })
    }
}
