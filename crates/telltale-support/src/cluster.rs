//! REQ: OPS-011 (ADR-172) — a cluster support package: one *part* per node, each made and
//! redacted by the node it came from under one key, put side by side in one archive with a summary.
//! A node's data never leaves it unredacted: only its part does, and the node that puts the package
//! together (the one asked) never sees another node's real names or addresses.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Level;
use crate::archive::{Tar, crc32, gzip};

/// The most a node's part may hold once unpacked (a defence against a part that claims to be
/// small and inflates to a lot; the cap on the whole package is far below it).
const MAX_PART_UNPACKED: usize = 64 * 1024 * 1024;

/// One file of a node's part: its path inside the node's folder, and its (redacted) text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartFile {
    pub path: String,
    pub text: String,
}

/// One node's contribution: what its own package would hold, as text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Part {
    /// The node's label: its pseudonym (or its name, at the level that shows real values).
    pub node: String,
    /// That node's `MANIFEST.json`.
    pub manifest: String,
    /// Values removed or replaced in it, by kind.
    pub redactions: BTreeMap<String, u32>,
    pub files: Vec<PartFile>,
}

impl Part {
    /// The part as it travels between nodes: JSON, gzip-compressed (the cluster channel carries
    /// at most about a mebibyte per answer, and text shrinks a lot).
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        gzip(&serde_json::to_vec(self).unwrap_or_default())
    }

    /// A part read back from [`Self::to_wire`]; `None` if the bytes aren't one.
    #[must_use]
    pub fn from_wire(bytes: &[u8]) -> Option<Self> {
        Self::from_wire_within(bytes, MAX_PART_UNPACKED)
    }

    /// [`Self::from_wire`] with its own limit on the unpacked size.
    #[must_use]
    pub fn from_wire_within(bytes: &[u8], limit: usize) -> Option<Self> {
        if bytes.len() < 18 || bytes[..3] != [0x1f, 0x8b, 8] {
            return None;
        }
        let body = &bytes[10..bytes.len() - 8];
        let json = miniz_oxide::inflate::decompress_to_vec_with_limit(body, limit).ok()?;
        let want = u32::from_le_bytes(bytes[bytes.len() - 8..bytes.len() - 4].try_into().ok()?);
        (crc32(&json) == want).then_some(())?;
        serde_json::from_slice(&json).ok()
    }

    /// Bytes of file content in the part.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.files.iter().map(|f| f.text.len()).sum()
    }
}

/// What the node that is putting the package together got from one node.
#[derive(Debug, Clone)]
pub enum NodeResult {
    Part(Part),
    /// The node didn't answer, answered too late, or can't make parts (an older version).
    Missing {
        node: String,
        why: String,
    },
}

#[derive(Debug, Serialize)]
struct NodeSummary {
    node: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    files: usize,
    bytes: usize,
}

#[derive(Debug, Serialize)]
struct ClusterManifest {
    package: &'static str,
    format: u32,
    kind: &'static str,
    created: String,
    level: Level,
    level_means: String,
    nodes: Vec<NodeSummary>,
    /// Values removed or replaced in the whole package, by kind.
    redactions: BTreeMap<String, u32>,
    notes: Vec<String>,
}

/// A finished cluster package.
#[derive(Debug)]
pub struct ClusterFinished {
    /// The `.tar.gz`.
    pub archive: Vec<u8>,
    /// `MANIFEST.json` as a value.
    pub manifest: serde_json::Value,
}

/// A folder name for a node: letters, digits, `-`, `_`, and `.`; never empty or hidden.
fn folder(node: &str, taken: &[String]) -> String {
    let cleaned: String = node
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_start_matches('.');
    let base = if trimmed.is_empty() { "node" } else { trimmed };
    let mut name = base.to_owned();
    let mut n = 1;
    while taken.contains(&name) {
        n += 1;
        name = format!("{base}-{n}");
    }
    name
}

/// Puts the nodes' parts into one package. A part over `share` bytes (what the caller gave each
/// node: the size cap divided by the number of nodes) is left out and listed as missing, and so is a
/// file whose path is not safe: a node that honours its share and the rules never trips either.
#[must_use]
pub fn assemble(
    created: &str,
    created_unix: u64,
    level: Level,
    share: usize,
    results: Vec<NodeResult>,
) -> ClusterFinished {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    let mut rows = Vec::new();
    let mut folders: Vec<String> = Vec::new();
    let mut redactions: BTreeMap<String, u32> = BTreeMap::new();
    let mut notes = vec![
        "Each node made and redacted its own part under one key, so a device has the same pseudonym in every node's files; \
         free text is redacted by pattern, which is best effort: look the package over before you attach it."
            .to_owned(),
    ];
    for r in results {
        match r {
            NodeResult::Missing { node, why } => rows.push(NodeSummary {
                node,
                status: "missing",
                note: Some(why),
                files: 0,
                bytes: 0,
            }),
            NodeResult::Part(p) if p.bytes() > share => {
                let held = p.bytes();
                rows.push(NodeSummary {
                    node: p.node,
                    status: "missing",
                    note: Some(format!(
                        "its part held {held} bytes, over its share of the size cap ({share})"
                    )),
                    files: 0,
                    bytes: 0,
                });
            }
            NodeResult::Part(p) => {
                let dir = folder(&p.node, &folders);
                folders.push(dir.clone());
                let (mut kept, mut bytes) = (0, 0);
                for f in &p.files {
                    let path = format!("nodes/{dir}/{}", f.path);
                    if path_allowed(&path) {
                        kept += 1;
                        bytes += f.text.len();
                        entries.push((path, f.text.clone().into_bytes()));
                    } else {
                        notes.push(format!(
                            "a file of {dir} had a path that is not allowed and was left out"
                        ));
                    }
                }
                entries.push((
                    format!("nodes/{dir}/MANIFEST.json"),
                    p.manifest.into_bytes(),
                ));
                for (k, v) in &p.redactions {
                    *redactions.entry(k.clone()).or_insert(0) += v;
                }
                rows.push(NodeSummary {
                    node: dir,
                    status: "ok",
                    note: None,
                    files: kept,
                    bytes,
                });
            }
        }
    }
    let manifest = ClusterManifest {
        package: "telltale-support",
        format: 2,
        kind: "cluster",
        created: created.to_owned(),
        level,
        level_means: level.meaning().to_owned(),
        nodes: rows,
        redactions,
        notes,
    };
    let text = serde_json::to_string_pretty(&manifest).unwrap_or_else(|_| "{}".to_owned());
    let mut tar = Tar::new();
    let _ = tar.add("MANIFEST.json", text.as_bytes(), created_unix);
    let _ = tar.add("README.txt", readme(&manifest).as_bytes(), created_unix);
    for (path, data) in &entries {
        let _ = tar.add(path, data, created_unix);
    }
    ClusterFinished {
        archive: gzip(&tar.finish()),
        manifest: serde_json::to_value(&manifest).unwrap_or(serde_json::Value::Null),
    }
}

/// Whether a path from another node may go into the archive. On top of the archive's own rules (no
/// empty or `..` part, not absolute, ASCII, no control character): no hidden part, and no character
/// that a Windows extractor reads as a separator or a drive (`\\`, `:`).
fn path_allowed(path: &str) -> bool {
    !path.split('/').any(|part| part.starts_with('.'))
        && !path.contains(['\\', ':'])
        && Tar::new().add(path, &[], 0).is_ok()
}

fn readme(m: &ClusterManifest) -> String {
    let listed: String = m
        .nodes
        .iter()
        .map(|n| match &n.note {
            Some(why) => format!("  - {}: {} ({why})\n", n.node, n.status),
            None => format!("  - {}: {}, {} files\n", n.node, n.status, n.files),
        })
        .collect();
    format!(
        "TelltaleDNS support package, cluster\n\
         ====================================\n\n\
         Made {created}. Nothing was uploaded: this file stayed on the machine that made it.\n\n\
         Level: {level}\n\
         {means}\n\n\
         Reading it\n\
         ----------\n\
         - MANIFEST.json lists the nodes and whether each answered; every node's folder under nodes/ has\n\
         \x20 its own MANIFEST.json and files, laid out as in a package from that one node.\n\
         - Each node redacted its own data before it left the node, under one key made for this package:\n\
         \x20 a device, group, or host has the same pseudonym (device-a3f9c2e1) in every node's files, and\n\
         \x20 only in this package. They can't be turned back into the real values from it.\n\
         - Free text (log lines, error messages) is redacted by pattern, which is best effort. Look\n\
         \x20 the package over before you attach it to an issue.\n\
         - A node marked missing did not answer in time, is older than this feature, or was over its\n\
         \x20 share of the size cap; the reason is next to it.\n\n\
         Nodes\n\
         -----\n\
         {listed}",
        created = m.created,
        level = m.level,
        means = m.level_means,
    )
}

#[cfg(test)]
#[path = "cluster_tests.rs"]
mod tests;
