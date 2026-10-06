//! Compiled filter snapshot: on-disk layout, manifest, and loading (`spec/05` §3, `02` §5).
//!
//! A snapshot directory holds:
//! - `subtree-<n>.fst`, `exact-<n>.fst`, `subdomains-<n>.fst` (n < `fst_shards`):
//!   reversed-label keys (`com.example.ads.`) → index into `listsets.bin`. A key's shard is a
//!   stable hash of its first two labels ([`shard_of`]), so every suffix of a query name with
//!   two or more labels lives in one shard and a lookup touches at most two shards per scope.
//!   Shards let the compiler build FSTs in parallel; it makes one per compile thread, and the
//!   manifest records how many.
//! - `listsets.bin`: the interned [`ListSetTable`]
//! - `modrules.fst` + `modrules.json`: rules with `$client`/`$dnstype`/`$denyallow`/
//!   `$dnsrewrite` (key → range of rules, evaluated only on a hit, §3.3)
//! - `regex.json`: regex rules with metadata (§3.2)
//! - `manifest.json`: version, list IDs, per-blob BLAKE3 + size, compile stats
//!
//! Blobs are content-addressed by their hash in the manifest, so cluster sync (CLU-003) ships
//! only blobs whose hash changed.

use std::fs;
use std::io;
use std::path::Path;

use fst::Map;
use serde::{Deserialize, Serialize};

pub use crate::compile::listset::{Class, ListSetTable};
use crate::parse::Scope;

/// Snapshot format; bump on incompatible layout changes.
pub const FORMAT: u32 = 1;

/// Most FST shards per scope (one per compile thread).
pub const MAX_FST_SHARDS: usize = 16;
/// Scope names in FST file names, indexed like [`Scope`] order: subtree, exact, subdomains.
pub const SCOPE_NAMES: [&str; 3] = ["subtree", "exact", "subdomains"];

/// File name of one domain FST shard.
pub fn domain_fst(scope: usize, shard: usize) -> String {
    format!("{}-{shard}.fst", SCOPE_NAMES[scope])
}

/// The shard (of `shards`) of a reversed key, scope byte stripped: FNV-1a of the key up to
/// the end of its second label (`com.example.` for `com.example.ads.`), or of the whole key
/// if it has one label.
pub fn shard_of(key: &[u8], shards: usize) -> usize {
    if shards <= 1 {
        return 0;
    }
    let mut dots = 0;
    let mut end = key.len();
    for (i, &b) in key.iter().enumerate() {
        if b == b'.' {
            dots += 1;
            if dots == 2 {
                end = i + 1;
                break;
            }
        }
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in &key[..end] {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    usize::try_from(h % shards as u64).unwrap_or(0)
}

pub const LISTSETS: &str = "listsets.bin";
pub const MODRULES_FST: &str = "modrules.fst";
pub const MODRULES: &str = "modrules.json";
pub const REGEX: &str = "regex.json";
pub const MANIFEST: &str = "manifest.json";

/// Every blob file, in manifest order, for a snapshot with `shards` FST shards.
pub fn blob_names(shards: usize) -> Vec<String> {
    let mut v: Vec<String> = (0..SCOPE_NAMES.len())
        .flat_map(|scope| (0..shards).map(move |shard| domain_fst(scope, shard)))
        .collect();
    v.extend([LISTSETS, MODRULES_FST, MODRULES, REGEX].map(String::from));
    v
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub version: u64,
    /// Domain FST shards per scope.
    pub fst_shards: u32,
    /// Unix seconds.
    pub created: u64,
    /// List ID = index. Bit `i` of every list bitset refers to `lists[i]`.
    pub lists: Vec<ManifestList>,
    pub blobs: Vec<Blob>,
    pub stats: CompileStats,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestList {
    pub id: u16,
    pub name: String,
    /// BLAKE3 of the list source this snapshot was compiled from.
    pub source_hash: String,
    pub kind: telltale_config::ListKind,
    #[serde(rename = "match")]
    pub match_mode: telltale_config::ListMatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blob {
    pub name: String,
    pub blake3: String,
    pub bytes: u64,
}

/// Totals and per-list counts (`spec/05` §6).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CompileStats {
    /// Distinct names per scope (one name can carry several lists).
    pub subtree_names: u64,
    pub exact_names: u64,
    pub subdomains_names: u64,
    pub listsets: u64,
    pub modrules: u64,
    pub regexes: u64,
    /// Rules removed by `$badfilter`.
    pub badfiltered: u64,
    /// Regexes the engine refused (size limits); listed in the compile report.
    pub regex_rejected: u64,
    /// Bytes of FSTs + list sets per distinct name (the `05` §3.1 ≤ 12 B target).
    pub bytes_per_name: f64,
    pub per_list: Vec<ListCompileStats>,
    /// REQ: OBS-009 (T7.14) — names two lists share, for each pair that shares any (list IDs
    /// `a` < `b`): the overlap matrix behind "this list adds nothing".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overlap: Vec<ListOverlap>,
}

/// Names lists `a` and `b` both hold.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListOverlap {
    pub a: u16,
    pub b: u16,
    pub names: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListCompileStats {
    pub id: u16,
    /// Names, regexes, and modifier rules this list contributes (`telltale_list_entries`).
    pub entries: u64,
    /// Names no other compiled list has (§6 "unique contribution").
    pub unique: u64,
    pub invalid: u64,
    pub unsupported: u64,
}

/// A rule kept outside the domain FSTs because of its modifiers (§3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModRule {
    pub list: u16,
    pub line: u32,
    pub scope: ScopeTag,
    pub allow: bool,
    pub important: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client: Vec<NegValue<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dnstype: Vec<NegValue<u16>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denyallow: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnsrewrite: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegValue<T> {
    pub value: T,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub negated: bool,
}

/// Serialized [`Scope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeTag {
    Subtree,
    Exact,
    Subdomains,
}

impl From<Scope> for ScopeTag {
    fn from(s: Scope) -> Self {
        match s {
            Scope::Subtree => Self::Subtree,
            Scope::Exact => Self::Exact,
            Scope::Subdomains => Self::Subdomains,
        }
    }
}

/// A regex rule (§3.2). Patterns match the lowercase query name without the trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegexRule {
    pub pattern: String,
    pub list: u16,
    pub line: u32,
    pub allow: bool,
    pub important: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub invert: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dnstype: Vec<NegValue<u16>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct ModRules {
    /// Sorted by key; `modrules.fst` maps each key to `start << 32 | count`.
    pub(crate) rules: Vec<ModRule>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Regexes {
    pub(crate) rules: Vec<RegexRule>,
}

/// A loaded snapshot. FSTs are read into memory for now (mmap needs `unsafe`, which only
/// `telltale-net` may use; ADR-018).
#[derive(Debug)]
pub struct Snapshot {
    pub manifest: Manifest,
    /// Domain FSTs: `[scope][shard]`, scopes in [`SCOPE_NAMES`] order.
    pub domains: [Vec<Map<Vec<u8>>>; 3],
    pub listsets: ListSetTable,
    pub modrules_index: Map<Vec<u8>>,
    pub modrules: Vec<ModRule>,
    pub regexes: Vec<RegexRule>,
}

/// One suffix of a query name that has an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainHit {
    pub scope: Scope,
    /// The matching name (`example.com` for a hit on `ads.example.com`).
    pub name: String,
    pub listset: u32,
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

impl Snapshot {
    /// Loads `dir`, verifying every blob against the manifest's size and BLAKE3.
    pub fn open(dir: &Path) -> io::Result<Self> {
        let manifest: Manifest = serde_json::from_slice(&fs::read(dir.join(MANIFEST))?)
            .map_err(|e| invalid(format!("manifest: {e}")))?;
        if manifest.format != FORMAT {
            return Err(invalid(format!(
                "snapshot format {} (this build reads {FORMAT})",
                manifest.format
            )));
        }
        let read = |name: &str| -> io::Result<Vec<u8>> {
            let data = fs::read(dir.join(name))?;
            let blob = manifest
                .blobs
                .iter()
                .find(|b| b.name == name)
                .ok_or_else(|| invalid(format!("{name} missing from manifest")))?;
            if data.len() as u64 != blob.bytes
                || blake3::hash(&data).to_hex().as_str() != blob.blake3
            {
                return Err(invalid(format!(
                    "{name}: content doesn't match the manifest"
                )));
            }
            Ok(data)
        };
        let fst = |name: &str| -> io::Result<Map<Vec<u8>>> {
            Map::new(read(name)?).map_err(|e| invalid(format!("{name}: {e}")))
        };
        let modrules: ModRules = serde_json::from_slice(&read(MODRULES)?)
            .map_err(|e| invalid(format!("{MODRULES}: {e}")))?;
        let regexes: Regexes =
            serde_json::from_slice(&read(REGEX)?).map_err(|e| invalid(format!("{REGEX}: {e}")))?;
        let shards = manifest.fst_shards as usize;
        if !(1..=MAX_FST_SHARDS).contains(&shards) {
            return Err(invalid(format!("manifest: {shards} FST shards")));
        }
        let mut domains: [Vec<Map<Vec<u8>>>; 3] = Default::default();
        for (scope, maps) in domains.iter_mut().enumerate() {
            for shard in 0..shards {
                maps.push(fst(&domain_fst(scope, shard))?);
            }
        }
        Ok(Self {
            domains,
            listsets: ListSetTable::read(&read(LISTSETS)?)?,
            modrules_index: fst(MODRULES_FST)?,
            modrules: modrules.rules,
            regexes: regexes.rules,
            manifest,
        })
    }

    /// Every suffix of `qname` with a domain entry, most specific last. Simple and allocating:
    /// for tests and explain; the query path uses the matcher's walk (T2.4).
    pub fn domain_hits(&self, qname: &str) -> Vec<DomainHit> {
        let name = qname.trim_end_matches('.').to_ascii_lowercase();
        let labels: Vec<&str> = name.split('.').collect();
        let mut hits = Vec::new();
        let mut key = String::new();
        for depth in 1..=labels.len() {
            key.push_str(labels[labels.len() - depth]);
            key.push('.');
            let full = depth == labels.len();
            let suffix = labels[labels.len() - depth..].join(".");
            let shard = shard_of(key.as_bytes(), self.domains[0].len());
            let mut check = |scope_idx: usize, scope: Scope| {
                if let Some(v) = self.domains[scope_idx][shard].get(key.as_bytes()) {
                    hits.push(DomainHit {
                        scope,
                        name: suffix.clone(),
                        listset: u32::try_from(v).unwrap_or(u32::MAX),
                    });
                }
            };
            check(0, Scope::Subtree);
            if full {
                check(1, Scope::Exact);
            } else {
                check(2, Scope::Subdomains);
            }
        }
        hits
    }

    /// Modifier rules attached to exactly `name` (any scope).
    pub fn modrules_for(&self, name: &str) -> &[ModRule] {
        let key = crate::compile::reversed_key(name);
        self.modrules_index
            .get(&key)
            .and_then(|v| {
                let start = usize::try_from(v >> 32).ok()?;
                let count = usize::try_from(v & 0xffff_ffff).ok()?;
                self.modrules.get(start..start + count)
            })
            .unwrap_or(&[])
    }

    /// The list name for an ID.
    pub fn list_name(&self, id: u16) -> Option<&str> {
        self.manifest
            .lists
            .get(usize::from(id))
            .map(|l| l.name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flt_003_shards_follow_the_first_two_labels() {
        let n = 4;
        let s = shard_of(b"com.example.", n);
        assert_eq!(shard_of(b"com.example.ads.", n), s);
        assert_eq!(shard_of(b"com.example.a.b.c.", n), s);
        assert!(shard_of(b"com.", n) < n);
        assert_eq!(shard_of(b"com.example.ads.", 1), 0);
        // Spread: 10k distinct registrable names fill every shard reasonably evenly.
        let mut counts = [0usize; 4];
        for i in 0..10_000 {
            counts[shard_of(format!("com.name{i}.").as_bytes(), n)] += 1;
        }
        assert!(counts.iter().all(|&c| c > 2_000), "{counts:?}");
    }
}
