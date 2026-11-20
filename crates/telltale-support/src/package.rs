//! REQ: OPS-011 (ADR-156) — the package: files added through the redactor (or already classified),
//! capped in size, with a manifest and a README, as one `.tar.gz` built in memory.

use serde_json::Value;

use crate::Level;
use crate::archive::{Tar, gzip};
use crate::classify::config_view;
use crate::cluster::{Part, PartFile};
use crate::manifest::{FileEntry, Manifest, Status};
use crate::pseudo::Pseudonyms;
use crate::redact::{Known, Redactor};

/// The smallest a file is cut to when the package is over its cap.
const FLOOR: usize = 2048;

/// What a package needs to start.
#[derive(Debug, Clone)]
pub struct Options {
    pub level: Level,
    /// The package's random key (kept in memory; the pseudonyms can't be reversed without it).
    pub key: [u8; 32],
    /// Names to keep readable (`--reveal`).
    pub reveal: Vec<String>,
    /// When it is made: Unix seconds (for the files' times) and RFC 3339 text (for the manifest).
    pub created_unix: u64,
    pub created: String,
    /// The most bytes of file content (the largest files are truncated first).
    pub max_bytes: usize,
    /// REQ: OPS-011 (ADR-172) — names get labels from a keyed hash (`device-a3f9c2e1`), the same
    /// in every package under this key, instead of numbers by first encounter. The nodes of a
    /// cluster package use it, so one device has one label in every node's files.
    pub keyed_labels: bool,
}

struct Item {
    entry: FileEntry,
    data: Vec<u8>,
    /// Truncate from the front (a log: the newest lines matter).
    keep_tail: bool,
}

/// A package being built.
#[derive(Debug)]
pub struct Package {
    opts: Options,
    red: Redactor,
    files: Vec<Item>,
    missing: Vec<FileEntry>,
    removed: Vec<String>,
    unclassified: Vec<String>,
    notes: Vec<String>,
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("path", &self.entry.path)
            .field("bytes", &self.data.len())
            .finish_non_exhaustive()
    }
}

/// A finished package.
#[derive(Debug)]
pub struct Finished {
    /// The `.tar.gz`.
    pub archive: Vec<u8>,
    pub manifest: Manifest,
    /// The pseudonym map (`pseudonym<TAB>original`), for `--keep-map`; never in the archive.
    pub map: String,
}

impl Package {
    /// Starts a package. Fails (with a reason) only if there are too many names to search for.
    pub fn new(opts: Options, known: &Known) -> Result<Self, String> {
        let mut pseudo = Pseudonyms::new(opts.key).with_reveal(opts.reveal.clone());
        if opts.keyed_labels {
            pseudo = pseudo.with_keyed_labels();
        }
        let mut red = Redactor::new(opts.level, pseudo);
        red.set_known(known)?;
        Ok(Self {
            opts,
            red,
            files: Vec::new(),
            missing: Vec::new(),
            removed: Vec::new(),
            unclassified: Vec::new(),
            notes: Vec::new(),
        })
    }

    /// The redactor (collectors that build structured files use it for their names).
    pub fn redactor(&mut self) -> &mut Redactor {
        &mut self.red
    }

    #[must_use]
    pub fn level(&self) -> Level {
        self.opts.level
    }

    fn push(
        &mut self,
        path: &str,
        collector: &str,
        data: Vec<u8>,
        redactions: std::collections::BTreeMap<String, u32>,
        keep_tail: bool,
    ) {
        let entry = FileEntry {
            path: path.to_owned(),
            collector: collector.to_owned(),
            bytes: data.len(),
            status: Status::Ok,
            note: None,
            redactions,
        };
        self.files.push(Item {
            entry,
            data,
            keep_tail,
        });
    }

    /// Adds free text (a log, an error, a timeline) through the redactor. `keep_tail`: if the
    /// package is over its cap, cut the oldest lines first.
    pub fn add_text(&mut self, path: &str, collector: &str, text: &str, keep_tail: bool) {
        let before = self.red.counts().clone();
        let out = self.red.text(text);
        let counts = self.red.counts().since(&before);
        self.push(path, collector, out.into_bytes(), counts, keep_tail);
    }

    /// Adds text the package made itself, with nothing in it to redact (build facts, counts).
    pub fn add_plain(&mut self, path: &str, collector: &str, text: String) {
        self.push(
            path,
            collector,
            text.into_bytes(),
            std::collections::BTreeMap::new(),
            false,
        );
    }

    /// Adds JSON a collector built from typed, already-safe values.
    pub fn add_json(&mut self, path: &str, collector: &str, value: &Value) {
        let text = serde_json::to_string_pretty(value).unwrap_or_else(|_| "null".to_owned());
        self.add_plain(path, collector, text);
    }

    /// Adds the effective configuration, redacted by class.
    pub fn add_config(&mut self, path: &str, collector: &str, cfg: &Value) {
        let before = self.red.counts().clone();
        let view = config_view(cfg, &mut self.red);
        let counts = self.red.counts().since(&before);
        self.removed.extend(view.dropped);
        self.unclassified.extend(view.unclassified);
        let text = serde_json::to_string_pretty(&view.value).unwrap_or_else(|_| "null".to_owned());
        self.push(path, collector, text.into_bytes(), counts, false);
    }

    /// Records that a collector gave nothing (slow, failed, or not available), so the manifest says so.
    pub fn add_missing(&mut self, path: &str, collector: &str, why: &str) {
        let why = self.red.text(why);
        self.missing.push(FileEntry {
            path: path.to_owned(),
            collector: collector.to_owned(),
            bytes: 0,
            status: Status::Missing,
            note: Some(why),
            redactions: std::collections::BTreeMap::new(),
        });
    }

    /// A line for the manifest's notes (redacted: a path or a name may be in it).
    pub fn note(&mut self, text: &str) {
        let t = self.red.text(text);
        self.notes.push(t);
    }

    /// Cuts the largest files until the content fits the cap.
    fn fit(&mut self) {
        let cap = self.opts.max_bytes;
        loop {
            let total: usize = self.files.iter().map(|f| f.data.len()).sum();
            if total <= cap {
                return;
            }
            let over = total - cap;
            let Some(big) = self
                .files
                .iter_mut()
                .filter(|f| f.data.len() > FLOOR)
                .max_by_key(|f| f.data.len())
            else {
                return;
            };
            let keep = big
                .data
                .len()
                .saturating_sub(over)
                .max(big.data.len() / 2)
                .max(FLOOR);
            truncate(big, keep);
        }
    }

    /// Fits the cap and builds the manifest ([`Self::finish`] and [`Self::finish_part`] share it).
    fn seal(&mut self) -> Manifest {
        self.fit();
        let mut files: Vec<FileEntry> = self.files.iter().map(|f| f.entry.clone()).collect();
        files.extend(self.missing.iter().cloned());
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let redactions = self
            .red
            .counts()
            .0
            .iter()
            .map(|(k, v)| ((*k).to_owned(), *v))
            .collect();
        self.removed.sort();
        self.removed.dedup();
        self.unclassified.sort();
        self.unclassified.dedup();
        let mut notes = self.notes.clone();
        notes.push(
            "Free text (log lines, error messages) is redacted by pattern, which is best effort: look the \
             package over before you attach it."
                .to_owned(),
        );
        Manifest {
            package: "telltale-support",
            format: 1,
            created: self.opts.created.clone(),
            level: self.opts.level,
            level_means: self.opts.level.meaning().to_owned(),
            files,
            redactions,
            config_fields_removed: self.removed.clone(),
            config_fields_unclassified: self.unclassified.clone(),
            notes,
        }
    }

    /// REQ: OPS-011 (ADR-172) — finishes this node's contribution to a cluster package: its files
    /// and manifest as text, for the node that is putting the package together. Everything in
    /// it has been through this node's redactor.
    #[must_use]
    pub fn finish_part(mut self, node: String) -> Part {
        self.part_now(node)
    }

    /// REQ: OPS-011 (ADR-172) — [`Self::finish_part`], cutting the files further (the largest
    /// first) until the part, compressed as it travels, fits `wire_limit` bytes (the cluster
    /// channel carries about a mebibyte per answer). Returns the part and its bytes; if even the
    /// smallest cut doesn't fit, the part as small as it gets (the caller sees the size).
    #[must_use]
    pub fn finish_part_for_wire(mut self, node: &str, wire_limit: usize) -> (Part, Vec<u8>) {
        loop {
            let part = self.part_now(node.to_owned());
            let wire = part.to_wire();
            let total: usize = self.files.iter().map(|f| f.data.len()).sum();
            if wire.len() <= wire_limit || total / 2 < FLOOR {
                return (part, wire);
            }
            self.opts.max_bytes = total / 2;
        }
    }

    fn part_now(&mut self, node: String) -> Part {
        let manifest = self.seal();
        let mut files: Vec<PartFile> = self
            .files
            .iter()
            .map(|it| PartFile {
                path: it.entry.path.clone(),
                text: String::from_utf8_lossy(&it.data).into_owned(),
            })
            .collect();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        Part {
            node,
            manifest: manifest.to_json(),
            redactions: manifest.redactions,
            files,
        }
    }

    /// Finishes the package: fits the cap, writes the manifest and README, and builds the archive.
    #[must_use]
    pub fn finish(mut self) -> Finished {
        let manifest = self.seal();
        let mut tar = Tar::new();
        let t = self.opts.created_unix;
        // The paths are this crate's callers' own fixed names; `Tar::add` refuses a bad one, and the
        // package then lacks that file rather than failing as a whole (the tests name every path).
        let put = |tar: &mut Tar, path: &str, data: &[u8]| {
            let _ = tar.add(path, data, t);
        };
        put(&mut tar, "MANIFEST.json", manifest.to_json().as_bytes());
        put(&mut tar, "README.txt", readme(&manifest).as_bytes());
        let mut items: Vec<&Item> = self.files.iter().collect();
        items.sort_by(|a, b| a.entry.path.cmp(&b.entry.path));
        for it in items {
            put(&mut tar, &it.entry.path, &it.data);
        }
        let archive = gzip(&tar.finish());
        Finished {
            archive,
            manifest,
            map: self.red.map(),
        }
    }
}

/// Cuts `item` to about `keep` bytes at a line boundary and says so.
fn truncate(item: &mut Item, keep: usize) {
    let len = item.data.len();
    let text_cut = |from: usize, to: usize, data: &[u8]| data[from..to].to_vec();
    if item.keep_tail {
        let start = len - keep;
        // The first whole line after the cut.
        let from = item.data[start..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(start, |i| start + i + 1);
        item.data = text_cut(from, len, &item.data);
        item.entry.note = Some(format!(
            "cut to fit the size cap: kept the newest {} of {len} bytes",
            item.data.len()
        ));
    } else {
        let to = item.data[..keep]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(keep, |i| i + 1);
        item.data = text_cut(0, to, &item.data);
        item.entry.note = Some(format!(
            "cut to fit the size cap: kept the first {} of {len} bytes",
            item.data.len()
        ));
    }
    item.entry.bytes = item.data.len();
    item.entry.status = Status::Truncated;
}

fn readme(m: &Manifest) -> String {
    format!(
        "TelltaleDNS support package\n\
         ===========================\n\n\
         Made {created}. Nothing was uploaded: this file stayed on the machine that made it.\n\n\
         Level: {level}\n\
         {means}\n\n\
         Reading it\n\
         ----------\n\
         - MANIFEST.json lists every file, which part of TelltaleDNS wrote it, whether it is whole,\n\
         \x20 and how many values of each kind were removed or replaced (counts, never the values).\n\
         - A pseudonym such as device-3 or 10.4.7.9 stands for the same value in every file of this\n\
         \x20 package, and only in this package. They can't be turned back into the real values from it.\n\
         - Free text (log lines, error messages) is redacted by pattern, which is best effort. Look\n\
         \x20 the package over before you attach it to an issue.\n\
         - A file marked missing in the manifest could not be collected (the reason is there); the\n\
         \x20 rest of the package is complete.\n",
        created = m.created,
        level = m.level,
        means = m.level_means,
    )
}

#[cfg(test)]
#[path = "package_tests.rs"]
mod tests;
