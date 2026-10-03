//! On-disk list sources: `<data_dir>/lists/<name>.src.zst` plus `<name>.meta.json`.
//!
//! REQ: FLT-004 — raw sources are kept (zstd) for offline recompiles and explain line lookups
//! (`spec/05` §3.4 step 1). Writes go to a temp file and are renamed into place, so a crash
//! never leaves a half-written source next to metadata that claims it's complete.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// zstd level for stored sources: fast enough for a Pi, ~4–5× smaller than raw lists.
const ZSTD_LEVEL: i32 = 3;

/// What we know about one list's stored source.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ListMeta {
    /// The URL, path, or `inline` the stored content came from. A different source means
    /// the stored copy and validators no longer apply.
    pub source: String,
    /// HTTP validators for conditional GETs, echoed back verbatim.
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// BLAKE3 of the raw (uncompressed) content.
    pub content_hash: Option<String>,
    /// Raw size and line count of the stored content.
    pub bytes: u64,
    pub lines: u64,
    /// Unix seconds.
    pub last_attempt: Option<u64>,
    /// Last time the source was confirmed current (a download, a 304, or an identical file).
    pub last_success: Option<u64>,
    /// Last time the content actually changed.
    pub last_changed: Option<u64>,
    /// The most recent failure, cleared on success.
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
}

impl ListMeta {
    /// True when a usable stored source exists.
    pub fn has_content(&self) -> bool {
        self.content_hash.is_some()
    }
}

/// The `lists/` directory.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// Opens (and creates) `<data_dir>/lists`.
    pub fn open(data_dir: &Path) -> io::Result<Self> {
        let dir = data_dir.join("lists");
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn src_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.src.zst"))
    }

    fn meta_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.meta.json"))
    }

    /// Loads metadata; a missing or corrupt file means "never fetched" (and is logged by the
    /// caller as such), so a damaged data dir heals on the next refresh.
    pub fn load_meta(&self, name: &str) -> ListMeta {
        let Ok(text) = fs::read_to_string(self.meta_path(name)) else {
            return ListMeta::default();
        };
        let meta: ListMeta = serde_json::from_str(&text).unwrap_or_default();
        // Metadata that claims content we don't have is useless for conditional GETs.
        if meta.has_content() && !self.src_path(name).is_file() {
            return ListMeta {
                content_hash: None,
                etag: None,
                last_modified: None,
                ..meta
            };
        }
        meta
    }

    pub fn save_meta(&self, name: &str, meta: &ListMeta) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(meta).map_err(io::Error::other)?;
        write_atomic(&self.meta_path(name), &json)
    }

    /// Stores new raw content (compressed) atomically.
    pub fn save_source(&self, name: &str, raw: &[u8]) -> io::Result<()> {
        let compressed = zstd::bulk::compress(raw, ZSTD_LEVEL)?;
        write_atomic(&self.src_path(name), &compressed)
    }

    /// Reads and decompresses a stored source.
    pub fn read_source(&self, name: &str) -> io::Result<Vec<u8>> {
        let file = fs::File::open(self.src_path(name))?;
        let mut out = Vec::new();
        zstd::stream::read::Decoder::new(file)?.read_to_end(&mut out)?;
        Ok(out)
    }

    /// Deletes stored files for lists no longer configured. Returns the names removed.
    pub fn prune(&self, keep: &[&str]) -> Vec<String> {
        let mut removed = Vec::new();
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return removed;
        };
        for entry in entries.flatten() {
            let file = entry.file_name();
            let Some(file) = file.to_str() else { continue };
            let Some(name) = file
                .strip_suffix(".src.zst")
                .or_else(|| file.strip_suffix(".meta.json"))
            else {
                continue;
            };
            if !keep.contains(&name) && fs::remove_file(entry.path()).is_ok() {
                removed.push(name.to_owned());
            }
        }
        removed.sort();
        removed.dedup();
        removed
    }
}

/// Write to `<path>.tmp`, fsync, rename over `path`.
fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// BLAKE3 hex digest.
pub fn content_hash(raw: &[u8]) -> String {
    blake3::hash(raw).to_hex().to_string()
}

/// Lines as a parser would see them (a final line without `\n` counts).
#[allow(clippy::naive_bytecount)] // once per download; not worth a dependency
pub fn count_lines(raw: &[u8]) -> u64 {
    let n = raw.iter().filter(|&&b| b == b'\n').count() as u64;
    n + u64::from(raw.last().is_some_and(|&b| b != b'\n'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flt_004_source_round_trip_and_prune() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let raw = b"ads.example.com\ntracker.example.net\n".repeat(100);
        store.save_source("a", &raw).unwrap();
        assert_eq!(store.read_source("a").unwrap(), raw);

        let meta = ListMeta {
            source: "https://example.com/a.txt".into(),
            etag: Some("\"v1\"".into()),
            content_hash: Some(content_hash(&raw)),
            bytes: raw.len() as u64,
            ..ListMeta::default()
        };
        store.save_meta("a", &meta).unwrap();
        assert_eq!(store.load_meta("a"), meta);

        store.save_source("b", b"x\n").unwrap();
        assert_eq!(store.prune(&["a"]), vec!["b".to_owned()]);
        assert!(store.read_source("b").is_err());
        assert!(store.read_source("a").is_ok());
    }

    #[test]
    fn flt_004_meta_without_source_drops_validators() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let meta = ListMeta {
            source: "https://example.com/a.txt".into(),
            etag: Some("\"v1\"".into()),
            content_hash: Some("abc".into()),
            ..ListMeta::default()
        };
        store.save_meta("a", &meta).unwrap();
        let loaded = store.load_meta("a");
        assert_eq!(loaded.etag, None);
        assert!(!loaded.has_content());
        // Corrupt metadata reads as "never fetched".
        fs::write(store.dir().join("c.meta.json"), b"{not json").unwrap();
        assert_eq!(store.load_meta("c"), ListMeta::default());
    }

    #[test]
    fn line_counting() {
        assert_eq!(count_lines(b""), 0);
        assert_eq!(count_lines(b"a"), 1);
        assert_eq!(count_lines(b"a\nb\n"), 2);
        assert_eq!(count_lines(b"a\nb"), 2);
    }
}
