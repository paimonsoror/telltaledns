//! `telltale backup create | restore | show` (REQ: API-007; T6.7, ADR-063): one archive with
//! the configuration files and the node's local data, to move a setup to a new machine or
//! keep a copy (Teleporter parity).
//!
//! A `.ttbk` is a tar stream, zstd-compressed with zstd's frame checksum:
//! - `config/<name>`: the configuration files the node was started with;
//! - `data/state.db`: users, API tokens, devices and names made in the UI, and the audit log,
//!   copied consistently while the server runs (`VACUUM INTO`), without sessions;
//! - `data/rollups.db` (statistics history) and `data/anomaly.json` (learned baselines);
//! - `data/qlog/...` (and `data/qlog-nodes/...`): the query log, only with `--include-qlog`;
//! - `manifest.json`, last: the format version, where things came from, and every entry's
//!   size and BLAKE3 hash.
//!
//! Lists, compiled snapshots, and the cache are rebuilt, so they aren't included. Neither is
//! the cluster identity (`cluster/`, with the CA key). Restore checks every hash before
//! anything is moved into place.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

/// `manifest.json`'s `format`.
const FORMAT: &str = "telltale-backup";
const VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Entry {
    pub path: String,
    pub size: u64,
    pub blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ConfigFile {
    /// Its name in the archive (`config/<name>`).
    pub name: String,
    /// Where it was read from.
    pub original: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Manifest {
    pub format: String,
    pub version: u32,
    pub telltale_version: String,
    /// Unix seconds.
    pub created: u64,
    pub node: String,
    pub data_dir: String,
    pub config_files: Vec<ConfigFile>,
    pub includes_qlog: bool,
    /// The node was a cluster member (its identity isn't in the backup).
    pub cluster_member: bool,
    pub entries: Vec<Entry>,
}

// ------------------------------------------------------------------ tar (ustar + GNU names)

fn octal(field: &mut [u8], n: u64) {
    let s = format!("{n:0width$o}", width = field.len() - 1);
    field[..s.len()].copy_from_slice(s.as_bytes());
}

fn header(name: &str, size: u64, typeflag: u8) -> [u8; 512] {
    let mut h = [0u8; 512];
    let n = name.as_bytes();
    h[..n.len().min(100)].copy_from_slice(&n[..n.len().min(100)]);
    octal(&mut h[100..108], 0o600);
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], 0);
    h[156] = typeflag;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].fill(b' ');
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    let s = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(s.as_bytes());
    h
}

struct TarWriter<W: Write> {
    out: W,
    entries: Vec<Entry>,
}

impl<W: Write> TarWriter<W> {
    fn pad(&mut self, size: u64) -> io::Result<()> {
        let rem = (size % 512) as usize;
        if rem != 0 {
            self.out.write_all(&[0u8; 512][..512 - rem])?;
        }
        Ok(())
    }

    fn head(&mut self, name: &str, size: u64) -> io::Result<()> {
        if name.len() > 99 {
            // GNU long name: a 'L' entry whose data is the name.
            let mut long = name.as_bytes().to_vec();
            long.push(0);
            self.out
                .write_all(&header("././@LongLink", long.len() as u64, b'L'))?;
            self.out.write_all(&long)?;
            self.pad(long.len() as u64)?;
        }
        self.out.write_all(&header(name, size, b'0'))
    }

    /// Streams `src` as `name`, hashing it. Exactly the size seen at open is copied: query
    /// log segments only grow, so that prefix is consistent.
    fn file(&mut self, name: &str, src: &Path) -> io::Result<()> {
        let mut f = File::open(src)?;
        let size = f.metadata()?.len();
        self.head(name, size)?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut left = size;
        while left > 0 {
            let want = usize::try_from(left.min(buf.len() as u64)).unwrap_or(buf.len());
            let n = f.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::other(format!(
                    "{} shrank while being read",
                    src.display()
                )));
            }
            hasher.update(&buf[..n]);
            self.out.write_all(&buf[..n])?;
            left -= n as u64;
        }
        self.pad(size)?;
        self.entries.push(Entry {
            path: name.to_owned(),
            size,
            blake3: hasher.finalize().to_hex().to_string(),
        });
        Ok(())
    }

    fn bytes(&mut self, name: &str, data: &[u8]) -> io::Result<()> {
        self.head(name, data.len() as u64)?;
        self.out.write_all(data)?;
        self.pad(data.len() as u64)
    }

    fn finish(mut self) -> io::Result<W> {
        self.out.write_all(&[0u8; 1024])?;
        Ok(self.out)
    }
}

// ------------------------------------------------------------------ create

/// What `create` wrote.
#[derive(Debug)]
pub(crate) struct Created {
    pub path: PathBuf,
    pub entries: usize,
    pub bytes: u64,
}

/// A consistent copy of an SQLite database (works while the server writes to it).
fn sqlite_copy(src: &Path, dst: &Path, strip: &[&str]) -> Result<(), String> {
    let db = rusqlite::Connection::open_with_flags(
        src,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("{}: {e}", src.display()))?;
    db.execute("VACUUM INTO ?1", [dst.to_string_lossy()])
        .map_err(|e| format!("{}: {e}", src.display()))?;
    if !strip.is_empty() {
        let copy = rusqlite::Connection::open(dst).map_err(|e| e.to_string())?;
        for t in strip {
            // A table that isn't there (an older schema) is fine.
            let _ = copy.execute(&format!("DELETE FROM {t}"), []);
        }
        copy.execute_batch("VACUUM").map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => stack.push(p),
                Ok(t) if t.is_file() => out.push(p),
                _ => {}
            }
        }
    }
    out.sort();
    out
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The default archive name: `telltale-<node>-<UTC time>.ttbk`.
pub(crate) fn default_name(node: &str) -> PathBuf {
    let secs = unix_now();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days.cast_signed() + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let node = crate::pihole::slug(node, 40);
    PathBuf::from(format!(
        "telltale-{}-{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z.ttbk",
        if node.is_empty() { "node" } else { &node },
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    ))
}

/// Writes a backup of the node configured by `files` / `cfg` to `out` (owner-only).
pub(crate) fn create(
    files: &[PathBuf],
    cfg: &telltale_config::Config,
    include_qlog: bool,
    out: &Path,
) -> Result<Created, String> {
    let data = PathBuf::from(cfg.node.data_dir.as_str());
    let stage = data.join(format!(".backup-{}", std::process::id()));
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(&stage).map_err(|e| format!("{}: {e}", stage.display()))?;
    let result = write_archive(files, cfg, &data, &stage, include_qlog, out);
    let _ = fs::remove_dir_all(&stage);
    result
}

fn write_archive(
    files: &[PathBuf],
    cfg: &telltale_config::Config,
    data: &Path,
    stage: &Path,
    include_qlog: bool,
    out: &Path,
) -> Result<Created, String> {
    let tmp = out.with_extension("ttbk.partial");
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let file = opts
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    let mut enc = zstd::stream::Encoder::new(BufWriter::new(file), 6).map_err(|e| e.to_string())?;
    enc.include_checksum(true).map_err(|e| e.to_string())?;
    let mut tar = TarWriter {
        out: enc,
        entries: Vec::new(),
    };
    let err = |e: io::Error| e.to_string();

    let mut config_files = Vec::new();
    let mut names: BTreeMap<String, usize> = BTreeMap::new();
    for f in files {
        let base = f.file_name().map_or_else(
            || "telltale.toml".into(),
            |n| n.to_string_lossy().into_owned(),
        );
        let n = names.entry(base.clone()).or_default();
        *n += 1;
        let name = if *n == 1 { base } else { format!("{n}-{base}") };
        tar.file(&format!("config/{name}"), f)
            .map_err(|e| format!("{}: {e}", f.display()))?;
        config_files.push(ConfigFile {
            name,
            original: fs::canonicalize(f)
                .unwrap_or_else(|_| f.clone())
                .display()
                .to_string(),
        });
    }

    for (db, strip) in [
        ("state.db", &["sessions", "idempotency"][..]),
        ("rollups.db", &[][..]),
    ] {
        let src = data.join(db);
        if src.exists() {
            let copy = stage.join(db);
            sqlite_copy(&src, &copy, strip)?;
            tar.file(&format!("data/{db}"), &copy).map_err(err)?;
        }
    }
    let anomaly = data.join("anomaly.json");
    if anomaly.exists() {
        tar.file("data/anomaly.json", &anomaly).map_err(err)?;
    }
    if include_qlog {
        for dir in ["qlog", "qlog-nodes"] {
            for f in files_under(&data.join(dir)) {
                let Ok(rel) = f.strip_prefix(data) else {
                    continue;
                };
                let rel = rel.to_string_lossy().replace('\\', "/");
                tar.file(&format!("data/{rel}"), &f)
                    .map_err(|e| format!("{}: {e}", f.display()))?;
            }
        }
    }

    let manifest = Manifest {
        format: FORMAT.into(),
        version: VERSION,
        telltale_version: env!("CARGO_PKG_VERSION").into(),
        created: unix_now(),
        node: cfg.node.name.to_string(),
        data_dir: data.display().to_string(),
        config_files,
        includes_qlog: include_qlog,
        cluster_member: data.join("cluster").join("cluster.json").exists(),
        entries: tar.entries.clone(),
    };
    let json = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    tar.bytes("manifest.json", &json).map_err(err)?;
    let entries = tar.entries.len();
    let enc = tar.finish().map_err(err)?;
    let mut w = enc.finish().map_err(err)?;
    w.flush().map_err(err)?;
    drop(w);
    fs::rename(&tmp, out).map_err(|e| format!("{}: {e}", out.display()))?;
    let bytes = fs::metadata(out).map_or(0, |m| m.len());
    Ok(Created {
        path: out.to_path_buf(),
        entries,
        bytes,
    })
}

// ------------------------------------------------------------------ read

/// An archive path is `config/<name>`, `data/<relative path>`, or `manifest.json`, with no
/// `..`, absolute, or empty parts.
fn safe(path: &str) -> bool {
    let p = Path::new(path);
    let ok_parts = p.components().all(|c| matches!(c, Component::Normal(_)));
    ok_parts
        && (path == "manifest.json"
            || path
                .strip_prefix("config/")
                .is_some_and(|n| !n.is_empty() && !n.contains('/'))
            || path.strip_prefix("data/").is_some_and(|n| !n.is_empty()))
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// Reads the archive, calling `sink(path, reader)` for each file in order; returns the
/// manifest. Each entry's size and hash are checked against the manifest at the end.
fn read_archive(
    archive: &Path,
    mut sink: impl FnMut(&str, &mut dyn Read) -> Result<(), String>,
) -> Result<Manifest, String> {
    let f = File::open(archive).map_err(|e| format!("{}: {e}", archive.display()))?;
    let mut r = zstd::stream::Decoder::new(BufReader::new(f))
        .map_err(|e| format!("{}: not a TelltaleDNS backup ({e})", archive.display()))?;
    let mut seen: BTreeMap<String, (u64, String)> = BTreeMap::new();
    let mut manifest: Option<Manifest> = None;
    let mut long: Option<String> = None;
    let bad = |what: &str| format!("{}: corrupt backup ({what})", archive.display());
    loop {
        let mut h = [0u8; 512];
        r.read_exact(&mut h).map_err(|e| bad(&e.to_string()))?;
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let size = u64::from_str_radix(cstr(&h[124..136]).trim(), 8).map_err(|_| bad("size"))?;
        let pad = (512 - size % 512) % 512;
        let mut body = (&mut r).take(size);
        match h[156] {
            b'L' => {
                let mut name = Vec::new();
                body.read_to_end(&mut name)
                    .map_err(|e| bad(&e.to_string()))?;
                long = Some(cstr(&name));
            }
            b'0' | 0 => {
                let name = long.take().unwrap_or_else(|| cstr(&h[..100]));
                if !safe(&name) {
                    return Err(bad(&format!("unexpected path `{name}`")));
                }
                if name == "manifest.json" {
                    let mut json = Vec::new();
                    body.read_to_end(&mut json)
                        .map_err(|e| bad(&e.to_string()))?;
                    manifest =
                        Some(serde_json::from_slice(&json).map_err(|e| bad(&e.to_string()))?);
                } else {
                    let mut hashing = HashingReader {
                        inner: &mut body,
                        hasher: blake3::Hasher::new(),
                        count: 0,
                    };
                    sink(&name, &mut hashing)?;
                    io::copy(&mut hashing, &mut io::sink()).map_err(|e| bad(&e.to_string()))?;
                    seen.insert(
                        name,
                        (
                            hashing.count,
                            hashing.hasher.finalize().to_hex().to_string(),
                        ),
                    );
                }
            }
            _ => return Err(bad("unexpected entry type")),
        }
        io::copy(&mut body, &mut io::sink()).map_err(|e| bad(&e.to_string()))?;
        io::copy(&mut (&mut r).take(pad), &mut io::sink()).map_err(|e| bad(&e.to_string()))?;
    }
    // Reading to the end lets zstd check its frame checksum.
    io::copy(&mut r, &mut io::sink()).map_err(|e| bad(&e.to_string()))?;
    let m = manifest.ok_or_else(|| bad("no manifest"))?;
    if m.format != FORMAT {
        return Err(bad("not a TelltaleDNS backup"));
    }
    if m.version > VERSION {
        return Err(format!(
            "{}: made by a newer TelltaleDNS (backup format {}); upgrade to restore it",
            archive.display(),
            m.version
        ));
    }
    let want: BTreeMap<String, (u64, String)> = m
        .entries
        .iter()
        .map(|e| (e.path.clone(), (e.size, e.blake3.clone())))
        .collect();
    if want != seen {
        return Err(bad("contents don't match the manifest"));
    }
    Ok(m)
}

struct HashingReader<'a, R: Read> {
    inner: &'a mut R,
    hasher: blake3::Hasher,
    count: u64,
}

impl<R: Read> Read for HashingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.count += n as u64;
        Ok(n)
    }
}

/// `telltale backup show`: checks the archive and returns its manifest.
pub(crate) fn show(archive: &Path) -> Result<Manifest, String> {
    read_archive(archive, |_, _| Ok(()))
}

// ------------------------------------------------------------------ restore

/// Where `restore` put things.
#[derive(Debug)]
pub(crate) struct Restored {
    pub manifest: Manifest,
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
    pub files: usize,
}

/// Restores `archive`: data into `data_dir` (default: where it came from) and config files
/// into `config_dir` (default: the first config file's directory). Nothing is moved into
/// place until every entry checks out; existing files are only replaced with `force`.
pub(crate) fn restore(
    archive: &Path,
    data_dir: Option<&Path>,
    config_dir: Option<&Path>,
    force: bool,
) -> Result<Restored, String> {
    // The manifest comes last, so read once to learn the defaults (and check everything).
    let m = show(archive)?;
    let data_dir = data_dir.map_or_else(|| PathBuf::from(&m.data_dir), Path::to_path_buf);
    let config_dir = config_dir.map_or_else(
        || {
            m.config_files
                .first()
                .and_then(|c| Path::new(&c.original).parent().map(Path::to_path_buf))
                .unwrap_or_else(|| PathBuf::from("/etc/telltale"))
        },
        Path::to_path_buf,
    );
    let target = |path: &str| -> PathBuf {
        match path.strip_prefix("config/") {
            Some(n) => config_dir.join(n),
            None => data_dir.join(path.strip_prefix("data/").unwrap_or(path)),
        }
    };
    let existing: Vec<String> = m
        .entries
        .iter()
        .map(|e| target(&e.path))
        .filter(|p| p.exists())
        .map(|p| p.display().to_string())
        .collect();
    if !existing.is_empty() && !force {
        return Err(format!(
            "these files exist (stop TelltaleDNS, then use --force to replace them): {}",
            existing.join(", ")
        ));
    }
    fs::create_dir_all(&data_dir).map_err(|e| format!("{}: {e}", data_dir.display()))?;
    fs::create_dir_all(&config_dir).map_err(|e| format!("{}: {e}", config_dir.display()))?;
    let stage = data_dir.join(format!(".restore-{}", std::process::id()));
    let _ = fs::remove_dir_all(&stage);
    let result = restore_staged(archive, &m, &stage, &target, &data_dir);
    let _ = fs::remove_dir_all(&stage);
    let files = result?;
    Ok(Restored {
        manifest: m,
        data_dir,
        config_dir,
        files,
    })
}

fn restore_staged(
    archive: &Path,
    m: &Manifest,
    stage: &Path,
    target: &dyn Fn(&str) -> PathBuf,
    data_dir: &Path,
) -> Result<usize, String> {
    // Extract to staging; read_archive checks every hash against the manifest.
    let mut staged = Vec::new();
    let again = read_archive(archive, |path, r| {
        let p = stage.join(path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut f = opts.open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        io::copy(r, &mut f).map_err(|e| format!("{}: {e}", p.display()))?;
        staged.push(path.to_owned());
        Ok(())
    })?;
    if again != *m {
        return Err(format!(
            "{}: changed while being restored",
            archive.display()
        ));
    }
    // Owned like the data directory (restore usually runs as root for a service user).
    #[cfg(unix)]
    let owner = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(data_dir).ok().map(|md| (md.uid(), md.gid()))
    };
    for path in &staged {
        let to = target(path);
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let from = stage.join(path);
        if fs::rename(&from, &to).is_err() {
            // Config files may live on another filesystem.
            fs::copy(&from, &to).map_err(|e| format!("{}: {e}", to.display()))?;
        }
        #[cfg(unix)]
        if let Some((uid, gid)) = owner {
            let _ = std::os::unix::fs::chown(&to, Some(uid), Some(gid));
        }
    }
    Ok(staged.len())
}

#[cfg(test)]
mod tests;
