//! Reads one file at a ref from a Git repository (REQ: CLU-003, OPS-005; ADR-049), speaking
//! Git's protocol v2 over a [`Transport`] (smart HTTP in the server; `git upload-pack` in
//! tests). No git binary and no working tree: a few small requests per change.
//!
//! 1. `ls-refs` resolves the ref (a branch, tag, or a commit ID) to a commit.
//! 2. Unless rewinds are allowed, a commits-only fetch proves the new commit descends from
//!    the last one used: history only moves forward (a force-push is refused).
//! 3. A blob-less fetch of that commit walks the tree to the file; then the file's blob alone.
//! 4. With allowed signers, the commit must carry an SSH signature by one of them.
//!
//! Everything is size-bounded by the transport and by [`Request::max_file`].

pub mod object;
pub mod pack;
pub mod pkt;
pub mod sshsig;

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;

use pack::{Kind, Object};
use pkt::{DELIM, FLUSH, Pkt, line};
pub use sshsig::AllowedSigners;

/// A boxed future, for object-safe transports.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Carries protocol-v2 requests to a repository.
pub trait Transport: Send + Sync {
    /// The capability advertisement (`GET …/info/refs?service=git-upload-pack`).
    fn advertise(&self) -> BoxFut<'_, Result<Vec<u8>, String>>;
    /// One stateless request (`POST …/git-upload-pack`); returns the whole response.
    fn upload_pack(&self, body: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>, String>>;
}

/// What to read.
#[derive(Debug, Clone)]
pub struct Request {
    /// Branch, tag, or full commit ID.
    pub git_ref: String,
    /// The file, relative to the repository root (`telltale/shared.toml`).
    pub path: String,
    /// The commit last used, if any.
    pub last: Option<String>,
    /// Accept a commit that doesn't descend from `last` (a force-push or a rewind).
    pub allow_rewind: bool,
    /// When set, commits must be SSH-signed by one of these.
    pub signers: Option<AllowedSigners>,
    /// Largest file and object accepted.
    pub max_file: usize,
}

/// A commit and the file in it.
#[derive(Debug, Clone)]
pub struct Fetched {
    pub commit: String,
    pub author: String,
    /// Committer time, Unix seconds.
    pub time: i64,
    pub subject: String,
    /// The allowed signer who signed it.
    pub signed_by: Option<String>,
    pub content: Vec<u8>,
}

/// The result of a poll.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// The ref still points at `last`.
    Unchanged(String),
    Changed(Fetched),
}

/// Why a poll failed. `refused` means the repository answered but the commit isn't
/// acceptable (rewound, unsigned, missing file): retrying won't help until someone pushes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub message: String,
    pub refused: bool,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn io(message: impl Into<String>) -> Error {
    Error {
        message: message.into(),
        refused: false,
    }
}

fn refuse(message: impl Into<String>) -> Error {
    Error {
        message: message.into(),
        refused: true,
    }
}

/// What the server can do.
#[derive(Debug, Default)]
struct Caps {
    shallow: bool,
    filter: bool,
}

async fn caps(t: &dyn Transport) -> Result<Caps, Error> {
    let raw = t.advertise().await.map_err(io)?;
    let mut c = Caps::default();
    let mut v2 = false;
    for p in pkt::parse(&raw).map_err(io)? {
        if let Pkt::Data(d) = p {
            let s = String::from_utf8_lossy(&d);
            let s = s.trim_end();
            if s == "version 2" {
                v2 = true;
            }
            if let Some(f) = s
                .strip_prefix("fetch=")
                .or(if s == "fetch" { Some("") } else { None })
            {
                c.shallow = f.split(' ').any(|x| x == "shallow");
                c.filter = f.split(' ').any(|x| x == "filter");
            }
        }
    }
    if !v2 {
        return Err(io("the server doesn't speak Git protocol v2"));
    }
    Ok(c)
}

fn is_oid(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn resolve(t: &dyn Transport, git_ref: &str) -> Result<String, Error> {
    if is_oid(git_ref) {
        return Ok(git_ref.to_ascii_lowercase());
    }
    let mut body = line(b"command=ls-refs\n");
    body.extend(line(b"agent=telltale\n"));
    body.extend_from_slice(DELIM);
    body.extend(line(b"peel\n"));
    let names = if git_ref.starts_with("refs/") {
        vec![git_ref.to_owned()]
    } else {
        vec![
            format!("refs/heads/{git_ref}"),
            format!("refs/tags/{git_ref}"),
        ]
    };
    for n in &names {
        body.extend(line(format!("ref-prefix {n}\n").as_bytes()));
    }
    body.extend_from_slice(FLUSH);
    let raw = t.upload_pack(body).await.map_err(io)?;
    for p in pkt::parse(&raw).map_err(io)? {
        let Pkt::Data(d) = p else { continue };
        let s = String::from_utf8_lossy(&d);
        let mut it = s.trim_end().split(' ');
        let (Some(oid), Some(name)) = (it.next(), it.next()) else {
            continue;
        };
        if names.iter().any(|n| n == name) {
            // An annotated tag points at its commit through `peeled:`.
            let peeled = it.find_map(|x| x.strip_prefix("peeled:"));
            return Ok(peeled.unwrap_or(oid).to_owned());
        }
    }
    Err(refuse(format!(
        "the repository has no branch or tag `{git_ref}`"
    )))
}

/// One fetch: returns the objects in the pack.
async fn fetch(
    t: &dyn Transport,
    want: &str,
    have: Option<&str>,
    deepen: Option<u32>,
    filter: Option<&str>,
    limit: usize,
) -> Result<HashMap<String, Object>, Error> {
    let mut body = line(b"command=fetch\n");
    body.extend(line(b"agent=telltale\n"));
    body.extend_from_slice(DELIM);
    body.extend(line(b"no-progress\n"));
    body.extend(line(b"ofs-delta\n"));
    if let Some(d) = deepen {
        body.extend(line(format!("deepen {d}\n").as_bytes()));
    }
    if let Some(f) = filter {
        body.extend(line(format!("filter {f}\n").as_bytes()));
    }
    body.extend(line(format!("want {want}\n").as_bytes()));
    if let Some(h) = have {
        body.extend(line(format!("have {h}\n").as_bytes()));
    }
    body.extend(line(b"done\n"));
    body.extend_from_slice(FLUSH);
    let raw = t.upload_pack(body).await.map_err(io)?;
    let mut pack = Vec::new();
    let mut in_pack = false;
    for p in pkt::parse(&raw).map_err(io)? {
        let Pkt::Data(d) = p else { continue };
        if !in_pack {
            if d.starts_with(b"ERR ") {
                return Err(io(String::from_utf8_lossy(&d[4..]).trim().to_owned()));
            }
            in_pack = d == b"packfile\n";
            continue;
        }
        match d.first() {
            Some(1) => pack.extend_from_slice(&d[1..]),
            Some(3) => return Err(io(String::from_utf8_lossy(&d[1..]).trim().to_owned())),
            _ => {}
        }
    }
    if pack.is_empty() {
        return Ok(HashMap::new());
    }
    pack::read(&pack, limit).map_err(io)
}

/// Whether `old` is an ancestor of `new` among the commits in `objs`.
fn descends(objs: &HashMap<String, Object>, new: &str, old: &str) -> bool {
    let mut queue = VecDeque::from([new.to_owned()]);
    let mut seen = HashSet::new();
    while let Some(id) = queue.pop_front() {
        if id == old {
            return true;
        }
        if !seen.insert(id.clone()) {
            continue;
        }
        if let Some(o) = objs.get(&id).filter(|o| o.kind == Kind::Commit)
            && let Ok(c) = object::commit(&o.data)
        {
            queue.extend(c.parents);
        }
    }
    false
}

/// Walks from `tree` to the file at `path`: its blob ID.
fn find_file(
    objs: &HashMap<String, Object>,
    tree: &str,
    path: &str,
    head: &str,
) -> Result<String, Error> {
    let mut tree_id = tree.to_owned();
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    for (i, part) in parts.iter().enumerate() {
        let tree = objs
            .get(&tree_id)
            .filter(|o| o.kind == Kind::Tree)
            .ok_or_else(|| io("the server didn't send a tree"))?;
        let entry = object::tree(&tree.data)
            .map_err(io)?
            .into_iter()
            .find(|e| e.name == *part)
            .ok_or_else(|| refuse(format!("{path} isn't in {head}")))?;
        if i + 1 == parts.len() {
            if entry.is_tree() {
                return Err(refuse(format!("{path} is a directory")));
            }
            return Ok(entry.oid);
        }
        tree_id = entry.oid;
    }
    Err(refuse("no file path given"))
}

/// Polls the repository: the file at the ref's commit, if the ref moved.
pub async fn fetch_file(t: &dyn Transport, req: &Request) -> Result<Outcome, Error> {
    let caps = caps(t).await?;
    let head = resolve(t, &req.git_ref).await?;
    if req.last.as_deref() == Some(head.as_str()) {
        return Ok(Outcome::Unchanged(head));
    }
    // History only moves forward.
    if let Some(old) = req.last.as_deref()
        && !req.allow_rewind
    {
        let (deepen, filter) = if caps.filter {
            (1000, Some("tree:0"))
        } else {
            (50, None)
        };
        let objs = fetch(
            t,
            &head,
            Some(old),
            caps.shallow.then_some(deepen),
            filter,
            req.max_file.max(1 << 20),
        )
        .await?;
        if !descends(&objs, &head, old) {
            // REQ: CLU-003 (review 05-08) — a history longer than the check fetched looks the
            // same as a rewind; say which it may be when the fetch was cut at its depth.
            let commits = objs.values().filter(|o| o.kind == Kind::Commit).count();
            if caps.shallow && commits >= usize::try_from(deepen).unwrap_or(usize::MAX) {
                return Err(refuse(format!(
                    "{head} doesn't descend from {old}, the commit in use, within the {deepen} commits this check reads: a force-push or rewind, or more than {deepen} commits since it was last read (refused; set allow_rewind once to accept it)"
                )));
            }
            return Err(refuse(format!(
                "{head} doesn't descend from {old}, the commit in use: a force-push or rewind (refused; set allow_rewind to accept it)"
            )));
        }
    }
    let objs = fetch(
        t,
        &head,
        None,
        caps.shallow.then_some(1),
        caps.filter.then_some("blob:none"),
        req.max_file.max(4 << 20),
    )
    .await?;
    let commit_obj = objs
        .get(&head)
        .ok_or_else(|| io("the server didn't send the commit"))?;
    let commit = object::commit(&commit_obj.data).map_err(io)?;
    let signed_by = match &req.signers {
        None => None,
        Some(s) => {
            let sig = commit.signature.as_deref().ok_or_else(|| {
                refuse(format!(
                    "{head} isn't signed, and signed commits are required"
                ))
            })?;
            Some(
                s.verify(sig, &commit.signed_payload)
                    .map_err(|e| refuse(format!("{head}: {e}")))?,
            )
        }
    };
    let blob_id = find_file(&objs, &commit.tree, &req.path, &head)?;
    let content = if let Some(o) = objs.get(&blob_id) {
        o.data.clone()
    } else {
        let more = fetch(t, &blob_id, None, None, None, req.max_file).await?;
        more.get(&blob_id)
            .filter(|o| o.kind == Kind::Blob)
            .map(|o| o.data.clone())
            .ok_or_else(|| io("the server didn't send the file"))?
    };
    if content.len() > req.max_file {
        return Err(refuse(format!(
            "{} is larger than {} bytes",
            req.path, req.max_file
        )));
    }
    Ok(Outcome::Changed(Fetched {
        commit: head,
        author: commit.author,
        time: commit.time,
        subject: commit.subject,
        signed_by,
        content,
    }))
}
