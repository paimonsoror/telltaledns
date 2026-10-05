//! REQ: CLU-003 (ADR-049) — the Git source against real `git upload-pack` (protocol v2):
//! fetch, unchanged, forward-only history, missing files, SSH-signed commits, tags, and
//! deltified packs.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::many_single_char_names,
    clippy::needless_pass_by_value,
    clippy::sliced_string_as_bytes,
    clippy::map_unwrap_or,
    clippy::format_push_string
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use telltale_git::{AllowedSigners, BoxFut, Outcome, Request, Transport, fetch_file, pack};

/// `git upload-pack --stateless-rpc`, as `git http-backend` runs it.
struct Local {
    dir: PathBuf,
    /// Hide the `filter` capability (a server without partial clone).
    no_filter: bool,
}

impl Local {
    fn run(&self, advertise: bool, body: Vec<u8>) -> Result<Vec<u8>, String> {
        use std::io::Write as _;
        let mut cmd = Command::new("git");
        cmd.arg("upload-pack").arg("--stateless-rpc");
        if advertise {
            cmd.arg("--advertise-refs");
        }
        let mut child = cmd
            .arg(&self.dir)
            .env("GIT_PROTOCOL", "version=2")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&body)
            .map_err(|e| e.to_string())?;
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        let mut o = out.stdout;
        if advertise && self.no_filter {
            // Drop the capability, then re-frame (the lengths changed).
            o = reframe(
                String::from_utf8_lossy(&o)
                    .replace(" filter", "")
                    .as_bytes(),
            );
        }
        Ok(o)
    }
}

/// Re-encodes pkt-lines whose length prefix no longer matches (after editing them).
fn reframe(b: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(b);
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while rest.len() >= 4 {
        let head = &rest[..4];
        if head == "0000" || head == "0001" {
            out.extend_from_slice(head.as_bytes());
            rest = &rest[4..];
            continue;
        }
        let nl = rest[4..].find('\n').map_or(rest.len(), |i| i + 5);
        out.extend(telltale_git::pkt::line(rest[4..nl].as_bytes()));
        rest = &rest[nl..];
    }
    out
}

impl Transport for Local {
    fn advertise(&self) -> BoxFut<'_, Result<Vec<u8>, String>> {
        Box::pin(async move { self.run(true, Vec::new()) })
    }
    fn upload_pack(&self, body: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>, String>> {
        Box::pin(async move { self.run(false, body) })
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args([
            "-c",
            "user.name=Ada",
            "-c",
            "user.email=ada@example.com",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn repo() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("r");
    std::fs::create_dir_all(dir.join("telltale")).unwrap();
    git(&dir, &["init", "-q", "-b", "main"]);
    git(&dir, &["config", "uploadpack.allowFilter", "true"]);
    git(&dir, &["config", "uploadpack.allowAnySHA1InWant", "true"]);
    (tmp, dir)
}

fn commit(dir: &Path, content: &str, msg: &str) -> String {
    std::fs::write(dir.join("telltale/shared.toml"), content).unwrap();
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", msg]);
    git(dir, &["rev-parse", "HEAD"])
}

fn req(last: Option<String>) -> Request {
    Request {
        git_ref: "main".into(),
        path: "telltale/shared.toml".into(),
        last,
        allow_rewind: false,
        signers: None,
        max_file: 1 << 20,
    }
}

fn changed(o: Outcome) -> telltale_git::Fetched {
    match o {
        Outcome::Changed(f) => f,
        Outcome::Unchanged(c) => panic!("unexpectedly unchanged at {c}"),
    }
}

// REQ: CLU-003 — the file at the ref's commit, with provenance; then nothing until it moves.
#[tokio::test]
async fn clu_003_git_source_reads_the_file_and_notices_changes() {
    for no_filter in [false, true] {
        let (_tmp, dir) = repo();
        std::fs::write(dir.join("README.md"), "other files are ignored\n").unwrap();
        let c1 = commit(&dir, "[[record]]\nname = \"a.test\"\n", "first");
        let t = Local {
            dir: dir.clone(),
            no_filter,
        };
        let f = changed(fetch_file(&t, &req(None)).await.unwrap());
        assert_eq!(f.commit, c1);
        assert_eq!(f.author, "Ada <ada@example.com>");
        assert_eq!(f.subject, "first");
        assert_eq!(f.content, b"[[record]]\nname = \"a.test\"\n");
        assert!(
            matches!(fetch_file(&t, &req(Some(c1.clone()))).await.unwrap(), Outcome::Unchanged(c) if c == c1)
        );
        let c2 = commit(&dir, "[[record]]\nname = \"b.test\"\n", "second");
        let f = changed(fetch_file(&t, &req(Some(c1.clone()))).await.unwrap());
        assert_eq!(
            (f.commit.as_str(), f.content.as_slice()),
            (c2.as_str(), &b"[[record]]\nname = \"b.test\"\n"[..])
        );
        // A force-push to a commit that doesn't descend from the one in use is refused.
        git(&dir, &["reset", "-q", "--hard", &c1]);
        let c3 = commit(&dir, "rewritten\n", "rewritten");
        let e = fetch_file(&t, &req(Some(c2.clone()))).await.unwrap_err();
        assert!(e.refused && e.message.contains("doesn't descend"), "{e:?}");
        let mut r = req(Some(c2.clone()));
        r.allow_rewind = true;
        assert_eq!(changed(fetch_file(&t, &r).await.unwrap()).commit, c3);
        // A missing file is refused; a commit ID works as the ref.
        let mut r = req(None);
        r.path = "telltale/missing.toml".into();
        assert!(fetch_file(&t, &r).await.unwrap_err().refused);
        let mut r = req(None);
        r.git_ref.clone_from(&c1);
        assert_eq!(
            changed(fetch_file(&t, &r).await.unwrap()).content,
            b"[[record]]\nname = \"a.test\"\n"
        );
    }
}

#[tokio::test]
async fn clu_003_annotated_tags_resolve_to_their_commit() {
    let (_tmp, dir) = repo();
    let c1 = commit(&dir, "x = 1\n", "tagged");
    git(&dir, &["tag", "-a", "v1", "-m", "release"]);
    let t = Local {
        dir,
        no_filter: false,
    };
    let mut r = req(None);
    r.git_ref = "v1".into();
    assert_eq!(changed(fetch_file(&t, &r).await.unwrap()).commit, c1);
}

// REQ: CLU-003 — with allowed signers, only commits SSH-signed by them are accepted.
#[tokio::test]
async fn clu_003_signed_commits_are_required_when_configured() {
    let (tmp, dir) = repo();
    let keygen = |name: &str| {
        let k = tmp.path().join(name);
        let ok = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", name, "-f"])
            .arg(&k)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        ok.then_some(k)
    };
    let (Some(good), Some(bad)) = (keygen("good"), keygen("bad")) else {
        eprintln!("ssh-keygen unavailable: skipping");
        return;
    };
    let public = std::fs::read_to_string(good.with_extension("pub")).unwrap();
    let mut it = public.split_whitespace();
    let signers = AllowedSigners::parse(&format!(
        "ada@example.com {} {}\n",
        it.next().unwrap(),
        it.next().unwrap()
    ));
    let signed = |key: &Path, content: &str| {
        std::fs::write(dir.join("telltale/shared.toml"), content).unwrap();
        git(&dir, &["add", "-A"]);
        let k = key.to_str().unwrap();
        git(
            &dir,
            &[
                "-c",
                "gpg.format=ssh",
                "-c",
                &format!("user.signingkey={k}"),
                "commit",
                "-q",
                "-S",
                "-m",
                "signed",
            ],
        );
        git(&dir, &["rev-parse", "HEAD"])
    };
    let t = Local {
        dir: dir.clone(),
        no_filter: false,
    };
    let mut r = req(None);
    r.signers = Some(signers);
    let unsigned = commit(&dir, "u = 1\n", "unsigned");
    let e = fetch_file(&t, &r).await.unwrap_err();
    assert!(
        e.refused && e.message.contains("isn't signed"),
        "{e:?} at {unsigned}"
    );
    signed(&bad, "b = 1\n");
    let e = fetch_file(&t, &r).await.unwrap_err();
    assert!(e.refused && e.message.contains("isn't allowed"), "{e:?}");
    let c = signed(&good, "g = 1\n");
    let f = changed(fetch_file(&t, &r).await.unwrap());
    assert_eq!(
        (f.commit, f.signed_by.as_deref()),
        (c, Some("ada@example.com"))
    );
}

// Packs with deltas (ofs-delta) decode to exactly Git's objects.
#[test]
fn packs_with_deltas_decode_to_gits_objects() {
    let (_tmp, dir) = repo();
    let mut text = String::new();
    for i in 0..200 {
        text.push_str(&format!(
            "[[record]]\nname = \"host{i}.home.arpa\"\ntype = \"A\"\nvalue = \"10.0.0.{}\"\n",
            i % 250
        ));
        if i % 40 == 0 {
            commit(&dir, &text, &format!("v{i}"));
        }
    }
    let objects = git(&dir, &["rev-list", "--objects", "--all"]);
    let ids: Vec<&str> = objects
        .lines()
        .map(|l| l.split(' ').next().unwrap())
        .collect();
    let out = Command::new("git")
        .args([
            "pack-objects",
            "--stdout",
            "--delta-base-offset",
            "--window=50",
        ])
        .current_dir(&dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write as _;
            c.stdin
                .take()
                .unwrap()
                .write_all(ids.join("\n").as_bytes())?;
            c.wait_with_output()
        })
        .unwrap();
    let objs = pack::read(&out.stdout, 1 << 20).unwrap();
    assert_eq!(objs.len(), ids.len());
    for id in ids {
        assert!(objs.contains_key(id), "{id} missing");
    }
}
