// REQ: OPS-004 — self-update: signature, checksum, up-to-date detection, atomic swap.

use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

const TEST_KEY: &str = "RWTneV9LVAQJrjA/SfPCf+XrSUZd+K+8weGanksjMDJn6FQlPL4Gfwwp";
const ASSET: &str = "telltale-x86_64-linux";

fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/selfupdate")
        .join(name);
    std::fs::read(p).unwrap()
}

/// Serves `files` (path → body) over plain HTTP; everything else is 404.
async fn serve(files: Vec<(&'static str, Vec<u8>)>) -> String {
    serve_stalling(files, "").await
}

/// [`serve`], except that a request for `stall` is never answered.
async fn serve_stalling(files: Vec<(&'static str, Vec<u8>)>, stall: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let files = files.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_owned();
                if path == stall {
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                    return;
                }
                let (status, body) = files
                    .iter()
                    .find(|(p, _)| *p == path)
                    .map_or(("404 Not Found", Vec::new()), |(_, b)| {
                        ("200 OK", b.clone())
                    });
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
            });
        }
    });
    format!("http://{addr}/r")
}

fn release() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("/r/SHA256SUMS", fixture("SHA256SUMS")),
        ("/r/SHA256SUMS.minisig", fixture("SHA256SUMS.minisig")),
        ("/r/telltale-x86_64-linux", fixture("release-binary")),
    ]
}

fn options(base: String, check: bool) -> Options {
    Options {
        channel: Channel::Stable,
        check,
        restart: false,
        to: None,
        base_url: Some(base),
        exe: None,
    }
}

fn old_binary(dir: &Path) -> PathBuf {
    let exe = dir.join("telltale");
    std::fs::write(&exe, b"#!/bin/sh\necho old\n").unwrap();
    set_executable(&exe).unwrap();
    exe
}

#[test]
fn ops_004_signature_and_checksums() {
    let sums = fixture("SHA256SUMS");
    let sig = fixture("SHA256SUMS.minisig");
    verify_signature(TEST_KEY, &sums, &sig).unwrap();
    // The release key didn't sign the fixtures, and a tampered file fails too.
    assert!(verify_signature(RELEASE_KEY, &sums, &sig).is_err());
    let mut tampered = sums.clone();
    tampered[0] ^= 1;
    assert!(verify_signature(TEST_KEY, &tampered, &sig).is_err());

    let want = sha256_hex(&fixture("release-binary"));
    assert_eq!(expected_sha256(&sums, ASSET).unwrap(), want);
    assert_eq!(
        expected_sha256(format!("{want} *{ASSET}\n").as_bytes(), ASSET).unwrap(),
        want
    );
    assert!(expected_sha256(&sums, "telltale-riscv-linux").is_err());
    assert!(expected_sha256(b"nothex  telltale-x86_64-linux\n", ASSET).is_err());
    assert!(asset_name().is_some());
}

#[cfg(unix)]
#[tokio::test]
async fn ops_004_update_check_and_swap() {
    let dir = tempfile::tempdir().unwrap();
    let exe = old_binary(dir.path());
    let base = serve(release()).await;

    // --check reports the update and changes nothing.
    let out = update(&options(base.clone(), true), &exe, ASSET, TEST_KEY)
        .await
        .unwrap();
    assert!(matches!(out, Outcome::Available { .. }));
    assert_eq!(std::fs::read(&exe).unwrap(), b"#!/bin/sh\necho old\n");

    // The update swaps the binary in and keeps the old one.
    let out = update(&options(base.clone(), false), &exe, ASSET, TEST_KEY)
        .await
        .unwrap();
    let Outcome::Updated { previous } = out else {
        panic!("{out:?}")
    };
    assert_eq!(std::fs::read(&exe).unwrap(), fixture("release-binary"));
    assert_eq!(std::fs::read(previous).unwrap(), b"#!/bin/sh\necho old\n");
    assert!(!dir.path().join(".telltale.new").exists());

    // Now it matches the release.
    let out = update(&options(base, false), &exe, ASSET, TEST_KEY)
        .await
        .unwrap();
    assert_eq!(out, Outcome::UpToDate);
}

/// REQ: OPS-014 (ADR-182) — one deadline for all the downloads of an update: a download that
/// stalls past it fails the update, and the installed binary stays as it was (nothing staged,
/// nothing set aside), so the root update service records `failed` with the old build in place.
#[cfg(unix)]
#[tokio::test]
async fn ops_014_downloads_that_take_too_long_install_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let exe = old_binary(dir.path());
    let base = serve_stalling(release(), "/r/telltale-x86_64-linux").await;
    let e = update_within(
        &options(base, false),
        &exe,
        ASSET,
        TEST_KEY,
        std::time::Duration::from_secs(2),
    )
    .await
    .unwrap_err();
    assert!(
        e.contains("didn't finish within 2 s") && e.contains("nothing installed"),
        "{e}"
    );
    assert_eq!(std::fs::read(&exe).unwrap(), b"#!/bin/sh\necho old\n");
    assert!(!dir.path().join(".telltale.new").exists());
    assert!(!dir.path().join("telltale.old").exists());
    assert_eq!(FETCH_DEADLINE.as_secs(), 480);
}

#[cfg(unix)]
#[tokio::test]
async fn ops_004_refuses_bad_signature_or_checksum() {
    let dir = tempfile::tempdir().unwrap();
    let exe = old_binary(dir.path());

    // Wrong key: nothing is downloaded or changed.
    let base = serve(release()).await;
    let err = update(&options(base, false), &exe, ASSET, RELEASE_KEY)
        .await
        .unwrap_err();
    assert!(err.contains("signature"), "{err}");

    // Signed checksums, but the binary was swapped on the server.
    let mut files = release();
    files[2].1 = b"#!/bin/sh\necho evil\n".to_vec();
    let base = serve(files).await;
    let err = update(&options(base, false), &exe, ASSET, TEST_KEY)
        .await
        .unwrap_err();
    assert!(err.contains("checksum mismatch"), "{err}");
    assert_eq!(std::fs::read(&exe).unwrap(), b"#!/bin/sh\necho old\n");

    // Missing signature file.
    let mut files = release();
    files.remove(1);
    let base = serve(files).await;
    assert!(
        update(&options(base, false), &exe, ASSET, TEST_KEY)
            .await
            .is_err()
    );
}

// ---- REQ: OPS-014 — pinned installs (`--to`) ----

fn pinned(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/pinned")
        .join(name);
    std::fs::read(p).unwrap()
}

fn pinned_key() -> String {
    String::from_utf8(pinned("test.pub"))
        .unwrap()
        .trim()
        .to_owned()
}

/// A release page whose `releases.json` is `index`.
fn pinned_release(index: &str) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("/r/SHA256SUMS", pinned("SHA256SUMS")),
        ("/r/SHA256SUMS.minisig", pinned("SHA256SUMS.minisig")),
        ("/r/telltale-x86_64-linux", pinned("release-binary")),
        ("/r/releases.json", pinned(index)),
        (
            "/r/releases.json.minisig",
            pinned(&format!("{index}.minisig")),
        ),
    ]
}

fn pinned_options(base: String, to: &str) -> Options {
    Options {
        channel: crate::node_update::channel_for(to),
        check: false,
        restart: false,
        to: Some(to.into()),
        base_url: Some(base),
        exe: None,
    }
}

#[test]
fn ops_014_a_pinned_release_is_downloaded_from_its_own_page() {
    let o = |channel, to: Option<&str>| Options {
        channel,
        check: false,
        restart: false,
        to: to.map(str::to_owned),
        base_url: None,
        exe: None,
    };
    assert_eq!(
        base_url(&o(Channel::Stable, Some("0.8.0"))),
        format!("{RELEASES}/download/v0.8.0")
    );
    assert_eq!(
        base_url(&o(Channel::Stable, None)),
        format!("{RELEASES}/latest/download")
    );
    assert_eq!(
        base_url(&o(Channel::Edge, Some("0.8.0-edge.393"))),
        format!("{RELEASES}/download/edge")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn ops_014_a_pinned_install_takes_only_the_version_its_signed_index_names() {
    let key = pinned_key();
    // The release: installed.
    let dir = tempfile::tempdir().unwrap();
    let exe = old_binary(dir.path());
    let base = serve(pinned_release("releases.json")).await;
    let out = update(&pinned_options(base.clone(), "9.9.9"), &exe, ASSET, &key)
        .await
        .unwrap();
    assert!(matches!(out, Outcome::Updated { .. }), "{out:?}");
    assert_eq!(std::fs::read(&exe).unwrap(), pinned("release-binary"));

    // Another version under that release's index: nothing is installed.
    let dir = tempfile::tempdir().unwrap();
    let exe = old_binary(dir.path());
    let err = update(&pinned_options(base, "9.9.8"), &exe, ASSET, &key)
        .await
        .unwrap_err();
    assert!(err.contains("names 9.9.9: not trusted"), "{err}");
    assert_eq!(std::fs::read(&exe).unwrap(), b"#!/bin/sh\necho old\n");

    // An index that lists another SHA-256 than SHA256SUMS: refused.
    let base = serve(pinned_release("releases-mismatch.json")).await;
    let err = update(&pinned_options(base, "9.9.9"), &exe, ASSET, &key)
        .await
        .unwrap_err();
    assert!(err.contains("disagree"), "{err}");

    // An index signed by another key: refused.
    let base = serve(pinned_release("releases.json")).await;
    let err = update(&pinned_options(base, "9.9.9"), &exe, ASSET, TEST_KEY)
        .await
        .unwrap_err();
    assert!(err.contains("signature"), "{err}");
    assert_eq!(std::fs::read(&exe).unwrap(), b"#!/bin/sh\necho old\n");
}

#[cfg(unix)]
#[tokio::test]
async fn ops_014_an_edge_build_installs_only_while_it_is_the_newest() {
    let key = pinned_key();
    let dir = tempfile::tempdir().unwrap();
    let exe = old_binary(dir.path());
    let base = serve(pinned_release("releases-edge.json")).await;
    let out = update(
        &pinned_options(base.clone(), "9.9.9-edge.6"),
        &exe,
        ASSET,
        &key,
    )
    .await
    .unwrap();
    // REQ: OPS-014 (ADR-182) — its own outcome, so the update service can say `unavailable`.
    assert_eq!(
        out,
        Outcome::Unavailable {
            serves: "9.9.9-edge.7".into(),
            commit: "abc1234".into()
        }
    );
    let err = unavailable_text("9.9.9-edge.6", "9.9.9-edge.7", "abc1234");
    assert!(
        err.contains("now serves 9.9.9-edge.7") && err.contains("only the newest edge build"),
        "{err}"
    );
    assert_eq!(std::fs::read(&exe).unwrap(), b"#!/bin/sh\necho old\n");
    let out = update(&pinned_options(base, "9.9.9-edge.7"), &exe, ASSET, &key)
        .await
        .unwrap();
    assert!(matches!(out, Outcome::Updated { .. }), "{out:?}");
}

/// REQ: OPS-014 (ADR-182) — the signed index must be of the version's own channel: an index of
/// the edge channel that names a release version installs nothing (part of "a request never
/// moves a stable node to edge": the build a stable node takes is a release's).
#[cfg(unix)]
#[tokio::test]
async fn ops_014_a_pinned_install_takes_only_an_index_of_the_versions_channel() {
    let key = pinned_key();
    let dir = tempfile::tempdir().unwrap();
    let exe = old_binary(dir.path());
    let base = serve(pinned_release("releases-channel.json")).await;
    let err = update(&pinned_options(base, "9.9.9"), &exe, ASSET, &key)
        .await
        .unwrap_err();
    assert!(err.contains("channel"), "{err}");
    assert_eq!(std::fs::read(&exe).unwrap(), b"#!/bin/sh\necho old\n");
}

/// REQ: OPS-004, OPS-014 — the smoke run (`--version`) of a binary that was just written can meet
/// "text file busy" (ETXTBSY): Linux refuses to exec a file some process still has open for
/// writing, and a parallel fork can hold a copy of that descriptor for a moment (it made
/// `ops_004_update_check_and_swap` fail now and then). A binary that is busy only for a moment still
/// runs: the exec is tried again. Here the file is written and kept open, the first try is made, and
/// the file is closed right after it, inside the same closure that starts the program: the second try
/// finds it free, whatever the clock does. On a kernel that runs a file open for writing there is
/// nothing to retry, and the test says so and ends.
#[cfg(unix)]
#[test]
fn ops_004_a_binary_busy_for_a_moment_still_runs() {
    use std::io::Write as _;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("busy");
    let mut open = Some(std::fs::File::create(&path).unwrap());
    open.as_mut()
        .unwrap()
        .write_all(b"#!/bin/sh\nexit 0\n")
        .unwrap();
    set_executable(&path).unwrap();

    let (mut starts, mut first_was_busy) = (0, false);
    let status = run_bounded_via(
        std::process::Command::new(&path).arg("--version"),
        VERSION_WAIT,
        |cmd| {
            starts += 1;
            let started = cmd.spawn();
            if starts == 1 {
                first_was_busy = started.as_ref().err().is_some_and(text_file_busy);
                drop(open.take()); // closed: the next try can run it
            }
            started
        },
    )
    .unwrap();
    assert!(status.success(), "{status}");
    if !first_was_busy {
        eprintln!("skipped (nothing to retry): this kernel runs a file that is open for writing");
        return;
    }
    assert_eq!(starts, 2, "busy once, then it ran");
}

/// REQ: OPS-004, OPS-014 — only "text file busy" is tried again, up to five times in all: busy
/// twice and then it runs; any other error is returned at once, untried again; busy every time is
/// five tries and then the same error, in the same words, as one try would have given.
#[test]
fn ops_004_only_text_file_busy_is_tried_again() {
    use std::io::{Error, ErrorKind};
    assert_eq!((EXEC_TRIES, EXEC_PAUSE), (5, Duration::from_millis(100)));
    let busy = || Error::from_raw_os_error(26);

    let mut calls = 0;
    let ran = retry_text_busy(EXEC_TRIES, Duration::ZERO, || {
        calls += 1;
        if calls <= 2 { Err(busy()) } else { Ok(calls) }
    });
    assert_eq!(ran.unwrap(), 3, "busy twice, then it runs");

    let mut calls = 0;
    let e = retry_text_busy::<()>(EXEC_TRIES, Duration::ZERO, || {
        calls += 1;
        Err(Error::from(ErrorKind::NotFound))
    })
    .unwrap_err();
    assert_eq!(
        (calls, e.kind()),
        (1, ErrorKind::NotFound),
        "another error is not tried again"
    );
    let mut calls = 0;
    let e = retry_text_busy::<()>(EXEC_TRIES, Duration::ZERO, || {
        calls += 1;
        Err(Error::from(ErrorKind::PermissionDenied))
    })
    .unwrap_err();
    assert_eq!((calls, e.kind()), (1, ErrorKind::PermissionDenied));

    let mut calls = 0;
    let e = retry_text_busy::<()>(EXEC_TRIES, Duration::ZERO, || {
        calls += 1;
        Err(busy())
    })
    .unwrap_err();
    assert_eq!(calls, 5, "busy every time: five tries");
    assert_eq!(
        e.to_string(),
        busy().to_string(),
        "and the error is the one a single try gives"
    );

    // The kind alone counts as busy too (not only the raw OS error).
    let mut calls = 0;
    let _ = retry_text_busy::<()>(3, Duration::ZERO, || {
        calls += 1;
        Err(Error::from(ErrorKind::ExecutableFileBusy))
    });
    assert_eq!(calls, 3);
}
