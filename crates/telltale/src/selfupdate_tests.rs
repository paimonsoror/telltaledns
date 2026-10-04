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
