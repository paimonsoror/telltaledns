use super::*;

/// A node's files: config, state.db with a user and a session, rollups, baselines, a query
/// log segment, and things a backup leaves out (cluster identity, lists, cache).
fn node(root: &Path) -> (Vec<PathBuf>, telltale_config::Config) {
    let data = root.join("data");
    fs::create_dir_all(data.join("qlog/2026/10/05")).unwrap();
    fs::create_dir_all(data.join("cluster")).unwrap();
    fs::create_dir_all(data.join("lists")).unwrap();
    let conf = root.join("etc/telltale.toml");
    fs::create_dir_all(conf.parent().unwrap()).unwrap();
    fs::write(
        &conf,
        format!(
            "[node]\nname = \"pi\"\ndata_dir = \"{}\"\n[[record]]\nname = \"nas.lan\"\ntype = \"A\"\nvalue = \"10.0.0.2\"\n",
            data.display()
        ),
    )
    .unwrap();
    let db = rusqlite::Connection::open(data.join("state.db")).unwrap();
    db.execute_batch(
        "CREATE TABLE users (name TEXT); INSERT INTO users VALUES ('admin');
         CREATE TABLE sessions (id TEXT); INSERT INTO sessions VALUES ('s1');
         CREATE TABLE idempotency (k TEXT); INSERT INTO idempotency VALUES ('k1');",
    )
    .unwrap();
    drop(db);
    let r = rusqlite::Connection::open(data.join("rollups.db")).unwrap();
    r.execute_batch(
        "CREATE TABLE rollup_hour (start INTEGER); INSERT INTO rollup_hour VALUES (1);",
    )
    .unwrap();
    drop(r);
    fs::write(data.join("anomaly.json"), b"{\"v\":1}").unwrap();
    fs::write(data.join("qlog/2026/10/05/11.seg"), vec![7u8; 5000]).unwrap();
    fs::write(data.join("cluster/cluster.json"), b"{}").unwrap();
    fs::write(data.join("cluster/ca.key"), b"secret").unwrap();
    fs::write(data.join("lists/x.src.zst"), b"list").unwrap();
    fs::write(data.join("cache.bin"), b"cache").unwrap();
    let cfg = telltale_config::Loader::new()
        .file(&conf)
        .load()
        .unwrap()
        .config;
    (vec![conf], cfg)
}

fn paths(m: &Manifest) -> Vec<&str> {
    m.entries.iter().map(|e| e.path.as_str()).collect()
}

// REQ: API-007 — a backup holds the config and local data (not the cluster identity, lists,
// or cache), restores elsewhere byte for byte, and refuses to overwrite without --force.
#[test]
fn api_007_backup_create_show_restore() {
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node(tmp.path());
    let out = tmp.path().join("b.ttbk");
    let c = create(&files, &cfg, false, &out).unwrap();
    assert_eq!(c.entries, 4);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let m = show(&out).unwrap();
    assert_eq!(
        paths(&m),
        [
            "config/telltale.toml",
            "data/state.db",
            "data/rollups.db",
            "data/anomaly.json"
        ]
    );
    assert!(m.cluster_member && !m.includes_qlog);
    assert_eq!(m.node, "pi");
    assert!(
        !tmp.path().join("data").read_dir().unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".backup")),
        "staging removed"
    );

    // Restore onto a "new machine".
    let new = tmp.path().join("new");
    let r = restore(&out, Some(&new.join("data")), Some(&new.join("etc")), false).unwrap();
    assert_eq!(r.files, 4);
    assert_eq!(
        fs::read(new.join("etc/telltale.toml")).unwrap(),
        fs::read(&files[0]).unwrap()
    );
    let db = rusqlite::Connection::open(new.join("data/state.db")).unwrap();
    let count = |t: &str| -> i64 {
        db.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(
        (count("users"), count("sessions"), count("idempotency")),
        (1, 0, 0)
    );
    assert!(new.join("data/rollups.db").exists() && new.join("data/anomaly.json").exists());
    assert!(!new.join("data/cluster").exists() && !new.join("data/lists").exists());

    // Again: the files exist now.
    let e = restore(&out, Some(&new.join("data")), Some(&new.join("etc")), false).unwrap_err();
    assert!(e.contains("--force"), "{e}");
    restore(&out, Some(&new.join("data")), Some(&new.join("etc")), true).unwrap();

    // REQ: CLU-008 (T6.14) — never under a running server (which holds the lock).
    let running = crate::datadir::lock(&new.join("data"), std::time::Duration::ZERO).unwrap();
    let e = restore(&out, Some(&new.join("data")), Some(&new.join("etc")), true).unwrap_err();
    assert!(e.contains("TelltaleDNS is running"), "{e}");
    drop(running);
    restore(&out, Some(&new.join("data")), Some(&new.join("etc")), true).unwrap();
}

#[test]
fn api_007_backup_with_query_log() {
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node(tmp.path());
    let out = tmp.path().join("b.ttbk");
    create(&files, &cfg, true, &out).unwrap();
    let m = show(&out).unwrap();
    assert!(m.includes_qlog);
    assert!(paths(&m).contains(&"data/qlog/2026/10/05/11.seg"));
    let new = tmp.path().join("new");
    restore(&out, Some(&new), Some(&new.join("etc")), false).unwrap();
    assert_eq!(
        fs::read(new.join("qlog/2026/10/05/11.seg")).unwrap(),
        vec![7u8; 5000]
    );
}

/// REQ: API-007, T8.2 (ADR-181) — a backup never holds the router keys saved from the UI: with
/// a `secrets/` folder of key files (nested too) and the API's list of them in the data
/// directory, no entry of the archive is under it, and no byte of what they hold is in the
/// archive, with or without the query log.
#[test]
fn api_007_a_backup_never_holds_router_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node(tmp.path());
    let data = tmp.path().join("data");
    let marker = format!(
        "router-key-marker-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    );
    fs::create_dir_all(data.join("secrets/nested")).unwrap();
    fs::write(
        data.join("secrets/router-udm.api_key.0123456789abcdef"),
        &marker,
    )
    .unwrap();
    fs::write(data.join("secrets/nested/key"), &marker).unwrap();
    fs::write(
        data.join("secrets/.written"),
        format!("{{\"router\":\"udm\",\"field\":\"api_key\",\"file\":\"{marker}\"}}\n"),
    )
    .unwrap();
    for qlog in [false, true] {
        let out = tmp.path().join(format!("b-{qlog}.ttbk"));
        create(&files, &cfg, qlog, &out).unwrap();
        let m = show(&out).unwrap();
        assert!(
            paths(&m).iter().all(|p| !p.contains("secrets")),
            "qlog={qlog}: {:?}",
            paths(&m)
        );
        let raw = zstd::stream::decode_all(fs::File::open(&out).unwrap()).unwrap();
        assert!(
            !raw.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "qlog={qlog}: the archive holds a key"
        );
    }
}

// A damaged archive is refused before anything is written.
#[test]
fn api_007_backup_corruption_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node(tmp.path());
    let out = tmp.path().join("b.ttbk");
    create(&files, &cfg, false, &out).unwrap();
    let mut bytes = fs::read(&out).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x55;
    let bad = tmp.path().join("bad.ttbk");
    fs::write(&bad, &bytes).unwrap();
    assert!(show(&bad).is_err());
    let new = tmp.path().join("new");
    assert!(restore(&bad, Some(&new), Some(&new.join("etc")), false).is_err());
    assert!(!new.join("state.db").exists());
    assert!(show(&files[0]).is_err(), "not an archive");
}

#[test]
fn api_007_backup_paths_stay_inside() {
    for ok in [
        "manifest.json",
        "config/a.toml",
        "data/state.db",
        "data/qlog/2026/1.seg",
    ] {
        assert!(safe(ok), "{ok}");
    }
    for bad in [
        "../x",
        "/etc/passwd",
        "data/../../x",
        "config/a/b.toml",
        "config/",
        "other/x",
        "data",
    ] {
        assert!(!safe(bad), "{bad}");
    }
}

#[test]
fn api_007_backup_default_name() {
    let n = default_name("Pi 4").display().to_string();
    assert!(
        n.starts_with("telltale-pi-4-2") && n.ends_with("Z.ttbk"),
        "{n}"
    );
}

/// The header blocks the archive writes for an entry `name` of `size` bytes (a GNU long-name
/// entry first when the name is longer than 99 bytes), made here field by field the way the
/// format has always been written, for a size that fits.
fn plain_head(name: &str, size: u64) -> Vec<u8> {
    // Octal digits, zero-padded to the field's length less one, from `start`.
    fn field(h: &mut [u8; 512], start: usize, len: usize, n: u64) {
        let width = len - 1;
        let s = format!("{n:0width$o}");
        h[start..start + s.len()].copy_from_slice(s.as_bytes());
    }
    fn block(name: &str, size: u64, typeflag: u8) -> [u8; 512] {
        let mut h = [0u8; 512];
        let n = &name.as_bytes()[..name.len().min(100)];
        h[..n.len()].copy_from_slice(n);
        field(&mut h, 100, 8, 0o600);
        field(&mut h, 108, 8, 0);
        field(&mut h, 116, 8, 0);
        field(&mut h, 124, 12, size);
        field(&mut h, 136, 12, 0);
        h[156] = typeflag;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].fill(b' ');
        let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        h
    }
    let mut out = Vec::new();
    if name.len() > 99 {
        let mut long = name.as_bytes().to_vec();
        long.push(0);
        out.extend_from_slice(&block("././@LongLink", long.len() as u64, b'L'));
        out.extend_from_slice(&long);
        out.resize(out.len().next_multiple_of(512), 0);
    }
    out.extend_from_slice(&block(name, size, b'0'));
    out
}

/// REQ: API-007 — an entry's size goes in the header's 12-byte field as octal digits: every
/// size that fits (up to 8^12 - 1 bytes) is written as it always was, and a file too large
/// for the field is refused with an error that names it, before anything of its entry is
/// written.
#[test]
fn api_007_backup_header_size_field_never_overflows() {
    let long = format!("data/qlog/{}/x.seg", "d".repeat(120));
    let (d99, e100) = ("d".repeat(99), "e".repeat(100));
    let names = [
        "data/rollups.db",
        d99.as_str(),
        e100.as_str(),
        long.as_str(),
    ];
    let writer = || TarWriter {
        out: Vec::new(),
        entries: Vec::new(),
    };
    for name in names {
        for size in [
            0,
            1,
            511,
            512,
            8u64.pow(11) - 1,
            8u64.pow(11),
            8u64.pow(12) - 1,
        ] {
            let mut tar = writer();
            tar.head(name, size).unwrap();
            assert_eq!(tar.out, plain_head(name, size), "{name}: {size}");
        }
    }
    let size_field = |size| {
        let mut tar = writer();
        tar.head("data/rollups.db", size).unwrap();
        tar.out[124..136].to_vec()
    };
    assert_eq!(size_field(8u64.pow(11) - 1), b"77777777777\0");
    assert_eq!(size_field(8u64.pow(12) - 1), b"777777777777");
    for name in names {
        for size in [8u64.pow(12), 8u64.pow(12) + 1, u64::MAX] {
            let mut tar = writer();
            let e = tar.head(name, size).unwrap_err().to_string();
            assert!(e.contains(name), "{name}: {e}");
            assert!(
                tar.out.is_empty(),
                "{name}: nothing of the entry is written"
            );
        }
    }
}

/// REQ: API-007 (T10.7) — where an archive says it came from is used only when it's a plain
/// absolute directory: not relative, not the root, no `..`.
#[test]
fn api_007_restore_trusts_only_plain_recorded_directories() {
    assert_eq!(
        recorded_dir("/var/lib/telltale", "--data-dir").unwrap(),
        PathBuf::from("/var/lib/telltale")
    );
    for bad in ["data", "/", "/var/lib/../../etc", "./x", ""] {
        let e = recorded_dir(bad, "--data-dir").unwrap_err();
        assert!(e.contains("--data-dir"), "{bad}: {e}");
    }
}
