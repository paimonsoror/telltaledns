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
