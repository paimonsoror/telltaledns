//! REQ: NFR-001 (ADR-169) — the image's zoneinfo is built from the package's `tzdata.zi` with
//! `zic -b fat` (see the Dockerfile): one copy of the database, each name a hard link to a single
//! file, instead of the distribution's three trees. Schedules read time zones through jiff, so this
//! builds a directory the way the image does and checks, from the host's `tzdata.zi`, that jiff can
//! read every file in it, that it lists every zone name the host's directory does, and that the
//! offset, abbreviation and daylight-saving flag agree with the host's for every zone (weekly) and
//! for twelve zones with every kind of rule (every six hours), from 2020 to 2075.
//!
//! It is `fat`, not `slim`, because jiff refuses one slim file (0.2.37 did, and 1.0.1 still does):
//! `America/Ojinaga` from tzdata 2025b ("expected last transition in `TZif` file to have DST
//! offset matching the offset derived from the POSIX time zone transition rule"), so a schedule in
//! that zone would fail. The first check below is the one that found it.
//!
//! It needs `zic` and the system's `tzdata.zi`; where they aren't installed it says so and passes.

#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use jiff::Timestamp;
use jiff::tz::{TimeZone, TimeZoneDatabase};

const ZONES: &[&str] = &[
    "UTC",
    "America/New_York",
    "Europe/London",
    "Europe/Berlin",
    "Australia/Sydney",
    "Australia/Lord_Howe", // a 30-minute daylight saving shift
    "Asia/Kolkata",
    "Pacific/Auckland",
    "America/Sao_Paulo", // daylight saving ended in 2019
    "Africa/Casablanca", // negative daylight saving around Ramadan
    "Asia/Tehran",       // daylight saving ended in 2022
    "America/Ojinaga",   // the zone jiff refuses when it is built slim
];

/// 2020-01-01 and 2075-01-01 (UTC), in seconds.
const FROM: i64 = 1_577_836_800;
const TO: i64 = 3_313_526_400;

fn first_existing(paths: &[&str]) -> Option<PathBuf> {
    paths.iter().map(PathBuf::from).find(|p| p.exists())
}

/// What a reader sees at `at`: the offset, the abbreviation and whether it is daylight saving.
fn view(zone: &TimeZone, at: i64) -> (jiff::tz::Offset, String, bool) {
    let info = zone.to_offset_info(Timestamp::from_second(at).unwrap());
    (
        info.offset(),
        info.abbreviation().to_owned(),
        info.dst().is_dst(),
    )
}

fn names(db: &TimeZoneDatabase) -> BTreeSet<String> {
    // `localtime` and `posixrules` are links to the host's own configuration, and `posix/` and `right/`
    // are alternate trees some packages add; none of them is a zone name a schedule uses.
    db.available()
        .map(|n| n.as_str().to_owned())
        .filter(|n| {
            n != "localtime"
                && n != "posixrules"
                && !n.starts_with("posix/")
                && !n.starts_with("right/")
        })
        .collect()
}

#[test]
fn nfr_001_the_zoneinfo_the_image_builds_reads_the_same_as_the_hosts() {
    let zic = first_existing(&["/usr/sbin/zic", "/usr/bin/zic", "/sbin/zic"]);
    let host_dir = first_existing(&["/usr/share/zoneinfo", "/usr/share/lib/zoneinfo"]);
    let (Some(zic), Some(host_dir)) = (zic, host_dir) else {
        eprintln!("skipped: zic or the system zoneinfo isn't installed here");
        return;
    };
    let source = host_dir.join("tzdata.zi");
    if !source.exists() {
        eprintln!("skipped: {} isn't installed here", source.display());
        return;
    }
    // The same command the Dockerfile runs.
    let built_dir = std::env::temp_dir().join(format!("tt-zoneinfo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&built_dir);
    let status = Command::new(&zic)
        .args(["-b", "fat", "-d"])
        .arg(&built_dir)
        .arg(&source)
        .status()
        .unwrap();
    assert!(status.success(), "zic -b fat failed");

    let host = TimeZoneDatabase::from_dir(&host_dir).unwrap();
    let built = TimeZoneDatabase::from_dir(&built_dir).unwrap();

    // No zone name is lost.
    let (host_names, built_names) = (names(&host), names(&built));
    let lost: Vec<_> = host_names.difference(&built_names).collect();
    assert!(lost.is_empty(), "the built zoneinfo lacks {lost:?}");
    assert!(
        host_names.len() > 300,
        "expected a full zone list, got {}",
        host_names.len()
    );

    // jiff reads every file in it (it refuses a file it finds inconsistent, and then the zone is unknown).
    let refused: Vec<String> = built_names
        .iter()
        .filter_map(|n| built.get(n).err().map(|e| format!("{n}: {e}")))
        .collect();
    assert!(
        refused.is_empty(),
        "jiff refuses these zones from a directory built the way the image builds it: {refused:?}"
    );

    // The zones with every kind of rule, every six hours.
    for name in ZONES {
        let (a, b) = (host.get(name).unwrap(), built.get(name).unwrap());
        for t in (FROM..TO).step_by(6 * 3600) {
            assert_eq!(
                view(&a, t),
                view(&b, t),
                "{name} at {t}: the built file disagrees with the host's"
            );
        }
    }
    // Every zone, weekly.
    for name in &host_names {
        let (a, b) = (host.get(name).unwrap(), built.get(name).unwrap());
        for t in (FROM..TO).step_by(7 * 86400) {
            assert_eq!(
                view(&a, t),
                view(&b, t),
                "{name} at {t}: the built file disagrees with the host's"
            );
        }
    }

    // For the log: the size of each directory, counting a file with several hard links once.
    eprintln!(
        "zoneinfo: host {} B, built {} B",
        dir_size(&host_dir),
        dir_size(&built_dir)
    );
    let _ = std::fs::remove_dir_all(&built_dir);
}

/// The sum of the sizes of the files below `dir`, counting a file with several hard links once.
fn dir_size(dir: &Path) -> u64 {
    fn walk(dir: &Path, seen: &mut BTreeSet<(u64, u64)>) -> u64 {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return 0;
        };
        rd.filter_map(Result::ok)
            .map(|e| match e.path().symlink_metadata() {
                Ok(m) if m.is_dir() => walk(&e.path(), seen),
                Ok(m) if m.is_file() && seen.insert((m.dev(), m.ino())) => m.len(),
                _ => 0,
            })
            .sum()
    }
    walk(dir, &mut BTreeSet::new())
}
