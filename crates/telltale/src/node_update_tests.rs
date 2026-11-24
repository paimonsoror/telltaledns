// REQ: OPS-014 — updates driven from the cluster: what a node agrees to, the request it writes,
// and what the root update service does with it.

use std::cell::Cell;

use super::*;
use crate::selfupdate::Outcome;

const NOW: u64 = 1_795_000_000_000;

fn here(dir: &Path, install: &str, version: &str, enabled: bool) -> Here {
    Here {
        node: "dns-02".into(),
        version: version.into(),
        install: install.into(),
        enabled,
        channel: None,
        data_dir: dir.to_path_buf(),
        result: dir.join("service").join("result.json"),
    }
}

/// A test's install: what the signed self-update would return for a version.
type Install<'a> = Box<dyn FnOnce(&str) -> Result<Outcome, String> + 'a>;

/// The install a test gives the update service, with a node that restarts and is healthy.
struct Installs<'a>(Option<Install<'a>>);

impl Host for Installs<'_> {
    fn install(&mut self, to: &str) -> Result<Outcome, String> {
        self.0
            .take()
            .map_or_else(|| Err("asked twice".to_owned()), |f| f(to))
    }
    fn restart(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn healthy(&mut self) -> Result<String, String> {
        Ok("checked at the test's address".into())
    }
    fn restore(&mut self, _: &Path) -> Result<(), String> {
        Ok(())
    }
}

/// The update service's run with `install`, for a node that restarts and comes up healthy.
fn serve<'a>(
    request: &Path,
    result: &Path,
    current: &str,
    now: u64,
    install: impl FnOnce(&str) -> Result<Outcome, String> + 'a,
) -> Served {
    serve_request(
        request,
        result,
        current,
        now,
        true,
        &mut Installs(Some(Box::new(install))),
    )
}

fn code(r: Result<NodeUpdate, Problem>) -> Code {
    r.unwrap_err().code
}

#[test]
fn ops_014_a_node_takes_only_newer_versions_it_can_install() {
    let d = tempfile::tempdir().unwrap();
    let native = here(d.path(), "native", "0.7.0", true);
    assert_eq!(
        code(request(
            &here(d.path(), "helm", "0.7.0", true),
            "0.8.0",
            "a",
            NOW
        )),
        Code::UpdateUnsupported
    );
    assert_eq!(
        code(request(
            &here(d.path(), "container", "0.7.0", true),
            "0.8.0",
            "a",
            NOW
        )),
        Code::UpdateUnsupported
    );
    assert_eq!(
        code(request(
            &here(d.path(), "native", "dev", true),
            "0.8.0",
            "a",
            NOW
        )),
        Code::UpdateUnsupported
    );
    assert_eq!(
        code(request(&native, "0.6.9", "a", NOW)),
        Code::UpdateDowngrade
    );
    assert_eq!(
        code(request(&native, "0.7.0-edge.400", "a", NOW)),
        Code::UpdateDowngrade
    );
    assert_eq!(
        code(request(&native, "latest", "a", NOW)),
        Code::UpdateInvalid
    );
    assert_eq!(
        code(request(
            &here(d.path(), "native", "0.7.0", false),
            "0.8.0",
            "a",
            NOW
        )),
        Code::UpdateNotEnabled
    );
    // Nothing was written for any of them.
    assert!(!d.path().join(REQUEST_FILE).exists());
    // The same version is up to date without a request.
    let same = request(&native, "0.7.0", "a", NOW).unwrap();
    assert_eq!(same.state.as_deref(), Some("up_to_date"));
    assert!(!d.path().join(REQUEST_FILE).exists());
}

#[test]
fn ops_014_a_request_is_written_for_the_update_service_and_shown_as_pending() {
    let dir = tempfile::tempdir().unwrap();
    // An edge node (a stable one never takes an edge build: ops_014_a_request_never_moves_...).
    let node = here(dir.path(), "native", "0.7.0-edge.400", true);
    let res = request(&node, "0.8.0-edge.393", "alice via k3s", NOW).unwrap();
    assert_eq!(res.state.as_deref(), Some("requested"));
    let asked = res.pending.unwrap();
    assert_eq!(
        (asked.to.as_str(), asked.by.as_str()),
        ("0.8.0-edge.393", "alice via k3s")
    );
    // REQ: OPS-014 (ADR-182) — in its own folder, `<data_dir>/update/request.json`: the only
    // place of the data directory the update service may write.
    let written = dir.path().join("update").join("request.json");
    assert_eq!(node.request_path(), written);
    let file: RequestFile = serde_json::from_slice(&std::fs::read(&written).unwrap()).unwrap();
    assert_eq!(file.id, asked.id);
    assert_eq!(file.requested_ms, NOW);
    // Nothing else in the data directory, and no temporary file left behind.
    let names = |p: &Path| -> Vec<String> {
        std::fs::read_dir(p)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    };
    assert_eq!(names(dir.path()), vec!["update".to_owned()]);
    assert_eq!(
        names(&dir.path().join("update")),
        vec!["request.json".to_owned()]
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&written), 0o640);
        assert_eq!(mode(&dir.path().join("update")), 0o750);
    }
    // A read shows it, and no run yet.
    let read = status(&node);
    assert_eq!(read.pending.unwrap().id, asked.id);
    assert!(read.last.is_none() && read.state.is_none());
}

#[test]
fn ops_014_the_update_service_installs_a_newer_version_once_and_records_it() {
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    let asked = request(&h, "0.8.0", "alice", NOW).unwrap().pending.unwrap();
    let calls = Cell::new(0);
    let served = serve(&h.request_path(), &h.result, "0.7.0", NOW + 1000, |to| {
        calls.set(calls.get() + 1);
        assert_eq!(to, "0.8.0");
        // While it installs, the node sees `installing`.
        assert_eq!(status(&h).last.unwrap().state, "installing");
        Ok(Outcome::Updated {
            previous: PathBuf::from("/usr/local/bin/telltale.old"),
        })
    });
    assert_eq!(
        served,
        Served::Done {
            state: "updated".into()
        }
    );
    assert_eq!(calls.get(), 1);
    let s = status(&h);
    assert!(s.pending.is_none(), "the request is consumed");
    let last = s.last.unwrap();
    assert_eq!(
        (
            last.id.as_str(),
            last.state.as_str(),
            last.from.as_str(),
            last.to.as_str()
        ),
        (asked.id.as_str(), "updated", "0.7.0", "0.8.0")
    );
    // Run again: nothing to do.
    let again = serve(
        &h.request_path(),
        &h.result,
        "0.8.0",
        NOW,
        |_| unreachable!(),
    );
    assert_eq!(again, Served::Nothing);
}

#[test]
fn ops_014_a_failed_install_is_recorded_and_does_not_restart() {
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0-edge.400", true);
    request(&h, "0.8.0-edge.393", "alice", NOW).unwrap();
    let mut host = Scripted {
        install: Some(Err("SHA256SUMS: the signature does not verify".into())),
        ..Scripted::default()
    };
    let served = serve_request(
        &h.request_path(),
        &h.result,
        "0.7.0-edge.400",
        NOW,
        true,
        &mut host,
    );
    assert_eq!(
        served,
        Served::Done {
            state: "failed".into()
        }
    );
    assert_eq!(host.calls, ["install 0.8.0-edge.393"], "never restarted");
    let last = status(&h).last.unwrap();
    assert_eq!(last.state, "failed");
    assert!(last.error.unwrap().contains("does not verify"));
}

/// Writes `body` as the request file, as the node's user would.
fn plant(h: &Here, body: &str) {
    if let Some(dir) = h.request_path().parent() {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(h.request_path(), body).unwrap();
}

#[test]
fn ops_014_the_update_service_trusts_nothing_in_the_request() {
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    let never = |_: &str| -> Result<Outcome, String> { panic!("must not install") };
    let ok = |id: &str, to: &str, at: u64| {
        format!(r#"{{"id":"{id}","to":"{to}","by":"alice","requestedMs":{at}}}"#)
    };
    for (body, why) in [
        (ok("1a-2b", "0.6.0", NOW), "older than the installed"),
        (ok("1a-2b", "0.7.0-edge.1", NOW), "older than the installed"),
        (ok("1a-2b", "0.8.0;reboot", NOW), "isn't a release"),
        (ok("../x", "0.8.0", NOW), "id is malformed"),
        (
            ok("1a-2b", "0.8.0", NOW - STALE_REQUEST_MS - 1),
            "more than an hour old",
        ),
        (ok("1a-2b", "0.8.0", NOW + 3_600_000), "from the future"),
        (
            r#"{"id":"1a","to":"0.8.0","by":"a","requestedMs":1,"url":"http://evil"}"#.to_owned(),
            "expected shape",
        ),
        ("not json".to_owned(), "expected shape"),
    ] {
        plant(&h, &body);
        let served = serve(&h.request_path(), &h.result, "0.7.0", NOW, never);
        assert_eq!(
            served,
            Served::Done {
                state: "refused".into()
            },
            "{body}"
        );
        let last = status(&h).last.unwrap();
        assert!(
            last.error.as_deref().unwrap().contains(why),
            "{body}: {last:?}"
        );
        assert!(
            !h.request_path().exists(),
            "a refused request is removed too: {body}"
        );
    }
    // A local build never installs from a request.
    plant(&h, &ok("1a-2b", "0.8.0", NOW));
    let served = serve(&h.request_path(), &h.result, "dev", NOW, never);
    assert_eq!(
        served,
        Served::Done {
            state: "refused".into()
        }
    );
    // The same version: up to date, nothing installed.
    plant(&h, &ok("1a-2b", "0.7.0", NOW));
    let served = serve(&h.request_path(), &h.result, "0.7.0", NOW, never);
    assert_eq!(
        served,
        Served::Done {
            state: "up_to_date".into()
        }
    );
}

#[cfg(unix)]
#[test]
fn ops_014_the_update_service_reads_no_symlink_or_large_file() {
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    let never = |_: &str| -> Result<Outcome, String> { panic!("must not install") };
    let secret = d.path().join("secret");
    std::fs::write(
        &secret,
        r#"{"id":"1a","to":"0.8.0","by":"a","requestedMs":1795000000000}"#,
    )
    .unwrap();
    std::fs::create_dir_all(h.request_path().parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&secret, h.request_path()).unwrap();
    let served = serve(&h.request_path(), &h.result, "0.7.0", NOW, never);
    assert_eq!(
        served,
        Served::Done {
            state: "refused".into()
        }
    );
    assert!(secret.exists(), "the link is removed, not its target");
    assert!(!h.request_path().exists());
    let last = status(&h).last.unwrap();
    assert!(last.error.unwrap().contains("regular file"));
    // A hard link to another file (two names) is refused as well.
    std::fs::hard_link(&secret, h.request_path()).unwrap();
    let served = serve(&h.request_path(), &h.result, "0.7.0", NOW, never);
    assert_eq!(
        served,
        Served::Done {
            state: "refused".into()
        }
    );
    // And anything over 4 KiB.
    plant(&h, &" ".repeat(5000));
    let served = serve(&h.request_path(), &h.result, "0.7.0", NOW, never);
    assert_eq!(
        served,
        Served::Done {
            state: "refused".into()
        }
    );
    // A symlink planted where the result goes is replaced, not written through.
    let outside = d.path().join("outside");
    std::fs::write(&outside, "keep").unwrap();
    std::fs::create_dir_all(h.result.parent().unwrap()).unwrap();
    std::fs::remove_file(&h.result).unwrap();
    std::os::unix::fs::symlink(&outside, &h.result).unwrap();
    plant(
        &h,
        r#"{"id":"1a","to":"0.7.0","by":"a","requestedMs":1795000000000}"#,
    );
    serve(&h.request_path(), &h.result, "0.7.0", NOW, never);
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
    assert!(
        !std::fs::symlink_metadata(&h.result)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

/// The one error the update service records for anything at the request that isn't a small
/// regular file of the node's own (the result is world-readable: it says no more than that).
const NOT_A_REQUEST: &str = "the request isn't a small regular file written by the node: ignored";

fn refused() -> Served {
    Served::Done {
        state: "refused".into(),
    }
}

/// Makes a FIFO at `p`, in this process: a child process (`mkfifo`) forked while another test
/// writes a binary it is about to run (the pinned self-update tests) can make that `exec` fail
/// with "Text file busy". (`mknodat` is Linux's in rustix.)
#[cfg(target_os = "linux")]
fn mkfifo(p: &Path) {
    use rustix::fs::{CWD, FileType, Mode};
    rustix::fs::mknodat(CWD, p, FileType::Fifo, Mode::from_raw_mode(0o600), 0)
        .unwrap_or_else(|e| panic!("mkfifo {}: {e}", p.display()));
}

/// The update service's run on a thread of its own, waited for at most 20 s: a run that blocks
/// (an open of a FIFO with no writer) fails the test instead of hanging it.
#[cfg(unix)]
fn serve_bounded(h: &Here, current: &'static str) -> Served {
    let (request, result) = (h.request_path(), h.result.clone());
    let (tx, rx) = std::sync::mpsc::channel();
    drop(std::thread::spawn(move || {
        let _ = tx.send(serve(&request, &result, current, NOW, |_| {
            Err("must not install".to_owned())
        }));
    }));
    rx.recv_timeout(std::time::Duration::from_secs(20))
        .expect("the update service blocked on the request")
}

/// REQ: OPS-014 (ADR-182) — a link to a FIFO at the request is refused without the update
/// service blocking on it (the open never follows a link and never waits for a writer); the
/// link goes, the FIFO it named stays, and the result says only that it wasn't a request.
#[cfg(target_os = "linux")]
#[test]
fn ops_014_a_link_to_a_fifo_is_refused_without_blocking() {
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    let fifo = d.path().join("fifo");
    mkfifo(&fifo);
    std::fs::create_dir_all(h.request_path().parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&fifo, h.request_path()).unwrap();
    assert_eq!(serve_bounded(&h, "0.7.0"), refused());
    assert!(
        std::fs::symlink_metadata(h.request_path()).is_err(),
        "the link is removed"
    );
    assert!(fifo.exists(), "the FIFO it named is left alone");
    assert_eq!(
        status(&h).last.unwrap().error.as_deref(),
        Some(NOT_A_REQUEST)
    );
}

/// REQ: OPS-014 (ADR-182) — a FIFO or an empty directory at the request is refused and removed
/// (so the path unit isn't started again for it), with the same one error. A directory with
/// something in it can't be removed without root reaching into the node's files: it is refused
/// each time (the path unit's start limit then stops it: ADR-182, the feature switched off).
#[cfg(target_os = "linux")]
#[test]
fn ops_014_a_fifo_or_directory_at_the_request_is_refused_and_removed() {
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    std::fs::create_dir_all(h.request_path().parent().unwrap()).unwrap();
    mkfifo(&h.request_path());
    assert_eq!(serve_bounded(&h, "0.7.0"), refused());
    assert!(
        std::fs::symlink_metadata(h.request_path()).is_err(),
        "the FIFO is removed"
    );
    assert_eq!(
        status(&h).last.unwrap().error.as_deref(),
        Some(NOT_A_REQUEST)
    );
    std::fs::create_dir(h.request_path()).unwrap();
    assert_eq!(serve_bounded(&h, "0.7.0"), refused());
    assert!(
        std::fs::symlink_metadata(h.request_path()).is_err(),
        "the empty directory is removed"
    );
    assert_eq!(
        status(&h).last.unwrap().error.as_deref(),
        Some(NOT_A_REQUEST)
    );
    std::fs::create_dir(h.request_path()).unwrap();
    std::fs::write(h.request_path().join("x"), "x").unwrap();
    assert_eq!(serve_bounded(&h, "0.7.0"), refused());
    assert!(
        h.request_path().join("x").exists(),
        "nothing inside is touched"
    );
}

/// REQ: OPS-014 (ADR-182) — the update service acts only on a version written exactly as a
/// release or edge build is: padded, with a newline, or with a leading zero is refused before
/// anything is fetched (it used to pass the downgrade check unparsed). The node never asks for
/// one either.
#[test]
fn ops_014_a_padded_or_unparseable_version_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.8.0", true);
    for to in [
        "0.9.0\n",
        " 0.9.0",
        "0.9.0 ",
        "0.09.0",
        "00.9.0",
        "0.9.0-edge.01",
    ] {
        let body = serde_json::json!({"id": "1a-2b", "to": to, "by": "alice", "requestedMs": NOW});
        plant(&h, &body.to_string());
        let asked = Cell::new(false);
        let served = serve(&h.request_path(), &h.result, "0.8.0", NOW, |_| {
            asked.set(true);
            Err("not here".to_owned())
        });
        assert!(!asked.get(), "{to:?}: nothing is fetched");
        assert_eq!(served, refused(), "{to:?}");
        assert!(
            status(&h)
                .last
                .unwrap()
                .error
                .unwrap()
                .contains("isn't a release or edge build version"),
            "{to:?}"
        );
    }
    for to in ["0.09.0", "00.9.0", "0.9.0-edge.01"] {
        assert_eq!(
            code(request(&h, to, "alice", NOW)),
            Code::UpdateInvalid,
            "{to:?}"
        );
    }
    assert!(!h.request_path().exists());
}

/// REQ: OPS-014 (ADR-182) — a request never changes a node's channel: a stable node takes only a
/// release (`update_channel`, 409, at the node: the same check answers the API and the cluster
/// RPC), and the update service refuses it again; an edge node takes an edge build or a newer
/// release.
#[test]
fn ops_014_a_request_never_moves_a_stable_node_to_edge() {
    let d = tempfile::tempdir().unwrap();
    let stable = here(d.path(), "native", "0.8.0", true);
    let e = request(&stable, "0.9.0-edge.1", "alice", NOW).unwrap_err();
    assert_eq!(
        (serde_json::to_value(e.code).unwrap(), e.status),
        (serde_json::json!("update_channel"), 409),
        "{e:?}"
    );
    assert!(
        e.hint.as_deref().is_some_and(|h| h
            .contains("telltale self-update --channel edge --restart")
            && h.contains("install.sh --edge --cluster-updates")),
        "{e:?}"
    );
    assert!(!stable.request_path().exists(), "nothing is written");
    // An edge node: an edge build, or a newer release.
    let edge_dir = tempfile::tempdir().unwrap();
    let edge = here(edge_dir.path(), "native", "0.8.0-edge.5", true);
    assert_eq!(
        request(&edge, "0.8.0-edge.9", "alice", NOW)
            .unwrap()
            .state
            .as_deref(),
        Some("requested")
    );
    std::fs::remove_file(edge.request_path()).unwrap();
    assert_eq!(
        request(&edge, "0.8.0", "alice", NOW)
            .unwrap()
            .state
            .as_deref(),
        Some("requested")
    );
    // The update service, on a stable node, refuses an edge build however it was asked.
    let body =
        serde_json::json!({"id": "1a-2b", "to": "0.9.0-edge.1", "by": "alice", "requestedMs": NOW});
    plant(&stable, &body.to_string());
    let asked = Cell::new(false);
    let served = serve(&stable.request_path(), &stable.result, "0.8.0", NOW, |_| {
        asked.set(true);
        Err("not here".to_owned())
    });
    assert!(!asked.get(), "nothing is fetched");
    assert_eq!(served, refused());
    assert!(
        status(&stable)
            .last
            .unwrap()
            .error
            .unwrap()
            .contains("stable channel"),
    );
}

/// REQ: OPS-014 (ADR-182) — the request's folder must be the node's own real directory: one
/// swapped for a link to another folder, or one anyone may write, is refused and nothing in it is
/// read or removed (root writes only in the node's `update/`, never through a link).
#[cfg(unix)]
#[test]
fn ops_014_a_request_folder_that_isnt_the_nodes_is_left_alone() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    let elsewhere = d.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    let body = serde_json::json!({"id": "1a-2b", "to": "0.8.0", "by": "a", "requestedMs": NOW});
    std::fs::write(elsewhere.join("request.json"), body.to_string()).unwrap();
    std::os::unix::fs::symlink(&elsewhere, d.path().join("update")).unwrap();
    assert_eq!(serve_bounded(&h, "0.7.0"), refused());
    assert!(
        elsewhere.join("request.json").exists(),
        "nothing is removed through the link"
    );
    assert_eq!(
        status(&h).last.unwrap().error.as_deref(),
        Some(NOT_A_REQUEST)
    );
    std::fs::remove_file(d.path().join("update")).unwrap();
    plant(&h, &body.to_string());
    std::fs::set_permissions(
        h.request_path().parent().unwrap(),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert_eq!(serve_bounded(&h, "0.7.0"), refused());
    assert!(
        h.request_path().exists(),
        "a folder anyone may write isn't the node's: nothing in it is touched"
    );
}

/// REQ: OPS-014 (ADR-182) — the shipped units agree with the code and keep root's reach small:
/// the path unit watches `<data_dir>/update/request.json`; the service reads it there and may
/// write only that folder, the binary's directory and its own state, with one capability and the
/// node unit's own sandbox; `systemctl` is run by its absolute path.
#[test]
fn ops_014_the_units_watch_and_write_only_the_request_folder() {
    let path = include_str!("../../../deploy/systemd/telltale-update.path");
    let svc = include_str!("../../../deploy/systemd/telltale-update.service");
    // `Here::request_path` (ops_014_a_request_is_written_...) for the default data directory.
    let request = "/var/lib/telltale/update/request.json".to_owned();
    let lines = |unit: &'static str, key: &str| -> Vec<&'static str> {
        unit.lines()
            .filter_map(|l| l.strip_prefix(key).and_then(|l| l.strip_prefix('=')))
            .collect()
    };
    assert_eq!(lines(path, "PathExists"), [request.as_str()]);
    assert_eq!(
        lines(svc, "ExecStart"),
        [format!("/usr/local/bin/telltale self-update --request {request} --restart").as_str()]
    );
    assert_eq!(
        lines(svc, "ReadWritePaths"),
        ["/usr/local/bin -/var/lib/telltale/update"]
    );
    for (key, want) in [
        ("CapabilityBoundingSet", "CAP_DAC_OVERRIDE"),
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "strict"),
        ("PrivateTmp", "yes"),
        ("ProtectProc", "invisible"),
        ("MemoryDenyWriteExecute", "yes"),
        ("RemoveIPC", "yes"),
        ("SystemCallFilter", "@system-service"),
        ("RestrictAddressFamilies", "AF_INET AF_INET6 AF_UNIX"),
        ("Type", "oneshot"),
    ] {
        assert_eq!(lines(svc, key), [want], "{key}");
    }
    // REQ: OPS-014 (ADR-182) — the channel and the health check's address are the unit's (as
    // install.sh writes them: deploy/systemd/update-units-test.sh), never the request's.
    assert_eq!(lines(svc, "User"), [] as [&str; 0]);
    assert_eq!(
        lines(svc, "Environment"),
        [
            "TELLTALE_INSTALL=native",
            "TELLTALE_LOG=info",
            "TELLTALE_UPDATE_CHANNEL=stable",
            "TELLTALE_UPDATE_HEALTH_URL=http://127.0.0.1:8053/readyz?startup=1",
        ]
    );
    assert_eq!(
        format!("{HEALTH_URL_ENV}={DEFAULT_HEALTH_URL}"),
        lines(svc, "Environment")[3]
    );
    let node = include_str!("../../../deploy/systemd/telltale.service");
    assert!(
        lines(node, "Environment").contains(&"TELLTALE_UPDATE_CHANNEL=stable"),
        "the node's unit names its channel too"
    );
    // `systemctl` is never looked up through PATH (the service may write /usr/local/bin).
    for (file, src) in [
        ("main.rs", include_str!("main.rs")),
        ("selfupdate.rs", include_str!("selfupdate.rs")),
    ] {
        assert!(
            !src.contains("Command::new(\"systemctl\")"),
            "{file} runs systemctl through PATH"
        );
    }
}

/// REQ: OPS-014 (ADR-182) — one at a time per node: a second request while the first waits for
/// the update service gets `update_in_progress` (409) and the first is kept as it was; so does
/// one while a run says `installing`, but not once that run is older than the update service's
/// limit (it died), nor once the first request is older than the service would take.
#[test]
fn ops_014_a_second_request_waits_for_the_first() {
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    let first = request(&h, "0.8.0", "alice", NOW).unwrap().pending.unwrap();
    let code_of = |e: &Problem| serde_json::to_value(e.code).unwrap();
    let e = request(&h, "0.8.1", "bob", NOW + 1000).unwrap_err();
    assert_eq!(
        (code_of(&e), e.status),
        (serde_json::json!("update_in_progress"), 409),
        "{e:?}"
    );
    let kept: RequestFile =
        serde_json::from_slice(&std::fs::read(h.request_path()).unwrap()).unwrap();
    assert_eq!(
        (kept.id.as_str(), kept.to.as_str()),
        (first.id.as_str(), "0.8.0")
    );
    // A request the update service would refuse for its age is replaced.
    let later = NOW + STALE_REQUEST_MS + 1;
    assert_eq!(
        request(&h, "0.8.1", "bob", later)
            .unwrap()
            .pending
            .unwrap()
            .to,
        "0.8.1"
    );
    // A run under way holds a new request off; one that has said `installing` for longer than
    // the update service may run doesn't.
    std::fs::remove_file(h.request_path()).unwrap();
    let installing = |at_ms: u64| ResultFile {
        id: "1a-2b".into(),
        to: "0.8.1".into(),
        from: "0.7.0".into(),
        state: "installing".into(),
        by: "bob".into(),
        at_ms,
        ..ResultFile::default()
    };
    std::fs::create_dir_all(h.result.parent().unwrap()).unwrap();
    std::fs::write(&h.result, serde_json::to_vec(&installing(later)).unwrap()).unwrap();
    let e = request(&h, "0.8.2", "carol", later + 60_000).unwrap_err();
    assert_eq!(
        code_of(&e),
        serde_json::json!("update_in_progress"),
        "{e:?}"
    );
    assert!(!h.request_path().exists());
    let after = later + RUNNING_MS + 1;
    assert_eq!(
        request(&h, "0.8.2", "carol", after)
            .unwrap()
            .state
            .as_deref(),
        Some("requested")
    );
}

/// REQ: OPS-014, AGT-002 (ADR-182) — a dry run makes the node's checks and says what would
/// happen, and writes nothing: `would_request`, `up_to_date`, or the same refusal a request
/// gets.
#[test]
fn ops_014_a_dry_run_writes_nothing() {
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    assert_eq!(
        dry_run(&h, "0.8.0", NOW).unwrap().state.as_deref(),
        Some("would_request")
    );
    assert_eq!(
        dry_run(&h, "0.7.0", NOW).unwrap().state.as_deref(),
        Some("up_to_date")
    );
    assert_eq!(
        dry_run(&h, "0.6.0", NOW).unwrap_err().code,
        Code::UpdateDowngrade
    );
    assert_eq!(
        dry_run(&h, "0.8.0-edge.1", NOW).unwrap_err().code,
        Code::UpdateChannel
    );
    assert!(
        std::fs::read_dir(d.path()).unwrap().next().is_none(),
        "nothing written"
    );
    request(&h, "0.8.0", "alice", NOW).unwrap();
    assert_eq!(
        dry_run(&h, "0.8.1", NOW).unwrap_err().code,
        Code::UpdateInProgress
    );
}

/// A host whose steps are scripted: the install's outcome, each restart command's and each health
/// check's answer in turn (none left: fine), whether the previous binary can be put back, the
/// channel set for the node, and whether the host is set up for an update (`not_ready`: why
/// not). `calls` has every step, in order.
#[derive(Default)]
struct Scripted {
    install: Option<Result<Outcome, String>>,
    restarts: Vec<Result<(), String>>,
    health: Vec<Result<(), String>>,
    restore_fails: bool,
    channel: Option<String>,
    not_ready: Option<String>,
    calls: Vec<String>,
}

impl Host for Scripted {
    fn channel(&self) -> Option<String> {
        self.channel.clone()
    }
    fn ready(&mut self) -> Result<(), String> {
        self.not_ready.clone().map_or(Ok(()), Err)
    }
    fn install(&mut self, to: &str) -> Result<Outcome, String> {
        self.calls.push(format!("install {to}"));
        self.install
            .take()
            .unwrap_or_else(|| Err("asked twice".into()))
    }
    fn restart(&mut self) -> Result<(), String> {
        self.calls.push("restart".into());
        if self.restarts.is_empty() {
            Ok(())
        } else {
            self.restarts.remove(0)
        }
    }
    fn healthy(&mut self) -> Result<String, String> {
        self.calls.push("healthy".into());
        if self.health.is_empty() {
            Ok("checked at the test's address".into())
        } else {
            self.health
                .remove(0)
                .map(|()| "checked at the test's address".into())
        }
    }
    fn restore(&mut self, previous: &Path) -> Result<(), String> {
        self.calls.push(format!("restore {}", previous.display()));
        if self.restore_fails {
            Err("no such file".into())
        } else {
            Ok(())
        }
    }
}

/// The install's outcome when it swapped the new build in.
fn installed() -> Outcome {
    Outcome::Updated {
        previous: PathBuf::from("/usr/local/bin/telltale.old"),
    }
}

/// REQ: OPS-014 (ADR-182) — the health gate: after the restart the new build must come up
/// healthy. One that doesn't is rolled back once: the previous binary put back, the node restarted
/// and checked again, and the run recorded as `rolled_back` with why (`ctl` stops on it, and
/// systemd sees a failed run). A healthy one is `updated` with no rollback.
#[test]
fn ops_014_a_build_that_does_not_come_up_is_rolled_back() {
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    let asked = request(&h, "0.8.0", "alice", NOW).unwrap().pending.unwrap();
    let mut host = Scripted {
        install: Some(Ok(installed())),
        health: vec![Err("status 503".into()), Ok(())],
        ..Scripted::default()
    };
    let served = serve_request(&h.request_path(), &h.result, "0.7.0", NOW, true, &mut host);
    assert_eq!(
        served,
        Served::Done {
            state: "rolled_back".into()
        }
    );
    assert_eq!(
        host.calls,
        [
            "install 0.8.0",
            "restart",
            "healthy",
            "restore /usr/local/bin/telltale.old",
            "restart",
            "healthy"
        ]
    );
    let last = status(&h).last.unwrap();
    assert_eq!(
        (last.id.as_str(), last.state.as_str()),
        (asked.id.as_str(), "rolled_back")
    );
    let why = last.error.unwrap();
    assert!(
        why.contains("status 503") && why.contains("0.7.0 is back"),
        "{why}"
    );
    assert!(!served_ok("rolled_back"), "systemd sees a failed run");
    // Healthy at once (another node: this one refuses 0.8.0 for a day now): updated, nothing
    // put back, and how its health was checked is recorded.
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    request(&h, "0.8.0", "alice", NOW).unwrap();
    let mut host = Scripted {
        install: Some(Ok(installed())),
        ..Scripted::default()
    };
    let served = serve_request(&h.request_path(), &h.result, "0.7.0", NOW, true, &mut host);
    assert_eq!(
        served,
        Served::Done {
            state: "updated".into()
        }
    );
    assert_eq!(host.calls, ["install 0.8.0", "restart", "healthy"]);
    assert_eq!(
        status(&h).last.unwrap().health.as_deref(),
        Some("checked at the test's address")
    );
    assert!(served_ok("updated") && served_ok("refused"));
}

/// REQ: OPS-014 (ADR-182) — the restart command's own outcome isn't the build's: a `systemctl
/// restart` that outlasts its wait (a long drain, a stop systemd ends with SIGKILL) or exits
/// non-zero goes on to the health check, which decides. Healthy then: `updated`, with the
/// restart's trouble noted in `health` (and nothing held back). Never healthy: rolled back, as
/// any build that doesn't come up.
#[test]
fn ops_014_a_slow_or_failed_restart_command_is_left_to_the_health_check() {
    let slow = "`systemctl restart telltale`: didn't finish within 60 s";
    let failed = "`systemctl restart telltale` exited with exit status: 1";
    for why in [slow, failed] {
        let d = tempfile::tempdir().unwrap();
        let h = here(d.path(), "native", "0.7.0", true);
        request(&h, "0.8.0", "hook", NOW).unwrap();
        let mut host = Scripted {
            install: Some(Ok(installed())),
            restarts: vec![Err(why.into())],
            ..Scripted::default()
        };
        let served = serve_request(&h.request_path(), &h.result, "0.7.0", NOW, true, &mut host);
        assert_eq!(
            served,
            Served::Done {
                state: "updated".into()
            },
            "{why}"
        );
        assert_eq!(host.calls, ["install 0.8.0", "restart", "healthy"], "{why}");
        let s = status(&h);
        let health = s.last.unwrap().health.unwrap();
        assert!(
            health.contains("checked at") && health.contains(why),
            "{health}"
        );
        assert!(s.held.is_none(), "{why}");
    }
    // Slow, and never healthy: rolled back (the previous build put back, restarted, checked).
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    request(&h, "0.8.0", "hook", NOW).unwrap();
    let mut host = Scripted {
        install: Some(Ok(installed())),
        restarts: vec![Err(slow.into())],
        health: vec![Err("not healthy within 120 s".into()), Ok(())],
        ..Scripted::default()
    };
    let served = serve_request(&h.request_path(), &h.result, "0.7.0", NOW, true, &mut host);
    assert_eq!(
        served,
        Served::Done {
            state: "rolled_back".into()
        }
    );
    assert_eq!(
        host.calls,
        [
            "install 0.8.0",
            "restart",
            "healthy",
            "restore /usr/local/bin/telltale.old",
            "restart",
            "healthy"
        ]
    );
    let why = status(&h).last.unwrap().error.unwrap();
    assert!(why.contains("not healthy within 120 s"), "{why}");
}

/// REQ: OPS-014 (ADR-182) — the previous build is back and restarted, but its check fails too:
/// then the check may be what's wrong (an address the node doesn't answer on), and the previous
/// build is in place, so the run is `rolled_back` with a note saying so, not `failed` ("didn't
/// bring the node back"). One attempt, no loop.
#[test]
fn ops_014_a_rollback_whose_check_fails_too_is_recorded_as_rolled_back() {
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    request(&h, "0.8.0", "alice", NOW).unwrap();
    let mut host = Scripted {
        install: Some(Ok(installed())),
        health: vec![Err("status 503".into()), Err("connection refused".into())],
        ..Scripted::default()
    };
    let served = serve_request(&h.request_path(), &h.result, "0.7.0", NOW, true, &mut host);
    assert_eq!(
        served,
        Served::Done {
            state: "rolled_back".into()
        }
    );
    assert_eq!(
        host.calls,
        [
            "install 0.8.0",
            "restart",
            "healthy",
            "restore /usr/local/bin/telltale.old",
            "restart",
            "healthy"
        ]
    );
    let why = status(&h).last.unwrap().error.unwrap();
    assert!(
        why.contains("status 503")
            && why.contains("connection refused")
            && why.contains("0.7.0 is back in place"),
        "{why}"
    );
    assert!(!why.contains("didn't bring the node back"), "{why}");
}

/// REQ: OPS-014 (ADR-182) — one attempt only: if the previous binary can't be put back, the run
/// records `failed` with both reasons and stops (no second rollback, no loop, no restart onto a
/// binary that isn't there).
#[test]
fn ops_014_a_failed_rollback_is_recorded_and_stops() {
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    request(&h, "0.8.0", "alice", NOW).unwrap();
    let mut host = Scripted {
        install: Some(Ok(installed())),
        health: vec![Err("status 503".into())],
        restore_fails: true,
        ..Scripted::default()
    };
    let served = serve_request(&h.request_path(), &h.result, "0.7.0", NOW, true, &mut host);
    assert_eq!(
        served,
        Served::Done {
            state: "failed".into()
        }
    );
    assert_eq!(
        host.calls,
        [
            "install 0.8.0",
            "restart",
            "healthy",
            "restore /usr/local/bin/telltale.old"
        ]
    );
    assert!(!served_ok("failed"));
}

/// REQ: OPS-014 (ADR-182) — a version whose new build was installed and rolled back isn't asked
/// for again on that node for 24 hours, counted from the run the node recorded (not from any
/// request): the node refuses it (`update_failed_recently`, 409: the same check answers the API
/// and the cluster RPC), naming the run, when, what failed, and the two ways out; it shows the
/// hold in its state (for `ctl`'s pre-flight); and the update service refuses it too, whoever
/// wrote the request. Another version may be asked for; once the day is over, the same again.
#[test]
fn ops_014_a_version_that_failed_is_not_asked_for_again_for_a_day() {
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    let run = request(&h, "0.8.0", "hook", NOW).unwrap().pending.unwrap();
    let mut host = Scripted {
        install: Some(Ok(installed())),
        health: vec![Err("status 503".into()), Ok(())],
        ..Scripted::default()
    };
    serve_request(&h.request_path(), &h.result, "0.7.0", NOW, true, &mut host);
    let recorded: ResultFile = read_json(&h.result).unwrap();
    assert_eq!(
        (recorded.state.as_str(), recorded.installed),
        ("rolled_back", true)
    );
    // The clock is the node's record of that run.
    let at = recorded.at_ms;
    let until = rfc3339(at + 24 * 3_600_000);
    let soon = at + 60_000;
    let e = request(&h, "0.8.0", "hook", soon).unwrap_err();
    assert_eq!(
        (serde_json::to_value(e.code).unwrap(), e.status),
        (serde_json::json!("update_failed_recently"), 409),
        "{e:?}"
    );
    let (at_text, until_text) = (rfc3339(at), format!("until {until}"));
    for part in [
        run.id.as_str(),
        "rolled_back",
        at_text.as_str(),
        "status 503",
        until_text.as_str(),
        "telltale self-update --to 0.8.0 --restart",
        "wait until then",
    ] {
        assert!(e.detail.contains(part), "{part}: {}", e.detail);
    }
    assert!(
        e.hint
            .as_deref()
            .is_some_and(|h| h.contains("self-update --to")),
        "{e:?}"
    );
    assert!(!h.request_path().exists(), "nothing is written");
    assert_eq!(
        serde_json::to_value(dry_run(&h, "0.8.0", soon).unwrap_err().code).unwrap(),
        serde_json::json!("update_failed_recently")
    );
    let held = status(&h).held.unwrap();
    assert_eq!(
        (held.to.as_str(), held.until.as_str()),
        ("0.8.0", until.as_str())
    );
    // Another version: asked as usual.
    request(&h, "0.8.1", "hook", soon).unwrap();
    std::fs::remove_file(h.request_path()).unwrap();
    // The update service refuses the held version, however the request was written, and that
    // refusal doesn't wipe the memory of the run.
    let body = serde_json::json!({"id": "1a-2c", "to": "0.8.0", "by": "x", "requestedMs": soon});
    plant(&h, &body.to_string());
    let asked = Cell::new(false);
    let served = serve(&h.request_path(), &h.result, "0.7.0", soon, |_| {
        asked.set(true);
        Err("not here".to_owned())
    });
    assert!(!asked.get(), "nothing is fetched");
    assert_eq!(served, refused());
    let why = status(&h).last.unwrap().error.unwrap();
    assert!(why.contains(&format!("until {until}")), "{why}");
    // Still held a minute before the day is over, counted from the recorded run.
    let almost = at + 24 * 3_600_000 - 60_000;
    assert_eq!(
        serde_json::to_value(request(&h, "0.8.0", "hook", almost).unwrap_err().code).unwrap(),
        serde_json::json!("update_failed_recently")
    );
    // A minute after, the same version again.
    let later = at + 24 * 3_600_000 + 60_000;
    assert_eq!(
        request(&h, "0.8.0", "hook", later)
            .unwrap()
            .state
            .as_deref(),
        Some("requested")
    );
}

/// REQ: OPS-014 (ADR-182) — only a run whose new build was installed and didn't come up holds a
/// version back. One that failed before anything was installed (a network error, the downloads'
/// deadline, a signature or checksum), an edge build the channel moved past (`unavailable`), or a
/// refused request holds nothing: a retry right after is asked for and installed (a passing
/// outage never blocks a version, and the hook, for a day). A run whose previous binary couldn't
/// be put back (`failed` after the install) does hold it.
#[test]
fn ops_014_a_failure_before_the_install_holds_nothing_back() {
    for outcome in [
        Err("https://github.com/x/SHA256SUMS: connect: Network is unreachable".to_owned()),
        Err("the downloads didn't finish within 480 s: nothing installed".to_owned()),
        Err("the signature does not verify with the release key: not trusted".to_owned()),
        Ok(Outcome::Unavailable {
            serves: "0.8.0-edge.9".into(),
            commit: "abc1234".into(),
        }),
    ] {
        let d = tempfile::tempdir().unwrap();
        let h = here(d.path(), "native", "0.8.0-edge.1", true);
        request(&h, "0.8.0-edge.5", "hook", NOW).unwrap();
        let mut host = Scripted {
            install: Some(outcome.clone()),
            ..Scripted::default()
        };
        let current = "0.8.0-edge.1";
        serve_request(&h.request_path(), &h.result, current, NOW, true, &mut host);
        let recorded: ResultFile = read_json(&h.result).unwrap();
        assert!(!recorded.installed, "{outcome:?}");
        assert!(status(&h).held.is_none(), "{outcome:?}");
        let soon = recorded.at_ms + 60_000;
        assert_eq!(
            request(&h, "0.8.0-edge.5", "hook", soon)
                .unwrap()
                .state
                .as_deref(),
            Some("requested"),
            "{outcome:?}"
        );
        let mut host = Scripted {
            install: Some(Ok(installed())),
            ..Scripted::default()
        };
        assert_eq!(
            serve_request(&h.request_path(), &h.result, current, soon, true, &mut host),
            Served::Done {
                state: "updated".into()
            },
            "{outcome:?}: the update service takes the retry"
        );
    }
    // A refused request holds nothing either.
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    plant(&h, "not json");
    let served = serve(&h.request_path(), &h.result, "0.7.0", NOW, |_| {
        Err("must not install".to_owned())
    });
    assert_eq!(served, refused());
    assert!(status(&h).held.is_none());
    // The previous binary couldn't be put back after the install: held.
    request(&h, "0.8.0", "hook", NOW).unwrap();
    let mut host = Scripted {
        install: Some(Ok(installed())),
        health: vec![Err("status 503".into())],
        restore_fails: true,
        ..Scripted::default()
    };
    let served = serve_request(&h.request_path(), &h.result, "0.7.0", NOW, true, &mut host);
    assert_eq!(
        served,
        Served::Done {
            state: "failed".into()
        }
    );
    let recorded: ResultFile = read_json(&h.result).unwrap();
    assert!(recorded.installed);
    assert_eq!(status(&h).held.unwrap().to, "0.8.0");
    assert_eq!(
        code(request(&h, "0.8.0", "hook", recorded.at_ms + 60_000)),
        Code::UpdateFailedRecently
    );
}

/// REQ: OPS-014 (ADR-182) — an edge build main has since passed can't be fetched: the update
/// service records `unavailable`, with the build the channel serves (so `ctl upgrade` can tell it
/// from a failure), installs nothing and doesn't restart the node; systemd sees a failed run.
#[test]
fn ops_014_an_edge_build_no_longer_served_is_unavailable() {
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.8.0-edge.1", true);
    request(&h, "0.8.0-edge.5", "hook", NOW).unwrap();
    let mut host = Scripted {
        install: Some(Ok(Outcome::Unavailable {
            serves: "0.8.0-edge.9".into(),
            commit: "abc1234".into(),
        })),
        ..Scripted::default()
    };
    let served = serve_request(
        &h.request_path(),
        &h.result,
        "0.8.0-edge.1",
        NOW,
        true,
        &mut host,
    );
    assert_eq!(
        served,
        Served::Done {
            state: "unavailable".into()
        }
    );
    assert_eq!(host.calls, ["install 0.8.0-edge.5"], "nothing restarted");
    let last = status(&h).last.unwrap();
    assert_eq!(last.state, "unavailable");
    assert!(
        last.error.unwrap().contains("now serves 0.8.0-edge.9"),
        "the build the channel serves"
    );
    assert!(!served_ok("unavailable"));
}

/// REQ: OPS-014 (ADR-182) — the channel is the one set for the node (`TELLTALE_UPDATE_CHANNEL`,
/// from `install.sh --edge`), not its version's: an edge node that took a release stays on edge
/// and takes the next edge build, at the node (the API and the cluster RPC) and at the update
/// service; a node set to stable refuses an edge build at both, whatever its version; with the
/// variable absent (an older install) the version's channel is used, as before.
#[test]
fn ops_014_an_edge_node_that_took_a_release_stays_on_edge() {
    let d = tempfile::tempdir().unwrap();
    let mut h = here(d.path(), "native", "0.8.0", true);
    h.channel = Some("edge".into());
    assert_eq!(status(&h).channel.as_deref(), Some("edge"));
    assert_eq!(
        request(&h, "0.8.1-edge.3", "hook", NOW)
            .unwrap()
            .state
            .as_deref(),
        Some("requested")
    );
    let mut host = Scripted {
        install: Some(Ok(installed())),
        channel: Some("edge".into()),
        ..Scripted::default()
    };
    let served = serve_request(&h.request_path(), &h.result, "0.8.0", NOW, true, &mut host);
    assert_eq!(
        served,
        Served::Done {
            state: "updated".into()
        }
    );
    assert_eq!(host.calls[0], "install 0.8.1-edge.3");
    // Set to stable: an edge build is refused at the node and at the update service.
    let d = tempfile::tempdir().unwrap();
    let mut h = here(d.path(), "native", "0.8.0-edge.5", true);
    h.channel = Some("stable".into());
    assert_eq!(status(&h).channel.as_deref(), Some("stable"));
    assert_eq!(
        code(request(&h, "0.8.0-edge.9", "hook", NOW)),
        Code::UpdateChannel
    );
    let body =
        serde_json::json!({"id": "1a-2b", "to": "0.8.0-edge.9", "by": "x", "requestedMs": NOW});
    plant(&h, &body.to_string());
    let mut host = Scripted {
        install: Some(Err("must not install".into())),
        channel: Some("stable".into()),
        ..Scripted::default()
    };
    let served = serve_request(
        &h.request_path(),
        &h.result,
        "0.8.0-edge.5",
        NOW,
        true,
        &mut host,
    );
    assert_eq!(served, refused());
    assert!(host.calls.is_empty(), "nothing is fetched");
    assert!(
        status(&h)
            .last
            .unwrap()
            .error
            .unwrap()
            .contains("stable channel")
    );
    // Not set (an older install): the version's channel.
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.8.0", true);
    assert_eq!(status(&h).channel.as_deref(), Some("stable"));
    assert_eq!(
        code(request(&h, "0.8.1-edge.1", "hook", NOW)),
        Code::UpdateChannel
    );
    let h = here(d.path(), "native", "0.8.0-edge.1", true);
    assert_eq!(status(&h).channel.as_deref(), Some("edge"));
}

/// REQ: OPS-014 (ADR-182) — the answer to a request carries the request as written, even when
/// the update service has taken the file already (`ctl upgrade` follows its id); and a peer's
/// `by` keeps its "(unverified)" marker however long the name it sent.
#[test]
fn ops_014_the_answer_names_the_request_written_and_marks_a_peers_by() {
    let dir = tempfile::tempdir().unwrap();
    let h = here(dir.path(), "native", "0.7.0", true);
    let written = RequestFile {
        id: "19a-0badcafe".into(),
        to: "0.8.0".into(),
        by: "alice".into(),
        requested_ms: NOW,
    };
    // No file at all (taken at once): the answer still names it.
    let answer = requested(&h, &written);
    let pending = answer.pending.unwrap();
    assert_eq!(
        (pending.id.as_str(), pending.to.as_str()),
        ("19a-0badcafe", "0.8.0")
    );
    assert_eq!(answer.state.as_deref(), Some("requested"));
    let long = "m".repeat(500);
    let by = peer_by(&long, &"n".repeat(300));
    assert!(by.ends_with(" (unverified)"), "{by}");
    assert!(by.chars().count() <= MAX_BY_STORED, "{}", by.len());
    let asked = request(&h, "0.8.0", &by, NOW).unwrap().pending.unwrap();
    assert!(asked.by.ends_with("(unverified)"), "{}", asked.by);
    // The update service takes such a `by`.
    let mut host = Scripted {
        install: Some(Ok(installed())),
        ..Scripted::default()
    };
    let served = serve_request(&h.request_path(), &h.result, "0.7.0", NOW, true, &mut host);
    assert_eq!(
        served,
        Served::Done {
            state: "updated".into()
        }
    );
    let last = status(&h).last.unwrap();
    assert!(last.by.ends_with("(unverified)"));
    // result.json says `by` is the node's word for it.
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&h.result).unwrap()).unwrap();
    assert_eq!(raw["byVerified"], serde_json::json!(false));
}

/// REQ: OPS-014, AGT-002 (ADR-182) — a dry run never removes anything: not even a request older
/// than the update service would take (a real request replaces it).
#[test]
fn ops_014_a_dry_run_leaves_a_dead_request_in_place() {
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    request(&h, "0.8.0", "alice", NOW).unwrap();
    let later = NOW + STALE_REQUEST_MS + 1;
    assert_eq!(
        dry_run(&h, "0.8.1", later).unwrap().state.as_deref(),
        Some("would_request")
    );
    assert!(h.request_path().exists(), "the dry run left it");
    request(&h, "0.8.1", "bob", later).unwrap();
}

/// REQ: OPS-014 (ADR-182) — a host that isn't set up for an update (an install location root
/// doesn't own alone, a health address it may not use) refuses the run before anything is
/// fetched, and says why; the node isn't restarted.
#[test]
fn ops_014_a_host_not_set_up_for_it_refuses_before_fetching() {
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    request(&h, "0.8.0", "alice", NOW).unwrap();
    let mut host = Scripted {
        install: Some(Err("must not install".into())),
        not_ready: Some(
            "install location is not root-owned: /home/pi/bin belongs to uid 1000".into(),
        ),
        ..Scripted::default()
    };
    let served = serve_request(&h.request_path(), &h.result, "0.7.0", NOW, true, &mut host);
    assert_eq!(served, refused());
    assert!(host.calls.is_empty(), "{:?}", host.calls);
    assert!(
        status(&h)
            .last
            .unwrap()
            .error
            .unwrap()
            .starts_with("install location is not root-owned")
    );
}

/// REQ: OPS-014 (ADR-182) — the health gate's address comes from the unit only: unset is the
/// old default (an older unit); empty (the API is off) is no check, so nothing is installed
/// (`refused: no health check configured`): nothing could prove the new build came up; and a
/// value must be a plain `http://` URL of `/readyz` at an IP address and port of this host.
#[test]
fn ops_014_the_health_gate_takes_only_a_plain_address_of_this_host() {
    let here_ip = |ip: std::net::IpAddr| ip == std::net::IpAddr::from([192, 168, 3, 2]);
    assert_eq!(
        health_gate(None, here_ip),
        Ok(HealthGate::Check(DEFAULT_HEALTH_URL.into()))
    );
    let e = health_gate(Some(""), here_ip).unwrap_err();
    assert!(
        e.starts_with("no health check configured") && e.contains(HEALTH_URL_ENV),
        "{e}"
    );
    for ok in [
        "http://127.0.0.1:8053/readyz?startup=1",
        "http://127.0.0.1:9443/readyz",
        "http://[::1]:8053/readyz?startup=1",
        "http://192.168.3.2:8053/readyz?startup=1",
    ] {
        assert_eq!(
            health_gate(Some(ok), here_ip),
            Ok(HealthGate::Check(ok.into())),
            "{ok}"
        );
    }
    for (bad, why) in [
        ("https://127.0.0.1:8053/readyz", "plain http://"),
        ("http://localhost:8053/readyz", "IP address and port"),
        ("http://user@127.0.0.1:8053/readyz", "IP address and port"),
        ("http://127.0.0.1/readyz", "IP address and port"),
        ("http://127.0.0.1:8053/metrics", "/readyz"),
        ("http://127.0.0.1:8053/readyz?x=1", "/readyz"),
        ("http://0.0.0.0:8053/readyz", "address one can ask"),
        ("http://10.9.9.9:8053/readyz", "of this host"),
        ("http://192.0.2.1:8053/readyz?startup=1", "of this host"),
    ] {
        let e = health_gate(Some(bad), here_ip).unwrap_err();
        assert!(e.contains(why) && e.contains(HEALTH_URL_ENV), "{bad}: {e}");
    }
    // The real check: loopback is this host's; a documentation address isn't (no packet sent).
    assert!(is_this_host(std::net::IpAddr::from([127, 0, 0, 1])));
    assert!(!is_this_host(std::net::IpAddr::from([192, 0, 2, 1])));
    // A unit whose variable is empty: the run is refused before anything is fetched, and the
    // node isn't restarted.
    let d = tempfile::tempdir().unwrap();
    let h = here(d.path(), "native", "0.7.0", true);
    request(&h, "0.8.0", "alice", NOW).unwrap();
    let mut host = Scripted {
        install: Some(Err("must not install".into())),
        not_ready: health_gate(Some(""), |_| false).err(),
        ..Scripted::default()
    };
    let served = serve_request(&h.request_path(), &h.result, "0.7.0", NOW, true, &mut host);
    assert_eq!(served, refused());
    assert!(host.calls.is_empty(), "{:?}", host.calls);
    assert!(
        status(&h)
            .last
            .unwrap()
            .error
            .unwrap()
            .starts_with("no health check configured")
    );
}

/// REQ: OPS-014 (ADR-182) — root runs and renames binaries only where root alone can write: the
/// binary and every folder above it owned by root and not writable by group or others (here
/// with this user standing in for root, in a folder of its own).
#[cfg(unix)]
#[test]
fn ops_014_the_install_location_must_be_roots_alone() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let top = d.path().canonicalize().unwrap();
    let bin = top.join("usr").join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let exe = bin.join("telltale");
    std::fs::write(&exe, "x").unwrap();
    let mode = |p: &Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m));
    for p in [&top, &top.join("usr"), &bin] {
        mode(p, 0o755).unwrap();
    }
    mode(&exe, 0o755).unwrap();
    let me = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(&exe).unwrap().uid()
    };
    assert_eq!(root_owned(&exe, me, &top), Ok(()));
    // Another owner.
    let e = root_owned(&exe, me + 1, &top).unwrap_err();
    assert!(e.starts_with("install location is not root-owned"), "{e}");
    // A folder its group may write, or a binary anyone may.
    mode(&bin, 0o775).unwrap();
    let e = root_owned(&exe, me, &top).unwrap_err();
    assert!(e.contains(&bin.display().to_string()), "{e}");
    mode(&bin, 0o755).unwrap();
    mode(&exe, 0o757).unwrap();
    assert!(root_owned(&exe, me, &top).is_err());
    mode(&exe, 0o755).unwrap();
    // Any folder on the way that anyone may write. (The walk stops at `top`, so the world-writable
    // temporary folder above it isn't looked at; in production `top` is `/`.)
    mode(&top.join("usr"), 0o777).unwrap();
    assert!(root_owned(&exe, me, &top).is_err());
}

/// REQ: OPS-014 (ADR-182) — the whole run (one deadline for the downloads, the test run, the
/// restart and health window, and a rollback's reset, restart and window) fits in the unit's
/// `TimeoutStartSec=` with a minute to spare, so systemd never kills it between the install and
/// its check (which would leave the new build unchecked and the run `installing`).
#[test]
fn ops_014_the_run_fits_in_the_units_time_limit() {
    let svc = include_str!("../../../deploy/systemd/telltale-update.service");
    let limit: u64 = svc
        .lines()
        .find_map(|l| l.strip_prefix("TimeoutStartSec="))
        .and_then(|v| v.trim().parse().ok())
        .expect("TimeoutStartSec");
    assert_eq!(HEALTH_WAIT.as_secs(), 120);
    assert_eq!(crate::selfupdate::FETCH_DEADLINE.as_secs(), 480);
    // REQ: OPS-004, OPS-014 — the budget counts the pauses of the "text file busy" tries before each
    // of the run's bounded programs, so raising `EXEC_TRIES` or `EXEC_PAUSE` can't use up the minute.
    assert_eq!(BOUNDED_RUNS, 4, "test run, restart, reset, second restart");
    let retry = crate::selfupdate::exec_retry_secs(BOUNDED_RUNS);
    assert!(retry >= 1, "the retry pauses are part of the budget");
    assert!(
        run_budget_secs() + 60 <= limit,
        "the run may take {} s (of which {retry} s of exec retries), the unit allows {limit} s",
        run_budget_secs()
    );
    // The node's lock on a run that says `installing` is the unit's limit.
    assert_eq!(RUNNING_MS / 1000, limit);
    // REQ: OPS-014 (ADR-182) — the restart command is waited for longer than the node unit takes
    // to stop (a drain, then SIGKILL), so the old process is gone when the health check starts.
    let node = include_str!("../../../deploy/systemd/telltale.service");
    let stop: u64 = node
        .lines()
        .find_map(|l| l.strip_prefix("TimeoutStopSec="))
        .and_then(|v| v.trim().parse().ok())
        .expect("TimeoutStopSec");
    assert!(crate::selfupdate::RESTART_WAIT.as_secs() >= 2 * stop);
    // REQ: OPS-014 (ADR-182) — `ctl upgrade` (and the chart's hook) waits for a node at least as
    // long as the update service may take.
    let ctl = crate::ctl::parse_duration(crate::ctl::UPGRADE_TIMEOUT).unwrap();
    assert!(
        u64::from(ctl) >= run_budget_secs(),
        "ctl waits {ctl} s, the run may take {} s",
        run_budget_secs()
    );
    let values = include_str!("../../../deploy/helm/telltale/values.yaml");
    let hook: u32 = values
        .lines()
        .skip_while(|l| !l.starts_with("upgradeHook:"))
        .find_map(|l| l.trim().strip_prefix("timeout: "))
        .and_then(|v| crate::ctl::parse_duration(v).ok())
        .expect("upgradeHook.timeout");
    assert!(
        u64::from(hook) >= run_budget_secs(),
        "the hook waits {hook} s"
    );
}

#[test]
fn ops_014_a_version_picks_its_channel() {
    assert_eq!(channel_for("0.8.0"), crate::selfupdate::Channel::Stable);
    assert_eq!(
        channel_for("0.8.0-edge.393"),
        crate::selfupdate::Channel::Edge
    );
}
