//! REQ: OBS-010, API-002 (ADR-179) — where a credential file named through the API may be: in a
//! folder meant for secrets. Docker and Compose put secrets in `/run/secrets/`, the Helm chart's
//! `secretMounts` in `/etc/telltale-secrets/`, and anything else can go in the data directory's
//! `secrets/` folder. Kubernetes' own service-account files (`/run/secrets/kubernetes.io/`) are
//! not a credential file's place.
//!
//! The path is compared by its components, first as written and then with its links followed as
//! far as it exists, against the folders with theirs followed: so `/run/secrets-x` is not under
//! `/run/secrets`, the links a Kubernetes Secret mount is made of (`token -> ..data/token`) stay
//! inside, and a link that leads out of a folder is refused, also when what it leads to isn't
//! there yet. A file that doesn't exist yet passes on the path alone: an administrator may create
//! it afterwards. Config-file entries never come here.

use std::path::{Path, PathBuf};

/// The folders meant for secrets besides `<data_dir>/secrets/`.
const FIXED_ROOTS: &[&str] = &["/run/secrets", "/etc/telltale-secrets"];

/// Under `/run/secrets` but never a credential file's place: the pod's service-account token, CA
/// and namespace, and (review round 2, security N5) the cloud workload-identity tokens projected
/// next to them: EKS's `eks.amazonaws.com` and Azure's `azure` (`/var/run/secrets/...` is the
/// same folder where `/var/run` links to `/run`). One list, for alert destinations (ADR-179) and
/// routers (ADR-181); it is checked as written and with links followed.
const EXCLUDED: &[&str] = &[
    "/run/secrets/kubernetes.io",
    "/var/run/secrets/kubernetes.io",
    "/run/secrets/eks.amazonaws.com",
    "/var/run/secrets/eks.amazonaws.com",
    "/run/secrets/azure",
    "/var/run/secrets/azure",
];

/// REQ: OBS-010, API-002 (ADR-179, ADR-181) — review round 2, security N6: what the routers
/// feature keeps in `<data_dir>/secrets/` (a router's key pasted in the UI, the list of them and
/// its temporary files, the request key), by the first name under that folder. An alert
/// destination never names one, so even an administrator can't send a key pasted in the UI to an
/// alert's address. A key a platform mounts (`/run/secrets/`, `/etc/telltale-secrets/`) is a
/// different case: an administrator may still name one for an alert destination, as ADR-179 has
/// it. Compared without regard to ASCII case (review round 3, S3: on a case-insensitive mount,
/// `ROUTER-x` opens `router-x`).
fn feature_file(first: &std::ffi::OsStr) -> bool {
    first.to_str().is_some_and(|n| {
        let n = n.to_ascii_lowercase();
        n.starts_with("router-") || n.starts_with(".written") || n.starts_with(".request-key")
    })
}

/// Links followed before giving up (a loop, or a chain that long, is refused).
const MAX_LINKS: u8 = 40;

/// The rule, as error messages say it.
pub(crate) fn places() -> &'static str {
    "an absolute path to a file under /run/secrets/, /etc/telltale-secrets/ or the data directory's secrets/ folder (not /run/secrets/kubernetes.io/), written without `.`, `..` or empty parts"
}

/// What the check asks the filesystem: the real calls, or a test's. A seam, because some answers
/// (a folder this process may not search) can't be made on a machine that runs tests as root.
struct Look {
    canonicalize: fn(&Path) -> std::io::Result<PathBuf>,
    /// `Ok(true)`: a link (not followed).
    is_link: fn(&Path) -> std::io::Result<bool>,
    read_link: fn(&Path) -> std::io::Result<PathBuf>,
}

fn fs_canonicalize(p: &Path) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(p)
}

fn fs_is_link(p: &Path) -> std::io::Result<bool> {
    std::fs::symlink_metadata(p).map(|m| m.file_type().is_symlink())
}

fn fs_read_link(p: &Path) -> std::io::Result<PathBuf> {
    std::fs::read_link(p)
}

/// The filesystem itself.
const FS: Look = Look {
    canonicalize: fs_canonicalize,
    is_link: fs_is_link,
    read_link: fs_read_link,
};

/// Whether `path` is a place for a credential file on a node whose data directory is
/// `data_dir`. Blocking (it may look at the filesystem). The answer says nothing about what is
/// there: every refusal is the same `false`.
pub(crate) fn allowed(path: &str, data_dir: &str) -> bool {
    allowed_with(&FS, path, data_dir)
}

/// [`allowed`], asking `look`.
fn allowed_with(look: &Look, path: &str, data_dir: &str) -> bool {
    let Some(p) = written(path) else {
        return false;
    };
    within(look, &p, &roots(data_dir)) && !names_a_feature_file(look, &p, data_dir)
}

/// Whether `p` (in normal form), as written or with its links followed, is one of the files the
/// routers feature keeps in `<data_dir>/secrets/` ([`feature_file`]).
fn names_a_feature_file(look: &Look, p: &Path, data_dir: &str) -> bool {
    let Some(d) = written(data_dir.trim_end_matches('/')) else {
        return false;
    };
    let folder = d.join("secrets");
    let first_under = |path: &Path, root: &Path| {
        path.strip_prefix(root)
            .ok()
            .and_then(|rest| rest.components().next())
            .is_some_and(|c| feature_file(c.as_os_str()))
    };
    let real_folder = resolve(look, &folder, 0);
    // A path that can't be resolved is refused by `within` already.
    let real = resolve(look, p, 0);
    first_under(p, &folder)
        || real.as_deref().is_some_and(|r| {
            first_under(r, &folder) || real_folder.as_deref().is_some_and(|f| first_under(r, f))
        })
}

/// REQ: API-002, T8.2 (ADR-181) — whether `path` is in this node's `<data_dir>/secrets/` folder,
/// by the rule of [`allowed`] (normal form, compared by components as written and with its links
/// followed) with that folder the only one: where the API writes a router's pasted key, and the
/// only place a key file it recorded is used from, or removed from. Blocking.
pub(crate) fn in_data_secrets(path: &str, data_dir: &str) -> bool {
    in_data_secrets_with(&FS, path, data_dir)
}

/// REQ: API-002, T8.2 (ADR-181) — the folders a platform fills with secrets, without the data
/// directory's: `/run/secrets/` (Docker and Compose) and `/etc/telltale-secrets/` (the Helm chart's
/// `secretMounts`).
pub(crate) fn mount_roots() -> Vec<PathBuf> {
    FIXED_ROOTS.iter().map(PathBuf::from).collect()
}

/// REQ: API-002, T8.2 (ADR-181) — [`mount_roots`] for a node whose data directory is `data_dir`:
/// the one list the use-time rule and the merge of the API's entries both ask. In test builds
/// only, `<data_dir>/mount` stands in for them too, so a test can put a mounted key there.
pub(crate) fn mount_roots_for(data_dir: &str) -> Vec<PathBuf> {
    #[cfg(test)]
    {
        let mut v = mount_roots();
        v.push(Path::new(data_dir).join("mount"));
        v
    }
    #[cfg(not(test))]
    {
        let _ = data_dir;
        mount_roots()
    }
}

/// REQ: API-002, T8.2 (ADR-181) — whether `path` is in one of `roots` (normally
/// [`mount_roots`]) by [`allowed`]'s rule: normal form, compared by components as written and
/// with links followed, never under Kubernetes' own `kubernetes.io` folder. Blocking.
pub(crate) fn in_folders(path: &str, roots: &[PathBuf]) -> bool {
    written(path).is_some_and(|p| within(&FS, &p, roots))
}

/// REQ: API-002, T8.2 (ADR-181) — review round 4 (final review M2): whether `path`, as written,
/// is under this node's `<data_dir>/secrets/` folder: both in normal form, compared by
/// components, and nothing looked up on the filesystem, so the answer can't change with what is
/// on disk (a link, a folder this process can't search). The merge of the API's entries asks it,
/// and must fail closed.
pub(crate) fn in_data_secrets_as_written(path: &str, data_dir: &str) -> bool {
    let (Some(p), Some(d)) = (written(path), written(data_dir.trim_end_matches('/'))) else {
        return false;
    };
    let folder = d.join("secrets");
    p.starts_with(&folder) && p != folder
}

/// [`in_data_secrets`], asking `look`.
fn in_data_secrets_with(look: &Look, path: &str, data_dir: &str) -> bool {
    let (Some(p), Some(d)) = (written(path), written(data_dir.trim_end_matches('/'))) else {
        return false;
    };
    within(look, &p, &[d.join("secrets")])
}

/// `p` (in normal form) is strictly under one of `roots`, as written and with its links followed
/// against the folders with theirs followed.
fn within(look: &Look, p: &Path, roots: &[PathBuf]) -> bool {
    if !inside(look, p, roots) {
        return false;
    }
    // The same, with links followed.
    let Some(real) = resolve(look, p, 0) else {
        return false;
    };
    let real_roots: Vec<PathBuf> = roots.iter().filter_map(|r| resolve(look, r, 0)).collect();
    inside(look, &real, &real_roots)
}

/// `path` as written, if it is in normal form: absolute, no empty, `.` or `..` part, no NUL.
fn written(path: &str) -> Option<PathBuf> {
    let rest = path.strip_prefix('/')?;
    if rest.is_empty() || path.contains('\0') {
        return None;
    }
    rest.split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..")
        .then(|| PathBuf::from(path))
}

/// The folders for `data_dir` (its `secrets/` counts only when the data directory is itself
/// written in normal form).
fn roots(data_dir: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = FIXED_ROOTS.iter().map(PathBuf::from).collect();
    if let Some(d) = written(data_dir.trim_end_matches('/')) {
        v.push(d.join("secrets"));
    }
    v
}

/// `p` is strictly under one of `roots` (by components) and not under an excluded folder, as
/// written or with its links followed.
fn inside(look: &Look, p: &Path, roots: &[PathBuf]) -> bool {
    let excluded = EXCLUDED.iter().map(PathBuf::from).chain(
        EXCLUDED
            .iter()
            .filter_map(|x| resolve(look, Path::new(x), 0)),
    );
    roots.iter().any(|r| p.starts_with(r) && p != r)
        && !excluded.into_iter().any(|x| p.starts_with(&x))
        && p.components().all(|c| {
            matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

/// `p` with its links followed as far as it exists, the rest as written; `None` (refused) for a
/// loop, a link that can't be read, or a part that can't be looked at (only a part that isn't
/// there lets the rest be taken as written).
fn resolve(look: &Look, p: &Path, links: u8) -> Option<PathBuf> {
    if links > MAX_LINKS {
        return None;
    }
    let parts: Vec<_> = p.components().collect();
    for i in (1..=parts.len()).rev() {
        let head: PathBuf = parts[..i].iter().collect();
        let tail: PathBuf = parts[i..].iter().collect();
        let missing = match (look.canonicalize)(&head) {
            Ok(real) => {
                return Some(if tail.as_os_str().is_empty() {
                    real
                } else {
                    real.join(tail)
                });
            }
            Err(e) => e.kind() == std::io::ErrorKind::NotFound,
        };
        match (look.is_link)(&head) {
            // A link whose target isn't there (yet), or a loop: follow it as written.
            Ok(true) => {
                let target = (look.read_link)(&head).ok()?;
                let parent = head.parent()?;
                let next = if target.is_absolute() {
                    target
                } else {
                    parent.join(target)
                };
                return resolve(look, &next.join(tail), links + 1);
            }
            // Not there: look one level up.
            Err(_) if missing => {}
            // There but not resolvable, or not to be looked at: refused.
            _ => return None,
        }
    }
    Some(p.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory for one test (removed at the end).
    struct Dir(PathBuf);
    impl Dir {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!(
                "telltale-secret-path-{tag}-{}-{}",
                std::process::id(),
                crate::maintenance::now_ms()
            ));
            std::fs::create_dir_all(&d).unwrap();
            Self(std::fs::canonicalize(&d).unwrap())
        }
        fn s(&self) -> String {
            self.0.to_str().unwrap().to_owned()
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// REQ: OBS-010 (ADR-179) — the rule by the path alone (none of these exist).
    #[test]
    fn obs_010_a_credential_file_is_under_a_secrets_folder_by_its_components() {
        let data = "/var/lib/telltale-test-data";
        for ok in [
            "/run/secrets/ntfy-token",
            "/run/secrets/nested/smtp-password",
            "/etc/telltale-secrets/ntfy/token",
            "/var/lib/telltale-test-data/secrets/ntfy-token",
        ] {
            assert!(allowed(ok, data), "{ok}");
        }
        for bad in [
            "",
            "/",
            "relative/token",
            "./run/secrets/x",
            "/run/secrets",
            "/run/secrets/",
            "/run/secrets//x",
            "/run/secrets/x/",
            "/run/secrets/./x",
            "/run/secrets/../etc/passwd",
            "/run/secrets/a\0b",
            "/run/secrets-evil/x",
            "/run/secretsx",
            "/run/secrets/kubernetes.io",
            "/run/secrets/kubernetes.io/serviceaccount/token",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/etc/telltale-secrets",
            "/etc/telltale-secretsx/y",
            "/var/lib/telltale-test-data/state.db",
            "/var/lib/telltale-test-data/secrets",
            "/var/lib/telltale-test-data/secrets/../state.db",
            "/etc/shadow",
            "/proc/self/environ",
        ] {
            assert!(!allowed(bad, data), "{bad:?}");
        }
        // A data directory not written in normal form adds no folder.
        assert!(!allowed("/x/secrets/t", "x"));
        assert!(!allowed("/x/../secrets/t", "/x/.."));
        assert!(allowed("/x/secrets/t", "/x/"));
    }

    /// REQ: OBS-010 (ADR-179) — links: a Kubernetes Secret mount's stay inside and pass; a link
    /// out of the folder, to a file, through a linked folder, to something not there yet, or in
    /// a loop, is refused.
    #[cfg(unix)]
    #[test]
    fn obs_010_links_are_followed_before_the_folder_is_compared() {
        use std::os::unix::fs::symlink;
        let d = Dir::new("links");
        let data = d.s();
        let sec = d.0.join("secrets");
        std::fs::create_dir_all(sec.join("..2026_11_19_00_00_00.1")).unwrap();
        std::fs::write(sec.join("..2026_11_19_00_00_00.1/token"), "t").unwrap();
        symlink("..2026_11_19_00_00_00.1", sec.join("..data")).unwrap();
        symlink("..data/token", sec.join("token")).unwrap();
        std::fs::create_dir_all(d.0.join("out")).unwrap();
        std::fs::write(d.0.join("out/file"), "x").unwrap();
        symlink(d.0.join("out/file"), sec.join("to-file")).unwrap();
        symlink(d.0.join("out"), sec.join("to-folder")).unwrap();
        symlink(d.0.join("not-there"), sec.join("dangling")).unwrap();
        symlink("../out/later", sec.join("dangling-relative")).unwrap();
        symlink("loop-b", sec.join("loop-a")).unwrap();
        symlink("loop-a", sec.join("loop-b")).unwrap();
        let p = |s: &str| format!("{data}/secrets/{s}");
        for ok in ["token", "..data/token", "not-yet", "sub/not-yet"] {
            assert!(allowed(&p(ok), &data), "{ok}");
        }
        for bad in [
            "to-file",
            "to-folder/file",
            "to-folder/not-yet",
            "dangling",
            "dangling-relative",
            "loop-a",
        ] {
            assert!(!allowed(&p(bad), &data), "{bad}");
        }
        // The data directory reached through a link of its own is still its folder.
        let alias = Dir::new("alias");
        let link = alias.0.join("data");
        symlink(&d.0, &link).unwrap();
        assert!(allowed(
            &format!("{}/secrets/token", link.to_str().unwrap()),
            link.to_str().unwrap()
        ));
    }

    /// REQ: OBS-010, API-002 (ADR-179, ADR-181) — review round 2, security N5: the cloud
    /// workload-identity tokens projected under `/run/secrets/` (`/var/run/secrets/`) are no
    /// credential file's place, for an alert destination (`allowed`) or a router (`in_folders`):
    /// EKS's `eks.amazonaws.com` and Azure's `azure`, as written and through a link.
    #[test]
    fn obs_010_cloud_identity_tokens_are_no_credential_files() {
        let data = "/var/lib/telltale-test-data";
        let roots = mount_roots();
        for bad in [
            "/run/secrets/eks.amazonaws.com/serviceaccount/token",
            "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
            "/run/secrets/azure/tokens/azure-identity-token",
            "/var/run/secrets/azure/tokens/azure-identity-token",
            "/run/secrets/kubernetes.io/serviceaccount/token",
        ] {
            assert!(!allowed(bad, data), "alert destination: {bad}");
            assert!(!in_folders(bad, &roots), "router: {bad}");
        }
        for ok in ["/run/secrets/unifi-key", "/etc/telltale-secrets/unifi/key"] {
            assert!(allowed(ok, data), "{ok}");
            assert!(in_folders(ok, &roots), "{ok}");
        }
    }

    /// REQ: OBS-010, API-002 (ADR-179, ADR-181) — review round 2, security N6: an alert
    /// destination can't name a file this feature keeps in `<data_dir>/secrets/` (a router's
    /// key, the list of them, the request key), as written or through a link, even for an
    /// administrator; any other file there is still allowed. The router's own rule is unchanged.
    #[cfg(unix)]
    #[test]
    fn obs_010_an_alert_destination_names_no_router_key() {
        use std::os::unix::fs::symlink;
        let d = Dir::new("feature-files");
        let data = d.s();
        let sec = d.0.join("secrets");
        std::fs::create_dir_all(&sec).unwrap();
        for f in [
            "router-udm.api_key.0123456789abcdef",
            ".written",
            ".request-key",
            "ntfy-token",
        ] {
            std::fs::write(sec.join(f), "x").unwrap();
        }
        symlink(
            sec.join("router-udm.api_key.0123456789abcdef"),
            sec.join("alias"),
        )
        .unwrap();
        let p = |s: &str| format!("{data}/secrets/{s}");
        for bad in [
            "router-udm.api_key.0123456789abcdef",
            "router-anything",
            ".written",
            ".written.0123456789abcdef.tmp",
            ".request-key",
            "alias",
        ] {
            assert!(!allowed(&p(bad), &data), "{bad}");
        }
        assert!(allowed(&p("ntfy-token"), &data));
        assert!(allowed(&p("nested/token"), &data));
        assert!(in_data_secrets(
            &p("router-udm.api_key.0123456789abcdef"),
            &data
        ));
    }

    /// REQ: OBS-010, API-002 (ADR-179, ADR-181) — review round 3, security S3: the feature's
    /// files are recognised whatever the ASCII case of the name (a case-insensitive mount opens
    /// `ROUTER-x` as `router-x`); an ordinary file of any case is still allowed.
    #[test]
    fn obs_010_feature_files_are_refused_in_any_case() {
        let data = "/var/lib/telltale-test-data";
        let p = |s: &str| format!("{data}/secrets/{s}");
        for bad in [
            "ROUTER-udm.api_key.0123456789abcdef",
            "Router-udm",
            ".Request-Key",
            ".WRITTEN",
            ".Written.0123456789abcdef.tmp",
        ] {
            assert!(!allowed(&p(bad), data), "{bad}");
        }
        assert!(allowed(&p("NTFY-Token"), data));
    }

    /// REQ: API-002, T8.2 (ADR-181) — a router key the API wrote is in the data directory's
    /// `secrets/` and nowhere else: the other folders for secrets, the data directory itself, a
    /// path not in normal form, and a link that leads out are not.
    #[cfg(unix)]
    #[test]
    fn api_002_a_router_key_is_in_the_data_directorys_secrets_folder() {
        use std::os::unix::fs::symlink;
        let d = Dir::new("router-keys");
        let data = d.s();
        let sec = d.0.join("secrets");
        std::fs::create_dir_all(&sec).unwrap();
        std::fs::write(sec.join("router-udm.api_key.1"), "k").unwrap();
        std::fs::write(d.0.join("state.db"), "db").unwrap();
        symlink(d.0.join("state.db"), sec.join("to-state")).unwrap();
        let p = |s: &str| format!("{data}/secrets/{s}");
        for ok in ["router-udm.api_key.1", "not-yet"] {
            assert!(in_data_secrets(&p(ok), &data), "{ok}");
        }
        for bad in [
            p("to-state"),
            p("../state.db"),
            format!("{data}/secrets"),
            format!("{data}/state.db"),
            "/run/secrets/udm-key".to_owned(),
            "/etc/telltale-secrets/udm/api_key".to_owned(),
            "secrets/router-udm.api_key.1".to_owned(),
        ] {
            assert!(!in_data_secrets(&bad, &data), "{bad}");
        }
        assert!(!in_data_secrets(&p("router-udm.api_key.1"), "relative"));
    }

    /// REQ: OBS-010 (ADR-179) — fails closed: a path whose links can't be looked at (a folder on
    /// the way this process may not search) is refused, not taken as written.
    #[cfg(unix)]
    #[test]
    fn obs_010_a_path_that_cannot_be_looked_at_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = Dir::new("locked");
        let data = d.s();
        let locked = d.0.join("secrets/locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::write(locked.join("token"), "t").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Root searches any folder: there is nothing it can't look at.
        let can_look = std::fs::read_dir(&locked).is_ok();
        let answer = allowed(&format!("{data}/secrets/locked/token"), &data);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        if can_look {
            // The same rule is checked whoever runs the tests, through the seam below.
            println!(
                "skipped: this process can search a folder of mode 000 (root), so the case can't be made here"
            );
        } else {
            assert!(!answer, "a path that can't be looked at is refused");
        }
    }

    /// A filesystem that has `/`, `/run`, `/run/secrets`, `/run/secrets/locked`, `/var` and
    /// `/var/lib/t`, and answers "permission denied" for everything under `/run/secrets/locked/`.
    fn fake_canonicalize(p: &Path) -> std::io::Result<PathBuf> {
        if p.starts_with("/run/secrets/locked") && p != Path::new("/run/secrets/locked") {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        let there = [
            "/",
            "/run",
            "/run/secrets",
            "/run/secrets/locked",
            "/var",
            "/var/lib",
            "/var/lib/t",
        ];
        if there.iter().any(|t| p == Path::new(t)) {
            Ok(p.to_path_buf())
        } else {
            Err(std::io::ErrorKind::NotFound.into())
        }
    }

    fn fake_is_link(p: &Path) -> std::io::Result<bool> {
        fake_canonicalize(p).map(|_| false)
    }

    fn fake_read_link(_: &Path) -> std::io::Result<PathBuf> {
        Err(std::io::ErrorKind::InvalidInput.into())
    }

    /// REQ: OBS-010 (ADR-179) — fails closed whoever runs the tests: through the seam, a part
    /// of the path that answers "permission denied" is refused, and a part that isn't there yet
    /// lets the rest be taken as written.
    #[test]
    fn obs_010_a_part_that_answers_permission_denied_is_refused() {
        let look = Look {
            canonicalize: fake_canonicalize,
            is_link: fake_is_link,
            read_link: fake_read_link,
        };
        assert!(!allowed_with(
            &look,
            "/run/secrets/locked/token",
            "/var/lib/t"
        ));
        assert!(!allowed_with(
            &look,
            "/run/secrets/locked/sub/token",
            "/var/lib/t"
        ));
        assert!(allowed_with(&look, "/run/secrets/token", "/var/lib/t"));
        assert!(allowed_with(&look, "/run/secrets/new/token", "/var/lib/t"));
        assert!(allowed_with(
            &look,
            "/var/lib/t/secrets/token",
            "/var/lib/t"
        ));
    }
}
