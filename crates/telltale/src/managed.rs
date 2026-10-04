//! Config made through the API and UI, merged with the config files (REQ: API-002, API-010;
//! ADR-040).
//!
//! Entries live in `state.db` by kind and name. The files stay authoritative: an entry the
//! files define is read-only through the API, and the API can't create a name the files use.
//! If the merged config doesn't validate (say a group named by an API client was removed
//! from the file), the files alone are used and the reason is logged: DNS never waits on, or
//! breaks because of, the API layer.

use std::path::Path;

use telltale_config::{ClientConfig, Config};
use telltale_store::state::State;
use tracing::{error, warn};

/// The kind name for devices.
pub(crate) const CLIENT: &str = "client";

/// Where the state database lives.
pub(crate) fn state_path(cfg: &Config) -> std::path::PathBuf {
    Path::new(cfg.node.data_dir.as_str()).join("state.db")
}

/// Devices stored through the API, decoded (bad rows are skipped with a warning).
pub(crate) fn clients(state: &State) -> Vec<ClientConfig> {
    let rows = match state.managed(CLIENT) {
        Ok(r) => r,
        Err(e) => {
            warn!("devices named in the UI are unavailable: {e}");
            return Vec::new();
        }
    };
    rows.into_iter()
        .filter_map(|m| match serde_json::from_str::<ClientConfig>(&m.body) {
            Ok(c) => Some(c),
            Err(e) => {
                warn!(device = %m.name, "skipping a stored device: {e}");
                None
            }
        })
        .collect()
}

/// `file` plus `extra` devices (names the files already use are skipped), if the result
/// validates; otherwise `Err` with the reasons.
pub(crate) fn merge_clients(
    file: &Config,
    extra: Vec<ClientConfig>,
) -> Result<Config, Vec<String>> {
    let mut cfg = file.clone();
    for c in extra {
        if cfg.client.iter().any(|f| f.name == c.name) {
            continue;
        }
        cfg.client.push(c);
    }
    telltale_config::validate_config(&cfg)
        .map(|_| cfg)
        .map_err(|errs| errs.iter().map(ToString::to_string).collect())
}

/// The effective config: `file` plus what the API stored. Opens `state.db` briefly; any
/// problem falls back to `file`.
pub(crate) fn effective(file: &Config) -> Config {
    let path = state_path(file);
    if !path.exists() {
        return file.clone();
    }
    let state = match State::open(&path) {
        Ok(s) => s,
        Err(e) => {
            warn!("devices named in the UI are unavailable ({e}); using the config files only");
            return file.clone();
        }
    };
    match merge_clients(file, clients(&state)) {
        Ok(c) => c,
        Err(errs) => {
            for e in &errs {
                error!("config made in the UI/API: {e}");
            }
            error!(
                "ignoring devices named in the UI until this is fixed; using the config files only"
            );
            file.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_config::SafeString;

    fn client(name: &str, ip: &str, groups: &[&str]) -> ClientConfig {
        ClientConfig {
            name: SafeString::new(name).unwrap(),
            match_keys: vec![SafeString::new(ip).unwrap()],
            groups: groups
                .iter()
                .map(|g| SafeString::new(*g).unwrap())
                .collect(),
        }
    }

    #[test]
    fn api_010_files_win_and_bad_entries_fall_back() {
        let mut file = Config::default();
        file.client
            .push(client("nas", "192.168.1.10", &["default"]));
        let merged = merge_clients(
            &file,
            vec![
                client("tv", "192.168.1.20", &["default"]),
                client("nas", "192.168.1.99", &["default"]), // the file's name: ignored
            ],
        )
        .unwrap();
        let names: Vec<&str> = merged.client.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["nas", "tv"]);
        assert_eq!(merged.client[0].match_keys[0].as_str(), "192.168.1.10");
        // A group that doesn't exist: the merge is refused with the reason.
        let err =
            merge_clients(&file, vec![client("phone", "192.168.1.30", &["kids"])]).unwrap_err();
        assert!(err.iter().any(|e| e.contains("kids")), "{err:?}");
    }

    #[test]
    fn api_010_effective_reads_state_db() {
        let dir = tempfile::tempdir().unwrap();
        let mut file = Config::default();
        file.node.data_dir = SafeString::new(dir.path().to_str().unwrap()).unwrap();
        assert_eq!(effective(&file), file, "no state.db yet");
        let state = State::open(&state_path(&file)).unwrap();
        let body = serde_json::to_string(&client("tv", "192.168.1.20", &["default"])).unwrap();
        state
            .put_managed(CLIENT, "tv", &body, None, None, 1, "admin")
            .unwrap();
        state
            .put_managed(CLIENT, "junk", "not json", None, None, 2, "admin")
            .unwrap();
        let eff = effective(&file);
        assert_eq!(eff.client.len(), 1);
        assert_eq!(eff.client[0].name.as_str(), "tv");
    }
}
