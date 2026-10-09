//! Configuration schema, validation, env overrides, and migrations.
//!
//! Part of TelltaleDNS. See `spec/02-architecture.md` §2 and `spec/08` §5.
//!
//! ```no_run
//! let loaded = telltale_config::Loader::new()
//!     .file("/etc/telltale/telltale.toml")
//!     .process_env()
//!     .load()
//!     .map_err(|errs| errs.into_iter().map(|e| e.to_string()).collect::<Vec<_>>());
//! ```

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]

mod env;
pub mod safesearch;
pub mod schedule;
pub mod schema;
pub mod services;
pub mod shared;
mod types;
mod validate;

use std::fmt;
use std::path::Path;

use toml::{Table, Value};

pub use env::ENV_PREFIX;
pub use schema::*;
pub use types::{ByteSize, Cidr, SafeString, parse_rfc3339};
pub use validate::{MAX_LISTS, MatchKey, UPSTREAM_SCHEMES, probe_target, valid_list_name};

/// A config problem located by its key path (e.g. `upstream[1].url`, `cache.bogus`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{path}: {message}")]
pub struct ConfigError {
    /// Dotted key path, with `[n]` for array elements. A file name for I/O and syntax errors.
    pub path: String,
    pub message: String,
}

impl ConfigError {
    pub fn new(path: impl Into<String>, message: impl fmt::Display) -> Self {
        Self {
            path: path.into(),
            message: message.to_string(),
        }
    }
}

/// A successfully loaded config plus non-fatal warnings.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub config: Config,
    pub warnings: Vec<String>,
}

/// Builds a [`Config`] from layered sources.
///
/// REQ: OPS-005 — precedence: built-in defaults < files (in the order added; later wins) <
/// environment variables. Tables merge key by key; arrays and scalars replace.
#[derive(Debug, Default)]
pub struct Loader {
    layers: Vec<(String, Result<String, String>)>,
    env: Vec<(String, String)>,
}

impl Loader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a TOML file layer. A read failure is reported by [`Loader::load`].
    #[must_use]
    pub fn file(mut self, path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read file: {e}"));
        self.layers.push((path.display().to_string(), text));
        self
    }

    /// Adds an in-memory TOML layer; `origin` names it in errors.
    #[must_use]
    pub fn toml_str(mut self, origin: impl Into<String>, text: impl Into<String>) -> Self {
        self.layers.push((origin.into(), Ok(text.into())));
        self
    }

    /// Uses these variables as the environment (for tests and embedding).
    #[must_use]
    pub fn env<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.env = vars
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self
    }

    /// Uses the process environment (non-UTF-8 variables are skipped).
    #[must_use]
    pub fn process_env(mut self) -> Self {
        self.env = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect();
        self
    }

    /// Merges, applies env overrides, deserializes, and validates. Returns every error found.
    pub fn load(self) -> Result<Loaded, Vec<ConfigError>> {
        let mut errors = Vec::new();
        let defaults = Table::try_from(Config::default())
            .map_err(|e| vec![ConfigError::new("<defaults>", e)])?;

        let mut root = Table::new();
        for (origin, text) in &self.layers {
            match text {
                Err(msg) => errors.push(ConfigError::new(origin.clone(), msg)),
                Ok(text) => match text.parse::<Table>() {
                    Ok(t) => merge(&mut root, t),
                    Err(e) => {
                        errors.push(ConfigError::new(origin.clone(), e.to_string().trim_end()));
                    }
                },
            }
        }
        let mut warnings = env::apply(&mut root, &defaults, &self.env, &mut errors);
        if !errors.is_empty() {
            return Err(errors);
        }

        let config: Config = match serde_path_to_error::deserialize(Value::Table(root)) {
            Ok(c) => c,
            Err(e) => {
                let path = e.path().to_string();
                let path = if path == "." {
                    "<root>".to_owned()
                } else {
                    path
                };
                // toml appends an "in `table`" context line; the path already says that.
                let msg = e.into_inner().to_string();
                let msg = msg.lines().next().unwrap_or_default().trim_end();
                return Err(vec![ConfigError::new(path, msg)]);
            }
        };

        warnings.extend(validate::validate(&config, &mut errors));
        if errors.is_empty() {
            Ok(Loaded { config, warnings })
        } else {
            Err(errors)
        }
    }
}

/// Deep-merges `over` into `base`: tables merge recursively, everything else replaces.
fn merge(base: &mut Table, over: Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(Value::Table(b)), Value::Table(o)) => merge(b, o),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

/// Validates a config built in code (the files plus entries made through the API,
/// ADR-040). Returns the warnings, or every error.
pub fn validate_config(config: &Config) -> Result<Vec<String>, Vec<ConfigError>> {
    let mut errors = Vec::new();
    let warnings = validate::validate(config, &mut errors);
    if errors.is_empty() {
        Ok(warnings)
    } else {
        Err(errors)
    }
}

/// JSON Schema for `telltale.toml` (`telltale config schema`), for editor completion.
pub fn json_schema() -> schemars::Schema {
    schemars::schema_for!(Config)
}
