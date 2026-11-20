//! REQ: OPS-011 (ADR-156) — the support package's pure core.
//!
//! A person who hits a problem sends one archive that holds what triage needs and nothing that
//! identifies them. This crate has the parts that need no running server, so they can be tested to
//! death: a `.tar.gz` writer ([`archive`]), keyed pseudonyms that keep structure ([`pseudo`]),
//! text redaction ([`redact`]), configuration classification that fails closed ([`classify`]), the
//! manifest ([`manifest`]), and the [`package::Package`] that puts them together. What goes into
//! the package, and when, is the `telltale` crate's job.

use serde::{Deserialize, Serialize};

pub mod archive;
pub mod classify;
pub mod cluster;
pub mod manifest;
pub mod package;
pub mod pseudo;
pub mod redact;

/// How much of the package is obfuscated (ADR-156).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub enum Level {
    /// IP and MAC addresses, host, device, client, group, node and pod names, e-mail addresses, URL
    /// hosts, and home paths are pseudonyms; no query names, no free text; only warnings and errors
    /// from the log. The default.
    #[default]
    #[serde(rename = "strict")]
    Strict,
    /// As `strict`, plus INFO log lines, top lists with pseudonymized names, and the opt-in
    /// query-log sample.
    #[serde(rename = "standard")]
    Standard,
    /// Values as they are. Secrets are still removed.
    #[serde(rename = "none")]
    Off,
}

impl Level {
    /// `strict`, `standard`, or `none`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Standard => "standard",
            Self::Off => "none",
        }
    }

    /// Reads a level's name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "strict" => Some(Self::Strict),
            "standard" => Some(Self::Standard),
            "none" => Some(Self::Off),
            _ => None,
        }
    }

    /// What the level means for reading the package, in a sentence or two.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::Strict => {
                "Addresses, MAC addresses, host, device, group, node, pod and namespace names, e-mail addresses, \
                 URL hosts and home paths are replaced by pseudonyms (device-1, group-2, ...): the same value \
                 always gets the same pseudonym inside this package, addresses on one subnet stay on one subnet, \
                 and private addresses stay private. No query names, no local zone contents and no free text \
                 are included, and the log holds warnings and errors only."
            }
            Self::Standard => {
                "As strict, and the log also holds INFO lines, top lists are included with pseudonymized names, \
                 and a sample of the query log is included if it was asked for."
            }
            Self::Off => {
                "Values are shown as they are: real addresses, names, and domains. Secrets (passwords, tokens, \
                 keys, credentials) are still removed. Read the package yourself before you attach it."
            }
        }
    }
}

impl std::fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_011_levels_parse_and_print_their_names() {
        for l in [Level::Strict, Level::Standard, Level::Off] {
            assert_eq!(Level::parse(l.as_str()), Some(l));
            assert_eq!(l.to_string(), l.as_str());
            assert_ne!(l.meaning(), "");
        }
        assert_eq!(Level::parse(" STRICT "), Some(Level::Strict));
        assert_eq!(Level::parse("off"), None);
        assert_eq!(Level::default(), Level::Strict);
        assert_eq!(serde_json::to_string(&Level::Off).unwrap(), "\"none\"");
    }
}
