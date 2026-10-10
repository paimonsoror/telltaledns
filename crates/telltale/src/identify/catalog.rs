//! Device signatures (REQ: OBS-025, ADR-117): the shipped catalog (`presets/devices.toml`)
//! plus an optional local file (`[identify] signatures_file`) in the same shape, where a
//! signature with a shipped `id` replaces it and `enabled = false` removes it.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;
use telltale_config::DeviceClass;

static SHIPPED: &str = include_str!("../../../../presets/devices.toml");
/// Most domains one signature may list (signatures are meant to be short).
const MAX_DOMAINS: usize = 16;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    device: Vec<SignatureIn>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureIn {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default = "unknown_class")]
    class: DeviceClass,
    #[serde(default)]
    vendors: Vec<String>,
    #[serde(default)]
    vendor_required: bool,
    #[serde(default)]
    hostname_patterns: Vec<String>,
    #[serde(default)]
    domains: Vec<DomainIn>,
    #[serde(default = "yes")]
    enabled: bool,
}

const fn yes() -> bool {
    true
}

const fn unknown_class() -> DeviceClass {
    DeviceClass::Other
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainIn {
    name: String,
    weight: f32,
}

/// One signature, normalized: lowercase matching keys, domains sorted by name.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Signature {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) class: DeviceClass,
    pub(crate) vendors: Vec<String>,
    pub(crate) vendor_required: bool,
    pub(crate) hostname_patterns: Vec<String>,
    /// The same, as characters (matched without allocating).
    pub(crate) hostname_globs: Vec<Vec<char>>,
    pub(crate) domains: Vec<(String, f32)>,
    pub(crate) total_weight: f32,
}

fn normalize(s: SignatureIn, origin: &str) -> Result<Option<Signature>, String> {
    let id = s.id.trim().to_owned();
    if id.is_empty() {
        return Err(format!("{origin}: a signature without an `id`"));
    }
    if !s.enabled {
        return Ok(None);
    }
    if s.name.trim().is_empty() {
        return Err(format!("{origin}: signature `{id}` has no `name`"));
    }
    if s.domains.len() > MAX_DOMAINS {
        return Err(format!(
            "{origin}: signature `{id}` lists more than {MAX_DOMAINS} domains"
        ));
    }
    let mut domains: Vec<(String, f32)> = Vec::with_capacity(s.domains.len());
    for d in s.domains {
        if !(d.weight.is_finite() && d.weight > 0.0) {
            return Err(format!(
                "{origin}: signature `{id}`: domain `{}` needs a positive weight",
                d.name
            ));
        }
        let name = d.name.trim().trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty() || domains.iter().any(|(n, _)| *n == name) {
            return Err(format!(
                "{origin}: signature `{id}`: an empty or repeated domain"
            ));
        }
        domains.push((name, d.weight));
    }
    domains.sort_by(|a, b| a.0.cmp(&b.0));
    // Fixed order, so the sum is the same everywhere.
    let total_weight = domains.iter().map(|d| d.1).sum();
    let lower = |v: Vec<String>| -> Vec<String> {
        v.into_iter()
            .map(|x| x.trim().to_lowercase())
            .filter(|x| !x.is_empty())
            .collect()
    };
    let hostname_patterns = lower(s.hostname_patterns);
    let hostname_globs = hostname_patterns
        .iter()
        .map(|p| p.chars().collect())
        .collect();
    Ok(Some(Signature {
        id,
        name: s.name.trim().to_owned(),
        class: s.class,
        vendors: lower(s.vendors),
        vendor_required: s.vendor_required,
        hostname_patterns,
        hostname_globs,
        domains,
        total_weight,
    }))
}

/// Parses a signatures file: `(id, Some(signature))`, or `(id, None)` for a removal.
fn parse(text: &str, origin: &str) -> Result<Vec<(String, Option<Signature>)>, String> {
    let f: File = toml::from_str(text).map_err(|e| format!("{origin}: {e}"))?;
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::with_capacity(f.device.len());
    for s in f.device {
        let id = s.id.trim().to_owned();
        if !seen.insert(id.clone()) {
            return Err(format!("{origin}: signature `{id}` appears twice"));
        }
        out.push((id, normalize(s, origin)?));
    }
    Ok(out)
}

/// The shipped catalog, by `id` (empty only if the embedded file were broken: a test keeps
/// that from shipping).
pub(crate) fn shipped() -> &'static [Signature] {
    static S: OnceLock<Vec<Signature>> = OnceLock::new();
    S.get_or_init(|| {
        parse(SHIPPED, "presets/devices.toml")
            .map(|v| {
                let mut v: Vec<Signature> = v.into_iter().filter_map(|(_, s)| s).collect();
                v.sort_by(|a, b| a.id.cmp(&b.id));
                v
            })
            .unwrap_or_default()
    })
}

/// The catalog in effect: the shipped one with `extra` (a local file's text) merged in,
/// sorted by `id`.
pub(crate) fn with_extra(extra: Option<(&str, &str)>) -> Result<Vec<Signature>, String> {
    let mut by_id: BTreeMap<String, Signature> = shipped()
        .iter()
        .map(|s| (s.id.clone(), s.clone()))
        .collect();
    if let Some((text, origin)) = extra {
        for (id, s) in parse(text, origin)? {
            match s {
                Some(s) => {
                    by_id.insert(id, s);
                }
                None => {
                    by_id.remove(&id);
                }
            }
        }
    }
    Ok(by_id.into_values().collect())
}

/// The shipped catalog's text parses (tests and `telltale config check`).
pub(crate) fn check_shipped() -> Result<usize, String> {
    parse(SHIPPED, "presets/devices.toml").map(|v| v.len())
}
