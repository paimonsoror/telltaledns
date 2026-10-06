//! Built-in upstream presets (REQ: UPS-004, `spec/04` §3).
//!
//! The catalog (`presets/upstreams.toml`) is compiled in. A preset is never referenced from
//! config: [`Preset::expand`] turns it into explicit `[[upstream]]` entries plus a group, so the
//! running config always shows exactly what's being used.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::endpoint::{Endpoint, Host, Protocol};

const CATALOG: &str = include_str!("../../../presets/upstreams.toml");

/// What a resolver filters on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Filtering {
    None,
    Malware,
    Family,
    Ads,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetEndpoint {
    pub url: String,
    #[serde(default)]
    pub tls_server_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    pub id: String,
    pub name: String,
    pub homepage: String,
    /// Incumbents that offer this preset ("pihole", "technitium").
    pub sources: Vec<String>,
    pub filtering: Filtering,
    pub dnssec: bool,
    pub ecs: bool,
    /// Placeholders used in URLs as `{name}`.
    #[serde(default)]
    pub params: Vec<String>,
    pub endpoint: Vec<PresetEndpoint>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    preset: Vec<Preset>,
}

/// The compiled-in catalog. Errors only if the shipped file is malformed (caught by tests).
pub fn catalog() -> Result<&'static [Preset], String> {
    static PARSED: OnceLock<Result<Vec<Preset>, String>> = OnceLock::new();
    PARSED
        .get_or_init(|| {
            toml::from_str::<Catalog>(CATALOG)
                .map(|c| c.preset)
                .map_err(|e| format!("presets/upstreams.toml: {e}"))
        })
        .as_deref()
        .map_err(Clone::clone)
}

/// Looks a preset up by ID.
pub fn find(id: &str) -> Option<&'static Preset> {
    catalog().ok()?.iter().find(|p| p.id == id)
}

/// One expanded `[[upstream]]` entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExpandedUpstream {
    pub name: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bootstrap: Vec<String>,
}

/// One expanded `[[upstream_group]]`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExpandedGroup {
    pub name: String,
    pub members: Vec<String>,
    pub strategy: String,
}

/// Result of expanding a preset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Expansion {
    pub upstream: Vec<ExpandedUpstream>,
    pub upstream_group: Vec<ExpandedGroup>,
    /// Endpoints left out, with the reason (unsupported protocol, IPv6 disabled, ...).
    #[serde(skip)]
    pub skipped: Vec<(String, String)>,
}

impl Expansion {
    /// Ready-to-paste `telltale.toml` snippet.
    pub fn to_toml(&self) -> Result<String, String> {
        toml::to_string(self).map_err(|e| e.to_string())
    }
}

/// An endpoint after parameter substitution, with its parsed form or why it can't be used.
pub type ResolvedEndpoint = (PresetEndpoint, Result<Endpoint, String>);

/// Options for [`Preset::expand`].
#[derive(Clone, Debug, Default)]
pub struct ExpandOptions {
    /// Only these protocols (empty = every supported one).
    pub protocols: Vec<Protocol>,
    /// Values for the preset's `params`.
    pub params: BTreeMap<String, String>,
    /// Leave out IPv6 endpoints.
    pub no_ipv6: bool,
    /// Group name (default: the preset ID).
    pub group: Option<String>,
}

fn valid_param(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Preset {
    /// Endpoints after substituting parameters, paired with their parsed form (or why not).
    pub fn endpoints(
        &self,
        params: &BTreeMap<String, String>,
    ) -> Result<Vec<ResolvedEndpoint>, String> {
        let missing: Vec<_> = self
            .params
            .iter()
            .filter(|p| !params.contains_key(*p))
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "preset `{}` needs: {}",
                self.id,
                missing
                    .iter()
                    .map(|p| format!("--param {p}=..."))
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
        }
        let mut out = Vec::new();
        for ep in &self.endpoint {
            let mut url = ep.url.clone();
            for name in &self.params {
                let v = &params[name];
                if !valid_param(v) {
                    return Err(format!(
                        "parameter `{name}`: only letters, digits, `-`, `_` allowed"
                    ));
                }
                url = url.replace(&format!("{{{name}}}"), v);
            }
            let parsed = Endpoint::parse(&url);
            out.push((
                PresetEndpoint {
                    url,
                    tls_server_name: ep.tls_server_name.clone(),
                },
                parsed,
            ));
        }
        Ok(out)
    }

    /// Plain IPv4 addresses this provider publishes, used as bootstrap for its hostnames.
    fn own_bootstrap(&self) -> Vec<String> {
        self.endpoint
            .iter()
            .filter_map(|e| Endpoint::parse(&e.url).ok())
            .filter(|e| e.protocol == Protocol::Udp)
            .filter_map(|e| match e.host {
                Host::Ip(ip) if ip.is_ipv4() => Some(ip.to_string()),
                _ => None,
            })
            .take(2)
            .collect()
    }

    /// Expands into explicit upstreams and one `fastest` group.
    pub fn expand(&self, opts: &ExpandOptions) -> Result<Expansion, String> {
        let bootstrap = self.own_bootstrap();
        let group = opts.group.clone().unwrap_or_else(|| self.id.clone());
        let mut upstream = Vec::new();
        let mut skipped = Vec::new();
        let mut counters: BTreeMap<Protocol, usize> = BTreeMap::new();
        for (ep, parsed) in self.endpoints(&opts.params)? {
            let parsed = match parsed {
                Ok(p) => p,
                Err(e) => {
                    skipped.push((ep.url, e));
                    continue;
                }
            };
            if !opts.protocols.is_empty() && !opts.protocols.contains(&parsed.protocol) {
                continue;
            }
            if opts.no_ipv6 && matches!(parsed.host, Host::Ip(ip) if ip.is_ipv6()) {
                skipped.push((ep.url, "IPv6 disabled".into()));
                continue;
            }
            let n = counters.entry(parsed.protocol).or_insert(0);
            *n += 1;
            upstream.push(ExpandedUpstream {
                name: format!("{}-{}-{n}", self.id, parsed.protocol),
                url: ep.url,
                tls_server_name: ep.tls_server_name,
                bootstrap: if matches!(parsed.host, Host::Name(_)) {
                    bootstrap.clone()
                } else {
                    Vec::new()
                },
            });
        }
        if upstream.is_empty() {
            return Err(format!(
                "preset `{}`: no usable endpoints for the chosen options",
                self.id
            ));
        }
        let members = upstream.iter().map(|u| u.name.clone()).collect();
        Ok(Expansion {
            upstream,
            upstream_group: vec![ExpandedGroup {
                name: group,
                members,
                strategy: "fastest".into(),
            }],
            skipped,
        })
    }

    /// Protocols this preset offers (whether or not TelltaleDNS supports them yet).
    pub fn protocols(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .endpoint
            .iter()
            .filter_map(|e| e.url.split_once("://").map(|(s, _)| s.to_string()))
            .collect();
        v.dedup();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ups_004_catalog_parses_and_ids_are_unique() {
        let c = catalog().unwrap();
        let mut ids: Vec<_> = c.iter().map(|p| p.id.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n, "duplicate preset ids");
    }

    #[test]
    fn ups_004_every_pihole_preset_is_present() {
        // The Pi-hole web UI's upstream presets.
        for id in [
            "google",
            "opendns",
            "level3",
            "comodo",
            "quad9",
            "quad9-unfiltered",
            "quad9-ecs",
            "cloudflare",
        ] {
            let p = find(id).unwrap_or_else(|| panic!("missing Pi-hole preset {id}"));
            assert!(
                p.sources.iter().any(|s| s == "pihole"),
                "{id} should be tagged pihole"
            );
        }
    }

    #[test]
    fn ups_004_common_technitium_providers_are_present() {
        for id in [
            "cloudflare",
            "google",
            "quad9",
            "adguard",
            "nextdns",
            "mullvad",
            "controld",
        ] {
            assert!(find(id).is_some(), "missing {id}");
        }
    }

    #[test]
    fn ups_004_every_endpoint_parses_or_is_a_known_future_protocol() {
        for p in catalog().unwrap() {
            let params = p
                .params
                .iter()
                .map(|k| (k.clone(), "abc123".to_string()))
                .collect();
            for (ep, parsed) in p.endpoints(&params).unwrap() {
                match parsed {
                    Ok(e) => {
                        if e.protocol == Protocol::Tls && matches!(e.host, Host::Ip(_)) {
                            assert!(
                                ep.tls_server_name.is_some(),
                                "{}: IP DoT needs tls_server_name",
                                ep.url
                            );
                        }
                    }
                    Err(err) => assert!(ep.url.starts_with("quic://"), "{}: {err}", ep.url),
                }
            }
        }
    }

    #[test]
    fn ups_004_expansion_is_valid_config() {
        let exp = find("quad9")
            .unwrap()
            .expand(&ExpandOptions::default())
            .unwrap();
        assert!(exp.upstream.iter().any(|u| u.url.starts_with("tls://")));
        let doh = exp
            .upstream
            .iter()
            .find(|u| u.url.starts_with("https://"))
            .unwrap();
        assert_eq!(
            doh.bootstrap,
            vec!["9.9.9.9", "149.112.112.112"],
            "own IPs bootstrap own hostnames"
        );
        let text = exp.to_toml().unwrap();
        let loaded = telltale_config::Loader::new()
            .toml_str("preset.toml", text.clone())
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap_or_else(|e| panic!("{e:?}\n{text}"));
        assert_eq!(loaded.config.upstream_group[0].name.as_str(), "quad9");
    }

    #[test]
    fn ups_004_templated_presets_need_params_and_include_doq() {
        let p = find("nextdns").unwrap();
        assert!(
            p.expand(&ExpandOptions::default())
                .unwrap_err()
                .contains("--param profile=")
        );
        let mut opts = ExpandOptions::default();
        opts.params.insert("profile".into(), "a1b2c3".into());
        let exp = p.expand(&opts).unwrap();
        assert_eq!(exp.upstream[0].url, "tls://a1b2c3.dns.nextdns.io");
        // UPS-002 (T7.7) — DoQ endpoints expand like the rest.
        assert!(exp.skipped.is_empty(), "{:?}", exp.skipped);
        assert!(
            exp.upstream
                .iter()
                .any(|u| u.url == "quic://a1b2c3.dns.nextdns.io")
        );
        opts.params.insert("profile".into(), "bad/../x".into());
        assert!(p.expand(&opts).is_err(), "parameters are validated");
    }

    #[test]
    fn ups_004_protocol_filter_and_ipv6_toggle() {
        let opts = ExpandOptions {
            protocols: vec![Protocol::Udp],
            no_ipv6: true,
            ..ExpandOptions::default()
        };
        let exp = find("cloudflare").unwrap().expand(&opts).unwrap();
        assert_eq!(exp.upstream.len(), 2);
        assert!(exp.upstream.iter().all(|u| u.url.starts_with("udp://1.")));
    }
}
