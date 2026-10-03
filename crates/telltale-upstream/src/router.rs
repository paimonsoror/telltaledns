//! Routing queries to upstream groups by domain suffix, client group, and qtype.
//!
//! REQ: UPS-007, DNS-017 (conditional forwarding incl. reverse zones). The longest matching
//! suffix wins; routes without suffixes match any name. Unmatched queries use `default`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use std::net::SocketAddr;

use telltale_config::{Config, HttpVersion, Strategy as CfgStrategy};
use telltale_proto::NameBuf;

use crate::bootstrap::Bootstrap;
use crate::endpoint::{Endpoint, Host};
use crate::group::{Group, Strategy};
use crate::tls::TlsOptions;
use crate::upstream::{Question, Upstream, UpstreamOptions};

#[derive(Debug)]
struct Route {
    suffixes: Vec<NameBuf>,
    client_groups: Vec<String>,
    qtypes: Vec<u16>,
    target: usize,
}

/// The selected group plus a cache view ID that keeps answers from different groups apart.
#[derive(Debug, Clone, Copy)]
pub struct Selection<'a> {
    pub group: &'a Arc<Group>,
    pub view: u16,
}

/// Routing table built from config.
#[derive(Debug, Default)]
pub struct Router {
    groups: Vec<Arc<Group>>,
    by_name: HashMap<String, usize>,
    routes: Vec<Route>,
    default: Option<usize>,
    upstreams: Vec<Arc<Upstream>>,
}

impl Router {
    /// Builds upstreams, groups, and routes with the built-in trust roots.
    pub fn from_config(cfg: &Config) -> Result<Self, Vec<String>> {
        Self::from_config_with(cfg, &TlsOptions::default())
    }

    /// Like [`Router::from_config`] with extra TLS settings. Options that aren't implemented
    /// yet are reported as errors rather than silently ignored.
    pub fn from_config_with(cfg: &Config, tls: &TlsOptions) -> Result<Self, Vec<String>> {
        let mut errors = Vec::new();
        let (upstreams, ups) = build_upstreams(cfg, tls, &mut errors);
        Self::assemble(cfg, upstreams, &ups, errors)
    }
}

/// Builds every `[[upstream]]`; problems are appended to `errors`.
fn build_upstreams<'c>(
    cfg: &'c Config,
    tls: &TlsOptions,
    errors: &mut Vec<String>,
) -> (Vec<Arc<Upstream>>, HashMap<&'c str, Arc<Upstream>>) {
    let mut ups: HashMap<&str, Arc<Upstream>> = HashMap::new();
    let mut upstreams = Vec::new();
    // UPS-009: shared system bootstrap, never pointing at our own listeners.
    let listen: Vec<_> = cfg.listen.iter().map(|l| l.addr).collect();
    let mut system_bootstrap: Option<Arc<Bootstrap>> = None;
    for (i, u) in cfg.upstream.iter().enumerate() {
        let id = u16::try_from(i + 1).unwrap_or(u16::MAX);
        let ep = match Endpoint::parse(&u.url) {
            Ok(ep) => ep,
            Err(e) => {
                errors.push(format!("upstream `{}`: {e}", u.name));
                continue;
            }
        };
        for (set, what) in [
            (!u.spki_pins.is_empty(), "spki_pins"),
            (u.proxy.is_some(), "proxy"),
            (u.ecs.as_deref().is_some_and(|e| e != "strip"), "ecs"),
            (u.http_version == HttpVersion::H3, "http_version = \"3\""),
        ] {
            if set {
                errors.push(format!(
                    "upstream `{}`: `{what}` is not supported yet",
                    u.name
                ));
            }
        }
        let bootstrap = match (&ep.host, u.bootstrap.is_empty()) {
            (Host::Ip(_), _) => None,
            (Host::Name(_), false) => Some(Arc::new(Bootstrap::new(
                u.bootstrap
                    .iter()
                    .map(|ip| SocketAddr::new(*ip, 53))
                    .collect(),
            ))),
            (Host::Name(_), true) => {
                let bs =
                    system_bootstrap.get_or_insert_with(|| Arc::new(Bootstrap::system(&listen)));
                if bs.servers().is_empty() {
                    errors.push(format!(
                            "upstream `{}`: hostname URL but no bootstrap servers (set `bootstrap = [\"9.9.9.9\"]` or use an IP)",
                            u.name
                        ));
                }
                Some(Arc::clone(bs))
            }
        };
        let opts = UpstreamOptions {
            timeout: Duration::from_millis(u64::from(u.timeout_ms)),
            weight: u.weight,
            pool_size: usize::from(u.pool_size),
            idle_timeout: Duration::from_millis(u64::from(u.idle_timeout_ms)),
            tls_server_name: u.tls_server_name.as_ref().map(ToString::to_string),
            tls_insecure_skip_verify: u.tls_insecure_skip_verify,
            headers: u
                .headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            bootstrap,
        };
        match Upstream::build(id, u.name.as_str(), ep, &opts, tls) {
            Ok(up) => {
                let up = Arc::new(up);
                upstreams.push(Arc::clone(&up));
                ups.insert(u.name.as_str(), up);
            }
            Err(e) => errors.push(e),
        }
    }
    (upstreams, ups)
}

impl Router {
    /// Builds groups and routes over already-built upstreams.
    fn assemble(
        cfg: &Config,
        upstreams: Vec<Arc<Upstream>>,
        ups: &HashMap<&str, Arc<Upstream>>,
        mut errors: Vec<String>,
    ) -> Result<Self, Vec<String>> {
        let mut groups = Vec::new();
        let mut by_name = HashMap::new();
        for g in &cfg.upstream_group {
            let members: Vec<_> = g
                .members
                .iter()
                .filter_map(|m| ups.get(m.as_str()).cloned())
                .collect();
            if members.len() != g.members.len() {
                continue; // a member failed above; already reported
            }
            let strategy = match g.strategy {
                CfgStrategy::Failover => Strategy::Failover,
                CfgStrategy::RoundRobin => Strategy::RoundRobin,
                CfgStrategy::Weighted => Strategy::Weighted,
                CfgStrategy::Fastest => Strategy::Fastest,
                CfgStrategy::Parallel => Strategy::Parallel {
                    fanout: usize::from(g.parallel_fanout),
                },
            };
            by_name.insert(g.name.to_string(), groups.len());
            groups.push(Arc::new(Group::new(g.name.as_str(), members, strategy)));
        }
        let mut routes = Vec::new();
        for (i, r) in cfg.route.iter().enumerate() {
            let Some(&target) = by_name.get(r.upstream_group.as_str()) else {
                continue;
            };
            let mut suffixes = Vec::new();
            for s in &r.match_suffix {
                match NameBuf::from_presentation(s) {
                    Ok(n) => suffixes.push(n),
                    Err(e) => errors.push(format!("route[{i}]: invalid suffix `{s}`: {e}")),
                }
            }
            let mut qtypes = Vec::new();
            for t in &r.match_qtype {
                match parse_qtype(t) {
                    Some(v) => qtypes.push(v),
                    None => errors.push(format!("route[{i}]: unknown qtype `{t}`")),
                }
            }
            routes.push(Route {
                suffixes,
                client_groups: r.match_group.iter().map(ToString::to_string).collect(),
                qtypes,
                target,
            });
        }
        let default = by_name.get("default").copied();
        if errors.is_empty() {
            Ok(Self {
                groups,
                by_name,
                routes,
                default,
                upstreams,
            })
        } else {
            Err(errors)
        }
    }

    /// Builds a router directly (tests, embedding).
    pub fn from_groups(groups: Vec<Arc<Group>>) -> Self {
        let by_name: HashMap<_, _> = groups
            .iter()
            .enumerate()
            .map(|(i, g)| (g.name.clone(), i))
            .collect();
        let default = by_name.get("default").copied();
        let upstreams = groups
            .iter()
            .flat_map(|g| g.members().iter().cloned())
            .collect();
        Self {
            groups,
            by_name,
            routes: Vec::new(),
            default,
            upstreams,
        }
    }

    /// Picks the group for `q` asked by a client in `client_groups`.
    pub fn select(&self, q: &Question, client_groups: &[&str]) -> Option<Selection<'_>> {
        let mut best: Option<(usize, usize)> = None; // (suffix label count, target)
        for r in &self.routes {
            if !r.qtypes.is_empty() && !r.qtypes.contains(&q.qtype) {
                continue;
            }
            if !r.client_groups.is_empty()
                && !r
                    .client_groups
                    .iter()
                    .any(|g| client_groups.contains(&g.as_str()))
            {
                continue;
            }
            let depth = if r.suffixes.is_empty() {
                Some(0)
            } else {
                r.suffixes
                    .iter()
                    .filter(|s| q.name.is_subdomain_of(s))
                    .map(NameBuf::label_count)
                    .max()
            };
            if let Some(d) = depth
                && best.is_none_or(|(bd, _)| d > bd)
            {
                best = Some((d, r.target));
            }
        }
        let idx = best.map(|(_, t)| t).or(self.default)?;
        Some(Selection {
            group: &self.groups[idx],
            view: u16::try_from(idx).unwrap_or(u16::MAX),
        })
    }

    pub fn group(&self, name: &str) -> Option<&Arc<Group>> {
        self.by_name.get(name).map(|&i| &self.groups[i])
    }

    pub fn upstreams(&self) -> &[Arc<Upstream>] {
        &self.upstreams
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}

/// Parses `A`, `aaaa`, `PTR`, ..., or `TYPE65`.
pub fn parse_qtype(s: &str) -> Option<u16> {
    use telltale_proto::rtype;
    let up = s.trim().to_ascii_uppercase();
    Some(match up.as_str() {
        "A" => rtype::A,
        "NS" => rtype::NS,
        "CNAME" => rtype::CNAME,
        "SOA" => rtype::SOA,
        "PTR" => rtype::PTR,
        "MX" => rtype::MX,
        "TXT" => rtype::TXT,
        "AAAA" => rtype::AAAA,
        "SRV" => rtype::SRV,
        "DS" => rtype::DS,
        "DNSKEY" => rtype::DNSKEY,
        "SVCB" => rtype::SVCB,
        "HTTPS" => rtype::HTTPS,
        "ANY" => rtype::ANY,
        other => other.strip_prefix("TYPE")?.parse().ok()?,
    })
}
