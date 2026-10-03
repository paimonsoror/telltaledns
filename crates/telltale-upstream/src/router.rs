//! Routing queries to upstream groups by domain suffix, client group, and qtype.
//!
//! REQ: UPS-007, DNS-017 (conditional forwarding incl. reverse zones). The longest matching
//! suffix wins; routes without suffixes match any name. Unmatched queries use `default`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use telltale_config::{Config, Strategy as CfgStrategy};
use telltale_proto::NameBuf;

use crate::endpoint::Endpoint;
use crate::group::{Group, Strategy};
use crate::upstream::{Question, Upstream};

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
    /// Builds upstreams, groups, and routes. Unsupported upstreams are reported as errors.
    pub fn from_config(cfg: &Config) -> Result<Self, Vec<String>> {
        let mut errors = Vec::new();
        let mut ups: HashMap<&str, Arc<Upstream>> = HashMap::new();
        let mut upstreams = Vec::new();
        for (i, u) in cfg.upstream.iter().enumerate() {
            let id = u16::try_from(i + 1).unwrap_or(u16::MAX);
            match Endpoint::parse(&u.url) {
                Ok(ep) if ep.socket_addr().is_none() => errors.push(format!(
                    "upstream `{}`: hostname URLs need bootstrap resolution, which arrives in the next release; use an IP address for now",
                    u.name
                )),
                Ok(ep) if !matches!(ep.protocol, crate::Protocol::Udp | crate::Protocol::Tcp) => errors.push(format!(
                    "upstream `{}`: {} upstreams arrive in the next release; use udp:// or tcp:// for now",
                    u.name, ep.protocol
                )),
                Ok(ep) => {
                    let up = Arc::new(Upstream::new(
                        id,
                        u.name.as_str(),
                        ep,
                        Duration::from_millis(u64::from(u.timeout_ms)),
                        u.weight,
                    ));
                    upstreams.push(Arc::clone(&up));
                    ups.insert(u.name.as_str(), up);
                }
                Err(e) => errors.push(format!("upstream `{}`: {e}", u.name)),
            }
        }
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
