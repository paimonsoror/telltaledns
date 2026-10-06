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
use crate::endpoint::{Endpoint, Host, Protocol};
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
    /// True if an explicit `[[route]]` matched (not just the default group).
    pub routed: bool,
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

/// REQ: UPS-011 (T7.16) — an upstream's TLS files, read now (a reload re-reads them).
fn upstream_tls(u: &telltale_config::Upstream) -> Result<crate::tls::UpstreamTls, String> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs = |path: &str| -> Result<Vec<CertificateDer<'static>>, String> {
        let v: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
            .map_err(|e| format!("{path}: {e}"))?
            .collect::<Result<_, _>>()
            .map_err(|e| format!("{path}: {e}"))?;
        if v.is_empty() {
            return Err(format!("{path}: no certificates in it"));
        }
        Ok(v)
    };
    let ca = match &u.tls_ca {
        Some(p) => certs(p.as_str())?,
        None => Vec::new(),
    };
    let client = match (&u.tls_client_cert, &u.tls_client_key) {
        (Some(c), Some(k)) => {
            let chain = certs(c.as_str())?;
            let key = PrivateKeyDer::from_pem_file(k.as_str())
                .map_err(|e| format!("{}: {e}", k.as_str()))?;
            Some(Arc::new((chain, key)))
        }
        _ => None,
    };
    Ok(crate::tls::UpstreamTls {
        ca,
        client,
        pins: u.spki_pins.iter().map(ToString::to_string).collect(),
    })
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
            // REQ: UPS-002 (T7.8) — `http_version = "3"` on an https:// upstream: HTTP/3.
            Ok(mut ep) if u.http_version == HttpVersion::H3 && ep.protocol == Protocol::Https => {
                ep.protocol = Protocol::H3;
                ep
            }
            Ok(ep) => ep,
            Err(e) => {
                errors.push(format!("upstream `{}`: {e}", u.name));
                continue;
            }
        };
        // REQ: UPS-010 (T7.16)
        let proxy = match u.proxy.as_deref().map(crate::proxy::Proxy::parse) {
            Some(Ok(p)) => Some(Arc::new(p)),
            Some(Err(e)) => {
                errors.push(format!("upstream `{}`: {e}", u.name));
                continue;
            }
            None => None,
        };
        // REQ: UPS-011 (T7.16) — CA, client certificate, pins.
        let up_tls = match upstream_tls(u) {
            Ok(t) => t,
            Err(e) => {
                errors.push(format!("upstream `{}`: {e}", u.name));
                continue;
            }
        };
        if u.ecs.as_deref().is_some_and(|e| e != "strip") {
            errors.push(format!("upstream `{}`: `ecs` is not supported yet", u.name));
        }
        let bootstrap = match (&ep.host, u.bootstrap.is_empty()) {
            (Host::Ip(_), _) => None,
            // The proxy resolves the name (REQ: UPS-010).
            (Host::Name(_), true) if proxy.is_some() => None,
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
            proxy,
            // REQ: UPS-011 (T7.16)
            tls: up_tls,
            plugin_args: u.args.iter().map(ToString::to_string).collect(),
            plugin_dir: Some(std::path::Path::new(cfg.node.data_dir.as_str()).join("plugins")),
            // REQ: DNS-012 (T7.15)
            recursive: telltale_recursor::Settings {
                qname_minimization: u.recursive.qname_minimization,
                case_randomization: u.recursive.case_randomization,
                ..telltale_recursor::Settings::default()
            }
            .with_ipv6(u.recursive.ipv6),
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
    /// The upstream group behind a cache view from [`Router::select`].
    pub fn group_by_view(&self, view: u16) -> Option<&Arc<Group>> {
        self.groups.get(usize::from(view))
    }

    pub fn select<S: AsRef<str>>(
        &self,
        q: &Question,
        client_groups: &[S],
    ) -> Option<Selection<'_>> {
        let mut best: Option<(usize, usize)> = None; // (suffix label count, target)
        for r in &self.routes {
            if !r.qtypes.is_empty() && !r.qtypes.contains(&q.qtype) {
                continue;
            }
            if !r.client_groups.is_empty()
                && !r
                    .client_groups
                    .iter()
                    .any(|g| client_groups.iter().any(|c| c.as_ref() == g.as_str()))
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
            routed: best.is_some(),
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
    telltale_proto::rtype::from_name(s)
}
