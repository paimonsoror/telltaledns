//! Cluster wiring (REQ: CLU-001): the `telltale cluster` commands, and starting the cluster
//! channel next to DNS. The channel never gates DNS (CLU-004): if the identity can't be read
//! or the port can't be bound, the node logs it and keeps answering.

use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use telltale_api::model::{ClusterInfo, ClusterPeer};
use telltale_api::time::format_us;
use telltale_cluster::net::{self, Cluster};
use telltale_cluster::node::{Identity, JoinRequest};
use telltale_cluster::pki;
use telltale_cluster::token::Token;
use tokio::sync::watch;
use tracing::{info, warn};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn data_dir(cfg: &telltale_config::Config) -> &Path {
    Path::new(cfg.node.data_dir.as_str())
}

/// Loads this node's cluster identity and starts its listener and dialer; `None` when the
/// node isn't clustered (or its identity is unreadable, which is logged).
pub(crate) fn start(
    cfg: &telltale_config::Config,
    stop: &watch::Receiver<bool>,
) -> Option<Arc<Cluster>> {
    let id = match Identity::load(data_dir(cfg)) {
        Ok(Some(id)) => id,
        Ok(None) => return None,
        Err(e) => {
            warn!("cluster: can't read this node's identity, running standalone: {e}");
            return None;
        }
    };
    info!(cluster = %id.meta.cluster_name, node = %id.meta.node_id, primary = id.holds_ca(), "cluster member");
    let dial_to = if id.holds_ca() {
        Vec::new()
    } else {
        id.meta.primary_urls.clone()
    };
    let cluster = Cluster::new(id, VERSION);
    if let Ok(addr) = cfg.cluster.listen.as_str().parse::<SocketAddr>() {
        let (c, stop) = (Arc::clone(&cluster), stop.clone());
        tokio::spawn(async move {
            if let Err(e) = net::serve(c, addr, stop).await {
                warn!(%addr, "cluster port: {e}; peers can't reach this node (DNS is unaffected)");
            }
        });
    } else {
        warn!("cluster.listen is not an address; the cluster port stays closed");
    }
    if !dial_to.is_empty() {
        tokio::spawn(net::dial(Arc::clone(&cluster), dial_to, stop.clone()));
    }
    Some(cluster)
}

/// The API's view of the cluster.
pub(crate) fn info(c: &Cluster) -> ClusterInfo {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let m = &c.identity.meta;
    let sync = c.sync_status();
    let expires = expiry_unix(&c.identity.cert_pem);
    ClusterInfo {
        cluster_id: m.cluster_id.clone(),
        name: m.cluster_name.clone(),
        node_id: m.node_id.clone(),
        site: m.site.clone(),
        primary: c.identity.holds_ca(),
        cert_expires_at: format_us(expires.saturating_mul(1_000_000)),
        config_seq: sync.seq,
        config_created_at: (sync.created_ms > 0)
            .then(|| format_us(sync.created_ms.saturating_mul(1000))),
        config_applied_at: (sync.applied_ms > 0)
            .then(|| format_us(sync.applied_ms.saturating_mul(1000))),
        last_sync_fetched: sync.fetched as u64,
        last_sync_ms: sync.duration_ms,
        sync_error: sync.error,
        peers: c
            .members()
            .into_iter()
            .map(|p| ClusterPeer {
                up: p.up(now_ms),
                last_seen_seconds_ago: now_ms.saturating_sub(p.last_seen_ms) / 1000,
                node_id: p.node_id,
                site: p.site,
                version: p.version,
                primary: p.primary,
                via: p.via.to_owned(),
                config_seq: p.applied_seq,
            })
            .collect(),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Days a certificate must have left before the check fails.
const CERT_WARN_DAYS: u64 = 14;
/// Lag tolerated before `in_sync` fails (a sync normally takes well under a second).
const LAG_WARN_SECS: u64 = 30;

#[allow(clippy::cast_precision_loss)] // per-mille and microseconds to display units
/// REQ: CLU-008 — the Cluster page's data.
pub(crate) fn view(c: &Cluster) -> telltale_api::model::ClusterView {
    use telltale_api::model::{ClusterEvent, ClusterNode, ClusterView};
    let now = now_ms();
    let me = &c.identity.meta;
    let local = c.local_state();
    let newest = c.newest_seq();
    let expires = expiry_unix(&c.identity.cert_pem);
    let lag_of = |seq: u64, since: Option<u64>| {
        (
            newest.saturating_sub(seq),
            since.map(|s| now.saturating_sub(s) / 1000),
        )
    };
    let (my_lag, my_behind) = lag_of(local.applied_seq, c.behind_since());
    let mut nodes = vec![ClusterNode {
        node_id: me.node_id.clone(),
        site: me.site.clone(),
        role: if c.identity.holds_ca() {
            "primary"
        } else {
            "replica"
        }
        .into(),
        this_node: true,
        eligible: me.eligible,
        version: c.version.clone(),
        up: true,
        connected: true,
        link: "self".into(),
        last_seen_seconds_ago: 0,
        rtt_ms: None,
        config_seq: local.applied_seq,
        config_lag: my_lag,
        behind_seconds: my_behind,
        ready: local.ready,
        qps: local.qps,
        servfail_percent: f64::from(local.servfail_permille) / 10.0,
        upstream_p90_ms: local.p90_us as f64 / 1000.0,
        uptime_seconds: local.uptime_s,
        cert_expires_at: Some(format_us(expires.saturating_mul(1_000_000))),
    }];
    let mut peers = c.members();
    peers.sort_by(|a, b| (&a.site, &a.node_id).cmp(&(&b.site, &b.node_id)));
    for p in &peers {
        let (lag, behind) = lag_of(p.applied_seq, p.behind_since_ms);
        nodes.push(ClusterNode {
            node_id: p.node_id.clone(),
            site: p.site.clone(),
            role: if p.primary { "primary" } else { "replica" }.into(),
            this_node: false,
            eligible: p.eligible,
            version: p.version.clone(),
            up: p.up(now),
            connected: p.connected,
            link: p.via.into(),
            last_seen_seconds_ago: now.saturating_sub(p.last_seen_ms) / 1000,
            rtt_ms: p.rtt_ms,
            config_seq: p.applied_seq,
            config_lag: lag,
            behind_seconds: behind,
            ready: p.ready,
            qps: p.qps,
            servfail_percent: f64::from(p.servfail_permille) / 10.0,
            upstream_p90_ms: p.p90_us as f64 / 1000.0,
            uptime_seconds: p.uptime_s,
            cert_expires_at: None,
        });
    }
    let sync = c.sync_status();
    let cert_days = expires.saturating_sub(now / 1000) / 86_400;
    let checks = health_checks(&nodes, peers.is_empty(), newest, sync.error, cert_days);
    let mut events: Vec<ClusterEvent> = c
        .events()
        .into_iter()
        .map(|e| ClusterEvent {
            at: format_us(e.ts_ms.saturating_mul(1000)),
            kind: e.kind.into(),
            node_id: e.node,
            detail: e.detail,
        })
        .collect();
    events.reverse();
    ClusterView {
        enabled: true,
        cluster_id: Some(me.cluster_id.clone()),
        name: Some(me.cluster_name.clone()),
        this_node: Some(me.node_id.clone()),
        newest_config_seq: newest,
        healthy: checks.iter().all(|c| c.ok),
        checks,
        nodes,
        events,
    }
}

/// The Cluster page's pass/fail list, each failure with what to do about it.
fn health_checks(
    nodes: &[telltale_api::model::ClusterNode],
    no_peers: bool,
    newest: u64,
    sync_error: Option<String>,
    cert_days: u64,
) -> Vec<telltale_api::model::ClusterCheck> {
    use telltale_api::model::ClusterCheck;
    let check = |id: &str, ok: bool, summary: String, fix: &str| ClusterCheck {
        id: id.into(),
        ok,
        summary,
        fix: (!ok).then(|| fix.to_owned()),
    };
    let down: Vec<&str> = nodes
        .iter()
        .filter(|n| !n.up)
        .map(|n| n.node_id.as_str())
        .collect();
    let primary_up = nodes.iter().any(|n| n.role == "primary" && n.up);
    let lagging: Vec<&str> = nodes
        .iter()
        .filter(|n| n.up && n.behind_seconds.is_some_and(|s| s > LAG_WARN_SECS))
        .map(|n| n.node_id.as_str())
        .collect();
    let not_serving: Vec<&str> = nodes
        .iter()
        .filter(|n| n.up && !n.ready)
        .map(|n| n.node_id.as_str())
        .collect();
    vec![
        check(
            "peers_up",
            down.is_empty() && !no_peers,
            if no_peers {
                "No other node has connected yet".into()
            } else if down.is_empty() {
                format!("All {} nodes are up", nodes.len())
            } else {
                format!("Not heard from in 15 s: {}", down.join(", "))
            },
            "Check that the node is running and can reach the primary's cluster port (`telltale cluster status` on it shows the URL); DNS on every node keeps working meanwhile.",
        ),
        check(
            "primary_present",
            primary_up,
            if primary_up {
                "The primary is up".into()
            } else {
                "The primary is unreachable".into()
            },
            "Configuration changes wait until the primary is back; every node keeps serving its last version. Check the primary's pod or service, and its cluster port.",
        ),
        check(
            "in_sync",
            lagging.is_empty(),
            if lagging.is_empty() {
                format!("Every reachable node runs configuration version {newest}")
            } else {
                format!("Behind for over {LAG_WARN_SECS} s: {}", lagging.join(", "))
            },
            "Look at the node's events for `sync_failed`; a configuration the node can't use (an unknown setting from a newer primary) needs that node upgraded.",
        ),
        check(
            "sync_errors",
            sync_error.is_none(),
            sync_error.map_or_else(
                || "No replication errors on this node".into(),
                |e| format!("Last sync failed: {e}"),
            ),
            "The node retries every 2 s and keeps serving its last version; the error says what's wrong.",
        ),
        check(
            "serving",
            not_serving.is_empty(),
            if not_serving.is_empty() {
                "Every reachable node is serving DNS".into()
            } else {
                format!("Not serving DNS: {}", not_serving.join(", "))
            },
            "A node that isn't ready has a listener that failed to bind or is shutting down; see its log.",
        ),
        check(
            "certificate",
            cert_days >= CERT_WARN_DAYS,
            format!("This node's cluster certificate is valid for {cert_days} more days"),
            "Renewal is automatic once T5.4 lands; until then, re-join the node with a fresh token before it expires.",
        ),
    ]
}

/// `telltale cluster init`.
pub(crate) fn init(
    cfg: &telltale_config::Config,
    out: &mut impl Write,
    name: &str,
    advertise: Vec<String>,
    site: Option<&str>,
) -> ExitCode {
    let site = site.unwrap_or(cfg.cluster.site.as_str());
    match Identity::init(data_dir(cfg), name, advertise, site) {
        Ok(id) => {
            let _ = writeln!(
                out,
                "Created cluster `{name}` (ID {}); this node ({}) is its primary and holds the cluster CA.",
                id.meta.cluster_id, id.meta.node_id
            );
            let _ = writeln!(
                out,
                "Restart telltale to open the cluster port ({}), then: telltale cluster token create",
                cfg.cluster.listen.as_str()
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

/// `telltale cluster token create`.
pub(crate) fn token_create(
    cfg: &telltale_config::Config,
    out: &mut impl Write,
    ttl_s: u64,
    urls: Vec<String>,
) -> ExitCode {
    let id = match Identity::load(data_dir(cfg)) {
        Ok(Some(id)) => id,
        Ok(None) => return fail("this node isn't in a cluster: run `telltale cluster init` first"),
        Err(e) => return fail(&e),
    };
    match id.create_token(ttl_s, (!urls.is_empty()).then_some(urls)) {
        Ok(t) => {
            // The token is the only output on stdout, so it can be piped into a Secret.
            let _ = writeln!(out, "{}", t.encode());
            eprintln!(
                "Valid for {} and usable by any number of nodes until then. Treat it like a password.",
                human(ttl_s)
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

/// `telltale cluster join`.
pub(crate) fn join(
    cfg: &telltale_config::Config,
    out: &mut impl Write,
    token: &str,
    advertise: Vec<String>,
    site: Option<&str>,
    eligible: bool,
) -> ExitCode {
    let dir = data_dir(cfg);
    match Identity::load(dir) {
        Ok(Some(id)) => {
            return fail(&format!(
                "this node is already in cluster `{}`",
                id.meta.cluster_name
            ));
        }
        Ok(None) => {}
        Err(e) => return fail(&e),
    }
    let token = match Token::decode(token.trim()) {
        Ok(t) => t,
        Err(e) => return fail(&e),
    };
    let key = match pki::new_node_key() {
        Ok(k) => k,
        Err(e) => return fail(&e.to_string()),
    };
    let site = site.unwrap_or(cfg.cluster.site.as_str()).to_owned();
    let req = JoinRequest {
        secret: token.secret.clone(),
        csr_pem: key.csr_pem.clone(),
        advertise: advertise.clone(),
        site: site.clone(),
        eligible,
        version: VERSION.to_owned(),
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fail(&e.to_string()),
    };
    let resp = match rt.block_on(net::join(&token, &req)) {
        Ok(r) => r,
        Err(e) => return fail(&format!("join failed: {e}")),
    };
    match Identity::save_joined(dir, &key.key_pem, &resp, &site, eligible, advertise) {
        Ok(id) => {
            let _ = writeln!(
                out,
                "Joined cluster `{}` as node {} (site {site}).",
                id.meta.cluster_name, id.meta.node_id
            );
            let _ = writeln!(out, "Restart telltale to connect.");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

/// `telltale cluster status`: this node's identity, offline. Live peers are in the API
/// (`GET /api/v1/system/info`, `cluster.peers`).
pub(crate) fn status(cfg: &telltale_config::Config, out: &mut impl Write) -> ExitCode {
    let id = match Identity::load(data_dir(cfg)) {
        Ok(Some(id)) => id,
        Ok(None) => {
            let _ = writeln!(out, "Not in a cluster (standalone).");
            return ExitCode::SUCCESS;
        }
        Err(e) => return fail(&e),
    };
    let m = &id.meta;
    let expires = expiry_unix(&id.cert_pem);
    let _ = writeln!(out, "cluster    {} ({})", m.cluster_name, m.cluster_id);
    let _ = writeln!(out, "node       {}", m.node_id);
    let _ = writeln!(out, "site       {}", m.site);
    let _ = writeln!(
        out,
        "role       {}",
        if id.holds_ca() {
            "primary (holds the cluster CA)"
        } else {
            "replica"
        }
    );
    let _ = writeln!(out, "eligible   {}", m.eligible);
    let _ = writeln!(
        out,
        "advertise  {}",
        if m.advertise.is_empty() {
            "-".to_owned()
        } else {
            m.advertise.join(", ")
        }
    );
    if !id.holds_ca() {
        let _ = writeln!(out, "primary    {}", m.primary_urls.join(", "));
    }
    let _ = writeln!(
        out,
        "cert until {}",
        format_us(expires.saturating_mul(1_000_000))
    );
    ExitCode::SUCCESS
}

/// When this node's cluster certificate expires (Unix seconds).
pub(crate) fn cert_expiry_unix(c: &Cluster) -> u64 {
    expiry_unix(&c.identity.cert_pem)
}

/// When a certificate expires (Unix seconds); `validity` gives (seconds left, lifetime).
fn expiry_unix(cert_pem: &str) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    pki::validity(cert_pem).map_or(0, |(left, _)| now.saturating_add_signed(left))
}

fn human(s: u64) -> String {
    match s {
        s if s % 86_400 == 0 => format!("{} day(s)", s / 86_400),
        s if s % 3600 == 0 => format!("{} hour(s)", s / 3600),
        s if s % 60 == 0 => format!("{} minute(s)", s / 60),
        s => format!("{s} seconds"),
    }
}

fn fail(e: &str) -> ExitCode {
    eprintln!("error: {e}");
    ExitCode::FAILURE
}

/// Parses `30m`, `1h`, `7d`, or plain seconds.
pub(crate) fn parse_ttl(s: &str) -> Result<u64, String> {
    let (n, mult) = match s.as_bytes().last() {
        Some(b's') => (&s[..s.len() - 1], 1),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3600),
        Some(b'd') => (&s[..s.len() - 1], 86_400),
        _ => (s, 1),
    };
    n.parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .filter(|&n| n > 0)
        .ok_or_else(|| format!("`{s}` is not a duration like 30m, 1h or 7d"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clu_001_token_ttl_parses_units() {
        assert_eq!(parse_ttl("90").unwrap(), 90);
        assert_eq!(parse_ttl("30m").unwrap(), 1800);
        assert_eq!(parse_ttl("1h").unwrap(), 3600);
        assert_eq!(parse_ttl("7d").unwrap(), 604_800);
        assert!(parse_ttl("0h").is_err());
        assert!(parse_ttl("soon").is_err());
        assert_eq!(human(3600), "1 hour(s)");
    }

    #[test]
    fn clu_001_init_status_and_token_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = telltale_config::Config::default();
        cfg.node.data_dir = telltale_config::SafeString::new(dir.path().to_string_lossy()).unwrap();
        let mut out = Vec::new();
        assert_eq!(status(&cfg, &mut out), ExitCode::SUCCESS);
        assert!(String::from_utf8_lossy(&out).contains("standalone"));
        assert_eq!(
            init(
                &cfg,
                &mut out,
                "home",
                vec!["https://192.168.3.2:8443".into()],
                Some("home-pi")
            ),
            ExitCode::SUCCESS
        );
        out.clear();
        assert_eq!(status(&cfg, &mut out), ExitCode::SUCCESS);
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("cluster    home")
                && text.contains("primary")
                && text.contains("home-pi"),
            "{text}"
        );
        assert_eq!(
            token_create(&cfg, &mut out, 3600, Vec::new()),
            ExitCode::SUCCESS
        );
        // A second init on the same node is refused.
        assert_eq!(
            init(&cfg, &mut out, "again", vec![], None),
            ExitCode::FAILURE
        );
    }
}
