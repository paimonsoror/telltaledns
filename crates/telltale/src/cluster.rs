//! Cluster wiring (REQ: CLU-001): the `telltale cluster` commands, and starting the cluster
//! channel next to DNS. The channel never gates DNS (CLU-004): if the identity can't be read
//! or the port can't be bound, the node logs it and keeps answering.

use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use telltale_api::model::{ClusterInfo, ClusterPeer};
use telltale_api::time::format_us;
use telltale_cluster::net::{self, Cluster};
use telltale_cluster::node::{Identity, JoinRequest};
use telltale_cluster::pki;
use telltale_cluster::token::Token;
use tokio::sync::watch;
use tracing::{info, warn};

const VERSION: &str = crate::build_info::VERSION;

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
    info!(cluster = %id.meta.cluster_name, node = %id.meta.node_id, primary = id.is_primary(), "cluster member");
    let cluster = Cluster::new(id, VERSION);
    // REQ: CLU-009 — the shared bootstrap secret works as a join token here (Helm). It's
    // re-read at every join, so a rotated Secret applies without a restart.
    if let Some(path) = &cfg.cluster.bootstrap_secret_file {
        cluster.set_bootstrap_file(std::path::PathBuf::from(path.as_str()));
    }
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
    // Every node dials: replicas reach the primary, and eligible nodes reach each other so a
    // returning old primary learns of a newer epoch (ADR-051).
    tokio::spawn(net::dial(Arc::clone(&cluster), stop.clone()));
    // REQ: CLU-005 — automatic failover (ADR-056): idle unless the cluster is in `auto` mode.
    tokio::spawn(net::mesh(Arc::clone(&cluster), stop.clone()));
    tokio::spawn(telltale_cluster::failover::run(
        Arc::clone(&cluster),
        stop.clone(),
    ));
    // REQ: CLU-001 — node certificates renew before they expire (T5.4c).
    tokio::spawn(telltale_cluster::renew::run(
        Arc::clone(&cluster),
        stop.clone(),
    ));
    // REQ: CLU-001 (T5.4c, ADR-066) — a CA rotation advances as members report in.
    let (c, mut stop_rot) = (Arc::clone(&cluster), stop.clone());
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop_rot.changed() => return,
                () = tokio::time::sleep(Duration::from_secs(10)) => {}
            }
            if let Some(msg) = telltale_cluster::rotation::step(&c) {
                info!("cluster: {msg}");
                c.event("ca_rotation", &c.identity.meta.node_id, msg);
            }
        }
    });
    // REQ: CLU-009 — ephemeral members that went away leave the registry.
    let ttl = Duration::from_secs(u64::from(cfg.cluster.ephemeral_ttl_secs));
    // Sweep at a quarter of the TTL (5-60 s), so a gone member leaves within ~1.25 × TTL.
    let every = (ttl / 4).clamp(Duration::from_secs(5), Duration::from_secs(60));
    let (c, mut stop) = (Arc::clone(&cluster), stop.clone());
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop.changed() => return,
                () = tokio::time::sleep(every) => {}
            }
            let gone = c.gc_ephemeral(ttl);
            if !gone.is_empty() {
                info!(
                    count = gone.len(),
                    "cluster: dropped ephemeral members no longer heard from"
                );
            }
        }
    });
    Some(cluster)
}

/// The shared bootstrap secret from `[cluster] bootstrap_secret_file`, if set and readable.
fn bootstrap_secret(cfg: &telltale_config::Config) -> Option<String> {
    let path = cfg.cluster.bootstrap_secret_file.as_ref()?;
    match std::fs::read_to_string(path.as_str()) {
        Ok(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        Ok(_) => {
            warn!(path = %path, "cluster: the bootstrap secret file is empty");
            None
        }
        Err(e) => {
            warn!(path = %path, "cluster: can't read the bootstrap secret: {e}");
            None
        }
    }
}

/// REQ: CLU-009 — on first start, create the cluster (`[cluster.init]`) or join it
/// (`join_url` + bootstrap secret), as the Helm chart's controller and resolver pods do.
/// Joining retries for up to `wait`; `Err` when it never succeeded.
pub(crate) async fn bootstrap(cfg: &telltale_config::Config, wait: Duration) -> Result<(), String> {
    let dir = data_dir(cfg);
    if Identity::load(dir)?.is_some() {
        return Ok(());
    }
    let c = &cfg.cluster;
    if let Some(init) = &c.init {
        let advertise = init.advertise.iter().map(ToString::to_string).collect();
        let id = Identity::init_with(
            dir,
            c.name.as_str(),
            advertise,
            c.site.as_str(),
            init.config_authority.as_str(),
        )?;
        info!(cluster = %id.meta.cluster_name, node = %id.meta.node_id, "created the cluster ([cluster.init])");
        return Ok(());
    }
    let Some(url) = &c.join_url else {
        return Ok(());
    };
    let secret = bootstrap_secret(cfg).ok_or("join_url needs a readable bootstrap_secret_file")?;
    let started = tokio::time::Instant::now();
    let mut last = String::new();
    while started.elapsed() < wait {
        match bootstrap_join(cfg, url.as_str(), &secret).await {
            Ok(id) => {
                info!(cluster = %id.meta.cluster_name, node = %id.meta.node_id, ephemeral = c.ephemeral, "joined the cluster (join_url)");
                return Ok(());
            }
            Err(e) => {
                if e != last {
                    warn!(%url, "cluster: joining failed, retrying: {e}");
                }
                last = e;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(format!(
        "couldn't join {url} within {}s: {last}",
        wait.as_secs()
    ))
}

async fn bootstrap_join(
    cfg: &telltale_config::Config,
    url: &str,
    secret: &str,
) -> Result<Identity, String> {
    let c = &cfg.cluster;
    let token = net::bootstrap_token(url, secret).await?;
    let key = pki::new_node_key().map_err(|e| e.to_string())?;
    let eligible = c.eligible && !c.ephemeral;
    let req = JoinRequest {
        witness: false,
        ephemeral: c.ephemeral,
        secret: token.secret.clone(),
        csr_pem: key.csr_pem.clone(),
        advertise: Vec::new(),
        site: c.site.to_string(),
        eligible,
        version: VERSION.to_owned(),
    };
    let resp = net::join(&token, &req).await?;
    Identity::save_joined(
        data_dir(cfg),
        &key.key_pem,
        &resp,
        c.site.as_str(),
        eligible,
        Vec::new(),
    )
}

/// The API's view of the cluster.
pub(crate) fn info(c: &Cluster) -> ClusterInfo {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let m = &c.identity.meta;
    let sync = c.sync_status();
    let expires = expiry_unix(&c.identity.reload().cert_pem);
    ClusterInfo {
        cluster_id: m.cluster_id.clone(),
        name: m.cluster_name.clone(),
        node_id: m.node_id.clone(),
        site: m.site.clone(),
        primary: c.is_primary(),
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

/// REQ: CLU-008 (T6.11) — the machines nodes run on: low disk, memory pressure, heat, and
/// clock drift, per node.
fn host_check(nodes: &[telltale_api::model::ClusterNode]) -> telltale_api::model::ClusterCheck {
    let problems: Vec<String> = nodes
        .iter()
        .filter_map(|n| {
            let w = &n.host.as_ref()?.latest.warnings;
            (!w.is_empty()).then(|| format!("{}: {}", n.node_id, w.join(", ")))
        })
        .collect();
    telltale_api::model::ClusterCheck {
        id: "host_resources".into(),
        ok: problems.is_empty(),
        summary: if problems.is_empty() {
            "The machines look fine (disk, memory, temperature, clocks)".into()
        } else {
            problems.join("; ")
        },
        fix: (!problems.is_empty()).then(|| {
            concat!(
                "Disk: shorten the query log's retention (`[telemetry.qlog] retention_days`, ",
                "`retention_bytes`) or free space. Memory: raise the container's limit, or use ",
                "fewer or smaller lists. Heat: check the Pi's cooling. Clock: make sure every ",
                "node runs NTP (systemd-timesyncd, chrony)."
            )
            .to_owned()
        }),
    }
}

fn started_at(ms: u64) -> Option<String> {
    (ms > 0).then(|| format_us(ms.saturating_mul(1000)))
}

/// REQ: CLU-008 (T6.14) — each node's share of the queries answered by the nodes that are up.
#[allow(clippy::cast_precision_loss)] // a percentage for display
fn query_shares(nodes: &mut [telltale_api::model::ClusterNode]) {
    let total: u64 = nodes.iter().filter(|n| n.up).map(|n| n.qps).sum();
    for n in nodes.iter_mut() {
        n.query_share_percent =
            (total > 0 && n.up).then(|| (n.qps as f64 * 1000.0 / total as f64).round() / 10.0);
    }
}

/// Queries per second below which a site's split isn't judged (too little to mean anything).
const BALANCE_MIN_QPS: u64 = 5;

/// REQ: CLU-008 (T6.14) — Kubernetes spreads queries over the pods of a site; one pod taking
/// more than twice its fair share means the spreading isn't working (a sticky client, a
/// node-local traffic policy with pods bunched on one node, or a pod the Service doesn't see).
/// Only for sites with two or more ready pods and enough traffic to judge.
#[allow(clippy::cast_precision_loss)] // ratios for display
fn balance_check(nodes: &[telltale_api::model::ClusterNode]) -> telltale_api::model::ClusterCheck {
    let mut sites: std::collections::BTreeMap<&str, Vec<&telltale_api::model::ClusterNode>> =
        std::collections::BTreeMap::new();
    for n in nodes.iter().filter(|n| n.up && n.ready && n.pod.is_some()) {
        sites.entry(n.site.as_str()).or_default().push(n);
    }
    let mut problems = Vec::new();
    for (site, pods) in &sites {
        let total: u64 = pods.iter().map(|n| n.qps).sum();
        if pods.len() < 2 || total < BALANCE_MIN_QPS {
            continue;
        }
        let fair = total as f64 / pods.len() as f64;
        if let Some(top) = pods.iter().max_by_key(|n| n.qps)
            && top.qps as f64 > 2.0 * fair
        {
            problems.push(format!(
                "{site}: {} answers {:.0}% of the site's queries ({} pods, fair share {:.0}%)",
                top.pod.as_deref().unwrap_or(&top.node_id),
                top.qps as f64 * 100.0 / total as f64,
                pods.len(),
                100.0 / pods.len() as f64
            ));
        }
    }
    telltale_api::model::ClusterCheck {
        id: "load_balance".into(),
        ok: problems.is_empty(),
        summary: if problems.is_empty() {
            "Queries are spread evenly over each site's pods (or there's one pod)".into()
        } else {
            problems.join("; ")
        },
        fix: (!problems.is_empty()).then(|| {
            concat!(
                "With `externalTrafficPolicy: Local`, a node only sends queries to its own pods: ",
                "spread the pods over nodes (the chart's `resolvers.affinity`, e.g. podAntiAffinity on ",
                "`app.kubernetes.io/component: resolver`). A few busy clients also stick to one pod; ",
                "that evens out with more clients."
            )
            .to_owned()
        }),
    }
}

/// REQ: CLU-008 — the Cluster page's data.
#[allow(clippy::cast_precision_loss)] // per-mille and microseconds to display units
#[allow(clippy::too_many_lines)] // one view, field by field
pub(crate) fn view(
    c: &Cluster,
    host: &crate::host::HostMonitor,
) -> telltale_api::model::ClusterView {
    use telltale_api::model::{ClusterNode, ClusterView};
    let now = now_ms();
    let me = &c.identity.meta;
    let local = c.local_state();
    let newest = c.newest_seq();
    let expires = expiry_unix(&c.identity.reload().cert_pem);
    let lag_of = |seq: u64, since: Option<u64>| {
        (
            newest.saturating_sub(seq),
            since.map(|s| now.saturating_sub(s) / 1000),
        )
    };
    let (my_lag, my_behind) = lag_of(local.applied_seq, c.behind_since());
    let registry = c.identity.reload().registry();
    let flags = |id: &str| {
        registry
            .iter()
            .find(|n| n.node_id == id)
            .map_or((false, false), |n| (n.ephemeral, n.witness))
    };
    let mut nodes = vec![ClusterNode {
        ephemeral: flags(&me.node_id).0,
        witness: me.witness,
        protocol: telltale_cluster::wire::PROTOCOL,
        source_commit: Some(local.source_commit.clone()).filter(|s| !s.is_empty()),
        node_id: me.node_id.clone(),
        site: me.site.clone(),
        role: match c.role().0 {
            telltale_cluster::node::Role::Primary => "primary",
            telltale_cluster::node::Role::Emergency => "emergency primary",
            telltale_cluster::node::Role::Replica => "replica",
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
        config_source: Some(c.config_source()),
        host: crate::host::report(host.latest(), &host.history(), None),
        kube_node: Some(local.kube_node.clone()).filter(|s| !s.is_empty()),
        pod: Some(local.pod.clone()).filter(|s| !s.is_empty()),
        started_at: started_at(local.started_ms),
        restarts: 0,
        cache_entries: local.cache_entries,
        cache_hit_percent: local.cache_hit_permille.map(|p| f64::from(p) / 10.0),
        query_share_percent: None,
    }];
    let mut peers = c.members();
    peers.sort_by(|a, b| (&a.site, &a.node_id).cmp(&(&b.site, &b.node_id)));
    for p in &peers {
        let (lag, behind) = lag_of(p.applied_seq, p.behind_since_ms);
        nodes.push(ClusterNode {
            ephemeral: flags(&p.node_id).0,
            witness: flags(&p.node_id).1,
            protocol: p.protocol,
            source_commit: Some(p.source_commit.clone()).filter(|s| !s.is_empty()),
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
            config_source: (!p.config_source.is_empty()).then(|| p.config_source.clone()),
            host: crate::host::report(
                p.host.clone(),
                &c.host_history(&p.node_id),
                p.clock_offset_ms,
            ),
            kube_node: Some(p.kube_node.clone()).filter(|s| !s.is_empty()),
            pod: Some(p.pod.clone()).filter(|s| !s.is_empty()),
            started_at: started_at(p.started_ms),
            restarts: p.restarts,
            cache_entries: p.cache_entries,
            cache_hit_percent: p.cache_hit_permille.map(|p| f64::from(p) / 10.0),
            query_share_percent: None,
        });
    }
    query_shares(&mut nodes);
    let sync = c.sync_status();
    let cert_days = expires.saturating_sub(now / 1000) / 86_400;
    let mut checks = health_checks(&nodes, peers.is_empty(), newest, sync.error, cert_days);
    let failover = failover_view(c, &nodes);
    checks.push(versions_check(&nodes));
    checks.push(host_check(&nodes));
    checks.push(balance_check(&nodes));
    // T5.4c (ADR-066) — a CA rotation in progress, and whom it waits for.
    if let Some(r) = telltale_cluster::rotation::current(&c.identity.reload()) {
        let waiting = if r.pending.is_empty() {
            "the next step comes within seconds".to_owned()
        } else {
            format!("waiting for {}", r.pending.join(", "))
        };
        checks.push(telltale_api::model::ClusterCheck {
            id: "ca_rotation".into(),
            ok: true,
            summary: format!(
                "CA rotation in progress (phase `{}`): {waiting}",
                r.phase
            ),
            fix: (!r.pending.is_empty()).then(|| {
                "A member that's away holds the rotation until it's back; links keep working meanwhile.".to_owned()
            }),
        });
    }
    // ADR-056 — `auto` without enough voters is manual in practice: say so.
    if failover.mode == "auto" {
        checks.push(failover_check(&failover));
    }
    let events = events_view(c);
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
        authority: Some(c.identity.reload().meta.config_authority),
        conflicts: Vec::new(),
        failover: Some(failover),
        source: None,
        host: None,
    }
}

/// The event log, newest first.
fn events_view(c: &Cluster) -> Vec<telltale_api::model::ClusterEvent> {
    use telltale_api::model::ClusterEvent;
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
    events
}

/// REQ: CLU-010 — mixed versions work (within one protocol version) but are meant to be
/// brief: an upgrade in progress.
fn versions_check(nodes: &[telltale_api::model::ClusterNode]) -> telltale_api::model::ClusterCheck {
    let mut versions: Vec<String> = nodes
        .iter()
        .map(|n| format!("{} (protocol {})", n.version, n.protocol))
        .collect();
    versions.sort();
    versions.dedup();
    let ok = versions.len() <= 1;
    telltale_api::model::ClusterCheck {
        id: "versions".into(),
        ok,
        summary: if ok {
            format!("Every node runs {}", versions.first().map_or("the same version", String::as_str))
        } else {
            format!("Mixed versions: {}", versions.join(", "))
        },
        fix: (!ok).then(|| {
            "Finish the upgrade: replicas first, then the primary. Nodes one protocol version apart keep working together meanwhile.".to_owned()
        }),
    }
}

/// Whether automatic failover can work: enough voters, and a majority reachable.
fn failover_check(f: &telltale_api::model::ClusterFailover) -> telltale_api::model::ClusterCheck {
    let majority = f.reachable_voters * 2 > f.voters;
    let (ok, summary, fix) = if f.active {
        (
            majority,
            format!(
                "{} of {} voters reachable (a majority elects and keeps the primary)",
                f.reachable_voters, f.voters
            ),
            "Bring voters back, or check the cluster port between them: without a majority, no primary keeps its lease and configuration changes pause (DNS keeps answering).",
        )
    } else {
        (
            false,
            format!(
                "Automatic failover needs 3 or more voters; this cluster has {}",
                f.voters
            ),
            "Add a witness (`telltale cluster join <token> --witness`, then `telltale cluster witness`) or another eligible node.",
        )
    };
    telltale_api::model::ClusterCheck {
        id: "failover".into(),
        ok,
        summary,
        fix: (!ok).then(|| fix.to_owned()),
    }
}

/// The election as the API reports it (ADR-056).
fn failover_view(
    c: &Cluster,
    nodes: &[telltale_api::model::ClusterNode],
) -> telltale_api::model::ClusterFailover {
    let id = c.identity.reload();
    let voters = telltale_cluster::failover::voters(&id);
    let reachable = voters
        .iter()
        .filter(|v| **v == id.meta.node_id || nodes.iter().any(|n| n.node_id == **v && n.connected))
        .count();
    let v = c.failover_view();
    telltale_api::model::ClusterFailover {
        mode: id.meta.failover.clone(),
        active: telltale_cluster::failover::active(&id),
        voters: u32::try_from(voters.len()).unwrap_or(u32::MAX),
        reachable_voters: u32::try_from(reachable).unwrap_or(u32::MAX),
        lease_held: v.leading.is_some() && v.lease_ms_left > 0,
        #[allow(clippy::cast_precision_loss)]
        lease_seconds_left: v.leading.map(|_| v.lease_ms_left as f64 / 1000.0),
        voted_epoch: v.ballot_epoch,
        voted_for: (!v.ballot_for.is_empty()).then(|| v.ballot_for.clone()),
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

/// REQ: CLU-005 — manual promotion (ADR-051): this node becomes primary in a new epoch.
/// `gitops_source` is whether this node's own configuration comes from Git (ADR-048).
/// Whether this node may be promoted now, and the epoch and mode it would take (AGT-002
/// dry run): `(epoch, emergency)`.
pub(crate) fn promote_plan(
    c: &Cluster,
    gitops_source: bool,
    emergency: bool,
) -> Result<(u64, bool), String> {
    use telltale_cluster::node::Role;
    let id = c.identity.reload();
    if c.is_primary() {
        return Err("this node is already the primary".into());
    }
    if !id.meta.eligible {
        return Err("this node isn't eligible to be primary (it joined without --eligible)".into());
    }
    if telltale_cluster::failover::active(&id) {
        return Err("automatic failover is on: the cluster elects its primary by vote (`telltale cluster set-failover manual` on the primary to promote by hand)".into());
    }
    if !id.holds_ca() {
        return Err("this node doesn't have the cluster key yet: the primary shares it with eligible nodes once they connect".into());
    }
    let gitops = id.meta.config_authority == "gitops";
    let now = now_ms();
    if let Some(p) = c.members().iter().find(|m| m.primary && m.up(now)) {
        // ADR-048 — an emergency primary only holds the cluster until a node that can publish
        // is back: that node takes over without anyone stopping the emergency primary (its
        // newer epoch fences it).
        let would_publish = !emergency && (!gitops || gitops_source);
        if !takeover_allowed(applied_manifest(c).as_ref(), &p.node_id, would_publish) {
            return Err(format!(
                "the primary ({}, site {}) is up: promote a node only when the primary is gone",
                p.node_id, p.site
            ));
        }
    }
    if gitops && !gitops_source && !emergency {
        return Err("this cluster's configuration comes from Git and this node isn't GitOps-managed: promote with emergency to keep the cluster coordinated on the last version".into());
    }
    let role = if emergency || (gitops && !gitops_source) {
        Role::Emergency
    } else {
        Role::Primary
    };
    let epoch = c
        .members()
        .iter()
        .map(|m| m.epoch)
        .fold(c.role().1, u64::max)
        + 1;
    Ok((epoch, role == Role::Emergency))
}

/// The manifest this node last applied (what it would take over from).
fn applied_manifest(c: &Cluster) -> Option<telltale_cluster::sync::ClusterManifest> {
    let bytes = std::fs::read(c.identity.dir.join("applied.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// ADR-048 — whether a node may be promoted while `primary_up` is up: only when that node is
/// the emergency primary of the version this node applied, and this node would publish
/// (it isn't asking to be an emergency primary itself).
fn takeover_allowed(
    applied: Option<&telltale_cluster::sync::ClusterManifest>,
    primary_up: &str,
    would_publish: bool,
) -> bool {
    would_publish && applied.is_some_and(|m| m.emergency && m.primary == primary_up)
}

/// Promotes this node to primary (ADR-051) after the checks in [`promote_plan`].
pub(crate) fn promote(c: &Cluster, gitops_source: bool, emergency: bool) -> Result<u64, String> {
    use telltale_cluster::node::Role;
    let (epoch, frozen) = promote_plan(c, gitops_source, emergency)?;
    let id = c.identity.reload();
    let role = if frozen {
        Role::Emergency
    } else {
        Role::Primary
    };
    c.set_role(role, epoch)?;
    c.event(
        "promoted",
        &id.meta.node_id,
        format!(
            "epoch {epoch}{}",
            if role == Role::Emergency {
                " (emergency: configuration frozen)"
            } else {
                ""
            }
        ),
    );
    tracing::warn!(
        epoch,
        emergency = role == Role::Emergency,
        "this node is now the cluster primary"
    );
    Ok(epoch)
}

/// `telltale cluster init`.
pub(crate) fn init(
    cfg: &telltale_config::Config,
    out: &mut impl Write,
    name: &str,
    advertise: Vec<String>,
    site: Option<&str>,
    authority: &str,
) -> ExitCode {
    let site = site.unwrap_or(cfg.cluster.site.as_str());
    match Identity::init_with(data_dir(cfg), name, advertise, site, authority) {
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
    witness: bool,
) -> ExitCode {
    let dir = data_dir(cfg);
    if witness && advertise.is_empty() {
        return fail("a witness needs --advertise: the voters dial it");
    }
    let eligible = eligible && !witness;
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
        witness,
        ephemeral: false,
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
        Ok(mut id) => {
            if witness && let Err(e) = id.mark_witness() {
                return fail(&e);
            }
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
        if id.is_primary() {
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
    if !id.is_primary() {
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
    expiry_unix(&c.identity.reload().cert_pem)
}

/// When a certificate expires (Unix seconds); `validity` gives (seconds left, lifetime).
fn expiry_unix(cert_pem: &str) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    pki::validity(cert_pem).map_or(0, |(left, _)| now.saturating_add_signed(left))
}

/// `telltale cluster promote`: offline (the running server picks it up when restarted). The
/// API and UI promote a running node without a restart.
pub(crate) fn promote_offline(
    cfg: &telltale_config::Config,
    out: &mut impl Write,
    emergency: bool,
) -> ExitCode {
    use telltale_cluster::node::Role;
    let mut id = match Identity::load(data_dir(cfg)) {
        Ok(Some(id)) => id,
        Ok(None) => return fail("this node isn't in a cluster"),
        Err(e) => return fail(&e),
    };
    if id.is_primary() {
        return fail("this node is already the primary");
    }
    if !id.meta.eligible || !id.holds_ca() {
        return fail(
            "this node can't be primary: it must be eligible and have received the cluster key",
        );
    }
    let gitops = id.meta.config_authority == "gitops";
    let source = crate::replication::gitops_capable(cfg);
    if gitops && !source && !emergency {
        return fail(
            "this cluster's configuration comes from Git and this node isn't GitOps-managed: use --emergency",
        );
    }
    let role = if emergency || (gitops && !source) {
        Role::Emergency
    } else {
        Role::Primary
    };
    let epoch = id.meta.epoch + 1;
    if let Err(e) = id.save_role(role, epoch) {
        return fail(&e);
    }
    let _ = writeln!(
        out,
        "This node is now the primary in epoch {epoch}{}. Restart telltale to take over.",
        if role == Role::Emergency {
            " (emergency: configuration stays at the last version)"
        } else {
            ""
        }
    );
    let _ = writeln!(
        out,
        "Only do this when the old primary is gone: if it's still running, it steps down when it sees epoch {epoch}, and its changes since are kept under Conflicts."
    );
    ExitCode::SUCCESS
}

/// `telltale cluster set-authority` (on the primary; restart to publish it).
pub(crate) fn set_authority(
    cfg: &telltale_config::Config,
    out: &mut impl Write,
    authority: &str,
) -> ExitCode {
    let id = match Identity::load(data_dir(cfg)) {
        Ok(Some(id)) => id,
        Ok(None) => return fail("this node isn't in a cluster"),
        Err(e) => return fail(&e),
    };
    if !id.is_primary() {
        return fail("run this on the primary");
    }
    if !matches!(authority, "api" | "gitops") {
        return fail("the authority is `api` or `gitops`");
    }
    if let Err(e) = id.save_authority(authority) {
        return fail(&e);
    }
    let _ = writeln!(
        out,
        "Config authority is now `{authority}`. Restart telltale to publish it; every node follows."
    );
    ExitCode::SUCCESS
}

/// `telltale cluster set-failover manual|auto` (ADR-056), on the primary.
pub(crate) fn set_failover(
    cfg: &telltale_config::Config,
    out: &mut impl Write,
    mode: &str,
) -> ExitCode {
    let id = match Identity::load(data_dir(cfg)) {
        Ok(Some(id)) => id,
        Ok(None) => return fail("this node isn't in a cluster"),
        Err(e) => return fail(&e),
    };
    if !id.is_primary() {
        return fail("run this on the primary");
    }
    if let Err(e) = id.save_failover(mode) {
        return fail(&e);
    }
    let voters = telltale_cluster::failover::voters(&id).len();
    let _ = writeln!(
        out,
        "Failover is now `{mode}`. Restart telltale to publish it; every node follows."
    );
    if mode == "auto" && voters < 3 {
        let _ = writeln!(
            out,
            "Note: the cluster has {voters} voter(s); elections need 3 or more. Add a witness \
             (`telltale cluster join <token> --witness --advertise <url>`, then `telltale cluster witness`)."
        );
    }
    ExitCode::SUCCESS
}

/// `telltale cluster rotate-ca [--status]` (T5.4c, ADR-066).
pub(crate) fn rotate_ca(
    cfg: &telltale_config::Config,
    out: &mut impl Write,
    status: bool,
) -> ExitCode {
    use telltale_cluster::rotation;
    let id = match Identity::load(data_dir(cfg)) {
        Ok(Some(id)) => id,
        Ok(None) => return fail("this node isn't in a cluster"),
        Err(e) => return fail(&e),
    };
    if status {
        match rotation::current(&id) {
            None => {
                let _ = writeln!(out, "No CA rotation in progress.");
            }
            Some(r) => {
                let waiting = match r.phase.as_str() {
                    "trust" => "members still to trust the new CA",
                    _ => "members still to get a certificate from the new CA",
                };
                let _ = writeln!(
                    out,
                    "CA rotation: phase `{}` (new CA {}).",
                    r.phase,
                    &r.new_fp[..r.new_fp.len().min(16)]
                );
                if r.pending.is_empty() {
                    let _ = writeln!(
                        out,
                        "Nothing to wait for: the next step comes within a few seconds."
                    );
                } else {
                    let _ = writeln!(
                        out,
                        "Waiting for {} {waiting}: {}",
                        r.pending.len(),
                        r.pending.join(", ")
                    );
                }
            }
        }
        return ExitCode::SUCCESS;
    }
    let label = {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        format!("rotated {secs}")
    };
    match rotation::start(&id, &label) {
        Ok(r) => {
            let _ = writeln!(
                out,
                "Started a CA rotation (new CA {}). The running primary sends it to every node,                  switches once all trust it, and retires the old CA once all have new certificates.                  Follow it with `telltale cluster rotate-ca --status` or on the Cluster page.",
                &r.new_fp[..r.new_fp.len().min(16)]
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

/// `telltale cluster witness`: a vote-only member (ADR-056). Runs the cluster channel and
/// the election, nothing else: no DNS, no lists, no API.
pub(crate) fn witness(cfg: &telltale_config::Config) -> ExitCode {
    let id = match Identity::load(data_dir(cfg)) {
        Ok(Some(id)) if id.meta.witness => id,
        Ok(Some(_)) => return fail("this node isn't a witness (join with --witness)"),
        Ok(None) => {
            return fail(
                "this node isn't in a cluster: `telltale cluster join <token> --witness` first",
            );
        }
        Err(e) => return fail(&e),
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fail(&e.to_string()),
    };
    rt.block_on(async {
        let (stop_tx, stop) = watch::channel(false);
        info!(cluster = %id.meta.cluster_name, node = %id.meta.node_id, "witness: voting in elections only");
        let cluster = Cluster::new(id, VERSION);
        let c = Arc::clone(&cluster);
        cluster.set_rpc_handler(Arc::new(move |peer, kind, body| {
            let c = Arc::clone(&c);
            Box::pin(async move {
                if kind != telltale_cluster::failover::KIND {
                    return Err("a witness only votes".to_owned());
                }
                tokio::task::spawn_blocking(move || telltale_cluster::failover::answer(&c, &peer, &body))
                    .await
                    .map_err(|e| e.to_string())?
            })
        }));
        if let Ok(addr) = cfg.cluster.listen.as_str().parse::<SocketAddr>() {
            let (c, stop) = (Arc::clone(&cluster), stop.clone());
            tokio::spawn(async move {
                if let Err(e) = net::serve(c, addr, stop).await {
                    warn!(%addr, "cluster port: {e}");
                }
            });
        }
        tokio::spawn(net::dial(Arc::clone(&cluster), stop.clone()));
        tokio::spawn(net::mesh(Arc::clone(&cluster), stop.clone()));
        tokio::spawn(telltale_cluster::failover::run(Arc::clone(&cluster), stop.clone()));
        // T5.4c: the CAs to trust (a rotation) and the witness's own certificate renewal.
        tokio::spawn(net::follow_trust(Arc::clone(&cluster), stop.clone()));
        tokio::spawn(telltale_cluster::renew::run(Arc::clone(&cluster), stop.clone()));
        tokio::spawn(telltale_cluster::renew::run(Arc::clone(&cluster), stop.clone()));
        // The registry and failover mode come with the primary's signed manifests.
        let mut incoming = cluster.incoming();
        let ca = cluster.identity.ca_pem.clone();
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                () = terminated() => break,
                r = incoming.changed() => {
                    if r.is_err() { break; }
                    let signed = incoming.borrow_and_update().clone();
                    if let Some(m) = signed.and_then(|s| s.verify(&ca).ok()) {
                        if !m.nodes.is_empty() {
                            let _ = cluster.identity.save_registry(&m.nodes);
                        }
                        if !m.failover.is_empty() {
                            let _ = cluster.identity.save_failover(&m.failover);
                        }
                    }
                }
            }
        }
        let _ = stop_tx.send(true);
    });
    ExitCode::SUCCESS
}

#[cfg(unix)]
async fn terminated() {
    if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        s.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[cfg(not(unix))]
async fn terminated() {
    std::future::pending::<()>().await;
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

    fn pod(site: &str, name: &str, qps: u64) -> telltale_api::model::ClusterNode {
        telltale_api::model::ClusterNode {
            node_id: format!("id-{name}"),
            site: site.into(),
            pod: Some(name.into()),
            up: true,
            ready: true,
            qps,
            ..Default::default()
        }
    }

    /// REQ: CLU-008 (T6.14) — shares add up over the nodes that are up; a site's pods are
    /// flagged only when one takes more than twice its fair share, with enough traffic.
    #[test]
    fn clu_008_query_shares_and_balance() {
        let mut nodes = vec![
            pod("k8s", "a", 30),
            pod("k8s", "b", 10),
            pod("k8s", "c", 10),
        ];
        let mut down = pod("k8s", "d", 99);
        down.up = false;
        nodes.push(down);
        query_shares(&mut nodes);
        let shares: Vec<Option<f64>> = nodes.iter().map(|n| n.query_share_percent).collect();
        assert_eq!(shares, [Some(60.0), Some(20.0), Some(20.0), None]);
        // 30 of 50 over 3 pods: 1.8× the fair share, not flagged.
        assert!(balance_check(&nodes).ok);
        nodes[0].qps = 90;
        let c = balance_check(&nodes);
        assert!(
            !c.ok && c.summary.contains("k8s: a answers 82%"),
            "{}",
            c.summary
        );
        // Too little traffic to judge, or a single pod: fine.
        let quiet = [pod("k8s", "a", 3), pod("k8s", "b", 0)];
        assert!(balance_check(&quiet).ok);
        let one = [pod("k8s", "a", 500), pod("home", "pi", 1)];
        assert!(balance_check(&one).ok);
        // Nodes outside Kubernetes (no pod) aren't judged.
        let mut pis = [pod("home", "x", 90), pod("home", "y", 1)];
        for n in &mut pis {
            n.pod = None;
        }
        assert!(balance_check(&pis).ok);
    }

    // REQ: CLU-005 (ADR-051, ADR-048) — who may be promoted.
    #[test]
    fn clu_005_promotion_rules() {
        use telltale_cluster::node::{JoinRequest, Role};
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let primary = Identity::init_with(
            a.path(),
            "home",
            vec!["https://p:8443".into()],
            "k8s",
            "gitops",
        )
        .unwrap();
        let p = Cluster::new(primary.clone(), "0.1.0");
        assert!(
            promote(&p, true, false)
                .unwrap_err()
                .contains("already the primary")
        );
        // An eligible replica, joined without the network.
        let token = primary.create_token(60, None).unwrap();
        let key = pki::new_node_key().unwrap();
        let resp = primary
            .accept_join(
                &JoinRequest {
                    witness: false,
                    ephemeral: false,
                    secret: token.secret,
                    csr_pem: key.csr_pem,
                    advertise: vec![],
                    site: "pi".into(),
                    eligible: true,
                    version: "0.1.0".into(),
                },
                None,
            )
            .unwrap();
        let replica =
            Identity::save_joined(b.path(), &key.key_pem, &resp, "pi", true, vec![]).unwrap();
        replica.save_authority("gitops").unwrap();
        let r = Cluster::new(replica.clone(), "0.1.0");
        assert!(
            promote(&r, false, false)
                .unwrap_err()
                .contains("cluster key")
        );
        let ca_key = std::fs::read_to_string(a.path().join("cluster/ca.key")).unwrap();
        assert!(replica.store_ca_key(&ca_key).unwrap());
        // Configuration from Git, and this node isn't Git-managed: only an emergency promotion.
        assert!(promote(&r, false, false).unwrap_err().contains("emergency"));
        assert_eq!(promote(&r, false, true).unwrap(), 2);
        assert_eq!(r.role(), (Role::Emergency, 2));
        assert_eq!(replica.reload().meta.role, Some(Role::Emergency));
        assert_eq!(replica.reload().meta.config_authority, "gitops");
    }

    /// REQ: CLU-005 (ADR-048) — a node that can publish takes over from an emergency primary
    /// while it's up; nothing else is promoted over a running primary.
    #[test]
    fn clu_005_takeover_from_an_emergency_primary() {
        use telltale_cluster::sync::ClusterManifest;
        let held = ClusterManifest {
            primary: "pi".into(),
            emergency: true,
            ..ClusterManifest::default()
        };
        assert!(takeover_allowed(Some(&held), "pi", true));
        assert!(
            !takeover_allowed(Some(&held), "pi", false),
            "not for another emergency"
        );
        assert!(
            !takeover_allowed(Some(&held), "other", true),
            "a different primary is up"
        );
        let real = ClusterManifest {
            primary: "pi".into(),
            ..ClusterManifest::default()
        };
        assert!(
            !takeover_allowed(Some(&real), "pi", true),
            "a real primary stays"
        );
        assert!(!takeover_allowed(None, "pi", true));
    }

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
                Some("home-pi"),
                "api"
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
            init(&cfg, &mut out, "again", vec![], None, "api"),
            ExitCode::FAILURE
        );
    }
}
