//! The `telltale_api::Backend` implementation: the API's view of this server (REQ: API-001,
//! API-002). Reads only shared state that already exists for `/metrics` and the pipeline;
//! nothing here sits on the query path.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use serde::Serialize;
use telltale_api::model::{
    ClientChange, ClientInfo, ConfigChange, ExplainBlock, ExplainClient, ExplainFilter,
    ExplainLine, ExplainParams, ExplainRoute, ExplainRule, Explanation, ForwardInfo, GroupInfo,
    Hour, LatencyBy, LatencyRow, ListInfo, LocalName, NameMatch, QueryPage, QueryParams, QueryRow,
    RecordInput, ScanStats, Step, SystemInfo, TimeBucket, TopItem, TopKind, UpstreamInfo,
};
use telltale_api::problem::{Code, Problem};
use telltale_api::time::format_us;
use telltale_api::{Backend, BoxFuture, ClientWrite, ManagedKind, ManagedWrite};
use telltale_store::qlog;
use telltale_store::rollup::{Level, merge};
use telltale_store::state::ManagedError;
use telltale_telemetry::agg::{Counts, HourSel, LatencyKey, Percentiles, Resolution};
use telltale_telemetry::{N_RCODE, Path as AnswerPath, Proto, QTYPES, Status};
use telltale_upstream::health::Breaker;

use crate::http::Sources;

/// The current name of the device at `ip` (v4-mapped), by today's client table.
fn device_name(src: &Sources, ip: [u8; 16]) -> Option<String> {
    let v6 = std::net::Ipv6Addr::from(ip);
    let ip = v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4);
    let state = src.pipeline.current();
    let clients = &state.policy.clients;
    let id = clients.identify(ip, None, None, &src.pipeline.neighbors);
    clients.client(id).map(|c| c.name.to_string())
}

/// The API backend over the server's shared state.
#[derive(Debug)]
pub(crate) struct ApiBackend {
    pub(crate) src: Arc<Sources>,
}

/// A serde enum's wire name (`BlockMode::NullIp` → `null_ip`), so API strings never drift
/// from config and explain output.
fn label<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_owned))
        .unwrap_or_default()
}

const RCODES: [&str; 16] = [
    "NOERROR",
    "FORMERR",
    "SERVFAIL",
    "NXDOMAIN",
    "NOTIMP",
    "REFUSED",
    "YXDOMAIN",
    "YXRRSET",
    "NXRRSET",
    "NOTAUTH",
    "NOTZONE",
    "DSOTYPENI",
    "RCODE12",
    "RCODE13",
    "RCODE14",
    "RCODE15",
];

fn rcode_name(rc: u8) -> String {
    RCODES
        .get(usize::from(rc))
        .map_or_else(|| format!("RCODE{rc}"), |s| (*s).to_owned())
}

fn rcode_value(name: &str) -> Option<u8> {
    let up = name.trim().to_ascii_uppercase();
    RCODES
        .iter()
        .position(|r| *r == up)
        .and_then(|i| u8::try_from(i).ok())
        .or_else(|| up.strip_prefix("RCODE").and_then(|n| n.parse().ok()))
}

fn qtype_name(t: u16) -> String {
    QTYPES
        .iter()
        .find(|(v, _)| *v == t)
        .map_or_else(|| format!("TYPE{t}"), |(_, n)| (*n).to_owned())
}

#[allow(clippy::cast_precision_loss)]
fn ms(us: u64) -> f64 {
    (us as f64 / 10.0).round() / 100.0
}

fn mapped(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn hour(h: Hour) -> HourSel {
    match h {
        Hour::Current => HourSel::Current,
        Hour::Previous => HourSel::Previous,
    }
}

fn latency_row(key: String, p: Percentiles) -> LatencyRow {
    LatencyRow {
        key,
        count: p.count,
        p50_ms: ms(p.p50),
        p90_ms: ms(p.p90),
        p99_ms: ms(p.p99),
        p999_ms: ms(p.p999),
        max_ms: ms(p.max),
    }
}

/// Comma-separated values, trimmed, empty ones dropped.
fn csv(v: Option<&String>) -> Vec<String> {
    v.map(|s| {
        s.split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(str::to_owned)
            .collect()
    })
    .unwrap_or_default()
}

impl ApiBackend {
    /// Count buckets at `step`: seconds from memory; minutes from the rollup database
    /// overlaid with memory (memory is fresher); hours and days from the rollup database,
    /// or summed from memory minutes when it isn't available.
    fn counts(&self, step: Step, from_s: u64, to_s: u64) -> Vec<(u64, Counts)> {
        let mem = |res| {
            self.src
                .pipeline
                .telemetry
                .aggregates()
                .series(res, from_s, to_s)
        };
        let db = self.src.rollups.as_ref();
        let stored = |level| {
            db.map(|d| {
                d.range(level, from_s, to_s).unwrap_or_else(|e| {
                    tracing::warn!("rollups: {e}");
                    Vec::new()
                })
            })
        };
        match step {
            Step::Second => mem(Resolution::Second),
            Step::Minute => {
                let live = mem(Resolution::Minute);
                let Some(old) = stored(Level::Minute) else {
                    return live;
                };
                let mut by: std::collections::BTreeMap<u64, Counts> = old.into_iter().collect();
                by.extend(live);
                by.into_iter().collect()
            }
            Step::Hour | Step::Day => {
                let level = if step == Step::Hour {
                    Level::Hour
                } else {
                    Level::Day
                };
                stored(level).unwrap_or_else(|| {
                    let width = level.width_s();
                    let mut by = std::collections::BTreeMap::<u64, Counts>::new();
                    for (start, c) in mem(Resolution::Minute) {
                        merge(by.entry(start - start % width).or_default(), &c);
                    }
                    by.into_iter().collect()
                })
            }
        }
    }

    /// List names of the active snapshot, by list ID.
    fn list_names(&self) -> Vec<String> {
        self.src
            .pipeline
            .filter
            .load()
            .as_ref()
            .and_then(|f| f.matcher.snapshot().cloned())
            .map(|s| s.manifest.lists.iter().map(|l| l.name.clone()).collect())
            .unwrap_or_default()
    }
}

fn qlog_filter(q: &QueryParams, from_us: u64, to_us: u64) -> Result<qlog::Filter, Problem> {
    let name = q
        .name
        .clone()
        .map(|n| match q.name_match.unwrap_or_default() {
            NameMatch::Substring => qlog::NameMatch::Substring(n),
            NameMatch::Exact => qlog::NameMatch::Exact(n),
            NameMatch::Suffix => qlog::NameMatch::Suffix(n),
            NameMatch::Glob => qlog::NameMatch::Glob(n),
            NameMatch::Regex => qlog::NameMatch::Regex(n),
        });
    let client_ip = match &q.client {
        None => None,
        Some(c) => Some(mapped(c.parse::<IpAddr>().map_err(|_| {
            Problem::invalid(format!("`client`: `{c}` is not an IP address"))
        })?)),
    };
    let status = csv(q.status.as_ref())
        .iter()
        .map(|s| {
            Status::ALL
                .into_iter()
                .find(|x| x.label() == s)
                .ok_or_else(|| {
                    let all: Vec<&str> = Status::ALL.iter().map(|x| x.label()).collect();
                    Problem::invalid(format!("`status`: unknown `{s}`"))
                        .hint(format!("One or more of: {}.", all.join(", ")))
                })
        })
        .collect::<Result<_, _>>()?;
    let qtype = csv(q.qtype.as_ref())
        .iter()
        .map(|t| {
            telltale_proto::rtype::from_name(t)
                .ok_or_else(|| Problem::invalid(format!("`qtype`: unknown type `{t}`")))
        })
        .collect::<Result<_, _>>()?;
    let rcode = csv(q.rcode.as_ref())
        .iter()
        .map(|r| {
            rcode_value(r).ok_or_else(|| {
                Problem::invalid(format!("`rcode`: unknown `{r}`"))
                    .hint("Use names such as NOERROR, NXDOMAIN, SERVFAIL, REFUSED.")
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(qlog::Filter {
        from_us,
        to_us,
        name,
        client_ip,
        status,
        qtype,
        rcode,
        upstream: q.upstream,
        min_total_us: q.min_latency_ms.map(|v| v.saturating_mul(1000)),
        ..qlog::Filter::default()
    })
}

impl Backend for ApiBackend {
    fn system_info(&self) -> SystemInfo {
        let cfg = self.src.config.load();
        let snap = self
            .src
            .pipeline
            .filter
            .load()
            .as_ref()
            .and_then(|f| f.matcher.snapshot().cloned());
        let node = crate::http::node_name(&cfg);
        let started_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_micros())
            .saturating_sub(self.src.started.elapsed().as_micros());
        SystemInfo {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            node,
            role: label(&cfg.node.role),
            uptime_seconds: self.src.started.elapsed().as_secs(),
            started_at: format_us(u64::try_from(started_us).unwrap_or(0)),
            listeners: cfg
                .listen
                .iter()
                .map(|l| format!("{}://{}", label(&l.proto), l.addr))
                .collect(),
            query_log: self.src.qlog.is_some(),
            filter_snapshot: snap.as_ref().map(|s| s.manifest.version),
            filter_names: snap.as_ref().map_or(0, |s| {
                let st = &s.manifest.stats;
                st.subtree_names + st.exact_names + st.subdomains_names
            }),
            client_ips_masked: self.src.masked_clients().map(|m| {
                telltale_api::model::MaskedClients {
                    share_percent: m.share_percent,
                    sources: m.sources,
                    queries: m.queries,
                    window_start: format_us(m.window_start_s.saturating_mul(1_000_000)),
                }
            }),
            cluster: self.src.cluster.as_deref().map(crate::cluster::info),
        }
    }

    // REQ: CLU-008
    fn cluster(&self) -> telltale_api::model::ClusterView {
        match &self.src.cluster {
            Some(c) => {
                let mut v = crate::cluster::view(c);
                let cfg = self.src.config.load_full();
                // REQ: CLU-006 — settings in this node's file that the primary's replace.
                if crate::replication::follows_primary(&cfg) {
                    let ignored =
                        telltale_config::shared::ignored_on_replica(&self.src.file_config.load());
                    v.checks.push(telltale_api::model::ClusterCheck {
                        id: "node_settings".into(),
                        ok: ignored.is_empty(),
                        summary: if ignored.is_empty() {
                            "This node's file holds only node-local settings".into()
                        } else {
                            format!("Ignored in this node's file (the primary's apply): {}", ignored.join(", "))
                        },
                        fix: (!ignored.is_empty()).then(|| {
                            "Remove them from this node's file, or mark records that should stay on this node with node_only = true.".to_owned()
                        }),
                    });
                    v.healthy = v.checks.iter().all(|c| c.ok);
                }
                v.conflicts = crate::replication::conflicts(&cfg)
                    .into_iter()
                    .map(|k| telltale_api::model::ClusterConflict {
                        epoch: k.epoch,
                        seq: k.seq,
                        published_at: format_us(k.created_ms.saturating_mul(1000)),
                        detected_at: format_us(k.detected_ms.saturating_mul(1000)),
                        new_primary: k.new_primary,
                        changed: k.changed,
                    })
                    .collect();
                v
            }
            None => telltale_api::model::ClusterView {
                enabled: false,
                cluster_id: None,
                name: None,
                this_node: None,
                newest_config_seq: 0,
                healthy: true,
                checks: Vec::new(),
                nodes: Vec::new(),
                events: Vec::new(),
                authority: None,
                conflicts: Vec::new(),
            },
        }
    }

    // REQ: CLU-005 (ADR-051)
    fn promote(
        &self,
        req: telltale_api::model::PromoteRequest,
        by: String,
    ) -> Result<telltale_api::model::ClusterView, Problem> {
        let c = self
            .src
            .cluster
            .as_ref()
            .ok_or_else(|| Problem::unavailable("this node isn't in a cluster"))?;
        let cfg = self.src.config.load_full();
        let gitops_source = cfg.cluster.config_source.as_str() == "gitops";
        crate::cluster::promote(c, gitops_source, req.emergency)
            .map_err(|e| Problem::new(telltale_api::problem::Code::Conflict, e))?;
        tracing::info!(by = %by, "promoted to cluster primary through the API");
        Ok(self.cluster())
    }

    // REQ: OBS-004, `spec/06` §3 — live windows from memory, longer ranges from rollups.
    fn timeseries(&self, step: Step, from_s: u64, to_s: u64) -> Vec<TimeBucket> {
        let series = self.counts(step, from_s, to_s);
        let groups: Vec<String> = self
            .src
            .pipeline
            .current()
            .policy
            .clients
            .groups()
            .iter()
            .map(|g| g.name.to_string())
            .collect();
        series
            .into_iter()
            .map(|(start, c)| {
                let mut b = TimeBucket {
                    start_unix_seconds: start,
                    total: c.total,
                    upstream_queries: c.upstreams.iter().sum(),
                    upstream_failures: c.upstream_failures,
                    ..TimeBucket::default()
                };
                for (i, s) in Status::ALL.iter().enumerate() {
                    if c.status[i] > 0 {
                        b.by_status.insert(s.label().to_owned(), c.status[i]);
                    }
                }
                for (i, n) in c.qtype.iter().enumerate() {
                    if *n > 0 {
                        let key = QTYPES.get(i).map_or("other", |(_, name)| name);
                        b.by_qtype.insert(key.to_owned(), *n);
                    }
                }
                for (i, n) in c.rcode.iter().enumerate() {
                    if *n > 0 {
                        let key = if i == N_RCODE - 1 {
                            "other".to_owned()
                        } else {
                            rcode_name(u8::try_from(i).unwrap_or(u8::MAX))
                        };
                        b.by_rcode.insert(key, *n);
                    }
                }
                // ADR-050 — by group (index → name; indexes past the table are "other").
                for (i, n) in c.groups.iter().enumerate() {
                    if *n > 0 {
                        let key = groups.get(i).cloned().unwrap_or_else(|| "other".into());
                        *b.by_group.entry(key).or_default() += n;
                    }
                }
                for (i, n) in c.group_blocked.iter().enumerate() {
                    if *n > 0 {
                        let key = groups.get(i).cloned().unwrap_or_else(|| "other".into());
                        *b.blocked_by_group.entry(key).or_default() += n;
                    }
                }
                b
            })
            .collect()
    }

    // REQ: FLT-005 (ADR-050)
    fn top_in_group(
        &self,
        kind: TopKind,
        h: Hour,
        limit: usize,
        group: &str,
    ) -> Result<Vec<TopItem>, Problem> {
        let gi = self.group_index(group)?;
        let k = match kind {
            TopKind::Domains => telltale_telemetry::agg::TopKind::Domains,
            TopKind::Blocked => telltale_telemetry::agg::TopKind::Blocked,
            TopKind::Nxdomain => telltale_telemetry::agg::TopKind::Nxdomain,
            TopKind::Clients => telltale_telemetry::agg::TopKind::Clients,
        };
        let tops =
            self.src
                .pipeline
                .telemetry
                .aggregates()
                .top_names_in_group(k, hour(h), gi, limit);
        Ok(tops
            .into_iter()
            .map(|t| TopItem {
                name: (kind == TopKind::Clients)
                    .then(|| t.key.parse::<IpAddr>().ok())
                    .flatten()
                    .and_then(|ip| device_name(&self.src, mapped(ip))),
                key: t.key,
                count: t.count,
                error_bound: t.error,
            })
            .collect())
    }

    fn top(&self, kind: TopKind, h: Hour, limit: usize, client: Option<IpAddr>) -> Vec<TopItem> {
        let agg = self.src.pipeline.telemetry.aggregates();
        let tops = match (kind, client) {
            (TopKind::Domains, Some(ip)) => agg.top_client_domains(mapped(ip), limit),
            (k, _) => {
                let k = match k {
                    TopKind::Domains => telltale_telemetry::agg::TopKind::Domains,
                    TopKind::Blocked => telltale_telemetry::agg::TopKind::Blocked,
                    TopKind::Nxdomain => telltale_telemetry::agg::TopKind::Nxdomain,
                    TopKind::Clients => telltale_telemetry::agg::TopKind::Clients,
                };
                agg.top_names(k, hour(h), limit)
            }
        };
        drop(agg);
        let policy = &self.src.pipeline.current().policy;
        tops.into_iter()
            .map(|t| {
                // Clients get their configured device name when they have one.
                let name = (kind == TopKind::Clients)
                    .then(|| t.key.parse::<IpAddr>().ok())
                    .flatten()
                    .and_then(|ip| {
                        let id =
                            policy
                                .clients
                                .identify(ip, None, None, &self.src.pipeline.neighbors);
                        policy.clients.client(id).map(|c| c.name.to_string())
                    });
                TopItem {
                    key: t.key,
                    name,
                    count: t.count,
                    error_bound: t.error,
                }
            })
            .collect()
    }

    fn latency(&self, by: LatencyBy, h: Hour) -> Vec<LatencyRow> {
        let sel = hour(h);
        let agg = self.src.pipeline.telemetry.aggregates();
        let mut rows = Vec::new();
        match by {
            LatencyBy::Path => {
                for p in AnswerPath::ALL {
                    for proto in Proto::ALL {
                        if let Some(v) = agg.latency(LatencyKey::Total(p, proto), sel) {
                            rows.push(latency_row(format!("{}/{}", p.label(), proto.label()), v));
                        }
                    }
                }
            }
            LatencyBy::Qtype => {
                for i in 0..=QTYPES.len() {
                    if let Some(v) = agg.latency(LatencyKey::Qtype(i), sel) {
                        let key = QTYPES.get(i).map_or("other", |(_, n)| n);
                        rows.push(latency_row(key.to_owned(), v));
                    }
                }
            }
            LatencyBy::Stage => {
                if let Some(v) = agg.latency(LatencyKey::StageUpstream, sel) {
                    rows.push(latency_row("upstream".to_owned(), v));
                }
            }
            LatencyBy::Upstream => {
                let router = Arc::clone(&self.src.pipeline.current().router);
                for u in router.upstreams() {
                    if let Some(v) = agg.latency(LatencyKey::Upstream(u.id), sel) {
                        rows.push(latency_row(u.name.clone(), v));
                    }
                }
            }
        }
        rows
    }

    // REQ: OBS-008 — live tail: filter, rate-cap, and format on a per-subscriber task.
    fn tail(
        &self,
        p: &telltale_api::model::TailParams,
    ) -> Result<tokio::sync::mpsc::Receiver<telltale_api::model::TailItem>, Problem> {
        let tail = self.src.tail.as_ref().ok_or_else(|| {
            Problem::unavailable("the live tail is off: the query-log privacy level is 3")
                .hint("Lower [telemetry.qlog] privacy_level to see live queries.")
        })?;
        let policy = &self.src.pipeline.current().policy;
        let groups: Vec<String> = policy
            .clients
            .groups()
            .iter()
            .map(|g| g.name.to_string())
            .collect();
        let src = Arc::clone(&self.src);
        let filter = crate::tail::Filter::parse(p, &groups)?;
        let (events, slot) = tail.subscribe().ok_or_else(|| {
            Problem::unavailable(format!(
                "too many live tails on this node (at most {})",
                crate::tail::MAX_SUBSCRIBERS
            ))
            .hint("Close another live view, or use GET /queries.")
        })?;
        let lists = self.list_names();
        Ok(crate::tail::spawn_subscriber(
            events,
            slot,
            filter,
            move |t| {
                let e = &t.ev;
                QueryRow {
                    time: format_us(e.ts_us),
                    ts_unix_micros: e.ts_us,
                    client: telltale_telemetry::agg::client_text(e.client_ip),
                    client_name: device_name(&src, e.client_ip),
                    group: groups.get(usize::from(e.group)).cloned(),
                    name: telltale_telemetry::event::dotted(&t.name),
                    qtype: qtype_name(e.qtype),
                    status: e.status.label().to_owned(),
                    rcode: e.rcode.map(rcode_name),
                    proto: e.proto.label().to_owned(),
                    list: e.rule.map(|x| {
                        lists
                            .get(usize::from(x.list))
                            .cloned()
                            .unwrap_or_else(|| format!("#{}", x.list))
                    }),
                    rule: e
                        .rule
                        .map(|x| if x.allow { "allow" } else { x.kind.label() }.to_owned()),
                    total_ms: ms(u64::from(e.t_total_us)),
                    upstream_ms: ms(u64::from(e.t_upstream_us)),
                    response_bytes: e.resp_size,
                    answers: e.answers,
                    node: None,
                }
            },
        ))
    }

    fn queries(
        &self,
        q: &QueryParams,
        from_us: u64,
        to_us: u64,
        limit: usize,
    ) -> Result<QueryPage, Problem> {
        if self.src.qlog.is_none() {
            return Err(
                Problem::unavailable("the query log is off on this node").hint(
                    "Enable it with [telemetry.qlog] enabled = true (and privacy_level below 3).",
                ),
            );
        }
        let mut filter = qlog_filter(q, from_us, to_us)?;
        if let Some(g) = &q.group {
            filter.group = Some(self.group_index(g)?);
        }
        let cursor = match &q.cursor {
            None => None,
            Some(c) => Some(qlog::Cursor::decode(c).ok_or_else(|| {
                Problem::invalid("`cursor`: not a cursor from this API")
                    .hint("Pass the nextCursor value from the previous page unchanged.")
            })?),
        };
        let dir = Path::new(self.src.config.load().node.data_dir.as_str()).join("qlog");
        let opts = qlog::Options {
            threads: std::thread::available_parallelism().map_or(1, |n| n.get().min(4)),
            on_thread_start: Some(telltale_net::background_thread),
        };
        let page = qlog::search_with(&dir, &filter, limit, cursor, &opts)
            .map_err(|e| Problem::internal(format!("query log: {e}")))?;
        let lists = self.list_names();
        let policy = &self.src.pipeline.current().policy;
        let groups = policy.clients.groups();
        let items = page
            .rows
            .iter()
            .map(|r| QueryRow {
                time: format_us(r.ts_us),
                ts_unix_micros: r.ts_us,
                client: telltale_telemetry::agg::client_text(r.client_ip),
                // REQ: API-010 — names are resolved now, from the address, so naming or
                // renaming a device relabels its history without rewriting the log.
                client_name: device_name(&self.src, r.client_ip),
                node: None,
                group: groups.get(usize::from(r.group)).map(|g| g.name.to_string()),
                name: r.name.clone(),
                qtype: qtype_name(r.qtype),
                status: r.status.label().to_owned(),
                rcode: r.rcode.map(rcode_name),
                proto: r.proto.label().to_owned(),
                list: r.rule.map(|x| {
                    lists
                        .get(usize::from(x.list))
                        .cloned()
                        .unwrap_or_else(|| format!("#{}", x.list))
                }),
                rule: r
                    .rule
                    .map(|x| if x.allow { "allow" } else { x.kind.label() }.to_owned()),
                total_ms: ms(u64::from(r.t_total_us)),
                upstream_ms: ms(u64::from(r.t_upstream_us)),
                response_bytes: r.resp_size,
                answers: r.answers,
            })
            .collect();
        Ok(QueryPage {
            items,
            next_cursor: page.next.map(|c| c.encode()),
            scanned: ScanStats {
                segments: page.stats.segments,
                blocks_read: page.stats.blocks_read,
                blocks_total: page.stats.blocks_total,
                rows_scanned: page.stats.rows_scanned,
            },
            missing_nodes: Vec::new(),
        })
    }

    fn explain(&self, p: &ExplainParams) -> Result<Explanation, Problem> {
        let qtype_text = p.qtype.clone().unwrap_or_else(|| "A".to_owned());
        let qtype = telltale_proto::rtype::from_name(&qtype_text)
            .ok_or_else(|| Problem::invalid(format!("`qtype`: unknown type `{qtype_text}`")))?;
        let client: IpAddr = p
            .client
            .as_deref()
            .unwrap_or("127.0.0.1")
            .parse()
            .map_err(|_| Problem::invalid("`client` is not an IP address"))?;
        let mac = match p.mac.as_deref().map(telltale_config::MatchKey::parse) {
            None => None,
            Some(Ok(telltale_config::MatchKey::Mac(m))) => Some(m),
            Some(_) => {
                return Err(Problem::invalid("`mac` is not a MAC address")
                    .hint("Use the form aa:bb:cc:dd:ee:ff."));
            }
        };
        let req = crate::explain::Request {
            name: &p.name,
            qtype,
            client,
            mac,
            client_id: None,
        };
        let cfg = self.src.config.load();
        let e = self
            .src
            .pipeline
            .explain(&req, crate::lists::source_reader(&cfg))
            .map_err(|e| Problem::invalid(e).hint("Pass a domain name such as ads.example.com."))?;
        Ok(Explanation {
            name: e.name,
            qtype: qtype_name(e.qtype),
            client: ExplainClient {
                ip: e.client.ip.to_string(),
                mac: e.client.mac,
                device: e.client.device,
                identified_by: e.client.identified_by.to_owned(),
                groups: e.client.groups,
            },
            outcome: label(&e.outcome),
            summary: e.summary,
            block: e.block.map(|b| ExplainBlock {
                list: b.list,
                mode: label(&b.mode),
                ttl_seconds: b.ttl,
                ede_code: b.ede_code,
            }),
            paused_until_unix_seconds: e.paused_until,
            filter: e.filter.map(|f| ExplainFilter {
                snapshot: f.snapshot,
                rules: f
                    .rules
                    .into_iter()
                    .map(|r| ExplainRule {
                        list: r.list,
                        tier: label(&r.tier),
                        kind: label(&r.kind),
                        scope: r.scope.map(|s| label(&s)),
                        name: r.name,
                        enabled: r.enabled,
                        winner: r.winner,
                        lines: r
                            .lines
                            .into_iter()
                            .map(|l| ExplainLine {
                                line: l.line,
                                text: l.text,
                            })
                            .collect(),
                    })
                    .collect(),
                notes: f.notes,
            }),
            route: e.route.map(|r| ExplainRoute {
                group: r.group,
                routed: r.routed,
            }),
            notes: e.notes,
        })
    }

    fn lists(&self) -> Vec<ListInfo> {
        let cfg = self.src.config.load();
        let shared = self.src.lists.load_full();
        let status = shared
            .as_ref()
            .map(|l| l.fetcher.status())
            .unwrap_or_default();
        let compiled = shared.as_ref().and_then(|l| {
            l.compiled
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .map(|c| c.manifest.clone())
        });
        cfg.list
            .iter()
            .map(|l| {
                let meta = status.iter().find(|(n, _)| *n == *l.name).map(|(_, m)| m);
                let entries = compiled.as_ref().map_or(0, |m| {
                    m.lists
                        .iter()
                        .position(|x| x.name == *l.name)
                        .and_then(|i| m.stats.per_list.get(i))
                        .map_or(0, |s| s.entries)
                });
                let source = l
                    .url
                    .as_ref()
                    .or(l.path.as_ref())
                    .map_or_else(|| "inline".to_owned(), ToString::to_string);
                let state = match meta {
                    Some(m) if m.last_error.is_some() && !m.has_content() => "failed",
                    Some(m) if m.has_content() => "ok",
                    _ => "pending",
                };
                ListInfo {
                    name: l.name.to_string(),
                    kind: label(&l.kind),
                    enabled: l.enabled,
                    source,
                    state: state.to_owned(),
                    error: meta.and_then(|m| m.last_error.clone()),
                    bytes: meta.map_or(0, |m| m.bytes),
                    lines: meta.map_or(0, |m| m.lines),
                    entries,
                    last_checked_unix_seconds: meta.and_then(|m| m.last_attempt),
                    last_changed_unix_seconds: meta.and_then(|m| m.last_changed),
                }
            })
            .collect()
    }

    fn groups(&self) -> Vec<GroupInfo> {
        let now = crate::pipeline::unix_now();
        let pauses = self.src.pipeline.pause.active(now);
        let global = pauses.iter().find(|(g, _)| g.is_none()).map(|(_, u)| *u);
        let policy = &self.src.pipeline.current().policy;
        // Last 24 hours from the minute series, per group: (queries, blocked).
        let agg = self.src.pipeline.telemetry.aggregates();
        let mut day = (Vec::<u64>::new(), Vec::<u64>::new());
        for (_, c) in agg.series(
            telltale_telemetry::agg::Resolution::Minute,
            now.saturating_sub(86_400),
            now + 60,
        ) {
            for (i, n) in c.groups.iter().enumerate() {
                if day.0.len() <= i {
                    day.0.resize(i + 1, 0);
                }
                day.0[i] += u64::from(*n);
            }
            for (i, n) in c.group_blocked.iter().enumerate() {
                if day.1.len() <= i {
                    day.1.resize(i + 1, 0);
                }
                day.1[i] += u64::from(*n);
            }
        }
        policy
            .clients
            .groups()
            .iter()
            .enumerate()
            .map(|(i, g)| GroupInfo {
                networks: g.networks.iter().map(ToString::to_string).collect(),
                color: g
                    .color
                    .as_deref()
                    .map_or_else(|| palette(i, &g.name), str::to_owned),
                queries_24h: day.0.get(i).copied().unwrap_or(0),
                blocked_24h: day.1.get(i).copied().unwrap_or(0),
                devices_this_hour: u64::try_from(agg.group_devices(
                    telltale_telemetry::agg::HourSel::Current,
                    u16::try_from(i).unwrap_or(u16::MAX),
                ))
                .unwrap_or(0),
                name: g.name.to_string(),
                priority: g.priority,
                lists: g
                    .lists
                    .as_ref()
                    .map(|l| l.iter().map(ToString::to_string).collect()),
                block_mode: label(&g.block.mode),
                block_ttl_seconds: g.block.ttl,
                paused_until_unix_seconds: pauses
                    .iter()
                    .find(|(n, _)| n.as_deref() == Some(&*g.name))
                    .map(|(_, u)| *u)
                    .max(global),
            })
            .collect()
    }

    fn clients(&self) -> Vec<ClientInfo> {
        let managed = managed_names(&self.src);
        self.src
            .config
            .load()
            .client
            .iter()
            .map(|c| client_info(c, &managed))
            .collect()
    }

    fn config_version(&self) -> u64 {
        self.src
            .auth
            .get()
            .and_then(|a| a.state().config_version().ok())
            .unwrap_or(0)
    }

    // REQ: OBS-013 — device anomalies with evidence.
    fn anomalies(&self, since_s: u64) -> Vec<telltale_api::model::AnomalyFinding> {
        let Some(a) = &self.src.anomalies else {
            return Vec::new();
        };
        a.findings()
            .into_iter()
            .filter(|f| f.window_start_s >= since_s)
            .map(|f| telltale_api::model::AnomalyFinding {
                kind: f.kind.label().to_owned(),
                client: telltale_telemetry::agg::client_text(f.client),
                client_name: device_name(&self.src, f.client),
                domain: f.domain,
                window_start: format_us(f.window_start_s.saturating_mul(1_000_000)),
                window_seconds: f.window_s,
                observed: f.observed,
                baseline: f.baseline,
                spread: f.spread,
                threshold: f.threshold,
                detail: f.detail,
            })
            .collect()
    }

    // REQ: API-011 — names on my network and domains sent elsewhere (ADR-042).
    fn local_names(&self) -> Vec<LocalName> {
        self.list_local_names()
    }

    fn forwards(&self) -> Vec<ForwardInfo> {
        self.list_forwards()
    }

    fn write_managed(&self, w: ManagedWrite) -> BoxFuture<Result<ConfigChange, Problem>> {
        if let Some(p) = self.replica_read_only() {
            return Box::pin(async move { Err(p) });
        }
        self.do_write_managed(w)
    }

    // REQ: API-002, API-010 — devices named through the API (ADR-040).
    fn write_client(&self, w: ClientWrite) -> BoxFuture<Result<ClientChange, Problem>> {
        if let Some(p) = self.replica_read_only() {
            return Box::pin(async move { Err(p) });
        }
        let src = Arc::clone(&self.src);
        Box::pin(async move {
            let state = src
                .auth
                .get()
                .map(|a| Arc::clone(a.state()))
                .ok_or_else(|| Problem::unavailable("the state database isn't open yet"))?;
            let (plan, current) = {
                let (src, state, w) = (Arc::clone(&src), Arc::clone(&state), w.clone());
                tokio::task::spawn_blocking(move || {
                    let current = state
                        .config_version()
                        .map_err(|e| Problem::internal(e.to_string()))?;
                    plan_client(&src, &state, &w).map(|p| (p, current))
                })
                .await
                .map_err(|e| Problem::internal(format!("request worker failed: {e}")))??
            };
            let change = |applied, version| ClientChange {
                applied,
                config_version: version,
                before: plan.before.clone(),
                after: plan
                    .after
                    .as_ref()
                    .map(|c| client_info(c, &[c.name.to_string()])),
                recent_queries: plan.recent_queries,
                warnings: plan.warnings.clone(),
            };
            if w.dry_run {
                if let Some(v) = w.expect
                    && v != current
                {
                    return Err(version_conflict(current));
                }
                return Ok(change(false, current));
            }
            let stored = {
                let (state, w, after) = (Arc::clone(&state), w.clone(), plan.after.clone());
                tokio::task::spawn_blocking(move || {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs());
                    match &after {
                        Some(c) => {
                            let body = serde_json::to_string(c).unwrap_or_default();
                            let from = (c.name.as_str() != w.name).then_some(w.name.as_str());
                            state.put_managed(
                                crate::managed::CLIENT,
                                c.name.as_str(),
                                &body,
                                from,
                                w.expect,
                                now,
                                &w.by,
                            )
                        }
                        None => state.delete_managed(crate::managed::CLIENT, &w.name, w.expect),
                    }
                })
                .await
                .map_err(|e| Problem::internal(format!("request worker failed: {e}")))?
            };
            let version = stored.map_err(|e| match e {
                ManagedError::VersionConflict { current } => version_conflict(current),
                ManagedError::NotFound { .. } => Problem::not_found(e.to_string()),
                ManagedError::State(e) => Problem::internal(e.to_string()),
            })?;
            // Apply: the main loop re-reads the files and state.db, validates, and swaps.
            let (tx, rx) = tokio::sync::oneshot::channel();
            let applied = src.reload.send(tx).await.is_ok() && rx.await.unwrap_or(false);
            if !applied {
                return Err(Problem::internal(
                    "the change was saved but couldn't be applied; the server log says why",
                ));
            }
            Ok(change(true, version))
        })
    }

    fn upstreams(&self) -> Vec<UpstreamInfo> {
        let cfg = self.src.config.load();
        let router = Arc::clone(&self.src.pipeline.current().router);
        router
            .upstreams()
            .iter()
            .map(|u| {
                let h = u.health.snapshot();
                UpstreamInfo {
                    id: u.id,
                    name: u.name.clone(),
                    endpoint: u.endpoint.to_string(),
                    groups: cfg
                        .upstream_group
                        .iter()
                        .filter(|g| g.members.iter().any(|m| **m == *u.name))
                        .map(|g| g.name.to_string())
                        .collect(),
                    breaker: match h.breaker {
                        Breaker::Closed => "closed",
                        Breaker::HalfOpen => "half_open",
                        Breaker::Open => "open",
                    }
                    .to_owned(),
                    requests: h.requests,
                    failures: h.failures,
                    latency_ewma_ms: h.ewma.map_or(0.0, |d| {
                        ms(u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
                    }),
                }
            })
            .collect()
    }
}

/// Names of the devices stored through the API.
fn managed_names(src: &Sources) -> Vec<String> {
    src.auth
        .get()
        .and_then(|a| a.state().managed(crate::managed::CLIENT).ok())
        .map(|m| m.into_iter().map(|e| e.name).collect())
        .unwrap_or_default()
}

fn client_info(c: &telltale_config::ClientConfig, managed: &[String]) -> ClientInfo {
    ClientInfo {
        name: c.name.to_string(),
        matches: c.match_keys.iter().map(ToString::to_string).collect(),
        groups: c.groups.iter().map(ToString::to_string).collect(),
        source: if managed.iter().any(|m| m == c.name.as_str()) {
            "api".to_owned()
        } else {
            "file".to_owned()
        },
    }
}

fn version_conflict(current: u64) -> Problem {
    Problem::new(
        Code::VersionConflict,
        format!("the configuration is now at version {current}"),
    )
    .hint("Re-read the clients (GET /api/v1/clients returns the version as ETag) and retry with If-Match.")
}

/// A validated device change.
struct ClientPlan {
    before: Option<ClientInfo>,
    /// `None` deletes.
    after: Option<telltale_config::ClientConfig>,
    recent_queries: u64,
    warnings: Vec<String>,
}

/// Checks a device write against the running configuration (ADR-040): files win, names are
/// unique, and the resulting configuration must validate.
fn plan_client(
    src: &Sources,
    state: &telltale_store::state::State,
    w: &ClientWrite,
) -> Result<ClientPlan, Problem> {
    let managed: Vec<String> = state
        .managed(crate::managed::CLIENT)
        .map_err(|e| Problem::internal(e.to_string()))?
        .into_iter()
        .map(|m| m.name)
        .collect();
    let cfg = src.config.load_full();
    let is_managed = |n: &str| managed.iter().any(|m| m == n);
    let in_files = |n: &str| cfg.client.iter().any(|c| c.name.as_str() == n) && !is_managed(n);
    if in_files(&w.name) {
        return Err(Problem::new(
            Code::Conflict,
            format!("`{}` is defined in the config files", w.name),
        )
        .hint("Change it in the config file, or name the device differently."));
    }
    let before = cfg
        .client
        .iter()
        .find(|c| c.name.as_str() == w.name)
        .map(|c| client_info(c, &managed));
    let after = match &w.input {
        None => {
            if before.is_none() {
                return Err(Problem::not_found(format!(
                    "no device named `{}` was created through the API",
                    w.name
                )));
            }
            None
        }
        Some(input) => {
            let name = input.name.as_deref().unwrap_or(&w.name).trim().to_owned();
            if name != w.name && (in_files(&name) || is_managed(&name)) {
                return Err(Problem::new(
                    Code::Conflict,
                    format!("there is already a device named `{name}`"),
                ));
            }
            let groups = if input.groups.is_empty() {
                vec!["default".to_owned()]
            } else {
                input.groups.clone()
            };
            let json =
                serde_json::json!({ "name": name, "match": input.matches, "groups": groups });
            let c: telltale_config::ClientConfig = serde_json::from_value(json)
                .map_err(|e| Problem::new(Code::InvalidConfig, format!("device: {e}")))?;
            Some(c)
        }
    };
    let mut candidate = (*cfg).clone();
    let new_name = after.as_ref().map(|c| c.name.to_string());
    candidate
        .client
        .retain(|c| c.name.as_str() != w.name && Some(c.name.as_str()) != new_name.as_deref());
    if let Some(c) = &after {
        candidate.client.push(c.clone());
    }
    let warnings = telltale_config::validate_config(&candidate).map_err(|errs| {
        Problem::new(
            Code::InvalidConfig,
            errs.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; "),
        )
        .hint("GET /api/v1/groups lists the groups a device can join.")
    })?;
    // AGT-002 impact: recent queries from the addresses it matches (they get the new label).
    let keys: Vec<String> = after
        .as_ref()
        .map(|c| c.match_keys.iter().map(ToString::to_string).collect())
        .or_else(|| before.as_ref().map(|b| b.matches.clone()))
        .unwrap_or_default();
    let nets: Vec<telltale_config::Cidr> = keys
        .iter()
        .filter_map(|k| telltale_config::Cidr::parse(k).ok())
        .collect();
    let agg = src.pipeline.telemetry.aggregates();
    let recent_queries = [HourSel::Current, HourSel::Previous]
        .into_iter()
        .flat_map(|h| agg.top_names(telltale_telemetry::agg::TopKind::Clients, h, 1000))
        .filter(|t| {
            t.key
                .parse::<IpAddr>()
                .is_ok_and(|ip| nets.iter().any(|n| n.contains(ip)))
        })
        .map(|t| t.count)
        .sum();
    drop(agg);
    Ok(ClientPlan {
        before,
        after,
        recent_queries,
        warnings,
    })
}

/// The `state.db` kind for an API kind.
fn kind_name(k: ManagedKind) -> &'static str {
    match k {
        ManagedKind::Record => crate::managed::RECORD,
        ManagedKind::Forward => crate::managed::FORWARD,
    }
}

/// A local name or domain as stored: lowercase, no trailing dot.
fn norm(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// A validated change to a local name or forwarded domain.
struct ManagedPlan {
    name: String,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
    /// What to store (`None` deletes).
    body: Option<String>,
    warnings: Vec<String>,
}

/// Parses a records body into stored form.
fn record_values(
    v: &serde_json::Value,
    name: &str,
) -> Result<Vec<crate::managed::RecordValue>, Problem> {
    let input: telltale_api::model::RecordsInput =
        serde_json::from_value(v.clone()).map_err(|e| Problem::invalid(format!("body: {e}")))?;
    if input.records.is_empty() {
        return Err(Problem::new(
            Code::InvalidConfig,
            format!("`{name}`: give at least one record (or DELETE the name)"),
        ));
    }
    Ok(input
        .records
        .into_iter()
        .map(|r| crate::managed::RecordValue {
            rtype: r.rtype.trim().to_ascii_uppercase(),
            value: r.value.trim().to_owned(),
            ttl: r.ttl,
        })
        .collect())
}

/// Parses a forward body into stored form.
fn forward_of(v: &serde_json::Value, name: &str) -> Result<crate::managed::Forward, Problem> {
    let input: telltale_api::model::ForwardInput =
        serde_json::from_value(v.clone()).map_err(|e| Problem::invalid(format!("body: {e}")))?;
    let servers: Vec<String> = input
        .servers
        .iter()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    if servers.is_empty() {
        return Err(Problem::new(
            Code::InvalidConfig,
            format!("`{name}`: give at least one server"),
        ));
    }
    Ok(crate::managed::Forward { servers })
}

/// Checks a local-name or forward write (ADR-042): files win, and the files plus every API
/// entry with this change must validate, record values included.
fn plan_managed(
    src: &Sources,
    state: &telltale_store::state::State,
    w: &ManagedWrite,
) -> Result<ManagedPlan, Problem> {
    let name = norm(&w.name);
    if name.is_empty() {
        return Err(Problem::invalid("the name is empty"));
    }
    let file = src.file_config.load_full();
    let in_files = match w.kind {
        ManagedKind::Record => file
            .record
            .iter()
            .any(|r| r.name.eq_ignore_ascii_case(&name)),
        ManagedKind::Forward => file
            .route
            .iter()
            .any(|r| r.match_suffix.iter().any(|s| s.eq_ignore_ascii_case(&name))),
    };
    if in_files {
        return Err(Problem::new(
            Code::Conflict,
            format!("`{name}` is defined in the config files"),
        )
        .hint("Change it in the config file."));
    }
    let mut entries = crate::managed::entries(state);
    let (before, after) = match w.kind {
        ManagedKind::Record => {
            let before = entries
                .records
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, r)| r.clone());
            entries.records.retain(|(n, _)| *n != name);
            let after = match &w.body {
                None => None,
                Some(v) => {
                    let recs = record_values(v, &name)?;
                    entries.records.push((name.clone(), recs.clone()));
                    Some(recs)
                }
            };
            (
                before.map(|b| serde_json::json!({ "name": name, "records": b })),
                after.map(|a| serde_json::json!({ "name": name, "records": a })),
            )
        }
        ManagedKind::Forward => {
            let before = entries
                .forwards
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, f)| f.clone());
            entries.forwards.retain(|(n, _)| *n != name);
            let after = match &w.body {
                None => None,
                Some(v) => {
                    let f = forward_of(v, &name)?;
                    entries.forwards.push((name.clone(), f.clone()));
                    Some(f)
                }
            };
            (
                before.map(|b| serde_json::json!({ "domain": name, "servers": b.servers })),
                after.map(|a| serde_json::json!({ "domain": name, "servers": a.servers })),
            )
        }
    };
    if w.body.is_none() && before.is_none() {
        return Err(Problem::not_found(format!(
            "`{name}` wasn't created through the API"
        )));
    }
    let merged = crate::managed::merge(&file, &entries)
        .map_err(|errs| Problem::new(Code::InvalidConfig, errs.join("; ")))?;
    let warnings = telltale_config::validate_config(&merged).unwrap_or_default();
    let body = match (w.kind, &after) {
        (_, None) => None,
        (ManagedKind::Record, Some(a)) => Some(a["records"].to_string()),
        (ManagedKind::Forward, Some(a)) => {
            Some(serde_json::json!({ "servers": a["servers"] }).to_string())
        }
    };
    Ok(ManagedPlan {
        name,
        before,
        after,
        body,
        warnings,
    })
}

impl ApiBackend {
    /// A group's index by name, or a 400 naming the groups that exist.
    fn group_index(&self, name: &str) -> Result<u16, Problem> {
        let policy = &self.src.pipeline.current().policy;
        let groups = policy.clients.groups();
        groups
            .iter()
            .position(|g| &*g.name == name)
            .and_then(|i| u16::try_from(i).ok())
            .ok_or_else(|| {
                Problem::invalid(format!("`group`: no group named `{name}`")).hint(format!(
                    "Groups: {}.",
                    groups
                        .iter()
                        .map(|g| g.name.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })
    }

    /// REQ: CLU-003 — a replica that follows the primary takes configuration only from it;
    /// writes go to the primary (forwarded automatically once T5.7 lands).
    fn replica_read_only(&self) -> Option<Problem> {
        let cfg = self.src.config.load_full();
        // ADR-048 — under a GitOps authority, configuration changes go to Git on every node.
        if let Some(c) = &self.src.cluster
            && c.identity.reload().meta.config_authority == "gitops"
        {
            return Some(
                Problem::new(
                    telltale_api::problem::Code::GitopsManaged,
                    "this cluster's configuration comes from Git",
                )
                .hint("change it in the Git repository; every node follows within seconds of the primary applying it"),
            );
        }
        let m = crate::replication::applied(&cfg)?;
        let at = self
            .src
            .cluster
            .as_ref()
            .and_then(|c| c.connected_primary())
            .unwrap_or_else(|| format!("node {}", m.primary));
        Some(
            Problem::new(
                telltale_api::problem::Code::Conflict,
                "this node is a cluster replica: its configuration comes from the primary",
            )
            .hint(format!(
                "make this change on the primary ({at}); it reaches every node within seconds"
            )),
        )
    }

    fn managed_names_of(&self, kind: &str) -> Vec<String> {
        self.src
            .auth
            .get()
            .and_then(|a| a.state().managed(kind).ok())
            .map(|m| m.into_iter().map(|e| e.name).collect())
            .unwrap_or_default()
    }

    pub(crate) fn list_local_names(&self) -> Vec<LocalName> {
        let api = self.managed_names_of(crate::managed::RECORD);
        let cfg = self.src.config.load();
        let mut out: Vec<LocalName> = Vec::new();
        for r in &cfg.record {
            let rec = RecordInput {
                rtype: r.rtype.to_ascii_uppercase(),
                value: r.value.to_string(),
                ttl: r.ttl,
            };
            match out
                .iter_mut()
                .find(|n| n.name.eq_ignore_ascii_case(&r.name))
            {
                Some(n) => n.records.push(rec),
                None => out.push(LocalName {
                    name: r.name.to_ascii_lowercase(),
                    records: vec![rec],
                    source: if api.iter().any(|a| a.eq_ignore_ascii_case(&r.name)) {
                        "api".into()
                    } else {
                        "file".into()
                    },
                }),
            }
        }
        out
    }

    pub(crate) fn list_forwards(&self) -> Vec<ForwardInfo> {
        let api = self.managed_names_of(crate::managed::FORWARD);
        let cfg = self.src.config.load();
        let url_of = |name: &str| {
            cfg.upstream
                .iter()
                .find(|u| u.name.as_str() == name)
                .map(|u| u.url.to_string())
        };
        let mut out = Vec::new();
        for r in &cfg.route {
            if !r.match_group.is_empty() || !r.match_qtype.is_empty() {
                continue; // per-group or per-type routes aren't "send this domain" routes
            }
            let servers: Vec<String> = cfg
                .upstream_group
                .iter()
                .find(|g| g.name == r.upstream_group)
                .map(|g| g.members.iter().filter_map(|m| url_of(m)).collect())
                .unwrap_or_default();
            for d in &r.match_suffix {
                out.push(ForwardInfo {
                    domain: d.to_ascii_lowercase(),
                    servers: servers.clone(),
                    source: if api.iter().any(|a| a.eq_ignore_ascii_case(d)) {
                        "api".into()
                    } else {
                        "file".into()
                    },
                });
            }
        }
        out
    }

    pub(crate) fn do_write_managed(
        &self,
        w: ManagedWrite,
    ) -> BoxFuture<Result<ConfigChange, Problem>> {
        let src = Arc::clone(&self.src);
        Box::pin(async move {
            let state = src
                .auth
                .get()
                .map(|a| Arc::clone(a.state()))
                .ok_or_else(|| Problem::unavailable("the state database isn't open yet"))?;
            let (plan, current) = {
                let (src, state, w) = (Arc::clone(&src), Arc::clone(&state), w.clone());
                tokio::task::spawn_blocking(move || {
                    let current = state
                        .config_version()
                        .map_err(|e| Problem::internal(e.to_string()))?;
                    plan_managed(&src, &state, &w).map(|p| (p, current))
                })
                .await
                .map_err(|e| Problem::internal(format!("request worker failed: {e}")))??
            };
            let change = |applied, version| ConfigChange {
                applied,
                config_version: version,
                before: plan.before.clone(),
                after: plan.after.clone(),
                warnings: plan.warnings.clone(),
            };
            if w.dry_run {
                if let Some(v) = w.expect
                    && v != current
                {
                    return Err(version_conflict(current));
                }
                return Ok(change(false, current));
            }
            let stored = {
                let (state, w, name, body) = (
                    Arc::clone(&state),
                    w.clone(),
                    plan.name.clone(),
                    plan.body.clone(),
                );
                tokio::task::spawn_blocking(move || {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs());
                    let kind = kind_name(w.kind);
                    match &body {
                        Some(b) => state.put_managed(kind, &name, b, None, w.expect, now, &w.by),
                        None => state.delete_managed(kind, &name, w.expect),
                    }
                })
                .await
                .map_err(|e| Problem::internal(format!("request worker failed: {e}")))?
            };
            let version = stored.map_err(|e| match e {
                ManagedError::VersionConflict { current } => version_conflict(current),
                ManagedError::NotFound { .. } => Problem::not_found(e.to_string()),
                ManagedError::State(e) => Problem::internal(e.to_string()),
            })?;
            let (tx, rx) = tokio::sync::oneshot::channel();
            let applied = src.reload.send(tx).await.is_ok() && rx.await.unwrap_or(false);
            if !applied {
                return Err(Problem::internal(
                    "the change was saved but couldn't be applied; the server log says why",
                ));
            }
            Ok(change(true, version))
        })
    }
}

/// A stable color for a group without one (ADR-050): `default` is neutral; others cycle a
/// palette by position, so colors don't shift when a group's stats change.
fn palette(i: usize, name: &str) -> String {
    const COLORS: [&str; 10] = [
        "#3b82f6", "#22c55e", "#f59e0b", "#ef4444", "#8b5cf6", "#06b6d4", "#ec4899", "#84cc16",
        "#f97316", "#14b8a6",
    ];
    if name == "default" {
        "#94a3b8".into()
    } else {
        COLORS[i % COLORS.len()].into()
    }
}
