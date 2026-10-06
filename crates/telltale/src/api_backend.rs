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
    clients.client(id).map(|c| c.name.to_string()).or_else(|| {
        // REQ: OPS-008 (T7.19) — an unnamed device is called by its DHCP host name.
        let IpAddr::V4(v4) = ip else { return None };
        src.pipeline
            .dhcp_leases
            .load()
            .get(&v4)
            .and_then(|l| l.hostname.clone())
            // REQ: T8.2 — then the routers' DHCP clients.
            .or_else(|| {
                src.pipeline
                    .router_leases
                    .load()
                    .get(&v4)
                    .and_then(|l| l.hostname.clone())
            })
            // REQ: T8.3 — then what the device announces over mDNS.
            .or_else(|| {
                src.pipeline
                    .mdns_names
                    .load()
                    .get(&v4)
                    .and_then(|l| l.hostname.clone())
            })
    })
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

pub(crate) fn rcode_name(rc: u8) -> String {
    RCODES
        .get(usize::from(rc))
        .map_or_else(|| format!("RCODE{rc}"), |s| (*s).to_owned())
}

pub(crate) fn rcode_value(name: &str) -> Option<u8> {
    let up = name.trim().to_ascii_uppercase();
    RCODES
        .iter()
        .position(|r| *r == up)
        .and_then(|i| u8::try_from(i).ok())
        .or_else(|| up.strip_prefix("RCODE").and_then(|n| n.parse().ok()))
}

pub(crate) fn qtype_name(t: u16) -> String {
    QTYPES
        .iter()
        .find(|(v, _)| *v == t)
        .map_or_else(|| format!("TYPE{t}"), |(_, n)| (*n).to_owned())
}

#[allow(clippy::cast_precision_loss)]
pub(crate) fn ms(us: u64) -> f64 {
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

pub(crate) fn latency_row(key: String, p: Percentiles) -> LatencyRow {
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
    /// The latency keys `by` breaks down into, with their names.
    fn latency_keys(&self, by: LatencyBy) -> Vec<(String, LatencyKey)> {
        match by {
            LatencyBy::Path => AnswerPath::ALL
                .into_iter()
                .flat_map(|p| {
                    Proto::ALL.into_iter().map(move |proto| {
                        (
                            format!("{}/{}", p.label(), proto.label()),
                            LatencyKey::Total(p, proto),
                        )
                    })
                })
                .collect(),
            LatencyBy::Qtype => (0..=QTYPES.len())
                .map(|i| {
                    let key = QTYPES.get(i).map_or("other", |(_, n)| n);
                    (key.to_owned(), LatencyKey::Qtype(i))
                })
                .collect(),
            LatencyBy::Stage => vec![("upstream".to_owned(), LatencyKey::StageUpstream)],
            LatencyBy::Upstream => {
                let router = Arc::clone(&self.src.pipeline.current().router);
                router
                    .upstreams()
                    .iter()
                    .map(|u| (u.name.clone(), LatencyKey::Upstream(u.id)))
                    .collect()
            }
        }
    }

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

/// REQ: FLT-010 (T7.10) — the group's schedules that are on at `now`.
fn schedules_on(cfg: &telltale_config::Config, group: &str, now: i64) -> Vec<String> {
    let Some(g) = cfg.group.iter().find(|x| x.name.as_str() == group) else {
        return Vec::new();
    };
    telltale_config::schedule::compile(cfg)
        .into_iter()
        .filter(|s| g.schedules.iter().any(|n| n.as_str() == s.name) && s.is_on(now))
        .map(|s| s.name)
        .collect()
}

/// REQ: FLT-013 (ADR-067) — a decision's list and kind for query-log rows. A quick rule is
/// named by its note (else its domain) and whom it applies to; one that no longer exists says so.
pub(crate) fn rule_labels(
    rule: Option<telltale_telemetry::event::Rule>,
    lists: &[String],
    quick: &telltale_policy::QuickRules,
    schedules: &[(u16, String)],
) -> (Option<String>, Option<String>) {
    use telltale_telemetry::event::RuleKind;
    let Some(x) = rule else { return (None, None) };
    // REQ: FLT-015 (T7.20) — an answer address refused.
    if x.kind == RuleKind::AnswerIp {
        return (
            Some("answer address (rebinding protection or a blocked range)".to_owned()),
            Some("answer_ip".to_owned()),
        );
    }
    // REQ: FLT-010 (T7.10) — a block-everything schedule.
    if x.kind == RuleKind::Schedule {
        let name = schedules.iter().find(|(r, _)| *r == x.list).map_or_else(
            || "a schedule (since removed)".to_owned(),
            |(_, n)| format!("schedule {n}"),
        );
        return (Some(name), Some("schedule".to_owned()));
    }
    if x.kind == RuleKind::Quick {
        let list = quick.by_ref(x.list).map_or_else(
            || "a quick rule (since removed)".to_owned(),
            |q| {
                let what = q.note.as_deref().unwrap_or(&q.domain);
                if q.targets.is_empty() {
                    format!("quick rule: {what}")
                } else {
                    format!("quick rule: {what} ({})", q.targets.join(", "))
                }
            },
        );
        let kind = if x.allow {
            "quick allow"
        } else {
            "quick block"
        };
        return (Some(list), Some(kind.to_owned()));
    }
    let list = lists
        .get(usize::from(x.list))
        .cloned()
        .unwrap_or_else(|| format!("#{}", x.list));
    let kind = if x.allow { "allow" } else { x.kind.label() };
    (Some(list), Some(kind.to_owned()))
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

impl ApiBackend {
    /// One query-log directory, as an API page. `node` labels its rows (shipped logs).
    fn search_dir(
        &self,
        dir: &Path,
        filter: &qlog::Filter,
        limit: usize,
        cursor: Option<qlog::Cursor>,
        node: Option<&str>,
    ) -> Result<QueryPage, Problem> {
        let opts = qlog::Options {
            threads: std::thread::available_parallelism().map_or(1, |n| n.get().min(4)),
            on_thread_start: Some(telltale_net::background_thread),
        };
        let page = qlog::search_with(dir, filter, limit, cursor, &opts)
            .map_err(|e| Problem::internal(format!("query log: {e}")))?;
        let lists = self.list_names();
        let policy = &self.src.pipeline.current().policy;
        let groups = policy.clients.groups();
        let quick = Arc::clone(&policy.quick);
        let schedules = self.src.pipeline.schedules.load().names.clone();
        let items = page
            .rows
            .iter()
            .map(|r| {
                let (list, rule) = rule_labels(r.rule, &lists, &quick, &schedules);
                QueryRow {
                    time: format_us(r.ts_us),
                    ts_unix_micros: r.ts_us,
                    client: telltale_telemetry::agg::client_text(r.client_ip),
                    // REQ: API-010 — names are resolved now, from the address, so naming or
                    // renaming a device relabels its history without rewriting the log.
                    client_name: device_name(&self.src, r.client_ip),
                    node: node.map(str::to_owned),
                    group: groups.get(usize::from(r.group)).map(|g| g.name.to_string()),
                    name: r.name.clone(),
                    qtype: qtype_name(r.qtype),
                    status: r.status.label().to_owned(),
                    rcode: r.rcode.map(rcode_name),
                    proto: r.proto.label().to_owned(),
                    list,
                    rule,
                    total_ms: ms(u64::from(r.t_total_us)),
                    upstream_ms: ms(u64::from(r.t_upstream_us)),
                    response_bytes: r.resp_size,
                    answers: r.answers,
                }
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

    /// This node's query log plus the logs shipped to it, newest first, paged with a
    /// federated cursor (one position per source; CLU-007).
    fn search_with_shipped(
        &self,
        filter: &qlog::Filter,
        limit: usize,
        cursor: Option<&str>,
        own: std::path::PathBuf,
        shipped: Vec<(String, std::path::PathBuf)>,
    ) -> Result<QueryPage, Problem> {
        use telltale_api::federation::{self, Bounds, NodePage};
        let prev: Bounds = match cursor {
            None => Bounds::new(),
            Some(c) => federation::decode_cursor(Some(c)).ok_or_else(bad_cursor)?,
        };
        let mut sources = vec![("self".to_owned(), own, None)];
        for (id, dir) in shipped {
            let label = self.site_of(&id);
            sources.push((format!("shipped:{id}"), dir, Some(label)));
        }
        let mut pages = Vec::new();
        for (key, dir, label) in sources {
            let Some(to) = federation::until(&prev, &key, filter.to_us) else {
                continue;
            };
            let mut f = filter.clone();
            f.to_us = to;
            let page = self.search_dir(&dir, &f, limit, None, label.as_deref())?;
            pages.push(NodePage {
                node: key,
                label: self.own_site(),
                page,
                asked: limit,
            });
        }
        Ok(federation::merge_queries(pages, limit, &prev))
    }

    /// A cluster node's site (else its ID), for labelling shipped rows.
    fn site_of(&self, id: &str) -> String {
        let Some(c) = &self.src.cluster else {
            return id.to_owned();
        };
        c.members()
            .into_iter()
            .find(|m| m.node_id == id)
            .map(|m| m.site)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                c.identity
                    .registry()
                    .into_iter()
                    .find(|n| n.node_id == id)
                    .map(|n| n.site)
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| id.to_owned())
    }

    /// This node's own site (else its ID; empty outside a cluster).
    fn own_site(&self) -> String {
        self.src.cluster.as_ref().map_or_else(String::new, |c| {
            let m = &c.identity.meta;
            if m.site.is_empty() {
                m.node_id.clone()
            } else {
                m.site.clone()
            }
        })
    }
}

fn bad_cursor() -> Problem {
    Problem::invalid("`cursor`: not a cursor from this API")
        .hint("Pass the nextCursor value from the previous page unchanged.")
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
            version: crate::build_info::VERSION.to_owned(),
            build: crate::build_info::api(),
            update: self
                .src
                .update
                .lock()
                .map_or_else(|e| e.into_inner().clone(), |u| u.clone()),
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
                let mut v = crate::cluster::view(c, &self.src.host);
                // ADR-049 — where the configuration comes from, when it's Git.
                v.source = crate::gitsource::view(&self.src.config.load(), c.is_primary());
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
                failover: None,
                source: None,
                // T6.11 — a standalone node still shows its machine.
                host: crate::host::report(self.src.host.latest(), &self.src.host.history(), None),
            },
        }
    }

    // REQ: API-007 (T6.7, ADR-063)
    fn backup(&self) -> Result<(String, Vec<u8>), Problem> {
        let cfg = self.src.config.load_full();
        let name = crate::backup::default_name(cfg.node.name.as_str());
        let tmp = std::path::Path::new(cfg.node.data_dir.as_str()).join(format!(
            ".backup-api-{}-{}.ttbk",
            std::process::id(),
            self.now_unix_seconds()
        ));
        let made = crate::backup::create(&self.src.config_files, &cfg, false, &tmp);
        let bytes = made.and_then(|_| std::fs::read(&tmp).map_err(|e| e.to_string()));
        let _ = std::fs::remove_file(&tmp);
        let bytes = bytes.map_err(|e| Problem::internal(format!("backup failed: {e}")))?;
        tracing::info!(bytes = bytes.len(), "backup downloaded through the API");
        Ok((name.display().to_string(), bytes))
    }

    // REQ: AGT-002 — the promotion checks without promoting.
    fn promote_plan(
        &self,
        req: &telltale_api::model::PromoteRequest,
    ) -> Result<telltale_api::model::PromotePlan, Problem> {
        let c = self
            .src
            .cluster
            .as_ref()
            .ok_or_else(|| Problem::unavailable("this node isn't in a cluster"))?;
        let cfg = self.src.config.load_full();
        let gitops_source = crate::replication::gitops_capable(&cfg);
        let (epoch, emergency) = crate::cluster::promote_plan(c, gitops_source, req.emergency)
            .map_err(|e| Problem::new(telltale_api::problem::Code::Conflict, e))?;
        let impact = if emergency {
            format!(
                "This node would become an emergency primary at epoch {epoch}: every node follows it, and the configuration stays at its last version until a Git-managed node takes over."
            )
        } else {
            format!(
                "This node would become the primary at epoch {epoch}: it publishes the configuration from the last version it applied, every node follows it, and an old primary that comes back steps down."
            )
        };
        Ok(telltale_api::model::PromotePlan {
            applied: false,
            epoch,
            emergency,
            impact,
        })
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
        let gitops_source = crate::replication::gitops_capable(&cfg);
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
                // T6.16 — stored buckets carry groups by name.
                for g in &c.named_groups {
                    if g.total > 0 {
                        *b.by_group.entry(g.name.to_string()).or_default() += g.total;
                    }
                    if g.blocked > 0 {
                        *b.blocked_by_group.entry(g.name.to_string()).or_default() += g.blocked;
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
            .map(|t| {
                let (name, groups) = self.client_labels(kind, &t.key);
                TopItem {
                    name,
                    groups,
                    key: t.key,
                    count: t.count,
                    error_bound: t.error,
                }
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
        tops.into_iter()
            .map(|t| {
                let (name, groups) = self.client_labels(kind, &t.key);
                TopItem {
                    key: t.key,
                    name,
                    groups,
                    count: t.count,
                    error_bound: t.error,
                }
            })
            .collect()
    }

    fn latency(&self, by: LatencyBy, h: Hour) -> Vec<LatencyRow> {
        let sel = hour(h);
        let agg = self.src.pipeline.telemetry.aggregates();
        self.latency_keys(by)
            .into_iter()
            .filter_map(|(name, key)| agg.latency(key, sel).map(|v| latency_row(name, v)))
            .collect()
    }

    // REQ: CLU-002 (T9.2) — the same keys' histograms, for an exact cluster merge.
    fn latency_hists(&self, by: LatencyBy, h: Hour) -> Vec<telltale_api::model::LatencyHist> {
        let sel = hour(h);
        let agg = self.src.pipeline.telemetry.aggregates();
        self.latency_keys(by)
            .into_iter()
            .filter_map(|(name, key)| {
                agg.latency_buckets(key, sel)
                    .map(|buckets| telltale_api::model::LatencyHist { key: name, buckets })
            })
            .collect()
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
                let (list, rule) = rule_labels(
                    e.rule,
                    &lists,
                    &src.pipeline.current().policy.quick,
                    &src.pipeline.schedules.load().names,
                );
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
                    list,
                    rule,
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
        let data_dir = self.src.config.load().node.data_dir.to_string();
        let dir = Path::new(&data_dir).join("qlog");
        // REQ: CLU-007 — query logs other nodes shipped here are searched too (ADR-055).
        let shipped = crate::ship::shipped_dirs(&data_dir);
        if !shipped.is_empty() {
            return self.search_with_shipped(&filter, limit, q.cursor.as_deref(), dir, shipped);
        }
        let cursor = match &q.cursor {
            None => None,
            Some(c) => Some(qlog::Cursor::decode(c).ok_or_else(bad_cursor)?),
        };
        self.search_dir(&dir, &filter, limit, cursor, None)
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
        // REQ: OBS-009 (T7.14) — hits per list ID on this node since it started.
        let mut hits: std::collections::HashMap<u16, u64> = std::collections::HashMap::new();
        for ((_, list), n) in &self.src.pipeline.telemetry.aggregates().exported.blocked {
            *hits.entry(*list).or_insert(0) += n;
        }
        cfg.list
            .iter()
            .map(|l| {
                let meta = status.iter().find(|(n, _)| *n == *l.name).map(|(_, m)| m);
                let id = compiled
                    .as_ref()
                    .and_then(|m| m.lists.iter().position(|x| x.name == *l.name));
                let per = compiled
                    .as_ref()
                    .zip(id)
                    .and_then(|(m, i)| m.stats.per_list.get(i));
                let entries = per.map_or(0, |s| s.entries);
                let unique = per.map_or(0, |s| s.unique);
                let list_hits = id
                    .and_then(|i| u16::try_from(i).ok())
                    .and_then(|i| hits.get(&i).copied())
                    .unwrap_or(0);
                let mut overlap: Vec<telltale_api::model::ListShare> = match (&compiled, id) {
                    (Some(m), Some(i)) => {
                        let i = u16::try_from(i).unwrap_or(u16::MAX);
                        m.stats
                            .overlap
                            .iter()
                            .filter_map(|o| {
                                let other = if o.a == i {
                                    o.b
                                } else if o.b == i {
                                    o.a
                                } else {
                                    return None;
                                };
                                m.lists.get(usize::from(other)).map(|x| {
                                    telltale_api::model::ListShare {
                                        list: x.name.clone(),
                                        names: o.names,
                                    }
                                })
                            })
                            .collect()
                    }
                    _ => Vec::new(),
                };
                overlap.sort_by(|a, b| b.names.cmp(&a.names).then(a.list.cmp(&b.list)));
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
                    unique,
                    hits: list_hits,
                    overlap,
                    last_checked_unix_seconds: meta.and_then(|m| m.last_attempt),
                    last_changed_unix_seconds: meta.and_then(|m| m.last_changed),
                }
            })
            .collect()
    }

    fn groups(&self) -> Vec<GroupInfo> {
        let cfg = self.src.config.load();
        let now_s = i64::try_from(crate::pipeline::unix_now()).unwrap_or(i64::MAX);
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
                blocked_services: g.services.iter().map(ToString::to_string).collect(),
                schedules: cfg
                    .group
                    .iter()
                    .find(|x| x.name.as_str() == &*g.name)
                    .map(|x| x.schedules.iter().map(ToString::to_string).collect())
                    .unwrap_or_default(),
                schedules_on: schedules_on(&cfg, &g.name, now_s),
                safe_search: g.safe_search.is_some(),
                youtube_restrict: g.safe_search.map(|y| {
                    match y {
                        telltale_config::YoutubeRestrict::Strict => "strict",
                        telltale_config::YoutubeRestrict::Moderate => "moderate",
                        telltale_config::YoutubeRestrict::Off => "off",
                    }
                    .to_owned()
                }),
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
                rebinding_protection: false,
                block_answer_ips: Vec::new(),
                rewrites: Vec::new(),
                dns64: false,
                dns64_prefix: None,
            })
            // REQ: T8.6 — answer filtering, rewrites, DNS64 (from the group's config).
            .map(|mut info| {
                if let Some(c) = cfg.group.iter().find(|x| x.name.as_str() == info.name) {
                    info.rebinding_protection = c.rebinding_protection;
                    info.block_answer_ips =
                        c.block_answer_ips.iter().map(ToString::to_string).collect();
                    info.rewrites = c
                        .rewrite
                        .iter()
                        .map(|r| telltale_api::model::RewriteInfo {
                            domain: r.domain.to_string(),
                            answer: r.answer.to_string(),
                        })
                        .collect();
                    info.dns64 = c.dns64;
                    info.dns64_prefix = c.dns64_prefix.as_ref().map(ToString::to_string);
                }
                info
            })
            .collect()
    }

    fn clients(&self) -> Vec<ClientInfo> {
        let managed = managed_names(&self.src);
        let state = self.src.pipeline.current();
        let clients = &state.policy.clients;
        self.src
            .config
            .load()
            .client
            .iter()
            .map(|c| {
                let mut info = client_info(c, &managed);
                // ADR-050 — a device without its own groups takes its network's.
                let (effective, from) = effective_groups(clients, c);
                info.effective_groups = effective;
                from.clone_into(&mut info.groups_from);
                info
            })
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

    // REQ: OPS-008 (T7.19) — this node's DHCP leases.
    fn dhcp_leases(&self) -> Vec<telltale_api::model::DhcpLease> {
        let mut v: Vec<telltale_api::model::DhcpLease> = self
            .src
            .pipeline
            .dhcp_leases
            .load()
            .values()
            .map(|l| telltale_api::model::DhcpLease {
                mac: l.mac.clone(),
                ip: l.ip.to_string(),
                hostname: l.hostname.clone(),
                client_name: device_name(&self.src, l.ip.to_ipv6_mapped().octets()),
                expires_unix_seconds: l.expires,
                reserved: l.reserved,
                source: "dhcp".to_owned(),
            })
            .collect();
        // REQ: T8.2 — the routers' DHCP clients too (TelltaleDNS's own leases win).
        let own: std::collections::HashSet<String> = v.iter().map(|l| l.ip.clone()).collect();
        for l in self.src.pipeline.router_leases.load().values() {
            if own.contains(&l.ip.to_string()) {
                continue;
            }
            v.push(telltale_api::model::DhcpLease {
                mac: l.mac.clone(),
                ip: l.ip.to_string(),
                hostname: l.hostname.clone(),
                client_name: device_name(&self.src, l.ip.to_ipv6_mapped().octets()),
                expires_unix_seconds: 0,
                reserved: false,
                source: "router".to_owned(),
            });
        }
        // REQ: T8.3, T8.6 — and the names devices announce over mDNS (leases and routers win).
        let known: std::collections::HashSet<String> = v.iter().map(|l| l.ip.clone()).collect();
        for l in self.src.pipeline.mdns_names.load().values() {
            if known.contains(&l.ip.to_string()) {
                continue;
            }
            v.push(telltale_api::model::DhcpLease {
                mac: String::new(),
                ip: l.ip.to_string(),
                hostname: l.hostname.clone(),
                client_name: device_name(&self.src, l.ip.to_ipv6_mapped().octets()),
                expires_unix_seconds: 0,
                reserved: false,
                source: "mdns".to_owned(),
            });
        }
        v.sort_by_key(|l| l.ip.parse::<std::net::Ipv4Addr>().map_or(0, u32::from));
        v
    }

    // REQ: AGT-012 (T8.4) — vqlog over this node's query log and the logs shipped to it.
    fn vqlog(
        &self,
        q: &telltale_api::vqlog::Query,
        from_us: u64,
        to_us: u64,
        dry_run: bool,
    ) -> Result<telltale_api::model::VqlogResult, Problem> {
        if self.src.qlog.is_none() {
            return Err(
                Problem::unavailable("the query log is off on this node").hint(
                    "Enable it with [telemetry.qlog] enabled = true (and privacy_level below 3).",
                ),
            );
        }
        let data_dir = self.src.config.load().node.data_dir.to_string();
        let mut dirs = vec![Path::new(&data_dir).join("qlog")];
        dirs.extend(
            crate::ship::shipped_dirs(&data_dir)
                .into_iter()
                .map(|(_, d)| d),
        );
        let groups = self
            .src
            .pipeline
            .current()
            .policy
            .clients
            .groups()
            .iter()
            .map(|g| g.name.to_string())
            .collect();
        let upstreams = self
            .upstreams()
            .into_iter()
            .map(|u| (u.id, u.name))
            .collect();
        let name = |ip: [u8; 16]| device_name(&self.src, ip);
        let ctx = crate::vqlog::Ctx {
            groups,
            upstreams,
            client_name: &name,
            qtype_name,
            rcode_name,
            rcode_value,
        };
        let opts = qlog::Options {
            threads: std::thread::available_parallelism().map_or(1, |n| n.get().min(4)),
            on_thread_start: Some(telltale_net::background_thread),
        };
        crate::vqlog::run(q, from_us, to_us, &dirs, &ctx, dry_run, &opts)
    }

    // REQ: OBS-009 (T7.14) — first-seen domains with their DGA scores.
    fn new_domains(
        &self,
        since_s: u64,
        client: Option<&str>,
        limit: usize,
    ) -> Vec<telltale_api::model::NewDomain> {
        let Some(a) = &self.src.anomalies else {
            return Vec::new();
        };
        let want = client.map(str::trim).filter(|c| !c.is_empty());
        a.new_domains(since_s, usize::MAX)
            .into_iter()
            .map(|d| (telltale_telemetry::agg::client_text(d.client), d))
            .filter(|(c, _)| want.is_none_or(|w| w == c))
            .take(limit)
            .map(|(c, d)| telltale_api::model::NewDomain {
                time: format_us(d.ts_s.saturating_mul(1_000_000)),
                client: c,
                client_name: device_name(&self.src, d.client),
                domain: d.domain,
                dga_score: (d.dga_score * 100.0).round() / 100.0,
            })
            .collect()
    }

    // REQ: API-011 — names on my network and domains sent elsewhere (ADR-042).
    fn local_names(&self) -> Vec<LocalName> {
        self.list_local_names()
    }

    // REQ: DNS-018 (T8.6) — the zones as loaded.
    fn zones(&self) -> Vec<telltale_api::model::ZoneInfo> {
        let cfg = self.src.config.load();
        let mut v: Vec<telltale_api::model::ZoneInfo> = self
            .src
            .pipeline
            .current()
            .policy
            .zones
            .iter()
            .map(|z| {
                let name = z
                    .apex
                    .display()
                    .to_string()
                    .trim_end_matches('.')
                    .to_owned();
                let file = cfg
                    .zone
                    .iter()
                    .find(|c| {
                        c.name
                            .as_str()
                            .trim_end_matches('.')
                            .eq_ignore_ascii_case(&name)
                    })
                    .and_then(|c| c.file.as_ref().map(ToString::to_string));
                telltale_api::model::ZoneInfo {
                    groups: z.groups.iter().map(ToString::to_string).collect(),
                    records: z.data.len() as u64,
                    file,
                    negative_ttl_seconds: z.negative_ttl,
                    name,
                }
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    fn forwards(&self) -> Vec<ForwardInfo> {
        self.list_forwards()
    }

    // REQ: DNS-006 (T6.13) — this node's cache.
    fn cache_stats(&self) -> Vec<telltale_api::model::CacheNodeStats> {
        let s = self.src.cache.stats();
        let looked = s.hits + s.misses;
        #[allow(clippy::cast_precision_loss)] // a percentage for display
        let hit_percent =
            (looked > 0).then(|| (s.hits as f64 / looked as f64 * 1000.0).round() / 10.0);
        vec![telltale_api::model::CacheNodeStats {
            node: None,
            entries: s.entries as u64,
            bytes: s.bytes as u64,
            hits: s.hits,
            misses: s.misses,
            hit_percent,
            stale_served: s.stale_served,
            prefetches: s.prefetches,
            evictions: s.evictions,
            inserts: s.inserts,
            uncacheable: s.uncacheable,
            settings: Some(cache_settings(&self.src.config.load().cache)),
            warm_start: self.src.cache_history.warm_start(),
            history: self.src.cache_history.points(),
        }]
    }

    // REQ: API-002 (T7.5, ADR-069) — upstreams, upstream groups, lists, and groups in effect,
    // with their sources (hidden files' entries included, so they can be brought back).
    fn config_entries(&self, kind: Option<&str>) -> Vec<telltale_api::model::ConfigEntry> {
        use crate::managed::{Named, Ovr};
        fn rows<T: Named + Serialize>(
            kind: &str,
            effective: &[T],
            file: &[T],
            stored: &[(String, Ovr<T>)],
            out: &mut Vec<telltale_api::model::ConfigEntry>,
        ) {
            let in_file = |n: &str| file.iter().any(|f| f.name() == n);
            for e in effective {
                let n = e.name();
                let api = stored.iter().any(|(s, _)| s == n);
                out.push(telltale_api::model::ConfigEntry {
                    kind: kind.to_owned(),
                    name: n.to_owned(),
                    source: match (api, in_file(n)) {
                        (true, true) => "override",
                        (true, false) => "added",
                        _ => "file",
                    }
                    .to_owned(),
                    definition: serde_json::to_value(e).ok(),
                });
            }
            for (n, o) in stored {
                if matches!(o, Ovr::Hidden) {
                    out.push(telltale_api::model::ConfigEntry {
                        kind: kind.to_owned(),
                        name: n.clone(),
                        source: "hidden".to_owned(),
                        definition: None,
                    });
                }
            }
        }
        let cfg = self.src.config.load();
        let file = self.src.file_config.load();
        let e = self
            .src
            .auth
            .get()
            .map(|a| crate::managed::entries(a.state()))
            .unwrap_or_default();
        let want = |k: &str| kind.is_none_or(|w| w == k);
        let mut out = Vec::new();
        if want("upstream") {
            // Upstreams a forwarded domain made are part of that domain, not listed here.
            let up: Vec<_> = cfg
                .upstream
                .iter()
                .filter(|u| !u.name.as_str().starts_with("forward:"))
                .cloned()
                .collect();
            rows("upstream", &up, &file.upstream, &e.upstreams, &mut out);
        }
        if want("upstream_group") {
            let g: Vec<_> = cfg
                .upstream_group
                .iter()
                .filter(|u| !u.name.as_str().starts_with("forward:"))
                .cloned()
                .collect();
            rows(
                "upstream_group",
                &g,
                &file.upstream_group,
                &e.upstream_groups,
                &mut out,
            );
        }
        if want("list") {
            rows("list", &cfg.list, &file.list, &e.lists, &mut out);
        }
        if want("group") {
            rows("group", &cfg.group, &file.group, &e.groups, &mut out);
        }
        out
    }

    // REQ: OPS-004 (ADR-046) — "Check now" in Settings.
    fn check_updates(
        &self,
    ) -> telltale_api::BoxFuture<Result<telltale_api::model::UpdateStatus, Problem>> {
        let cfg = self.src.config.load();
        let fut = crate::updates::check_now(
            Arc::clone(&self.src.update),
            cfg.updates.check,
            cfg.updates.index_url.as_ref().map(ToString::to_string),
        );
        Box::pin(async move { Ok(fut.await) })
    }

    // REQ: FLT-012 (T7.9) — the blockable services catalog.
    fn services(&self) -> Vec<telltale_api::model::ServiceInfo> {
        telltale_config::services::catalog()
            .iter()
            .map(|s| telltale_api::model::ServiceInfo {
                id: s.id.clone(),
                name: s.name.clone(),
                category: s.category.clone(),
                domains: s
                    .rules
                    .iter()
                    .map(|r| r.trim_start_matches("||").trim_end_matches('^').to_owned())
                    .collect(),
            })
            .collect()
    }

    // REQ: FLT-009 (T7.1) — this node's pauses.
    fn blocking_state(&self) -> Vec<telltale_api::model::BlockingNode> {
        let now = crate::pipeline::unix_now();
        let mut pauses: Vec<telltale_api::model::PauseInfo> = self
            .src
            .pipeline
            .pause
            .active(now)
            .into_iter()
            .map(|(group, until)| telltale_api::model::PauseInfo {
                group: group.map(|g| g.to_string()),
                until: telltale_api::time::format_us(until.saturating_mul(1_000_000)),
                seconds_left: until.saturating_sub(now),
            })
            .collect();
        pauses.sort_by(|a, b| a.group.cmp(&b.group));
        vec![telltale_api::model::BlockingNode {
            node: None,
            pauses,
            error: None,
        }]
    }

    fn blocking_pause(
        &self,
        group: Option<&str>,
        minutes: u32,
        _node: Option<&str>,
    ) -> Result<Vec<telltale_api::model::BlockingNode>, Problem> {
        let until = crate::pipeline::unix_now() + u64::from(minutes) * 60;
        match group {
            Some(g) => {
                self.known_group(g)?;
                self.src.pipeline.pause.pause_group(g, until);
            }
            None => self.src.pipeline.pause.pause_all(until),
        }
        Ok(self.blocking_state())
    }

    fn blocking_resume(
        &self,
        group: Option<&str>,
        _node: Option<&str>,
    ) -> Result<Vec<telltale_api::model::BlockingNode>, Problem> {
        let pause = &self.src.pipeline.pause;
        if let Some(g) = group {
            self.known_group(g)?;
            pause.pause_group(g, 0);
        } else {
            // Every pause: everyone's and each group's.
            pause.pause_all(0);
            let groups = pause.active(crate::pipeline::unix_now());
            for g in groups.into_iter().filter_map(|(g, _)| g) {
                pause.pause_group(&g, 0);
            }
        }
        Ok(self.blocking_state())
    }

    // REQ: DNS-006, OBS-003 (T6.15) — this node's top entries and makeup.
    fn cache_entries(
        &self,
        sort: &str,
        limit: usize,
        _node: Option<&str>,
    ) -> Result<Vec<telltale_api::model::CacheNodeEntries>, Problem> {
        use telltale_cache::TopBy;
        let by = match sort {
            "bytes" => TopBy::Bytes,
            "expiring" => TopBy::Expiring,
            "hits" => TopBy::Hits,
            other => return Err(Problem::invalid(format!("`sort`: `{other}`"))),
        };
        let (top, m) = self.src.cache.top(by, limit, std::time::Instant::now());
        Ok(vec![telltale_api::model::CacheNodeEntries {
            node: None,
            makeup: telltale_api::model::CacheMakeup {
                positive: m.positive,
                nxdomain: m.nxdomain,
                nodata: m.nodata,
                servfail: m.servfail,
                stale: m.stale,
                validated: m.validated,
            },
            entries: top
                .into_iter()
                .map(|t| {
                    let mut name = telltale_proto::NameBuf::default();
                    let shown = telltale_proto::read_name_uncompressed(&t.name, 0, &mut name)
                        .map_or_else(|_| "?".to_owned(), |_| name.display().to_string());
                    let e = t.info;
                    telltale_api::model::CacheTopEntry {
                        name: shown,
                        qtype: qtype_name(e.qtype),
                        rcode: rcode_name(e.rcode),
                        answers: e.answers,
                        authentic: e.authentic,
                        dnssec_ok: e.dnssec_ok,
                        ttl_left_seconds: i64::from(e.ttl) - i64::from(e.age_secs),
                        age_seconds: u64::from(e.age_secs),
                        bytes: e.bytes as u64,
                        hits: e.hits,
                    }
                })
                .collect(),
            error: None,
        }])
    }

    fn cache_lookup(&self, name: &str) -> Result<Vec<telltale_api::model::CacheEntry>, Problem> {
        let n = telltale_proto::NameBuf::from_presentation(name.trim())
            .map_err(|e| Problem::invalid(format!("`name`: {e}")))?;
        let now = std::time::Instant::now();
        Ok(self
            .src
            .cache
            .inspect(&n, now)
            .into_iter()
            .map(|e| telltale_api::model::CacheEntry {
                node: None,
                qtype: qtype_name(e.qtype),
                rcode: rcode_name(e.rcode),
                answers: e.answers,
                authentic: e.authentic,
                dnssec_ok: e.dnssec_ok,
                checking_disabled: e.checking_disabled,
                ttl_left_seconds: i64::from(e.ttl) - i64::from(e.age_secs),
                age_seconds: u64::from(e.age_secs),
                bytes: e.bytes as u64,
                hits: e.hits,
            })
            .collect())
    }

    fn cache_flush(
        &self,
        name: Option<&str>,
        subtree: bool,
        _node: Option<&str>,
    ) -> Result<Vec<telltale_api::model::CacheFlushNode>, Problem> {
        let removed = match name {
            Some(n) => {
                let n = telltale_proto::NameBuf::from_presentation(n.trim())
                    .map_err(|e| Problem::invalid(format!("`name`: {e}")))?;
                self.src.cache.flush_name(&n, subtree)
            }
            None => self.src.cache.flush_all_counted(),
        };
        Ok(vec![telltale_api::model::CacheFlushNode {
            node: None,
            removed: Some(removed as u64),
            error: None,
        }])
    }

    // REQ: FLT-005 (T6.12) — quick rules in effect, with how long each has left.
    fn rules(&self) -> Vec<telltale_api::model::RuleInfo> {
        let cfg = self.src.config.load();
        let file = self.src.file_config.load();
        let now = unix_now_secs();
        let mut out: Vec<telltale_api::model::RuleInfo> = cfg
            .rule
            .iter()
            .map(|r| {
                let at = r
                    .expires
                    .as_deref()
                    .and_then(telltale_config::parse_rfc3339);
                telltale_api::model::RuleInfo {
                    id: r.id.to_string(),
                    action: if r.action == telltale_config::RuleAction::Allow {
                        "allow"
                    } else {
                        "block"
                    }
                    .to_owned(),
                    domain: r.domain.to_string(),
                    devices: r.devices.iter().map(ToString::to_string).collect(),
                    groups: r.groups.iter().map(ToString::to_string).collect(),
                    expires: r.expires.as_ref().map(ToString::to_string),
                    expires_in_seconds: at.map(|a| u64::try_from(a - now).unwrap_or(0)),
                    note: r.note.as_ref().map(ToString::to_string),
                    created_by: r.created_by.as_ref().map(ToString::to_string),
                    created: r.created.as_ref().map(ToString::to_string),
                    source: if file.rule.iter().any(|f| f.id == r.id) {
                        "file"
                    } else {
                        "api"
                    }
                    .to_owned(),
                }
            })
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    // REQ: CLU-003 (ADR-049) — a push webhook checks the Git source at once.
    fn git_hook(&self, signature: Option<String>, body: Vec<u8>) -> Result<(), Problem> {
        let cfg = self.src.config.load();
        if cfg.cluster.git.is_none() {
            return Err(Problem::not_found(
                "this node has no Git configuration source",
            ));
        }
        crate::gitsource::webhook_ok(&cfg, signature.as_deref(), &body).map_err(|e| {
            Problem::new(Code::Unauthorized, e).hint(
                "Set the webhook's secret to the contents of [cluster.git] webhook_secret_file.",
            )
        })?;
        self.src.git_poke.notify_one();
        Ok(())
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
                impact: plan.impact.clone(),
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
        effective_groups: c.groups.iter().map(ToString::to_string).collect(),
        groups_from: "device".to_owned(),
    }
}

/// The groups that apply to a configured device and where they come from (ADR-050): its
/// own, else the network group of the first address or subnet it's matched by, else the
/// default. A device known only by MAC or client ID gets its group from wherever it's seen.
fn effective_groups(
    clients: &telltale_policy::ClientTable,
    c: &telltale_config::ClientConfig,
) -> (Vec<String>, &'static str) {
    if !c.groups.is_empty() {
        return (c.groups.iter().map(ToString::to_string).collect(), "device");
    }
    let names = |g: u16| {
        clients
            .groups()
            .get(usize::from(g))
            .map(|g| vec![g.name.to_string()])
            .unwrap_or_default()
    };
    let mut addressed = false;
    for key in &c.match_keys {
        let ip = key.split('/').next().and_then(|a| a.parse::<IpAddr>().ok());
        if let Some(ip) = ip {
            addressed = true;
            if let Some(g) = clients.network_group(ip) {
                return (names(g), "network");
            }
        }
    }
    if addressed || clients.groups().iter().all(|g| g.networks.is_empty()) {
        let default = clients
            .groups()
            .iter()
            .find(|g| g.name.as_ref() == "default")
            .map(|g| vec![g.name.to_string()])
            .unwrap_or_default();
        return (default, "default");
    }
    (Vec::new(), "network")
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
    impact: String,
    warnings: Vec<String>,
}

/// AGT-002 impact of a device change: recent queries from the addresses it matches (they
/// get the new label), and a sentence.
fn client_impact(
    src: &Sources,
    name: &str,
    before: Option<&ClientInfo>,
    after: Option<&telltale_config::ClientConfig>,
) -> (u64, String) {
    let keys: Vec<String> = after
        .map(|c| c.match_keys.iter().map(ToString::to_string).collect())
        .or_else(|| before.map(|b| b.matches.clone()))
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
    let impact = match after {
        None => format!(
            "Deletes `{name}`: its queries ({recent_queries} in the last two hours) show the address again, and it falls back to its network's group or `default`."
        ),
        Some(a) => {
            let groups: Vec<String> = a.groups.iter().map(ToString::to_string).collect();
            let groups = if groups.is_empty() {
                "its network's group (or `default`)".to_owned()
            } else {
                groups.join(", ")
            };
            format!(
                "{} `{}` ({} address(es)); its {recent_queries} queries in the last two hours, and all history, show that name, and it gets {groups}.",
                if before.is_some() { "Changes" } else { "Names" },
                a.name,
                a.match_keys.len()
            )
        }
    };
    (recent_queries, impact)
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
    let (recent_queries, impact) = client_impact(src, &w.name, before.as_ref(), after.as_ref());
    Ok(ClientPlan {
        before,
        after,
        recent_queries,
        impact,
        warnings,
    })
}

/// The `state.db` kind for an API kind.
fn kind_name(k: ManagedKind) -> &'static str {
    match k {
        ManagedKind::Record => crate::managed::RECORD,
        ManagedKind::Forward => crate::managed::FORWARD,
        ManagedKind::Rule => crate::managed::RULE,
        ManagedKind::Upstream => crate::managed::UPSTREAM,
        ManagedKind::UpstreamGroup => crate::managed::UPSTREAM_GROUP,
        ManagedKind::List => crate::managed::LIST,
        ManagedKind::Group => crate::managed::GROUP,
    }
}

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// REQ: FLT-005 (T6.12, ADR-067) — every 5 s, deletes quick rules made through the API whose
/// expiry has passed, and audit-logs each as `rule.expire`. Only a standalone node or the
/// primary does this (replicas receive the deletion with the next version, and stop applying
/// an expired rule on their own anyway). Rules from the config files are left alone: they
/// simply stop applying.
pub(crate) fn spawn_rule_sweep(
    src: Arc<Sources>,
    auth: Arc<telltale_api::auth::Auth>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let backend = ApiBackend {
            src: Arc::clone(&src),
        };
        loop {
            tokio::select! {
                _ = stop.changed() => return,
                () = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
            }
            if src.cluster.as_ref().is_some_and(|c| !c.is_primary()) {
                continue;
            }
            let expired = backend
                .rules()
                .into_iter()
                .filter(|r| r.source == "api" && r.expires_in_seconds == Some(0));
            for r in expired {
                let w = ManagedWrite {
                    kind: ManagedKind::Rule,
                    name: r.id.clone(),
                    body: None,
                    dry_run: false,
                    expect: None,
                    by: "rule expiry".into(),
                };
                match backend.write_managed(w).await {
                    Ok(c) if c.applied => auth.record(
                        &telltale_api::auth::Actor::system("rule expiry"),
                        "rule.expire",
                        &r.id,
                        &serde_json::json!({ "before": c.before, "configVersion": c.config_version }),
                    ),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(rule = %r.id, "an expired quick rule wasn't removed: {}", e.detail),
                }
            }
        }
    });
}

/// REQ: FLT-005 (T6.12, ADR-067) — a rule body as stored: validated shape, the expiry as an
/// absolute time (from `expires` or `forMinutes`), and who made it and when.
fn rule_of(
    v: &serde_json::Value,
    id: &str,
    by: &str,
) -> Result<telltale_config::RuleConfig, Problem> {
    use telltale_config::{RuleAction, RuleConfig, SafeString};
    let input: telltale_api::model::RuleInput =
        serde_json::from_value(v.clone()).map_err(|e| Problem::invalid(format!("body: {e}")))?;
    let safe = |what: &str, s: &str| {
        SafeString::new(s.trim()).map_err(|e| Problem::invalid(format!("`{what}`: {e}")))
    };
    let action = match input.action.trim() {
        "allow" => RuleAction::Allow,
        "block" => RuleAction::Block,
        other => {
            return Err(Problem::invalid(format!(
                "`action`: `{other}` (use `allow` or `block`)"
            )));
        }
    };
    let now = unix_now_secs();
    let expires = match (input.expires.as_deref(), input.for_minutes) {
        (Some(_), Some(_)) => {
            return Err(Problem::invalid("give `expires` or `forMinutes`, not both"));
        }
        (Some(e), None) => {
            let at = telltale_config::parse_rfc3339(e).ok_or_else(|| {
                Problem::invalid(format!("`expires`: `{e}` isn't an RFC 3339 time"))
                    .hint("For example 2026-10-05T21:30:00Z, or use forMinutes.")
            })?;
            if at <= now {
                return Err(Problem::new(
                    Code::InvalidConfig,
                    "`expires` is in the past",
                ));
            }
            Some(safe("expires", e)?)
        }
        (None, Some(0)) => return Err(Problem::invalid("`forMinutes` must be at least 1")),
        (None, Some(m)) => {
            let at = u64::try_from(now).unwrap_or(0) + u64::from(m) * 60;
            Some(safe("expires", &format_us(at * 1_000_000))?)
        }
        (None, None) => None,
    };
    Ok(RuleConfig {
        id: safe("id", id)?,
        action,
        domain: safe("domain", &norm(&input.domain))?,
        devices: input
            .devices
            .iter()
            .map(|d| safe("devices", d))
            .collect::<Result<_, _>>()?,
        groups: input
            .groups
            .iter()
            .map(|g| safe("groups", g))
            .collect::<Result<_, _>>()?,
        expires,
        note: input
            .note
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(|n| safe("note", n))
            .transpose()?,
        created_by: Some(safe("createdBy", by)?),
        created: Some(safe(
            "created",
            &format_us(u64::try_from(now).unwrap_or(0) * 1_000_000),
        )?),
    })
}

/// AGT-002 impact of a quick rule: recent queries for its domain (or names under it) and a
/// sentence saying for whom it changes.
fn rule_impact(src: &Sources, rule: &telltale_config::RuleConfig, setting: bool) -> (u64, String) {
    let domain = rule.domain.as_str();
    let under = format!(".{domain}");
    let agg = src.pipeline.telemetry.aggregates();
    let recent_queries: u64 = [HourSel::Current, HourSel::Previous]
        .into_iter()
        .flat_map(|h| agg.top_names(telltale_telemetry::agg::TopKind::Domains, h, 1000))
        .filter(|t| t.key == domain || t.key.ends_with(&under))
        .map(|t| t.count)
        .sum();
    drop(agg);
    let whom = if !rule.devices.is_empty() {
        format!(
            "for {}",
            rule.devices
                .iter()
                .map(telltale_config::SafeString::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else if !rule.groups.is_empty() {
        format!(
            "for the group(s) {}",
            rule.groups
                .iter()
                .map(telltale_config::SafeString::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        "for everyone".to_owned()
    };
    let action = if rule.action == telltale_config::RuleAction::Allow {
        "allowed"
    } else {
        "blocked"
    };
    let until = rule
        .expires
        .as_deref()
        .map_or(String::new(), |e| format!(" until {e}"));
    let impact = if setting {
        format!(
            "`{domain}` and its subdomains are {action} {whom}{until}, before any list; {recent_queries} queries for them in the last two hours (at least)."
        )
    } else {
        format!(
            "`{domain}` goes back to the lists {whom}; {recent_queries} queries for it in the last two hours (at least)."
        )
    };
    (recent_queries, impact)
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
    recent_queries: u64,
    impact: String,
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

/// AGT-002 impact of a local-name or forward change: recent queries for the name (or names
/// under the domain), and a sentence.
fn managed_impact(src: &Sources, kind: ManagedKind, name: &str, setting: bool) -> (u64, String) {
    let agg = src.pipeline.telemetry.aggregates();
    let under = format!(".{name}");
    let recent_queries: u64 = [HourSel::Current, HourSel::Previous]
        .into_iter()
        .flat_map(|h| agg.top_names(telltale_telemetry::agg::TopKind::Domains, h, 1000))
        .filter(|t| match kind {
            ManagedKind::Record => t.key == name,
            ManagedKind::Forward | ManagedKind::Rule => t.key == name || t.key.ends_with(&under),
            _ => false,
        })
        .map(|t| t.count)
        .sum();
    drop(agg);
    let impact = match (kind, setting) {
        (ManagedKind::Record, true) => format!(
            "TelltaleDNS answers `{name}` itself from now on; {recent_queries} queries for it in the last two hours (at least) went elsewhere."
        ),
        (ManagedKind::Record, false) => format!(
            "`{name}` goes back to the upstreams; {recent_queries} queries for it in the last two hours (at least)."
        ),
        (ManagedKind::Forward, true) => format!(
            "Names under `{name}` go to the servers given; {recent_queries} queries for them in the last two hours (at least)."
        ),
        (ManagedKind::Forward, false) => format!(
            "Names under `{name}` go back to the default upstreams; {recent_queries} queries for them in the last two hours (at least)."
        ),
        (ManagedKind::Rule, _) => String::new(), // rule_impact says it better
        (ManagedKind::Upstream | ManagedKind::UpstreamGroup, _) => {
            "Applies on the next query; answers already cached stay until they expire.".into()
        }
        (ManagedKind::List, true) => {
            "The list is downloaded and compiled in the background; blocking changes when that's done.".into()
        }
        (ManagedKind::List, false) => "Its blocks stop when the lists are compiled again (seconds).".into(),
        (ManagedKind::Group, _) => "Applies to the group's devices on their next query.".into(),
    };
    (recent_queries, impact)
}

/// Checks a local-name, forward, or quick-rule write (ADR-042): files win, and the files plus
/// every API entry with this change must validate, record values included.
#[allow(clippy::too_many_lines)] // one branch per kind of entry
fn plan_managed(
    src: &Sources,
    state: &telltale_store::state::State,
    w: &ManagedWrite,
) -> Result<ManagedPlan, Problem> {
    if matches!(
        w.kind,
        ManagedKind::Upstream | ManagedKind::UpstreamGroup | ManagedKind::List | ManagedKind::Group
    ) {
        return plan_override(src, state, w);
    }
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
        ManagedKind::Rule => file.rule.iter().any(|r| r.id.eq_ignore_ascii_case(&name)),
        _ => false,
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
        ManagedKind::Rule => {
            let before = entries
                .rules
                .iter()
                .find(|r| r.id.as_str() == name)
                .cloned();
            entries.rules.retain(|r| r.id.as_str() != name);
            let after = match &w.body {
                None => None,
                Some(v) => {
                    let r = rule_of(v, &name, &w.by)?;
                    entries.rules.push(r.clone());
                    Some(r)
                }
            };
            (
                before.map(|b| serde_json::to_value(b).unwrap_or_default()),
                after.map(|a| serde_json::to_value(a).unwrap_or_default()),
            )
        }
        _ => return Err(Problem::internal("handled by plan_override")),
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
        (_, Some(a)) => Some(a.to_string()),
    };
    let (recent_queries, impact) = if w.kind == ManagedKind::Rule {
        let rule = after
            .as_ref()
            .or(before.as_ref())
            .and_then(|v| serde_json::from_value::<telltale_config::RuleConfig>(v.clone()).ok());
        rule.map_or((0, String::new()), |r| rule_impact(src, &r, body.is_some()))
    } else {
        managed_impact(src, w.kind, &name, body.is_some())
    };
    Ok(ManagedPlan {
        name,
        before,
        after,
        body,
        recent_queries,
        impact,
        warnings,
    })
}

/// ADR-069 — one kind's change: returns (the entry before, the body to store).
fn override_step<T>(
    name: &str,
    body: Option<&serde_json::Value>,
    in_files: bool,
    current: Option<&T>,
    stored: &mut Vec<(String, crate::managed::Ovr<T>)>,
) -> Result<(Option<serde_json::Value>, Option<String>), Problem>
where
    T: crate::managed::Named + Clone + Serialize + serde::de::DeserializeOwned,
{
    let before = current.map(|c| serde_json::to_value(c).unwrap_or_default());
    let had = stored.iter().any(|(n, _)| n == name);
    stored.retain(|(n, _)| n != name);
    let body = match body {
        Some(v) => {
            let mut v = v.clone();
            if let Some(o) = v.as_object_mut() {
                o.insert("name".into(), serde_json::Value::String(name.to_owned()));
            } else {
                return Err(Problem::invalid("the body must be an object"));
            }
            let t: T = serde_json::from_value(v)
                .map_err(|e| Problem::new(Code::InvalidConfig, format!("{e}")))?;
            let s = serde_json::to_string(&t).unwrap_or_default();
            stored.push((name.to_owned(), crate::managed::Ovr::Set(t)));
            Some(s)
        }
        // DELETE: what the API stored goes (the files' entry is back), else hide the files'.
        None if had => None,
        None if in_files => {
            stored.push((name.to_owned(), crate::managed::Ovr::Hidden));
            Some(crate::managed::HIDDEN.to_owned())
        }
        None => return Err(Problem::not_found(format!("no `{name}`"))),
    };
    Ok((before, body))
}

/// The entry named `name`, as JSON.
fn named_json<T: crate::managed::Named + Serialize>(
    items: &[T],
    name: &str,
) -> Option<serde_json::Value> {
    items
        .iter()
        .find(|i| i.name() == name)
        .map(|x| serde_json::to_value(x).unwrap_or_default())
}

/// REQ: API-002 (T7.5, ADR-069) — a change to an upstream, upstream group, list, or group: it
/// may override or hide the files' entry of the same name. `PUT` stores a definition; `DELETE`
/// removes what the API stored (so the files' entry, if any, is back), or else hides the
/// files' entry. The merged configuration must validate.
fn plan_override(
    src: &Sources,
    state: &telltale_store::state::State,
    w: &ManagedWrite,
) -> Result<ManagedPlan, Problem> {
    use crate::managed::Named;
    let name = w.name.trim().to_owned();
    if name.is_empty() {
        return Err(Problem::invalid("the name is empty"));
    }
    let file = src.file_config.load_full();
    let mut entries = crate::managed::entries(state);
    let before_cfg = crate::managed::merge(&file, &entries).unwrap_or_else(|_| (*file).clone());

    let (before, body) = match w.kind {
        ManagedKind::Upstream => override_step(
            &name,
            w.body.as_ref(),
            file.upstream.iter().any(|u| u.name() == name),
            before_cfg.upstream.iter().find(|u| u.name() == name),
            &mut entries.upstreams,
        )?,
        ManagedKind::UpstreamGroup => override_step(
            &name,
            w.body.as_ref(),
            file.upstream_group.iter().any(|u| u.name() == name),
            before_cfg.upstream_group.iter().find(|u| u.name() == name),
            &mut entries.upstream_groups,
        )?,
        ManagedKind::List => override_step(
            &name,
            w.body.as_ref(),
            file.list.iter().any(|u| u.name() == name),
            before_cfg.list.iter().find(|u| u.name() == name),
            &mut entries.lists,
        )?,
        _ => override_step(
            &name,
            w.body.as_ref(),
            file.group.iter().any(|u| u.name() == name),
            before_cfg.group.iter().find(|u| u.name() == name),
            &mut entries.groups,
        )?,
    };
    let merged = crate::managed::merge(&file, &entries)
        .map_err(|errs| Problem::new(Code::InvalidConfig, errs.join("; ")))?;
    let after = match w.kind {
        ManagedKind::Upstream => named_json(&merged.upstream, &name),
        ManagedKind::UpstreamGroup => named_json(&merged.upstream_group, &name),
        ManagedKind::List => named_json(&merged.list, &name),
        _ => named_json(&merged.group, &name),
    };
    let warnings = telltale_config::validate_config(&merged).unwrap_or_default();
    let (recent_queries, impact) = managed_impact(src, w.kind, &name, w.body.is_some());
    Ok(ManagedPlan {
        name,
        before,
        after,
        body,
        recent_queries,
        impact,
        warnings,
    })
}

impl ApiBackend {
    /// For a client row of a top list: its device name and the groups that apply to it now.
    fn client_labels(&self, kind: TopKind, key: &str) -> (Option<String>, Vec<String>) {
        let Some(ip) = (kind == TopKind::Clients)
            .then(|| key.parse::<IpAddr>().ok())
            .flatten()
        else {
            return (None, Vec::new());
        };
        let state = self.src.pipeline.current();
        let clients = &state.policy.clients;
        let id = clients.identify(ip, None, None, &self.src.pipeline.neighbors);
        (
            clients.client(id).map(|c| c.name.to_string()),
            clients
                .group_names(id)
                .iter()
                .map(ToString::to_string)
                .collect(),
        )
    }

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
            // T7.5 — on a Git-managed node, what to add to Git to keep the change.
            let keep_in_git = (src.config.load().cluster.config_source.as_str() == "gitops")
                .then(|| keep_in_git(w.kind, &plan.name, w.body.as_ref(), plan.after.as_ref()));
            let change = |applied, version| ConfigChange {
                applied,
                config_version: version,
                before: plan.before.clone(),
                after: plan.after.clone(),
                recent_queries: plan.recent_queries,
                impact: plan.impact.clone(),
                warnings: plan.warnings.clone(),
                keep_in_git: keep_in_git.clone(),
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

impl ApiBackend {
    /// `Ok` when `name` is a configured group (pauses are kept by name, so a typo would pause
    /// nobody without saying so).
    fn known_group(&self, name: &str) -> Result<(), Problem> {
        let policy = &self.src.pipeline.current().policy;
        if policy.clients.groups().iter().any(|g| &*g.name == name) {
            Ok(())
        } else {
            Err(Problem::invalid(format!("`group`: no group `{name}`"))
                .hint("GET /api/v1/groups lists them."))
        }
    }
}

/// REQ: API-002 (T7.5, ADR-069) — the configuration TOML that makes an API change permanent in
/// Git: the section(s) to add (from what the request set), or which block to remove.
fn keep_in_git(
    kind: ManagedKind,
    name: &str,
    body: Option<&serde_json::Value>,
    after: Option<&serde_json::Value>,
) -> String {
    let section = match kind {
        ManagedKind::Record => "record",
        ManagedKind::Forward => "route",
        ManagedKind::Rule => "rule",
        ManagedKind::Upstream => "upstream",
        ManagedKind::UpstreamGroup => "upstream_group",
        ManagedKind::List => "list",
        ManagedKind::Group => "group",
    };
    let head = "# Add to the configuration in Git (with the Helm chart: under `config:`).\n";
    let Some(body) = body else {
        return if after.is_some() {
            format!(
                "# Nothing to change in Git: the configuration's own [[{section}]] `{name}` applies again.\n"
            )
        } else {
            format!("# Remove the [[{section}]] `{name}` from the configuration in Git.\n")
        };
    };
    // Tables to render under `section`: one per record, the request's fields otherwise.
    let tables: Vec<(&str, serde_json::Value)> = match kind {
        ManagedKind::Record => body
            .get("records")
            .and_then(serde_json::Value::as_array)
            .map(|rs| {
                rs.iter()
                    .map(|r| {
                        let mut t = r.clone();
                        if let Some(o) = t.as_object_mut() {
                            o.insert("name".into(), name.into());
                        }
                        ("record", t)
                    })
                    .collect()
            })
            .unwrap_or_default(),
        ManagedKind::Forward => {
            let group = crate::managed::forward_group(name);
            let servers: Vec<String> = body
                .get("servers")
                .and_then(serde_json::Value::as_array)
                .map(|v| {
                    v.iter()
                        .filter_map(|s| s.as_str().map(crate::managed::server_url))
                        .collect()
                })
                .unwrap_or_default();
            let mut t: Vec<(&str, serde_json::Value)> = servers
                .iter()
                .enumerate()
                .map(|(i, url)| {
                    (
                        "upstream",
                        serde_json::json!({ "name": format!("{group}#{}", i + 1), "url": url }),
                    )
                })
                .collect();
            let members: Vec<String> = (1..=servers.len())
                .map(|i| format!("{group}#{i}"))
                .collect();
            t.push((
                "upstream_group",
                serde_json::json!({ "name": group, "members": members, "strategy": "failover" }),
            ));
            t.push(("route", serde_json::json!({ "match_suffix": [name], "upstream_group": group, "dnssec_nta": true })));
            t
        }
        ManagedKind::Rule => after.map(|a| vec![("rule", a.clone())]).unwrap_or_default(),
        _ => {
            let mut t = body.clone();
            if let Some(o) = t.as_object_mut() {
                // `name` first, as people write it.
                let mut ordered = serde_json::Map::new();
                ordered.insert("name".into(), name.into());
                for (k, v) in o.iter().filter(|(k, _)| *k != "name") {
                    ordered.insert(k.clone(), v.clone());
                }
                *o = ordered;
            }
            vec![(section, t)]
        }
    };
    let mut out = String::from(head);
    for (sec, t) in tables {
        let mut root = toml::Table::new();
        let Ok(toml::Value::Table(table)) = toml::Value::try_from(&t) else {
            continue;
        };
        root.insert(
            sec.to_owned(),
            toml::Value::Array(vec![toml::Value::Table(table)]),
        );
        if let Ok(s) = toml::to_string(&root) {
            out.push_str(&s);
        }
    }
    out
}

/// REQ: DNS-006 (T6.15) — `[cache]` as the API shows it.
fn cache_settings(c: &telltale_config::CacheConfig) -> telltale_api::model::CacheSettings {
    telltale_api::model::CacheSettings {
        max_bytes: c.max_bytes.bytes(),
        max_entries: (c.max_entries > 0).then_some(u64::from(c.max_entries)),
        min_ttl_seconds: c.min_ttl,
        max_ttl_seconds: c.max_ttl,
        negative_ttl_max_seconds: c.negative_ttl_max,
        servfail_ttl_seconds: c.servfail_ttl,
        serve_stale: c.serve_stale,
        stale_max_age_seconds: c.stale_max_age,
        prefetch: c.prefetch,
        prefetch_threshold_percent: c.prefetch_threshold_pct,
        prefetch_min_hits: c.prefetch_min_hits,
        persist: c.persist,
    }
}

#[cfg(test)]
mod keep_in_git_tests {
    use super::*;

    /// REQ: API-002 (T7.5) — the TOML that keeps an API change in Git.
    #[test]
    fn api_002_keep_in_git_toml() {
        let up = keep_in_git(
            ManagedKind::Upstream,
            "quad9",
            Some(
                &serde_json::json!({ "url": "tls://9.9.9.9", "tls_server_name": "dns.quad9.net" }),
            ),
            None,
        );
        assert!(up.contains("[[upstream]]\nname = \"quad9\"\n"), "{up}");
        assert!(up.contains("url = \"tls://9.9.9.9\""), "{up}");
        let parsed: toml::Table = toml::from_str(&up).unwrap();
        assert_eq!(
            parsed["upstream"][0]["tls_server_name"].as_str(),
            Some("dns.quad9.net")
        );
        let rec = keep_in_git(
            ManagedKind::Record,
            "nas.home",
            Some(&serde_json::json!({ "records": [{ "type": "A", "value": "192.168.1.10" }] })),
            None,
        );
        let parsed: toml::Table = toml::from_str(&rec).unwrap();
        assert_eq!(parsed["record"][0]["name"].as_str(), Some("nas.home"));
        let fwd = keep_in_git(
            ManagedKind::Forward,
            "corp.example",
            Some(&serde_json::json!({ "servers": ["10.0.0.53"] })),
            None,
        );
        let parsed: toml::Table = toml::from_str(&fwd).unwrap();
        assert_eq!(
            parsed["route"][0]["upstream_group"].as_str(),
            Some("forward:corp.example")
        );
        assert_eq!(
            parsed["upstream"][0]["url"].as_str(),
            Some("udp://10.0.0.53")
        );
        let gone = keep_in_git(ManagedKind::List, "ads", None, None);
        assert!(gone.starts_with("# Remove the [[list]] `ads`"), "{gone}");
        let back = keep_in_git(ManagedKind::List, "ads", None, Some(&serde_json::json!({})));
        assert!(back.contains("Nothing to change in Git"), "{back}");
    }
}
